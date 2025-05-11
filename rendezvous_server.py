# rendezvous_server.py -- A simple rendezvous server for peer-to-peer file sharing

from flask import Flask, jsonify, request
from datetime import datetime, timedelta
import pymongo
import logging
import os
import secrets
from argon2 import PasswordHasher
import time
import uuid
import json

# Configure logging
os.makedirs("logs", exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("logs/rendezvous_server.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("rendezvous_server")

# Session Configuration
SESSION_TIMEOUT_MINUTES = 120  # 2 hours
TOKEN_LENGTH = 32

# MongoDB Configuration
MONGO_URI = "mongodb://localhost:27017/"
DB_NAME = "ciphershare"

# Password hasher
ph = PasswordHasher()

app = Flask(__name__)
peers = {}
active_sessions = {}  # Maps session tokens to user information
network_version = 0  # Global network version counter

# Initialize MongoDB connection
try:
    mongo_client = pymongo.MongoClient(MONGO_URI)
    db = mongo_client[DB_NAME]
    
     # Collections
    users_collection = db["users"]
    sessions_collection = db["sessions"]
    
    # Create unique index on username
    users_collection.create_index([("username", pymongo.ASCENDING)], unique=True)
    sessions_collection.create_index([("token", pymongo.ASCENDING)], unique=True)
    sessions_collection.create_index([("expires", pymongo.ASCENDING)])
    
    logger.info("Connected to MongoDB successfully")
except Exception as e:
    logger.error(f"MongoDB connection error: {e}")
    raise
    

def generate_session_token():
    """Generate a secure random session token."""
    return secrets.token_hex(TOKEN_LENGTH)

def create_session(username):
    """
    Create a new session for the specified user.
    
    Args:
        username (str): The username to create a session for
        
    Returns:
        str: The generated session token
    """
    token = generate_session_token()
    expires = datetime.now() + timedelta(minutes=SESSION_TIMEOUT_MINUTES)
    
    # Check if user already has a session
    existing_session = sessions_collection.find_one({"username": username})
    if existing_session:
        # Invalidate the existing session
        sessions_collection.delete_one({"username": username})
        logger.info(f"Previous session for user '{username}' was invalidated")
    
    # Create a new session record
    session = {
        "token": token,
        "username": username,
        "created_at": datetime.now(),
        "expires": expires,
        "ip_address": request.remote_addr,
        "user_agent": request.headers.get("User-Agent", "Unknown")
    }
    
    sessions_collection.insert_one(session)
    logger.info(f"Created new session for user '{username}'")
    
    return token

def validate_session(token):
    """
    Validate a session token.
    
    Args:
        token (str): The session token to validate
        
    Returns:
        tuple: (is_valid, username or None)
    """
    if not token:
        return False, None
    
    # Find the session
    session = sessions_collection.find_one({"token": token})
    
    if not session:
        logger.warning(f"Invalid session token: {token[:10]}...")
        return False, None
    
    # Check if expired
    if session["expires"] < datetime.now():
        logger.warning(f"Expired session token for user '{session['username']}'")
        sessions_collection.delete_one({"token": token})
        return False, None
    
    # Session is valid
    return True, session["username"]


@app.route('/register', methods=['POST'])
def register():
    """Register a peer with the rendezvous server."""
    global network_version
    data = request.json
    
    # Validate session token
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        logger.warning(f"Unauthorized register attempt: Missing or invalid Authorization header")
        return jsonify({'status': 'error', 'message': 'Unauthorized'}), 401
    
    token = auth_header.split(' ')[1]
    is_valid, username = validate_session(token)
    
    if not is_valid:
        logger.warning(f"Unauthorized register attempt with invalid token")
        return jsonify({'status': 'error', 'message': 'Invalid session'}), 401
    
    # Check if username matches the one in the request
    if username != data.get('username'):
        logger.warning(f"Username mismatch in register request: token username '{username}' != request username '{data.get('username')}'")
        return jsonify({'status': 'error', 'message': 'Username mismatch'}), 403
    
    # Check if user already has a registered peer
    for peer_id, peer_info in peers.items():
        if peer_info.get('username') == username and peer_id != data.get('peer_id'):
            logger.warning(f"User '{username}' attempted to register multiple peers")
            return jsonify({'status': 'error', 'message': 'User already has an active peer'}), 409
    
    peer_id = data.get('peer_id')
    address = data.get('address')
    
    logger.info(f"Registering peer: {peer_id} ({username}) at {address}")
    
    peers[peer_id] = {
        'address': address,
        'username': username,
        'last_seen': datetime.now(),
        'files': data.get('files', [])
    }
    
    network_version += 1
    return jsonify({'status': 'ok', 'version': network_version})

@app.route('/heartbeat', methods=['POST'])
def heartbeat():
    """Handle heartbeat from a peer."""
    global network_version
    data = request.json
    peer_id = data.get('peer_id')
    
    # Validate session token
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        logger.warning(f"Unauthorized heartbeat attempt for peer {peer_id}")
        return jsonify({'status': 'error', 'message': 'Unauthorized'}), 401
    
    token = auth_header.split(' ')[1]
    is_valid, username = validate_session(token)
    
    if not is_valid:
        logger.warning(f"Heartbeat with invalid token for peer {peer_id}")
        return jsonify({'status': 'error', 'message': 'Invalid session'}), 401
    
    # Check if username matches
    if username != data.get('username'):
        logger.warning(f"Username mismatch in heartbeat: token username '{username}' != request username '{data.get('username')}'")
        return jsonify({'status': 'error', 'message': 'Username mismatch'}), 403
    
    if peer_id in peers:
        # Update peer information
        peers[peer_id]['last_seen'] = datetime.now()
        peers[peer_id]['files'] = data.get('files', [])
        
        if 'username' in data:
            peers[peer_id]['username'] = data['username']
        
        network_version += 1
        logger.debug(f"Heartbeat from peer: {peer_id}")
        return jsonify({'status': 'ok', 'version': network_version})
    else:
        logger.warning(f"Heartbeat from unknown peer: {peer_id}")
        return jsonify({'status': 'error', 'message': 'Unknown peer'}), 404

@app.route('/peers')
def list_peers():
    global network_version
    
     # Validate session token
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        logger.warning(f"Unauthorized peers list request")
        return jsonify({'status': 'error', 'message': 'Unauthorized'}), 401
    
    token = auth_header.split(' ')[1]
    is_valid, username = validate_session(token)
    
    if not is_valid:
        logger.warning(f"Peers list request with invalid token")
        return jsonify({'status': 'error', 'message': 'Invalid session'}), 401
    
    # Cleanup old peers
    for peer_id in list(peers.keys()):
        if (datetime.now() - peers[peer_id]['last_seen']) > timedelta(seconds=10):
            del peers[peer_id]
            network_version += 1
    
    logger.info(f"Returning {len(peers)} active peers to user '{username}'")        
    return jsonify({'peers': peers, 'version': network_version})

@app.route('/version')
def get_version():
    """Get the current network version."""
    # Validate session token
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        logger.warning(f"Unauthorized version request")
        return jsonify({'status': 'error', 'message': 'Unauthorized'}), 401
    
    token = auth_header.split(' ')[1]
    is_valid, _ = validate_session(token)
    
    if not is_valid:
        logger.warning(f"Version request with invalid token")
        return jsonify({'status': 'error', 'message': 'Invalid session'}), 401
    
    return jsonify({'version': network_version})


# User authentication endpoints
@app.route('/user/register', methods=['POST'])
def register_user():
    """Register a new user."""
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        logger.warning("User registration attempt with missing username or password")
        return jsonify({'status': 'error', 'message': 'Username and password are required'}), 400
    
    # Input validation
    if len(username) < 3:
        logger.warning(f"User registration attempt with username too short: '{username}'")
        return jsonify({'status': 'error', 'message': 'Username must be at least 3 characters'}), 400
    
    if len(password) < 8:
        logger.warning(f"User registration attempt with password too short for username: '{username}'")
        return jsonify({'status': 'error', 'message': 'Password must be at least 8 characters'}), 400
    
    # Check if username already exists
    if users_collection.find_one({"username": username}):
        logger.warning(f"User registration attempt with existing username: '{username}'")
        return jsonify({'status': 'error', 'message': 'Username already exists'}), 409
    
    try:
        # Hash the password with Argon2
        password_hash = ph.hash(password)
        
        # Create user record
        user = {
            "username": username,
            "password_hash": password_hash,
            "created_at": datetime.now(),
            "last_login": None,
            "login_attempts": 0,
            "status": "active"
        }
        
        # Insert into database
        users_collection.insert_one(user)
        logger.info(f"User '{username}' registered successfully from IP {request.remote_addr}")
        
        return jsonify({'status': 'success', 'message': 'User registered successfully'})
        
    except Exception as e:
        logger.error(f"Error registering user '{username}': {str(e)}")
        return jsonify({'status': 'error', 'message': f'Registration error: {str(e)}'}), 500

@app.route('/user/login', methods=['POST'])
def login_user():
    """Authenticate a user and create a session."""
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        logger.warning("Login attempt with missing username or password")
        return jsonify({'status': 'error', 'message': 'Username and password are required'}), 400
    
    # Get user from database
    user = users_collection.find_one({"username": username})
    
    if not user:
        logger.warning(f"Login attempt for non-existent user: '{username}' from IP {request.remote_addr}")
        return jsonify({'status': 'error', 'message': 'Invalid username or password'}), 401
    
    # Check if account is locked
    if user.get("status") == "locked":
        logger.warning(f"Login attempt for locked account: '{username}' from IP {request.remote_addr}")
        return jsonify({'status': 'error', 'message': 'Account is locked. Please contact administrator.'}), 403
    
    # Verify password
    try:
        ph.verify(user["password_hash"], password)
        
        # Reset login attempts on successful login
        users_collection.update_one(
            {"username": username},
            {"$set": {"login_attempts": 0, "last_login": datetime.now()}}
        )
        
        # Create a new session
        token = create_session(username)
        
        logger.info(f"User '{username}' logged in successfully from IP {request.remote_addr}")
        
        return jsonify({
            'status': 'success', 
            'message': 'Login successful',
            'token': token
        })
        
    except argon2.exceptions.VerifyMismatchError:
        # Increment login attempts
        users_collection.update_one(
            {"username": username},
            {"$inc": {"login_attempts": 1}}
        )
        
        # Check if account should be locked (5 failed attempts)
        updated_user = users_collection.find_one({"username": username})
        if updated_user.get("login_attempts", 0) >= 5:
            users_collection.update_one(
                {"username": username},
                {"$set": {"status": "locked"}}
            )
            logger.warning(f"Account '{username}' locked after 5 failed login attempts")
        
        logger.warning(f"Failed login attempt for user '{username}' from IP {request.remote_addr}")
        return jsonify({'status': 'error', 'message': 'Invalid username or password'}), 401
    
    except Exception as e:
        logger.error(f"Login error for user '{username}': {str(e)}")
        return jsonify({'status': 'error', 'message': 'Login error'}), 500

@app.route('/user/logout', methods=['POST'])
def logout_user():
    """Log out a user by invalidating their session."""
    # Get the token from the Authorization header
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        logger.warning(f"Unauthorized logout attempt")
        return jsonify({'status': 'error', 'message': 'Unauthorized'}), 401
    
    token = auth_header.split(' ')[1]
    
    # Get session information before deleting
    session = sessions_collection.find_one({"token": token})
    if session:
        username = session.get("username")
        # Delete the session
        sessions_collection.delete_one({"token": token})
        logger.info(f"User '{username}' logged out successfully")
        return jsonify({'status': 'success', 'message': 'Logout successful'})
    else:
        logger.warning(f"Logout attempt with invalid token")
        return jsonify({'status': 'error', 'message': 'Invalid session'}), 401

@app.route('/user/validate', methods=['POST'])
def validate_token():
    """Validate a session token."""
    data = request.json
    token = data.get('token')
    
    if not token:
        return jsonify({'valid': False, 'message': 'No token provided'}), 400
    
    is_valid, username = validate_session(token)
    
    if is_valid:
        return jsonify({'valid': True, 'username': username})
    else:
        return jsonify({'valid': False, 'message': 'Invalid or expired token'}), 401

@app.route('/session/verify', methods=['GET'])
def verify_session():
    """Verify if a session is valid."""
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'valid': False, 'message': 'No token provided'}), 401
    
    token = auth_header.split(' ')[1]
    is_valid, username = validate_session(token)
    
    if is_valid:
        return jsonify({'valid': True, 'username': username})
    else:
        return jsonify({'valid': False, 'message': 'Invalid or expired token'}), 401

# ==============================================================================================
# Endpoint to find peers with specific files
@app.route('/peers/<filename>')
def get_peers_with_file(filename):
    """Get peers that have a specific file/chunk."""
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'status': 'error', 'message': 'Unauthorized'}), 401
    
    token = auth_header.split(' ')[1]
    is_valid, username = validate_session(token)
    if not is_valid:
        return jsonify({'status': 'error', 'message': 'Invalid session'}), 401

    matching_peers = {
        pid: info for pid, info in peers.items() 
        if filename in info['files']
    }
    return jsonify({'peers': matching_peers})
# ==============================================================================================

# Background task to clean up expired sessions
def cleanup_expired_sessions():
    """Remove expired sessions from the database."""
    while True:
        try:
            result = sessions_collection.delete_many({"expires": {"$lt": datetime.now()}})
            if result.deleted_count > 0:
                logger.info(f"Cleaned up {result.deleted_count} expired sessions")
        except Exception as e:
            logger.error(f"Error cleaning up expired sessions: {str(e)}")
        
        # Sleep for 5 minutes
        time.sleep(300)

# Start the cleanup thread
import threading
cleanup_thread = threading.Thread(target=cleanup_expired_sessions, daemon=True)
cleanup_thread.start()

if __name__ == '__main__':
    logger.info("Starting Rendezvous Server on port 5001")
    app.run(host='0.0.0.0', port=5001)