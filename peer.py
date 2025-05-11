# peer.py -- Client-side code for a secure P2P file sharing application using Streamlit and HTTP server

import streamlit as st
import os
import shutil
import threading
import requests
import socket
import time
import hashlib
import json
from http.server import HTTPServer, SimpleHTTPRequestHandler
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import pymongo
import secrets
import logging
import uuid
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import random
import binascii
# Configuration
RENDEZVOUS_SERVER = "http://localhost:5001"
PEERS_ROOT = "peers"
CHUNK_SIZE = 256 * 1024  # 256KB
LOG_DIR = "logs"
PASSWORD_MIN_LENGTH = 8
SESSION_TIMEOUT_MINUTES = 120

# Create required directories
os.makedirs(PEERS_ROOT, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(LOG_DIR, "ciphershare.log")),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("ciphershare")
    
class FileChangeHandler(FileSystemEventHandler):
    """Handles file change events."""
    def __init__(self, callback):
        """
        Initialize with a callback function.
        
        Args:
            callback: Function to call when a file change is detected
        """
        self.callback = callback
        
    def on_modified(self, event):
        """
        Called when a file is modified.
        
        Args:
            event: The file modification event
        """
        self.callback()

class P2PRequestHandler(SimpleHTTPRequestHandler):
    """HTTP request handler for P2P file sharing with authentication."""
    def __init__(self, *args, **kwargs):
        self.peer_id = kwargs.pop('peer_id')
        self.auth_token = kwargs.pop('auth_token', None)
        directory = kwargs.pop('directory', None)
        super().__init__(*args, directory=directory, **kwargs)
        
    def log_message(self, format, *args):
        """Override log_message to use our logger."""
        logger.info(f"{self.address_string()} - {format%args}")
    
    def do_GET(self):
        # Check if request has valid auth token
        auth_header = self.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            logger.warning(f"Unauthorized request from {self.client_address}")
            self.send_response(401)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(b'Unauthorized: Authentication required')
            return
        
        token = auth_header.split(' ')[1]
        #  Check if there's any token provided,if they have a token, they're authorized
        if not token:
            logger.warning(f"Request with invalid token from {self.client_address}")
            self.send_response(403)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(b'Forbidden: Invalid token')
            return


        
        # Log the file being requested
        filename = os.path.basename(self.path)
        logger.info(f"Serving file: {filename} to {self.client_address}")
                
        # Continue with the regular file handling
        super().do_GET()


class SecurityError(Exception):
    def __init__(self, message="Security violation detected"):
        self.message = message
        super().__init__(self.message)

class PeerNode:
    SYMMETRIC_KEY = b'supersecretkey123456789012345678'

    def __init__(self, host, port,username,auth_token):
        """
        Initialize a peer node.
        
        Args:
            host: Host address
            port: Port number
            username: Username associated with this peer
            auth_token: Authentication token for API requests
        """
        if len(self.SYMMETRIC_KEY) != 32:
            raise ValueError(f"Invalid AES-256 key length: {len(self.SYMMETRIC_KEY)} bytes")
        self.peer_id = f"{host}_{port}"
        self.host = host
        self.port = port
        self.username = username
        self.auth_token = auth_token
        self.base_dir = os.path.join(PEERS_ROOT, self.peer_id)
        self.shared_dir = os.path.join(self.base_dir, "shared")
        self.download_dir = os.path.join(self.base_dir, "downloads")
        self.server = None
        self.observer = None
        self.running = True

        os.makedirs(self.shared_dir, exist_ok=True)
        os.makedirs(self.download_dir, exist_ok=True)
        
        logger.info(f"Initializing peer node for user '{username}' at {host}:{port}")
        
        self.start_server()
        self.register_with_rendezvous()
        self.start_file_watcher()
        threading.Thread(target=self.heartbeat, daemon=True).start()

        logger.info(f"Peer node started: {self.peer_id}")
        
    def start_server(self):
        try:
            handler = lambda *args: P2PRequestHandler(*args, peer_id=self.peer_id,auth_token=self.auth_token,
                    directory=self.shared_dir)
            self.server = HTTPServer((self.host, self.port), handler)
            threading.Thread(target=self.server.serve_forever, daemon=True).start()
            logger.info(f"HTTP server started on {self.host}:{self.port}")
        except Exception as e:
            logger.error(f"Failed to start HTTP server: {str(e)}")
            raise
        
    def start_file_watcher(self):
        """Start watching for file changes in the shared directory."""
        try:
            self.observer = Observer()
            event_handler = FileChangeHandler(self.on_file_change)
            self.observer.schedule(event_handler, self.shared_dir, recursive=False)
            self.observer.start()
            logger.info(f"File watcher started for {self.shared_dir}")
        except Exception as e:
            logger.error(f"Failed to start file watcher: {str(e)}")
            raise

    def on_file_change(self):
        """Handle file change events by updating the rendezvous server."""
        logger.debug("File change detected, updating rendezvous server")
        self.register_with_rendezvous()

    def register_with_rendezvous(self):
        try:
            headers = {"Authorization": f"Bearer {self.auth_token}"}
            response = requests.post(
                f"{RENDEZVOUS_SERVER}/register",
                json={
                    'peer_id': self.peer_id,
                    'username': self.username,
                    'address': f"{self.host}:{self.port}",
                    'files': self.get_shared_files()
                },
                headers=headers,
                timeout=5
            )
            
            if response.status_code == 200:
                logger.info(f"Registered with rendezvous server: {response.json()}")
            elif response.status_code == 401 or response.status_code == 403:
                logger.error("Authentication failure with rendezvous server")
                st.session_state.authenticated = False
                st.session_state.token = None
                st.session_state.auth_error = "Your session has expired. Please log in again."
            else:
                logger.warning(f"Failed to register with rendezvous server: {response.status_code}")
        except Exception as e:
            logger.error(f"Error registering with rendezvous server: {str(e)}")

    def heartbeat(self):
        """Send periodic heartbeats to the rendezvous server."""
        while self.running:
            try:
                time.sleep(5)
                headers = {"Authorization": f"Bearer {self.auth_token}"}
                response = requests.post(
                    f"{RENDEZVOUS_SERVER}/heartbeat",
                    json={
                        'peer_id': self.peer_id,
                        'username': self.username,
                        'files': self.get_shared_files()
                    },
                    headers=headers,
                    timeout=5
                )
                
                if response.status_code == 200:
                    logger.debug(f"Heartbeat successful")
                elif response.status_code == 401 or response.status_code == 403:
                    logger.error("Authentication failure during heartbeat")
                    self.running = False
                    st.session_state.authenticated = False
                    st.session_state.token = None
                    st.session_state.auth_error = "Your session has expired. Please log in again."
                else:
                    logger.warning(f"Heartbeat failed: {response.status_code}")
            except Exception as e:
                logger.error(f"Heartbeat error: {str(e)}")


    def fetch_all_usernames(self):
        """Fetch all usernames from the rendezvous server."""
        try:
            headers = {"Authorization": f"Bearer {self.auth_token}"}
            response = requests.get(f"{RENDEZVOUS_SERVER}/user/all_usernames", headers=headers, timeout=5)

            if response.status_code == 200:
                usernames = response.json().get("usernames", [])
                logger.info(f"Fetched usernames: {usernames}")
                return usernames
            elif response.status_code in (401, 403):
                logger.error("Authentication failure when fetching usernames")
                st.session_state.authenticated = False
                st.session_state.token = None
                st.session_state.auth_error = "Your session has expired. Please log in again."
            else:
                logger.warning(f"Failed to fetch usernames: {response.status_code}")
                return []
        except Exception as e:
            logger.error(f"Error fetching usernames: {str(e)}")
            return []

# ===========================================================================================
# p2p getting shared files meta data!

    # def get_shared_files(self):
    #     return [f for f in os.listdir(self.shared_dir) if f.endswith('.manifest')]


    def get_shared_files(self):
        """Return all files in shared directory (both chunks and manifests)."""
        return os.listdir(self.shared_dir)

    def get_peers_with_file(self, filename):
        """Query rendezvous server for peers having specific file."""
        try:
            headers = {"Authorization": f"Bearer {self.auth_token}"}
            response = requests.get(
                f"{RENDEZVOUS_SERVER}/peers/{filename}",
                headers=headers,
                timeout=2
            )
            return response.json().get('peers', {}) if response.ok else {}
        except Exception as e:
            return {}
# ===========================================================================================

    def get_peers(self):
        try:
            headers = {"Authorization": f"Bearer {self.auth_token}"}
            response = requests.get(
                f"{RENDEZVOUS_SERVER}/peers", 
                headers=headers,
                timeout=2
            )
            
            if response.status_code == 200:
                peers = response.json().get('peers', {})
                logger.debug(f"Found {len(peers)} peers on the network")
                return peers
            elif response.status_code == 401 or response.status_code == 403:
                logger.error("Authentication failure when getting peers")
                st.session_state.authenticated = False
                st.session_state.token = None
                st.session_state.auth_error = "Your session has expired. Please log in again."
                return {}
            else:
                logger.warning(f"Failed to get peers: {response.status_code}")
                return {}
                
        except Exception as e:
            logger.error(f"Error getting peers: {str(e)}")
            return {}
    
    def get_manifest_metadata(self, manifest_name):
        """Retrieve metadata for a given manifest by name from the network."""
        # Find peers that have the manifest
        peers_with_manifest = self.get_peers_with_file(manifest_name)
        if not peers_with_manifest:
            logger.warning(f"No peers found with manifest '{manifest_name}'")
            return None

        # Convert to list to handle cases where peer IDs might be modified during iteration
        available_peers = list(peers_with_manifest.items())
        
        # Try each peer until successful download
        for peer_id, peer_info in available_peers:
            peer_address = peer_info['address']
            logger.info(f"Attempting to download manifest '{manifest_name}' from {peer_id} at {peer_address}")

            # Download the manifest file without adding to shared directory
            success = self.download_file(peer_id, manifest_name, add_to_shared=False)
            if success:
                # Read the downloaded manifest from download directory
                manifest_path = os.path.join(self.download_dir, manifest_name)
                try:
                    with open(manifest_path, 'r') as f:
                        metadata = json.load(f)
                    logger.info(f"Successfully retrieved metadata for '{manifest_name}'")
                    
                    # Cleanup temporary file
                    os.remove(manifest_path)
                    return metadata
                except json.JSONDecodeError as jde:
                    logger.error(f"Invalid JSON in manifest '{manifest_name}': {str(jde)}")
                    os.remove(manifest_path)
                except Exception as e:
                    logger.error(f"Error reading manifest '{manifest_name}': {str(e)}")
                    if os.path.exists(manifest_path):
                        os.remove(manifest_path)
            else:
                logger.warning(f"Failed to download manifest '{manifest_name}' from {peer_id}")

        logger.error(f"Could not retrieve manifest '{manifest_name}' from any available peers")
        return None

    

    def download_file(self, peer_address, filename, expected_hash=None, progress_callback=None,add_to_shared=True):
        """Download a file from another peer with integrity verification."""
        dest_path = os.path.join(self.download_dir, filename)
        try:
            if '_' in peer_address:
                host, port = peer_address.split('_')
            else:
                host, port = peer_address.split('.')
            url = f"http://{host}:{port}/{filename}"
            headers = {'Authorization': f'Bearer {self.auth_token}'}
        


            logger.info(f"Downloading {filename} from {peer_address}")
            response = requests.get(url, stream=True, timeout=10, headers=headers)
            print(f"response: {response}")
            if response.status_code == 200:
                # peer_dir = os.path.join(self.download_dir, peer_address.replace(':', '_'))
                # os.makedirs(peer_dir, exist_ok=True)
                # dest_path = os.path.join(peer_dir, filename)
                total_size = int(response.headers.get('content-length', 0))
                downloaded = 0
                sha256 = hashlib.sha256()  # Initialize hash object
                
                with open(dest_path, 'wb') as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        if chunk:
                            f.write(chunk)
                            sha256.update(chunk)  # Update hash with each chunk
                            downloaded += len(chunk)
                            if progress_callback and total_size > 0:
                                progress = min(int((downloaded / total_size) * 100), 100)
                                progress_callback(progress)
                
                # Verify hash if expected_hash is provided
                if expected_hash:
                    computed_hash = sha256.hexdigest()
                    if computed_hash != expected_hash:
                        logger.error(f"Hash mismatch for {filename}. Expected {expected_hash}, got {computed_hash}")
                        os.remove(dest_path)  # Remove corrupted file
                        return False
                    
                logger.info(f"Download complete: {filename}")

                # Save directly to shared directory
                if add_to_shared:
                    share_path = os.path.join(self.shared_dir, filename)
                    shutil.copy(dest_path, share_path)

                return True
                
            elif response.status_code in (401, 403):
                logger.error("Authentication failure during file download")
                st.session_state.authenticated = False
                st.session_state.token = None
                st.session_state.auth_error = "Your session has expired. Please log in again."
                return False
            else:
                logger.error(f"Download failed: HTTP {response.status_code}")
                return False
            
        except Exception as e:
            logger.error(f"Download error: {str(e)}")
            if os.path.exists(dest_path):
                os.remove(dest_path)  # Cleanup on error
            return False


    def _decrypt_data(self, encrypted_data, iv, expected_hash):
        """Decrypt data and verify against original hash."""
        try:
            # Initialize cipher
            cipher = Cipher(
                algorithms.AES(self.SYMMETRIC_KEY),
                modes.CBC(iv),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            
            # Decrypt and unpad
            padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
            unpadder = padding.PKCS7(128).unpadder()
            decrypted_data = unpadder.update(padded_data) + unpadder.finalize()
            
            # Verify integrity
            computed_hash = hashlib.sha256(decrypted_data).digest()
            if computed_hash != expected_hash:
                raise SecurityError("File integrity check failed. File may be tampered.")
                
            return decrypted_data
        except ValueError as ve:
            raise SecurityError(f"Decryption failed: {str(ve)}")

    def upload_file(self, uploaded_file, allowed_users=None):
        """Handle file encryption, chunking, and manifest creation."""
        if allowed_users is None:
            allowed_users = []
        try:
            # Read the entire file into memory
            file_data = uploaded_file.getvalue()
            
            # Encrypt the file data
            encrypted_data, iv, original_hash = self._encrypt_data(file_data)
            
            # Split encrypted data into chunks
            chunks = []
            for i in range(0, len(encrypted_data), CHUNK_SIZE):
                chunk = encrypted_data[i:i+CHUNK_SIZE]
                chunks.append(chunk)
            
            # Create manifest with encryption metadata
            manifest = {
                "original_filename": uploaded_file.name,
                "total_chunks": len(chunks),
                "allowed_users": [self.username] + allowed_users,
                "owner": self.username,
                "iv": iv.hex(),  # Store IV as hexadecimal string
                "original_hash": original_hash.hex(),  # SHA-256 of original file
                "chunks": [],
                "encrypted_size": len(encrypted_data),
            }
            
            # Write encrypted chunks and populate manifest
            for i, chunk in enumerate(chunks):
                chunk_name = f"{uploaded_file.name}.part{i+1:04}"
                chunk_path = os.path.join(self.shared_dir, chunk_name)
                
                # Write encrypted chunk
                with open(chunk_path, 'wb') as cf:
                    cf.write(chunk)
                
                # Calculate hash of encrypted chunk
                chunk_hash = hashlib.sha256(chunk).hexdigest()
                manifest['chunks'].append({
                    "chunk_name": chunk_name,
                    "sha256": chunk_hash
                })
            
            # Write manifest file
            manifest_path = os.path.join(self.shared_dir, f"{uploaded_file.name}.manifest")
            with open(manifest_path, 'w') as mf:
                json.dump(manifest, mf)
            
            # Update rendezvous server
            self.register_with_rendezvous()
            
            return True, f"File shared successfully: {uploaded_file.name}"
        
        except Exception as e:
            logger.error(f"Upload error: {str(e)}")
            return False, f"Failed to upload file: {str(e)}"


    
    def _encrypt_data(self, data):
        """Encrypt data using AES-256-CBC with PKCS7 padding.
        
        Returns:
            tuple: (encrypted_bytes, iv, original_hash)
        """
        # Generate random initialization vector
        iv = os.urandom(16)
            
        # Create cipher object
        cipher = Cipher(
            algorithms.AES(self.SYMMETRIC_KEY),
            modes.CBC(iv),
            backend=default_backend()
            )
            
        # Pad data to AES block size (128 bits)
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()
            
        # Encrypt data
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
            
         # Calculate hash of original data
        original_hash = hashlib.sha256(data).digest()
            
        return encrypted_data, iv, original_hash

    def shutdown(self):
        """Shutdown the peer node."""
        logger.info(f"Shutting down peer node: {self.peer_id}")
        self.running = False
        
        if self.server:
            self.server.shutdown()
            logger.info("HTTP server stopped")
        
        if self.observer:
            self.observer.stop()
            self.observer.join()
            logger.info("File watcher stopped")
        
        logger.info(f"Peer node shutdown complete")

# Session Verification Functions
def verify_session_token(token):
    """
    Verify if a session token is valid by checking with the rendezvous server.
    
    Args:
        token: The session token to verify
        
    Returns:
        tuple: (is_valid, username)
    """
    try:
        headers = {"Authorization": f"Bearer {token}"}
        response = requests.get(
            f"{RENDEZVOUS_SERVER}/session/verify",
            headers=headers,
            timeout=3
        )
        
        if response.status_code == 200:
            data = response.json()
            if data.get('valid'):
                return True, data.get('username')
        
        return False, None
        
    except Exception as e:
        logger.error(f"Error verifying session: {str(e)}")
        return False, None

def register_user(username, password):
    """
    Register a new user.
    
    Args:
        username: Username to register
        password: Password for the user
        
    Returns:
        tuple: (success, message)
    """
    try:
        response = requests.post(
            f"{RENDEZVOUS_SERVER}/user/register",
            json={
                'username': username,
                'password': password
            },
            timeout=5
        )
        
        data = response.json()
        
        if response.status_code == 200:
            logger.info(f"User '{username}' registered successfully")
            return True, data.get('message', 'Registration successful')
        else:
            logger.warning(f"Failed to register user '{username}': {data.get('message')}")
            return False, data.get('message', 'Registration failed')
        
    except Exception as e:
        logger.error(f"Error during registration: {str(e)}")
        return False, f"Registration error: {str(e)}"

def login_user(username, password):
    """
    Authenticate a user.
    
    Args:
        username: Username to authenticate
        password: Password to verify
        
    Returns:
        tuple: (success, message, token)
    """
    try:
        response = requests.post(
            f"{RENDEZVOUS_SERVER}/user/login",
            json={
                'username': username,
                'password': password
            },
            timeout=5
        )
        
        data = response.json()
        
        if response.status_code == 200:
            logger.info(f"User '{username}' logged in successfully")
            return True, data.get('message', 'Login successful'), data.get('token')
        else:
            logger.warning(f"Login failed for user '{username}': {data.get('message')}")
            return False, data.get('message', 'Login failed'), None
        
    except Exception as e:
        logger.error(f"Error during login: {str(e)}")
        return False, f"Login error: {str(e)}", None

# Modified encryption/decryption functions with static key (INSECURE!)
def encrypt_credentials(username, password):
    """INSECURE! Encrypt credentials using fixed key"""
    # Fixed encryption parameters (INSECURE!)
    key = b'supersecretkey123456789012345678'  # Same as PeerNode key
    iv = os.urandom(16)
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    data = json.dumps({'username': username, 'password': password}).encode()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()

    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return json.dumps({
        'iv': iv.hex(),
        'ciphertext': ciphertext.hex()
    }).encode()

def decrypt_credentials(file_data):
    """INSECURE! Decrypt credentials using fixed key"""
    try:
        encrypted_file = json.loads(file_data.decode())
        iv = bytes.fromhex(encrypted_file['iv'])
        ciphertext = bytes.fromhex(encrypted_file['ciphertext'])
        
        # Use fixed key (INSECURE!)
        key = b'supersecretkey123456789012345678'
        
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        
        unpadder = padding.PKCS7(128).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()
        
        credentials = json.loads(data.decode())
        return credentials['username'], credentials['password']
    except Exception as e:
        raise SecurityError(f"Decryption failed: {str(e)}")
        
def logout_user(token):
    """
    Log out a user by invalidating their session.
    
    Args:
        token: Session token to invalidate
        
    Returns:
        tuple: (success, message)
    """
    if not token:
        return False, "No active session"
    
    try:
        headers = {"Authorization": f"Bearer {token}"}
        response = requests.post(
            f"{RENDEZVOUS_SERVER}/user/logout",
            headers=headers,
            timeout=5
        )
        
        data = response.json()
        
        if response.status_code == 200:
            logger.info("User logged out successfully")
            return True, data.get('message', 'Logout successful')
        else:
            logger.warning(f"Logout failed: {data.get('message')}")
            return False, data.get('message', 'Logout failed')
        
    except Exception as e:
        logger.error(f"Error during logout: {str(e)}")
        return False, f"Logout error: {str(e)}"
    
    
# Streamlit UI
st.set_page_config(
    page_title="CipherShare", 
    page_icon="🔐", 
    layout="wide",
    initial_sidebar_state="expanded"
)
st.title("🔐 CipherShare - Secure P2P File Sharing")

# Initialize session state
if 'authenticated' not in st.session_state:
    st.session_state.authenticated = False

if 'username' not in st.session_state:
    st.session_state.username = None
    
if 'token' not in st.session_state:
    st.session_state.token = None
    
if 'auth_error' not in st.session_state:
    st.session_state.auth_error = None

if 'prompt_download' not in st.session_state:
    st.session_state.prompt_download = False

if 'encrypted_credentials' not in st.session_state:
    st.session_state.encrypted_credentials = None

# Check for session expiry or other auth errors
if st.session_state.auth_error and st.session_state.authenticated:
    st.error(st.session_state.auth_error)
    st.session_state.authenticated = False
    st.session_state.token = None
    st.session_state.username = None
    st.session_state.auth_error = None
    
    if 'peer' in st.session_state:
        peer = st.session_state.peer
        peer.shutdown()
        del st.session_state.peer
    
    time.sleep(2)
    st.rerun()

# Verify existing session token if present
if st.session_state.token and not st.session_state.authenticated:
    is_valid, username = verify_session_token(st.session_state.token)
    if is_valid and username:
        st.session_state.authenticated = True
        st.session_state.username = username
        logger.info(f"Revalidated session for user '{username}'")
    else:
        st.session_state.token = None
        st.session_state.username = None
        logger.warning("Session token validation failed")

# Authentication UI
if not st.session_state.authenticated:
    st.markdown("### 👤 Authentication")
    success = False
    token = None
    tab1, tab2 = st.tabs(["Login", "Register"])
    
    with tab1:
        login_tab, file_login_tab = st.tabs(["Manual Login", "File Login"])
        
        with login_tab:
            with st.form("login_form"):
                username = st.text_input("Username")
                password = st.text_input("Password", type="password")
                submit_login = st.form_submit_button("Login")
                
                if submit_login:
                    if not username or not password:
                        st.error("Please enter both username and password")
                        logger.warning("Login attempt with empty fields")
                    else:
                        success, message,token = login_user(username, password)
                        if success and token:
                            st.session_state.authenticated = True
                            st.session_state.username = username
                            st.session_state.token = token
                            st.success(message)
                            # Generate encrypted credentials file
                            encrypted_data = encrypt_credentials(username, password) 
                            st.session_state.encrypted_credentials = encrypted_data
                            st.session_state.prompt_download = True
                            logger.info(f"User '{username}' logged in successfully")
                            time.sleep(1)
                            st.rerun()
                        else:
                            st.error(message)
                            logger.warning(f"Login failed for user '{username}': {message}")
        with file_login_tab:
            with st.form("file_login_form"):
                creds_file = st.file_uploader("Upload credentials file", type=["csf"])
                submit_file_login = st.form_submit_button("Login with File")
                
                if submit_file_login:
                    if not creds_file:
                        st.error("Please provide a credentials file")
                    else:
                        try:
                            file_data = creds_file.getvalue()
                            username, password = decrypt_credentials(file_data)
                            success, message, token = login_user(username, password)
                            if success and token:
                                st.session_state.authenticated = True
                                st.session_state.username = username
                                st.session_state.token = token
                                st.success("Logged in successfully!")
                                time.sleep(1)
                                st.rerun()
                            else:
                                st.error("Invalid credentials in file")
                        except SecurityError as se:
                            st.error(str(se))
                        except Exception as e:
                            st.error(f"Invalid credentials file: {str(e)}")
        # After successful manual login:
    
    with tab2:
        with st.form("register_form"):
            new_username = st.text_input("Choose a Username")
            new_password = st.text_input("Choose a Password", type="password")
            confirm_password = st.text_input("Confirm Password", type="password")
            submit_register = st.form_submit_button("Register")
            
            if submit_register:
                if not new_username or not new_password or not confirm_password:
                    st.error("Please fill in all fields")
                    logger.warning("Registration attempt with empty fields")
                elif new_password != confirm_password:
                    st.error("Passwords don't match")
                    logger.warning(f"Registration passwords don't match for username '{new_username}'")
                elif len(new_password) < PASSWORD_MIN_LENGTH:
                    st.error(f"Password must be at least {PASSWORD_MIN_LENGTH} characters long")
                    logger.warning(f"Registration password too short for username '{new_username}'")
                else:
                    success, message = register_user(new_username, new_password)
                    if success:
                        st.success(message)
                        logger.info(f"User '{new_username}' registered successfully")
                        time.sleep(1)
                        st.rerun()
                    else:
                        st.error(message)
                        logger.warning(f"Registration failed for '{new_username}': {message}")

# Main Application UI (only shown to authenticated users)
elif st.session_state.authenticated:
    
    st.sidebar.markdown(f"### 👤 Logged in as: **{st.session_state.username}**")
    
    if st.sidebar.button("Logout"):
        logger.info(f"User '{st.session_state.username}' logging out")
        
        # Shutdown peer node if active
        if 'peer' in st.session_state:
            peer = st.session_state.peer
            peer.shutdown()
            del st.session_state.peer
            logger.info("Peer node shut down during logout")
        
        # Logout from server
        success, message = logout_user(st.session_state.token)
        if success:
            st.success(message)
            logger.info("Logout successful")
        else:
            st.error(message)
            logger.warning(f"Logout failed: {message}")
        
        # Clear session state
        st.session_state.authenticated = False
        st.session_state.username = None
        st.session_state.token = None
        
        time.sleep(1)
        st.rerun()
    
    # Node initialization        
    if 'peer' not in st.session_state:
        # Display logged in user in sidebar
        # print all session state variable

        if st.session_state.get('prompt_download'):
            st.markdown("---")
            st.info("### 🔒 Credentials Backup")
            st.write("Download your encrypted credentials file for easy future logins:")
            
            st.download_button(
                label="Download Credentials File",
                data=st.session_state.encrypted_credentials,
                file_name=f"{st.session_state.username}_ciphershare_credentials.csf",
                mime="application/octet-stream",
                key="credentials_download"
            )
            
            if st.button("Dismiss", key="dismiss_download"):
                del st.session_state.prompt_download
                del st.session_state.encrypted_credentials
                st.rerun()
            
            st.markdown("---")
        st.subheader("Initialize Your Node")
        
        host = socket.gethostbyname(socket.gethostname())
        port = st.number_input("Node Port", min_value=1024, max_value=65535, value=8000)
        
        if st.button("🚀 Start Node"):
            try:
                logger.info(f"Starting peer node for user '{st.session_state.username}' on {host}:{port}")
                st.session_state.peer = PeerNode(host, port, st.session_state.username, st.session_state.token)
                st.success(f"Node started at {host}:{port}")
                logger.info(f"Node started successfully at {host}:{port}")
                time.sleep(1)
                st.rerun()
            except Exception as e:
                st.error(f"Failed to start node: {str(e)}")
                logger.error(f"Failed to start node: {str(e)}")
                
# ==============================================================================================================================
    # App is running here...
# ==============================================================================================================================
    # Main application (when node is running)
    if 'peer' in st.session_state:
        peer = st.session_state.peer
        usernames = peer.fetch_all_usernames()

        # Get shared files
        shared_manifests = peer.get_shared_files()
        peers = peer.get_peers()
        shared_files = []
        
        for manifest in shared_manifests:
            try:
                with open(os.path.join(peer.shared_dir, manifest), 'r') as f:
                    data = json.load(f)
                    shared_files.append({
                        'original': data['original_filename'],
                        'manifest': manifest,
                        'chunks': [chunk['chunk_name'] for chunk in data['chunks']]
                    })
            except Exception as e:
                logger.error(f"Error reading manifest {manifest}: {str(e)}")
        
        # File upload section in sidebar
        with st.sidebar:
            st.subheader("📤 Upload & Share Files")
            uploaded_file = st.file_uploader("Select file to share", type=None)
            usernames_without_self = [u for u in usernames if u != peer.username]
            if uploaded_file:
                # Fetch other users
                selected_users = st.multiselect(
                    "Share with users", 
                    usernames_without_self, 
                    key=f"share_users_{uploaded_file.name}"
                )
    
                temp_path = os.path.join(peer.shared_dir, uploaded_file.name)
                col1, col2 = st.columns([2,1])
                with col1:
                    st.markdown(f"**{uploaded_file.name}**")
                with col2:
                    if not any(f['original'] == uploaded_file.name for f in shared_files):
                        if st.button(f"Share ➡️", key=f"share_{uploaded_file.name}"):
                            logger.info(f"Sharing file: {uploaded_file.name}")
                            
                            # Call the new upload_file method
                            success, message = peer.upload_file(uploaded_file,selected_users)
                            
                            if success:
                                st.success(message)
                                logger.info(f"File shared successfully: {uploaded_file.name}")
                                time.sleep(1)
                                st.rerun()
                            else:
                                st.error(message)
                                logger.error(f"Error sharing file: {message}")
                    else:
                        st.success("Already shared")
                        logger.debug(f"File '{uploaded_file.name}' already shared")


        st.markdown("---")

        with st.container():
            st.subheader("✅ Currently Sharing")
            
            if not shared_files:
                st.info("No files being shared")
            else:
                for file_info in shared_files:
                    cols = st.columns([4,1])
                    with cols[0]:
                        st.markdown(f"**{shared_files.index(file_info) + 1}. {file_info['original']}** ")
                        with st.expander(f"Details for {file_info['original']}"):
                            st.markdown(f"""
                            **{file_info['original']}**  
                            Chunks: {len(file_info['chunks'])}  
                            **Encryption Details: -**  
                            - **Algorithm:** AES-256-CBC  
                            - **Key Length:** 256 bits  
                            - **IV Length:** 128 bits  
                            """)
                    with cols[1]:
                        if st.button(f"❌ Stop", key=f"unshare_{file_info['original']}"):
                            try:
                                logger.info(f"Stopping sharing of file: {file_info['original']}")
                                
                                # Delete manifest
                                manifest_path = os.path.join(peer.shared_dir, file_info['manifest'])
                                if os.path.exists(manifest_path):
                                    os.remove(manifest_path)
                                # Delete chunks    
                                for chunk in file_info['chunks']:
                                    chunk_path = os.path.join(peer.shared_dir, chunk)
                                    if os.path.exists(chunk_path):
                                        os.remove(chunk_path)
                                        
                                st.success(f"Stopped sharing: {file_info['original']}")
                                logger.info(f"Stopped sharing file: {file_info['original']}")
                                time.sleep(1)
                                st.rerun()
                            except Exception as e:
                                st.error(f"Error stopping sharing: {str(e)}")
                                logger.error(f"Error stopping sharing of {file_info['original']}: {str(e)}")

        st.markdown("---")
        
        with st.container():
            st.subheader("🌐 Network Files")
            
            unique_manifests = {}
            for peer_id, peer_data in peers.items():
                # if peer_id == peer.peer_id:
                #     continue
                manifest_files = [f for f in peer_data.get('files', []) if f.endswith('.manifest')]
                for manifest in manifest_files:
                    if manifest not in unique_manifests:
                        unique_manifests[manifest] = []
                    unique_manifests[manifest].append({
                        "peer_id": peer_id,
                        "username": peer_data.get('username', 'Unknown')
                    })



            if not peers:
                st.info("No peers found")
            else:
                for manifest_file, file_sharers in unique_manifests.items():
                    peers_with_file = peer.get_peers_with_file(manifest_file)
                    #st.write(f"peers_with_file: {peers_with_file}")
                    manifest_metadata = peer.get_manifest_metadata(manifest_file)
                    if not manifest_metadata:
                        st.error(f"Failed to retrieve metadata for {manifest_file}")
                        continue

                    allowed_users = manifest_metadata.get('allowed_users', [])
                    owner = manifest_metadata.get('owner', 'Unknown')
                    total_chunks = manifest_metadata.get('total_chunks', 0)

                    original_name = manifest_file[:-9]  # Remove ".manifest" suffix
                    file_exists = False
                    if peer.peer_id in peers_with_file:
                            file_exists = True
                    with st.expander(f"**📁 {original_name} ({len(file_sharers)} sharers)**"):

                            # file sharers usernames
                            sharers_usernames = [sharer['username'] for sharer in file_sharers]
                            peer_ids = [sharer['peer_id'] for sharer in file_sharers]

                            cols = st.columns([1,1])
                            with cols[0]:
                                st.markdown("**File Sharers:**")
                                for idx, (peer_id, username) in enumerate(zip(peer_ids, sharers_usernames)):
                                    if peer_id == peer.peer_id:
                                        if username ==owner:
                                            st.markdown(f"{idx+1}. {username} ({peer_id}) **[You]** (Owner)")
                                        else:
                                            st.markdown(f"{idx+1}. {username} ({peer_id}) **[You]**")
                                    else:
                                        if username == owner:
                                            st.markdown(f"{idx+1}. {username} ({peer_id}) **[Owner]**")
                                        else:
                                            st.markdown(f"{idx+1}. {username} ({peer_id})")
                            
                            with cols[1]:
                                if peer.username not in allowed_users:
                                    st.error("❌ You are not allowed to download this file") 
                                elif file_exists:
                                    st.success("You are already a sharer")
                                else:
                                    if st.button("⬇️ Download", key=f"dl_{peer_id}_{original_name}"):
                                        dl_status = st.empty()
                                        progress_bar = st.progress(0)
                                        status_container = st.empty()
                                        
                                        try:
                                            dl_status.markdown("📥 Downloading manifest...")
                                            manifest_downloaded = peer.download_file(
                                                peer_ids[0], manifest_file)

                                            if not manifest_downloaded:
                                                st.error("Manifest download failed")
                                                continue

                                            manifest_path = os.path.join(
                                                peer.download_dir,
                                                # peer_data['address'].replace(':', '_'),
                                                manifest_file
                                            )
                                            with open(manifest_path, 'r') as f:
                                                manifest = json.load(f)
                                            
                                            total_chunks = len(manifest['chunks'])
                                            downloaded_chunks = 0
                                            all_success = True
                                            
                                            dl_status.markdown(f"📡 Downloading {total_chunks} chunks...")


                                            for idx, chunk in enumerate(manifest['chunks']):

                                                status_container.markdown(f"Chunk {idx+1}/{total_chunks}")
                                                status_placeholder = st.empty()

                                                def update_progress(p):
                                                    overall = int(((downloaded_chunks + (p/100)) / total_chunks) * 100)
                                                    progress_bar.progress(overall)
                                                    with st.spinner(f"Downloading chunk {idx+1} ({p}%)..."):
                                                        pass

                                                # Select a random peer with this chunk
                                                selected_peer = random.choice(file_sharers)
                                                # st.write(f"peerid: {selected_peer['peer_id']}")
                                                # delay
                                                # time.sleep(2)
                                                # Download the chunk
                                                with st.spinner(f"Downloading from {selected_peer['username']}..."):
                                                    success = peer.download_file(
                                                        selected_peer['peer_id'],
                                                        chunk['chunk_name'],
                                                        expected_hash=chunk['sha256'],
                                                        progress_callback=update_progress
                                                    )
                                                    time.sleep(1)


                                                # Verify checksum again for UI display
                                                chunk_path = os.path.join(
                                                    peer.download_dir,
                                                    # peer_data['address'].replace(':', '_'),
                                                    chunk['chunk_name']
                                                )
                                                with open(chunk_path, 'rb') as cf:
                                                    data = cf.read()
                                                    computed_hash = hashlib.sha256(data).hexdigest()

                                                # Update chunk verification status
                                                col1_placeholder = st.empty()
                                                col2_placeholder = st.empty()
                                                with col1_placeholder.container():
                                                    st.markdown("**Expected Checksum:**")
                                                    st.code(chunk['sha256'][:64])
                                                with col2_placeholder.container():
                                                    st.markdown("**Computed Checksum:**")
                                                    if computed_hash == chunk['sha256']:
                                                        st.code(computed_hash[:64])
                                                        st.success("✅ Hashes match!")
                                                    else:
                                                        st.error("❌ Hashes mismatch!")
                                                        st.code(computed_hash[:64])
                                                time.sleep(0.5)  # Small delay before processing the next chunk
                                                # Clear the previous status before processing the next chunk
                                                col1_placeholder.empty()
                                                col2_placeholder.empty()

                                                if computed_hash != chunk['sha256']:
                                                    all_success = False
                                                    os.remove(chunk_path)
                                                    status_placeholder.error("❌ Verification failed")
                                                    break
                                                else:
                                                    status_placeholder.success("✅ Verified")
                                                    downloaded_chunks += 1
                                                    progress_bar.progress(int((downloaded_chunks / total_chunks) * 100))
                                                status_placeholder.empty()

                                            if all_success:
                                                dl_status.markdown("🔧 Reassembling file...")
                                                output_path = os.path.join(
                                                    peer.download_dir,
                                                    # peer_data['address'].replace(':', '_'),
                                                    manifest['original_filename']
                                                )
                                                
                                                # Sort chunks numerically by their part number
                                                sorted_chunks = sorted(manifest['chunks'], 
                                                                    key=lambda x: int(x['chunk_name'].split('.part')[-1]))

                                                # First write encrypted chunks to temporary file
                                                temp_path = output_path + ".encrypted"
                                                with open(temp_path, 'wb') as out_file:
                                                    for chunk_info in sorted_chunks:
                                                        chunk_path = os.path.join(
                                                            peer.download_dir,
                                                            # peer_data['address'].replace(':', '_'),
                                                            chunk_info['chunk_name']
                                                        )
                                                        # Save a copy of the encrypted chunk to shared_dir
                                                        shared_chunk_path = os.path.join(peer.shared_dir, chunk_info['chunk_name'])
                                                        shutil.copy(chunk_path, shared_chunk_path)

                                                        with open(chunk_path, 'rb') as cf:
                                                            out_file.write(cf.read())

                                                        os.remove(chunk_path)

                                                # Save the manifest file to the shared directory
                                                shared_manifest_path = os.path.join(peer.shared_dir, manifest_file)
                                                shutil.copy(manifest_path, shared_manifest_path)

                                                # Now decrypt the temporary file
                                                try:
                                                    with open(temp_path, 'rb') as f:
                                                        encrypted_data = f.read()
                                                    
                                                    # Get IV and hash from manifest
                                                    iv = bytes.fromhex(manifest['iv'])  # IV stored as hex string
                                                    expected_hash = bytes.fromhex(manifest['original_hash'])  # Hash stored as hex string

                                                    # Decrypt the data
                                                    decrypted_data = peer._decrypt_data(encrypted_data, iv, expected_hash)

                                                    # Write decrypted data to final output
                                                    with open(output_path, 'wb') as f:
                                                        f.write(decrypted_data)

                                                    # Remove temporary encrypted file
                                                    os.remove(temp_path)

                                                    # Display success messages
                                                    dl_status.markdown(f"""
                                                    ### ✅ Download Complete!
                                                    **File integrity verified**  
                                                    Final SHA-256 checksum:  
                                                    `{manifest['original_hash']}`  
                                                    Saved to: `{output_path}`
                                                    """)
                                                    
                                                    # Display download summary
                                                    st.markdown("### 📊 Download Summary")
                                                    st.markdown(f"""
                                                    - **Total chunks:** {total_chunks}
                                                    - **Chunk size:** {CHUNK_SIZE // 1024} KB
                                                    - **Verified chunks:** {total_chunks}/{total_chunks}
                                                    - **Final file size:** {os.path.getsize(output_path) // 1024} KB
                                                    - **Final SHA-256:** `{manifest['original_hash']}`
                                                    """)


                                                    os.remove(manifest_path)
                                                    progress_bar.progress(100)
                                                    logger.info(f"File download complete: {original_name}")
                                                    peer.register_with_rendezvous()                
                                                    time.sleep(3)
                                                    st.rerun()

                                                except Exception as e:
                                                    progress_bar.empty()
                                                    dl_status.markdown(f"⚠️ Error: {str(e)}")
                                                    # Clean up temporary files if decryption failed
                                                    if os.path.exists(temp_path):
                                                        os.remove(temp_path)
                                                    if os.path.exists(output_path):
                                                        os.remove(output_path)
                                        except Exception as e:
                                            progress_bar.empty()
                                            dl_status.markdown(f"⚠️ Error: {str(e)}")
            if st.button("Rendezvous Discovery!", key="refresh_network_files", help="Click to refresh network files"):
                st.rerun()

        st.markdown("---")

        # Downloaded files section
        with st.container():
            st.subheader("📥 Downloaded Files")
            downloaded_files = []
            # get usernames except for the current peer usernmae
            for file in os.listdir(peer.download_dir):
                    if not (file.endswith('.manifest') or file.endswith('.part')):
                        downloaded_files.append(file)
            
            if not downloaded_files:
                st.info("No downloads yet")
            else:
                sources = [username for username in sharers_usernames if username != peer.username]

                # In the downloaded files section (around line 1512):
                for file in downloaded_files:
                    file_path = os.path.join(peer.download_dir, file)
                    with st.container():
                        cols = st.columns([3, 1.5, 1])
                        with cols[0]:
                            st.subheader(file)
                            st.caption(f"Source: {', '.join(sources)}")
                            
                            # Calculate file checksum on hover
                            with st.expander("Verify Integrity Now"):
                                if os.path.exists(file_path):
                                    with st.spinner("Calculating checksum..."):
                                        file_hash = hashlib.sha256()
                                        file_size = os.path.getsize(file_path)
                                        last_modified = datetime.fromtimestamp(os.path.getmtime(file_path))
                                        with open(file_path, 'rb') as f:
                                            while chunk := f.read(8192):
                                                file_hash.update(chunk)
                                        st.markdown(f"""
                                        **File Details:**  
                                        - **Name:** {file}  
                                        - **Source:** {', '.join(sources)}  
                                        - **Size:** {file_size / 1024:.2f} KB  
                                        - **Last Modified:** {last_modified}  

                                        **Integrity Check:**  
                                        - **SHA-256 Checksum:**  
                                        `{file_hash.hexdigest()}`
                                        """)
                                else:
                                    st.warning("File not found")
                        
                        with cols[1]:
                            st.markdown("**Integrity Status**")
                            if os.path.exists(file_path):
                                st.success("✅ Verified (on download)")
                            else:
                                st.error("❌ File missing")
                        with cols[2]:
                            if st.button("Delete", key=f"delete_{file}"):
                                file_path = os.path.join(peer.download_dir, file)
                                if os.path.exists(file_path):
                                    os.remove(file_path)
                                    st.success(f"Deleted {file}")
                                    st.rerun()

        st.markdown("---")

        col1, col2, col3 = st.columns([2, 2, 1])
        with col2:
            if st.button("Stop Node", type="primary", key="stop_node"):
                peer.shutdown()
                del st.session_state.peer
                st.success("Node stopped successfully")
                time.sleep(1)
                st.rerun()