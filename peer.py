import streamlit as st
import os
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

class PeerNode:
    def __init__(self, host, port,username,auth_token):
        """
        Initialize a peer node.
        
        Args:
            host: Host address
            port: Port number
            username: Username associated with this peer
            auth_token: Authentication token for API requests
        """
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

    def get_shared_files(self):
        return [f for f in os.listdir(self.shared_dir) if f.endswith('.manifest')]

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

    def download_file(self, peer_address, filename, expected_hash=None, progress_callback=None):
        """Download a file from another peer with integrity verification."""
        try:
            host, port = peer_address.split(':')
            url = f"http://{host}:{port}/{filename}"
            headers = {'Authorization': f'Bearer {self.auth_token}'}
            
            logger.info(f"Downloading {filename} from {peer_address}")
            response = requests.get(url, stream=True, timeout=10, headers=headers)
            
            if response.status_code == 200:
                peer_dir = os.path.join(self.download_dir, peer_address.replace(':', '_'))
                os.makedirs(peer_dir, exist_ok=True)
                dest_path = os.path.join(peer_dir, filename)
                
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

    def upload_file(self, uploaded_file):
        """Handle file upload and chunking process.
        
        Args:
            uploaded_file: File object to upload
            
        Returns:
            tuple: (success, message)
        """
        try:
            temp_path = os.path.join(self.shared_dir, uploaded_file.name)
            
            # Save uploaded file temporarily
            with open(temp_path, 'wb') as f:
                f.write(uploaded_file.getbuffer())
            
            # Split file into chunks
            chunks = []
            with open(temp_path, 'rb') as f:
                while chunk := f.read(CHUNK_SIZE):
                    chunks.append(chunk)
            
            # Create manifest structure
            manifest = {
                "original_filename": uploaded_file.name,
                "total_chunks": len(chunks),
                "owner": self.username,
                "chunks": []
            }
            
            # Write chunks and populate manifest
            for i, chunk in enumerate(chunks):
                chunk_name = f"{uploaded_file.name}.part{i+1:04}"
                chunk_path = os.path.join(self.shared_dir, chunk_name)
                
                with open(chunk_path, 'wb') as cf:
                    cf.write(chunk)
                
                manifest['chunks'].append({
                    "chunk_name": chunk_name,
                    "sha256": hashlib.sha256(chunk).hexdigest()
                })
            
            # Write manifest file
            manifest_path = os.path.join(self.shared_dir, f"{uploaded_file.name}.manifest")
            with open(manifest_path, 'w') as mf:
                json.dump(manifest, mf)
            
            # Clean up temporary file
            os.remove(temp_path)
            
            # Update rendezvous server with new files
            self.register_with_rendezvous()
            
            return True, f"File shared successfully: {uploaded_file.name}"
            
        except Exception as e:
            logger.error(f"Error uploading file: {str(e)}")
            return False, f"Error sharing file: {str(e)}"

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
    
    tab1, tab2 = st.tabs(["Login", "Register"])
    
    with tab1:
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
                        logger.info(f"User '{username}' logged in successfully")
                        time.sleep(1)
                        st.rerun()
                    else:
                        st.error(message)
                        logger.warning(f"Login failed for user '{username}': {message}")
    
    
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
    # Display logged in user in sidebar
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

    # Main application (when node is running)
    if 'peer' in st.session_state:
        peer = st.session_state.peer
        
        # Get shared files
        shared_manifests = peer.get_shared_files()
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
            except:
                logger.error(f"Error reading manifest {manifest}: {str(e)}")
        
        # File upload section in sidebar
        with st.sidebar:
            st.subheader("📤 Upload & Share Files")
            uploaded_file = st.file_uploader("Select file to share", type=None)
            
            if uploaded_file:
                temp_path = os.path.join(peer.shared_dir, uploaded_file.name)
                col1, col2 = st.columns([2,1])
                with col1:
                    st.markdown(f"**{uploaded_file.name}**")
                with col2:
                    if not any(f['original'] == uploaded_file.name for f in shared_files):
                        if st.button(f"Share ➡️", key=f"share_{uploaded_file.name}"):
                            logger.info(f"Sharing file: {uploaded_file.name}")
                            
                            # Call the new upload_file method
                            success, message = peer.upload_file(uploaded_file)
                            
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
                        st.markdown(f"""
                        **{file_info['original']}**  
                        Chunks: {len(file_info['chunks'])}
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
            
            peers = peer.get_peers()
            
            if not peers:
                st.info("No peers found")
            else:
                for peer_id, peer_data in peers.items():
                    if peer_id == peer.peer_id:
                        continue
                    
                    with st.expander(f"👤 User: {peer_data.get('username', 'Unknown')} ({peer_id})"):
                        manifest_files = [f for f in peer_data.get('files', []) 
                                        if f.endswith('.manifest')]
                        if not manifest_files:
                            st.write("No files shared")
                            continue
                        
                        for manifest_file in manifest_files:
                            original_name = manifest_file[:-9]
                            cols = st.columns([1,1])
                            with cols[0]:
                                st.markdown(f"**{original_name}**")
                            with cols[1]:

                                if st.button("⬇️ Download", key=f"dl_{peer_id}_{original_name}"):
                                    dl_status = st.empty()
                                    progress_bar = st.progress(0)
                                    status_container = st.empty()
                                    
                                    try:
                                        dl_status.markdown("📥 Downloading manifest...")
                                        manifest_downloaded = peer.download_file(
                                            peer_data['address'], manifest_file)
                                        
                                        if not manifest_downloaded:
                                            st.error("Manifest download failed")
                                            continue

                                        manifest_path = os.path.join(
                                            peer.download_dir,
                                            peer_data['address'].replace(':', '_'),
                                            manifest_file
                                        )
                                        
                                        with open(manifest_path, 'r') as f:
                                            manifest = json.load(f)
                                        
                                        total_chunks = len(manifest['chunks'])
                                        downloaded_chunks = 0
                                        all_success = True
                                        
                                        dl_status.markdown(f"📡 Downloading {total_chunks} chunks...")
                                        
# Update the chunk processing loop with integrity visualization

                                        for idx, chunk in enumerate(manifest['chunks']):
                                            status_container.markdown(f"Chunk {idx+1}/{total_chunks}")
                                            status_placeholder = st.empty()
                                            def update_progress(p):
                                                overall = int(((downloaded_chunks + (p/100)) / total_chunks) * 100)
                                                progress_bar.progress(overall)
                                                with st.spinner(f"Downloading chunk {idx+1} ({p}%)..."):
                                                    pass

                                            # Download the chunk
                                            success = peer.download_file(
                                                peer_data['address'],
                                                chunk['chunk_name'],
                                                expected_hash=chunk['sha256'],
                                                progress_callback=update_progress
                                            )

                                            # Verify checksum again for UI display
                                            chunk_path = os.path.join(
                                                peer.download_dir,
                                                peer_data['address'].replace(':', '_'),
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
                                            time.sleep(0.2)  # Small delay before processing the next chunk
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
                                                peer_data['address'].replace(':', '_'),
                                                manifest['original_filename']
                                            )
                                            
                                            # Sort chunks numerically by their part number
                                            sorted_chunks = sorted(manifest['chunks'], 
                                                                key=lambda x: int(x['chunk_name'].split('.part')[-1]))
                                            
                                            with open(output_path, 'wb') as out_file:
                                                for chunk_info in sorted_chunks:
                                                    chunk_path = os.path.join(
                                                        peer.download_dir,
                                                        peer_data['address'].replace(':', '_'),
                                                        chunk_info['chunk_name']
                                                    )
                                                    with open(chunk_path, 'rb') as cf:
                                                        out_file.write(cf.read())
                                                    os.remove(chunk_path)

                                            # Calculate the final file checksum
                                            with open(output_path, 'rb') as f:
                                                file_hash = hashlib.sha256()
                                                while chunk := f.read(8192):
                                                    file_hash.update(chunk)
                                            file_checksum = file_hash.hexdigest()

                                            dl_status.markdown(f"""
                                            ### ✅ Download Complete!
                                            **File integrity verified**  
                                            Final SHA-256 checksum:  
                                            `{file_checksum}`  
                                            Saved to: `{output_path}`
                                            """)
                                            
                                            # Display download summary directly
                                            st.markdown("### 📊 Download Summary")
                                            st.markdown(f"""
                                            - **Total chunks:** {total_chunks}
                                            - **Chunk size:** {CHUNK_SIZE // 1024} KB
                                            - **Verified chunks:** {total_chunks}/{total_chunks}
                                            - **Final file size:** {os.path.getsize(output_path) // 1024} KB
                                            - **Final SHA-256:** `{file_checksum}`
                                            """)
                                                        
                                            os.remove(manifest_path)
                                            progress_bar.progress(100)
                                            dl_status.markdown(f"✅ Saved to: {output_path}")
                                            logger.info(f"File download complete: {original_name}")
                                            time.sleep(3)
                                            st.rerun()
                                        else:
                                            progress_bar.empty()
                                            dl_status.markdown("❌ Download failed")
                                    
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
            for peer_dir in os.listdir(peer.download_dir):
                peer_path = os.path.join(peer.download_dir, peer_dir)
                if os.path.isdir(peer_path):
                    for file in os.listdir(peer_path):
                        if not (file.endswith('.manifest') or file.endswith('.part')):
                            downloaded_files.append({
                                'name': file,
                                'source': peer_dir.replace('_', ':')
                            })
            
            if not downloaded_files:
                st.info("No downloads yet")
            else:
                # In the downloaded files section (around line 1512):
                for file in downloaded_files:
                    file_path = os.path.join(peer.download_dir, file['source'].replace(':', '_'), file['name'])
                    with st.container():
                        cols = st.columns([3, 1.5, 1])
                        with cols[0]:
                            st.subheader(file['name'])
                            st.caption(f"Source: {file['source']}")
                            
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
                                        - **Name:** {file['name']}  
                                        - **Source:** {file['source']}  
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
                            if st.button("Delete", key=f"delete_{file['name']}"):
                                file_path = os.path.join(peer.download_dir, file['source'].replace(':', '_'), file['name'])
                                if os.path.exists(file_path):
                                    os.remove(file_path)
                                    st.success(f"Deleted {file['name']}")
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