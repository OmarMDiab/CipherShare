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
import base64

# Configuration
RENDEZVOUS_SERVER = "http://localhost:5001"
PEERS_ROOT = "peers"
CHUNK_SIZE = 256 * 1024  # 256KB

# MongoDB Configuration
MONGO_URI = "mongodb://localhost:27017/"
DB_NAME = "ciphershare"

# Initialize MongoDB connection
try:
    mongo_client = pymongo.MongoClient(MONGO_URI)
    db = mongo_client[DB_NAME]
    users_collection = db["users"]
    # Create unique index on username
    users_collection.create_index([("username", pymongo.ASCENDING)], unique=True)
    st.session_state.db_connected = True
except Exception as e:
    st.session_state.db_connected = False
    print(f"MongoDB connection error: {e}")
    
class FileChangeHandler(FileSystemEventHandler):
    def __init__(self, callback):
        self.callback = callback
        
    def on_modified(self, event):
        self.callback()

class P2PRequestHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        self.peer_id = kwargs.pop('peer_id')
        self.auth_token = kwargs.pop('auth_token', None)
        super().__init__(*args, directory=os.path.join(PEERS_ROOT, self.peer_id, "shared"), **kwargs)
    
    def do_GET(self):
        # Check if request has valid auth token
        auth_header = self.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            self.send_response(401)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(b'Unauthorized: Authentication required')
            return
        
        token = auth_header.split(' ')[1]
        #  Check if there's any token provided
        if not token:
            self.send_response(403)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(b'Forbidden: Invalid token')
            return
            
        # Continue with the regular file handling
        super().do_GET()

class PeerNode:
    def __init__(self, host, port,username):
        self.peer_id = f"{host}_{port}"
        self.host = host
        self.port = port
        self.username = username
        self.auth_token = self.generate_auth_token()
        self.base_dir = os.path.join(PEERS_ROOT, self.peer_id)
        self.shared_dir = os.path.join(self.base_dir, "shared")
        self.download_dir = os.path.join(self.base_dir, "downloads")
        self.server = None
        self.observer = None
        self.running = True

        os.makedirs(self.shared_dir, exist_ok=True)
        os.makedirs(self.download_dir, exist_ok=True)
        
        self.start_server()
        self.register_with_rendezvous()
        self.start_file_watcher()
        threading.Thread(target=self.heartbeat, daemon=True).start()

    def generate_auth_token(self):
        """Generate a random auth token for this session"""
        return secrets.token_hex(16)
    
    def start_server(self):
        handler = lambda *args: P2PRequestHandler(*args, peer_id=self.peer_id)
        self.server = HTTPServer((self.host, self.port), handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def start_file_watcher(self):
        self.observer = Observer()
        event_handler = FileChangeHandler(self.on_file_change)
        self.observer.schedule(event_handler, self.shared_dir, recursive=False)
        self.observer.start()

    def on_file_change(self):
        self.register_with_rendezvous()

    def register_with_rendezvous(self):
        try:
            requests.post(f"{RENDEZVOUS_SERVER}/register",
                         json={'peer_id': self.peer_id,
                               'username': self.username,
                               'address': f"{self.host}:{self.port}",
                               'files': self.get_shared_files()})
        except:
            pass

    def heartbeat(self):
        while self.running:
            time.sleep(5)
            try:
                requests.post(f"{RENDEZVOUS_SERVER}/heartbeat",
                             json={'peer_id': self.peer_id,
                                   'username': self.username,
                                  'files': self.get_shared_files()})
            except:
                pass

    def get_shared_files(self):
        return [f for f in os.listdir(self.shared_dir) if f.endswith('.manifest')]

    def get_peers(self):
        try:
            response = requests.get(f"{RENDEZVOUS_SERVER}/peers", timeout=2)
            return response.json().get('peers', {})
        except:
            return {}

    def download_file(self, peer_address, filename, progress_callback=None):
        try:
            host, port = peer_address.split(':')
            url = f"http://{host}:{port}/{filename}"
            headers = {'Authorization': f'Bearer {self.auth_token}'}
            response = requests.get(url, stream=True, timeout=10, headers=headers)
            
            if response.status_code == 200:
                peer_dir = os.path.join(self.download_dir, peer_address.replace(':', '_'))
                os.makedirs(peer_dir, exist_ok=True)
                dest_path = os.path.join(peer_dir, filename)
                
                total_size = int(response.headers.get('content-length', 0))
                downloaded = 0
                
                with open(dest_path, 'wb') as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        if chunk:
                            f.write(chunk)
                            downloaded += len(chunk)
                            if progress_callback and total_size > 0:
                                progress = min(int((downloaded / total_size) * 100), 100)
                                progress_callback(progress)
                return True
        except Exception as e:
            print(f"Download error: {e}")
            return False

# Authentication Functions
def hash_password(password, salt=None):
    """
    Hash a password using SHA-256 (temporary, will upgrade to Argon2 later)
    Returns (hash, salt) tuple
    """
    if not salt:
        salt = secrets.token_hex(16)
    
    # Combine password and salt, then hash
    salted_password = password + salt
    hashed = hashlib.sha256(salted_password.encode()).hexdigest()
    
    return hashed, salt

def verify_password(password, stored_hash, salt):
    """Verify a password against a stored hash"""
    calculated_hash, _ = hash_password(password, salt)
    return calculated_hash == stored_hash

def register_user(username, password):
    """Register a new user with the given username and password"""
    if not st.session_state.db_connected:
        return False, "Database not connected"
    
    try:
        # Check if username already exists
        if users_collection.find_one({"username": username}):
            return False, "Username already exists"
        
        # Hash the password
        password_hash, salt = hash_password(password)
        
        # Create user record
        user = {
            "username": username,
            "password_hash": password_hash,
            "salt": salt,
            "created_at": time.time()
        }
        
        # Insert into database
        users_collection.insert_one(user)
        return True, "User registered successfully"
    except Exception as e:
        return False, f"Registration error: {str(e)}"

def login_user(username, password):
    """Authenticate a user with the given username and password"""
    if not st.session_state.db_connected:
        return False, "Database not connected"
    
    try:
        # Find user by username
        user = users_collection.find_one({"username": username})
        if not user:
            return False, "Invalid username or password"
        
        # Verify password
        if verify_password(password, user["password_hash"], user["salt"]):
            return True, "Login successful"
        else:
            return False, "Invalid username or password"
    except Exception as e:
        return False, f"Login error: {str(e)}"

# Initialize session state
if 'authenticated' not in st.session_state:
    st.session_state.authenticated = False

if 'username' not in st.session_state:
    st.session_state.username = None
    
    
# Streamlit UI
st.title("📁 Distributed P2P File Sharing")
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
                else:
                    success, message = login_user(username, password)
                    if success:
                        st.session_state.authenticated = True
                        st.session_state.username = username
                        st.success(message)
                        st.rerun()
                    else:
                        st.error(message)
    
    with tab2:
        with st.form("register_form"):
            new_username = st.text_input("Choose a Username")
            new_password = st.text_input("Choose a Password", type="password")
            confirm_password = st.text_input("Confirm Password", type="password")
            submit_register = st.form_submit_button("Register")
            
            if submit_register:
                if not new_username or not new_password or not confirm_password:
                    st.error("Please fill in all fields")
                elif new_password != confirm_password:
                    st.error("Passwords don't match")
                elif len(new_password) < 8:
                    st.error("Password must be at least 8 characters long")
                else:
                    success, message = register_user(new_username, new_password)
                    if success:
                        st.success(message)
                        time.sleep(1)
                        st.experimental_rerun()
                    else:
                        st.error(message)

# Main Application UI (only shown to authenticated users)
elif st.session_state.authenticated:
    st.sidebar.markdown(f"### 👤 Logged in as: **{st.session_state.username}**")
    
    if st.sidebar.button("Logout"):
        st.session_state.authenticated = False
        st.session_state.username = None
        if 'peer' in st.session_state:
            peer = st.session_state.peer
            peer.running = False
            peer.server.shutdown()
            if peer.observer:
                peer.observer.stop()
            del st.session_state.peer
        st.rerun()
            
    if 'peer' not in st.session_state:
        st.subheader("Initialize Your Node")
        host = socket.gethostbyname(socket.gethostname())
        port = st.number_input("Node Port", min_value=1024, max_value=65535, value=8000)
        if st.button("🚀 Start Node"):
            st.session_state.peer = PeerNode(host, port,st.session_state.username)
            st.success(f"Node started at {host}:{port}")
            time.sleep(1)
            st.rerun()

    if 'peer' in st.session_state:
        peer = st.session_state.peer
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
                pass

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
                            with open(temp_path, 'wb') as f:
                                f.write(uploaded_file.getbuffer())
                            
                            chunks = []
                            with open(temp_path, 'rb') as f:
                                while chunk := f.read(CHUNK_SIZE):
                                    chunks.append(chunk)
                            
                            manifest = {
                                "original_filename": uploaded_file.name,
                                "total_chunks": len(chunks),
                                "owner": st.session_state.username,
                                "chunks": []
                            }
                            
                            for i, chunk in enumerate(chunks):
                                chunk_name = f"{uploaded_file.name}.part{i+1:04}"
                                chunk_path = os.path.join(peer.shared_dir, chunk_name)
                                with open(chunk_path, 'wb') as cf:
                                    cf.write(chunk)
                                manifest['chunks'].append({
                                    "chunk_name": chunk_name,
                                    "sha256": hashlib.sha256(chunk).hexdigest()
                                })
                            
                            manifest_path = os.path.join(peer.shared_dir, f"{uploaded_file.name}.manifest")
                            with open(manifest_path, 'w') as mf:
                                json.dump(manifest, mf)
                            os.remove(temp_path)
                            st.rerun()
                    else:
                        st.success("Already shared")

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
                            manifest_path = os.path.join(peer.shared_dir, file_info['manifest'])
                            if os.path.exists(manifest_path):
                                os.remove(manifest_path)
                            for chunk in file_info['chunks']:
                                chunk_path = os.path.join(peer.shared_dir, chunk)
                                if os.path.exists(chunk_path):
                                    os.remove(chunk_path)
                            st.rerun()

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
                            cols = st.columns([2,1])
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
                                        
                                        for idx, chunk in enumerate(manifest['chunks']):
                                            status_container.markdown(f"Chunk {idx+1}/{total_chunks}")
                                            
                                            def update_progress(p):
                                                overall = int(((downloaded_chunks + (p/100)) / total_chunks) * 100)
                                                progress_bar.progress(overall)
                                            
                                            success = peer.download_file(
                                                peer_data['address'],
                                                chunk['chunk_name'],
                                                progress_callback=update_progress
                                            )
                                            
                                            if not success:
                                                all_success = False
                                                st.error(f"Failed chunk: {chunk['chunk_name']}")
                                                break
                                            
                                            chunk_path = os.path.join(
                                                peer.download_dir,
                                                peer_data['address'].replace(':', '_'),
                                                chunk['chunk_name']
                                            )
                                            with open(chunk_path, 'rb') as cf:
                                                data = cf.read()
                                                checksum = hashlib.sha256(data).hexdigest()
                                                if checksum != chunk['sha256']:
                                                    all_success = False
                                                    os.remove(chunk_path)
                                                    st.error(f"Checksum failed: {chunk['chunk_name']}")
                                                    break
                                            
                                            downloaded_chunks += 1
                                            progress_bar.progress(int((downloaded_chunks / total_chunks) * 100))
                                        
                                        if all_success:
                                            dl_status.markdown("🔧 Reassembling file...")
                                            output_path = os.path.join(
                                                peer.download_dir,
                                                peer_data['address'].replace(':', '_'),
                                                manifest['original_filename']
                                            )
                                            with open(output_path, 'wb') as out_file:
                                                for chunk in sorted(manifest['chunks'], 
                                                                key=lambda x: x['chunk_name']):
                                                    chunk_path = os.path.join(
                                                        peer.download_dir,
                                                        peer_data['address'].replace(':', '_'),
                                                        chunk['chunk_name']
                                                    )
                                                    with open(chunk_path, 'rb') as cf:
                                                        out_file.write(cf.read())
                                                    os.remove(chunk_path)
                                            
                                            os.remove(manifest_path)
                                            progress_bar.progress(100)
                                            dl_status.markdown(f"✅ Saved to: {output_path}")
                                            time.sleep(2)
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
                for file in downloaded_files:
                    with st.container():
                        cols = st.columns([3, 1])
                        with cols[0]:
                            st.subheader(file['name'])
                            st.caption(f"Source: {file['source']}")
                        with cols[1]:
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
                peer.running = False
                peer.server.shutdown()
                if peer.observer:
                    peer.observer.stop()
                del st.session_state.peer
                st.rerun()