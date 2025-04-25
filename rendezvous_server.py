from flask import Flask, jsonify, request
from datetime import datetime, timedelta
import pymongo

app = Flask(__name__)
peers = {}
network_version = 0  # Global network version counter

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
    print("Connected to MongoDB successfully")
except Exception as e:
    print(f"MongoDB connection error: {e}")
    
    
@app.route('/register', methods=['POST'])
def register():
    global network_version
    data = request.json
    peers[data['peer_id']] = {
        'address': data['address'],
        'username': data.get('username', 'Unknown'),
        'last_seen': datetime.now(),
        'files': data.get('files', [])
    }
    network_version += 1
    return jsonify({'status': 'ok', 'version': network_version})

@app.route('/heartbeat', methods=['POST'])
def heartbeat():
    global network_version
    data = request.json
    if data['peer_id'] in peers:
        peers[data['peer_id']]['last_seen'] = datetime.now()
        peers[data['peer_id']]['files'] = data.get('files', [])
        if 'username' in data:
            peers[data['peer_id']]['username'] = data['username']
        network_version += 1
    return jsonify({'status': 'ok', 'version': network_version})

@app.route('/peers')
def list_peers():
    global network_version
    # Cleanup old peers
    for peer_id in list(peers.keys()):
        if (datetime.now() - peers[peer_id]['last_seen']) > timedelta(seconds=10):
            del peers[peer_id]
            network_version += 1
    return jsonify({'peers': peers, 'version': network_version})

@app.route('/version')
def get_version():
    return jsonify({'version': network_version})

@app.route('/user/check', methods=['POST'])
def check_user():
    """Check if a username already exists"""
    data = request.json
    username = data.get('username')
    
    if not username:
        return jsonify({'status': 'error', 'message': 'Username is required'}), 400
    
    user = users_collection.find_one({"username": username})
    if user:
        return jsonify({'exists': True})
    
    return jsonify({'exists': False})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001)