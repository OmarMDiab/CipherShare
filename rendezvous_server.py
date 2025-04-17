from flask import Flask, jsonify, request
from datetime import datetime, timedelta

app = Flask(__name__)
peers = {}
network_version = 0  # Global network version counter

@app.route('/register', methods=['POST'])
def register():
    global network_version
    data = request.json
    peers[data['peer_id']] = {
        'address': data['address'],
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

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001)