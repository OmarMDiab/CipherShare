# Distributed Peer-to-Peer File Sharing Network

A decentralized file sharing system implementing efficient peer discovery and secure chunk-based file transfers.
![
Home Screen
](https://images\Home_Screen.pngimages\Home_Screen.png)

## Key Components

### Rendezvous Server (`rendezvous_server.py`)

- Centralized peer coordination service with REST API endpoints
- Peer registration/management system with last-seen timestamp
- Network version synchronization across nodes
- Automatic peer eviction (10-second inactivity threshold)
- Heartbeat mechanism for peer status updates
- JSON-based peer listing endpoint

### Peer Node (`peer.py`)

- Streamlit-based graphical interface for node management
- Automated file synchronization (Watchdog integration)
- File chunking system (256KB blocks with manifest metadata)
- SHA-256 checksum verification for data integrity
- Parallel HTTP transfer engine with progress tracking
- Persistent download management with source tracking
- Decentralized peer discovery via rendezvous server
- Node lifecycle management (start/stop controls)

## Technical Features

**Network Architecture**

- REST-based peer coordination
- Version-controlled network state
- Decentralized direct peer transfers
- Fault-tolerant heartbeat system

**Data Handling**

- Multi-chunk file segmentation
- JSON manifest files with chunk metadata
- Checksum validation pipeline
- Automatic file reassembly
- Cross-platform file management

**Operational Security**

- Host-based peer identification
- Transfer timeouts (10-second threshold)
- Encrypted checksum verification
- Session-based node isolation

## Getting Started

### Requirements

- Required packages: Flask, Streamlit, Requests, Watchdog

### Deployment

```bash
# Install dependencies
pip install flask streamlit requests watchdog

# Start rendezvous server (Port 5001)
python rendezvous_server.py

# In new terminal - Start Peer Node
streamlit run peer.py  # Peer 1

streamlit run peer.py  # Peer 2
```
