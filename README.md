# py-netmesh

A decentralized, peer-to-peer mesh network with end-to-end encrypted messaging and file transfer. Built entirely from scratch in Python.

![Demo](demo.gif)

---

## What is it?

py-netmesh is an application-layer mesh network that runs entirely without a central server or routing authority. Nodes discover each other autonomously using a gossip protocol, build routing tables using distance vector routing, and communicate over encrypted channels using RSA/AES encryption. Any node can send messages or files to any other node in the mesh, routed through intermediate nodes.

This project was built as an exercise in exploring mesh networking, cryptography, and custom file transfers from first principles.

---

## Features

- **Decentralized node discovery** via gossip protocol and UDP broadcast
- **Distance vector routing** -- nodes maintain and propagate routing tables, dynamically finding the shortest paths through the mesh
- **Hybrid RSA/AES encryption** -- RSA for key exchange and simple chat messages, hybrid RSA/AES-GCM for file payload encryption
- **PSS signature verification** on chat messages
- **Batch UDP file transfer** with acknowledgment, retransmit logic, and kernel-level buffer optimization
- **Node dropout detection** via health checks and death packet propagation
- **Duplicate alias handling** -- conflicts detected and resolved automatically
- **LAN broadcast mode**, **localhost mode**, and a **debug mode** that offers more feedback on certain operations
- **Multi-hop routing** -- messages and files route through intermediate nodes

---

## Design Decisions

### UDP over TCP
py-netmesh was conceptualized with anonymity & decentralization at the forefront, which made UDP the natural protocol choice. UDP's connectionless architecture allows a wide network of nodes to have minimal direct connection with each other, all the while propagating each other's existence through PROBE packets and gossip architecture. Nodes can only directly connect to their neighbors, meaning they are more or less reliant on neighborly connections to reach far away nodes. Such is the nature of py-netmesh's decentralized gossip system, in which I chose isolation and decentralization over convenience.

The UDP decision, however, is not without its downsides. File transfers run perfectly on localhost, but are incredibly inconsistent on WiFi and, when not failing, are markedly slower than their loopback counterpart. Partially responsible for this, I believe, is the sluggishness of my Kindle Fire's processor, which likely struggled under the weight of thousands of cryptographic operations. Some control flow in the form of time.sleep(0.0125) after each chunk seemed to stymie the bleeding, but LAN file transfers remain inconsistent.

### Hybrid Encryption 
File transfers use RSA/AES Hybrid encryption rather than pure RSA. This was due to RSA's size constraints, which even the conservative 8kb chunk size exceeds. A hybrid RSA/AES design was therefore necessary, where the AES key is sent encrypted with RSA, and used on all subsequent chunk payloads.

### File Transfers
File transfers, like everything else, use UDP. This was done because A: it is consistent with the above outlined architecture, and B: I wanted to explore building a custom file transfer protocol. File transfers use a custom batch processing system, where chunks per window are dynamically calculated based on receiving node's distance. This system has its limitations, such as a lack of retry mechanism and transfers being outright cancelled upon seq mismatch. More on limitations detailed below.

### Death Packets
Death packets that announce a node's absence were deemed necessary after realizing the shortcomings of periodic healthchecks. Given the linear topology of the network and nodes sharing each other's routing tables, dead nodes would not naturally decay in other nodes' routing tables beyond a certain point. Picture a network of nodes A, B, C, and D. For instance, if Node A drops out, Node B, its neighbor, would soon realize and update its routing table. However, if we have a Node C, that gets updates from both B and D, Node C's "last_seen" would continually be updated by Node D, which is in turn being updated by Node C. So the two would essentially tell each other that Node A lives, all the while Node B fails to share news of the decay. A network-wide death announcement 

---

## Architecture

### Node Discovery - The Gossip Protocol
Nodes broadcast PROBE packets containing their identity, public key, and known routing table. Receiving nodes update their own routing tables and re-broadcast new information to their neighbors. On LAN, discovery uses UDP broadcast to `255.255.255.255`. In test mode, nodes send directly to adjacent ports on localhost. Nodes can only reach their direct neighbors, and have no direct access to nodes >1 hop away. This keeps the system decentralized and each node slightly more anonymous than they would be in the case of a central routing authority.

### Routing
Each node maintains a distance vector routing table mapping node IDs to next-hop information and hop counts. When a node receives a PROBE containing a shorter path to a known node, it updates its routing table and propagates the improvement. Packets are forwarded hop-by-hop toward their destination. 

### Encryption
py-netmesh utilizes both RSA and AES encryption to keep data secure. Chat messages are encrypted using the destination node's public RSA key and PSS signed by the sender. 
For file transfers, a random AES-256 session key is generated per file transfer and encrypted with the recipient's RSA public key using OAEP padding. All payload data is then encrypted with AES-GCM using the session key, with AAD binding each chunk to its sequence number and file ID for integrity.

### File Transfer
Files are split into 8KB chunks and sent using a batch processing protocol. The sender waits for an ACK after each window before advancing. On timeout, the window is resent. Sequence numbers are tracked on both sides to detect and handle out-of-order or duplicate delivery.

### Node Dropout
Nodes announce their departure by broadcasting a DEATH packet to neighbors, which propagates through the mesh. A background health check also removes nodes whose `last_seen` timestamp exceeds a threshold, handling ungraceful exits such as crashes or signal kills.

---

## Installation

```bash
git clone https://github.com/ZappatheHackka/py-netmesh
cd py-netmesh
pip install -r requirements.txt
```

**Dependencies:**
- `cryptography`
- `prompt_toolkit`

---

## Usage

### Starting a node

```bash
python cli.py start [--ip IP] [--port PORT] [--lan] [--debug]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--ip` | `127.0.0.1` | IP address for this node. Use your LAN IP when running on a real network. |
| `--port` | `50000` | UDP port to listen on. Adjacent ports (port±1) are automatically added as allowed neighbors. |
| `--lan` | `False` | Enable LAN broadcast mode. Nodes discover each other via UDP broadcast on the local network. |
| `--debug` | `False` | Enable additional debug print statements for development and testing. |

### Examples

**Localhost test - two nodes on the same machine:**
```bash
# Terminal 1
python cli.py start --port 5000

# Terminal 2
python cli.py start --port 5001
```

**LAN mode - across devices on the same network:**
```bash
python cli.py start --ip 192.168.1.5 --port 5000 --lan
```

**Ubuntu bonus**
Check the simulate nodes folder for scripts to easily launch multiple nodes at once.

### Commands

Once a node is running, the following commands are available:

| Command | Description |
|---------|-------------|
| `/list` | List all known nodes in the mesh with hop count and IP |
| `/msg <alias> <text>` | Send an encrypted message to a node |
| `/send_file <alias> <filepath>` | Send a file to a node |
| `/allow <port>` | Add a port to the allowed neighbors list |
| `/change_filedir <path>` | Change the directory where incoming files are saved |
| `/?` | Show command reference |
| `/quit` | Announce departure and exit cleanly |

### Received files

Incoming files are saved to `py_netmesh_received_files/` in the current working directory by default. Use `/change_filedir` to change this.

---

## Limitations

- **WiFi file transfer reliability** - UDP over WiFi is subject to packet loss and corruption. File transfers on lossy connections may fail. For reliable large file transfer, use localhost mode or a wired connection. A future improvement would implement per-packet retry logic, more robust failure handling on seq mismatch, or switch to TCP for the file transfer layer. 
- **No persistent state** - routing tables are built from scratch each time a node starts. Nodes must rediscover each other on restart.
- **Alias uniqueness** - alias conflicts are detected and resolved locally, but the resolution is not guaranteed to be consistent across all nodes in a large mesh.
- **LAN broadcast scope** - discovery relies on UDP broadcast, which is limited to the local subnet. Nodes on different subnets or behind routers with broadcast filtering will not discover each other automatically.
- **Limited LAN Testing** - LAN mode was tested between my laptop and Kindle Fire running Termux. Kindle's processing limitations were discovered to cause issues with file transfers in a LAN environment.

---

## Future Work

- Per-packet retry logic for file transfer reliability on lossy networks
- More robust handling of seq mismatches, rather than outright transfer cancellation
- More dynamic option for window resend failures besides cancelling the transfer
- Experiment with TCP transport layer switch for file transfers
- Explore different decryption architecture to optimize for weaker devices
- Allow proper retry for failed file transfers 

---

## Tested On

- Ubuntu / Pop!_OS (primary development environment)
- Android (Termux) - node discovery and encrypted chat confirmed working across devices on LAN. File transfers are less consistent, but can work. More testing required.

---

*Built by Christopher Cottone — [github.com/ZappatheHackka](https://github.com/ZappatheHackka)*
