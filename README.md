# WireGuard Automation Server

Run this code to set up a WireGuard configuration server with HTTP API.

## Installation

First, ensure you have WireGuard installed on your server:
```bash
sudo apt-get update
sudo apt-get install wireguard
```

Then, use [git](https://git-scm.com/downloads) to clone this repository:
```bash
git clone https://github.com/Adi7015YT/WireGuard-Auto-Connect.git && cd WireGuard-Auto-Connect;
```

## Configuration

**FIRST, CUSTOMIZE THE CONFIGURATION IN THE `wg_config_server.py` FILE:**

1. Set your server's public address and port:
```python
ADDRESS = "your-server.com:51820"  # Your server's public address
```

2. Configure DNS settings (optional):
```python
DNS = "1.1.1.1"  # Change to your preferred DNS
```

3. Adjust server listening settings (if needed):
```python
SERVER_HOST = '0.0.0.0'  # Listen on all interfaces
SERVER_PORT = 51821      # API server port
```

## Usage

Start the configuration server:
```bash
sudo python3 wg_config_server.py
```

The server will start listening for client requests on port 51821.

### Client Usage

Clients can retrieve their configuration with a single command:

```bash
# Download configuration
curl "http://your-server.com:51821/?username=client1" > client1.conf

# Set up WireGuard (on client machine)
sudo wg-quick up ./client1.conf
```

Or combine both commands:

```bash
curl "http://your-server.com:51821/?username=client1" | sudo tee /etc/wireguard/wg0-client1.conf && sudo wg-quick up wg0-client1.conf
```

## Features

- **HTTP API**: Simple RESTful interface for configuration requests
- **Automatic IP Management**: Server automatically assigns unused IP addresses
- **Peer Management**: Automatically adds peers to server configuration
- **No External Dependencies**: Pure Python implementation
- **Secure**: Automatic key generation and management

## Requirements

- Python 3.9+
- WireGuard installed on server
- Superuser access (for server operation)
- Client machines need `curl` and `wg-quick`

## Security Notes

- The server runs on HTTP by default. For production use, consider:
  - Adding HTTPS/TLS encryption
  - Implementing client authentication
  - Using a reverse proxy with SSL termination
  - Restricting access with firewall rules

## Contributing

Pull requests are welcome. Please open an issue first to discuss significant changes.

## License

[GNU GPLv3](https://choosealicense.com/licenses/gpl-3.0/)

## Repository Structure

```
wg-automation-server/
├── wg_config_server.py    # Main server script
├── README.md              # This file
├── requirements.txt       # Python requirements
```

This implementation provides a complete solution for automating WireGuard configuration distribution through a simple HTTP API, making it easy for clients to get connected with a single command.
