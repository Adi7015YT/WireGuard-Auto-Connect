"""
WireGuard Configuration Server with HTTP API
Run this on your WireGuard server to handle client requests

"""

import ipaddress
import os
import pathlib
import shutil
import subprocess
import textwrap
from typing import Iterator
from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import urllib.parse

# Configuration - Customize these
SERVER_HOST = '0.0.0.0'  # Listen on all interfaces
SERVER_PORT = 51821      # Use a different port than WireGuard's default
ADDRESS = "your-server.com:51820"  # Your server's public address
DNS = "1.1.1.1"

def check_requirements() -> None:
    """Check if required tools are installed and we have superuser access."""
    assert shutil.which("wg") is not None, "'wg' must be installed."
    assert os.getuid() == 0, "You must have super user permissions to run this program."

def get_wg_show_output() -> tuple[str, ...]:
    """Get information about used ips, interface name, public key and etc."""
    raw_output = subprocess.check_output(["wg", "show"], text=True)
    raw_list = raw_output.split("\n")
    lines = [line.strip() for line in raw_list if line]
    assert lines, "Empty output from `wg show` command."
    return tuple(lines)

def find_interface(wg_show_output: tuple[str, ...]) -> str:
    """Finding interface name (e.g. wg0)."""
    for line in wg_show_output:
        if line.startswith("interface: "):
            return line.split()[-1]
    raise Exception("Cannot find interface name.")

def find_server_public_key(wg_show_output: tuple[str, ...]) -> str:
    """Finding sever public key."""
    for line in wg_show_output:
        if line.startswith("public key: "):
            return line.split()[-1]
    raise Exception("Cannot find server public key")

def gen_private_key() -> str:
    """Generating private key."""
    private_key = subprocess.check_output(["wg", "genkey"], text=True).strip()
    return private_key

def gen_public_key(private_key: str) -> str:
    """Generating public key from private key."""
    with subprocess.Popen(["echo", private_key], stdout=subprocess.PIPE) as ps_stdout:
        public_key = subprocess.check_output(
            ["wg", "pubkey"], stdin=ps_stdout.stdout, text=True
        ).strip()
        ps_stdout.wait()
    return public_key

def find_address(interface_name: str) -> tuple[ipaddress.IPv4Network, ipaddress.IPv4Address]:
    """Find ip network by reading config file."""
    assumed_file = pathlib.Path(f"/etc/wireguard/{interface_name}.conf")
    assert assumed_file.is_file(), f"cannot find config file: {assumed_file!r}"
    with open(assumed_file, encoding="utf-8") as config:
        for line in config.readlines():
            if line.startswith("Address"):
                ip = line.split()[-1]
                return ipaddress.ip_network(ip, strict=False), ipaddress.ip_address(
                    ip.split("/")[0]
                )
    raise Exception("Address not found!")

def find_using_ips(wg_output: tuple[str, ...]) -> Iterator[str]:
    """Find all using ips by reading configs."""
    for line in wg_output:
        if line.startswith("allowed ips") and "(none)" not in line:
            yield line.split()[-1]

def find_unused_ip(used_ips: set[ipaddress.IPv4Address], address: ipaddress.IPv4Network) -> ipaddress.IPv4Address:
    """Find an unused IP in the subnet."""
    for new_ip in address.hosts():
        if new_ip not in used_ips:
            return new_ip
    raise Exception("All valid IPs are used.")

def make_new_ip(interface_name: str, wg_output: tuple[str, ...]) -> str:
    """Returning an unused new valid ip which is in our address network."""
    address, address_as_ip = find_address(interface_name)
    used_ips = {
        ipaddress.ip_address(ip.split("/")[0]) for ip in find_using_ips(wg_output)
    }
    used_ips.add(address_as_ip)
    new_ip = find_unused_ip(used_ips, address)
    return f"{new_ip}/32"

def make_new_config_file(address: str, private_key: str, server_public_key: str) -> str:
    """Make new config file with exclusive DNS address."""
    config = textwrap.dedent(
        f"""\
            [Interface]
            Address = {address}
            PrivateKey = {private_key}
            DNS = {DNS}
            
            [Peer]
            PublicKey = {server_public_key}
            AllowedIPs = 0.0.0.0/0
            Endpoint = {ADDRESS}
            PersistentKeepalive = 25"""
    )
    return config

def insert_new_peer(public_key: str, allowed_ips: str, interface_name: str) -> None:
    """Insert new peer to WireGuard."""
    process = subprocess.call(
        ["wg", "set", interface_name, "peer", public_key, "allowed-ips", allowed_ips],
        stdout=subprocess.DEVNULL,
    )
    assert process == 0, "inserting new peer failed."

def save_new_config(interface_name: str) -> None:
    """Save the new configs."""
    process = subprocess.call(
        ["wg-quick", "save", interface_name],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    assert process == 0, "saving new config failed."

class ConfigHandler(BaseHTTPRequestHandler):
    """HTTP request handler for configuration requests."""
    
    def __init__(self, wg_show_output, interface_name, server_public_key, *args, **kwargs):
        self.wg_show_output = wg_show_output
        self.interface_name = interface_name
        self.server_public_key = server_public_key
        super().__init__(*args, **kwargs)
    
    def do_GET(self):
        """Handle GET requests for configuration."""
        try:
            # Parse query parameters
            parsed_path = urllib.parse.urlparse(self.path)
            query_params = urllib.parse.parse_qs(parsed_path.query)
            
            # Get username from query parameters
            if 'username' not in query_params:
                self.send_error(400, "Username parameter required")
                return
                
            username = query_params['username'][0]
            if not username:
                self.send_error(400, "Username cannot be empty")
                return
            
            # Generate keys and IP
            private_key = gen_private_key()
            public_key = gen_public_key(private_key)
            ip = make_new_ip(self.interface_name, self.wg_show_output)
            
            # Create config
            config = make_new_config_file(ip, private_key, self.server_public_key)
            
            # Add peer to server
            insert_new_peer(public_key, ip, self.interface_name)
            save_new_config(self.interface_name)
            
            # Send response
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(config.encode('utf-8'))
            
            print(f"Configuration generated for: {username}")
            
        except Exception as e:
            self.send_error(500, f"Error generating configuration: {str(e)}")
            print(f"Error handling request: {e}")

def run_server():
    """Run the HTTP server."""
    check_requirements()
    
    # Get server information
    wg_show_output = get_wg_show_output()
    interface_name = find_interface(wg_show_output)
    server_public_key = find_server_public_key(wg_show_output)
    
    # Create a custom handler with the server context
    handler_class = lambda *args: ConfigHandler(wg_show_output, interface_name, server_public_key, *args)
    
    # Start the server
    server = HTTPServer((SERVER_HOST, SERVER_PORT), handler_class)
    print(f"WireGuard configuration server listening on {SERVER_HOST}:{SERVER_PORT}")
    print(f"Server public key: {server_public_key}")
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("Server shutting down")
        server.shutdown()

if __name__ == "__main__":
    run_server()
