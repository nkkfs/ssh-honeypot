#!/usr/bin/env python3
"""
SSH Honeypot - Catches SSH login attempts and logs them
"""

import socket
import threading
import time
import json
import sqlite3
import hashlib
import os
from datetime import datetime
import paramiko
import requests

class SSHHoneypot:
    def __init__(self, bind_ip='0.0.0.0', port=2222, log_file='honeypot.log'):
        self.bind_ip = bind_ip
        self.port = port
        self.log_file = log_file
        self.running = False
        
        # Create database
        self.init_database()
        
        # Generate server key
        self.server_key = paramiko.RSAKey.generate(2048)
        
    def init_database(self):
        """Initialize SQLite database for logging"""
        self.conn = sqlite3.connect('honeypot.db', check_same_thread=False)
        self.cursor = self.conn.cursor()
        
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS ssh_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                source_ip TEXT,
                source_port INTEGER,
                username TEXT,
                password TEXT,
                password_hash TEXT,
                session_duration REAL,
                commands TEXT,
                geolocation TEXT,
                user_agent TEXT
            )
        ''')
        
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS connections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                source_ip TEXT,
                source_port INTEGER,
                event_type TEXT,
                details TEXT
            )
        ''')
        
        self.conn.commit()
    
    def get_geolocation(self, ip):
        """Get geolocation for IP address"""
        try:
            response = requests.get(f'http://ip-api.com/json/{ip}', timeout=5)
            if response.status_code == 200:
                data = response.json()
                return f"{data.get('country', 'Unknown')}, {data.get('city', 'Unknown')}"
        except:
            pass
        return "Unknown"
    
    def log_connection(self, ip, port, event_type, details=""):
        """Log connection events"""
        timestamp = datetime.now().isoformat()
        
        self.cursor.execute('''
            INSERT INTO connections (timestamp, source_ip, source_port, event_type, details)
            VALUES (?, ?, ?, ?, ?)
        ''', (timestamp, ip, port, event_type, details))
        self.conn.commit()
        
        # Also log to file
        log_entry = {
            'timestamp': timestamp,
            'source_ip': ip,
            'source_port': port,
            'event_type': event_type,
            'details': details
        }
        
        with open(self.log_file, 'a') as f:
            f.write(json.dumps(log_entry) + '\n')
        
        print(f"[{timestamp}] {event_type}: {ip}:{port} - {details}")
    
    def log_ssh_attempt(self, ip, port, username, password, session_duration, commands):
        """Log SSH login attempt"""
        timestamp = datetime.now().isoformat()
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        geolocation = self.get_geolocation(ip)
        
        self.cursor.execute('''
            INSERT INTO ssh_attempts 
            (timestamp, source_ip, source_port, username, password, password_hash, 
             session_duration, commands, geolocation, user_agent)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (timestamp, ip, port, username, password, password_hash, 
              session_duration, commands, geolocation, ""))
        
        self.conn.commit()
        
        print(f"[{timestamp}] SSH LOGIN: {ip}:{port} - {username}:{password} ({geolocation})")

class SSHServerInterface(paramiko.ServerInterface):
    def __init__(self, honeypot, client_ip, client_port):
        self.honeypot = honeypot
        self.client_ip = client_ip
        self.client_port = client_port
        self.username = None
        self.password = None
        self.session_start = time.time()
        self.commands = []
    
    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
    
    def check_auth_password(self, username, password):
        """Always reject password auth but log the attempt"""
        self.username = username
        self.password = password
        
        # Log the attempt
        session_duration = time.time() - self.session_start
        self.honeypot.log_ssh_attempt(
            self.client_ip, self.client_port, 
            username, password, session_duration, 
            json.dumps(self.commands)
        )
        
        # Sometimes accept to make it more realistic
        # Accept common combinations to see what attackers do
        if username.lower() in ['admin', 'root', 'user'] and password in ['123456', 'password', 'admin']:
            return paramiko.AUTH_SUCCESSFUL
        
        return paramiko.AUTH_FAILED
    
    def check_auth_publickey(self, username, key):
        """Reject all public key auth"""
        return paramiko.AUTH_FAILED
    
    def get_allowed_auths(self, username):
        return 'password'
    
    def check_channel_shell_request(self, channel):
        """Handle shell requests"""
        return True
    
    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        """Handle PTY requests"""
        return True

def handle_ssh_connection(honeypot, client_socket, client_address):
    """Handle individual SSH connection"""
    client_ip, client_port = client_address
    
    honeypot.log_connection(client_ip, client_port, "SSH_CONNECT")
    
    try:
        # Create SSH transport
        transport = paramiko.Transport(client_socket)
        transport.add_server_key(honeypot.server_key)
        
        # Create server interface
        server_interface = SSHServerInterface(honeypot, client_ip, client_port)
        
        try:
            transport.start_server(server=server_interface)
        except paramiko.SSHException:
            honeypot.log_connection(client_ip, client_port, "SSH_ERROR", "Failed to start SSH server")
            return
        
        # Wait for auth
        chan = transport.accept(20)
        if chan is None:
            honeypot.log_connection(client_ip, client_port, "SSH_TIMEOUT", "No channel opened")
            return
        
        # If auth succeeded, simulate a shell
        if chan:
            honeypot.log_connection(client_ip, client_port, "SSH_AUTH_SUCCESS", 
                                  f"User: {server_interface.username}")
            
            # Send fake banner
            chan.send(b"Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-88-generic x86_64)\r\n")
            chan.send(b"$ ")
            
            # Handle commands for a bit
            start_time = time.time()
            while time.time() - start_time < 300:  # 5 minutes max
                try:
                    data = chan.recv(1024)
                    if not data:
                        break
                    
                    command = data.decode('utf-8', errors='ignore').strip()
                    if command:
                        server_interface.commands.append(command)
                        honeypot.log_connection(client_ip, client_port, "SSH_COMMAND", command)
                        
                        # Send fake responses
                        if command.lower() in ['ls', 'dir']:
                            chan.send(b"bin  boot  dev  etc  home  lib  usr  var\r\n")
                        elif command.lower() == 'whoami':
                            chan.send(f"{server_interface.username}\r\n".encode())
                        elif command.lower() == 'pwd':
                            chan.send(b"/home/user\r\n")
                        elif command.lower() in ['exit', 'quit', 'logout']:
                            chan.send(b"Goodbye!\r\n")
                            break
                        else:
                            chan.send(b"bash: command not found\r\n")
                        
                        chan.send(b"$ ")
                
                except socket.timeout:
                    break
                except:
                    break
            
            chan.close()
    
    except Exception as e:
        honeypot.log_connection(client_ip, client_port, "SSH_EXCEPTION", str(e))
    
    finally:
        try:
            transport.close()
        except:
            pass
        
        honeypot.log_connection(client_ip, client_port, "SSH_DISCONNECT")

def main():
    print("SSH Honeypot starting...")
    
    honeypot = SSHHoneypot(bind_ip='0.0.0.0', port=2222)
    
    # Create socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server_socket.bind((honeypot.bind_ip, honeypot.port))
        server_socket.listen(100)
        honeypot.running = True
        
        print(f"SSH Honeypot listening on {honeypot.bind_ip}:{honeypot.port}")
        
        while honeypot.running:
            try:
                client_socket, client_address = server_socket.accept()
                
                # Handle connection in separate thread
                thread = threading.Thread(
                    target=handle_ssh_connection,
                    args=(honeypot, client_socket, client_address)
                )
                thread.daemon = True
                thread.start()
                
            except KeyboardInterrupt:
                print("\nShutting down honeypot...")
                honeypot.running = False
                break
            except Exception as e:
                print(f"Error accepting connection: {e}")
    
    finally:
        server_socket.close()
        honeypot.conn.close()

if __name__ == "__main__":
    main()