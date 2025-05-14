import socket
import time
import sys
import os
import random
import argparse
import threading
import concurrent.futures
import json
import ssl
import struct
import string
from datetime import datetime
try:
    from colorama import Fore, Back, Style, init
    init(autoreset=True)
    COLORS_AVAILABLE = True
except ImportError:
    COLORS_AVAILABLE = False
    print("For better display, install colorama: pip install colorama")

# Setup colors
if COLORS_AVAILABLE:
    C_RESET = Style.RESET_ALL
    C_BOLD = Style.BRIGHT
    C_GREEN = Fore.GREEN
    C_BLUE = Fore.BLUE
    C_RED = Fore.RED
    C_YELLOW = Fore.YELLOW
    C_CYAN = Fore.CYAN
    C_MAGENTA = Fore.MAGENTA
else:
    C_RESET = C_BOLD = C_GREEN = C_BLUE = C_RED = C_YELLOW = C_CYAN = C_MAGENTA = ""

# User agents list for HTTP requests
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.59",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
]

# Main Network Load Testing Class
class NetworkLoadTester:
    def __init__(self):
        self.target = ""
        self.port = 80
        self.threads = 10
        self.duration = 30
        self.packet_size = 1024
        self.protocol = "TCP"
        self.http_method = "GET"
        self.http_path = "/"
        self.use_ssl = False
        self.running = False
        self.start_time = 0
        self.packets_sent = 0
        self.bytes_sent = 0
        self.connections = 0
        self.failed = 0
        self.config_file = "loadtest_config.json"
        self.ramp_up = False
        self.custom_payload = ""
        self.payload_name = "Custom"  # New attribute to track current payload
        
        self.spoof_ip = None
        self.spoof_mode = "none"  # none, fixed, random, range
        self.spoof_ip_range_start = None
        self.spoof_ip_range_end = None

        # Dictionary of predefined payloads
        self.predefined_payloads = {
            "minecraft_ping": {
                "name": "Minecraft Server List Ping (1.16.5)",
                "description": "Status request packet for Minecraft servers",
                "protocol": "TCP",
                "port": 25565,
                "payload": b"\x10\x00\x74\x00\x05\x6c\x6f\x63\x61\x6c\x68\x6f\x73\x74\x63\xdd\x01",
                "is_binary": True
            },
            "minecraft_login": {
                "name": "Minecraft Handshake + Status (1.20.1)",
                "description": "Complete handshake followed by a status request",
                "protocol": "TCP",
                "port": 25565,
                "payload": b"\x16\x00\x00\x00\xf9\x03\x09\x6c\x6f\x63\x61\x6c\x68\x6f\x73\x74\x63\xdd\x01\x01\x00",
                "is_binary": True
            },
            "minecraft_login_attempt": {
                "name": "Minecraft Login Request",
                "description": "Simulates a player login sequence start",
                "protocol": "TCP", 
                "port": 25565,
                "payload": b"\x0f\x00\x00\x00\xf9\x03\x09\x6c\x6f\x63\x61\x6c\x68\x6f\x73\x74\x63\xdd\x02\x0c\x00\x07\x54\x65\x73\x74\x55\x73\x65\x72",
                "is_binary": True
            },
            "rdp_connection": {
                "name": "RDP Connection Request",
                "description": "Initial RDP (Remote Desktop) connection packet",
                "protocol": "TCP",
                "port": 3389,
                "payload": b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00",
                "is_binary": True
            },
            "rdp_negotiation": {
                "name": "RDP Negotiation Packet",
                "description": "RDP protocol negotiation request",
                "protocol": "TCP",
                "port": 3389,
                "payload": b"\x03\x00\x00\x2c\x27\xe0\x00\x00\x00\x00\x00\x43\x6f\x6f\x6b\x69\x65\x3a\x20\x6d\x73\x74\x73\x68\x61\x73\x68\x3d\x74\x65\x73\x74\x0d\x0a\x01\x00\x08\x00\x03\x00\x00\x00",
                "is_binary": True
            },
            "http_basic": {
                "name": "HTTP Basic Request",
                "description": "Simple HTTP GET request",
                "protocol": "HTTP",
                "port": 80,
                "payload": "GET / HTTP/1.1\r\nHost: target\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n",
                "is_binary": False
            },
            "dns_query": {
                "name": "DNS Query",
                "description": "Simple DNS A record query",
                "protocol": "UDP",
                "port": 53,
                "payload": b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03\x77\x77\x77\x07\x65\x78\x61\x6d\x70\x6c\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01",
                "is_binary": True
            },
            "smtp_commands": {
                "name": "SMTP Command Sequence",
                "description": "Basic SMTP command flow",
                "protocol": "TCP",
                "port": 25,
                "payload": "HELO example.com\r\nMAIL FROM: <test@example.com>\r\nRCPT TO: <admin@target.com>\r\nDATA\r\nTest message\r\n.\r\nQUIT\r\n",
                "is_binary": False
            },
            "ssh_init": {
                "name": "SSH Connection Attempt",
                "description": "SSH protocol version exchange",
                "protocol": "TCP",
                "port": 22,
                "payload": "SSH-2.0-OpenSSH_8.2p1\r\n",
                "is_binary": False
            },
            "ftp_commands": {
                "name": "FTP Command Sequence",
                "description": "Basic FTP authentication attempt",
                "protocol": "TCP",
                "port": 21,
                "payload": "USER anonymous\r\nPASS test@example.com\r\nPWD\r\nQUIT\r\n",
                "is_binary": False
            }
        }
    
    def clear_screen(self):
        os.system('clear')  # For Linux
    
    def print_banner(self):
        banner = f"""
{C_CYAN}╔══════════════════════════════════════════════════════════╗
║ {C_BOLD}{C_YELLOW}      NETWORK LOAD TESTING TOOL - LEGAL USE ONLY       {C_CYAN}║
║ {C_BOLD}{C_GREEN}                    VERSION 2.0                         {C_CYAN}║
╚══════════════════════════════════════════════════════════╝
{C_RESET}"""
        print(banner)
    
    def print_menu(self):
        self.clear_screen()
        self.print_banner()
        
        # Show SSL indicator if HTTP with SSL is enabled
        ssl_status = ""
        if self.protocol == "HTTP" and self.use_ssl:
            ssl_status = f" {C_GREEN}(HTTPS){C_RESET}"
        
        # Show HTTP method if protocol is HTTP
        http_method = ""
        if self.protocol == "HTTP":
            http_method = f" {self.http_method} {self.http_path}"
        
        # Show payload indicator if a payload is set
        payload_info = ""
        if self.custom_payload:
            if isinstance(self.custom_payload, bytes):
                payload_size = len(self.custom_payload)
            else:
                payload_size = len(self.custom_payload.encode())
            payload_info = f" {C_MAGENTA}[Payload: {self.payload_name} - {payload_size} bytes]{C_RESET}"
        
        # Show IP spoofing indicator if enabled
        spoofing_info = ""
        if hasattr(self, 'spoof_ip') and self.spoof_ip:
            spoofing_info = f" {C_RED}[IP Spoofing: {self.spoof_ip}]{C_RESET}"
        
        menu = f"""
{C_GREEN}[1]{C_RESET} Set Target & Port     {C_BLUE}(Current: {self.target}:{self.port}){C_RESET}
{C_GREEN}[2]{C_RESET} Select Protocol       {C_BLUE}(Current: {self.protocol}{ssl_status}{http_method}){payload_info}
{C_GREEN}[3]{C_RESET} Set Thread Count      {C_BLUE}(Current: {self.threads}){C_RESET}
{C_GREEN}[4]{C_RESET} Set Test Duration     {C_BLUE}(Current: {self.duration} seconds){C_RESET}
{C_GREEN}[5]{C_RESET} Set Packet Size       {C_BLUE}(Current: {self.packet_size} bytes){C_RESET}
{C_GREEN}[6]{C_RESET} Advanced Settings     {C_BLUE}(Ramp-up, Payloads, etc.){C_RESET}
{C_GREEN}[7]{C_RESET} Save/Load Config      {C_BLUE}(Save or load test settings){C_RESET}
{C_GREEN}[8]{C_RESET} Start Test            {spoofing_info}
{C_GREEN}[9]{C_RESET} Network Scanner       {C_BLUE}(Port scan, IP range scan){C_RESET}
{C_GREEN}[10]{C_RESET} IP Spoofer           {C_BLUE}(Configure source IP spoofing){C_RESET}
{C_RED}[0]{C_RESET} Exit
"""
        print(menu)
    
    def get_input(self, prompt, validator=None, error_msg=None):
        while True:
            try:
                user_input = input(f"{C_YELLOW}{prompt}: {C_RESET}")
                if validator and not validator(user_input):
                    print(f"{C_RED}{error_msg}{C_RESET}")
                    continue
                return user_input
            except KeyboardInterrupt:
                print(f"\n{C_RED}Operation canceled{C_RESET}")
                return None
    
    def set_target(self):
        self.clear_screen()
        self.print_banner()
        print(f"{C_CYAN}Set Target and Port{C_RESET}\n")
        
        def is_valid_host(host):
            if not host:
                return False
            try:
                socket.gethostbyname(host)
                return True
            except:
                return False
        
        target = self.get_input("Enter target IP or domain", 
                                 is_valid_host, 
                                 "Invalid address. Please try again")
        
        if target is None:
            return
        
        def is_valid_port(port):
            try:
                port_num = int(port)
                return 1 <= port_num <= 65535
            except:
                return False
        
        port = self.get_input("Enter port number (1-65535)", 
                              is_valid_port, 
                              "Invalid port. Must be between 1-65535")
        
        if port is None:
            return
        
        self.target = target
        self.port = int(port)
        print(f"\n{C_GREEN}Target set: {self.target}:{self.port}{C_RESET}")
        input("\nPress Enter to return to menu...")
    
    def set_protocol(self):
        self.clear_screen()
        self.print_banner()
        print(f"{C_CYAN}Select Protocol{C_RESET}\n")
        print(f"{C_GREEN}[1]{C_RESET} TCP")
        print(f"{C_GREEN}[2]{C_RESET} UDP")
        print(f"{C_GREEN}[3]{C_RESET} HTTP")
        print(f"{C_GREEN}[4]{C_RESET} ICMP (Ping)")
        print(f"{C_GREEN}[5]{C_RESET} Slowloris")
        print(f"{C_GREEN}[6]{C_RESET} SYN Flood")
        
        def is_valid_choice(choice):
            return choice in ['1', '2', '3', '4', '5', '6']
        
        choice = self.get_input("\nSelect protocol", 
                                is_valid_choice, 
                                "Invalid selection")
        
        if choice is None:
            return
        
        protocols = {'1': 'TCP', '2': 'UDP', '3': 'HTTP', '4': 'ICMP', '5': 'SLOWLORIS', '6': 'SYN'}
        self.protocol = protocols[choice]
        
        # If HTTP is selected, ask for additional settings
        if self.protocol == "HTTP":
            self.configure_http_settings()
        
        print(f"\n{C_GREEN}Protocol selected: {self.protocol}{C_RESET}")
        input("\nPress Enter to return to menu...")
    
    def configure_http_settings(self):
        self.clear_screen()
        self.print_banner()
        print(f"{C_CYAN}Configure HTTP Settings{C_RESET}\n")
        
        # HTTP Method
        print(f"{C_GREEN}[1]{C_RESET} GET")
        print(f"{C_GREEN}[2]{C_RESET} POST")
        print(f"{C_GREEN}[3]{C_RESET} HEAD")
        
        def is_valid_http_method(choice):
            return choice in ['1', '2', '3']
        
        method_choice = self.get_input("\nSelect HTTP method", 
                                is_valid_http_method, 
                                "Invalid selection")
        
        if method_choice is None:
            return
        
        methods = {'1': 'GET', '2': 'POST', '3': 'HEAD'}
        self.http_method = methods[method_choice]
        
        # HTTP Path
        path = self.get_input("Enter request path (default: /)", None, None)
        if path:
            self.http_path = path
        else:
            self.http_path = "/"
        
        # SSL (HTTPS)
        ssl_choice = self.get_input("Use SSL/HTTPS? (y/n)", None, None)
        self.use_ssl = ssl_choice.lower() == 'y'
        
        print(f"\n{C_GREEN}HTTP settings configured{C_RESET}")
    
    def set_threads(self):
        self.clear_screen()
        self.print_banner()
        print(f"{C_CYAN}Set Thread Count{C_RESET}\n")
        
        def is_valid_threads(threads):
            try:
                threads_num = int(threads)
                return 1 <= threads_num <= 5000
            except:
                return False
        
        threads = self.get_input("Enter number of threads (1-5000)", 
                                 is_valid_threads, 
                                 "Invalid number. Must be between 1-5000")
        
        if threads is None:
            return
        
        self.threads = int(threads)
        print(f"\n{C_GREEN}Thread count set: {self.threads}{C_RESET}")
        input("\nPress Enter to return to menu...")
    
    def set_duration(self):
        self.clear_screen()
        self.print_banner()
        print(f"{C_CYAN}Set Test Duration{C_RESET}\n")
        
        def is_valid_duration(duration):
            try:
                duration_num = int(duration)
                return 1 <= duration_num <= 3600
            except:
                return False
        
        duration = self.get_input("Enter test duration in seconds (1-3600)", 
                                  is_valid_duration, 
                                  "Invalid duration. Must be between 1-3600 seconds")
        
        if duration is None:
            return
        
        self.duration = int(duration)
        print(f"\n{C_GREEN}Test duration set: {self.duration} seconds{C_RESET}")
        input("\nPress Enter to return to menu...")
    
    def set_packet_size(self):
        self.clear_screen()
        self.print_banner()
        print(f"{C_CYAN}Set Packet Size{C_RESET}\n")
        
        def is_valid_size(size):
            try:
                size_num = int(size)
                return 64 <= size_num <= 65507
            except:
                return False
        
        packet_size = self.get_input("Enter packet size in bytes (64-65507)", 
                                    is_valid_size, 
                                    "Invalid size. Must be between 64-65507 bytes")
        
        if packet_size is None:
            return
        
        self.packet_size = int(packet_size)
        print(f"\n{C_GREEN}Packet size set: {self.packet_size} bytes{C_RESET}")
        input("\nPress Enter to return to menu...")
    
    def set_advanced_options(self):
        self.clear_screen()
        self.print_banner()
        print(f"{C_CYAN}Advanced Settings{C_RESET}\n")
        
        print(f"{C_GREEN}[1]{C_RESET} Ramp-up settings")
        print(f"{C_GREEN}[2]{C_RESET} Custom payload")
        print(f"{C_GREEN}[3]{C_RESET} Predefined payloads")
        print(f"{C_GREEN}[4]{C_RESET} Return to main menu")
        
        choice = self.get_input("\nSelect option", None, None)
        
        if choice == '1':
            self._set_rampup_options()
        elif choice == '2':
            self._set_custom_payload()
        elif choice == '3':
            self._set_predefined_payload()
        else:
            return
    
    def _set_rampup_options(self):
        """Set ramp-up options"""
        self.clear_screen()
        self.print_banner()
        print(f"{C_CYAN}Ramp-up Settings{C_RESET}\n")
        
        # Ramp-up option
        ramp_choice = self.get_input("Enable gradual ramp-up of connections? (y/n)", None, None)
        self.ramp_up = ramp_choice.lower() == 'y'
        
        print(f"\n{C_GREEN}Ramp-up settings updated{C_RESET}")
        input("\nPress Enter to return to menu...")
    
    def _set_custom_payload(self):
        """Set custom payload"""
        self.clear_screen()
        self.print_banner()
        print(f"{C_CYAN}Custom Payload{C_RESET}\n")
        
        print(f"{C_YELLOW}Enter custom payload (leave blank and press Enter when done):{C_RESET}")
        print(f"{C_YELLOW}For binary payloads, use \\x notation (e.g. \\x00\\x01\\x02){C_RESET}\n")
        
        payload_lines = []
        while True:
            line = input()
            if not line:
                break
            payload_lines.append(line)
        
        if payload_lines:
            self.custom_payload = "\n".join(payload_lines)
            self.payload_name = "Custom"
            print(f"\n{C_GREEN}Custom payload set ({len(self.custom_payload)} bytes){C_RESET}")
        else:
            self.custom_payload = ""
            self.payload_name = "None"
            print(f"\n{C_GREEN}Custom payload cleared{C_RESET}")
        
        input("\nPress Enter to return to menu...")
    
    def _set_predefined_payload(self):
        """Select a predefined payload"""
        self.clear_screen()
        self.print_banner()
        print(f"{C_CYAN}Predefined Payloads{C_RESET}\n")
        
        # Display available payloads
        payloads = list(self.predefined_payloads.items())
        for i, (key, payload) in enumerate(payloads, 1):
            print(f"{C_GREEN}[{i}]{C_RESET} {payload['name']}")
            print(f"   {C_BLUE}Description:{C_RESET} {payload['description']}")
            print(f"   {C_BLUE}Protocol:{C_RESET} {payload['protocol']} (Port: {payload['port']})")
            print()
        
        print(f"{C_GREEN}[0]{C_RESET} Cancel and return to previous menu")
        
        # Get user selection
        while True:
            try:
                choice = int(self.get_input("\nSelect a payload", None, None) or "0")
                if 0 <= choice <= len(payloads):
                    break
                print(f"{C_RED}Invalid choice. Please select a number between 0 and {len(payloads)}{C_RESET}")
            except ValueError:
                print(f"{C_RED}Please enter a number{C_RESET}")
        
        if choice == 0:
            return
        
        # Apply selected payload
        payload_key, payload_info = payloads[choice-1]
        
        # Set the payload
        if payload_info['is_binary']:
            # For binary payloads, we already have them as bytes in the dictionary
            self.custom_payload = payload_info['payload']
        else:
            # For text payloads, we store them as strings
            self.custom_payload = payload_info['payload']
        
        # Store the name for display
        self.payload_name = payload_info['name']
        
        # Suggest changing protocol and port if different from current settings
        if payload_info['protocol'] != self.protocol or payload_info['port'] != self.port:
            print(f"\n{C_YELLOW}This payload is designed for {payload_info['protocol']} on port {payload_info['port']}.{C_RESET}")
            change = self.get_input("Would you like to update your protocol and port settings to match? (y/n)", None, None)
            
            if change.lower() == 'y':
                self.protocol = payload_info['protocol']
                self.port = payload_info['port']
                print(f"{C_GREEN}Protocol set to {self.protocol} and port set to {self.port}{C_RESET}")
        
        print(f"\n{C_GREEN}Predefined payload '{payload_info['name']}' selected{C_RESET}")
        input("\nPress Enter to return to menu...")
    
    def save_load_config(self):
        self.clear_screen()
        self.print_banner()
        print(f"{C_CYAN}Save/Load Configuration{C_RESET}\n")
        print(f"{C_GREEN}[1]{C_RESET} Save current configuration")
        print(f"{C_GREEN}[2]{C_RESET} Load configuration")
        print(f"{C_GREEN}[3]{C_RESET} Return to main menu")
        
        choice = self.get_input("\nSelect option", None, None)
        
        if choice == '1':
            self.save_config()
        elif choice == '2':
            self.load_config()
        else:
            return
    
    def save_config(self):
        config = {
            'target': self.target,
            'port': self.port,
            'protocol': self.protocol,
            'threads': self.threads,
            'duration': self.duration,
            'packet_size': self.packet_size,
            'http_method': self.http_method,
            'http_path': self.http_path,
            'use_ssl': self.use_ssl,
            'ramp_up': self.ramp_up,
            'payload_name': self.payload_name
        }
        
        # Handle custom payload
        if self.custom_payload:
            if isinstance(self.custom_payload, bytes):
                # Convert binary payload to hex string for storage
                config['custom_payload'] = ''.join(f'\\x{b:02x}' for b in self.custom_payload)
                config['payload_is_binary'] = True
            else:
                # Store text payload directly
                config['custom_payload'] = self.custom_payload
                config['payload_is_binary'] = False
        else:
            config['custom_payload'] = ""
            config['payload_is_binary'] = False
        
        filename = self.get_input("Enter filename to save configuration", None, None) or self.config_file
        
        try:
            with open(filename, 'w') as f:
                json.dump(config, f, indent=4)
            print(f"\n{C_GREEN}Configuration saved to {filename}{C_RESET}")
        except Exception as e:
            print(f"\n{C_RED}Error saving configuration: {str(e)}{C_RESET}")
        
        input("\nPress Enter to return to menu...")
    
    def load_config(self):
        filename = self.get_input("Enter filename to load configuration", None, None) or self.config_file
        
        try:
            if not os.path.exists(filename):
                print(f"\n{C_RED}File not found: {filename}{C_RESET}")
                input("\nPress Enter to return to menu...")
                return
                
            with open(filename, 'r') as f:
                config = json.load(f)
            
            self.target = config.get('target', '')
            self.port = config.get('port', 80)
            self.protocol = config.get('protocol', 'TCP')
            self.threads = config.get('threads', 10)
            self.duration = config.get('duration', 30)
            self.packet_size = config.get('packet_size', 1024)
            self.http_method = config.get('http_method', 'GET')
            self.http_path = config.get('http_path', '/')
            self.use_ssl = config.get('use_ssl', False)
            self.ramp_up = config.get('ramp_up', False)
            self.payload_name = config.get('payload_name', 'Custom')
            
            # Handle payload loading
            stored_payload = config.get('custom_payload', '')
            is_binary = config.get('payload_is_binary', False)
            
            if stored_payload:
                if is_binary:
                    # Convert hex string back to binary
                    try:
                        self.custom_payload = bytes.fromhex(stored_payload.replace('\\x', ''))
                    except:
                        print(f"{C_RED}Warning: Could not parse binary payload. Using as text.{C_RESET}")
                        self.custom_payload = stored_payload
                else:
                    self.custom_payload = stored_payload
            else:
                self.custom_payload = ""
            
            print(f"\n{C_GREEN}Configuration loaded from {filename}{C_RESET}")
        except Exception as e:
            print(f"\n{C_RED}Error loading configuration: {str(e)}{C_RESET}")
        
        input("\nPress Enter to return to menu...")
    
    def start_test(self):
        """Start the network load test"""
        self.clear_screen()
        self.print_banner()
        print(f"{C_CYAN}Starting Network Load Test{C_RESET}\n")
        
        if not self.target:
            print(f"{C_RED}Error: Target is not set. Please set the target first.{C_RESET}")
            input("\nPress Enter to return to the menu...")
            return
        
        print(f"{C_GREEN}Target:{C_RESET} {self.target}:{self.port}")
        print(f"{C_GREEN}Protocol:{C_RESET} {self.protocol}")
        print(f"{C_GREEN}Threads:{C_RESET} {self.threads}")
        print(f"{C_GREEN}Duration:{C_RESET} {self.duration} seconds")
        print(f"{C_GREEN}Packet Size:{C_RESET} {self.packet_size} bytes")
        
        if self.custom_payload:
            print(f"{C_GREEN}Custom Payload:{C_RESET} {self.payload_name}")
        
        if self.spoof_ip and self.spoof_mode != "none":
            print(f"{C_GREEN}IP Spoofing:{C_RESET} {self.spoof_ip}")
        
        confirm = input(f"\n{C_YELLOW}Start the test? (y/n): {C_RESET}")
        if confirm.lower() != 'y':
            return
        
        # Initialize counters
        self.running = True
        self.start_time = time.time()
        self.packets_sent = 0
        self.bytes_sent = 0
        self.connections = 0
        self.failed = 0
        
        # Select the appropriate worker function
        if self.protocol == "TCP":
            worker = self.tcp_worker
        elif self.protocol == "UDP":
            worker = self.udp_worker
        elif self.protocol == "HTTP":
            worker = self.http_worker
        elif self.protocol == "ICMP":
            worker = self.icmp_worker
        elif self.protocol == "SLOWLORIS":
            worker = self.slowloris_worker
        elif self.protocol == "SYN":
            worker = self.syn_flood_worker
        else:
            print(f"{C_RED}Error: Unsupported protocol selected.{C_RESET}")
            input("\nPress Enter to return to the menu...")
            return
        
        # Start threads
        threads = []
        for _ in range(self.threads):
            t = threading.Thread(target=worker)
            t.daemon = True
            threads.append(t)
            t.start()
        
        # Monitor progress
        try:
            while self.running:
                elapsed = time.time() - self.start_time
                if elapsed >= self.duration:
                    self.running = False
                    break
                
                print(f"\r{C_GREEN}Packets Sent:{C_RESET} {self.packets_sent}  "
                      f"{C_GREEN}Bytes Sent:{C_RESET} {self.bytes_sent}  "
                      f"{C_GREEN}Connections:{C_RESET} {self.connections}  "
                      f"{C_RED}Failed:{C_RESET} {self.failed}  "
                      f"{C_YELLOW}Elapsed:{C_RESET} {elapsed:.2f}s", end="")
                time.sleep(1)
        except KeyboardInterrupt:
            self.running = False
            print(f"\n{C_RED}Test interrupted by user.{C_RESET}")
        
        # Wait for threads to finish
        for t in threads:
            t.join()
        
        # Display results
        print(f"\n\n{C_CYAN}Test Completed{C_RESET}")
        print(f"{C_GREEN}Packets Sent:{C_RESET} {self.packets_sent}")
        print(f"{C_GREEN}Bytes Sent:{C_RESET} {self.bytes_sent}")
        print(f"{C_GREEN}Connections:{C_RESET} {self.connections}")
        print(f"{C_RED}Failed:{C_RESET} {self.failed}")
        print(f"{C_YELLOW}Duration:{C_RESET} {self.duration} seconds")
        input("\nPress Enter to return to the menu...")

    def tcp_worker(self):
        """TCP worker for sending packets"""
        while self.running:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2)
                s.connect((self.target, self.port))
                
                if self.custom_payload:
                    payload = self.custom_payload.encode() if isinstance(self.custom_payload, str) else self.custom_payload
                else:
                    payload = random.randbytes(self.packet_size)
                
                s.send(payload)
                s.close()
                
                with threading.Lock():
                    self.packets_sent += 1
                    self.bytes_sent += len(payload)
                    self.connections += 1
            except:
                with threading.Lock():
                    self.failed += 1
            
            if time.time() - self.start_time >= self.duration:
                self.running = False

    def udp_worker(self):
        """UDP worker for sending packets"""
        while self.running:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                
                if self.custom_payload:
                    payload = self.custom_payload.encode() if isinstance(self.custom_payload, str) else self.custom_payload
                else:
                    payload = random.randbytes(self.packet_size)
                
                s.sendto(payload, (self.target, self.port))
                
                with threading.Lock():
                    self.packets_sent += 1
                    self.bytes_sent += len(payload)
            except:
                with threading.Lock():
                    self.failed += 1
            
            if time.time() - self.start_time >= self.duration:
                self.running = False

    def http_worker(self):
        """HTTP worker for sending requests"""
        while self.running:
            try:
                protocol = "https" if self.use_ssl else "http"
                url = f"{protocol}://{self.target}:{self.port}{self.http_path}"
                
                headers = {
                    "User-Agent": random.choice(USER_AGENTS),
                    "Connection": "keep-alive"
                }
                
                if self.http_method == "GET":
                    response = requests.get(url, headers=headers, timeout=2)
                elif self.http_method == "POST":
                    response = requests.post(url, headers=headers, data=self.custom_payload, timeout=2)
                elif self.http_method == "HEAD":
                    response = requests.head(url, headers=headers, timeout=2)
                
                with threading.Lock():
                    self.packets_sent += 1
                    self.bytes_sent += len(response.content)
                    self.connections += 1
            except:
                with threading.Lock():
                    self.failed += 1
            
            if time.time() - self.start_time >= self.duration:
                self.running = False

    def icmp_worker(self):
        """ICMP worker for sending ping packets"""
        while self.running:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
                s.settimeout(2)
                
                icmp_type = 8  # Echo Request
                icmp_code = 0
                icmp_checksum = 0
                icmp_id = random.randint(1, 65535)
                icmp_seq = random.randint(1, 65535)
                payload = random.randbytes(self.packet_size - 8)
                
                icmp_header = struct.pack("!BBHHH", icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq)
                packet = icmp_header + payload
                
                s.sendto(packet, (self.target, 0))
                
                with threading.Lock():
                    self.packets_sent += 1
                    self.bytes_sent += len(packet)
            except:
                with threading.Lock():
                    self.failed += 1
            
            if time.time() - self.start_time >= self.duration:
                self.running = False

    def run_port_scanner(self):
        """Run port scanner feature"""
        while True:
            self.clear_screen()
            self.print_banner()
            print(f"{C_CYAN}Network Scanner{C_RESET}\n")
            
            print(f"{C_GREEN}[1]{C_RESET} Port Scanner (Single host)")
            print(f"{C_GREEN}[2]{C_RESET} IP Range Scanner")
            print(f"{C_GREEN}[3]{C_RESET} Return to main menu")
            
            choice = input(f"{C_YELLOW}Select option: {C_RESET}")  # Fixed this line
            
            if choice == '1':
                self._run_single_host_port_scan()
            elif choice == '2':
                self._run_ip_range_scan()
            elif choice == '3':
                return
            else:
                print(f"{C_RED}Invalid option!{C_RESET}")
                input("\nPress Enter to continue...")

    def configure_ip_spoofing(self):
        """Configure IP spoofing settings"""
        self.clear_screen()
        self.print_banner()
        print(f"{C_CYAN}IP Spoofing Configuration{C_RESET}\n")
        
        print(f"{C_RED}WARNING: IP spoofing requires root/administrator privileges.{C_RESET}")
        print(f"{C_RED}Many networks block spoofed packets. Use only for testing purposes.{C_RESET}\n")
        
        # Check for admin/root privileges
        admin_privileges = False
        try:
            if os.name == 'nt':  # Windows
                import ctypes
                admin_privileges = ctypes.windll.shell32.IsUserAnAdmin() != 0
            else:  # Unix-like
                admin_privileges = os.geteuid() == 0
        except:
            pass
        
        if not admin_privileges:
            print(f"{C_YELLOW}Notice: You are not running as administrator/root.{C_RESET}")
            print(f"{C_YELLOW}IP spoofing will likely fail without proper permissions.{C_RESET}\n")
        
        print(f"{C_GREEN}Select Spoofing Mode:{C_RESET}")
        print(f"{C_GREEN}[1]{C_RESET} No spoofing (use real source IP)")
        print(f"{C_GREEN}[2]{C_RESET} Fixed source IP (specify one IP address)")
        print(f"{C_GREEN}[3]{C_RESET} Random source IP (completely random)")
        print(f"{C_GREEN}[4]{C_RESET} IP range (random IP from a specified range)")
        
        choice = input(f"\n{C_YELLOW}Select option: {C_RESET}")
        
        if choice == '1':
            self.spoof_mode = "none"
            self.spoof_ip = None
            print(f"\n{C_GREEN}IP spoofing disabled{C_RESET}")
        
        elif choice == '2':
            self.spoof_mode = "fixed"
            ip = input(f"\n{C_YELLOW}Enter source IP address to use: {C_RESET}")
            
            # Validate IP
            try:
                socket.inet_aton(ip)
                self.spoof_ip = ip
                print(f"\n{C_GREEN}Fixed source IP set to: {ip}{C_RESET}")
            except:
                print(f"\n{C_RED}Invalid IP address format{C_RESET}")
                self.spoof_ip = None
                self.spoof_mode = "none"
        
        elif choice == '3':
            self.spoof_mode = "random"
            self.spoof_ip = "random"
            print(f"\n{C_GREEN}Random source IP spoofing enabled{C_RESET}")
        
        elif choice == '4':
            self.spoof_mode = "range"
            start_ip = input(f"\n{C_YELLOW}Enter start IP address: {C_RESET}")
            end_ip = input(f"{C_YELLOW}Enter end IP address: {C_RESET}")
            
            # Validate IPs
            try:
                socket.inet_aton(start_ip)
                socket.inet_aton(end_ip)
                
                # Convert to integers for comparison
                start_int = self._ip_to_int(start_ip)
                end_int = self._ip_to_int(end_ip)
                
                # Make sure start < end
                if start_int > end_int:
                    start_ip, end_ip = end_ip, start_ip
                    start_int, end_int = end_int, start_int
                
                self.spoof_ip_range_start = start_ip
                self.spoof_ip_range_end = end_ip
                self.spoof_ip = f"range:{start_ip}-{end_ip}"
                
                print(f"\n{C_GREEN}IP range spoofing enabled: {start_ip} to {end_ip}{C_RESET}")
            except:
                print(f"\n{C_RED}Invalid IP address format{C_RESET}")
                self.spoof_ip = None
                self.spoof_mode = "none"
        
        else:
            print(f"\n{C_RED}Invalid option selected{C_RESET}")
        
        # Show supported protocols
        print(f"\n{C_YELLOW}Note: IP spoofing is most effective with:{C_RESET}")
        print(f"- UDP protocol")
        print(f"- SYN Flood attacks")
        print(f"- ICMP (ping) packets")
        print(f"Other protocols may ignore spoofed IPs or require additional configuration.")
        
        input(f"\n{C_GREEN}Press Enter to return to menu...{C_RESET}")
    
    def _get_source_ip(self):
        """Get a source IP address based on spoofing configuration"""
        if not self.spoof_ip or self.spoof_mode == "none":
            # No spoofing, use real IP
            return socket.gethostbyname(socket.gethostname())
        
        if self.spoof_mode == "fixed":
            # Fixed IP
            return self.spoof_ip
        
        if self.spoof_mode == "random":
            # Generate completely random IP
            return f"{random.randint(1, 254)}.{random.randint(0, 254)}."  \
                   f"{random.randint(0, 254)}.{random.randint(1, 254)}"
        
        if self.spoof_mode == "range":
            # Random IP from specified range
            start_int = self._ip_to_int(self.spoof_ip_range_start)
            end_int = self._ip_to_int(self.spoof_ip_range_end)
            
            # Get random integer between start and end
            ip_int = random.randint(start_int, end_int)
            
            # Convert back to IP string
            return self._int_to_ip(ip_int)
        
        # Fallback to real IP if something went wrong
        return socket.gethostbyname(socket.gethostname())
    
    def _run_single_host_port_scan(self):
        """Scan ports on a single host"""
        self.clear_screen()
        self.print_banner()
        print(f"{C_CYAN}Port Scanner - Single Host{C_RESET}\n")
        
        # Get target
        target = input(f"{C_YELLOW}Enter target IP or domain: {C_RESET}")
        if not target:
            return
        
        try:
            # Resolve hostname to IP
            ip = socket.gethostbyname(target)
            print(f"\nTarget resolved: {target} ({ip})")
        except socket.gaierror:
            print(f"\n{C_RED}Error: Could not resolve hostname {target}{C_RESET}")
            input("\nPress Enter to return...")
            return
        
        # Port scan mode
        print(f"\n{C_CYAN}Scan Mode:{C_RESET}")
        print(f"{C_GREEN}[1]{C_RESET} Quick scan (common ports)")
        print(f"{C_GREEN}[2]{C_RESET} Full scan (1-1024)")
        print(f"{C_GREEN}[3]{C_RESET} Custom port range")
        print(f"{C_GREEN}[4]{C_RESET} Specific ports (comma separated)")
        
        scan_mode = input(f"\n{C_YELLOW}Select scan mode: {C_RESET}")
        
        # Determine ports to scan based on mode
        if scan_mode == '1':
            # Common ports: HTTP, HTTPS, FTP, SSH, Telnet, SMTP, DNS, etc.
            ports = [21, 22, 23, 25, 53, 80, 110, 123, 143, 443, 465, 587, 993, 995, 3306, 3389, 5432, 8080, 8443]
            print(f"\nScanning {len(ports)} common ports...")
        elif scan_mode == '2':
            ports = range(1, 1025)
            print(f"\nScanning ports 1-1024...")
        elif scan_mode == '3':
            try:
                start_port = int(input(f"{C_YELLOW}Enter start port (1-65535): {C_RESET}") or "1")
                end_port = int(input(f"{C_YELLOW}Enter end port (1-65535): {C_RESET}") or "1024")
                if start_port > end_port:
                    start_port, end_port = end_port, start_port
                ports = range(start_port, end_port + 1)
                print(f"\nScanning ports {start_port}-{end_port}...")
            except ValueError:
                print(f"\n{C_RED}Invalid port number{C_RESET}")
                input("\nPress Enter to return...")
                return
        elif scan_mode == '4':
            port_input = input(f"{C_YELLOW}Enter ports separated by commas (e.g. 80,443,8080): {C_RESET}")
            try:
                ports = [int(p.strip()) for p in port_input.split(',') if p.strip()]
                print(f"\nScanning {len(ports)} specified ports...")
            except ValueError:
                print(f"\n{C_RED}Error: Invalid port specification{C_RESET}")
                input("\nPress Enter to return...")
                return
        else:
            print(f"\n{C_RED}Invalid option selected{C_RESET}")
            input("\nPress Enter to return...")
            return
        
        # Get timeout and threads
        try:
            timeout = float(input(f"{C_YELLOW}Enter connection timeout in seconds (0.1-5.0): {C_RESET}") or "1.0")
            max_threads = int(input(f"{C_YELLOW}Enter max threads (1-100): {C_RESET}") or "50")
        except ValueError:
            print(f"\n{C_RED}Invalid input{C_RESET}")
            input("\nPress Enter to return...")
            return
        
        # Initialize counters and results
        open_ports = []
        closed_ports = 0
        filtered_ports = 0
        start_time = time.time()
        
        # Show scanning animation
        animation_thread = threading.Thread(target=self._scan_animation)
        animation_thread.daemon = True
        self.running = True
        animation_thread.start()
        
        try:
            # Function to scan a single port
            def scan_port(port):
                nonlocal closed_ports, filtered_ports
                
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(timeout)
                    result = s.connect_ex((ip, port))
                    
                    if result == 0:  # Port is open
                        try:
                            service = socket.getservbyport(port)
                        except:
                            service = "unknown"
                        open_ports.append((port, service))
                    else:
                        closed_ports += 1
                    s.close()
                except:
                    filtered_ports += 1
            
            # Scan ports using thread pool
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
                executor.map(scan_port, ports)
        
        finally:
            self.running = False
            animation_thread.join(timeout=1)
        
        # Calculate scan time
        scan_time = time.time() - start_time
        
        # Display results
        self.clear_screen()
        self.print_banner()
        print(f"{C_CYAN}Port Scan Results for {target} ({ip}){C_RESET}\n")
        print(f"{C_YELLOW}Scan completed in {scan_time:.2f} seconds{C_RESET}")
        print(f"Scanned {len(list(ports)) if not isinstance(ports, list) else len(ports)} ports\n")
        
        print(f"{C_GREEN}Open Ports:{C_RESET} {len(open_ports)}")
        print(f"{C_RED}Closed Ports:{C_RESET} {closed_ports}")
        print(f"{C_YELLOW}Filtered/Unavailable Ports:{C_RESET} {filtered_ports}\n")
        
        if open_ports:
            print(f"{C_CYAN}Open Port Details:{C_RESET}")
            print("╔═════════╤═══════════════════════╗")
            print("║  PORT   │  SERVICE              ║")
            print("╟─────────┼───────────────────────╢")
            for port, service in sorted(open_ports):
                print(f"║ {port:7d} │ {service:21} ║")
            print("╚═════════╧═══════════════════════╝")
        else:
            print(f"{C_RED}No open ports found.{C_RESET}")
        
        # Ask to save results
        save_choice = input(f"\n{C_YELLOW}Save results to file? (y/n): {C_RESET}")
        if save_choice.lower() == 'y':
            filename = f"port_scan_{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            
            try:
                with open(filename, 'w') as f:
                    f.write(f"Port Scan Results for {target} ({ip})\n")
                    f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"Scan Duration: {scan_time:.2f} seconds\n")
                    f.write(f"Scanned Ports: {len(list(ports)) if not isinstance(ports, list) else len(ports)}\n\n")
                    
                    f.write(f"Open Ports: {len(open_ports)}\n")
                    f.write(f"Closed Ports: {closed_ports}\n")
                    f.write(f"Filtered/Unavailable Ports: {filtered_ports}\n\n")
                    
                    if open_ports:
                        f.write("Open Port Details:\n")
                        f.write("PORT      SERVICE\n")
                        f.write("-----------------\n")
                        for port, service in sorted(open_ports):
                            f.write(f"{port:5d}      {service}\n")
                
                print(f"\n{C_GREEN}Results saved to {filename}{C_RESET}")
            except Exception as e:
                print(f"\n{C_RED}Error saving results: {str(e)}{C_RESET}")
        
        input("\nPress Enter to return...")

    def _run_ip_range_scan(self):
        """Scan an IP range for specific ports"""
        self.clear_screen()
        self.print_banner()
        print(f"{C_CYAN}IP Range Scanner{C_RESET}\n")
        
        print("IP Range Format Options:")
        print(f"{C_GREEN}[1]{C_RESET} CIDR notation (e.g., 192.168.1.0/24)")
        print(f"{C_GREEN}[2]{C_RESET} Range with start/end IPs (e.g., 192.168.1.1-192.168.1.254)")
        print(f"{C_GREEN}[3]{C_RESET} Range with wildcard (e.g., 192.168.1.*)")
        
        range_format = input(f"\n{C_YELLOW}Select IP range format: {C_RESET}")
        
        ip_list = []
        
        if range_format == '1':  # CIDR
            cidr = input(f"{C_YELLOW}Enter IP range in CIDR notation (e.g., 192.168.1.0/24): {C_RESET}")
            try:
                # Simple CIDR parsing for common masks
                ip_parts = cidr.split('/')
                if len(ip_parts) != 2:
                    raise ValueError("Invalid CIDR format")
                
                base_ip = ip_parts[0]
                mask_bits = int(ip_parts[1])
                
                if not 0 <= mask_bits <= 32:
                    raise ValueError("Invalid mask bits")
                
                # Convert IP to integer
                ip_int = self._ip_to_int(base_ip)
                
                # Calculate number of IPs in range
                ip_count = 2 ** (32 - mask_bits)
                
                # Get network address (bitwise AND with mask)
                network_ip_int = ip_int & ((2 ** 32 - 1) - (2 ** (32 - mask_bits) - 1))
                
                # Generate IPs in range
                for i in range(ip_count):
                    # Skip network address (i=0) and broadcast address (i=ip_count-1) 
                    # for masks smaller than /31
                    if mask_bits < 31 and (i == 0 or i == ip_count - 1):
                        continue
                    
                    current_ip_int = network_ip_int + i
                    ip_list.append(self._int_to_ip(current_ip_int))
                
                print(f"\nGenerated {len(ip_list)} IP addresses from {cidr}")
            except Exception as e:
                print(f"\n{C_RED}Error parsing CIDR: {str(e)}{C_RESET}")
                input("\nPress Enter to return...")
                return
            
        elif range_format == '2':  # Start-End
            start_ip = input(f"{C_YELLOW}Enter start IP address: {C_RESET}")
            end_ip = input(f"{C_YELLOW}Enter end IP address: {C_RESET}")
            
            try:
                start_ip_int = self._ip_to_int(start_ip)
                end_ip_int = self._ip_to_int(end_ip)
                
                if start_ip_int > end_ip_int:
                    start_ip_int, end_ip_int = end_ip_int, start_ip_int
                
                # Limit to reasonable range
                if end_ip_int - start_ip_int > 10000:
                    print(f"{C_YELLOW}Warning: Large IP range detected. Limiting to first 10000 addresses.{C_RESET}")
                    end_ip_int = start_ip_int + 10000
                
                for ip_int in range(start_ip_int, end_ip_int + 1):
                    ip_list.append(self._int_to_ip(ip_int))
                
                print(f"\nGenerated {len(ip_list)} IP addresses from {start_ip} to {end_ip}")
            except Exception as e:
                print(f"\n{C_RED}Error generating IP range: {str(e)}{C_RESET}")
                input("\nPress Enter to return...")
                return
            
        elif range_format == '3':  # Wildcard
            wildcard_ip = input(f"{C_YELLOW}Enter IP with wildcard (e.g., 192.168.1.*): {C_RESET}")
            
            try:
                if not wildcard_ip.endswith('.*'):
                    raise ValueError("IP must end with '.*'")
                
                base_ip = wildcard_ip.rstrip('.*')
                
                if not base_ip.endswith('.'):
                    base_ip += '.'
                
                # Generate all IPs in the last octet
                for i in range(1, 255):
                    ip_list.append(f"{base_ip}{i}")
                
                print(f"\nGenerated {len(ip_list)} IP addresses from {wildcard_ip}")
            except Exception as e:
                print(f"\n{C_RED}Error generating IP range: {str(e)}{C_RESET}")
                input("\nPress Enter to return...")
                return
        else:
            print(f"\n{C_RED}Invalid option selected{C_RESET}")
            input("\nPress Enter to return...")
            return
        
        # Get ports to scan
        print(f"\n{C_CYAN}Select ports to scan:{C_RESET}")
        print(f"{C_GREEN}[1]{C_RESET} Single port")
        print(f"{C_GREEN}[2]{C_RESET} Multiple specific ports")
        print(f"{C_GREEN}[3]{C_RESET} Common ports")
        
        port_option = input(f"\n{C_YELLOW}Select option: {C_RESET}")
        
        ports = []
        if port_option == '1':
            try:
                port = int(input(f"{C_YELLOW}Enter port number (1-65535): {C_RESET}"))
                if 1 <= port <= 65535:
                    ports = [port]
                else:
                    print(f"{C_RED}Invalid port number{C_RESET}")
                    input("\nPress Enter to return...")
                    return
            except ValueError:
                print(f"{C_RED}Invalid port number{C_RESET}")
                input("\nPress Enter to return...")
                return
        elif port_option == '2':
            try:
                port_input = input(f"{C_YELLOW}Enter ports separated by commas (e.g. 80,443,8080): {C_RESET}")
                ports = [int(p.strip()) for p in port_input.split(',') if p.strip()]
                
                # Validate ports
                for port in ports:
                    if not 1 <= port <= 65535:
                        raise ValueError(f"Invalid port: {port}")
            except ValueError as e:
                print(f"{C_RED}Error: {str(e)}{C_RESET}")
                input("\nPress Enter to return...")
                return
        elif port_option == '3':
            # Common ports
            ports = [21, 22, 23, 25, 53, 80, 110, 123, 143, 443, 465, 587, 993, 995, 3306, 3389, 5432, 8080, 8443]
        else:
            print(f"\n{C_RED}Invalid option selected{C_RESET}")
            input("\nPress Enter to return...")
            return
        
        # Get scan settings
        try:
            timeout = float(input(f"\n{C_YELLOW}Enter connection timeout in seconds (0.1-5.0): {C_RESET}") or "0.5")
            max_threads = int(input(f"{C_YELLOW}Enter max threads (1-200): {C_RESET}") or "100")
        except ValueError:
            print(f"\n{C_RED}Invalid input{C_RESET}")
            input("\nPress Enter to return...")
            return
        
        # Initialize results
        results = []
        start_time = time.time()
        active_hosts = 0
        scanned_hosts = 0
        total_hosts = len(ip_list)
        
        # Show scanning animation and progress
        self.scan_progress = 0
        animation_thread = threading.Thread(target=self._scan_progress_animation, args=(total_hosts,))
        animation_thread.daemon = True
        self.running = True
        animation_thread.start()
        
        try:
            # Function to scan a single IP for specified ports
            def scan_ip(ip):
                nonlocal active_hosts, scanned_hosts
                
                open_ports_on_host = []
                host_active = False
                
                for port in ports:
                    try:
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s.settimeout(timeout)
                        result = s.connect_ex((ip, port))
                        
                        if result == 0:  # Port is open
                            try:
                                service = socket.getservbyport(port)
                            except:
                                service = "unknown"
                            open_ports_on_host.append((port, service))
                            host_active = True
                        
                        s.close()
                    except:
                        pass
                
                if host_active:
                    active_hosts += 1
                    results.append((ip, open_ports_on_host))
                
                scanned_hosts += 1
                self.scan_progress = scanned_hosts
            
            # Scan IPs using thread pool
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
                executor.map(scan_ip, ip_list)
        
        finally:
            self.running = False
            animation_thread.join(timeout=1)
        
        # Calculate scan time
        scan_time = time.time() - start_time
        
        # Display results
        self.clear_screen()
        self.print_banner()
        print(f"{C_CYAN}IP Range Scan Results{C_RESET}\n")
        print(f"{C_YELLOW}Scan completed in {scan_time:.2f} seconds{C_RESET}")
        print(f"Scanned {total_hosts} hosts for {len(ports)} ports")
        print(f"Active hosts: {active_hosts} ({active_hosts/total_hosts*100:.1f}%)\n")
        
        if results:
            print(f"{C_CYAN}Active Hosts with Open Ports:{C_RESET}")
            
            for ip, open_ports in results:
                if open_ports:
                    hostname = "Unknown"
                    try:
                        hostname = socket.gethostbyaddr(ip)[0]
                    except:
                        pass
                    
                    print(f"\n{C_GREEN}{ip}{C_RESET} ({hostname})")
                    print("  PORT     SERVICE")
                    print("  ------------------")
                    for port, service in sorted(open_ports):
                        print(f"  {port:5d}    {service}")
        else:
            print(f"{C_RED}No active hosts found with open ports.{C_RESET}")
        
        # Ask to save results
        save_choice = input(f"\n{C_YELLOW}Save results to file? (y/n): {C_RESET}")
        if save_choice.lower() == 'y':
            filename = f"ip_range_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            
            try:
                with open(filename, 'w') as f:
                    f.write(f"IP Range Scan Results\n")
                    f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"Scan Duration: {scan_time:.2f} seconds\n")
                    f.write(f"Scanned Hosts: {total_hosts}\n")
                    f.write(f"Scanned Ports: {', '.join(str(p) for p in ports)}\n")
                    f.write(f"Active Hosts: {active_hosts} ({active_hosts/total_hosts*100:.1f}%)\n\n")
                    
                    if results:
                        f.write("Active Hosts with Open Ports:\n")
                        f.write("==============================\n\n")
                        
                        for ip, open_ports in results:
                            if open_ports:
                                hostname = "Unknown"
                                try:
                                    hostname = socket.gethostbyaddr(ip)[0]
                                except:
                                    pass
                                
                                f.write(f"{ip} ({hostname})\n")
                                f.write("  PORT     SERVICE\n")
                                f.write("  ------------------\n")
                                for port, service in sorted(open_ports):
                                    f.write(f"  {port:5d}    {service}\n")
                                f.write("\n")
                    else:
                        f.write("No active hosts found with open ports.\n")
                
                print(f"\n{C_GREEN}Results saved to {filename}{C_RESET}")
            except Exception as e:
                print(f"\n{C_RED}Error saving results: {str(e)}{C_RESET}")
        
        input("\nPress Enter to return...")

    def _ip_to_int(self, ip):
        """Convert an IP address to integer"""
        octets = ip.split('.')
        if len(octets) != 4:
            raise ValueError("Invalid IP address format")
            
        return int(octets[0]) << 24 | int(octets[1]) << 16 | int(octets[2]) << 8 | int(octets[3])

    def _int_to_ip(self, ip_int):
        """Convert an integer to IP address"""
        return f"{(ip_int >> 24) & 0xFF}.{(ip_int >> 16) & 0xFF}.{(ip_int >> 8) & 0xFF}.{ip_int & 0xFF}"

    def _scan_animation(self):
        """Display a simple scanning animation"""
        animation_chars = ['|', '/', '-', '\\']
        i = 0
        
        while self.running:
            self.clear_screen()
            self.print_banner()
            print(f"{C_CYAN}Scanning in progress... {animation_chars[i]}{C_RESET}")
            print(f"{C_YELLOW}Please wait, this may take some time.{C_RESET}")
            
            i = (i + 1) % len(animation_chars)
            time.sleep(0.1)

    def _scan_progress_animation(self, total):
        """Display a scanning animation with progress"""
        animation_chars = ['|', '/', '-', '\\']
        i = 0
        
        while self.running:
            self.clear_screen()
            self.print_banner()
            
            progress = int((self.scan_progress / total) * 100) if total > 0 else 0
            bar_length = 40
            filled_length = int(bar_length * self.scan_progress / total) if total > 0 else 0
            bar = f"{C_GREEN}{'█' * filled_length}{C_RESET}{'░' * (bar_length - filled_length)}"
            
            print(f"{C_CYAN}Scanning in progress... {animation_chars[i]}{C_RESET}")
            print(f"{C_YELLOW}Hosts scanned: {self.scan_progress}/{total} ({progress}%){C_RESET}")
            print(f"[{bar}]")
            print(f"{C_YELLOW}Please wait, this may take some time.{C_RESET}")
            
            i = (i + 1) % len(animation_chars)
            time.sleep(0.1)
    
    def run(self):
        while True:
            self.print_menu()
            choice = input(f"{C_YELLOW}Please select an option: {C_RESET}")
            
            if choice == '1':
                self.set_target()
            elif choice == '2':
                self.set_protocol()
            elif choice == '3':
                self.set_threads()
            elif choice == '4':
                self.set_duration()
            elif choice == '5':
                self.set_packet_size()
            elif choice == '6':
                self.set_advanced_options()
            elif choice == '7':
                self.save_load_config()
            elif choice == '8':
                self.start_test()
            elif choice == '9':
                self.run_port_scanner()
            elif choice == '10':
                self.configure_ip_spoofing()
            elif choice == '0':
                self.clear_screen()
                print(f"{C_GREEN}Thanks for using this tool!{C_RESET}")
                sys.exit(0)
            else:
                print(f"\n{C_RED}Invalid option!{C_RESET}")
                input("\nPress Enter to continue...")

if __name__ == "__main__":
    print(f"{C_YELLOW}Loading Network Load Testing Tool v2.0...{C_RESET}")
    time.sleep(0.5)
    tester = NetworkLoadTester()
    try:
        tester.run()
    except KeyboardInterrupt:
        print(f"\n{C_RED}Program terminated{C_RESET}")
        sys.exit(0)
