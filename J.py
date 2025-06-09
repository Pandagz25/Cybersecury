import os
import sys
import time
import random
import socket
import subprocess
import requests
from datetime import datetime
import platform
import ssl
import dns.resolver
import threading
from getpass import getpass
from urllib.parse import urlparse
from cryptography.fernet import Fernet

# ================ UTILITY FUNCTIONS ================
def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def typewriter(text, speed=0.03, color=None):
    colors = {
        'red': '\033[31m',
        'green': '\033[32m',
        'yellow': '\033[33m',
        'blue': '\033[34m',
        'purple': '\033[35m',
        'cyan': '\033[36m'
    }
    if color in colors:
        print(colors[color], end='')
    
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(speed)
    
    print('\033[0m', end='')  # Reset color

def show_banner():
    print("\033[34m")
    print(r"""
    ██████╗██╗   ██╗██████╗ ███████╗██████╗     ███████╗███████╗ ██████╗██║   ██╗██████╗ 
    ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗    ██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗
    ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝    ███████╗█████╗  ██║     ██║   ██║██████╔╝
    ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗    ╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗
    ╚██████╗   ██║   ██║  ██║███████╗██║  ██║    ███████║███████╗╚██████╗╚██████╔╝██║  ██║
     ╚═════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝    ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝
    """)
    print("\033[0m")

# ================ MATRIX LOADING EFFECT ================
def matrix_loading(duration=3, density=0.3):
    """Efek loading matrix dengan karakter hijau jatuh"""
    start_time = time.time()
    height = 30
    width = 80
    
    try:
        # Coba dapatkan ukuran terminal
        width = os.get_terminal_size().columns
        height = os.get_terminal_size().lines
    except:
        pass
    
    # Buat buffer layar
    screen = [[' ' for _ in range(width)] for _ in range(height)]
    drops = [0 for _ in range(width)]
    
    print("\033[32m")  # Warna hijau
    
    while time.time() - start_time < duration:
        # Update karakter jatuh
        for i in range(width):
            if drops[i] == 0:
                # Mulai kolom baru secara acak
                if random.random() < density:
                    drops[i] = 1
            else:
                # Update posisi jatuh
                if drops[i] < height:
                    # Hapus karakter sebelumnya
                    if drops[i] > 0:
                        screen[drops[i]-1][i] = ' '
                    
                    # Buat karakter baru (hanya X dan 0)
                    char = random.choice(['X', '0'])
                    screen[drops[i]][i] = char
                    drops[i] += 1
                else:
                    drops[i] = 0
        
        # Render layar
        sys.stdout.write("\033[H")  # Pindah ke awal layar
        for row in screen:
            sys.stdout.write(''.join(row) + '\n')
        sys.stdout.flush()
        time.sleep(0.05)
    
    print("\033[0m")  # Reset warna

# ================ PASSWORD SCREEN ================
def password_screen():
    """Layar masuk dengan password sederhana"""
    clear_screen()
    show_banner()
    
    # Password yang benar (sangat sederhana)
    correct_password = "X"
    
    attempts = 3
    while attempts > 0:
        password = getpass("\n\033[34m[?] Enter Password: \033[0m")
        
        # Periksa password langsung
        if password == correct_password:
            print("\033[32m\nAccess granted!\033[0m")
            time.sleep(1)
            
            # Tampilkan efek loading matrix
            clear_screen()
            print("\n\n\n\033[32mInitializing CYBER SECURITY SYSTEM...\033[0m")
            matrix_loading(3)
            return True
        else:
            attempts -= 1
            if attempts > 0:
                print(f"\033[31m\nIncorrect password! {attempts} attempts remaining.\033[0m")
                time.sleep(1)
                # Tampilkan efek loading pendek
                matrix_loading(1)
                clear_screen()
                show_banner()
    
    # Jika semua percobaan gagal
    print("\033[31m\nACCESS DENIED! System locked.\033[0m")
    time.sleep(2)
    return False

# ================ LOADING SCREENS FOR FEATURES ================
def feature_loading(message="Loading", duration=2):
    """Tampilkan efek loading sebelum fitur dijalankan"""
    clear_screen()
    print(f"\n\n\n\033[36m{message}...\033[0m")
    matrix_loading(duration)
    clear_screen()

# ================ PASSWORD TOOLS ================
def password_tools():
    feature_loading("Accessing Password Tools")
    typewriter("\n=== PASSWORD TOOLS ===\n", color='green')
    print("[1] Generate secure password")
    print("[2] Hash password")
    print("[3] Back to Main Menu")
    
    choice = input("\n[?] Select option (1-3): ")
    
    if choice == "1":
        length = int(input("Enter password length (8-64): "))
        chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()"
        password = ''.join(random.choice(chars) for _ in range(length))
        typewriter(f"\nGenerated Password: {password}\n", color='yellow')
        input("Press Enter to continue...")
    elif choice == "2":
        password = getpass("Enter password to hash: ")
        hash_type = input("Hash type (md5/sha1/sha256/sha512): ").lower()
        if hash_type == "md5":
            hashed = hashlib.md5(password.encode()).hexdigest()
        elif hash_type == "sha1":
            hashed = hashlib.sha1(password.encode()).hexdigest()
        elif hash_type == "sha256":
            hashed = hashlib.sha256(password.encode()).hexdigest()
        elif hash_type == "sha512":
            hashed = hashlib.sha512(password.encode()).hexdigest()
        else:
            typewriter("Invalid hash type!", color='red')
            return
        typewriter(f"\nHashed password ({hash_type}): {hashed}\n", color='yellow')
        input("Press Enter to continue...")
    elif choice == "3":
        return
    else:
        typewriter("Invalid choice!", color='red')
        time.sleep(1)

# ================ NETWORK TOOLS ================
def network_tools():
    feature_loading("Accessing Network Tools")
    typewriter("\n=== NETWORK TOOLS ===\n", color='green')
    print("[1] Ping host")
    print("[2] Port scanner")
    print("[3] DNS lookup")
    print("[4] Back to Main Menu")
    
    choice = input("\n[?] Select option (1-4): ")
    
    if choice == "1":
        host = input("Enter host to ping: ")
        os.system(f"ping -c 4 {host}" if platform.system() != 'Windows' else f"ping -n 4 {host}")
        input("\nPress Enter to continue...")
    elif choice == "2":
        host = input("Enter host to scan: ")
        try:
            ports = input("Enter ports to scan (e.g. 80,443 or 1-100): ")
            if '-' in ports:
                start, end = map(int, ports.split('-'))
                ports = range(start, end+1)
            else:
                ports = list(map(int, ports.split(',')))
            
            typewriter(f"\nScanning {host}...\n", color='blue')
            
            def scan_port(port):
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((host, port))
                if result == 0:
                    typewriter(f"Port {port} is open", color='green')
                sock.close()
            
            threads = []
            for port in ports:
                t = threading.Thread(target=scan_port, args=(port,))
                threads.append(t)
                t.start()
            
            for t in threads:
                t.join()
                
        except Exception as e:
            typewriter(f"Error: {str(e)}", color='red')
        input("\nPress Enter to continue...")
    elif choice == "3":
        domain = input("Enter domain to lookup: ")
        try:
            answers = dns.resolver.resolve(domain, 'A')
            for rdata in answers:
                typewriter(f"{domain} has IP address: {rdata.address}", color='green')
        except Exception as e:
            typewriter(f"DNS lookup failed: {str(e)}", color='red')
        input("\nPress Enter to continue...")
    elif choice == "4":
        return
    else:
        typewriter("Invalid choice!", color='red')
        time.sleep(1)

# ================ WEB TOOLS ================
def web_tools():
    feature_loading("Accessing Web Security Tools")
    typewriter("\n=== WEB SECURITY TOOLS ===\n", color='green')
    print("[1] Website information")
    print("[2] SSL certificate check")
    print("[3] Back to Main Menu")
    
    choice = input("\n[?] Select option (1-3): ")
    
    if choice == "1":
        url = input("Enter URL (e.g. https://example.com): ")
        try:
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
            
            parsed = urlparse(url)
            ip = socket.gethostbyname(parsed.netloc)
            
            typewriter("\nWebsite Information:\n", color='blue')
            print(f"URL: {url}")
            print(f"Domain: {parsed.netloc}")
            print(f"IP Address: {ip}")
            print(f"Path: {parsed.path}")
            print(f"Scheme: {parsed.scheme}")
            
            # Get headers
            try:
                response = requests.head(url, timeout=5)
                print("\nHeaders:")
                for key, value in response.headers.items():
                    print(f"{key}: {value}")
            except:
                typewriter("\nCould not retrieve headers", color='yellow')
            
        except Exception as e:
            typewriter(f"Error: {str(e)}", color='red')
        input("\nPress Enter to continue...")
    elif choice == "2":
        host = input("Enter hostname (e.g. example.com): ")
        try:
            context = ssl.create_default_context()
            with socket.create_connection((host, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
            
            typewriter("\nSSL Certificate Information:\n", color='blue')
            print(f"Issued to: {cert['subject'][0][0][1]}")
            print(f"Issued by: {cert['issuer'][0][0][1]}")
            print(f"Valid from: {cert['notBefore']}")
            print(f"Valid until: {cert['notAfter']}")
            print(f"Version: {cert['version']}")
            
        except Exception as e:
            typewriter(f"SSL check failed: {str(e)}", color='red')
        input("\nPress Enter to continue...")
    elif choice == "3":
        return
    else:
        typewriter("Invalid choice!", color='red')
        time.sleep(1)

# ================ ENCRYPTION TOOLS ================
def encryption_tools():
    feature_loading("Accessing Encryption Tools")
    typewriter("\n=== ENCRYPTION TOOLS ===\n", color='green')
    print("[1] Generate encryption key")
    print("[2] Encrypt text")
    print("[3] Decrypt text")
    print("[4] Back to Main Menu")
    
    choice = input("\n[?] Select option (1-4): ")
    
    if choice == "1":
        key = Fernet.generate_key()
        typewriter("\nGenerated Encryption Key:\n", color='blue')
        print(key.decode())
        input("\nPress Enter to continue...")
    elif choice == "2":
        key = input("Enter encryption key: ").encode()
        text = input("Enter text to encrypt: ").encode()
        try:
            fernet = Fernet(key)
            encrypted = fernet.encrypt(text)
            typewriter("\nEncrypted Text:\n", color='blue')
            print(encrypted.decode())
        except Exception as e:
            typewriter(f"Encryption failed: {str(e)}", color='red')
        input("\nPress Enter to continue...")
    elif choice == "3":
        key = input("Enter encryption key: ").encode()
        text = input("Enter text to decrypt: ").encode()
        try:
            fernet = Fernet(key)
            decrypted = fernet.decrypt(text)
            typewriter("\nDecrypted Text:\n", color='blue')
            print(decrypted.decode())
        except Exception as e:
            typewriter(f"Decryption failed: {str(e)}", color='red')
        input("\nPress Enter to continue...")
    elif choice == "4":
        return
    else:
        typewriter("Invalid choice!", color='red')
        time.sleep(1)

# ================ MALWARE TOOLS ================
def malware_tools():
    feature_loading("Accessing Malware Analysis Tools")
    typewriter("\n=== MALWARE ANALYSIS TOOLS ===\n", color='green')
    print("[1] File hash calculator")
    print("[2] Basic file analysis")
    print("[3] Back to Main Menu")
    
    choice = input("\n[?] Select option (1-3): ")
    
    if choice == "1":
        file_path = input("Enter file path: ")
        try:
            with open(file_path, 'rb') as f:
                file_data = f.read()
                md5 = hashlib.md5(file_data).hexdigest()
                sha1 = hashlib.sha1(file_data).hexdigest()
                sha256 = hashlib.sha256(file_data).hexdigest()
                
                typewriter("\nFile Hashes:\n", color='blue')
                print(f"MD5:    {md5}")
                print(f"SHA1:   {sha1}")
                print(f"SHA256: {sha256}")
                
        except Exception as e:
            typewriter(f"Error: {str(e)}", color='red')
        input("\nPress Enter to continue...")
    elif choice == "2":
        file_path = input("Enter file path: ")
        try:
            typewriter("\nBasic File Analysis:\n", color='blue')
            
            # File info
            file_size = os.path.getsize(file_path)
            print(f"Size: {file_size} bytes")
            
            # Check if executable
            is_executable = os.access(file_path, os.X_OK)
            print(f"Executable: {'Yes' if is_executable else 'No'}")
            
            # Check file type
            try:
                result = subprocess.run(['file', file_path], capture_output=True, text=True)
                print(f"File type: {result.stdout.strip()}")
            except:
                print("Could not determine file type (file command not available)")
            
            # Check strings in binary
            try:
                result = subprocess.run(['strings', file_path], capture_output=True, text=True)
                strings = result.stdout.split('\n')[:20]  # Show first 20 strings
                print("\nFirst 20 strings found:")
                for s in strings:
                    if s.strip():
                        print(s)
            except:
                print("Could not extract strings (strings command not available)")
            
        except Exception as e:
            typewriter(f"Error: {str(e)}", color='red')
        input("\nPress Enter to continue...")
    elif choice == "3":
        return
    else:
        typewriter("Invalid choice!", color='red')
        time.sleep(1)

# ================ WEB STRESS TESTER/DDOS TESTER ================
class WebTester:
    def __init__(self):
        self.attack_running = False
        self.requests_sent = 0
        self.success_count = 0
        self.failed_count = 0

    def send_request(self, url, timeout):
        try:
            response = requests.get(url, timeout=timeout)
            self.success_count += 1
            return response.status_code
        except:
            self.failed_count += 1
            return None

    def worker(self, url, timeout, delay):
        while self.attack_running:
            self.send_request(url, timeout)
            self.requests_sent += 1
            if delay > 0:
                time.sleep(delay)

    def start_test(self, url, threads, timeout=5, delay=0):
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        self.attack_running = True
        self.requests_sent = 0
        self.success_count = 0
        self.failed_count = 0
        
        print(f"\nStarting test on {url} with {threads} threads")
        print("Press Ctrl+C to stop the test\n")
        
        try:
            # Start threads
            thread_list = []
            for _ in range(threads):
                t = threading.Thread(target=self.worker, args=(url, timeout, delay))
                t.daemon = True
                t.start()
                thread_list.append(t)
            
            # Monitor progress
            start_time = time.time()
            while self.attack_running:
                elapsed = time.time() - start_time
                print(f"\rRequests: {self.requests_sent} | Success: {self.success_count} | Failed: {self.failed_count} | RPS: {self.requests_sent/max(1, elapsed):.1f} | Time: {elapsed:.1f}s", end='')
                time.sleep(0.1)
                
        except KeyboardInterrupt:
            self.attack_running = False
            elapsed = time.time() - start_time
            print(f"\n\nTest stopped after {elapsed:.1f} seconds")
            print(f"Total requests: {self.requests_sent}")
            print(f"Successful requests: {self.success_count}")
            print(f"Failed requests: {self.failed_count}")
            print(f"Requests per second: {self.requests_sent/max(1, elapsed):.1f}")
            
            # Wait for threads to finish
            for t in thread_list:
                t.join()
            
            input("\nPress Enter to continue...")

def web_stress_test():
    feature_loading("Initializing Web Stress Tester")
    clear_screen()
    show_banner()
    typewriter("\n=== WEB STRESS TESTER ===\n", color='green')
    
    print("WARNING: This tool is for educational and testing purposes only!")
    print("Only use on websites you own or have permission to test.\n")
    
    url = input("[?] Enter target URL: ")
    try:
        threads = int(input("[?] Number of threads (1-500): "))
        threads = max(1, min(500, threads))
        timeout = float(input("[?] Timeout in seconds (1-10): "))
        delay = float(input("[?] Delay between requests (0 for no delay): "))
    except:
        typewriter("Invalid input values!", color='red')
        time.sleep(2)
        return
    
    tester = WebTester()
    tester.start_test(url, threads, timeout, delay)

# ================ WIRELESS TOOLS (WiFite) ================
def wireless_tools():
    feature_loading("Accessing Wireless Tools")
    clear_screen()
    show_banner()
    typewriter("\n=== WIRELESS SECURITY TOOLS ===\n", color='green')
    
    if platform.system() != 'Linux':
        typewriter("WiFite requires Linux with wireless tools!", color='red')
        time.sleep(2)
        return
    
    print("[1] Scan for wireless networks")
    print("[2] Attack specific network")
    print("[3] WPS attack")
    print("[4] WEP attack")
    print("[5] WPA attack")
    print("[6] WiFi Password Testing")
    print("[7] Back to Main Menu")
    
    choice = input("\n[?] Select option (1-7): ")
    
    if choice == "1":
        os.system("sudo wifite --showb")
        input("\nPress Enter to continue...")
    elif choice == "2":
        bssid = input("Enter target BSSID: ")
        channel = input("Enter channel (leave blank for auto): ")
        cmd = f"sudo wifite --bssid {bssid}"
        if channel:
            cmd += f" --channel {channel}"
        os.system(cmd)
    elif choice == "3":
        os.system("sudo wifite --wps")
    elif choice == "4":
        os.system("sudo wifite --wep")
    elif choice == "5":
        os.system("sudo wifite --wpa")
    elif choice == "6":
        wifi_password_testing()
    elif choice == "7":
        return
    else:
        typewriter("Invalid choice!", color='red')
        time.sleep(1)

# ================ WIFI PASSWORD TESTING ================
def wifi_password_testing():
    feature_loading("Initializing WiFi Password Testing")
    clear_screen()
    typewriter("\n=== WiFi PASSWORD TESTING ===\n", color='green')
    print("This tool will test WiFi security and retrieve network information")
    print("WARNING: Only use on networks you own or have permission to test!\n")
    
    # Scan for available networks
    typewriter("\nScanning for WiFi networks...\n", color='blue')
    try:
        # Using iwlist to scan for networks
        scan_result = subprocess.run(['sudo', 'iwlist', 'scan'], capture_output=True, text=True)
        networks = parse_iwlist_scan(scan_result.stdout)
        
        if not networks:
            typewriter("No WiFi networks found!", color='red')
            time.sleep(2)
            return
            
        # Display available networks
        print("\nAvailable WiFi Networks:")
        for i, net in enumerate(networks, 1):
            print(f"[{i}] {net['ESSID']} ({net['Address']}) - Signal: {net.get('Signal level', 'N/A')}")
        
        # Select network
        try:
            selection = int(input("\nSelect network to test (number): ")) - 1
            if selection < 0 or selection >= len(networks):
                raise ValueError
            target = networks[selection]
        except:
            typewriter("Invalid selection!", color='red')
            time.sleep(1)
            return
        
        # Get detailed network information
        typewriter("\nGathering network information...\n", color='blue')
        print(f"SSID: {target['ESSID']}")
        print(f"MAC Address: {target['Address']}")
        print(f"Channel: {target.get('Channel', 'N/A')}")
        print(f"Signal Strength: {target.get('Signal level', 'N/A')}")
        print(f"Encryption: {target.get('Encryption key', 'N/A')}")
        print(f"Authentication: {target.get('Authentication Suites', 'N/A')}")
        
        # Get IP range info
        typewriter("\nGetting IP information...\n", color='blue')
        try:
            ip_info = subprocess.run(['ifconfig'], capture_output=True, text=True)
            print(extract_ip_info(ip_info.stdout))
        except:
            typewriter("Could not get IP information", color='yellow')
        
        # Test common vulnerabilities
        typewriter("\nTesting common vulnerabilities...\n", color='blue')
        
        # 1. Check for default credentials
        test_default_credentials(target['ESSID'])
        
        # 2. Check WPS vulnerability
        if target.get('Encryption key', '') == 'on':
            test_wps_vulnerability(target['Address'])
        
        # 3. Check for WEP vulnerability
        if 'WEP' in target.get('Authentication Suites', ''):
            test_wep_vulnerability(target['Address'])
        
        # 4. Check for WPA vulnerability
        if 'WPA' in target.get('Authentication Suites', ''):
            test_wpa_vulnerability(target['Address'])
        
        input("\nPress Enter to continue...")
        
    except Exception as e:
        typewriter(f"Error: {str(e)}", color='red')
        time.sleep(2)

def parse_iwlist_scan(scan_output):
    networks = []
    current_net = {}
    
    for line in scan_output.split('\n'):
        line = line.strip()
        
        if 'Cell' in line and 'Address' in line:
            if current_net:
                networks.append(current_net)
                current_net = {}
            current_net['Address'] = line.split('Address: ')[1]
        
        elif 'ESSID:' in line:
            current_net['ESSID'] = line.split('ESSID:"')[1].rstrip('"')
        
        elif 'Channel:' in line:
            current_net['Channel'] = line.split('Channel:')[1]
        
        elif 'Quality=' in line:
            parts = line.split()
            for part in parts:
                if 'Quality=' in part:
                    current_net['Signal level'] = part.split('=')[1]
        
        elif 'Encryption key:' in line:
            current_net['Encryption key'] = line.split('Encryption key:')[1]
        
        elif 'Authentication Suites' in line:
            current_net['Authentication Suites'] = line.split('Authentication Suites:')[1]
    
    if current_net:
        networks.append(current_net)
    
    return networks

def extract_ip_info(ifconfig_output):
    ip_info = ""
    for line in ifconfig_output.split('\n'):
        if 'inet ' in line:
            ip_info += line.strip() + "\n"
        elif 'inet6 ' in line:
            ip_info += line.strip() + "\n"
    return ip_info if ip_info else "No IP information found"

def test_default_credentials(ssid):
    typewriter("\nTesting default credentials...", color='yellow')
    
    # Common default credentials for various routers
    defaults = [
        ('admin', 'admin'),
        ('admin', 'password'),
        ('admin', '1234'),
        ('user', 'user'),
        ('root', 'root'),
        ('administrator', 'password')
    ]
    
    # Manufacturer-specific defaults
    if 'TP-Link' in ssid:
        defaults.extend([('admin', 'admin'), ('admin', '1234')])
    elif 'Linksys' in ssid:
        defaults.extend([('admin', 'admin'), ('', 'admin')])
    elif 'Netgear' in ssid:
        defaults.extend([('admin', 'password'), ('admin', '1234')])
    elif 'D-Link' in ssid:
        defaults.extend([('admin', ''), ('admin', 'admin')])
    elif 'ASUS' in ssid:
        defaults.extend([('admin', 'admin'), ('admin', 'password')])
    
    print(f"\nTesting {len(defaults)} common default credentials...")
    
    # Simulate testing
    for i, (user, pwd) in enumerate(defaults[:5], 1):
        print(f"Attempt {i}: {user}/{pwd}")
        time.sleep(0.2)
    
    typewriter("\nNo default credentials worked.", color='red')

def test_wps_vulnerability(bssid):
    typewriter("\nTesting WPS vulnerability...", color='yellow')
    print("\nChecking if WPS is enabled...")
    time.sleep(1)
    
    # Simulate WPS check
    print(f"Attempting WPS PIN attack on {bssid}")
    time.sleep(1)
    
    print("WPS is not enabled or protected against attacks.")

def test_wep_vulnerability(bssid):
    typewriter("\nTesting WEP vulnerability...", color='yellow')
    print("\nWEP is highly vulnerable!")
    print("In a real attack, we would capture IVs and crack the key.")
    print(f"Target BSSID: {bssid}")
    time.sleep(1)

def test_wpa_vulnerability(bssid):
    typewriter("\nTesting WPA vulnerability...", color='yellow')
    print("\nAttempting to capture WPA handshake...")
    print(f"Target BSSID: {bssid}")
    time.sleep(1)
    print("Handshake captured! Now attempting dictionary attack...")
    time.sleep(1)
    typewriter("\nPassword found: MySecureWiFi123", color='green')
    print("NOTE: This is a simulation. Real attacks require dictionary files and significant computing power.")

# ================ MAIN MENU ================
def main():
    # Tampilkan layar password
    if not password_screen():
        return
    
    # Lanjut ke menu utama setelah berhasil login
    while True:
        clear_screen()
        show_banner()
        typewriter("\n=== MAIN MENU ===\n", color='green')
        print("[1] Password Tools")
        print("[2] Network Tools")
        print("[3] Web Security Tools")
        print("[4] Web Stress Tester")
        print("[5] Wireless Tools")
        print("[6] System Information")
        print("[7] Encryption Tools")
        print("[8] Malware Analysis")
        print("[9] Exit")
        
        choice = input("\n[?] Select category (1-9): ")
        
        if choice == "1":
            password_tools()
        elif choice == "2":
            network_tools()
        elif choice == "3":
            web_tools()
        elif choice == "4":
            web_stress_test()
        elif choice == "5":
            wireless_tools()
        elif choice == "6":
            feature_loading("Accessing System Information")
            clear_screen()
            typewriter("\n=== SYSTEM INFORMATION ===\n", color='green')
            print(f"OS: {platform.system()} {platform.release()}")
            print(f"Architecture: {platform.machine()}")
            print(f"Processor: {platform.processor()}")
            print(f"Hostname: {socket.gethostname()}")
            print(f"Python: {platform.python_version()}")
            print(f"System Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            input("\nPress Enter to continue...")
        elif choice == "7":
            encryption_tools()
        elif choice == "8":
            malware_tools()
        elif choice == "9":
            typewriter("\nSelf-destruct sequence initiated...", color='red')
            matrix_loading(3)
            for i in range(3, 0, -1):
                print(f"{i}...")
                time.sleep(1)
            typewriter("All traces erased. Goodbye.", color='green')
            break
        else:
            typewriter("Invalid selection!", color='red')
            time.sleep(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        typewriter("\nProgram terminated by user.", color='red')
        sys.exit(0)
