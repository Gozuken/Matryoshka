#!/usr/bin/env python3
"""
Matryoshka Anonymous Messenger - Client Interface
Person 3 - Client Implementation (Enhanced for Production)
"""

import argparse
import json
import re
import sys
import time
import os
from typing import List, Dict, Optional, Tuple
import requests
from requests.exceptions import RequestException, ConnectionError, Timeout

try:
    from core.circuit_builder import build_circuit, send_through_circuit
except ImportError:
    print("✗ Error: core.circuit_builder module not found. Please ensure it exists.")
    sys.exit(1)


# Configuration class for better management
class Config:
    """Configuration manager for the client."""
    
    def __init__(self, server_ip: Optional[str] = None, directory_port: int = 5000):
        """
        Initialize configuration.
        
        Args:
            server_ip: IP address of the server (e.g., "1.2.3.4")
            directory_port: Port for directory service (default: 5000)
        """
        # Priority: CLI arg > Environment variable > Default (localhost)
        self.server_ip = server_ip or os.environ.get('MATRYOSHKA_SERVER_IP', 'localhost')
        self.directory_port = directory_port
        self.directory_url = f"http://{self.server_ip}:{self.directory_port}/relays"
    
    def get_directory_url(self) -> str:
        """Get the full directory URL."""
        return self.directory_url
    
    def __str__(self) -> str:
        return f"Server: {self.server_ip}, Directory: {self.directory_url}"


# Try to force UTF-8 output on Windows consoles (best-effort)
try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except Exception:
    pass

# Status prefixes (ASCII to avoid UnicodeEncodeError on some Windows codepages)
OK_PREFIX = "[OK]"
ERR_PREFIX = "[ERR]"
INFO_PREFIX = "[INFO]"

# ANSI color codes for terminal output
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def print_header(config: Config):
    """Print the application header with configuration info."""
    print(f"{Colors.HEADER}{Colors.BOLD}{'=' * 45}")
    print("=== Matryoshka Anonymous Messenger ===")
    print(f"{'=' * 45}{Colors.ENDC}")
    print(f"{Colors.OKCYAN}Configuration: {config}{Colors.ENDC}\n")


def print_success(message: str):
    """Print a success message."""
    print(f"{Colors.OKGREEN}{OK_PREFIX} {message}{Colors.ENDC}")


def print_error(message: str):
    """Print an error message."""
    print(f"{Colors.FAIL}{ERR_PREFIX} Error: {message}{Colors.ENDC}")


def print_info(message: str, verbose: bool = False):
    """Print an info message (only if verbose)."""
    if verbose:
        print(f"{Colors.OKCYAN}{INFO_PREFIX} {message}{Colors.ENDC}")


def query_directory(directory_url: str, verbose: bool = False) -> Optional[List[Dict]]:
    """
    Query the directory server for available relays.
    
    Args:
        directory_url: URL of the directory server endpoint
        verbose: Enable verbose output
        
    Returns:
        List of relay dictionaries or None on error
    """
    try:
        print_info(f"Querying directory server at {directory_url}...", verbose=verbose)
        response = requests.get(directory_url, timeout=10)
        response.raise_for_status()
        
        data = response.json()
        
        if "relays" not in data:
            print_error("Invalid response format from directory server")
            return None
        
        relays = data.get("relays", [])
        count = data.get("count", len(relays))
        
        print_success(f"Found {count} relays")
        return relays
        
    except ConnectionError:
        print_error("Directory server is down or unreachable")
        print_info(f"Make sure the directory server is running at {directory_url}", verbose=True)
        return None
    except Timeout:
        print_error("Directory server request timed out")
        return None
    except RequestException as e:
        print_error(f"Network error while querying directory: {str(e)}")
        return None
    except json.JSONDecodeError:
        print_error("Invalid JSON response from directory server")
        return None
    except Exception as e:
        print_error(f"Unexpected error querying directory: {str(e)}")
        return None


def validate_destination(destination: str) -> Tuple[bool, Optional[str]]:
    """
    Validate destination format (IP:PORT).
    
    Args:
        destination: Destination string in format IP:PORT
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not destination:
        return False, "Destination cannot be empty"
    
    # Pattern: IP:PORT
    pattern = r'^(\d{1,3}\.){3}\d{1,3}:\d{1,5}$'
    if not re.match(pattern, destination):
        return False, "Invalid destination format. Expected IP:PORT (e.g., 192.168.1.1:8080)"
    
    parts = destination.split(':')
    ip_parts = parts[0].split('.')
    port = int(parts[1])
    
    # Validate IP range
    for part in ip_parts:
        num = int(part)
        if num < 0 or num > 255:
            return False, "Invalid IP address. Each octet must be 0-255"
    
    # Validate port range
    if port < 1 or port > 65535:
        return False, "Invalid port. Must be between 1 and 65535"
    
    return True, None


def display_circuit_info(circuit: object, num_relays: int, verbose: bool = False):
    """
    Display circuit details to user.
    
    Args:
        circuit: The circuit object
        num_relays: Number of relays in the circuit
        verbose: Enable verbose output
    """
    if verbose and hasattr(circuit, '__dict__'):
        print_info(f"Circuit object: {type(circuit).__name__}", verbose=verbose)
        print_info(f"Circuit details: {circuit.__dict__}", verbose=verbose)


def build_circuit_with_relays(num_relays: int, config: Config, verbose: bool = False) -> Optional[object]:
    """
    Build a circuit using available relays.
    
    Args:
        num_relays: Number of relays to use in the circuit
        config: Configuration object with directory URL
        verbose: Enable verbose output
        
    Returns:
        Circuit object or None on error
    """
    print("Building circuit...")
    
    try:
        directory_url = config.get_directory_url()
        circuit = build_circuit(num_relays=num_relays, directory_url=directory_url)

        print_success(f"Selected {num_relays} relays for circuit")
        print_success("Circuit established")
        
        # Display circuit info if verbose
        display_circuit_info(circuit, num_relays, verbose)
        
        return circuit
        
    except Exception as e:
        print_error(f"Failed to build circuit: {str(e)}")
        if verbose:
            import traceback
            traceback.print_exc()
        return None


def send_message(circuit: object, message: str, destination: str, config: Config, verbose: bool = False) -> Tuple[bool, Optional[str]]:
    """
    Send anonymous message through circuit and print status.
    
    Args:
        circuit: The circuit object to send through
        message: Message content to send
        destination: Destination in IP:PORT format
        config: Configuration object
        verbose: Enable verbose output
        
    Returns:
        Tuple of (success: bool, response: Optional[str])
    """
    if not circuit:
        print_error("No circuit available")
        return False, None
    
    if not message or not message.strip():
        print_error("Message cannot be empty")
        return False, None
    
    # Validate destination
    is_valid, error_msg = validate_destination(destination)
    if not is_valid:
        print_error(error_msg)
        return False, None
    
    print("Sending message...")
    print_info(f"Sending message to {destination}...", verbose=verbose)
    print_info(f"Message length: {len(message)} bytes", verbose=verbose)
    
    start_time = time.time()
    
    try:
        # Send through circuit
        directory_url = config.get_directory_url()
        print_info(f"Using directory: {directory_url}", verbose=verbose)
        result = send_through_circuit(circuit, message, destination, directory_url=directory_url)
        
        elapsed = time.time() - start_time
        
        # Handle result (could be bool or tuple)
        if isinstance(result, tuple):
            success = result[0]
            response = result[1] if len(result) > 1 else None
        else:
            success = bool(result)
            response = None
        
        if success:
            print_success(f"Message delivered in {elapsed:.2f}s")
            if response and verbose:
                print_info(f"Response: {response}", verbose=verbose)
            return True, response
        else:
            print_error("Message delivery failed")
            return False, response
            
    except ConnectionError as e:
        print_error(f"Connection error: {str(e)}")
        return False, None
    except Timeout:
        print_error("Request timed out")
        return False, None
    except Exception as e:
        print_error(f"Unexpected error sending message: {str(e)}")
        if verbose:
            import traceback
            traceback.print_exc()
        return False, None


def interactive_mode(config: Config, verbose: bool = False):
    """
    Run the client in interactive mode.
    
    Args:
        config: Configuration object
        verbose: Enable verbose output
    """
    print_header(config)
    
    # Query directory to verify connection
    directory_url = config.get_directory_url()
    relays = query_directory(directory_url, verbose=verbose)
    
    if not relays:
        print_error("Cannot proceed without relay information")
        print_info("Tip: Make sure your server is running and accessible", verbose=True)
        print_info(f"Expected directory at: {directory_url}", verbose=True)
        return
    
    # Build initial circuit
    circuit = build_circuit_with_relays(num_relays=3, config=config, verbose=verbose)
    
    if not circuit:
        print_error("Failed to establish initial circuit. Exiting.")
        return
    
    print(f"\n{Colors.BOLD}Ready to send messages!{Colors.ENDC}\n")
    
    # Main loop
    while True:
        try:
            # Get destination
            print(f"{Colors.BOLD}Enter destination (IP:PORT):{Colors.ENDC} ", end='')
            destination = input().strip()
            
            if not destination:
                print_error("Destination cannot be empty")
                continue
            
            # Validate destination
            is_valid, error_msg = validate_destination(destination)
            if not is_valid:
                print_error(error_msg)
                continue
            
            # Get message
            print(f"{Colors.BOLD}Enter message:{Colors.ENDC} ", end='')
            message = input().strip()
            
            if not message:
                print_error("Message cannot be empty")
                continue
            
            # Send message
            success, response = send_message(circuit, message, destination, config=config, verbose=verbose)
            
            if success:
                print(f"\n{Colors.OKGREEN}{Colors.BOLD}Message sent anonymously{Colors.ENDC}\n")
            else:
                print(f"\n{Colors.FAIL}{Colors.BOLD}Failed to send message.{Colors.ENDC}\n")
            
            # Ask if user wants to continue
            print(f"{Colors.BOLD}Send another message? (y/n):{Colors.ENDC} ", end='')
            continue_choice = input().strip().lower()
            
            if continue_choice not in ['y', 'yes']:
                print(f"\n{Colors.OKCYAN}Goodbye!{Colors.ENDC}\n")
                break
                
        except KeyboardInterrupt:
            print(f"\n\n{Colors.WARNING}Interrupted by user.{Colors.ENDC}")
            print(f"{Colors.OKCYAN}Goodbye!{Colors.ENDC}\n")
            break
        except EOFError:
            print(f"\n\n{Colors.OKCYAN}Goodbye!{Colors.ENDC}\n")
            break
        except Exception as e:
            print_error(f"Unexpected error: {str(e)}")
            if verbose:
                import traceback
                traceback.print_exc()


def _build_http_get_request(path: str, host: str) -> str:
    """Build an HTTP GET request string."""
    if not path.startswith('/'):
        path = '/' + path

    return (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "User-Agent: matryoshka-cli\r\n"
        "Accept: */*\r\n"
        "Connection: close\r\n"
        "\r\n"
    )


def main():
    """Main entry point for the client."""
    parser = argparse.ArgumentParser(
        description="Matryoshka Anonymous Messenger - Client Interface",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Connect to remote server
  python client.py --server 1.2.3.4
  
  # Send a message non-interactively
  python client.py --server 1.2.3.4 -m "Hello" -d "10.0.0.1:8080"
  
  # Send HTTP GET request
  python client.py --server 1.2.3.4 --http-get / -d "10.0.0.1:8080"
  
  # Use environment variable for server
  export MATRYOSHKA_SERVER_IP=1.2.3.4
  python client.py

Environment Variables:
  MATRYOSHKA_SERVER_IP    Server IP address (default: localhost)
        """
    )
    
    # Configuration arguments
    parser.add_argument(
        '--server', '-s',
        type=str,
        help='Server IP address (e.g., 1.2.3.4). Can also use MATRYOSHKA_SERVER_IP env var.'
    )
    
    parser.add_argument(
        '--directory-port',
        type=int,
        default=5000,
        help='Directory service port (default: 5000)'
    )
    
    # Message arguments
    parser.add_argument(
        '--message', '-m',
        type=str,
        help='Message to send (non-interactive mode)'
    )

    parser.add_argument(
        '--http-get',
        type=str,
        help='Send an HTTP GET request instead of a raw message. Value is the path (e.g. / or /health).'
    )

    parser.add_argument(
        '--http-host',
        type=str,
        help='Host header to use with --http-get (default: destination IP)'
    )

    parser.add_argument(
        '--http-save',
        type=str,
        default=None,
        help='If provided, save HTTP response body to this file'
    )
    
    parser.add_argument(
        '--dest', '-d',
        type=str,
        help='Destination in IP:PORT format (non-interactive mode)'
    )
    
    # Other options
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose output'
    )
    
    parser.add_argument(
        '--no-open',
        action='store_true',
        help="Do not open HTML responses in a browser (useful for servers/gateways)"
    )
    
    args = parser.parse_args()
    
    # Create configuration
    config = Config(server_ip=args.server, directory_port=args.directory_port)

    # Non-interactive mode: raw message
    if args.message and args.dest:
        print_header(config)
        
        circuit = build_circuit_with_relays(num_relays=3, config=config, verbose=args.verbose)
        if circuit is None:
            sys.exit(1)
        
        success, _response = send_message(circuit, args.message, args.dest, config=config, verbose=args.verbose)
        sys.exit(0 if success else 1)

    # Non-interactive mode: HTTP GET
    if args.http_get and args.dest:
        print_header(config)

        dest_ip = args.dest.split(':', 1)[0]
        host = args.http_host or dest_ip
        http_req = _build_http_get_request(args.http_get, host)

        circuit = build_circuit_with_relays(num_relays=3, config=config, verbose=args.verbose)
        if circuit is None:
            sys.exit(1)

        success, response = send_message(circuit, http_req, args.dest, config=config, verbose=args.verbose)

        # If response appears to be an HTTP response, try to render HTML content
        if response:
            resp_strip = response.lstrip()
            body_to_open = None
            body_to_save = None
            if resp_strip.startswith("HTTP/"):
                try:
                    header, body = resp_strip.split("\r\n\r\n", 1)
                    # Check Content-Type header for HTML
                    if "content-type" in header.lower() and "html" in header.lower():
                        body_to_open = body
                    # If --http-save requested, save the body
                    if args.http_save:
                        body_to_save = body
                except ValueError:
                    pass
            elif "<html" in response.lower() or response.lstrip().startswith("<"):
                body_to_open = response
                if args.http_save:
                    body_to_save = response

            if body_to_open is not None:
                if not args.no_open:
                    try:
                        import tempfile, webbrowser

                        t = tempfile.NamedTemporaryFile(delete=False, suffix=".html", mode="w", encoding="utf-8")
                        t.write(body_to_open)
                        t.flush()
                        t.close()
                        print_info(f"Opening HTML response in browser: {t.name}", verbose=args.verbose)
                        webbrowser.open("file://" + t.name)
                    except Exception:
                        print_error("Failed to open HTML response in browser")
                else:
                    # Print a short message indicating HTML was received
                    print_info("HTML response received (not opening browser due to --no-open).", verbose=True)

            if args.http_save and body_to_save is not None:
                try:
                    path = args.http_save
                    with open(path, 'wb') as f:
                        f.write(body_to_save.encode('utf-8'))
                    print_success(f"Saved HTTP response body to {path}")
                except Exception as e:
                    print_error(f"Failed to save HTTP response: {e}")

        sys.exit(0 if success else 1)

    # Bad args cases
    if args.message or args.http_get or args.dest:
        print_error("Provide either (--message and --dest) or (--http-get and --dest)")
        parser.print_help()
        sys.exit(1)

    # Default: interactive mode
    interactive_mode(config=config, verbose=args.verbose)


if __name__ == "__main__":
    main()


"""
README - Matryoshka Anonymous Messenger Client (Production Version)

QUICK START:
    # Connect to your server (replace with your actual server IP)
    python client.py --server YOUR_SERVER_IP
    
    # Or set environment variable
    export MATRYOSHKA_SERVER_IP=YOUR_SERVER_IP
    python client.py

USAGE MODES:
    1. Interactive mode (recommended for testing):
        python client.py --server 1.2.3.4
        python client.py --server 1.2.3.4 --verbose
    
    2. Non-interactive mode (good for scripts):
        python client.py --server 1.2.3.4 --message "Hello" --dest "10.0.0.1:8080"
        python client.py -s 1.2.3.4 -m "Hello" -d "10.0.0.1:5000" -v
    
    3. HTTP mode (fetch web pages anonymously):
        python client.py --server 1.2.3.4 --http-get / --dest "10.0.0.1:80"

CONFIGURATION:
    Server IP can be specified via:
    1. Command line: --server 1.2.3.4 (highest priority)
    2. Environment: export MATRYOSHKA_SERVER_IP=1.2.3.4
    3. Default: localhost (for local testing)
    
    Directory port defaults to 5000 (can be changed with --directory-port)

FEATURES:
    - Production-ready server configuration
    - Environment variable support for deployment
    - CLI interface with colored output
    - Directory server query for relay discovery
    - Circuit building with configurable relay count
    - Anonymous message sending through multi-hop circuit
    - HTTP GET request support
    - Input validation for destinations
    - Comprehensive error handling
    - Loop mode for sending multiple messages
    - Verbose mode for debugging

REQUIREMENTS:
    - Python 3.6+
    - requests library: pip install requests
    - core.circuit_builder module (build_circuit, send_through_circuit)

DEPLOYMENT TIPS:
    1. Set MATRYOSHKA_SERVER_IP in your environment for production
    2. Use --verbose flag when debugging connectivity issues
    3. Make sure your server's directory service is running on port 5000
    4. Make sure your relays are accessible from the client machine
    5. Test with a single message before running scripts

TROUBLESHOOTING:
    Q: "Directory server is down or unreachable"
    A: Check that your server is running and accessible at SERVER_IP:5000
    
    Q: "Connection error" when sending messages
    A: Verify relays are running on ports 8000+ and accessible
    
    Q: "Failed to build circuit"
    A: Use --verbose to see detailed error messages

AUTHOR: Person 3 - Client Interface Implementation (Enhanced)
"""
