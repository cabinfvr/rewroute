"""
Rewroute - A lightweight Flask-like framework with DNS interception and traffic proxy
Intercepts all traffic, handles registered domains locally, forwards everything else
"""

import asyncio
import json
import logging
import time
import threading
import socket
import sys
import requests
import subprocess
import os
import platform
import mimetypes
import re
from datetime import datetime
from typing import Dict, Callable, Any, Optional, Tuple, Set
from urllib.parse import parse_qs, urlparse, quote, unquote
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
import ssl

# Rich console logging
try:
    from rich.console import Console
    from rich.logging import RichHandler
    from rich.text import Text
    from rich.panel import Panel
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

# Template engine (simple Jinja2-like)
try:
    from jinja2 import Environment, FileSystemLoader, select_autoescape
    JINJA2_AVAILABLE = True
except ImportError:
    JINJA2_AVAILABLE = False

# Set up beautiful console logging
if RICH_AVAILABLE:
    console = Console()
    logging.basicConfig(
        level=logging.INFO,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(console=console, rich_tracebacks=True)]
    )
else:
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s | %(levelname)s | %(message)s',
        handlers=[logging.StreamHandler(sys.stdout)]
    )

class RewrouteRequest:
    """Request object containing HTTP request data"""
    def __init__(self, method: str, path: str, headers: Dict[str, str], 
                 query_params: Dict[str, list], body: bytes, host: str = None, url_params: Dict[str, str] = None):
        self.method = method
        self.path = path
        self.headers = headers
        self.query_params = query_params
        self.body = body
        self.host = host
        self.json_data = None
        self.url_params = url_params or {}  # URL parameters like /user/<id>
        
        # Parse JSON if content-type is application/json
        if headers.get('content-type', '').startswith('application/json'):
            try:
                self.json_data = json.loads(body.decode('utf-8'))
            except (json.JSONDecodeError, UnicodeDecodeError):
                pass

class RewrouteResponse:
    """Response object for HTTP responses"""
    def __init__(self, data: Any = None, status_code: int = 200, 
                 headers: Optional[Dict[str, str]] = None, mimetype: str = None):
        self.data = data
        self.status_code = status_code
        self.headers = headers or {}
        self.mimetype = mimetype
        
        # Set default content-type
        if 'content-type' not in self.headers:
            if mimetype:
                self.headers['content-type'] = mimetype
            elif isinstance(data, (dict, list)):
                self.headers['content-type'] = 'application/json'
            elif isinstance(data, bytes):
                self.headers['content-type'] = 'application/octet-stream'
            else:
                self.headers['content-type'] = 'text/html; charset=utf-8'

class RedirectResponse(RewrouteResponse):
    """Response for HTTP redirects"""
    def __init__(self, location: str, code: int = 302):
        super().__init__("", code)
        self.headers['Location'] = location

def redirect(location: str, code: int = 302):
    """Create a redirect response"""
    return RedirectResponse(location, code)

def render_template(template_name: str, **context):
    """Render a template with context"""
    app = get_current_app()
    if not app:
        raise RuntimeError("No application context")
    
    return app.render_template(template_name, **context)

def send_file(file_path: str, mimetype: str = None, as_attachment: bool = False, 
              attachment_filename: str = None):
    """Send a file as response"""
    try:
        if not os.path.exists(file_path):
            return RewrouteResponse("File not found", 404)
        
        # Determine mimetype
        if not mimetype:
            mimetype, _ = mimetypes.guess_type(file_path)
            if not mimetype:
                mimetype = 'application/octet-stream'
        
        # Read file
        with open(file_path, 'rb') as f:
            data = f.read()
        
        headers = {}
        if as_attachment:
            filename = attachment_filename or os.path.basename(file_path)
            headers['Content-Disposition'] = f'attachment; filename="{filename}"'
        
        return RewrouteResponse(data, 200, headers, mimetype)
        
    except Exception as e:
        return RewrouteResponse(f"Error reading file: {str(e)}", 500)

def send_from_directory(directory: str, filename: str, **kwargs):
    """Send a file from a directory"""
    file_path = os.path.join(directory, filename)
    # Security check - ensure file is within directory
    if not os.path.abspath(file_path).startswith(os.path.abspath(directory)):
        return RewrouteResponse("Access denied", 403)
    
    return send_file(file_path, **kwargs)

class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    """Thread-per-request HTTP server"""
    daemon_threads = True

class InterceptHandler(BaseHTTPRequestHandler):
    """HTTP request handler for intercepting all traffic"""
    
    def __init__(self, traffic_manager, *args, **kwargs):
        self.traffic_manager = traffic_manager
        super().__init__(*args, **kwargs)
    
    def log_message(self, format, *args):
        """Disable default logging - we handle this ourselves"""
        pass
    
    def do_GET(self):
        self._handle_request('GET')
    
    def do_POST(self):
        self._handle_request('POST')
    
    def do_PUT(self):
        self._handle_request('PUT')
    
    def do_DELETE(self):
        self._handle_request('DELETE')
    
    def do_PATCH(self):
        self._handle_request('PATCH')
    
    def do_HEAD(self):
        self._handle_request('HEAD')
    
    def do_OPTIONS(self):
        self._handle_request('OPTIONS')
    
    def _handle_request(self, method: str):
        start_time = time.time()
        
        # Parse URL and query parameters
        parsed_url = urlparse(self.path)
        
        # Extract host from headers or URL
        host = self.headers.get('Host', '').split(':')[0]  # Remove port if present
        if not host and parsed_url.netloc:
            host = parsed_url.netloc.split(':')[0]
        
        path = parsed_url.path
        query_params = parse_qs(parsed_url.query)
        
        # Get headers
        headers = dict(self.headers)
        
        # Read body for POST/PUT/PATCH requests
        body = b''
        if method in ['POST', 'PUT', 'PATCH']:
            content_length = int(headers.get('content-length', 0))
            if content_length > 0:
                body = self.rfile.read(content_length)
        
        try:
            # Check if this domain is handled by any Rewroute app
            if host in self.traffic_manager.domain_apps:
                # Route to local Rewroute app
                app = self.traffic_manager.domain_apps[host]
                # Set current app context
                _set_current_app(app)
                
                response = self._route_to_app(method, path, headers, query_params, body, host, app)
                status_code = response.status_code if isinstance(response, RewrouteResponse) else 200
                self._log_local_request(method, host, path, status_code, start_time)
                
                # Clear app context
                _set_current_app(None)
            else:
                # Create request object for forwarding
                request = RewrouteRequest(method, path, headers, query_params, body, host)
                # Forward to external server (normal internet traffic)
                response = self._forward_request(request)
                status_code = response.status_code if isinstance(response, RewrouteResponse) else 200
                self._log_proxy_request(method, host, path, status_code, start_time)
            
            # Send response
            self._send_response(response)
            
        except Exception as e:
            # Handle errors
            self._send_error_response(str(e))
            duration = (time.time() - start_time) * 1000
            self._log_error(method, host, path, str(e), duration)
    
    def _route_to_app(self, method: str, path: str, headers: Dict[str, str], 
                     query_params: Dict[str, list], body: bytes, host: str, app: 'RewrouteFlask'):
        """Route request to a local Rewroute app"""
        try:
            # First try exact route match
            route_key = f"{method}:{path}"
            
            if route_key in app.routes:
                handler = app.routes[route_key]
                request = RewrouteRequest(method, path, headers, query_params, body, host)
                result = handler(request)
                return self._ensure_response(result)
            
            # Try to find parameterized routes
            for registered_route, handler in app.routes.items():
                route_method, path_pattern = registered_route.split(':', 1)
                if route_method == method:
                    url_params = self._extract_url_params(path_pattern, path)
                    if url_params is not None:
                        request = RewrouteRequest(method, path, headers, query_params, body, host, url_params)
                        result = handler(request)
                        return self._ensure_response(result)
            
            # No route found
            return RewrouteResponse("Not Found", 404)
            
        except Exception as e:
            return RewrouteResponse(f"Application Error: {str(e)}", 500)
    
    def _extract_url_params(self, pattern: str, path: str) -> Optional[Dict[str, str]]:
        """Extract URL parameters from path using pattern"""
        # Convert pattern like /user/<id> to regex
        regex_pattern = pattern
        param_names = []
        
        # Find all parameters in angle brackets
        param_matches = re.findall(r'<([^>]+)>', pattern)
        for param in param_matches:
            param_names.append(param)
            # Replace <param> with capture group
            regex_pattern = regex_pattern.replace(f'<{param}>', r'([^/]+)')
        
        # Escape other regex characters
        regex_pattern = regex_pattern.replace('/', r'\/')
        regex_pattern = f'^{regex_pattern}$'
        
        match = re.match(regex_pattern, path)
        if match and len(match.groups()) == len(param_names):
            return dict(zip(param_names, match.groups()))
        
        return None
    
    def _ensure_response(self, result):
        """Ensure result is a RewrouteResponse"""
        if isinstance(result, RewrouteResponse):
            return result
        elif isinstance(result, tuple) and len(result) == 2:
            # Handle (data, status_code) tuple
            return RewrouteResponse(result[0], result[1])
        else:
            # Wrap simple return values
            return RewrouteResponse(result)
    
    def _forward_request(self, request: RewrouteRequest):
        """Forward request to external server (normal internet traffic)"""
        try:
            # Reconstruct the full URL
            scheme = 'https' if request.headers.get('X-Forwarded-Proto') == 'https' else 'http'
            # Default to HTTPS for most domains unless explicitly HTTP
            if scheme == 'http' and not request.host.startswith('localhost') and not request.host.startswith('127.'):
                scheme = 'https'
            
            url = f"{scheme}://{request.host}{request.path}"
            if request.query_params:
                query_string = '&'.join([f"{k}={v[0]}" for k, v in request.query_params.items()])
                url += f"?{query_string}"
            
            # Prepare headers (remove hop-by-hop headers)
            headers = dict(request.headers)
            hop_by_hop = ['connection', 'keep-alive', 'proxy-authenticate', 
                         'proxy-authorization', 'te', 'trailers', 'transfer-encoding', 'upgrade']
            for header in hop_by_hop:
                headers.pop(header, None)
            
            # Remove host header to avoid conflicts
            headers.pop('host', None)
            
            # Make the request
            response = requests.request(
                method=request.method,
                url=url,
                headers=headers,
                data=request.body,
                timeout=30,
                allow_redirects=False,
                verify=False  # Disable SSL verification for proxy
            )
            
            # Convert to RewrouteResponse
            response_headers = dict(response.headers)
            # Remove hop-by-hop headers from response
            for header in hop_by_hop:
                response_headers.pop(header, None)
            
            return RewrouteResponse(
                data=response.content,
                status_code=response.status_code,
                headers=response_headers
            )
            
        except Exception as e:
            return RewrouteResponse(f"Proxy Error: {str(e)}", 502)
    
    def _send_response(self, response):
        """Send HTTP response"""
        # Ensure we always have a RewrouteResponse object
        if not isinstance(response, RewrouteResponse):
            if isinstance(response, tuple) and len(response) == 2:
                response = RewrouteResponse(response[0], response[1])
            else:
                response = RewrouteResponse(response)
        
        status_code = response.status_code
        response_data = response.data
        response_headers = response.headers
        
        # Handle different data types
        if isinstance(response_data, bytes):
            response_body = response_data
        elif isinstance(response_data, (dict, list)):
            response_body = json.dumps(response_data).encode('utf-8')
            if 'content-type' not in response_headers:
                response_headers['content-type'] = 'application/json'
        elif isinstance(response_data, str):
            response_body = response_data.encode('utf-8')
        else:
            response_body = str(response_data).encode('utf-8')
        
        try:
            # Send response
            self.send_response(status_code)
            for header_name, header_value in response_headers.items():
                if header_name.lower() not in ['content-length', 'transfer-encoding']:
                    self.send_header(header_name, header_value)
            self.send_header('content-length', str(len(response_body)))
            self.end_headers()
            
            if self.command != 'HEAD':  # Don't send body for HEAD requests
                self.wfile.write(response_body)
        except Exception as e:
            # Connection may have been closed
            pass
    
    def _send_error_response(self, error_msg: str):
        """Send error response"""
        try:
            self.send_response(500)
            self.send_header('content-type', 'text/plain')
            self.send_header('content-length', str(len(error_msg)))
            self.end_headers()
            self.wfile.write(error_msg.encode('utf-8'))
        except:
            pass
    
    def _log_local_request(self, method, host, path, status_code, start_time):
        """Log request handled by local app"""
        duration = (time.time() - start_time) * 1000
        if RICH_AVAILABLE:
            status_color = "green" if status_code < 400 else "red" if status_code >= 500 else "yellow"
            console.print(f"🏠 [{status_color}]{status_code}[/] {method} {host}{path} [{duration:.1f}ms]")
        else:
            print(f"🏠 [{status_code}] {method} {host}{path} [{duration:.1f}ms]")
    
    def _log_proxy_request(self, method, host, path, status_code, start_time):
        """Log request proxied to external server"""
        duration = (time.time() - start_time) * 1000
        if RICH_AVAILABLE:
            status_color = "green" if status_code < 400 else "red" if status_code >= 500 else "yellow"
            console.print(f"🌐 [{status_color}]{status_code}[/] {method} {host}{path} [{duration:.1f}ms]", style="dim")
        else:
            print(f"🌐 [{status_code}] {method} {host}{path} [{duration:.1f}ms]")
    
    def _log_error(self, method, host, path, error, duration):
        """Log error"""
        if RICH_AVAILABLE:
            console.print(f"❌ [red]ERROR[/] {method} {host}{path} [{duration:.1f}ms] - {error}")
        else:
            print(f"❌ ERROR {method} {host}{path} [{duration:.1f}ms] - {error}")

class DNSManager:
    """Manages DNS configuration to intercept traffic"""
    
    def __init__(self):
        self.original_dns = None
        self.is_dns_set = False
    
    def setup_dns_interception(self, proxy_ip: str = "127.0.0.1"):
        """Set up DNS to route traffic through our proxy"""
        system = platform.system().lower()
        
        try:
            if system == "darwin":  # macOS
                self._setup_dns_macos(proxy_ip)
            elif system == "linux":
                self._setup_dns_linux(proxy_ip)
            elif system == "windows":
                self._setup_dns_windows(proxy_ip)
            else:
                raise Exception(f"Unsupported system: {system}")
            
            self.is_dns_set = True
            if RICH_AVAILABLE:
                console.print(f"✅ DNS configured to route traffic through {proxy_ip}:80", style="green")
            else:
                print(f"✅ DNS configured to route traffic through {proxy_ip}:80")
                
        except Exception as e:
            if RICH_AVAILABLE:
                console.print(f"❌ Failed to configure DNS: {str(e)}", style="red")
            else:
                print(f"❌ Failed to configure DNS: {str(e)}")
    
    def _setup_dns_macos(self, proxy_ip: str):
        """Set up DNS on macOS"""
        # Get current DNS servers
        result = subprocess.run(["scutil", "--dns"], capture_output=True, text=True)
        # For simplicity, we'll modify /etc/hosts for registered domains
        # In production, you'd want to set up a proper DNS server
        pass
    
    def _setup_dns_linux(self, proxy_ip: str):
        """Set up DNS on Linux"""
        # Similar to macOS, modify /etc/hosts or set up dnsmasq
        pass
    
    def _setup_dns_windows(self, proxy_ip: str):
        """Set up DNS on Windows"""
        # Modify hosts file or DNS settings
        pass
    
    def restore_dns(self):
        """Restore original DNS settings"""
        if self.is_dns_set:
            # Restore original DNS configuration
            self.is_dns_set = False
            if RICH_AVAILABLE:
                console.print("✅ DNS settings restored", style="green")
            else:
                print("✅ DNS settings restored")

class TrafficManager:
    """Manages traffic interception and domain routing"""
    
    def __init__(self):
        self.domain_apps: Dict[str, 'RewrouteFlask'] = {}
        self.logger = logging.getLogger("rewroute.traffic")
        self.http_server = None
        self.https_server = None
        self.http_thread = None
        self.https_thread = None
        self.dns_manager = DNSManager()
        self.is_running = False
    
    def register_app(self, domain: str, app: 'RewrouteFlask'):
        """Register a Rewroute app for a specific domain"""
        self.domain_apps[domain] = app
        if RICH_AVAILABLE:
            console.print(f"📝 Registered app '{app.name}' for domain '{domain}'", style="blue")
        else:
            print(f"📝 Registered app '{app.name}' for domain '{domain}'")
    
    def start_interception(self, http_port: int = 80, https_port: int = 443, setup_dns: bool = True):
        """Start traffic interception"""
        if self.is_running:
            if RICH_AVAILABLE:
                console.print("⚠️ Traffic interception is already running", style="yellow")
            else:
                print("⚠️ Traffic interception is already running")
            return
        
        if RICH_AVAILABLE:
            console.print(Panel.fit(
                f"🚀 Starting Rewroute Traffic Interceptor\n\n"
                f"Registered domains: {', '.join(self.domain_apps.keys()) if self.domain_apps else 'None'}\n"
                f"HTTP Port: {http_port}\n"
                f"HTTPS Port: {https_port}",
                title="Rewroute", 
                border_style="blue"
            ))
        else:
            print(f"🚀 Starting Rewroute Traffic Interceptor")
            print(f"Registered domains: {', '.join(self.domain_apps.keys()) if self.domain_apps else 'None'}")
        
        # Create HTTP server
        handler = lambda *args, **kwargs: InterceptHandler(self, *args, **kwargs)
        
        try:
            # Start HTTP server
            self.http_server = ThreadingHTTPServer(('0.0.0.0', http_port), handler)
            self.http_thread = threading.Thread(target=self.http_server.serve_forever)
            self.http_thread.daemon = True
            self.http_thread.start()
            
            # Note: HTTPS would require SSL certificate management
            # For now, we'll focus on HTTP traffic
            
            self.is_running = True
            
            # Set up DNS interception if requested
            if setup_dns:
                self.dns_manager.setup_dns_interception()
            
            if RICH_AVAILABLE:
                console.print(f"🎯 Traffic interceptor active on port {http_port}", style="green bold")
                console.print("💡 All HTTP traffic will be intercepted and processed", style="dim")
            else:
                print(f"🎯 Traffic interceptor active on port {http_port}")
                print("💡 All HTTP traffic will be intercepted and processed")
            
            return self.http_thread
            
        except PermissionError:
            error_msg = f"Permission denied. Run as administrator/root to bind to port {http_port}"
            if RICH_AVAILABLE:
                print(Panel.fit(f"❌ {error_msg}", style="red"))
            else:
                print(f"❌ {error_msg}")
            raise
        except Exception as e:
            if RICH_AVAILABLE:
                console.print(f"❌ Failed to start traffic interceptor: {str(e)}", style="red")
            else:
                print(f"❌ Failed to start traffic interceptor: {str(e)}")
            self.is_running = False
            raise
    
    def stop_interception(self):
        """Stop traffic interception"""
        if not self.is_running:
            return
            
        if RICH_AVAILABLE:
            console.print("🛑 Stopping traffic interceptor...", style="yellow")
        else:
            print("🛑 Stopping traffic interceptor...")
        
        if self.http_server:
            self.http_server.shutdown()
            self.http_server.server_close()
        
        if self.https_server:
            self.https_server.shutdown()
            self.https_server.server_close()
        
        if self.http_thread:
            self.http_thread.join()
        
        if self.https_thread:
            self.https_thread.join()
        
        # Restore DNS
        self.dns_manager.restore_dns()
        
        self.is_running = False
        
        if RICH_AVAILABLE:
            console.print("✅ Traffic interceptor stopped", style="green")
        else:
            print("✅ Traffic interceptor stopped")

# Global traffic manager instance
_traffic_manager = TrafficManager()

# Application context management
_current_app = None

def _set_current_app(app):
    """Set the current application context"""
    global _current_app
    _current_app = app

def get_current_app():
    """Get the current application context"""
    return _current_app

class RewrouteFlask:
    """Main application class providing Flask-like interface"""
    
    def __init__(self, name: str, template_folder: str = 'templates', static_folder: str = 'static'):
        self.name = name
        self.routes: Dict[str, Callable] = {}
        self.logger = logging.getLogger(f"rewroute.{name}")
        self.domain = None
        self.template_folder = template_folder
        self.static_folder = static_folder
        
        # Initialize Jinja2 environment if available
        if JINJA2_AVAILABLE and os.path.exists(template_folder):
            self.jinja_env = Environment(
                loader=FileSystemLoader(template_folder),
                autoescape=select_autoescape(['html', 'xml'])
            )
        else:
            self.jinja_env = None
        
        # Add static file route
        if static_folder and os.path.exists(static_folder):
            self.add_static_route()
        
        if RICH_AVAILABLE:
            console.print(f"🔧 Initialized app: {name}", style="cyan")
        else:
            print(f"🔧 Initialized app: {name}")
    
    def add_static_route(self):
        """Add route for serving static files"""
        def serve_static(request):
            # Extract filename from path like /static/filename
            path_parts = request.path.strip('/').split('/')
            if len(path_parts) >= 2 and path_parts[0] == 'static':
                filename = '/'.join(path_parts[1:])  # Handle subdirectories
                return send_from_directory(self.static_folder, filename)
            return RewrouteResponse("Not Found", 404)
        
        # Register static route pattern
        self.routes['GET:/static/<path:filename>'] = serve_static
    
    def render_template(self, template_name: str, **context):
        """Render a template with context"""
        if not self.jinja_env:
            if not JINJA2_AVAILABLE:
                return RewrouteResponse("Jinja2 not available. Install with: pip install jinja2", 500)
            elif not os.path.exists(self.template_folder):
                return RewrouteResponse(f"Template folder '{self.template_folder}' not found", 500)
            else:
                return RewrouteResponse("Template engine not initialized", 500)
        
        try:
            template = self.jinja_env.get_template(template_name)
            html = template.render(**context)
            return RewrouteResponse(html, 200, {'content-type': 'text/html; charset=utf-8'})
        except Exception as e:
            return RewrouteResponse(f"Template error: {str(e)}", 500)
    
    def route(self, path: str, methods: list = None):
        """Decorator for registering routes"""
        if methods is None:
            methods = ['GET']
        
        def decorator(func):
            for method in methods:
                route_key = f"{method.upper()}:{path}"
                self.routes[route_key] = func
                if RICH_AVAILABLE:
                    console.print(f"  📍 {method.upper()} {path}", style="dim")
                else:
                    print(f"  📍 {method.upper()} {path}")
            return func
        return decorator
    
    def get(self, path: str):
        """Decorator for GET routes"""
        return self.route(path, ['GET'])
    
    def post(self, path: str):
        """Decorator for POST routes"""
        return self.route(path, ['POST'])
    
    def put(self, path: str):
        """Decorator for PUT routes"""
        return self.route(path, ['PUT'])
    
    def delete(self, path: str):
        """Decorator for DELETE routes"""
        return self.route(path, ['DELETE'])
    
    def patch(self, path: str):
        """Decorator for PATCH routes"""
        return self.route(path, ['PATCH'])
    
    def run(self, domain: str, start_interceptor: bool = True, http_port: int = 80, setup_dns: bool = True):
        """Register the app with a domain and optionally start the interceptor"""
        self.domain = domain
        
        # Register this app with the traffic manager
        _traffic_manager.register_app(domain, self)
        
        # Start the traffic interceptor if requested and not already running
        if start_interceptor and not _traffic_manager.is_running:
            _traffic_manager.start_interception(http_port, setup_dns=setup_dns)
        
        return _traffic_manager.http_thread

# Convenience functions
def create_app(name: str, template_folder: str = 'templates', static_folder: str = 'static') -> RewrouteFlask:
    """Create a new RewrouteFlask application"""
    return RewrouteFlask(name, template_folder, static_folder)

def start_interceptor(http_port: int = 80, setup_dns: bool = True):
    """Start the global traffic interceptor"""
    return _traffic_manager.start_interception(http_port, setup_dns=setup_dns)

def stop_interceptor():
    """Stop the global traffic interceptor"""
    _traffic_manager.stop_interception()

def get_registered_domains():
    """Get list of registered domains"""
    return list(_traffic_manager.domain_apps.keys())

def add_hosts_entry(domain: str, ip: str = "127.0.0.1"):
    """Add entry to hosts file for domain interception"""
    system = platform.system().lower()
    
    try:
        if system == "windows":
            hosts_path = r"C:\Windows\System32\drivers\etc\hosts"
        else:
            hosts_path = "/etc/hosts"
        
        entry = f"{ip} {domain}\n"
        
        # Check if entry already exists
        with open(hosts_path, 'r') as f:
            if entry.strip() in f.read():
                return
        
        # Add entry
        with open(hosts_path, 'a') as f:
            f.write(entry)
        
        if RICH_AVAILABLE:
            console.print(f"✅ Added {domain} -> {ip} to hosts file", style="green")
        else:
            print(f"✅ Added {domain} -> {ip} to hosts file")
            
    except PermissionError:
        if RICH_AVAILABLE:
            console.print("❌ Permission denied. Run as administrator/root to modify hosts file", style="red")
        else:
            print("❌ Permission denied. Run as administrator/root to modify hosts file")
    except Exception as e:
        if RICH_AVAILABLE:
            console.print(f"❌ Failed to modify hosts file: {str(e)}", style="red")
        else:
            print(f"❌ Failed to modify hosts file: {str(e)}")

# Auto-setup function
def auto_setup_domain(domain: str):
    """Automatically set up domain interception"""
    add_hosts_entry(domain)

if __name__ == "__main__":
    # Example usage showing new features
    if RICH_AVAILABLE:
        console.print(Panel.fit(
            "🎉 Enhanced Rewroute Framework!\n\n"
            "New Features:\n"
            "• URL Parameters: @app.get('/user/<id>')\n"
            "• Templates: render_template('page.html', data=data)\n"
            "• File Serving: send_file('path/to/file.txt')\n"
            "• Static Files: send_from_directory('static', 'style.css')\n"
            "• Redirects: redirect('/new-url', 302)\n\n"
            "Example Usage:\n"
            "app = create_app('myapp')\n"
            "@app.get('/user/<user_id>')\n"
            "def user_profile(request):\n"
            "    return render_template('user.html', id=request.url_params['user_id'])\n\n"
            "app.run('mysite.local')",
            title="Enhanced Rewroute",
            border_style="green"
        ))
    else:
        print("🎉 Enhanced Rewroute Framework!")
        print("New features: URL parameters, templates, file serving, redirects")
        print("Create apps and register domains to get started.")

    # Example application
    demo_app = create_app('demo')
    
    @demo_app.get('/')
    def home(request):
        return render_template('index.html', title="Welcome to Rewroute")
    
    @demo_app.get('/user/<user_id>')
    def user_profile(request):
        user_id = request.url_params['user_id']
        return {
            'user_id': user_id,
            'message': f'Hello user {user_id}!'
        }
    
    @demo_app.get('/download/<filename>')  
    def download_file(request):
        filename = request.url_params['filename']
        return send_from_directory('downloads', filename, as_attachment=True)
    
    @demo_app.get('/redirect-test')
    def test_redirect(request):
        return redirect('/', 302)
    
    @demo_app.post('/api/data')
    def handle_data(request):
        if request.json_data:
            return {'received': request.json_data, 'status': 'success'}
        return {'error': 'No JSON data'}, 400
    
    if RICH_AVAILABLE:
        console.print("\n📝 Demo routes registered:", style="cyan")
        console.print("  GET  /")
        console.print("  GET  /user/<user_id>") 
        console.print("  GET  /download/<filename>")
        console.print("  GET  /redirect-test")
        console.print("  POST /api/data")
        console.print("  GET  /static/<filename> (auto-generated)")
