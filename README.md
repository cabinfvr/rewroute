# Rewroute Framework Documentation

**A lightweight Flask-like framework with DNS interception and traffic proxy capabilities**

Rewroute is a powerful Python framework that combines the simplicity of Flask with advanced traffic interception capabilities. It can intercept all HTTP traffic, handle registered domains locally, and forward everything else to external servers.

## Table of Contents

1. [Quick Start](#quick-start)
2. [Installation](#installation)
3. [Core Concepts](#core-concepts)
4. [API Reference](#api-reference)
5. [Advanced Features](#advanced-features)
6. [Examples](#examples)
7. [Configuration](#configuration)
8. [Security Considerations](#security-considerations)

## Quick Start

```python
from rewroute import create_app, render_template, redirect

# Create a new application
app = create_app('myapp')

# Define routes
@app.get('/')
def home(request):
    return render_template('index.html', title="Welcome to Rewroute")

@app.get('/user/<user_id>')
def user_profile(request):
    user_id = request.url_params['user_id']
    return {'user_id': user_id, 'name': f'User {user_id}'}

@app.post('/api/data')
def handle_data(request):
    if request.json_data:
        return {'received': request.json_data, 'status': 'success'}
    return {'error': 'No JSON data'}, 400

# Run the application on a domain
# This will intercept all traffic to 'mysite.local'
app.run('mysite.local')
```

## Installation

### Dependencies

**Required:**
```bash
pip install requests
```

**Optional (for enhanced features):**
```bash
pip install rich jinja2
```

- `rich`: Beautiful console output and logging
- `jinja2`: Template engine support

### System Requirements

- Python 3.6+
- Administrator/root privileges (for DNS interception and port 80/443 binding)
- Supported platforms: Windows, macOS, Linux

## Core Concepts

### Traffic Interception

Rewroute works by intercepting all HTTP traffic on your system:

1. **DNS Management**: Modifies system DNS or hosts file to route traffic
2. **Proxy Server**: Runs local HTTP/HTTPS servers on ports 80/443
3. **Smart Routing**: Registered domains → local apps, everything else → internet

### Application Structure

```python
# Create application
app = create_app('app_name', template_folder='templates', static_folder='static')

# Register routes
@app.route('/path', methods=['GET', 'POST'])
def handler(request):
    return response

# Bind to domain and start
app.run('domain.local')
```

### Request/Response Cycle

1. HTTP request comes in
2. Rewroute checks if domain is registered
3. If registered: routes to local app
4. If not registered: proxies to external server
5. Response sent back to client

## API Reference

### Application Class

#### `create_app(name, template_folder='templates', static_folder='static')`

Creates a new Rewroute application.

**Parameters:**
- `name` (str): Application name
- `template_folder` (str): Directory for templates
- `static_folder` (str): Directory for static files

**Returns:** `RewrouteFlask` instance

### Route Decorators

#### `@app.route(path, methods=None)`

Register a route handler.

**Parameters:**
- `path` (str): URL path pattern (supports parameters like `/user/<id>`)
- `methods` (list): HTTP methods (default: `['GET']`)

#### HTTP Method Shortcuts

```python
@app.get(path)      # GET only
@app.post(path)     # POST only
@app.put(path)      # PUT only
@app.delete(path)   # DELETE only
@app.patch(path)    # PATCH only
```

### Request Object

The request object passed to route handlers contains:

```python
class RewrouteRequest:
    method: str              # HTTP method
    path: str               # URL path
    headers: Dict[str, str] # HTTP headers
    query_params: Dict[str, list]  # Query parameters
    body: bytes             # Request body
    host: str               # Host header
    json_data: dict         # Parsed JSON (if applicable)
    url_params: Dict[str, str]     # URL parameters from path
```

**Example:**
```python
@app.get('/user/<user_id>')
def user_handler(request):
    user_id = request.url_params['user_id']  # From URL
    name = request.query_params.get('name', [''])[0]  # From ?name=value
    return f"User {user_id}, Name: {name}"
```

### Response Types

#### `RewrouteResponse(data, status_code=200, headers=None, mimetype=None)`

Explicit response object.

**Parameters:**
- `data`: Response data (str, dict, list, bytes)
- `status_code` (int): HTTP status code
- `headers` (dict): HTTP headers
- `mimetype` (str): Content type

#### Shorthand Returns

```python
# String response
return "Hello World"

# JSON response
return {"key": "value"}

# Tuple (data, status_code)
return "Not Found", 404

# RewrouteResponse object
return RewrouteResponse("Custom", 201, {"X-Custom": "header"})
```

### Template Rendering

#### `render_template(template_name, **context)`

Render Jinja2 templates.

**Requirements:** `pip install jinja2`

```python
@app.get('/')
def home(request):
    return render_template('index.html', 
                         title="My Site", 
                         users=['Alice', 'Bob'])
```

**Template (templates/index.html):**
```html
<!DOCTYPE html>
<html>
<head>
    <title>{{ title }}</title>
</head>
<body>
    <h1>{{ title }}</h1>
    <ul>
    {% for user in users %}
        <li>{{ user }}</li>
    {% endfor %}
    </ul>
</body>
</html>
```

### File Serving

#### `send_file(file_path, mimetype=None, as_attachment=False, attachment_filename=None)`

Send a file as response.

```python
@app.get('/download/<filename>')
def download(request):
    filename = request.url_params['filename']
    return send_file(f'files/{filename}', as_attachment=True)
```

#### `send_from_directory(directory, filename, **kwargs)`

Safely serve files from a directory.

```python
@app.get('/static/<filename>')
def static_files(request):
    filename = request.url_params['filename']
    return send_from_directory('static', filename)
```

### Redirects

#### `redirect(location, code=302)`

Create redirect responses.

```python
@app.get('/old-page')
def redirect_old(request):
    return redirect('/new-page', 301)  # Permanent redirect
```

### Application Management

#### `app.run(domain, start_interceptor=True, http_port=80, setup_dns=True)`

Start the application on a domain.

**Parameters:**
- `domain` (str): Domain to intercept (e.g., 'mysite.local')
- `start_interceptor` (bool): Start traffic interceptor
- `http_port` (int): HTTP port (default: 80)
- `setup_dns` (bool): Modify DNS/hosts file

### Global Functions

#### `start_interceptor(http_port=80, setup_dns=True)`

Manually start the traffic interceptor.

#### `stop_interceptor()`

Stop traffic interception and restore DNS.

#### `get_registered_domains()`

Get list of registered domains.

#### `add_hosts_entry(domain, ip='127.0.0.1')`

Add domain to hosts file.

#### `auto_setup_domain(domain)`

Automatically configure domain interception.

## Advanced Features

### URL Parameters

Capture dynamic parts of URLs:

```python
@app.get('/user/<user_id>')
@app.get('/post/<int:post_id>')  # Note: int converter not implemented
@app.get('/file/<path:filename>')  # Note: path converter not implemented
def handler(request):
    # Access via request.url_params
    user_id = request.url_params['user_id']
    return f"User: {user_id}"
```

### Multiple Apps on Different Domains

```python
# Blog app
blog = create_app('blog')

@blog.get('/')
def blog_home(request):
    return "Welcome to the blog!"

blog.run('blog.local', start_interceptor=False)

# Admin app
admin = create_app('admin')

@admin.get('/')
def admin_home(request):
    return render_template('admin.html')

admin.run('admin.local', start_interceptor=False)

# Start interceptor once for all apps
start_interceptor()
```

### Static File Handling

Static files are automatically served from the `static_folder`:

```
project/
├── app.py
├── static/
│   ├── css/
│   │   └── style.css
│   ├── js/
│   │   └── app.js
│   └── images/
│       └── logo.png
└── templates/
    └── index.html
```

Access via: `http://domain.local/static/css/style.css`

### JSON API Development

```python
@app.post('/api/users')
def create_user(request):
    if not request.json_data:
        return {'error': 'JSON required'}, 400
    
    user_data = request.json_data
    # Process user creation
    return {
        'id': 123,
        'name': user_data.get('name'),
        'status': 'created'
    }, 201

@app.get('/api/users/<user_id>')
def get_user(request):
    user_id = request.url_params['user_id']
    # Fetch user data
    return {
        'id': user_id,
        'name': 'John Doe',
        'email': 'john@example.com'
    }
```

### Error Handling

```python
@app.get('/error-test')
def error_handler(request):
    try:
        # Some operation that might fail
        result = risky_operation()
        return {'result': result}
    except Exception as e:
        return {'error': str(e)}, 500
```

### Custom Headers

```python
@app.get('/api/data')
def api_data(request):
    data = {'message': 'Hello API'}
    headers = {
        'X-API-Version': '1.0',
        'Access-Control-Allow-Origin': '*'
    }
    return RewrouteResponse(data, 200, headers)
```

## Examples

### Complete Blog Application

```python
from rewroute import create_app, render_template, redirect, send_from_directory

# Create blog application
blog = create_app('blog', template_folder='templates', static_folder='static')

# Sample data
posts = [
    {'id': 1, 'title': 'First Post', 'content': 'Hello World!'},
    {'id': 2, 'title': 'Second Post', 'content': 'More content here.'}
]

@blog.get('/')
def home(request):
    return render_template('index.html', posts=posts)

@blog.get('/post/<post_id>')
def view_post(request):
    post_id = int(request.url_params['post_id'])
    post = next((p for p in posts if p['id'] == post_id), None)
    
    if not post:
        return render_template('404.html'), 404
    
    return render_template('post.html', post=post)

@blog.post('/post/<post_id>/comment')
def add_comment(request):
    post_id = int(request.url_params['post_id'])
    comment = request.json_data.get('comment', '')
    
    # Save comment logic here
    return {'success': True, 'message': 'Comment added'}

@blog.get('/admin')
def admin(request):
    return render_template('admin.html', posts=posts)

# Start the blog
blog.run('myblog.local')
```

### REST API Example

```python
from rewroute import create_app

api = create_app('api')

# In-memory data store
users = {}
next_id = 1

@api.get('/api/users')
def list_users(request):
    return {'users': list(users.values())}

@api.post('/api/users')
def create_user(request):
    global next_id
    
    if not request.json_data:
        return {'error': 'JSON data required'}, 400
    
    user = {
        'id': next_id,
        'name': request.json_data.get('name'),
        'email': request.json_data.get('email')
    }
    
    users[next_id] = user
    next_id += 1
    
    return user, 201

@api.get('/api/users/<user_id>')
def get_user(request):
    user_id = int(request.url_params['user_id'])
    user = users.get(user_id)
    
    if not user:
        return {'error': 'User not found'}, 404
    
    return user

@api.put('/api/users/<user_id>')
def update_user(request):
    user_id = int(request.url_params['user_id'])
    
    if user_id not in users:
        return {'error': 'User not found'}, 404
    
    if request.json_data:
        users[user_id].update(request.json_data)
    
    return users[user_id]

@api.delete('/api/users/<user_id>')
def delete_user(request):
    user_id = int(request.url_params['user_id'])
    
    if user_id not in users:
        return {'error': 'User not found'}, 404
    
    del users[user_id]
    return {'message': 'User deleted'}

# Start API server
api.run('api.local')
```

### File Upload Handler

```python
from rewroute import create_app, send_file
import os

app = create_app('fileserver')

UPLOAD_DIR = 'uploads'
os.makedirs(UPLOAD_DIR, exist_ok=True)

@app.post('/upload')
def upload_file(request):
    # Note: This is simplified - you'd need proper multipart handling
    filename = request.headers.get('X-Filename', 'uploaded_file')
    filepath = os.path.join(UPLOAD_DIR, filename)
    
    with open(filepath, 'wb') as f:
        f.write(request.body)
    
    return {'message': 'File uploaded', 'filename': filename}

@app.get('/download/<filename>')
def download_file(request):
    filename = request.url_params['filename']
    filepath = os.path.join(UPLOAD_DIR, filename)
    
    if not os.path.exists(filepath):
        return {'error': 'File not found'}, 404
    
    return send_file(filepath, as_attachment=True)

@app.get('/files')
def list_files(request):
    files = os.listdir(UPLOAD_DIR)
    return {'files': files}

app.run('files.local')
```

## Configuration

### Environment Variables

```python
import os

# Configuration
DEBUG = os.getenv('DEBUG', 'false').lower() == 'true'
HOST = os.getenv('HOST', 'localhost')
PORT = int(os.getenv('PORT', 80))

app = create_app('myapp')

if DEBUG:
    # Add debug routes
    @app.get('/debug')
    def debug_info(request):
        return {
            'headers': dict(request.headers),
            'query_params': request.query_params,
            'method': request.method
        }

app.run(HOST, http_port=PORT)
```

### Logging Setup

```python
import logging

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s | %(name)s | %(levelname)s | %(message)s'
)

logger = logging.getLogger('myapp')

@app.get('/log-test')
def log_test(request):
    logger.info(f"Request from {request.headers.get('User-Agent')}")
    return "Check the logs!"
```

## Security Considerations

### Important Security Notes

⚠️ **Rewroute is designed for development and testing purposes. Use with caution in production environments.**

### Security Features

1. **Path Traversal Protection**: `send_from_directory()` prevents access outside designated directories
2. **Request Validation**: Built-in JSON parsing with error handling
3. **Header Sanitization**: Automatic hop-by-hop header removal in proxy mode

### Security Best Practices

1. **Input Validation**:
```python
@app.post('/api/user')
def create_user(request):
    data = request.json_data
    
    # Validate input
    if not data or 'name' not in data:
        return {'error': 'Name required'}, 400
    
    name = data['name'].strip()
    if len(name) < 2:
        return {'error': 'Name too short'}, 400
    
    # Process validated data
    return {'user': name}
```

2. **HTTPS in Production**: 
   - Configure SSL certificates for HTTPS support
   - Use reverse proxy (nginx) for production deployments

3. **Access Control**:
```python
def require_auth(handler):
    def wrapper(request):
        token = request.headers.get('Authorization')
        if not token or not validate_token(token):
            return {'error': 'Unauthorized'}, 401
        return handler(request)
    return wrapper

@app.get('/admin/users')
@require_auth
def admin_users(request):
    return {'users': get_all_users()}
```

4. **Rate Limiting**: Implement custom rate limiting logic in handlers

### DNS and System Modifications

Rewroute modifies system DNS settings and requires administrator privileges:

- **Hosts File**: Adds entries to redirect domains
- **DNS Settings**: May modify system DNS configuration
- **Port Binding**: Requires root/admin for ports 80/443

Always run `stop_interceptor()` to restore original settings.

### Proxy Security

When proxying external traffic:
- SSL verification is disabled for simplicity
- Headers are forwarded (review for sensitive data)
- Timeouts prevent hanging connections

## Troubleshooting

### Common Issues

1. **Permission Denied on Port 80/443**
   ```bash
   # Linux/macOS
   sudo python app.py
   
   # Windows (Run as Administrator)
   python app.py
   ```

2. **Rich Console Not Working**
   ```bash
   pip install rich
   ```

3. **Templates Not Rendering**
   ```bash
   pip install jinja2
   # Ensure templates/ directory exists
   ```

4. **Domain Not Intercepting**
   - Check hosts file was modified
   - Verify no other services on port 80
   - Try `add_hosts_entry('domain.local')` manually

5. **Static Files 404**
   - Ensure static/ directory exists
   - Check file permissions
   - Verify path in browser

### Debug Mode

```python
# Enable verbose logging
import logging
logging.getLogger().setLevel(logging.DEBUG)

# Add debug route
@app.get('/debug/<path:info>')
def debug_handler(request):
    return {
        'path': request.path,
        'url_params': request.url_params,
        'method': request.method,
        'headers': dict(request.headers),
        'query': request.query_params
    }
```

---

## Contributing

This framework is extensible and welcomes contributions. Key areas for enhancement:

- HTTPS/SSL certificate management
- WebSocket support
- Database integration helpers
- Authentication middleware
- Caching mechanisms
- Advanced routing (regex patterns)
- Request/response middleware
- Session management

---

**Rewroute Framework** - Powerful local development with global traffic interception capabilities.
