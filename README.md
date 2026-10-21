# Multi-threaded HTTP Server

[![CI](https://github.com/NEERASA-VEDA-VARSHIT/Multi-threaded-HTTP-Server-Using-Socket-Programming/actions/workflows/ci.yml/badge.svg)](https://github.com/NEERASA-VEDA-VARSHIT/Multi-threaded-HTTP-Server-Using-Socket-Programming/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue.svg)](https://www.python.org/)
[![Code Style: Ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![Tests: 14/14 Passed](https://img.shields.io/badge/tests-14%20passed-brightgreen.svg)](tests/)

A lightweight, concurrent HTTP/1.1 web server implemented from scratch using raw Python TCP socket programming, queue-based thread pool concurrency, path containment security, and automated integration tests.

## ⚡ Quick Start

1. **Start the server:**
   ```bash
   python server.py
   ```

2. **Open your browser:**
   - Navigate to `http://127.0.0.1:8080/`
   - Test file downloads and navigation

3. **Test JSON uploads:**
   ```bash
   curl -X POST http://127.0.0.1:8080/upload \
     -H "Content-Type: application/json" \
     -d '{"name": "Test", "message": "Hello!"}'
   ```

## 🚀 Features

### Core Functionality
- **Multi-threaded Architecture**: Configurable thread pool for handling concurrent requests
- **Socket Programming**: Low-level TCP socket implementation
- **HTTP/1.1 Protocol**: Full request/response handling with proper headers
- **Static File Serving**: HTML, images, and text file delivery
- **Binary File Transfer**: Efficient binary downloads with proper MIME types
- **JSON Upload**: POST endpoint for JSON data uploads

### Security Features
- **Path Traversal Protection**: Prevents directory traversal attacks (../, ./, etc.)
- **Host Header Validation**: Ensures requests come from authorized hosts
- **Request Size Limits**: Prevents buffer overflow attacks
- **Input Sanitization**: Validates and sanitizes all input data

### Advanced Features
- **Connection Management**: Keep-alive support with configurable timeouts
- **Thread Pool Management**: Queue-based connection handling
- **Comprehensive Logging**: Detailed request/response logging with timestamps
- **Error Handling**: Proper HTTP status codes and error responses
- **Content-Type Detection**: Automatic MIME type detection

## 📁 Project Structure

```
project/
├── server.py                    # Main server implementation
├── README.md                   # This file
└── resources/
    ├── index.html              # Homepage
    ├── about.html              # About page
    ├── contact.html            # Contact page
    ├── sample.txt              # Sample text file
    ├── data.txt                # Additional text file
    ├── logo.png                # Small PNG image
    ├── large_image.png         # Large PNG image (>1MB)
    ├── photo.jpg               # Small JPEG image
    ├── large_photo.jpg         # Large JPEG image (>1MB)
    ├── test_data1.json         # Sample JSON for POST testing
    ├── test_data2.json         # Additional JSON for POST testing
    └── uploads/                # Directory for POST uploads (auto-created)
```

## 🛠️ Installation & Usage

### Prerequisites
- Python 3.7 or higher
- No external dependencies (uses only standard library)

### Running the Server

```bash
# Basic usage (default: localhost:8080, 10 threads)
python server.py

# Custom port
python server.py 9000

# Custom host and port
python server.py 9000 0.0.0.0

# Custom host, port, and thread pool size
python server.py 9000 0.0.0.0 20
```

### Command Line Arguments
1. **Port** (optional): Port number (default: 8080)
2. **Host** (optional): Host address (default: 127.0.0.1)
3. **Max Threads** (optional): Maximum thread pool size (default: 10)


## 🧪 Testing

### Browser Testing
Open your web browser and navigate to:
- `http://127.0.0.1:8080/` - View the homepage
- `http://127.0.0.1:8080/about.html` - View the about page
- `http://127.0.0.1:8080/contact.html` - View the contact page

### File Download Testing
Test binary file downloads by clicking on:
- `http://127.0.0.1:8080/logo.png` - Download small PNG image
- `http://127.0.0.1:8080/large_image.png` - Download large PNG image (>1MB)
- `http://127.0.0.1:8080/photo.jpg` - Download small JPEG image
- `http://127.0.0.1:8080/large_photo.jpg` - Download large JPEG image (>1MB)
- `http://127.0.0.1:8080/sample.txt` - Download text file
- `http://127.0.0.1:8080/data.txt` - Download additional text file

### POST Request Testing
Test JSON uploads using curl or Postman:
```bash
curl -X POST http://127.0.0.1:8080/upload \
  -H "Content-Type: application/json" \
  -d '{"name": "Test User", "message": "Hello Server!"}'
```

### Test Scenarios Covered

#### Basic Functionality
- ✅ GET / → Serves resources/index.html (displayed in browser)
- ✅ GET /about.html → Serves HTML file
- ✅ GET /logo.png → Downloads PNG file as binary
- ✅ GET /photo.jpg → Downloads JPEG file as binary
- ✅ GET /sample.txt → Downloads text file as binary
- ✅ POST /upload with JSON → Creates file in uploads directory

#### Error Handling
- ❌ GET /nonexistent.png → Returns 404
- ❌ PUT /index.html → Returns 405
- ❌ POST /upload with non-JSON → Returns 415

#### Security Tests
- ❌ GET /../etc/passwd → Returns 403
- ❌ GET /./././../config → Returns 403
- ❌ Request with Host: evil.com → Returns 403
- ❌ Request without Host header → Returns 400

#### Binary Transfer Tests
- ✅ Downloaded PNG file matches original (checksum verification)
- ✅ Downloaded JPEG file matches original
- ✅ Large image files (>1MB) transfer completely
- ✅ Binary data integrity maintained (no corruption)

#### Concurrency Tests
- ✅ Handle 5 simultaneous file downloads
- ✅ Queue connections when thread pool is full
- ✅ Multiple clients downloading large files simultaneously

## 🔧 Binary Transfer Implementation

The server implements efficient binary file transfer with the following features:

### File Reading
- Files are opened in binary mode (`'rb'`) to preserve data integrity
- Large files are read in 8KB chunks to manage memory efficiently
- Content-Length header is calculated and sent before file data

### Response Headers
```http
HTTP/1.1 200 OK
Content-Type: application/octet-stream
Content-Length: [file size in bytes]
Content-Disposition: attachment; filename="[filename]"
Date: [current date in RFC 7231 format]
Server: Multi-threaded HTTP Server
Connection: [keep-alive or close]
```

### Supported File Types
- `.html` → `text/html; charset=utf-8` (rendered in browser)
- `.txt` → `application/octet-stream` (downloaded as file)
- `.png` → `application/octet-stream` (downloaded as file)
- `.jpg/.jpeg` → `application/octet-stream` (downloaded as file)

## 🏗️ Thread Pool Architecture

The server uses a thread pool pattern for efficient concurrent request handling:

### Components
1. **Main Thread**: Accepts incoming connections
2. **Worker Threads**: Process individual client connections
3. **Connection Queue**: Queues connections when all workers are busy
4. **Thread Pool Manager**: Manages thread lifecycle and queue

### Thread Safety
- All shared resources are protected with locks
- Queue operations are thread-safe
- No race conditions or deadlocks
- Proper synchronization for logging and status updates

### Connection Handling
- Each connection is handled by a dedicated worker thread
- Keep-alive connections can handle multiple requests
- Connection timeout after 30 seconds of inactivity
- Maximum 100 requests per persistent connection

## 🔒 Security Measures Implemented

### Path Traversal Protection
- Validates all requested paths
- Prevents access to files outside the resources directory
- Blocks dangerous patterns: `../`, `./`, `//`
- Returns 403 Forbidden for unauthorized access attempts

### Host Header Validation
- Validates Host header in all requests
- Prevents host header injection attacks
- Only accepts requests from authorized hosts
- Returns 400/403 for invalid host headers

### Input Validation
- Validates HTTP request format
- Sanitizes all input data
- Limits request size to 8192 bytes
- Proper error handling for malformed requests



## 🧪 Automated Testing & Verification

The server features a comprehensive automated pytest test suite (	ests/test_server.py) with 14 unit and live socket integration tests:

`ash
# Run all tests
pytest -v

# Run with coverage report
pytest --cov=server --cov-report=term-missing

# Run lint and format check with Ruff
ruff check server.py tests/
ruff format --check server.py tests/
`

### Verified Test Contracts (14/14 Passing)
1. **Path Traversal Containment**: Enforces that ../, ../../etc/passwd, and Windows-style paths are blocked.
2. **HTTP/1.1 Request Parsing**: Validates request-line components, case-insensitive headers, and JSON bodies.
3. **RFC 7231 Response Formatting**: Verifies date headers, server tokens, status codes, and content lengths.
4. **Live Socket Verification**: Binds ephemeral socket listeners to test concurrent GET, 404, 403, 405, and 201 JSON uploads.

## 📊 Performance Metrics

The server has been tested with:
- **Concurrent Requests**: Successfully handles 10+ simultaneous requests
- **Large File Transfers**: Efficiently transfers files >1MB
- **Thread Pool Management**: Properly queues connections when saturated
- **Memory Usage**: Efficient memory management for binary transfers
- **Response Times**: Sub-second response times for most requests

## 🚧 Known Limitations

1. **Single Process**: Server runs in a single process (no process forking)
2. **Memory Usage**: Large file uploads are loaded entirely into memory
3. **No HTTPS**: HTTP only (no SSL/TLS support)
4. **Basic Authentication**: No user authentication system
5. **No Caching**: No response caching implemented
6. **No Compression**: No gzip compression for responses

## 🎯 Protocol Compliance & Architecture

### ✅ Server Configuration
- Runs on localhost (127.0.0.1) by default
- Default port 8080 with command-line argument support
- Configurable host, port, and thread pool size

### ✅ Socket Implementation
- TCP sockets for communication
- Proper socket lifecycle management
- Queue size of 100 for incoming connections

### ✅ Multi-threading & Concurrency
- Configurable thread pool (default: 10 threads)
- Connection queue for saturated thread pool
- Proper synchronization with mutexes/locks
- Thread-safe shared resource access

### ✅ HTTP Request Handling
- Parses method, path, version, and headers
- Supports GET and POST methods
- Returns 405 for unsupported methods
- Handles requests up to 8192 bytes

### ✅ File Serving
- HTML files served with proper content type
- Binary files downloaded with application/octet-stream
- Content-Disposition headers for file downloads
- Proper MIME type handling

### ✅ Security
- Path traversal protection
- Host header validation
- Input sanitization
- Comprehensive error handling

### ✅ Connection Management
- Keep-alive support with timeouts
- Connection limits (100 requests per connection)
- Proper connection lifecycle management

## 📝 Server Logs

The server provides comprehensive logging with timestamps and thread information:

```
[2025-10-10 11:20:43] [MainThread] HTTP Server started on http://127.0.0.1:8080
[2025-10-10 11:20:43] [MainThread] Thread pool size: 10
[2025-10-10 11:20:43] [MainThread] Serving files from 'C:\Users\INFINIX\Desktop\CN\Final project\resources'
[2025-10-10 11:20:43] [Thread-1] Connection from 127.0.0.1:57499
[2025-10-10 11:20:43] [Thread-1] Request: GET /large_image.png HTTP/1.1
[2025-10-10 11:20:43] [Thread-1] Host validation: 127.0.0.1:8080 ✓
[2025-10-10 11:20:43] [Thread-1] Sending binary file: large_image.png (1048620 bytes)
[2025-10-10 11:20:43] [Thread-1] Connection closed
```

## 🎉 Features Demonstrated

### Technical Implementation
- **Socket Programming**: Low-level TCP socket implementation
- **HTTP Protocol**: Complete HTTP/1.1 request/response handling
- **Multi-threading**: Efficient thread pool with connection queuing
- **Security**: Path traversal protection and host header validation
- **File Handling**: Binary file transfer with proper MIME types
- **Error Handling**: Comprehensive HTTP status code responses

### Implementation Features
- **Custom Server Name**: `Multi-threaded HTTP Server`
- **Clean Code Style**: Well-structured implementation
- **Educational Comments**: Comprehensive documentation
- **Unique Function Names**: Descriptive naming conventions

## 👨‍💻 Author

NEERASA VEDA VARSHIT

