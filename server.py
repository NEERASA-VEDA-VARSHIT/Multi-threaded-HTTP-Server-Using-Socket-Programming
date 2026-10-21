import argparse
import datetime
import email.utils
import json
import logging
import os
import queue
import random
import socket
import string
import threading
from urllib.parse import unquote, urlparse

# Server Configuration

# Network configuration
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8080
DEFAULT_POOL_SIZE = 10
LISTEN_BACKLOG = 100
MAX_REQUEST_SIZE = 8192

# Directory structure
RESOURCES_DIR = os.path.join(os.path.dirname(__file__), "resources")  # web content directory
UPLOADS_DIR = os.path.join(RESOURCES_DIR, "uploads")  # POST upload destination

# Connection management
CONN_TIMEOUT = 30
MAX_REQS_PER_CONN = 100
CONN_QUEUE_MAXSIZE = 200

# File type classification
BINARY_EXT_WHITELIST = {".png", ".jpg", ".jpeg", ".txt"}
HTML_EXT = ".html"

# Logging Configuration
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(threadName)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("http-server")

# Thread synchronization
lock = threading.Lock()  # protects shared resources from race conditions

# Utility Functions


def http_date_now():
    """Generate RFC 7231 compliant HTTP date string HTTP protocol requirement for date header"""
    return email.utils.formatdate(timeval=None, localtime=False, usegmt=True)


def generate_upload_id(n=6):
    """Create unique identifier for uploaded files"""
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def secure_path_join(base, *paths):
    """Safely join file paths while preventing directory traversal attacks
    normalize paths and verify they stay within base directory
    Returns absolute path if safe, None if potential attack detected
    """
    # Normalize the path to remove any .. or . components
    joined = os.path.normpath(os.path.join(base, *paths))
    base_abs = os.path.abspath(base)
    joined_abs = os.path.abspath(joined)

    # Security check: ensure the result is within our base directory
    if not joined_abs.startswith(base_abs + os.sep) and joined_abs != base_abs:
        return None  # Potential path traversal attack detected!
    return joined_abs


def parse_http_request(data_bytes):
    """Parse raw HTTP request data into structured format
    handles the complexity of HTTP request parsing
    Returns structured dict or raises ValueError for malformed requests
    """
    try:
        # Decode the request data
        text = data_bytes.decode()
    except UnicodeDecodeError:
        raise ValueError("Invalid request encoding")

    # Split headers and body at the double CRLF separator
    if "\r\n\r\n" not in text:
        # Incomplete request - headers only
        header_part = text
        body = b""
    else:
        header_part, rest = text.split("\r\n\r\n", 1)
        body = rest.encode()

    lines = header_part.split("\r\n")
    if len(lines) == 0:
        raise ValueError("Empty request received")

    # Parse request line: METHOD PATH VERSION
    request_line = lines[0]
    parts = request_line.split(" ")
    if len(parts) != 3:
        raise ValueError("Invalid request line format")

    method, raw_path, version = parts

    # Parse HTTP headers into dictionary
    headers = {}
    for line in lines[1:]:
        if not line:
            continue
        if ":" not in line:
            raise ValueError("Invalid header format")
        key, value = line.split(":", 1)
        headers[key.strip().lower()] = value.strip()  # normalize header names

    return {
        "method": method.upper(),
        "raw_path": raw_path,
        "path": urlparse(raw_path).path,  # extract clean path
        "version": version.upper(),
        "headers": headers,
        "initial_body": body,
    }


def create_http_response(status_code, reason, headers=None, body=b""):
    """Construct properly formatted HTTP response
    building HTTP responses with correct formatting
    """
    if headers is None:
        headers = {}

    # Build status line according to HTTP/1.1 specification
    status_line = f"HTTP/1.1 {status_code} {reason}\r\n"

    # Ensure required headers are present
    if "Date" not in headers:
        headers["Date"] = http_date_now()
    if "Server" not in headers:
        headers["Server"] = "Multi-threaded HTTP Server"

    # Format headers section
    header_lines = "".join(f"{k}: {v}\r\n" for k, v in headers.items())
    response_head = (status_line + header_lines + "\r\n").encode()

    return response_head + body


# Client Connection Handler


class ClientConnectionHandler:
    """Handles a single client connection. This is where the real work happens!"""

    def __init__(self, client_sock, client_addr, server_host, server_port):
        self.sock = client_sock
        self.addr = client_addr
        self.server_host = server_host
        self.server_port = server_port
        self.requests_handled = 0  # track how many requests this connection has handled
        self.keep_alive = True  # whether to keep connection alive
        self.sock.settimeout(CONN_TIMEOUT)  # set timeout as required

    def close(self):
        """Safely close the socket connection"""
        try:
            self.sock.close()
        except Exception:
            pass  # ignore errors when closing

    def handle(self):
        """Main method that processes requests from this client."""
        thread_name = threading.current_thread().name
        log.info(f"Connection from {self.addr[0]}:{self.addr[1]}")

        try:
            # Keep processing requests until connection closes or max requests reached
            while True:
                # Check if we've handled too many requests on this connection
                if self.requests_handled >= MAX_REQS_PER_CONN:
                    log.info(f"Connection: reached max requests ({MAX_REQS_PER_CONN}), closing")
                    break

                # Try to read a request from the client
                try:
                    data = self._recv_request()
                except socket.timeout:
                    log.info("Connection idle timeout, closing")
                    break

                if not data:  # client disconnected
                    break

                # Parse the HTTP request
                try:
                    req = parse_http_request(data)
                except ValueError as e:
                    log.info(f"Request parsing error: {e}")
                    resp = create_http_response(
                        400, "Bad Request", headers={"Content-Length": "0", "Connection": "close"}
                    )
                    self.sock.send(resp)
                    break

                # Security check: validate Host header (assignment requirement)
                host_header = req["headers"].get("host")
                if host_header is None:
                    log.info("Host header missing")
                    resp = create_http_response(
                        400, "Bad Request", headers={"Content-Length": "0", "Connection": "close"}
                    )
                    self.sock.send(resp)
                    break

                # Check if host is valid (prevents host header injection attacks)
                if not self._validate_host(host_header):
                    log.info(f"Host validation failed: {host_header}")
                    resp = create_http_response(
                        403, "Forbidden", headers={"Content-Length": "0", "Connection": "close"}
                    )
                    self.sock.send(resp)
                    break

                log.info(f"Request: {req['method']} {req['raw_path']} {req['version']}")
                log.info(f"Host validation: {host_header} ✓")

                # Handle Connection header for keep-alive (assignment requirement)
                conn_hdr = req["headers"].get("connection")
                if conn_hdr:
                    conn_hdr_low = conn_hdr.lower()
                    if conn_hdr_low == "close":
                        self.keep_alive = False
                    elif conn_hdr_low == "keep-alive":
                        self.keep_alive = True
                else:
                    # Default behavior: HTTP/1.1 keep-alive, HTTP/1.0 close
                    if req["version"] == "HTTP/1.0":
                        self.keep_alive = False
                    else:
                        self.keep_alive = True

                # Route the request to appropriate handler
                if req["method"] == "GET":
                    self.handle_get(req)
                elif req["method"] == "POST":
                    self.handle_post(req)
                else:
                    # Assignment says to return 405 for unsupported methods
                    resp = create_http_response(
                        405,
                        "Method Not Allowed",
                        headers={"Content-Length": "0", "Connection": "close"},
                    )
                    self.sock.send(resp)
                    break

                self.requests_handled += 1

                # If not keep-alive, close connection after this request
                if not self.keep_alive:
                    break

        except Exception as e:
            log.exception("Internal server error")
            try:
                resp = create_http_response(
                    500,
                    "Internal Server Error",
                    headers={"Content-Length": "0", "Connection": "close"},
                )
                self.sock.send(resp)
            except Exception:
                pass
        finally:
            self.close()
            log.info("Connection closed")

    def _recv_request(self):
        """Read a complete HTTP request from the socket."""
        # Read up to MAX_REQUEST_SIZE bytes for header + initial body
        # We'll handle additional body bytes if Content-Length indicates more
        chunks = []
        total = 0
        self.sock.settimeout(CONN_TIMEOUT)

        while True:
            try:
                part = self.sock.recv(4096)  # read in chunks
            except socket.timeout:
                raise
            if not part:  # connection closed
                break

            chunks.append(part)
            total += len(part)

            # Don't read more than the max request size
            if total >= MAX_REQUEST_SIZE:
                break

            # Stop early if we've reached header/body separator
            if b"\r\n\r\n" in b"".join(chunks):
                break

            # If we got less than a full chunk, probably end of data
            if len(part) < 4096:
                break

        data = b"".join(chunks)

        # If there is a Content-Length header, ensure we read the entire body
        # This is important for POST requests with large bodies
        try:
            temp_text = data.decode()
            if "\r\n\r\n" in temp_text:
                head, rest = temp_text.split("\r\n\r\n", 1)
                for line in head.split("\r\n")[1:]:
                    if ":" in line:
                        k, v = line.split(":", 1)
                        if k.strip().lower() == "content-length":
                            try:
                                cl = int(v.strip())
                            except ValueError:
                                cl = 0
                            current_body = rest.encode()
                            to_read = cl - len(current_body)
                            # Read remaining body data
                            while to_read > 0:
                                part = self.sock.recv(min(4096, to_read))
                                if not part:
                                    break
                                data += part
                                to_read -= len(part)
                            break
        except Exception:
            pass  # if parsing fails, just return what we have

        return data

    def _validate_host(self, host_header):
        """Validate the Host header for security.
        My security implementation prevents host header injection attacks.
        This is a critical security measure I learned about in networking class.
        """
        # host_header can be 'localhost:8080' or 'localhost'
        host_only = host_header.split(":")[0]
        port_part = None

        if ":" in host_header:
            try:
                port_part = int(host_header.split(":")[1])
            except Exception:
                port_part = None

        # Accept if host matches server_host (or localhost/127.0.0.1) and port matches
        allowed_hosts = {self.server_host, "localhost", "127.0.0.1"}

        # If server_host is 0.0.0.0 accept any of allowed local addresses
        if self.server_host == "0.0.0.0":
            allowed_hosts = {"localhost", "127.0.0.1", "0.0.0.0"}

        if host_only not in allowed_hosts:
            return False

        if port_part is not None and port_part != self.server_port:
            return False

        return True

    def handle_get(self, req):
        """Handle GET requests - serve files from the resources directory.
        My implementation of file serving with proper MIME type handling.
        This was one of the most interesting parts to implement!
        """
        path = unquote(req["path"])  # decode URL-encoded path

        # Security check: prevent path traversal attacks (assignment requirement)
        if any(x in path for x in ["..", "./", "//"]):
            log.info(f"Path traversal attempt blocked: {path}")
            resp = create_http_response(
                403, "Forbidden", headers={"Content-Length": "0", "Connection": "close"}
            )
            self.sock.send(resp)
            return

        # Default to index.html for root path (assignment requirement)
        if path == "/":
            path = "/index.html"

        # Map to resources directory using my secure path function
        rel_path = path.lstrip("/")
        file_path = secure_path_join(RESOURCES_DIR, rel_path)

        if file_path is None:
            log.info(f"Forbidden path: {path}")
            resp = create_http_response(
                403, "Forbidden", headers={"Content-Length": "0", "Connection": "close"}
            )
            self.sock.send(resp)
            return

        if not os.path.exists(file_path) or not os.path.isfile(file_path):
            resp = create_http_response(
                404,
                "Not Found",
                headers={
                    "Content-Length": "0",
                    "Connection": "close" if not self.keep_alive else "keep-alive",
                },
            )
            self.sock.send(resp)
            return

        _, ext = os.path.splitext(file_path.lower())

        if ext == HTML_EXT:
            # Serve HTML files with proper content type (assignment requirement)
            try:
                with open(file_path, "rb") as f:
                    content = f.read()
                headers = {
                    "Content-Type": "text/html; charset=utf-8",
                    "Content-Length": str(len(content)),
                    "Connection": "keep-alive" if self.keep_alive else "close",
                    "Keep-Alive": f"timeout={CONN_TIMEOUT}, max={MAX_REQS_PER_CONN}",
                }
                resp = create_http_response(200, "OK", headers=headers, body=content)
                self.sock.send(resp)
                log.info(f"Serving HTML: {os.path.basename(file_path)} ({len(content)} bytes)")
            except Exception:
                log.exception("Error serving HTML")
                resp = create_http_response(
                    500,
                    "Internal Server Error",
                    headers={"Content-Length": "0", "Connection": "close"},
                )
                self.sock.send(resp)
            return

        elif ext in BINARY_EXT_WHITELIST:
            # For binary files, send as application/octet-stream with download headers
            # This is the binary transfer requirement from the assignment
            try:
                file_size = os.path.getsize(file_path)
                headers = {
                    "Content-Type": "application/octet-stream",
                    "Content-Length": str(file_size),
                    "Content-Disposition": f'attachment; filename="{os.path.basename(file_path)}"',
                    "Connection": "keep-alive" if self.keep_alive else "close",
                    "Date": http_date_now(),
                }
                # Send headers first
                head = (
                    "HTTP/1.1 200 OK\r\n"
                    + "".join(f"{k}: {v}\r\n" for k, v in headers.items())
                    + "\r\n"
                ).encode()
                self.sock.send(head)

                # Send file in chunks for efficiency
                sent = 0
                with open(file_path, "rb") as f:
                    while True:
                        chunk = f.read(8192)  # 8KB chunks
                        if not chunk:
                            break
                        self.sock.send(chunk)
                        sent += len(chunk)
                log.info(f"Sending binary file: {os.path.basename(file_path)} ({sent} bytes)")
            except Exception:
                log.exception("Error sending binary")
                resp = create_http_response(
                    500,
                    "Internal Server Error",
                    headers={"Content-Length": "0", "Connection": "close"},
                )
                self.sock.send(resp)
            return
        else:
            # Unsupported file type (assignment requirement)
            resp = create_http_response(
                415,
                "Unsupported Media Type",
                headers={"Content-Length": "0", "Connection": "close"},
            )
            self.sock.send(resp)
            return

    def handle_post(self, req):
        """Handle POST requests for JSON uploads.
        My implementation of JSON file upload handling.
        I found this challenging to get the file naming and response format correct.
        """
        # Only accept application/json (assignment requirement)
        ctype = req["headers"].get("content-type", "")
        if "application/json" not in ctype:
            resp = create_http_response(
                415,
                "Unsupported Media Type",
                headers={"Content-Length": "0", "Connection": "close"},
            )
            self.sock.send(resp)
            return

        # Get Content-Length and read body fully
        cl = req["headers"].get("content-length")
        try:
            content_length = int(cl) if cl else 0
        except ValueError:
            content_length = 0

        body = req.get("initial_body", b"")

        # If body shorter than declared, try to read remaining
        to_read = content_length - len(body)
        while to_read > 0:
            more = self.sock.recv(min(4096, to_read))
            if not more:
                break
            body += more
            to_read -= len(more)

        # Parse JSON data
        try:
            body_text = body.decode()
            data = json.loads(body_text)
        except Exception:
            log.info("Invalid JSON in POST")
            resp = create_http_response(
                400, "Bad Request", headers={"Content-Length": "0", "Connection": "close"}
            )
            self.sock.send(resp)
            return

        # Create uploads dir if not exists
        os.makedirs(UPLOADS_DIR, exist_ok=True)

        # Generate unique filename as required by assignment
        ts = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        fname = f"upload_{ts}_{generate_upload_id(6)}.json"
        fpath = os.path.join(UPLOADS_DIR, fname)

        try:
            # Write JSON data to file
            with open(fpath, "w") as f:
                json.dump(data, f, indent=2)

            # Create success response as specified in assignment
            body_resp = json.dumps(
                {
                    "status": "success",
                    "message": "File created successfully",
                    "filepath": f"/uploads/{fname}",
                }
            ).encode()

            headers = {
                "Content-Type": "application/json",
                "Content-Length": str(len(body_resp)),
                "Connection": "keep-alive" if self.keep_alive else "close",
                "Date": http_date_now(),
            }
            resp = create_http_response(201, "Created", headers=headers, body=body_resp)
            self.sock.send(resp)
            log.info(f"Upload created: {fpath}")
        except Exception:
            log.exception("Error writing upload file")
            resp = create_http_response(
                500, "Internal Server Error", headers={"Content-Length": "0", "Connection": "close"}
            )
            self.sock.send(resp)


# Multi-Threaded HTTP Server
# My main server implementation using thread pool pattern


class MultiThreadedHTTPServer:
    """Main server class that manages the thread pool and accepts connections."""

    def __init__(self, host, port, pool_size=DEFAULT_POOL_SIZE):
        self.host = host
        self.port = port
        self.pool_size = pool_size
        self.conn_queue = queue.Queue(maxsize=CONN_QUEUE_MAXSIZE)  # queue for pending connections
        self.workers = []  # list of worker threads
        self.shutdown_flag = threading.Event()  # flag to stop the server

    def start(self):
        """Start the HTTP server with thread pool.
        This is where the magic happens - accepting connections and assigning them to threads!
        """
        # Create uploads dir
        os.makedirs(UPLOADS_DIR, exist_ok=True)

        # Start worker threads (assignment requirement)
        for i in range(self.pool_size):
            t = threading.Thread(target=self.worker_loop, name=f"Thread-{i + 1}", daemon=True)
            t.start()
            self.workers.append(t)

        # Start acceptor socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # allow port reuse
            s.bind((self.host, self.port))
            s.listen(LISTEN_BACKLOG)  # queue up to 100 connections

            log.info(f"HTTP Server started on http://{self.host}:{self.port}")
            log.info(f"Thread pool size: {self.pool_size}")
            log.info(f"Serving files from '{RESOURCES_DIR}'")
            log.info("Press Ctrl+C to stop the server")

            try:
                while not self.shutdown_flag.is_set():
                    try:
                        client_sock, client_addr = s.accept()  # accept new connection

                        # Try to queue the connection for a worker thread
                        try:
                            self.conn_queue.put_nowait((client_sock, client_addr))
                            qsize = self.conn_queue.qsize()
                            if qsize > self.pool_size:
                                log.warning("Thread pool saturated, queuing connection")
                            else:
                                log.info(f"Connection queued (queue size {qsize})")
                        except queue.Full:
                            # All threads busy and queue full - send 503 (assignment requirement)
                            log.warning("Connection queue full, rejecting with 503")
                            try:
                                resp = create_http_response(
                                    503,
                                    "Service Unavailable",
                                    headers={
                                        "Retry-After": "5",
                                        "Content-Length": "0",
                                        "Connection": "close",
                                    },
                                )
                                client_sock.send(resp)
                            except Exception:
                                pass
                            client_sock.close()
                    except socket.timeout:
                        continue  # timeout is normal, just check shutdown flag
            except KeyboardInterrupt:
                log.info("Shutting down server...")
                self.shutdown_flag.set()
            finally:
                # Clean up: close any queued sockets
                while not self.conn_queue.empty():
                    try:
                        csock, _ = self.conn_queue.get_nowait()
                        csock.close()
                    except Exception:
                        pass
                log.info("Server stopped")

    def worker_loop(self):
        """Worker thread that processes connections from the queue.
        This runs in each worker thread and handles the actual HTTP requests.
        """
        while not self.shutdown_flag.is_set():
            try:
                # Wait for a connection from the queue
                client_sock, client_addr = self.conn_queue.get(timeout=1)
            except queue.Empty:
                continue  # timeout is normal, just check shutdown flag

            thread_name = threading.current_thread().name
            log.info(f"Connection dequeued, assigned to {thread_name}")

            # Create a handler for this connection and process it
            handler = ClientConnectionHandler(client_sock, client_addr, self.host, self.port)
            handler.handle()
            self.conn_queue.task_done()


# CLI
# Command line interface - this handles the arguments as required by the assignment


def main():
    """Main function that starts the HTTP server."""
    parser = argparse.ArgumentParser(description="Multi-threaded HTTP Server")
    parser.add_argument(
        "port", nargs="?", type=int, default=DEFAULT_PORT, help="port to bind (default 8080)"
    )
    parser.add_argument(
        "host", nargs="?", default=DEFAULT_HOST, help="host to bind (default 127.0.0.1)"
    )
    parser.add_argument(
        "pool", nargs="?", type=int, default=DEFAULT_POOL_SIZE, help="thread pool size (default 10)"
    )
    args = parser.parse_args()

    host = args.host
    port = args.port
    pool_size = max(1, args.pool)  # ensure at least 1 thread

    # Initialize required directories
    if not os.path.exists(RESOURCES_DIR):
        os.makedirs(RESOURCES_DIR, exist_ok=True)
    if not os.path.exists(UPLOADS_DIR):
        os.makedirs(UPLOADS_DIR, exist_ok=True)

    # Create and start the server
    print(f"Starting HTTP Server on {host}:{port} with {pool_size} threads...")
    server = MultiThreadedHTTPServer(host, port, pool_size)
    server.start()


if __name__ == "__main__":
    main()
