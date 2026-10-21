import json
import os
import socket
import threading

import pytest

from server import (
    RESOURCES_DIR,
    ClientConnectionHandler,
    create_http_response,
    parse_http_request,
    secure_path_join,
)


class TestSecurityAndPathContainment:
    def test_secure_path_join_allows_valid_subpaths(self):
        valid = secure_path_join(RESOURCES_DIR, "index.html")
        assert valid is not None
        assert os.path.isabs(valid)
        assert valid.startswith(os.path.abspath(RESOURCES_DIR))

    def test_secure_path_join_blocks_parent_directory_traversal(self):
        malicious = secure_path_join(RESOURCES_DIR, "../server.py")
        assert malicious is None

    def test_secure_path_join_blocks_deep_traversal(self):
        malicious = secure_path_join(RESOURCES_DIR, "../../../etc/passwd")
        assert malicious is None

    def test_secure_path_join_blocks_windows_escapes(self):
        malicious = secure_path_join(RESOURCES_DIR, "..\\..\\windows\\system32")
        assert malicious is None


class TestHTTPRequestParsing:
    def test_parse_valid_get_request(self):
        raw = b"GET /index.html HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nUser-Agent: test\r\n\r\n"
        req = parse_http_request(raw)
        assert req["method"] == "GET"
        assert req["path"] == "/index.html"
        assert req["version"] == "HTTP/1.1"
        assert req["headers"]["host"] == "127.0.0.1:8080"
        assert req["headers"]["user-agent"] == "test"

    def test_parse_post_request_with_body(self):
        body = b'{"key": "value"}'
        raw = (
            b"POST /upload HTTP/1.1\r\n"
            b"Host: 127.0.0.1:8080\r\n"
            b"Content-Type: application/json\r\n"
            b"Content-Length: 16\r\n\r\n" + body
        )
        req = parse_http_request(raw)
        assert req["method"] == "POST"
        assert req["path"] == "/upload"
        assert req["initial_body"] == body

    def test_parse_malformed_request_line_raises_error(self):
        raw = b"INVALID_REQUEST\r\n\r\n"
        with pytest.raises(ValueError):
            parse_http_request(raw)

    def test_parse_empty_request_raises_error(self):
        with pytest.raises(ValueError):
            parse_http_request(b"")


class TestHTTPResponseBuilder:
    def test_create_http_response_headers_and_status(self):
        body = b"<h1>Hello World</h1>"
        headers = {"Content-Type": "text/html", "Content-Length": str(len(body))}
        resp = create_http_response(200, "OK", headers, body)
        resp_text = resp.decode("latin1")

        assert resp_text.startswith("HTTP/1.1 200 OK\r\n")
        assert "Content-Type: text/html\r\n" in resp_text
        assert "Server: Multi-threaded HTTP Server\r\n" in resp_text
        assert "Date: " in resp_text
        assert resp_text.endswith("<h1>Hello World</h1>")


class TestLiveSocketServer:
    @classmethod
    def setup_class(cls):
        """Bind a live server socket on an ephemeral port to test client handlers."""
        cls.server_host = "127.0.0.1"
        cls.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        cls.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        cls.server_sock.bind((cls.server_host, 0))
        cls.server_port = cls.server_sock.getsockname()[1]
        cls.server_sock.listen(5)
        cls.running = True

        def accept_loop():
            while cls.running:
                try:
                    cls.server_sock.settimeout(0.5)
                    client_sock, client_addr = cls.server_sock.accept()
                    handler = ClientConnectionHandler(
                        client_sock, client_addr, cls.server_host, cls.server_port
                    )
                    t = threading.Thread(target=handler.handle, daemon=True)
                    t.start()
                except socket.timeout:
                    continue
                except OSError:
                    break

        cls.thread = threading.Thread(target=accept_loop, daemon=True)
        cls.thread.start()

    @classmethod
    def teardown_class(cls):
        cls.running = False
        try:
            cls.server_sock.close()
        except Exception:
            pass

    def send_raw_request(self, raw_bytes):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((self.server_host, self.server_port))
        s.sendall(raw_bytes)
        s.settimeout(2.0)
        chunks = []
        try:
            while True:
                data = s.recv(4096)
                if not data:
                    break
                chunks.append(data)
        except socket.timeout:
            pass
        finally:
            s.close()
        return b"".join(chunks)

    def test_get_index_html_returns_200(self):
        req = (
            f"GET /index.html HTTP/1.1\r\n"
            f"Host: {self.server_host}:{self.server_port}\r\n"
            f"Connection: close\r\n\r\n"
        ).encode()
        resp = self.send_raw_request(req)
        assert b"HTTP/1.1 200 OK" in resp
        assert b"text/html" in resp

    def test_get_nonexistent_file_returns_404(self):
        req = (
            f"GET /does_not_exist_xyz.html HTTP/1.1\r\n"
            f"Host: {self.server_host}:{self.server_port}\r\n"
            f"Connection: close\r\n\r\n"
        ).encode()
        resp = self.send_raw_request(req)
        assert b"HTTP/1.1 404 Not Found" in resp

    def test_path_traversal_returns_403_or_404(self):
        req = (
            f"GET /../server.py HTTP/1.1\r\n"
            f"Host: {self.server_host}:{self.server_port}\r\n"
            f"Connection: close\r\n\r\n"
        ).encode()
        resp = self.send_raw_request(req)
        # Server must reject traversal with 403 Forbidden or 404 Not Found
        assert (b"HTTP/1.1 403 Forbidden" in resp) or (b"HTTP/1.1 404 Not Found" in resp)

    def test_unsupported_method_returns_405(self):
        req = (
            f"DELETE /index.html HTTP/1.1\r\n"
            f"Host: {self.server_host}:{self.server_port}\r\n"
            f"Connection: close\r\n\r\n"
        ).encode()
        resp = self.send_raw_request(req)
        assert b"HTTP/1.1 405 Method Not Allowed" in resp

    def test_post_upload_json_returns_201(self):
        payload = json.dumps({"test_key": "test_val"}).encode()
        req = (
            f"POST /upload HTTP/1.1\r\n"
            f"Host: {self.server_host}:{self.server_port}\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(payload)}\r\n"
            f"Connection: close\r\n\r\n"
        ).encode() + payload
        resp = self.send_raw_request(req)
        assert b"HTTP/1.1 201 Created" in resp
        assert b"application/json" in resp
