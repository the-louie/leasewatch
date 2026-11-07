"""A small SMTP server for the tests (Python 3.12 has no smtpd): port 0, scripted replies, optional STARTTLS or
implicit TLS with a certificate made at test time (no key in the repo). Synthetic data only."""
from __future__ import annotations

import base64
import os
import shutil
import socket
import socketserver
import ssl
import subprocess
import threading


def make_cert(directory: str) -> tuple[str, str] | None:
    """A self-signed certificate for 127.0.0.1 (cert path, key path), or None without the openssl command."""
    if not shutil.which("openssl"):
        return None
    cert, key = os.path.join(directory, "cert.pem"), os.path.join(directory, "key.pem")
    r = subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
                        "-keyout", key, "-out", cert, "-days", "1", "-subj", "/CN=127.0.0.1",
                        "-addext", "subjectAltName=IP:127.0.0.1"], capture_output=True, timeout=60)
    return (cert, key) if r.returncode == 0 else None


class _Handler(socketserver.StreamRequestHandler):
    server: "FakeSmtp"

    def out(self, line: str) -> None:
        self.request.sendall(line.encode() + b"\r\n")

    def handle(self) -> None:
        srv = self.server
        try:
            if srv.implicit_tls:
                self.request = srv.tls.wrap_socket(self.request, server_side=True)
                self.rfile = self.request.makefile("rb")
                srv.tls_used = True
            self.out("220 mail.example.com ESMTP")
            self.session()
        except (OSError, ssl.SSLError):
            pass  # the client gave up (e.g. it refused the certificate)
        finally:
            if isinstance(self.request, ssl.SSLSocket):
                self.rfile.close()
                self.request.close()  # the server closes only the plain socket it accepted

    def finish(self) -> None:
        try:
            super().finish()
        except OSError:
            pass  # the client is gone

    def code(self, verb: str, default: str) -> None:
        self.out(self.server.replies.get(verb, default))

    def session(self) -> None:
        srv = self.server
        while True:
            raw = self.rfile.readline()
            if not raw:
                return
            line = raw.decode("utf-8", "replace").rstrip("\r\n")
            verb = line.split(" ", 1)[0].upper()
            srv.commands.append(verb)
            if verb in ("EHLO", "HELO"):
                srv.ehlo_names.append(line.split(" ", 1)[1] if " " in line else "")
                ext = list(srv.extensions)
                if srv.tls_used:
                    ext = [e for e in ext if e != "STARTTLS"]
                lines = ["mail.example.com"] + ext
                for i, e in enumerate(lines):
                    self.out(("250-" if i < len(lines) - 1 else "250 ") + e)
            elif verb == "STARTTLS":
                self.out("220 go ahead")
                self.request = srv.tls.wrap_socket(self.request, server_side=True)
                self.rfile = self.request.makefile("rb")
                srv.tls_used = True
            elif verb == "AUTH":
                parts = line.split(" ")
                if parts[1].upper() == "PLAIN":
                    blob = parts[2] if len(parts) > 2 else None
                    if blob is None:
                        self.out("334 ")
                        blob = self.rfile.readline().decode().strip()
                    _, user, pw = base64.b64decode(blob).decode().split("\0")
                else:  # LOGIN
                    self.out("334 VXNlcm5hbWU6")
                    user = base64.b64decode(self.rfile.readline().strip()).decode()
                    self.out("334 UGFzc3dvcmQ6")
                    pw = base64.b64decode(self.rfile.readline().strip()).decode()
                srv.auth.append((user, pw))
                self.code("AUTH", "235 ok")
            elif verb == "MAIL":
                srv.mail_from.append(line)
                self.code("MAIL", "250 ok")
            elif verb == "RCPT":
                srv.rcpts.append(line)
                self.code("RCPT", "250 ok")
            elif verb == "DATA":
                r = srv.replies.get("DATA_START", "354 go")
                self.out(r)
                if not r.startswith("354"):
                    continue
                data = b""
                while True:
                    chunk = self.rfile.readline()
                    if not chunk or chunk == b".\r\n":
                        break
                    data += chunk[1:] if chunk.startswith(b"..") else chunk
                srv.messages.append(data)
                self.code("DATA", "250 queued")
            elif verb == "QUIT":
                self.out("221 bye")
                return
            elif verb in ("RSET", "NOOP"):
                self.out("250 ok")
            else:
                self.out("502 not implemented")


class FakeSmtp(socketserver.ThreadingTCPServer):
    """Records what the client sent. `replies` maps a verb (AUTH, MAIL, RCPT, DATA, DATA_START) to a reply line."""
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, extensions: tuple = ("8BITMIME", "AUTH PLAIN LOGIN"), tls: ssl.SSLContext | None = None,
                 implicit_tls: bool = False, replies: dict | None = None) -> None:
        super().__init__(("127.0.0.1", 0), _Handler)
        self.extensions, self.tls, self.implicit_tls = extensions, tls, implicit_tls
        self.replies = replies or {}
        self.commands: list[str] = []
        self.ehlo_names: list[str] = []
        self.auth: list[tuple[str, str]] = []
        self.mail_from: list[str] = []
        self.rcpts: list[str] = []
        self.messages: list[bytes] = []
        self.tls_used = False
        self.port = self.server_address[1]
        self._t = threading.Thread(target=self.serve_forever, daemon=True)
        self._t.start()

    def close(self) -> None:
        self.shutdown()
        self.server_close()
        self._t.join(5)


def server_tls(cert: str, key: str) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    return ctx


def silent_listener() -> socket.socket:
    """A socket that accepts the TCP connection (backlog) but never greets: the client must time out."""
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    s.listen(1)
    return s

