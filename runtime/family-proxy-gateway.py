#!/usr/bin/env python3
"""Single-origin cookie login gateway for the family proxy management UI."""

import base64
import hashlib
import hmac
import http.client
import ipaddress
import os
import secrets
import threading
import time
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

CONFIG = Path("/etc/family-proxy-ui/router.env")
SECRET_PATH = Path("/etc/family-proxy-ui/gateway.secret")
LAN = ipaddress.ip_network("__FAMILY_LAN_CIDR__")
SESSION_TTL = 12 * 60 * 60
HOP_BY_HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailers", "transfer-encoding", "upgrade"}

LOGIN_PAGE = '''<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>家庭旁路</title><style>:root{color-scheme:dark;font-family:-apple-system,BlinkMacSystemFont,"PingFang SC",sans-serif;background:#000;color:#f5f5f7}*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;padding:20px}.box{width:min(360px,100%);padding:28px;border:1px solid #2c2c2e;border-radius:10px;background:#1c1c1e}h1{font-size:24px;margin:0 0 8px}p{margin:0 0 22px;color:#98989d;font-size:14px}label{display:block;margin:13px 0 6px;font-size:13px}input{width:100%;height:40px;border:1px solid #48484a;border-radius:7px;background:#2c2c2e;color:#fff;padding:0 11px;font:15px inherit;outline:none}input:focus{border-color:#0a84ff;box-shadow:0 0 0 3px rgba(10,132,255,.2)}button{width:100%;height:40px;margin-top:20px;border:0;border-radius:7px;background:#0a84ff;color:#fff;font:600 15px inherit}.error{min-height:18px;margin-top:12px;color:#ff6961;font-size:13px}</style><main class="box"><h1>家庭旁路</h1><p>登录后可管理设备、规则与机场候选池。</p><form method="post" action="/login"><label>用户名</label><input name="username" autocomplete="username" required autofocus><label>密码</label><input name="password" type="password" autocomplete="current-password" required><button>登录</button><div class="error">__ERROR__</div></form></main>'''


def config():
    return dict(line.strip().split("=", 1) for line in CONFIG.read_text().splitlines()
                if "=" in line and not line.lstrip().startswith("#"))


def secret():
    value = SECRET_PATH.read_bytes()
    if len(value) < 32:
        raise RuntimeError("gateway secret is invalid")
    return value.strip()


def credentials_valid(username, password):
    values = config()
    try:
        digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(values["UI_PASSWORD_SALT"]), 210000).hex()
        return hmac.compare_digest(username, values["UI_USERNAME"]) and hmac.compare_digest(digest, values["UI_PASSWORD_HASH"])
    except (KeyError, ValueError):
        return False


def sign(payload):
    return hmac.new(secret(), payload.encode(), hashlib.sha256).hexdigest()


def make_session(username):
    payload = f"{int(time.time())}:{username}:{secrets.token_urlsafe(12)}"
    return base64.urlsafe_b64encode((payload + ":" + sign(payload)).encode()).decode().rstrip("=")


def valid_session(cookie_header):
    try:
        cookies = SimpleCookie(cookie_header)
        raw = cookies["family_session"].value
        decoded = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)).decode()
        issued, username, nonce, signature = decoded.rsplit(":", 3)
        payload = f"{issued}:{username}:{nonce}"
        return int(issued) + SESSION_TTL >= time.time() and hmac.compare_digest(signature, sign(payload))
    except (KeyError, ValueError, UnicodeDecodeError):
        return False


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def allowed(self):
        try:
            return ipaddress.ip_address(self.client_address[0]) in LAN
        except ValueError:
            return False

    def page(self, status=HTTPStatus.OK, error=""):
        body = LOGIN_PAGE.replace("__ERROR__", error).encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def redirect(self, location):
        self.send_response(HTTPStatus.SEE_OTHER)
        self.send_header("Location", location)
        self.send_header("Cache-Control", "no-store")
        self.end_headers()

    def login(self):
        size = int(self.headers.get("Content-Length", "0"))
        if size > 8192:
            self.page(HTTPStatus.BAD_REQUEST, "请求过大")
            return
        body = parse_qs(self.rfile.read(size).decode(errors="replace"))
        username = body.get("username", [""])[0]
        password = body.get("password", [""])[0]
        if not credentials_valid(username, password):
            self.page(HTTPStatus.UNAUTHORIZED, "用户名或密码不正确")
            return
        self.send_response(HTTPStatus.SEE_OTHER)
        self.send_header("Location", "/")
        self.send_header("Set-Cookie", f"family_session={make_session(username)}; Path=/; Max-Age={SESSION_TTL}; HttpOnly; SameSite=Strict")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()

    def dns_request(self, path):
        return path.startswith((
            "/dns/", "/api/v1/", "/api/v2/", "/plugins/", "/maintenance-api/",
        ))

    def target(self, path, query):
        if path == "/airport":
            return ("redirect", "/airport/")
        if path == "/dns":
            return ("redirect", "/dns/")
        if path.startswith("/airport/"):
            suffix = path[len("/airport"):]
            return ("backend", "127.0.0.1", 18090, suffix + ("?" + query if query else ""))
        if path.startswith("/dns/"):
            suffix = path[len("/dns"):]
            return ("backend", "__FAMILY_PROXY_IP__", 18091, suffix + ("?" + query if query else ""))
        if path.startswith("/maintenance-api/"):
            return ("backend", "127.0.0.1", 18102, path[len("/maintenance-api"):] + ("?" + query if query else ""))
        if path.startswith(("/api/v1/", "/api/v2/", "/plugins/")):
            return ("backend", "__FAMILY_PROXY_IP__", 18091, path + ("?" + query if query else ""))
        return ("backend", "127.0.0.1", 18093, path + ("?" + query if query else ""))

    def proxy(self, request_path=None):
        parsed = urlsplit(request_path or self.path)
        is_dns = self.dns_request(parsed.path)
        target = self.target(parsed.path, parsed.query)
        if target[0] == "redirect":
            self.redirect(target[1])
            return
        _, host, port, path = target
        length = int(self.headers.get("Content-Length", "0"))
        if length > 12 * 1024 * 1024:
            self.send_error(HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
            return
        body = self.rfile.read(length) if length else None
        headers = {key: value for key, value in self.headers.items() if key.lower() not in HOP_BY_HOP | {"host", "authorization", "cookie"}}
        headers["Host"] = f"{host}:{port}"
        headers["X-Family-Gateway"] = secret().decode()
        headers["X-Forwarded-For"] = self.client_address[0]
        if is_dns:
            upstream_auth = config().get("DNS_UPSTREAM_AUTH_B64", "").strip()
            if upstream_auth:
                headers["Authorization"] = "Basic " + upstream_auth
        try:
            connection = http.client.HTTPConnection(host, port, timeout=75)
            connection.request(self.command, path, body=body, headers=headers)
            response = connection.getresponse()
            response_body = response.read()
            if is_dns and response.status == HTTPStatus.UNAUTHORIZED:
                self.send_error(HTTPStatus.BAD_GATEWAY, "DNS 管理后端认证未配置")
                return
            content_type = response.getheader("Content-Type", "")
            if is_dns and "text/html" in content_type:
                values = config()
                proxy_ip = values["FAMILY_PROXY_IP"]
                html = response_body.decode("utf-8")
                html = html.replace(
                    "function apiUrl(path) { return new URL(path, window.location.origin).toString(); }",
                    "function apiUrl(path) { const prefix = window.location.pathname.startsWith('/dns/') ? '/dns' : ''; return new URL(prefix + path, window.location.origin).toString(); }",
                )
                html = html.replace(f'href="http://{proxy_ip}:18088/"', 'href="/"')
                html = html.replace(f'href="http://{proxy_ip}:18088/rules"', 'href="/rules"')
                html = html.replace(f'href="http://{proxy_ip}:18090/"', 'href="/airport/"')
                html = html.replace('<a class="active" href="/">DNS</a>', '<a class="active" href="/dns/">DNS</a>')
                response_body = html.encode("utf-8")
            self.send_response(response.status, response.reason)
            for key, value in response.getheaders():
                if key.lower() not in HOP_BY_HOP | {"content-length", "set-cookie"}:
                    self.send_header(key, value)
            self.send_header("Content-Length", str(len(response_body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(response_body)
        except OSError:
            self.send_error(HTTPStatus.BAD_GATEWAY, "管理后端暂不可用")

    def do_GET(self):
        if not self.allowed():
            self.send_error(HTTPStatus.FORBIDDEN)
            return
        if self.path == "/favicon.ico":
            self.send_response(HTTPStatus.NO_CONTENT)
            self.end_headers()
            return
        # Preserve the existing unauthenticated RouterOS health probe without
        # exposing the interactive management interface.
        if self.client_address[0] == "__FAMILY_ROUTER_IP__" and self.path == "/":
            self.proxy("/api/health")
            return
        if self.path == "/login":
            self.page()
            return
        if not valid_session(self.headers.get("Cookie", "")):
            self.redirect("/login")
            return
        self.proxy()

    def do_POST(self):
        if not self.allowed():
            self.send_error(HTTPStatus.FORBIDDEN)
            return
        if self.path == "/login":
            self.login()
            return
        if self.path == "/logout":
            self.send_response(HTTPStatus.SEE_OTHER)
            self.send_header("Location", "/login")
            self.send_header("Set-Cookie", "family_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict")
            self.end_headers()
            return
        if not valid_session(self.headers.get("Cookie", "")):
            self.send_error(HTTPStatus.UNAUTHORIZED)
            return
        self.proxy()


class LegacyAirportRedirect(BaseHTTPRequestHandler):
    """Redirect cached direct-port bookmarks back through the login gateway."""

    def log_message(self, *_):
        pass

    def redirect(self):
        try:
            allowed = ipaddress.ip_address(self.client_address[0]) in LAN
        except ValueError:
            allowed = False
        if not allowed:
            self.send_error(HTTPStatus.FORBIDDEN)
            return
        self.send_response(HTTPStatus.PERMANENT_REDIRECT)
        self.send_header("Location", "http://__FAMILY_PROXY_IP__:18088/airport/")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()

    do_GET = redirect
    do_HEAD = redirect


if __name__ == "__main__":
    legacy = ThreadingHTTPServer(("__FAMILY_PROXY_IP__", 18090), LegacyAirportRedirect)
    threading.Thread(target=legacy.serve_forever, daemon=True).start()
    ThreadingHTTPServer(("__FAMILY_PROXY_IP__", 18088), Handler).serve_forever()
