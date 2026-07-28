#!/usr/bin/env python3
"""Single-origin cookie login gateway for the family proxy management UI."""

import base64
import hashlib
import hmac
import http.client
import ipaddress
import json
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


PAGE_LAYOUT = {
    "devices": [("traffic", "流量观察", "#trafficObservation"), ("z4pro", "Z4Pro 运行详情", "#z4Status"),
                ("router", "RB5009 运行详情", "#routerStatus"), ("wireguard", "WireGuard 远程互联", "#wireguardStatus")],
    "dns": [("rankings", "常用域名与活跃设备", "#rank-domains"), ("observability", "分流结果与较慢查询", "#rank-effective"),
            ("data_management", "数据管理页", "#page-data")],
    "airport": [("subscription_help", "订阅来源说明", "#subs > .muted"), ("switch_history", "自动切换历史", "#events")],
    "rules": [("guide", "规则使用说明", ".hint"), ("preview", "规则命中预览", ".route-preview")],
    "maintenance": [("guide", "维护说明", ".notice")],
}


def inject_page_layout(html, page):
    sections = PAGE_LAYOUT.get(page)
    if not sections or "family-layout-settings" in html:
        return html
    encoded = json.dumps(sections, ensure_ascii=False)
    client = f'''<style>
.family-layout-hidden{{display:none!important}}.family-layout-settings{{width:32px;height:32px;margin:0 0 0 8px;padding:0;border:0;border-radius:6px;background:#2c2c2e;color:#d1d1d6;font-size:17px;line-height:1;cursor:pointer}}.family-layout-settings:hover{{background:#3a3a3c;color:#fff}}.family-layout-dialog{{width:min(440px,calc(100% - 28px));padding:0;border:1px solid #48484a;border-radius:10px;background:#1c1c1e;color:#f5f5f7;box-shadow:0 24px 80px rgba(0,0,0,.62)}}.family-layout-dialog::backdrop{{background:rgba(0,0,0,.65)}}.family-layout-head{{padding:18px 20px 14px;border-bottom:1px solid #38383a}}.family-layout-head h2{{margin:0;font-size:17px}}.family-layout-head p{{margin:6px 0 0;color:#8e8e93;font-size:12px;line-height:1.5}}.family-layout-list{{padding:8px 20px}}.family-layout-item{{display:grid;grid-template-columns:16px 16px minmax(0,1fr) auto;align-items:center;gap:10px;padding:10px 0;border-top:1px solid #38383a;color:#f5f5f7;font-size:14px;cursor:grab}}.family-layout-item:first-child{{border-top:0}}.family-layout-item.dragging{{opacity:.42}}.family-layout-item.drop-target{{box-shadow:0 -2px 0 #0a84ff}}.family-layout-handle{{color:#8e8e93;font-size:16px;line-height:1;user-select:none}}.family-layout-item input{{width:16px;height:16px;margin:0;accent-color:#0a84ff}}.family-layout-label{{min-width:0;cursor:pointer}}.family-layout-moves{{display:flex;gap:2px}}.family-layout-moves button{{width:26px;height:26px;padding:0;border:0;border-radius:5px;background:transparent;color:#0a84ff;font:600 14px inherit;cursor:pointer}}.family-layout-moves button:hover:not(:disabled){{background:rgba(10,132,255,.16)}}.family-layout-moves button:disabled{{color:#48484a;cursor:default}}.family-layout-foot{{display:flex;align-items:center;justify-content:space-between;gap:10px;padding:14px 20px;border-top:1px solid #38383a}}.family-layout-status{{min-height:18px;color:#8e8e93;font-size:12px}}.family-layout-actions{{display:flex;gap:8px}}.family-layout-actions button{{height:34px;border:0;border-radius:6px;padding:0 11px;background:#2c2c2e;color:#f5f5f7;font:600 12px -apple-system,BlinkMacSystemFont,"PingFang SC",sans-serif;cursor:pointer}}.family-layout-actions .primary{{background:#0a84ff;color:#fff}}@media(max-width:720px){{.family-layout-settings{{margin-left:0}}.family-layout-dialog{{width:min(100% - 20px,440px)}}}}
</style><script>(function(){{
const page={page!r}, sections={encoded}, defaultOrder=sections.map(row=>row[0]); let hidden=new Set(),order=[...defaultOrder],dragKey='';
function row(key){{return sections.find(item=>item[0]===key)}}
function targets(key){{let item=row(key),node=item&&document.querySelector(item[2]);if(!node)return[];return[node.closest('details')||node.closest('section')||node]}}
function normalizeOrder(value){{let clean=Array.isArray(value)?value.filter(key=>defaultOrder.includes(key)):[];clean.push(...defaultOrder.filter(key=>!clean.includes(key)));return clean}}
function reorder(){{let parents=new Map();order.forEach(key=>targets(key).forEach(node=>{{let nodes=parents.get(node.parentElement)||[];if(!nodes.includes(node))nodes.push(node);parents.set(node.parentElement,nodes)}}));parents.forEach(nodes=>{{if(nodes.length<2)return;let marker=document.createComment('family-layout-order');nodes[0].parentElement.insertBefore(marker,nodes[0]);nodes.forEach(node=>marker.parentElement.insertBefore(node,marker));marker.remove()}})}}
function apply(){{reorder();sections.forEach(item=>targets(item[0]).forEach(node=>node.classList.toggle('family-layout-hidden',hidden.has(item[0]))));document.querySelectorAll('input[data-layout-key]').forEach(box=>box.checked=!hidden.has(box.dataset.layoutKey))}}
function status(text,bad=false){{let node=document.querySelector('#family-layout-status');if(node){{node.textContent=text;node.style.color=bad?'#ff6961':'#8e8e93'}}}}
async function request(path,opt={{}}){{let response=await fetch(path,{{...opt,headers:{{'Content-Type':'application/json',...(opt.headers||{{}})}}}});let body=await response.json();if(!response.ok)throw Error(body.error||'请求失败');return body}}
function open(){{document.querySelector('#family-layout-dialog').showModal()}}function close(){{document.querySelector('#family-layout-dialog').close()}}
function move(key,to){{let from=order.indexOf(key);if(from<0||to<0||to>=order.length||from===to)return;order.splice(from,1);order.splice(to,0,key);renderList()}}
function moveBefore(key,before,after=false){{let from=order.indexOf(key);if(from<0||key===before)return;order.splice(from,1);let to=order.indexOf(before)+(after?1:0);order.splice(to,0,key);renderList()}}
function renderList(){{let list=document.querySelector('#family-layout-list');if(!list)return;list.innerHTML=order.map((key,index)=>{{let item=row(key),id='family-layout-'+key;return '<div class="family-layout-item" draggable="true" data-layout-key="'+key+'"><span class="family-layout-handle" title="拖动排序" aria-hidden="true">⠿</span><input id="'+id+'" type="checkbox" data-layout-key="'+key+'" '+(hidden.has(key)?'':'checked')+'><label class="family-layout-label" for="'+id+'">'+item[1]+'</label><span class="family-layout-moves"><button type="button" data-move="-1" aria-label="上移 '+item[1]+'" title="上移" '+(index===0?'disabled':'')+'>↑</button><button type="button" data-move="1" aria-label="下移 '+item[1]+'" title="下移" '+(index===order.length-1?'disabled':'')+'>↓</button></span></div>'}}).join('');list.querySelectorAll('.family-layout-item').forEach(item=>{{item.addEventListener('dragstart',()=>{{dragKey=item.dataset.layoutKey;item.classList.add('dragging')}});item.addEventListener('dragend',()=>{{dragKey='';list.querySelectorAll('.drop-target,.dragging').forEach(node=>node.classList.remove('drop-target','dragging'))}});item.addEventListener('dragover',event=>{{event.preventDefault();item.classList.add('drop-target')}});item.addEventListener('dragleave',()=>item.classList.remove('drop-target'));item.addEventListener('drop',event=>{{event.preventDefault();let rect=item.getBoundingClientRect();moveBefore(dragKey,item.dataset.layoutKey,event.clientY>rect.top+rect.height/2)}});item.querySelectorAll('[data-move]').forEach(button=>button.addEventListener('click',event=>{{event.preventDefault();event.stopPropagation();move(item.dataset.layoutKey,order.indexOf(item.dataset.layoutKey)+Number(button.dataset.move))}}))}})}}
async function save(reset=false){{if(reset){{hidden=new Set();order=[...defaultOrder];renderList()}}let next=order.filter(key=>{{let box=document.querySelector('input[data-layout-key="'+key+'"]');return box&&!box.checked}});try{{status('正在保存…');let data=await request('/api/page-layout',{{method:'POST',body:JSON.stringify({{page,hidden:next,order}})}});hidden=new Set(data.hidden||[]);order=normalizeOrder(data.order);apply();status(reset?'已恢复默认显示':'已保存');setTimeout(close,280)}}catch(error){{status(error.message,true)}}}}
function mount(){{let host=document.querySelector('.topbar-inner')||document.querySelector('header')||document.body;let button=document.createElement('button');button.type='button';button.className='family-layout-settings';button.title='页面显示设置';button.setAttribute('aria-label','页面显示设置');button.textContent='⚙';button.onclick=open;host.append(button);let dialog=document.createElement('dialog');dialog.id='family-layout-dialog';dialog.className='family-layout-dialog';dialog.innerHTML='<div class="family-layout-head"><h2>页面显示</h2><p>拖动手柄或使用箭头排序；只隐藏次要信息，不影响服务、规则或设备接管。</p></div><div id="family-layout-list" class="family-layout-list"></div><div class="family-layout-foot"><span id="family-layout-status" class="family-layout-status"></span><div class="family-layout-actions"><button type="button" id="family-layout-reset">恢复默认</button><button type="button" class="primary" id="family-layout-save">保存</button></div></div>';document.body.append(dialog);dialog.addEventListener('click',event=>{{if(event.target===dialog)close()}});document.querySelector('#family-layout-reset').onclick=()=>save(true);document.querySelector('#family-layout-save').onclick=()=>save(false);request('/api/page-layout').then(data=>{{let prefs=data[page]||{{}};hidden=new Set(prefs.hidden||[]);order=normalizeOrder(prefs.order);renderList();apply()}}).catch(error=>{{renderList();status('设置读取失败：'+error.message,true)}})}}
if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',mount);else mount();
}})();</script>'''
    return html.replace("</body>", client + "</body>")


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
        if path.startswith("/dns/maintenance-api/"):
            suffix = path[len("/dns/maintenance-api"):]
            return ("backend", "127.0.0.1", 18102, suffix + ("?" + query if query else ""))
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
            if "text/html" in content_type:
                html = response_body.decode("utf-8")
                if is_dns:
                    values = config()
                    proxy_ip = values["FAMILY_PROXY_IP"]
                    html = html.replace(
                        "function apiUrl(path) { return new URL(path, window.location.origin).toString(); }",
                        "function apiUrl(path) { const prefix = window.location.pathname.startsWith('/dns/') ? '/dns' : ''; return new URL(prefix + path, window.location.origin).toString(); }",
                    )
                    html = html.replace(f'href="http://{proxy_ip}:18088/"', 'href="/"')
                    html = html.replace(f'href="http://{proxy_ip}:18088/rules"', 'href="/rules"')
                    html = html.replace(f'href="http://{proxy_ip}:18090/"', 'href="/airport/"')
                    html = html.replace('<a class="active" href="/">DNS</a>', '<a class="active" href="/dns/">DNS</a>')
                page = None
                if parsed.path == "/":
                    page = "devices"
                elif parsed.path == "/rules":
                    page = "rules"
                elif parsed.path == "/mihomo-maintenance":
                    page = "maintenance"
                elif parsed.path.startswith("/airport/"):
                    page = "airport"
                elif parsed.path.startswith("/dns/"):
                    page = "dns"
                if page:
                    html = inject_page_layout(html, page)
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


class RouterHealthProbe(Handler):
    """Expose the health probe on a dedicated RouterOS-only listener."""

    def do_GET(self):
        if self.client_address[0] != "__FAMILY_ROUTER_IP__":
            self.send_error(HTTPStatus.FORBIDDEN)
            return
        if self.path != "/":
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        self.proxy("/api/health")


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
    health = ThreadingHTTPServer(("__FAMILY_PROXY_IP__", 18087), RouterHealthProbe)
    threading.Thread(target=health.serve_forever, daemon=True).start()
    ThreadingHTTPServer(("__FAMILY_PROXY_IP__", 18088), Handler).serve_forever()
