#!/usr/bin/env python3
"""Single-origin cookie login gateway for the family proxy management UI."""

import base64
import hashlib
import hmac
import html
import http.client
import ipaddress
import json
import os
import re
import secrets
import subprocess
import threading
import time
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlsplit

CONFIG = Path("/etc/family-proxy-ui/router.env")
SECRET_PATH = Path("/etc/family-proxy-ui/gateway.secret")
SETUP_STATE_PATH = Path("/etc/family-proxy-ui/setup-state.json")
LAN = ipaddress.ip_network(os.environ.get("FAMILY_LAN_CIDR", "__FAMILY_LAN_CIDR__"))
SESSION_TTL = 12 * 60 * 60
SETUP_LOCK = threading.Lock()
HOP_BY_HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailers", "transfer-encoding", "upgrade"}

LOGIN_PAGE = '''<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>家庭旁路</title><style>:root{color-scheme:dark;font-family:-apple-system,BlinkMacSystemFont,"PingFang SC",sans-serif;background:#000;color:#f5f5f7}*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;padding:20px}.box{width:min(360px,100%);padding:28px;border:1px solid #2c2c2e;border-radius:10px;background:#1c1c1e}h1{font-size:24px;margin:0 0 8px}p{margin:0 0 22px;color:#98989d;font-size:14px}label{display:block;margin:13px 0 6px;font-size:13px}input{width:100%;height:40px;border:1px solid #48484a;border-radius:7px;background:#2c2c2e;color:#fff;padding:0 11px;font:15px inherit;outline:none}input:focus{border-color:#0a84ff;box-shadow:0 0 0 3px rgba(10,132,255,.2)}button{width:100%;height:40px;margin-top:20px;border:0;border-radius:7px;background:#0a84ff;color:#fff;font:600 15px inherit}.error{min-height:18px;margin-top:12px;color:#ff6961;font-size:13px}</style><main class="box"><h1>家庭旁路</h1><p>登录后可管理设备、规则与机场候选池。</p><form method="post" action="/login"><label>用户名</label><input name="username" autocomplete="username" required autofocus><label>密码</label><input name="password" type="password" autocomplete="current-password" required><button>登录</button><div class="error">__ERROR__</div></form></main>'''

SETUP_PAGE = '''<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>首次设置 - 家庭旁路</title><style>:root{color-scheme:dark;font-family:-apple-system,BlinkMacSystemFont,"PingFang SC",sans-serif;background:#0b0c0e;color:#f5f5f7}*{box-sizing:border-box}body{margin:0;padding:28px 16px 48px}.box{width:min(760px,100%);margin:auto;padding:28px;border:1px solid #2c2c2e;border-radius:10px;background:#1c1c1e}h1{font-size:25px;margin:0 0 8px}h2{font-size:16px;margin:26px 0 12px;padding-top:20px;border-top:1px solid #38383a}p,.hint{color:#98989d;font-size:13px;line-height:1.55}.grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px 18px}.field{min-width:0}label{display:block;margin:0 0 6px;font-size:13px}input{width:100%;height:40px;border:1px solid #48484a;border-radius:7px;background:#2c2c2e;color:#fff;padding:0 11px;font:15px inherit;outline:none}input:focus{border-color:#0a84ff;box-shadow:0 0 0 3px rgba(10,132,255,.2)}.check{display:flex;align-items:center;gap:9px;margin-top:14px;color:#d1d1d6;font-size:13px}.check input{width:17px;height:17px;margin:0}.error{min-height:20px;margin-top:16px;color:#ff6961;font-size:13px}.actions{display:flex;justify-content:flex-end;gap:10px;margin-top:24px}button{height:40px;border:0;border-radius:7px;padding:0 18px;background:#0a84ff;color:#fff;font:600 14px inherit;cursor:pointer}button:focus{box-shadow:0 0 0 3px rgba(10,132,255,.25);outline:none}@media(max-width:620px){.box{padding:22px 18px}.grid{grid-template-columns:1fr}.actions button{width:100%}.actions{display:block}}</style><main class="box"><h1>首次设置</h1><p>完成本机控制面的基础配置后，才会进入正常登录页。此页面仅接受局域网连接，不会写入 RouterOS 规则、接管设备或导入订阅。</p><form method="post" action="/setup"><input type="hidden" name="token" value="__TOKEN__"><h2>RouterOS 控制连接</h2><div class="grid"><div class="field"><label for="router_host">API 地址</label><input id="router_host" name="router_host" value="__ROUTER_HOST__" autocomplete="off" required></div><div class="field"><label for="router_user">API 用户</label><input id="router_user" name="router_user" value="__ROUTER_USER__" autocomplete="username" required></div><div class="field"><label for="router_password">API 密码</label><input id="router_password" name="router_password" type="password" autocomplete="new-password" required></div></div><h2>管理页账号</h2><div class="grid"><div class="field"><label for="ui_username">用户名</label><input id="ui_username" name="ui_username" value="__UI_USERNAME__" autocomplete="username" required></div><div class="field"><label for="ui_password">新密码</label><input id="ui_password" name="ui_password" type="password" autocomplete="new-password" minlength="12" required></div><div class="field"><label for="ui_password_confirm">确认密码</label><input id="ui_password_confirm" name="ui_password_confirm" type="password" autocomplete="new-password" minlength="12" required></div></div><h2>可选服务</h2><div class="grid"><div class="field"><label for="dns_username">DNS 页面用户名</label><input id="dns_username" name="dns_username" autocomplete="off"></div><div class="field"><label for="dns_password">DNS 页面密码</label><input id="dns_password" name="dns_password" type="password" autocomplete="new-password"></div><div class="field"><label for="mosdns_api_url">MosDNS API 地址</label><input id="mosdns_api_url" name="mosdns_api_url" value="__MOSDNS_API_URL__" autocomplete="off"></div><div class="field"><label for="geodata_proxy">GEO 更新代理</label><input id="geodata_proxy" name="geodata_proxy" value="__GEODATA_PROXY__" autocomplete="off"></div></div><label class="check"><input type="checkbox" name="router_cn_auto_sync" __ROUTER_CN_AUTO_SYNC__> 每周更新后同步 RouterOS 国内地址表</label><label class="check"><input type="checkbox" name="geodata_auto_update" __GEODATA_AUTO_UPDATE__> 自动更新 Mihomo GEO 数据（需服务器可直连官方源）</label><div class="error">__ERROR__</div><div class="actions"><button type="submit">保存并进入系统</button></div></form></main>'''

SETUP_COMPLETE_PAGE = '''<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>设置完成 - 家庭旁路</title><style>:root{color-scheme:dark;font-family:-apple-system,BlinkMacSystemFont,"PingFang SC",sans-serif;background:#0b0c0e;color:#f5f5f7}body{margin:0;min-height:100vh;display:grid;place-items:center;padding:20px}.box{width:min(440px,100%);padding:28px;border:1px solid #2c2c2e;border-radius:10px;background:#1c1c1e}h1{font-size:24px;margin:0 0 10px}p{color:#98989d;font-size:14px;line-height:1.6}a{display:inline-block;margin-top:12px;color:#fff;background:#0a84ff;border-radius:7px;padding:11px 16px;text-decoration:none;font-weight:600}</style><main class="box"><h1>设置已完成</h1><p>控制面正在重新加载新配置。等待几秒后进入管理页登录。</p><a href="/login">进入登录页</a></main>'''

SETUP_ERROR_PAGE = '''<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>首次设置 - 家庭旁路</title><style>:root{color-scheme:dark;font-family:-apple-system,BlinkMacSystemFont,"PingFang SC",sans-serif;background:#0b0c0e;color:#f5f5f7}body{margin:0;min-height:100vh;display:grid;place-items:center;padding:20px}.box{width:min(500px,100%);padding:28px;border:1px solid #633b3b;border-radius:10px;background:#1c1c1e}h1{font-size:22px;margin:0 0 10px}.error{color:#ff6961;font-size:14px;line-height:1.6}a{color:#fff}</style><main class="box"><h1>首次设置无法继续</h1><p class="error">__ERROR__</p><a href="__SETUP_LINK__">返回设置页</a></main>'''


PAGE_LAYOUT = {
    "devices": [("devices", "设备", "#devices", True), ("manual_add", "按 IP 手动加入", "#manualAdd", True),
                ("bypass", "旁路运行状态", "#bypassStatus"), ("traffic", "流量观察", "#trafficObservation"),
                ("z4pro", "Z4Pro 运行详情", "#z4Status"), ("router", "RB5009 运行详情", "#routerStatus"),
                ("wireguard", "WireGuard 远程互联", "#wireguardStatus")],
    "dns": [("rankings", "常用域名与活跃设备", "#rank-domains"), ("observability", "分流结果与较慢查询", "#rank-effective"),
            ("data_management", "数据管理页", "#page-data")],
    "airport": [("subscription_help", "订阅来源说明", "#subs > .muted"), ("switch_history", "自动切换历史", "#runtime")],
    "rules": [("guide", "规则使用说明", ".hint"), ("preview", "规则命中预览", ".route-preview")],
    "maintenance": [("guide", "维护说明", ".notice")],
}


def inject_page_layout(html, page):
    sections = PAGE_LAYOUT.get(page)
    if not sections or "family-layout-settings" in html:
        return html
    settings_button = '<button type="button" class="family-layout-settings" title="页面显示设置" aria-label="页面显示设置">⚙</button>'
    if '<div class="topbar-inner">' in html:
        html = re.sub(
            r'(<div class="topbar-inner">.*?)(</div></header>)',
            lambda match: match.group(1) + settings_button + match.group(2),
            html,
            count=1,
            flags=re.S,
        )
    encoded = json.dumps(sections, ensure_ascii=False)
    client = f'''<style>
.family-layout-hidden{{display:none!important}}.family-layout-settings{{width:32px;height:32px;margin:0 0 0 8px;padding:0;border:0;border-radius:6px;background:#2c2c2e;color:#d1d1d6;font-size:17px;line-height:1;cursor:pointer}}.family-layout-settings:hover{{background:#3a3a3c;color:#fff}}.family-layout-dialog{{width:min(440px,calc(100% - 28px));padding:0;border:1px solid #48484a;border-radius:10px;background:#1c1c1e;color:#f5f5f7;box-shadow:0 24px 80px rgba(0,0,0,.62)}}.family-layout-dialog::backdrop{{background:rgba(0,0,0,.65)}}.family-layout-head{{padding:18px 20px 14px;border-bottom:1px solid #38383a}}.family-layout-head h2{{margin:0;font-size:17px}}.family-layout-head p{{margin:6px 0 0;color:#8e8e93;font-size:12px;line-height:1.5}}.family-layout-list{{padding:8px 20px}}.family-layout-item{{display:grid;grid-template-columns:16px 70px minmax(0,1fr) auto;align-items:center;gap:10px;padding:10px 0;border-top:1px solid #38383a;color:#f5f5f7;font-size:14px;cursor:grab}}.family-layout-item:first-child{{border-top:0}}.family-layout-item.dragging{{opacity:.42}}.family-layout-item.drop-target{{box-shadow:0 -2px 0 #0a84ff}}.family-layout-handle{{color:#8e8e93;font-size:16px;line-height:1;user-select:none}}.family-layout-visibility{{display:flex;align-items:center;gap:6px;color:#aeaeb2;font-size:12px;cursor:pointer}}.family-layout-visibility input,.family-layout-expand input{{appearance:none;position:relative;width:30px;height:18px;margin:0;border:1px solid #636366;border-radius:999px;background:#3a3a3c;cursor:pointer;transition:background .12s ease,border-color .12s ease}}.family-layout-visibility input:before,.family-layout-expand input:before{{position:absolute;top:2px;left:2px;width:12px;height:12px;border-radius:50%;background:#fff;content:"";transition:transform .12s ease}}.family-layout-visibility input:checked,.family-layout-expand input:checked{{border-color:#0a84ff;background:#0a84ff}}.family-layout-visibility input:checked:before,.family-layout-expand input:checked:before{{transform:translateX(12px)}}.family-layout-visibility input:disabled{{cursor:default;opacity:.48}}.family-layout-label{{min-width:0;cursor:pointer}}.family-layout-moves{{display:flex;gap:2px}}.family-layout-moves button{{width:26px;height:26px;padding:0;border:0;border-radius:5px;background:transparent;color:#0a84ff;font:600 14px inherit;cursor:pointer}}.family-layout-moves button:hover:not(:disabled){{background:rgba(10,132,255,.16)}}.family-layout-moves button:disabled{{color:#48484a;cursor:default}}.family-layout-foot{{display:flex;align-items:center;justify-content:space-between;gap:10px;padding:14px 20px;border-top:1px solid #38383a}}.family-layout-status{{min-height:18px;color:#8e8e93;font-size:12px}}.family-layout-actions{{display:flex;gap:8px}}.family-layout-actions button{{height:34px;border:0;border-radius:6px;padding:0 11px;background:#2c2c2e;color:#f5f5f7;font:600 12px -apple-system,BlinkMacSystemFont,"PingFang SC",sans-serif;cursor:pointer}}.family-layout-actions .primary{{background:#0a84ff;color:#fff}}@media(max-width:720px){{.family-layout-settings{{margin-left:0}}.family-layout-dialog{{width:min(100% - 20px,440px)}}}}
</style><script>(function(){{
const page={page!r}, sections={encoded}, defaultOrder=sections.map(row=>row[0]); let hidden=new Set(),order=[...defaultOrder],dragKey='';
function row(key){{return sections.find(item=>item[0]===key)}}
function locked(key){{let item=row(key);return Boolean(item&&item[3])}}
function targets(key){{let item=row(key),node=item&&document.querySelector(item[2]);if(!node)return[];return[node.closest('details')||node.closest('section')||node]}}
function normalizeOrder(value){{let clean=Array.isArray(value)?value.filter(key=>defaultOrder.includes(key)):[];clean.push(...defaultOrder.filter(key=>!clean.includes(key)));return clean}}
function reorder(){{let parents=new Map();order.forEach(key=>targets(key).forEach(node=>{{let nodes=parents.get(node.parentElement)||[];if(!nodes.includes(node))nodes.push(node);parents.set(node.parentElement,nodes)}}));parents.forEach(nodes=>{{if(nodes.length<2)return;let marker=document.createComment('family-layout-order');nodes[0].parentElement.insertBefore(marker,nodes[0]);nodes.forEach(node=>marker.parentElement.insertBefore(node,marker));marker.remove()}})}}
function apply(){{reorder();sections.forEach(item=>targets(item[0]).forEach(node=>node.classList.toggle('family-layout-hidden',hidden.has(item[0]))));document.querySelectorAll('input[data-layout-key]').forEach(box=>box.checked=!hidden.has(box.dataset.layoutKey))}}
function status(text,bad=false){{let node=document.querySelector('#family-layout-status');if(node){{node.textContent=text;node.style.color=bad?'#ff6961':'#8e8e93'}}}}
async function request(path,opt={{}}){{let response=await fetch(path,{{...opt,headers:{{'Content-Type':'application/json',...(opt.headers||{{}})}}}});let body=await response.json();if(!response.ok)throw Error(body.error||'请求失败');return body}}
function open(){{document.querySelector('#family-layout-dialog').showModal()}}function close(){{document.querySelector('#family-layout-dialog').close()}}
function move(key,to){{let from=order.indexOf(key);if(from<0||to<0||to>=order.length||from===to)return;order.splice(from,1);order.splice(to,0,key);renderList()}}
function moveBefore(key,before,after=false){{let from=order.indexOf(key);if(from<0||key===before)return;order.splice(from,1);let to=order.indexOf(before)+(after?1:0);order.splice(to,0,key);renderList()}}
function renderList(){{let list=document.querySelector('#family-layout-list');if(!list)return;list.innerHTML=order.map((key,index)=>{{let item=row(key),id='family-layout-'+key,control='<label class="family-layout-visibility" for="'+id+'"><input id="'+id+'" type="checkbox" data-layout-key="'+key+'" '+(hidden.has(key)?'':'checked')+(locked(key)?' disabled title="固定显示"':'')+'><span>显示</span></label>';return '<div class="family-layout-item" draggable="true" data-layout-key="'+key+'"><span class="family-layout-handle" title="拖动排序" aria-hidden="true">⠿</span>'+control+'<label class="family-layout-label" for="'+id+'">'+item[1]+(locked(key)?' · 固定显示':'')+'</label><span class="family-layout-moves"><button type="button" data-move="-1" aria-label="上移 '+item[1]+'" title="上移" '+(index===0?'disabled':'')+'>↑</button><button type="button" data-move="1" aria-label="下移 '+item[1]+'" title="下移" '+(index===order.length-1?'disabled':'')+'>↓</button></span></div>'}}).join('');list.querySelectorAll('.family-layout-item').forEach(item=>{{item.addEventListener('dragstart',()=>{{dragKey=item.dataset.layoutKey;item.classList.add('dragging')}});item.addEventListener('dragend',()=>{{dragKey='';list.querySelectorAll('.drop-target,.dragging').forEach(node=>node.classList.remove('drop-target','dragging'))}});item.addEventListener('dragover',event=>{{event.preventDefault();item.classList.add('drop-target')}});item.addEventListener('dragleave',()=>item.classList.remove('drop-target'));item.addEventListener('drop',event=>{{event.preventDefault();let rect=item.getBoundingClientRect();moveBefore(dragKey,item.dataset.layoutKey,event.clientY>rect.top+rect.height/2)}});item.querySelectorAll('[data-move]').forEach(button=>button.addEventListener('click',event=>{{event.preventDefault();event.stopPropagation();move(item.dataset.layoutKey,order.indexOf(item.dataset.layoutKey)+Number(button.dataset.move))}}))}})}}
async function save(reset=false){{if(reset){{hidden=new Set();order=[...defaultOrder];renderList()}}let next=order.filter(key=>{{if(locked(key))return false;let box=document.querySelector('input[data-layout-key="'+key+'"]');return box&&!box.checked}});try{{status('正在保存…');let data=await request('/api/page-layout',{{method:'POST',body:JSON.stringify({{page,hidden:next,order}})}});hidden=new Set(data.hidden||[]);order=normalizeOrder(data.order);apply();status(reset?'已恢复默认显示':'已保存');setTimeout(close,280)}}catch(error){{status(error.message,true)}}}}
function mount(){{let host=document.querySelector('.topbar-inner')||document.querySelector('header')||document.body;let button=document.querySelector('.family-layout-settings');if(!button){{button=document.createElement('button');button.type='button';button.className='family-layout-settings';button.title='页面显示设置';button.setAttribute('aria-label','页面显示设置');button.textContent='⚙';host.append(button)}}button.onclick=open;let dialog=document.createElement('dialog');dialog.id='family-layout-dialog';dialog.className='family-layout-dialog';dialog.innerHTML='<div class="family-layout-head"><h2>页面显示</h2><p>拖动手柄或使用箭头排序；标记为固定显示的核心入口不能隐藏，其余区块可按需隐藏。</p></div><div id="family-layout-list" class="family-layout-list"></div><div class="family-layout-foot"><span id="family-layout-status" class="family-layout-status"></span><div class="family-layout-actions"><button type="button" id="family-layout-reset">恢复默认</button><button type="button" class="primary" id="family-layout-save">保存</button></div></div>';document.body.append(dialog);dialog.addEventListener('click',event=>{{if(event.target===dialog)close()}});document.querySelector('#family-layout-reset').onclick=()=>save(true);document.querySelector('#family-layout-save').onclick=()=>save(false);request('/api/page-layout').then(data=>{{let prefs=data[page]||{{}};hidden=new Set(prefs.hidden||[]);order=normalizeOrder(prefs.order);renderList();apply()}}).catch(error=>{{renderList();status('设置读取失败：'+error.message,true)}})}}
if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',mount);else mount();
}})();</script>'''
    foldable = {
        "devices": ["bypass", "traffic", "z4pro", "router", "wireguard"],
    }.get(page, [])
    enhancements = ('''<style>
.family-layout-moves{display:none!important}.family-layout-item{grid-template-columns:16px 70px minmax(0,1fr) auto!important}.family-layout-handle{touch-action:none;cursor:grab}.family-layout-item.family-layout-touch-dragging{opacity:.46;cursor:grabbing}.family-layout-expand{display:flex;align-items:center;gap:6px;margin:0;color:#aeaeb2;font-size:12px;white-space:nowrap;cursor:pointer}.family-layout-expand-label{display:inline}.tabs.family-layout-no-switch-history{grid-template-columns:repeat(2,minmax(0,1fr))}
</style><script>(()=>{
const layoutPage=''' + json.dumps(page) + ''';
const foldable=new Set(''' + json.dumps(foldable, ensure_ascii=False) + ''');
let expanded=new Set(),touchItem=null;
function layoutRows(){return [...document.querySelectorAll('#family-layout-list .family-layout-item')]}
function applyFoldState(){foldable.forEach(key=>{document.querySelectorAll({bypass:'#bypassStatus',traffic:'#trafficObservation',z4pro:'#z4Status',router:'#routerStatus',wireguard:'#wireguardStatus'}[key]||'').forEach(node=>{let section=node.closest('details');if(section)section.open=expanded.has(key)})})}
function applyAirportState(hidden){if(layoutPage!=='airport')return;let isHidden=(hidden||[]).includes('switch_history'),tabs=document.querySelector('.tabs'),button=[...document.querySelectorAll('.tabs button')].find(node=>node.textContent.trim()==='切换状态'),panel=document.querySelector('#runtime');if(!isHidden)return;if(panel?.classList.contains('on'))document.querySelector('.tabs button')?.click();tabs?.classList.add('family-layout-no-switch-history');button?.remove();panel?.remove();document.querySelector('#filter')?.remove()}
function enhanceList(){let list=document.querySelector('#family-layout-list');if(!list)return;layoutRows().forEach(item=>{let key=item.dataset.layoutKey;if(foldable.has(key)&&!item.querySelector('[data-layout-expanded]')){let label=document.createElement('label');label.className='family-layout-expand';label.title='控制该诊断区块默认是否展开';label.setAttribute('aria-label','默认展开 '+(item.querySelector('.family-layout-label')?.textContent||''));let text=document.createElement('span');text.className='family-layout-expand-label';text.textContent='默认展开';let box=document.createElement('input');box.type='checkbox';box.dataset.layoutExpanded=key;box.checked=expanded.has(key);label.append(text,box);item.append(label)}if(item.dataset.touchReady)return;item.dataset.touchReady='1';item.addEventListener('pointerdown',event=>{if(!event.target.closest('.family-layout-handle'))return;touchItem=item;item.classList.add('family-layout-touch-dragging');try{item.setPointerCapture(event.pointerId)}catch(_){}});item.addEventListener('pointermove',event=>{if(touchItem!==item)return;event.preventDefault();let target=document.elementFromPoint(event.clientX,event.clientY)?.closest('.family-layout-item');if(!target||target===item||!list.contains(target))return;let rect=target.getBoundingClientRect();list.insertBefore(item,event.clientY>rect.top+rect.height/2?target.nextSibling:target)});item.addEventListener('pointerup',()=>{if(touchItem===item){item.classList.remove('family-layout-touch-dragging');touchItem=null}});item.addEventListener('pointercancel',()=>{if(touchItem===item){item.classList.remove('family-layout-touch-dragging');touchItem=null}})})}
function readPrefs(){let rows=layoutRows(),hidden=rows.filter(row=>{let box=row.querySelector('input[data-layout-key]');return box&&!box.checked&&!box.disabled}).map(row=>row.dataset.layoutKey),order=rows.map(row=>row.dataset.layoutKey),nextExpanded=rows.filter(row=>row.querySelector('input[data-layout-expanded]')?.checked&&!hidden.includes(row.dataset.layoutKey)).map(row=>row.dataset.layoutKey);return {hidden,order,expanded:nextExpanded}}
function setStatus(text,bad=false){let node=document.querySelector('#family-layout-status');if(node){node.textContent=text;node.style.color=bad?'#ff6961':'#8e8e93'}}
async function saveEnhanced(reset){let payload=reset?{page:layoutPage,hidden:[],order:[...document.querySelectorAll('#family-layout-list .family-layout-item')].map(row=>row.dataset.layoutKey).sort((a,b)=>0),expanded:[]}:Object.assign({page:layoutPage},readPrefs());if(reset){let original={'devices':['devices','manual_add','bypass','traffic','z4pro','router','wireguard'],'dns':['rankings','observability','data_management'],'airport':['subscription_help','switch_history'],'rules':['guide','preview'],'maintenance':['guide']}[layoutPage]||[];payload.order=original}try{setStatus('正在保存…');let response=await fetch('/api/page-layout',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)}),data=await response.json();if(!response.ok)throw Error(data.error||'请求失败');expanded=new Set(data.expanded||[]);applyFoldState();applyAirportState(data.hidden||[]);setStatus(reset?'已恢复默认':'已保存');setTimeout(()=>location.reload(),240)}catch(error){setStatus(error.message,true)}}
function interceptActions(){document.addEventListener('click',event=>{let button=event.target.closest('#family-layout-save,#family-layout-reset');if(!button)return;event.preventDefault();event.stopImmediatePropagation();saveEnhanced(button.id==='family-layout-reset')},true)}
function loadState(){fetch('/api/page-layout').then(response=>response.json()).then(data=>{let prefs=data[layoutPage]||{};expanded=new Set(prefs.expanded||[]);applyFoldState();applyAirportState(prefs.hidden||[]);enhanceList()}).catch(()=>enhanceList())}
function updateDialogHint(){let hint=document.querySelector('.family-layout-head p'),text='拖住左侧手柄调整顺序；“显示”控制区块是否可见；“默认展开”仅决定折叠区块打开状态。';if(hint&&hint.textContent!==text)hint.textContent=text}
new MutationObserver(()=>{enhanceList();updateDialogHint()}).observe(document.documentElement,{childList:true,subtree:true});interceptActions();loadState();updateDialogHint();
})();</script>''')
    injection = client + enhancements
    if "</head>" in html:
        return html.replace("</head>", injection + "</head>", 1)
    return html.replace("</body>", injection + "</body>", 1)


def config():
    return dict(line.strip().split("=", 1) for line in CONFIG.read_text().splitlines()
                if "=" in line and not line.lstrip().startswith("#"))


def merge_env_text(text, updates, remove=()):
    """Replace selected env keys without exposing or reordering unrelated settings."""
    remove = set(remove)
    seen = set()
    lines = []
    for raw in text.splitlines():
        if "=" in raw and not raw.lstrip().startswith("#"):
            key = raw.split("=", 1)[0].strip()
            if key in remove:
                continue
            if key in updates:
                lines.append(f"{key}={updates[key]}")
                seen.add(key)
                continue
        lines.append(raw)
    for key, value in updates.items():
        if key not in seen:
            lines.append(f"{key}={value}")
    return "\n".join(lines).rstrip("\n") + "\n"


def setup_state():
    try:
        value = json.loads(SETUP_STATE_PATH.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError):
        return {}


def setup_pending():
    return setup_state().get("pending") is True


def setup_link():
    token = setup_state().get("token", "")
    return "/setup?" + urlencode({"token": token}) if token else "/setup"


def setup_token_valid(token):
    expected = setup_state().get("token", "")
    return bool(expected and token and hmac.compare_digest(str(token), str(expected)))


def hash_password(password):
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 210000).hex()
    return salt.hex(), digest


def valid_endpoint(value):
    return bool(value and len(value) <= 255 and re.fullmatch(r"[A-Za-z0-9_.:-]+", value))


def valid_url(value, allow_blank=False):
    if not value and allow_blank:
        return True
    parsed = urlsplit(value)
    return (parsed.scheme in {"http", "https"} and bool(parsed.netloc)
            and not any(char.isspace() for char in value) and len(value) <= 255)


def setup_updates(form):
    def get(name):
        return form.get(name, [""])[0].strip()

    router_host = get("router_host")
    router_user = get("router_user")
    router_password = form.get("router_password", [""])[0]
    ui_username = get("ui_username")
    ui_password = form.get("ui_password", [""])[0]
    ui_password_confirm = form.get("ui_password_confirm", [""])[0]
    dns_username = get("dns_username")
    dns_password = form.get("dns_password", [""])[0]
    mosdns_api_url = get("mosdns_api_url")
    geodata_proxy = get("geodata_proxy")

    if not valid_endpoint(router_host):
        raise ValueError("RouterOS API 地址格式不正确")
    if not router_user or len(router_user) > 64 or not re.fullmatch(r"[^=\r\n]+", router_user):
        raise ValueError("RouterOS API 用户格式不正确")
    if not router_password or "\n" in router_password or "\r" in router_password:
        raise ValueError("RouterOS API 密码不能为空")
    if not ui_username or len(ui_username) > 64 or not re.fullmatch(r"[^=\r\n]+", ui_username):
        raise ValueError("管理页用户名格式不正确")
    if len(ui_password) < 12 or "\n" in ui_password or "\r" in ui_password:
        raise ValueError("管理页密码至少需要 12 个字符")
    if ui_password != ui_password_confirm:
        raise ValueError("两次输入的管理页密码不一致")
    if bool(dns_username) != bool(dns_password) or "\n" in dns_password or "\r" in dns_password:
        raise ValueError("DNS 页面用户名和密码必须同时填写")
    if not valid_url(mosdns_api_url) or not valid_url(geodata_proxy, allow_blank=True):
        raise ValueError("可选服务地址必须是 http 或 https 地址")

    salt, digest = hash_password(ui_password)
    dns_auth = base64.b64encode(f"{dns_username}:{dns_password}".encode()).decode() if dns_username else ""
    return {
        "ROUTER_HOST": router_host,
        "ROUTER_USER": router_user,
        "ROUTER_PASSWORD": router_password,
        "UI_USERNAME": ui_username,
        "UI_PASSWORD_SALT": salt,
        "UI_PASSWORD_HASH": digest,
        "DNS_UPSTREAM_AUTH_B64": dns_auth,
        "MOSDNS_API_URL": mosdns_api_url,
        "FAMILY_GEODATA_PROXY": geodata_proxy,
        "ROUTER_CN_AUTO_SYNC": "true" if "router_cn_auto_sync" in form else "false",
        "MIHOMO_GEODATA_AUTO_UPDATE": "true" if "geodata_auto_update" in form else "false",
        "SETUP_PENDING": "false",
    }


def write_setup_config(updates):
    temporary = CONFIG.with_suffix(".new")
    merged = merge_env_text(CONFIG.read_text(encoding="utf-8"), updates, remove=("UI_PASSWORD",))
    temporary.write_text(merged, encoding="utf-8")
    os.chmod(temporary, 0o600)
    os.replace(temporary, CONFIG)


def write_setup_state(state):
    temporary = SETUP_STATE_PATH.with_suffix(".new")
    temporary.write_text(json.dumps(state, ensure_ascii=False) + "\n", encoding="utf-8")
    os.chmod(temporary, 0o600)
    os.replace(temporary, SETUP_STATE_PATH)


def setup_page(error=""):
    values = config()
    checked_router = "checked" if values.get("ROUTER_CN_AUTO_SYNC", "true").lower() == "true" else ""
    checked_geodata = "checked" if values.get("MIHOMO_GEODATA_AUTO_UPDATE", "false").lower() == "true" else ""
    replacements = {
        "__TOKEN__": html.escape(setup_state().get("token", ""), quote=True),
        "__ROUTER_HOST__": html.escape(values.get("ROUTER_HOST", ""), quote=True),
        "__ROUTER_USER__": html.escape(values.get("ROUTER_USER", ""), quote=True),
        "__UI_USERNAME__": html.escape(values.get("UI_USERNAME", ""), quote=True),
        "__MOSDNS_API_URL__": html.escape(values.get("MOSDNS_API_URL", "http://127.0.0.1:9099"), quote=True),
        "__GEODATA_PROXY__": html.escape(values.get("FAMILY_GEODATA_PROXY", "http://127.0.0.1:7890"), quote=True),
        "__ROUTER_CN_AUTO_SYNC__": checked_router,
        "__GEODATA_AUTO_UPDATE__": checked_geodata,
        "__ERROR__": html.escape(error),
    }
    body = SETUP_PAGE
    for marker, value in replacements.items():
        body = body.replace(marker, value)
    return body.encode("utf-8")


def setup_error_page(error):
    body = SETUP_ERROR_PAGE.replace("__ERROR__", html.escape(error)).replace(
        "__SETUP_LINK__", html.escape(setup_link(), quote=True)).encode("utf-8")
    return body


def restart_after_setup():
    try:
        subprocess.run(
            ["systemctl", "restart", "family-proxy-ui", "family-mihomo-sub-import"],
            check=True, capture_output=True, timeout=30,
        )
        if config().get("MIHOMO_GEODATA_AUTO_UPDATE", "false").lower() == "true":
            subprocess.run(["systemctl", "enable", "--now", "family-mihomo-geodata-refresh.timer"],
                           check=True, capture_output=True, timeout=15)
        else:
            subprocess.run(["systemctl", "disable", "--now", "family-mihomo-geodata-refresh.timer"],
                           check=False, capture_output=True, timeout=15)
    except (OSError, subprocess.SubprocessError):
        # Configuration is already durable; the next installer/upgrade retries the reload.
        pass


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

    def setup_response(self, body, status=HTTPStatus.OK):
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.end_headers()
        self.wfile.write(body)

    def handle_setup(self, form):
        token = form.get("token", [""])[0]
        with SETUP_LOCK:
            if not setup_token_valid(token):
                self.setup_response(setup_error_page("安装向导令牌无效或已使用，请重新运行安装器获取新地址。"), HTTPStatus.FORBIDDEN)
                return
            try:
                updates = setup_updates(form)
                write_setup_config(updates)
                write_setup_state({"pending": False, "completed_at": int(time.time()), "version": 1})
            except (OSError, ValueError) as exc:
                self.setup_response(setup_page(str(exc)), HTTPStatus.BAD_REQUEST)
                return
        self.setup_response(SETUP_COMPLETE_PAGE.encode("utf-8"))
        threading.Thread(target=restart_after_setup, daemon=True).start()

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
                self.send_error(HTTPStatus.BAD_GATEWAY, "DNS management backend authentication is unavailable")
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
                    html = html.replace(
                        "</head>",
                        '<style>@media(min-width:761px){.topbar-inner{position:relative}.topbar-inner .nav{position:absolute;left:50%;transform:translateX(-50%)}}@media(max-width:760px){.topbar-inner{position:static}.topbar-inner .nav{position:static;transform:none}}@media(min-width:901px){.header-inner{position:relative}.header-inner .global-nav{position:absolute;left:50%;transform:translateX(-50%)}}@media(max-width:900px){.header-inner{position:static}.header-inner .global-nav{position:static;transform:none}}</style></head>',
                        1,
                    )
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
            # BaseHTTPRequestHandler puts the reason phrase in HTTP headers,
            # which must be Latin-1.  Keep it ASCII so a transient upstream
            # restart always returns a valid 502 rather than breaking the page.
            self.send_error(HTTPStatus.BAD_GATEWAY, "Management backend temporarily unavailable")

    def do_GET(self):
        if not self.allowed():
            self.send_error(HTTPStatus.FORBIDDEN)
            return
        parsed = urlsplit(self.path)
        if parsed.path == "/favicon.ico":
            self.send_response(HTTPStatus.NO_CONTENT)
            self.end_headers()
            return
        if setup_pending():
            if parsed.path in {"/", "/login"}:
                self.redirect(setup_link())
                return
            if parsed.path == "/setup":
                token = parse_qs(parsed.query).get("token", [""])[0]
                if not setup_token_valid(token):
                    self.setup_response(setup_error_page("安装向导令牌无效或已使用，请打开安装器输出的完整地址。"), HTTPStatus.FORBIDDEN)
                    return
                self.setup_response(setup_page())
                return
        if parsed.path == "/setup":
            self.redirect("/login")
            return
        if parsed.path == "/login":
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
        parsed = urlsplit(self.path)
        if setup_pending() and parsed.path == "/setup":
            size = int(self.headers.get("Content-Length", "0"))
            if size > 32768:
                self.setup_response(setup_error_page("请求内容过大。"), HTTPStatus.BAD_REQUEST)
                return
            form = parse_qs(self.rfile.read(size).decode(errors="replace"))
            self.handle_setup(form)
            return
        if parsed.path == "/login":
            self.login()
            return
        if parsed.path == "/logout":
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
