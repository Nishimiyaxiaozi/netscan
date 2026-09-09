#!/usr/bin/env python3
"""
NetScan — 一个类似 nmap 的轻量网络扫描工具，内置 Web 可视化界面。

仅使用 Python 标准库，无需安装第三方依赖。

功能：
  - 主机发现（TCP 探测，无需 root 权限）
  - 端口扫描（TCP connect 扫描，asyncio 高并发）
  - 服务识别（banner 抓取 + 常见端口签名）
  - Web 可视化界面（实时进度、结果表格、JSON 导出）
  - 命令行模式（无 UI 直接扫描）

用法：
  Web 模式:  python3 netscan.py web --port 8000
  CLI 模式:  python3 netscan.py scan 192.168.1.0/24 -p 22,80,443,1000-2000

免责声明：仅用于对您拥有授权的网络进行安全测试与管理，未经授权的扫描可能违法。
"""

import argparse
import asyncio
import html
import ipaddress
import json
import socket
import sys
import threading
import time
import uuid
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# ---------------------------------------------------------------- 常见端口签名
SERVICE_NAMES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn", 143: "imap",
    443: "https", 445: "smb", 465: "smtps", 587: "smtp", 993: "imaps",
    995: "pop3s", 1433: "mssql", 1521: "oracle", 2049: "nfs", 3306: "mysql",
    3389: "rdp", 5432: "postgresql", 5900: "vnc", 6379: "redis",
    8080: "http-proxy", 8443: "https-alt", 9200: "elasticsearch",
    11211: "memcached", 27017: "mongodb",
}

BANNER_PROBES = {
    21: None, 22: None, 25: None, 80: b"GET / HTTP/1.0\r\nHost: {host}\r\n\r\n",
    443: None, 587: None, 3306: None, 6379: b"PING\r\n",
}

DEFAULT_DISCOVERY_PORTS = [80, 443, 22, 445, 3389, 8080]

TOP_100_PORTS = [
    7, 20, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113, 119,
    135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514, 515,
    543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995, 1025, 1026, 1027,
    1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000, 2001, 2049, 2121,
    2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051, 5060, 5101,
    5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 6646, 7070, 8000,
    8008, 8009, 8080, 8081, 8443, 8888, 9100, 9120, 9944, 9999, 10000, 27017,
    32768, 49152, 49154,
]


# ---------------------------------------------------------------- 扫描核心
def parse_targets(spec):
    """把 '192.168.1.1-50, 10.0.0.0/30, example.com' 解析成 IP/主机名列表。"""
    targets = []
    for part in spec.replace(",", " ").split():
        part = part.strip()
        if not part:
            continue
        if "-" in part and "/" not in part:
            # 形如 192.168.1.1-50 的范围
            base, _, end = part.rpartition("-")
            if "." in base:
                prefix = base.rsplit(".", 1)[0] + "."
                start_last = int(base.rsplit(".", 1)[1])
                end = int(end)
                for i in range(start_last, end + 1):
                    targets.append(f"{prefix}{i}")
            else:
                targets.append(part)
        elif "/" in part:
            try:
                for ip in ipaddress.ip_network(part, strict=False).hosts():
                    targets.append(str(ip))
            except ValueError:
                targets.append(part)
        else:
            targets.append(part)
    return targets


def parse_ports(spec):
    """把 '22,80,443,1000-2000' 解析成端口列表；'top100' 为内置常用端口表。"""
    spec = spec.strip().lower()
    if spec in ("top100", "top-100"):
        return list(TOP_100_PORTS)
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            ports.update(range(int(a), int(b) + 1))
        else:
            ports.add(int(part))
    return sorted(p for p in ports if 1 <= p <= 65535)


def service_name(port):
    if port in SERVICE_NAMES:
        return SERVICE_NAMES[port]
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


async def probe_banner(host, port, timeout):
    """连接成功后尝试读取服务 banner。"""
    probe = BANNER_PROBES.get(port)
    try:
        fut = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(fut, timeout)
    except Exception:
        return ""
    banner = ""
    try:
        if probe:
            writer.write(probe.replace(b"{host}", host.encode()))
            await writer.drain()
        line = await asyncio.wait_for(reader.readline(), timeout)
        banner = line.decode("utf-8", "replace").strip()
    except Exception:
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass
    return banner[:200]


class ScanJob:
    """一次扫描任务，在后台线程里跑 asyncio 事件循环，供 Web UI 轮询。"""

    def __init__(self, targets, ports, timeout=1.5, concurrency=500,
                 discover=True, grab_banner=True):
        self.id = uuid.uuid4().hex[:12]
        self.targets = targets
        self.ports = ports
        self.timeout = timeout
        self.sem_limit = concurrency
        self.discover = discover
        self.grab_banner = grab_banner
        self.total = 0
        self.done = 0
        self.started_at = time.time()
        self.finished_at = None
        self.results = []          # 每个 host: {ip, status, open_ports: [...]}
        self.error = None

    def status(self):
        return {
            "id": self.id,
            "total": self.total,
            "done": self.done,
            "finished": self.finished_at is not None,
            "error": self.error,
            "elapsed": round((self.finished_at or time.time()) - self.started_at, 2),
            "results": self.results,
        }

    def run(self):
        self.total = len(self.targets) * len(self.ports)
        if self.discover:
            self.total += len(self.targets) * len(DEFAULT_DISCOVERY_PORTS)
        try:
            asyncio.run(self._scan())
        except Exception as exc:  # noqa: BLE001
            self.error = str(exc)
        self.finished_at = time.time()

    async def _scan(self):
        sem = asyncio.Semaphore(self.sem_limit)
        loop = asyncio.get_running_loop()

        async def try_connect(host, port):
            async with sem:
                try:
                    fut = asyncio.open_connection(host, port)
                    _, writer = await asyncio.wait_for(fut, self.timeout)
                    writer.close()
                    return True
                except Exception:
                    return False

        # 解析主机名
        resolved = []
        for t in self.targets:
            try:
                info = await loop.run_in_executor(
                    None, socket.gethostbyname, t)
                resolved.append(info if t != info else t)
                if t != info:
                    resolved[-1] = t  # 保留原始目标名用于展示
            except socket.gaierror:
                self.results.append(
                    {"host": t, "ip": "", "status": "主机名解析失败", "open_ports": []})
                self.done += len(self.ports)
                continue

        hosts = []
        for t in resolved:
            try:
                ipaddress.ip_address(t)
                hosts.append(t)
            except ValueError:
                hosts.append(t)  # 主机名，直接当目标扫描

        # 主机发现
        if self.discover:
            alive = []
            for host in hosts:
                probes = [try_connect(host, p) for p in DEFAULT_DISCOVERY_PORTS]
                results = await asyncio.gather(*probes)
                self.done += len(DEFAULT_DISCOVERY_PORTS)
                if any(results):
                    alive.append(host)
                else:
                    self.results.append(
                        {"host": host, "ip": host, "status": "无响应",
                         "open_ports": []})
            hosts = alive
        else:
            alive_hosts = []
            for h in hosts:
                try:
                    ipaddress.ip_address(h)
                    alive_hosts.append(h)
                except ValueError:
                    alive_hosts.append(h)
            hosts = alive_hosts

        # 端口扫描
        for host in hosts:
            open_ports = []

            async def scan_one(port):
                ok = await try_connect(host, port)
                self.done += 1
                if ok:
                    entry = {
                        "port": port,
                        "service": service_name(port),
                        "banner": "",
                    }
                    if self.grab_banner:
                        entry["banner"] = await probe_banner(
                            host, port, self.timeout)
                    open_ports.append(entry)

            await asyncio.gather(*(scan_one(p) for p in self.ports))
            open_ports.sort(key=lambda e: e["port"])
            ip = host
            hostname = ""
            if not host.replace(".", "").isdigit():
                hostname, ip = host, host
            else:
                try:
                    hostname, _, _ = socket.gethostbyaddr(host)
                except (socket.herror, OSError):
                    pass
            self.results.append({
                "host": hostname or host,
                "ip": ip,
                "status": "存活" if open_ports else "存活（无开放端口）",
                "open_ports": open_ports,
            })


JOBS = {}          # job_id -> ScanJob
JOBS_LOCK = threading.Lock()


def start_job(**kwargs):
    job = ScanJob(**kwargs)
    with JOBS_LOCK:
        JOBS[job.id] = job
    threading.Thread(target=job.run, daemon=True).start()
    return job


# ---------------------------------------------------------------- Web 服务
PAGE = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>NetScan — 网络扫描可视化</title>
<style>
  :root {
    --bg: #0d1117; --panel: #161b22; --border: #30363d;
    --text: #e6edf3; --muted: #8b949e; --accent: #58a6ff;
    --green: #3fb950; --red: #f85149; --yellow: #d29922;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; background: var(--bg); color: var(--text);
    font: 14px/1.6 -apple-system, "Segoe UI", "PingFang SC", "Microsoft YaHei", sans-serif;
  }
  header {
    display: flex; align-items: center; gap: 12px;
    padding: 14px 24px; border-bottom: 1px solid var(--border);
    background: var(--panel);
  }
  header h1 { font-size: 18px; margin: 0; color: var(--accent); }
  header .tag { color: var(--muted); font-size: 12px; }
  .wrap { max-width: 1080px; margin: 24px auto; padding: 0 16px; }
  .card {
    background: var(--panel); border: 1px solid var(--border);
    border-radius: 10px; padding: 20px; margin-bottom: 20px;
  }
  .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; }
  .grid3 { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 14px; }
  label { display: block; font-size: 12px; color: var(--muted); margin-bottom: 4px; }
  input[type=text], select {
    width: 100%; padding: 8px 10px; border-radius: 6px;
    border: 1px solid var(--border); background: #0d1117; color: var(--text);
    font: inherit;
  }
  input:focus { outline: 1px solid var(--accent); }
  .row { display: flex; gap: 10px; align-items: center; margin-top: 14px; flex-wrap: wrap; }
  button {
    padding: 9px 22px; border: none; border-radius: 6px; cursor: pointer;
    font: inherit; font-weight: 600;
  }
  .btn-primary { background: var(--accent); color: #04121f; }
  .btn-primary:hover { filter: brightness(1.15); }
  .btn-ghost { background: transparent; color: var(--muted); border: 1px solid var(--border); }
  .btn-ghost:hover { color: var(--text); }
  button:disabled { opacity: .45; cursor: not-allowed; }
  .progress-bar {
    height: 8px; background: #0d1117; border: 1px solid var(--border);
    border-radius: 4px; overflow: hidden; flex: 1;
  }
  .progress-bar > div {
    height: 100%; width: 0; background: linear-gradient(90deg, var(--accent), var(--green));
    transition: width .3s;
  }
  .stat { color: var(--muted); font-size: 12px; min-width: 180px; }
  table { width: 100%; border-collapse: collapse; margin-top: 12px; }
  th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid var(--border); }
  th { color: var(--muted); font-size: 12px; font-weight: 500; }
  .badge {
    display: inline-block; padding: 1px 8px; border-radius: 10px;
    font-size: 12px;
  }
  .b-open  { background: rgba(63,185,80,.15); color: var(--green); }
  .b-dead  { background: rgba(248,81,73,.15); color: var(--red); }
  .b-err   { background: rgba(210,153,34,.15); color: var(--yellow); }
  .b-svc   { background: rgba(88,166,255,.15); color: var(--accent); }
  .port-tag {
    display: inline-block; margin: 2px 6px 2px 0; padding: 2px 8px;
    background: #0d1117; border: 1px solid var(--border); border-radius: 4px;
    font-size: 12px; cursor: pointer;
  }
  .port-tag:hover { border-color: var(--accent); }
  .banner { color: var(--muted); font-size: 12px; }
  .hidden { display: none !important; }
  .err-msg { color: var(--red); margin-top: 10px; }
  .chips { display: flex; gap: 8px; flex-wrap: wrap; margin-top: 8px; }
  .chip {
    padding: 3px 10px; font-size: 12px; border: 1px solid var(--border);
    border-radius: 12px; color: var(--muted); cursor: pointer;
  }
  .chip:hover { color: var(--accent); border-color: var(--accent); }
  .modal {
    position: fixed; inset: 0; background: rgba(0,0,0,.6);
    display: flex; align-items: center; justify-content: center;
  }
  .modal-inner {
    background: var(--panel); border: 1px solid var(--border);
    border-radius: 10px; padding: 24px; width: min(560px, 92vw);
    max-height: 80vh; overflow: auto;
  }
  .modal-inner h3 { margin-top: 0; }
  footer { text-align: center; color: var(--muted); font-size: 12px; padding: 20px; }
</style>
</head>
<body>
<header>
  <h1>NetScan</h1>
  <span class="tag">轻量网络扫描 · TCP Connect · 仅用于授权测试</span>
</header>

<div class="wrap">
  <div class="card">
    <div class="grid">
      <div>
        <label>扫描目标（IP / CIDR / 范围 / 域名，逗号或空格分隔）</label>
        <input type="text" id="targets" placeholder="例：192.168.1.0/24, 10.0.0.1-100, example.com">
        <div class="chips">
          <span class="chip" onclick="fill('127.0.0.1')">127.0.0.1</span>
          <span class="chip" onclick="fill('192.168.1.0/24')">192.168.1.0/24</span>
          <span class="chip" onclick="fill('10.0.0.1-100')">10.0.0.1-100</span>
        </div>
      </div>
      <div>
        <label>端口（如 22,80,443,1000-2000；top100 = 常用端口表）</label>
        <input type="text" id="ports" value="top100">
        <div class="chips">
          <span class="chip" onclick="fillPort('top100')">Top 100</span>
          <span class="chip" onclick="fillPort('22,80,443')">Web/SSH</span>
          <span class="chip" onclick="fillPort('1-1024')">1-1024</span>
          <span class="chip" onclick="fillPort('1-65535')">1-65535（慢）</span>
        </div>
      </div>
    </div>
    <div class="grid3" style="margin-top:14px">
      <div>
        <label>超时（秒）</label>
        <input type="text" id="timeout" value="1.5">
      </div>
      <div>
        <label>并发数</label>
        <input type="text" id="concurrency" value="500">
      </div>
      <div>
        <label>选项</label>
        <select id="options">
          <option value="discover,banner">主机发现 + 抓 Banner</option>
          <option value="banner">跳过主机发现，直接扫端口</option>
          <option value="">仅端口连通性</option>
        </select>
      </div>
    </div>
    <div class="row">
      <button class="btn-primary" id="btnStart" onclick="startScan()">开始扫描</button>
      <button class="btn-ghost" onclick="exportJson()" id="btnExport" disabled>导出 JSON</button>
      <div class="progress-bar hidden" id="progressWrap"><div id="progressFill"></div></div>
      <div class="stat hidden" id="stat"></div>
    </div>
    <div class="err-msg hidden" id="errMsg"></div>
  </div>

  <div class="card hidden" id="resultCard">
    <div id="summary"></div>
    <table>
      <thead>
        <tr><th style="width:22%">主机</th><th style="width:16%">IP</th>
            <th style="width:14%">状态</th><th>开放端口</th></tr>
      </thead>
      <tbody id="tbody"></tbody>
    </table>
  </div>
</div>

<div class="modal hidden" id="modal" onclick="if(event.target===this)closeModal()">
  <div class="modal-inner" id="modalBody"></div>
</div>

<footer>NetScan · 纯 Python 标准库实现 · 请仅对您拥有授权的网络进行扫描</footer>

<script>
let currentJobId = null;
let pollTimer = null;
let lastStatus = null;

function fill(v)  { document.getElementById('targets').value = v; }
function fillPort(v){ document.getElementById('ports').value = v; }

async function startScan() {
  const targets = document.getElementById('targets').value.trim();
  if (!targets) { showError('请填写扫描目标'); return; }
  const opts = document.getElementById('options').value.split(',');
  const body = {
    targets,
    ports: document.getElementById('ports').value || 'top100',
    timeout: parseFloat(document.getElementById('timeout').value) || 1.5,
    concurrency: parseInt(document.getElementById('concurrency').value) || 500,
    discover: opts.includes('discover'),
    grab_banner: opts.includes('banner'),
  };
  hideError();
  document.getElementById('btnStart').disabled = true;
  try {
    const r = await fetch('/api/scan', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(body)});
    const data = await r.json();
    if (!r.ok) throw new Error(data.error || '启动失败');
    currentJobId = data.id;
    lastStatus = null;
    document.getElementById('progressWrap').classList.remove('hidden');
    document.getElementById('stat').classList.remove('hidden');
    document.getElementById('resultCard').classList.add('hidden');
    pollTimer = setInterval(poll, 500);
  } catch (e) {
    showError(e.message);
    document.getElementById('btnStart').disabled = false;
  }
}

async function poll() {
  if (!currentJobId) return;
  try {
    const r = await fetch('/api/status/' + currentJobId);
    const s = await r.json();
    lastStatus = s;
    const pct = s.total ? Math.round(100 * s.done / s.total) : 0;
    document.getElementById('progressFill').style.width = pct + '%';
    document.getElementById('stat').textContent =
      `已完成 ${s.done}/${s.total} (${pct}%) · 耗时 ${s.elapsed}s · 存活 ${s.results.length}`;
    if (s.finished) {
      clearInterval(pollTimer);
      renderResults(s);
      document.getElementById('btnStart').disabled = false;
      document.getElementById('btnExport').disabled = false;
    }
  } catch (e) { /* 网络抖动，下一轮继续 */ }
}

function renderResults(s) {
  document.getElementById('resultCard').classList.remove('hidden');
  const tbody = document.getElementById('tbody');
  tbody.innerHTML = '';
  let alive = 0, openCount = 0;
  for (const host of s.results) {
    const isOpen = host.open_ports.length > 0;
    if (isOpen) { alive++; openCount += host.open_ports.length; }
    const cls = isOpen ? 'b-open' : (host.status.includes('失败') ? 'b-err' : 'b-dead');
    const badge = `<span class="badge ${cls}">${esc(host.status)}</span>`;
    const portHtml = host.open_ports.map(p =>
      `<span class="port-tag" onclick="showDetail('${esc(host.ip)}',${p.port})">${p.port}/${esc(p.service)}</span>`
    ).join('') || '<span class="banner">—</span>';
    tbody.insertAdjacentHTML('beforeend',
      `<tr><td>${esc(host.host)}</td><td>${esc(host.ip)}</td><td>${badge}</td><td>${portHtml}</td></tr>`);
  }
  document.getElementById('summary').innerHTML =
    `<strong>扫描完成</strong> · 目标 ${s.results.length} 个 · 存活并有开放端口 ${alive} 个 · 开放端口共 ${openCount} 个 · 耗时 ${s.elapsed}s`;
}

async function showDetail(ip, port) {
  let banner = '';
  for (const h of (lastStatus?.results || [])) {
    if (h.ip === ip) {
      const p = h.open_ports.find(x => x.port === port);
      if (p) banner = p.banner;
    }
  }
  document.getElementById('modalBody').innerHTML =
    `<h3>${esc(ip)} : ${port}</h3>` +
    `<p><span class="badge b-svc">TCP</span> <span class="badge b-open">开放</span></p>` +
    `<label>Banner / 服务标识</label>` +
    `<pre style="background:#0d1117;border:1px solid var(--border);border-radius:6px;padding:12px;white-space:pre-wrap">${esc(banner || '（无 banner，可能是 HTTP/443 等静默服务）')}</pre>` +
    `<div class="row"><button class="btn-ghost" onclick="closeModal()">关闭</button></div>`;
  document.getElementById('modal').classList.remove('hidden');
}
function closeModal() { document.getElementById('modal').classList.add('hidden'); }

function exportJson() {
  if (!lastStatus) return;
  const blob = new Blob([JSON.stringify(lastStatus, null, 2)], {type: 'application/json'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `netscan_${lastStatus.id}.json`;
  a.click();
}

function showError(m) {
  const e = document.getElementById('errMsg');
  e.textContent = '✗ ' + m; e.classList.remove('hidden');
}
function hideError() { document.getElementById('errMsg').classList.add('hidden'); }
function esc(s) { return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
</script>
</body>
</html>"""


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="application/json"):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/" or self.path.startswith("/index"):
            self._send(200, PAGE, "text/html; charset=utf-8")
        elif self.path.startswith("/api/status/"):
            job_id = self.path.rsplit("/", 1)[1]
            with JOBS_LOCK:
                job = JOBS.get(job_id)
            if job:
                self._send(200, json.dumps(job.status(), ensure_ascii=False))
            else:
                self._send(404, '{"error": "任务不存在"}')
        else:
            self._send(404, '{"error": "not found"}')

    def do_POST(self):
        if self.path != "/api/scan":
            return self._send(404, '{"error": "not found"}')
        try:
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length) or b"{}")
            ports = parse_ports(body.get("ports") or "top100")
            targets = parse_targets(body.get("targets") or "")
            if not targets:
                return self._send(400, '{"error": "没有有效的扫描目标"}')
            if not ports:
                return self._send(400, '{"error": "没有有效的端口"}')
            if len(targets) * len(ports) > 3_000_000:
                return self._send(400, '{"error": "目标数 × 端口数过大，请缩小范围"}')
            job = start_job(
                targets=targets,
                ports=ports,
                timeout=float(body.get("timeout") or 1.5),
                concurrency=min(int(body.get("concurrency") or 500), 2000),
                discover=bool(body.get("discover", True)),
                grab_banner=bool(body.get("grab_banner", True)),
            )
            self._send(200, json.dumps({"id": job.id}))
        except (ValueError, json.JSONDecodeError) as exc:
            self._send(400, json.dumps({"error": f"参数错误: {exc}"}))

    def log_message(self, fmt, *args):  # 静默访问日志
        pass


def cli_scan(args):
    """命令行模式，扫描完直接打印结果表。"""
    targets = parse_targets(args.targets)
    ports = parse_ports(args.ports)
    if not targets or not ports:
        sys.exit("错误：没有有效的目标或端口")
    print(f"[+] 目标 {len(targets)} 个，端口 {len(ports)} 个，超时 {args.timeout}s")
    job = ScanJob(targets, ports, timeout=args.timeout,
                  concurrency=args.concurrency, discover=not args.no_discovery,
                  grab_banner=True)
    t0 = time.time()

    def progress():
        while job.finished_at is None:
            print(f"\r[进度] {job.done}/{job.total}", end="", flush=True)
            time.sleep(0.5)

    threading.Thread(target=progress, daemon=True).start()
    job.run()
    print(f"\r[进度] 完成，耗时 {time.time() - t0:.1f}s          ")
    print(f"\n{'主机':<32}{'IP':<18}{'状态':<14}开放端口")
    print("-" * 90)
    for r in job.results:
        ports_str = ", ".join(
            f"{p['port']}/{p['service']}" for p in r["open_ports"]) or "—"
        print(f"{r['host']:<32}{r['ip']:<18}{r['status']:<14}{ports_str}")
    out = args.output
    if out:
        with open(out, "w", encoding="utf-8") as f:
            json.dump(job.status(), f, ensure_ascii=False, indent=2)
        print(f"\n[+] 结果已保存到 {out}")


def main():
    parser = argparse.ArgumentParser(
        prog="netscan", description="NetScan — 类 nmap 的轻量网络扫描工具")
    sub = parser.add_subparsers(dest="mode", required=True)

    w = sub.add_parser("web", help="启动 Web 可视化界面")
    w.add_argument("--host", default="127.0.0.1", help="监听地址（默认 127.0.0.1）")
    w.add_argument("--port", type=int, default=8000, help="监听端口（默认 8000）")
    w.add_argument("--no-browser", action="store_true", help="不自动打开浏览器")

    s = sub.add_parser("scan", help="命令行扫描模式")
    s.add_argument("targets", help="目标，如 192.168.1.0/24 或 example.com")
    s.add_argument("-p", "--ports", default="top100", help="端口，如 22,80,1000-2000 或 top100")
    s.add_argument("-t", "--timeout", type=float, default=1.5, help="连接超时秒数")
    s.add_argument("-c", "--concurrency", type=int, default=500, help="并发连接数")
    s.add_argument("--no-discovery", action="store_true", help="跳过主机发现")
    s.add_argument("-o", "--output", help="结果保存为 JSON 文件")

    args = parser.parse_args()
    if args.mode == "web":
        url = f"http://{args.host}:{args.port}"
        print(f"[+] NetScan Web 界面: {url}  (Ctrl+C 退出)")
        if not args.no_browser:
            threading.Timer(0.6, lambda: webbrowser.open(url)).start()
        try:
            ThreadingHTTPServer((args.host, args.port), Handler).serve_forever()
        except KeyboardInterrupt:
            print("\n[+] 已退出")
    else:
        cli_scan(args)


if __name__ == "__main__":
    main()
