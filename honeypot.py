import asyncio
import json
import os
import signal
import sys
import sqlite3
import threading
import time
from collections import deque
from dataclasses import dataclass, asdict
from typing import Deque, Dict, List, Optional

import hashlib
import hmac
import uuid

import requests
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
import uvicorn


if getattr(sys, "frozen", False):
  BASE_DIR = os.path.dirname(sys.executable)
else:
  BASE_DIR = os.path.dirname(__file__)


CONFIG_PATH = os.path.join(BASE_DIR, "config.json")
DB_PATH = os.path.join(BASE_DIR, "honeypot.db")


PORT_PROTOCOL: Dict[int, str] = {
  # Well-known login and infra services (privileged ports)
  20: "FTP-Data",
  21: "FTP",
  22: "SSH",
  23: "Telnet",
  25: "SMTP",
  53: "DNS",
  67: "DHCP-Server",
  68: "DHCP-Client",
  69: "TFTP",
  80: "HTTP",
  88: "Kerberos",
  110: "POP3",
  119: "NNTP",
  123: "NTP",
  135: "MSRPC",
  137: "NetBIOS-NS",
  138: "NetBIOS-DGM",
  139: "NetBIOS-SSN",
  143: "IMAP",
  161: "SNMP",
  389: "LDAP",
  443: "HTTPS",
  445: "SMB",
  465: "SMTPS",
  514: "Syslog",
  587: "Submission",
  631: "IPP",
  636: "LDAPS",
  873: "rsync",
  993: "IMAPS",
  995: "POP3S",
  990: "FTPS",
  1433: "MSSQL",
  1521: "Oracle",
  1723: "PPTP",
  1812: "RADIUS-Auth",
  1813: "RADIUS-Acct",
  2049: "NFS",
  27017: "MongoDB",
  27018: "MongoDB",
  27019: "MongoDB",
  3306: "MySQL",
  3389: "RDP",
  4333: "MySQL-Alt",
  5432: "PostgreSQL",
  5900: "VNC",
  5984: "CouchDB",
  6379: "Redis",
  500: "ISAKMP",
  4500: "IPsec-NAT-T",
  5060: "SIP",
  5061: "SIPS",
  8000: "HTTP-Alt",
  8008: "HTTP-Alt",
  8080: "HTTP-Proxy",
  8081: "HTTP-Alt",
  8083: "HTTP-Alt",
  8086: "HTTP-Alt",
  8088: "HTTP-Alt",
  8090: "HTTP-Alt",
  8181: "HTTP-Alt",
  8222: "HTTP-Alt",
  8243: "HTTPS-Alt",
  8280: "HTTP-Alt",
  8333: "Bitcoin",
  8443: "HTTPS-Alt",
  8530: "WSUS",
  8531: "WSUS-SSL",
  8554: "RTSP",
  8834: "Nessus",
  8880: "HTTP-Alt",
  8883: "MQTTS",
  8888: "HTTP-Alt",
  9000: "HTTP-Alt",
  9042: "Cassandra",
  9060: "IBM-DB2",
  9090: "HTTP-Alt",
  9091: "HTTP-Alt",
  9200: "Elasticsearch",
  9300: "Elasticsearch-Node",
  9418: "Git",
  9443: "HTTPS-Alt",
  11211: "Memcached",
  15672: "RabbitMQ",
  25565: "Minecraft",
  27015: "SourceGame",
  27016: "SourceGame",
  27960: "Quake3",
}


def _protocol_for_port(port: int) -> str:
  try:
    return PORT_PROTOCOL.get(int(port), f"TCP/{int(port)}")
  except Exception:
    return f"TCP/{port}"


async def _send_deceptive_response(writer: asyncio.StreamWriter, port: int, data: bytes) -> None:
  proto = _protocol_for_port(port)
  text = ""
  try:
    text = data[:512].decode("utf-8", errors="replace")
  except Exception:
    text = ""
  lower = text.lower()

  try:
    if proto == "SSH":
      writer.write(b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n")
      await writer.drain()
      return

    if proto == "LDAP":
      writer.write(b"version: 3\n")
      await writer.drain()
      return

    if proto == "SIP":
      writer.write(
        b"SIP/2.0 200 OK\r\n"
        b"Server: Asterisk PBX\r\n"
        b"Content-Length: 0\r\n\r\n"
      )
      await writer.drain()
      return

    if proto == "Minecraft":
      writer.write("§1\0\0A Minecraft Server\n".encode("utf-8", errors="ignore"))
      await writer.drain()
      return

    if proto == "SourceGame":
      writer.write(b"Source Engine Query\n")
      await writer.drain()
      return

    if proto == "Quake3":
      writer.write(b"\xff\xff\xff\xffprint\nQuake 3 Server\n")
      await writer.drain()
      return

    if "http" in proto.lower() or lower.startswith(("get ", "post ", "head ", "put ", "delete ", "options ")):
      if "authorization:" in lower or "login" in lower or "signin" in lower:
        writer.write(
          b"HTTP/1.1 401 Unauthorized\r\n"
          b"WWW-Authenticate: Basic realm=\"Restricted\"\r\n"
          b"Content-Length: 0\r\n"
          b"Connection: close\r\n\r\n"
        )
      else:
        first_line = text.splitlines()[0] if text.splitlines() else ""
        path = "/"
        try:
          parts = first_line.split()
          if len(parts) >= 2:
            path = parts[1]
        except Exception:
          path = "/"

        body_str: str
        if "wp-login.php" in path or "wp-admin" in path or "wp-content" in path or "xmlrpc.php" in path:
          body_str = (
            "<!DOCTYPE html>"
            "<html><head>"
            "<meta charset=\"UTF-8\">"
            "<title>Log In &lsaquo; My Blog &#8212; WordPress</title>"
            "<meta name=\"generator\" content=\"WordPress 5.8.1\" />"
            "</head>"
            "<body class=\"login login-action-login wp-core-ui\">"
            "<div id=\"login\">"
            "<h1><a href=\"https://wordpress.org/\" tabindex=\"-1\">Powered by WordPress</a></h1>"
            "<form name=\"loginform\" id=\"loginform\" action=\"/wp-login.php\" method=\"post\">"
            "<p><label for=\"user_login\">Username or Email Address<br />"
            "<input type=\"text\" name=\"log\" id=\"user_login\" class=\"input\" value=\"\" size=\"20\"></label></p>"
            "<p><label for=\"user_pass\">Password<br />"
            "<input type=\"password\" name=\"pwd\" id=\"user_pass\" class=\"input\" value=\"\" size=\"20\"></label></p>"
            "<p class=\"submit\"><input type=\"submit\" name=\"wp-submit\" id=\"wp-submit\" class=\"button button-primary button-large\" value=\"Log In\"></p>"
            "</form>"
            "<p id=\"backtoblog\"><a href=\"/\">&larr; Go to My Blog</a></p>"
            "</div>"
            "</body></html>"
          )
        elif "phpmyadmin" in path or ".php" in path:
          body_str = (
            "<!DOCTYPE html>"
            "<html><head>"
            "<meta charset=\"utf-8\">"
            "<title>phpMyAdmin</title>"
            "</head><body>"
            "<h1>Welcome to phpMyAdmin</h1>"
            "<p>Version 4.9.7</p>"
            "</body></html>"
          )
        else:
          body_str = (
            "<html><head><title>Welcome</title></head>"
            "<body><h1>It works!</h1><p>Service ready.</p></body></html>"
          )

        body = body_str.encode("utf-8", errors="ignore")
        headers = (
          b"HTTP/1.1 200 OK\r\n"
          b"Server: Apache/2.4.49 (Ubuntu)\r\n"
          b"Content-Type: text/html; charset=utf-8\r\n"
          + f"Content-Length: {len(body)}\r\n".encode("ascii", errors="ignore")
          + b"Connection: close\r\n\r\n"
        )
        writer.write(headers + body)
      await writer.drain()
      return

    if proto == "FTP" or proto == "Telnet":
      if "user " in lower or "pass " in lower:
        writer.write(b"530 Login incorrect.\r\n")
      else:
        writer.write(b"220 ProFTPD 1.3.5a Server ready.\r\n")
      await writer.drain()
      return

    if proto == "SMTP":
      if "auth" in lower or "login" in lower:
        writer.write(b"535 5.7.8 Authentication credentials invalid\r\n")
      else:
        writer.write(b"220 mail.example.com ESMTP Postfix\r\n")
      await writer.drain()
      return

    if proto in ("IMAP", "POP3"):
      if "login" in lower or "auth" in lower or "pass " in lower:
        writer.write(b"-ERR Authentication failed.\r\n")
      else:
        if proto == "IMAP":
          writer.write(b"* OK [CAPABILITY IMAP4rev1] Dovecot ready.\r\n")
        else:
          writer.write(b"+OK POP3 server ready\r\n")
      await writer.drain()
      return

    if proto == "Redis":
      if "auth" in lower:
        writer.write(b"-WRONGPASS invalid username-password pair\r\n")
      else:
        writer.write(b"+PONG\r\n")
      await writer.drain()
      return

    if proto == "Memcached":
      writer.write(b"STORED\r\n")
      await writer.drain()
      return

    if proto in ("MySQL", "PostgreSQL"):
      writer.write(b"Access denied for user (using password: YES)\n")
      await writer.drain()
      return

    if proto == "MongoDB":
      writer.write(b"Authentication failed.\n")
      await writer.drain()
      return

    if any(k in lower for k in ("user", "pass", "login", "auth")):
      writer.write(b"Authentication failed.\n")
      await writer.drain()
      return

    msg = f"Service ready on port {port}\n".encode("utf-8", errors="ignore")
    writer.write(msg)
    await writer.drain()
  except Exception:
    return


@dataclass
class HoneypotEvent:
  timestamp: int
  ip: str
  port: int
  protocol: str
  bytes_received: int
  preview: str
  hex_sample: Optional[str] = None
  base64_sample: Optional[str] = None
  printable_ratio: Optional[float] = None
  has_null_bytes: Optional[bool] = None
  lat: Optional[float] = None
  lon: Optional[float] = None

  def to_threat_payload(self) -> Dict:
    payload: Dict[str, object] = {
      "timestamp": self.timestamp,
      "ip": self.ip,
      "protocol": self.protocol,
      "port": self.port,
      "attackType": "honeypot",
      "bytesReceived": self.bytes_received,
      "preview": self.preview,
      "reason": "honeypot",
      "details": f"{self.protocol} connection captured by honeypot on port {self.port} ({self.bytes_received} bytes)",
    }

    if self.hex_sample:
      payload["hexSample"] = self.hex_sample
    if self.base64_sample:
      payload["base64Sample"] = self.base64_sample
    if self.printable_ratio is not None:
      payload["printableRatio"] = float(self.printable_ratio)
    if self.has_null_bytes is not None:
      payload["hasNullBytes"] = bool(self.has_null_bytes)

    if self.lat is not None and self.lon is not None:
      try:
        payload["lat"] = float(self.lat)
        payload["lon"] = float(self.lon)
      except Exception:
        pass

    return payload


class ThreatReporter:
  def __init__(self, config: Optional[Dict] = None) -> None:
    cfg = config or {}

    self.client_id = os.environ.get("THREAT_REPORTER_CLIENT_ID") or cfg.get("threat_reporter_client_id")
    self.api_key = os.environ.get("THREAT_REPORTER_API_KEY") or cfg.get("threat_reporter_api_key", "")
    self.api_secret = os.environ.get("THREAT_REPORTER_SECRET") or cfg.get("threat_reporter_secret")
    self.server_url = os.environ.get("THREAT_REPORTER_SERVER") or cfg.get("threat_reporter_server")

    env_broadcast = os.environ.get("THREAT_REPORTER_BROADCAST_LOCATION")
    if env_broadcast is not None:
      val = env_broadcast.strip().lower()
      self.broadcast_location = val in ("1", "true", "yes", "on")
    else:
      self.broadcast_location = bool(cfg.get("broadcast_location", False))

    if not self.client_id or not self.api_secret or not self.server_url:
      raise RuntimeError(
        "Threat Reporter credentials must be provided via environment or config.json"
      )

  def report_threat(self, event: HoneypotEvent) -> Optional[str]:
    payload = event.to_threat_payload()
    try:
      if hasattr(self, "broadcast_location"):
        payload["broadcastLocation"] = bool(getattr(self, "broadcast_location"))
    except Exception:
      pass
    nonce = str(uuid.uuid4())
    signature_input = f"{self.client_id}{nonce}{json.dumps(payload, separators=(",", ":"))}"
    signature = hmac.new(
      self.api_secret.encode(),
      signature_input.encode(),
      hashlib.sha256,
    ).hexdigest()

    try:
      resp = requests.post(
        f"{self.server_url}/api/threats/report",
        json={
          "clientId": self.client_id,
          "nonce": nonce,
          "payload": payload,
          "signature": signature,
        },
        timeout=5,
      )
      if resp.status_code != 201:
        try:
          data = resp.json()
          err = data.get("error")
        except Exception:
          err = resp.text
        print(f"[WARN] Failed to report threat: {resp.status_code} {err}", file=sys.stderr)
        return None
      data = resp.json()
      return data.get("id")
    except Exception as exc:
      print(f"[WARN] Error reporting threat: {exc}", file=sys.stderr)
      return None


class HoneypotServer:
  def __init__(self, config: Dict, reporter: Optional[ThreatReporter]) -> None:
    self.config = config
    self.reporter = reporter
    self.events: Deque[HoneypotEvent] = deque(maxlen=int(config.get("max_events", 200)))
    self.servers: List[asyncio.AbstractServer] = []
    self.udp_transports: List[asyncio.DatagramTransport] = []
    self.total_connections = 0
    self._geo_cache: Dict[str, Optional[tuple]] = {}
    self._db_path = DB_PATH
    self._db_lock = threading.Lock()
    self._db_conn = sqlite3.connect(self._db_path, check_same_thread=False)
    self._init_db()

  def _init_db(self) -> None:
    with self._db_lock:
      cur = self._db_conn.cursor()
      cur.execute(
        """
        CREATE TABLE IF NOT EXISTS honeypot_events (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          timestamp_ms INTEGER NOT NULL,
          ip TEXT NOT NULL,
          port INTEGER NOT NULL,
          protocol TEXT NOT NULL,
          bytes_received INTEGER NOT NULL,
          preview TEXT,
          hex_sample TEXT,
          base64_sample TEXT,
          printable_ratio REAL,
          has_null_bytes INTEGER,
          lat REAL,
          lon REAL
        )
        """
      )
      cur.execute(
        "CREATE INDEX IF NOT EXISTS idx_honeypot_events_ts ON honeypot_events(timestamp_ms DESC)"
      )
      cur.execute(
        "CREATE INDEX IF NOT EXISTS idx_honeypot_events_ip ON honeypot_events(ip)"
      )

      # Migrations for older DBs that may miss newer columns.
      for ddl in [
        "ALTER TABLE honeypot_events ADD COLUMN lat REAL",
        "ALTER TABLE honeypot_events ADD COLUMN lon REAL",
        "ALTER TABLE honeypot_events ADD COLUMN hex_sample TEXT",
        "ALTER TABLE honeypot_events ADD COLUMN base64_sample TEXT",
        "ALTER TABLE honeypot_events ADD COLUMN printable_ratio REAL",
        "ALTER TABLE honeypot_events ADD COLUMN has_null_bytes INTEGER",
      ]:
        try:
          cur.execute(ddl)
        except Exception:
          continue
      self._db_conn.commit()

  def _lookup_geo(self, ip: str) -> tuple[Optional[float], Optional[float]]:
    """Best-effort IP geolocation using ip-api.com, with in-memory caching.

    Returns (lat, lon) or (None, None) if lookup fails.
    """
    if ip in self._geo_cache:
      cached = self._geo_cache[ip]
      if cached is None:
        return None, None
      return cached  # type: ignore[return-value]

    lat: Optional[float] = None
    lon: Optional[float] = None
    try:
      resp = requests.get(
        f"http://ip-api.com/json/{ip}?fields=status,lat,lon",
        timeout=2,
      )
      if resp.ok:
        data = resp.json()
        if data.get("status") == "success":
          lat = data.get("lat")
          lon = data.get("lon")
    except Exception:
      pass

    if lat is not None and lon is not None:
      self._geo_cache[ip] = (float(lat), float(lon))
      return float(lat), float(lon)

    self._geo_cache[ip] = None
    return None, None

  def _persist_event(self, event: HoneypotEvent) -> None:
    try:
      with self._db_lock:
        cur = self._db_conn.cursor()
        cur.execute(
          "INSERT INTO honeypot_events (timestamp_ms, ip, port, protocol, bytes_received, preview, hex_sample, base64_sample, printable_ratio, has_null_bytes, lat, lon) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
          (
            int(event.timestamp),
            event.ip,
            int(event.port),
            event.protocol,
            int(event.bytes_received),
            event.preview,
            event.hex_sample,
            event.base64_sample,
            float(event.printable_ratio) if event.printable_ratio is not None else None,
            1 if event.has_null_bytes else 0 if event.has_null_bytes is not None else None,
            float(event.lat) if event.lat is not None else None,
            float(event.lon) if event.lon is not None else None,
          ),
        )
        self._db_conn.commit()
    except Exception as exc:
      print(f"[WARN] Failed to persist honeypot event: {exc}", file=sys.stderr)

  def _handle_event_background(self, event: HoneypotEvent) -> None:
    try:
      lat, lon = self._lookup_geo(event.ip)
      if lat is not None and lon is not None:
        event.lat = float(lat)
        event.lon = float(lon)
    except Exception:
      pass

    self._persist_event(event)
    reporting_enabled = bool(self.config.get("reporting_enabled", True))
    if reporting_enabled and self.reporter is not None:
      try:
        self.reporter.report_threat(event)
      except Exception as exc:
        print(f"[WARN] Error in Threat Reporter while sending event: {exc}", file=sys.stderr)

  def total_connections_all_time(self) -> int:
    """Return total number of honeypot events stored in SQLite (all time)."""
    try:
      with self._db_lock:
        cur = self._db_conn.cursor()
        cur.execute("SELECT COUNT(*) FROM honeypot_events")
        row = cur.fetchone()
        return int(row[0]) if row and row[0] is not None else 0
    except Exception as exc:
      print(f"[WARN] Failed to compute total connections from DB: {exc}", file=sys.stderr)
      return self.total_connections

  def recent_events_from_db(self, limit: int) -> List[HoneypotEvent]:
    """Fetch most recent events from SQLite for UI display."""
    events: List[HoneypotEvent] = []
    try:
      with self._db_lock:
        cur = self._db_conn.cursor()
        cur.execute(
          "SELECT timestamp_ms, ip, port, protocol, bytes_received, preview, hex_sample, base64_sample, printable_ratio, has_null_bytes, lat, lon "
          "FROM honeypot_events ORDER BY timestamp_ms DESC LIMIT ?",
          (int(limit),),
        )
        rows = cur.fetchall()
    except Exception as exc:
      print(f"[WARN] Failed to load recent events from DB: {exc}", file=sys.stderr)
      return events

    for row in rows:
      try:
        (
          ts_ms,
          ip,
          port,
          protocol,
          bytes_received,
          preview,
          hex_sample,
          base64_sample,
          printable_ratio,
          has_null_bytes,
          lat,
          lon,
        ) = row
        ev = HoneypotEvent(
          timestamp=int(ts_ms),
          ip=str(ip),
          port=int(port),
          protocol=str(protocol),
          bytes_received=int(bytes_received),
          preview=str(preview) if preview is not None else "",
          hex_sample=str(hex_sample) if hex_sample is not None else None,
          base64_sample=str(base64_sample) if base64_sample is not None else None,
          printable_ratio=float(printable_ratio) if printable_ratio is not None else None,
          has_null_bytes=bool(has_null_bytes) if has_null_bytes is not None else None,
          lat=float(lat) if lat is not None else None,
          lon=float(lon) if lon is not None else None,
        )
        events.append(ev)
      except Exception:
        continue

    return events

  def stats_summary(self) -> Dict[str, object]:
    """Aggregate basic statistics for the WebUI from SQLite.

    Includes all-time and recent connection counts, unique IPs,
    protocol breakdown, and the most active ports.
    """
    summary: Dict[str, object] = {
      "total_all_time": 0,
      "unique_ips": 0,
      "last_1h": 0,
      "last_24h": 0,
      "by_protocol": {},
      "top_ports": [],
    }

    now_ms = int(time.time() * 1000)
    cutoff_1h = now_ms - 3600 * 1000
    cutoff_24h = now_ms - 24 * 3600 * 1000

    try:
      with self._db_lock:
        cur = self._db_conn.cursor()

        cur.execute("SELECT COUNT(*) FROM honeypot_events")
        row = cur.fetchone()
        if row and row[0] is not None:
          summary["total_all_time"] = int(row[0])

        cur.execute("SELECT COUNT(DISTINCT ip) FROM honeypot_events")
        row = cur.fetchone()
        if row and row[0] is not None:
          summary["unique_ips"] = int(row[0])

        cur.execute(
          "SELECT COUNT(*) FROM honeypot_events WHERE timestamp_ms >= ?",
          (cutoff_1h,),
        )
        row = cur.fetchone()
        if row and row[0] is not None:
          summary["last_1h"] = int(row[0])

        cur.execute(
          "SELECT COUNT(*) FROM honeypot_events WHERE timestamp_ms >= ?",
          (cutoff_24h,),
        )
        row = cur.fetchone()
        if row and row[0] is not None:
          summary["last_24h"] = int(row[0])

        by_protocol: Dict[str, int] = {}
        cur.execute(
          "SELECT protocol, COUNT(*) FROM honeypot_events GROUP BY protocol"
        )
        for proto, count in cur.fetchall() or []:
          try:
            by_protocol[str(proto)] = int(count)
          except Exception:
            continue
        summary["by_protocol"] = by_protocol

        top_ports: List[Dict[str, int]] = []
        cur.execute(
          "SELECT port, COUNT(*) AS c FROM honeypot_events "
          "GROUP BY port ORDER BY c DESC LIMIT 5"
        )
        for port, count in cur.fetchall() or []:
          try:
            top_ports.append({"port": int(port), "count": int(count)})
          except Exception:
            continue
        summary["top_ports"] = top_ports

    except Exception as exc:
      print(f"[WARN] Failed to compute stats from DB: {exc}", file=sys.stderr)

    return summary

  def usage_series(self, max_days: int = 365) -> List[Dict[str, int]]:
    """Return per-day total bytes_received for up to max_days back.

    Results are ordered by day (ascending) and each item has:
    {"day_start_ms": <epoch_ms_at_midnight_utc>, "bytes": <sum_bytes>}.
    """
    series: List[Dict[str, int]] = []
    try:
      now_ms = int(time.time() * 1000)
      day_ms = 24 * 3600 * 1000
      today_day_index = now_ms // day_ms
      oldest_day_index = max(0, today_day_index - max_days + 1)

      with self._db_lock:
        cur = self._db_conn.cursor()
        cur.execute(
          "SELECT (timestamp_ms / ?) AS day_idx, SUM(bytes_received) "
          "FROM honeypot_events "
          "WHERE (timestamp_ms / ?) BETWEEN ? AND ? "
          "GROUP BY day_idx ORDER BY day_idx ASC",
          (day_ms, day_ms, oldest_day_index, today_day_index),
        )
        rows = cur.fetchall()

      for day_idx, total_bytes in rows or []:
        try:
          d_idx = int(day_idx)
          b = int(total_bytes or 0)
          day_start_ms = d_idx * day_ms
          series.append({"day_start_ms": day_start_ms, "bytes": b})
        except Exception:
          continue
    except Exception as exc:
      print(f"[WARN] Failed to compute usage series from DB: {exc}", file=sys.stderr)

    return series

  async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    peer = writer.get_extra_info("peername") or ("?", 0)
    ip, _ = peer[0], peer[1]
    sock = writer.get_extra_info("socket")
    try:
      local_port = sock.getsockname()[1]
    except Exception:
      local_port = 0
    chunks: List[bytes] = []
    total = 0
    max_bytes = 8192
    overall_deadline = time.time() + 3.0
    while total < max_bytes and time.time() < overall_deadline:
      timeout = max(0.1, overall_deadline - time.time())
      try:
        chunk = await asyncio.wait_for(reader.read(1024), timeout=timeout)
      except asyncio.TimeoutError:
        break
      if not chunk:
        break
      chunks.append(chunk)
      total += len(chunk)

    data = b"".join(chunks)

    self.total_connections += 1

    preview = ""
    hex_sample: Optional[str] = None
    base64_sample: Optional[str] = None
    printable_ratio: Optional[float] = None
    has_null_bytes: Optional[bool] = None
    if data:
      try:
        preview = data[:1024].decode("utf-8", errors="replace")[:300]
      except Exception:
        preview = repr(data)[:300]

      slice_bytes = data[:1024]
      hex_sample = slice_bytes[:256].hex()
      import base64 as _b64

      base64_sample = _b64.b64encode(slice_bytes[:512]).decode("ascii", errors="replace")

      window = slice_bytes[:200]
      if window:
        printable = sum(1 for b in window if 32 <= b <= 126)
        printable_ratio = float(printable) / float(len(window))
        has_null_bytes = any(b == 0 for b in window)

    event = HoneypotEvent(
      timestamp=int(time.time() * 1000),
      ip=str(ip),
      port=int(local_port),
      protocol=_protocol_for_port(int(local_port)),
      bytes_received=len(data),
      preview=preview,
      hex_sample=hex_sample,
      base64_sample=base64_sample,
      printable_ratio=printable_ratio,
      has_null_bytes=has_null_bytes,
    )
    self.events.appendleft(event)

    loop = asyncio.get_running_loop()
    loop.run_in_executor(None, self._handle_event_background, event)
    try:
      await _send_deceptive_response(writer, int(local_port), data)
    except Exception:
      pass

    try:
      writer.close()
      await writer.wait_closed()
    except Exception:
      pass

  async def start(self) -> None:
    mode = (self.config.get("mode") or "all").lower()
    ports: List[int] = []

    if mode == "list":
      ports = [int(p) for p in self.config.get("ports", [])]
    else:
      ports = list(range(1, 65536))
    exclude = {int(p) for p in self.config.get("exclude_ports", [])}
    ui_port = int(self.config.get("ui_port", 8080))
    exclude.add(ui_port)
    if exclude:
      ports = [p for p in ports if p not in exclude]

    # In mode="all", avoid exhausting OS file descriptors by limiting
    # how many ports we actually bind. This can be raised via config
    # ("max_listen_ports") if you also raise the OS ulimit.
    if mode == "all":
      max_listen = int(self.config.get("max_listen_ports", 4096))
      if max_listen > 0 and len(ports) > max_listen:
        ports = ports[:max_listen]

    loop = asyncio.get_running_loop()

    for port in ports:
      try:
        server = await asyncio.start_server(
          self.handle_client,
          host="0.0.0.0",
          port=port,
        )
        self.servers.append(server)
      except (OSError, PermissionError):
        continue
      except Exception:
        continue

      try:
        class UDPPotProtocol(asyncio.DatagramProtocol):
          def __init__(self, parent: "HoneypotServer", local_port: int) -> None:
            self.parent = parent
            self.local_port = local_port

          def datagram_received(self, data: bytes, addr) -> None:
            ip, _ = addr
            self.parent.total_connections += 1

            preview = ""
            hex_sample: Optional[str] = None
            base64_sample: Optional[str] = None
            printable_ratio: Optional[float] = None
            has_null_bytes: Optional[bool] = None
            if data:
              try:
                preview = data[:1024].decode("utf-8", errors="replace")[:300]
              except Exception:
                preview = repr(data)[:300]

              slice_bytes = data[:1024]
              hex_sample = slice_bytes[:256].hex()
              import base64 as _b64

              base64_sample = _b64.b64encode(slice_bytes[:512]).decode("ascii", errors="replace")

              window = slice_bytes[:200]
              if window:
                printable = sum(1 for b in window if 32 <= b <= 126)
                printable_ratio = float(printable) / float(len(window))
                has_null_bytes = any(b == 0 for b in window)

            event = HoneypotEvent(
              timestamp=int(time.time() * 1000),
              ip=str(ip),
              port=int(self.local_port),
              protocol=_protocol_for_port(int(self.local_port)),
              bytes_received=len(data),
              preview=preview,
              hex_sample=hex_sample,
              base64_sample=base64_sample,
              printable_ratio=printable_ratio,
              has_null_bytes=has_null_bytes,
            )
            self.parent.events.appendleft(event)

            loop_ref = asyncio.get_event_loop()
            loop_ref.run_in_executor(None, self.parent._handle_event_background, event)

        transport, _ = await loop.create_datagram_endpoint(
          lambda: UDPPotProtocol(self, port),
          local_addr=("0.0.0.0", port),
        )
        self.udp_transports.append(transport)
      except (OSError, PermissionError):
        continue
      except Exception:
        continue

    tcp_ports = len(self.servers)
    udp_ports = len(self.udp_transports)
    print(f"[INFO] Honeypot listening on {tcp_ports} TCP ports and {udp_ports} UDP ports (mode={mode})")

  async def stop(self) -> None:
    for server in self.servers:
      server.close()
      await server.wait_closed()
    for transport in self.udp_transports:
      try:
        transport.close()
      except Exception:
        pass
    try:
      with self._db_lock:
        self._db_conn.close()
    except Exception:
      pass

  def listening_ports(self) -> List[int]:
    ports: List[int] = []
    for server in self.servers:
      for sock in server.sockets or []:
        try:
          ports.append(sock.getsockname()[1])
        except Exception:
          continue
    for transport in self.udp_transports:
      try:
        addr = transport.get_extra_info("sockname")
        if addr and len(addr) >= 2:
          ports.append(addr[1])
      except Exception:
        continue
    return sorted(set(ports))


def _sha256_hex(path: str) -> str:
  h = hashlib.sha256()
  with open(path, "rb") as f:
    for chunk in iter(lambda: f.read(65536), b""):
      h.update(chunk)
  return h.hexdigest()


def load_config() -> Dict:
  if os.path.exists(CONFIG_PATH):
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
      return json.load(f)
  example_path = os.path.join(BASE_DIR, "config.example.json")
  if os.path.exists(example_path):
    with open(example_path, "r", encoding="utf-8") as f:
      return json.load(f)
  return {
    "mode": "all",
    "ports": [22, 23, 25, 53, 80, 110, 135, 139, 143, 161, 389, 443, 445, 465, 587, 993, 995, 1025, 1080, 1433, 1521, 1723, 1883, 1900, 2049, 2077, 2082, 2083, 2086, 2087, 2095, 2096, 2375, 2376, 2483, 2484, 27017, 27018, 27019, 3000, 3128, 3306, 3389, 3478, 3690, 4333, 4444, 4500, 5000, 5060, 5061, 5432, 5671, 5672, 5900, 5938, 5984, 6000, 6379, 6443, 6667, 6881, 7000, 7001, 7199, 7443, 7547, 8000, 8008, 8010, 8080, 8081, 8083, 8086, 8088, 8090, 8161, 8181, 8222, 8243, 8280, 8333, 8443, 8530, 8531, 8554, 8561, 8765, 8834, 8880, 8883, 8888, 9000, 9042, 9060, 9090, 9091, 9200, 9300, 9418, 9443, 9559, 9600, 9917, 9987, 9999, 10000, 11211, 15672, 16010, 17778, 18080, 1935, 27015, 27016, 50000, 50030, 50070, 60000],
    "ui_host": "0.0.0.0",
    "ui_port": 8080,
    "max_events": 200,
    "reporting_enabled": True,
    # Safety limit when mode="all" so we don't exhaust file descriptors
    # trying to bind every port from 1-65535. You can raise this if you
    # increase the OS ulimit for open files.
    "max_listen_ports": 1000,
  }


def create_app(honeypot: HoneypotServer) -> FastAPI:
  app = FastAPI()
  app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
  )

  @app.get("/", response_class=HTMLResponse)
  async def index() -> str:
    return """<!DOCTYPE html>
<html lang=\"en\">
<head>
  <meta charset=\"UTF-8\" />
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />
  <title>InfoBot Honeypot</title>
  <style>
    :root {
      --bg: #020617;
      --bg-elevated: #020617;
      --card: #020617;
      --muted: #1f2937;
      --primary: #22d3ee;
      --primary-soft: rgba(34, 211, 238, 0.15);
      --destructive: #f97373;
      --text: #e5e7eb;
      --muted-text: #9ca3af;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: system-ui, -apple-system, BlinkMacSystemFont, \"SF Pro Text\", sans-serif;
      background:
        radial-gradient(circle at top, rgba(34,211,238,0.18), transparent 55%),
        radial-gradient(circle at bottom, rgba(248,113,113,0.10), transparent 55%),
        #020617;
      color: var(--text);
      min-height: 100vh;
      display: flex;
      align-items: stretch;
      justify-content: center;
      padding: 16px;
    }
    .shell {
      width: 100%;
      max-width: 960px;
      background: radial-gradient(circle at top left, rgba(34,211,238,0.12), transparent 55%),
                  radial-gradient(circle at bottom right, rgba(248,113,113,0.10), transparent 55%),
                  rgba(15,23,42,0.96);
      border-radius: 12px;
      border: 1px solid rgba(148,163,184,0.22);
      box-shadow: 0 0 35px rgba(56,189,248,0.35);
      padding: 16px;
      display: flex;
      flex-direction: column;
      gap: 12px;
      position: relative;
      overflow: hidden;
    }
    .shell::after {
      content: "";
      position: absolute;
      inset: -40px;
      pointer-events: none;
      background-image:
        radial-gradient(circle at 50% 10%, rgba(34,211,238,0.18) 0, transparent 60%),
        radial-gradient(circle at 10% 90%, rgba(59,130,246,0.22) 0, transparent 65%),
        radial-gradient(circle at 90% 60%, rgba(45,212,191,0.16) 0, transparent 70%);
      mix-blend-mode: screen;
      opacity: 0.6;
      filter: blur(3px);
      transform: translate3d(0,0,0) scale(1.02);
      animation: warpField 38s ease-in-out infinite alternate;
      z-index: 0;
    }
    .network-anim {
      position: absolute;
      inset: -32px;
      background-image:
        radial-gradient(circle at 10% 20%, rgba(56,189,248,0.35) 0, transparent 35%),
        radial-gradient(circle at 80% 30%, rgba(45,212,191,0.25) 0, transparent 40%),
        radial-gradient(circle at 30% 80%, rgba(248,113,113,0.24) 0, transparent 40%),
        linear-gradient(120deg, rgba(15,23,42,0.4) 0, rgba(15,23,42,0.9) 45%, rgba(15,23,42,0.4) 100%),
        repeating-linear-gradient(135deg, rgba(30,64,175,0.75) 0, rgba(30,64,175,0.75) 1px, transparent 1px, transparent 9px);
      opacity: 0.55;
      mix-blend-mode: screen;
      filter: blur(0.2px);
      pointer-events: none;
      animation: networkDrift 32s linear infinite alternate;
    }
    .network-anim::before,
    .network-anim::after {
      content: "";
      position: absolute;
      inset: -40px;
      background-image:
        repeating-linear-gradient(120deg,
          rgba(34,211,238,0.0) 0,
          rgba(34,211,238,0.0) 12px,
          rgba(34,211,238,0.55) 13px,
          rgba(34,211,238,0.85) 16px,
          rgba(34,211,238,0.0) 18px),
        repeating-linear-gradient(300deg,
          rgba(59,130,246,0.0) 0,
          rgba(59,130,246,0.0) 18px,
          rgba(59,130,246,0.4) 19px,
          rgba(59,130,246,0.8) 22px,
          rgba(59,130,246,0.0) 24px);
      mix-blend-mode: screen;
      opacity: 0.45;
      animation: trafficStreamA 11s linear infinite;
    }
    .network-anim::after {
      opacity: 0.35;
      animation: trafficStreamB 17s linear infinite;
    }
    .header, .grid {
      position: relative;
      z-index: 1;
    }
    .header {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      justify-content: space-between;
      gap: 8px;
    }
    .title {
      font-size: 18px;
      font-weight: 600;
      letter-spacing: 0.04em;
      text-transform: uppercase;
    }
    .title span {
      font-family: \"SF Mono\", ui-monospace, Menlo, monospace;
      color: var(--primary);
    }
    .pill {
      font-family: \"SF Mono\", ui-monospace, Menlo, monospace;
      font-size: 11px;
      padding: 4px 8px;
      border-radius: 999px;
      border: 1px solid rgba(34,211,238,0.6);
      background: rgba(15,23,42,0.9);
      color: var(--primary);
      letter-spacing: 0.14em;
      text-transform: uppercase;
    }
    .grid {
      display: grid;
      grid-template-columns: 1fr;
      gap: 12px;
    }
    @media (min-width: 768px) {
      .grid {
        grid-template-columns: 1.1fr 1.2fr;
      }
    }
    .card {
      background: radial-gradient(circle at top, rgba(15,23,42,0.9), rgba(15,23,42,0.98));
      border-radius: 10px;
      border: 1px solid rgba(148,163,184,0.35);
      padding: 10px 12px;
      position: relative;
      overflow: hidden;
    }
    .card::before {
      content: "";
      position: absolute;
      inset: 0;
      pointer-events: none;
      background-image:
        linear-gradient(rgba(148,163,184,0.12) 1px, transparent 1px),
        linear-gradient(90deg, rgba(148,163,184,0.12) 1px, transparent 1px);
      background-size: 18px 18px;
      opacity: 0.35;
      mix-blend-mode: soft-light;
    }
    .card-inner {
      position: relative;
      z-index: 1;
    }
    .card-title {
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0.2em;
      color: var(--muted-text);
      margin-bottom: 6px;
      font-family: \"SF Mono\", ui-monospace, Menlo, monospace;
    }
    .stat-row {
      display: flex;
      justify-content: space-between;
      align-items: center;
      font-size: 12px;
      margin-bottom: 2px;
    }
    .stat-label {
      color: var(--muted-text);
      text-transform: uppercase;
      letter-spacing: 0.12em;
      font-size: 10px;
    }
    .stat-value {
      font-family: \"SF Mono\", ui-monospace, Menlo, monospace;
      font-size: 12px;
    }
    .stat-value.accent {
      color: var(--primary);
    }
    .badge {
      display: inline-flex;
      align-items: center;
      padding: 2px 6px;
      border-radius: 999px;
      border: 1px solid rgba(34,211,238,0.6);
      background: rgba(15,23,42,0.9);
      font-size: 10px;
      text-transform: uppercase;
      letter-spacing: 0.14em;
      font-family: \"SF Mono\", ui-monospace, Menlo, monospace;
      color: var(--primary);
    }
    .events {
      max-height: 320px;
      overflow-y: auto;
      border-radius: 8px;
      border: 1px solid rgba(31,41,55,0.9);
      background: radial-gradient(circle at top, rgba(15,23,42,0.92), rgba(15,23,42,0.98));
    }
    .event-row {
      padding: 6px 8px;
      border-bottom: 1px solid rgba(31,41,55,0.9);
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 6px;
      font-size: 11px;
    }
    .event-row:last-child {
      border-bottom: none;
    }
    .mono {
      font-family: \"SF Mono\", ui-monospace, Menlo, monospace;
      font-size: 11px;
      word-break: break-all;
    }
    .muted {
      color: var(--muted-text);
      font-size: 10px;
    }
    .payload-inline {
      margin-top: 1px;
      padding: 1px 4px;
      border-radius: 999px;
      background: rgba(15,23,42,0.95);
      border: 1px solid rgba(55,65,81,0.8);
      max-width: 260px;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
      font-size: 10px;
      opacity: 0.9;
    }
    .pill-small {
      font-size: 9px;
      letter-spacing: 0.18em;
      text-transform: uppercase;
      color: rgba(148,163,184,0.9);
      font-family: \"SF Mono\", ui-monospace, Menlo, monospace;
    }
    .usage-controls {
      display: inline-flex;
      gap: 4px;
      margin-top: 6px;
      margin-bottom: 4px;
      flex-wrap: wrap;
    }
    .usage-chip {
      border-radius: 999px;
      border: 1px solid rgba(55,65,81,0.9);
      padding: 2px 6px;
      font-size: 10px;
      font-family: "SF Mono", ui-monospace, Menlo, monospace;
      text-transform: uppercase;
      letter-spacing: 0.14em;
      background: rgba(15,23,42,0.9);
      color: var(--muted-text);
      cursor: pointer;
    }
    .usage-chip.active {
      border-color: rgba(34,211,238,0.8);
      color: var(--primary);
      background: rgba(15,23,42,0.98);
    }
    .usage-shell {
      border-radius: 8px;
      border: 1px solid rgba(30,64,175,0.8);
      background: radial-gradient(circle at top, rgba(15,23,42,0.9), rgba(15,23,42,0.98));
      padding: 4px;
    }
    .usage-meta {
      display: flex;
      justify-content: space-between;
      align-items: center;
      font-size: 10px;
      color: var(--muted-text);
      margin-top: 2px;
      font-family: "SF Mono", ui-monospace, Menlo, monospace;
    }
    .map-shell {
      position: relative;
      border-radius: 8px;
      overflow: hidden;
      border: 1px solid rgba(30,64,175,0.8);
      background: radial-gradient(circle at top, rgba(15,23,42,0.9), rgba(15,23,42,0.98));
    }
    .map-caption {
      font-size: 10px;
      color: var(--muted-text);
      padding: 4px 6px 2px 6px;
      border-top: 1px solid rgba(30,64,175,0.6);
      background: radial-gradient(circle at bottom, rgba(15,23,42,0.96), rgba(15,23,42,1));
      font-family: \"SF Mono\", ui-monospace, Menlo, monospace;
      text-transform: uppercase;
      letter-spacing: 0.16em;
    }
    @keyframes networkDrift {
      0% {
        transform: translate3d(0, 0, 0) scale(1.02);
      }
      50% {
        transform: translate3d(-26px, 18px, 0) scale(1.05);
      }
      100% {
        transform: translate3d(18px, -22px, 0) scale(1.03);
      }
    }
    @keyframes warpField {
      0% {
        transform: translate3d(0, 0, 0) scale(1.02) rotate(0deg);
        opacity: 0.4;
      }
      50% {
        transform: translate3d(-18px, 10px, 0) scale(1.06) rotate(1.5deg);
        opacity: 0.7;
      }
      100% {
        transform: translate3d(22px, -14px, 0) scale(1.08) rotate(-1.5deg);
        opacity: 0.45;
      }
    }
    @keyframes trafficStreamA {
      0% {
        transform: translate3d(-40px, 0, 0);
        opacity: 0.35;
      }
      50% {
        transform: translate3d(20px, -10px, 0);
        opacity: 0.6;
      }
      100% {
        transform: translate3d(60px, -30px, 0);
        opacity: 0.35;
      }
    }
    @keyframes trafficStreamB {
      0% {
        transform: translate3d(40px, 10px, 0) scale(1.05);
        opacity: 0.3;
      }
      50% {
        transform: translate3d(-10px, 0, 0) scale(1.03);
        opacity: 0.55;
      }
      100% {
        transform: translate3d(-60px, 24px, 0) scale(1.02);
        opacity: 0.3;
      }
    }
  </style>
  <script src="https://cdn.jsdelivr.net/npm/topojson-client@3/dist/topojson-client.min.js"></script>
</head>
<body>
  <div class=\"shell\">
    <div class=\"network-anim\"></div>
    <div class=\"header\">
      <div>
        <div class=\"title\">Inf0b0t THREAT-VIS <span>HONEYPOT</span></div>
        <div class=\"pill-small\">[ PASSIVE TCP/UDP SENTRY ]</div>
        <div class=\"muted\">Side-project of <b>Inf0b0t</b></div>
      </div>
      <div class=\"pill\" id=\"status-pill\">STATUS · INIT</div>
    </div>

    <div class=\"grid\">
      <div class=\"card\">
        <div class=\"card-inner\">
          <div class=\"card-title\">Runtime</div>
          <div class=\"stat-row\">
            <span class=\"stat-label\">Listening Ports</span>
            <span class=\"stat-value accent\" id=\"ports-count\">0</span>
          </div>
          <div class=\"stat-row\">
            <span class=\"stat-label\">Total Connections</span>
            <span class=\"stat-value\" id=\"total-connections\">0</span>
          </div>
          <div class=\"stat-row\">
            <span class=\"stat-label\">Mode</span>
            <span class=\"stat-value\" id=\"mode\">-</span>
          </div>
          <div class=\"stat-row\" style=\"margin-top:6px;\">
            <span class=\"stat-label\">Ports</span>
            <span class=\"stat-value mono\" id=\"ports-list\">-</span>
          </div>
            <div class=\"stat-row\" style=\"margin-top:6px;\">
              <span class=\"stat-label\">Unique IPs</span>
              <span class=\"stat-value\" id=\"unique-ips\">0</span>
            </div>
            <div class=\"stat-row\">
              <span class=\"stat-label\">Last 1h</span>
              <span class=\"stat-value\" id=\"last-1h\">0</span>
            </div>
            <div class=\"stat-row\">
              <span class=\"stat-label\">Last 24h</span>
              <span class=\"stat-value\" id=\"last-24h\">0</span>
            </div>
            <div class=\"stat-row\">
              <span class=\"stat-label\">TCP / UDP</span>
              <span class=\"stat-value mono\" id=\"proto-split\">-</span>
            </div>
            <div class=\"stat-row\">
              <span class=\"stat-label\">Top Ports</span>
              <span class=\"stat-value mono\" id=\"top-ports\">-</span>
            </div>
        </div>
      </div>

      <div class=\"card\">
        <div class=\"card-inner\">
          <div class=\"card-title\">Attack Map</div>
          <div class=\"map-shell\">
            <svg id=\"attack-map\" viewBox=\"0 0 320 180\" preserveAspectRatio=\"xMidYMid meet\"></svg>
            <div class=\"map-caption\">Recent source IPs (geo-located)</div>
          </div>
        </div>
      </div>
        <div class=\"card\">
          <div class=\"card-inner\">
            <div class=\"card-title\">Attack Volume</div>
            <div class=\"usage-controls\">
              <button class=\"usage-chip active\" data-range=\"day\">Day</button>
              <button class=\"usage-chip\" data-range=\"week\">Week</button>
              <button class=\"usage-chip\" data-range=\"month\">Month</button>
              <button class=\"usage-chip\" data-range=\"year\">Year</button>
              <button class=\"usage-chip\" data-range=\"all\">All</button>
            </div>
            <div class=\"usage-shell\">
              <svg id=\"usage-chart\" viewBox=\"0 0 320 120\" preserveAspectRatio=\"xMidYMid meet\"></svg>
              <div class=\"usage-meta\">
                <span id=\"usage-range-label\">Last 24 hours</span>
                <span id=\"usage-total-label\">0 B</span>
              </div>
            </div>
          </div>
        </div>

      <div class=\"card\">
        <div class=\"card-inner\">
          <div class=\"card-title\">Recent Activity</div>
          <div class=\"events\" id=\"events\"></div>
        </div>
      </div>
    </div>
  </div>

  <script>
    let worldMapInitStarted = false;
    let worldMapCountries = null;
    let usageSeries = [];
    let usageRange = 'day';

    async function initWorldMapData() {
      if (worldMapCountries || worldMapInitStarted) return;
      worldMapInitStarted = true;
      try {
        const res = await fetch('https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json');
        if (!res.ok) return;
        const topo = await res.json();
        if (!window.topojson || !topo.objects || !topo.objects.countries) return;
        const geo = window.topojson.feature(topo, topo.objects.countries);
        const polys = [];
        if (geo && Array.isArray(geo.features)) {
          geo.features.forEach((f) => {
            const geom = f.geometry;
            if (!geom) return;
            if (geom.type === 'Polygon' && Array.isArray(geom.coordinates)) {
              if (geom.coordinates.length) polys.push(geom.coordinates[0]);
            } else if (geom.type === 'MultiPolygon' && Array.isArray(geom.coordinates)) {
              geom.coordinates.forEach((poly) => {
                if (Array.isArray(poly) && poly.length) polys.push(poly[0]);
              });
            }
          });
        }
        if (polys.length) worldMapCountries = polys;
      } catch (e) {
        console.error('world map load failed', e);
      }
    }

    function projectLonLat(lon, lat, mapLeft, mapTop, mapWidth, mapHeight) {
      const xNorm = (lon + 180) / 360;
      const yNorm = 1 - (lat + 90) / 180;
      return {
        x: mapLeft + xNorm * mapWidth,
        y: mapTop + yNorm * mapHeight,
      };
    }

    function buildPathFromCoords(coords, mapLeft, mapTop, mapWidth, mapHeight) {
      if (!coords || !coords.length) return '';
      let d = '';
      for (let i = 0; i < coords.length; i++) {
        const lon = coords[i][0];
        const lat = coords[i][1];
        const pt = projectLonLat(lon, lat, mapLeft, mapTop, mapWidth, mapHeight);
        d += (i === 0 ? 'M' : 'L') + pt.x + ' ' + pt.y;
      }
      return d + 'Z';
    }

    function ipToPoint(ip) {
      let hash = 0;
      for (let i = 0; i < ip.length; i++) {
        hash = (hash * 31 + ip.charCodeAt(i)) >>> 0;
      }
      const x = (hash & 0xffff) / 0xffff;
      const y = ((hash >>> 16) & 0xffff) / 0xffff;
      return { x, y: 1 - y };
    }

    function formatBytes(num) {
      if (!num || num <= 0) return '0 B';
      const units = ['B', 'KB', 'MB', 'GB', 'TB'];
      let idx = 0;
      let n = num;
      while (n >= 1024 && idx < units.length - 1) {
        n /= 1024;
        idx++;
      }
      return `${n.toFixed(n >= 10 || idx === 0 ? 0 : 1)} ${units[idx]}`;
    }

    function renderUsageChart() {
      const svg = document.getElementById('usage-chart');
      if (!svg || !Array.isArray(usageSeries) || !usageSeries.length) return;

      while (svg.firstChild) svg.removeChild(svg.firstChild);

      const width = 320;
      const height = 120;
      const ns = 'http://www.w3.org/2000/svg';
      const paddingLeft = 8;
      const paddingRight = 4;
      const paddingTop = 6;
      const paddingBottom = 14;

      const innerWidth = width - paddingLeft - paddingRight;
      const innerHeight = height - paddingTop - paddingBottom;

      const dayMs = 24 * 60 * 60 * 1000;
      const now = Date.now();

      let rangeDays;
      if (usageRange === 'day') rangeDays = 1;
      else if (usageRange === 'week') rangeDays = 7;
      else if (usageRange === 'month') rangeDays = 30;
      else if (usageRange === 'year') rangeDays = 365;
      else rangeDays = 365;

      const minTime = usageRange === 'all' ? usageSeries[0].day_start_ms : now - rangeDays * dayMs;
      const maxTime = usageSeries[usageSeries.length - 1].day_start_ms + dayMs;

      const filtered = usageSeries.filter((p) => p.day_start_ms + dayMs >= minTime && p.day_start_ms <= maxTime);
      if (!filtered.length) return;

      let maxBytes = 0;
      let totalBytes = 0;
      filtered.forEach((p) => {
        const b = p.bytes || 0;
        if (b > maxBytes) maxBytes = b;
        totalBytes += b;
      });
      if (maxBytes <= 0) maxBytes = 1;

      const bg = document.createElementNS(ns, 'rect');
      bg.setAttribute('x', '0');
      bg.setAttribute('y', '0');
      bg.setAttribute('width', String(width));
      bg.setAttribute('height', String(height));
      bg.setAttribute('fill', 'rgba(15,23,42,0.98)');
      svg.appendChild(bg);

      const steps = 3;
      for (let i = 0; i <= steps; i++) {
        const y = paddingTop + (innerHeight * i) / steps;
        const line = document.createElementNS(ns, 'line');
        line.setAttribute('x1', String(paddingLeft));
        line.setAttribute('y1', String(y));
        line.setAttribute('x2', String(paddingLeft + innerWidth));
        line.setAttribute('y2', String(y));
        line.setAttribute('stroke', 'rgba(30,64,175,0.4)');
        line.setAttribute('stroke-width', '0.5');
        line.setAttribute('stroke-dasharray', '2 4');
        svg.appendChild(line);
      }

      const path = document.createElementNS(ns, 'path');
      let d = '';
      filtered.forEach((p, idx) => {
        const t = p.day_start_ms;
        const x = paddingLeft + ((t - minTime) / (maxTime - minTime)) * innerWidth;
        const y = paddingTop + innerHeight * (1 - (p.bytes || 0) / maxBytes);
        d += (idx === 0 ? 'M' : 'L') + x + ' ' + y;
      });
      if (d) {
        path.setAttribute('d', d);
        path.setAttribute('fill', 'none');
        path.setAttribute('stroke', '#22d3ee');
        path.setAttribute('stroke-width', '1.4');
        svg.appendChild(path);
      }

      const area = document.createElementNS(ns, 'path');
      if (filtered.length) {
        let dArea = '';
        filtered.forEach((p, idx) => {
          const t = p.day_start_ms;
          const x = paddingLeft + ((t - minTime) / (maxTime - minTime)) * innerWidth;
          const y = paddingTop + innerHeight * (1 - (p.bytes || 0) / maxBytes);
          dArea += (idx === 0 ? 'M' : 'L') + x + ' ' + y;
        });
        const last = filtered[filtered.length - 1];
        const first = filtered[0];
        const xLast = paddingLeft + ((last.day_start_ms - minTime) / (maxTime - minTime)) * innerWidth;
        const xFirst = paddingLeft + ((first.day_start_ms - minTime) / (maxTime - minTime)) * innerWidth;
        dArea += `L${xLast} ${paddingTop + innerHeight}L${xFirst} ${paddingTop + innerHeight}Z`;
        area.setAttribute('d', dArea);
        area.setAttribute('fill', 'rgba(34,211,238,0.16)');
        area.setAttribute('stroke', 'none');
        svg.insertBefore(area, path);
      }

      const rangeLabel = document.getElementById('usage-range-label');
      if (rangeLabel) {
        const labelMap = {
          day: 'Last 24 hours',
          week: 'Last 7 days',
          month: 'Last 30 days',
          year: 'Last 365 days',
          all: 'All time',
        };
        rangeLabel.textContent = labelMap[usageRange] || 'All time';
      }

      const totalLabel = document.getElementById('usage-total-label');
      if (totalLabel) totalLabel.textContent = formatBytes(totalBytes);
    }

    async function fetchUsage() {
      try {
        const res = await fetch('/api/usage');
        if (!res.ok) return;
        const data = await res.json();
        usageSeries = Array.isArray(data.series) ? data.series : [];
        renderUsageChart();
      } catch (e) {
        console.error(e);
      }
    }

    async function fetchStatus() {
      try {
        const res = await fetch('/api/status');
        if (!res.ok) return;
        const data = await res.json();
        document.getElementById('total-connections').textContent = data.total_connections;
        document.getElementById('ports-count').textContent = data.listening_ports.length;
        document.getElementById('mode').textContent = data.mode.toUpperCase();
        document.getElementById('ports-list').textContent = data.listening_ports.slice(0, 20).join(', ') + (data.listening_ports.length > 20 ? ' …' : '');
        const pill = document.getElementById('status-pill');
        pill.textContent = 'STATUS · ONLINE';

        const stats = data.stats || {};
        const byProtocol = stats.by_protocol || {};
        const topPorts = Array.isArray(stats.top_ports) ? stats.top_ports : [];

        const uniqueEl = document.getElementById('unique-ips');
        if (uniqueEl) uniqueEl.textContent = (stats.unique_ips ?? 0).toString();

        const last1hEl = document.getElementById('last-1h');
        if (last1hEl) last1hEl.textContent = (stats.last_1h ?? 0).toString();

        const last24hEl = document.getElementById('last-24h');
        if (last24hEl) last24hEl.textContent = (stats.last_24h ?? 0).toString();

        const protoEl = document.getElementById('proto-split');
        if (protoEl) {
          const tcp = byProtocol.TCP || byProtocol.tcp || 0;
          const udp = byProtocol.UDP || byProtocol.udp || 0;
          protoEl.textContent = `TCP: ${tcp} · UDP: ${udp}`;
        }

        const topPortsEl = document.getElementById('top-ports');
        if (topPortsEl) {
          if (!topPorts.length) {
            topPortsEl.textContent = '-';
          } else {
            topPortsEl.textContent = topPorts
              .map((p) => `${p.port}:${p.count}`)
              .join('  ');
          }
        }
      } catch (e) {
        console.error(e);
      }
    }

    function sanitizePreview(input) {
      if (!input) return '';
      let out = '';
      for (let i = 0; i < input.length; i++) {
        const ch = input[i];
        const code = ch.charCodeAt(0);
        // Keep basic printable ASCII; normalize common whitespace to space.
        if (code >= 32 && code <= 126) {
          out += ch;
        } else if (ch === ' ') {
          out += ' ';
        } else if (ch === '\\n' || ch === '\\r' || ch === '\\t') {
          out += ' ';
        } else {
          // Non-printable / binary bytes become a dot so they
          // don't blow up the layout or show gibberish.
          out += '.';
        }
      }
      out = out.replace(/\\s+/g, ' ').trim();
      if (!out) return '';
      const nonDot = out.replace(/\\./g, '').length;
      const ratio = nonDot / out.length;
      if (ratio < 0.2) {
        return `[binary payload, ${input.length} bytes]`;
      }
      return out;
    }

    async function fetchEvents() {
      try {
        const res = await fetch('/api/events');
        if (!res.ok) return;
        const data = await res.json();
        const container = document.getElementById('events');
        container.innerHTML = '';
        const eventsArr = Array.isArray(data.events) ? data.events.slice(0, 100) : [];
        for (const ev of eventsArr) {
          const row = document.createElement('div');
          row.className = 'event-row';

          const left = document.createElement('div');
          const right = document.createElement('div');

          const ts = new Date(ev.timestamp).toLocaleTimeString();
          const previewSanitized = sanitizePreview(ev.preview || '');
          const preview = previewSanitized || '<no payload>';

          const ipLine = document.createElement('div');
          ipLine.className = 'mono';
          ipLine.textContent = `${ev.ip} · ${ev.port}`;

          const previewLine = document.createElement('div');
          previewLine.className = 'payload-inline mono';
          previewLine.textContent = preview;

          left.appendChild(ipLine);
          left.appendChild(previewLine);

          const tsDiv = document.createElement('div');
          tsDiv.className = 'muted';
          tsDiv.style.textAlign = 'right';
          tsDiv.textContent = ts;

          const metaDiv = document.createElement('div');
          metaDiv.className = 'mono';
          metaDiv.style.fontSize = '10px';
          metaDiv.style.opacity = '0.85';
          metaDiv.textContent = `${ev.bytes_received} B · HONEYPOT`;

          right.appendChild(tsDiv);
          right.appendChild(metaDiv);

          row.appendChild(left);
          row.appendChild(right);
          container.appendChild(row);
        }

        const svg = document.getElementById('attack-map');
        if (svg) {
          while (svg.firstChild) svg.removeChild(svg.firstChild);

          let width = 320;
          let height = 180;
          try {
            const vb = svg.viewBox && svg.viewBox.baseVal;
            if (vb && vb.width && vb.height) {
              width = vb.width;
              height = vb.height;
            }
          } catch (_) {}

          const ns = 'http://www.w3.org/2000/svg';

          const padding = 12;
          const mapLeft = padding;
          const mapTop = padding;
          const mapWidth = width - padding * 2;
          const mapHeight = height - padding * 2;

          // Background
          const bg = document.createElementNS(ns, 'rect');
          bg.setAttribute('x', '0');
          bg.setAttribute('y', '0');
          bg.setAttribute('width', String(width));
          bg.setAttribute('height', String(height));
          bg.setAttribute('fill', 'rgba(15,23,42,0.98)');
          svg.appendChild(bg);

          // Subtle lat/long grid
          for (let i = 0; i <= 8; i++) {
            const x = mapLeft + (mapWidth * i) / 8;
            const line = document.createElementNS(ns, 'line');
            line.setAttribute('x1', String(x));
            line.setAttribute('y1', String(mapTop));
            line.setAttribute('x2', String(x));
            line.setAttribute('y2', String(mapTop + mapHeight));
            line.setAttribute('stroke', 'rgba(30,64,175,0.35)');
            line.setAttribute('stroke-width', '0.4');
            line.setAttribute('stroke-dasharray', '2 4');
            svg.appendChild(line);
          }

          for (let j = 0; j <= 4; j++) {
            const y = mapTop + (mapHeight * j) / 4;
            const line = document.createElementNS(ns, 'line');
            line.setAttribute('x1', String(mapLeft));
            line.setAttribute('y1', String(y));
            line.setAttribute('x2', String(mapLeft + mapWidth));
            line.setAttribute('y2', String(y));
            line.setAttribute('stroke', 'rgba(37,99,235,0.35)');
            line.setAttribute('stroke-width', '0.4');
            line.setAttribute('stroke-dasharray', '2 4');
            svg.appendChild(line);
          }

          // Real world map: country polygons from world-atlas via topojson
          if (Array.isArray(worldMapCountries) && worldMapCountries.length) {
            worldMapCountries.forEach((coords) => {
              const d = buildPathFromCoords(coords, mapLeft, mapTop, mapWidth, mapHeight);
              if (!d) return;
              const path = document.createElementNS(ns, 'path');
              path.setAttribute('d', d);
              path.setAttribute('fill', 'rgba(30,64,175,0.55)');
              path.setAttribute('stroke', 'rgba(56,189,248,0.7)');
              path.setAttribute('stroke-width', '0.4');
              path.setAttribute('opacity', '0.95');
              svg.appendChild(path);
            });
          }

          // Border around the map area
          const border = document.createElementNS(ns, 'rect');
          border.setAttribute('x', String(mapLeft));
          border.setAttribute('y', String(mapTop));
          border.setAttribute('width', String(mapWidth));
          border.setAttribute('height', String(mapHeight));
          border.setAttribute('fill', 'none');
          border.setAttribute('stroke', 'rgba(30,64,175,0.9)');
          border.setAttribute('stroke-width', '0.8');
          svg.appendChild(border);

          const maxDots = 80;
          const events = Array.isArray(data.events) ? data.events.slice(0, maxDots) : [];
          events.forEach((ev, idx) => {
            let xNorm;
            let yNorm;

            if (typeof ev.lat === 'number' && typeof ev.lon === 'number') {
              const lat = Math.max(-85, Math.min(85, ev.lat));
              const lon = Math.max(-180, Math.min(180, ev.lon));
              xNorm = (lon + 180) / 360;
              yNorm = 1 - (lat + 90) / 180;
            } else {
              const pt = ipToPoint(String(ev.ip || ''));
              xNorm = pt.x;
              yNorm = pt.y;
            }

            const cx = mapLeft + xNorm * mapWidth;
            const cy = mapTop + yNorm * mapHeight;

            const glow = document.createElementNS(ns, 'circle');
            glow.setAttribute('cx', String(cx));
            glow.setAttribute('cy', String(cy));
            glow.setAttribute('r', '5');
            glow.setAttribute('fill', 'rgba(34,211,238,0.28)');
            glow.setAttribute('stroke', 'none');
            svg.appendChild(glow);

            const dot = document.createElementNS(ns, 'circle');
            dot.setAttribute('cx', String(cx));
            dot.setAttribute('cy', String(cy));
            dot.setAttribute('r', '2.8');
            dot.setAttribute('fill', idx === 0 ? '#22d3ee' : '#38bdf8');
            dot.setAttribute('stroke', 'rgba(15,23,42,0.9)');
            dot.setAttribute('stroke-width', '0.6');
            svg.appendChild(dot);
          });

          if (!events.length) {
            const label = document.createElementNS(ns, 'text');
            label.setAttribute('x', String(mapLeft + mapWidth / 2));
            label.setAttribute('y', String(mapTop + mapHeight / 2));
            label.setAttribute('text-anchor', 'middle');
            label.setAttribute('dominant-baseline', 'middle');
            label.setAttribute('fill', 'rgba(148,163,184,0.9)');
            label.setAttribute('font-size', '10');
            label.textContent = 'Waiting for attacker traffic…';
            svg.appendChild(label);
          }
        }
      } catch (e) {
        console.error(e);
      }
    }

    function initUsageControls() {
      const chips = Array.from(document.querySelectorAll('.usage-chip'));
      chips.forEach((chip) => {
        chip.addEventListener('click', () => {
          const range = chip.getAttribute('data-range') || 'day';
          usageRange = range;
          chips.forEach((c) => c.classList.toggle('active', c === chip));
          renderUsageChart();
        });
      });
    }

    initWorldMapData();
    initUsageControls();
    fetchStatus();
    fetchEvents();
    fetchUsage();
    setInterval(fetchStatus, 5000);
    setInterval(fetchEvents, 3000);
  </script>
</body>
</html>"""

  @app.get("/api/status", response_class=JSONResponse)
  async def status() -> JSONResponse:
    return JSONResponse(
      {
        "total_connections": honeypot.total_connections_all_time(),
        "listening_ports": honeypot.listening_ports(),
        "mode": (honeypot.config.get("mode") or "all").lower(),
        "stats": honeypot.stats_summary(),
      }
    )

  @app.get("/api/events", response_class=JSONResponse)
  async def events() -> JSONResponse:
    recent = honeypot.recent_events_from_db(honeypot.config.get("max_events", 200))
    return JSONResponse(
      {
        "events": [
          {
            **asdict(ev),
          }
          for ev in recent
        ]
      }
    )

  @app.get("/api/usage", response_class=JSONResponse)
  async def usage() -> JSONResponse:
    series = honeypot.usage_series(365)
    return JSONResponse({"series": series})

  return app


async def main() -> None:
  config = load_config()

  reporting_enabled = bool(config.get("reporting_enabled", True))

  expected_cfg = os.environ.get("HONEYPOT_CONFIG_CHECKSUM")
  if expected_cfg and os.path.exists(CONFIG_PATH):
    actual_cfg = _sha256_hex(CONFIG_PATH)
    if actual_cfg != expected_cfg:
      print(
        "[ERROR] CONFIG INTEGRITY CHECK FAILED - expected",
        expected_cfg,
        "got",
        actual_cfg,
        file=sys.stderr,
      )
      raise SystemExit(1)

  expected_bin = os.environ.get("HONEYPOT_BINARY_CHECKSUM")
  if expected_bin:
    try:
      binary_path = os.path.realpath(__file__)
      actual_bin = _sha256_hex(binary_path)
      if actual_bin != expected_bin:
        print(
          "[ERROR] BINARY INTEGRITY CHECK FAILED - expected",
          expected_bin,
          "got",
          actual_bin,
          file=sys.stderr,
        )
        raise SystemExit(1)
    except Exception as exc:
      print(f"[WARN] Unable to verify binary checksum: {exc}", file=sys.stderr)

  reporter: Optional[ThreatReporter] = None
  if reporting_enabled:
    try:
      reporter = ThreatReporter(config)
    except RuntimeError as exc:
      print(
        "[WARN] Threat Reporter reporting disabled due to configuration error:",
        exc,
        file=sys.stderr,
      )

  honeypot = HoneypotServer(config, reporter)
  await honeypot.start()

  app = create_app(honeypot)

  ui_host = config.get("ui_host", "0.0.0.0")
  ui_port = int(config.get("ui_port", 8080))

  config_uvicorn = uvicorn.Config(app, host=ui_host, port=ui_port, loop="asyncio", lifespan="on")
  server = uvicorn.Server(config_uvicorn)

  loop = asyncio.get_running_loop()

  stop_event = asyncio.Event()

  def _handle_signal(*_: object) -> None:
    loop.call_soon_threadsafe(stop_event.set)

  for sig in (signal.SIGINT, signal.SIGTERM):
    try:
      loop.add_signal_handler(sig, _handle_signal)
    except NotImplementedError:
      pass

  async def run_uvicorn() -> None:
    await server.serve()

  uvicorn_task = asyncio.create_task(run_uvicorn())

  await stop_event.wait()
  print("[INFO] Shutting down honeypot...")
  await honeypot.stop()
  uvicorn_task.cancel()
  try:
    await uvicorn_task
  except asyncio.CancelledError:
    pass


if __name__ == "__main__":
  try:
    asyncio.run(main())
  except KeyboardInterrupt:
    pass
