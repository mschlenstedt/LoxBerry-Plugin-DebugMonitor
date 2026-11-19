#!/usr/bin/env python3
"""Debug Monitor MCP server.

Gives AI assistants (Claude Code, Claude Desktop and other MCP clients)
read-only access to the recorded and live debug messages of the Miniservers.
The filtering happens here on the LoxBerry; the client only gets the result.

Two transports, same tools:
  --http   MCP "Streamable HTTP" on a TCP port (POST /mcp, JSON responses),
           every request needs "Authorization: Bearer <token>". Meant for the
           own network only.
  --stdio  JSON-RPC over stdin/stdout, started through SSH:
           ssh loxberry@<host> perl <bindir>/dmon_ctl.pl mcp-stdio

Data sources: the recordings on the storage, finished recordings still waiting
in RAM, the recording being written in RAM, and the live buffer of the
receiver for the newest seconds. Nothing is written except the PID file and
the log session. Only the Python standard library is used; the decoding of the
datagrams comes from dmon_receiver.py next to this file.
"""

import argparse
import collections
import datetime
import glob
import gzip
import hmac
import importlib.util
import json
import os
import re
import signal
import struct
import sys
import threading
import time
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

_spec = importlib.util.spec_from_file_location(
    "dmon_receiver", os.path.join(os.path.dirname(os.path.abspath(__file__)), "dmon_receiver.py"))
rx = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rx)

SERVER_NAME = "loxberry-plugin-debugmonitor"
# Tool names carry "miniserver_": Claude prefixes mcp__<server>__ and allows
# 64 characters in all, "loxone_miniserver_" would not fit for every tool
TOOL_PREFIX = "miniserver_"
PROTOCOLS = ("2025-06-18", "2025-03-26", "2024-11-05")
MAX_LIMIT = 2000
MAX_RANGE_DAYS = 31
FILE_MARGIN = 900          # seconds: Miniserver clocks may differ from the LoxBerry
REC_NAME = re.compile(r"^(?:pending_)?dm_(\d{8}_\d{6})(?:_crash)?\.raw\.gz$")
TYPE_RE = re.compile(r"^(mDNS|[A-Z][A-Z0-9_]{1,11})\b")
ERR_RE = re.compile(r"\b(error|errors|failed|failure|fail|exception|refused|denied|timeout|timed out|invalid|"
                    r"unreachable|not found|too many requests)\b|HTTP\d*\s+[45]\d\d\b", re.I)
TYPES = ("http", "tcp", "udp", "dns", "ssl", "prg", "lnk", "err", "seq", "other", "binary")

INSTRUCTIONS = (
    "Debug messages of Loxone Miniservers, received by the Debug Monitor plugin on a LoxBerry. "
    "Each line: Miniserver date and time, Miniserver IP, message. Times are the Miniserver's own "
    "local clock (as in the Loxone Monitor). Start with 'miniserver_status' or "
    "'miniserver_list_recordings' to see which period is available, then narrow down with "
    "'miniserver_search', 'miniserver_context', 'miniserver_http_requests' or 'miniserver_summary'. "
    "'miniserver_http_requests' resolves who called the Miniserver (client IP, port 80/443, "
    "user agent, status). "
    "Binary records (task monitor and others) are left out unless asked for.")


##########################################################################
# Data access
##########################################################################

class Entry:
    __slots__ = ("dt", "ip", "text", "kind", "binary", "data", "recv")

    def __init__(self, dt, ip, text, kind, binary, data=None, recv=None):
        self.dt, self.ip, self.text, self.kind, self.binary, self.data, self.recv = \
            dt, ip, text, kind, binary, data, recv

    def line(self):
        return f"{self.dt:%Y-%m-%d %H:%M:%S}.{self.dt.microsecond // 1000:03d} {self.ip:<15} {self.text}"


def read_config(path):
    try:
        with open(path, encoding="utf-8") as f:
            c = json.load(f)
    except (OSError, ValueError):
        c = {}
    return c if isinstance(c, dict) else {}


class Store:
    def __init__(self, a):
        self.a = a

    def recdir(self):
        rec = read_config(self.a.config).get("record") or {}
        return rec.get("path") or self.a.recdir

    def files(self):
        """All recordings, oldest first: (path, start, end, size, where)."""
        out = []
        now = time.time()
        for where, pattern in (("storage", os.path.join(self.recdir(), "dm_*.raw.gz")),
                               ("ram", os.path.join(self.a.rundir, "pending_dm_*.raw.gz"))):
            for p in glob.glob(pattern):
                m = REC_NAME.match(os.path.basename(p))
                if not m:
                    continue
                try:
                    st = os.stat(p)
                except OSError:
                    continue
                start = datetime.datetime.strptime(m.group(1), "%Y%m%d_%H%M%S").timestamp()
                out.append((p, start, st.st_mtime, st.st_size, where))
        cur = os.path.join(self.a.rundir, "rec_current" + rx.REC_SUFFIX)
        try:
            st = os.stat(cur)
            status = self.status() or {}
            start = (status.get("record") or {}).get("since") or st.st_mtime
            out.append((cur, start, now, st.st_size, "ram (being written)"))
        except OSError:
            pass
        out.sort(key=lambda f: f[1])
        return out

    def status(self):
        try:
            with open(os.path.join(self.a.rundir, "status.json"), encoding="utf-8") as f:
                return json.load(f)
        except (OSError, ValueError):
            return None

    @staticmethod
    def _records(path):
        """(receive time, datagram) of one recording. The file being written is
        an unfinished gzip stream: everything flushed so far is read."""
        if os.path.basename(path).startswith("rec_current"):
            try:
                with open(path, "rb") as f:
                    raw = f.read()
                data = zlib.decompressobj(16 + zlib.MAX_WBITS).decompress(raw)
            except (OSError, zlib.error):
                return
            pos = 0
            while pos + rx.RAW_REC.size <= len(data):
                ts, ln = rx.RAW_REC.unpack_from(data, pos)
                if pos + rx.RAW_REC.size + ln > len(data):
                    break
                yield ts, data[pos + rx.RAW_REC.size:pos + rx.RAW_REC.size + ln]
                pos += rx.RAW_REC.size + ln
            return
        try:
            with gzip.open(path, "rb") as f:
                while True:
                    head = f.read(rx.RAW_REC.size)
                    if len(head) < rx.RAW_REC.size:
                        break
                    ts, ln = rx.RAW_REC.unpack(head)
                    data = f.read(ln)
                    if len(data) < ln:
                        break
                    yield ts, data
        except (OSError, EOFError, zlib.error):
            return

    def entries(self, start, end, ip=None):
        """Entries with Miniserver time in [start, end], oldest first. Recordings
        first, then the live buffer for what is not recorded yet."""
        t0, t1 = start.timestamp() - FILE_MARGIN, end.timestamp() + FILE_MARGIN
        newest = {}
        for path, fstart, fend, _size, _where in self.files():
            if fend < t0 or fstart > t1:
                continue
            for ts, data in self._records(path):
                if ts < t0 - FILE_MARGIN:
                    continue
                if ts > t1 + FILE_MARGIN:
                    break
                dt, mip, text, kind = rx.decode(data, ts)
                mip = mip or "?"
                if ip and mip != ip:
                    continue
                if mip not in newest or dt > newest[mip]:
                    newest[mip] = dt
                if start <= dt <= end:
                    yield Entry(dt, mip, text, kind, kind not in (0, None), data, ts)
        for e in self.live(ip):
            if e.dt > newest.get(e.ip, datetime.datetime.min) and start <= e.dt <= end:
                yield e

    def live(self, ip=None):
        out = []
        for name in ("live.1.jsonl", "live.jsonl"):
            try:
                with open(os.path.join(self.a.rundir, name), encoding="utf-8") as f:
                    for raw in f:
                        try:
                            j = json.loads(raw)
                        except ValueError:
                            continue
                        if ip and j.get("ip") != ip:
                            continue
                        t = j.get("t") or ""
                        try:
                            dt = datetime.datetime.strptime(f"{j['d']} {t}", "%Y-%m-%d %H:%M:%S.%f")
                        except (KeyError, ValueError):
                            if j.get("k") == -1 and out:
                                dt = out[-1].dt      # SEQ_ERROR lines carry no time
                            else:
                                continue
                        b = j.get("b")
                        binary = (b == 1) if b is not None else (j.get("k") not in (1, None))
                        out.append(Entry(dt, j.get("ip") or "?", j.get("m", ""), j.get("k"), binary))
            except OSError:
                continue
        return out


##########################################################################
# Filters and helpers
##########################################################################

def parse_time(v, default):
    """now | -15m / -2h / -1d / -30s | HH:MM[:SS] (today, or yesterday if that
    lies in the future) | YYYY-MM-DD HH:MM[:SS][.fff] (also with T)."""
    if v in (None, ""):
        return default
    s = str(v).strip()
    now = datetime.datetime.now()
    if s.lower() == "now":
        return now
    m = re.fullmatch(r"-\s*(\d+(?:\.\d+)?)\s*([smhd])", s.lower())
    if m:
        mult = {"s": 1, "m": 60, "h": 3600, "d": 86400}[m.group(2)]
        return now - datetime.timedelta(seconds=float(m.group(1)) * mult)
    m = re.fullmatch(r"(\d{1,2}):(\d{2})(?::(\d{2})(?:\.(\d{1,3}))?)?", s)
    if m:
        dt = now.replace(hour=int(m.group(1)), minute=int(m.group(2)), second=int(m.group(3) or 0),
                         microsecond=int((m.group(4) or "0").ljust(3, "0")) * 1000)
        return dt - datetime.timedelta(days=1) if dt > now + datetime.timedelta(minutes=5) else dt
    s2 = s.replace("T", " ")
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            return datetime.datetime.strptime(s2, fmt)
        except ValueError:
            pass
    raise ValueError(f"cannot read time '{v}' (use e.g. -15m, 20:39, 2026-11-19 20:39:07)")


def time_range(args, default_minutes=60):
    end = parse_time(args.get("end"), datetime.datetime.now())
    start = parse_time(args.get("start"), end - datetime.timedelta(minutes=default_minutes))
    if start > end:
        start, end = end, start
    if end - start > datetime.timedelta(days=MAX_RANGE_DAYS):
        raise ValueError(f"time range longer than {MAX_RANGE_DAYS} days")
    return start, end


def group_of(e):
    if e.binary:
        return "binary"
    m = e.text
    if m.startswith("HTTP"):
        return "http"
    if m.startswith("TCP"):
        return "tcp"
    if m.startswith("UDP"):
        return "udp"
    if m.startswith("DNS"):
        return "dns"
    if m.startswith("SEQ_ERROR"):
        return "seq"
    return "other"


def matches_type(e, types):
    if not types:
        return True
    g = group_of(e)
    for t in types:
        if t == g:
            return True
        if t == "ssl" and e.text.startswith("SSL"):
            return True
        if t == "prg" and e.text.startswith("PRG"):
            return True
        if t == "lnk" and re.search(r"\bLNK\b", e.text):
            return True
        if t == "err" and not e.binary and ERR_RE.search(e.text):
            return True
    return False


def as_list(v):
    if v in (None, ""):
        return []
    return [str(x).lower() for x in v] if isinstance(v, list) else [str(v).lower()]


def limit_of(args, default):
    try:
        n = int(args.get("limit", default))
    except (TypeError, ValueError):
        n = default
    return max(1, min(MAX_LIMIT, n))


def text_filter(args):
    text = (args.get("text") or "").lower()
    rgx = args.get("regex")
    if rgx:
        try:
            rgx = re.compile(rgx, re.I)
        except re.error as e:
            raise ValueError(f"bad regex: {e}")
    return lambda e: (not text or text in e.text.lower()) and (not rgx or rgx.search(e.text))


def fmt_range(start, end):
    return f"{start:%Y-%m-%d %H:%M:%S} - {end:%Y-%m-%d %H:%M:%S}"


def human(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024


##########################################################################
# HTTP sessions as the Miniserver logs them (level 3)
##########################################################################

# Two firmware formats: "TCP socket accept (<ip> <port>/<source port>)" and
# "TCP <n> accept listen port <port> (from <ip>/<source port>)"
RE_ACCEPT = re.compile(r"TCP socket accept \((\d+\.\d+\.\d+\.\d+) (\d+)/(\d+)\)")
RE_ACCEPT_OLD = re.compile(r"accept listen port (\d+) \(from (\d+\.\d+\.\d+\.\d+)/(\d+)\)")
RE_CONN = re.compile(r"HTTP Client (HTTP\d+) connected, Socket \d+ Port (\d+)")
RE_REQ = re.compile(r"(HTTP\d+) (GET|POST|PUT|DELETE|HEAD|OPTIONS) (\S+)")
RE_UA = re.compile(r"(HTTP\d+) Line User-Agent: ?(.*)")
RE_STATUS = re.compile(r"(HTTP\d+) ([1-5]\d\d)\b ?(.*)")


def http_sessions(entries):
    """Requests per Miniserver: time, client, port, user agent, request, status."""
    accept = {}            # (ms ip, source port) -> (client ip, listen port)
    open_ = {}             # (ms ip, HTTPn) -> session
    for e in entries:
        if e.binary:
            continue
        m = RE_ACCEPT.search(e.text)
        if m:
            accept[(e.ip, m.group(3))] = (m.group(1), m.group(2))
            continue
        m = RE_ACCEPT_OLD.search(e.text)
        if m:
            accept[(e.ip, m.group(3))] = (m.group(2), m.group(1))
            continue
        m = RE_CONN.match(e.text)
        if m:
            key = (e.ip, m.group(1))
            if key in open_ and open_[key]["request"]:
                yield open_[key]
            client = accept.get((e.ip, m.group(2)), ("", ""))
            open_[key] = {"time": e.dt, "ms": e.ip, "srcport": m.group(2), "client": client[0],
                          "port": client[1], "ua": "", "request": "", "status": ""}
            continue
        m = RE_REQ.match(e.text)
        if m:
            key = (e.ip, m.group(1))
            s = open_.get(key)
            if s is None or s["request"]:
                if s and s["request"]:
                    yield s
                s = open_[key] = {"time": e.dt, "ms": e.ip, "srcport": "", "client": "", "port": "",
                                  "ua": "", "request": "", "status": ""}
            s["request"] = f"{m.group(2)} {m.group(3)}"
            continue
        m = RE_UA.match(e.text)
        if m and (e.ip, m.group(1)) in open_:
            open_[(e.ip, m.group(1))]["ua"] = m.group(2).strip()
            continue
        m = RE_STATUS.match(e.text)
        if m and (e.ip, m.group(1)) in open_:
            open_[(e.ip, m.group(1))]["status"] = f"{m.group(2)} {m.group(3)}".strip()
    for s in open_.values():
        if s["request"]:
            yield s


def strip_value(req):
    """GET /dev/sps/io/<name>/<value> -> GET /dev/sps/io/<name>/… for grouping."""
    return re.sub(r"^(\S+ /j?dev/sps/io/[^/]+)/[^/ ]+$", r"\1/…", req.split(" HTTP/")[0])


##########################################################################
# Tools
##########################################################################

TIME_PROPS = {
    "start": {"type": "string", "description": "Start: -15m, -2h, 20:39, 2026-11-19 20:39:07 (Miniserver time). Default: 60 minutes before end."},
    "end": {"type": "string", "description": "End, same formats. Default: now."},
}
IP_PROP = {"ip": {"type": "string", "description": "Only this Miniserver (IP address)."}}
TYPES_PROP = {"types": {"type": "array", "items": {"type": "string", "enum": list(TYPES)},
                        "description": "Message groups: http, tcp, udp, dns, ssl, prg, lnk (Extensions / Loxone Link), "
                                       "err (error words, HTTP 4xx/5xx), seq (SEQ_ERROR), other, binary."}}

TOOLS = [
    {"name": TOOL_PREFIX + "status",
     "description": "Loxone Miniserver debug monitor (LoxBerry plugin): Receiver state: running, UDP port, Miniservers sending (packets, last packet), recording "
                    "settings and the period covered by recordings.",
     "inputSchema": {"type": "object", "properties": {}}},
    {"name": TOOL_PREFIX + "list_recordings",
     "description": "Loxone Miniserver debug monitor (LoxBerry plugin): All recordings with start, end and size, including the one being written in RAM.",
     "inputSchema": {"type": "object", "properties": {}}},
    {"name": TOOL_PREFIX + "search",
     "description": "Loxone Miniserver debug monitor (LoxBerry plugin): Debug lines in a time range, filtered by Miniserver, message group, text and regex. "
                    "Returns at most 'limit' lines (default 200, the newest unless keep=first).",
     "inputSchema": {"type": "object", "properties": {
         **TIME_PROPS, **IP_PROP, **TYPES_PROP,
         "text": {"type": "string", "description": "Substring, case-insensitive."},
         "regex": {"type": "string", "description": "Regular expression (Python), case-insensitive."},
         "include_binary": {"type": "boolean", "description": "Also binary records (hex). Default false."},
         "limit": {"type": "integer", "description": "Max lines, 1-2000. Default 200."},
         "keep": {"type": "string", "enum": ["last", "first"], "description": "Which lines to keep when more match. Default last."}}}},
    {"name": TOOL_PREFIX + "context",
     "description": "Loxone Miniserver debug monitor (LoxBerry plugin): All lines around a point in time (default 10 s before and after), e.g. to see what led to an error.",
     "inputSchema": {"type": "object", "required": ["time"], "properties": {
         "time": {"type": "string", "description": "Point in time, e.g. 20:39:07.531 or 2026-11-19 20:39:07."},
         **IP_PROP,
         "before": {"type": "number", "description": "Seconds before. Default 10."},
         "after": {"type": "number", "description": "Seconds after. Default 10."},
         "include_binary": {"type": "boolean"},
         "limit": {"type": "integer", "description": "Max lines. Default 500."}}}},
    {"name": TOOL_PREFIX + "http_requests",
     "description": "Loxone Miniserver debug monitor (LoxBerry plugin): HTTP requests to the Miniserver with the caller resolved: client IP, port (80 http / 443 https), "
                    "user agent, request and status (only errors are logged by the Miniserver, e.g. 401). "
                    "Needs Miniserver monitor level 3 for client and user agent. group=true counts per caller and input.",
     "inputSchema": {"type": "object", "properties": {
         **TIME_PROPS, **IP_PROP,
         "client": {"type": "string", "description": "Only callers whose IP contains this."},
         "path": {"type": "string", "description": "Only requests containing this."},
         "status": {"type": "string", "description": "'error' for any error status, or a code like 401."},
         "group": {"type": "boolean", "description": "Count per caller, user agent, input and status. Default false."},
         "limit": {"type": "integer", "description": "Max rows. Default 200."}}}},
    {"name": TOOL_PREFIX + "summary",
     "description": "Loxone Miniserver debug monitor (LoxBerry plugin): Overview of a time range per Miniserver: lines, message groups, most frequent types, "
                    "most frequent error messages, swapped datagrams (SEQ_ERROR), HTTP callers.",
     "inputSchema": {"type": "object", "properties": {**TIME_PROPS, **IP_PROP}}},
    {"name": TOOL_PREFIX + "taskmon",
     "description": "Loxone Miniserver debug monitor (LoxBerry plugin): Task monitor of the Miniserver right now: "
                    "CPU usage, heap, max heap, temperature, uptime, network and link counters, and the threads "
                    "with CPU %, stack, context switches and state, busiest first.",
     "inputSchema": {"type": "object", "properties": {
         **IP_PROP,
         "threads": {"type": "integer", "description": "Number of threads to list, busiest first. Default 15, 0 = all."}}}},
    {"name": TOOL_PREFIX + "resources",
     "description": "Loxone Miniserver debug monitor (LoxBerry plugin): History of the task monitor figures as CSV "
                    "rows (one per Miniserver and interval, usually 5 minutes): CPU average and peak, heap, max heap, "
                    "temperature, threads, uptime, network counters. Needs the recording with CSV switched on.",
     "inputSchema": {"type": "object", "properties": {
         **TIME_PROPS, **IP_PROP,
         "limit": {"type": "integer", "description": "Max rows, 1-2000. Default 500 (the newest)."}}}},
    {"name": TOOL_PREFIX + "live_tail",
     "description": "Loxone Miniserver debug monitor (LoxBerry plugin): The newest lines from the running receiver (live buffer in RAM, the last minutes).",
     "inputSchema": {"type": "object", "properties": {
         **IP_PROP, **TYPES_PROP,
         "text": {"type": "string"},
         "include_binary": {"type": "boolean"},
         "lines": {"type": "integer", "description": "Number of lines, 1-2000. Default 50."}}}},
]


class Tools:
    def __init__(self, store):
        self.s = store

    def call(self, name, args):
        if name not in {t["name"] for t in TOOLS}:
            raise KeyError(name)
        return getattr(self, "t_" + name[len(TOOL_PREFIX):])(args or {})

    def t_status(self, args):
        st = self.s.status() or {}
        files = self.s.files()
        out = []
        out.append(f"Receiver: {'running' if st.get('running') else 'stopped'}, UDP port {st.get('port', '?')}")
        for src in st.get("sources") or []:
            ago = time.time() - (src.get("last") or 0)
            out.append(f"  Miniserver {src['ip']}: {src.get('packets', 0)} packets since start, last {ago:.0f} s ago")
        rec = st.get("record")
        if rec:
            out.append(f"Recording to {rec.get('target')}, in RAM since "
                       f"{datetime.datetime.fromtimestamp(rec['since']):%Y-%m-%d %H:%M:%S}" if rec.get("since") else
                       f"Recording to {rec.get('target')}")
        else:
            out.append("Recording: off (only the live buffer of the last minutes is available)")
        if files:
            out.append(f"Recordings: {len(files)} files, "
                       f"{datetime.datetime.fromtimestamp(files[0][1]):%Y-%m-%d %H:%M} - "
                       f"{datetime.datetime.fromtimestamp(files[-1][2]):%Y-%m-%d %H:%M}")
        out.append(f"Now (LoxBerry clock): {datetime.datetime.now():%Y-%m-%d %H:%M:%S}")
        return "\n".join(out)

    def t_list_recordings(self, args):
        files = self.s.files()
        if not files:
            return "No recordings."
        rows = [f"{datetime.datetime.fromtimestamp(f[1]):%Y-%m-%d %H:%M:%S}  "
                f"{datetime.datetime.fromtimestamp(f[2]):%Y-%m-%d %H:%M:%S}  {human(f[3]):>9}  {f[4]}  "
                f"{os.path.basename(f[0])}" for f in files]
        return "start                end                       size  where  file\n" + "\n".join(rows)

    def _select(self, args, start, end):
        types = as_list(args.get("types"))
        binary = bool(args.get("include_binary")) or "binary" in types
        tf = text_filter(args)
        for e in self.s.entries(start, end, args.get("ip") or None):
            if e.binary and not binary:
                continue
            if matches_type(e, types) and tf(e):
                yield e

    def t_search(self, args):
        start, end = time_range(args)
        limit = limit_of(args, 200)
        keep_first = args.get("keep") == "first"
        n, rows = 0, collections.deque(maxlen=None if keep_first else limit)
        for e in self._select(args, start, end):
            n += 1
            if keep_first and len(rows) >= limit:
                continue
            rows.append(e.line())
        head = f"{n} lines in {fmt_range(start, end)}"
        if n > len(rows):
            head += f", showing the {'first' if keep_first else 'last'} {len(rows)}"
        return head + ("\n" + "\n".join(rows) if rows else "")

    def t_context(self, args):
        t = parse_time(args.get("time"), None)
        if t is None:
            raise ValueError("time is required")
        before = float(args.get("before", 10))
        after = float(args.get("after", 10))
        start, end = t - datetime.timedelta(seconds=before), t + datetime.timedelta(seconds=after)
        limit = limit_of(args, 500)
        rows = []
        for e in self._select(args, start, end):
            mark = ">" if abs((e.dt - t).total_seconds()) < 0.0005 else " "
            rows.append(mark + e.line())
            if len(rows) >= limit:
                break
        return f"{len(rows)} lines in {fmt_range(start, end)}\n" + "\n".join(rows)

    def t_http_requests(self, args):
        start, end = time_range(args)
        limit = limit_of(args, 200)
        client = args.get("client") or ""
        path = (args.get("path") or "").lower()
        status = (args.get("status") or "").lower()
        sel = []
        for s in http_sessions(self.s.entries(start, end, args.get("ip") or None)):
            if client and client not in s["client"]:
                continue
            if path and path not in s["request"].lower():
                continue
            if status == "error" and not s["status"]:
                continue
            if status and status != "error" and not s["status"].startswith(status):
                continue
            sel.append(s)
        if args.get("group"):
            c = collections.Counter()
            for s in sel:
                c[(s["ms"], s["client"] or "?", s["port"] or "?", s["ua"] or "?",
                   strip_value(s["request"]), s["status"] or "-")] += 1
            rows = [f"{n:6d}  {ms:<15} {cl:<15} {po:>3}  {st:<16} {ua[:30]:<30} {rq}"
                    for (ms, cl, po, ua, rq, st), n in c.most_common(limit)]
            return (f"{len(sel)} requests in {fmt_range(start, end)}, {len(c)} groups\n"
                    "count   miniserver      client          port status           user agent                     request\n"
                    + "\n".join(rows))
        rows = [f"{s['time']:%Y-%m-%d %H:%M:%S}.{s['time'].microsecond // 1000:03d} {s['ms']:<15} "
                f"{(s['client'] or '?'):<15} {(s['port'] or '?'):>3}  {(s['miniserver_status'] or '-'):<16} "
                f"{(s['ua'] or '?')[:30]:<30} {s['request']}" for s in sel[-limit:]]
        head = f"{len(sel)} requests in {fmt_range(start, end)}"
        if len(sel) > limit:
            head += f", showing the last {limit}"
        return (head + "\ntime                    miniserver      client          port status           "
                       "user agent                     request\n" + "\n".join(rows))

    def t_summary(self, args):
        start, end = time_range(args)
        per = collections.defaultdict(lambda: {"lines": 0, "binary": 0, "groups": collections.Counter(),
                                               "types": collections.Counter(), "errors": collections.Counter(),
                                               "swaps": 0, "seq": None, "first": None, "last": None})
        entries = []
        for e in self.s.entries(start, end, args.get("ip") or None):
            p = per[e.ip]
            p["lines"] += 1
            p["first"] = p["first"] or e.dt
            p["last"] = e.dt
            if e.binary:
                p["binary"] += 1
            else:
                p["groups"][group_of(e)] += 1
                m = TYPE_RE.match(e.text)
                p["types"][m.group(1) if m else "(none)"] += 1
                if ERR_RE.search(e.text):
                    p["errors"][re.sub(r"\d+", "#", e.text)[:120]] += 1
                entries.append(e)
            if e.data is not None and e.kind is not None and e.kind < 0xFF00:
                cur = int.from_bytes(e.data[8:10], "little")
                if p["seq"] is not None and ((cur - p["seq"]) % 65536) >= 32768:
                    p["swaps"] += 1
                p["seq"] = cur
        if not per:
            return f"No lines in {fmt_range(start, end)}."
        out = [f"Summary {fmt_range(start, end)}"]
        for ip, p in sorted(per.items()):
            out.append(f"\nMiniserver {ip}: {p['lines']} lines ({p['binary']} binary), "
                       f"{p['first']:%H:%M:%S} - {p['last']:%H:%M:%S}, swapped datagrams: {p['swaps']}")
            out.append("  groups: " + ", ".join(f"{g} {n}" for g, n in p["groups"].most_common()))
            out.append("  types:  " + ", ".join(f"{t} {n}" for t, n in p["types"].most_common(12)))
            if p["errors"]:
                out.append("  most frequent error lines (digits as #):")
                out += [f"    {n:5d}  {t}" for t, n in p["errors"].most_common(10)]
        c = collections.Counter()
        for s in http_sessions(entries):
            c[(s["ms"], s["client"] or "?", s["ua"] or "?", "error" if s["status"] else "ok")] += 1
        if c:
            out.append("\nHTTP callers (miniserver, client, user agent, ok/error):")
            out += [f"  {n:6d}  {ms:<15} {cl:<15} {st:<5} {ua[:40]}" for (ms, cl, ua, st), n in c.most_common(15)]
        return "\n".join(out)

    def t_taskmon(self, args):
        try:
            with open(os.path.join(self.s.a.rundir, "taskmon.json"), encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, ValueError):
            return "No task monitor data: the receiver is not running or no Miniserver sends its debug stream."
        try:
            top = int(args.get("threads", 15))
        except (TypeError, ValueError):
            top = 15
        ip = args.get("ip")
        out = []
        for msip, snap in sorted(data.items()):
            if ip and msip != ip:
                continue
            st = snap["stats"]
            up = st["time_ms"] // 1000
            out.append(f"Miniserver {msip}, {datetime.datetime.fromtimestamp(snap['time']):%Y-%m-%d %H:%M:%S}: "
                       f"CPU {snap['usage']} %, heap {st['heap'] // 1024} kB of max {st['heap_max'] // 1024} kB, "
                       f"temperature {str(st['temp']) + ' C' if st['temp'] else 'n/a'}, {st['threads']} threads, "
                       f"uptime {up // 86400} d {up % 86400 // 3600} h {up % 3600 // 60} min")
            out.append(f"  LAN: TxP {st['txp']}, RxP {st['rxp']}, TxE/c {st['txe']}/{st['txc']}, "
                       f"EOF/Ovrun {st['eof']}/{st['ovrun']}, NoBuf/Sof {st['nobuf']}/{st['sof']}, Frag {st['frag']}")
            out.append(f"  Link: Sent {st['sent']}, Rcv {st['rcv']}, Err/OvE {st['err']}/{st['ove']}, "
                       f"TEC/REC {st['tec']}/{st['rec']}, context switches {st['cosw'] or 'n/a'}")
            hist = [u for _t, u in snap.get("hist") or []]
            if hist:
                out.append(f"  CPU last {len(hist) // 2} s: average {sum(hist) / len(hist):.1f} %, peak {max(hist):.1f} %")
            gen2 = st.get("gen") == 2 or all(not t["stack"][1] for t in snap["threads"])
            ths = sorted(snap["threads"], key=lambda t: -t["cpu"])
            if top:
                ths = ths[:top]
            out.append("  thread        cpu%   time        stack          ctx  state")
            for t in ths:
                name = rx.thread_name(t["id"])
                tm = "endless" if t["time"] is None else t["time"]
                stack = f"{t['stack'][0]}/{t['stack'][1]}" if t["stack"][1] else "n/a"
                out.append(f"  {name:<12} {t['cpu']:6.2f} {str(tm):>8} {stack:>12} {t['ctx']:>12}  "
                           f"{rx.thread_state(t, gen2)}")
        return "\n".join(out) if out else f"No task monitor data for {ip}."

    def t_resources(self, args):
        start, end = time_range(args, default_minutes=24 * 60)
        limit = limit_of(args, 500)
        ip = args.get("ip")
        files = glob.glob(os.path.join(self.s.recdir(), "taskmon_*.csv")) + \
            glob.glob(os.path.join(self.s.a.rundir, rx.CSV_PENDING + "taskmon_*.csv"))
        rows = []
        for fn in files:
            try:
                with open(fn, encoding="utf-8") as f:
                    for line in f:
                        if line.startswith("time,"):
                            continue
                        parts = line.rstrip("\n").split(",")
                        if len(parts) < 3 or (ip and parts[1] != ip):
                            continue
                        try:
                            t = datetime.datetime.strptime(parts[0], "%Y-%m-%d %H:%M:%S")
                        except ValueError:
                            continue
                        if start <= t <= end:
                            rows.append((t, line.rstrip("\n")))
            except OSError:
                continue
        rows.sort()
        if not rows:
            return f"No CSV rows in {fmt_range(start, end)} (CSV off, recording off, or not written yet)."
        head = f"{len(rows)} rows in {fmt_range(start, end)}"
        if len(rows) > limit:
            head += f", showing the newest {limit}"
        return head + "\n" + rx.TM_CSV_HEADER.rstrip("\n") + "\n" + "\n".join(r for _t, r in rows[-limit:])

    def t_live_tail(self, args):
        try:
            n = max(1, min(MAX_LIMIT, int(args.get("lines", 50))))
        except (TypeError, ValueError):
            n = 50
        types = as_list(args.get("types"))
        binary = bool(args.get("include_binary")) or "binary" in types
        tf = text_filter(args)
        rows = [e.line() for e in self.s.live(args.get("ip") or None)
                if (binary or not e.binary) and matches_type(e, types) and tf(e)]
        return f"{min(n, len(rows))} of {len(rows)} lines in the live buffer\n" + "\n".join(rows[-n:])


##########################################################################
# JSON-RPC / MCP
##########################################################################

class Mcp:
    def __init__(self, tools, log, version):
        self.tools, self.log, self.version = tools, log, version

    def handle(self, msg, who="stdio"):
        """One JSON-RPC message -> response dict, or None for a notification."""
        if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0":
            return self._error(None, -32600, "invalid request")
        mid, method, params = msg.get("id"), msg.get("method"), msg.get("params") or {}
        if mid is None:
            return None            # notification (initialized, cancelled, ...)
        try:
            if method == "initialize":
                want = params.get("protocolVersion")
                return self._result(mid, {
                    "protocolVersion": want if want in PROTOCOLS else PROTOCOLS[0],
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {"name": SERVER_NAME, "version": self.version},
                    "instructions": INSTRUCTIONS})
            if method == "ping":
                return self._result(mid, {})
            if method == "tools/list":
                return self._result(mid, {"tools": TOOLS})
            if method == "tools/call":
                name, args = params.get("name"), params.get("arguments") or {}
                t0 = time.time()
                try:
                    text = self.tools.call(name, args)
                    err = False
                except KeyError:
                    return self._error(mid, -32602, f"unknown tool: {name}")
                except ValueError as e:
                    text, err = f"Error: {e}", True
                except Exception as e:  # noqa: BLE001 - reported to the client, logged here
                    text, err = f"Error: {e!r}", True
                    self.log.err(f"Tool {name} failed: {e!r}")
                self.log.inf(f"{who}: {name} {json.dumps(args, ensure_ascii=False)[:300]} "
                             f"-> {len(text)} chars in {time.time() - t0:.2f} s")
                return self._result(mid, {"content": [{"type": "text", "text": text}], "isError": err})
            return self._error(mid, -32601, f"method not found: {method}")
        except Exception as e:  # noqa: BLE001
            return self._error(mid, -32603, repr(e))

    @staticmethod
    def _result(mid, result):
        return {"jsonrpc": "2.0", "id": mid, "result": result}

    @staticmethod
    def _error(mid, code, message):
        return {"jsonrpc": "2.0", "id": mid, "error": {"code": code, "message": message}}


def make_handler(mcp, token):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "DebugMonitorMCP"

        def _send(self, code, body=b"", ctype="application/json", extra=None):
            self.send_response(code)
            if body:
                self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            if body:
                self.wfile.write(body)

        def _authorised(self):
            got = self.headers.get("Authorization", "")
            return bool(token) and hmac.compare_digest(got.encode(), f"Bearer {token}".encode())

        def _origin_ok(self):
            # Browsers send Origin; a page from elsewhere must not drive the server
            # (DNS rebinding). MCP clients outside a browser send none.
            origin = self.headers.get("Origin")
            if not origin:
                return True
            host = (self.headers.get("Host") or "").split(":")[0]
            return re.sub(r"^https?://", "", origin).split(":")[0] in (host, "localhost", "127.0.0.1")

        def do_GET(self):
            if self.path.split("?")[0] == "/mcp":
                # No server-initiated stream: every answer comes with the POST
                self._send(405, extra={"Allow": "POST"})
            else:
                self._send(200, b"Debug Monitor MCP server - endpoint /mcp\n", "text/plain; charset=utf-8")

        def do_DELETE(self):
            self._send(405, extra={"Allow": "POST"})

        def do_POST(self):
            if self.path.split("?")[0] != "/mcp":
                return self._send(404)
            if not self._origin_ok():
                return self._send(403)
            if not self._authorised():
                mcp.log.warn(f"Request without valid token from {self.client_address[0]}")
                return self._send(401, b'{"error":"unauthorized"}', extra={"WWW-Authenticate": "Bearer"})
            try:
                length = int(self.headers.get("Content-Length") or 0)
                msg = json.loads(self.rfile.read(length) or b"null")
            except (ValueError, OSError):
                return self._send(400, json.dumps(Mcp._error(None, -32700, "parse error")).encode())
            who = self.client_address[0]
            if isinstance(msg, list):
                res = [r for r in (mcp.handle(m, who) for m in msg) if r is not None]
                if not res:
                    return self._send(202)
                return self._send(200, json.dumps(res, ensure_ascii=False).encode())
            res = mcp.handle(msg, who)
            if res is None:
                return self._send(202)
            self._send(200, json.dumps(res, ensure_ascii=False).encode())

        def log_message(self, fmt, *args):
            pass

    return Handler


def run_stdio(mcp):
    for raw in sys.stdin:
        raw = raw.strip()
        if not raw:
            continue
        try:
            msg = json.loads(raw)
        except ValueError:
            res = Mcp._error(None, -32700, "parse error")
        else:
            res = mcp.handle(msg) if not isinstance(msg, list) else \
                [r for r in (mcp.handle(m) for m in msg) if r is not None] or None
        if res is not None:
            sys.stdout.write(json.dumps(res, ensure_ascii=False) + "\n")
            sys.stdout.flush()
    return 0


def main():
    p = argparse.ArgumentParser(description="Debug Monitor MCP server")
    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument("--http", action="store_true")
    mode.add_argument("--stdio", action="store_true")
    p.add_argument("--port", type=int, default=7780)
    p.add_argument("--config", required=True)
    p.add_argument("--rundir", required=True)
    p.add_argument("--recdir", required=True)
    p.add_argument("--pidfile", default="")
    p.add_argument("--version", default="")
    p.add_argument("--logfile", default="")
    p.add_argument("--logdbkey", default="")
    p.add_argument("--loglevel", type=int, default=6)
    a = p.parse_args()

    log = rx.Log(a.logfile, a.loglevel)
    mcp = Mcp(Tools(Store(a)), log, a.version)
    if a.stdio:
        return run_stdio(mcp)

    token = ((read_config(a.config).get("mcp") or {}).get("token") or "").strip()
    if not token:
        log.err("No access token configured - not started")
        rx.logend(a.logdbkey, "MCP server not started.", log.status)
        return 2
    try:
        httpd = ThreadingHTTPServer(("0.0.0.0", a.port), make_handler(mcp, token))
    except OSError as e:
        log.err(f"Cannot listen on TCP port {a.port}: {e}")
        rx.logend(a.logdbkey, "MCP server not started.", log.status)
        return 2
    httpd.daemon_threads = True
    if a.pidfile:
        with open(a.pidfile, "w") as f:
            f.write(str(os.getpid()))
    log.ok(f"MCP server listening on TCP port {a.port}, endpoint /mcp")

    def on_term(signum, frame):
        threading.Thread(target=httpd.shutdown, daemon=True).start()
    signal.signal(signal.SIGTERM, on_term)
    signal.signal(signal.SIGINT, on_term)
    try:
        httpd.serve_forever(poll_interval=0.5)
    finally:
        httpd.server_close()
        if a.pidfile:
            try:
                os.unlink(a.pidfile)
            except OSError:
                pass
        log.ok("MCP server stopped")
        rx.logend(a.logdbkey, "MCP server stopped.", log.status)
    return 0


if __name__ == "__main__":
    sys.exit(main())
