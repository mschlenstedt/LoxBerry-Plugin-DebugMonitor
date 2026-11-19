#!/usr/bin/env python3
"""Debug Monitor receiver.

Receives the debug stream of a Loxone Miniserver: UDP, one message per
datagram, switched on in Loxone Config (Diagnose -> Monitor, "Benutzerdefiniert"
with this LoxBerry as target). The receiver

  * keeps the latest decoded lines for the web interface in a file in RAM
    (tmpfs, live.jsonl, rotated at LIVE_ROTATE bytes),
  * records every datagram unchanged and compressed in RAM and moves the file
    to the chosen storage in ONE write per interval - the SD card never sees
    a write per packet,
  * optionally forwards every datagram unchanged to a second receiver
    (e.g. the Loxone Monitor on a PC).

The receive loop never waits for a disk or a network share: moving a finished
recording runs in its own thread.

Raw record format (same as the development tools): per datagram 8 byte receive
time (big-endian double, Unix seconds), 4 byte length (big-endian), payload.

Started by DebugMonitor.pm (web interface and boot). All paths come in as
arguments, the LoxBerry Python library is not needed.
"""

import argparse
import collections
import datetime
import gzip
import json
import os
import signal
import socket
import struct
import subprocess
import sys
import threading
import time

LOX_EPOCH = datetime.datetime(2009, 1, 1)
RAW_REC = struct.Struct(">dI")
HEADER_LEN = 29
LIVE_ROTATE = 2 * 1024 * 1024      # live.jsonl -> live.1.jsonl
LIVE_EVERY = 0.4                    # seconds between live writes
STATUS_EVERY = 2.0                  # seconds between status writes
TMP_MAX_BYTES = 64 * 1024 * 1024    # compressed recording in RAM, then move early
MAX_PENDING = 3                     # finished recordings waiting in RAM for the storage
REC_PREFIX = "dm_"
REC_SUFFIX = ".raw.gz"
TM_EVERY = 1.0                      # seconds between taskmon.json writes
TM_HISTORY = 600                    # CPU samples kept for the graph (5 min at 2/s)
CSV_PENDING = "csvpending_"         # CSV rows waiting in RAM for the storage
TM_CSV_HEADER = ("time,miniserver,cpu_avg_pct,cpu_max_pct,heap_kb,heap_max_kb,temp_c,threads,"
                 "uptime_s,txp,rxp,nobuf,sent,rcv,link_err,tec,cosw,csint\n")

# Thread names of the task monitor: the stream carries only an ID, the Loxone
# Monitor names them from a fixed table (same IDs on Gen 1 and Gen 2). Also in
# templates/taskmon.html.
THREAD_NAMES = {
    0x0200: "Idle", 0x0201: "Main", 0x0202: "ETH", 0x0203: "TCP", 0x0204: "NTP", 0x0205: "DHCP",
    0x0206: "DebugSend", 0x0208: "Lnk", 0x0209: "Watchdog", 0x020A: "Netbios", 0x020C: "SSDP",
    0x020D: "PRG", 0x020E: "MQ", 0x0210: "EIB", 0x0211: "CAN", 0x0212: "IO", 0x0213: "SMTP",
    0x0214: "HTC", 0x0215: "EIBrcv", 0x0216: "LoxCfg", 0x0217: "Stats", 0x0218: "EibIP",
    0x0219: "PrgEx", 0x021A: "AQ", 0x021B: "mDNS", 0x021F: "TICK", 0x028D: "Ping", 0x0290: "Sys",
    0x0291: "LnkTx", 0x0292: "VUdp", 0x0293: "Listen", 0x029F: "DevDisc", 0x02A0: "DNS",
    0x02A1: "Update", 0x0353: "LxPair", 0x021E: "IPC", 0x0220: "SIA", 0x0207: "SR",
}
# Threads that exist several times: base ID plus instance number (HTTP35 =
# 0x0230 + 35, VO22 = 0x2710 + 22), seen on Gen 1 and Gen 2
THREAD_SERIES = ((0x0230, 64, "HTTP"), (0x2710, 500, "VO"), (0x2904, 500, "VI"), (0x02A8, 16, "Modbus"),
                 (0x02EE, 8, "ExecutableComm"), (0x0302, 8, "Media"))


def thread_name(tid):
    if tid in THREAD_NAMES:
        return THREAD_NAMES[tid]
    for base, count, name in THREAD_SERIES:
        if base <= tid < base + count:
            return f"{name}{tid - base}"
    return f"0x{tid:04x}"

def thread_state(t, gen2):
    """State text of a thread as the Loxone Monitor shows it. Gen 1: 0 Running,
    2 Wait, 4 Ready, plus what it waits for (0x0267 Listen<port>, 0x0266
    RcvEv<n>, other objects "Wr <n>"). Gen 2: low nibble the state, high
    nibble after a slash ("Sleep/3")."""
    if gen2:
        lo, hi = t["state"] & 15, t["state"] >> 4
        return {0: "Ready", 1: "Running", 2: "Sleep", 4: "Sleep"}.get(lo, f"State {lo}") + f"/{hi}"
    s = {0: "Running", 2: "Wait", 4: "Ready"}.get(t["state"], f"State {t['state']}")
    if t["obj"]:
        s += (f" Listen{t['port']}" if t["obj"] == 0x0267 else
              f" RcvEv{t['port']}" if t["obj"] == 0x0266 else f" Wr {t['port']}")
    return s


# Statistics record of the task monitor (kind ffff), 32 bit values from byte 28 on
TM_STATS = (("cosw", 4), ("csint", 8), ("heap_max", 12), ("heap", 16), ("idle", 20), ("total", 24),
            ("wdog", 28), ("time_ms", 36), ("ticks", 40), ("lnk", 44), ("emac", 48),
            ("txp", 52), ("txe", 56), ("txc", 60), ("exhau", 64), ("urun", 68), ("rxp", 72),
            ("eof", 76), ("ovrun", 80), ("nobuf", 84), ("sof", 88), ("frag", 92),
            ("sent", 96), ("rcv", 100), ("err", 104), ("ove", 108), ("tec", 112), ("rec", 116),
            ("threads", 120), ("temp", 124), ("gen", 128))

SEVERITY = {0: "EMERGE", 1: "ALERT", 2: "CRITICAL", 3: "ERROR", 4: "WARNING", 5: "OK", 6: "INFO", 7: "DEBUG"}


class Log:
    """Writes into the log session that DebugMonitor.pm opened (same line format
    as LoxBerry::Log with addtime). Severity < 0 is always written."""

    def __init__(self, filename, level):
        self.filename = filename
        self.level = level
        self.lock = threading.Lock()
        # Worst severity of the session, handed to LOGEND - like LoxBerry::Log,
        # whose STATUS colours the session in the log list
        self.status = None

    def write(self, sev, msg):
        if sev >= 0 and (self.status is None or sev < self.status):
            self.status = sev
        if not self.filename or (sev >= 0 and sev > self.level):
            return
        now = datetime.datetime.now()
        tag = SEVERITY.get(sev, "INFO") if sev >= 0 else "INFO"
        line = f"{now:%H:%M:%S}.{now.microsecond // 1000:03d} <{tag}> {msg}\n"
        with self.lock:
            try:
                with open(self.filename, "a", encoding="utf-8") as f:
                    f.write(line)
            except OSError:
                pass

    def err(self, m): self.write(3, m)
    def warn(self, m): self.write(4, m)
    def ok(self, m): self.write(5, m)
    def inf(self, m): self.write(6, m)
    def deb(self, m): self.write(7, m)


def write_atomic(path, text):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(text)
    os.replace(tmp, path)


def decode(data, recv_ts):
    """Decodes one datagram into what the web interface shows.

    29 byte header, little-endian: 0-1 1f fa, 2-3 length without the first two
    bytes, 6-7 kind of record, 8-9 sequence, 10-11 milliseconds, 12-15 seconds
    since 2009-01-01 (local time of the Miniserver), 16-19 IP of the Miniserver.
    Kind 0 = text message: byte 28 is 01, the text follows from byte 29,
    null-terminated, ending with 1f 1f. Every other kind is binary (e.g. ffff to
    fffb, at level 3 also fffa = the parts of the task monitor) - its content starts at byte 28,
    which only by chance is 01 now and then; the Loxone Monitor does not show
    those as text either. Binary records are shown as hex.

    Returns (time, ip, text, kind); kind is None for foreign datagrams."""
    if len(data) >= HEADER_LEN and data[0] == 0x1F and data[1] == 0xFA:
        ms = int.from_bytes(data[10:12], "little")
        secs = int.from_bytes(data[12:16], "little")
        ip = ".".join(str(b) for b in data[16:20])
        kind = int.from_bytes(data[6:8], "little")
        if ms < 1000:
            t = LOX_EPOCH + datetime.timedelta(seconds=secs, milliseconds=ms)
        else:
            t = datetime.datetime.fromtimestamp(recv_ts)
        if kind == 0:
            body = data[HEADER_LEN:]
            text = body.split(b"\0", 1)[0].decode("utf-8", "replace").rstrip("\r\n")
        else:
            body = data[HEADER_LEN - 1:]
            if body.endswith(b"\x1f\x1f"):
                body = body[:-2]
            text = f"[{kind:04x}, {len(body)} B] " + body[:64].hex(" ") + (" …" if len(body) > 64 else "")
        return t, ip, text, kind
    t = datetime.datetime.fromtimestamp(recv_ts)
    return t, None, "[raw " + str(len(data)) + " B] " + data[:96].hex(" "), None


class TaskMon:
    """Task monitor of every Miniserver, as the Loxone Monitor shows it.

    Every 0.5 s a Miniserver sends one statistics record (kind ffff) and the
    thread list in 40 byte records, spread over kinds fffd, fffc, fffb ...
    (fffe repeats part of it and is skipped). A cycle is complete when as many
    records arrived as the statistics announce (@120). The newest cycle of each
    Miniserver goes to taskmon.json in RAM for the web interface; with the
    recording on, one CSV row per Miniserver and interval is collected in RAM
    and saved together with the recording."""

    def __init__(self, rundir, csv_min, log):
        self.rundir = rundir
        self.path = os.path.join(rundir, "taskmon.json")
        self.csv_sec = csv_min * 60 if csv_min else 0
        self.log = log
        self.ms = {}
        self.next_write = 0.0
        self.next_csv = (time.time() // self.csv_sec + 1) * self.csv_sec if self.csv_sec else 0

    def feed(self, ip, kind, data, now):
        if not ip or len(data) < 32:
            return
        m = self.ms.get(ip)
        if m is None:
            m = self.ms[ip] = {"cur": None, "snap": None, "hist": collections.deque(maxlen=TM_HISTORY),
                               "acc": [0.0, 0, 0.0]}
        p = data[28:]
        if kind == 0xFFFF:
            if len(p) < 132:
                return
            st = {k: struct.unpack_from("<I", p, o)[0] for k, o in TM_STATS}
            m["cur"] = {"t": now, "stats": st, "parts": {}}
        elif 0xFF00 <= kind <= 0xFFFD and m["cur"] is not None:
            cur = m["cur"]
            cur["parts"][kind] = p
            recs = sum(len(x) // 40 for x in cur["parts"].values())
            if recs >= cur["stats"]["threads"] > 0:
                self._finish(ip, m, cur)
                m["cur"] = None

    def _finish(self, ip, m, cur):
        st = cur["stats"]
        total = st["total"] or 0
        usage = round(100.0 * (1 - st["idle"] / total), 2) if total else None
        # Each part ends with the 1f 1f trailer: only whole 40 byte records count
        raw = b"".join(cur["parts"][k][:len(cur["parts"][k]) // 40 * 40]
                       for k in sorted(cur["parts"], reverse=True))
        threads = []
        for i in range(min(st["threads"], len(raw) // 40)):
            r = raw[i * 40:(i + 1) * 40]
            ctx, ss, su, _ptr, tm = struct.unpack_from("<IHHII", r, 0)
            tid, x22, obj, port, cpu, mem, nmem = struct.unpack_from("<HHHHIII", r, 20)
            threads.append({"id": tid, "cpu": round(100.0 * cpu / total, 2) if total else 0,
                            "time": None if tm == 0xFFFFFFFF else tm, "stack": [su * 4, ss * 4],
                            "ctx": ctx, "state": r[16], "prio": r[17], "obj": obj, "port": port,
                            "mem": mem, "nmem": nmem})
        m["snap"] = {"time": cur["t"], "usage": usage, "stats": st, "threads": threads}
        if usage is not None:
            m["hist"].append((round(cur["t"], 1), usage))
            acc = m["acc"]
            acc[0] += usage
            acc[1] += 1
            acc[2] = max(acc[2], usage)

    def tick(self, now, csv_on):
        if now >= self.next_write and self.ms:
            self.next_write = now + TM_EVERY
            out = {ip: {**m["snap"], "hist": list(m["hist"])} for ip, m in self.ms.items() if m["snap"]}
            try:
                write_atomic(self.path, json.dumps(out, separators=(",", ":")))
            except OSError:
                pass
        if self.csv_sec and now >= self.next_csv:
            self.next_csv = (now // self.csv_sec + 1) * self.csv_sec
            if csv_on:
                self.csv_rows(now)
            for m in self.ms.values():
                m["acc"] = [0.0, 0, 0.0]

    def csv_rows(self, now):
        """One row per Miniserver for the interval that just ended."""
        stamp = datetime.datetime.fromtimestamp(now).strftime("%Y-%m-%d %H:%M:%S")
        month = datetime.datetime.fromtimestamp(now).strftime("%Y-%m")
        for ip, m in self.ms.items():
            snap, acc = m["snap"], m["acc"]
            if not snap or not acc[1]:
                continue
            st = snap["stats"]
            row = [stamp, ip, f"{acc[0] / acc[1]:.2f}", f"{acc[2]:.2f}", st["heap"] // 1024,
                   st["heap_max"] // 1024, st["temp"] or "", st["threads"], st["time_ms"] // 1000,
                   st["txp"], st["rxp"], st["nobuf"], st["sent"], st["rcv"], st["err"], st["tec"],
                   st["cosw"], st["csint"]]
            name = f"{CSV_PENDING}taskmon_{ip}_{month}.csv"
            try:
                with open(os.path.join(self.rundir, name), "a", encoding="utf-8") as f:
                    f.write(",".join(str(x) for x in row) + "\n")
            except OSError as e:
                self.log.err(f"Task monitor CSV row lost: {e}")

    def clear(self):
        try:
            os.unlink(self.path)
        except OSError:
            pass


class Recorder:
    """Compressed recording in RAM, moved to the storage once per interval."""

    def __init__(self, rundir, target, flush_sec, keep_mb, keep_days, log):
        self.rundir = rundir
        self.target = target
        self.flush_sec = flush_sec
        self.keep_bytes = keep_mb * 1024 * 1024
        self.keep_sec = keep_days * 86400
        self.log = log
        self.gz = None
        self.cur = os.path.join(rundir, "rec_current" + REC_SUFFIX)
        self.packets = 0
        self.started = 0.0
        self.name = ""
        self.mover = None
        self.last_move = None       # {"file", "time", "ok", "error"}
        self.moved_files = 0
        self.lock = threading.Lock()

    def _open(self):
        # A leftover from a crash is kept as a pending file, not overwritten -
        # unless nothing of it reached the file (the gzip stream buffers)
        if os.path.exists(self.cur):
            if os.path.getsize(self.cur) == 0:
                os.unlink(self.cur)
            else:
                os.replace(self.cur, os.path.join(self.rundir, "pending_" + time.strftime("%Y%m%d_%H%M%S") + "_crash" + REC_SUFFIX))
        self.packets = 0
        self.started = time.time()
        self.name = REC_PREFIX + time.strftime("%Y%m%d_%H%M%S", time.localtime(self.started)) + REC_SUFFIX
        # The name stored inside the gzip header is what unpackers use for the
        # extracted file, so it carries the final name, not the RAM file name
        self.fh = open(self.cur, "wb")
        self.gz = gzip.GzipFile(filename=self.name[:-3], mode="wb", compresslevel=6, fileobj=self.fh)

    def write(self, ts, data):
        if self.gz is None:
            self._open()
        self.gz.write(RAW_REC.pack(ts, len(data)))
        self.gz.write(data)
        self.packets += 1

    def ram_bytes(self):
        try:
            return os.path.getsize(self.cur)
        except OSError:
            return 0

    def due(self, now):
        if self.gz is None:
            return False
        return now - self.started >= self.flush_sec or self.ram_bytes() >= TMP_MAX_BYTES

    def rotate(self, final=False):
        """Closes the current file and hands it to the mover. With final=True the
        move runs synchronously (shutdown)."""
        if self.gz is not None:
            self.gz.close()
            self.fh.close()
            self.gz = None
            if self.packets:
                os.replace(self.cur, os.path.join(self.rundir, "pending_" + self.name))
            else:
                os.unlink(self.cur)
        if final:
            if self.mover and self.mover.is_alive():
                self.mover.join(60)
            self._move_all()
        elif not (self.mover and self.mover.is_alive()):
            self.mover = threading.Thread(target=self._move_all, daemon=True)
            self.mover.start()

    def pending(self):
        return sorted(f for f in os.listdir(self.rundir) if f.startswith("pending_") and f.endswith(REC_SUFFIX))

    def _move_all(self):
        with self.lock:
            for f in self.pending():
                src = os.path.join(self.rundir, f)
                name = f[len("pending_"):]
                if not name.startswith(REC_PREFIX):
                    name = REC_PREFIX + name
                dst = os.path.join(self.target, name)
                try:
                    os.makedirs(self.target, exist_ok=True)
                    part = dst + ".part"
                    with open(src, "rb") as i, open(part, "wb") as o:
                        while True:
                            b = i.read(1024 * 1024)
                            if not b:
                                break
                            o.write(b)
                        o.flush()
                        os.fsync(o.fileno())
                    os.replace(part, dst)
                    os.unlink(src)
                    self.moved_files += 1
                    self.last_move = {"file": name, "time": time.time(), "ok": 1, "error": ""}
                    self.log.ok(f"Recording saved: {dst} ({os.path.getsize(dst)} bytes)")
                except OSError as e:
                    self.last_move = {"file": name, "time": time.time(), "ok": 0, "error": str(e)}
                    self.log.err(f"Recording could not be saved to {self.target}: {e}")
                    break
            self._move_csv()
            # The storage is gone (share offline, stick pulled): do not fill the RAM
            left = self.pending()
            while len(left) > MAX_PENDING:
                drop = left.pop(0)
                os.unlink(os.path.join(self.rundir, drop))
                self.log.err(f"Storage not reachable, recording dropped from RAM: {drop}")
            self._prune()

    def _move_csv(self):
        """Task monitor CSV rows collected in RAM: appended to one file per
        Miniserver and month on the storage, in the same write as the recording."""
        for f in sorted(os.listdir(self.rundir)):
            if not (f.startswith(CSV_PENDING) and f.endswith(".csv")):
                continue
            src = os.path.join(self.rundir, f)
            dst = os.path.join(self.target, f[len(CSV_PENDING):])
            try:
                with open(src, encoding="utf-8") as i:
                    rows = i.read()
                os.makedirs(self.target, exist_ok=True)
                new = not os.path.exists(dst)
                with open(dst, "a", encoding="utf-8") as o:
                    o.write((TM_CSV_HEADER if new else "") + rows)
                    o.flush()
                    os.fsync(o.fileno())
                os.unlink(src)
            except OSError as e:
                self.log.err(f"Task monitor CSV could not be saved to {self.target}: {e}")
                return

    def _prune(self):
        try:
            files = sorted(f for f in os.listdir(self.target) if f.startswith(REC_PREFIX) and f.endswith(REC_SUFFIX))
        except OSError:
            return
        info = []
        for f in files:
            try:
                st = os.stat(os.path.join(self.target, f))
                info.append((f, st.st_size, st.st_mtime))
            except OSError:
                pass
        total = sum(s for _, s, _ in info)
        now = time.time()
        # The newest recording is always kept, even if it alone exceeds the limit
        for f, size, mtime in info[:-1]:
            too_old = self.keep_sec and now - mtime > self.keep_sec
            too_big = self.keep_bytes and total > self.keep_bytes
            if not (too_old or too_big):
                break
            try:
                os.unlink(os.path.join(self.target, f))
                total -= size
                self.log.inf(f"Old recording deleted: {f}")
            except OSError as e:
                self.log.warn(f"Could not delete {f}: {e}")


class Receiver:
    def __init__(self, a):
        self.a = a
        self.log = Log(a.logfile, a.loglevel)
        self.cfg = self._config()
        self.stop = False
        self.seq = 0
        self.packets = 0
        self.bytes = 0
        self.last_packet = None
        self.sources = {}
        # Per Miniserver: message counter state (bytes 8-9) and swaps seen
        self.msg_seq = {}
        self.missing = {}
        self.started = time.time()
        self.live_buf = []
        self.live_path = os.path.join(a.rundir, "live.jsonl")
        self.live_old = os.path.join(a.rundir, "live.1.jsonl")
        self.status_path = os.path.join(a.rundir, "status.json")
        self.fwd = None
        self.fwd_packets = 0
        self.fwd_errors = 0
        self.fwd_error = ""
        self.error = ""
        rec = self.cfg["record"]
        self.tm = TaskMon(a.rundir, rec["csv_min"], self.log)
        self.tm.clear()
        self.rec = None
        if rec["enabled"]:
            target = rec["path"] or a.recdir
            self.rec = Recorder(a.rundir, target, rec["flush_min"] * 60, rec["keep_mb"], rec["keep_days"], self.log)

    def _config(self):
        with open(self.a.config, encoding="utf-8") as f:
            c = json.load(f)
        r = c.get("record") or {}
        w = c.get("forward") or {}
        return {
            "port": int(c.get("port") or 7777),
            "record": {
                "enabled": int(r.get("enabled", 1) or 0),
                "path": str(r.get("path") or ""),
                "flush_min": max(1, int(r.get("flush_min") or 60)),
                "keep_mb": max(0, int(r.get("keep_mb") or 0)),
                "keep_days": max(0, int(r.get("keep_days") or 0)),
                "csv": int(r.get("csv", 1) or 0),
                "csv_min": max(1, int(r.get("csv_min") or 5)),
            },
            "forward": {
                "enabled": int(w.get("enabled", 0) or 0),
                "host": str(w.get("host") or ""),
                "port": int(w.get("port") or 7777),
            },
        }

    # --- Live view and status -----------------------------------------------

    def _check_seq(self, data, kind, ip, now):
        """Out-of-order datagrams, reported like the Loxone Monitor does:
        "SEQ_ERROR <n> lines missing <received>/<previous>". All messages share
        one counter (bytes 8-9), only the task monitor (kinds from ff00 on:
        ffff-fffb, at level 3 also fffa) counts on its own. Plain gaps are not
        reported: a Miniserver skips counter values on purpose (on one
        Miniserver almost a third), and the Loxone Monitor, fed with the very same
        datagrams, does not report them either. A swap shows as three lines
        around it (1, -2, 1), as in the Loxone Monitor."""
        if kind is None or kind >= 0xFF00 or not ip:
            return
        cur = int.from_bytes(data[8:10], "little")
        st = self.msg_seq.get(ip)
        self.msg_seq[ip] = {"prev": cur, "before": st["prev"] if st else None, "after": False}
        if st is None:
            return
        prev, before = st["prev"], st["before"]
        gap = self._gap(prev, cur)
        if gap < 0:
            # The datagram before the swapped one jumped ahead
            if before is not None and self._gap(before, prev) != 0:
                self._seq_line(ip, now, self._gap(before, prev), prev, before)
            self._seq_line(ip, now, gap, cur, prev)
            self.missing[ip] = self.missing.get(ip, 0) + 1
            self.msg_seq[ip]["after"] = True
        elif st["after"] and gap != 0:
            self._seq_line(ip, now, gap, cur, prev)

    @staticmethod
    def _gap(prev, cur):
        g = (cur - prev - 1) % 65536
        return g - 65536 if g >= 32768 else g

    def _seq_line(self, ip, now, gap, cur, prev):
        self.seq += 1
        self.live_buf.append(json.dumps({
            "s": self.seq,
            "d": datetime.datetime.fromtimestamp(now).strftime("%Y-%m-%d"),
            "t": "",
            "ip": ip,
            "k": -1,
            "b": 0,
            "m": f"SEQ_ERROR {gap} lines missing {cur}/{prev}",
        }, ensure_ascii=False) + "\n")

    def _flush_live(self):
        if not self.live_buf:
            return
        lines, self.live_buf = self.live_buf, []
        with open(self.live_path, "a", encoding="utf-8") as f:
            f.write("".join(lines))
        if os.path.getsize(self.live_path) > LIVE_ROTATE:
            os.replace(self.live_path, self.live_old)
            # Create the new file right away: a reader must never find none
            open(self.live_path, "a", encoding="utf-8").close()

    def _write_status(self, running=True):
        rec = None
        if self.rec:
            rec = {
                "target": self.rec.target,
                "ram_bytes": self.rec.ram_bytes(),
                "ram_packets": self.rec.packets if self.rec.gz else 0,
                "since": self.rec.started or None,
                "next_move": (self.rec.started + self.rec.flush_sec) if self.rec.gz else None,
                "pending": len(self.rec.pending()),
                "moved": self.rec.moved_files,
                "last_move": self.rec.last_move,
            }
        st = {
            "running": 1 if running else 0,
            "pid": os.getpid(),
            "port": self.cfg["port"],
            "started": self.started,
            "updated": time.time(),
            "packets": self.packets,
            "bytes": self.bytes,
            "last_packet": self.last_packet,
            "sources": [{"ip": ip, "packets": v[0], "last": v[1], "swapped": self.missing.get(ip, 0)}
                        for ip, v in sorted(self.sources.items())],
            "record": rec,
            "forward": {
                "enabled": 1 if self.fwd else 0,
                "target": f"{self.cfg['forward']['host']}:{self.cfg['forward']['port']}" if self.cfg["forward"]["enabled"] else "",
                "packets": self.fwd_packets,
                "errors": self.fwd_errors,
                "error": self.fwd_error,
            },
            "error": self.error,
        }
        try:
            write_atomic(self.status_path, json.dumps(st))
        except OSError:
            pass

    # --- Forwarding ----------------------------------------------------------

    def _setup_forward(self):
        f = self.cfg["forward"]
        if not f["enabled"] or not f["host"]:
            return
        try:
            info = socket.getaddrinfo(f["host"], f["port"], socket.AF_INET, socket.SOCK_DGRAM)
            addr = info[0][4]
        except OSError as e:
            self.fwd_error = f"cannot resolve {f['host']}: {e}"
            self.log.err("Forwarding off: " + self.fwd_error)
            return
        self.fwd_addr = addr
        self.fwd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.log.inf(f"Forwarding every datagram to {addr[0]}:{addr[1]}")

    def _forward(self, data):
        try:
            self.fwd.sendto(data, self.fwd_addr)
            self.fwd_packets += 1
        except OSError as e:
            self.fwd_errors += 1
            if str(e) != self.fwd_error:
                self.fwd_error = str(e)
                self.log.warn("Forwarding failed: " + self.fwd_error)

    # --- Main loop -----------------------------------------------------------

    def run(self):
        os.makedirs(self.a.rundir, exist_ok=True)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
        except OSError:
            pass
        try:
            sock.bind(("0.0.0.0", self.cfg["port"]))
        except OSError as e:
            self.error = f"port {self.cfg['port']}: {e}"
            self.log.err("Cannot listen on UDP " + self.error)
            self._write_status(running=False)
            return 2
        sock.settimeout(0.2)
        with open(self.a.pidfile, "w") as f:
            f.write(str(os.getpid()))
        self._setup_forward()
        self.log.ok(f"Listening on UDP port {self.cfg['port']}")
        if self.rec:
            self.log.inf(f"Recording to {self.rec.target}, one write every {self.rec.flush_sec // 60} min")
            # Moves leftovers of an earlier run and applies the current size and
            # age limits right away, not only after the first interval
            self.rec.rotate()
        else:
            self.log.inf("Recording is off")

        next_live = next_status = 0.0
        try:
            while not self.stop:
                try:
                    data, addr = sock.recvfrom(65535)
                except socket.timeout:
                    data = None
                except InterruptedError:
                    continue
                now = time.time()
                if data:
                    self.packets += 1
                    self.bytes += len(data)
                    self.last_packet = now
                    src = self.sources.setdefault(addr[0], [0, 0])
                    src[0] += 1
                    src[1] = now
                    if self.fwd:
                        self._forward(data)
                    if self.rec:
                        self.rec.write(now, data)
                    t, ip, text, kind = decode(data, now)
                    self._check_seq(data, kind, ip, now)
                    if kind is not None and kind >= 0xFF00:
                        self.tm.feed(ip, kind, data, now)
                    self.seq += 1
                    self.live_buf.append(json.dumps({
                        "s": self.seq,
                        "d": t.strftime("%Y-%m-%d"),
                        "t": t.strftime("%H:%M:%S.") + f"{t.microsecond // 1000:03d}",
                        "ip": ip or addr[0],
                        "k": kind,
                        "b": 0 if kind == 0 else 1,
                        "m": text,
                    }, ensure_ascii=False) + "\n")
                if now >= next_live:
                    self._flush_live()
                    next_live = now + LIVE_EVERY
                    self.tm.tick(now, bool(self.rec) and self.cfg["record"]["csv"])
                if now >= next_status:
                    if self.rec and self.rec.due(now):
                        self.rec.rotate()
                    self._write_status()
                    next_status = now + STATUS_EVERY
        finally:
            self._flush_live()
            if self.rec and self.cfg["record"]["csv"]:
                self.tm.csv_rows(time.time())     # the part of the interval so far
            self.tm.clear()
            if self.rec:
                self.log.inf("Saving the current recording before stopping")
                self.rec.rotate(final=True)
            self._write_status(running=False)
            sock.close()
            try:
                os.unlink(self.a.pidfile)
            except OSError:
                pass
            self.log.ok(f"Stopped after {self.packets} datagrams")
        return 0


def logend(dbkey, text, status=None):
    """LOGEND has to go through LoxBerry::Log, the session lives in its database.
    The session status (worst severity) is passed along; without it the new
    Log object knows no messages and LOGEND marks the session as OK."""
    if not dbkey or dbkey == "0":
        return
    code = ('use LoxBerry::Log; my $l = LoxBerry::Log->new(dbkey => $ARGV[0], append => 1); '
            '$l->{STATUS} = $ARGV[2] if (defined $ARGV[2] and $ARGV[2] ne ""); $l->LOGEND($ARGV[1]);')
    try:
        subprocess.run(["perl", "-e", code, dbkey, text, "" if status is None else str(status)], timeout=20,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except (OSError, subprocess.SubprocessError):
        pass


def main():
    p = argparse.ArgumentParser(description="Debug Monitor receiver")
    p.add_argument("--config", required=True)
    p.add_argument("--rundir", required=True)
    p.add_argument("--recdir", required=True)
    p.add_argument("--pidfile", required=True)
    p.add_argument("--logfile", default="")
    p.add_argument("--logdbkey", default="")
    p.add_argument("--loglevel", type=int, default=6)
    a = p.parse_args()

    r = Receiver(a)

    def on_term(signum, frame):
        r.stop = True
    signal.signal(signal.SIGTERM, on_term)
    signal.signal(signal.SIGINT, on_term)

    try:
        rc = r.run()
    except Exception as e:  # noqa: BLE001 - last line of defence, goes to the log
        r.log.err(f"Receiver crashed: {e!r}")
        r.error = repr(e)
        r._write_status(running=False)
        rc = 1
    logend(a.logdbkey, "Receiver stopped." if rc == 0 else "Receiver ended with an error.", r.log.status)
    return rc


if __name__ == "__main__":
    sys.exit(main())
