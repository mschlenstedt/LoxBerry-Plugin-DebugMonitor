#!/usr/bin/env python3
"""Switches the debug output of a Loxone Miniserver, the way Loxone Config does
it in "Diagnose -> Monitor -> Miniserver Debug Einstellungen".

Config talks to the Miniserver over its binary channel: a token login, then
GET /wsx with the token hash, a start frame and binary records. Record 0x8c
reads the setting, 0x8b sets it, the Miniserver confirms with 0x8a. The token
needs right bit 3 (value 8); without it the Miniserver closes the channel.

Reads one JSON object from stdin (the credentials never appear on the command
line):
  {"host", "port", "tls", "user", "pass", "action": "query|set|off",
   "target": "ip:port", "level": 1-3, "days": 1-7}
Writes one JSON object to stdout:
  {"ok": 1, "on": bool, "level": 0-3, "target": "ip:port", "until": unix}
  {"ok": 0, "error": "<key>", "detail": "..."}
"until" is only known after "set": the value 0x8c reports is not the expiry.
"""
import base64
import hashlib
import hmac
import json
import socket
import ssl
import struct
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

EPOCH_2009 = 1230768000          # 2009-01-01 00:00 UTC, the Miniserver's epoch
MAGIC_REQ = b"\xef\xbe\xed\xfe"
MAGIC_RSP = b"\xfe\xaf\xed\xfe"
TOKEN_RIGHTS = 8                 # bit 3: needed for the binary channel
CLIENT_INFO = "LoxBerry Debug Monitor"
TIMEOUT = 8


class Fail(Exception):
    def __init__(self, key, detail=""):
        super().__init__(key)
        self.key, self.detail = key, str(detail)[:300]


class Miniserver:
    def __init__(self, c):
        self.host = c["host"]
        self.tls = bool(c.get("tls"))
        self.port = int(c.get("port") or (443 if self.tls else 80))
        self.user, self.pw = c["user"], c["pass"]
        self.ctx = ssl._create_unverified_context() if self.tls else None   # IP address: no matching certificate
        self.sock, self.buf, self.seq = None, b"", 0
        self.token, self.alg = None, "SHA1"

    # --- HTTP -----------------------------------------------------------------
    def http(self, path, basic=False):
        url = f"{'https' if self.tls else 'http'}://{self.host}:{self.port}{path}"
        req = urllib.request.Request(url, headers={"User-Agent": "LoxBerry-DebugMonitor"})
        if basic:
            req.add_header("Authorization", "Basic " + base64.b64encode(f"{self.user}:{self.pw}".encode()).decode())
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT, context=self.ctx) as r:
                body, code = r.read().decode("utf-8", "replace"), r.status
        except urllib.error.HTTPError as e:
            body, code = e.read().decode("utf-8", "replace"), e.code
        except (OSError, ValueError) as e:
            raise Fail("msconnect", e)
        try:
            ll = json.loads(body)["LL"]
            code = int(ll.get("Code") or ll.get("code") or code)
            return code, ll.get("value")
        except (ValueError, KeyError, TypeError, AttributeError):
            return code, None

    def _hash(self):
        return hashlib.sha256 if self.alg == "SHA256" else hashlib.sha1

    def _getkey2(self):
        code, v = self.http("/jdev/sys/getkey2/" + urllib.parse.quote(self.user, safe=""))
        if code != 200 or not isinstance(v, dict) or "key" not in v:
            raise Fail("mslogin", f"getkey2 {code}")
        self.alg = "SHA256" if str(v.get("hashAlg", "")).upper() == "SHA256" else "SHA1"
        return v

    def get_token(self):
        v = self._getkey2()
        pwhash = self._hash()(f"{self.pw}:{v['salt']}".encode()).hexdigest().upper()
        h = hmac.new(bytes.fromhex(v["key"]), f"{self.user}:{pwhash}".encode(), self._hash()).hexdigest()
        hx = hashlib.sha256(f"{socket.gethostname()}|{self.user}|debugmonitor".encode()).hexdigest()
        uuid = f"{hx[0:8]}-{hx[8:12]}-{hx[12:16]}-{hx[16:20]}-{hx[20:32]}"
        user = urllib.parse.quote(self.user, safe="")
        code, v = self.http(f"/jdev/sys/gettoken/{h}/{user}/{TOKEN_RIGHTS}/{uuid}/{urllib.parse.quote(CLIENT_INFO)}")
        if code != 200 or not isinstance(v, dict) or "token" not in v:
            raise Fail("mslogin", f"gettoken {code}")
        self.token = v["token"]

    def kill_token(self):
        if not self.token:
            return
        try:
            v = self._getkey2()
            h = hmac.new(bytes.fromhex(v["key"]), self.token.encode(), self._hash()).hexdigest()
            self.http(f"/jdev/sys/killtoken/{h}/{urllib.parse.quote(self.user, safe='')}", basic=True)
        except Fail:
            pass
        self.token = None

    # --- Binary channel -------------------------------------------------------
    def open_channel(self):
        code, key = self.http("/jdev/sys/getkey")
        if code != 200 or not key:
            raise Fail("mslogin", f"getkey {code}")
        autht = hmac.new(bytes.fromhex(key), self.token.encode(), self._hash()).hexdigest().upper()
        try:
            s = socket.create_connection((self.host, self.port), timeout=TIMEOUT)
            if self.tls:
                s = self.ctx.wrap_socket(s, server_hostname=self.host)
            s.sendall((f"GET /wsx?autht={autht}&user={urllib.parse.quote(self.user, safe='')} HTTP/1.1\r\n"
                       f"Host: {self.host}\r\nUpgrade: WebSocket\r\nConnection: Upgrade\r\n\r\n").encode())
            head = b""
            while b"\r\n\r\n" not in head:
                d = s.recv(4096)
                if not d:
                    break
                head += d
        except OSError as e:
            raise Fail("msconnect", e)
        self.sock = s
        first = head.split(b"\r\n")[0].decode("latin-1")
        if " 101 " not in first:
            raise Fail("msrefused", first)
        self.buf = head.split(b"\r\n\r\n", 1)[1]
        s.settimeout(0.3)
        # Start frame, then 16 bytes and record 0x01 with 32 bytes. Config sends
        # changing values in both; the Miniserver accepts zeros as well, but
        # the 16 bytes must be there.
        s.sendall(b"\x00dev/loxone/start\xff")
        time.sleep(0.5)
        s.sendall(b"\0" * 16 + self._rec(0x01, b"\0" * 32))
        flags, pay = self.wait(0x01)
        if flags & 0x40:
            # Refused. A u32 reason follows the record: 2 = the token lacks the
            # rights, 3 = Loxone Config is connected - the Miniserver takes only
            # one such channel at a time.
            code = self.reason(pay)
            raise Fail({2: "msrights", 3: "msbusy"}.get(code, "msrefused"), f"code {code}")

    def reason(self, pay):
        if len(pay) >= 4:
            return struct.unpack("<I", pay[:4])[0]
        end = time.time() + 1
        while len(self.buf) < 4 and time.time() < end:
            try:
                d = self.sock.recv(4096)
            except (socket.timeout, ssl.SSLWantReadError):
                continue
            except OSError:
                break
            if not d:
                break
            self.buf += d
        return struct.unpack("<I", self.buf[:4])[0] if len(self.buf) >= 4 else None

    def _rec(self, cmd, payload=b""):
        r = struct.pack("<BBHII", cmd, 0, 0, len(payload), self.seq) + MAGIC_REQ + payload
        self.seq += 1
        return r + b"\0" * ((-len(payload)) % 4)

    def send(self, cmd, payload=b""):
        try:
            self.sock.sendall(self._rec(cmd, payload))
        except OSError as e:
            raise Fail("msconnect", e)

    def wait(self, want, timeout=TIMEOUT):
        """Reads records until one of type `want` arrives. Keeps the channel
        alive meanwhile, as Config does."""
        end = time.time() + timeout
        alive = time.time() + 1.5
        while time.time() < end:
            while len(self.buf) >= 16:
                if self.buf[12:16] != MAGIC_RSP:
                    raise Fail("msprotocol", self.buf[:32].hex(" "))
                cmd, flags, l2, l4, _ = struct.unpack("<BBHII", self.buf[:12])
                ln = l2 if flags & 0x10 else l4
                tot = 16 + ln + ((-ln) % 4)
                if len(self.buf) < tot:
                    break
                pay, self.buf = self.buf[16:16 + ln], self.buf[tot:]
                if cmd == want:
                    return flags, pay
            if time.time() > alive and self.seq:
                self.send(0x14)
                alive = time.time() + 1.5
            try:
                d = self.sock.recv(65536)
            except (socket.timeout, ssl.SSLWantReadError):
                continue
            except OSError as e:
                raise Fail("msconnect", e)
            if not d:
                raise Fail("msclosed")
            self.buf += d
        raise Fail("mstimeout", f"0x{want:02x}")

    def close(self):
        if self.sock:
            try:
                self.send(0x0d)
                self.sock.close()
            except (OSError, Fail):
                pass
            self.sock = None


def parse(pay):
    """Level code 3-5 is level 1-3. The target is "ip:port" in 0x8a and
    "/dev/udp/ip/port" in 0x8c, "/dev/null" or "" when switched off."""
    code, until = struct.unpack("<II", pay[16:24]) if len(pay) >= 24 else (0, 0)
    text = pay[24:].split(b"\0")[0].decode("latin-1")
    if text.startswith("/dev/udp/"):
        ip, _, port = text[9:].partition("/")
        text = f"{ip}:{port}"
    elif text.startswith("/dev/"):
        text = ""
    on = bool(text) and code >= 3
    return {"on": on, "level": code - 2 if on else 0, "target": text if on else "",
            "until": until + EPOCH_2009 if on and until else 0}


def run(c):
    action = c.get("action", "query")
    if action == "set":
        level, days, target = int(c["level"]), int(c["days"]), str(c["target"])
        if not (1 <= level <= 3 and 1 <= days <= 7 and target):
            raise Fail("badvalue")
    ms = Miniserver(c)
    try:
        ms.get_token()
        ms.open_channel()
        if action == "query":
            ms.send(0x8c, b"\0" * 28)
            pay = ms.wait(0x8c)[1]
            r = parse(pay)
            # 0x8c does not report the expiry but now + the set duration
            raw = struct.unpack("<I", pay[20:24])[0] if len(pay) >= 24 else 0
            r["days"] = max(1, round((raw + EPOCH_2009 - time.time()) / 86400)) if raw else 0
            r["until"] = 0
        elif action == "set":
            until = int(time.time()) - EPOCH_2009 + days * 86400
            ms.send(0x8b, b"\0" * 16 + struct.pack("<II", level + 2, until) + target.encode() + b"\0")
            r = parse(ms.wait(0x8a)[1])
        elif action == "off":
            ms.send(0x8b, b"\0" * 28)
            r = parse(ms.wait(0x8a)[1])
        else:
            raise Fail("badvalue", action)
        ms.close()
        r["ok"] = 1
        return r
    finally:
        ms.close()
        ms.kill_token()


def main():
    try:
        c = json.loads(sys.stdin.read())
        out = run(c)
    except Fail as e:
        out = {"ok": 0, "error": e.key, "detail": e.detail}
    except (ValueError, KeyError, TypeError) as e:
        out = {"ok": 0, "error": "badvalue", "detail": repr(e)}
    print(json.dumps(out))


if __name__ == "__main__":
    main()
