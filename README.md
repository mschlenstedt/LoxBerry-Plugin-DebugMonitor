# Debug Monitor for LoxBerry

A LoxBerry plugin that receives the debug messages of Loxone Miniservers on the LoxBerry instead of the Loxone Monitor on a PC.

A Miniserver can send debug messages over UDP: every incoming HTTP request with its sender, TCP connections, Modbus, extensions, program blocks, and twice a second the task monitor with CPU load, memory and all threads. Normally they end up in the Loxone Monitor on a PC that has to run all the time. This plugin receives them around the clock, from one or several Miniservers at once, shows them live in the browser, records them without wearing out the SD card, and makes them searchable for AI assistants through a built-in MCP server.

## Documentation

- [LoxBerry Wiki (user documentation, German)](https://wiki.loxberry.de/plugins/debugmonitor/start)

## Requirements

- LoxBerry 4.0.0.15 or newer
- A Loxone Miniserver (Gen 1 or Gen 2) in the same network
- The Miniserver entered in the LoxBerry Miniserver settings, with user and password
- A free UDP port on the LoxBerry (default 7777)

Nothing is installed besides the plugin itself: the Python parts use only the standard library.

## What the plugin does

- Switches the debug output of each Miniserver on and off from the web interface, with level (1–3) and maximum duration (1–7 days) — the same settings as in Loxone Config. Switching it on in Loxone Config works as well; the plugin notices and shows it as "activated externally".
- Live monitor in its own window, in the colours of the Loxone Monitor, with Miniserver selection, text filter and message types (HTTP, TCP, UDP, SSL, PRG, LNK, errors). Out-of-order packets are marked as `SEQ_ERROR`, like the Loxone Monitor does.
- Task monitor in its own window: CPU, heap, temperature, LAN and link counters, CPU history of the last five minutes and the full thread list.
- Recording of every packet, compressed in RAM and written to the storage (USB stick, network share or the plugin's data folder) once per interval, from 15 minutes to 4 hours. Old recordings are removed by size and age.
- Task monitor figures as CSV, one file per Miniserver and month, every minute to every hour.
- Download of recordings as readable text or raw.
- Forwarding of every packet unchanged to a second receiver, so the Loxone Monitor on the PC keeps working alongside — a Miniserver sends to one target only.
- Read-only access for AI assistants over the Model Context Protocol (MCP), by HTTP with an access key or by SSH.
- A watchdog restarts the receiver and the MCP server after a crash or hang.

## Installation

In the LoxBerry web interface, open **Plugin Manager → Install plugin** and enter the ZIP URL of the [latest release](https://github.com/mschlenstedt/LoxBerry-Plugin-DebugMonitor/releases/latest).

After the installation the monitor is stopped on purpose: as long as the debug output of the Miniserver is off, nothing arrives anyway. Switch it on under **Settings → Debug messages on the Miniserver**, then start the monitor.

## AI access (MCP)

The MCP server lets an AI assistant such as Claude Code search the recordings and the live stream itself. The assistant asks for a time range, a Miniserver, a message type or a text and only gets the result; the searching is done on the LoxBerry. The access is read-only — nothing on the Miniserver or the LoxBerry can be changed through it.

Enable it in the **AI access** tab; the plugin then generates an access key and shows the ready-made command. For Claude Code:

```sh
claude mcp add --transport http loxberry-plugin-debugmonitor http://<loxberry-ip>:7780/mcp --header "Authorization: Bearer <access-key>"
```

Or over SSH, without an open port and without a key (requires a key-based SSH login as `loxberry`; the tab shows the exact path):

```sh
claude mcp add loxberry-plugin-debugmonitor -- ssh loxberry@<loxberry-ip> perl <bindir>/dmon_ctl.pl mcp-stdio
```

| Tool | Returns |
|---|---|
| `miniserver_status` | receiver, sending Miniservers, time range of the recordings |
| `miniserver_list_recordings` | all recordings with time range and size |
| `miniserver_search` | messages by time range, Miniserver, message type, text or regex |
| `miniserver_context` | all messages around a point in time |
| `miniserver_http_requests` | HTTP requests with sender IP, port, user agent and error status |
| `miniserver_summary` | overview: message types, most frequent errors, out-of-order packets, HTTP callers |
| `miniserver_taskmon` | current task monitor: CPU, heap, temperature, counters, busiest threads |
| `miniserver_resources` | history of the task monitor figures from the CSV files |
| `miniserver_live_tail` | the newest messages from the running receiver |

Sender and user agent of an HTTP request are only logged by the Miniserver from debug level 3 on.

## Security

The debug messages reveal a lot about an installation: IP addresses and programs accessing the Miniserver, names of inputs and outputs with their values, Modbus and extension devices. Do not share recordings or the MCP access key, do not open any port of the plugin in your router, and read a recording yourself before posting it in a forum. The MCP server is meant for the local network only.

## How it is put together

### Receiver

`dmon_receiver.py` is the only process that touches the UDP port. It never waits for a disk or a network share: finished recordings are moved to the storage in a separate thread. If the storage is unreachable (e.g. a share is offline), the recording stays in RAM and is written the next time.

Raw record format: per datagram 8 bytes receive time (big-endian double, Unix seconds), 4 bytes length (big-endian), then the payload. Recordings are stored as `dm_YYYYMMDD_HHMMSS.raw.gz`.

### Switching the Miniserver debug output

`dmon_msdebug.py` talks to the Miniserver the way Loxone Config does in *Diagnose → Monitor → Miniserver Debug Einstellungen*: token login, then the binary channel over `/wsx`, where one record reads the setting and another one sets it. The credentials are read from stdin and never appear on a command line. The user needs the corresponding right; it has been tested with administrator rights.

### Process supervision

Start and stop go through `DebugMonitor.pm`, shared by the web interface and `dmon_ctl.pl`. Whether the receiver should run is decided by a flag file in the config folder: a monitor stopped by hand stays stopped across reboots and plugin upgrades. The daemon starts it at boot unless that flag is set; a cron job checks every minute whether receiver and MCP server are running and answering, and gives up after five failed restarts in a row until the monitor is started by hand. All processes run as `loxberry`.

### MCP server

`dmon_mcp.py` serves the same tools over HTTP (bearer token) and over stdin/stdout for SSH. Its data sources are the recordings on the storage, finished recordings still waiting in RAM, the recording being written, and the live buffer of the receiver. It runs independently of the monitor, so recordings stay searchable while the monitor is stopped.

## Repository layout

| Path | Content |
|---|---|
| `bin/` | receiver (`dmon_receiver.py`), MCP server (`dmon_mcp.py`), Miniserver debug switch (`dmon_msdebug.py`), shared logic (`DebugMonitor.pm`), command line control (`dmon_ctl.pl`) |
| `webfrontend/htmlauth/` | `index.cgi` (settings, monitor, AI access and log tabs), `monitor.cgi` and `taskmon.cgi` (full-screen windows), `ajax.cgi` (JSON interface) |
| `templates/` | page templates, JavaScript, CSS and language files (German, English) |
| `config/` | default configuration |
| `daemon/`, `cron/` | start at boot, watchdog every minute |
| `postroot.sh`, `preupgrade.sh`, `postupgrade.sh`, `uninstall/` | installation lifecycle |

## Support

Questions and bug reports in the [LoxForum thread](https://www.loxforum.com/forum/projektforen/loxberry/plugins/495928-neues-plugin-debug-monitor-ms-debugmeldungen-am-loxberry-mit-mcp-server) or as an issue in this repository.

This plugin is not affiliated with Loxone. Use at your own risk.
