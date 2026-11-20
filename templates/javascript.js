<script>
(function () {
	'use strict';
	var L = <TMPL_VAR JS_STRINGS>;
	var CFG = <TMPL_VAR CFG_JSON>;
	var LBIP = '<TMPL_VAR LBIP ESCAPE=JS>';
	var MS = <TMPL_VAR MS_JSON>;
	var page = document.getElementById('dm-page');
	if (!page) return;
	var form = page.dataset.form;

	// --- Helpers ------------------------------------------------------------
	function $(id) { return document.getElementById(id); }
	function fmt(s) { var a = arguments, i = 1; return String(s).replace(/%s/g, function () { return a[i++]; }); }
	function esc(s) { return String(s == null ? '' : s).replace(/[&<>"]/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]; }); }
	function num(n) { return Number(n || 0).toLocaleString(); }
	function bytes(n) {
		if (n == null) return '–';
		var u = ['B', 'KB', 'MB', 'GB', 'TB'], i = 0;
		while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
		return (i ? n.toLocaleString(undefined, { maximumFractionDigits: 1 }) : n) + ' ' + u[i];
	}
	function dur(sec) {
		sec = Math.max(0, sec);
		if (sec < 1) return sec.toLocaleString(undefined, { maximumFractionDigits: 1 }) + ' s';
		if (sec < 60) return Math.round(sec) + ' s';
		var m = Math.floor(sec / 60);
		if (m < 60) return m + ' min';
		var h = Math.floor(m / 60);
		if (h < 48) return h + ' h ' + (m % 60) + ' min';
		return Math.floor(h / 24) + ' d';
	}
	function clock(ts) { return new Date(ts * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }); }
	function datetime(ts) { return new Date(ts * 1000).toLocaleString([], { dateStyle: 'short', timeStyle: 'short' }); }
	function errText(d) { return (d && L['ERR_' + d.error]) || L.ERR_unknown; }

	function api(action, params, post) {
		var body = new URLSearchParams(params || {});
		var url = 'ajax.cgi?action=' + encodeURIComponent(action);
		var opt = { cache: 'no-store' };
		if (post) {
			opt.method = 'POST';
			opt.body = body;
		} else if (params) {
			url += '&' + body.toString();
		}
		return fetch(url, opt)
			.then(function (r) { return r.json(); })
			.catch(function () { return { ok: 0, error: 'network' }; });
	}

	function dot(cls) { return '<span class="dm-dot ' + cls + '"></span> '; }

	// Copy buttons: data-copy names the element whose text is copied
	function bindCopy() {
		page.querySelectorAll('.dm-copy').forEach(function (b) { b.addEventListener('click', function () {
			var t = $(this.getAttribute('data-copy')).textContent, btn = this;
			var done = function () { btn.innerHTML = '<i class="pi pi-check"></i>'; setTimeout(function () { btn.innerHTML = '<i class="pi pi-copy"></i>'; }, 1500); };
			if (navigator.clipboard && window.isSecureContext) {
				navigator.clipboard.writeText(t).then(done, function () {});
			} else {
				// Plain http: the clipboard API is not available
				var ta = document.createElement('textarea');
				ta.value = t; ta.style.position = 'fixed'; ta.style.opacity = '0';
				document.body.appendChild(ta); ta.select();
				try { document.execCommand('copy'); done(); } catch (e) { /* nothing to do */ }
				ta.remove();
			}
		}); });
	}

	var last = null;   // last status answer
	var busy = '';     // 'starting' | 'stopping' while a button works

	// --- Monitor tab --------------------------------------------------------
	if (form === 'monitor') {
		var prevPos = '';
		var shot = $('mon-preview'), previewZebra = 0;
		// Type column as in the monitor window
		var RE_TYPE = /^(mDNS|[A-Z][A-Z0-9_]{1,11})(\s+)([\s\S]*)$/;
		var msg = function (m) {
			var t = RE_TYPE.exec(m);
			// No type: empty column, so every message starts at the same place
			return t ? '<span class="ty">' + esc(t[1]) + '</span> ' + esc(t[3]) : '<span class="ty"></span> ' + esc(m);
		};
		var refresh = function () {
			api('status').then(function (d) {
				var st = d.receiver || {};
				var on = d.running && st.last_packet && (d.now - st.last_packet) < 10;
				$('mon-state').innerHTML = dot(d.running ? (on ? 'on' : 'idle') : 'off') +
					esc(d.running ? (on ? L.ST_RUNNING : L.ST_WAITING) : L.ST_STOPPED) +
					(d.running ? ' · UDP ' + esc(st.port) + ' · ' + num(st.packets) : '');
			});
			api('live', { pos: prevPos }).then(function (d) {
				if (!d.ok) return;
				prevPos = d.pos;
				var rows = [];
				(d.data || '').split('\n').forEach(function (s) {
					if (!s) return;
					try {
						var l = JSON.parse(s);
						// Binary records only in the full monitor
						var bin = l.b !== undefined ? l.b === 1 : (l.k !== undefined && l.k !== null && l.k !== 1);
						if (!bin) rows.push(l);
					} catch (e) { /* half line at a rotation */ }
				});
				rows = rows.slice(-14);
				if (!rows.length) return;
				var html = rows.map(function (l) {
					// Same colours as the monitor window
					var c = /^HTTP/.test(l.m) ? 'http' : /^TCP/.test(l.m) ? 'tcp' : /^UDP/.test(l.m) ? 'udp' :
						/^DNS/.test(l.m) ? 'dns' : /^SEQ_ERROR/.test(l.m) ? 'seq' : 'ms';
					return '<div class="ln c-' + c + ((previewZebra++ % 2) ? ' z' : '') + '"><span class="t">' + esc(l.t) + '</span> ' + msg(l.m) + '</div>';
				}).join('');
				shot.insertAdjacentHTML('beforeend', html);
				while (shot.childElementCount > 14) shot.removeChild(shot.firstElementChild);
			});
		};
		refresh();
		setInterval(refresh, 3000);
		return;
	}

	// --- AI access tab (MCP server) --------------------------------------------
	if (form === 'ai') {
		// Unique name: Loxone uses "loxone-" for its own MCP servers
		var MCP_NAME = 'loxberry-plugin-debugmonitor';
		var mc = CFG.mcp || {};
		var fOn = $('f-mcp'), fPort = $('f-mcpport'), token = mc.token || '';
		fOn.checked = !!Number(mc.enabled);
		fPort.value = mc.port || 7780;
		var cmds = function () {
			var url = 'http://' + (LBIP || 'loxberry') + ':' + (fPort.value.trim() || '7780') + '/mcp';
			var bearer = 'Bearer ' + (token || '<token>');
			$('mcp-token').textContent = token || L.AI_NOTOKEN;
			$('cmd-http').textContent = 'claude mcp add --transport http ' + MCP_NAME + ' ' + url + ' --header "Authorization: ' + bearer + '"';
			$('cmd-json').textContent = JSON.stringify({ mcpServers: { [MCP_NAME]: { type: 'http', url: url,
				headers: { Authorization: bearer } } } }, null, 2);
		};
		var msg = function (text, isErr) {
			$('mcp-msg').textContent = text || '';
			$('mcp-msg').classList.toggle('dm-err', !!isErr);
		};
		var mcpState = function () {
			api('status').then(function (d) {
				if (!d || d.ok === 0) return;
				var on = d.mcp && d.mcp.running, el = $('mcp-state');
				el.className = 'dm-pill ' + (on ? 'ok' : '');
				el.innerHTML = on ? '<i class="pi pi-check"></i> ' + esc(fmt(L.AI_RUNNING, (LBIP || 'loxberry') + ':' + (CFG.mcp.port || fPort.value)))
					: esc(Number(CFG.mcp.enabled) ? L.AI_DOWN : L.AI_OFF);
			});
		};
		fPort.addEventListener('input', function () { cmds(); $('mcpport-result').innerHTML = ''; });
		$('btn-mcpcheck').addEventListener('click', function () {
			api('mcpportcheck', { port: fPort.value.trim() }).then(function (d) {
				var map = { free: ['ok', 'pi-check', L.PORT_FREE], own: ['ok', 'pi-check', L.AI_PORT_OWN],
					used: ['err', 'pi-times', L.PORT_USED], invalid: ['err', 'pi-times', L.PORT_INVALID] };
				var m = map[d && d.result] || map.invalid;
				$('mcpport-result').innerHTML = '<span class="dm-pill ' + m[0] + '"><i class="pi ' + m[1] + '"></i> ' + esc(m[2]) + '</span>';
			});
		});
		$('btn-mcpsave').addEventListener('click', function () {
			msg(L.LOADING);
			api('mcpsave', { enabled: fOn.checked ? 1 : 0, port: fPort.value.trim() }, true).then(function (d) {
				if (!d.ok) return msg(errText(d), true);
				token = d.token || token;
				CFG.mcp = { enabled: fOn.checked ? 1 : 0, port: Number(fPort.value), token: token };
				cmds();
				msg(L.SAVED);
				mcpState();
			});
		});
		$('btn-mcptoken').addEventListener('click', function () {
			// Second click confirms: the old token stops working for every client
			var btn = this;
			if (token && !btn.dataset.sure) {
				btn.dataset.sure = '1';
				btn.dataset.label = btn.innerHTML;
				btn.innerHTML = '<i class="pi pi-exclamation-triangle"></i> ' + esc(L.AI_TOKEN_SURE);
				setTimeout(function () { delete btn.dataset.sure; btn.innerHTML = btn.dataset.label; }, 4000);
				return;
			}
			delete btn.dataset.sure;
			if (btn.dataset.label) btn.innerHTML = btn.dataset.label;
			api('mcptoken', {}, true).then(function (d) {
				if (!d.ok) return msg(errText(d), true);
				token = d.token; CFG.mcp.token = token;
				cmds();
				msg(L.AI_TOKEN_DONE);
			});
		});
		bindCopy();
		cmds();
		mcpState();
		setInterval(mcpState, 5000);
		return;
	}

	// --- Start tab: form ------------------------------------------------------
	var f = {
		port: $('f-port'), rec: $('f-rec'), flush: $('f-flush'), keepmb: $('f-keepmb'), keepdays: $('f-keepdays'),
		csvmin: $('f-csvmin'),
		fwd: $('f-fwd'), fwdhost: $('f-fwdhost'), fwdport: $('f-fwdport')
	};
	var saved = null;

	function fill(c) {
		f.port.value = c.port;
		f.rec.checked = !!Number(c.record.enabled);
		if (![].some.call(f.flush.options, function (o) { return o.value == c.record.flush_min; })) {
			f.flush.insertAdjacentHTML('beforeend', '<option value="' + esc(c.record.flush_min) + '">' + esc(c.record.flush_min) + ' min</option>');
		}
		f.flush.value = String(c.record.flush_min);
		f.keepmb.value = c.record.keep_mb;
		f.keepdays.value = c.record.keep_days;
		// One select for both: 0 = no CSV, otherwise the interval in minutes
		f.csvmin.value = Number(c.record.csv) ? String(c.record.csv_min) : '0';
		f.fwd.checked = !!Number(c.forward.enabled);
		f.fwdhost.value = c.forward.host;
		f.fwdport.value = c.forward.port;
		toggles();
	}
	function recpath() {
		var el = $('recpath');
		return el ? el.value : '';
	}
	function collect() {
		return {
			port: f.port.value.trim(),
			record: {
				enabled: f.rec.checked ? 1 : 0,
				path: recpath(),
				flush_min: f.flush.value,
				keep_mb: f.keepmb.value.trim(),
				keep_days: f.keepdays.value.trim(),
				csv: f.csvmin.value === '0' ? 0 : 1,
				csv_min: f.csvmin.value === '0' ? (CFG.record.csv_min || 5) : f.csvmin.value
			},
			forward: {
				enabled: f.fwd.checked ? 1 : 0,
				host: f.fwdhost.value.trim(),
				port: f.fwdport.value.trim()
			}
		};
	}
	function dirty() { return saved !== null && JSON.stringify(collect()) !== saved; }
	function toggles() {
		$('rec-opts').classList.toggle('dm-off', !f.rec.checked);
		$('fwd-opts').classList.toggle('dm-off', !f.fwd.checked);
	}

	// The storage widget fills its hidden field after loading; take the
	// "saved" snapshot only then, otherwise the page starts out dirty.
	fill(CFG);
	setTimeout(function () { saved = JSON.stringify(collect()); bar(); }, 1500);

	page.addEventListener('input', function (e) {
		if (e.target === f.port) { $('port-result').innerHTML = ''; }
		bar();
	});
	page.addEventListener('change', function () { toggles(); bar(); });

	bindCopy();

	// --- Port check -------------------------------------------------------------
	function portPill(result) {
		var map = { free: ['ok', 'pi-check', L.PORT_FREE], own: ['ok', 'pi-check', L.PORT_OWN],
			used: ['err', 'pi-times', L.PORT_USED], invalid: ['err', 'pi-times', L.PORT_INVALID] };
		var m = map[result] || map.invalid;
		return '<span class="dm-pill ' + m[0] + '"><i class="pi ' + m[1] + '"></i> ' + esc(m[2]) + '</span>';
	}
	$('btn-check').addEventListener('click', function () {
		$('port-result').innerHTML = '<span class="dm-pill">' + esc(L.LOADING) + '</span>';
		api('portcheck', { port: f.port.value.trim() }).then(function (d) {
			$('port-result').innerHTML = d.ok ? portPill(d.result) : '<span class="dm-pill err">' + esc(errText(d)) + '</span>';
		});
	});

	// --- Status -----------------------------------------------------------------
	function card(d) {
		var st = d.receiver || {};
		var on = d.running && st.last_packet && (d.now - st.last_packet) < 10;
		var state = busy === 'starting' ? ['idle', L.ST_STARTING] :
			busy === 'stopping' ? ['idle', L.ST_STOPPING] :
			!d.running && d.stopped ? ['off', L.ST_STOPPED] :
			// Not running although not stopped by the user: crashed, the watchdog takes over
			!d.running ? ['bad', (d.watchdog || {}).gaveup ? L.ST_GAVEUP : L.ST_CRASHED] :
			on ? ['on', L.ST_RUNNING] : ['idle', L.ST_WAITING];
		$('st-state').innerHTML = dot(state[0]) + esc(state[1]);
		var since = $('st-since');
		since.hidden = !(d.running && st.started);
		if (!since.hidden) {
			since.className = 'dm-pill ' + (on ? 'ok' : '');
			since.textContent = fmt(L.SINCE, dur(d.now - st.started));
		}
		$('st-port').textContent = d.running ? st.port : CFG.port;
		$('st-packets').textContent = d.running || st.packets ? num(st.packets) : '–';
		$('st-last').textContent = st.last_packet ? fmt(L.AGO, dur(d.now - st.last_packet)) : L.NEVER;
		var src = (st.sources || []).map(function (s) { return s.ip; });
		$('st-src').textContent = src.length ? fmt(L.FROM, src.join(', ')) : '';
		var fw = st.forward || {};
		$('st-fwd').textContent = d.running && fw.enabled ? fmt(L.FWD_STATE, num(fw.packets)) +
			(fw.errors ? ' · ' + fmt(L.FWD_ERRORS, num(fw.errors), fw.error) : '') : '';
		recRam(d);
	}
	function bar() {
		var d = last || { running: 0 };
		var t, x;
		if (dirty()) { t = L.BAR_DIRTY_T; x = L.BAR_DIRTY; }
		else if (d.running) { t = L.BAR_RUNNING_T; x = fmt(L.BAR_RUNNING, (d.receiver || {}).port || CFG.port); }
		else { t = L.BAR_STOPPED_T; x = L.BAR_STOPPED; }
		$('bar-title').textContent = t;
		if (!$('bar-text').dataset.msg) $('bar-text').textContent = x;
		$('btn-save').classList.toggle('lb-btn-primary', dirty());
		$('btn-start').disabled = !!busy;
		$('btn-stop').disabled = !!busy || !d.running;
		$('btn-start').innerHTML = '<i class="pi ' + (d.running ? 'pi-refresh' : 'pi-play') + '"></i> ' +
			esc(d.running ? L.RESTART : '<TMPL_VAR START.START ESCAPE=JS>');
	}
	function message(text, err) {
		var el = $('bar-text');
		el.dataset.msg = '1';
		el.textContent = text;
		el.classList.toggle('dm-err', !!err);
		clearTimeout(message.t);
		message.t = setTimeout(function () { delete el.dataset.msg; el.classList.remove('dm-err'); bar(); }, err ? 8000 : 3500);
	}
	function poll() {
		api('status').then(function (d) {
			if (d.ok) { last = d; card(d); bar(); msWatch(d); }
		});
	}

	// --- Recordings -------------------------------------------------------------
	function recRam(d) {
		var r = (d.receiver || {}).record;
		var ram = $('rec-ram'), er = $('rec-err');
		if (!d.running || !r) { ram.hidden = true; er.hidden = true; return; }
		var parts = [];
		// The gzip stream buffers internally, so the file size lags far behind;
		// the packet count is what the user can relate to
		if (r.ram_packets && r.next_move) parts.push(fmt(L.REC_RAM, num(r.ram_packets), clock(r.next_move)));
		if (r.pending) parts.push(fmt(L.REC_WAITING, r.pending));
		ram.textContent = parts.join(' · ');
		ram.hidden = !parts.length;
		var lm = r.last_move;
		er.hidden = !(lm && !Number(lm.ok));
		if (!er.hidden) er.textContent = fmt(L.REC_LAST_ERR, lm.error);
		if (moveFailed !== !er.hidden) { moveFailed = !er.hidden; lastRecs = ''; }
	}
	var moveFailed = false;
	var lastRecs = '';
	function recordings() {
		api('recordings').then(function (d) {
			if (!d.ok) return;
			var key = JSON.stringify(d);
			if (key === lastRecs) return;
			lastRecs = key;
			$('rec-sum').textContent = fmt(L.REC_TOTAL, num(d.files.length), bytes(d.total), bytes(d.free_bytes));
			delAll(d.files.length);
			if (!d.files.length) {
				$('rec-list').innerHTML = '<li class="dm-sub">' + esc(d.exists || moveFailed ? L.REC_NONE : L.REC_NODIR) + '</li>';
				return;
			}
			$('rec-list').innerHTML = d.files.map(function (r) {
				var q = 'ajax.cgi?action=download&file=' + encodeURIComponent(r.name);
				return '<li><span class="dm-mono">' + esc(r.name) + '</span>' +
					'<span class="dm-sub">' + esc(datetime(r.mtime)) + ' · ' + esc(bytes(r.size)) + '</span>' +
					'<span class="dm-recact">' +
					(r.csv ? '<a class="lb-btn lb-btn-sm" href="' + q + '"><i class="pi pi-table"></i> CSV</a>' :
					'<a class="lb-btn lb-btn-sm" href="' + q + '&fmt=txt"><i class="pi pi-file"></i> ' + esc(L.REC_TEXT) + '</a>' +
					'<a class="lb-btn lb-btn-sm" href="' + q + '&fmt=raw"><i class="pi pi-download"></i> ' + esc(L.REC_RAW) + '</a>') +
					'<button type="button" class="lb-btn lb-btn-sm" data-del="' + esc(r.name) + '"><i class="pi pi-trash"></i> ' + esc(L.REC_DELETE) + '</button>' +
					'</span></li>';
			}).join('');
		});
	}
	// "Delete all": also two clicks; the button names how many files go
	var delAllCount = 0;
	function delAll(n) {
		var b = $('btn-delall');
		delAllCount = n;
		b.hidden = !n;
		b.classList.remove('lb-btn-danger');
		b.querySelector('span').textContent = L.REC_DELETE_ALL;
	}
	$('btn-delall').addEventListener('click', function () {
		var b = this;
		if (!b.classList.contains('lb-btn-danger')) {
			b.classList.add('lb-btn-danger');
			b.querySelector('span').textContent = fmt(L.REC_DELETE_ALL_SURE, num(delAllCount));
			setTimeout(function () { if (b.classList.contains('lb-btn-danger')) delAll(delAllCount); }, 4000);
			return;
		}
		b.disabled = true;
		api('deleteall', {}, true).then(function (d) {
			b.disabled = false;
			if (!d.ok) message(errText(d), true);
			else message(fmt(L.REC_DELETED_ALL, num(d.deleted)));
			lastRecs = '';
			recordings();
		});
	});
	$('rec-list').addEventListener('click', function (e) {
		var b = e.target.closest('[data-del]');
		if (!b) return;
		// Two clicks instead of a browser dialog
		if (!b.classList.contains('lb-btn-danger')) {
			b.classList.add('lb-btn-danger');
			b.innerHTML = '<i class="pi pi-trash"></i> ' + esc(L.REC_DELETE_SURE);
			setTimeout(function () { lastRecs = ''; recordings(); }, 4000);
			return;
		}
		api('deleterec', { file: b.dataset.del }, true).then(function (d) {
			if (!d.ok) message(errText(d), true);
			lastRecs = '';
			recordings();
		});
	});

	// --- Buttons ----------------------------------------------------------------
	$('btn-save').addEventListener('click', function () {
		var btn = this;
		btn.disabled = true;
		api('save', { data: JSON.stringify(collect()) }, true).then(function (d) {
			btn.disabled = false;
			if (!d.ok) { message(errText(d) + (d.detail ? ' (' + d.detail + ')' : ''), true); return; }
			CFG = Object.assign(CFG, d.config);
			saved = JSON.stringify(collect());
			message(d.restarted ? L.SAVED_RESTARTED : L.SAVED);
			lastRecs = '';
			poll();
			recordings();
		});
	});
	$('btn-start').addEventListener('click', function () {
		var go = function () {
			busy = 'starting'; bar(); if (last) card(last);
			api('start', {}, true).then(function (d) {
				busy = '';
				if (!d.ok) message(errText(d) + (d.detail ? ' (' + d.detail + ')' : ''), true);
				poll();
			});
		};
		// Unsaved changes are saved first - "Start" means "with what I see"
		if (dirty()) {
			api('save', { data: JSON.stringify(collect()) }, true).then(function (d) {
				if (!d.ok) { message(errText(d), true); return; }
				CFG = Object.assign(CFG, d.config);
				saved = JSON.stringify(collect());
				if (d.restarted) { message(L.SAVED_RESTARTED); poll(); return; }
				go();
			});
		} else {
			go();
		}
	});
	$('btn-stop').addEventListener('click', function () {
		busy = 'stopping'; bar(); if (last) card(last);
		api('stop', {}, true).then(function () {
			busy = '';
			poll();
			setTimeout(function () { lastRecs = ''; recordings(); }, 500);
		});
	});

	// --- Debug output of the Miniservers -------------------------------------
	// One card per Miniserver: what it does now, level and duration, switch.
	// The receiver sees who sends. If that does not match a card - a Miniserver
	// sends although its card says otherwise, or its card says it sends to us
	// and nothing came for 30 s - the card asks the Miniserver again, once per
	// change. That catches switching in Loxone Config and the expiry.
	var MSS = {};
	function msWatch(d) {
		var src = {};
		((d.receiver || {}).sources || []).forEach(function (s) { src[s.ip] = s.last; });
		MS.forEach(function (m) {
			var s = MSS[m.nr];
			if (!s) return;
			s.active = !!(d.running && src[m.ip] && d.now - src[m.ip] < 30);
			if (s.busy || s.active === !!(s.on && s.self) || s.activeAtQuery === s.active) return;
			s.query();
		});
	}
	function msCards() {
		var box = $('ms-list');
		if (!MS.length) { box.innerHTML = '<p class="dm-help">' + esc(L.MS_NONE) + '</p>'; return; }
		var opts = function (vals, label) {
			return vals.map(function (v) { return '<option value="' + v + '">' + esc(label(v)) + '</option>'; }).join('');
		};
		box.innerHTML = MS.map(function (m) {
			var id = 'ms' + m.nr;
			return '<div class="lb-card dm-set dm-ms" id="' + id + '">' +
				'<div class="dm-mshead"><span class="dm-name">' + esc(m.name) + '</span><span class="dm-mono dm-sub">' + esc(m.ip) + '</span>' +
				'<span class="dm-msstate" id="' + id + '-st">' + dot('') + esc(L.MS_QUERY) + '</span>' +
				'<button type="button" class="lb-btn lb-btn-sm dm-msre" id="' + id + '-re" title="' + esc(L.MS_REFRESH) + '"><i class="pi pi-refresh"></i></button></div>' +
				'<div class="dm-portrow">' +
				'<div class="dm-fld"><label class="dm-k" for="' + id + '-lv">' + esc(L.MS_LEVEL) + '</label><select class="lb-select dm-auto" id="' + id + '-lv">' +
				opts([1, 2, 3], function (v) { return v === 1 ? L.MS_LEVEL_1 : v === 3 ? L.MS_LEVEL_3 : String(v); }) + '</select></div>' +
				'<div class="dm-fld"><label class="dm-k" for="' + id + '-dy">' + esc(L.MS_DAYS) + '</label><select class="lb-select dm-auto" id="' + id + '-dy">' +
				opts([1, 2, 3, 4, 5, 6, 7], function (v) { return v === 1 ? L.MS_DAY : fmt(L.MS_DAYS_N, v); }) + '</select></div>' +
				'<button type="button" class="lb-btn lb-btn-primary" id="' + id + '-on"><i class="pi pi-play"></i> <span>' + esc(L.MS_ON) + '</span></button>' +
				'<button type="button" class="lb-btn" id="' + id + '-off"><i class="pi pi-power-off"></i> ' + esc(L.MS_OFF) + '</button>' +
				'</div><p class="dm-help dm-err" id="' + id + '-err" hidden></p></div>';
		}).join('');
		MS.forEach(function (m) {
			var id = 'ms' + m.nr, s = MSS[m.nr] = {};
			var ctl = [id + '-lv', id + '-dy', id + '-on', id + '-off'];
			var show = function (d, first) {
				var st = $(id + '-st'), er = $(id + '-err');
				s.busy = false;
				$(id + '-re').disabled = false;
				// Without an answer the state is unknown: settings and switches stay
				// disabled until a query succeeds
				if (!d.ok) {
					st.innerHTML = dot('bad') + '–';
					er.textContent = errText(d); er.hidden = false;
					return;
				}
				er.hidden = true;
				ctl.forEach(function (c) { $(c).disabled = false; });
				s.on = d.on; s.self = d.self;
				if (first || d.on) { $(id + '-lv').value = d.want_level || 3; $(id + '-dy').value = d.want_days || 1; }
				// Three states: off; switched on here, so the end is known; switched on
				// elsewhere (Loxone Config), then only the set duration is known
				var days = d.days === 1 ? L.MS_DAY : fmt(L.MS_DAYS_N, d.days || '?');
				var t = !d.on ? L.MS_DISABLED :
					d.until ? fmt(L.MS_ACTIVE, datetime(d.until), d.level) :
					d.self ? fmt(L.MS_EXTERN, d.level, days) : fmt(L.MS_EXTERN_OTHER, d.target, d.level, days);
				st.innerHTML = dot(d.on ? (d.self ? 'on' : 'idle') : '') + esc(t);
				$(id + '-on').querySelector('span').textContent = d.on && d.self ? L.MS_APPLY : L.MS_ON;
				$(id + '-off').disabled = !d.on;
			};
			var run = function (action, params, post, first) {
				s.busy = true; s.activeAtQuery = s.active;
				ctl.concat(id + '-re').forEach(function (c) { $(c).disabled = true; });
				$(id + '-st').innerHTML = dot('') + esc(post ? L.MS_SWITCHING : L.MS_QUERY);
				params.ms = m.nr;
				api(action, params, post).then(function (d) { show(d, first); });
			};
			$(id + '-on').addEventListener('click', function () { run('msdebugset', { on: 1, level: $(id + '-lv').value, days: $(id + '-dy').value }, true); });
			$(id + '-off').addEventListener('click', function () { run('msdebugset', { on: 0 }, true); });
			$(id + '-re').addEventListener('click', function () { run('msdebug', {}, false); });
			s.query = function () { run('msdebug', {}, false); };
			run('msdebug', {}, false, true);
		});
	}
	msCards();

	poll();
	recordings();
	setInterval(poll, 2000);
	setInterval(recordings, 15000);
})();
</script>
