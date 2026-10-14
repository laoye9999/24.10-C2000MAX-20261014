/*
 * SPDX-License-Identifier: GPL-2.0
 * Node Settings page: collapse each node, and show its TCP reachability.
 *
 * Two problems this solves on a subscription-backed setup:
 *
 *  - CBI renders every field of every node inline. With 52 nodes that is
 *    1352 inputs in one page (~870 KB, seconds to render, and unreadable).
 *    Each node is collapsed here to a one-line summary.
 *
 *  - Nothing showed whether a node was reachable. The status page's latency
 *    test runs through the proxy, so it only works for the node already in
 *    use. This opens a plain TCP connection to the node's own server, which
 *    tells "the server is down" apart from "the proxy is misconfigured".
 *
 * The collapse wraps each section's children in a container instead of
 * hiding fields individually: CBI's depends() toggles individual fields'
 * display as you edit, and hiding those directly would fight with it.
 *
 * The summary line is rebuilt rather than written once. The controls it reads
 * do not exist when this file first runs -- see refreshSummaries() below.
 */
(function () {
	'use strict';

	var ACT = window.HP_ACTION_URL;
	var PREFIX = 'cbi-homeproxy-';
	var POLL_MS = 1500;
	var lastResults = null;
	// Labels come from the controller so they get translated like the rest of
	// the package instead of being hardcoded here.
	var L = window.HP_I18N || {};
	function t(k, d) { return L[k] || d; }

	function esc(s) {
		return String(s == null ? '' : s).replace(/[&<>"]/g, function (c) {
			return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c];
		});
	}

	function statusHTML(r) {
		if (!r) return '<span style="color:#888">' + esc(t('untested', 'Untested')) + '</span>';
		if (r.ok) {
			return '<span style="color:#0a0;font-weight:bold">' +
				esc(t('ok', 'OK')) + ' ' + r.ms + ' ms</span>';
		}
		return '<span style="color:#c00;font-weight:bold">' + esc(t('fail', 'Fail')) +
			(r.error ? '（' + esc(r.error) + '）' : '') + '</span>';
	}

	function fieldset(sec) {
		return document.getElementById(PREFIX + sec);
	}

	// The node sections CBI rendered, whatever element it rendered them as.
	//
	// This was written against `fieldset.cbi-section-node`, which no LuCI in
	// service emits any more. The templates this firmware ships render a
	// `div` -- /usr/lib/lua/luci/view/cbi/tsection.htm:26 is
	// `<div class="cbi-section-node" id="cbi-<config>-<section>">`, and
	// nsection.htm:14, nullsection.htm:8 and sysauth.ut:21 agree. Verified on
	// the target. So the selector matched nothing, the list came back empty,
	// and every caller below silently did nothing: no collapse header, no
	// per-node test link, no sweep progress, and sortNodes() returning early
	// on `list.length < 2` however many nodes the page had.
	//
	// The tag qualifier is what was wrong, so it is what goes: the class and
	// the id prefix together already identify a node section unambiguously,
	// and dropping it matches both the old markup and this one.
	//
	// The prefix is `cbi-homeproxy-cfg`, not just `cbi-homeproxy-`: an
	// anonymous UCI section is named `cfgXXXXXX`, while the page's Actions box
	// is a section named `actions`, and both render the same wrapper shape.
	// Matching the shorter prefix collapsed the Actions box too, hiding the
	// buttons that live in it behind a header for a "node" that is not one.
	function nodes() {
		return document.querySelectorAll(
			'.cbi-section-node[id^="' + PREFIX + 'cfg"]');
	}

	function closestNode(el) {
		while (el && el.nodeType === 1) {
			if (el.className && String(el.className).indexOf('cbi-section-node') !== -1 &&
				el.id && el.id.indexOf(PREFIX + 'cfg') === 0)
				return el;
			el = el.parentNode;
		}
		return null;
	}

	// Read one field's current value.
	//
	// The id is not on the control. CBI wraps every option in a div carrying
	// `id="cbid.homeproxy.<section>.<option>"` and leaves the real control to
	// /luci-static/resources/cbi.js, which builds it at runtime inside that
	// div -- measured on the device, `<div id="cbid.homeproxy.cfg0546ab.name">
	// <input id="widget.cbid.homeproxy.cfg0546ab.name" value="Tokyo">`
	// for a text field, and the same shape around a `<select>` for a dropdown.
	//
	// Reading `.value` off the id'd element therefore reads it off a div,
	// where it is undefined, and every field looked empty: the collapsed line
	// said "(unnamed)" and nothing else, whatever the node was actually
	// called. That is why the descent to the control is here, and why the
	// summary is rewritten once the controls exist.
	function field(sec, name) {
		var el = document.getElementById('cbid.homeproxy.' + sec + '.' + name);
		if (!el) return '';
		if (typeof el.value === 'string') return el.value;   // no wrapper: old markup
		var c = el.querySelector('select, input:not([type=hidden])' +
			':not([type=checkbox]):not([type=radio]), textarea');
		if (!c) c = el.querySelector('input, select, textarea');
		if (c && typeof c.value === 'string') return c.value;
		return '';
	}

	function summarize(head, sec) {
		var n = head.querySelector('.hp-node-name');
		var ty = head.querySelector('.hp-node-type');
		var a = head.querySelector('.hp-node-addr');
		if (n) n.textContent = field(sec, 'name') || t('unnamed', '(unnamed)');
		if (ty) {
			var v = field(sec, 'type');
			ty.textContent = v;
			ty.style.display = v ? '' : 'none';
		}
		if (a) {
			var s = field(sec, 'server'), p = field(sec, 'port');
			a.textContent = s ? (s + (p ? ':' + p : '')) : '';
		}
	}

	function body(fs) { return fs.querySelector('.hp-node-body'); }

	function setStatus(sec, r) {
		var fs = fieldset(sec);
		var el = fs && fs.querySelector('.hp-node-tcp');
		if (el) el.innerHTML = statusHTML(r);
	}

	function decorate() {
		var list = nodes();
		for (var i = 0; i < list.length; i++) {
			var fs = list[i];
			if (fs.getAttribute('data-hp-done') === '1') continue;
			fs.setAttribute('data-hp-done', '1');

			var sec = fs.id.substring(PREFIX.length);

			var head = document.createElement('div');
			head.className = 'hp-node-head';
			head.setAttribute('style',
				'cursor:pointer;padding:6px 8px;margin:2px 0;border-radius:4px;' +
				'background:rgba(127,127,127,0.12);display:flex;' +
				'align-items:center;gap:10px;flex-wrap:wrap');
			head.innerHTML =
				'<span class="hp-toggle" style="width:1em">▶</span>' +
				'<b class="hp-node-name"></b>' +
				'<span class="hp-node-type" style="color:#888;font-size:0.85em;' +
					'border:1px solid rgba(127,127,127,0.4);border-radius:3px;' +
					'padding:0 4px"></span>' +
				'<span class="hp-node-addr" style="color:#888"></span>' +
				'<span class="hp-node-tcp" style="margin-left:auto">' + statusHTML(null) + '</span>' +
				'<span class="hp-node-test" style="text-decoration:underline;color:#00aeff">' + esc(t('test', 'Test')) + '</span>';
			fs.insertBefore(head, fs.firstChild);

			// Move everything else into a wrapper we can show/hide as one.
			var box = document.createElement('div');
			box.className = 'hp-node-body';   // anyExpanded() looks for this
			while (head.nextSibling) box.appendChild(head.nextSibling);
			fs.appendChild(box);
			box.style.display = 'none';

			head.addEventListener('click', function (h, b, ev) {
				var t = ev.target;
				if (t && t.className === 'hp-node-test') return;   // the per-node test link
				toggle(h, b, b.style.display === 'none');
			}.bind(null, head, box));

			head.querySelector('.hp-node-test').addEventListener('click',
				function (s, ev) { ev.stopPropagation(); testOne(s); }.bind(null, sec));

			summarize(head, sec);
		}
	}

	function toggle(head, box, open) {
		box.style.display = open ? '' : 'none';
		var tg = head.querySelector('.hp-toggle');
		if (tg) tg.textContent = open ? '▼' : '▶';
		syncToggleAll();
	}

	// The one button offers whichever of the two actions makes sense from where
	// the list actually is, so opening a single node by hand leaves it offering
	// to close them rather than lying about it.
	function syncToggleAll() {
		var a = document.getElementById('hp-toggle-all');
		if (a) a.value = anyExpanded() ? t('collapseAll', 'Collapse all')
			: t('expandAll', 'Expand all');
	}

	function setAll(open) {
		var list = nodes();
		for (var i = 0; i < list.length; i++) {
			var head = list[i].querySelector('.hp-node-head');
			var box = body(list[i]);
			if (head && box) toggle(head, box, open);
		}
		syncToggleAll();
	}

	// Rewrite every collapsed line from what is on the page now.
	//
	// This runs more than once because the values arrive late. cbi.js builds
	// the controls from the server's `data-ui-widget` placeholders, and it
	// does not do that on DOMContentLoaded: luci.js waits for DOMContentLoaded,
	// then for four promise-chained dependencies including a probe of the RPC
	// endpoint, and only then calls cbi_init(). On this router that is a
	// network round trip after the page is up, so at the moment decorate()
	// runs there is nothing to read yet and every node summarises as
	// "(unnamed)".
	//
	// `luci-loaded` is the event luci.js fires when it is done, but it is only
	// fired if that probe succeeds, so a bounded retry runs alongside it and
	// stops as soon as the fields answer. Rebuilding a few text nodes 40 times
	// is free; a permanently blank summary is not.
	function refreshSummaries() {
		var list = nodes();
		for (var i = 0; i < list.length; i++) {
			var head = list[i].querySelector('.hp-node-head');
			if (head) summarize(head, list[i].id.substring(PREFIX.length));
		}
	}

	function namesArrived() {
		var list = nodes();
		for (var i = 0; i < list.length; i++) {
			if (!field(list[i].id.substring(PREFIX.length), 'name')) return false;
		}
		return list.length > 0;
	}

	// Renaming a node should not leave the collapsed line showing the old
	// name. Listening on the document instead of per field keeps working for
	// controls that were not on the page when this ran, and `widget-change` is
	// what LuCI's dropdowns and switches send.
	function edited(ev) {
		var fs = closestNode(ev.target);
		if (!fs) return;
		var head = fs.querySelector('.hp-node-head');
		if (head) summarize(head, fs.id.substring(PREFIX.length));
	}

	// A plain POST: XHR's own .post helper is a constructor method on this
	// firmware, and relying on it is what silently killed the buttons before.
	function post(data, cb) {
		var x = new XMLHttpRequest();
		x.open('POST', ACT, true);
		x.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
		x.onreadystatechange = function () {
			if (x.readyState !== 4) return;
			var j = null;
			try { j = JSON.parse(x.responseText); } catch (e) { j = null; }
			if (cb) cb(j);
		};
		x.send(Object.keys(data).map(function (k) {
			return encodeURIComponent(k) + '=' + encodeURIComponent(data[k]);
		}).join('&'));
	}

	function getStatus(cb) {
		var x = new XMLHttpRequest();
		x.open('GET', ACT + '?action=tcp_status', true);
		x.onreadystatechange = function () {
			if (x.readyState !== 4) return;
			var j = null;
			try { j = JSON.parse(x.responseText); } catch (e) { j = null; }
			cb(j);
		};
		x.send(null);
	}

	function testOne(sec) {
		var fs = fieldset(sec);
		var el = fs && fs.querySelector('.hp-node-tcp');
		if (el) el.innerHTML = '<span style="color:#888">' + esc(t('testing', 'Testing…')) + '</span>';
		post({ action: 'tcp_test', node: sec }, function (r) {
			if (el) el.innerHTML = statusHTML(r);
			if (r) {
				lastResults = lastResults || {};
				lastResults[sec] = r;
				sortNodes(lastResults);
			}
		});
	}

	var polling = null;

	function progress(text) {
		var el = document.getElementById('hp-tcp-progress');
		if (el) el.textContent = text;
	}

	// Reorder so the usable nodes come first, fastest first, with everything
	// unreachable collected at the end -- the list is a picking list, and the
	// node you want is almost always "a working one, near the top".
	//
	// Two things this deliberately does NOT do:
	//   * sort during a sweep. Results arrive one at a time; re-sorting on
	//     each would make the list crawl while you read it.
	//   * sort at all while a node is open. Someone editing a node should not
	//     have it slide out from under them.
	function anyExpanded() {
		var list = nodes();
		for (var i = 0; i < list.length; i++) {
			var b = body(list[i]);
			if (b && b.style.display !== 'none') return true;
		}
		return false;
	}

	// A node is not one element. tsection.htm puts the section's Delete button
	// in a `.cbi-section-remove` div immediately *before* the body, and only
	// the body carries an id this file can recognise. Moving the bodies alone
	// left every Delete button next to whichever node slid into its place, so
	// the unit that moves is the pair.
	function rows() {
		var list = nodes(), out = [];
		for (var i = 0; i < list.length; i++) {
			var prev = list[i].previousElementSibling;
			var rm = (prev && prev.className &&
				String(prev.className).indexOf('cbi-section-remove') !== -1) ? prev : null;
			out.push({ node: list[i], remove: rm });
		}
		return out;
	}

	function sortNodes(results) {
		if (!results) return;
		if (anyExpanded()) { progress(t('sortSkipped', 'Sorted when all nodes are collapsed')); return; }

		var arr = rows();
		if (arr.length < 2) return;
		var parent = arr[0].node.parentNode;
		if (!parent) return;

		arr.sort(function (a, b) {
			function key(fs) {
				var r = results[fs.id.substring(PREFIX.length)];
				if (r && r.ok) return [0, r.ms || 0];    // reachable, fastest first
				if (r) return [1, 0];                    // tested and unreachable
				return [2, 0];                           // not tested
			}
			var ka = key(a.node), kb = key(b.node);
			if (ka[0] !== kb[0]) return ka[0] - kb[0];
			return ka[1] - kb[1];
		});

		// The section's Add button is a sibling of the nodes, so the sorted
		// list has to be inserted before it rather than appended past it.
		var anchor = null;
		for (var c = parent.firstElementChild; c; c = c.nextElementSibling) {
			if (c.className && String(c.className).indexOf('cbi-section-create') !== -1) {
				anchor = c;
				break;
			}
		}

		// Move (not clone) each node into its sorted position: the inputs keep
		// their values, and so do the listeners attached to them.
		for (var i = 0; i < arr.length; i++) {
			if (arr[i].remove) parent.insertBefore(arr[i].remove, anchor);
			parent.insertBefore(arr[i].node, anchor);
		}
	}

	function applyResults(j) {
		if (!j || !j.results) return false;
		lastResults = j.results;
		Object.keys(j.results).forEach(function (sec) {
			setStatus(sec, j.results[sec]);
		});
		return true;
	}

	function poll() {
		if (polling) return;
		polling = setInterval(function () {
			getStatus(function (j) {
				if (!applyResults(j)) return;
				progress(j.done
					? (t('done', 'Done') + ' ' + (j.tested || 0) + '/' + (j.total || 0))
					: (t('running', 'Testing') + ' ' + (j.tested || 0) + '/' + (j.total || 0)));
				if (j.done) {
					clearInterval(polling);
					polling = null;
					sortNodes(j.results);
				}
			});
		}, POLL_MS);
	}

	function testAll() {
		progress(t('starting', 'Starting…'));
		post({ action: 'tcp_test_all' }, function () { poll(); });
	}

	function boot() {
		decorate();

		var btn = document.getElementById('hp-tcp-all');
		if (btn) btn.addEventListener('click', testAll);

		// One button, and it always says what it will do: everything is closed
		// when the page loads, so it offers to open them.
		var all = document.getElementById('hp-toggle-all');
		if (all) all.addEventListener('click', function () { setAll(!anyExpanded()); });
		syncToggleAll();

		document.addEventListener('change', edited, true);
		document.addEventListener('widget-change', edited, true);
		document.addEventListener('luci-loaded', function () { setTimeout(refreshSummaries, 0); });

		var tries = 0;
		var settle = setInterval(function () {
			refreshSummaries();
			if (++tries >= 40 || namesArrived()) clearInterval(settle);
		}, 250);

		// Automatic: show whatever the last sweep left behind, and start a new
		// one if there is nothing on record. Testing automatically is the
		// point -- a stale list of dead servers is worse than no list.
		getStatus(function (j) {
			if (j && j.results && Object.keys(j.results).length) {
				applyResults(j);
				progress(j.done
					? (t('lastResult', 'Last result') + ' ' + (j.tested || 0))
					: (t('lastIncomplete', 'Last run incomplete') + ' ' + (j.tested || 0) + '/' + (j.total || 0)));
				if (j.done) sortNodes(j.results); else poll();
			} else {
				testAll();
			}
		});
	}

	if (document.readyState === 'complete' || document.readyState === 'interactive') {
		setTimeout(boot, 0);
	} else {
		document.addEventListener('DOMContentLoaded', boot);
	}
}());
