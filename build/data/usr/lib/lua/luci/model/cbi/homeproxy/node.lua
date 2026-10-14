-- SPDX-License-Identifier: GPL-2.0
-- Node management. Each `config node` section is one sing-box outbound.
--
-- Field names here are the flat names homeproxy.nodes produces from a share
-- link, so a node pasted from a subscription and a node typed in by hand are
-- the same kind of object and go through the same build_outbound().

local m, s, o

m = Map("homeproxy", translate("Node Settings"),
	translate("One entry per proxy server. Nodes imported from a subscription " ..
		"appear here too and are replaced when that subscription updates."))


-- The wrapper draws the child-page tab strip, except when the active theme
-- draws one itself; the test for that is in view/homeproxy/nav.htm.
m.template = "homeproxy/map"

-------------------------------------------------------------------- actions

-- This section is created BEFORE the node list so that it renders above it:
-- CBI emits sections in the order they were added.
--
-- It hangs off the shared `actions` placeholder because a page-level control
-- has to belong to a real section -- SimpleSection's section is nil, and LuCI
-- then dies on save while building the field name.
--
-- Both controls live in ONE DummyValue so they can share a row. As two
-- separate options each would be emitted as its own cbi-value block and they
-- would stack instead.
local qa = m:section(TypedSection, "actions", translate("Actions"))
qa.anonymous = true
qa.addremove = false

--- Quote a Lua string as a JavaScript string literal. Not string.format("%q"):
--- that escapes non-ASCII bytes as octal \ooo, and the script runs in strict
--- mode where an octal escape is a syntax error -- which would kill the whole
--- file the moment a translation contained an ellipsis.
local function jsstr(s)
	return '"' .. tostring(s):gsub("\\", "\\\\"):gsub('"', '\\"'):gsub("\n", "\\n") .. '"'
end

--- The node list runs to dozens of entries and CBI renders every field of every
--- one of them inline, so this page also carries the collapse +
--- TCP-reachability script. See /luci-static/homeproxy/node.js.
local actions = qa:option(DummyValue, "_actions", " ")
actions.rawhtml = true
function actions.cfgvalue(self, section)
	local labels = {
		untested       = translate("Untested"),
		testing        = translate("Testing…"),
		ok             = translate("Reachable"),
		fail           = translate("Unreachable"),
		test           = translate("Test"),
		starting       = translate("Starting…"),
		done           = translate("Done"),
		running        = translate("Testing"),
		lastResult     = translate("Last result"),
		lastIncomplete = translate("Last run incomplete"),
		unnamed        = translate("(unnamed)"),
		sortSkipped    = translate("Sorting waits until every node is collapsed."),
		expandAll      = translate("Expand all"),
		collapseAll    = translate("Collapse all"),
	}
	local pairs_js = {}
	for k, v in pairs(labels) do
		pairs_js[#pairs_js + 1] = k .. ": " .. jsstr(v)
	end

	-- One row, three cells. flex-wrap rather than a fixed split so a narrow
	-- phone stacks them instead of squashing all three into unreadable
	-- columns.
	local cell = '<div style="flex:1 1 20em;min-width:16em">'
	return string.format(
		'<script>window.HP_ACTION_URL = %s; window.HP_I18N = {%s};</script>' ..
		'<script src="/luci-static/homeproxy/node.js"></script>' ..
		'<div style="display:flex;gap:2em;flex-wrap:wrap;align-items:flex-start">' ..
			cell ..
				'<input type="button" class="cbi-button cbi-button-apply" value="%s" onclick="location.href=\'%s\'" />' ..
				'<div class="cbi-value-description" style="margin-top:0.5em">%s</div>' ..
			'</div>' ..
			cell ..
				'<input type="button" class="cbi-button cbi-button-apply" id="hp-tcp-all" value="%s" />' ..
				' <span id="hp-tcp-progress" class="cbi-value-description">%s</span>' ..
				'<div class="cbi-value-description" style="margin-top:0.5em">%s</div>' ..
			'</div>' ..
			cell ..
				'<input type="button" class="cbi-button" id="hp-toggle-all" value="%s" />' ..
				'<div class="cbi-value-description" style="margin-top:0.5em">%s</div>' ..
			'</div>' ..
		'</div>',
		jsstr(luci.dispatcher.build_url("admin", "services", "homeproxy", "action")),
		table.concat(pairs_js, ", "),
		translate("Paste a share link"),
		luci.dispatcher.build_url("admin", "services", "homeproxy", "import"),
		translate("Opens a box where you can paste node links; they are parsed and added automatically."),
		translate("Test TCP reachability"),
		translate("Not tested yet."),
		translate("Opens a TCP connection to each node's own server, without going " ..
			"through the proxy, so it shows whether the server itself is reachable."),
		translate("Expand all"),
		translate("Opens or closes every node's settings at once. The list is " ..
			"collapsed when the page loads."))
end

---------------------------------------------------------------------- nodes

-- No tblsection template. A table puts one node per row and one field per
-- column, and this form has two dozen fields, so the table grew wider than any
-- screen and could only be read by scrolling sideways. The default section
-- template stacks each node's fields vertically instead, so the list is read
-- by scrolling down.
s = m:section(TypedSection, "node", translate("Nodes"))
s.anonymous = true
s.addremove = true

o = s:option(Value, "name", translate("Name"))
o.rmempty = false

o = s:option(ListValue, "type", translate("Type"))
for _, t in ipairs({ "shadowsocks", "vmess", "vless", "trojan",
		"hysteria2", "tuic", "socks", "http" }) do
	o:value(t)
end
o.rmempty = false

o = s:option(Value, "server", translate("Server"))
o.rmempty = false
o.datatype = "host"

o = s:option(Value, "port", translate("Port"))
o.datatype = "port"
o.rmempty = false

--------------------------------------------------------------------- shared

o = s:option(Flag, "tls", translate("TLS"))
o.default = "0"

o = s:option(Value, "sni", translate("SNI / Host"))
o:depends("tls", "1")

o = s:option(Flag, "insecure", translate("Skip Certificate Verification"))
o:depends("tls", "1")

o = s:option(Value, "alpn", translate("ALPN"),
	translate("Comma separated, for example h2,http/1.1"))
o:depends("tls", "1")

o = s:option(ListValue, "fingerprint", translate("uTLS Fingerprint"))
o:value("", translate("Default"))
for _, fp in ipairs({ "chrome", "firefox", "safari", "ios", "android", "edge", "random" }) do
	o:value(fp)
end
o:depends("tls", "1")

o = s:option(Value, "reality_public_key", translate("Reality Public Key"))
o:depends("tls", "1")

o = s:option(Value, "reality_short_id", translate("Reality Short ID"))
o:depends("tls", "1")

--------------------------------------------------------------------- transport

o = s:option(ListValue, "transport", translate("Transport"))
o:value("", translate("TCP (default)"))
for _, t in ipairs({ "ws", "grpc", "http", "httpupgrade", "quic" }) do
	o:value(t)
end

o = s:option(Value, "transport_path", translate("Path"))
o:depends("transport", "ws")
o:depends("transport", "http")
o:depends("transport", "httpupgrade")

o = s:option(Value, "transport_host", translate("Host Header"))
o:depends("transport", "ws")
o:depends("transport", "http")
o:depends("transport", "httpupgrade")

o = s:option(Value, "transport_service_name", translate("gRPC Service Name"))
o:depends("transport", "grpc")

--------------------------------------------------------------------- per type

o = s:option(Value, "uuid", translate("UUID"))
o:depends("type", "vmess")
o:depends("type", "vless")
o:depends("type", "tuic")

o = s:option(Value, "password", translate("Password"))
o:depends("type", "shadowsocks")
o:depends("type", "trojan")
o:depends("type", "hysteria2")
o:depends("type", "tuic")
o:depends("type", "socks")
o:depends("type", "http")

o = s:option(Value, "username", translate("Username"))
o:depends("type", "socks")
o:depends("type", "http")

o = s:option(Value, "method", translate("Method"))
o:depends("type", "shadowsocks")

o = s:option(Value, "flow", translate("Flow"))
o:depends("type", "vless")

o = s:option(ListValue, "vmess_security", translate("Encryption"))
for _, v in ipairs({ "auto", "none", "zero", "aes-128-gcm", "chacha20-poly1305" }) do
	o:value(v)
end
o:depends("type", "vmess")

o = s:option(Value, "alter_id", translate("Alter ID"))
o.datatype = "uinteger"
o:depends("type", "vmess")

o = s:option(Value, "obfs_password", translate("Obfs Password"))
o:depends("type", "hysteria2")

o = s:option(ListValue, "congestion_control", translate("Congestion Control"))
for _, v in ipairs({ "bbr", "cubic", "new_reno" }) do
	o:value(v)
end
o:depends("type", "tuic")

o = s:option(Value, "ss_plugin", translate("Plugin"))
o:depends("type", "shadowsocks")

o = s:option(Value, "ss_plugin_opts", translate("Plugin Options"))
o:depends("type", "shadowsocks")

function m.on_after_commit(self)
	luci.sys.call("/etc/init.d/homeproxy restart >/dev/null 2>&1")
end

return m
