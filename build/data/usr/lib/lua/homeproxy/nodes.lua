-- SPDX-License-Identifier: GPL-2.0
-- homeproxy 21.02 backport -- node model.
--
-- Two representations, one conversion path:
--
--   flat fields  <-- share-link parsers            (subscription import)
--                <-- LuCI CBI forms                (manual editing)
--                <-- /etc/config/homeproxy         (storage)
--                     |
--                     v  build_outbound()
--                sing-box outbound tables          (runtime)
--
-- Keeping storage flat means UCI stays editable with `uci set` and the LuCI
-- editor has nothing nested to render. This is the piece upstream wrote in
-- ucode; here it is plain Lua 5.1.

local u = require "homeproxy.util"

local M = {}

--------------------------------------------------------------------- helpers

--- v2ray/xray share links describe transports through a shared vocabulary.
local function transport_fields(q, f)
	local net = q.type or q.net or "tcp"
	if net == "" or net == "tcp" or net == "none" or net == "raw" then
		return
	end

	if net == "ws" then
		f.transport = "ws"
		f.transport_path = q.path or "/"
		f.transport_host = q.host
	elseif net == "grpc" then
		f.transport = "grpc"
		f.transport_service_name = q.serviceName or q.path
		if f.transport_service_name == "/" then f.transport_service_name = nil end
	elseif net == "h2" or net == "http" then
		f.transport = "http"
		f.transport_path = q.path or "/"
		f.transport_host = q.host
	elseif net == "httpupgrade" then
		f.transport = "httpupgrade"
		f.transport_path = q.path or "/"
		f.transport_host = q.host
	elseif net == "quic" then
		f.transport = "quic"
	end
	-- Anything else is dropped rather than emitted as an invalid transport,
	-- which would make sing-box reject the entire config.
end

--- TLS-ish query parameters -> flat fields. `security` is the link's own field.
local function tls_fields(q, f, security)
	if security ~= "tls" and security ~= "reality" and security ~= "xtls" then
		return
	end

	f.tls = "1"

	local sni = q.sni or q.peer
	if sni and sni ~= "" then f.sni = sni end

	if u.to_bool(q.allowInsecure) or u.to_bool(q.insecure) or u.to_bool(q.skip_cert_verify) then
		f.insecure = "1"
	end

	if q.alpn and q.alpn ~= "" then f.alpn = q.alpn end

	if q.fp and q.fp ~= "" then
		f.fingerprint = q.fp
	elseif security == "reality" then
		f.fingerprint = "chrome"
	end

	if security == "reality" then
		f.reality_public_key = q.pbk or q.public_key
		f.reality_short_id = q.sid
	end
end

--------------------------------------------------------------------- parsers
-- Each parser returns a flat field table plus the display name.

local function parse_ss(uri)
	local body, frag = uri:match("^ss://([^#]*)#?(.*)$")
	if not body then return nil end
	local name = u.url_decode(frag or "")

	local f = { type = "shadowsocks", name = name }

	-- SIP002: ss://base64(method:password)@host:port?plugin=...
	local userinfo, hostport, qs = body:match("^([^@]+)@([^%?]+)%??(.*)$")
	if userinfo then
		local decoded = u.b64_decode(userinfo) or u.url_decode(userinfo)
		if not decoded then return nil end
		f.method, f.password = decoded:match("^([^:]+):(.*)$")
		f.server, f.port = u.split_hostport(hostport)

		local q = u.parse_query(qs)
		if q.plugin and q.plugin ~= "" then
			f.ss_plugin = q.plugin
			f.ss_plugin_opts = q.plugin_opts
		end
		if not (f.method and f.server and f.port) then return nil end
		return f
	end

	-- Legacy: ss://base64(method:password@host:port)
	local decoded = u.b64_decode(body)
	if not decoded then return nil end
	local auth, hostport = decoded:match("^(.*)@([^@]+)$")
	if not auth then return nil end
	f.method, f.password = auth:match("^([^:]+):(.*)$")
	f.server, f.port = u.split_hostport(hostport)
	if not (f.method and f.server and f.port) then return nil end
	return f
end

local function parse_vmess(uri)
	local body = uri:match("^vmess://([^#]*)")
	local json = u.b64_decode(body or "")
	if not json then return nil end

	local ok, v = pcall(function()
		return require("luci.jsonc").parse(json)
	end)
	if not ok or type(v) ~= "table" or not v.add then return nil end

	local f = {
		type = "vmess",
		name = v.ps,
		server = v.add,
		port = tonumber(v.port),
		uuid = v.id,
		alter_id = tostring(tonumber(v.aid) or 0),
		vmess_security = (v.scy and v.scy ~= "" and v.scy) or "auto",
	}

	transport_fields({ type = v.net, host = v.host, path = v.path, serviceName = v.path }, f)

	if v.tls == "tls" or v.tls == true then
		tls_fields({ sni = v.sni or v.host, alpn = v.alpn, fp = v.fp }, f, "tls")
	end

	return f
end

local function parse_vless(uri)
	local userinfo, hostport, qs, frag =
		uri:match("^vless://([^@]+)@([^%?]+)%??([^#]*)%#?(.*)$")
	if not userinfo then return nil end

	local q = u.parse_query(qs)
	local f = {
		type = "vless",
		name = u.url_decode(frag or ""),
		uuid = u.url_decode(userinfo),
		packet_encoding = "xudp",
	}
	f.server, f.port = u.split_hostport(hostport)

	if q.flow and q.flow ~= "" and q.flow ~= "none" then f.flow = q.flow end

	tls_fields(q, f, q.security or "none")
	transport_fields(q, f)

	return f
end

local function parse_trojan(uri)
	local userinfo, hostport, qs, frag =
		uri:match("^trojan://([^@]+)@([^%?]+)%??([^#]*)%#?(.*)$")
	if not userinfo then return nil end

	local q = u.parse_query(qs)
	local f = {
		type = "trojan",
		name = u.url_decode(frag or ""),
		password = u.url_decode(userinfo),
	}
	f.server, f.port = u.split_hostport(hostport)

	if q.security == "none" then
		f.tls = "1"
		f.sni = q.sni
		if u.to_bool(q.allowInsecure) then f.insecure = "1" end
	else
		tls_fields(q, f, "tls")
		f.tls = f.tls or "1"
	end
	f.sni = f.sni or f.server

	transport_fields(q, f)

	return f
end

local function parse_hysteria2(uri)
	-- Both hysteria2:// and hy2:// reach here. The auth component is matched
	-- non-greedily so a password containing '@' still resolves.
	local auth, hostport, qs, frag =
		uri:match("^h[^:]+://(.-)@([^%?]+)%??([^#]*)%#?(.*)$")
	if not auth then return nil end

	local q = u.parse_query(qs)
	local f = {
		type = "hysteria2",
		name = u.url_decode(frag or ""),
		password = u.url_decode(auth),
	}
	f.server, f.port = u.split_hostport(hostport)
	f.port = f.port or 443

	if q.obfs == "salamander" and q["obfs-password"] and q["obfs-password"] ~= "" then
		f.obfs_type = "salamander"
		f.obfs_password = q["obfs-password"]
	end

	tls_fields(q, f, "tls")
	f.tls = "1"
	f.sni = f.sni or f.server

	return f
end

local function parse_tuic(uri)
	local userinfo, hostport, qs, frag =
		uri:match("^tuic://([^@]+)@([^%?]+)%??([^#]*)%#?(.*)$")
	if not userinfo then return nil end

	local q = u.parse_query(qs)
	local uuid, password = u.url_decode(userinfo):match("^(.-):(.*)$")

	local f = {
		type = "tuic",
		name = u.url_decode(frag or ""),
		uuid = uuid,
		password = password,
	}
	f.server, f.port = u.split_hostport(hostport)
	f.port = f.port or 443

	f.congestion_control = q.congestion_control or "bbr"
	f.udp_relay_mode = q.udp_relay_mode or "native"

	tls_fields(q, f, "tls")
	f.tls = "1"
	f.alpn = q.alpn or "h3"
	f.sni = f.sni or f.server

	return f
end

local function parse_socks(uri)
	local body, frag = uri:match("^socks5?://([^#]*)#?(.*)$")
	if not body then return nil end

	local creds, hostport = body:match("^(.*)@([^@]+)$")
	if not hostport then hostport = body end

	local f = {
		type = "socks",
		name = u.url_decode(frag or ""),
	}
	f.server, f.port = u.split_hostport(hostport)
	f.port = f.port or 1080

	if creds then
		local decoded = u.b64_decode(creds) or u.url_decode(creds)
		if decoded then f.username, f.password = decoded:match("^(.-):(.*)$") end
	end

	return f
end

local function parse_http(uri)
	local body, frag = uri:match("^https?://([^#]*)#?(.*)$")
	if not body then return nil end

	local creds, hostport = body:match("^(.*)@([^@]+)$")
	if not hostport then hostport = body end

	local f = {
		type = "http",
		name = u.url_decode(frag or ""),
	}
	f.server, f.port = u.split_hostport(hostport)
	f.port = f.port or 80

	if creds then
		local decoded = u.b64_decode(creds) or u.url_decode(creds)
		if decoded then f.username, f.password = decoded:match("^(.-):(.*)$") end
	end

	return f
end

local PARSERS = {
	["ss"] = parse_ss,
	["vmess"] = parse_vmess,
	["vless"] = parse_vless,
	["trojan"] = parse_trojan,
	["hysteria2"] = parse_hysteria2,
	["hy2"] = parse_hysteria2,
	["tuic"] = parse_tuic,
	["socks"] = parse_socks,
	["socks5"] = parse_socks,
	["http"] = parse_http,
	["https"] = parse_http,
}

--- Parse one share link into flat fields.
-- @return fields table or nil, error string
function M.parse_link(link)
	if type(link) ~= "string" then return nil, "empty link" end
	link = u.trim(link)
	if link == "" then return nil, "empty link" end

	local scheme = link:lower():match("^([a-z0-9]+)://")
	if not scheme then return nil, "no scheme" end

	local parser = PARSERS[scheme]
	if not parser then return nil, "unsupported scheme: " .. scheme end

	local f = parser(link)
	if not f then return nil, "malformed " .. scheme .. " link" end
	if not f.server or f.server == "" or not f.port then
		return nil, "missing server or port"
	end

	f.name = u.trim(f.name or "")
	if f.name == "" then
		f.name = string.format("%s-%s:%d", f.type, f.server, f.port)
	end

	return f
end

--- Parse a subscription body: one link per line. Blank lines and '#' comments
--- are skipped silently; every other non-empty line is attempted, and anything
--- unparseable is reported. Reporting stray lines matters in practice -- an
--- expired subscription typically answers with an HTML error page, and
--- "0 nodes imported" alone tells the user nothing about why.
-- @return list of field tables, list of failure descriptions
--- One pass over a subscription body: one share link per line.
--- Appends to good/bad and returns the number of nodes found.
local function scan_lines(body, good, bad)
	for line in body:gmatch("[^\r\n]+") do
		local l = u.trim(line)
		if l ~= "" and not l:match("^#") then
			local f, err = M.parse_link(l)
			if f then
				good[#good + 1] = f
			else
				bad[#bad + 1] = string.sub(l, 1, 48) .. " ... (" .. (err or "?") .. ")"
			end
		end
	end
	return #good
end

function M.parse_subscription(body)
	local good, bad = {}, {}
	if type(body) ~= "string" then return good, bad end

	scan_lines(body, good, bad)

	-- Most providers return the whole list as one base64 blob rather than one
	-- link per line. The line-by-line pass then sees a single enormous line
	-- and reports it as "no scheme", importing nothing -- which reads exactly
	-- like an expired account in the log.
	--
	-- Only decode when the plain pass found nothing, and only accept the
	-- result if it actually yields nodes: a normal plaintext body is never
	-- reinterpreted, and a genuinely broken body still reports as unreadable
	-- instead of silently "succeeding" with an empty list.
	if #good == 0 then
		local decoded = u.b64_decode(body)
		if decoded and decoded:find("://", 1, true) then
			local g2, b2 = {}, {}
			if scan_lines(decoded, g2, b2) > 0 then
				return g2, b2
			end
		end
	end

	return good, bad
end

--------------------------------------------------------------------- builder

local function build_tls(f)
	if not u.to_bool(f.tls) then return nil end

	local tls = { enabled = true }
	if f.sni and f.sni ~= "" then tls.server_name = f.sni end
	if u.to_bool(f.insecure) then tls.insecure = true end
	if f.alpn and f.alpn ~= "" then tls.alpn = u.split(f.alpn, ",") end
	if f.fingerprint and f.fingerprint ~= "" then
		tls.utls = { enabled = true, fingerprint = f.fingerprint }
	end
	if f.reality_public_key and f.reality_public_key ~= "" then
		tls.utls = tls.utls or { enabled = true, fingerprint = "chrome" }
		tls.reality = {
			enabled = true,
			public_key = f.reality_public_key,
			short_id = f.reality_short_id,
		}
	end

	return tls
end

local function build_transport(f)
	local t = f.transport
	if not t or t == "" or t == "tcp" or t == "none" then return nil end

	if t == "ws" then
		local o = { type = "ws", path = f.transport_path or "/" }
		if f.transport_host and f.transport_host ~= "" then
			o.headers = { Host = f.transport_host }
		end
		return o
	elseif t == "grpc" then
		return { type = "grpc", service_name = f.transport_service_name }
	elseif t == "http" then
		local o = { type = "http", path = f.transport_path or "/" }
		if f.transport_host and f.transport_host ~= "" then
			o.host = u.split(f.transport_host, ",")
		end
		return o
	elseif t == "httpupgrade" then
		return { type = "httpupgrade", host = f.transport_host, path = f.transport_path or "/" }
	elseif t == "quic" then
		return { type = "quic" }
	end

	return nil
end

--- Flat fields -> sing-box outbound. Returns nil for an unusable node.
function M.build_outbound(f, tag)
	local typ = f.type
	if not typ or typ == "" then return nil end
	if not f.server or f.server == "" or not f.port then return nil end

	local ob = { type = typ, tag = tag or f.tag or f.name }

	if typ == "shadowsocks" then
		ob.server = f.server
		ob.server_port = tonumber(f.port)
		ob.method = f.method
		ob.password = f.password
		if f.ss_plugin and f.ss_plugin ~= "" then
			ob.plugin = f.ss_plugin
			ob.plugin_opts = f.ss_plugin_opts
		end
		return ob
	end

	ob.server = f.server
	ob.server_port = tonumber(f.port)

	if typ == "vmess" then
		ob.uuid = f.uuid
		ob.security = f.vmess_security or "auto"
		ob.alter_id = tonumber(f.alter_id) or 0
		ob.tls = build_tls(f)
		ob.transport = build_transport(f)
	elseif typ == "vless" then
		ob.uuid = f.uuid
		ob.packet_encoding = f.packet_encoding or "xudp"
		if f.flow and f.flow ~= "" and f.flow ~= "none" then ob.flow = f.flow end
		ob.tls = build_tls(f)
		ob.transport = build_transport(f)
	elseif typ == "trojan" then
		ob.password = f.password
		ob.tls = build_tls(f) or { enabled = true, server_name = f.server }
		ob.transport = build_transport(f)
	elseif typ == "hysteria2" then
		ob.password = f.password
		-- A password is enough to mean salamander.
		--
		-- This required `f.obfs_type == "salamander"`, and obfs_type is set in
		-- exactly one place -- the link parser (see obfs_type in parse_link).
		-- The node form offers an "Obfs Password" field and no other way to
		-- express obfs, so a hysteria2 node typed in by hand took the password,
		-- saved it, and then had it dropped here: the outbound went out without
		-- obfs, the server rejected the handshake, and nothing on the page said
		-- the field had been ignored. sing-box has one obfs type for hysteria2,
		-- so the presence of a password is the whole choice; only an explicit
		-- different type is honoured as "no obfs".
		if f.obfs_password and f.obfs_password ~= ""
			and (not f.obfs_type or f.obfs_type == "" or f.obfs_type == "salamander") then
			ob.obfs = { type = "salamander", password = f.obfs_password }
		end
		ob.tls = build_tls(f) or { enabled = true, server_name = f.server }
	elseif typ == "tuic" then
		ob.uuid = f.uuid
		ob.password = f.password
		ob.congestion_control = f.congestion_control or "bbr"
		ob.udp_relay_mode = f.udp_relay_mode or "native"
		local tls = build_tls(f) or { enabled = true }
		tls.alpn = u.split(f.alpn or "h3", ",")
		ob.tls = tls
	elseif typ == "socks" then
		ob.version = "5"
		ob.username = f.username
		ob.password = f.password
	elseif typ == "http" then
		ob.username = f.username
		ob.password = f.password
		ob.tls = build_tls(f)
	else
		return nil
	end

	return ob
end

return M
