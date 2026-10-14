-- End-to-end harness: reproduce exactly what /etc/init.d/homeproxy does,
-- but from a synthetic section table so nothing on the device is touched.
package.path = "/tmp/hp-test/lib/?.lua;/tmp/hp-test/lib/?/init.lua;/usr/lib/lua/?.lua;" .. package.path

local loader  = require "homeproxy.uci_loader"
local confgen = require "homeproxy.confgen"
local util    = require "homeproxy.util"
local nodes   = require "homeproxy.nodes"

local ok, jsonc = pcall(require, "luci.jsonc")
if not ok then
	io.stderr:write("FATAL: luci.jsonc not available: " .. tostring(jsonc) .. "\n")
	os.exit(2)
end

-- Mirrors the shipped /etc/config/homeproxy verbatim.
local sections = {
	global = {
		type = "global", enabled = "0", proxy_mode = "rule", default_node = "",
		log_level = "warn", tcp_fast_open = "1", sniff = "1", sniff_override = "1",
		ipv6 = "1", dns_hijack = "1", clash_api = "1", clash_port = "9090",
		routing_mark = "2",
	},
	inbound = {
		type = "inbound", tproxy_port = "5330",
		lan_interface = "br-lan", udp_timeout = "5m",
	},
	actions = { type = "actions", _placeholder = "1" },
	dns = {
		type = "dns", strategy = "prefer_ipv4", local_dns = "223.5.5.5",
		remote_dns = "https://1.1.1.1/dns-query",
		rule_set_base = "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo",
		rule_set_interval = "7d",
	},
}

local mode = arg[1] or "empty"

if mode == "noded" then
	-- A realistic vless+reality node, as the subscription importer would store it.
	local f = nodes.parse_link(
		"vless://11111111-2222-3333-4444-555555555555@example.com:443" ..
		"?encryption=none&flow=xtls-rprx-vision&security=reality" ..
		"&sni=www.microsoft.com&fp=chrome&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ..
		"&sid=0123abcd&type=tcp#Test%20Node")
	if not f then
		io.stderr:write("FATAL: node link failed to parse\n")
		os.exit(3)
	end
	-- libuci exposes the UCI section type as ".type" and section name as
	-- ".name"; the sing-box protocol lives in the plain "type" option.
	f[".type"] = "node"
	f[".name"] = "node1"
	sections.node1 = f
	sections.global.default_node = "node1"

	-- And a shadowsocks node, to exercise the ss branch.
	local g = nodes.parse_link("ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@ss.example.net:8388#SS%20Node")
	if g then
		g[".type"] = "node"
		g[".name"] = "node2"
		sections.node2 = g
	end
end

local cfg = loader.from_sections(sections)
local config = confgen.build(cfg)

local json = jsonc.stringify(config, true)
if type(json) ~= "string" or json == "" then
	io.stderr:write("FATAL: serialisation produced nothing\n")
	os.exit(4)
end

io.write(json, "\n")
io.stderr:write(string.format("OK: %d bytes, %d node(s), mode=%s\n",
	#json, #(cfg.nodes or {}), tostring((cfg.global or {}).proxy_mode)))
