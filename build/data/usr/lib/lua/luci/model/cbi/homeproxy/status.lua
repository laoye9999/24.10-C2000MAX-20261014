-- SPDX-License-Identifier: GPL-2.0
-- Client settings. Mirrors the `global`, `inbound` and `dns` sections of
-- /etc/config/homeproxy.

local m, s, o

m = Map("homeproxy", translate("HomeProxy Status"),
	translate("Transparent proxy client based on sing-box."))


-- The wrapper draws the child-page tab strip, except when the active theme
-- draws one itself; the test for that is in view/homeproxy/nav.htm.
m.template = "homeproxy/map"
--------------------------------------------------------------------- global

s = m:section(TypedSection, "global", translate("Global Settings"))
s.anonymous = true
s.addremove = false

o = s:option(Flag, "enabled", translate("Enable"),
	translate("Start the proxy and install the transparent proxy rules."))
o.rmempty = false

-- Not a UCI option: the boot-time state lives in /etc/rc.d, so this reads and
-- writes the symlink directly instead of storing anything.
o = s:option(Flag, "_autostart", translate("Start on Boot"),
	translate("Without this the proxy stays off after a reboot, even though " ..
		"it is enabled above."))
o.rmempty = false
function o.cfgvalue(self, section)
	return luci.sys.call("ls /etc/rc.d/S*homeproxy >/dev/null 2>&1") == 0 and "1" or "0"
end
function o.write(self, section, value)
	local verb = (value == "1") and "enable" or "disable"
	luci.sys.call("/etc/init.d/homeproxy " .. verb .. " >/dev/null 2>&1")
end

o = s:option(ListValue, "proxy_mode", translate("Proxy Mode"))
o:value("rule", translate("Rule - mainland direct, everything else proxied"))
o:value("global", translate("Global - everything proxied"))
o:value("direct", translate("Direct - nothing proxied"))
o.default = "rule"
o.rmempty = false

o = s:option(ListValue, "default_node", translate("Default Node"),
	translate("Used until you pick another one on the status page."))
do
	local uci = require("luci.model.uci").cursor()
	uci:foreach("homeproxy", "node", function(sec)
		o:value(sec[".name"], sec.name or sec[".name"])
	end)
end
o.rmempty = true

o = s:option(ListValue, "log_level", translate("Log Level"))
for _, lv in ipairs({ "trace", "debug", "info", "warn", "error", "fatal" }) do
	o:value(lv)
end
o.default = "warn"
o.rmempty = false

-- These two live in `global`, and are declared here rather than further down
-- in the Inbound section where they used to be.
--
-- The section an option is declared in is the section LuCI writes it to, and
-- the generator reads both of these from `global` (see the two
-- get(cfg.global, ...) calls in confgen.lua). Declared under `inbound` they
-- wrote homeproxy.inbound.dns_hijack / .sniff_override, which nothing has
-- ever read: flipping either switch saved a value and changed no behaviour.
o = s:option(Flag, "dns_hijack", translate("Intercept DNS"),
	translate("Answer LAN clients' port-53 queries from sing-box so polluted " ..
		"answers are never used for proxied domains. On this firmware the " ..
		"vendor's own dns_redirect sends every UDP query to the router's " ..
		"dnsmasq before sing-box can see it, so UDP is answered there " ..
		"regardless and only TCP queries are intercepted here."))
o.rmempty = false

o = s:option(Flag, "sniff_override", translate("Sniff Override"),
	translate("Dial the domain recovered from the TLS handshake instead of the " ..
		"address the client connected to. Required here: clients resolve through " ..
		"dnsmasq, which returns polluted answers for blocked domains, so turning " ..
		"this off makes every foreign site time out while mainland sites work."))
o.default = "1"
o.rmempty = false

-- Declared on the `global` section, because that is where firewall.sh reads it
-- from (`uci -q get homeproxy.global.self_proxy`). An option declared in the
-- wrong section is written somewhere nothing reads, which is the dns_hijack /
-- sniff_override failure spelled out above -- and this one would present as
-- the switch simply not doing anything.
o = s:option(Flag, "self_proxy", translate("Proxy Router's Own Traffic"),
	translate("Capture what the router itself originates, not only what the LAN " ..
		"forwards. DNS, NTP and the router's own addresses are always left " ..
		"direct, because the tunnel needs to resolve its node and validate its " ..
		"own certificates. While this is on, a proxy that is down takes the " ..
		"router's own connections with it."))
o.default = "0"
o.rmempty = false

--------------------------------------------------------------------- inbound

s = m:section(TypedSection, "inbound", translate("Inbound"))
s.anonymous = true
s.addremove = false

o = s:option(Value, "lan_interface", translate("LAN Interface"),
	translate("Only traffic forwarded from this interface is proxied. " ..
		"Traffic the router itself originates is never captured."))
o.default = "br-lan"
o.rmempty = false

o = s:option(Value, "tproxy_port", translate("TPROXY Port"))
o.datatype = "port"
o.default = "5330"

o = s:option(Value, "udp_timeout", translate("UDP Timeout"))
o.default = "5m"

--------------------------------------------------------------------- dns

s = m:section(TypedSection, "dns", translate("DNS"))
s.anonymous = true
s.addremove = false

o = s:option(ListValue, "strategy", translate("Domain Strategy"))
o:value("prefer_ipv4", translate("Prefer IPv4"))
o:value("prefer_ipv6", translate("Prefer IPv6"))
o:value("ipv4_only", translate("IPv4 only"))
o:value("ipv6_only", translate("IPv6 only"))
o.default = "prefer_ipv4"

o = s:option(Value, "local_dns", translate("Local DNS"),
	translate("Used for mainland domains and for resolving node server names."))
o.datatype = "ip4addr"
o.default = "223.5.5.5"

o = s:option(Value, "remote_dns", translate("Remote DNS"),
	translate("Used for proxied domains, reached through the proxy. " ..
		"Accepts udp, tls://, https:// and quic:// forms."))
o.default = "https://1.1.1.1/dns-query"

o = s:option(Value, "rule_set_base", translate("Rule Set Source"),
	translate("Base URL the .srs routing rule sets are fetched from. " ..
		"The default jsDelivr mirror is reachable from mainland networks."))
o.default = "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo"

o = s:option(Value, "rule_set_interval", translate("Rule Set Update Interval"))
o.default = "7d"

--------------------------------------------------------------------- apply

function m.on_after_commit(self)
	-- A settings change is only meaningful once the daemon has been
	-- restarted with the regenerated config.
	luci.sys.call("/etc/init.d/homeproxy restart >/dev/null 2>&1")
end

return m
