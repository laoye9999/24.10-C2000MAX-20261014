-- SPDX-License-Identifier: GPL-2.0
-- homeproxy 21.02 backport -- sing-box configuration generator.
--
-- M.build(cfg) is a translation, not a pure function: a plain Lua table in, a
-- sing-box config table out. It does not read UCI itself -- gen_config.lua
-- supplies that -- but it does stat the rule-set files, because `type: local`
-- versus `type: remote` is decided by whether the file on disk is actually
-- usable (usable_rule_set below). Both halves are still testable off-device:
-- with cfg.subscriptions-style tables in, and with a rule-set directory
-- pointed at somewhere real.
--
-- The header used to claim it "never reads UCI or touches the filesystem". It
-- has opened rule-set files since they moved to local copies, and the claim was
-- the kind that stops the next reader looking for filesystem behaviour here --
-- which is where the local/remote fallback, and the failure mode it carries,
-- both live.
--
-- Target core: sing-box 1.12.x.

local nodes = require "homeproxy.nodes"
local u = require "homeproxy.util"

local M = {}

--------------------------------------------------------------------- defaults

local DEFAULTS = {
	log_level = "warn",
	proxy_mode = "rule",          -- rule | global | direct
	tproxy_port = 5330,
	dns_port = 5331,
	lan_interface = "br-lan",
	udp_timeout = "5m",
	-- Capture IPv6 as well as IPv4. On by default: this device's ISP delegates
	-- a public prefix, and a client that reaches a blocked site over IPv6 --
	-- which it will prefer -- is not proxied at all, so the site simply fails
	-- instead of falling back to the proxied IPv4 path.
	ipv6 = true,
	-- SO_MARK applied to connections the direct outbound originates. Distinct
	-- from the TPROXY mark (1) so the two never collide.
	routing_mark = 2,
	sniff = true,
	-- Without this, sing-box sniffs the SNI to *route* the connection but
	-- still dials the original destination address. Clients here resolve
	-- through the router's dnsmasq, which returns poisoned answers for
	-- blocked domains, so the proxy would be asked to connect to a bogus IP
	-- and every foreign site would time out -- mainland sites unaffected.
	-- Upstream homeproxy defaults this on too.
	sniff_override = true,
	tcp_fast_open = true,
	route_final = "proxy",

	-- The key is the *UCI option name*, not the sing-box field it becomes:
	-- get() looks the default up under whatever key its caller passes. This
	-- one is spelled `strategy` -- see /etc/config/homeproxy's `config dns`
	-- section, and the ListValue on the status page that writes it.
	strategy = "prefer_ipv4",
	local_dns = "223.5.5.5",
	remote_dns = "https://1.1.1.1/dns-query",
	dns_hijack = true,

	-- Rule-set endpoints. GitHub raw is unreachable from most mainland
	-- networks, so the default goes through jsDelivr, which stays reachable.
	rule_set_base = "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo",
	rule_set_interval = "7d",
}

local function get(t, k)
	if t == nil then return DEFAULTS[k] end
	local v = t[k]
	if v == nil then return DEFAULTS[k] end
	return v
end

--- rule_set_interval, checked.
---
--- It is free text: the CBI field has no datatype, and get() passes both an
--- empty option and any typed-in string straight through. It is only ever
--- emitted for the `type: remote` rule-set fallback -- but there a value
--- sing-box cannot parse ("7 days", "1w", or a field the user cleared) fails
--- config *decode*, and decode failure is fatal at startup. So the one branch
--- that exists to make a bad local file survivable would be the branch that
--- stops the service from starting at all. A year is not a meaningful value
--- for this field either, so the bound is deliberately tight.
local function rule_set_interval(cfg)
	local v = get(cfg.dns, "rule_set_interval")
	if type(v) == "string" and v:match("^%d+[smhd]$") then return v end
	return DEFAULTS.rule_set_interval
end

local function num(v, fallback)
	local n = tonumber(v)
	if n == nil or n <= 0 or n > 65535 then return fallback end
	return n
end

--------------------------------------------------------------------- rule sets

--- The rule sets we route on. `file` is the upstream filename inside
--- geo/<kind>/, which drops the tag's prefix (geosite-cn -> geosite/cn.srs).
local RULE_SETS = {
	["geosite-cn"]              = { kind = "geosite", file = "cn" },
	["geosite-geolocation-!cn"] = { kind = "geosite", file = "geolocation-!cn" },
	["geoip-cn"]                = { kind = "geoip",   file = "cn" },
}

--- Where the downloaded rule sets live. Shipped in the package, and refreshed
--- in the background by /usr/share/homeproxy/update-rule-sets.sh.
local DEFAULT_RULE_SET_DIR = "/etc/homeproxy/rule_set"

--- Is this a rule set sing-box can actually load?
---
--- Existence alone is not enough. A download killed halfway leaves a short or
--- empty file, and sing-box treats that exactly like a missing one -- it fails
--- to start, which procd turns into a crash loop. So check the size and the
--- SRS magic before pointing the config at it; a rejected file falls back to
--- the remote form below, which can still succeed.
local function usable_rule_set(path)
	local fh = io.open(path, "rb")
	if not fh then return false end
	local head = fh:read(4)
	local size = fh:seek("end")
	fh:close()
	if type(head) ~= "string" or #head < 4 or (size or 0) < 512 then return false end
	return head:sub(1, 3) == "SRS"
end

--- Emit definitions for the named rule sets.
---
--- `dns.rule_set` and `route.rule_set` are separate namespaces: a DNS rule
--- referring to "geosite-cn" is an error unless that tag is declared under
--- `dns`, even when the same tag exists under `route`. So each consumer asks
--- for the sets it actually references.
---
--- A `type: local` entry when we have the file, `type: remote` when we do not.
--- Local is the normal case and it matters: sing-box resolves remote rule sets
--- during startup and *exits* if the fetch fails. On this device
--- cdn.jsdelivr.net is RST'd by the GFW, so a remote-only config in rule mode
--- could never start at all -- the service crash-looped until procd gave up.
--- Serving them from disk means a cold start needs no network whatsoever.
local function build_rule_sets(cfg, tags)
	local base = get(cfg.dns, "rule_set_base")
	local dir = get(cfg.dns, "rule_set_dir")
	if not dir or dir == "" then dir = DEFAULT_RULE_SET_DIR end
	local out = {}

	for _, tag in ipairs(tags) do
		local rs = RULE_SETS[tag]
		if rs then
			local path = dir .. "/" .. tag .. ".srs"
			if usable_rule_set(path) then
				out[#out + 1] = {
					type = "local",
					tag = tag,
					format = "binary",
					path = path,
				}
			else
				out[#out + 1] = {
					type = "remote",
					tag = tag,
					format = "binary",
					url = base .. "/" .. rs.kind .. "/" .. rs.file .. ".srs",
					update_interval = rule_set_interval(cfg),
					-- Rule-set fetches must survive a cold start, when the proxy
					-- may not be usable yet, so they always go out direct.
					download_detour = "direct",
				}
			end
		end
	end

	return out
end

--------------------------------------------------------------------- dns

local function build_dns(cfg, mode, has_proxy)
	local dns = {
		servers = {},
		rules = {},
		-- `strategy`, matching the UCI option. This read `dns_strategy`
		-- until it was noticed that no such option exists anywhere: the
		-- config file, the status page's ListValue and this generator now
		-- all say `strategy`, so the lookup always missed, always fell
		-- through to the default, and the Domain Strategy dropdown was
		-- inert -- it saved and redisplayed the choice and changed nothing
		-- about the generated config.
		strategy = get(cfg.dns, "strategy"),
		independent_cache = true,
	}

	dns.servers[#dns.servers + 1] = {
		tag = "dns-local",
		type = "udp",
		server = get(cfg.dns, "local_dns"),
		detour = "direct",
	}

	-- sing-box 1.12 splits the endpoint into `type` + `server` + `path`, and
	-- `server` must be a bare address: "https://1.1.1.1/dns-query" is rejected
	-- with "invalid server address". Decompose whatever the user configured.
	local remote = get(cfg.dns, "remote_dns")
	local scheme, rest = remote:match("^([%a][%w+%-.]*)://(.+)$")
	if not scheme then
		scheme, rest = "udp", remote
	end

	local hostport, path = rest:match("^([^/]+)(/.*)$")
	if not hostport then
		hostport, path = rest, nil
	end

	local remote_server = {
		tag = "dns-remote",
		type = scheme,
		server = hostport,
		detour = "proxy",
	}

	if scheme == "https" and path and path ~= "" then
		remote_server.path = path
	end

	-- An endpoint named by hostname still needs a plain resolver to bootstrap
	-- itself; the local one is always reachable.
	if not hostport:match("^%d+%.%d+%.%d+%.%d+$") then
		remote_server.domain_resolver = "dns-local"
	end

	-- Only registered when there is somewhere to send it. The remote resolver
	-- detours through the `proxy` outbound, and sing-box refuses to start at
	-- all if a DNS server detours to an outbound that does not exist -- which
	-- is the state every fresh install is in, before any node is configured.
	if has_proxy then
		dns.servers[#dns.servers + 1] = remote_server
	end

	if has_proxy and mode == "rule" then
		-- Mainland domains resolve locally, everything else through the proxy,
		-- so a poisoned answer never reaches the client for a proxied name.
		--
		-- There is no `dns.rule_set`: sing-box 1.12 rejects it as an unknown
		-- field. DNS rules resolve their `rule_set` tags against the top-level
		-- `route.rule_set`, so build_route declares these tags as well.
		dns.rules = {
			{ rule_set = { "geosite-cn" }, server = "dns-local" },
			{ rule_set = { "geosite-geolocation-!cn" }, server = "dns-remote" },
		}
		dns.final = "dns-local"
	elseif has_proxy and mode == "global" then
		-- Everything is proxied, so everything resolves remotely too.
		dns.rules = {}
		dns.final = "dns-remote"
	else
		-- No usable proxy (or direct mode): never send lookups into a tunnel
		-- that may not be up.
		dns.rules = {}
		dns.final = "dns-local"
	end

	return dns
end

--------------------------------------------------------------------- inbounds

local function build_inbounds(cfg)
	local port = num(get(cfg.inbound, "tproxy_port"), DEFAULTS.tproxy_port)

	local function tproxy(tag, listen)
		return {
			type = "tproxy",
			tag = tag,
			listen = listen,
			listen_port = port,
			-- sing-box wants network as a list here, not a "tcp,udp" string.
			network = { "tcp", "udp" },
			udp_timeout = get(cfg.inbound, "udp_timeout"),
			sniff = u.to_bool(get(cfg.global, "sniff")),
			-- Use the sniffed domain as the dial target, not the address the
			-- client actually connected to. See the note on DEFAULTS.
			sniff_override_destination = u.to_bool(get(cfg.global, "sniff_override")),
		}
	end

	local inbounds = { tproxy("tproxy-in", "0.0.0.0") }

	-- IPv6 needs its own inbound, not a wider listen address.
	--
	-- firewall.sh redirects v6 flows to [::1]:port, and a socket bound to
	-- 0.0.0.0 is a v4 socket -- it never receives them. Widening this one to
	-- "::" instead would depend on the kernel not setting IPV6_V6ONLY, which
	-- Go decides for itself; two explicit listeners have no such ambiguity.
	--
	-- Only declared when the firewall will actually install the v6 rules, so
	-- a v4-only line does not end up with a listener nothing feeds.
	if u.to_bool(get(cfg.global, "ipv6")) then
		inbounds[#inbounds + 1] = tproxy("tproxy-in6", "::1")
	end

	-- DNS deliberately gets no inbound of its own.
	--
	-- LAN port-53 traffic is already captured here along with everything else:
	-- the TPROXY rule sends it to this same port, `sniff` recognises it as DNS,
	-- and the {"protocol":"dns","action":"hijack-dns"} route rule answers it
	-- from the dns block. A separate DNS inbound plus a nat REDIRECT would mean
	-- the packet is handled twice -- marked in mangle and re-destinationed in
	-- nat -- and the two paths fight; the query ends up dialled as an ordinary
	-- connection to the upstream resolver and hangs.
	--
	-- Note the ordering that makes this safe: queries aimed at the router's own
	-- dnsmasq have a private destination, and the firewall RETURNs those before
	-- TPROXY ever sees them, so LAN name resolution keeps working.

	return inbounds
end

--------------------------------------------------------------------- outbounds

local function build_outbounds(cfg)
	local outbounds, tags = {}, {}
	local used, tag_of = {}, {}

	-- Seed the dedup with the tags this generator emits itself.
	--
	-- The loop below disambiguates on exactly this ground -- "sing-box rejects
	-- duplicate tags" -- but `used` was only ever consulted for *nodes*, and the
	-- fixed outbounds are appended afterwards without looking at it at all. So a
	-- node whose display name is "direct", "block" or "proxy" produced two
	-- outbounds with that tag; sing-box refuses to register the second
	-- ("duplicate outbound tag") and the process exits during construction,
	-- which procd respawns into a crash loop -- the "started it and nothing
	-- happened" presentation, with nothing in LuCI to explain it. It does not
	-- take two nodes: one node named "direct" is enough.
	--
	-- Keep this list in step with the fixed outbounds below: direct (line ~357),
	-- block (~362) and the proxy selector (~378).
	for _, reserved in ipairs({ "direct", "block", "proxy" }) do
		used[reserved] = true
	end

	for _, node in ipairs(cfg.nodes or {}) do
		local section = node.tag or node.name
		if section and section ~= "" then
			-- The outbound tag is what the Clash API reports, and therefore
			-- what the node picker in LuCI shows. Prefer the human-readable
			-- name over the UCI section id, which looks like "cfg0446ab".
			local preferred = node.name
			if not preferred or preferred == "" then preferred = section end

			local tag = tostring(preferred)
			if used[tag] then
				-- Names are not unique, and sing-box rejects duplicate tags,
				-- so disambiguate rather than emit an invalid config.
				local base, n = tag, 2
				while used[base .. " #" .. n] do n = n + 1 end
				tag = base .. " #" .. n
			end
			used[tag] = true
			tag_of[section] = tag

			local ob = nodes.build_outbound(node, tag)
			if ob then
				-- Nodes given as hostnames need a resolver of their own.
				if not tostring(ob.server):match("^%d+%.%d+%.%d+%.%d+$")
					and not tostring(ob.server):match(":") then
					ob.domain_resolver = "dns-local"
				end
				if u.to_bool(get(cfg.global, "tcp_fast_open")) then
					ob.tcp_fast_open = true
				end
				outbounds[#outbounds + 1] = ob
				tags[#tags + 1] = tag
			end
		end
	end

	-- The direct outbound must carry `routing_mark`, not just a type and tag.
	-- sing-box refuses to start with "detour to an empty direct outbound makes
	-- no sense" when a DNS server detours here through a bare `direct` -- a
	-- check that `sing-box check` does not perform, so this only shows up at
	-- runtime. The mark also keeps traffic the direct outbound originates from
	-- being re-captured, which is the same trick upstream uses.
	outbounds[#outbounds + 1] = {
		type = "direct",
		tag = "direct",
		routing_mark = tonumber(get(cfg.global, "routing_mark")) or DEFAULTS.routing_mark,
	}
	outbounds[#outbounds + 1] = { type = "block", tag = "block" }

	if #tags > 0 then
		-- default_node is stored as a UCI section name; translate it to
		-- whichever tag that node actually ended up with.
		local default = tag_of[get(cfg.global, "default_node")]
			or get(cfg.global, "default_node")
		if not default or default == "" then default = tags[1] end
		local known = false
		for _, t in ipairs(tags) do
			if t == default then known = true end
		end
		if not known then default = tags[1] end

		outbounds[#outbounds + 1] = {
			type = "selector",
			tag = "proxy",
			outbounds = tags,
			default = default,
		}
	end

	return outbounds, tags
end

--------------------------------------------------------------------- route

local function build_route(cfg, node_tags)
	local mode = get(cfg.global, "proxy_mode")
	local has_proxy = #node_tags > 0

	local rules = {}

	-- DNS interception must come first: a hijacked query resolves through the
	-- dns block, whose own rules already separate local from remote lookups.
	if u.to_bool(get(cfg.global, "dns_hijack")) then
		rules[#rules + 1] = { protocol = "dns", action = "hijack-dns" }
	end

	-- Never proxy traffic that is already local to the LAN.
	rules[#rules + 1] = { ip_is_private = true, outbound = "direct" }

	local final
	if not has_proxy then
		final = "direct"
	elseif mode == "direct" then
		final = "direct"
	elseif mode == "global" then
		final = "proxy"
	else
		-- rule mode: mainland addresses go direct, the rest through the proxy.
		rules[#rules + 1] = { rule_set = { "geoip-cn" }, outbound = "direct" }
		rules[#rules + 1] = { rule_set = { "geosite-cn" }, outbound = "direct" }
		final = "proxy"
	end

	return {
		rules = rules,
		-- Declared here rather than under `dns`: route and DNS rules share this
		-- one registry, and a tag referenced by a DNS rule but missing here
		-- fails at startup with "rule-set not found".
		rule_set = (has_proxy and mode == "rule")
			and build_rule_sets(cfg, { "geoip-cn", "geosite-cn", "geosite-geolocation-!cn" })
			or {},
		final = final,
		auto_detect_interface = true,
		-- Without this, sing-box 1.12 warns on every outbound that lacks its
		-- own domain_resolver, and the fallback behaviour is removed in 1.14.
		-- Outbound server names resolve through the local resolver, which is
		-- always reachable even when the proxy itself is not.
		default_domain_resolver = "dns-local",
	}
end

--------------------------------------------------------------------- entry point

--- Build a sing-box configuration table from a plain settings table.
-- @param cfg table with keys: global, inbound, dns, nodes (see gen_config.lua)
-- @return config table, or nil plus an error string
function M.build(cfg)
	cfg = cfg or {}

	local mode = get(cfg.global, "proxy_mode")
	local outbounds, node_tags = build_outbounds(cfg)
	local has_proxy = #node_tags > 0

	local config = {
		log = {
			level = get(cfg.global, "log_level"),
			timestamp = true,
		},
		dns = build_dns(cfg, mode, has_proxy),
		inbounds = build_inbounds(cfg),
		outbounds = outbounds,
		route = build_route(cfg, node_tags),
		experimental = {
			-- Persisted so rule sets survive a reboot instead of being
			-- re-fetched on every cold start. Rewritten at most once per
			-- rule_set_interval, so the flash cost is negligible.
			cache_file = {
				enabled = true,
				path = "/etc/homeproxy/cache.db",
			},
		},
	}

	-- The Clash API drives the node-switching and traffic views in LuCI.
	if u.to_bool(get(cfg.global, "clash_api")) then
		config.experimental.clash_api = {
			external_controller = "127.0.0.1:" .. tostring(num(
				get(cfg.global, "clash_port"), 9090)),
			default_mode = "rule",
		}
	end

	return config
end

--- Convenience wrapper: build and serialise with the router's luci.jsonc.
function M.build_json(cfg)
	local config = M.build(cfg)
	if not config then return nil end
	return require("luci.jsonc").stringify(config, true)
end

M.DEFAULTS = DEFAULTS

return M
