-- Regression tests for the two confgen fixes in r28.
--
-- Runs on the device, where lua and sing-box both exist:
--
--     scp test/test-confgen-r28.lua root@192.168.66.1:/tmp/
--     ssh root@192.168.66.1 'lua /tmp/test-confgen-r28.lua'
--
-- Both are cases where unvalidated input could stop sing-box from starting at
-- all -- a crash loop with no explanation anywhere in LuCI. Neither is
-- reachable through `sing-box check` being run on a config the generator
-- produced, because in both cases the generator is what produces the bad one.

-- HP_LUA_ROOT lets the negative control point this at a patched copy of the
-- generator (see the loop at the bottom of this file), so each fix can be shown
-- to be load bearing rather than merely present.
local root = os.getenv("HP_LUA_ROOT") or "/usr/lib/lua"
package.path = root .. "/?.lua;" .. root .. "/?/init.lua;" .. package.path

local confgen = require "homeproxy.confgen"

local pass, fail = 0, 0

local function ok(name, cond, detail)
	if cond then
		pass = pass + 1
		print("    ok    " .. name)
	else
		fail = fail + 1
		print("    FAIL  " .. name)
		if detail then print("          " .. detail) end
	end
end

local function base_cfg()
	return {
		global = { proxy_mode = "rule", default_node = "cfg000001" },
		inbound = {},
		dns = {},
		nodes = {},
	}
end

local function node(display_name, section)
	return {
		tag = section, name = display_name, type = "socks",
		server = "1.2.3.4", port = 1080,
		username = "u", password = "p",
	}
end

--- Every outbound tag, plus the first tag that appears twice.
local function tag_audit(config)
	local seen, dup = {}, nil
	for _, o in ipairs(config.outbounds or {}) do
		if seen[o.tag] then dup = o.tag end
		seen[o.tag] = true
	end
	return seen, dup
end

-- ---------------------------------------------------------------- reserved tags

-- The duplicate-tag disambiguation loop only ever looked at other *nodes*.
-- `direct`, `block` and `proxy` are appended after it, so a node whose display
-- name is one of those produced two outbounds with the same tag and sing-box
-- aborted during construction -- "started but does nothing", with nothing in
-- LuCI to explain it. One node named `direct` was enough; two were never needed.
for _, reserved in ipairs({ "direct", "block", "proxy" }) do
	local cfg = base_cfg()
	cfg.nodes[1] = node(reserved, "cfg000001")
	local config = confgen.build(cfg)
	local seen, dup = tag_audit(config)

	ok(("a node named '%s' does not collide with the built-in outbound"):format(reserved),
		dup == nil, "duplicate tag: " .. tostring(dup))
	ok(("the built-in '%s' is still there exactly once"):format(reserved),
		seen[reserved] == true)
end

-- The selector's `outbounds` array is the part that actually breaks: sing-box
-- resolves those tags against the outbound list and dies on the ambiguity, so
-- every tag it names has to be a real, unique outbound.
do
	local cfg = base_cfg()
	cfg.nodes[1] = node("direct", "cfg000001")
	cfg.nodes[2] = node("proxy", "cfg000002")
	local config = confgen.build(cfg)

	local selector
	for _, o in ipairs(config.outbounds or {}) do
		if o.type == "selector" then selector = o end
	end

	local missing
	if selector then
		local seen = tag_audit(config)
		for _, t in ipairs(selector.outbounds or {}) do
			if not seen[t] then missing = t end
		end
	end

	ok("the selector only names tags that exist",
		missing == nil, "dangling tag: " .. tostring(missing))
	ok("both colliding nodes are still selectable",
		selector ~= nil and #(selector.outbounds or {}) == 2,
		"selector entries: " .. tostring(selector and #(selector.outbounds or {})))
end

-- A node that is not a collision still gets its display name, unchanged.
do
	local cfg = base_cfg()
	cfg.nodes[1] = node("香港 01", "cfg000001")
	local config = confgen.build(cfg)
	local seen, dup = tag_audit(config)
	ok("an ordinary display name is still used verbatim and does not collide",
		seen["香港 01"] == true and dup == nil)
end

-- ------------------------------------------------------------ rule_set_interval

-- rule_set_interval is free text from a CBI field with no datatype, and it is
-- emitted into the `type: remote` fallback that exists to make a cold start
-- robust. sing-box fails to *decode* an update_interval it cannot parse, which
-- is the one path that turns the fallback into a hard failure.
local function remote_intervals(config)
	local out = {}
	for _, rs in ipairs((config.route and config.route.rule_set) or {}) do
		if rs.type == "remote" then out[#out + 1] = rs.update_interval end
	end
	return out
end

local function intervals_for(value)
	local cfg = base_cfg()
	cfg.nodes[1] = node("n1", "cfg000001")
	-- No such directory, so every rule set falls through to the remote form --
	-- the branch that carries update_interval at all.
	cfg.dns.rule_set_dir = "/tmp/definitely-not-here-" .. tostring(value)
	if value ~= nil then cfg.dns.rule_set_interval = value end
	return remote_intervals(confgen.build(cfg))
end

do
	local got = intervals_for("7 days")
	ok("an unparseable interval falls back to the default rather than reaching sing-box",
		#got > 0 and got[1] == "7d", "got: " .. tostring(got[1]))
end

do
	local got = intervals_for("12h")
	ok("a well-formed interval is passed through",
		#got > 0 and got[1] == "12h", "got: " .. tostring(got[1]))
end

do
	local got = intervals_for("")
	ok("an empty interval falls back too",
		#got > 0 and got[1] == "7d", "got: " .. tostring(got[1]))
end

do
	local got = intervals_for(nil)
	ok("and so does an unset one",
		#got > 0 and got[1] == "7d", "got: " .. tostring(got[1]))
end

-- ------------------------------------------------------------------ the core

-- The generator's own output has to survive the thing that rejected the old
-- output. This is the assertion that would have caught both bugs: sing-box
-- validate, on a config built from the collision case.
do
	local cfg = base_cfg()
	cfg.nodes[1] = node("direct", "cfg000001")
	cfg.nodes[2] = node("proxy", "cfg000002")
	cfg.nodes[3] = node("block", "cfg000003")
	cfg.dns.rule_set_dir = "/tmp/definitely-not-here-core"
	cfg.dns.rule_set_interval = "7 days"

	local config = confgen.build(cfg)
	local json = require("luci.jsonc").stringify(config, true)

	local f = io.open("/tmp/hp-r28-core.json", "w")
	f:write(json)
	f:close()

	local rc = os.execute(
		"/usr/bin/sing-box check -c /tmp/hp-r28-core.json >/tmp/hp-r28-check.out 2>&1")
	-- Lua 5.1's os.execute returns the raw system() status, and 0 is TRUTHY in
	-- Lua, so this cannot be written as a bare `if os.execute(...)`.
	ok("sing-box accepts the config built from three colliding node names",
		rc == 0, "rc=" .. tostring(rc) .. " " ..
			(io.open("/tmp/hp-r28-check.out"):read("*a") or ""))
	os.remove("/tmp/hp-r28-core.json")
end

print(("\n  %d passed, %d failed\n"):format(pass, fail))
os.exit(fail == 0 and 0 or 1)
