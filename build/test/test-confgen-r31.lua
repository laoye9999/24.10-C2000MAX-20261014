-- Regression tests for the r31 confgen change: `routing_mark` on every
-- outbound that dials, not only on `direct`.
--
-- Runs on the device, where lua and sing-box both exist:
--
--     scp test/test-confgen-r31.lua root@192.168.66.1:/tmp/
--     ssh root@192.168.66.1 'lua /tmp/test-confgen-r31.lua'
--
-- Why this is not cosmetic. firewall.sh's OUTPUT chain captures router-
-- originated traffic and RETURNs on exactly this mark to keep sing-box's own
-- connection to the node out of that capture. Before r31 only the `direct`
-- outbound carried it. Leave it off the node and the tunnel's own packets are
-- captured, routed onto lo, handed back to sing-box, and dialled again -- a
-- loop that does not fail closed, because it retries. The box talks to itself
-- at line rate until it is unusable.
--
-- So the two things that have to hold are: every outbound with a server
-- carries the mark, and a mark of 0 never reaches the config. sing-box reads
-- 0 as "no mark" and accepts it happily; the firewall's exclusion would then
-- match nothing at all.
--
-- Negative control -- confirms these assertions are actually the ones speaking
-- for the fix, rather than passing because the fix happens to be present:
--
--     mkdir -p /tmp/nofix-r31/homeproxy
--     cp /usr/lib/lua/homeproxy/*.lua /tmp/nofix-r31/homeproxy/
--     sed -i '/ob.routing_mark = routing_mark(cfg)/d' \
--         /tmp/nofix-r31/homeproxy/confgen.lua
--     HP_LUA_ROOT=/tmp/nofix-r31 lua /tmp/test-confgen-r31.lua
--
-- Expect the node-mark assertions to fail there and the rest to pass.

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

local function base_cfg(mark)
	local g = { proxy_mode = "global", default_node = "cfg000001" }
	if mark ~= nil then g.routing_mark = mark end
	return { global = g, inbound = {}, dns = {}, nodes = {} }
end

local function node(display_name, section)
	return {
		tag = section, name = display_name, type = "socks",
		server = "1.2.3.4", port = 1080,
		username = "u", password = "p",
	}
end

--- Outbounds that dial: those are the ones whose sockets need the mark.
--- A selector and `block` have no server and open no socket.
local function dialling(config)
	local out = {}
	for _, o in ipairs(config.outbounds or {}) do
		if o.server ~= nil then out[#out + 1] = o end
	end
	return out
end

local function mark_of(config, tag)
	for _, o in ipairs(config.outbounds or {}) do
		if o.tag == tag then return o.routing_mark end
	end
	return nil
end

-- ---------------------------------------------------------------- the mark

do
	local cfg = base_cfg(nil)
	cfg.nodes = { node("Node A", "cfg000001"), node("Node B", "cfg000002") }
	local config = confgen.build(cfg)

	-- Two nodes. `direct` is not in this list -- it has no server field --
	-- which is why it is asserted separately below.
	local d = dialling(config)
	ok("the config has dialling outbounds to check", #d >= 2,
		"found " .. #d)

	local bad = {}
	for _, o in ipairs(d) do
		if o.routing_mark ~= 2 then
			bad[#bad + 1] = o.tag .. "=" .. tostring(o.routing_mark)
		end
	end
	ok("every outbound that dials carries routing_mark 2", #bad == 0,
		table.concat(bad, ", "))

	-- Called out separately from the loop above because it is the one that
	-- existed before r31, and the regression that would go unnoticed is a
	-- change that adds the mark to nodes and drops it from `direct` -- the
	-- direct outbound serves the DNS resolver the node lookup depends on.
	ok("the direct outbound still carries it", mark_of(config, "direct") == 2,
		"direct=" .. tostring(mark_of(config, "direct")))

	ok("the selector has no server, so no mark is expected",
		mark_of(config, "proxy") == nil, tostring(mark_of(config, "proxy")))
end

-- ------------------------------------------------------- rejected values
--
-- 0 is the one that matters most: sing-box accepts it and means "no mark", so
-- the firewall's exclusion would match nothing and every packet to the node
-- would be fed back in.
--
-- "0x10" and " 7 " matter for a different reason, and are the reason the
-- grammar is spelled out rather than delegated to tonumber(): tonumber reads
-- them as 16 and 7, firewall.sh's `*[!0-9]*` test reads them as garbage and
-- falls back to 2. The generator and the firewall have to disagree about
-- nothing here, so the narrowing happens on this side too.
--
-- The rest are values sing-box would refuse at decode, which is fatal at
-- startup -- procd respawns five times and gives up.

do
	local bad = { "0", "-5", "3.5", "abc", "", "0x10", " 7 ", "99999999999", "007x" }
	local survived = {}
	for _, v in ipairs(bad) do
		local cfg = base_cfg(v)
		cfg.nodes = { node("Node A", "cfg000001") }
		local built = confgen.build(cfg)
		local m = mark_of(built, "Node A")
		if m ~= 2 then survived[#survived + 1] = v .. "->" .. tostring(m) end
	end
	ok("0, negatives, fractions, hex and junk all fall back to 2",
		#survived == 0, table.concat(survived, ", "))

	-- And a value that is simply different is honoured, so the fallback above
	-- is a rejection and not a hard-coded constant.
	local cfg = base_cfg("7")
	cfg.nodes = { node("Node A", "cfg000001") }
	local built = confgen.build(cfg)
	local wrong = {}
	for _, o in ipairs(dialling(built)) do
		if o.routing_mark ~= 7 then
			wrong[#wrong + 1] = o.tag .. "=" .. tostring(o.routing_mark)
		end
	end
	ok("a different valid mark is used everywhere", #wrong == 0,
		table.concat(wrong, ", "))
end

-- --------------------------------------------------------------- end to end
--
-- The assertions above read the Lua table. This is the one that asks sing-box
-- whether it agrees the config is a config.

do
	local cfg = base_cfg(nil)
	cfg.nodes = { node("Node A", "cfg000001"), node("Node B", "cfg000002") }
	local config = confgen.build(cfg)
	local json = confgen.build_json(config)

	local path = "/tmp/hp-r31-core.json"
	local f = io.open(path, "w")
	if f then
		f:write(json)
		f:close()
	end

	-- Lua 5.1: os.execute returns the raw status, and 0 is truthy, so the
	-- comparison has to be explicit.
	local rc = os.execute("/usr/bin/sing-box check -c " .. path .. " >/dev/null 2>&1")
	ok("sing-box accepts a config whose outbounds carry the mark", rc == 0,
		"sing-box check exited " .. tostring(rc))
	os.remove(path)
end

print(string.format("\n%d passed, %d failed\n", pass, fail))
os.exit(fail == 0 and 0 or 1)
