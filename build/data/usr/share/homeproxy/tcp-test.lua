#!/usr/bin/lua
-- SPDX-License-Identifier: GPL-2.0
-- TCP-test every configured node and record the result for the web UI.
--
-- Run detached by the controller when the user presses "全部测试". Rewrites
-- the result file after EVERY node rather than once at the end, so the page
-- can poll it and fill the list in progressively -- with a few dozen nodes a
-- single write at the end would leave the UI blank for a minute.
--
--   tcp-test.lua [timeout-ms]

package.path = "/usr/lib/lua/?.lua;/usr/lib/lua/?/init.lua;" .. package.path

local OUT   = "/tmp/homeproxy-tcp.json"
local LOCK  = "/tmp/homeproxy-tcp.lock"
local TIMEOUT = tonumber(arg and arg[1]) or 2000

local function write_result(tbl)
	local ok, jsonc = pcall(require, "luci.jsonc")
	local fh = io.open(OUT, "w")
	if not fh then return end
	if ok and jsonc then
		fh:write(jsonc.stringify(tbl))
	else
		-- Should not happen (luci-lib-jsonc is a dependency), but a plain
		-- empty result is better than a file the UI cannot parse.
		fh:write('{"at":' .. tostring(os.time() or 0) .. ',"done":true,"results":{}}')
	end
	fh:close()
end

-- One run at a time: two full sweeps at once would double the connect storm
-- for no benefit, and the second would overwrite the first.
local lock = io.open(LOCK, "w")
if not lock then os.exit(0) end
lock:write(tostring(os.time() or 0))
lock:close()

local ok_uci, uci = pcall(require, "luci.model.uci")
local sections = {}
if ok_uci then
	local cur = uci.cursor()
	cur:foreach("homeproxy", "node", function(s)
		sections[#sections + 1] = {
			section = s[".name"] or s[".index"],
			name    = s.name or s[".name"] or "?",
			server  = s.server or "",
			port    = s.port or "",
		}
	end)
end

local tcp = require "homeproxy.tcp"
local results = {}
local at = os.time() or 0

write_result({ at = at, done = (#sections == 0), total = #sections, tested = 0, results = results })

local tested = 0
for _, n in ipairs(sections) do
	local ok, ms, err = tcp.ping(n.server, tonumber(n.port), TIMEOUT)
	results[n.section] = {
		name = n.name,
		host = n.server,
		port = n.port,
		ok   = ok and true or false,
		ms   = ms,
		error = err,
	}
	tested = tested + 1
	write_result({ at = at, done = false, total = #sections, tested = tested, results = results })
end

write_result({ at = at, done = true, total = #sections, tested = tested, results = results })
os.remove(LOCK)
