#!/usr/bin/lua
-- SPDX-License-Identifier: GPL-2.0
-- homeproxy 21.02 backport -- subscription importer.
--
--   lua subscribe.lua            update every enabled subscription
--   lua subscribe.lua <section>  update just that one
--
-- Nodes belonging to a subscription are replaced wholesale on each update,
-- matched by the `subscription` option on the node section. Hand-added nodes
-- are never touched, and a subscription that returns junk cannot destroy the
-- nodes from a working one.

package.path = "/usr/lib/lua/?.lua;/usr/lib/lua/?/init.lua;" .. package.path

local nodes = require "homeproxy.nodes"
local util = require "homeproxy.util"
local loader = require "homeproxy.uci_loader"

local only = arg[1]

-- --- one at a time ---------------------------------------------------------
--
-- Two schedulers run this script: the hourly cron and the Update buttons on the
-- subscription page, which now start it detached and can be pressed more than
-- once. Nothing serialised them, and the import is a read-modify-write --
-- replace_subscription_nodes loads /etc/config/homeproxy into one cursor,
-- deletes the sections it saw, adds the new ones, and commits the whole package
-- from that in-memory copy. When two runs' commits land inside one another the
-- loser's snapshot is written over the winner's, and the nodes the first run
-- had just imported are gone.
--
-- What makes that worse than an ordinary lost update is the stamp: the
-- per-subscription `last_update` is written by a separate uci call that does
-- survive, so the next automatic attempt is suppressed for the whole interval
-- and the subscription silently keeps the node list it had before. No error is
-- shown anywhere. The window is small -- the two commits have to start within
-- the winner's commit duration -- but it is not rare enough to leave open, and
-- a manual update is exactly what a user does when the automatic one looks
-- stale, i.e. during the window the cron is in.
--
-- A directory rather than an flock'd file, because Lua cannot hold an fd open
-- across the run the way a shell can. mkdir is atomic, so exactly one caller
-- gets it, and the pid inside makes it self-healing: a run killed without
-- cleaning up leaves a pid that is no longer alive, and the next caller takes
-- the lock over instead of waiting on it forever.
local LOCK = "/var/run/homeproxy-subscribe.lock"
local held = false

--- Did the shell command succeed?
---
--- Lua 5.1's os.execute returns the raw system() status and 5.2+ returns
--- true/nil -- and 0 is *truthy* in Lua, so a bare `if os.execute(...)` is
--- taken on 5.1 whether or not the command worked.
local function ok(rc)
	return rc == true or rc == 0
end

local function own_pid()
	local fh = io.open("/proc/self/stat", "r")
	if not fh then return nil end
	local line = fh:read("*l")
	fh:close()
	return line and line:match("^(%d+)")
end

local function release_lock()
	if not held then return end
	held = false
	os.execute("rm -rf " .. LOCK .. " 2>/dev/null")
end

local function claim()
	if not ok(os.execute("mkdir " .. LOCK .. " 2>/dev/null")) then return false end
	held = true
	local fh = io.open(LOCK .. "/pid", "w")
	if fh then
		fh:write(tostring(own_pid() or 0))
		fh:close()
	end
	return true
end

local function take_lock()
	if claim() then return true end

	-- Held. That only blocks us if the holder is still alive; note that a
	-- missing pid file is read as *held*, which is the conservative direction
	-- and covers the moment between the mkdir and the write.
	local fh = io.open(LOCK .. "/pid", "r")
	local other = fh and tonumber(fh:read("*l"))
	if fh then fh:close() end
	if not other or ok(os.execute("kill -0 " .. other .. " 2>/dev/null")) then
		return false
	end

	os.execute("rm -rf " .. LOCK .. " 2>/dev/null")
	return claim()
end

local function fail(msg)
	release_lock()
	io.stderr:write("homeproxy: " .. msg .. "\n")
	os.exit(1)
end

--- Fetch a URL with curl. Returns body, or nil plus a reason.
local function fetch(url)
	if not url or url == "" then return nil, "empty url" end

	local cmd = string.format(
		"curl -fsSL --connect-timeout 15 --max-time 120 -A %s %s",
		util.shell_quote("homeproxy/1.0 (OpenWrt 21.02)"),
		util.shell_quote(url))

	local fh = io.popen(cmd, "r")
	if not fh then return nil, "cannot run curl" end

	local body = fh:read("*a")
	local ok = fh:close()

	if not ok then
		return nil, "download failed (check the URL and that curl is installed)"
	end
	if not body or body == "" then
		return nil, "empty response"
	end

	return body
end

if not take_lock() then
	-- Written to the log the page renders, so a second click explains itself
	-- instead of appearing to do nothing.
	io.write("homeproxy: another update is already running; not starting a second one\n")
	os.exit(0)
end

local cfg, err = loader.load()
if not cfg then fail(err) end

local subs = cfg.subscriptions or {}
if #subs == 0 then
	io.write("homeproxy: no subscriptions configured\n")
	release_lock()
	os.exit(0)
end

--- Has this subscription's interval elapsed? An explicit section argument
--- always counts as due, so a manual "update now" is never a no-op.
local function due(sub)
	local interval = tonumber(sub.interval) or 24
	if interval <= 0 then
		return false -- "never", manual only
	end

	local last = tonumber(sub.last_update) or 0
	return (os.time() - last) >= interval * 3600
end

local updated, skipped, failed = 0, 0, 0

for _, sub in ipairs(subs) do
	local section = sub.section
	local label = sub.name or section

	if only and only ~= section then
		skipped = skipped + 1
	elseif (not only or only == "") and not due(sub) then
		-- nothing to do; the hourly cron run mostly lands here
		skipped = skipped + 1
	elseif sub.enabled == "0" then
		io.write(string.format("homeproxy: %s is disabled, skipping\n", label))
		skipped = skipped + 1
	else
		local body, ferr = fetch(sub.url)
		if not body then
			io.write(string.format("homeproxy: %s: %s\n", label, ferr))
			failed = failed + 1
		else
			local good, bad = nodes.parse_subscription(body)

			if #good == 0 then
				-- A subscription that yields nothing is far more likely to be
				-- an expired account or an error page than a genuinely empty
				-- feed, so leave the existing nodes in place rather than
				-- wiping the user's working setup.
				io.write(string.format(
					"homeproxy: %s: parsed 0 nodes (%d unreadable line(s)), keeping existing nodes\n",
					label, #bad))
				for i = 1, math.min(#bad, 3) do
					io.write("homeproxy:   " .. bad[i] .. "\n")
				end
				failed = failed + 1
			else
				local n = loader.replace_subscription_nodes(section, good)
				-- Record success on the section itself so the interval check
				-- only counts attempts that actually bore fruit.
				os.execute(string.format("uci set homeproxy.%s.last_update=%s 2>/dev/null",
					section, util.shell_quote(tostring(os.time()))))
				os.execute("uci commit homeproxy 2>/dev/null")

				io.write(string.format(
					"homeproxy: %s: imported %d node(s)%s\n",
					label, n,
					#bad > 0 and string.format(" (%d line(s) unreadable)", #bad) or ""))
				updated = updated + 1
			end
		end
	end
end

-- Record the attempt so LuCI can show "last updated".
os.execute(string.format(
	"uci set homeproxy.global.last_update=%s 2>/dev/null; uci commit homeproxy 2>/dev/null",
	util.shell_quote(os.date("%Y-%m-%d %H:%M:%S"))))

io.write(string.format("homeproxy: %d updated, %d skipped, %d failed\n",
	updated, skipped, failed))

release_lock()

if failed > 0 then
	os.exit(1)
end
