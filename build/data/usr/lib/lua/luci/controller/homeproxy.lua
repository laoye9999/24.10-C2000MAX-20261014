-- SPDX-License-Identifier: GPL-2.0
-- LuCI controller for the homeproxy 21.02 backport.
--
-- Written against LuCI's Lua dispatcher (21.02 predates the JS client). The
-- action and api endpoints exist because both the service control and the
-- Clash API live on the router: the browser cannot reach 127.0.0.1:9090.

module("luci.controller.homeproxy", package.seeall)

-- Deliberately no file-level `local X = require "..."`.
--
-- LuCI builds its menu index once, then caches it as *bytecode*
-- (/tmp/luci-indexcache.*.lua) and reloads it with loadfile() on every
-- subsequent request. string.dump does not carry upvalues, so any file-local
-- captured by index() comes back nil on the second request. That is exactly
-- how this file first failed:
--
--   homeproxy.lua:22: attempt to index upvalue 'fs' (a nil value)
--
-- So each function requires what it needs itself. The cost is a table lookup
-- in package.loaded; the alternative is a page that works once and then breaks.

local CLASH = "http://127.0.0.1:9090"
local SUBSCRIBE_LOG = "/tmp/homeproxy-subscribe.log"

--- Shell-quote a value for safe interpolation into a command line.
--- Module-level (not local) so it survives bytecode caching.
function shell_quote(s)
	return "'" .. tostring(s):gsub("'", "'\\''") .. "'"
end

function index()
	local fs = require "nixio.fs"
	-- Not the bare `_` alias. In this firmware there is no global `_` at all
	-- (`_G._` is nil), so `_("Client Settings")` silently handed entry() a
	-- value that never got translated and the menu stayed English. Requiring
	-- translate explicitly is also what the bytecode-cache note above wants.
	local translate = require("luci.i18n").translate

	if not fs.access("/etc/config/homeproxy") then
		return
	end

	entry({"admin", "services", "homeproxy"}, firstchild(), translate("HomeProxy"), 60).dependent = false
	-- Running status and the client settings share one page: the widgets are
	-- injected above the form by view/homeproxy/map.htm. The route stayed at
	-- /status so existing bookmarks keep working.
	entry({"admin", "services", "homeproxy", "status"}, cbi("homeproxy/status"), translate("Running Status"), 1)
	entry({"admin", "services", "homeproxy", "node"}, cbi("homeproxy/node"), translate("Node Settings"), 3)
	entry({"admin", "services", "homeproxy", "subscription"}, cbi("homeproxy/subscription"), translate("Subscription"), 4)
	entry({"admin", "services", "homeproxy", "import"}, call("import_node"), translate("Add Node"), 5)
	entry({"admin", "services", "homeproxy", "log"}, template("homeproxy/log"), translate("Logs"), 6)

	entry({"admin", "services", "homeproxy", "action"}, call("action")).leaf = true
	entry({"admin", "services", "homeproxy", "api"}, call("api")).leaf = true
end

--------------------------------------------------------------------- action

-- POST /admin/services/homeproxy/action
function action()
	local http = require "luci.http"
	local sys = require "luci.sys"
	local fs = require "nixio.fs"

	local function reply(tbl)
		http.prepare_content("application/json")
		http.write_json(tbl)
	end

	local method = http.getenv("REQUEST_METHOD")
	local what = http.formvalue("action") or ""

	-- Queries that change nothing may be fetched with GET, which is what the
	-- status page does when it polls. Everything that mutates state must be a
	-- POST. Demanding POST for the read-only ones makes the running/stopped
	-- indicator permanently read "stopped".
	local READ_ONLY = { service_status = true, subscribe_status = true,
	                    tcp_status = true }
	if method ~= "POST" and not READ_ONLY[what] then
		http.status(405, "Method Not Allowed")
		return reply({ ok = false, error = "POST required for action: " .. what })
	end

	if what == "start" or what == "stop" or what == "restart" then
		local rc = sys.call("/etc/init.d/homeproxy " .. what .. " >/dev/null 2>&1")
		return reply({ ok = rc == 0 })

	elseif what == "subscribe" then
		local rc = sys.call(string.format(
			"/usr/bin/lua /usr/lib/lua/homeproxy/subscribe.lua >%s 2>&1",
			SUBSCRIBE_LOG))
		return reply({ ok = rc == 0, output = fs.readfile(SUBSCRIBE_LOG) or "" })

	elseif what == "subscribe_status" then
		return reply({ ok = true, output = fs.readfile(SUBSCRIBE_LOG) or "" })

	elseif what == "service_status" then
		-- pidof, not pgrep: this firmware's busybox ships neither pkill nor
		-- pgrep, but pidof is present.
		local running = sys.call("pidof sing-box >/dev/null 2>&1") == 0
		return reply({ ok = true, running = running })

	elseif what == "tcp_test" then
		-- One node, answered synchronously: it is a single connect with a
		-- 2s cap and the user is waiting for the number.
		local section = http.formvalue("node") or ""
		if section == "" or not section:match("^[%w_]+$") then
			http.status(400, "Bad Request")
			return reply({ ok = false, error = "invalid node" })
		end

		local all = require("luci.model.uci").cursor():get_all("homeproxy", section)
		if not all or all[".type"] ~= "node" then
			http.status(404, "Not Found")
			return reply({ ok = false, error = "no such node" })
		end

		local tcp = require "homeproxy.tcp"
		local ok, ms, err = tcp.ping(all.server, tonumber(all.port), 2000)
		return reply({ ok = ok and true or false, ms = ms, error = err })

	elseif what == "tcp_test_all" then
		-- A full sweep is one connect per node with a 2s cap each, so with a
		-- few dozen nodes it can run for a minute -- far past what a browser
		-- will wait for. Detach it and let the page poll tcp_status.
		sys.call("lua /usr/share/homeproxy/tcp-test.lua >/dev/null 2>&1 &")
		return reply({ ok = true, started = true })

	elseif what == "tcp_status" then
		local body = fs.readfile("/tmp/homeproxy-tcp.json")
		if not body then
			return reply({ ok = true, ready = false })
		end
		-- Already JSON written by the test script; pass it through untouched.
		http.prepare_content("application/json")
		http.write(body)
		return

	elseif what == "select" then
		-- Switching the active node is a PUT to the Clash API, which the
		-- read-only `api` endpoint will not do. Kept here so the one mutating
		-- call stays on a path that validates its input.
		-- Deliberately not a character whitelist.
		--
		-- The name is only ever *data* on this path: it is serialised into a
		-- JSON body for the Clash API PUT and never reaches a URL or a
		-- command word -- the endpoint is the constant below and the body
		-- goes through shell_quote. So any whitelist narrow enough to mean
		-- anything rejects real nodes: `Tokyo #2` is the name the
		-- importer itself gives a duplicate, and a Chinese name is what a
		-- Chinese-language UI invites. Both used to answer 400 here, so the
		-- status page's dropdown moved, the request failed, and the node
		-- never switched. Rejected instead is what a name cannot carry:
		-- control characters, and a length no node name should reach.
		local node = http.formvalue("node") or ""
		if node == "" or node:len() > 200 or node:match("%c") then
			http.status(400, "Bad Request")
			return reply({ ok = false, error = "invalid node name" })
		end

		local payload = string.format('{"name":%s}',
			require("luci.jsonc").stringify(node))
		local rc = sys.call(string.format(
			"curl -sS -m 5 -X PUT -H 'Content-Type: application/json' -d %s %s >/dev/null 2>&1",
			shell_quote(payload),
			shell_quote(CLASH .. "/proxies/proxy")))
		return reply({ ok = rc == 0 })
	end

	http.status(400, "Bad Request")
	return reply({ ok = false, error = "unknown action: " .. what })
end

--------------------------------------------------------------------- import

--- Paste-a-link importer.
--
-- Rendered as a plain HTML form rather than a CBI map: this firmware's LuCI
-- replaces CBI widgets with a client-side JS layer, and a textarea plus a
-- submit button is exactly the kind of control that layer is least predictable
-- about. Owning the markup keeps the one path that matters working.
--
-- Accepts either a single share link or a whole subscription body, one per
-- line, and creates one node per link.
function import_node()
	local http = require "luci.http"

	-- The plugin's own modules live in /usr/lib/lua, which is not guaranteed to
	-- be on package.path in every LuCI dispatch context.
	package.path = "/usr/lib/lua/?.lua;" .. package.path

	local result

	if http.getenv("REQUEST_METHOD") == "POST" then
		result = do_import(http.formvalue("links") or "")
		if result.imported > 0 then
			-- A manual "restart" is what actually pushes the new node into
			-- sing-box; failing that the change lands on the next restart.
			require("luci.sys").call("/etc/init.d/homeproxy restart >/dev/null 2>&1")
		end
	end

	luci.template.render("homeproxy/import", {
		result = result,
		nodes_url = luci.dispatcher.build_url("admin", "services", "homeproxy", "node"),
	})
end

--- Parse pasted text and create a node per link.
-- @return table with imported/failed counts and per-line messages
function do_import(text)
	package.path = "/usr/lib/lua/?.lua;" .. package.path

	local ok_nodes, nodes = pcall(require, "homeproxy.nodes")
	local ok_loader, loader = pcall(require, "homeproxy.uci_loader")

	local out = { imported = 0, failed = 0, messages = {} }

	if not ok_nodes or not ok_loader then
		out.messages[#out.messages + 1] = {
			ok = false,
			text = "内部错误：无法加载 homeproxy 模块",
		}
		return out
	end

	for line in tostring(text):gmatch("[^\r\n]+") do
		local trimmed = line:gsub("^%s+", ""):gsub("%s+$", "")
		if trimmed ~= "" and not trimmed:match("^#") then
			local fields, err = nodes.parse_link(trimmed)

			if not fields then
				out.failed = out.failed + 1
				out.messages[#out.messages + 1] = {
					ok = false,
					text = string.sub(trimmed, 1, 40) .. "… — " .. tostring(err),
				}
			else
				local ok, werr = pcall(loader.write_node, fields)
				if ok then
					out.imported = out.imported + 1
					out.messages[#out.messages + 1] = {
						ok = true,
						text = string.format("%s  (%s:%s)",
							tostring(fields.name),
							tostring(fields.server),
							tostring(fields.port)),
					}
				else
					out.failed = out.failed + 1
					out.messages[#out.messages + 1] = {
						ok = false,
						text = tostring(fields.name) .. " — 写入失败: " .. tostring(werr),
					}
				end
			end
		end
	end

	return out
end

--------------------------------------------------------------------- api

-- Only these Clash API endpoints are exposed to the browser. Passing the
-- caller's path through unchecked would let any authenticated LuCI user talk
-- to arbitrary endpoints on the router's loopback interface.
--
-- Built inside the function rather than kept as a file-local, for the same
-- bytecode-cache reason as everything else in this file.
function route_allowed(path)
	-- The node name in the last two routes arrives *percent-encoded*: the page
	-- builds that segment with encodeURIComponent (widgets.htm, hpTest),
	-- because node names are user-editable and routinely carry the things
	-- that need encoding -- spaces, the `#` the importer puts on a duplicate,
	-- or non-ASCII. So the alphabet to allow is the one encoding produces:
	-- the unreserved marks, plus %XX escapes.
	--
	-- Without `%` in the set the pattern could only ever match a name that
	-- needed no encoding at all, and any other name answered 403 -- a node
	-- called `Tokyo #2` could not be latency-tested at all.
	local seg = "[%w%-%._~!*'()%%]+"

	local routes = {
		"^/version$",
		"^/configs$",
		"^/connections$",
		"^/proxies$",
		"^/proxies/" .. seg .. "$",
		"^/proxies/" .. seg .. "/delay$",
	}

	local base = path:match("^([^?]*)") or path

	-- `%` has to be allowed for a name to be encoded at all, but an escape
	-- standing for `.` or `/` would decode on the Clash side into a path
	-- separator and walk the request back out of /proxies -- which is the one
	-- thing this whitelist exists to prevent. encodeURIComponent never emits
	-- either: both are in its unreserved set and travel as literals.
	if base:lower():match("%%2[ef]") then return false end

	for _, pattern in ipairs(routes) do
		if base:match(pattern) then return true end
	end
	return false
end

-- GET /admin/services/homeproxy/api?path=/connections
function api()
	local http = require "luci.http"
	local sys = require "luci.sys"

	local path = http.formvalue("path") or "/version"

	if not route_allowed(path) then
		http.status(403, "Forbidden")
		http.prepare_content("application/json")
		return http.write_json({ error = "endpoint not allowed: " .. path })
	end

	-- The path is whitelisted above and shell-quoted here, so nothing
	-- user-supplied can escape into the command line.
	local body = sys.exec(string.format("curl -sS -m 6 %s 2>/dev/null",
		shell_quote(CLASH .. path)))

	if not body or body == "" then
		http.status(503, "Service Unavailable")
		http.prepare_content("application/json")
		return http.write_json({ error = "clash api unreachable; is homeproxy running?" })
	end

	-- Pass the payload through untouched: it is already JSON, and re-encoding
	-- it here would only risk mangling fields we do not model.
	http.prepare_content("application/json")
	http.write(body)
end
