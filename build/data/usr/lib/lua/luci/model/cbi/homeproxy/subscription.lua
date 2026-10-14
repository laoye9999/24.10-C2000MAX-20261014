-- SPDX-License-Identifier: GPL-2.0
-- Subscription management.
--
-- Updating a subscription replaces only the nodes tagged with that
-- subscription's section name, so hand-added nodes and other subscriptions are
-- unaffected.

local m, s, o

m = Map("homeproxy", translate("Subscription"),
	translate("Fetched links are parsed into nodes. Updating replaces that " ..
		"subscription's nodes and leaves everything else alone."))


-- The wrapper draws the child-page tab strip, except when the active theme
-- draws one itself; the test for that is in view/homeproxy/nav.htm.
m.template = "homeproxy/map"
s = m:section(TypedSection, "subscription", translate("Subscriptions"))
s.anonymous = true
s.addremove = true
s.template = "cbi/tblsection"

o = s:option(Flag, "enabled", translate("Enable"))
o.default = "1"
o.rmempty = false

o = s:option(Value, "name", translate("Name"))
o.rmempty = true

o = s:option(Value, "url", translate("URL"))
o.rmempty = false

o = s:option(ListValue, "interval", translate("Update Interval"))
o:value("0", translate("Never (manual only)"))
o:value("6", translate("Every 6 hours"))
o:value("12", translate("Every 12 hours"))
o:value("24", translate("Daily"))
o:value("168", translate("Weekly"))
o.default = "24"
o.rmempty = false

-- Fetch this subscription now. Button is handled client-side by LuCI's cbi
-- template, and write() runs on the router where the URL is reachable.

-- Start a subscription fetch and return without waiting for it.
--
-- This used to be a plain `luci.sys.call`, which blocks until the script
-- finishes. subscribe.lua fetches each enabled subscription serially with
-- `curl --connect-timeout 15 --max-time 120` and has no overall budget, so one
-- URL that is black-holed costs 15s and one that accepts the connection and
-- then stalls costs two minutes -- multiplied by however many subscriptions
-- are enabled, which for a lapsed provider is all of them.
--
-- uhttpd's `script_timeout` is 60s by default and it applies that as a
-- one-shot timer on the request process, so what the user got was a 502 after
-- a minute with no result on the page. And because subscribe.lua is a
-- grandchild (luci.sys.call runs it under `sh`), that SIGKILL never reached it:
-- the fetch ran on to completion writing only to the log, and a second click
-- started a second copy on top of the first.
--
-- Detaching is what the full TCP sweep on the status page already does, and it
-- needs nothing new on the page: "Last Result" below is rendered from this same
-- file, so the update reports itself there as it goes.
local function start_update(section)
	local log = "/tmp/homeproxy-subscribe.log"

	-- Truncated here rather than by the child's own redirect. The page is
	-- reloaded the moment this returns, and this way the pane shows *this*
	-- run's output from the first render, instead of the previous run's until
	-- the child gets around to opening the file.
	luci.sys.call(": > " .. log)

	luci.sys.call(string.format(
		"/usr/bin/lua /usr/lib/lua/homeproxy/subscribe.lua %s >>%s 2>&1 &",
		section or "", log))
end

o = s:option(Button, "_update", translate("Update"))
o.inputtitle = translate("Update now")
o.inputstyle = "apply"
function o.write(self, section)
	start_update(section)
	luci.http.redirect(luci.dispatcher.build_url("admin/services/homeproxy/subscription"))
end

o = s:option(DummyValue, "last_update", translate("Last Update"),
	translate("Recorded when any subscription is refreshed."))
o.rawhtml = true
function o.cfgvalue(self, section)
	local uci = require("luci.model.uci").cursor()
	local v = uci:get("homeproxy", "global", "last_update")
	return v and luci.util.pcdata(v) or "-"
end

--------------------------------------------------------------------- update all

-- A TypedSection over the `actions` placeholder in /etc/config/homeproxy, not
-- a SimpleSection. SimpleSection is constructed with a nil section, and LuCI
-- passes that nil straight down to every child's parse() -- an AbstractValue
-- then dies building its form field name:
--
--   cbi.lua:1364: attempt to concatenate local 'section' (a nil value)
--
-- which turned every save on this page into an HTTP 500. Attaching the same
-- widgets to a real section avoids it.
s = m:section(TypedSection, "actions", translate("Update All"))
s.anonymous = true
s.addremove = false
o = s:option(Button, "_all", translate("Refresh"))
o.inputtitle = translate("Update all subscriptions")
o.inputstyle = "apply"
function o.write(self, section)
	start_update(nil)
	luci.http.redirect(luci.dispatcher.build_url("admin/services/homeproxy/subscription"))
end

o = s:option(DummyValue, "_result", translate("Last Result"))
o.rawhtml = true
function o.cfgvalue(self, section)
	local f = io.open("/tmp/homeproxy-subscribe.log", "r")
	if not f then
		return translate("No update has run yet.")
	end
	local body = f:read("*a")
	f:close()
	return "<pre style='white-space:pre-wrap'>" .. luci.util.pcdata(body) .. "</pre>"
end

function m.on_after_commit(self)
	luci.sys.call("/etc/init.d/homeproxy restart >/dev/null 2>&1")
end

return m
