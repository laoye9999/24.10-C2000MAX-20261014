#!/usr/bin/lua
-- SPDX-License-Identifier: GPL-2.0
-- homeproxy 21.02 backport -- render /etc/config/homeproxy into a sing-box
-- configuration file.
--
--   lua gen_config.lua [output-path]      (default /var/run/homeproxy/config.json)
--
-- The file is written to a temporary name and renamed into place, so a
-- generator error never leaves a half-written config for sing-box to read.

-- Make the module path self-sufficient: this script is invoked from init.d,
-- where the firmware's default package.path may not include /usr/lib/lua.
package.path = "/usr/lib/lua/?.lua;/usr/lib/lua/?/init.lua;" .. package.path

local loader = require "homeproxy.uci_loader"
local confgen = require "homeproxy.confgen"

local out = arg[1] or "/var/run/homeproxy/config.json"

local function fail(msg)
	io.stderr:write("homeproxy: " .. msg .. "\n")
	os.exit(1)
end

local ok, jsonc = pcall(require, "luci.jsonc")
if not ok then
	fail("luci-lib-jsonc is not installed (opkg install luci-lib-jsonc)")
end

local cfg, err = loader.load()
if not cfg then
	fail(err)
end

local config = confgen.build(cfg)

local json = jsonc.stringify(config, true)
if type(json) ~= "string" or json == "" then
	fail("serialisation produced nothing")
end

local tmp = out .. ".tmp"
local fh, oerr = io.open(tmp, "w")
if not fh then
	fail("cannot write " .. tmp .. ": " .. tostring(oerr))
end
fh:write(json)
fh:write("\n")
fh:close()

if os.rename(tmp, out) == nil then
	os.remove(tmp)
	fail("cannot rename " .. tmp .. " to " .. out)
end

-- Summary on stdout, which procd captures into the system log.
local n = #(cfg.nodes or {})
io.write(string.format(
	"homeproxy: wrote %s (%d bytes, %d node(s), mode=%s)\n",
	out, #json, n, tostring((cfg.global or {}).proxy_mode or "rule")))
