-- SPDX-License-Identifier: GPL-2.0
-- homeproxy 21.02 backport -- UCI access.
--
-- Split in two so the interesting half is testable off-device:
--   from_sections() is pure and takes a plain table of sections
--   load() reads /etc/config/homeproxy through libuci and calls it
--
-- Uses libuci-lua (`require "uci"`) rather than LuCI's wrapper, because these
-- scripts also run from init.d where no LuCI request context exists.

local M = {}

local function copy(t)
	local o = {}
	for k, v in pairs(t) do o[k] = v end
	return o
end

--- Normalise a section table from either libuci or LuCI, which disagree about
--- whether the type/name live in `.type` or bare `type`.
local function section_type(sec)
	return sec[".type"] or sec.type
end

local function section_name(sec, fallback)
	return sec[".name"] or sec.name or fallback
end

--- Should this key be written as a UCI option?
---
--- Skips "tag" (it identifies the section, it is not an option), nil values,
--- and anything with a leading dot, which is UCI's reserved namespace --
--- writing those either fails or corrupts the section.
local function writable_option(key, value)
	return type(key) == "string"
		and key ~= "tag"
		and key:sub(1, 1) ~= "."
		and value ~= nil
end

--- Raw UCI sections -> the settings table confgen.build() expects.
-- @param sections table keyed by section name, values are option tables
function M.from_sections(sections)
	local cfg = {
		global = {},
		inbound = {},
		dns = {},
		nodes = {},
		subscriptions = {},
	}

	for key, sec in pairs(sections) do
		local typ = section_type(sec)
		if typ == "global" then
			cfg.global = copy(sec)
		elseif typ == "inbound" then
			cfg.inbound = copy(sec)
		elseif typ == "dns" then
			cfg.dns = copy(sec)
		elseif typ == "node" then
			local node = copy(sec)
			-- The UCI section name is the only stable identity a node has.
			--
			-- This comment used to say the section name "becomes the sing-box
			-- outbound tag". It does not: confgen prefers the *display name*
			-- (build_outbounds: `local preferred = node.name`), falling back to
			-- the section only when there is no name. The difference is load
			-- bearing rather than pedantic -- display names are not unique, and
			-- the " #2" the generator appends to a duplicate is recomputed from
			-- scratch on every build and never written back to UCI, so a tag is
			-- not a value that can be stored and looked up later. Anything that
			-- needs to refer to a node across builds (global.default_node, and
			-- the `subscription` back-reference on an imported node) has to use
			-- this section name, and confgen translates it through tag_of.
			node.tag = section_name(sec, key)
			cfg.nodes[#cfg.nodes + 1] = node
		elseif typ == "subscription" then
			local sub = copy(sec)
			sub.section = section_name(sec, key)
			cfg.subscriptions[#cfg.subscriptions + 1] = sub
		end
	end

	-- Deterministic order: Lua's pairs() has none, and node order decides the
	-- default selector entry and the order nodes appear in LuCI.
	local function by_tag(a, b)
		return tostring(a.tag or a.section) < tostring(b.tag or b.section)
	end
	table.sort(cfg.nodes, by_tag)
	table.sort(cfg.subscriptions, by_tag)

	return cfg
end

--- Read the live configuration.
-- @return settings table, or nil plus an error string
function M.load()
	local ok, uci = pcall(require, "uci")
	if not ok then
		return nil, "libuci-lua is not installed (opkg install libuci-lua)"
	end

	local cursor = uci.cursor()
	local sections = {}

	local ok2, err = pcall(function()
		cursor:foreach("homeproxy", nil, function(sec)
			local name = section_name(sec)
			if name then
				sections[name] = sec
			else
				-- Anonymous section: synthesise a stable key from the type and
				-- the section's index so ordering still works.
				sections[string.format("@%s[%d]", tostring(section_type(sec)),
					#sections)] = sec
			end
		end)
	end)

	if not ok2 then
		return nil, "failed to read /etc/config/homeproxy: " .. tostring(err)
	end

	return M.from_sections(sections)
end

--- Write a node's fields into UCI as a new or existing section.
--- Used by the subscription importer.
function M.write_node(fields, section)
	local cursor = require("uci").cursor()

	local name = section
	if not name or name == "" then
		cursor:load("homeproxy")
		name = cursor:add("homeproxy", "node")
	end

	for k, v in pairs(fields) do
		if writable_option(k, v) then
			cursor:set("homeproxy", name, k, tostring(v))
		end
	end
	cursor:commit("homeproxy")

	return name
end

--- Replace every node belonging to a subscription.
--- Nodes are matched by the `subscription` option, so re-importing a feed
--- replaces exactly its own nodes and leaves hand-added ones alone.
function M.replace_subscription_nodes(sub_section, list)
	local cursor = require("uci").cursor()
	cursor:load("homeproxy")

	cursor:foreach("homeproxy", "node", function(sec)
		local name = section_name(sec)
		if name and sec.subscription == sub_section then
			cursor:delete("homeproxy", name)
		end
	end)

	for _, fields in ipairs(list) do
		local name = cursor:add("homeproxy", "node")
		for k, v in pairs(fields) do
			if writable_option(k, v) then
				cursor:set("homeproxy", name, k, tostring(v))
			end
		end
		cursor:set("homeproxy", name, "subscription", sub_section)
	end

	cursor:commit("homeproxy")
	return #list
end

return M
