-- SPDX-License-Identifier: GPL-2.0
-- homeproxy 21.02 backport -- shared helpers.
--
-- Pure Lua 5.1 (the runtime shipped by OpenWrt 21.02). Deliberately avoids
-- ucode, and avoids shelling out for anything that can be done in-process.

local M = {}

local B64CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
local B64MAP = {}
for i = 1, #B64CHARS do
	B64MAP[B64CHARS:sub(i, i)] = i - 1
end

--- Decode standard or URL-safe base64. Padding is optional, whitespace ignored.
-- @return decoded string, or nil if the input is not valid base64
function M.b64_decode(s)
	if type(s) ~= "string" then return nil end
	s = s:gsub("%s", ""):gsub("-", "+"):gsub("_", "/")
	if s == "" then return "" end

	local pad = #s % 4
	if pad == 1 then return nil end
	if pad > 0 then s = s .. string.rep("=", 4 - pad) end

	local out, buf, n = {}, 0, 0
	for i = 1, #s do
		local c = s:sub(i, i)
		if c == "=" then break end
		local v = B64MAP[c]
		if not v then return nil end
		buf = buf * 64 + v
		n = n + 1
		if n == 4 then
			out[#out + 1] = string.char(
				math.floor(buf / 65536) % 256,
				math.floor(buf / 256) % 256,
				buf % 256)
			buf, n = 0, 0
		end
	end

	-- Tail handling. Each sextet is 6 bits, so a partial group of n sextets
	-- holds 6n bits and yields floor(6n/8) bytes taken from the high end:
	--   n == 2 -> 12 bits -> 1 byte  : high 8 bits are buf / 2^4
	--   n == 3 -> 18 bits -> 2 bytes : high 8 are buf / 2^10, next 8 are buf / 2^2
	if n == 2 then
		out[#out + 1] = string.char(math.floor(buf / 16) % 256)
	elseif n == 3 then
		out[#out + 1] = string.char(
			math.floor(buf / 1024) % 256,
			math.floor(buf / 4) % 256)
	end

	return table.concat(out)
end

--- Percent-decode, treating '+' as space (the application/x-www-form-urlencoded rule).
function M.url_decode(s)
	if type(s) ~= "string" then return nil end
	s = s:gsub("+", " ")
	return (s:gsub("%%(%x%x)", function(h)
		return string.char(tonumber(h, 16))
	end))
end

function M.url_encode(s)
	return (tostring(s):gsub("[^%w%-%._~]", function(c)
		return string.format("%%%02X", c:byte())
	end))
end

function M.trim(s)
	return (tostring(s or ""):gsub("^%s+", ""):gsub("%s+$", ""))
end

--- Split on a Lua pattern. Empty fields are preserved.
function M.split(s, pat)
	local out = {}
	if s == nil or s == "" then return out end
	local pos = 1
	while true do
		local from, to = s:find(pat, pos)
		if not from then
			out[#out + 1] = s:sub(pos)
			break
		end
		out[#out + 1] = s:sub(pos, from - 1)
		pos = to + 1
	end
	return out
end

--- Split "host:port", tolerating bracketed IPv6 literals.
function M.split_hostport(s)
	s = tostring(s or "")

	-- Drop a path/query/fragment a caller left attached. Share links carry the
	-- authority as `host:port` and several kinds follow it with `/?...` --
	-- hysteria2 always, ss whenever it has a plugin. The match below is
	-- anchored on digits, so `host:60000/` fails it, the whole string is taken
	-- as the host, and the caller's `port = port or 443` silently dials 443
	-- against a server name that can never resolve. Fixing it here covers
	-- every parser at once instead of eight separate patterns.
	s = s:match("^([^/%?#]*)") or s

	local host, port
	if s:sub(1, 1) == "[" then
		host, port = s:match("^%[([^%]]+)%]:(%d+)$")
		if not host then host = s:match("^%[([^%]]+)%]$") end
	else
		host, port = s:match("^(.-):(%d+)$")
		if not host then host = s end
	end
	return host, tonumber(port)
end

--- Parse an "a=1&b=2" query string into a table. Bare keys map to "".
function M.parse_query(qs)
	local q = {}
	if type(qs) ~= "string" or qs == "" then return q end
	for pair in qs:gmatch("[^&]+") do
		local k, v = pair:match("^([^=]+)=(.*)$")
		if k then
			q[M.url_decode(k)] = M.url_decode(v)
		else
			q[M.url_decode(pair)] = ""
		end
	end
	return q
end

--- Quote a value for safe interpolation into a /bin/sh command line.
function M.shell_quote(s)
	return "'" .. tostring(s):gsub("'", "'\\''") .. "'"
end

--- UCI booleans and common string spellings -> Lua boolean.
function M.to_bool(v)
	if v == nil then return false end
	if type(v) == "boolean" then return v end
	if type(v) == "number" then return v ~= 0 end
	v = tostring(v):lower()
	return v == "1" or v == "true" or v == "yes" or v == "on" or v == "enabled"
end

--- Read a whole file. Returns nil plus an error string on failure.
function M.read_file(path)
	local fh, err = io.open(path, "r")
	if not fh then return nil, err end
	local data = fh:read("*a")
	fh:close()
	return data
end

--- Run a command and capture stdout. Returns output, exit-status-ish boolean.
function M.exec(cmd)
	local fh = io.popen(cmd .. " 2>/dev/null")
	if not fh then return nil, false end
	local out = fh:read("*a")
	local ok = fh:close()
	return out, ok
end

--- True when every character is a valid hostname label character.
function M.is_valid_host(h)
	if type(h) ~= "string" or h == "" then return false end
	if h:match("^%d+%.%d+%.%d+%.%d+$") then return true end
	if h:match("^[%x:]+$") and h:find(":") then return true end -- IPv6 literal
	return h:match("^[%w%.%-]+$") ~= nil and not h:match("^[%.%-]") and not h:match("[%.%-]$")
end

--- Monotonic-ish unique tag suffix, so repeated imports never collide.
local seq = 0
function M.next_seq()
	seq = seq + 1
	return seq
end

return M
