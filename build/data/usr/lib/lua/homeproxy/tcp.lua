-- SPDX-License-Identifier: GPL-2.0
-- TCP reachability test for homeproxy.
--
-- Answers one question: can this router open a TCP connection to the node's
-- server:port right now? It deliberately does NOT go through sing-box -- the
-- point is to separate "the server is unreachable" from "the proxy is
-- configured wrong", which is the first thing you want to know when a node
-- stops working.
--
-- nixio is the only tool needed. This firmware's busybox `nc` is the minimal
-- build (it accepts nothing but `nc HOST PORT`), so there is no -z/-w to use.
--
-- Every call is non-blocking with a poll() timeout: a node on the far side of
-- a black hole would otherwise hang the caller for the kernel's own connect
-- timeout, which is minutes.

local M = {}

-- Returns ok, milliseconds, error-string
function M.ping(host, port, timeout_ms)
	local nixio = require "nixio"

	host = tostring(host or "")
	port = tonumber(port)
	if host == "" or not port or port < 1 or port > 65535 then
		return false, 0, "地址或端口无效"
	end

	-- nixio.poll returns (count, ready); only `out` is worth waiting for.
	local sock = nixio.socket("inet", "stream")
	if not sock then
		return false, 0, "无法创建 socket"
	end
	sock:setblocking(false)

	local s0, u0 = nixio.gettimeofday()
	local ok, err = sock:connect(host, port)
	if not ok and err ~= nixio.const.EINPROGRESS then
		sock:close()
		-- An unresolvable name lands here and nixio reports it as
		-- "No error information", which says nothing useful to a user.
		local msg = nixio.strerror(err)
		if not msg or msg == "No error information" or msg == "Success" then
			msg = "域名解析失败或地址无效"
		end
		return false, 0, msg
	end

	local cnt, ready = nixio.poll(
		{ { fd = sock, events = nixio.poll_flags("out") } }, timeout_ms)

	local s1, u1 = nixio.gettimeofday()
	local ms = (s1 - s0) * 1000 + math.floor((u1 - u0) / 1000)

	if not cnt or cnt == 0 then
		sock:close()
		return false, ms, "超时"
	end

	local rev = (ready and ready[1] and ready[1].revents) or 0
	local bad = nixio.poll_flags("err") + nixio.poll_flags("hup") + nixio.poll_flags("nval")
	sock:close()

	if nixio.bit.band(rev, bad) ~= 0 then
		return false, ms, "拒绝或不可达"
	end
	return true, ms, nil
end

return M
