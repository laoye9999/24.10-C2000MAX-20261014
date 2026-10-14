#!/usr/bin/env lua
-- Regression test for the DNS `strategy` option.
--
-- Unlike test-firewall-guard.sh this one cannot run in the build environment,
-- because there is no Lua there. It runs on the target. This file is under
-- build/test/, which is not packaged, so it is pushed rather than installed:
--
--     scp build/test/test-confgen.lua root@192.168.66.1:/tmp/
--     ssh root@192.168.66.1 'lua /tmp/test-confgen.lua'
--
-- The module under test defaults to the installed one. To test a copy that
-- is not installed yet, push that too and name it:
--
--     ssh root@192.168.66.1 'lua /tmp/test-confgen.lua /tmp/confgen.lua'
--
-- What it pins down: the option is spelled `strategy` in every place that
-- touches it -- /etc/config/homeproxy's `config dns` section, the ListValue
-- on the status page that writes it, and the generator that reads it. The
-- generator used to read `dns_strategy`, which is an option that exists
-- nowhere, so the lookup always missed and always fell through to the
-- built-in default. The generated config therefore said `prefer_ipv4` no
-- matter what the dropdown was set to, and the dropdown looked like it
-- worked because the default happened to match what it shipped with.
--
-- The check builds through the real UCI loader rather than a hand-written
-- table, so it exercises the option as it is actually stored. Pass a module
-- path as arg[1] to test a copy that is not installed yet.

package.path = '/usr/lib/lua/?.lua;' .. package.path

local module_path = arg and arg[1] or nil
if not module_path or module_path == '-' then
	module_path = '/usr/lib/lua/homeproxy/confgen.lua'
end

local f = io.open(module_path, 'r')
if not f then
	io.stderr:write('cannot read ' .. module_path .. '\n')
	os.exit(2)
end
f:close()

local ok, loader = pcall(require, 'homeproxy.uci_loader')
if not ok then
	io.stderr:write('homeproxy.uci_loader is not installed: ' .. tostring(loader) .. '\n')
	os.exit(2)
end

local cfg, err = loader.load()
if not cfg then
	io.stderr:write('could not load the config: ' .. tostring(err) .. '\n')
	os.exit(2)
end

local confgen = dofile(module_path)

local failed = 0

local function check(what, want, got)
	if want == got then
		print(string.format('    ok    %s', what))
	else
		failed = failed + 1
		print(string.format('    FAIL  %s', what))
		print(string.format('          expected [%s], got [%s]', tostring(want), tostring(got)))
	end
end

print('\n  ' .. module_path)

-- Every value the ListValue offers has to survive the round trip. Testing
-- only the shipped default would not have caught this: the point of the bug
-- is that the default is the one value that always came out.
for _, s in ipairs({ 'prefer_ipv4', 'prefer_ipv6', 'ipv4_only', 'ipv6_only' }) do
	cfg.dns.strategy = s
	check('uci strategy=' .. s .. ' reaches the generated config',
		s, confgen.build(cfg).dns.strategy)
end

-- A config that never set the option must still get a value, or the dns
-- block goes out with strategy absent.
cfg.dns.strategy = nil
check('an unset option still yields the built-in default',
	'prefer_ipv4', confgen.build(cfg).dns.strategy)

print(string.format('\n  %d passed, %d failed\n', 5 - failed, failed))
os.exit(failed == 0 and 0 or 1)
