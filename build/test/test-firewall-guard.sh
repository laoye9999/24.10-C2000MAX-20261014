#!/bin/sh
# Regression tests for firewall-guard.sh.
#
# The guard is a shell script whose whole job is to drive iptables, so it is
# tested by giving it a sandbox to drive instead: a PATH of fakes for the
# commands it uses to look at the world (netstat, ip, nslookup, logger,
# start-stop-daemon), a fake firewall.sh it can call, and state files the test
# flips to make the port, the WAN or the resolver disappear. The phases, the
# tick arithmetic, the teardown decision and the recovery budget are all the
# real script -- only the observations are synthetic.
#
#   build/test/test-firewall-guard.sh [test-name ...]
#
# Needs nothing beyond a POSIX shell, grep and sleep.

set -u

HERE=$(cd "$(dirname "$0")" && pwd)
GUARD=$HERE/../data/usr/share/homeproxy/firewall-guard.sh

[ -f "$GUARD" ] || { echo "cannot find firewall-guard.sh at $GUARD" >&2; exit 2; }

PORT=5330
TOTAL_PASS=0
TOTAL_FAIL=0
CURRENT=""
GUARD_JOB=""

# ------------------------------------------------------------------ harness

sandbox() {
	SB=$(mktemp -d "${TMPDIR:-/tmp}/hpg-test.XXXXXX")
	mkdir -p "$SB/bin" "$SB/state" "$SB/run"
	# The fakes read their inputs from $STATE, so this is the directory
	# holding port/wan/dns/rules -- not the sandbox root.
	export STATE="$SB/state"

	state port 1
	state wan 1
	state dns 1
	state rules 0
	: > "$SB/state/calls"
	: > "$SB/state/log"

	cat > "$SB/bin/netstat" <<'EOF'
#!/bin/sh
[ "$(cat "$STATE/port")" = "1" ] && echo "tcp 0 0 0.0.0.0:5330 0.0.0.0:* LISTEN"
exit 0
EOF

	cat > "$SB/bin/ip" <<'EOF'
#!/bin/sh
[ "$(cat "$STATE/wan")" = "1" ] && echo "default via 192.168.31.1 dev eth1"
exit 0
EOF

	# Both halves of the busybox nslookup output, because the guard's check is
	# anchored on the answer line and a fake that omitted the Server header
	# would not exercise the thing that check was written for.
	cat > "$SB/bin/nslookup" <<'EOF'
#!/bin/sh
if [ "$(cat "$STATE/dns")" != "1" ]; then
	echo "Server:		127.0.0.1"
	echo "Address:	127.0.0.1:53"
	echo "** server can't find $1: NXDOMAIN"
	exit 1
fi
echo "Server:		127.0.0.1"
echo "Address:	127.0.0.1:53"
echo "Name:	$1"
echo "Address: 39.156.66.10"
EOF

	cat > "$SB/bin/logger" <<'EOF'
#!/bin/sh
echo "$*" >> "$STATE/log"
EOF

	# Logged, never run: a real recovery would restart the service under test.
	cat > "$SB/bin/start-stop-daemon" <<'EOF'
#!/bin/sh
echo "start-stop-daemon $*" >> "$STATE/calls"
exit 0
EOF

	# Stands in for the real firewall.sh. `check` derives its answer from the
	# same file `up` and `down` write, so the test can also drop the rules out
	# from under the guard the way the vendor's eqos does.
	#
	# It also records whether fd 1000 is open in itself. This runs as a child
	# of the guard and inherits the guard's descriptors -- verified for
	# both /bin/sh and busybox sh, neither of which closes high fds when it
	# runs a script -- so it is a faithful report of the guard's own table
	# without needing /proc of another process, which macOS lacks.
	cat > "$SB/bin/firewall.sh" <<'EOF'
#!/bin/sh
echo "firewall:$1" >> "$STATE/calls"
if [ -e /dev/fd/1000 ] || [ -e /proc/self/fd/1000 ]; then
	echo open > "$STATE/fd1000"
else
	echo closed > "$STATE/fd1000"
fi
case "$1" in
	check) [ "$(cat "$STATE/rules")" = "1" ] && exit 0 || exit 1 ;;
	up)    echo 1 > "$STATE/rules"; exit 0 ;;
	down)  echo 0 > "$STATE/rules"; exit 0 ;;
esac
exit 2
EOF

	chmod +x "$SB/bin"/*
}

state() { echo "$2" > "$SB/state/$1"; }
get()   { cat "$SB/state/$1" 2>/dev/null; }
calls() { cat "$SB/state/calls" 2>/dev/null; }
log()   { cat "$SB/state/log" 2>/dev/null; }

count_call() {
	# grep -c prints 0 and exits 1 when nothing matches; the count is what
	# matters, not the status.
	n=$(grep -c -- "$1" "$SB/state/calls" 2>/dev/null)
	echo "${n:-0}"
}

last_fw_call() {
	grep '^firewall:' "$SB/state/calls" 2>/dev/null | tail -n 1
}

# Start the guard against the sandbox. TICK 1 and GONE_TICKS 2 turn a twenty
# second production outage into two seconds; the ratios are unchanged.
#
# The optional argument is the acquire window (the real script's second
# parameter, 180s in production). It defaults to 1 so that every test except
# the ones that are *about* phase 1 spends its time in the watch phase, which
# is where the outage logic lives.
start_guard() {
	PATH="$SB/bin:$PATH" STATE="$SB/state" \
	FIREWALL="$SB/bin/firewall.sh" \
	RECOVER_FILE="$SB/run/recover" \
	TICK=1 GONE_TICKS=2 PROBE_TICKS=1 VERIFY_TICKS=1 HEALTHY_TICKS=100000 \
	MAX_RECOVER=${MAX_RECOVER:-3} RECOVER_WINDOW=${RECOVER_WINDOW:-1800} \
		sh "$GUARD" "$PORT" "${1:-1}" &
	GUARD_JOB=$!
}

stop_guard() {
	[ -n "$GUARD_JOB" ] || return 0
	kill "$GUARD_JOB" 2>/dev/null
	wait "$GUARD_JOB" 2>/dev/null
	GUARD_JOB=""
}

cleanup() {
	stop_guard
	[ -n "${SB:-}" ] && rm -rf "$SB"
}

expect() {
	if [ "$2" = "$3" ]; then
		TOTAL_PASS=$((TOTAL_PASS + 1))
		printf '    ok    %s\n' "$1"
	else
		TOTAL_FAIL=$((TOTAL_FAIL + 1))
		printf '    FAIL  %s\n' "$1"
		printf '          expected [%s], got [%s]\n' "$2" "$3"
		[ -n "$(log)" ] && printf '          log: %s\n' "$(tr '\n' '|' < "$SB/state/log")"
	fi
}

test_case() {
	CURRENT=$1
	printf '\n  %s\n' "$CURRENT"
	sandbox
	"$CURRENT"
	stop_guard
	rm -rf "$SB"
	unset SB
}

# -------------------------------------------------------------- the cases

# The regression this whole phase exists for. Before it, the rules stayed
# installed for as long as nobody restarted the service, so a dead proxy left
# every LAN client pointed at a closed socket.
test_dead_proxy_pulls_the_rules() {
	start_guard
	sleep 2
	expect "installs the rules once the port and WAN are up" "1" "$(get rules)"

	state port 0
	sleep 4
	expect "the rules are gone" "0" "$(get rules)"
	expect "down was called" "1" "$(count_call 'firewall:down')"
	expect "and it was the last thing done to the firewall" \
		"firewall:down" "$(last_fw_call)"

	# The proxy comes back -- by recovery, or by the user pressing start. The
	# guard has stayed resident and must pick the rules back up.
	state port 1
	sleep 3
	expect "the rules are reinstalled when the proxy returns" "1" "$(get rules)"
}

# A restart is not an outage. /etc/init.d/homeproxy restart stops sing-box and
# starts it again, and the port is closed for a second or two in between;
# tearing the firewall down for that would churn the LAN on every config save.
test_brief_gap_does_not_pull_the_rules() {
	start_guard
	sleep 2
	expect "installs the rules" "1" "$(get rules)"

	state port 0
	sleep 1
	state port 1
	sleep 2

	expect "a one-tick gap leaves the rules alone" "0" "$(count_call 'firewall:down')"
	expect "the rules are still up" "1" "$(get rules)"
}

# The guard used to exit after its timeout, which meant a proxy that never came
# up was never noticed again -- and, worse, an *existing* install was never
# revisited. It now waits indefinitely, but must still never install early.
test_never_installs_before_the_proxy_listens() {
	state port 0
	start_guard
	sleep 4

	expect "never calls up" "0" "$(count_call 'firewall:up')"
	expect "leaves the rules absent" "0" "$(get rules)"

	state port 1
	sleep 2
	expect "and installs as soon as it does listen" "1" "$(get rules)"
}

# Deliberate: with no default route nothing the LAN sends can reach the
# internet by any path, so tearing down would change nothing, and a WAN flap
# would otherwise rebuild the rules for no reason -- with a window in between
# where traffic escapes through the direct route unnoticed.
test_wan_loss_does_not_pull_the_rules() {
	start_guard
	sleep 2
	expect "installs the rules" "1" "$(get rules)"

	state wan 0
	sleep 5
	expect "the rules survive the WAN going away" "1" "$(get rules)"
	expect "down is never called" "0" "$(count_call 'firewall:down')"

	state wan 1
	sleep 2
	expect "and survive it coming back" "1" "$(get rules)"
}

# /etc/init.d/eqos flushes the built-in PREROUTING chain on every interface
# event. The hotplug hook used to be the only thing that noticed; it stands
# down while the guard is alive, so the guard has to be the one that notices.
test_rules_flushed_underneath_are_reinstalled() {
	start_guard
	sleep 2
	expect "installs the rules" "1" "$(get rules)"

	state rules 0        # eqos, from another process entirely
	sleep 3
	expect "the flush is noticed and repaired" "1" "$(get rules)"
	expect "up was called a second time" "2" "$(count_call 'firewall:up')"
	expect "nothing was torn down" "0" "$(count_call 'firewall:down')"
}

# procd gives up after five crashes; a sixth restart loop would be churn for
# nothing. The bound has to hold across outages, since each one is a fresh
# episode and only a long healthy stretch clears the budget.
test_recovery_attempts_are_bounded() {
	start_guard
	sleep 4

	outage=0
	while [ "$outage" -lt 4 ]; do
		outage=$((outage + 1))
		state port 1
		sleep 2
		state port 0
		sleep 4
	done

	expect "exactly MAX_RECOVER restarts, across four separate outages" \
		"3" "$(count_call start-stop-daemon)"
	expect "and the refusal is logged rather than repeated silently" \
		"1" "$(grep -c 'not restarting it again' "$SB/state/log" 2>/dev/null)"

	# The point of the bound is that the guard is still there afterwards: a
	# proxy that comes back late must still get its rules.
	state port 1
	sleep 3
	expect "the guard is still watching after the budget is spent" \
		"1" "$(get rules)"
}

# The acquire conditions used to latch: `if [ "$ready_port" = "0" ]` meant that
# once the port had been seen listening it was never tested again, and the
# install decision was taken from that memory. On a cold boot sing-box binds
# :5330 within seconds and the modem can take minutes, so the port was always
# seen first -- and if sing-box then died, the stale flag still authorised the
# install at the first tick where the WAN and DNS went green, putting the full
# capture in front of a closed port. That is the one state this script exists to
# prevent, and the success line would have said the proxy was listening.
#
# This test needs a phase 1 long enough to outlive the port, hence the explicit
# acquire window.
test_a_dead_listener_does_not_authorise_the_install() {
	state wan 0          # the modem has not produced a default route yet
	state port 1         # ... but sing-box has already bound the port
	start_guard 6
	sleep 2              # long enough for the old latch to have been set

	state port 0         # sing-box dies while the modem is still dialling
	state wan 1          # and then the WAN arrives
	sleep 3

	expect "a port seen earlier does not authorise an install after it is gone" \
		"0" "$(count_call 'firewall:up')"
	expect "the rules stay off" "0" "$(get rules)"

	state port 1
	sleep 3
	expect "and it installs once the port is genuinely back" "1" "$(get rules)"
}

# The guard reaches the target through /etc/rc.common, whose start() takes
# procd's per-service lock on fd 1000 and expects it back when the process
# that took it exits (procd_lock, /lib/functions/procd.sh:55). Every other
# service does exit; a resident guard does not, so unless it closes the fd
# itself the lock is held for the whole life of the service.
#
# Then every later stop() and reload() -- both of which begin with that same
# lock, and both of which fall through to a *blocking* flock when the
# non-blocking attempt fails -- waits on it forever. That is not theoretical:
# an opkg install of r26 parked for minutes with its prerm stuck at
# `/etc/init.d/homeproxy stop`, and the package database was left
# mid-transaction. It also made try_recover() unreachable, since the recovery
# it asks for is exactly that restart.
#
# The fd is opened here before the guard starts, so the guard inherits it
# exactly as start-stop-daemon hands it over. The fake firewall.sh reports
# what it sees, and that child is the guard's own descriptor table.
test_the_guard_closes_the_procd_lock_it_inherited() {
	exec 1000>"$SB/run/procd_homeproxy.lock"

	start_guard
	sleep 3

	expect "the guard does not keep procd's lock fd open" \
		"closed" "$(get fd1000)"
	expect "and it did get far enough to call the firewall" \
		"1" "$(get rules)"

	exec 1000>&-
}

# ------------------------------------------------------------------ driver

CASE_LIST="test_dead_proxy_pulls_the_rules
test_brief_gap_does_not_pull_the_rules
test_never_installs_before_the_proxy_listens
test_a_dead_listener_does_not_authorise_the_install
test_wan_loss_does_not_pull_the_rules
test_rules_flushed_underneath_are_reinstalled
test_recovery_attempts_are_bounded
test_the_guard_closes_the_procd_lock_it_inherited"

if [ "$#" -gt 0 ]; then
	CASE_LIST="$*"
fi

trap cleanup EXIT

for c in $CASE_LIST; do
	test_case "$c"
done

printf '\n  %d passed, %d failed\n\n' "$TOTAL_PASS" "$TOTAL_FAIL"
[ "$TOTAL_FAIL" -eq 0 ]
