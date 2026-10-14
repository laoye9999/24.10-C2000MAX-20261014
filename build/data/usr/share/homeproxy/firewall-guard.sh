#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
# homeproxy 21.02 backport -- firewall setup, and the watchdog that follows it.
#
# This script runs in two phases and never installs the rules before the proxy
# can serve them.
#
# --- phase 1: acquire ------------------------------------------------------
#
# The firewall rules are installed here and never by the init script directly.
# Three conditions must all hold first:
#
#   1. the tproxy port is listening,
#   2. the WAN has a default route, and
#   3. the uplink can actually resolve a name
#
# Until all three are true the LAN is left completely alone and keeps working
# through the ordinary router path.
#
# On a cold boot this device's WAN is behind a modem that takes minutes to get
# an address; sing-box started without a default interface fails every dial
# with "no route to host", so capturing the LAN then removes the connection
# rather than degrading it -- measured at roughly three minutes of total outage
# on a reboot.
#
# The DNS check catches the second half of that window: a default route can
# exist for a minute or more before the upstream resolver answers, and
# capturing the LAN in between pointed every client at a proxy that could not
# even resolve its own node's hostname. Domestic traffic worked, everything
# foreign timed out.
#
# If the conditions never hold the script does not give up -- it falls through
# to phase 2 and keeps waiting, because the same three conditions decide
# whether the rules belong up at any later moment too.
#
# Satisfying the conditions is not the same as installing successfully, so a
# failed install is *retried*, not treated as final. On a cold boot this
# firmware has not always loaded the iptables extension modules that
# `-j TPROXY` needs -- the vendor's own S99access_ctl hits "No chain/target/
# match by that name" around the same moment -- and firewall.sh runs under
# `set -e`, so it aborts on the first such failure. Measured on the HC-WT9303:
# the install failed at boot+33s, a manual restart two minutes later succeeded
# with the same arguments.
#
# --- phase 2: watch --------------------------------------------------------
#
# The rules, once installed, used to be left alone forever. That is the one
# state this device must never be in and the one nothing was checking: TPROXY
# rules in front of a port that nobody is listening on. A marked packet is
# delivered to a closed socket and dropped -- no RST, no ICMP, no fallback --
# so every LAN flow to a public address stops dead instead of falling back to
# the ordinary route. Reproduced before this phase existed: seven kills drove
# procd to "crash loop 6 crashes" and gave up, sing-box stayed dead, the mangle
# jump was still installed, and `firewall.sh check` still reported success.
# The UI showed a running service; the LAN had no internet and no explanation.
#
# So the guard now stays resident and keeps the two in step:
#
#   * the port gone for GONE_TICKS -- pull the rules, so the LAN falls back to
#     the direct route instead of a black hole;
#   * the rules gone but the port alive -- put them back (the vendor's eqos
#     flushes the built-in PREROUTING chain on every interface event, which is
#     what /etc/hotplug.d/iface/99-homeproxy exists for; that hook stands down
#     while this guard is running -- see the kill -0 on guard.pid there -- so
#     the job is this loop's while the guard lives);
#   * the port back after either -- resume installing, on the same three
#     conditions as phase 1.
#
# It deliberately does NOT tear down when the WAN goes away. With no default
# route nothing the LAN sends can reach the internet by any path, so removing
# the rules would change nothing; and when the WAN returns the rules are
# already correct. Tearing down on a flap would only add a rebuild cycle and,
# worse, a window where traffic escapes through the direct route unnoticed.
#
#   firewall-guard.sh <port> [acquire-timeout-seconds]

port=$1
acquire=${2:-180}

[ -n "$port" ] || exit 1

# --- the inherited procd lock, and why it has to go -----------------------
#
# The init script reaches this process through /etc/rc.common, whose start()
# takes procd's per-service lock before it does anything else:
#
#     exec 1000>"/tmp/lock/procd_homeproxy.lock"
#     flock 1000
#
# (procd_lock, /lib/functions/procd.sh:55). rc.common expects that lock to go
# away when the process which took it exits, and for every other service it
# does. A guard that stays resident does not: start-stop-daemon forks, the fd
# is inherited, and the lock is then held for as long as the service runs, by
# a process that will never release it.
#
# What that breaks is every later rc.common stop() and reload(). Both begin
# with procd_lock, and both start with a *non-blocking* `flock -n 1000` that
# fails against the lock we are sitting on -- so each falls through to the
# blocking `flock 1000` on the next line and waits there forever. Measured on
# the target: an `opkg install` of r26 sat for four minutes with its prerm
# stopped at `/etc/init.d/homeproxy stop`, which sat behind a /etc/rc.common
# `stop` blocked in `flock 1000`, which sat behind this guard. It would have
# waited indefinitely, and the package database was left mid-transaction.
#
# And the part that matters most here: try_recover() below asks for exactly
# that restart, so the recovery path could never have completed either. The
# one safety net this script exists to provide was unreachable.
#
# fd 1000 is procd's and nothing in this script uses it. Close it here, at the
# top, so that everything started afterwards -- including the recovery helper
# -- is born without it.
exec 1000>&-

# Resolving is the cheapest proof that the uplink is genuinely usable. Ping is
# not an option: this device's upstream gateway does not answer it.
PROBE_NAME=${PROBE_NAME:-www.baidu.com}

FIREWALL=${FIREWALL:-/usr/share/homeproxy/firewall.sh}

# Recovery budget, kept in a file rather than a variable because the guard
# that spends it is not the guard that reads it back: a recovery restart hands
# off to a fresh process.
RECOVER_FILE=${RECOVER_FILE:-/var/run/homeproxy/guard-recover}

# Watch-phase timings. TICK is the loop period in seconds and the unit every
# other value below is expressed in, so they stay proportional if it changes.
#
# Every value here is overridable from the environment, which is what lets
# test/test-firewall-guard.sh drive a whole outage in a few seconds instead of
# the twenty it takes in production. Nothing on the device sets them.
TICK=${TICK:-2}
GONE_TICKS=${GONE_TICKS:-10}          # 20s without a listener before the rules are pulled
PROBE_TICKS=${PROBE_TICKS:-5}         # 10s between uplink probes while waiting to install
VERIFY_TICKS=${VERIFY_TICKS:-5}       # 10s between "are the rules still there" checks
HEALTHY_TICKS=${HEALTHY_TICKS:-300}   # 10min of a live listener clears the recovery budget

# A recovery restart is bounded. procd has already made five attempts and given
# up by the time this fires, so if three more do not help the cause is not
# transient -- a wrong node, a missing binary, a config sing-box rejects -- and
# another attempt only adds churn. After the window expires the budget is
# available again, on the grounds that something may have been fixed since.
MAX_RECOVER=${MAX_RECOVER:-3}
RECOVER_WINDOW=${RECOVER_WINDOW:-1800}

log_msg() { logger -t homeproxy "$*"; }

# The match has to be on the *answer*, not on the resolver header.
#
# busybox nslookup prints this whenever the resolver replied at all, including
# when the reply is NXDOMAIN:
#
#     Server:             127.0.0.1
#     Address:    127.0.0.1:53
#
# so a `grep -q "^Address"` is satisfied by a lookup that resolved nothing --
# it only ever proved that dnsmasq was up, which is the state this check exists
# to look past. Verified on the target: a query for a name under .invalid still
# prints that header before "** server can't find ...: NXDOMAIN".
#
# The answer line carries no :port suffix, so anchoring on a bare dotted quad
# skips the server line while still matching every answer. Verified on the
# target against both a working lookup and a guaranteed NXDOMAIN.
uplink_ok() {
	nslookup "$PROBE_NAME" 2>/dev/null \
		| grep -qE '^Address: *[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+ *$'
}

port_listening() {
	netstat -lnt 2>/dev/null | grep -q ":$port "
}

wan_up() {
	ip route show default 2>/dev/null | grep -q .
}

# Exit 0 only when the rules are both present and attached -- the same test the
# hotplug hook makes. Deriving this from the rules rather than remembering it
# is what catches eqos flushing them behind our back.
rules_present() {
	"$FIREWALL" check >/dev/null 2>&1
}

# --- recovery budget -------------------------------------------------------
# Stored as "count last-epoch". Anything unreadable reads back as 0, which is
# the permissive direction: a corrupt file allows another restart rather than
# locking recovery out for good.

recover_count() {
	rc=$(cat "$RECOVER_FILE" 2>/dev/null)
	rc=${rc%% *}
	case "$rc" in
		''|*[!0-9]*) echo 0 ;;
		*) echo "$rc" ;;
	esac
}

recover_last() {
	rl=$(cat "$RECOVER_FILE" 2>/dev/null)
	rl=${rl##* }
	case "$rl" in
		''|*[!0-9]*) echo 0 ;;
		*) echo "$rl" ;;
	esac
}

spend_recover() {
	printf '%s %s\n' "$(( $(recover_count) + 1 ))" "$(date +%s)" > "$RECOVER_FILE"
}

# --- recovery --------------------------------------------------------------

# The proxy is not listening: safe while the rules are down, but nothing is
# proxied. Ask the init script for one more attempt, bounded as described
# above. Called once per outage -- see the caller for why that matters.
#
# The restart must not run as a child of this script. The init script's
# stop_guard collects the guard's children with `pgrep -P` and kills them
# before it does anything else, and `/etc/init.d/homeproxy restart` is exactly
# what calls it -- so a restart this script forked would be killed by its own
# hand-off, halfway, after stopping the service and before starting it again.
# start-stop-daemon -b forks and exits, so the helper is reparented to init and
# is never listed as a child of ours, and its `sleep` outlives this call.
# Staying resident rather than exiting also keeps guard.pid valid across the
# hand-off, which is what stops the hotplug hook from re-installing rules in
# the gap.
try_recover() {
	count=$(recover_count)

	if [ "$count" -ge "$MAX_RECOVER" ]; then
		if [ $(( $(date +%s) - $(recover_last) )) -lt "$RECOVER_WINDOW" ]; then
			log_msg "proxy is not listening and $count recovery attempts have already failed; not restarting it again for now. Check the log, or start the service by hand."
			return 0
		fi
	fi

	spend_recover
	log_msg "proxy is not listening, restarting homeproxy (attempt $(( count + 1 )) of $MAX_RECOVER) so the rules can come back"
	start-stop-daemon -S -b -x /bin/sh -- \
		-c 'sleep 5; /etc/init.d/homeproxy restart >/dev/null 2>&1'
	return 0
}

# --- phase 1: acquire ------------------------------------------------------

ready_port=0
ready_wan=0
i=0
attempts=0
installed=0

while [ "$i" -lt "$acquire" ]; do
	# Read afresh every tick, not latched.
	#
	# These two used to be set once and never re-evaluated -- `if [ "$x" = "0" ]`
	# means that after the first success the test is never made again -- so the
	# install decision below was taken from a memory of the state rather than
	# from the state. On a cold boot sing-box binds :5330 within seconds and the
	# modem can take minutes, so the port was seen long before the WAN, and the
	# flag then authorised the install at the first tick where WAN and DNS went
	# green. If sing-box had died in between (OOM, or a crash loop that has
	# already spent procd's five respawns) that installs the full capture in
	# front of a dead port -- the one state this script exists to prevent -- and
	# the success line below would say the proxy was listening.
	#
	# Written as nested ifs rather than `[ x ] && y=1`: that form happens to work
	# here but relies on && / || precedence that is easy to misread.
	ready_port=0
	if port_listening; then
		ready_port=1
	fi

	ready_wan=0
	if wan_up; then
		ready_wan=1
	fi

	if [ "$ready_port" = "1" ] && [ "$ready_wan" = "1" ]; then
		# Only worth probing once the cheap conditions hold.
		if uplink_ok; then
			# `up` tears down before it builds, so retrying cannot
			# accumulate a half-installed ruleset -- each attempt starts
			# from the clean state do_down leaves behind.
			out=$("$FIREWALL" up 2>&1)
			status=$?
			if [ "$status" -eq 0 ]; then
				log_msg "proxy listening on :$port, WAN up and DNS answering, firewall rules installed"
				installed=1
				break
			fi

			attempts=$((attempts + 1))

			# The reason is worth recording because this script's own
			# stdio goes to /dev/null (start-stop-daemon -b), so nothing
			# else will ever surface it. Only the first one is logged:
			# the output does not change between attempts and this runs
			# once a second.
			if [ "$attempts" = "1" ]; then
				reason=$(printf '%s' "$out" | tr '\n' ';')
				log_msg "firewall setup failed, retrying until ${acquire}s: $reason"
			fi
		fi
	fi

	sleep 1
	i=$((i + 1))
done

if [ "$installed" = "1" ]; then
	:
elif [ "$attempts" -gt 0 ]; then
	log_msg "no rules after ${acquire}s (port=$ready_port wan=$ready_wan, $attempts failed install attempt(s)); LAN keeps working directly, still watching"
else
	log_msg "no rules after ${acquire}s (port=$ready_port wan=$ready_wan); LAN keeps working directly, still watching"
fi

# --- phase 2: watch --------------------------------------------------------

down_ticks=0
up_ticks=0
t=0
install_fails=0
recovered_this_outage=0

while :; do
	sleep "$TICK"
	t=$((t + 1))

	if port_listening; then
		down_ticks=0
		recovered_this_outage=0

		up_ticks=$((up_ticks + 1))
		if [ "$up_ticks" -ge "$HEALTHY_TICKS" ]; then
			up_ticks=0
			# A long healthy stretch means whatever went wrong is over;
			# give the next failure a fresh budget rather than letting an
			# old one expire under it.
			if [ "$(recover_count)" != "0" ]; then
				printf '0 0\n' > "$RECOVER_FILE"
				log_msg "proxy healthy for $(( HEALTHY_TICKS * TICK ))s, recovery budget reset"
			fi
		fi

		# Trust the rules, not the memory of having installed them. eqos
		# flushes the built-in PREROUTING chain on every interface event,
		# so "installed" from an earlier tick is not evidence that the jump
		# is still there. Checked on this tick and not on every tick
		# because the check costs two iptables calls.
		if [ "$installed" = "1" ] && [ $(( t % VERIFY_TICKS )) -eq 0 ]; then
			if ! rules_present; then
				installed=0
				install_fails=0
				log_msg "mangle rules are gone (an interface event flushed them); reinstalling"
			fi
		fi

		# Runs on the same tick as the verify above, so a flush is noticed
		# and repaired without waiting for another probe.
		if [ "$installed" = "0" ] && [ $(( t % PROBE_TICKS )) -eq 0 ]; then
			if wan_up && uplink_ok; then
				if out=$("$FIREWALL" up 2>&1); then
					installed=1
					install_fails=0
					log_msg "firewall rules installed"
				else
					install_fails=$((install_fails + 1))
					if [ "$install_fails" = "1" ]; then
						reason=$(printf '%s' "$out" | tr '\n' ';')
						log_msg "firewall setup failed, will keep retrying: $reason"
					fi
				fi
			fi
		fi
	else
		up_ticks=0
		down_ticks=$((down_ticks + 1))

		if [ "$down_ticks" -ge "$GONE_TICKS" ]; then
			# The whole point of this phase, and only when the rules are
			# actually up: with nothing installed there is nothing to
			# black-hole and nothing to undo.
			if [ "$installed" = "1" ]; then
				"$FIREWALL" down >/dev/null 2>&1
				installed=0
				install_fails=0
				log_msg "proxy has not been listening on :$port for $(( GONE_TICKS * TICK ))s; firewall rules removed so the LAN falls back to a direct route"
			fi

			# Once per outage, not once per tick -- try_recover spends a
			# unit of the budget every time it is called, so calling it
			# from this branch unguarded would burn all three attempts in
			# six seconds. Cleared again when the port comes back.
			if [ "$recovered_this_outage" = "0" ]; then
				recovered_this_outage=1
				try_recover
			fi
		fi
	fi
done
