#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
# Refresh the sing-box rule sets that confgen.lua serves from local files.
#
# Why the config uses local files at all: sing-box resolves `type: remote`
# rule sets *during startup* and exits if the fetch fails. On this device
# cdn.jsdelivr.net is RST'd by the GFW, so a remote-only rule-mode config could
# never start -- procd respawned it into a crash loop and the UI just looked
# dead. Moving the files on disk means startup needs no network.
#
# This script is what keeps them current, and it is safe to fail: each file is
# downloaded to the side and swapped in only after it validates, so a failed
# refresh leaves the previous copy in place and the service running.
#
#   update-rule-sets.sh [--force]
#
# Without --force it does nothing until rule_set_interval has elapsed.

set -u

DIR=/etc/homeproxy/rule_set
STAMP=/etc/homeproxy/rule_set.stamp
TAG=homeproxy

# tag kind file -- kept in step with RULE_SETS in confgen.lua.
SETS="geoip-cn geoip cn
geosite-cn geosite cn
geosite-geolocation-!cn geosite geolocation-!cn"

# Tried in order until one yields a usable file. The canonical host,
# cdn.jsdelivr.net, is deliberately absent: it is the one that is RST'd here,
# so every refresh would pay a timeout for a fetch that cannot succeed. The
# value configured in UCI is appended below, in case the user has a mirror of
# their own -- their choice should win, but only after the ones that work.
MIRRORS="https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo
https://gcore.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo"

FORCE=0
[ "${1:-}" = "--force" ] && FORCE=1

# --- one at a time --------------------------------------------------------
# Two invocations can overlap: the cron fires every six hours, and postinst
# starts a --force refresh in the background whenever a .srs is missing. They
# would otherwise share the fixed per-set temp path below, and curl -o
# truncates -- so the second run's curl opens the file the first run is about
# to validate, and whichever finishes last can move a byte-mix of two
# downloads into place. That file passes the size and magic check and then
# fails inside sing-box at startup, which is the exact failure the local files
# exist to remove. The lock removes the class; the per-pid temp name below
# removes the instance. Non-blocking and silent: the loser is not an error,
# it is a run whose work the winner is already doing.
exec 9>/var/run/homeproxy-ruleset.lock 2>/dev/null || exit 0
flock -n 9 2>/dev/null || exit 0

# --- interval -------------------------------------------------------------
# rule_set_interval is a sing-box duration ("7d", "12h", "30m", "3600s").
# Anything unparseable falls back to a week rather than to "never".
interval_seconds() {
	v=$(uci -q get homeproxy.dns.rule_set_interval)
	[ -n "$v" ] || v=7d
	n=${v%[dhms]}
	u=${v#"$n"}
	case "$u" in
		d) echo $((n * 86400)) ;;
		h) echo $((n * 3600)) ;;
		m) echo $((n * 60)) ;;
		s) echo "$n" ;;
		*) [ "$v" = "${v#*[!0-9]}" ] && echo "$v" || echo 604800 ;;
	esac
}

# --- download -------------------------------------------------------------
# A usable rule set is 512 bytes or more and starts with the SRS magic. The
# size floor catches a connection cut mid-transfer; the magic catches an HTML
# error page saved under the right name. Either one reaching sing-box is fatal
# at startup, so the bar is checked here rather than trusted.
fetch_one() {
	url=$1
	dst=$2
	# Named per process. It used to be a fixed path shared by every run, which
	# matters because the check below reads the file back off disk rather than
	# reading what this curl wrote.
	tmp="$DIR/.$(basename "$dst").tmp.$$"

	curl -fsS --max-time 120 --connect-timeout 10 -o "$tmp" "$url" 2>/dev/null || {
		rm -f "$tmp"
		return 1
	}

	size=$(wc -c < "$tmp" 2>/dev/null || echo 0)
	if [ "$size" -lt 512 ]; then
		rm -f "$tmp"
		return 1
	fi
	if [ "$(head -c 3 "$tmp" 2>/dev/null)" != "SRS" ]; then
		rm -f "$tmp"
		return 1
	fi

	mv -f "$tmp" "$dst"
	return 0
}

# --- throttle -------------------------------------------------------------
if [ "$FORCE" = "0" ] && [ -f "$STAMP" ]; then
	age=$(( $(date +%s) - $(date -r "$STAMP" +%s 2>/dev/null || echo 0) ))
	want=$(interval_seconds)
	# Sub-hour intervals would have the cron run every time; the cron is what
	# actually sets the floor.
	[ "$age" -lt "$want" ] && exit 0
fi

mkdir -p "$DIR"

# The user's configured base, if it is not one we already try.
base=$(uci -q get homeproxy.dns.rule_set_base)
case "$base" in
	https://fastly.jsdelivr.net/*|https://gcore.jsdelivr.net/*) base= ;;
	"") base= ;;
	*) MIRRORS="$MIRRORS
$base" ;;
esac

# The loop body runs in a subshell (it is fed by a pipe), so state that has to
# outlive it is kept in a file rather than a variable.
rm -f /tmp/.homeproxy-ruleset-changed /tmp/.homeproxy-ruleset-failed

echo "$SETS" | while read -r tag kind file; do
	[ -n "$tag" ] || continue

	old=""
	[ -f "$DIR/$tag.srs" ] && old=$(md5sum "$DIR/$tag.srs" | cut -d' ' -f1)

	ok=0
	for m in $MIRRORS; do
		if fetch_one "$m/$kind/$file.srs" "$DIR/$tag.srs"; then
			ok=1
			break
		fi
	done

	if [ "$ok" = "0" ]; then
		logger -t "$TAG" "rule set $tag: every mirror failed, keeping the existing copy"
		touch /tmp/.homeproxy-ruleset-failed
		continue
	fi

	new=$(md5sum "$DIR/$tag.srs" | cut -d' ' -f1)
	if [ "$old" != "$new" ]; then
		logger -t "$TAG" "rule set $tag updated"
		# The restart has to happen outside this loop's subshell, so it is
		# recorded and acted on below.
		touch /tmp/.homeproxy-ruleset-changed
	fi
done

# The stamp is the throttle's memory, so it records *success*, not "we ran".
#
# It used to be touched unconditionally, which made a run in which every mirror
# failed indistinguishable from a good one: the cron firing while the modem is
# still dialling, or the postinst --force fetch on a box with no WAN, wrote the
# stamp and suppressed the next attempt for the whole rule_set_interval -- a
# week by default. That is backwards for a *missing or truncated* file, where
# this throttle is the only automatic repair path there is: confgen falls back
# to `type: remote` for the tag, which is exactly the startup-time download the
# local files exist to remove, and the file then stays broken for a week.
#
# A partial failure counts as failure for the same reason: it is the sets that
# did not arrive that need the next run, and stamping would defer those too.
if [ -f /tmp/.homeproxy-ruleset-failed ]; then
	rm -f /tmp/.homeproxy-ruleset-failed
	logger -t "$TAG" "not advancing the rule-set throttle: a set failed to refresh, so the next run retries"
else
	touch "$STAMP"
fi

# No restart.
#
# The comment here used to say local rule sets are read once at startup, so a
# changed file needs a restart. That is not true of this core. sing-box watches
# the directory these files live in and reloads a set when its file is replaced:
#
#   p=$(pgrep -f 'sing-box run')
#   ls -l /proc/$p/fd                       # three anon_inode:inotify fds
#   cat /proc/$p/fdinfo/<each of them>      # all name ino:59 sdev:12, mask:fc6
#   ls -id /etc/homeproxy/rule_set          # inode 89 == 0x59 -- the directory
#
# The mask fc6 includes IN_MOVED_TO and IN_CREATE, which is exactly what the
# `mv -f "$tmp" "$dst"` above produces -- the watcher is the `fswatch` package
# sing-box links for this (> strings /usr/bin/sing-box | grep fswatch), and it
# handles rename-replace on purpose. Verified on the device against sing-box
# 1.12.25.
#
# So the restart was a full service bounce for a file that had already been
# reloaded. The cost was not just the bounce: stop removes the firewall rules,
# and start re-enters the guard's acquire gate, which waits for the port, the
# WAN *and* a working resolver before the rules go back. Healthy, that is a few
# seconds of dropped connections for every LAN flow. If the WAN happened to be
# down when the six-hourly cron fired, the LAN stayed on the direct route until
# the gate opened -- minutes, on this device's modem -- during a refresh that
# changed nothing about routing.
#
# Re-run the four commands above if sing-box is ever downgraded: the watcher is
# a property of the core, not of this script.
if [ -f /tmp/.homeproxy-ruleset-changed ]; then
	rm -f /tmp/.homeproxy-ruleset-changed
	logger -t "$TAG" "rule sets changed; sing-box reloads local sets in place, no restart needed"
fi

exit 0
