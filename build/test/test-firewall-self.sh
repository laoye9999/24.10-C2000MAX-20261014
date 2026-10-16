#!/bin/sh
# Regression tests for firewall.sh's router-originated-traffic half
# (global.self_proxy), driven against the real script with fake iptables.
#
#   test/test-firewall-self.sh [case-name ...]
#
# Runs on the host: needs only sh, grep, awk. No iptables, no device.
#
# What this is actually protecting, in order of how much it costs to get wrong:
#
#   1. The `-m mark --mark <routing_mark> -j RETURN` that keeps sing-box's own
#      socket out of the chain must come FIRST, before CONNMARK --restore-mark.
#      CONNMARK restore overwrites the packet mark, so a restore in front of
#      it erases the only thing distinguishing the tunnel from the traffic
#      about to be fed into the tunnel. The result is not a broken flow, it is
#      sing-box dialling itself at line rate.
#   2. The OUTPUT chain must not be built at all unless asked. It is the one
#      piece here that can leave the box unable to reach anything new.
#   3. DNS and NTP follow global.full_tunnel, which is on by default. Leaving
#      them direct is what the bootstrap hazard argues for -- the resolver the
#      tunnel needs to find its own node must not sit behind the tunnel -- but
#      leaving them direct is also billed traffic, since the node's disguise
#      only covers what is inside the tunnel. The hazard is answered by the
#      routing_mark RETURN in 1, not by these rules, which is why the option
#      can be on by default; the test asserts both directions so that turning
#      it back off is a thing that was checked rather than assumed.
#   4. down has to remove all of it, or the box keeps an OUTPUT rule nobody
#      can see and nobody remembers installing.
#
# The rule-order assertions read the chain back the way iptables -S emits it
# rather than matching a fixed list: the fake below stores rules verbatim, so
# the assertions are about relative position, which is the property that
# matters and the one a reordering edit would break.

set -u

CURRENT=""
TOTAL_PASS=0
TOTAL_FAIL=0

# --------------------------------------------------------------------- sandbox

sandbox() {
	SB=$(mktemp -d "${TMPDIR:-/tmp}/hp-fwself.XXXXXX")
	mkdir -p "$SB/bin" "$SB/state"
	export SB STATE="$SB/state"
	: > "$STATE/calls"
	: > "$STATE/log"

	# --- fake iptables / ip6tables ------------------------------------
	#
	# Stores chains and rules in two flat files and answers -S / -C / -D from
	# them, so the script under test sees the semantics it relies on:
	# ipt_add's -C-then-A, and del_jump's parse -S output and delete by spec.
	for t in iptables ip6tables; do
		cat > "$SB/bin/$t" <<'FAKE'
#!/bin/sh
key=$(basename "$0")
chains="$STATE/chains.$key"; rules="$STATE/rules.$key"
touch "$chains" "$rules"
echo "$key $*" >> "$STATE/calls"

[ "${1:-}" = "-t" ] && { tbl=$2; shift 2; } || tbl=filter
op=${1:-}; shift
chn=${1:-}
# One shift, not two: only the chain name has been consumed so far. Tolerant
# because -N carries no spec and the list is empty by then.
[ $# -gt 0 ] && shift
spec="$*"

case "$op" in
	-N) grep -qx "$tbl|$chn" "$chains" || echo "$tbl|$chn" >> "$chains" ;;
	-A) # HP_FAIL_MATCH makes one rule unwritable, the way a missing kernel
	    # extension or a bad option does. Nothing is stored and the exit status
	    # is the failure a real iptables would return.
	    case "${HP_FAIL_MATCH:-}" in
		    "") ;;
		    *) case "$spec" in *"$HP_FAIL_MATCH"*) exit 2 ;; esac ;;
	    esac
	    echo "$tbl|$chn|$spec" >> "$rules" ;;
	-C) grep -qx "$tbl|$chn" "$chains" || exit 1
	    grep -qxF "$tbl|$chn|$spec" "$rules" || exit 1 ;;
	-D) grep -qxF "$tbl|$chn|$spec" "$rules" || exit 1
	    grep -vxF "$tbl|$chn|$spec" "$rules" > "$rules.t" && mv "$rules.t" "$rules" ;;
	-F) grep -vx "$tbl|$chn|.*" "$rules" > "$rules.t" && mv "$rules.t" "$rules" ;;
	-X) grep -vx "$tbl|$chn" "$chains" > "$chains.t" && mv "$chains.t" "$chains"
	    grep -vx "$tbl|$chn|.*" "$rules" > "$rules.t" && mv "$rules.t" "$rules" ;;
	-S) grep -qx "$tbl|$chn" "$chains" || exit 1
	    grep "^$tbl|$chn|" "$rules" | while IFS='|' read -r t c s; do
		[ -n "$s" ] && echo "-A $c $s"
	    done ;;
esac
exit 0
FAKE
		chmod +x "$SB/bin/$t"
	done

	# --- fake ip ------------------------------------------------------
	cat > "$SB/bin/ip" <<'FAKE'
#!/bin/sh
echo "ip $*" >> "$STATE/calls"
case "$*" in
	*"addr show"*)
		case "$1" in
			-6) echo "    inet6 2408:840d:6c20:47f1::1/64 scope global" ;;
			*)  echo "    inet 192.168.66.1/24 brd 192.168.66.255 scope global br-lan" ;;
		esac ;;
	*"rule show"*) : ;;                 # nothing installed yet
	*"route show"*) echo "local default dev lo" ;;
esac
exit 0
FAKE
	chmod +x "$SB/bin/ip"

	# --- fake uci -----------------------------------------------------
	cat > "$SB/bin/uci" <<'FAKE'
#!/bin/sh
# uci -q get homeproxy.<key>   (the script only ever reads)
[ "${1:-}" = "-q" ] && shift
[ "${1:-}" = "get" ] && shift
case "$1" in
	homeproxy.inbound.tproxy_port)      echo "${HP_PORT:-5330}" ;;
	homeproxy.inbound.lan_interface)    echo "br-lan" ;;
	homeproxy.global.ipv6)              echo "${HP_IPV6:-1}" ;;
	homeproxy.global.dns_hijack)        echo "1" ;;
	homeproxy.global.self_proxy)        echo "${HP_SELF:-0}" ;;
	homeproxy.global.routing_mark)      echo "${HP_RMARK:-2}" ;;
	homeproxy.global.full_tunnel)       echo "${HP_FULL_TUNNEL:-1}" ;;
	dhcp.@dnsmasq\[0\].dns_redirect|"dhcp.@dnsmasq[0].dns_redirect") echo "1" ;;
	*) exit 1 ;;
esac
exit 0
FAKE
	chmod +x "$SB/bin/uci"

	# The built-in chains always exist in real iptables and are never created
	# with -N. Seeding them is what makes `-C OUTPUT ...` (which do_check uses)
	# answer the way the device would; without it the fake reports every rule
	# in a built-in chain as missing and check always fails.
	for t in iptables ip6tables; do
		for c in PREROUTING INPUT FORWARD OUTPUT POSTROUTING; do
			echo "mangle|$c" >> "$STATE/chains.$t"
		done
	done

	# modprobe: absent is fine, the script ignores failure.
	PATH="$SB/bin:$PATH"
	export PATH

	# Never the real /var/run path: this runs on the host.
	HP_STATE_FILE="$STATE/firewall-state"
	export HP_STATE_FILE

	FIREWALL="$HP_FIREWALL"
}

# HP_KEEP=1 leaves the sandbox behind, so a failing case can be poked at by
# hand: the fake rule database is a readable file, and `sh -x` against it shows
# exactly which -C the script under test found missing.
cleanup() { [ -n "${HP_KEEP:-}" ] && { echo "    (kept $SB)"; return 0; }; [ -n "${SB:-}" ] && rm -rf "$SB"; }

# ------------------------------------------------------------------- drivers

# The HP_* knobs are passed explicitly rather than relied on to be inherited:
# `HP_SELF=1 run up` sets it for the function, but whether that reaches the
# script the function spawns is shell-dependent, and a silently-unset knob
# makes every assertion about it vacuously true.
run() {
	STATE="$STATE" PATH="$PATH" \
	HP_PORT="${HP_PORT:-}" HP_IPV6="${HP_IPV6:-}" \
	HP_SELF="${HP_SELF:-}" HP_RMARK="${HP_RMARK:-}" \
	HP_FULL_TUNNEL="${HP_FULL_TUNNEL:-}" \
	HP_FAIL_MATCH="${HP_FAIL_MATCH:-}" \
	sh "$FIREWALL" "$@" >>"$STATE/log" 2>&1
	echo $?
}

# The chain's rules, in order, one per line.
chain_rules() { # $1=tool $2=chain
	grep "^mangle|$2|" "$STATE/rules.$1" 2>/dev/null | sed "s/^mangle|$2|//"
}

chain_exists() { # $1=tool $2=chain
	grep -qx "mangle|$2" "$STATE/chains.$1" 2>/dev/null
}

# Position of the first rule matching a pattern, or empty.
pos_of() { # $1=tool $2=chain $3=pattern
	chain_rules "$1" "$2" | grep -n -e "$3" | head -n 1 | cut -d: -f1
}

expect() { # $1=what $2=want $3=got
	if [ "$2" = "$3" ]; then
		printf '    ok    %s\n' "$1"
		TOTAL_PASS=$((TOTAL_PASS + 1))
	else
		printf '    FAIL  %s\n          want: %s\n          got:  %s\n' "$1" "$2" "$3"
		TOTAL_FAIL=$((TOTAL_FAIL + 1))
		[ -s "$STATE/log" ] && sed 's/^/          | /' "$STATE/log"
	fi
}

expect_nonempty() { # $1=what $2=got
	if [ -n "$2" ]; then
		printf '    ok    %s\n' "$1"
		TOTAL_PASS=$((TOTAL_PASS + 1))
	else
		printf '    FAIL  %s (empty)\n' "$1"
		TOTAL_FAIL=$((TOTAL_FAIL + 1))
	fi
}

test_case() {
	CURRENT=$1
	printf '\n  %s\n' "$1"
	sandbox
	"$1"
	cleanup
}

# ------------------------------------------------------------------ test cases

test_self_proxy_off_builds_nothing_in_output() {
	HP_SELF=0 run up >/dev/null
	expect "OUTPUT chain not created"        "no"  "$(chain_exists iptables HOMEPROXY_OUT && echo yes || echo no)"
	expect "loopback chain not created"      "no"  "$(chain_exists iptables HOMEPROXY_LO && echo yes || echo no)"
	expect "no jump in OUTPUT"               "0"   "$(grep -c '^iptables -t mangle -A OUTPUT' "$STATE/calls")"
	expect "forwarded half still built"      "1"   "$(grep -c '^iptables -t mangle -A PREROUTING -i br-lan -j HOMEPROXY$' "$STATE/calls")"
}

test_self_proxy_on_builds_both_families() {
	HP_SELF=1 run up >/dev/null
	expect "v4 OUTPUT chain created"         "yes" "$(chain_exists iptables HOMEPROXY_OUT && echo yes || echo no)"
	expect "v4 loopback chain created"       "yes" "$(chain_exists iptables HOMEPROXY_LO && echo yes || echo no)"
	expect "v6 OUTPUT chain created"         "yes" "$(chain_exists ip6tables HOMEPROXY_OUT && echo yes || echo no)"
	expect "v6 loopback chain created"       "yes" "$(chain_exists ip6tables HOMEPROXY_LO && echo yes || echo no)"
	expect "v4 jump into OUTPUT"             "1"   "$(grep -c '^iptables -t mangle -A OUTPUT -j HOMEPROXY_OUT$' "$STATE/calls")"
	expect "v6 jump into OUTPUT"             "1"   "$(grep -c '^ip6tables -t mangle -A OUTPUT -j HOMEPROXY_OUT$' "$STATE/calls")"
	expect "v4 loopback jump"                "1"   "$(grep -c '^iptables -t mangle -A PREROUTING -i lo -j HOMEPROXY_LO$' "$STATE/calls")"
	expect "v6 loopback jump"                "1"   "$(grep -c '^ip6tables -t mangle -A PREROUTING -i lo -j HOMEPROXY_LO$' "$STATE/calls")"
}

test_the_singbox_exclusion_comes_first() {
	HP_SELF=1 HP_RMARK=2 run up >/dev/null
	excl=$(pos_of iptables HOMEPROXY_OUT '--mark 2 -j RETURN')
	mark=$(pos_of iptables HOMEPROXY_OUT '--set-mark 480')
	expect_nonempty "exclusion rule present" "$excl"
	expect_nonempty "mark rule present"      "$mark"

	# First, not merely early. Anything ahead of it -- a CONNMARK restore, a
	# range check, even a counter -- is a rule that runs before the tunnel has
	# been told apart from the traffic about to be pushed into it.
	expect "it is the first rule in the chain" "1" "$excl"

	if [ -n "$excl" ] && [ -n "$mark" ] && [ "$excl" -lt "$mark" ]; then
		printf '    ok    and it precedes every marking rule\n'
		TOTAL_PASS=$((TOTAL_PASS + 1))
	else
		printf '    FAIL  exclusion must precede the marking rules (got %s vs %s)\n' "${excl:-none}" "${mark:-none}"
		TOTAL_FAIL=$((TOTAL_FAIL + 1))
	fi
}

test_every_packet_is_marked_and_nothing_else_is() {
	HP_SELF=1 run up >/dev/null
	expect "tcp is marked unconditionally" "1" \
		"$(chain_rules iptables HOMEPROXY_OUT | grep -c -e '^-p tcp -j MARK --set-mark 480$')"
	expect "udp is marked unconditionally" "1" \
		"$(chain_rules iptables HOMEPROXY_OUT | grep -c -e '^-p udp -j MARK --set-mark 480$')"

	# No CONNMARK anywhere, on either family. Not a style preference: this
	# firmware's ip6tables has no CONNMARK extension, so a SYN-plus-restore
	# design would install cleanly on IPv4, fail on IPv6, and leave the v6 half
	# with a chain that only ever marked the first packet of each flow.
	expect "no CONNMARK in v4" "0" "$(chain_rules iptables HOMEPROXY_OUT | grep -c -e 'CONNMARK')"
	expect "no CONNMARK in v6" "0" "$(chain_rules ip6tables HOMEPROXY_OUT | grep -c -e 'CONNMARK')"

	# Nor a SYN or ctstate test, for the same reason.
	expect "no SYN-only rule"  "0" "$(chain_rules iptables HOMEPROXY_OUT | grep -c -e '--tcp-flags')"
	expect "no ctstate rule"   "0" "$(chain_rules iptables HOMEPROXY_OUT | grep -c -e 'ctstate')"

	# And ICMP is deliberately left alone: no rule may match it, or ping, IPv4
	# PMTU discovery, NDP and router advertisements would all be steered into a
	# proxy port that has no interest in any of them.
	expect "no icmp rule"  "0" "$(chain_rules iptables HOMEPROXY_OUT | grep -c -e '-p icmp')"
	expect "no icmpv6 rule" "0" "$(chain_rules ip6tables HOMEPROXY_OUT | grep -c -e 'ipv6-icmp')"
}

test_dns_and_ntp_follow_full_tunnel() {
	# full_tunnel is on in the shipped default, and when it is on the router's
	# own resolver and clock traffic goes *into* the tunnel instead of around
	# it. That is the point of the option: traffic that bypasses the tunnel
	# bypasses the node's Host header with it, and is billed. What made the
	# old RETURNs safe to remove is that the bootstrap loop this file has
	# always guarded against needs only the *node's* hostname, and sing-box
	# resolves that through a `direct` outbound carrying routing_mark -- which
	# rule (a) returns before any of this is reached.
	HP_SELF=1 run up >/dev/null
	expect "on: udp 53 not returned"  "0" "$(chain_rules iptables HOMEPROXY_OUT | grep -c -- '-p udp --dport 53 -j RETURN')"
	expect "on: tcp 53 not returned"  "0" "$(chain_rules iptables HOMEPROXY_OUT | grep -c -- '-p tcp --dport 53 -j RETURN')"
	expect "on: tcp 853 not returned" "0" "$(chain_rules iptables HOMEPROXY_OUT | grep -c -- '-p tcp --dport 853 -j RETURN')"
	expect "on: udp 123 not returned" "0" "$(chain_rules iptables HOMEPROXY_OUT | grep -c -- '-p udp --dport 123 -j RETURN')"
	expect "on: v6 udp 53 not returned"  "0" "$(chain_rules ip6tables HOMEPROXY_OUT | grep -c -- '-p udp --dport 53 -j RETURN')"
	expect "on: v6 tcp 853 not returned" "0" "$(chain_rules ip6tables HOMEPROXY_OUT | grep -c -- '-p tcp --dport 853 -j RETURN')"
	expect "on: v6 udp 123 not returned" "0" "$(chain_rules ip6tables HOMEPROXY_OUT | grep -c -- '-p udp --dport 123 -j RETURN')"

	# Not merely absent -- covered. A rule that vanished without the mark
	# behind it would drop the query, and a resolver that stops answering is
	# not obviously better than one that leaks.
	expect "on: udp still marked" "1" \
		"$(chain_rules iptables HOMEPROXY_OUT | grep -c -e '^-p udp -j MARK --set-mark 480$')"
	expect "on: v6 udp still marked" "1" \
		"$(chain_rules ip6tables HOMEPROXY_OUT | grep -c -e '^-p udp -j MARK --set-mark 480$')"

	# And with the option off the old shape comes back exactly, so nobody has
	# to reason about what the RETURNs used to be.
	HP_SELF=1 HP_FULL_TUNNEL=0 run up >/dev/null
	expect "off: udp 53 returned"   "1" "$(chain_rules iptables HOMEPROXY_OUT | grep -c -- '-p udp --dport 53 -j RETURN')"
	expect "off: tcp 53 returned"   "1" "$(chain_rules iptables HOMEPROXY_OUT | grep -c -- '-p tcp --dport 53 -j RETURN')"
	expect "off: tcp 853 returned"  "1" "$(chain_rules iptables HOMEPROXY_OUT | grep -c -- '-p tcp --dport 853 -j RETURN')"
	expect "off: udp 123 returned"  "1" "$(chain_rules iptables HOMEPROXY_OUT | grep -c -- '-p udp --dport 123 -j RETURN')"
	expect "off: v6 udp 53 returned"   "1" "$(chain_rules ip6tables HOMEPROXY_OUT | grep -c -- '-p udp --dport 53 -j RETURN')"
	expect "off: v6 tcp 853 returned"  "1" "$(chain_rules ip6tables HOMEPROXY_OUT | grep -c -- '-p tcp --dport 853 -j RETURN')"
	expect "off: v6 udp 123 returned"  "1" "$(chain_rules ip6tables HOMEPROXY_OUT | grep -c -- '-p udp --dport 123 -j RETURN')"
}

test_the_two_halves_exclude_the_same_destinations() {
	# The forwarded half and the OUTPUT half must agree about what is not
	# public internet traffic. A range missing from the forwarded half leaks
	# LAN traffic; the same range missing from the OUTPUT half can send the
	# router's own connection to its own management address -- or its WAN
	# address -- into the proxy. They are one variable today; this is what
	# notices if that stops being true.
	HP_SELF=1 run up >/dev/null
	fwd=$(chain_rules iptables HOMEPROXY | grep -- '-d .* -j RETURN' | sort)
	out=$(chain_rules iptables HOMEPROXY_OUT | grep -- '-d .* -j RETURN' | sort)
	expect "the two halves return the same destinations" "$fwd" "$out"

	fwd6=$(chain_rules ip6tables HOMEPROXY | grep -- '-d .* -j RETURN' | sort)
	out6=$(chain_rules ip6tables HOMEPROXY_OUT | grep -- '-d .* -j RETURN' | sort)
	expect "v6 likewise" "$fwd6" "$out6"

	# And it is a real list, not two empty strings agreeing with each other.
	expect_nonempty "the list is not empty" "$fwd"
}


test_the_mark_grammar_matches_the_generator() {
	# confgen.lua narrows routing_mark to plain decimal so that it agrees with
	# exactly these cases. "0x10" is the one that shows why: Lua's tonumber()
	# reads it as 16, this reads it as junk and falls back to 2, and a generator
	# marking the tunnel 16 against a firewall excluding on 2 is not a
	# misconfiguration -- it is the loop, arrived at by a disagreement over
	# spelling.
	HP_SELF=1 HP_RMARK=0x10 run up >/dev/null
	expect "hex is rejected, not read as 16" "1" \
		"$(chain_rules iptables HOMEPROXY_OUT | grep -c -e '--mark 2 -j RETURN')"

	HP_SELF=1 HP_RMARK=0 run up >/dev/null
	expect "0 is rejected (sing-box reads it as no mark)" "1" \
		"$(chain_rules iptables HOMEPROXY_OUT | grep -c -e '--mark 2 -j RETURN')"

	HP_SELF=1 HP_RMARK=7 run up >/dev/null
	expect "a plain decimal is used as given" "1" \
		"$(chain_rules iptables HOMEPROXY_OUT | grep -c -e '--mark 7 -j RETURN')"
}

test_a_mark_collision_disables_the_feature() {
	# routing_mark == FWMARK would make the exclusion rule match every packet
	# this chain is about to mark, silently proxying nothing.
	HP_SELF=1 HP_RMARK=480 run up >/dev/null
	expect "no OUTPUT chain on collision" "no" "$(chain_exists iptables HOMEPROXY_OUT && echo yes || echo no)"
	expect "and it says so"               "1"  "$(grep -c 'collides with the TPROXY mark' "$STATE/log")"
	# the forwarded half must be unaffected
	expect "forwarded half still built"   "1"  "$(grep -c '^iptables -t mangle -A PREROUTING -i br-lan -j HOMEPROXY$' "$STATE/calls")"
}

test_down_removes_everything() {
	HP_SELF=1 run up >/dev/null
	HP_SELF=1 run down >/dev/null
	expect "v4 OUTPUT chain gone"    "no" "$(chain_exists iptables HOMEPROXY_OUT && echo yes || echo no)"
	expect "v4 loopback chain gone"  "no" "$(chain_exists iptables HOMEPROXY_LO && echo yes || echo no)"
	expect "v6 OUTPUT chain gone"    "no" "$(chain_exists ip6tables HOMEPROXY_OUT && echo yes || echo no)"
	expect "v6 loopback chain gone"  "no" "$(chain_exists ip6tables HOMEPROXY_LO && echo yes || echo no)"
	expect "no rules left in v4 OUTPUT" "0" "$(grep -c '^mangle|HOMEPROXY_OUT|' "$STATE/rules.iptables")"
	expect "state file removed"      "no" "$([ -f "$STATE/firewall-state" ] && echo yes || echo no)"
}

test_a_rule_that_will_not_install_is_reported_not_recorded() {
	# Found on the device, not by reading. ip6tables on this firmware has no
	# CONNMARK extension, so one rule in the v6 chain was refused. The build
	# carried on regardless and reported success, because `set -e` is suspended
	# for everything inside an `if (...)` condition -- so the state file
	# claimed a v6 half that was not there. That file is precisely what
	# do_check consults, and the guard's whole repair path hangs off it.
	HP_SELF=1 HP_FAIL_MATCH='MARK --set-mark 480' run up >/dev/null

	expect "the failed half is not recorded as installed" "self=0" \
		"$(grep '^self=' "$STATE/firewall-state")"
	expect "v6 likewise"  "self6=0" "$(grep '^self6=' "$STATE/firewall-state")"

	# And it is torn back down rather than left half-built: a chain whose rules
	# stop part way through the exclusions is worse than no chain at all.
	expect "no partial OUTPUT chain left" "no" \
		"$(chain_exists iptables HOMEPROXY_OUT && echo yes || echo no)"

	# The forwarded half must be untouched -- it is what the LAN depends on.
	expect "the forwarded half is still built" "1" \
		"$(grep -c '^iptables -t mangle -A PREROUTING -i br-lan -j HOMEPROXY$' "$STATE/calls")"
	expect "check still passes, so the guard does not loop" "0" "$(run check)"
}

test_check_repairs_a_lost_output_chain() {
	HP_SELF=1 run up >/dev/null
	expect "check passes after up" "0" "$(run check)"

	# The failure mode this firmware actually produces: something flushes a
	# built-in chain and the jump goes with it. eqos does exactly this to
	# PREROUTING on every interface event.
	#
	# The jump is deleted rather than the chain, because iptables refuses to
	# delete a chain that is still referenced -- "the chain vanished and left
	# a dangling jump" is not a state the kernel will produce.
	STATE="$STATE" "$SB/bin/iptables" -t mangle -D OUTPUT -j HOMEPROXY_OUT
	expect "check fails once the jump is gone" "1" "$(run check)"

	# The loopback jump matters just as much, and in the other direction:
	# without it the OUTPUT chain still marks packets, so they are routed onto
	# lo and then dropped -- the router's own connections fail instead of
	# quietly falling back to a direct route. Failing to notice that turns a
	# brief eqos flush into an outage that lasts until someone looks.
	STATE="$STATE" "$SB/bin/iptables" -t mangle -D PREROUTING -i lo -j HOMEPROXY_LO
	expect "check fails once the loopback jump is gone" "1" "$(run check)"
}

test_check_does_not_demand_a_half_that_failed() {
	# A box where ip6tables is present but ipv6 is switched off: check must not
	# keep asking for a v6 chain nobody built, or the guard reinstalls every
	# 10s and each reinstall tears the working IPv4 rules down first.
	HP_SELF=1 HP_IPV6=0 run up >/dev/null
	expect "no v6 chain built"        "no" "$(chain_exists ip6tables HOMEPROXY_OUT && echo yes || echo no)"
	expect "check still passes"       "0"  "$(run check)"

	# And with IPv6 on, the v6 half becoming the thing that is missing must be
	# noticed -- that gap is what a v4-only check used to hide.
	HP_SELF=1 HP_IPV6=1 run up >/dev/null
	STATE="$STATE" "$SB/bin/ip6tables" -t mangle -D PREROUTING -i br-lan -j HOMEPROXY
	expect "v6 loss is noticed"       "1"  "$(run check)"
}

# -------------------------------------------------------------------------- run

HP_FIREWALL=${HP_FIREWALL:-$(cd "$(dirname "$0")/.." && pwd)/data/usr/share/homeproxy/firewall.sh}
export HP_FIREWALL

if [ ! -f "$HP_FIREWALL" ]; then
	echo "firewall.sh not found at $HP_FIREWALL" >&2
	exit 2
fi

CASE_LIST="
test_self_proxy_off_builds_nothing_in_output
test_self_proxy_on_builds_both_families
test_the_singbox_exclusion_comes_first
test_dns_and_ntp_follow_full_tunnel
test_the_two_halves_exclude_the_same_destinations
test_every_packet_is_marked_and_nothing_else_is
test_the_mark_grammar_matches_the_generator
test_a_mark_collision_disables_the_feature
test_down_removes_everything
test_a_rule_that_will_not_install_is_reported_not_recorded
test_check_repairs_a_lost_output_chain
test_check_does_not_demand_a_half_that_failed
"

trap cleanup EXIT

if [ $# -gt 0 ]; then
	for c in "$@"; do test_case "$c"; done
else
	for c in $CASE_LIST; do test_case "$c"; done
fi

printf '\n  %d passed, %d failed\n\n' "$TOTAL_PASS" "$TOTAL_FAIL"
[ "$TOTAL_FAIL" -eq 0 ]
