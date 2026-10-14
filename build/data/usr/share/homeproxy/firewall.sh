#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
# homeproxy -- transparent proxy firewall rules, IPv4 and IPv6.
#
# Upstream implements this against firewall4/nftables directly. Here it is
# iptables + ip rule instead, which on this firmware means the *nft-backed*
# iptables (xtables-nft-multi, "iptables v1.8.10 (nf_tables)"). The rules
# therefore live inside the nft ruleset, in `table ip mangle` and
# `table ip6 mangle`.
#
# That is safe with respect to firewall4. fw4's generated ruleset is
#
#     table inet fw4
#     flush table inet fw4
#     table inet fw4 { ... }
#
# i.e. it flushes *its own table only* and never issues a bare `flush ruleset`.
# So a `fw4 reload` -- which fires on every WAN event, DHCP renew and WiFi
# reload -- leaves these chains alone. Verified by reading `fw4 print` on the
# target device.
#
#   firewall.sh up      install rules
#   firewall.sh down    remove rules (safe to run repeatedly)
#   firewall.sh status  report state, for the LuCI status page
#   firewall.sh check   exit 0 only if the rules are installed and attached
#                       (used by /etc/hotplug.d/iface/99-homeproxy, which has
#                       to re-install them after the vendor's eqos wipes them)
#
# Deliberate safety choices:
#   * The mangle jump matches only `-i <lan_interface>`, i.e. traffic being
#     *forwarded from the LAN*. Router-originated traffic never enters the
#     chain, so a broken ruleset cannot lock you out of SSH.
#   * Traffic *destined to the router itself* is RETURNed explicitly. On IPv4
#     the private ranges happen to cover this, but on IPv6 the router holds a
#     global address out of the ISP prefix, and without the RETURN the LAN
#     could no longer reach the router's own web UI over IPv6 -- TPROXY would
#     redirect it to a proxy port that has no interest in it.
#   * All rules live in dedicated chains; nothing existing is modified.
#     `down` flushes and deletes them and removes the policy route.
#   * `up` is idempotent -- it tears down first, so repeated calls converge.
#   * IPv6 is built as an independent step. If it fails part way it is rolled
#     back on its own and IPv4 stays up, rather than `set -e` aborting the
#     whole install and leaving a half-built ruleset.

set -e

CHAIN="HOMEPROXY"

# Deliberately NOT the usual fwmark 1 / table 100 pair.
#
# This firmware ships PassWall, whose scripts install exactly
# `ip rule add fwmark 1 lookup 100` and `ip route add local 0.0.0.0/0 dev lo
# table 100` -- the same mark and the same table. PassWall is disabled today,
# but the two would share one policy rule and one table, and whichever ran its
# teardown second would flush the other's default route out from under it.
# Anything else on the box that happens to use the customary pair fails the
# same way, so this takes a private pair instead of the familiar one.
TABLE_ROUTE=120
# Decimal on purpose: the rule show/delete helpers below render it with
# `printf %x`, which does not reliably parse a 0x literal in this shell.
# 480 is 0x1e0, which is what `ip rule show` will print it as.
FWMARK=480

UCI="uci -q get homeproxy"

log()  { echo "homeproxy: $*"; }
warn() { echo "homeproxy: $*" >&2; }

# ------------------------------------------------------------------- settings

load_settings() {
	TPROXY_PORT=$($UCI inbound.tproxy_port 2>/dev/null || echo 5330)
	LAN_IF=$($UCI inbound.lan_interface 2>/dev/null || echo br-lan)
	IPV6=$($UCI global.ipv6 2>/dev/null || echo 1)

	[ -n "$TPROXY_PORT" ] || TPROXY_PORT=5330
	[ -n "$LAN_IF" ] || LAN_IF=br-lan

	# Default on. This device's ISP hands out a public IPv6 prefix, and an
	# IPv6 path around the proxy is a hole big enough to defeat it: clients
	# prefer IPv6, so a blocked site would fail outright rather than fall back
	# to the proxied IPv4 route.
	case "$IPV6" in
		""|1|on|true|yes|enabled) IPV6=1 ;;
		*) IPV6=0 ;;
	esac

	# A wrong interface name would silently proxy nothing; a wrong port would
	# send every LAN flow into a closed socket. Refuse rather than guess.
	case "$TPROXY_PORT" in
		*[!0-9]*) warn "non-numeric port, aborting"; exit 1 ;;
	esac

	# --- who answers port 53 ------------------------------------------
	#
	# This firmware forces every LAN DNS query to its own dnsmasq. With
	# dhcp.@dnsmasq[0].dns_redirect=1 -- which the vendor sets, and which is
	# set on this device -- /etc/init.d/dnsmasq installs
	#
	#     meta nfproto { ipv4, ipv6 } udp dport 53 counter redirect to :53
	#
	# into `table inet dnsmasq`: a nat prerouting chain at priority -95.
	#
	# TPROXY sits earlier (mangle, -150), so it would already have bound the
	# query to sing-box's socket by the time that redirect rewrites the
	# destination, and the reply then no longer matches what conntrack
	# recorded for the flow. That is the "handled twice, and the query simply
	# hangs" failure this script used to carry a warning about.
	#
	# Fighting it is not worth it: dnsmasq is what answers DNS on this box
	# with the package absent, and sniff_override is what keeps proxied
	# domains usable when its answers are polluted. So while the firmware is
	# redirecting UDP :53, leave UDP :53 alone and let it keep doing so.
	DNS_REDIRECT=$(uci -q get "dhcp.@dnsmasq[0].dns_redirect" 2>/dev/null || echo 0)
	DNS_HIJACK=$($UCI global.dns_hijack 2>/dev/null || echo 1)

	case "$DNS_HIJACK" in
		""|1|on|true|yes|enabled) DNS_HIJACK=1 ;;
		*) DNS_HIJACK=0 ;;
	esac

	# TCP :53 has no redirect in front of it, so it can still be captured and
	# answered by sing-box -- unless interception is switched off altogether,
	# in which case both are left to find their own way out (and, since the
	# chain also RETURNs the router's own addresses, that means sing-box does
	# not see them).
	if [ "$DNS_REDIRECT" = "1" ] || [ "$DNS_HIJACK" = "0" ]; then
		SKIP_DNS_UDP=1
	else
		SKIP_DNS_UDP=0
	fi
	if [ "$DNS_HIJACK" = "0" ]; then
		SKIP_DNS_TCP=1
	else
		SKIP_DNS_TCP=0
	fi
}

# ------------------------------------------------------------------- helpers

# Any loop that touches iptables is bounded. A wrong loop condition here does
# not just fail, it spins forever on the router -- which is exactly how an
# earlier revision of this file hung in `down`.
LOOP_MAX=32

have() { command -v "$1" >/dev/null 2>&1; }

# Insert a rule only if an identical one is not already present, so repeated
# `up` calls cannot accumulate duplicates.
ipt_add() {
	tool=$1; table=$2; shift 2
	$tool -t "$table" -C "$@" 2>/dev/null || $tool -t "$table" -A "$@"
}

# Delete every rule in $chain that jumps to $target, whoever added it and
# whatever qualifiers it carries.
#
# Matching with `-C chain -j target` does NOT work: iptables treats
# `-i br-lan -j HOMEPROXY` and `-j HOMEPROXY` as different rules, so a
# qualifier-carrying jump would survive forever and keep pointing at a chain
# that `down` is about to delete.
#
# `-S` is used rather than parsing `-L --line-numbers` columns: -S re-emits
# each rule in the same syntax `-D` accepts, so the delete is by exact spec.
# The older column-parsing form assumed a prot/opt/source/destination layout
# that the nft backend is free to format differently -- notably it inserts a
# `--` column placeholder for rules it renders from nft syntax.
del_jump() {
	tool=$1; table=$2; chain=$3; target=$4
	i=0
	while [ "$i" -lt "$LOOP_MAX" ]; do
		spec=$($tool -t "$table" -S "$chain" 2>/dev/null | awk -v t="$target" '
			{
				for (n = 1; n < NF; n++)
					if ($n == "-j" && $(n + 1) == t) { print; next }
			}' | head -n 1)
		[ -n "$spec" ] || break
		# "-A <chain> <qualifiers>" -> just the qualifiers, which is the
		# argument list -D wants.
		rest=${spec#-A $chain }
		# Deliberately unquoted: the qualifiers must reach iptables as
		# separate words. They are a rule spec this script itself wrote, not
		# user input.
		# shellcheck disable=SC2086
		$tool -t "$table" -D "$chain" $rest 2>/dev/null || break
		i=$((i + 1))
	done
	return 0
}

flush_and_delete() {
	tool=$1; table=$2; chain=$3
	# -F empties the chain but keeps it, so flushing in a loop never
	# terminates. Flush once, then delete once.
	$tool -t "$table" -F "$chain" 2>/dev/null || true
	$tool -t "$table" -X "$chain" 2>/dev/null || true
}

# Every address assigned to the router, one per line, without prefix length.
# Used to RETURN traffic addressed to the box itself: on IPv6 that includes a
# globally routable address, which no static range covers.
local_addrs_v4() { ip -4 addr show 2>/dev/null | awk '/inet /{ sub(/\/.*/, "", $2); print $2 }'; }
local_addrs_v6() { ip -6 addr show 2>/dev/null | awk '/inet6 /{ sub(/\/.*/, "", $2); print $2 }'; }

# Remove the policy routing TPROXY depends on.
del_policy_route() {
	fam=$1
	i=0
	while [ "$i" -lt $LOOP_MAX ] \
		&& ip $fam rule show 2>/dev/null | grep -q "fwmark 0x$(printf '%x' $FWMARK) lookup $TABLE_ROUTE"; do
		ip $fam rule del fwmark $FWMARK lookup $TABLE_ROUTE 2>/dev/null || break
		i=$((i + 1))
	done
	ip $fam route flush table $TABLE_ROUTE 2>/dev/null || true
}

# ------------------------------------------------------------------- down

# Deliberately unconditional with respect to the IPv6 *setting*: if the user
# turns IPv6 off, `up` will not rebuild the v6 chain but the existing one must
# still be removed, and `down` is the only thing that does that. Removing
# what is not there is a no-op.
do_down() {
	# Detach first, then delete, so there is never a window where a jump
	# points at a missing chain.
	if have iptables; then
		del_jump iptables mangle PREROUTING "$CHAIN"
		flush_and_delete iptables mangle "$CHAIN"
		del_policy_route -4
	fi

	if have ip6tables; then
		del_jump ip6tables mangle PREROUTING "$CHAIN"
		flush_and_delete ip6tables mangle "$CHAIN"
		del_policy_route -6
	fi

	log "rules removed"
}

# ------------------------------------------------------------------- up

# Build the chain for one address family.
#
# $1 = iptables tool (iptables / ip6tables)
# $2 = family flag for `ip` (-4 / -6)
# $3.. = destination ranges that must never be proxied, in that tool's syntax
build_family() {
	tool=$1; fam=$2; shift 2

	# Tolerated rather than fatal: do_down above normally removes the chain, but
	# if it could not (a jump to it still existed, say) then reusing what is
	# there is strictly better than aborting -- every rule below goes in
	# through ipt_add, which checks before it appends, so the result converges
	# either way.
	$tool -t mangle -N "$CHAIN" 2>/dev/null || true

	# Bypass everything that is not public internet traffic.
	#
	# This is load-bearing, not politeness. The chain hangs off PREROUTING, so
	# packets *destined to the router itself* pass through it too -- and that
	# includes the SSH session installing these rules. Without the returns
	# below, TPROXY would redirect that session to the (not yet listening)
	# proxy port and lock the operator out, with no way left to run `down`.
	#
	# The static ranges are the cheap majority; the loop after them covers the
	# router's own addresses, which on IPv6 are globally routable and match no
	# range at all.
	# Deliberately unquoted: each range must be its own argument.
	# shellcheck disable=SC2068
	for net in $@; do
		ipt_add $tool mangle "$CHAIN" -d "$net" -j RETURN
	done

	if [ "$fam" = "-4" ]; then addrs=$(local_addrs_v4); else addrs=$(local_addrs_v6); fi
	for a in $addrs; do
		ipt_add $tool mangle "$CHAIN" -d "$a" -j RETURN
	done

	# --- DNS ----------------------------------------------------------
	# Keeping DNS out of TPROXY, for the reasons set out in load_settings:
	# the firmware's own redirect owns UDP :53, and the user can switch
	# interception off. Placed after the RETURNs above so that traffic to the
	# router's own resolver is already gone, and before TPROXY so it can never
	# be marked. Both are no-ops when the option is off -- ipt_add checks
	# first, so a stale rule from a previous configuration is not a problem,
	# and `up` tears the chain down before rebuilding anyway.
	if [ "$SKIP_DNS_UDP" = "1" ]; then
		ipt_add $tool mangle "$CHAIN" -p udp --dport 53 -j RETURN
	fi
	if [ "$SKIP_DNS_TCP" = "1" ]; then
		ipt_add $tool mangle "$CHAIN" -p tcp --dport 53 -j RETURN
	fi

	# --- TPROXY -------------------------------------------------------
	# The on-ip for IPv6 must be a v6 literal. A listener on 0.0.0.0 is a v4
	# socket and would never receive these packets, which is why confgen
	# declares a second tproxy inbound bound to ::1 rather than reusing it.
	if [ "$fam" = "-4" ]; then ONIP=127.0.0.1; else ONIP=::1; fi

	ipt_add $tool mangle "$CHAIN" -p tcp -j TPROXY \
		--on-ip "$ONIP" --on-port "$TPROXY_PORT" --tproxy-mark $FWMARK
	ipt_add $tool mangle "$CHAIN" -p udp -j TPROXY \
		--on-ip "$ONIP" --on-port "$TPROXY_PORT" --tproxy-mark $FWMARK

	ipt_add $tool mangle PREROUTING -i "$LAN_IF" -j "$CHAIN"

	# --- policy routing -----------------------------------------------
	# TPROXY marks packets; this steers marked packets to the local socket
	# instead of out the WAN.
	ip $fam rule show 2>/dev/null | grep -q "fwmark 0x$(printf '%x' $FWMARK) lookup $TABLE_ROUTE" \
		|| ip $fam rule add fwmark $FWMARK lookup $TABLE_ROUTE
	ip $fam route show table $TABLE_ROUTE 2>/dev/null | grep -q "^local" \
		|| ip $fam route add local default dev lo table $TABLE_ROUTE
}

do_up() {
	load_settings

	# Start from a known state. do_down reads no settings, so the order here
	# does not matter.
	do_down >/dev/null 2>&1 || true

	# Load what TPROXY needs before the first rule that references it.
	#
	# Nothing else on this firmware uses these, so on a cold boot they are not
	# loaded yet, and `-j TPROXY` then fails with "No chain/target/match by
	# that name" -- under `set -e` that aborts the whole install. iptables can
	# usually pull an extension in by itself via modprobe, but it is not
	# reliable this early: the vendor's own S99access_ctl logs exactly that
	# error at boot, and the guard's first install attempt failed the same
	# way. Asking explicitly costs nothing when they are already loaded.
	#
	# nft_tproxy is the one that actually backs `-j TPROXY` when iptables is
	# an nft wrapper; the xt_* names only matter for a legacy iptables and are
	# harmless when it is not.
	for m in nft_tproxy xt_TPROXY xt_socket nf_tproxy_ipv4 nf_tproxy_ipv6 \
			nf_socket_ipv4 nf_socket_ipv6; do
		modprobe "$m" 2>/dev/null || true
	done

	# --- IPv4 ---------------------------------------------------------
	build_family iptables -4 \
		0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 \
		169.254.0.0/16 172.16.0.0/12 192.168.0.0/16 224.0.0.0/4 \
		240.0.0.0/4 255.255.255.255/32

	# --- DNS ----------------------------------------------------------
	# This script still installs no nat REDIRECT of its own, and the reasoning
	# about why a second handler for :53 is harmful lives in load_settings
	# along with what is actually done about it (the firmware installs one for
	# UDP :53 whether or not this package is present, so the chain steps aside
	# for it there).
	#
	# Queries aimed at the router's own dnsmasq are returned before TPROXY
	# either way: their destination is one of the router's own addresses.

	# --- IPv6 ---------------------------------------------------------
	n6="disabled"
	if [ "$IPV6" = "1" ]; then
		if ! have ip6tables; then
			n6="skipped (no ip6tables)"
		else
			if build_family ip6tables -6 \
					::/128 ::1/128 fc00::/7 fe80::/10 ff00::/8; then
				n6="tproxy :$TPROXY_PORT on $LAN_IF"
			else
				# Roll the v6 half back on its own. A half-installed v6
				# chain would black-hole IPv6 for the whole LAN, which is
				# worse than not proxying it -- and IPv4 must stay up
				# either way, so this must not abort the install.
				warn "IPv6 setup failed; rolling IPv6 back, IPv4 remains active"
				del_jump ip6tables mangle PREROUTING "$CHAIN" || true
				flush_and_delete ip6tables mangle "$CHAIN" || true
				del_policy_route -6 || true
				n6="failed, rolled back"
			fi
		fi
	fi

	log "tproxy :$TPROXY_PORT on $LAN_IF, ipv4=on, ipv6=$n6"
}

# ------------------------------------------------------------------- status

# Exit 0 only if the rules are both present and attached. The interface
# hotplug hook uses this to decide whether it has to re-install them, and it
# has to be cheap: it runs on every interface event.
do_check() {
	have iptables || return 1
	iptables -t mangle -S "$CHAIN" >/dev/null 2>&1 || return 1
	iptables -t mangle -C PREROUTING -i "$LAN_IF" -j "$CHAIN" 2>/dev/null || return 1
	return 0
}

do_status() {
	if have iptables && iptables -t mangle -S "$CHAIN" >/dev/null 2>&1; then
		echo "chain:   present"
	else
		echo "chain:   absent"
	fi

	if have iptables && iptables -t mangle -C PREROUTING -i "$LAN_IF" -j "$CHAIN" 2>/dev/null; then
		echo "jump:    installed"
	else
		echo "jump:    missing"
	fi

	if ip rule show 2>/dev/null | grep -q "lookup $TABLE_ROUTE"; then
		echo "ip rule: present"
	else
		echo "ip rule: absent"
	fi

	if ip route show table $TABLE_ROUTE 2>/dev/null | grep -q "^local"; then
		echo "route:   present"
	else
		echo "route:   absent"
	fi

	# IPv6 reported separately: a v4-only line legitimately has none, and
	# that is not a fault.
	if [ "$IPV6" != "1" ]; then
		echo "ipv6:    disabled in config"
	elif ! have ip6tables; then
		echo "ipv6:    ip6tables missing"
	elif ip6tables -t mangle -C PREROUTING -i "$LAN_IF" -j "$CHAIN" 2>/dev/null; then
		echo "ipv6:    installed"
	else
		echo "ipv6:    not installed"
	fi

	# Worth reporting because on this firmware the answer is normally
	# "dnsmasq", not sing-box: the vendor's dns_redirect is on and the chain
	# steps aside for it. Without this line that reads as the Intercept DNS
	# option being broken.
	if [ "$SKIP_DNS_UDP" = "1" ] && [ "$SKIP_DNS_TCP" = "1" ]; then
		echo "dns:     not intercepted"
	elif [ "$SKIP_DNS_UDP" = "1" ]; then
		echo "dns:     udp dnsmasq (firmware redirect), tcp sing-box"
	else
		echo "dns:     intercepted by sing-box"
	fi
}

# ------------------------------------------------------------------- main

case "$1" in
	up)     do_up ;;
	down)   load_settings; do_down ;;
	status) load_settings; do_status ;;
	# Written as an if rather than `do_check; exit $?` so that the test runs
	# in a condition context, where `set -e` does not abort the script the
	# moment the rule turns out to be missing -- which is the normal case for
	# this subcommand.
	check)  load_settings; if do_check; then exit 0; else exit 1; fi ;;
	*)      echo "usage: $0 {up|down|status|check}" >&2; exit 2 ;;
esac
