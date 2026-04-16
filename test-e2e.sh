#!/usr/bin/env bash
# test-e2e.sh — end-to-end integration test for dhcpd6-unnumbered.
#
# Creates a veth pair, starts the daemon on one end, and uses the dhcpv6test
# client binary to exercise both the normal-MAC and virtual-MAC paths.
#
# Requirements: root (CAP_NET_ADMIN + CAP_NET_RAW), Go toolchain.
#
# Usage:
#   sudo ./test-e2e.sh
#
# On success  : exits 0  (both test cases passed)
# On failure  : exits 1  (tail of the daemon log is printed for diagnosis)

set -euo pipefail

# Go may not be in root's PATH — find it the same way the Makefile does.
GO=$(command -v go 2>/dev/null || echo /usr/local/go/bin/go)
[[ -x "$GO" ]] || { echo "FATAL: go binary not found (tried \$PATH and /usr/local/go/bin/go)" >&2; exit 1; }

SRV_IF=d6test-srv
CLI_IF=d6test-cli
HOST_ROUTE=2001:db8::1/128    # /128 host route on srv — the address offered to the client
ACCEPT_PFX=2001:db8::/32      # daemon only offers IPs within this prefix
DAEMON_LOG=/tmp/dhcpd6-test-daemon.log
DAEMON_BIN=./dhcpd6-unnumbered
CLIENT_BIN=/tmp/dhcpv6test-e2e
DAEMON_PID=
EXIT_CODE=1

log() { echo "  $*"; }
die() { echo "FATAL: $*" >&2; exit 1; }
hdr() { echo; echo "── $* ──"; }

cleanup() {
    hdr "cleanup"
    if [[ -n "${DAEMON_PID:-}" ]] && kill -0 "$DAEMON_PID" 2>/dev/null; then
        kill "$DAEMON_PID"
        wait "$DAEMON_PID" 2>/dev/null || true
        log "daemon stopped"
    fi
    if ip link show "$SRV_IF" &>/dev/null; then
        ip link del "$SRV_IF"
        log "veth pair ($SRV_IF <-> $CLI_IF) removed"
    fi
    rm -f "$CLIENT_BIN"
    exit "$EXIT_CODE"
}
trap cleanup EXIT INT TERM

[[ $EUID -eq 0 ]] || die "must run as root"
cd "$(dirname "$0")"

# ── Build ────────────────────────────────────────────────────────────────────
hdr "building"
"$GO" build -o "$DAEMON_BIN" .
log "daemon:  $DAEMON_BIN"
"$GO" build -o "$CLIENT_BIN" ./cmd/dhcpv6test
log "client:  $CLIENT_BIN"

# ── Veth pair ────────────────────────────────────────────────────────────────
hdr "setting up veth pair  ($SRV_IF <-> $CLI_IF)"
ip link del "$SRV_IF" 2>/dev/null || true
ip link add "$SRV_IF" type veth peer name "$CLI_IF"
ip link set "$SRV_IF" up
ip link set "$CLI_IF" up

# Wait for both link-local IPv6 addresses and for the server-side TxPackets
# counter to go positive.  The daemon's linkReady() check requires TxPackets > 0
# (it was added so the listener isn't started before the link is fully usable —
# e.g. before the link-local address has been assigned).  The kernel sends NDP
# Neighbour Solicitations for DAD as soon as a link-local address is configured,
# which increments TxPackets naturally.
#
# We also wait until neither address is in the "tentative" DAD state.  Linux
# refuses to use a tentative address as the source of outgoing packets
# (EADDRNOTAVAIL), so the daemon must not start until DAD has completed.
# On this kernel DAD takes ~2s; we poll up to 5s to be safe.
echo -n "  waiting for link-local addresses, NDP traffic, and DAD completion"
SRV_LL= CLI_LL=
for i in $(seq 1 50); do
    SRV_LL=$(ip -6 addr show dev "$SRV_IF" scope link 2>/dev/null \
             | awk '/inet6/{print $2; exit}' | cut -d/ -f1)
    CLI_LL=$(ip -6 addr show dev "$CLI_IF" scope link 2>/dev/null \
             | awk '/inet6/{print $2; exit}' | cut -d/ -f1)
    TX=$(cat /sys/class/net/"$SRV_IF"/statistics/tx_packets 2>/dev/null || echo 0)
    SRV_TENT=$(ip -6 addr show dev "$SRV_IF" scope link 2>/dev/null | grep -c tentative || true)
    CLI_TENT=$(ip -6 addr show dev "$CLI_IF" scope link 2>/dev/null | grep -c tentative || true)
    if [[ -n "$SRV_LL" && -n "$CLI_LL" && "$TX" -gt 0 && "$SRV_TENT" -eq 0 && "$CLI_TENT" -eq 0 ]]; then
        echo " (ready after $((i * 100))ms)"
        break
    fi
    echo -n "."
    sleep 0.1
done

[[ -n "$SRV_LL" ]] || die "no link-local address on $SRV_IF after 5s"
[[ -n "$CLI_LL" ]] || die "no link-local address on $CLI_IF after 5s"

SRV_TENT=$(ip -6 addr show dev "$SRV_IF" scope link 2>/dev/null | grep -c tentative || true)
[[ "$SRV_TENT" -eq 0 ]] || die "$SRV_IF link-local address still tentative after 5s — DAD did not complete"

TX=$(cat /sys/class/net/"$SRV_IF"/statistics/tx_packets)
if [[ "$TX" -eq 0 ]]; then
    # Veth pair with no traffic yet.  A single ping6 from cli to srv causes srv
    # to send an ICMP echo reply, satisfying the TxPackets > 0 requirement.
    log "TxPackets still 0 — sending ping6 to seed NDP/ICMP traffic"
    ping6 -c 2 -W 1 -I "$CLI_IF" "$SRV_LL" >/dev/null 2>&1 || true
    TX=$(cat /sys/class/net/"$SRV_IF"/statistics/tx_packets)
    [[ "$TX" -gt 0 ]] || die "$SRV_IF TxPackets still 0 after ping — linkReady() will never fire"
fi

log "$SRV_IF  link-local: $SRV_LL  (tx_packets: $TX)"
log "$CLI_IF  link-local: $CLI_LL"

# Check OperState — the daemon also requires OperState == IF_OPER_UP (6).
# On modern kernels veth reports UP when both ends are up; warn if not.
SRV_OPER=$(cat /sys/class/net/"$SRV_IF"/operstate 2>/dev/null || echo unknown)
if [[ "$SRV_OPER" != "up" ]]; then
    echo "  WARNING: $SRV_IF operstate is '$SRV_OPER', not 'up'." \
         "linkReady() requires OperUp — daemon may not bind to this interface."
fi

# Add the /128 host route that the daemon reads via getHostRoutesIPv6() to
# decide which address to offer.  Without a matching route, the daemon logs
# "no host routes" and silently drops all solicits.
ip -6 route add "$HOST_ROUTE" dev "$SRV_IF"
log "host route added: $HOST_ROUTE dev $SRV_IF"

# ── Daemon ───────────────────────────────────────────────────────────────────
hdr "starting daemon  (log: $DAEMON_LOG)"
"$DAEMON_BIN" \
    -regex "^${SRV_IF}$" \
    -accept-prefix "$ACCEPT_PFX" \
    -dns "2620:fe::9" \
    -loglevel debug \
    >"$DAEMON_LOG" 2>&1 &
DAEMON_PID=$!
log "pid: $DAEMON_PID"

# Wait until the daemon logs that it has bound to our interface.
echo -n "  waiting for daemon to bind"
BOUND=0
for i in $(seq 1 50); do
    if grep -q "Starting DHCPv6 server for Interface ${SRV_IF}" "$DAEMON_LOG" 2>/dev/null; then
        echo " (ready after $((i * 100))ms)"
        BOUND=1
        break
    fi
    kill -0 "$DAEMON_PID" 2>/dev/null || {
        echo
        echo "  daemon exited unexpectedly — last log lines:"
        tail -20 "$DAEMON_LOG"
        die "daemon failed to start"
    }
    echo -n "."
    sleep 0.1
done

if [[ $BOUND -eq 0 ]]; then
    echo
    echo "  daemon never bound to $SRV_IF — last log lines:"
    tail -20 "$DAEMON_LOG"
    die "daemon did not bind within 5s (check operstate warning above)"
fi

# ── Test ─────────────────────────────────────────────────────────────────────
hdr "running dhcpv6test on $CLI_IF"
if "$CLIENT_BIN" -interface "$CLI_IF" -timeout 4s; then
    EXIT_CODE=0
    echo
    echo "╔══════════════════════════════════╗"
    echo "║       ALL TESTS PASSED  ✓        ║"
    echo "╚══════════════════════════════════╝"
else
    echo
    echo "╔══════════════════════════════════╗"
    echo "║         TESTS FAILED  ✗          ║"
    echo "╚══════════════════════════════════╝"
    echo
    hdr "last 40 lines of daemon log ($DAEMON_LOG)"
    tail -40 "$DAEMON_LOG"
fi
