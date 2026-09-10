#!/bin/sh
set -eu

WAN_IF="${1:-wan}"
IFB_IF="${2:-ifb0}"
LINE_RATE="${3:-300mbit}"
PROTECT_RATE="${4:-80mbit}"

validate_ifname() {
  case "$1" in
    ''|*[!A-Za-z0-9_.:@-]*)
      echo "invalid interface name: $1" >&2
      exit 1
      ;;
  esac
}

validate_ifname "$WAN_IF"
validate_ifname "$IFB_IF"

modprobe ifb 2>/dev/null || true
ip link add "$IFB_IF" type ifb 2>/dev/null || true
ip link set dev "$IFB_IF" up

tc qdisc del dev "$WAN_IF" clsact 2>/dev/null || true
tc qdisc del dev "$IFB_IF" root 2>/dev/null || true

tc qdisc add dev "$WAN_IF" clsact
tc filter add dev "$WAN_IF" ingress protocol ip prio 20 matchall \
  action mirred egress redirect dev "$IFB_IF"
tc filter add dev "$WAN_IF" ingress protocol ipv6 prio 21 matchall \
  action mirred egress redirect dev "$IFB_IF" 2>/dev/null || true

tc qdisc add dev "$IFB_IF" root handle 1: htb default 20
tc class add dev "$IFB_IF" parent 1: classid 1:1 htb rate "$LINE_RATE" ceil "$LINE_RATE"

# Realtime gets priority and can borrow up to the configured line rate.
tc class add dev "$IFB_IF" parent 1:1 classid 1:10 htb rate 1mbit ceil "$LINE_RATE" prio 0

# Normal class is the default path for unknown or unclassified traffic.
tc class add dev "$IFB_IF" parent 1:1 classid 1:20 htb rate "$LINE_RATE" ceil "$LINE_RATE" prio 1

# Bulk is dynamically controlled when realtime and bulk conflict.
tc class add dev "$IFB_IF" parent 1:1 classid 1:30 htb rate "$LINE_RATE" ceil "$LINE_RATE" prio 2

tc qdisc add dev "$IFB_IF" parent 1:10 handle 10: fq_codel
tc qdisc add dev "$IFB_IF" parent 1:20 handle 20: fq_codel
tc qdisc add dev "$IFB_IF" parent 1:30 handle 30: fq_codel

echo "configured $WAN_IF ingress redirect -> $IFB_IF egress shaping"
echo "line_rate=$LINE_RATE protect_rate=$PROTECT_RATE"
