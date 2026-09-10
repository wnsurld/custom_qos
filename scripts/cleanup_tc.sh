#!/bin/sh
set -eu

WAN_IF="${1:-wan}"
IFB_IF="${2:-ifb0}"

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

tc qdisc del dev "$WAN_IF" clsact 2>/dev/null || true
tc qdisc del dev "$IFB_IF" root 2>/dev/null || true
ip link set dev "$IFB_IF" down 2>/dev/null || true
ip link delete "$IFB_IF" type ifb 2>/dev/null || true

echo "cleaned tc/ifb state for wan=$WAN_IF ifb=$IFB_IF"
