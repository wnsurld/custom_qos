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

echo "== $WAN_IF qdisc =="
tc qdisc show dev "$WAN_IF" || true

echo
echo "== $WAN_IF ingress filters =="
tc filter show dev "$WAN_IF" ingress || true

echo
echo "== $IFB_IF qdisc =="
tc qdisc show dev "$IFB_IF" || true

echo
echo "== $IFB_IF classes =="
tc -s class show dev "$IFB_IF" || true

echo
echo "== $IFB_IF filters =="
tc filter show dev "$IFB_IF" || true
