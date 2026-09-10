#!/bin/sh
set -eu

WAN_IF="${1:-wan}"
BPF_OBJ="${2:-build/flowmon.bpf.o}"

validate_ifname() {
  case "$1" in
    ''|*[!A-Za-z0-9_.:@-]*)
      echo "invalid interface name: $1" >&2
      exit 1
      ;;
  esac
}

validate_ifname "$WAN_IF"

if [ ! -f "$BPF_OBJ" ]; then
  echo "missing BPF object: $BPF_OBJ" >&2
  echo "run: make bpf" >&2
  exit 1
fi

tc qdisc add dev "$WAN_IF" clsact 2>/dev/null || true

tc filter add dev "$WAN_IF" parent ffff: protocol ip prio 5 bpf \
  da obj "$BPF_OBJ" sec tc

echo "attached flow monitor BPF program to $WAN_IF ingress"
