#!/bin/sh
set -eu

IFB_IF="${1:-ifb0}"
BULK_RATE="${2:-80mbit}"
BULK_CEIL="${3:-$BULK_RATE}"

validate_ifname() {
  case "$1" in
    ''|*[!A-Za-z0-9_.:@-]*)
      echo "invalid interface name: $1" >&2
      exit 1
      ;;
  esac
}

validate_ifname "$IFB_IF"

tc class change dev "$IFB_IF" parent 1:1 classid 1:30 htb \
  rate "$BULK_RATE" ceil "$BULK_CEIL" prio 2

echo "bulk class 1:30 on $IFB_IF changed to rate=$BULK_RATE ceil=$BULK_CEIL"
