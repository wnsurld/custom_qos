#!/bin/sh
set -eu

SDK_DIR="${1:?usage: $0 /path/to/openwrt-sdk [package-name]}"
PKG_NAME="${2:-adaptive-latency}"
DEST="$SDK_DIR/package/$PKG_NAME"

if [ ! -d "$SDK_DIR/package" ]; then
  echo "not an OpenWrt SDK/source tree: $SDK_DIR" >&2
  exit 1
fi

rm -rf "$DEST"
mkdir -p "$DEST"

cp -R bpf "$DEST/"
cp -R daemon "$DEST/"
cp -R scripts "$DEST/"
cp Makefile "$DEST/source.mk"
cp openwrt/Makefile "$DEST/Makefile"
cp -R openwrt/files "$DEST/files"

echo "staged OpenWrt package at $DEST"
echo "next: cd $SDK_DIR && make package/$PKG_NAME/compile V=s"
