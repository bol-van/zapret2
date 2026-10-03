#!/bin/bash

EXEDIR="$(dirname "$0")"
EXEDIR="$(cd "$EXEDIR"; pwd)"

. "$EXEDIR/common.inc"

BASEURL=https://github.com/bol-van/musl-cross/releases/download/latest

check_prog curl tar xz

[ -d "$TOOLCHAINS" ] || mkdir -p "$TOOLCHAINS"

ask_target 1

(
cd "$TOOLCHAINS"
for t in $TGT; do
	[ -d "$t" ] && rm -r "$t"
	if [ "$t" = arm-buildroot-linux-musleabi ]; then
		curl $CURL_OPT -Lo - https://toolchains.bootlin.com/downloads/releases/toolchains/armv5-eabi/tarballs/armv5-eabi--musl--stable-2024.02-1.tar.bz2 | tar -xj
		mv armv5-eabi--musl--stable-2024.02-1 "$t"
	else
		curl $CURL_OPT -Lo - "${BASEURL}/${t}.tar.xz" | tar -Jx
	fi
done
)
