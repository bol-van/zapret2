#!/bin/sh
[ "$table" != "mangle" ] && [ "$table" != "nat" ] && exit 0
[ -f /var/run/zapret2.pid ] && /opt/zapret2/init.d/sysv/zapret2 restart-fw
exit 0
