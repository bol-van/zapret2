IFNAMSIZ=16

resolve_lower_devices()
{
	# $1 - interface name
	[ -d "/sys/class/net/$1" ] && {
		find "/sys/class/net/$1" -follow -maxdepth 1 -name "lower_*" |
		{
			local l lower lowers
			while read lower; do
				lower="$(basename "$lower")"
				l="${lower#lower_*}"
				[  "$l" != "$lower" ] && append_separator_list lowers ' ' '' "$l"
			done
			printf "$lowers"
		}
	}
}
is_bridge()
{
	# $1 - interface name
	[ -d "/sys/class/net/$1/bridge" ]
}
is_vlan()
{
	# $1 - interface name
	[ -f "/sys/class/net/$1/uevent" ] && grep -qFx 'DEVTYPE=vlan' "/sys/class/net/$1/uevent"
}

use_wlan_prefix()
{
	local KERNEL_VERSION KERNEL_MAJOR REMAINDER KERNEL_MINOR
	[ -z "$USE_WLAN_PREFIX" ] && {
		KERNEL_VERSION=$(uname -r)
		KERNEL_MAJOR="${KERNEL_VERSION%%.*}"
		REMAINDER="${KERNEL_VERSION#*.}"
		KERNEL_MINOR="${REMAINDER%%.*}"
		if [ "$KERNEL_MAJOR" -gt 6 ] || { [ "$KERNEL_MAJOR" -eq 6 ] && [ "$KERNEL_MINOR" -ge 17 ]; }; then
			USE_WLAN_PREFIX=1
		else
			USE_WLAN_PREFIX=0
		fi
	}
	[ "$USE_WLAN_PREFIX" = 1 ]
}

device_is_wireless()
{
	[ -d "/sys/class/net/$1/phy80211" ] || [ -d "/sys/class/net/$1/wireless" ]
}
resolve_hw_offload_port()
{
	local devname="$1"

	if use_wlan_prefix; then
		echo -n "$devname"
		return
	fi

	if echo "$devname" | grep -qE '^.+\.sta[0-9]+$'; then
		local prefix="${devname%.sta*}"
		echo -n "${prefix}.sta*"
		return
	fi

	local dev_len=${#devname}
	local max_len=$((IFNAMSIZ - 5))

	if ! device_is_wireless "$devname" || [ "$dev_len" -ge "$max_len" ]; then
		echo "$devname"
		return
	fi

	echo -n "$devname ${devname}.sta*"
}

# copy openwrt behaviour but without netifd query
resolve_hw_offload()
{
	# $1 - interface name
	if is_bridge "$1" || is_vlan "$1" ; then
		resolve_lower_devices "$1"
	else
		resolve_hw_offload_port "$1"
	fi
}
