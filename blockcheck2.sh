#!/bin/sh

EXEDIR="$(dirname "$0")"
EXEDIR="$(cd "$EXEDIR"; pwd)"
ZAPRET_BASE=${ZAPRET_BASE:-"$EXEDIR"}
ZAPRET_RW=${ZAPRET_RW:-"$ZAPRET_BASE"}
ZAPRET_CONFIG=${ZAPRET_CONFIG:-"$ZAPRET_RW/config"}
ZAPRET_CONFIG_DEFAULT="$ZAPRET_BASE/config.default"
BLOCKCHECK2D="$ZAPRET_BASE/blockcheck2.d"

CURL=${CURL:-curl}

[ -f "$ZAPRET_CONFIG" ] || {
	[ -f "$ZAPRET_CONFIG_DEFAULT" ] && {
		ZAPRET_CONFIG_DIR="$(dirname "$ZAPRET_CONFIG")"
		[ -d "$ZAPRET_CONFIG_DIR" ] || mkdir -p "$ZAPRET_CONFIG_DIR"
		cp "$ZAPRET_CONFIG_DEFAULT" "$ZAPRET_CONFIG"
	}
}
[ -f "$ZAPRET_CONFIG" ] && . "$ZAPRET_CONFIG"
. "$ZAPRET_BASE/common/base.sh"
. "$ZAPRET_BASE/common/dialog.sh"
. "$ZAPRET_BASE/common/elevate.sh"
. "$ZAPRET_BASE/common/fwtype.sh"
. "$ZAPRET_BASE/common/virt.sh"

TEST_DEFAULT=${TEST_DEFAULT:-standard}
DOMAINS_DEFAULT=${DOMAINS_DEFAULT:-rutracker.org}
SOCKS_PORT=${SOCKS_PORT:-1993}
WS_UID=${WS_UID:-1}
WS_GID=${WS_GID:-3003}
NFQWS2=${NFQWS2:-${ZAPRET_BASE}/nfq2/nfqws2}
DVTWS2=${DVTWS2:-${ZAPRET_BASE}/nfq2/dvtws2}
WINWS2=${WINWS2:-${ZAPRET_BASE}/nfq2/winws2}
MDIG=${MDIG:-${ZAPRET_BASE}/mdig/mdig}
DESYNC_MARK=0x10000000
CURL_MAX_TIME=${CURL_MAX_TIME:-2}
CURL_MAX_TIME_QUIC=${CURL_MAX_TIME_QUIC:-$CURL_MAX_TIME}
CURL_MAX_TIME_DOH=${CURL_MAX_TIME_DOH:-2}
# CURL_PAD pads every curl request with the given number of bytes, useful
# for the "16 KB" whitelist-style block (see docs): that block triggers on
# total bytes transferred on the connection, not on how much of it was an
# actual response, so padding the request is enough to test for it even
# against a target with no large page of its own to download - e.g. a bare
# IP from a provider's range rather than a known blocked domain. The padding
# is written straight to a small temp file (nothing large ever passes
# through a shell variable, command substitution, or argument) and attached
# as a header with curl's own @filename form of -H, which reads the file
# instead of taking the value on the command line - unlike an equivalent
# amount of data passed via --data/--data-binary, this doesn't conflict with
# HEAD requests, so it composes cleanly with CURL_HTTPS_GET either way.
CURL_PAD=${CURL_PAD:-0}
PAD_MAX_HEADER=${PAD_MAX_HEADER:-4000}
USER_AGENT=${USER_AGENT:-Mozilla}
HTTP_PORT=${HTTP_PORT:-80}
HTTPS_PORT=${HTTPS_PORT:-443}
QUIC_PORT=${QUIC_PORT:-443}
UNBLOCKED_DOM=${UNBLOCKED_DOM:-iana.org}
SIM_SUCCESS_RATE=${SIM_SUCCESS_RATE:-10}

IPFW_RULE_MAX=${IPFW_RULE_MAX:-999}
IPFW_RULE_NUM=${IPFW_RULE_NUM:-$(($$ % $IPFW_RULE_MAX + 1))}
IPFW_DIVERT_PORT=${IPFW_DIVERT_PORT:-$(($$ % 64536 + 1000))}
QNUM=${QNUM:-$(($$ % 64536 + 1000))}

PARALLEL_OUT=/tmp/zapret_parallel_$$
HDRTEMP=/tmp/zapret-hdr-$$

sweep_stale_pidfiles()
{
	# $1 - fixed filename prefix immediately preceding the pid
	#
	# A normal exit already removes this run's own PARALLEL_OUT/HDRTEMP
	# files (unprepare_all(), further down), which covers Ctrl+C,
	# a closed terminal, and a plain kill. kill -9 and crashes bypass
	# that, as they would for any script's cleanup, and can leave
	# stale files behind indefinitely, since nothing about a later run
	# gives it any reason to know about a different PID's leftovers.
	# Removes a matching file only once its PID (the run that created
	# it) is confirmed no longer running, so a genuinely still-running
	# concurrent instance - a different PID, its own files - is never
	# touched.
	local f pid prefix="$1"
	for f in "$prefix"*; do
		[ -e "$f" ] || continue
		pid=${f#"$prefix"}
		pid=${pid%%[!0-9]*}
		[ -n "$pid" ] || continue
		kill -0 "$pid" 2>/dev/null || rm -f "$f"
	done
}
sweep_stale_pidfiles /tmp/zapret_parallel_
sweep_stale_pidfiles /tmp/zapret-hdr-

NFT_TABLE=blockcheck$$
IPT_OUT_CHAIN=blockcheck_output_$$
IPT_IN_CHAIN=blockcheck_input_$$
IPT_COMMENT="-m comment --comment blockcheck_$$"

DNSCHECK_DNS=${DNSCHECK_DNS:-8.8.8.8 1.1.1.1 77.88.8.1}
DNSCHECK_DOM=${DNSCHECK_DOM:-pornhub.com ej.ru rutracker.org www.torproject.org bbc.com}
DOH_SERVERS=${DOH_SERVERS:-"https://cloudflare-dns.com/dns-query https://dns.google/dns-query https://dns.quad9.net/dns-query https://dns.adguard.com/dns-query https://common.dot.dns.yandex.net/dns-query"}
DNSCHECK_DIG1=/tmp/dig1.txt
DNSCHECK_DIG2=/tmp/dig2.txt
DNSCHECK_DIGS=/tmp/digs.txt


unset PF_STATUS
PF_RULES_SAVE=/tmp/pf-zapret-save.conf

unset ALL_PROXY

apply_header_padfile()
{
	local n=1 left size f pid
	if [ "$CURL_PAD" -gt 0 ] 2>/dev/null; then
		# A normal exit already removes this run's own pad file (see
		# cleanup() below), which covers Ctrl+C, a closed terminal, and
		# a plain kill. kill -9 and crashes bypass that, as they would
		# for any script's cleanup, so sweep any such leftover from
		# a previous run before making this run's own - only once its PID
		# is confirmed no longer running, so a genuinely still-running
		# concurrent instance (different PID, its own file) is never
		# touched
		for f in /tmp/zapret-curlpad-*; do
			[ -e "$f" ] || continue
			pid=${f##*-}
			case "$pid" in ''|*[!0-9]*) continue ;; esac
			kill -0 "$pid" 2>/dev/null || rm -f "$f"
		done
		left=$CURL_PAD
		CURL_PAD_FILE=/tmp/zapret-curlpad-$$
		rm -f "$CURL_PAD_FILE"
		touch "$CURL_PAD_FILE"
		while [ "$left" -ge 14 ]; do
			left=$(($left-14))
			if [ "$left" -gt "$PAD_MAX_HEADER" ]; then
				size="$PAD_MAX_HEADER"
			else
				size=$left
			fi
			left=$(($left-$size))
			# if the next header would be too small add the remainder to the current header
			[ "$left" -lt 14 ] && size=$(($size+$left))

			printf 'X-Pad-%04d: ' $n >> "$CURL_PAD_FILE"
			head -c $size /dev/zero | tr '\0' A >> "$CURL_PAD_FILE"
			# curl internally adds 0D0A line ending even if it's 0A in the file
			echo >> "$CURL_PAD_FILE"
			n=$(($n+1))
		done
		CURL_OPT="${CURL_OPT}${CURL_OPT:+ }-H @$CURL_PAD_FILE"
	fi
}


killwait()
{
	# $1 - signal (-9, -2, ...)
	# $2 - pid
	local KILL=kill
	# avoid internal bash kill in cygwin to support -f
	[ "$UNAME" = "CYGWIN" ] && KILL=/bin/kill
	$KILL $1 $2
	# suppress job kill message
	wait $2 2>/dev/null
}

exitp()
{
	local A

	[ "$BATCH" = 1 ] || {
		echo
		echo press enter to continue
		read A
	}
	exit $1
}

pf_is_avail()
{
	[ -c /dev/pf ]
}
pf_status()
{
	pfctl -qsi  | sed -nre "s/^Status: ([^ ]+).*$/\1/p"
}
pf_is_enabled()
{
	[ "$(pf_status)" = Enabled ]
}
pf_save()
{
	PF_STATUS=0
	pf_is_enabled && PF_STATUS=1
	[ "$UNAME" = "OpenBSD" ] && pfctl -sr >"$PF_RULES_SAVE"
}
pf_restore()
{
	[ -n "$PF_STATUS" ] || return
	case "$UNAME" in
		OpenBSD)
			if [ -f "$PF_RULES_SAVE" ]; then
				pfctl -qf "$PF_RULES_SAVE"
			else
				echo | pfctl -qf -
			fi
			;;
	esac
	if [ "$PF_STATUS" = 1 ]; then
		pfctl -qe
	else
		pfctl -qd
	fi
}
pf_clean()
{
	rm -f "$PF_RULES_SAVE"
}
opf_dvtws_anchor()
{
	# $1 - tcp/udp
	# $2 - port
	# $3 - ip list
	local iplist family=inet
	[ "$IPV" = 6 ] && family=inet6
	make_comma_list iplist "$3"
	echo "set reassemble no"
	[ "$1" = tcp ] && echo "pass in quick $family proto $1 from {$iplist} port $2 flags SA/SA divert-packet port $IPFW_DIVERT_PORT no state"
	echo "pass in  quick $family proto $1 from {$iplist} port $2 no state"
	echo "pass out quick $family proto $1 to   {$iplist} port $2 divert-packet port $IPFW_DIVERT_PORT no state"
	echo "pass"
}
opf_prepare_dvtws()
{
	# $1 - tcp/udp
	# $2 - port
	# $3 - ip list
	opf_dvtws_anchor $1 $2 "$3" | pfctl -qf -
	pfctl -qe
}

cleanup()
{
	case "$UNAME" in
		OpenBSD)
		    pf_clean
		    ;;
	esac
	[ -n "$CURL_PAD_FILE" ] && rm -f "$CURL_PAD_FILE"
}

IPT()
{
	$IPTABLES -C "$@" >/dev/null 2>/dev/null || $IPTABLES -I "$@"
}
IPT_DEL()
{
	$IPTABLES -C "$@" >/dev/null 2>/dev/null && $IPTABLES -D "$@"
}
IPT_ADD_DEL()
{
	on_off_function IPT IPT_DEL "$@"
}
IPFW_ADD()
{
	ipfw -qf add $IPFW_RULE_NUM "$@"
}
IPFW_DEL()
{
	ipfw -qf delete $IPFW_RULE_NUM 2>/dev/null
}
ipt6_has_raw()
{
	ip6tables -nL -t raw >/dev/null 2>/dev/null
}
ipt6_has_frag()
{
	ip6tables -A OUTPUT -m frag 2>/dev/null || return 1
	ip6tables -D OUTPUT -m frag 2>/dev/null
}
ipt_has_nfq()
{
	# cannot just check /proc/net/ip_tables_targets because of iptables-nft or modules not loaded yet
	iptables -A OUTPUT -t mangle -p 255 -j NFQUEUE --queue-num $QNUM --queue-bypass 2>/dev/null || return 1
	iptables -D OUTPUT -t mangle -p 255 -j NFQUEUE --queue-num $QNUM --queue-bypass 2>/dev/null
	return 0
}
nft_has_nfq()
{
	local res=1
	nft delete table ${NFT_TABLE}_test 2>/dev/null
	nft add table ${NFT_TABLE}_test 2>/dev/null && {
		nft add chain ${NFT_TABLE}_test test
		nft add rule ${NFT_TABLE}_test test queue num $QNUM bypass 2>/dev/null && res=0
		nft delete table ${NFT_TABLE}_test
	}
	return $res
}

doh_resolve()
{
	# $1 - ip version 4/6
	# $2 - hostname
	# $3 - doh server URL. use $DOH_SERVER if empty
	"$MDIG" --family=$1 --dns-make-query=$2 | "$CURL" --max-time $CURL_MAX_TIME_DOH -s --data-binary @- -H "Content-Type: application/dns-message" "${3:-$DOH_SERVER}" | "$MDIG" --dns-parse-query
}
doh_find_working()
{
	local doh

	[ -n "$DOH_SERVER" ] && return 0
	echo "* searching working DoH server"
	DOH_SERVER=
	for doh in $DOH_SERVERS; do
		echo -n "$doh : "
		if doh_resolve 4 iana.org $doh >/dev/null 2>/dev/null; then
			echo OK
			DOH_SERVER="$doh"
			return 0
		else
			echo FAIL
		fi
	done
	echo all DoH servers failed
	return 1
}

mdig_vars()
{
	# $1 - ip version 4/6
	# $2 - hostname

	hostvar=$(echo $2 | sed -e 's/[\./?&#@%*$^:~=!()+-]/_/g' | tr 'A-Z' 'a-z')
	cachevar=DNSCACHE_${hostvar}_$1
	countvar=${cachevar}_COUNT
	eval count=\$${countvar}
}
mdig_cache()
{
	# $1 - ip version 4/6
	# $2 - hostname
	local hostvar cachevar countvar count ip ips
	mdig_vars "$@"
	[ -n "$count" ] || {
		# windows version of mdig outputs 0D0A line ending. remove 0D.
		if [ "$SECURE_DNS" = 1 ]; then
			ips="$(echo $2 | doh_resolve $1 $2 | tr -d '\r' | xargs)"
		else
			ips="$(echo $2 | "$MDIG" --family=$1 | tr -d '\r' | xargs)"
		fi
		[ -n "$ips" ] || return 1
		count=0
		for ip in $ips; do
			eval ${cachevar}_$count=$ip
			count=$(($count+1))
		done
		eval $countvar=$count
	}
	return 0
}
mdig_resolve()
{
	# $1 - ip version 4/6
	# $2 - var to receive result
	# $3 - hostname, possibly with uri : rutracker.org/xxx/xxxx
	local hostvar cachevar countvar count n sdom

	split_by_separator "$3" / sdom
	mdig_vars "$1" "$sdom"
	if [ -n "$count" ]; then
		n=$(random 0 $(($count-1)))
		eval $2=\$${cachevar}_$n
		return 0
	else
		mdig_cache "$1" "$sdom" && mdig_resolve "$1" "$2" "$sdom"
	fi
}
mdig_resolve_all()
{
	# $1 - ip version 4/6
	# $2 - var to receive result
	# $3 - hostname

	local hostvar cachevar countvar count ip__ ips__ n sdom

	split_by_separator "$3" / sdom
	mdig_vars "$1" "$sdom"
	if [ -n "$count" ]; then
		n=0
		while [ "$n" -lt $count ]; do
			eval ip__=\$${cachevar}_$n
			if [ -n "$ips__" ]; then
				ips__="$ips__ $ip__"
			else
				ips__="$ip__"
			fi
			n=$(($n + 1))
		done
		eval $2="\$ips__"
		return 0
	else
		mdig_cache "$1" "$sdom" && mdig_resolve_all "$1" "$2" "$sdom"
	fi
}

netcat_setup()
{
	[ -n "$NCAT" ] || {
		if exists ncat; then
			NCAT=ncat
		elif exists nc; then
			# busybox netcat does not support any required options
			is_linked_to_busybox nc && return 1
			NCAT=nc
		else
			return 1
		fi
	}
	return 0
}
netcat_test()
{
	# $1 - ip
	# $2 - port
	local cmd
	netcat_setup && {
		cmd="$NCAT -z -w 2 $1 $2"
		echo $cmd
		$cmd 2>&1
	}
}

check_system()
{
	echo \* checking system

	UNAME=$(uname)
	SUBSYS=
	local s

	# can be passed FWTYPE=iptables to override default nftables preference
	case "$UNAME" in
		Linux)
			PKTWS="$NFQWS2"
			PKTWSD=nfqws2
			linux_fwtype
			[ "$FWTYPE" = iptables -o "$FWTYPE" = nftables ] || {
				echo firewall type $FWTYPE not supported in $UNAME
				exitp 5
			}
			;;
		FreeBSD)
			PKTWS="$DVTWS2"
			PKTWSD=dvtws2
			FWTYPE=ipfw
			[ -f /etc/platform ] && read SUBSYS </etc/platform
			;;
		OpenBSD)
			PKTWS="$DVTWS2"
			PKTWSD=dvtws2
			FWTYPE=opf
			;;
		CYGWIN*)
			UNAME=CYGWIN
			PKTWS="$WINWS2"
			PKTWSD=winws2
			FWTYPE=windivert
			# ts fooling requires timestamps. they are disabled by default in windows.
			echo enabling tcp timestamps
			netsh interface tcp set global timestamps=enabled >/dev/null
			;;
		*)
			echo $UNAME not supported
			exitp 5
	esac
	echo $UNAME${SUBSYS:+/$SUBSYS} detected
	echo -n 'kernel: '
	if [ -f "/proc/version" ]; then
		cat /proc/version
	else
		uname -a
	fi
	[ -f /etc/os-release ] && {
		. /etc/os-release
		[ -n "$PRETTY_NAME" ] && echo "distro: $PRETTY_NAME"
		[ -n "$OPENWRT_RELEASE" ] && echo "openwrt release: $OPENWRT_RELEASE"
		[ -n "$OPENWRT_BOARD" ] && echo "openwrt board: $OPENWRT_BOARD"
		[ -n "$OPENWRT_ARCH" ] && echo "openwrt arch: $OPENWRT_ARCH"
	}
	echo firewall type is $FWTYPE
	echo CURL=$CURL
	"$CURL" --version
}

zp_already_running()
{
	case "$UNAME" in
		CYGWIN)
			win_process_exists $PKTWSD || win_process_exists winws || win_process_exists goodbyedpi
			;;
		FreeBSD|OpenBSD)
			process_exists $PKTWSD || process_exists tpws || process_exists dvtws
			;;
		Linux)
			process_exists $PKTWSD || process_exists tpws || process_exists nfqws
			;;
		*)
			return 1
	esac
}
check_already()
{
	echo \* checking already running DPI bypass processes
	if zp_already_running; then
		echo "!!! WARNING. some dpi bypass processes already running !!!"
		echo "!!! WARNING. blockcheck requires all DPI bypass methods disabled !!!"
		echo "!!! WARNING. pls stop all dpi bypass instances that may interfere with blockcheck !!!"
	fi
}

freebsd_module_loaded()
{
	# $1 - module name
	kldstat -qm "${1}"
}
freebsd_modules_loaded()
{
	# $1,$2,$3, ... - module names
	while [ -n "$1" ]; do
		freebsd_module_loaded $1 || return 1
		shift
	done
	return 0
}

check_prerequisites()
{
	echo \* checking prerequisites

	[ "$SKIP_PKTWS" = 1 -o -x "$PKTWS" ] &&  [ -x "$MDIG" ] || {
		local target
		case $UNAME in
			OpenBSD)
				target="bsd"
				echo $PKTWS or $MDIG is not available. \`gmake -C \"$ZAPRET_BASE\" bsd \`
				;;
			*)
				echo $PKTWS or $MDIG is not available. run \"$ZAPRET_BASE/install_bin.sh\" or \`make -C \"$ZAPRET_BASE\" $target\`
		esac
		exitp 6
	}

	local prog progs='curl'
	[ "$SKIP_PKTWS" = 1 ] || {
		case "$UNAME" in
			Linux)
				case "$FWTYPE" in
					iptables)
						ipt_has_nfq || {
							echo NFQUEUE iptables or ip6tables target is missing. pls install modules.
							exitp 6
						}
						progs="$progs iptables ip6tables"
						;;
					nftables)
						nft_has_nfq || {
							echo nftables queue support is not available. pls install modules.
							exitp 6
						}
						progs="$progs nft"
						;;
				esac
				;;
			FreeBSD)
				freebsd_modules_loaded ipfw ipdivert || {
					echo ipfw or ipdivert kernel module not loaded
						exitp 6
				}
				[ "$(sysctl -qn net.inet.ip.fw.enable)" = 0 -o "$(sysctl -qn net.inet6.ip6.fw.enable)" = 0 ] && {
					echo ipfw is disabled. use : ipfw enable firewall
					exitp 6
				}
				pf_is_avail && {
					pf_save
					[ "$SUBSYS" = "pfSense" ] && {
						# pfsense's ipfw may not work without these workarounds
						sysctl net.inet.ip.pfil.outbound=ipfw,pf 2>/dev/null
						sysctl net.inet.ip.pfil.inbound=ipfw,pf 2>/dev/null
						sysctl net.inet6.ip6.pfil.outbound=ipfw,pf 2>/dev/null
						sysctl net.inet6.ip6.pfil.inbound=ipfw,pf 2>/dev/null
						pfctl -qd
						pfctl -qe
						pf_restore
					}
				}
				progs="$progs ipfw"
				;;
			OpenBSD)
				pf_is_avail || {
					echo pf is not available
					exitp 6
				}
				pf_save
				progs="$progs pfctl"
				;;
		esac
	}

	for prog in $progs; do
		exists $prog || {
			echo $prog does not exist. please install
			exitp 6
		}
	done

	if exists nslookup; then
		LOOKUP=nslookup
	elif exists host; then
		LOOKUP=host
	else
		echo nslookup or host does not exist. please install
		exitp 6
	fi
}


curl_translate_code()
{
	# $1 - code
	printf $1
	case $1 in
		0) printf ": ok"
		;;
		1) printf ": unsupported protocol"
		;;
		2) printf ": early initialization code failed"
		;;
		3) printf ": the URL was not properly formatted"
		;;
		4) printf ": feature not supported by libcurl"
		;;
		5) printf ": could not resolve proxy"
		;;
		6) printf ": could not resolve host"
		;;
		7) printf ": could not connect"
		;;
		8) printf ": invalid server reply"
		;;
		9) printf ": remote access denied"
		;;
		27) printf ": out of memory"
		;;
		28) printf ": operation timed out"
		;;
		35) printf ": SSL connect error"
		;;
	esac
}
curl_supports_tls13()
{
	local r
	"$CURL" --tlsv1.3 -Is -o /dev/null --max-time 1 http://127.0.0.1:65535 2>/dev/null
	# return code 2 = init failed. likely bad command line options
	[ $? = 2 ] && return 1
	# curl can have tlsv1.3 key present but ssl library without TLS 1.3 support
	# this is online test because there's no other way to trigger library incompatibility case
	"$CURL" --tlsv1.3 --max-time 1 -Is -o /dev/null https://iana.org 2>/dev/null
	r=$?
	[ $r != 4 -a $r != 35 ]
}

curl_supports_tlsmax()
{
	# supported only in OpenSSL and LibreSSL
	"$CURL" --version | grep -Fq -e OpenSSL -e LibreSSL -e BoringSSL -e GnuTLS -e quictls || return 1
	# supported since curl 7.54
	"$CURL" --tls-max 1.2 -Is -o /dev/null --max-time 1 http://127.0.0.1:65535 2>/dev/null
	# return code 2 = init failed. likely bad command line options
	[ $? != 2 ]
}

curl_supports_connect_to()
{
	"$CURL" --connect-to 127.0.0.1:: -o /dev/null --max-time 1 http://127.0.0.1:65535 2>/dev/null
	[ "$?" != 2 ]
}

curl_supports_http3()
{
	# if it has http3 : curl: (3) HTTP/3 requested for non-HTTPS URL
	# otherwise : curl: (2) option --http3-only: is unknown
	"$CURL" --connect-to 127.0.0.1:: -o /dev/null --max-time 1 --http3-only http://127.0.0.1:65535 2>/dev/null
	[ "$?" != 2 ]
}

hdrfile_http_code()
{
	# $1 - hdr file
	sed -nre '1,1 s/^HTTP\/1\.[0,1] ([0-9]+) .*$/\1/p' "$1"
}
hdrfile_location()
{
	# $1 - hdr file

	# some DPIs return CRLF line ending
	tr -d '\015' <"$1" | sed -nre 's/^[Ll][Oo][Cc][Aa][Tt][Ii][Oo][Nn]:[ 	]*([^ 	]*)[ 	]*$/\1/p'
}

curl_with_subst_ip()
{
	# $1 - domain
	# $2 - port
	# $3 - ip
	# $4+ - curl params
	local ip="$3"
	case "$ip" in
		*:*) ip="[$ip]" ;;
	esac
	local connect_to="--connect-to $1::$ip${2:+:$2}" arg
	shift ; shift ; shift;
	[ "$CURL_VERBOSE" = 1 ] && arg="-v"
	[ "$CURL_CMD" = 1 ] && echo $CURL ${arg:+$arg }$connect_to "$@"
	ALL_PROXY="$ALL_PROXY" "$CURL" ${arg:+$arg }$connect_to "$@"
}
curl_with_dig()
{
	# $1 - ip version : 4/6
	# $2 - domain name
	# $3 - port
	# $4+ - curl params
	local dom="$2" port=$3
	local sdom suri ip

	split_by_separator "$dom" / sdom suri
	mdig_resolve $1 ip "$sdom"
	shift ; shift ; shift
	if [ -n "$ip" ]; then
		curl_with_subst_ip "$sdom" "$port" "$ip" "$@"
	else
		return 6
	fi
}
curl_probe()
{
	# $1 - ip version : 4/6
	# $2 - domain name
	# $3 - port
	# $4 - subst ip
	# $5+ - curl params
	local ipv=$1 dom="$2" port=$3 subst=$4
	shift; shift; shift; shift
	if [ -n "$subst" ]; then
		curl_with_subst_ip "$dom" $port $subst "$@"
	else
		curl_with_dig $ipv "$dom" $port "$@"
	fi
}
curl_test_http()
{
	# $1 - ip version : 4/6
	# $2 - domain name
	# $3 - subst ip
	# $4 - "detail" - detail info

	local code loc hdrt="${HDRTEMP}_${!:-$$}.txt" dom="$(tolower "$2")"
	curl_probe $1 "$2" $HTTP_PORT "$3" -SsD "$hdrt" -A "$USER_AGENT" --max-time $CURL_MAX_TIME $CURL_OPT "http://$2" -o /dev/null 2>&1 || {
		code=$?
		rm -f "$hdrt"
		return $code
	}
	if [ "$4" = "detail" ] ; then
		head -n 1 "$hdrt"
		grep "^[lL]ocation:" "$hdrt"
	else
		code=$(hdrfile_http_code "$hdrt")
		[ "$code" = 301 -o "$code" = 302 -o "$code" = 307 -o "$code" = 308 ] && {
			loc=$(hdrfile_location "$hdrt")
			split_by_separator "$dom" / dom
			tolower "$loc" | grep -qE "^https?://.*$dom(/|$)" ||
			tolower "$loc" | grep -vqE '^https?://' || {
				echo suspicious redirection $code to : $loc
				rm -f "$hdrt"
				return 254
			}
		}
	fi
	rm -f "$hdrt"
	[ "$code" = 400 ] && {
		# this can often happen if the server receives fake packets it should not receive
		echo http code $code. likely the server receives fakes.
		return 254
	}
	return 0
}
curl_test_https_tls12()
{
	# $1 - ip version : 4/6
	# $2 - domain name
	# $3 - subst ip

	# do not use tls 1.3 to make sure server certificate is not encrypted
	curl_probe $1 "$2" $HTTPS_PORT "$3" $HTTPS_HEAD -Ss -A "$USER_AGENT" --max-time $CURL_MAX_TIME $CURL_OPT --tlsv1.2 $TLSMAX12 "https://$2" -o /dev/null 2>&1
}
curl_test_https_tls13()
{
	# $1 - ip version : 4/6
	# $2 - domain name
	# $3 - subst ip

	# force TLS1.3 mode
	curl_probe $1 "$2" $HTTPS_PORT "$3" $HTTPS_HEAD -Ss -A "$USER_AGENT" --max-time $CURL_MAX_TIME $CURL_OPT --tlsv1.3 $TLSMAX13 "https://$2" -o /dev/null 2>&1
}

curl_test_http3()
{
	# $1 - ip version : 4/6
	# $2 - domain name

	# force QUIC only mode without tcp
	curl_with_dig $1 "$2" $QUIC_PORT $HTTPS_HEAD -Ss -A "$USER_AGENT" --max-time $CURL_MAX_TIME_QUIC --http3-only $CURL_OPT "https://$2" -o /dev/null 2>&1
}

ipt_aux_scheme()
{
	# $1 - 1 - add , 0 - del
	# $2 - tcp/udp
	# $3 - port

	# to avoid possible INVALID state drop
	[ "$2" = tcp ] && IPT_ADD_DEL $1 INPUT -p $2 --sport $3 ! --syn $IPT_COMMENT -j ACCEPT

	local icmp_filter="-p icmp -m icmp --icmp-type"
	[ "$IPV" = 6 ] && icmp_filter="-p icmpv6 -m icmp6 --icmpv6-type"
	IPT_ADD_DEL $1 INPUT $icmp_filter time-exceeded -m connmark --mark $DESYNC_MARK/$DESYNC_MARK $IPT_COMMENT -j DROP 

	# for strategies with incoming packets involved (autottl)
	IPT_ADD_DEL $1 OUTPUT -p $2 --dport $3 -m conntrack --ctstate INVALID $IPT_COMMENT -j ACCEPT
	if [ "$IPV" = 6 -a -n "$IP6_DEFRAG_DISABLE" ]; then
		# the only way to reliable disable ipv6 defrag. works only in 4.16+ kernels
		IPT_ADD_DEL $1 OUTPUT -t raw -p $2 -m frag $IPT_COMMENT -j CT --notrack
	elif [ "$IPV" = 4 ]; then
		# enable fragments
		IPT_ADD_DEL $1 OUTPUT -f $IPT_COMMENT -j ACCEPT
	fi
	# enable everything generated by nfqws (works only in OUTPUT, not in FORWARD)
	# raw table may not be present
	IPT_ADD_DEL $1 OUTPUT -t raw -m mark --mark $DESYNC_MARK/$DESYNC_MARK $IPT_COMMENT -j CT --notrack
}
ipt_scheme()
{
	# $1 - tcp/udp
	# $2 - port
	# $3 - ip list

	local ip

	$IPTABLES -t mangle -N $IPT_OUT_CHAIN 2>/dev/null
	$IPTABLES -t mangle -F $IPT_OUT_CHAIN
	IPT OUTPUT -t mangle -j $IPT_OUT_CHAIN

	# prevent loop
	$IPTABLES -t mangle -A $IPT_OUT_CHAIN -m mark --mark $DESYNC_MARK/$DESYNC_MARK -j RETURN
	$IPTABLES -t mangle -A $IPT_OUT_CHAIN ! -p $1 -j RETURN
	$IPTABLES -t mangle -A $IPT_OUT_CHAIN -p $1 ! --dport $2 -j RETURN

	for ip in $3; do
		$IPTABLES -t mangle -A $IPT_OUT_CHAIN -d $ip -j CONNMARK --or-mark $DESYNC_MARK
		$IPTABLES -t mangle -A $IPT_OUT_CHAIN -d $ip -j NFQUEUE --queue-num $QNUM
	done

	ipt_aux_scheme 1 $1 $2
}
nft_scheme()
{
	# $1 - tcp/udp
	# $2 - port
	# $3 - ip list

	local iplist ipver=$IPV
	[ "$IPV" = 6 ] || ipver=
	make_comma_list iplist $3

	nft add table inet $NFT_TABLE
	nft "add chain inet $NFT_TABLE postnat { type filter hook postrouting priority 102; }"
	nft "add rule inet $NFT_TABLE postnat meta nfproto ipv${IPV} $1 dport $2 mark and $DESYNC_MARK == 0 ip${ipver} daddr {$iplist} ct mark set ct mark or $DESYNC_MARK queue num $QNUM"
	# for strategies with incoming packets involved (autottl)
	nft "add chain inet $NFT_TABLE prenat { type filter hook prerouting priority -102; }"
	# enable everything generated by nfqws (works only in OUTPUT, not in FORWARD)
	nft "add chain inet $NFT_TABLE predefrag { type filter hook output priority -402; }"
	nft "add rule inet $NFT_TABLE predefrag meta nfproto ipv${IPV} mark and $DESYNC_MARK !=0 notrack"
	[ "$IPV" = 4 ] && {
		nft "add rule inet $NFT_TABLE prenat icmp type time-exceeded ct mark and $DESYNC_MARK != 0 drop"
		nft "add rule inet $NFT_TABLE prenat icmp type time-exceeded ct state invalid drop"
	}
	[ "$IPV" = 6 ] && {
		nft "add rule inet $NFT_TABLE prenat icmpv6 type time-exceeded ct mark and $DESYNC_MARK != 0 drop"
		nft "add rule inet $NFT_TABLE prenat icmpv6 type time-exceeded ct state invalid drop"
	}
}

pktws_ipt_prepare()
{
	# $1 - tcp/udp
	# $2 - port
	# $3 - ip list

	local ip v=

	case "$FWTYPE" in
		iptables)
			ipt_scheme $1 $2 "$3"
			;;
		nftables)
			nft_scheme $1 $2 "$3"
			;;
		ipfw)
			# disable PF to avoid interferences
			pf_is_avail && pfctl -qd
			for ip in $3; do
				IPFW_ADD divert $IPFW_DIVERT_PORT $1 from me to $ip $2 proto ip${IPV} out not diverted
			done
			;;
		opf)
			opf_prepare_dvtws $1 $2 "$3"
			;;
		windivert)
			[ "$IPV" = 6 ] && v="v6"
			WF="--wf-l3=ipv${IPV} --wf-${1}-out=$2"
			WFRAWF=
			for ip in $3; do
				[ -n "$WFRAWF" ] && WFRAWF="$WFRAWF or "
				WFRAWF="${WFRAWF}ip${v}.DstAddr=$ip or ip${v}.SrcAddr=$ip"
			done
			;;

	esac
}
pktws_ipt_unprepare()
{
	# $1 - tcp/udp
	# $2 - port

	case "$FWTYPE" in
		iptables)
			ipt_aux_scheme 0 $1 $2
			IPT_DEL OUTPUT -t mangle -j $IPT_OUT_CHAIN
			$IPTABLES -t mangle -F $IPT_OUT_CHAIN 2>/dev/null
			$IPTABLES -t mangle -X $IPT_OUT_CHAIN 2>/dev/null
			;;
		nftables)
			nft delete table inet $NFT_TABLE 2>/dev/null
			;;
		ipfw)
			IPFW_DEL
			pf_is_avail && pf_restore
			;;
		opf)
			pf_restore
			;;
		windivert)
			unset WF WFRAWF
			;;
	esac
}

pktws_ipt_prepare_tcp()
{
	# $1 - port
	# $2 - ip list

	local ip iplist ipver

	pktws_ipt_prepare tcp $1 "$2"

	# for autottl mode and tcp_mss detection
	case "$FWTYPE" in
		iptables)
			$IPTABLES -N $IPT_IN_CHAIN -t mangle 2>/dev/null
			$IPTABLES -F $IPT_IN_CHAIN -t mangle 2>/dev/null
			IPT INPUT -t mangle -j $IPT_IN_CHAIN
			$IPTABLES -t mangle -A $IPT_IN_CHAIN ! -p tcp -j RETURN
			$IPTABLES -t mangle -A $IPT_IN_CHAIN -p tcp ! --sport $1 -j RETURN
			$IPTABLES -t mangle -A $IPT_IN_CHAIN -p tcp ! --tcp-flags SYN,ACK SYN,ACK -j RETURN
			for ip in $2; do
				$IPTABLES -A $IPT_IN_CHAIN -t mangle -s $ip -j NFQUEUE --queue-num $QNUM
			done
			;;
		nftables)
			ipver=$IPV
			[ "$IPV" = 6 ] || ipver=
			make_comma_list iplist $2
			nft "add rule inet $NFT_TABLE prenat meta nfproto ipv${IPV} tcp sport $1 tcp flags & (syn | ack) == (syn | ack) ip${ipver} saddr {$iplist} queue num $QNUM"
			;;
		ipfw)
			for ip in $2; do
				IPFW_ADD divert $IPFW_DIVERT_PORT tcp from $ip $1 to me proto ip${IPV} tcpflags syn,ack in not diverted
			done
			;;
	esac
}
pktws_ipt_unprepare_tcp()
{
	# $1 - port

	pktws_ipt_unprepare tcp $1

	case "$FWTYPE" in
		iptables)
			IPT_DEL INPUT -t mangle -j $IPT_IN_CHAIN
			$IPTABLES -t mangle -F $IPT_IN_CHAIN 2>/dev/null
			$IPTABLES -t mangle -X $IPT_IN_CHAIN 2>/dev/null
			;;
	esac
}
pktws_ipt_prepare_udp()
{
	# $1 - port
	# $2 - ip list

	pktws_ipt_prepare udp $1 "$2"
}
pktws_ipt_unprepare_udp()
{
	# $1 - port

	pktws_ipt_unprepare udp $1
}


pktws_start()
{
	case "$UNAME" in
		Linux)
			"$NFQWS2" --uid $WS_UID:$WS_GID --fwmark=$DESYNC_MARK --qnum=$QNUM --lua-init=@"$ZAPRET_BASE/lua/zapret-lib.lua" --lua-init=@"$ZAPRET_BASE/lua/zapret-antidpi.lua" "$@" >/dev/null &
			;;
		FreeBSD|OpenBSD)
			"$DVTWS2" --port=$IPFW_DIVERT_PORT --lua-init=@"$ZAPRET_BASE/lua/zapret-lib.lua" --lua-init=@"$ZAPRET_BASE/lua/zapret-antidpi.lua" "$@" >/dev/null &
			;;
		CYGWIN)
			# some methods require empty acks
			# use raw filter to filter target ip addresses in-kernel to allow multiple blockchecks running at the same time
			# use guard timer to kill unmanaged pktws instances
			"$WINWS2" --wf-tcp-empty=1 $WF --wf-raw-filter="$WFRAWF" \
				--lua-init="timer_set('exit_guard',function(name,data) io.stderr:write('exit_guard\n'); os.exit(3000); end,20000,true)" \
				--lua-init=@"$ZAPRET_BASE/lua/zapret-lib.lua" --lua-init=@"$ZAPRET_BASE/lua/zapret-antidpi.lua" "$@" >/dev/null &
			;;
	esac
	PID=$!
	# give some time to initialize
	minsleep
}

ws_kill()
{
	local sig
	[ -z "$PID" ] || {
		sig=-9
		# use fast kill using TerminateProcess() in cygwin
		[ "$UNAME" = "CYGWIN" ] && sig=-f
		killwait $sig $PID 2>/dev/null
		PID=
	}
}

check_domain_port_block()
{
	# $1 - domain
	# $2 - port
	local ip ips
	echo
	echo \* port block tests ipv$IPV $1:$2
	if netcat_setup; then
		mdig_resolve_all $IPV ips $1
		if [ -n "$ips" ]; then
			for ip in $ips; do
				if netcat_test $ip $2; then
					echo $ip connects
				else
					echo $ip does not connect. netcat code $?
				fi
			done
		else
			echo "ipv${IPV} $1 does not resolve"
		fi
	else
		echo suitable netcat not found. busybox nc is not supported. pls install nmap ncat or openbsd netcat.
	fi
}

curl_test()
{
	# $1 - test function
	# $2 - domain
	# $3 - subst ip
	# $4 - param of test function
	local code=0 n=0 p pids

	if [ "$PARALLEL" = 1 ]; then
		rm -f "${PARALLEL_OUT}"*
		for n in $(seq -s ' ' 1 $REPEATS); do
			$1 "$IPV" "$2" $3 "$4" >"${PARALLEL_OUT}_$n" &
			pids="${pids:+$pids }$!"
		done
		n=1
		for p in $pids; do
			[ $REPEATS -gt 1 ] && printf "[attempt $n] "
			if wait $p; then
				[ $REPEATS -gt 1 ] && echo 'AVAILABLE'
			else
				code=$?
				cat "${PARALLEL_OUT}_$n"
			fi
			n=$(($n+1))
		done
		rm -f "${PARALLEL_OUT}"*
	else
		while [ $n -lt $REPEATS ]; do
			n=$(($n+1))
			[ $REPEATS -gt 1 ] && printf "[attempt $n] "
			if $1 "$IPV" "$2" $3 "$4" ; then
				[ $REPEATS -gt 1 ] && echo 'AVAILABLE'
			else
				code=$?
				[ "$SCANLEVEL" = quick ] && break
			fi
		done
	fi
	[ "$4" = detail ] || {
		if [ $code = 254 ]; then
			echo "UNAVAILABLE"
		elif [ $code = 0 ]; then
			echo '!!!!! AVAILABLE !!!!!'
		else
			echo "UNAVAILABLE code=$code"
		fi
	}
	return $code
}
ws_curl_test()
{
	# $1 - ws start function
	# $2 - test function
	# $3 - domain
	# $4,$5,$6, ... - ws params
	local code ws_start=$1 testf=$2 dom="$3"

	[ "$SIMULATE" = 1 ] && {
		n=$(random 0 99)
		if [ "$n" -lt "$SIM_SUCCESS_RATE" ]; then
			echo "SUCCESS"
			return 0
		else
			echo "FAILED"
			return 7
		fi
	}
	shift
	shift
	shift
	$ws_start "$@"
	curl_test $testf "$dom"
	code=$?
	ws_kill
	return $code
}
pktws_curl_test()
{
	# $1 - test function
	# $2 - domain
	# $3,$4,$5, ... - nfqws/dvtws params
	local testf=$1 dom="$2" strategy code

	shift; shift;
	echo - $testf ipv$IPV $dom : $PKTWSD ${WF:+$WF }${PKTWS_EXTRA_PRE:+$PKTWS_EXTRA_PRE }${PKTWS_EXTRA_PRE_1:+"$PKTWS_EXTRA_PRE_1" }${PKTWS_EXTRA_PRE_2:+"$PKTWS_EXTRA_PRE_2" }${PKTWS_EXTRA_PRE_3:+"$PKTWS_EXTRA_PRE_3" }${PKTWS_EXTRA_PRE_4:+"$PKTWS_EXTRA_PRE_4" }${PKTWS_EXTRA_PRE_5:+"$PKTWS_EXTRA_PRE_5" }${PKTWS_EXTRA_PRE_6:+"$PKTWS_EXTRA_PRE_6" }${PKTWS_EXTRA_PRE_7:+"$PKTWS_EXTRA_PRE_7" }${PKTWS_EXTRA_PRE_8:+"$PKTWS_EXTRA_PRE_8" }${PKTWS_EXTRA_PRE_9:+"$PKTWS_EXTRA_PRE_9" }$@${PKTWS_EXTRA_POST:+ $PKTWS_EXTRA_POST}${PKTWS_EXTRA_POST_1:+ "$PKTWS_EXTRA_POST_1"}${PKTWS_EXTRA_POST_2:+ "$PKTWS_EXTRA_POST_2"}${PKTWS_EXTRA_POST_3:+ "$PKTWS_EXTRA_POST_3"}${PKTWS_EXTRA_POST_4:+ "$PKTWS_EXTRA_POST_4"}${PKTWS_EXTRA_POST_5:+ "$PKTWS_EXTRA_POST_5"}${PKTWS_EXTRA_POST_6:+ "$PKTWS_EXTRA_POST_6"}${PKTWS_EXTRA_POST_7:+ "$PKTWS_EXTRA_POST_7"}${PKTWS_EXTRA_POST_8:+ "$PKTWS_EXTRA_POST_8"}${PKTWS_EXTRA_POST_9:+ "$PKTWS_EXTRA_POST_9"}
	ws_curl_test pktws_start $testf "$dom" ${PKTWS_EXTRA_PRE:+$PKTWS_EXTRA_PRE }${PKTWS_EXTRA_PRE_1:+"$PKTWS_EXTRA_PRE_1" }${PKTWS_EXTRA_PRE_2:+"$PKTWS_EXTRA_PRE_2" }${PKTWS_EXTRA_PRE_3:+"$PKTWS_EXTRA_PRE_3" }${PKTWS_EXTRA_PRE_4:+"$PKTWS_EXTRA_PRE_4" }${PKTWS_EXTRA_PRE_5:+"$PKTWS_EXTRA_PRE_5" }${PKTWS_EXTRA_PRE_6:+"$PKTWS_EXTRA_PRE_6" }${PKTWS_EXTRA_PRE_7:+"$PKTWS_EXTRA_PRE_7" }${PKTWS_EXTRA_PRE_8:+"$PKTWS_EXTRA_PRE_8" }${PKTWS_EXTRA_PRE_9:+"$PKTWS_EXTRA_PRE_9" }"$@"${PKTWS_EXTRA_POST:+ $PKTWS_EXTRA_POST}${PKTWS_EXTRA_POST_1:+ "$PKTWS_EXTRA_POST_1"}${PKTWS_EXTRA_POST_2:+ "$PKTWS_EXTRA_POST_2"}${PKTWS_EXTRA_POST_3:+ "$PKTWS_EXTRA_POST_3"}${PKTWS_EXTRA_POST_4:+ "$PKTWS_EXTRA_POST_4"}${PKTWS_EXTRA_POST_5:+ "$PKTWS_EXTRA_POST_5"}${PKTWS_EXTRA_POST_6:+ "$PKTWS_EXTRA_POST_6"}${PKTWS_EXTRA_POST_7:+ "$PKTWS_EXTRA_POST_7"}${PKTWS_EXTRA_POST_8:+ "$PKTWS_EXTRA_POST_8"}${PKTWS_EXTRA_POST_9:+ "$PKTWS_EXTRA_POST_9"}

	code=$?
	[ "$code" = 0 ] && {
		strategy="$@"
		strategy_append_extra_pktws
		report_append "$dom" "$testf ipv${IPV}" "$PKTWSD ${WF:+$WF }$strategy"
	}
	return $code
}
strategy_append_extra_pktws()
{
	strategy="${strategy:+${PKTWS_EXTRA_PRE:+$PKTWS_EXTRA_PRE }${PKTWS_EXTRA_PRE_1:+"$PKTWS_EXTRA_PRE_1" }${PKTWS_EXTRA_PRE_2:+"$PKTWS_EXTRA_PRE_2" }${PKTWS_EXTRA_PRE_3:+"$PKTWS_EXTRA_PRE_3" }${PKTWS_EXTRA_PRE_4:+"$PKTWS_EXTRA_PRE_4" }${PKTWS_EXTRA_PRE_5:+"$PKTWS_EXTRA_PRE_5" }${PKTWS_EXTRA_PRE_6:+"$PKTWS_EXTRA_PRE_6" }${PKTWS_EXTRA_PRE_7:+"$PKTWS_EXTRA_PRE_7" }${PKTWS_EXTRA_PRE_8:+"$PKTWS_EXTRA_PRE_8" }${PKTWS_EXTRA_PRE_9:+"$PKTWS_EXTRA_PRE_9" }$strategy${PKTWS_EXTRA_POST:+ $PKTWS_EXTRA_POST}${PKTWS_EXTRA_POST_1:+ "$PKTWS_EXTRA_POST_1"}${PKTWS_EXTRA_POST_2:+ "$PKTWS_EXTRA_POST_2"}${PKTWS_EXTRA_POST_3:+ "$PKTWS_EXTRA_POST_3"}${PKTWS_EXTRA_POST_4:+ "$PKTWS_EXTRA_POST_4"}${PKTWS_EXTRA_POST_5:+ "$PKTWS_EXTRA_POST_5"}${PKTWS_EXTRA_POST_6:+ "$PKTWS_EXTRA_POST_6"}${PKTWS_EXTRA_POST_7:+ "$PKTWS_EXTRA_POST_7"}${PKTWS_EXTRA_POST_8:+ "$PKTWS_EXTRA_POST_8"}${PKTWS_EXTRA_POST_9:+ "$PKTWS_EXTRA_POST_9"}}"
}


xxxws_curl_test_update()
{
	# $1 - xxx_curl_test function
	# $2 - test function
	# $3 - domain
	# $4,$5,$6, ... - nfqws2/dvtws2 params
	local code xxxf=$1 testf=$2 dom="$3"
	shift
	shift
	shift
	$xxxf $testf "$dom" "$@"
	code=$?
	[ $code = 0 ] && strategy="${strategy:-$@}"
	return $code
}
pktws_curl_test_update()
{
	xxxws_curl_test_update pktws_curl_test "$@"
}

report_append()
{
	# $1 - domain
	# $2 - test function + ipver
	# $3 - value
	local hashstr hash hashvar hashcountvar val ct

	# save resources if only one domain
	[ "$DOMAINS_COUNT" -gt 1 ] && {
		hashstr="$2 : $3"
		hash="$(echo -n "$hashstr" | md5f)"
		hashvar=RESHASH_${hash}
		hashcountvar=${hashvar}_COUNTER

		NRESHASH=${NRESHASH:-0}

		eval val="\$$hashvar"
		if [ -n "$val" ]; then
			eval ct="\$$hashcountvar"
			ct=$(($ct + 1))
			eval $hashcountvar="\$ct"
		else
			eval $hashvar=\"$hashstr\"
			eval $hashcountvar=1
			eval RES_$NRESHASH="\$hash"
			NRESHASH=$(($NRESHASH+1))
		fi
	}

	NREPORT=${NREPORT:-0}
	eval REPORT_${NREPORT}=\"$2 $1 : $3\"
	NREPORT=$(($NREPORT+1))
}
report_print()
{
	local n=0 s
	NREPORT=${NREPORT:-0}
	while [ $n -lt $NREPORT ]; do
		eval s=\"\${REPORT_$n}\"
		echo $s
		n=$(($n+1))
	done
}
result_intersection_print()
{
	local n=0 hash hashvar hashcountvar ct val
	while : ; do
		eval hash=\"\$RES_$n\"
		[ -n "$hash" ] || break
		hashvar=RESHASH_${hash}
		hashcountvar=${hashvar}_COUNTER
		eval ct=\"\$$hashcountvar\"
		[ "$ct" = "$DOMAINS_COUNT" ] && {
			eval val=\"\$$hashvar\"
			echo "$val"
		}
		n=$(($n + 1))
	done
}
result_coverage_print()
{
	# Lists every distinct successful strategy together with how many of the
	# DOMAINS_COUNT domains/targets it worked for, most-covered first.
	# Unlike result_intersection_print, a strategy doesn't need 100% coverage
	# to be listed here - useful when DOMAINS is a set of largely independent
	# targets (e.g. one IP per ASN/provider) where no single strategy is
	# expected to satisfy every one of them, and the question is which
	# strategy gets closest.
	local n=0 hash hashvar hashcountvar ct val
	while : ; do
		eval hash=\"\$RES_$n\"
		[ -n "$hash" ] || break
		hashvar=RESHASH_${hash}
		hashcountvar=${hashvar}_COUNTER
		eval ct=\"\$$hashcountvar\"
		eval val=\"\$$hashvar\"
		printf '%s %s\n' "$ct" "$val"
		n=$(($n + 1))
	done | sort -rn | while IFS=' ' read -r ct rest; do
		echo "$ct/$DOMAINS_COUNT : $rest"
	done
}
report_strategy()
{
	# $1 - test function
	# $2 - domain
	# $3 - daemon
	echo
	if [ -n "$strategy" ]; then
		# trim spaces at the end
		strategy="$(echo "$strategy" | xargs)"
		echo "!!!!! $1: working strategy found for ipv${IPV} $2 : $3 $strategy !!!!!"
		echo
		return 0
	else
		echo "$1: $3 strategy for ipv${IPV} $2 not found"
		echo
		report_append "$2" "$1 ipv${IPV}" "$3 not working"
		return 1
	fi
}

test_runner()
{
	# $1 - function name
	# $2+ - params

	local n script FUNC=$1

	shift

	TESTDIR="$BLOCKCHECK2D/$TEST"
	[ -d "$TESTDIR" ] && {
		dir_is_not_empty "$TESTDIR" && {
			for script in "$TESTDIR/"*.sh; do
				[ -f "$script" ] || continue
				unset -f $FUNC
				. "$script"
				existf $FUNC && {
					echo
					echo "* script : $TEST/$(basename "$script")"
					$FUNC "$@"
				}
			done
		}
	}
}

pktws_check_domain_http_bypass()
{
	# $1 - test function
	# $2 - encrypted test : 0 = plain, 1 - encrypted with server reply risk, 2 - encrypted without server reply risk
	# $3 - domain

	local strategy func
	if [ "$2" = 0 ]; then
		func=pktws_check_http
	elif [ "$2" = 1 ]; then
		func=pktws_check_https_tls12
	elif [ "$2" = 2 ]; then
		func=pktws_check_https_tls13
	else
		return 1
	fi
	test_runner $func "$1" "$3"
	strategy_append_extra_pktws
	report_strategy $1 $3 $PKTWSD
}

pktws_check_domain_http3_bypass()
{
	# $1 - test function
	# $2 - domain

	local strategy
	test_runner pktws_check_http3 "$@"
	strategy_append_extra_pktws
	report_strategy $1 $2 $PKTWSD
}


check_dpi_ip_block()
{
	# $1 - test function
	# $2 - domain

	local blocked_dom=$2
	local blocked_ip blocked_ips unblocked_ip

	echo 
	echo "- IP block tests (requires manual interpretation)"

	echo "> testing $UNBLOCKED_DOM on it's original ip"
	if curl_test $1 $UNBLOCKED_DOM; then
		mdig_resolve $IPV unblocked_ip $UNBLOCKED_DOM
		[ -n "$unblocked_ip" ] || {
			echo $UNBLOCKED_DOM does not resolve. tests not possible.
			return 1
		}

		echo "> testing $blocked_dom on $unblocked_ip ($UNBLOCKED_DOM)"
		curl_test $1 $blocked_dom $unblocked_ip detail

		mdig_resolve_all $IPV blocked_ips $blocked_dom
		for blocked_ip in $blocked_ips; do
			echo "> testing $UNBLOCKED_DOM on $blocked_ip ($blocked_dom)"
			curl_test $1 $UNBLOCKED_DOM $blocked_ip detail
		done
	else
		echo $UNBLOCKED_DOM is not available. skipping this test.
	fi
}

curl_has_reason_to_continue()
{
	# $1 - curl return code
	for c in 1 2 3 4 6 27 ; do
		[ $1 = $c ] && return 1
	done
	return 0
}

check_domain_prolog()
{
	# $1 - test function
	# $2 - port
	# $3 - domain

	local code

	[ "$SIMULATE" = 1 ] && return 0

	echo
	echo \* $1 ipv$IPV $3

	echo "- checking without DPI bypass"
	curl_test $1 $3 && {
		report_append "$3" "$1 ipv${IPV}" "working without bypass"
		[ "$SCANLEVEL" = force ] || return 1
	}
	code=$?
	curl_has_reason_to_continue $code || {
		report_append "$3" "$1 ipv${IPV}" "test aborted, no reason to continue. curl code $(curl_translate_code $code)"
		return 1
	}
	return 0
}
check_domain_http_tcp()
{
	# $1 - test function
	# $2 - port
	# $3 - encrypted test : 0 = plain, 1 - encrypted with server reply risk, 2 - encrypted without server reply risk
	# $4 - domain

	local ips

	# in case was interrupted before
	ws_kill

	check_domain_prolog $1 $2 $4 || return

	[ "$SKIP_IPBLOCK" = 1 ] || check_dpi_ip_block $1 $4

	[ "$SKIP_PKTWS" = 1 ] || {
		echo
	        echo preparing $PKTWSD redirection
		mdig_resolve_all $IPV ips $4
		pktws_ipt_prepare_tcp $2 "$ips"

		pktws_check_domain_http_bypass $1 $3 $4

		echo clearing $PKTWSD redirection
		pktws_ipt_unprepare_tcp $2
	}
}
check_domain_http_udp()
{
	# $1 - test function
	# $2 - port
	# $3 - domain

	local ips

	# in case was interrupted before
	ws_kill

	check_domain_prolog $1 $2 $3 || return

	[ "$SKIP_PKTWS" = 1 ] || {
		echo
	        echo preparing $PKTWSD redirection
		mdig_resolve_all $IPV ips $3
		pktws_ipt_prepare_udp $2 "$ips"

		pktws_check_domain_http3_bypass $1 $3

		echo clearing $PKTWSD redirection
		pktws_ipt_unprepare_udp $2
	}
}


check_domain_http()
{
	# $1 - domain
	check_domain_http_tcp curl_test_http $HTTP_PORT 0 $1
}
check_domain_https_tls12()
{
	# $1 - domain
	check_domain_http_tcp curl_test_https_tls12 $HTTPS_PORT 1 $1
}
check_domain_https_tls13()
{
	# $1 - domain
	check_domain_http_tcp curl_test_https_tls13 $HTTPS_PORT 2 $1
}
check_domain_http3()
{
	# $1 - domain
	check_domain_http_udp curl_test_http3 $QUIC_PORT $1
}

configure_ip_version()
{
	if [ "$IPV" = 6 ]; then
		LOCALHOST=::1
		LOCALHOST_IPT=[${LOCALHOST}]
		IPVV=6
	else
		IPTABLES=iptables
		LOCALHOST=127.0.0.1
		LOCALHOST_IPT=$LOCALHOST
		IPVV=
	fi
	IPTABLES=ip${IPVV}tables
}
configure_curl_opt()
{
	# wolfssl : --tlsv1.x mandates exact ssl version, tls-max not supported
	# openssl : --tlsv1.x means "version equal or greater", tls-max supported
	TLSMAX12=
	TLSMAX13=
	curl_supports_tlsmax && {
		TLSMAX12="--tls-max 1.2"
		TLSMAX13="--tls-max 1.3"
	}
	TLS13=
	curl_supports_tls13 && TLS13=1
	HTTP3=
	curl_supports_http3 && HTTP3=1

	HTTPS_HEAD=-I
	[ "$CURL_HTTPS_GET" = 1 ] && HTTPS_HEAD=
}

linux_ipv6_defrag_can_be_disabled()
{
	linux_min_version 4 16
}

configure_defrag()
{
	IP6_DEFRAG_DISABLE=

	[ "$IPVS" = 4 ] && return

	[ "$UNAME" = "Linux" ] && {
		linux_ipv6_defrag_can_be_disabled || {
			echo "WARNING ! ipv6 defrag can only be effectively disabled in linux kernel 4.16+"
			echo "WARNING ! ipv6 ipfrag tests are disabled"
			echo
			return
		}
	}

	case "$FWTYPE" in
		iptables)
			if ipt6_has_raw ; then
				if ipt6_has_frag; then
					IP6_DEFRAG_DISABLE=1
				else
					echo "WARNING ! ip6tables does not have '-m frag' module, ipv6 ipfrag tests are disabled"
					echo
				fi
			else
				echo "WARNING ! ip6tables raw table is not available, ipv6 ipfrag tests are disabled"
				echo
			fi
			[ -n "$IP6_DEFRAG_DISABLE" ] && {
				local ipexe="$(readlink -f $(whichq ip6tables))"
				if contains "$ipexe" nft; then
					echo "WARNING ! ipv6 ipfrag tests may have no effect if ip6tables-nft is used. current ip6tables point to : $ipexe"
				else
					echo "WARNING ! ipv6 ipfrag tests may have no effect if ip6table_raw kernel module is not loaded with parameter : raw_before_defrag=1"
				fi
				echo
			}
			;;
		*)
			IP6_DEFRAG_DISABLE=1
			;;
	esac
}

ask_params()
{
	local d dirs more_dirs=

	echo
	echo NOTE ! this test should be run with zapret or any other bypass software disabled, without VPN
	echo

	curl_supports_connect_to || {
		echo "installed curl does not support --connect-to option. pls install at least curl 7.49"
		echo "current curl version:"
		"$CURL" --version
		exitp 1
	}

	[ -n "$TEST" ] || {
		dir_is_not_empty "$BLOCKCHECK2D" || {
			echo "directory '$BLOCKCHECK2D' is absent or empty"
			exitp 1
		}
		TEST="$TEST_DEFAULT"
		[ "$BATCH" = 1 ] || {
			for d in "$BLOCKCHECK2D"/* ; do
				more_dirs=${dirs:+1}
				[ -d "$d" ] && dirs="${dirs:+$dirs }$(basename "$d")"
			done
			[ -n "$dirs" ] || {
				echo "no subdirs found in '$BLOCKCHECK2D'"
				exitp 1
			}
			if [ -z "$more_dirs" ]; then
				TEST="$dirs"
			else
				echo "select test :"
				ask_list TEST "$dirs" "$TEST"
			fi
		}
	}
	[ -d "$BLOCKCHECK2D/$TEST" ] || {
		echo "directory '$BLOCKCHECK2D/$TEST' does not exist"
		exitp 1
	}

	local dom
	[ -n "$DOMAINS" ] || {
		DOMAINS="$DOMAINS_DEFAULT"
		[ "$BATCH" = 1 ] || {
			echo "specify domain(s) to test. multiple domains are space separated. URIs are supported (rutracker.org/forum/index.php)"
			printf "domain(s) (default: $DOMAINS) : "
			read dom
			[ -n "$dom" ] && DOMAINS="$dom"
		}
	}
	DOMAINS_COUNT="$(echo "$DOMAINS" | wc -w | trim)"

	local IPVS_def=4
	[ -n "$IPVS" ] || {
		# yandex public dns
		pingtest 6 2a02:6b8::feed:0ff && IPVS_def=46
		[ "$BATCH" = 1 ] || {
			printf "ip protocol version(s) - 4, 6 or 46 for both (default: $IPVS_def) : "
			read IPVS
		}
		[ -n "$IPVS" ] || IPVS=$IPVS_def
		[ "$IPVS" = 4 -o "$IPVS" = 6 -o "$IPVS" = 46 ] || {
			echo 'invalid ip version(s). should be 4, 6 or 46.'
			exitp 1
		}
	}
	[ "$IPVS" = 46 ] && IPVS="4 6"

	configure_curl_opt

	[ -n "$ENABLE_HTTP" ] || {
		ENABLE_HTTP=1
		[ "$BATCH" = 1 ] || {
			echo
			ask_yes_no_var ENABLE_HTTP "check http"
		}
	}

	[ -n "$ENABLE_HTTPS_TLS12" ] || {
		ENABLE_HTTPS_TLS12=1
		[ "$BATCH" = 1 ] || {
			echo
			ask_yes_no_var ENABLE_HTTPS_TLS12 "check https tls 1.2"
		}
	}

	[ -n "$ENABLE_HTTPS_TLS13" ] || {
		ENABLE_HTTPS_TLS13=0
		if [ -n "$TLS13" ]; then
			[ "$BATCH" = 1 ] || {
				echo
				echo "TLS 1.3 uses encrypted ServerHello. DPI cannot check domain name in server response."
				echo "This can allow more bypass strategies to work."
				echo "What works for TLS 1.2 will also work for TLS 1.3 but not vice versa."
				echo "Most sites nowadays support TLS 1.3 but not all. If you can't find a strategy for TLS 1.2 use this test."
				echo "TLS 1.3 only strategy is better than nothing."
				ask_yes_no_var ENABLE_HTTPS_TLS13 "check https tls 1.3"
			}
		fi
	}
	[ "$ENABLE_HTTPS_TLS13" = 1 -a -z "$TLS13" ] && {
			echo
			echo "WARNING ! installed curl version does not support TLS 1.3 . tests disabled."
			ENABLE_HTTPS_TLS13=0
	}

	[ -n "$ENABLE_HTTP3" ] || {
		ENABLE_HTTP3=0
		if [ -n "$HTTP3" ]; then
			ENABLE_HTTP3=1
			[ "$BATCH" = 1 ] || {
				echo
				echo "make sure target domain(s) support QUIC or result will be negative in any case"
				ask_yes_no_var ENABLE_HTTP3 "check http3 QUIC"
			}
		fi
	}
	[ "$ENABLE_HTTP3" = 1 -a -z "$HTTP3" ] && {
			echo
			echo "WARNING ! installed curl version does not support http3 QUIC. tests disabled."
			ENABLE_HTTP3=0
	}

	[ -n "$REPEATS" ] || {
		[ "$BATCH" = 1 ] || {
			echo
			echo "sometimes ISPs use multiple DPIs or load balancing. bypass strategies may work unstable."
			printf "how many times to repeat each test (default: 1) : "
			read REPEATS
		}
		REPEATS=$((0+${REPEATS:-1}))
		[ "$REPEATS" = 0 ] && {
			echo invalid repeat count
			exitp 1
		}
	}
	[ -z "$PARALLEL" -a $REPEATS -gt 1 ] && {
		PARALLEL=0
		[ "$BATCH" = 1 ] || {
			echo
			echo "parallel scan can greatly increase speed but may also trigger DDoS protection and cause false result"
			ask_yes_no_var PARALLEL "enable parallel scan"
		}
	}
	PARALLEL=${PARALLEL:-0}

	[ -n "$SCANLEVEL" ] || {
		SCANLEVEL=standard
		[ "$BATCH" = 1 ] || {
			echo
			echo quick    - in multi-attempt mode skip further attempts after first failure
			echo standard - do investigation what works on your DPI
			echo force    - scan maximum despite of result
			ask_list SCANLEVEL "quick standard force" "$SCANLEVEL"
		}
	}

	echo

	configure_defrag
}



ping_with_fix()
{
	local ret
	$PING $2 $1 >/dev/null 2>/dev/null
	ret=$?
	# can be because of unsupported -4 option
	if [ "$ret" = 2 -o "$ret" = 64 ]; then
		ping $2 $1 >/dev/null
	else
		return $ret
	fi
}

pingtest()
{
	# $1 - ip version : 4 or 6
	# $2 - domain or ip

	# ping command can vary a lot. some implementations have -4/-6 options. others don.t

	local PING=ping ret
	if [ "$1" = 6 ]; then
		if exists ping6; then
			PING=ping6
		else
			PING="ping -6"
		fi
	else
		if [ "$UNAME" = FreeBSD -o "$UNAME" = OpenBSD ]; then
			# ping by default pings ipv4, ping6 only pings ipv6
			# in FreeBSD -4/-6 options are supported, in others not
			PING=ping
		else
			# this can be linux or cygwin
			# in linux it's not possible for sure to figure out if it supports -4/-6. only try and check for result code=2 (invalid option)
			PING="ping -4"
		fi
	fi
	case "$UNAME" in
		OpenBSD)
			$PING -c 1 -w 1 $2 >/dev/null
			;;
		CYGWIN)
			if starts_with "$(which ping)" /cygdrive; then
				# cygwin does not have own ping by default. use windows PING.
				$PING -n 1 -w 1000 $2 >/dev/null
			else
				ping_with_fix $2 '-c 1 -w 1'
			fi
			;;
		*)
			ping_with_fix $2 '-c 1 -W 1'
			;;
	esac
}
dnstest()
{
	# $1 - dns server. empty for system resolver
	"$LOOKUP" iana.org $1 >/dev/null 2>/dev/null
}
find_working_public_dns()
{
	local dns
	for dns in $DNSCHECK_DNS; do
		pingtest 4 $dns && dnstest $dns && {
			PUBDNS=$dns
			return 0
		}
	done
	return 1
}
lookup4()
{
	# $1 - domain
	# $2 - DNS
	case "$LOOKUP" in
		nslookup)
			if is_linked_to_busybox nslookup; then
				nslookup $1 $2 2>/dev/null | sed -e '1,3d' -nre 's/^.*:[^0-9]*(([0-9]{1,3}\.){3}[0-9]{1,3}).*$/\1/p'
			else
				nslookup $1 $2 2>/dev/null | sed -e '1,3d' -nre 's/^[^0-9]*(([0-9]{1,3}\.){3}[0-9]{1,3}).*$/\1/p'
			fi
			;;
		host)
			host -t A $1 $2 | grep "has address" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}'
			;;
	esac
}
check_dns_spoof()
{
	# $1 - domain
	# $2 - public DNS

	# windows version of mdig outputs 0D0A line ending. remove 0D.
	echo $1 | "$MDIG" --family=4 | tr -d '\r' >"$DNSCHECK_DIG1"
	lookup4 $1 $2 >"$DNSCHECK_DIG2"
	# check whether system resolver returns anything other than public DNS
	grep -qvFf "$DNSCHECK_DIG2" "$DNSCHECK_DIG1"
}
check_dns_cleanup()
{
	rm -f "$DNSCHECK_DIG1" "$DNSCHECK_DIG2" "$DNSCHECK_DIGS" 2>/dev/null
}
check_dns_()
{
	local C1 C2 dom

	DNS_IS_SPOOFED=0

	[ "$SKIP_DNSCHECK" = 1 ] && return 0

	echo \* checking DNS

	[ -f "$DNSCHECK_DIGS" ] && rm -f "$DNSCHECK_DIGS"

	dnstest || {
		echo -- DNS is not working. It's either misconfigured or blocked or you don't have inet access.
		return 1
	}
	echo system DNS is working

	if find_working_public_dns ; then
		echo comparing system resolver to public DNS : $PUBDNS
		for dom in $DNSCHECK_DOM; do
			if check_dns_spoof $dom $PUBDNS ; then
				echo $dom : MISMATCH
				echo -- system resolver :
				cat "$DNSCHECK_DIG1"
				echo -- $PUBDNS :
				cat "$DNSCHECK_DIG2"
				check_dns_cleanup
				echo -- POSSIBLE DNS HIJACK DETECTED. ZAPRET WILL NOT HELP YOU IN CASE DNS IS SPOOFED !!!
				echo -- DNS CHANGE OR DNSCRYPT MAY BE REQUIRED
				DNS_IS_SPOOFED=1
				return 1
			else
				echo $dom : OK
				cat "$DNSCHECK_DIG1" >>"$DNSCHECK_DIGS"
			fi
		done
	else
		echo no working public DNS was found. looks like public DNS blocked.
		for dom in $DNSCHECK_DOM; do echo $dom; done | "$MDIG" --threads=10 --family=4 >"$DNSCHECK_DIGS"
	fi

	echo "checking resolved IP uniqueness for : $DNSCHECK_DOM"
	echo "censor's DNS can return equal result for multiple blocked domains."
	C1=$(wc -l <"$DNSCHECK_DIGS")
	C2=$(sort -u "$DNSCHECK_DIGS" | wc -l)
	[ "$C1" -eq 0 ] &&
	{
		echo -- DNS is not working. It's either misconfigured or blocked or you don't have inet access.
		check_dns_cleanup
		return 1
	}
	[ "$C1" = "$C2" ] ||
	{
		echo system dns resolver has returned equal IPs for some domains checked above \($C1 total, $C2 unique\)
		echo non-unique IPs :
		sort "$DNSCHECK_DIGS" | uniq -d
		echo -- POSSIBLE DNS HIJACK DETECTED. ZAPRET WILL NOT HELP YOU IN CASE DNS IS SPOOFED !!!
		echo -- DNSCRYPT MAY BE REQUIRED
		check_dns_cleanup
		DNS_IS_SPOOFED=1
		return 1
	}
	echo all resolved IPs are unique
	echo -- DNS looks good
	echo -- NOTE this check is Russia targeted. In your country other domains may be blocked.
	check_dns_cleanup
	return 0
}

check_dns()
{
	local r
	check_dns_
	r=$?
	[ "$DNS_IS_SPOOFED" = 1 ] && SECURE_DNS=${SECURE_DNS:-1}
	[ "$SECURE_DNS" = 1 ] && {
		doh_find_working || {
			echo could not find working DoH server. exiting.
			exitp 7
		}
	}
	return $r
}

block_signals()
{
	# prevent signal function reenter
	trap '' QUIT TERM HUP PIPE INT
}
untrap()
{
	trap - QUIT TERM HUP PIPE INT
}

unprepare_all()
{
	# make sure we are not in a middle state that impacts connectivity
	ws_kill
	wait
	[ -n "$IPV" ] && {
		pktws_ipt_unprepare_tcp $HTTP_PORT
		pktws_ipt_unprepare_tcp $HTTPS_PORT
		pktws_ipt_unprepare_udp $QUIC_PORT
	}
	cleanup
	rm -f "${HDRTEMP}"* "${PARALLEL_OUT}"*
}
sigint()
{
	block_signals
	echo
	echo terminating...
	unprepare_all
	# exitp can wait for the user input. restore default signal behavior without trap
	untrap
	exitp 1
}
sigint_cleanup()
{
	block_signals
	cleanup
	exit 1
}
sigsilent()
{
	block_signals
	# must not write anything here to stdout
	unprepare_all
	exit 1
}

fsleep_setup
fix_sbin_path
check_system
check_already
[ "$UNAME" != CYGWIN  -a "$SKIP_PKTWS" != 1 ] && require_root
check_prerequisites
trap sigint_cleanup INT
check_dns
check_virt
ask_params
apply_header_padfile
trap - INT

PID=
NREPORT=
unset WF
trap sigint INT
trap sigsilent PIPE HUP TERM QUIT
for dom in $DOMAINS; do
	for IPV in $IPVS; do
		configure_ip_version
		[ "$ENABLE_HTTP" = 1 ] && {
			[ "$SKIP_IPBLOCK" = 1 ] || check_domain_port_block $dom $HTTP_PORT
			check_domain_http $dom
		}
		[ "$ENABLE_HTTPS_TLS12" = 1 -o "$ENABLE_HTTPS_TLS13" = 1 ] && [ "$SKIP_IPBLOCK" != 1 ] && check_domain_port_block $dom $HTTPS_PORT
		[ "$ENABLE_HTTPS_TLS12" = 1 ] && check_domain_https_tls12 $dom
		[ "$ENABLE_HTTPS_TLS13" = 1 ] && check_domain_https_tls13 $dom
		[ "$ENABLE_HTTP3" = 1 ] && check_domain_http3 $dom
	done
done
untrap

cleanup

echo
echo \* SUMMARY
report_print
[ "$DOMAINS_COUNT" -gt 1 ] && {
	echo
	echo \* COMMON
	result_intersection_print
	echo
	echo \* COVERAGE
	result_coverage_print
	echo
	[ "$SCANLEVEL" = force ] || {
		echo "blockcheck optimizes test sequence. To save time some strategies can be skipped if their test is considered useless."
		echo "That's why COMMON intersection can miss strategies that would work for all domains, and COVERAGE counts can undercount."
		echo "Use \"force\" scan level to test all strategies and generate trustable results."
		echo "Current scan level was \"$SCANLEVEL\"".
	}
}
echo
echo "Please note this SUMMARY does not guarantee a magic pill for you to copy/paste and be happy."
echo "Understanding how strategies work is very desirable."
echo "This knowledge allows to understand better which strategies to prefer and which to avoid if possible, how to combine strategies."
echo "Blockcheck does it's best to prioritize good strategies but it's not bullet-proof."
echo "It was designed not as magic pill maker but as a DPI bypass test tool."

exitp 0
