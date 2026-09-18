#!/bin/sh

# Auto-strategy selector for zapret2
# This script tests multiple domains and finds individual strategies for each
# Domains that work with basic strategy are skipped from deep scanning

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

# Global variables for auto-mode
AUTO_MODE=0
DOMAIN_STRATEGIES_FILE=""
BASIC_STRATEGY_WORKING_DOMAINS=""
ADVANCED_SCAN_NEEDED_DOMAINS=""

apply_header_padfile()
{
	local n=1 left size
	if [ "$CURL_PAD" -gt 0 ] 2>/dev/null; then
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
			[ "$left" -lt 14 ] && size=$(($size+$left))

			printf 'X-Pad-%04d: ' $n >> "$CURL_PAD_FILE"
			head -c $size /dev/zero | tr '\0' A >> "$CURL_PAD_FILE"
			echo >> "$CURL_PAD_FILE"
			n=$(($n+1))
		done
		CURL_OPT="${CURL_OPT}${CURL_OPT:+ }-H @$CURL_PAD_FILE"
	fi
}

killwait()
{
	local KILL=kill
	[ "$UNAME" = "CYGWIN" ] && KILL=/bin/kill
	$KILL $1 $2
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
	hostvar=$(echo $2 | sed -e 's/[\.\/?&#@%*$^:~=!()+-]/_/g' | tr 'A-Z' 'a-z')
	cachevar=DNSCACHE_${hostvar}_$1
	countvar=${cachevar}_COUNT
	eval count=\$${countvar}
}
mdig_cache()
{
	local hostvar cachevar countvar count ip ips
	mdig_vars "$@"
	[ -n "$count" ] || {
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
	kldstat -qm "${1}"
}
freebsd_modules_loaded()
{
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
	[ $? = 2 ] && return 1
	"$CURL" --tlsv1.3 --max-time 1 -Is -o /dev/null https://iana.org 2>/dev/null
	r=$?
	[ $r != 4 -a $r != 35 ]
}

curl_supports_tlsmax()
{
	"$CURL" --version | grep -Fq -e OpenSSL -e LibreSSL -e BoringSSL -e GnuTLS -e quictls || return 1
	"$CURL" --tls-max 1.2 -Is -o /dev/null --max-time 1 http://127.0.0.1:65535 2>/dev/null
	[ $? != 2 ]
}

curl_supports_connect_to()
{
	"$CURL" --connect-to 127.0.0.1:: -o /dev/null --max-time 1 http://127.0.0.1:65535 2>/dev/null
	[ "$?" != 2 ]
}

curl_supports_http3()
{
	"$CURL" --connect-to 127.0.0.1:: -o /dev/null --max-time 1 --http3-only http://127.0.0.1:65535 2>/dev/null
	[ "$?" != 2 ]
}

hdrfile_http_code()
{
	sed -nre '1,1 s/^HTTP\/1\.[0,1] ([0-9]+) .*$/\1/p' "$1"
}
hdrfile_location()
{
	grep -i '^location:' "$1" | sed -re 's/^[Ll]ocation:[[:space:]]*//'
}

curl_test()
{
	local dom=$2 ip=$3 detail=$4 url proto port_arg ipver_str
	local ip_arg="--connect-to $2::"
	
	[ -n "$ip" ] && ip_arg="--connect-to $2::$ip"
	
	case "$1" in
		curl_test_http)
			proto=http
			url="$proto://$2/"
			;;
		curl_test_https_tls12)
			proto=https
			url="$proto://$2/"
			;;
		curl_test_https_tls13)
			proto=https
			url="$proto://$2/"
			;;
		curl_test_http3)
			proto=https
			url="$proto://$2/"
			;;
	esac
	
	[ "$detail" = "detail" ] && echo "testing $url on IP: ${ip:-default}"
	
	$CURL -s -S -I --max-time $CURL_MAX_TIME $CURL_OPT $ip_arg $url 2>&1 | tee $HDRTEMP | head -1 | grep -qiE 'HTTP/[0-9]' 
}

check_domain_port_block()
{
	local dom=$1 port=$2 ip ips
	
	echo
	echo "* testing if $dom:$port is blocked by IP"
	
	mdig_resolve_all $IPV ips $dom
	for ip in $ips; do
		echo "testing $dom ($ip):$port"
		netcat_test $ip $port
	done
}

curl_test_http()
{
	curl_test curl_test_http "$@"
}
curl_test_https_tls12()
{
	curl_test curl_test_https_tls12 "$@"
}
curl_test_https_tls13()
{
	curl_test curl_test_https_tls13 "$@"
}
curl_test_http3()
{
	curl_test curl_test_http3 "$@"
}

pktws_start()
{
	local extra_params="$@"
	
	echo starting $PKTWSD $extra_params
	$PKTWS $extra_params &
	PID=$!
	sleep 1
}

ws_kill()
{
	[ -n "$PID" ] && killwait -15 $PID
	PID=
}

pktws_ipt_prepare_tcp()
{
	local port=$1 ips=$2
	
	case "$FWTYPE" in
		iptables)
			$IPTABLES -N $IPT_OUT_CHAIN 2>/dev/null
			$IPTABLES -N $IPT_IN_CHAIN 2>/dev/null
			$IPTABLES -I OUTPUT -o lo -j RETURN
			$IPTABLES -I $IPT_OUT_CHAIN -p tcp -m multiport --dports $port -j NFQUEUE --queue-num $QNUM $IPT_COMMENT
			$IPTABLES -I OUTPUT -j $IPT_OUT_CHAIN
			$IPTABLES -I $IPT_IN_CHAIN -p tcp -m multiport --sports $port -j NFQUEUE --queue-num $QNUM $IPT_COMMENT
			$IPTABLES -I INPUT -j $IPT_IN_CHAIN
			;;
		nftables)
			nft add table $NFT_TABLE
			nft add chain $NFT_TABLE output { type filter hook output priority 0 \; }
			nft add chain $NFT_TABLE input { type filter hook input priority 0 \; }
			nft add rule $NFT_TABLE output meta lo devtype loopback return
			nft add rule $NFT_TABLE output tcp dport $port queue num $QNUM
			nft add rule $NFT_TABLE input tcp sport $port queue num $QNUM
			;;
		ipfw)
			opf_prepare_dvtws tcp $port "$ips"
			;;
		opf)
			opf_prepare_dvtws tcp $port "$ips"
			;;
	esac
}

pktws_ipt_unprepare_tcp()
{
	local port=$1
	
	case "$FWTYPE" in
		iptables)
			$IPTABLES -D INPUT -j $IPT_IN_CHAIN 2>/dev/null
			$IPTABLES -F $IPT_IN_CHAIN 2>/dev/null
			$IPTABLES -X $IPT_IN_CHAIN 2>/dev/null
			$IPTABLES -D OUTPUT -j $IPT_OUT_CHAIN 2>/dev/null
			$IPTABLES -F $IPT_OUT_CHAIN 2>/dev/null
			$IPTABLES -X $IPT_OUT_CHAIN 2>/dev/null
			$IPTABLES -D OUTPUT -o lo -j RETURN 2>/dev/null
			;;
		nftables)
			nft delete table $NFT_TABLE 2>/dev/null
			;;
		ipfw)
			pf_restore
			;;
		opf)
			pf_restore
			;;
	esac
}

pktws_ipt_prepare_udp()
{
	local port=$1 ips=$2
	
	case "$FWTYPE" in
		iptables)
			$IPTABLES -N $IPT_OUT_CHAIN 2>/dev/null
			$IPTABLES -I OUTPUT -o lo -j RETURN
			$IPTABLES -I $IPT_OUT_CHAIN -p udp -m multiport --dports $port -j NFQUEUE --queue-num $QNUM $IPT_COMMENT
			$IPTABLES -I OUTPUT -j $IPT_OUT_CHAIN
			;;
		nftables)
			nft add table $NFT_TABLE
			nft add chain $NFT_TABLE output { type filter hook output priority 0 \; }
			nft add rule $NFT_TABLE output meta lo devtype loopback return
			nft add rule $NFT_TABLE output udp dport $port queue num $QNUM
			;;
		ipfw)
			opf_prepare_dvtws udp $port "$ips"
			;;
		opf)
			opf_prepare_dvtws udp $port "$ips"
			;;
	esac
}

pktws_ipt_unprepare_udp()
{
	local port=$1
	
	case "$FWTYPE" in
		iptables)
			$IPTABLES -D OUTPUT -j $IPT_OUT_CHAIN 2>/dev/null
			$IPTABLES -F $IPT_OUT_CHAIN 2>/dev/null
			$IPTABLES -X $IPT_OUT_CHAIN 2>/dev/null
			$IPTABLES -D OUTPUT -o lo -j RETURN 2>/dev/null
			;;
		nftables)
			nft delete table $NFT_TABLE 2>/dev/null
			;;
		ipfw)
			pf_restore
			;;
		opf)
			pf_restore
			;;
	esac
}

strategy_append_extra_pktws()
{
	strategy="${strategy:+${PKTWS_EXTRA_PRE:+$PKTWS_EXTRA_PRE }${PKTWS_EXTRA_PRE_1:+\"$PKTWS_EXTRA_PRE_1\" }${PKTWS_EXTRA_PRE_2:+\"$PKTWS_EXTRA_PRE_2\" }${PKTWS_EXTRA_PRE_3:+\"$PKTWS_EXTRA_PRE_3\" }${PKTWS_EXTRA_PRE_4:+\"$PKTWS_EXTRA_PRE_4\" }${PKTWS_EXTRA_PRE_5:+\"$PKTWS_EXTRA_PRE_5\" }${PKTWS_EXTRA_PRE_6:+\"$PKTWS_EXTRA_PRE_6\" }${PKTWS_EXTRA_PRE_7:+\"$PKTWS_EXTRA_PRE_7\" }${PKTWS_EXTRA_PRE_8:+\"$PKTWS_EXTRA_PRE_8\" }${PKTWS_EXTRA_PRE_9:+\"$PKTWS_EXTRA_PRE_9\" }$strategy${PKTWS_EXTRA_POST:+ $PKTWS_EXTRA_POST}${PKTWS_EXTRA_POST_1:+ \"$PKTWS_EXTRA_POST_1\"}${PKTWS_EXTRA_POST_2:+ \"$PKTWS_EXTRA_POST_2\"}${PKTWS_EXTRA_POST_3:+ \"$PKTWS_EXTRA_POST_3\"}${PKTWS_EXTRA_POST_4:+ \"$PKTWS_EXTRA_POST_4\"}${PKTWS_EXTRA_POST_5:+ \"$PKTWS_EXTRA_POST_5\"}${PKTWS_EXTRA_POST_6:+ \"$PKTWS_EXTRA_POST_6\"}${PKTWS_EXTRA_POST_7:+ \"$PKTWS_EXTRA_POST_7\"}${PKTWS_EXTRA_POST_8:+ \"$PKTWS_EXTRA_POST_8\"}${PKTWS_EXTRA_POST_9:+ \"$PKTWS_EXTRA_POST_9\"}}"
}

xxxws_curl_test_update()
{
	local testf=$1 dom="$2" strategy code
	shift 2
	
	ws_kill
	pktws_start "$@"
	code=1
	if $testf $dom; then
		code=0
		strategy="$@"
		strategy_append_extra_pktws
		report_append "$dom" "$testf ipv${IPV}" "$PKTWSD ${WF:+$WF }$strategy"
	fi
	[ $code = 0 ] && strategy="${strategy:-$@}"
	ws_kill
	return $code
}

pktws_curl_test_update()
{
	xxxws_curl_test_update pktws_curl_test "$@"
}

report_append()
{
	local hashstr hash hashvar hashcountvar val ct

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
			eval RES_$NRESHASH=\"\$hash\"
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
	echo
	if [ -n "$strategy" ]; then
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
	local strategy
	test_runner pktws_check_http3 "$@"
	strategy_append_extra_pktws
	report_strategy $1 $2 $PKTWSD
}

check_dpi_ip_block()
{
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
	for c in 1 2 3 4 6 27 ; do
		[ $1 = $c ] && return 1
	done
	return 0
}

check_domain_prolog()
{
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
	local ips

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
	local ips

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
	check_domain_http_tcp curl_test_http $HTTP_PORT 0 $1
}
check_domain_https_tls12()
{
	check_domain_http_tcp curl_test_https_tls12 $HTTPS_PORT 1 $1
}
check_domain_https_tls13()
{
	check_domain_http_tcp curl_test_https_tls13 $HTTPS_PORT 2 $1
}
check_domain_http3()
{
	check_domain_http_udp curl_test_http3 $QUIC_PORT $1
}

configure_ip_version()
{
	[ "$IPV" = 6 ] && IPV=6 || IPV=4
}

configure_curl_opt()
{
	CURL_OPT=""
	curl_supports_tls13 && CURL_OPT="--tlsv1.3"
	curl_supports_tlsmax && CURL_OPT="$CURL_OPT --tls-max 1.3"
}

configure_defrag()
{
	IPV4_DEFRAG_DISABLE=0
	IPV6_DEFRAG_DISABLE=0
	
	case "$UNAME" in
		Linux)
			[ "$(cat /proc/sys/net/ipv4/ipfrag_time 2>/dev/null)" = 30 ] || IPV4_DEFRAG_DISABLE=1
			[ "$(cat /proc/sys/net/ipv6/conf/all/frag_timeout 2>/dev/null)" = 60 ] || IPV6_DEFRAG_DISABLE=1
			;;
		FreeBSD)
			[ "$(sysctl -qn net.inet.ip.fragpackets 2>/dev/null)" = 0 ] || IPV4_DEFRAG_DISABLE=1
			[ "$(sysctl -qn net.inet6.ip6.fragpackets 2>/dev/null)" = 0 ] || IPV6_DEFRAG_DISABLE=1
			;;
		OpenBSD)
			IPV6_DEFRAG_DISABLE=1
			;;
		*)
			IPV6_DEFRAG_DISABLE=1
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
				echo "Most sites nowadays support TLS 1.3 but not all. If you can't find a strategy for TLS 1.2 use this test."
				echo "TLS 1.3 only strategy is better than nothing."
				ask_yes_no_var ENABLE_HTTPS_TLS13 "check https tls 1.3 only"
			}
		fi
	}

	[ -n "$ENABLE_HTTP3" ] || {
		ENABLE_HTTP3=0
		if curl_supports_http3; then
			[ "$BATCH" = 1 ] || {
				echo
				echo "HTTP/3 (QUIC) uses UDP. It's a different protocol from TCP-based HTTP/1.1 and HTTP/2."
				echo "If you want to test HTTP/3 bypass strategies enable this."
				ask_yes_no_var ENABLE_HTTP3 "check http3 (QUIC)"
			}
		else
			echo "your curl does not support HTTP/3 (QUIC). skipping http3 tests."
		fi
	}

	[ -n "$SKIP_IPBLOCK" ] || {
		SKIP_IPBLOCK=0
		[ "$BATCH" = 1 ] || {
			echo
			echo "IP block test checks if DPI blocks based on IP addresses rather than hostnames."
			echo "This test requires manual interpretation of results."
			ask_yes_no_var SKIP_IPBLOCK "skip IP block test"
		}
	}

	[ -n "$SKIP_PKTWS" ] || {
		SKIP_PKTWS=0
		[ "$BATCH" = 1 ] || {
			echo
			echo "Packet workspace test ($PKTWSD) is the main part of blockcheck."
			echo "It tries various DPI bypass strategies."
			ask_yes_no_var SKIP_PKTWS "skip $PKTWSD tests"
		}
	}

	[ -n "$SIMULATE" ] || {
		SIMULATE=0
		[ "$BATCH" = 1 ] || {
			echo
			echo "Simulation mode skips actual tests and just prints what would be tested."
			ask_yes_no_var SIMULATE "enable simulation mode"
		}
	}

	[ -n "$PARALLEL" ] || {
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
	if [ "$ret" = 2 -o "$ret" = 64 ]; then
		ping $2 $1 >/dev/null
	else
		return $ret
	fi
}

pingtest()
{
	local PING=ping ret
	if [ "$1" = 6 ]; then
		if exists ping6; then
			PING=ping6
		else
			PING="ping -6"
		fi
	else
		if [ "$UNAME" = FreeBSD -o "$UNAME" = OpenBSD ]; then
			PING=ping
		else
			PING="ping -4"
		fi
	fi
	case "$UNAME" in
		OpenBSD)
			$PING -c 1 -w 1 $2 >/dev/null
			;;
		CYGWIN)
			if starts_with "$(which ping)" /cygdrive; then
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
	case "$LOOKUP" in
		nslookup)
			nslookup $1 $2 2>/dev/null | sed -nre '/^Name:/,/^[^ ]/ { s/^Address:[[:space:]]+//p }'
			;;
		host)
			host -t A $1 $2 2>/dev/null | sed -nre 's/.*[[:space:]]has[[:space:]]address[[:space:]]//p'
			;;
	esac
}
lookup6()
{
	case "$LOOKUP" in
		nslookup)
			nslookup -query=aaaa $1 $2 2>/dev/null | sed -nre '/^Name:/,/^[^ ]/ { s/^Address:[[:space:]]+//p }'
			;;
		host)
			host -t AAAA $1 $2 2>/dev/null | sed -nre 's/.*[[:space:]]has[[:space:]]IPv6[[:space:]]address[[:space:]]//p'
			;;
	esac
}

check_dns_spoof()
{
	local dom dns1 dns2 ip1 ip2

	echo
	echo "* DNS spoofing test"
	
	for dom in $DNSCHECK_DOM; do
		dns1=$(echo $DNSCHECK_DNS | awk '{print $1}')
		dns2=$(echo $DNSCHECK_DNS | awk '{print $2}')
		
		[ -n "$dns1" -a -n "$dns2" ] || continue
		
		ip1=$(lookup4 $dom $dns1 | head -1)
		ip2=$(lookup4 $dom $dns2 | head -1)
		
		[ -n "$ip1" -a -n "$ip2" ] || continue
		
		if [ "$ip1" != "$ip2" ]; then
			echo "$dom : DNS returns different IPs ($dns1->$ip1, $dns2->$ip2)"
		fi
	done
}

check_dns_cleanup()
{
	echo
	echo "* DNS cleanup test - not implemented"
}

check_dns_()
{
	check_dns_spoof
	check_dns_cleanup
}

check_dns()
{
	echo \* checking DNS
	
	find_working_public_dns && PUBDNS_USED=$PUBDNS || PUBDNS_USED=""
	
	[ -n "$PUBDNS_USED" ] && {
		echo "using public DNS: $PUBDNS_USED"
		export DNSCHECK_DNS="$PUBDNS_USED"
	}
	
	check_dns_
}

block_signals()
{
	trap '' INT PIPE HUP TERM QUIT
}

untrap()
{
	trap - INT PIPE HUP TERM QUIT
}

unprepare_all()
{
	ws_kill
	pktws_ipt_unprepare_tcp $HTTP_PORT 2>/dev/null
	pktws_ipt_unprepare_tcp $HTTPS_PORT 2>/dev/null
	pktws_ipt_unprepare_udp $QUIC_PORT 2>/dev/null
}

sigint()
{
	echo
	echo "SIGINT received"
	sigint_cleanup
	exitp 130
}

sigint_cleanup()
{
	block_signals
	unprepare_all
	cleanup
}

sigsilent()
{
	trap '' $1
}

# ============================================================================
# AUTO-MODE FUNCTIONS: Individual strategy selection per domain
# ============================================================================

# Save strategy for a specific domain
save_domain_strategy()
{
	# $1 - domain
	# $2 - protocol (http/https-tls12/https-tls13/http3)
	# $3 - strategy string
	local domain=$1 proto=$2 strategy=$3
	local strategy_file="$DOMAIN_STRATEGIES_FILE"
	
	echo "$domain|$proto|$strategy" >> "$strategy_file"
	echo "Saved strategy for $domain ($proto): $strategy"
}

# Load strategy for a specific domain
load_domain_strategy()
{
	# $1 - domain
	# $2 - protocol
	local domain=$1 proto=$2
	local strategy_file="$DOMAIN_STRATEGIES_FILE"
	
	[ -f "$strategy_file" ] || return 1
	
	grep "^${domain}|${proto}|" "$strategy_file" | tail -1 | cut -d'|' -f3
}

# Test basic strategy quickly for a domain
test_basic_strategy_quick()
{
	# $1 - test function
	# $2 - domain
	local test_func=$1 domain=$2
	local basic_strategy="--lua-desync=http_hostcase"
	
	echo "Testing basic strategy for $domain..."
	
	ws_kill
	pktws_start $basic_strategy
	
	if $test_func $domain; then
		ws_kill
		return 0
	else
		ws_kill
		return 1
	fi
}

# Full strategy scan for a single domain
scan_domain_strategies()
{
	# $1 - test function  
	# $2 - encrypted flag (0/1/2)
	# $3 - domain
	local test_func=$1 enc_flag=$2 domain=$3
	
	echo
	echo "=========================================="
	echo "Advanced strategy scan for: $domain"
	echo "=========================================="
	
	# Run full blockcheck for this domain only
	local saved_domains="$DOMAINS"
	DOMAINS="$domain"
	DOMAINS_COUNT=1
	
	# Reset reports for clean domain-specific output
	NREPORT=0
	NRESHASH=0
	unset strategy
	
	check_domain_http_tcp $test_func $enc_flag 0 $domain
	
	DOMAINS="$saved_domains"
	DOMAINS_COUNT=$(echo "$DOMAINS" | wc -w | trim)
}

# Main auto-mode: test all domains with basic, then advanced for failures
run_auto_mode()
{
	local dom proto test_func enc_flag
	
	echo
	echo "============================================"
	echo "AUTO MODE: Individual strategy per domain"
	echo "============================================"
	echo
	
	DOMAIN_STRATEGIES_FILE="/tmp/zapret_domain_strategies_$$.txt"
	rm -f "$DOMAIN_STRATEGIES_FILE"
	
	BASIC_STRATEGY_WORKING_DOMAINS=""
	ADVANCED_SCAN_NEEDED_DOMAINS=""
	
	# Phase 1: Quick test with basic strategy for all domains
	echo "PHASE 1: Testing basic strategy for all domains..."
	echo
	
	for dom in $DOMAINS; do
		for IPV in $IPVS; do
			configure_ip_version
			
			if [ "$ENABLE_HTTP" = 1 ]; then
				test_func=curl_test_http
				if test_basic_strategy_quick $test_func $dom; then
					echo "✓ $dom (HTTP/IPv${IPV}): Works with basic strategy"
					save_domain_strategy "$dom" "http" "--lua-desync=http_hostcase"
					BASIC_STRATEGY_WORKING_DOMAINS="$BASIC_STRATEGY_WORKING_DOMAINS $dom"
				else
					echo "✗ $dom (HTTP/IPv${IPV}): Basic strategy FAILED - needs advanced scan"
					ADVANCED_SCAN_NEEDED_DOMAINS="$ADVANCED_SCAN_NEEDED_DOMAINS $dom"
				fi
			fi
			
			if [ "$ENABLE_HTTPS_TLS12" = 1 ]; then
				test_func=curl_test_https_tls12
				if test_basic_strategy_quick $test_func $dom; then
					echo "✓ $dom (HTTPS-TLS1.2/IPv${IPV}): Works with basic strategy"
					save_domain_strategy "$dom" "https-tls12" "--lua-desync=http_hostcase"
					BASIC_STRATEGY_WORKING_DOMAINS="$BASIC_STRATEGY_WORKING_DOMAINS $dom"
				else
					echo "✗ $dom (HTTPS-TLS1.2/IPv${IPV}): Basic strategy FAILED - needs advanced scan"
					ADVANCED_SCAN_NEEDED_DOMAINS="$ADVANCED_SCAN_NEEDED_DOMAINS $dom"
				fi
			fi
			
			if [ "$ENABLE_HTTPS_TLS13" = 1 ]; then
				test_func=curl_test_https_tls13
				if test_basic_strategy_quick $test_func $dom; then
					echo "✓ $dom (HTTPS-TLS1.3/IPv${IPV}): Works with basic strategy"
					save_domain_strategy "$dom" "https-tls13" "--lua-desync=http_hostcase"
					BASIC_STRATEGY_WORKING_DOMAINS="$BASIC_STRATEGY_WORKING_DOMAINS $dom"
				else
					echo "✗ $dom (HTTPS-TLS1.3/IPv${IPV}): Basic strategy FAILED - needs advanced scan"
					ADVANCED_SCAN_NEEDED_DOMAINS="$ADVANCED_SCAN_NEEDED_DOMAINS $dom"
				fi
			fi
			
			if [ "$ENABLE_HTTP3" = 1 ]; then
				test_func=curl_test_http3
				if test_basic_strategy_quick $test_func $dom; then
					echo "✓ $dom (HTTP3/IPv${IPV}): Works with basic strategy"
					save_domain_strategy "$dom" "http3" "--lua-desync=http_hostcase"
					BASIC_STRATEGY_WORKING_DOMAINS="$BASIC_STRATEGY_WORKING_DOMAINS $dom"
				else
					echo "✗ $dom (HTTP3/IPv${IPV}): Basic strategy FAILED - needs advanced scan"
					ADVANCED_SCAN_NEEDED_DOMAINS="$ADVANCED_SCAN_NEEDED_DOMAINS $dom"
				fi
			fi
		done
	done
	
	# Phase 2: Advanced scan only for domains that failed basic test
	echo
	echo "PHASE 2: Advanced strategy scan for failed domains..."
	echo "Domains needing advanced scan:$ADVANCED_SCAN_NEEDED_DOMAINS"
	echo
	
	if [ -n "$(echo $ADVANCED_SCAN_NEEDED_DOMAINS | tr -d ' ')" ]; then
		for dom in $ADVANCED_SCAN_NEEDED_DOMAINS; do
			for IPV in $IPVS; do
				configure_ip_version
				
				[ "$ENABLE_HTTP" = 1 ] && scan_domain_strategies curl_test_http 0 "$dom"
				[ "$ENABLE_HTTPS_TLS12" = 1 ] && scan_domain_strategies curl_test_https_tls12 1 "$dom"
				[ "$ENABLE_HTTPS_TLS13" = 1 ] && scan_domain_strategies curl_test_https_tls13 2 "$dom"
				[ "$ENABLE_HTTP3" = 1 ] && scan_domain_strategies curl_test_http3 0 "$dom"
			done
		done
	else
		echo "All domains work with basic strategy! No advanced scan needed."
	fi
	
	# Phase 3: Print summary
	echo
	echo "============================================"
	echo "FINAL SUMMARY: Per-Domain Strategies"
	echo "============================================"
	echo
	
	if [ -f "$DOMAIN_STRATEGIES_FILE" ]; then
		echo "Domain strategies saved to: $DOMAIN_STRATEGIES_FILE"
		echo
		echo "Strategies found:"
		echo "----------------"
		cat "$DOMAIN_STRATEGIES_FILE" | while IFS='|' read -r domain proto strategy; do
			echo "Domain: $domain | Protocol: $proto | Strategy: $strategy"
		done
		echo
		echo "Domains working with basic strategy:$BASIC_STRATEGY_WORKING_DOMAINS"
		echo "Domains requiring custom strategies:$ADVANCED_SCAN_NEEDED_DOMAINS"
	else
		echo "No strategies were saved."
	fi
	
	echo
	echo "To use these strategies, parse the file and configure zapret accordingly."
}

# Main execution
check_system
check_already
check_prerequisites
check_dns

AUTO_MODE=1
ask_params

if [ "$AUTO_MODE" = 1 ]; then
	run_auto_mode
else
	# Original behavior
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
fi
