[ -n "$ZAPRET_NFT_TABLE" ] || ZAPRET_NFT_TABLE=zapret2
nft_connbytes="ct original packets"

# required for : nft -f -
create_dev_stdin

nft_create_table()
{
	nft add table inet $ZAPRET_NFT_TABLE
}
nft_del_table()
{
	nft delete table inet $ZAPRET_NFT_TABLE 2>/dev/null
}
nft_list_table()
{
	nft -t list table inet $ZAPRET_NFT_TABLE
}

nft_add_chain()
{
	# $1 - chain
	# $2 - params
	nft add chain inet $ZAPRET_NFT_TABLE $1 "{ $2 }"
}
nft_del_chain()
{
	# $1 - chain
	nft delete chain inet $ZAPRET_NFT_TABLE $1
}

nft_create_set()
{
	# $1 - set name
	# $2 - params
	nft create set inet $ZAPRET_NFT_TABLE $1 "{ $2 }" 2>/dev/null
}
nft_del_set()
{
	# $1 - set name
	nft delete set inet $ZAPRET_NFT_TABLE $1
}
nft_flush_set()
{
	# $1 - set name
	nft flush set inet $ZAPRET_NFT_TABLE $1
}
nft_flush_chain()
{
	# $1 - set name
	nft flush chain inet $ZAPRET_NFT_TABLE $1
}
nft_set_exists()
{
	# $1 - set name
	nft -t list set inet $ZAPRET_NFT_TABLE $1 2>/dev/null >/dev/null
}
nft_flush_chain()
{
	# $1 - chain name
	nft flush chain inet $ZAPRET_NFT_TABLE $1
}
nft_chain_empty()
{
	# $1 - chain name
	local count=$(nft list chain inet $ZAPRET_NFT_TABLE $1 | wc -l)
	[ "$count" -le 4 ]
}
nft_rule_exists()
{
	# $1 - chain
	# $2 - rule
	local rule
	# convert rule to nft output form
	nft_flush_chain ruletest
	nft_add_rule ruletest "$2"
	rule=$(nft list chain inet $ZAPRET_NFT_TABLE ruletest | sed -n '3s/\t//gp')
	nft_flush_chain ruletest
	nft list chain inet $ZAPRET_NFT_TABLE $1 | trim | grep -qxF "$rule"
}

nft_del_all_chains_from_table()
{
	# $1 - table_name with or without family

	# delete all chains with possible references to each other
	# cannot just delete all in the list because of references
	# avoid infinite loops
	local chains deleted=1 error=1
	while [ -n "$deleted" -a -n "$error" ]; do
		chains=$(nft -t list table $1 2>/dev/null | sed -nre "s/^[ 	]*chain ([^ ]+) \{/\1/p" | xargs)
		[ -n "$chains" ] || break
		deleted=
		error=
		for chain in $chains; do
			if nft delete chain $1 $chain 2>/dev/null; then
				deleted=1
			else
				error=1
			fi
		done
	done
}

# ipset checks cost some CPU. do not populate jump from hook until something is added to the chain
nft_activate_chain4()
{
	# $1 - chain name
	# $2 - saddr/daddr
	local b rule markf= act flt_ifname
	[ "$DISABLE_IPV4" = "1" ] || {
		eval act="\$${1}_act4"
		[ -n "$act" ] && return

		b=0
		nft_wanif_filter_present && b=1
		flt_ifname="oifname"
		starts_with "$1" pre && flt_ifname="iifname"

		[ "$2" = daddr ] && markf=$(nft_mark_filter)
		rule="meta mark and $DESYNC_MARK == 0 $markf"
		[ $b = 1 ] && rule="$rule $flt_ifname @wanif"
		rule="$rule ip $2 != @nozapret jump $1"
		nft_rule_exists ${1}_hook "$rule" || nft_add_rule ${1}_hook $rule

		eval ${1}_act4=1
	}
}
nft_activate_chain6()
{
	# $1 - chain name
	# $2 - saddr/daddr
	local b rule markf= act flt_ifname
	[ "$DISABLE_IPV6" = "1" ] || {
		eval act="\$${1}_act6"
		[ -n "$act" ] && return

		b=0
		nft_wanif6_filter_present && b=1
		flt_ifname="oifname"
		starts_with "$1" pre && flt_ifname="iifname"

		[ "$2" = daddr ] && markf=$(nft_mark_filter)
		rule="meta mark and $DESYNC_MARK == 0 $markf"
		[ $b = 1 ] && rule="$rule $flt_ifname @wanif6"
		rule="$rule ip6 $2 != @nozapret6 jump $1"
		nft_rule_exists ${1}_hook "$rule" || nft_add_rule ${1}_hook $rule

		eval ${1}_act6=1
	}
}

nft_create_chains()
{
cat << EOF | nft -f -
	add chain inet $ZAPRET_NFT_TABLE forward_hook { type filter hook forward priority -1; }
	flush chain inet $ZAPRET_NFT_TABLE forward_hook

	add chain inet $ZAPRET_NFT_TABLE flow_offload
	flush chain inet $ZAPRET_NFT_TABLE flow_offload
	add chain inet $ZAPRET_NFT_TABLE flow_offload_zapret
	flush chain inet $ZAPRET_NFT_TABLE flow_offload_zapret
	add chain inet $ZAPRET_NFT_TABLE flow_offload_always
	flush chain inet $ZAPRET_NFT_TABLE flow_offload_always

	add chain inet $ZAPRET_NFT_TABLE postrouting
	flush chain inet $ZAPRET_NFT_TABLE postrouting
	add chain inet $ZAPRET_NFT_TABLE postrouting_hook { type filter hook postrouting priority 99; }
	flush chain inet $ZAPRET_NFT_TABLE postrouting_hook

	add chain inet $ZAPRET_NFT_TABLE postnat
	flush chain inet $ZAPRET_NFT_TABLE postnat
	add chain inet $ZAPRET_NFT_TABLE postnat_hook { type filter hook postrouting priority 101; }
	flush chain inet $ZAPRET_NFT_TABLE postnat_hook

	add chain inet $ZAPRET_NFT_TABLE prerouting
	flush chain inet $ZAPRET_NFT_TABLE prerouting
	add chain inet $ZAPRET_NFT_TABLE prerouting_hook { type filter hook prerouting priority -99; }
	flush chain inet $ZAPRET_NFT_TABLE prerouting_hook

	add chain inet $ZAPRET_NFT_TABLE prenat_hook { type filter hook prerouting priority -101; }
	flush chain inet $ZAPRET_NFT_TABLE prenat_hook
	add chain inet $ZAPRET_NFT_TABLE prenat
	flush chain inet $ZAPRET_NFT_TABLE prenat

	add chain inet $ZAPRET_NFT_TABLE predefrag { type filter hook output priority -401; }
	flush chain inet $ZAPRET_NFT_TABLE predefrag
	add chain inet $ZAPRET_NFT_TABLE predefrag_nfqws
	flush chain inet $ZAPRET_NFT_TABLE predefrag_nfqws
	add rule inet $ZAPRET_NFT_TABLE predefrag mark and $DESYNC_MARK !=0 jump predefrag_nfqws comment "nfqws generated : avoid drop by INVALID conntrack state"
	add rule inet $ZAPRET_NFT_TABLE predefrag_nfqws mark and $DESYNC_MARK_POSTNAT !=0 notrack comment "postnat traffic"
	add rule inet $ZAPRET_NFT_TABLE predefrag_nfqws ip frag-off & 0x1fff != 0 notrack comment "ipfrag"
	add rule inet $ZAPRET_NFT_TABLE predefrag_nfqws exthdr frag exists notrack comment "ipfrag"
	add rule inet $ZAPRET_NFT_TABLE predefrag_nfqws tcp flags ! syn,rst,ack notrack comment "datanoack"

	add set inet $ZAPRET_NFT_TABLE wanif { type ifname; }
	add set inet $ZAPRET_NFT_TABLE wanif6 { type ifname; }
	add set inet $ZAPRET_NFT_TABLE lanif { type ifname; }

	add chain inet $ZAPRET_NFT_TABLE ruletest
	flush chain inet $ZAPRET_NFT_TABLE ruletest
EOF
	[ -n "$POSTNAT_ALL" ] && {
		nft_flush_chain predefrag_nfqws
		nft_add_rule predefrag_nfqws notrack comment \"do not track nfqws generated packets to avoid nat tampering and defragmentation\"
	}
	[ "$FILTER_TTL_EXPIRED_ICMP" = 1 ] && {
		if is_postnat; then
			# can be caused by untracked nfqws-generated packets
			nft_add_rule prerouting_hook icmp type time-exceeded ct state invalid drop
		else
			nft_add_rule postrouting_hook mark and $DESYNC_MARK != 0 ct mark set ct mark or $DESYNC_MARK comment \"nfqws related : prevent ttl expired socket errors\"
		fi
		[ "$DISABLE_IPV4" = "1" ] || {
			nft_add_rule prerouting_hook icmp type time-exceeded ct mark and $DESYNC_MARK != 0 drop comment \"nfqws related : prevent ttl expired socket errors\"
		}
		[ "$DISABLE_IPV6" = "1" ] || {
			nft_add_rule prerouting_hook icmpv6 type time-exceeded ct mark and $DESYNC_MARK != 0 drop comment \"nfqws related : prevent ttl expired socket errors\"
		}
	}
}
nft_del_chains()
{
	# do not delete all chains because of additional user hooks
	# they must be inside zapret table to use nfsets

cat << EOF | nft -f - 2>/dev/null
	delete chain inet $ZAPRET_NFT_TABLE postrouting_hook
	delete chain inet $ZAPRET_NFT_TABLE postnat_hook
	delete chain inet $ZAPRET_NFT_TABLE prerouting_hook
	delete chain inet $ZAPRET_NFT_TABLE prenat_hook
	delete chain inet $ZAPRET_NFT_TABLE forward_hook
	delete chain inet $ZAPRET_NFT_TABLE postrouting
	delete chain inet $ZAPRET_NFT_TABLE postnat
	delete chain inet $ZAPRET_NFT_TABLE prerouting
	delete chain inet $ZAPRET_NFT_TABLE prenat
	delete chain inet $ZAPRET_NFT_TABLE predefrag
	delete chain inet $ZAPRET_NFT_TABLE predefrag_nfqws
	delete chain inet $ZAPRET_NFT_TABLE flow_offload
	delete chain inet $ZAPRET_NFT_TABLE flow_offload_zapret
	delete chain inet $ZAPRET_NFT_TABLE flow_offload_always
	delete chain inet $ZAPRET_NFT_TABLE ruletest
EOF
}
nft_del_flowtable()
{
	nft delete flowtable inet $ZAPRET_NFT_TABLE ft 2>/dev/null
}
nft_create_or_update_flowtable()
{
	# $1 = flags ('offload' for hw offload)
	# $2,$3,$4,... - interfaces
	# can be called multiple times to add interfaces. interfaces can only be added , not removed
	local flags=$1 devices makelist
	shift
	# warning ! nft versions at least up to 1.0.1 do not allow interface names starting with digit in flowtable and do not allow quoting
	# warning ! openwrt fixes this in post-21.x snapshots with special nft patch
	# warning ! in traditional linux distros nft is unpatched and will fail with quoted interface definitions if unfixed
	[ -n "$flags" ] && flags="flags $flags;"
	for makelist in make_quoted_comma_list make_comma_list; do
		$makelist devices "$@"
		[ -n "$devices" ] && devices="devices={$devices};"
		nft add flowtable inet $ZAPRET_NFT_TABLE ft "{ hook ingress priority -1; $flags $devices }" && break
	done
}
nft_flush_ifsets()
{
cat << EOF | nft -f -  2>/dev/null

	for set in wanif wanif6 lanif; do
		flush set inet $ZAPRET_NFT_TABLE $set
	done
EOF
}
nft_list_ifsets()
{
	for set in wanif wanif6 lanif; do
		nft list set inet $ZAPRET_NFT_TABLE $set
	done
	nft list flowtable inet $ZAPRET_NFT_TABLE ft 2>/dev/null
}

nft_create_firewall()
{
	nft_create_table
	nft_del_flowtable
	nft_create_chains
}
nft_del_firewall()
{
	nft_del_chains
	nft_del_flowtable
	# leave ifsets and ipsets because they may be used by custom rules
}

nft_add_rule()
{
	# $1 - chain
	# $2,$3,... - rule(s)
	local chain="$1"
	shift
	nft add rule inet $ZAPRET_NFT_TABLE $chain $FW_EXTRA_PRE "$@"
}
nft_insert_rule()
{
	# $1 - chain
	# $2,$3,... - rule(s)
	local chain="$1"
	shift
	nft insert rule inet $ZAPRET_NFT_TABLE $chain $FW_EXTRA_PRE "$@"
}
nft_add_set_element()
{
	# $1 - set or map name
	# $2 - element
	[ -z "$2" ] || nft add element inet $ZAPRET_NFT_TABLE $1 "{ $2 }"
}
nft_add_set_elements()
{
	# $1 - set or map name
	# $2,$3,... - element(s)
	local set="$1" elements
	shift
	make_comma_list elements "$@"
	nft_add_set_element $set "$elements"
}
nft_reverse_nfqws_rule()
{
	echo "$@" | sed -e 's/oifname /iifname /g' -e 's/dport /sport /g' -e 's/daddr /saddr /g' -e 's/ct original /ct reply /g' -e "s/mark and $DESYNC_MARK == 0//g"
}
nft_add_nfqws_flow_exempt_rule()
{
	# $1 - rule (must be all filters in one var)
	local FW_EXTRA_POST= FW_EXTRA_PRE=
	[ "$FLOWOFFLOAD" = 'software' -o "$FLOWOFFLOAD" = 'hardware' ] && \
		nft_insert_rule flow_offload_zapret "$1" return comment \"direct flow offloading exemption\"
}

nft_apply_flow_offloading()
{
	# ft can be absent
	nft_add_rule flow_offload_always flow add @ft 2>/dev/null && {
		nft_add_rule flow_offload_always counter comment \"if offload works here must not be too much traffic\"

		[ "$DISABLE_IPV4" = "1" ] || {
			# allow only outgoing packets to initiate flow offload
			nft_add_rule forward_hook meta l4proto "{ tcp, udp }" oifname @wanif jump flow_offload
			nft_add_rule flow_offload ip daddr == @nozapret goto flow_offload_always
		}
		[ "$DISABLE_IPV6" = "1" ] || {
			nft_add_rule forward_hook meta l4proto "{ tcp, udp }" oifname @wanif6 jump flow_offload
			nft_add_rule flow_offload ip6 daddr == @nozapret6 goto flow_offload_always
		}
		nft_add_rule flow_offload jump flow_offload_zapret

		nft_add_rule flow_offload_zapret goto flow_offload_always
	}
}



nft_filter_apply_ipset_target4()
{
	# $1 - var name of ipv4 nftables filter
	if [ "$MODE_FILTER" = "ipset" ]; then
		eval $1="\"\$$1 ip daddr @zapret\""
	fi
}
nft_filter_apply_ipset_target6()
{
	# $1 - var name of ipv6 nftables filter
	if [ "$MODE_FILTER" = "ipset" ]; then
		eval $1="\"\$$1 ip6 daddr @zapret6\""
	fi
}
nft_filter_apply_ipset_target()
{
	# $1 - var name of ipv4 nftables filter
	# $2 - var name of ipv6 nftables filter
	nft_filter_apply_ipset_target4 $1
	nft_filter_apply_ipset_target6 $2
}

nft_mark_filter()
{
	[ -n "$FILTER_MARK" ] && echo "mark and $FILTER_MARK != 0"
}

nft_script_add_ifset_element()
{
	# $1 - set name
	# $2 - space separated elements
	local elements
	[ -n "$2" ] && {
		make_quoted_comma_list elements $2
		script="${script}
add element inet $ZAPRET_NFT_TABLE $1 { $elements }"
	}
}
nft_fill_ifsets()
{
	# $1 - space separated lan interface names
	# $2 - space separated wan interface names
	# $3 - space separated wan6 interface names
	# 4,5,6 is needed for pppoe+openwrt case. looks like it's not easily possible to resolve ethernet device behind a pppoe interface
	# $4 - space separated lan physical interface names (optional)
	# $5 - space separated wan physical interface names (optional)
	# $6 - space separated wan6 physical interface names (optional)

	local script i j ALLDEVS devs b

	# if large sets exist nft works very ineffectively
	# looks like it analyzes the whole table blob to find required data pieces
	# calling all in one shot helps not to waste cpu time many times

	script="flush set inet $ZAPRET_NFT_TABLE wanif
flush set inet $ZAPRET_NFT_TABLE wanif6
flush set inet $ZAPRET_NFT_TABLE lanif"
	nft_script_add_ifset_element lanif "$1"

	[ "$DISABLE_IPV4" = "1" ] || nft_script_add_ifset_element wanif "$2"
	[ "$DISABLE_IPV6" = "1" ] || nft_script_add_ifset_element wanif6 "$3"

	echo "$script" | nft -f -

	case "$FLOWOFFLOAD" in
		software)
			ALLDEVS=$(unique $1 $2 $3)
			# unbound flowtable may cause error in older nft version
			nft_create_or_update_flowtable '' $ALLDEVS 2>/dev/null
			;;
		hardware)
			ALLDEVS=$(unique $1 $2 $3 $4 $5 $6)
			# first create unbound flowtable. may cause error in older nft version
			nft_create_or_update_flowtable 'offload' 2>/dev/null
			# then add elements. some of them can cause error because unsupported
			for i in $ALLDEVS; do
				# bridge members must be added instead of the bridge itself
				# some members may not support hw offload. example : lan1 lan2 lan3 support, wlan0 wlan1 - not
				b=
				devs=$(resolve_hw_offload $i)
				for j in $devs; do
					# do not display error if addition failed
					nft_create_or_update_flowtable 'offload' $j && b=1 2>/dev/null
				done
				[ -n "$b" ] || {
					# no lower devices added ? try to add interface itself
					nft_create_or_update_flowtable 'offload' $i 2>/dev/null
				}
			done
			;;
	esac
}

nft_only()
{
	linux_fwtype

	case "$FWTYPE" in
		nftables)
			"$@"
			;;
	esac
}


nft_print_op()
{
	echo "Inserting nftables ipv$3 rule for $2 : $1"
}
is_postnat()
{
	[ "$POSTNAT" != 0 -o "$POSTNAT_ALL" = 1 ]
}
get_postchain()
{
	if is_postnat ; then
		echo -n postnat
	else
		echo -n postrouting
	fi
}
get_prechain()
{
	if is_postnat ; then
		echo -n prenat
	else
		echo -n prerouting
	fi
}
_nft_fw_nfqws_post4()
{
	# $1 - filter ipv4
	# $2 - queue number
	# $3 - not-empty if wan interface filtering required

	[ "$DISABLE_IPV4" = "1" -o -z "$1" ] || {
		local filter="$1" port="$2" rule chain=$(get_postchain) setmark
		nft_print_op "$filter" "nfqws postrouting (qnum $port)" 4
		rule="meta nfproto ipv4 $filter"
		is_postnat && setmark="meta mark set meta mark or $DESYNC_MARK_POSTNAT"
		nft_insert_rule $chain $rule $setmark $CONNMARKER $FW_EXTRA_POST queue num $port bypass
		nft_add_nfqws_flow_exempt_rule "$rule"
		nft_activate_chain4 $chain daddr
	}
}
_nft_fw_nfqws_post6()
{
	# $1 - filter ipv6
	# $2 - queue number
	# $3 - not-empty if wan interface filtering required

	[ "$DISABLE_IPV6" = "1" -o -z "$1" ] || {
		local filter="$1" port="$2" rule chain=$(get_postchain) setmark
		nft_print_op "$filter" "nfqws postrouting (qnum $port)" 6
		rule="meta nfproto ipv6 $filter"
		is_postnat && setmark="meta mark set meta mark or $DESYNC_MARK_POSTNAT"
		nft_insert_rule $chain $rule $setmark $CONNMARKER $FW_EXTRA_POST queue num $port bypass
		nft_add_nfqws_flow_exempt_rule "$rule"
		nft_activate_chain6 $chain daddr
	}
}
nft_fw_nfqws_post()
{
	# $1 - filter ipv4
	# $2 - filter ipv6
	# $3 - queue number

	nft_fw_nfqws_post4 "$1" $3
	nft_fw_nfqws_post6 "$2" $3
}

_nft_fw_nfqws_pre4()
{
	# $1 - filter ipv4
	# $2 - queue number
	# $3 - not-empty if wan interface filtering required

	[ "$DISABLE_IPV4" = "1" -o -z "$1" ] || {
		local filter="$1" port="$2" rule chain=$(get_prechain)
		nft_print_op "$filter" "nfqws prerouting (qnum $port)" 4
		rule="meta nfproto ipv4 $filter"
		nft_insert_rule $chain $rule $CONNMARKER $FW_EXTRA_POST queue num $port bypass
		nft_activate_chain4 $chain saddr
	}
}
_nft_fw_nfqws_pre6()
{
	# $1 - filter ipv6
	# $2 - queue number
	# $3 - not-empty if wan interface filtering required

	[ "$DISABLE_IPV6" = "1" -o -z "$1" ] || {
		local filter="$1" port="$2" rule chain=$(get_prechain)
		nft_print_op "$filter" "nfqws prerouting (qnum $port)" 6
		rule="meta nfproto ipv6 $filter"
		nft_insert_rule $chain $rule $CONNMARKER $FW_EXTRA_POST queue num $port bypass
		nft_activate_chain6 $chain saddr
	}
}
nft_fw_nfqws_pre()
{
	# $1 - filter ipv4
	# $2 - filter ipv6
	# $3 - queue number

	nft_fw_nfqws_pre4 "$1" $3
	nft_fw_nfqws_pre6 "$2" $3
}

nft_fw_nfqws_both4()
{
	# $1 - filter ipv4
	# $2 - queue number
	nft_fw_nfqws_post4 "$@"
	nft_fw_nfqws_pre4 "$(nft_reverse_nfqws_rule $1)" $2
}
nft_fw_nfqws_both6()
{
	# $1 - filter ipv6
	# $2 - queue number
	nft_fw_nfqws_post6 "$@"
	nft_fw_nfqws_pre6 "$(nft_reverse_nfqws_rule $1)" $2
}
nft_fw_nfqws_both()
{
	# $1 - filter ipv4
	# $2 - filter ipv6
	# $3 - queue number
	nft_fw_nfqws_both4 "$1" "$3"
	nft_fw_nfqws_both6 "$2" "$3"
}

zapret_reload_ifsets()
{
	nft_only nft_create_table ; nft_fill_ifsets_overload
	return 0
}
zapret_list_ifsets()
{
	nft_only nft_list_ifsets
	return 0
}
zapret_list_table()
{
	nft_only nft_list_table
	return 0
}



nft_fw_reverse_nfqws_rule4()
{
	nft_fw_nfqws_pre4 "$(nft_reverse_nfqws_rule "$1")" $2
}
nft_fw_reverse_nfqws_rule6()
{
	nft_fw_nfqws_pre6 "$(nft_reverse_nfqws_rule "$1")" $2
}
nft_fw_reverse_nfqws_rule()
{
	# ensure that modes relying on incoming traffic work
	# $1 - rule4
	# $2 - rule6
	# $3 - queue number
	nft_fw_reverse_nfqws_rule4 "$1" $3
	nft_fw_reverse_nfqws_rule6 "$2" $3
}

nft_first_packets()
{
	# $1 - packet count
	[ -n "$1" -a "$1" != keepalive ] && [ "$1" -ge 1 ] &&
	{
		if [ "$1" = 1 ] ; then
			echo "$nft_connbytes 1"
		else
			echo "$nft_connbytes 1-$1"
		fi
	}
}

nft_apply_nfqws_in_out()
{
	# $1 - tcp,udp
	# $2 - ports
	# $3 - PKT_OUT. special value : 'keepalive'
	# $4 - PKT_IN
	local f4 f6 first_packets_only
	[ -n "$2" ] || return
	[ -n "$3" -a "$3" != 0 ] &&
	{
		first_packets_only="$(nft_first_packets $3)"
		f4="$1 dport {$2} $first_packets_only"
		f6=$f4
		nft_filter_apply_ipset_target f4 f6
		nft_fw_nfqws_post "$f4" "$f6" $QNUM
	}
	[ -n "$4" -a "$4" != 0 ] &&
	{
		first_packets_only="$(nft_first_packets $4)"
		f4="$1 dport {$2} $first_packets_only"
		f6=$f4
		nft_filter_apply_ipset_target f4 f6
		nft_fw_reverse_nfqws_rule "$f4" "$f6" $QNUM
	}
}

zapret_apply_firewall_standard_nfqws_rules_nft()
{
	[ "$NFQWS2_ENABLE" = 1 ] && {
		nft_apply_nfqws_in_out tcp "$NFQWS2_PORTS_TCP" "$NFQWS2_TCP_PKT_OUT" "$NFQWS2_TCP_PKT_IN"
		nft_apply_nfqws_in_out tcp "$NFQWS2_PORTS_TCP_KEEPALIVE" keepalive "$NFQWS2_TCP_PKT_IN"
		nft_apply_nfqws_in_out udp "$NFQWS2_PORTS_UDP" "$NFQWS2_UDP_PKT_OUT" "$NFQWS2_UDP_PKT_IN"
		nft_apply_nfqws_in_out udp "$NFQWS2_PORTS_UDP_KEEPALIVE" keepalive "$NFQWS2_UDP_PKT_IN"
	}
}
zapret_apply_firewall_standard_rules_nft()
{
	zapret_apply_firewall_standard_nfqws_rules_nft
}

zapret_apply_firewall_rules_nft()
{
	zapret_apply_firewall_standard_rules_nft
	custom_runner zapret_custom_firewall_nft
}

zapret_apply_firewall_nft()
{
	echo Applying nftables

	create_ipset no-update
	nft_create_firewall
	nft_fill_ifsets_overload

	zapret_apply_firewall_rules_nft

	[ "$FLOWOFFLOAD" = 'software' -o "$FLOWOFFLOAD" = 'hardware' ] && nft_apply_flow_offloading

	return 0
}
zapret_unapply_firewall_nft()
{
	echo Clearing nftables

	nft_del_firewall
	custom_runner zapret_custom_firewall_nft_flush
	return 0
}
zapret_do_firewall_nft()
{
	# $1 - 1 - add, 0 - del

	if [ "$1" = 0 ] ; then
		zapret_unapply_firewall_nft
	else
		zapret_apply_firewall_nft
	fi

	return 0
}

# ctmark is not available in POSTNAT mode
CONNMARKER=
[ "$FILTER_TTL_EXPIRED_ICMP" = 1 ] && is_postnat && CONNMARKER="ct mark set ct mark or $DESYNC_MARK"
