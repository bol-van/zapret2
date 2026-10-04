. "$TESTDIR/def.inc"

pktws_check_faked()
{
	# $1 - test function
	# $2 - domain
	# $3 - payload_type
	# $4 - splits
	# $5 - pattern
	# $6 - PRE args for nfqws2
	local testf=$1 domain="$2" pre="$6"
	local ok ok_any ttls attls f fooling
	local splitf splitfs= split splits="$4"
	local PAYLOAD="--payload=$3"
	local FAKED_PATTERN="$5"

	[ "$MAX_TTL" = 0 ] || ttls=$(seq -s ' ' $MIN_TTL $MAX_TTL)
	[ "$MAX_AUTOTTL_DELTA" = 0 ] || attls=$(seq -s ' ' $MIN_AUTOTTL_DELTA $MAX_AUTOTTL_DELTA)

	# do not test fakedsplit if multisplit works
	[ "$need_multisplit" = 0 -a "$SCANLEVEL" != force ] || splitfs=fakedsplit
	# do not test fakeddisorder if multidisorder works
	[ "$need_multidisorder" = 0 -a "$SCANLEVEL" != force ] || splitfs="${splitfs:+$splitfs }fakeddisorder"

	ok_any=0
	for splitf in $splitfs; do
		ok=0
		for ttl in $ttls; do
			# orig-ttl=1 with start/cutoff limiter drops empty ACK packet in response to SYN,ACK. it does not reach DPI or server.
			# missing ACK is transmitted in the first data packet of TLS/HTTP proto
			for split in $splits; do
				for f in '' "--payload=empty --out-range=s1<d1 --lua-desync=pktmod:ip${IPVV}_ttl=1"; do
					pktws_curl_test_update $testf $domain ${FAKED_PATTERN:+--blob=faked_pat:@"$FAKED_PATTERN" }$pre $PAYLOAD --lua-desync=$splitf:${FAKED_PATTERN:+pattern=faked_pat:}pos=$split:ip${IPVV}_ttl=$ttl:repeats=$FAKE_REPEATS $f && {
						ok=1
						[ "$SCANLEVEL" = force ] || break
					}
				done
				[ "$SCANLEVEL" = veryquick -a "$ok" = 1 ] && break
			done
			[ "$ok" = 1 ] && break
		done
		for fooling in $FOOLINGS_TCP; do
			for split in $splits; do
				pktws_curl_test_update $testf $domain ${FAKED_PATTERN:+--blob=faked_pat:@"$FAKED_PATTERN" }$pre $PAYLOAD --lua-desync=$splitf:${FAKED_PATTERN:+pattern=faked_pat:}pos=$split:$fooling && ok=1
				# duplicate SYN with MD5
				contains "$fooling" tcp_md5 && pktws_curl_test_update $testf $domain ${FAKED_PATTERN:+--blob=faked_pat:@"$FAKED_PATTERN" }$pre $PAYLOAD --lua-desync=$splitf:${FAKED_PATTERN:+pattern=faked_pat:}pos=$split:$fooling:repeats=$FAKE_REPEATS --payload=empty --out-range="<s1" --lua-desync=send:$TCP_MD5 && ok=1
				[ "$SCANLEVEL" = veryquick -a "$ok" = 1 ] && break
			done
			[ "$SCANLEVEL" = veryquick -a "$ok" = 1 ] && break
		done
		for ttl in $attls; do
			for split in $splits; do
				for f in '' "--payload=empty --out-range=s1<d1 --lua-desync=pktmod:ip${IPVV}_ttl=1"; do
					pktws_curl_test_update $testf $domain ${FAKED_PATTERN:+--blob=faked_pat:@"$FAKED_PATTERN" }$pre $PAYLOAD --lua-desync=$splitf:${FAKED_PATTERN:+pattern=faked_pat:}pos=$split:ip${IPVV}_autottl=-$ttl,3-20:repeats=$FAKE_REPEATS $f && {
						ok=1
						[ "$SCANLEVEL" = force ] || break
					}
				done
				[ "$SCANLEVEL" = veryquick -a "$ok" = 1 ] && break
			done
			[ "$SCANLEVEL" = veryquick -a "$ok" = 1 ] && break
		done
		[ $ok = 0 -a "$SCANLEVEL" != force ] && eval need_$splitf=1
		[ $ok = 1 ] && ok_any=1
		[ "$SCANLEVEL" = veryquick -a "$ok_any" = 1 ] && break
	done
	[ "$ok_any" = 1 ]
}

pktws_check_http()
{
	# $1 - test function
	# $2 - domain
	# $3 - PRE args for nfqws2
	[ "$NOTEST_FAKED_HTTP" = 1 ] && { echo "SKIPPED"; return; }

	local splits='method+2 midsld method+2,midsld'
	pktws_check_faked $1 "$2" http_req "$splits" "$FAKED_PATTERN_HTTP" "$3"
}

pktws_check_https_tls()
{
	# $1 - test function
	# $2 - domain
	# $3 - PRE args for nfqws2

	local splits='2 1 sniext+1 sniext+4 host+1 midsld 1,midsld 1,sniext+1,host+1,midsld-2,midsld,midsld+2,endhost-1'
	pktws_check_faked $1 "$2" tls_client_hello "$splits" "$FAKED_PATTERN_HTTPS" "$3"
}

pktws_check_https_tls12()
{
	# $1 - test function
	# $2 - domain

	[ "$NOTEST_FAKED_HTTPS" = 1 ] && { echo "SKIPPED"; return; }

	pktws_check_https_tls "$1" "$2" && [ "$SCANLEVEL" != force ] && return

	# do not use 'need' values obtained with wssize
	local need_fakedsplit_save=$need_fakedsplit need_fakeddisorder_save=$need_fakeddisorder
	pktws_check_https_tls "$1" "$2" --lua-desync=wssize:wsize=1:scale=6
	need_fakedsplit=$need_fakedsplit_save need_fakeddisorder=$need_fakeddisorder_save
}

pktws_check_https_tls13()
{
	# $1 - test function
	# $2 - domain

	[ "$NOTEST_FAKED_HTTPS" = 1 ] && { echo "SKIPPED"; return; }

	pktws_check_https_tls "$1" "$2"
}
