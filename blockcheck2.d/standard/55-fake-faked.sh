. "$TESTDIR/def.inc"

pktws_check_http()
{
	# $1 - test function
	# $2 - domain
	[ "$NOTEST_FAKE_FAKED_HTTP" = 1 ] && { echo "SKIPPED"; return 0; }

	local testf=$1 domain="$2"
	local ok ttls attls f ff fake fooling splitf splitfs= split splits='method+2 midsld method+2,midsld'
	local PAYLOAD="--payload=http_req"

	if [ -n "$FAKE_HTTP" ]; then
		fake=fake_http
	else
		fake=fake_default_http
	fi

	[ "$MAX_TTL" = 0 ] || ttls=$(seq -s ' ' $MIN_TTL $MAX_TTL)
	[ "$MAX_AUTOTTL_DELTA" = 0 ] || attls=$(seq -s ' ' $MIN_AUTOTTL_DELTA $MAX_AUTOTTL_DELTA)

	# do not test fake + multisplit if multisplit works
	[ "$need_fakedsplit" = 0 -a "$SCANLEVEL" != force ] || splitfs=fakedsplit
	# do not test fake + fakeddisorder if fakeddisorder works
	[ "$need_fakeddisorder" = 0 -a "$SCANLEVEL" != force ] || splitfs="${splitfs:+$splitfs }fakeddisorder"

	for splitf in $splitfs; do
		ok=0
		for ttl in $ttls; do
			for split in $splits; do
				# orig-ttl=1 with start/cutoff limiter drops empty ACK packet in response to SYN,ACK. it does not reach DPI or server.
				# missing ACK is transmitted in the first data packet of TLS/HTTP proto
				for ff in $fake 0x00000000; do
					for f in '' "--payload=empty --out-range=s1<d1 --lua-desync=pktmod:ip${IPVV}_ttl=1"; do
						pktws_curl_test_update $testf $domain ${FAKE_HTTP:+--blob=$fake:@"$FAKE_HTTP" }${FAKED_PATTERN_HTTP:+--blob=faked_pat:@"$FAKED_PATTERN_HTTP" }$PAYLOAD "--lua-desync=fake:blob=${ff}:ip${IPVV}_ttl=$ttl:repeats=$FAKE_REPEATS" --lua-desync=$splitf:${FAKED_PATTERN_HTTP:+pattern=faked_pat:}pos=$split:ip${IPVV}_ttl=$ttl:repeats=$FAKE_REPEATS $f && {
							ok=1
							[ "$SCANLEVEL" = force ] || break
						}
					done
				done
				[ "$SCANLEVEL" = veryquick -a "$ok" = 1 ] && break
			done
			[ "$ok" = 1 ] && break
		done
		for fooling in $FOOLINGS_TCP; do
			for split in $splits; do
				for ff in $fake 0x00000000; do
					pktws_curl_test_update $testf $domain ${FAKE_HTTP:+--blob=$fake:@"$FAKE_HTTP" }${FAKED_PATTERN_HTTP:+--blob=faked_pat:@"$FAKED_PATTERN_HTTP" }$PAYLOAD --lua-desync=fake:blob=$ff:$fooling:repeats=$FAKE_REPEATS --lua-desync=$splitf:${FAKED_PATTERN_HTTP:+pattern=faked_pat:}pos=$split:$fooling:repeats=$FAKE_REPEATS && ok=1
					# duplicate SYN with MD5
					contains "$fooling" tcp_md5 && pktws_curl_test_update $testf $domain ${FAKE_HTTP:+--blob=$fake:@"$FAKE_HTTP" }${FAKED_PATTERN_HTTP:+--blob=faked_pat:@"$FAKED_PATTERN_HTTP" }$PAYLOAD --lua-desync=fake:blob=$ff:$fooling:repeats=$FAKE_REPEATS --lua-desync=$splitf:${FAKED_PATTERN_HTTP:+pattern=faked_pat:}pos=$split:$fooling:repeats=$FAKE_REPEATS --payload=empty "--out-range=<s1" --lua-desync=send:$TCP_MD5 && ok=1
				done
				[ "$SCANLEVEL" = veryquick -a "$ok" = 1 ] && break
			done
			[ "$SCANLEVEL" = veryquick -a "$ok" = 1 ] && break
		done
		for ttl in $attls; do
			for split in $splits; do
				for ff in $fake 0x00000000; do
					for f in '' "--payload=empty --out-range=s1<d1 --lua-desync=pktmod:ip${IPVV}_ttl=1"; do
						pktws_curl_test_update $testf $domain  ${FAKE_HTTP:+--blob=$fake:@"$FAKE_HTTP" }${FAKED_PATTERN_HTTP:+--blob=faked_pat:@"$FAKED_PATTERN_HTTP" }$PAYLOAD --lua-desync=fake:blob=$ff:ip${IPVV}_autottl=-$ttl,3-20:repeats=$FAKE_REPEATS --lua-desync=$splitf:${FAKED_PATTERN_HTTP:+pattern=faked_pat:}pos=$split:ip${IPVV}_autottl=-$ttl,3-20:repeats=$FAKE_REPEATS $f && {
							ok=1
							[ "$SCANLEVEL" = force ] || break
						}
					done
				done
				[ "$SCANLEVEL" = veryquick -a "$ok" = 1 ] && break
			done
			[ "$SCANLEVEL" = veryquick -a "$ok" = 1 ] && break
		done
		[ "$SCANLEVEL" = veryquick -a "$ok" = 1 ] && break
	done
}

pktws_fake_https_vary_()
{
	local ok_any=0 testf=$1 domain="$2" fooling="$3" pre="$4" post="$5"
	shift; shift; shift
	pktws_curl_test_update $testf $domain ${FAKE_HTTPS:+--blob=$fake:@"$FAKE_HTTPS" }${FAKED_PATTERN_HTTPS:+--blob=faked_pat:@"$FAKED_PATTERN_HTTPS" }$pre $PAYLOAD --lua-desync=fake:blob=$fake:$fooling:repeats=$FAKE_REPEATS --lua-desync=$splitf:${FAKED_PATTERN_HTTPS:+pattern=faked_pat:}pos=$split:$fooling $post && ok_any=1
	[ "$ok_any" = 1 -a "$SCANLEVEL" = veryquick ] && { ok=1; return 0; }
	pktws_curl_test_update $testf $domain ${FAKED_PATTERN_HTTPS:+--blob=faked_pat:@"$FAKED_PATTERN_HTTPS" }$pre $PAYLOAD --lua-desync=fake:blob=0x00000000:$fooling:repeats=$FAKE_REPEATS --lua-desync=$splitf:${FAKED_PATTERN_HTTPS:+pattern=faked_pat:}pos=$split:$fooling $post && ok_any=1
	[ "$ok_any" = 1 -a "$SCANLEVEL" = veryquick ] && { ok=1; return 0; }
	pktws_curl_test_update $testf $domain ${FAKE_HTTPS:+--blob=$fake:@"$FAKE_HTTPS" }${FAKED_PATTERN_HTTPS:+--blob=faked_pat:@"$FAKED_PATTERN_HTTPS" }$pre $PAYLOAD --lua-desync=fake:blob=0x00000000:$fooling:repeats=$FAKE_REPEATS --lua-desync=fake:blob=$fake:$fooling:tls_mod=rnd,dupsid:repeats=$FAKE_REPEATS --lua-desync=$splitf:${FAKED_PATTERN_HTTPS:+pattern=faked_pat:}pos=$split:$fooling $post && ok_any=1
	[ "$ok_any" = 1 -a "$SCANLEVEL" = veryquick ] && { ok=1; return 0; }
	pktws_curl_test_update $testf $domain ${FAKE_HTTPS:+--blob=$fake:@"$FAKE_HTTPS" }${FAKED_PATTERN_HTTPS:+--blob=faked_pat:@"$FAKED_PATTERN_HTTPS" }$pre $PAYLOAD --lua-desync=multisplit:blob=$fake:$fooling:pos=2:nodrop:repeats=$FAKE_REPEATS --lua-desync=$splitf:${FAKED_PATTERN_HTTPS:+pattern=faked_pat:}pos=$split:$fooling $post && ok_any=1
	[ "$ok_any" = 1 -a "$SCANLEVEL" = veryquick ] && { ok=1; return 0; }
	pktws_curl_test_update $testf $domain ${FAKE_HTTPS:+--blob=$fake:@"$FAKE_HTTPS" }${FAKED_PATTERN_HTTPS:+--blob=faked_pat:@"$FAKED_PATTERN_HTTPS" }$pre $PAYLOAD --lua-desync=fake:blob=$fake:$fooling:tls_mod=rnd,dupsid,padencap:repeats=$FAKE_REPEATS --lua-desync=$splitf:${FAKED_PATTERN_HTTPS:+pattern=faked_pat:}pos=$split:$fooling $post && ok_any=1
	[ "$ok_any" = 1 ] && ok=1

}
pktws_fake_https_vary()
{
	local ok_any=0 fooling="$3"
	pktws_fake_https_vary_ "$1" "$2" "$3" "$4" "$5" && ok_any=1
	# duplicate SYN with MD5
	contains "$fooling" tcp_md5 && \
		pktws_fake_https_vary_  "$1" "$2" "$3" "$4" "${5:+$5 }--payload=empty --out-range=<s1 --lua-desync=send:$TCP_MD5" && ok_any=1
	[ "$ok_any" = 1 ]
}

pktws_check_https_tls()
{
	# $1 - test function
	# $2 - domain
	# $3 - PRE args for nfqws2

	local testf=$1 domain="$2" pre="$3"
	local ok ok_any ttls attls f fake fooling splitf splitfs= split splits='2 1 sniext+1 sniext+4 host+1 midsld 1,midsld 1,sniext+1,host+1,midsld-2,midsld,midsld+2,endhost-1'
	local PAYLOAD="--payload=tls_client_hello"

	shift; shift

	if [ -n "$FAKE_HTTPS" ]; then
		fake=fake_tls
	else
		fake=fake_default_tls
	fi

	[ "$MAX_TTL" = 0 ] || ttls=$(seq -s ' ' $MIN_TTL $MAX_TTL)
	[ "$MAX_AUTOTTL_DELTA" = 0 ] || attls=$(seq -s ' ' $MIN_AUTOTTL_DELTA $MAX_AUTOTTL_DELTA)

	# do not test fake + fakedsplit if fakedsplit works
	[ "$need_fakedsplit" = 0 -a "$SCANLEVEL" != force ] || splitfs=fakedsplit
	# do not test fake + fakeddisorder if fakeddisorder works
	[ "$need_fakeddisorder" = 0 -a "$SCANLEVEL" != force ] || splitfs="${splitfs:+$splitfs }fakeddisorder"

	ok_any=0
	for splitf in $splitfs; do
		ok=0
		for ttl in $ttls; do
			for split in $splits; do
				# orig-ttl=1 with start/cutoff limiter drops empty ACK packet in response to SYN,ACK. it does not reach DPI or server.
				# missing ACK is transmitted in the first data packet of TLS/HTTP proto
				for f in '' "--payload=empty --out-range=s1<d1 --lua-desync=pktmod:ip${IPVV}_ttl=1"; do
					pktws_fake_https_vary $testf $domain "ip${IPVV}_ttl=$ttl" "$pre" "$f" && [ "$SCANLEVEL" != force ] && break
				done
				[ "$SCANLEVEL" = veryquick -a "$ok" = 1 ] && break
			done
			[ "$ok" = 1 ] && break
		done
		for fooling in $FOOLINGS_TCP; do
			for split in $splits; do
				pktws_fake_https_vary $testf $domain "$fooling" "$pre"
				[ "$SCANLEVEL" = veryquick -a "$ok" = 1 ] && break
			done
			[ "$SCANLEVEL" = veryquick -a "$ok" = 1 ] && break
		done
		for ttl in $attls; do
			for split in $splits; do
				for f in '' "--payload=empty --out-range=s1<d1 --lua-desync=pktmod:ip${IPVV}_ttl=1"; do
					pktws_fake_https_vary $testf $domain "ip${IPVV}_autottl=-$ttl,3-20" "$pre" "$f" && [ "$SCANLEVEL" != force ] && break
				done
				[ "$SCANLEVEL" = veryquick -a "$ok" = 1 ] && break
			done
			[ "$SCANLEVEL" = veryquick -a "$ok" = 1 ] && break
		done
		[ "$ok" = 1 ] && ok_any=1
		[ "$SCANLEVEL" = veryquick -a "$ok_any" = 1 ] && break
	done
	[ "$ok_any" = 1 ]
}

pktws_check_https_tls12()
{
	# $1 - test function
	# $2 - domain

	[ "$NOTEST_FAKE_FAKED_HTTPS" = 1 ] && { echo "SKIPPED"; return 0; }

	pktws_check_https_tls "$1" "$2" && [ "$SCANLEVEL" != force ] && return
	pktws_check_https_tls "$1" "$2" --lua-desync=wssize:wsize=1:scale=6
}

pktws_check_https_tls13()
{
	# $1 - test function
	# $2 - domain

	[ "$NOTEST_FAKE_FAKED_HTTPS" = 1 ] && { echo "SKIPPED"; return 0; }

	pktws_check_https_tls "$1" "$2"
}
