. "$TESTDIR/def.inc"

pktws_check_http()
{
	# $1 - test function
	# $2 - domain
	[ "$NOTEST_FAKE_MULTI_HTTP" = 1 ] && { echo "SKIPPED"; return 0; }

	local testf=$1 domain="$2"
	local ok ttls attls f ff fake fooling splitf splitfs= split splits='method+2 midsld method+2,midsld'
	local PAYLOAD="--payload=http_req"

	if [ -n "$FAKE_HTTP" ]; then
		fake=fake_http
	else
		fake=fake_default_http
	fi

	ttls=$(seq -s ' ' $MIN_TTL $MAX_TTL)
	attls=$(seq -s ' ' $MIN_AUTOTTL_DELTA $MAX_AUTOTTL_DELTA)

	# do not test fake + multisplit if multisplit works
	[ "$need_multisplit" = 0 -a "$SCANLEVEL" != force ] || splitfs=multisplit
	# do not test fake + multidisorder if multidisorder works
	[ "$need_multidisorder" = 0 -a "$SCANLEVEL" != force ] || splitfs="${splitfs:+$splitfs }$MULTIDISORDER"

	for splitf in $splitfs; do
		ok=0
		for ttl in $ttls; do
			for split in $splits; do
				# orig-ttl=1 with start/cutoff limiter drops empty ACK packet in response to SYN,ACK. it does not reach DPI or server.
				# missing ACK is transmitted in the first data packet of TLS/HTTP proto
				for ff in $fake 0x00000000; do
					for f in '' "--payload=empty --out-range=s1<d1 --lua-desync=pktmod:ip${IPVV}_ttl=1"; do
						pktws_curl_test_update $testf $domain ${FAKE_HTTP:+--blob=$fake:@"$FAKE_HTTP" }$PAYLOAD "--lua-desync=fake:blob=${ff}:ip${IPVV}_ttl=$ttl:repeats=$FAKE_REPEATS" --lua-desync=$splitf:pos=$split $f && {
							ok=1
							[ "$SCANLEVEL" = force ] || break
						}
					done
				done
			done
			[ "$ok" = 1 ] && break
		done
		for fooling in $FOOLINGS_TCP; do
			for split in $splits; do
				for ff in $fake 0x00000000; do
					pktws_curl_test_update $testf $domain ${FAKE_HTTP:+--blob=$fake:@"$FAKE_HTTP" }$PAYLOAD --lua-desync=fake:blob=$ff:$fooling:repeats=$FAKE_REPEATS --lua-desync=$splitf:pos=$split && ok=1
					# duplicate SYN with MD5
					contains "$fooling" tcp_md5 && pktws_curl_test_update $testf $domain ${FAKE_HTTP:+--blob=fake_http:@"$FAKE_HTTP" }$PAYLOAD --lua-desync=fake:blob=$ff:$fooling:repeats=$FAKE_REPEATS --lua-desync=$splitf:pos=$split --payload empty "--out-range=<s1" --lua-desync=send:tcp_md5 && ok=1
				done
			done
		done
		for ttl in $attls; do
			for split in $splits; do
				for ff in $fake 0x00000000; do
					for f in '' "--payload=empty --out-range=s1<d1 --lua-desync=pktmod:ip${IPVV}_ttl=1"; do
						pktws_curl_test_update $testf $domain  ${FAKE_HTTP:+--blob=$fake:@"$FAKE_HTTP" }$PAYLOAD --lua-desync=fake:blob=$ff:ip${IPVV}_autottl=-$ttl,3-20:repeats=$FAKE_REPEATS --lua-desync=$splitf:pos=$split $f && {
							ok=1
							[ "$SCANLEVEL" = force ] || break
						}
					done
				done
			done
		done
	done
}

pktws_fake_https_vary_()
{
	local ok_any=0 testf=$1 domain="$2" fooling="$3" pre="$4" post="$5"
	shift; shift; shift
	pktws_curl_test_update $testf $domain ${FAKE_HTTPS:+--blob=$fake:@"$FAKE_HTTPS" }$pre $PAYLOAD --lua-desync=fake:blob=$fake:$fooling:repeats=$FAKE_REPEATS --lua-desync=$splitf:pos=$split $post && ok_any=1
	pktws_curl_test_update $testf $domain $pre $PAYLOAD --lua-desync=fake:blob=0x00000000:$fooling:repeats=$FAKE_REPEATS --lua-desync=$splitf:pos=$split $post && ok_any=1
	pktws_curl_test_update $testf $domain $pre $PAYLOAD --lua-desync=fake:blob=0x00000000:$fooling:repeats=$FAKE_REPEATS --lua-desync=fake:blob=$fake:$fooling:tls_mod=rnd,dupsid:repeats=$FAKE_REPEATS --lua-desync=$splitf:pos=$split $post && ok_any=1
	pktws_curl_test_update $testf $domain ${FAKE_HTTPS:+--blob=$fake:@"$FAKE_HTTPS" }$pre $PAYLOAD --lua-desync=multisplit:blob=$fake:$fooling:pos=2:nodrop:repeats=$FAKE_REPEATS --lua-desync=$splitf:pos=$split $post && ok_any=1
	pktws_curl_test_update $testf $domain ${FAKE_HTTPS:+--blob=$fake:@"$FAKE_HTTPS" }$pre $PAYLOAD --lua-desync=fake:blob=$fake:$fooling:tls_mod=rnd,dupsid,padencap:repeats=$FAKE_REPEATS --lua-desync=$splitf:pos=$split $post && ok_any=1
	[ "$ok_any" = 1 ] && ok=1
}
pktws_fake_https_vary()
{
	local ok_any=0 fooling="$3"
	pktws_fake_https_vary_ "$1" "$2" "$3" "$4" "$5" && ok_any=1
	# duplicate SYN with MD5
	contains "$fooling" tcp_md5 && \
		pktws_fake_https_vary_  "$1" "$2" "$3" "$4" "${5:+$5 }--payload=empty --out-range=<s1 --lua-desync=send:tcp_md5" && ok_any=1
	[ "$ok_any" = 1 ]
}

pktws_check_https_tls()
{
	# $1 - test function
	# $2 - domain
	# $3 - PRE args for nfqws2

	[ "$NOTEST_FAKE_MULTI_HTTPS" = 1 ] && { echo "SKIPPED"; return 0; }

	local testf=$1 domain="$2" pre="$3"
	local ok ok_any ttls attls f fake fooling splitf splitfs= split splits='2 1 sniext+1 sniext+4 host+1 midsld 1,midsld 1,midsld,1220 1,sniext+1,host+1,midsld-2,midsld,midsld+2,endhost-1'
	local PAYLOAD="--payload=tls_client_hello"

	shift; shift

	if [ -n "$FAKE_HTTPS" ]; then
		fake=fake_tls
	else
		fake=fake_default_tls
	fi

	ttls=$(seq -s ' ' $MIN_TTL $MAX_TTL)
	attls=$(seq -s ' ' $MIN_AUTOTTL_DELTA $MAX_AUTOTTL_DELTA)

	# do not test fake + multisplit if multisplit works
	[ "$need_multisplit" = 0 -a "$SCANLEVEL" != force ] || splitfs=multisplit
	# do not test fake + multidisorder if multidisorder works
	[ "$need_multidisorder" = 0 -a "$SCANLEVEL" != force ] || splitfs="${splitfs:+$splitfs }$MULTIDISORDER"

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
			done
			[ "$ok" = 1 ] && break
		done
		for fooling in $FOOLINGS_TCP; do
			for split in $splits; do
				pktws_fake_https_vary $testf $domain "$fooling" "$pre"
			done
		done
		for ttl in $attls; do
			for split in $splits; do
				for f in '' "--payload=empty --out-range=s1<d1 --lua-desync=pktmod:ip${IPVV}_ttl=1"; do
					pktws_fake_https_vary $testf $domain "ip${IPVV}_autottl=-$ttl,3-20" "$pre" "$f" && [ "$SCANLEVEL" != force ] && break
				done
			done
		done
		[ "$ok" = 1 ] && ok_any=1
	done
	[ "$ok_any" = 1 ]
}

pktws_check_https_tls12()
{
	# $1 - test function
	# $2 - domain
	pktws_check_https_tls "$1" "$2" && [ "$SCANLEVEL" != force ] && return
	pktws_check_https_tls "$1" "$2" --lua-desync=wssize:wsize=1:scale=6
}

pktws_check_https_tls13()
{
	# $1 - test function
	# $2 - domain
	pktws_check_https_tls "$1" "$2"
}
