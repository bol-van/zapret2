pktws_check_http()
{
	# $1 - test function
	# $2 - domain

	[ "$NOTEST_SEQOVL_HTTP" = 1 ] && { echo "SKIPPED"; return; }

	local PAYLOAD="--payload http_req"

	local ok pat= split f f2

	pat=${SEQOVL_PATTERN_HTTP:+seqovl_pat}
	pat=${pat:-fake_default_http}

	pktws_curl_test_update $1 $2 $PAYLOAD --lua-desync=tcpseg:pos=0,-1:seqovl=1 --lua-desync=drop
	pktws_curl_test_update $1 $2 ${SEQOVL_PATTERN_HTTP:+--blob=$pat:@"$SEQOVL_PATTERN_HTTP" }$PAYLOAD --lua-desync=tcpseg:pos=0,-1:seqovl=#$pat:seqovl_pattern=$pat --lua-desync=drop

	ok=0
	for split in method+2 method+2,midsld; do
		pktws_curl_test_update $1 $2 $PAYLOAD --lua-desync=multisplit:pos=$split:seqovl=1 && ok=1
		pktws_curl_test_update $1 $2 ${SEQOVL_PATTERN_HTTP:+--blob=$pat:@"$SEQOVL_PATTERN_HTTP" }$PAYLOAD --lua-desync=multisplit:pos=$split:seqovl=#$pat:seqovl_pattern=$pat && ok=1
		[ "$ok" = 1 -a "$SCANLEVEL" != force ] && break
	done
	for split in 'method+1 method+2' 'midsld-1 midsld' 'method+1 method+2,midsld'; do
		f="$(extract_arg 1 $split)"
		f2="$(extract_arg 2 $split)"
		pktws_curl_test_update $1 $2 $PAYLOAD --lua-desync=$MULTIDISORDER:pos=$f2:seqovl=$f
		pktws_curl_test_update $1 $2 ${SEQOVL_PATTERN_HTTP:+--blob=$pat:@"$SEQOVL_PATTERN_HTTP" }$PAYLOAD --lua-desync=$MULTIDISORDER:pos=$f2:seqovl=$f:seqovl_pattern=$pat
	done
}

pktws_seqovl_tests_tls()
{
	# $1 - test function
	# $2 - domain/uri
	# $3 - PRE args for nfqws2
	local ok ok_any
	local testf=$1 domain="$2" pre="$3"
	local pat rnd_mod padencap_mod split f f2
	local PAYLOAD="--payload tls_client_hello"

	pat=${SEQOVL_PATTERN_HTTPS:+seqovl_pat}
	pat=${pat:-fake_default_tls}
	rnd_mod="--lua-init=$pat=tls_mod($pat,'rnd')"
	padencap_mod="--lua-desync=luaexec:code=desync.pat=tls_mod($pat,'rnd,dupsid,padencap',desync.reasm_data)"

	ok=0
	pktws_curl_test_update $testf $domain $pre $PAYLOAD --lua-desync=tcpseg:pos=0,-1:seqovl=1 --lua-desync=drop && ok=1
	pktws_curl_test_update $testf $domain ${SEQOVL_PATTERN_HTTPS:+--blob=$pat:@"$SEQOVL_PATTERN_HTTPS" }$rnd_mod $pre $PAYLOAD --lua-desync=tcpseg:pos=0,-1:seqovl=#$pat:seqovl_pattern=$pat --lua-desync=drop && ok=1
	pktws_curl_test_update $testf $domain ${SEQOVL_PATTERN_HTTPS:+--blob=$pat:@"$SEQOVL_PATTERN_HTTPS" }$pre $PAYLOAD $padencap_mod --lua-desync=tcpseg:pos=0,-1:seqovl=#pat:seqovl_pattern=pat --lua-desync=drop && ok=1
	ok_any=$ok

	ok=0
	for split in 10 10,sniext+1 10,sniext+4 10,midsld; do
		pktws_curl_test_update $testf $domain $pre $PAYLOAD --lua-desync=multisplit:pos=$split:seqovl=1 && ok=1
		pktws_curl_test_update $testf $domain ${SEQOVL_PATTERN_HTTPS:+--blob=$pat:@"$SEQOVL_PATTERN_HTTPS" }$rnd_mod $pre $PAYLOAD --lua-desync=multisplit:pos=$split:seqovl=#$pat:seqovl_pattern=$pat && ok=1
		pktws_curl_test_update $testf $domain ${SEQOVL_PATTERN_HTTPS:+--blob=$pat:@"$SEQOVL_PATTERN_HTTPS" }$pre $PAYLOAD $padencap_mod --lua-desync=multisplit:pos=$split:seqovl=#pat:seqovl_pattern=pat && ok=1
		[ "$ok" = 1 -a "$SCANLEVEL" != force ] && break
	done
	for split in '1 2' 'sniext sniext+1' 'sniext+3 sniext+4' 'midsld-1 midsld' '1 2,midsld'; do
		f="$(extract_arg 1 $split)"
		f2="$(extract_arg 2 $split)"
		pktws_curl_test_update $1 $2 $PAYLOAD --lua-desync=$MULTIDISORDER:pos=$f2:seqovl=$f && ok=1
		pktws_curl_test_update $testf $domain ${SEQOVL_PATTERN_HTTPS:+--blob=$pat:@"$SEQOVL_PATTERN_HTTPS" }$rnd_mod $pre $PAYLOAD --lua-desync=$MULTIDISORDER:pos=$f2:seqovl=$f:seqovl_pattern=$pat && ok=1
	done
	[ "$ok" = 1 ] && ok_any=1
	[ "$ok_any" = 1 ]
}

pktws_check_https_tls()
{
	# $1 - test function
	# $2 - domain
	# $3 - PRE args for nfqws2

	[ "$NOTEST_SEQOVL_HTTPS" = 1 ] && { echo "SKIPPED"; return; }

	pktws_seqovl_tests_tls "$1" "$2" "$3"
}

pktws_check_https_tls12()
{
	# $1 - test function
	# $2 - domain
	pktws_seqovl_tests_tls "$1" "$2" && [ "$SCANLEVEL" != force ] && return
	pktws_seqovl_tests_tls "$1" "$2" --lua-desync=wssize:wsize=1:scale=6
}

pktws_check_https_tls13()
{
	# $1 - test function
	# $2 - domain
	pktws_seqovl_tests_tls "$1" "$2"
}
