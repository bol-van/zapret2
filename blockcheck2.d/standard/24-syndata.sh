. "$TESTDIR/def.inc"

pktws_check_http()
{
	# $1 - test function
	# $2 - domain

	local PAYLOAD="--payload http_req" split

	for split in '' multisplit $MULTIDISORDER; do
		pktws_curl_test_update "$1" "$2" --lua-desync=syndata ${split:+$PAYLOAD --lua-desync=$split}
		pktws_curl_test_update "$1" "$2" --lua-desync=syndata:blob=fake_default_http $PAYLOAD ${split:+$PAYLOAD --lua-desync=$split}
	done
}

pktws_check_https_tls()
{
	# $1 - test function
	# $2 - domain
	# $3 - PRE args for nfqws2

	local PAYLOAD="--payload tls_client_hello" ok=0 pre="$3" split

	for split in '' multisplit $MULTIDISORDER; do
		pktws_curl_test_update "$1" "$2" $pre --lua-desync=syndata ${split:+$PAYLOAD --lua-desync=$split} && ok=1
		pktws_curl_test_update "$1" "$2" $pre --lua-desync=syndata:blob=0x1603 ${split:+$PAYLOAD --lua-desync=$split} && ok=1
		pktws_curl_test_update "$1" "$2" $pre --lua-desync=syndata:blob=fake_default_tls:tls_mod=rnd,dupsid,rndsni ${split:+$PAYLOAD --lua-desync=$split} && ok=1
		pktws_curl_test_update "$1" "$2" $pre --lua-desync=syndata:blob=fake_default_tls:tls_mod=rnd,dupsid,sni=google.com ${split:+$PAYLOAD --lua-desync=$split} && ok=1
	done

	[ "$ok" = 1 ]
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
