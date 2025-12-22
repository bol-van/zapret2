pktws_simple_split_tests()
{
	# $1 - test function
	# $2 - domain/uri
	# $3 - splits
	# $4 - PRE args for nfqws2
	local pos ok ok_any pre="$4"
	local splitf splitfs="multisplit $MULTIDISORDER"

	ok_any=0
	for splitf in $splitfs; do
		eval need_$splitf=0
		ok=0
		for pos in $3; do
			pktws_curl_test_update $1 $2 $pre $PAYLOAD --lua-desync=$splitf:pos=$pos && ok=1
		done
		[ "$ok" = 1 -a "$SCANLEVEL" != force ] || eval need_$splitf=1
		[ "$ok" = 1 ] && ok_any=1
	done
	[ "$ok_any" = 1 ]
}


pktws_check_http()
{
	# $1 - test function
	# $2 - domain
	local splits_http='method+2 midsld method+2,midsld'
	local PAYLOAD="--payload http_req"

	[ "$NOTEST_MULTI_HTTP" = 1 ] && { echo "SKIPPED"; return; }

	pktws_simple_split_tests "$1" "$2" "$splits_http"
}

pktws_check_https_tls()
{
	# $1 - test function
	# $2 - domain
	# $3 - PRE args for nfqws2
	local splits_tls='2 1 sniext+1 sniext+4 host+1 midsld 1,midsld 1,midsld,1220 1,sniext+1,host+1,midsld-2,midsld,midsld+2,endhost-1'
	local PAYLOAD="--payload tls_client_hello"

	[ "$NOTEST_MULTI_HTTPS" = 1 ] && { echo "SKIPPED"; return; }

	pktws_simple_split_tests "$1" "$2" "$splits_tls" "$3"
}

pktws_check_https_tls12()
{
	# $1 - test function
	# $2 - domain
	pktws_check_https_tls "$1" "$2" && [ "$SCANLEVEL" != force ] && return

	# do not use 'need' values obtained with wssize
	local need_multisplit_save=$need_multisplit need_multidisorder_save=$need_multidisorder
	pktws_check_https_tls "$1" "$2" --lua-desync=wssize:wsize=1:scale=6
	need_multisplit=$need_multisplit_save; need_multidisorder=$need_multidisorder_save
}

pktws_check_https_tls13()
{
	# $1 - test function
	# $2 - domain
	pktws_check_https_tls "$1" "$2"
}
