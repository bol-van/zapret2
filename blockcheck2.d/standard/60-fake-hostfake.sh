. "$TESTDIR/def.inc"

pktws_hostfake_vary_()
{
	local testf=$1 domain="$2" fooling="$3" pre="$4" post="$5" disorder
	shift; shift; shift

	for disorder in '' 'disorder_after:'; do
		pktws_curl_test_update $testf $domain $pre ${FAKE:+--blob=$fake:@"$FAKE" }$PAYLOAD --lua-desync=fake:blob=$fake:$fooling:repeats=$FAKE_REPEATS --lua-desync=hostfakesplit:${HOSTFAKE:+host=${HOSTFAKE}:}${disorder}$fooling:repeats=$FAKE_REPEATS $post && ok=1
		[ "$ok" = 1 -a "$SCANLEVEL" = veryquick ] && return 0
		pktws_curl_test_update $testf $domain $pre ${FAKE:+--blob=$fake:@"$FAKE" }$PAYLOAD --lua-desync=fake:blob=$fake:$fooling:repeats=$FAKE_REPEATS --lua-desync=hostfakesplit:${HOSTFAKE:+host=${HOSTFAKE}:}${disorder}nofake1:$fooling:repeats=$FAKE_REPEATS $post && ok=1
		[ "$ok" = 1 -a "$SCANLEVEL" = veryquick ] && return 0
		pktws_curl_test_update $testf $domain $pre ${FAKE:+--blob=$fake:@"$FAKE" }$PAYLOAD --lua-desync=fake:blob=$fake:$fooling:repeats=$FAKE_REPEATS --lua-desync=hostfakesplit:${HOSTFAKE:+host=${HOSTFAKE}:}${disorder}nofake2:$fooling:repeats=$FAKE_REPEATS $post && ok=1
		[ "$ok" = 1 -a "$SCANLEVEL" = veryquick ] && return 0
		pktws_curl_test_update $testf $domain $pre ${FAKE:+--blob=$fake:@"$FAKE" }$PAYLOAD --lua-desync=fake:blob=$fake:$fooling:repeats=$FAKE_REPEATS --lua-desync=hostfakesplit:${HOSTFAKE:+host=${HOSTFAKE}:}${disorder}midhost=midsld:$fooling:repeats=$FAKE_REPEATS $post && ok=1
		[ "$ok" = 1 -a "$SCANLEVEL" = veryquick ] && return 0
		pktws_curl_test_update $testf $domain $pre ${FAKE:+--blob=$fake:@"$FAKE" }$PAYLOAD --lua-desync=fake:blob=$fake:$fooling:repeats=$FAKE_REPEATS --lua-desync=hostfakesplit:${HOSTFAKE:+host=${HOSTFAKE}:}${disorder}nofake1:midhost=midsld:$fooling:repeats=$FAKE_REPEATS $post && ok=1
		[ "$ok" = 1 -a "$SCANLEVEL" = veryquick ] && return 0
		pktws_curl_test_update $testf $domain $pre ${FAKE:+--blob=$fake:@"$FAKE" }$PAYLOAD --lua-desync=fake:blob=$fake:$fooling:repeats=$FAKE_REPEATS --lua-desync=hostfakesplit:${HOSTFAKE:+host=${HOSTFAKE}:}${disorder}nofake2:midhost=midsld:$fooling:repeats=$FAKE_REPEATS $post && ok=1
		[ "$ok" = 1 -a "$SCANLEVEL" = veryquick ] && return 0
	done
}
pktws_hostfake_vary()
{
	local fooling="$3"
	pktws_hostfake_vary_ "$1" "$2" "$3" "$4" "$5"
	# duplicate SYN with MD5
	contains "$fooling" tcp_md5 && \
		pktws_hostfake_vary_  "$1" "$2" "$3" "$4" "${5:+$5 }--payload=empty --out-range=<s1 --lua-desync=send:$TCP_MD5"
}

pktws_check_hostfake()
{
	# $1 - test function
	# $2 - domain
	# $3 - PRE args for nfqws2
	local testf=$1 domain="$2" pre="$3"
	local ok ttls attls f fooling

	[ "$need_hostfakesplit" = 0 ] && return 0

	[ "$MAX_TTL" = 0 ] || ttls=$(seq -s ' ' $MIN_TTL $MAX_TTL)
	[ "$MAX_AUTOTTL_DELTA" = 0 ] || attls=$(seq -s ' ' $MIN_AUTOTTL_DELTA $MAX_AUTOTTL_DELTA)

	ok=0
	for ttl in $ttls; do
		for f in '' "--payload=empty --out-range=s1<d1 --lua-desync=pktmod:ip${IPVV}_ttl=1"; do
			pktws_hostfake_vary $testf $domain "ip${IPVV}_ttl=$ttl" "$pre" "$f" && {
				ok=1
				[ "$SCANLEVEL" = force ] || break
			}
		done
		[ "$ok" = 1 ] && break
	done
	for fooling in $FOOLINGS_TCP; do
		pktws_hostfake_vary $testf $domain "$fooling" "$pre" && ok=1
		[ "$SCANLEVEL" = veryquick -a "$ok" = 1 ] && break
	done
	for ttl in $attls; do
		for f in '' "--payload=empty --out-range=s1<d1 --lua-desync=pktmod:ip${IPVV}_ttl=1"; do
			pktws_hostfake_vary $testf $domain "ip${IPVV}_autottl=-$ttl,3-20" "$pre" "$f" && {
				ok=1
				[ "$SCANLEVEL" = force ] || break
			}
		done
		[ "$SCANLEVEL" = veryquick -a "$ok" = 1 ] && break
	done
	[ "$ok" = 1 ]
}


pktws_check_http()
{
	[ "$NOTEST_FAKE_HOSTFAKE_HTTP" = 1 ] && { echo "SKIPPED"; return 0; }

	local PAYLOAD="--payload=http_req"
	local FAKE="$FAKE_HTTP"

	if [ -n "$FAKE_HTTP" ]; then
		fake=fake_http
	else
		fake=fake_default_http
	fi

	pktws_check_hostfake "$1" "$2"
}

pktws_check_https_tls()
{
	# $1 - test function
	# $2 - domain
	# $3 - PRE args for nfqws2

	local PAYLOAD="--payload=tls_client_hello"
	local FAKE="$FAKE_HTTPS"

	if [ -n "$FAKE_HTTPS" ]; then
		fake=fake_tls
	else
		fake=fake_default_tls
	fi

	pktws_check_hostfake "$1" "$2" "$3"
}

pktws_check_https_tls12()
{
	# $1 - test function
	# $2 - domain

	[ "$NOTEST_FAKE_HOSTFAKE_HTTPS" = 1 ] && { echo "SKIPPED"; return 0; }

	pktws_check_https_tls "$1" "$2" && [ "$SCANLEVEL" != force ] && return
	pktws_check_https_tls "$1" "$2" --lua-desync=wssize:wsize=1:scale=6
}

pktws_check_https_tls13()
{
	# $1 - test function
	# $2 - domain

	[ "$NOTEST_FAKE_HOSTFAKE_HTTPS" = 1 ] && { echo "SKIPPED"; return 0; }

	pktws_check_https_tls "$1" "$2"
}
