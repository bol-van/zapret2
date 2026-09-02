-- nfqws2 C functions tests
-- to run : --lua-init=@zapret-lib.lua --lua-init=@zapret-tests.lua --lua-init="test_all()"

function test_assert(b)
	assert(b, "test failed")
end

function test_run(tests,...)
	for k,f in pairs(tests) do
		f(...)
	end
end


function test_all(...)
	test_run({
		test_crypto, test_bin, test_time, test_gzip, test_ipstr, test_dissect, test_csum, test_resolve,
		test_get_source_ip, test_ifaddrs, test_rawsend, test_timer},...)
end


function test_crypto(...)
	test_run({test_random, test_bop, test_aes, test_aes_gcm, test_aes_ctr, test_hkdf, test_hash},...)
end

function test_random()
	print("* random")

	local rnds={}
	for i=1,20 do
		local rnd = bcryptorandom(math.random(10,20))
		print("random: "..string2hex(rnd))
		test_assert(not rnds[rnd]) -- should not be repeats
		rnds[rnd] = true
	end
end

function test_bop()
	print("* bop")

	for n,test in ipairs(
		{
			{ fb = bxor, fbit = bitxor, nb = "bxor", nbit="bitxor" },
			{ fb = bor, fbit = bitor, nb = "bor", nbit="bitor" },
			{ fb = band, fbit = bitand, nb = "band", nbit="bitand" }
		}) do
		for k=1,5 do
			local r = {}
			for i=1,6 do r[i] = math.random(0,0xFFFFFFFFFFFF) end
			local v1 = bu48(r[1])..bu48(r[2])..bu48(r[3])
			local v2 = bu48(r[4])..bu48(r[5])..bu48(r[6])
			print("x1     : "..string2hex(v1))
			print("x2     : "..string2hex(v2))
			local v3 = test.fb(v1,v2)
			local v4 = bu48(test.fbit(r[1],r[4]))..bu48(test.fbit(r[2],r[5]))..bu48(test.fbit(r[3],r[6]))
			print(test.nb.."   : "..string2hex(v3))
			print(test.nbit.." : "..string2hex(v4))
			print("result : "..(v3==v4 and "OK" or "FAIL"))
			test_assert(v3==v4)
		end
	end
end

function test_hash()
	print("* hash")

	local hashes={}
	for i=1,5 do
		local rnd = brandom(math.random(5,64))
		print("data:   "..string2hex(rnd))
		for k,sha in pairs({"sha256","sha224"}) do
			local hsh = hash(sha, rnd)
			print(sha..": "..string2hex(hsh))
			local hsh2 = hash(sha, rnd)
			test_assert(hsh==hsh2)
			test_assert(not hashes[hsh])
			hashes[hsh] = true
		end
	end
end

function test_hkdf()
	print("* hkdf")

	local nblob = 2
	local okms = {}
	for nsalt=1,nblob do
		local salt = brandom(math.random(10,20))
		for nikm=1,nblob do
			local ikm = brandom(math.random(5,10))
			for ninfo=1,nblob do
				local info = brandom(math.random(5,10))
				for k,sha in pairs({"sha256","sha224"}) do
					local okm_prev
					for k,okml in pairs({8, 16, 50}) do
						local okm
						print("* hkdf "..sha)
						print("salt: "..string2hex(salt))
						print("ikm : "..string2hex(ikm))
						print("info: "..string2hex(info))
						print("okml: "..tostring(okml))
						okm = hkdf(sha, salt, ikm, info, okml)
						test_assert(okm)
						print("okm: "..string2hex(okm))
						if okms[okm] then
							print("duplicate okm !")
						end
						okms[okm] = true
						test_assert(not okm_prev or okm_prev==string.sub(okm, 1, #okm_prev))
						okm_prev = okm
					end
				end
			end
		end
	end
end

function test_aes()
	print("* aes")

	local clear_text="test "..brandom_az09(11)
	local encrypted, decrypted

	for key_size=16,32,8 do
		local key = brandom(key_size)

		print()
		print("* aes test key_size "..tostring(key_size))

		print("clear text: "..clear_text)

		print("* encrypting")
		encrypted = aes(true, key, clear_text)
		print("encrypted: "..str_or_hex(encrypted))

		print("* decrypting everything good")
		decrypted = aes(false, key, encrypted)
		print("decrypted: "..str_or_hex(decrypted))
		print( decrypted==clear_text and "DECRYPT OK" or "DECRYPT ERROR" )
		test_assert(decrypted==clear_text)

		print("* decrypting bad payload with good key")
		decrypted = aes(false, key, brandom(16))
		print("decrypted: "..str_or_hex(decrypted))
		print( decrypted==clear_text and "DECRYPT OK" or "DECRYPT ERROR" )
		test_assert(decrypted~=clear_text)

		print("* decrypting good payload with bad key")
		decrypted = aes(false, brandom(key_size), encrypted)
		print("decrypted: "..str_or_hex(decrypted))
		print( decrypted==clear_text and "DECRYPT OK" or "DECRYPT ERROR" )
		test_assert(decrypted~=clear_text)

	end
end

function test_aes_gcm()
	print("* aes_gcm")

	local authenticated_data = "authenticated message "..brandom_az09(math.random(10,50))
	local clear_text="test message "..brandom_az09(math.random(10,50))
	local iv, key, encrypted, atag, decrypted, atag2

	for key_size=16,32,8 do
		iv = brandom(12)
		key = brandom(key_size)

		print()
		print("* aes_gcm test key_size "..tostring(key_size))

		print("clear text: "..clear_text)
		print("authenticated data: "..authenticated_data)

		print("* encrypting")
		encrypted, atag = aes_gcm(true, key, iv, clear_text, authenticated_data)
		print("encrypted: "..str_or_hex(encrypted))
		print("auth tag: "..string2hex(atag))

		print("* decrypting everything good")
		decrypted, atag2 = aes_gcm(false, key, iv, encrypted, authenticated_data)
		print("decrypted: "..str_or_hex(decrypted))
		print( decrypted==clear_text and "DECRYPT OK" or "DECRYPT ERROR" )
		test_assert(decrypted==clear_text)
		print("auth tag: "..string2hex(atag2))
		print( atag==atag2 and "TAG OK" or "TAG ERROR" )
		test_assert(atag==atag2)

		print("* decrypting bad payload with good key/iv and correct authentication data")
		decrypted, atag2 = aes_gcm(false, key, iv, brandom(#encrypted), authenticated_data)
		print("decrypted: "..str_or_hex(decrypted))
		print( decrypted==clear_text and "DECRYPT OK" or "DECRYPT ERROR" )
		test_assert(decrypted~=clear_text)
		print("auth tag: "..string2hex(atag2))
		print( atag==atag2 and "TAG OK" or "TAG ERROR" )
		test_assert(atag~=atag2)

		print("* decrypting good payload with good key/iv and incorrect authentication data")
		decrypted, atag2 = aes_gcm(false, key, iv, encrypted, authenticated_data.."x")
		print("decrypted: "..str_or_hex(decrypted))
		print( decrypted==clear_text and "DECRYPT OK" or "DECRYPT ERROR" )
		test_assert(decrypted==clear_text)
		print("auth tag: "..string2hex(atag2))
		print( atag==atag2 and "TAG OK" or "TAG ERROR" )
		test_assert(atag~=atag2)

		print("* decrypting good payload with bad key, good iv and correct authentication data")
		decrypted, atag2 = aes_gcm(false, brandom(key_size), iv, encrypted, authenticated_data)
		print("decrypted: "..str_or_hex(decrypted))
		print( decrypted==clear_text and "DECRYPT OK" or "DECRYPT ERROR" )
		test_assert(decrypted~=clear_text)
		print("auth tag: "..string2hex(atag2))
		print( atag==atag2 and "TAG OK" or "TAG ERROR" )
		test_assert(atag~=atag2)

		print("* decrypting good payload with good key, bad iv and correct authentication data")
		decrypted, atag2 = aes_gcm(false, key, brandom(12), encrypted, authenticated_data)
		print("decrypted: "..str_or_hex(decrypted))
		print( decrypted==clear_text and "DECRYPT OK" or "DECRYPT ERROR" )
		test_assert(decrypted~=clear_text)
		print("auth tag: "..string2hex(atag2))
		print( atag==atag2 and "TAG OK" or "TAG ERROR" )
		test_assert(atag~=atag2)
	end
end

function test_aes_ctr()
	print("* aes_ctr")

	local clear_text="test message "..brandom_az09(math.random(10,50))
	local iv, key, encrypted, decrypted

	for key_size=16,32,8 do
		iv = brandom(16)
		key = brandom(key_size)

		print()
		print("* aes_ctr test key_size "..tostring(key_size))

		print("clear text: "..clear_text)

		print("* encrypting")
		encrypted = aes_ctr(key, iv, clear_text)
		print("encrypted: "..str_or_hex(encrypted))

		print("* decrypting")
		decrypted = aes_ctr(key, iv, encrypted)
		print("decrypted: "..str_or_hex(decrypted))
		print( decrypted==clear_text and "DECRYPT OK" or "DECRYPT ERROR" )
		test_assert(decrypted==clear_text)

		print("* decrypting with bad key")
		decrypted = aes_ctr(bu8(bitand(u8(string.sub(key,1,1))+1,0xFF))..string.sub(key,2), iv, encrypted)
		print("decrypted: "..str_or_hex(decrypted))
		print( decrypted==clear_text and "DECRYPT OK" or "DECRYPT ERROR" )
		test_assert(decrypted~=clear_text)

		print("* decrypting with bad iv")
		decrypted = aes_ctr(key, bu8(bitand(u8(string.sub(iv,1,1))+1,0xFF))..string.sub(iv,2), encrypted)
		print("decrypted: "..str_or_hex(decrypted))
		print( decrypted==clear_text and "DECRYPT OK" or "DECRYPT ERROR" )
		test_assert(decrypted~=clear_text)
	end

	-- openssl enc -aes-256-ctr -d -in rnd.bin -out rnd_decrypted.bin -K c39383634d87eb3b6e56edf2c8c0ba99cc8cadf000fb2cd737e37947eecde5fd -iv d745164b233f10b93945526ffe94b87f
	print("* aes_ctr const tests")

	local data="\x9d\x9c\xa0\x78\x2e\x17\x84\xfc\x87\xc7\xf5\xdf\x5b\xb5\x71\xfd\xb9\xcb\xd2\x4d\xae\x2f\xf0\x19\xf3\xad\x79\xa8\x9a\xb4\xed\x28\x88\x3c\xe1\x78\x91\x23\x27\xd4\x8d\x94\xb3\xd0\x81\x88\xd2\x55\x95\x8a\x88\x70\x67\x99\x75\xb2\xee\x30\x0f\xe7\xc6\x32\x10"
	local iv="\xd7\x45\x16\x4b\x23\x3f\x10\xb9\x39\x45\x52\x6f\xfe\x94\xb8\x7f"
	local tests = {
		{
			key="\xc3\x93\x83\x63\x4d\x87\xeb\x3b\x6e\x56\xed\xf2\xc8\xc0\xba\x99\xcc\x8c\xad\xf0\x00\xfb\x2c\xd7\x37\xe3\x79\x47\xee\xcd\xe5\xfd",
			result="\x8C\x2C\x15\x99\x83\x37\x33\xEE\xA1\x70\xA7\x4A\x44\x2E\x6F\x56\x22\x41\xE1\xFC\xC5\x84\x21\x1C\x16\xC6\xE9\x75\x22\x57\x55\x4A\x02\x04\xCE\xAD\xE9\x0A\x45\xAB\x4E\x38\xB8\xB2\x6F\x95\xDA\x46\x4F\x9E\xB1\xFF\xF4\x40\x8A\x57\x25\xD2\xF6\xB6\x93\x65\x75"
		},
		{
			key="\xc3\x93\x83\x63\x4d\x87\xeb\x3b\x6e\x56\xed\xf2\xc8\xc0\xba\x99\xcc\x8c\xad\xf0\x00\xfb\x2c\xd7",
			result="\xB0\x4C\xC9\xDB\x0C\xE5\x67\x51\x1D\x24\x3C\x15\x87\x1B\xF9\x62\x84\x8C\xD0\x57\x33\x93\xE0\x71\x91\x3A\x11\x26\xCA\x77\xA7\x54\xBD\xC6\x5E\x96\x60\x2C\x94\x0F\xBA\x3E\x79\xDC\x48\xA0\x22\x97\xA7\x77\x55\xC8\x14\xEA\xC2\xF5\xA0\x88\x6F\xE2\x44\x32\x68"
		},
		{
			key="\xc3\x93\x83\x63\x4d\x87\xeb\x3b\x6e\x56\xed\xf2\xc8\xc0\xba\x99",
			result="\xD9\xAC\xC7\x7D\xC8\xC9\xF1\x59\x9A\xDF\x15\xF3\x58\x61\xFD\x2B\x1D\x01\x9A\x5F\x04\x53\xA2\xA8\xFD\x52\xDC\x8A\xE9\x3B\x2E\x5E\x0D\x13\xCB\xBD\x16\xED\xC1\xF2\x0D\x68\x62\xB7\xD5\x0F\x8D\xD4\xEB\xA1\xC5\x75\xF2\x0B\x26\x75\x1D\x7E\x5A\x37\xA6\x8A\xCD"
		}
	}
	for k,t in pairs(tests) do
		local decrypted = aes_ctr(t.key, iv, data)
		io.write("KEY SIZE "..(#t.key*8).." ")
		print( decrypted==t.result and "DECRYPT OK" or "DECRYPT ERROR" )
		test_assert(decrypted==t.result)
	end
end

function test_ub()
	print("* ub")

	for k,f in pairs({{u8,bu8,0xFF,8}, {u16,bu16,0xFFFF,16}, {u24,bu24,0xFFFFFF,24}, {u32,bu32,0xFFFFFFFF,32}, {u48,bu48,0xFFFFFFFFFFFF,48}}) do
		local v = math.random(0,f[3])
		local pos = math.random(1,20)
		local s = brandom(pos-1)..f[2](v)..brandom(20)
		local v2 = f[1](s,pos)
		print(string.format("u%u pos=%u %016X %016X",f[4],pos,v,v2))
		test_assert(v==v2)
	end
end

function test_bit()
	print("* bit")

	local v, v2, v3, v4, b1, b2, pow

	for i=1,100 do
		v = math.random(0,0xFFFFFFFFFFFF)
		b1 = math.random(1,16)

		v2 = bitrshift(v, b1)
		pow = 2^b1
		v3 = divint(v, pow)
		print(string.format("rshift(0x%X,%u) = 0x%X  0x%X/%u = 0x%X", v,b1,v2, v,pow,v3))
		test_assert(v2==v3)

		v = math.random(0,0xFFFFFFFFF)
		b1 = math.random(1,12)
		v2 = bitlshift(v, b1)
		pow = 2^b1
		v3 = (v * pow) % 0x1000000000000
		print(string.format("lshift(0x%X,%u) = 0x%X  0x%X*%u %% 0x100000000000 = 0x%X", v,b1,v2, v,pow,v3))
		test_assert(v2==v3)

		v2 = math.random(0,0xFFFFFFFFFFFF)
		v3 = bitxor(v, v2)
		v4 = bitor(v, v2) - bitand(v, v2)
		print(string.format("xor(0x%X,0x%X) = %X  or/and/minus = %X", v, v2, v3, v4))
		test_assert(v3==v4)

		b1 = math.random(1,31)
		b2 = b1 + math.random(1,16)
		v2 = bitget(v, b1, b2)
		pow = 2^(b2-b1+1) - 1
		v3 = bitand(bitrshift(v,b1), pow)
		print(string.format("bitget(0x%X,%u,%u) = 0x%X  bitand/bitrshift/pow = 0x%X", v, b1, b2, v2, v3))
		test_assert(v2==v3)

		v4 = math.random(0,pow)
		v2 = bitset(v, b1, b2, v4)
		v3 = bitor(bitlshift(v4, b1), bitand(v, bitnot(bitlshift(pow, b1))))
		print(string.format("bitset(0x%X,%u,%u,0x%X) = 0x%X  bitand/bitnot/bitlshift/pow = 0x%X", v, b1, b2, v4, v2, v3))
		test_assert(v2==v3)
	end
end

function test_swap()
	print("* swap")

	local v1, v2, v3

	v1 = math.random(0,0xFFFF)
	v2 = swap16(v1)
	v3 = divint(v1,0x100) + v1%0x100*0x100
	print("swap16: "..(v2==v3 and "OK" or "FAIL"))
	test_assert(v2==v3)

	v1 = math.random(0,0xFFFFFF)
	v2 = swap24(v1)
	v3 = divint(v1,0x10000) + divint(v1,0x100)%0x100*0x100 + v1%0x100*0x10000
	print("swap24: "..(v2==v3 and "OK" or "FAIL"))
	test_assert(v2==v3)

	v1 = math.random(0,0xFFFFFFFF)
	v2 = swap32(v1)
	v3 = divint(v1,0x1000000) + divint(v1,0x10000)%0x100*0x100 + divint(v1,0x100)%0x100*0x10000 + v1%0x100*0x1000000
	print("swap32: "..(v2==v3 and "OK" or "FAIL"))
	test_assert(v2==v3)

	v1 = math.random(0,0xFFFFFFFFFFFF)
	v2 = swap48(v1)
	v3 =    divint(v1,0x10000000000) +
		divint(v1,0x100000000)%0x100*0x100 +
		divint(v1,0x1000000)%0x100*0x10000 +
		divint(v1,0x10000)%0x100*0x1000000 +
		divint(v1,0x100)%0x100*0x100000000 +
		v1%0x100*0x10000000000
	print("swap48: "..(v2==v3 and "OK" or "FAIL"))
	test_assert(v2==v3)
end

function test_ux()
	print("* ux")

	local v1, v2, v3, usum, sum

	for k,test in pairs({
		{ add=u8add, fname="u8add", max = 0xFF },
		{ add=u16add, fname="u16add", max = 0xFFFF },
		{ add=u24add, fname="u24add", max = 0xFFFFFF },
		{ add=u32add, fname="u32add", max = 0xFFFFFFFF },
		{ add=u48add, fname="u48add", max = 0xFFFFFFFFFFFF }
	}) do
		io.write(test.fname.." : ")
		for i=1,1000 do
			v1=math.random(-test.max,test.max)
			v2=math.random(-test.max,test.max)
			v3=math.random(-test.max,test.max)
			usum = test.add(v1,v2,v3)
			sum = bitand((v1+v2+v3)%(test.max+1),test.max)
			if sum~=usum then
				print(string.format("FAIL: 0x%012X + 0x%012X + 0x%012X = 0x%012X 0x%012X",v1,v2,v3,usum,sum))
			end
			test_assert(sum==usum)
		end
		print("OK")
	end
end

function test_bin(...)
	test_run({test_ub, test_bit, test_swap, test_ux},...)
end

function test_time(...)
	print("* time")

	local unixtime=os.time()
	local tm = localtime(unixtime);
	local t
	print()
	print("now: "..tm.str.." "..tm.zone.." = "..unixtime)
	local tm = gmtime(unixtime);
	print("gmt: "..tm.str.." "..tm.zone.." = "..unixtime)
	print()
	for i=1,20 do
		unixtime = math.random(0,0x7FFFFFFF);
		tm = localtime(unixtime);
		t = timelocal(tm)
		print("timelocal: "..tm.str.." "..tm.zone.." = "..t)
		print( t==unixtime and "LOCALTIME OK" or "LOCALTIME FAILED" )
		test_assert(t==unixtime)

		unixtime = math.random(0,0x7FFFFFFF);
		tm = gmtime(unixtime);
		t = timegm(tm)
		print("timegm: "..tm.str.." "..tm.zone.." = "..t)
		print( t==unixtime and "GMTIME OK" or "GMTIME FAILED" )
		test_assert(t==unixtime)
	end
	unixtime = math.random(0x80000000,0xFFFFFFFF);
	tm = gmtime(unixtime)
	t = timegm(tm)
	print( t==unixtime and "TIME 0x80000000..0xFFFFFFFF OK" or "TIME 0x80000000..0xFFFFFFFF FAILED : "..unixtime.." != "..t.." ("..tm.str..")" )
	unixtime = math.random(0x100000000,0x200000000);
	tm = gmtime(unixtime)
	t = timegm(tm)
	print( t==unixtime and "TIME 64 OK" or "TIME 64 FAILED : "..unixtime.." != "..t.." ("..tm.str..")" )
end

function test_gzip()
	print("* gzip")

	local s=""
	for i=1,math.random(2000,3000) do
		local rnd=brandom(math.random(1,50))
		s=s..rnd..string.rep(bu8(math.random(0,255)),100-#rnd)
	end
	local v=math.random(100001,199999)
	local level=math.random(1,9)
	local memlevel=math.random(1,8)
	print("gzip: original size "..#s)
	print("gzip: cut point "..(v+1))
	print("gzip: level "..level)
	print("gzip: memlevel "..memlevel)
	local gz = gzip_init(nil, level, memlevel)
	local zip = gzip_deflate(gz,string.sub(s,1,v))
	zip = zip..gzip_deflate(gz,string.sub(s,v+1))
	zip = zip..gzip_deflate(gz,nil) -- finalize
	gzip_end(gz)
	print("gzip: deflated size "..#zip)
	local v=math.random(2,#zip-1)
	print("gunzip: cut point "..(v+1))
	gz = gunzip_init()
	local unzip = gunzip_inflate(gz,string.sub(zip,1,v))
	unzip = unzip..gunzip_inflate(gz,string.sub(zip,v+1))
	gunzip_end(gz)
	print("gunzip: inflated size "..#unzip)
	print("gzip+gunzip: "..(s==unzip and "OK" or "FAIL"))
	test_assert(s==unzip)
end

function test_ipstr()
	print("* ipstr")

	local s_ip, ip, s_ip2

	s_ip = string.format("%u.%u.%u.%u", math.random(0,255), math.random(0,255), math.random(0,255), math.random(0,255))
	ip = pton(s_ip)
	s_ip2 = ntop(ip)
	print("IP: "..s_ip)
	print("IPBIN: "..string2hex(ip))
	print("IP2: "..s_ip2)
	test_assert(s_ip==s_ip2)

	s_ip = string.format("%x:%x:%x:%x:%x:%x:%x:%x", math.random(1,0xFFFF), math.random(1,0xFFFF), math.random(1,0xFFFF), math.random(1,0xFFFF), math.random(1,0xFFFF), math.random(1,0xFFFF), math.random(1,0xFFFF), math.random(1,0xFFFF))
	ip = pton(s_ip)
	s_ip2 = ntop(ip)
	print("IP: "..s_ip)
	print("IPBIN: "..string2hex(ip))
	print("IP2: "..s_ip2)
	test_assert(s_ip==s_ip2)
end


function test_dissect()
	print("* dissect")

	local raw1, raw2

	for i=1,20 do
		print("* dissect test "..tostring(i))

		local ip_tcp = {
			ip = {
				ip_tos = math.random(0,255),
				ip_id = math.random(0,0xFFFF),
				ip_off = 0,
				ip_ttl = math.random(0,255),
				ip_p = IPPROTO_TCP,
				ip_src = brandom(4),
				ip_dst = brandom(4),
				options = brandom(math.random(0,40))
			},
			tcp = {
				th_sport = math.random(0,0xFFFF),
				th_dport = math.random(0,0xFFFF),
				th_seq = math.random(0,0xFFFFFFFF),
				th_ack = math.random(0,0xFFFFFFFF),
				th_x2 = math.random(0,0xF),
				th_flags = math.random(0,0xFF),
				th_win = math.random(0,0xFFFF),
				th_urp = math.random(0,0xFFFF),
				options = {
					{ kind = 1 },
					{ kind = 0xE0, data = brandom(math.random(1,10)) },
					{ kind = 1 },
					{ kind = 0xE1, data = brandom(math.random(1,10)) }
				}
			},
			payload = brandom(math.random(0, 20))
		}
		raw1 = reconstruct_dissect(ip_tcp)
		print("IP+TCP : "..string2hex(raw1))
		dis1 = dissect(raw1)
		raw2 = reconstruct_dissect(dis1)
		dis2 = dissect(raw2)
		print("IP+TCP2: "..string2hex(raw2))
		print( raw1==raw2 and "DISSECT OK" or "DISSECT FAILED" )
		test_assert(raw1==raw2)

		print("IP standalone")
		raw1 = reconstruct_iphdr(ip_tcp.ip)
		print("IP1: "..string2hex(raw1))
		dis1 = dissect_iphdr(raw1)
		raw2 = reconstruct_iphdr(dis1)
		print("IP2: "..string2hex(raw2))
		print( raw1==raw2 and "DISSECT OK" or "DISSECT FAILED" )
		test_assert(raw1==raw2)

		print("TCP standalone")
		raw1 = reconstruct_tcphdr(ip_tcp.tcp)
		print("TCP1: "..string2hex(raw1))
		dis1 = dissect_tcphdr(raw1)
		raw2 = reconstruct_tcphdr(dis1)
		print("TCP2: "..string2hex(raw2))
		print( raw1==raw2 and "DISSECT OK" or "DISSECT FAILED" )
		test_assert(raw1==raw2)

		local ip_icmp = {
			ip = {
				ip_tos = math.random(0,255),
				ip_id = math.random(0,0xFFFF),
				ip_off = 0,
				ip_ttl = math.random(0,255),
				ip_p = IPPROTO_ICMP,
				ip_src = brandom(4),
				ip_dst = brandom(4),
				options = brandom(math.random(0,40))
			},
			icmp = {
				icmp_type = ICMP_DEST_UNREACH, icmp_code=ICMP_UNREACH_PORT,
				icmp_data = math.random(1,0xFFFFFFFF)
			}
		}
		print("ICMP standalone")
		raw1 = reconstruct_icmphdr(ip_icmp.icmp)
		print("ICMP1: "..string2hex(raw1))
		dis1 = dissect_icmphdr(raw1)
		raw2 = reconstruct_icmphdr(dis1)
		print("ICMP2: "..string2hex(raw2))
		print( raw1==raw2 and "DISSECT OK" or "DISSECT FAILED" )
		test_assert(raw1==raw2)

		local ip6_udp = {
			ip6 = {
				ip6_flow = 0x60000000 + math.random(0,0xFFFFFFF),
				ip6_hlim = math.random(1,0xFF),
				ip6_src = brandom(16),
				ip6_dst = brandom(16),
				exthdr = {
					{ type = IPPROTO_HOPOPTS, data = brandom(6+8*math.random(0,2)) },
					{ type = IPPROTO_AH, data = brandom(6+4*math.random(0,4)) }
				}
			},
			udp = {
				uh_sport = math.random(0,0xFFFF),
				uh_dport = math.random(0,0xFFFF)
			},
			payload = brandom(math.random(0, 20))
		}

		raw1 = reconstruct_dissect(ip6_udp)
		print("IP6+UDP : "..string2hex(raw1))
		dis1 = dissect(raw1)
		raw2 = reconstruct_dissect(dis1)
		dis2 = dissect(raw2)
		print("IP6+UDP2: "..string2hex(raw2))
		print( raw1==raw2 and "DISSECT OK" or "DISSECT FAILED" )
		test_assert(raw1==raw2)

		raw1 = string.sub(reconstruct_dissect(ip6_udp),1,-4-#ip6_udp.payload)
		dis1 = dissect(raw1, false)
		dis2 = dissect(raw1, true)
		local ok = not dis1.ip6 and dis2.ip6
		print("IP6 partial : "..(ok and "OK" or "FAIL"))
		test_assert(ok)

		print("IP6+IPP")
		dis1 = {ip6 = ip6_udp.ip6, payload=brandom(math.random(1,1))}
		raw1 = reconstruct_dissect(dis1,{ip6_last_proto=IPPROTO_IPIP})
		dis2 = dissect(raw1)
		raw2 = reconstruct_dissect(dis2,{ip6_preserve_next=true})
		print("IP6+IPP1: "..string2hex(raw1))
		print("IP6+IPP2: "..string2hex(raw2))
		print( raw1==raw2 and "DISSECT OK" or "DISSECT FAILED" )
		test_assert(raw1==raw2)

		print("UDP standalone")
		raw1 = reconstruct_udphdr(ip6_udp.udp)
		print("UDP1: "..string2hex(raw1))
		dis1 = dissect_udphdr(raw1)
		raw2 = reconstruct_udphdr(dis1)
		print("UDP2: "..string2hex(raw2))
		print( raw1==raw2 and "DISSECT OK" or "DISSECT FAILED" )
		test_assert(raw1==raw2)

		print("IP6 standalone")
		ip6_udp.ip6.ip6_plen = nil
		raw1 = reconstruct_ip6hdr(ip6_udp.ip6,{ip6_last_proto=IPPROTO_UDP})
		print("IP1: "..string2hex(raw1))
		dis1 = dissect_ip6hdr(raw1)
		raw2 = reconstruct_ip6hdr(dis1,{ip6_last_proto=IPPROTO_UDP})
		print("IP2: "..string2hex(raw2))
		print( raw1==raw2 and "DISSECT OK" or "DISSECT FAILED" )
		test_assert(raw1==raw2)
	end
end

function test_csum()
	print("* csum")

	local payload = brandom(math.random(10,20))
	local ip4b, ip6b, raw, tcpb, udpb, icmpb, dis1, dis2
	local ip = {
		ip_tos = math.random(0,255),
		ip_id = math.random(0,0xFFFF),
		ip_len = math.random(0,0xFFFF),
		ip_off = 0,
		ip_ttl = math.random(0,255),
		ip_p = IPPROTO_TCP,
		ip_src = brandom(4),
		ip_dst = brandom(4),
		options = brandom(4*math.random(0,10))
	}
	ip4b = reconstruct_iphdr(ip)
	raw =	bu8(0x40 + 5 + #ip.options/4) ..
		bu8(ip.ip_tos) ..
		bu16(ip.ip_len) ..
		bu16(ip.ip_id) ..
		bu16(ip.ip_off) ..
		bu8(ip.ip_ttl) ..
		bu8(ip.ip_p) ..
		bu16(0) ..
		ip.ip_src .. ip.ip_dst ..
		ip.options
	raw = csum_ip4_fix(raw)
	print( raw==ip4b and "IP4 RECONSTRUCT+CSUM OK" or "IP4 RECONSTRUCT+CSUM FAILED" )
	test_assert(raw==ip4b)


	local tcp = {
		th_sport = math.random(0,0xFFFF),
		th_dport = math.random(0,0xFFFF),
		th_seq = math.random(0,0xFFFFFFFF),
		th_ack = math.random(0,0xFFFFFFFF),
		th_x2 = math.random(0,0xF),
		th_flags = math.random(0,0xFF),
		th_win = math.random(0,0xFFFF),
		th_urp = math.random(0,0xFFFF),
		options = {
			{ kind = 1 },
			{ kind = 0xE0, data = brandom(math.random(1,10)) },
			{ kind = 1 },
			{ kind = 0xE1, data = brandom(math.random(1,10)) }
		}
	}
	tcpb = reconstruct_tcphdr(tcp)
	raw =	bu16(tcp.th_sport) ..
		bu16(tcp.th_dport) ..
		bu32(tcp.th_seq) ..
		bu32(tcp.th_ack) ..
		bu8(l4_len({tcp = tcp}) * 4 + tcp.th_x2) ..
		bu8(tcp.th_flags) ..
		bu16(tcp.th_win) ..
		bu16(0) ..
		bu16(tcp.th_urp) ..
		bu8(tcp.options[1].kind)..
		bu8(tcp.options[2].kind)..bu8(2 + #tcp.options[2].data)..tcp.options[2].data ..
		bu8(tcp.options[3].kind)..
		bu8(tcp.options[4].kind)..bu8(2 + #tcp.options[4].data)..tcp.options[4].data
	raw = raw .. string.rep(bu8(0), bitand(4-bitand(#raw,3),3))
	print( raw==tcpb and "TCP RECONSTRUCT OK" or "TCP RECONSTRUCT FAILED" )
	test_assert(raw==tcpb)

	raw = reconstruct_dissect({ip=ip, tcp=tcp, payload=payload})
	dis1 = dissect(raw)
	ip.ip_len = IP_BASE_LEN + #ip.options + #tcpb + #payload
	ip4b = reconstruct_iphdr(ip)
	tcpb = csum_tcp_fix(ip4b,tcpb,payload)
	dis2 = dissect(ip4b..tcpb..payload)
	print( dis1.tcp.th_sum==dis2.tcp.th_sum and "TCP+IP4 CSUM OK" or "TCP+IP4 CSUM FAILED" )
	test_assert(dis1.tcp.th_sum==dis2.tcp.th_sum)


	local ip6 = {
		ip6_flow = 0x60000000 + math.random(0,0xFFFFFFF),
		ip6_hlim = math.random(1,0xFF),
		ip6_src = brandom(16),
		ip6_dst = brandom(16),
		exthdr = {
			{ type = IPPROTO_HOPOPTS, data = brandom(6+8*math.random(0,2)) }
		}
	}
	ip6.ip6_plen = packet_len({ip6=ip6,tcp=tcp,payload=payload}) - IP6_BASE_LEN
	ip6b = reconstruct_ip6hdr(ip6, {ip6_last_proto=IPPROTO_TCP})
	raw =	bu32(ip6.ip6_flow) ..
		bu16(ip6.ip6_plen) ..
		bu8(ip6.exthdr[1].type) ..
		bu8(ip6.ip6_hlim) ..
		ip6.ip6_src .. ip6.ip6_dst ..
		bu8(IPPROTO_TCP) ..
		bu8((#ip6.exthdr[1].data+2)/8 - 1) ..
		ip6.exthdr[1].data
	print( raw==ip6b and "IP6 RECONSTRUCT OK" or "IP6 RECONSTRUCT FAILED" )
	test_assert(raw==ip6b)

	raw = reconstruct_dissect({ip6=ip6, tcp=tcp, payload=payload})
	dis1 = dissect(raw)
	tcpb = csum_tcp_fix(ip6b,tcpb,payload)
	dis2 = dissect(ip6b..tcpb..payload)
	print( dis1.tcp.th_sum==dis2.tcp.th_sum and "TCP+IP6 CSUM OK" or "TCP+IP6 CSUM FAILED" )
	test_assert(dis1.tcp.th_sum==dis2.tcp.th_sum)

	local udp = {
		uh_sport = math.random(0,0xFFFF),
		uh_dport = math.random(0,0xFFFF),
		uh_ulen = UDP_BASE_LEN + #payload
	}

	udpb = reconstruct_udphdr(udp)
	raw =	bu16(udp.uh_sport) ..
		bu16(udp.uh_dport) ..
		bu16(udp.uh_ulen) ..
		bu16(0)
	print( raw==udpb and "UDP RECONSTRUCT OK" or "UDP RECONSTRUCT FAILED" )
	test_assert(raw==udpb)

	ip.ip_p = IPPROTO_UDP
	raw = reconstruct_dissect({ip=ip, udp=udp, payload=payload})
	dis1 = dissect(raw)
	ip.ip_p = IPPROTO_UDP
	ip.ip_len = IP_BASE_LEN + #ip.options + #udpb + #payload
	ip4b = reconstruct_iphdr(ip)
	udpb = csum_udp_fix(ip4b,udpb,payload)
	dis2 = dissect(ip4b..udpb..payload)
	print( dis1.udp.uh_sum==dis2.udp.uh_sum and "UDP+IP4 CSUM OK" or "UDP+IP4 CSUM FAILED" )
	test_assert(dis1.udp.uh_sum==dis2.udp.uh_sum)

	ip6.ip6_plen = packet_len({ip6=ip6,udp=udp,payload=payload}) - IP6_BASE_LEN
	ip6b = reconstruct_ip6hdr(ip6, {ip6_last_proto=IPPROTO_UDP})
	raw = reconstruct_dissect({ip6=ip6, udp=udp, payload=payload})
	dis1 = dissect(raw)
	udpb = csum_udp_fix(ip6b,udpb,payload)
	dis2 = dissect(ip6b..udpb..payload)
	print( dis1.udp.uh_sum==dis2.udp.uh_sum and "UDP+IP6 CSUM OK" or "UDP+IP6 CSUM FAILED" )
	test_assert(dis1.udp.uh_sum==dis2.udp.uh_sum)

	local icmp = {
		icmp_type = math.random(0,0xFF), icmp_code=math.random(0,0xFF),
		icmp_data = math.random(0,0xFFFFFFFF)
	}
	ip.ip_p = IPPROTO_ICMP
	ip4b = reconstruct_iphdr(ip)
	ip6.ip6_plen = packet_len({ip6=ip6,icmp=icmp,payload=payload}) - IP6_BASE_LEN
	ip6b = reconstruct_ip6hdr(ip6, {ip6_last_proto=IPPROTO_ICMPV6})

	icmpb = reconstruct_icmphdr(icmp)
	raw =	bu8(icmp.icmp_type) ..
		bu8(icmp.icmp_code) ..
		bu16(0) ..
		bu32(icmp.icmp_data)
	print( raw==icmpb and "ICMP RECONSTRUCT OK" or "ICMP RECONSTRUCT FAILED" )
	test_assert(raw==icmpb)

	raw = reconstruct_dissect({ip=ip, icmp=icmp, payload=payload})
	dis1 = dissect(raw)
	icmpb = csum_icmp_fix(ip4b,icmpb,payload)
	dis2 = dissect(ip4b..icmpb..payload)
	print( dis1.icmp.icmp_cksum==dis2.icmp.icmp_cksum and "ICMP+IP4 CSUM OK" or "ICMP+IP4 CSUM FAILED" )
	test_assert(dis1.icmp.icmp_cksum==dis2.icmp.icmp_cksum)

	raw = reconstruct_dissect({ip6=ip6, icmp=icmp, payload=payload})
	dis1 = dissect(raw)
	icmpb = csum_icmp_fix(ip6b,icmpb,payload)
	dis2 = dissect(ip6b..icmpb..payload)
	print( dis1.icmp.icmp_cksum==dis2.icmp.icmp_cksum and "ICMP+IP6 CSUM OK" or "ICMP+IP6 CSUM FAILED" )
	test_assert(dis1.icmp.icmp_cksum==dis2.icmp.icmp_cksum)
end

function test_resolve()
	print("* resolve")

	local pos

	local tdis = tls_dissect(fake_default_tls)
	local extlen_pos = 5 + 6 + 32 + 1 + 2 + 1 + #tdis.handshake[TLS_HANDSHAKE_TYPE_CLIENT].dis.session_id + #tdis.handshake[TLS_HANDSHAKE_TYPE_CLIENT].dis.cipher_suites*2 + #tdis.handshake[TLS_HANDSHAKE_TYPE_CLIENT].dis.compression_methods
	print("fake_default_tls size "..#fake_default_tls.." extlen="..extlen_pos)
	local m="1,extlen,sniext,host,sld,midsld,endsld,endhost,-5"
	pos = resolve_multi_pos(fake_default_tls,"tls_client_hello",m,true)
	test_assert(pos)
	print("resolve_multi_pos tls : "..m.." : "..table.concat(pos," "))
	m = "host,endhost"
	pos = resolve_range(fake_default_tls,"tls_client_hello",m,false,true)
	test_assert(pos)
	print("resolve_range tls : "..m.." : "..table.concat(pos," "))
	m = "1"
	pos = resolve_pos(fake_default_tls,"tls_client_hello",m,true)
	test_assert(pos==1)
	print("resolve_pos tls : "..m.." : "..pos)
	m = "-1"
	pos = resolve_pos(fake_default_tls,"tls_client_hello",m,true)
	test_assert(pos==(#fake_default_tls-1))
	print("resolve_pos tls : "..m.." : "..pos)
	m = "extlen"
	pos = resolve_pos(fake_default_tls,"tls_client_hello",m,true)
	test_assert(pos==extlen_pos)
	print("resolve_pos tls : "..m.." : "..pos)
	m = "midsld"
	pos = resolve_pos(fake_default_tls,"tls_client_hello",m,true)
	test_assert(pos)
	print("resolve_pos tls : "..m.." : "..pos)
	m = "method"
	pos = resolve_pos(fake_default_tls,"tls_client_hello",m,true)
	test_assert(not pos)
	print("resolve_pos tls non-existent : "..m.." : "..tostring(pos))

	local host_pos = string.find(fake_default_http,"Host: ")+6-1
	print("fake_default_http size "..#fake_default_http.." host="..host_pos)
	m = "method,host,sld,midsld,endsld,endhost,-5"
	pos = resolve_multi_pos(fake_default_http,"http_req",m,true)
	test_assert(pos)
	test_assert(pos[1]==0)
	test_assert(pos[2]==host_pos)
	print("resolve_multi_pos http : "..m.." : "..table.concat(pos," "))
	m = "sniext"
	pos = resolve_pos(fake_default_http,"http_req",m,true)
	test_assert(not pos)
	print("resolve_pos http non-existent : "..m.." : "..tostring(pos))
end

function test_get_source_ip(opts)
	print("* get_source_ip")

	for k,d in ipairs({
		'127.0.0.1','192.168.1.1','10.1.1.1','1.1.1.1','255.255.255.255',
		'::1','fc81::4','2a06::1','2001:470::1','2002:0101:0101::1','::1.1.1.1'})
	do
		local src = get_source_ip(pton(d))
		print((src and ntop(src) or "?").." => "..d)
	end
end
function test_ifaddrs(opts)
	print("* ifaddrs")

	local ifa = get_ifaddrs()
	test_assert(ifa)
	for ifname,ifinfo in pairs(ifa) do
		print(ifname.." index="..tostring(ifinfo.index).." mtu="..tostring(ifinfo.mtu))
		for i,addr in ipairs(ifinfo.addr) do
			print(" "..ntop(addr.addr)..(addr.netmask and " mask "..tostring(ntop(addr.netmask)) or ""))
		end
	end
end

function print_current_time()
	local sec,nsec = clock_gettime()
	local t = sec + nsec/1000000000;
	print("time: "..t)
end
function timer_info_print(tinfo)
	print(" timer_info.name="..tinfo.name)
	print(" timer_info.period="..tinfo.period)
	print(" timer_info.oneshot="..tostring(tinfo.oneshot))
	print(" timer_info.fires="..tinfo.fires)
end
function timer_info_print_by_name(name)
	local tinfo = timer_info(name)
	timer_info_print(tinfo)
end

function timer1(name, data)
	print("timer "..name.." fired. data="..tostring(data))
	print_current_time()
	timer_info_print_by_name(name)
end
function timer2(name, data)
	data.n = data.n+1
	print("timer "..name.." fired. data.n="..tostring(data.n))
	print_current_time()
	timer_info_print_by_name(name)
	if data.n>=4 then
		timer_del(name)
	end
end
function test_timer(opts)
	-- anonymous function
	timer_set("t0",function(name,data)
		print("timer "..name.." fired. anonymous timer function")
		print_current_time()
		end,
		100,true)

	-- pass function as function
	timer_set("t1",timer1,500,true,"sample_data");
	local tbl = {n=0}
	-- pass function through string name
	timer_set("t2","timer2",700,false,tbl);

	print("* timers\n")
	local timers=timer_enum()
	for i,name in ipairs(timers) do
		print("TIMER "..i.." :")
		timer_info_print_by_name(name)
	end
	print_current_time()
	print()
end


function test_rawsend(opts)
	print("* rawsend")

	local ifout = (opts and opts.ifout) and opts.ifout
	local function rawsend_fail_warning()
		if not opts or not opts.ifout or #opts.ifout==0 then
			local un = uname()
			if string.sub(un.sysname,1,6)=="CYGWIN" then
				print("windivert requires interface name in the form '<int>.<int>'. take it from winws2 output with '--debug' option and call test_rawsend({ifout=interface_name})")
			end
		end
	end
	local function rawsend_dissect_print(dis, options, reconstruct)
		if options then
			options.ifout = ifout
		else
			options = { ifout = ifout }
		end
		local b = rawsend_dissect(dis, options, reconstruct)
		if not b then
			print("rawsend_dissect failed")
			rawsend_fail_warning()
		end
		return b
	end
	local function rawsend_print(raw, options)
		if options then
			options.ifout = ifout
		else
			options = { ifout = ifout }
		end
		print("rawsend: "..string2hex(raw))
		local b = rawsend(raw, options)
		if not b then
			print("rawsend failed")
			rawsend_fail_warning()
		end
		return b
	end
	local ip, ip6, udp, dis, ddis, raw_ip, raw_udp, raw
	local payload = brandom(math.random(100,1200))

	local target
	for ifname,ifinfo in pairs(get_ifaddrs()) do
		for k,v in pairs(ifinfo.addr) do
			if #v.addr==4 and string.sub(v.addr,1,2)=="\xC0\xA8" then
				target = string.sub(v.addr,1,3)..bu8(u8add(u8(v.addr,4),1))
				break
			end
		end
	end
	target = target or pton("192.168.254.32")
	print("ipv4 target is "..ntop(target))
	ip = {
		ip_tos = 0,
		ip_id = math.random(0,0xFFFF),
		ip_off = 0,
		ip_ttl = 1,
		ip_p = IPPROTO_UDP,
		ip_src = get_source_ip(target),
		ip_dst = target
	}
	if not ip.ip_src then
		print("dest "..ntop(target).." unreachable")
		test_assert(false)
	end
	udp = {
		uh_sport = math.random(0,0xFFFF),
		uh_dport = math.random(0,0xFFFF)
	}
	dis = {ip = ip, udp = udp, payload = payload}
	print("send ipv4 udp")
	test_assert(rawsend_dissect_print(dis, {repeats=3}))
	ddis = ipfrag2(dis, {ipfrag_pos_udp = 80})
	for k,d in pairs(ddis) do
		print("send ipv4 udp frag "..k)
		test_assert(rawsend_dissect_print(d))
	end

	local ip2=ip
	ip2.ip_len = IP_BASE_LEN + UDP_BASE_LEN + #payload
	raw_ip = reconstruct_iphdr(ip2)
	raw_udp = reconstruct_udphdr({uh_sport = udp.uh_sport, uh_dport = udp.uh_dport, uh_ulen = UDP_BASE_LEN + #payload})
	raw_udp = csum_udp_fix(raw_ip,raw_udp,payload)
	raw = raw_ip .. raw_udp .. payload
	print("send ipv4 udp using pure rawsend without dissect")
	test_assert(rawsend_print(raw, {repeats=5}))

	for ifname,ifinfo in pairs(get_ifaddrs()) do
		for k,v in pairs(ifinfo.addr) do
			if #v.addr==16 and (string.sub(v.addr,1,1)=="\xFC" or string.sub(v.addr,1,1)=="\xFD") then
				target = string.sub(v.addr,1,1)..bu8(u8add(u8(v.addr,2),1))..string.sub(v.addr,3)
				break
			end
		end
	end
	target = target or pton("fdce:3124:164a:5318::2")
	print("ipv6 target is "..ntop(target))
	ip6 = {
		ip6_flow = 0x60000000,
		ip6_hlim = 1,
		ip6_src = get_source_ip(target),
		ip6_dst = target
	}
	if not ip6.ip6_src then
		print("dest "..ntop(target).." unreachable")
		test_assert(false)
	end
	dis = {ip6 = ip6, udp = udp, payload = payload}
	print("send ipv6 udp")
	test_assert(rawsend_dissect_print(dis, {repeats=3}))

	ip2 = deepcopy(ip6)
	ip2.ip6_plen = UDP_BASE_LEN + #payload
	raw_ip = reconstruct_ip6hdr(ip2, {ip6_last_proto = IPPROTO_UDP})
	raw_udp = reconstruct_udphdr({uh_sport = udp.uh_sport, uh_dport = udp.uh_dport, uh_ulen = UDP_BASE_LEN + #payload})
	raw_udp = csum_udp_fix(raw_ip,raw_udp,payload)
	raw = raw_ip .. raw_udp .. payload
	print("send ipv6 udp using pure rawsend without dissect")
	test_assert(rawsend_print(raw, {repeats=7}))

	ddis = ipfrag2(dis, {ipfrag_pos_udp = 80})
	for k,d in ipairs(ddis) do
		print("send ipv6 udp frag "..k)
		test_assert(rawsend_dissect_print(d))
	end

	ip6.exthdr={{ type = IPPROTO_HOPOPTS, data = "\x00\x00\x00\x00\x00\x00" }}
	print("send ipv6 udp with hopbyhop ext header")
	test_assert(rawsend_dissect_print(dis, {repeats=3}))

	ddis = ipfrag2(dis, {ipfrag_pos_udp = 80})
	for k,d in ipairs(ddis) do
		print("send ipv6 udp frag "..k.." with hopbyhop ext header")
		test_assert(rawsend_dissect_print(d))
	end

	insert_ip6_exthdr(ip6, nil, IPPROTO_DSTOPTS, "\x00\x00\x00\x00\x00\x00")
	insert_ip6_exthdr(ip6, nil, IPPROTO_DSTOPTS, "\x00\x00\x00\x00\x00\x00")
	ip6.ip6_flow = 0x60001234
	ddis = ipfrag2(dis, {ipfrag_pos_udp = 80})
	for k,d in ipairs(ddis) do
		print("send ipv6 udp frag "..k.." with hopbyhop, destopt ext headers in unfragmentable part and another destopt ext header in fragmentable part")
		test_assert(rawsend_dissect_print(d, {fwmark = 0x50EA}))
	end

	fix_ip_proto(dis) -- ip6_preserve_next requires next fields in ip6.exthdr
	ip6.ip6_flow = 0x6000AE38
	ddis = ipfrag2(dis, {ipfrag_pos_udp = 72, ipfrag_next = IPPROTO_TCP})
	for k,d in ipairs(ddis) do
		print("send ipv6 udp frag "..k.." with hopbyhop, destopt ext headers in unfragmentable part and another destopt ext header in fragmentable part. forge next proto in fragment header of the second fragment to TCP")
		-- reconstruct dissect using next proto fields in the dissect. do not auto fix next proto chain.
		-- by default reconstruct fixes next proto chain
		test_assert(rawsend_dissect_print(d, {fwmark = 0x409A, repeats=2}, {ip6_preserve_next = true}))
	end

	local icmp = {
		icmp_type = ICMP_ECHO, icmp_code=0,
		icmp_data = u32(bu16(math.random(1,0xFFFF))..bu16(1))
	}
	ip.ip_p = IPPROTO_ICMP
	payload=brandom_az09(math.random(10,1100))
	dis = {ip = ip, icmp = icmp, payload = payload}
	print("send ipv4 icmp")
	test_assert(rawsend_dissect_print(dis, {fwmark = 0xD133, repeats=3}))

	ip6.exthdr={{ type = IPPROTO_HOPOPTS, data = "\x00\x00\x00\x00\x00\x00" }}
	ip6.ip6_flow=0x60009E3B
	icmp.icmp_type = ICMP6_ECHO_REQUEST
	dis = {ip6 = ip6, icmp = icmp, payload = payload}
	print("send ipv6 icmp")
	test_assert(rawsend_dissect_print(dis, {fwmark = 0x8E10, repeats=3}))

	ip2 = {
		ip_tos = 0,
		ip_id = math.random(0,0xFFFF),
		ip_off = 0,
		ip_ttl = 64,
		ip_p = IPPROTO_UDP,
		ip_src = pton("10.1.1.1"),
		ip_dst = pton("10.1.1.2"),
	}

	dis = {ip = ip2, udp = udp, payload = payload}
	raw_udp = reconstruct_dissect(dis)

	ip6.ip6_flow=0x6000583F
	dis = {ip6 = ip6, payload = raw_udp}
	print("send ipv6 ipip")
	test_assert(rawsend_dissect_print(dis, {fwmark = 0x8E10, repeats=3}, {ip6_last_proto=IPPROTO_IPIP}))

	dis = {ip = ip, payload = raw_udp}
	dis.ip.ip_p = IPPROTO_IPIP
	print("send ipv4 ipip")
	test_assert(rawsend_dissect_print(dis, {fwmark = 0x8E10, repeats=3}, {ip6_last_proto=IPPROTO_IPIP}))
end
