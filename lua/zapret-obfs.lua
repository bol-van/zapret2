-- test case : --in-range=a --out-range=a --lua-desync=wgobfs:secret=mycoolpassword
-- encrypt standard wireguard messages - initiation, response, cookie - and change udp packet size
-- do not encrypt data messages and keepalives
-- wgobfs adds maximum of 30+padmax bytes to udp size
-- reduce MTU of wireguard interface to avoid ip fragmentation !
-- without knowing the secret encrypted packets should be crypto strong white noise with no signature
-- arg : secret - shared secret. any string. must be the same on both peers
-- arg : padmin - min random garbage bytes. 0 by default
-- arg : padmax - max random garbage bytes. 16 by default
-- NOTE : this function does not depend on zapret-lib.lua and should not be run under orchestrator (uses direct instance_cutoff)
function wgobfs(ctx, desync)
	if not desync.dis.udp then
		instance_cutoff_shim(ctx, desync)
		return
	end

	local padmin = desync.arg.padmin and tonumber(desync.arg.padmin) or 0
	local padmax = desync.arg.padmax and tonumber(desync.arg.padmax) or 16
	local function genkey()
		-- cache key in a global var bound to instance name
		local key_cache_name = desync.func_instance.."_key"
		local key = _G[key_cache_name]
		if not key then
			key = hkdf("sha256", "wgobfs_salt", desync.arg.secret, nil, 16)
			_G[key_cache_name] = key
		end
		return key
	end
	local function maybe_encrypted_payload(payload)
		for k,plsize in pairs({2+12+16+148, 2+12+16+92, 2+12+16+64}) do
			if #payload>=(plsize+padmin) and #payload<=(plsize+padmax) then
				return true
			end
		end
		return false
	end
	local function wg_payload_from_size(payload)
		if #payload==148 then return "wireguard_initiation"
		elseif #payload==92 then return "wireguard_response"
		elseif #payload==64 then return "wireguard_cookie"
		else return nil
		end
	end

	if not desync.arg.secret or #desync.arg.secret==0 then
		error("wgobfs: secret required")
	end
	if padmin>padmax then
		error("wgobfs: padmin>padmax")
	end
	if (desync.l7payload=="wireguard_initiation" or desync.l7payload=="wireguard_response" or desync.l7payload=="wireguard_cookie") and #desync.dis.payload<65506 then
		DLOG("wgobfs: encrypting '"..desync.l7payload.."'. size "..#desync.dis.payload)
		local key = genkey()
		-- in aes-gcm every message require it's own crypto secure random iv
		-- encrypting more than one message with the same iv is considered catastrophic failure
		-- iv must be sent with encrypted message
		local iv = bcryptorandom(12)
		local encrypted, atag = aes_gcm(true, key, iv, bu16(#desync.dis.payload)..desync.dis.payload..brandom(math.random(padmin,padmax)), nil)
		desync.dis.payload = iv..atag..encrypted
		return VERDICT_MODIFY
	end

	if desync.l7payload=="unknown" and maybe_encrypted_payload(desync.dis.payload) then
		local key = genkey()
		local iv = string.sub(desync.dis.payload,1,12)
		local atag = string.sub(desync.dis.payload,13,28)
		local decrypted, atag2 = aes_gcm(false, key, iv, string.sub(desync.dis.payload,29))
		if atag==atag2 then
			local plen = u16(decrypted)
			if plen>(#decrypted-2) then
				DLOG("wgobfs: bad decrypted payload data")
			else
				desync.dis.payload = string.sub(decrypted, 3, 3+plen-1)
				if b_debug then DLOG("wgobfs: decrypted '"..(wg_payload_from_size(desync.dis.payload) or "unknown").."' message. size "..plen) end
				return VERDICT_MODIFY
			end
		else
			DLOG("wgobfs: decrypt auth tag mismatch")
		end
	end
end

-- test case :
--  endpoint1:
--   --filter-icmp=0,8,128,129 --filter-ipp=193,198,209,250 --filter-tcp=* --filter-udp=* --in-range=a --lua-desync=ippxor:ippxor=192:dataxor=0xABCD
--   nft add rule inet ztest pre meta mark and 0x40000000 == 0 meta l4proto {193, 198, 209, 250} queue num 200 bypass
--   nft add rule inet ztest post meta mark and 0x40000000 == 0 tcp dport "{5001}" queue num 200 bypass
--   nft add rule inet ztest post meta mark and 0x40000000 == 0 udp dport "{5001}" queue num 200 bypass
--   iperf -i 1 -c endpoint2
--  endpoint2:
--   --filter-icmp=0,8,128,129 --filter-ipp=193,198,209,250 --filter-tcp=* --filter-udp=* --in-range=a --lua-desync=ippxor:ippxor=192:dataxor=0xABCD --server
--   nft add rule inet ztest pre meta mark and 0x40000000 == 0 meta l4proto {193, 198, 209, 250} queue num 200 bypass
--   nft add rule inet ztest post meta mark and 0x40000000 == 0 tcp sport "{5001}" queue num 200 bypass
--   nft add rule inet ztest post meta mark and 0x40000000 == 0 udp sport "{5001}" queue num 200 bypass
--   iperf -s
-- xor ip protocol number and optionally xor tcp,udp,icmp payload with supplied blob pattern
-- arg : ippxor - value to xor ip protocol number
-- arg : dataxor - blob to xor tcp, udp or icmp payload
-- arg : rebuild - always reconstruct desync.dis if after ippxor packet becomes tcp,udp or icmp
function ippxor(ctx, desync)
	local dataxor
	local function need_dxor(dis)
		return dataxor and dis.payload and #dis.payload>0 and (dis.tcp or dis.udp or dis.icmp)
	end
	local function dxor(dis)
		dis.payload = bxor(dis.payload, pattern(dataxor,1,#dis.payload))
	end

	if not desync.arg.ippxor then
		error("ippxor: ippxor value required")
	end
	local ippxor = tonumber(desync.arg.ippxor)
	if ippxor<0 or ippxor>0xFF then
		error("ippxor: invalid ippxor value. should be 0..255")
	end
	if desync.arg.dataxor then
		dataxor = blob(desync,desync.arg.dataxor)
		if #dataxor==0 then
			error("ippxor: empty dataxor value")
		end
	end

	local bdxor = need_dxor(desync.dis)
	if bdxor then
		DLOG("ippxor: dataxor size="..#desync.dis.payload)
		dxor(desync.dis)
	end

	local l3_from = ip_proto_l3(desync.dis)
	local l3_to = bitxor(l3_from, ippxor)
	DLOG("ippxor: "..l3_from.." => "..l3_to)
	fix_ip_proto(desync.dis, l3_to)

	if	(not bdxor and dataxor or desync.arg.rebuild) and
		(l3_to==IPPROTO_TCP and not desync.dis.tcp or
		l3_to==IPPROTO_UDP and not desync.dis.udp or
		l3_to==IPPROTO_ICMP and not (desync.dis.ip and desync.dis.icmp) or
		l3_to==IPPROTO_ICMPV6 and not (desync.dis.ip6 and desync.dis.icmp))
	then
		DLOG("ippxor: packet rebuild")
		local raw_ip = reconstruct_dissect(desync.dis, {ip6_preserve_next=true})
		local dis = dissect(raw_ip)
		if not dis.ip and not dis.ip6 then
			DLOG_ERR("ippxor: could not rebuild packet")
			return
		end
		desync.dis = dis
	end

	if not bdxor and need_dxor(desync.dis) then
		DLOG("ippxor: dataxor size="..#desync.dis.payload)
		dxor(desync.dis)
	end

	return VERDICT_MODIFY + VERDICT_PRESERVE_NEXT
end

-- test case:
--  endpoint1:
--   --in-range=a --lua-desync=udp2icmp
--   nft add rule inet ztest post meta mark and 0x40000000 == 0 udp dport 12345 queue num 200 bypass
--   nft add rule inet ztest pre meta mark and 0x40000000 == 0 meta l4proto "{icmp,icmpv6}" queue num 200 bypass
--  endpoint2:
--   --in-range=a --lua-desync=udp2icmp --server
--   nft add rule inet ztest post meta mark and 0x40000000 == 0 udp sport 12345 queue num 200 bypass
--   nft add rule inet ztest pre meta mark and 0x40000000 == 0 meta l4proto "{icmp,icmpv6}" queue num 200 bypass
-- packs udp datagram to icmp message without changing packet size
-- function keeps icmp identifier as (sport xor dport) to help traverse NAT (it won't help if NAT changes id)
-- one end must be in server mode, another - in client mode
-- arg : ctype - client icmp type
-- arg : ccode - client icmp code
-- arg : stype - server icmp type
-- arg : scode - server icmp code
-- arg : dataxor - blob to xor udp payload
-- arg : server=[0|1] - override server mode. by default use "--server" nfqws2 parameter
-- arg : cgnat - do not rely on identifier - cgnat in most cases changes it. expand udp packet size by 2 (may exceed MTU !)
-- arg : id_lifetime - mapped identifiers lifetime in seconds
function udp2icmp(ctx, desync)
	local dataxor
	local bserver
	if desync.arg.server then
		bserver = desync.arg.server~="0"
	else
		bserver = b_server
	end

	local function one_byte_arg(name)
		if desync.arg[name] then
			local v = tonumber(desync.arg[name])
			if v<0 or v>0xFF then
				error("udp2icmp: invalid type or code value. should be 0..255")
			end
			return v
		end
	end
	local function ictype(send)
		local ctype = one_byte_arg("ctype")
		local stype = one_byte_arg("stype")
		if logical_xor(ctype,stype) then
			error("udp2icmp: ctype and stype must be both set or not set")
		end
		if not ctype then
			ctype = desync.dis.ip6 and ICMP6_ECHO_REQUEST or ICMP_ECHO
			stype = desync.dis.ip6 and ICMP6_ECHO_REPLY or ICMP_ECHOREPLY
		end
		return logical_xor(send,bserver) and ctype or stype
	end
	local function iccode(send)
		local ccode = one_byte_arg("ccode")
		local scode = one_byte_arg("scode")
		if logical_xor(ccode,scode) then
			error("udp2icmp: ccode and scode must be both set or not set")
		end
		if not ccode then
			ccode = 0
			scode = 0
		end
		return logical_xor(send,bserver) and ccode or scode
	end
	local function plxor()
		if dataxor then
			DLOG("udp2icmp: dataxor")
			desync.dis.payload = bxor(desync.dis.payload, pattern(dataxor,1,#desync.dis.payload))
		end
	end
	local function map_purge()
		if udp2icmp_map then
			local last = udp2icmp_map.purge or 0
			local now = os.time()
			local timeout = desync.arg.id_lifetime and tonumber(desync.arg.id_lifetime) or 60
			if last~=now then
				for k,v in pairs(udp2icmp_map) do
					if type(v)=='table' and v.t then
						if now>=(v.t + timeout) then
							udp2icmp_map[k] = nil
						end
					end
				end
				udp2icmp_map.purge=now
			end
		end
	end

	map_purge()

	if desync.arg.dataxor then
		dataxor = blob(desync,desync.arg.dataxor)
		if #dataxor==0 then
			error("udp2icmp: empty dataxor value")
		end
	end

	if desync.dis.udp then
		plxor()
		if b_debug then -- save some cpu
			DLOG("udp2icmp: udp => icmp sport="..desync.dis.udp.uh_sport.." dport="..desync.dis.udp.uh_dport.." size="..#desync.dis.payload)
		end
		local id = bitxor(desync.dis.udp.uh_sport,desync.dis.udp.uh_dport)
		if desync.arg.cgnat then
			if bserver then
				-- extract original icmp identifier from the map. it must match original or NAT will not deliver
				local map_id = (desync.dis.ip6 and desync.dis.ip6.ip6_dst or desync.dis.ip.ip_dst)..
					(desync.dis.ip6 and desync.dis.ip6.ip6_src or desync.dis.ip.ip_src)..
					bu16(desync.dis.udp.uh_dport)..bu16(desync.dis.udp.uh_sport)
				if udp2icmp_map then
					local id_ = udp2icmp_map[map_id]
					if id_ then
						id=id_.id
						if b_debug then DLOG(string.format("udp2icmp: found mapped icmp identifier %04X",id)) end
						id_.t=os.time() -- update time
					else
						DLOG("udp2icmp: mapped icmp identifier NOT found !")
					end
				end
				
			else
				-- cgnat changes identifier. save it in the end of the packet, expand packet size by 2
				desync.dis.payload = desync.dis.payload .. bu16(id)
				DLOG("udp2icmp: expanding udp size to "..#desync.dis.payload)
			end
		end
		desync.dis.icmp = {
			icmp_type = ictype(true),
			icmp_code = iccode(true),
			icmp_data = u32(bu16(id)..(bserver and bu16(desync.dis.udp.uh_sport) or bu16(desync.dis.udp.uh_dport)))
		}
		desync.dis.udp = nil
		fix_ip_proto(desync.dis)
		return VERDICT_MODIFY
	elseif desync.dis.icmp and desync.dis.icmp.icmp_type==ictype(false) and desync.dis.icmp.icmp_code==iccode(false) then
		local pl = bitand(desync.dis.icmp.icmp_data,0xFFFF)
		local pm
		local id = bitrshift(desync.dis.icmp.icmp_data,16)
		if bserver and desync.arg.cgnat then
			if #desync.dis.payload<2 then
				DLOG("udp2icmp: udp is less than 2 bytes and cgnat is on ! doing nothing")
				return VERDICT_PASS
			end
			if not udp2icmp_map then udp2icmp_map={} end

			pm = bitxor(u16(desync.dis.payload,#desync.dis.payload-1),pl) -- use right 2 bytes
			desync.dis.payload = string.sub(desync.dis.payload,1,-3) -- shrink right 2 bytes
			DLOG("udp2icmp: shrinking udp size to "..#desync.dis.payload)

			-- keep original icmp identifier indexed by ip/port tuple
			local map_id = (desync.dis.ip6 and desync.dis.ip6.ip6_src or desync.dis.ip.ip_src)..
				(desync.dis.ip6 and desync.dis.ip6.ip6_dst or desync.dis.ip.ip_dst)..
				bu16(pm)..bu16(pl)
			udp2icmp_map[map_id] = { id=id, t=os.time() }
			if b_debug then	DLOG(string.format("udp2icmp: stored mapped icmp identifier %04X",id)) end
		else
			pm = bitxor(id,pl)
		end

		desync.dis.udp = {
			uh_sport = bserver and pm or pl,
			uh_dport = bserver and pl or pm,
			uh_ulen = UDP_BASE_LEN + #desync.dis.payload
		}
		desync.dis.icmp = nil
		fix_ip_proto(desync.dis)
		if b_debug then -- save some cpu
			DLOG("udp2icmp: icmp => udp sport="..desync.dis.udp.uh_sport.." dport="..desync.dis.udp.uh_dport.." size="..#desync.dis.payload)
		end
		plxor()
		return VERDICT_MODIFY
	end
end

--[[
 test case :
 both:
   nft create table inet ztest
   nft add chain inet ztest post "{type filter hook output priority mangle;}"
   nft add chain inet ztest pre "{type filter hook input priority mangle;}"
   nft add chain inet ztest predefrag "{type filter hook output priority -401;}"
   nft add rule inet ztest predefrag "mark & 0x40000000 != 0x00000000 notrack"
 client:
   --in-range="<d1" --out-range="<d1" --lua-desync=synhide:synack:ghost=2
   nft add rule inet ztest post "meta mark & 0x40000000 == 0x00000000 tcp dport { 80, 443 } tcp flags & (fin | syn | rst | ack | urg) == syn queue flags bypass to 200"
   nft add rule inet ztest pre meta "mark & 0x40000000 == 0x00000000 tcp sport { 80, 443 } tcp flags & (fin | syn | rst | ack | urg) == (rst | ack) tcp urgptr != 0 queue flags bypass to 200"
   nft add rule inet ztest pre meta "mark & 0x40000000 == 0x00000000 tcp sport { 80, 443 } tcp flags & (fin | syn | rst | ack | urg) == (rst | ack) tcp option 172 exists queue flags bypass to 200"
   nft add rule inet ztest pre meta "mark & 0x40000000 == 0x00000000 tcp sport { 80, 443 } tcp flags & (fin | syn | rst | ack | urg) == (rst | ack) @th,100,4 != 0 queue flags bypass to 200"
  server:
   --in-range=a --lua-desync=synhide:synack
   nft add rule inet ztest post "meta mark & 0x40000000 == 0x00000000 tcp sport { 80, 443 } tcp flags & (fin | syn | rst | ack | urg) == (syn | ack) queue flags bypass to 200"
   nft add rule inet ztest pre "meta mark & 0x40000000 == 0x00000000 tcp dport { 80, 443 } tcp flags & (fin | syn | rst | ack | urg) == ack tcp urgptr != 0 queue flags bypass to 200"
   nft add rule inet ztest pre "meta mark & 0x40000000 == 0x00000000 tcp dport { 80, 443 } tcp flags & (fin | syn | rst | ack | urg) == ack tcp option 172 exists queue flags bypass to 200"
   nft add rule inet ztest pre "meta mark & 0x40000000 == 0x00000000 tcp dport { 80, 443 } tcp flags & (fin | syn | rst | ack | urg) == ack @th,100,4 != 0 queue flags bypass to 200"
   nft add rule inet ztest pre "meta mark & 0x40000000 == 0x00000000 tcp dport { 80, 443 } tcp flags & (fin | syn | rst | ack | urg) == ack ct state new queue flags bypass to 200"

 hides tcp handshake from DPI optionally using ghost SYN packet with low ttl to punch NAT hole
 NOTE: linux conntrack treats packets without SYN in SYN_SENT state as INVALID ! NAT does not work !
 NOTE: the only found workaround - put NFQUEUE handler to that packet. It should only return pass verdict.
 NOTE: BSD and CGNAT should work
 NOTE: won't likely pass home routers even with hardware offload enabled - SYN state is managed in netfilter before offload. but can work from router itself.

 arg : ghost - ghost syn ttl for ipv4. must be hop_to_last_nat+1. syn is not ghosted if not supplied
 arg : ghost6 - ghost syn hl for ipv6. must be hop_to_last_nat+1. syn is not ghosted if not supplied
 arg : synack - also fake synack. NOTE: will likely not work with magic=tsecr on *nix clients because they expect valid echoed tsecr in SYN,ACK
 arg : magic=[x2|urp|opt|tsecr] - where to put magic value to recognize modified packets
 arg : x2=bit - th_x2 bit used for magic=x2 - 1,2,4,8
 arg : kind - kind of tcp option for magic=opt
 arg : opt=hex - tcp option value
 arg : xorseq=hex - 4 hex bytes to xor seq
--]]
function synhide(ctx, desync)
	if not desync.dis.tcp then
		instance_cutoff_shim(ctx, desync)
		return
	end

	local fl = bitand(desync.dis.tcp.th_flags, TH_SYN+TH_ACK+TH_FIN+TH_RST+TH_URG)
	local tsidx = find_tcp_option(desync.dis.tcp.options, TCP_KIND_TS)
	local magic
	if desync.arg.magic then
		if desync.arg.magic~="tsecr" and desync.arg.magic~="x2" and desync.arg.magic~="urp" and desync.arg.magic~="opt" then
			error("synhide: invalid magic mode '"..desync.arg.magic.."'")
		end
		magic = desync.arg.magic
		if magic=="tsecr" and not tsidx then
			DLOG("synhide: cannot use tsecr magic because timestamp option is absent")
			instance_cutoff_shim(ctx, desync)
			return
		end
	else
		magic = "x2"
	end
	DLOG("synhide: magic="..magic)

	local x2
	if desync.arg.x2 then
		x2 = tonumber(desync.arg.x2)
		if x2<1 or x2>0x0F then
			error("synhide: invalid x2 value")
		end
	else
		-- some firewalls allow only AECN bit (1). if reserved bits are !=0 => administratively prohibited
		x2 = 1
	end

	local kind
	if desync.arg.kind then
		kind = tonumber(desync.arg.kind)
		-- do not allow noop and end
		if kind<2 or kind>0xFF then
			error("synhide: invalid kind value")
		end
	else
		kind = 172 -- accurate ecn
	end

	local opt
	if desync.arg.opt then
		opt = parse_hex(desync.arg.opt)
		if not opt then
			error("synhide: invalid opt value")
		end
	else
		opt=""
	end


	local xorseq
	if desync.arg.xorseq then
		xorseq = parse_hex(desync.arg.xorseq)
		if not xorseq or #xorseq~=4 then
			error("synhide: invalid xorseq value")
		end
		xorseq = u32(xorseq)
	end

	local function make_magic(client)
		local m
		-- use client seq0
		m = client and desync.dis.tcp.th_seq or desync.dis.tcp.th_ack-1
		m = bitxor(bitrshift(m,16),bitand(m,0xFFFF))
		if m==0 then
			-- 0 is not acceptable
			m = client and desync.dis.tcp.th_dport or desync.dis.tcp.th_sport
		end
		return m
	end
	local function xorhdr()
		if xorseq then
			desync.dis.tcp.th_ack = bitxor(desync.dis.tcp.th_ack, xorseq)
			desync.dis.tcp.th_seq = bitxor(desync.dis.tcp.th_seq, xorseq)
		end
	end
	local function ver_magic(client)
		local r = false
		xorhdr()
		if magic=="tsecr" then
			r = make_magic(client)==u16(string.sub(desync.dis.tcp.options[tsidx].data,7))
		elseif magic=="x2" then
			r = bitand(desync.dis.tcp.th_x2, x2)~=0
		elseif magic=="urp" then
			r = desync.dis.tcp.th_urp == make_magic(client)
		elseif magic=="opt" then
			local idx = find_tcp_option(desync.dis.tcp.options, kind)
			r = idx and desync.dis.tcp.options[idx].data == opt
		end
		xorhdr()
		return r
	end
	local function set_magic(client)
		if magic=="tsecr" then
			desync.dis.tcp.options[tsidx].data = string.sub(desync.dis.tcp.options[tsidx].data,1,6) .. bu16(make_magic(client))
		elseif magic=="x2" then
			desync.dis.tcp.th_x2 = bitor(desync.dis.tcp.th_x2, x2)
		elseif magic=="urp" then
			desync.dis.tcp.th_urp = make_magic(client)
		elseif magic=="opt" then
			table.insert(desync.dis.tcp.options, {kind=kind, data=opt})
		end
		xorhdr()
	end
	local function clear_magic()
		xorhdr()
		if magic=="tsecr" then
			desync.dis.tcp.options[tsidx].data = string.sub(desync.dis.tcp.options[tsidx].data,1,6) .. "\x00\x00"
		elseif magic=="x2" then
			desync.dis.tcp.th_x2 = bitand(desync.dis.tcp.th_x2,bitnot(x2))
		elseif magic=="urp" then
			desync.dis.tcp.th_urp = 0
		elseif magic=="opt" then
			local idx = find_tcp_option(desync.dis.tcp.options, kind)
			if idx then
				table.remove(desync.dis.tcp.options, idx)
			end
		end
		desync.track = conntrack_feed(desync.dis)
	end

	if fl==TH_SYN then
		-- client sent
		local ttl = tonumber(desync.dis.ip and desync.arg.ghost or (desync.dis.ip6 and desync.arg.ghost6))
		if ttl then
			DLOG("synhide: punch NAT hole with ttl="..ttl)
			local dis = deepcopy(desync.dis)
			if dis.ip then
				dis.ip.ip_ttl = ttl
			elseif dis.ip6 then
				dis.ip6.ip6_hlim = ttl
			end
			if not rawsend_dissect(dis, rawsend_opts_base(desync)) then
				instance_cutoff_shim(ctx, desync) -- failed
				return
			end
		end
		DLOG("synhide: client sends SYN. remove SYN")
		set_magic(true)
		-- remove SYN, set ACK
		desync.dis.tcp.th_flags = bitor(bitand(desync.dis.tcp.th_flags, bitnot(TH_SYN)), TH_ACK)
		if not desync.arg.synack then
			DLOG("synhide: mission complete")
			instance_cutoff_shim(ctx, desync)
		end
		return VERDICT_MODIFY
	elseif fl==(TH_SYN+TH_ACK) then
		-- server sent
		if desync.arg.synack then
			DLOG("synhide: server sends SYN+ACK. remove SYN, set RST")
			set_magic(false)
			desync.dis.tcp.th_flags = bitor(bitand(desync.dis.tcp.th_flags, bitnot(TH_SYN)), TH_RST)
			return VERDICT_MODIFY
		else
			DLOG("synhide: server sends SYN+ACK. do not remove SYN because 'synack' arg is not set.")
			instance_cutoff_shim(ctx, desync)
			return -- do nothing
		end
	elseif fl==TH_ACK and ver_magic(true) then
		DLOG("synhide: server received magic. restore SYN")
		desync.dis.tcp.th_flags = bitor(bitand(desync.dis.tcp.th_flags, bitnot(TH_ACK)), TH_SYN)
		clear_magic()
		if not desync.arg.synack then
			DLOG("synhide: mission complete")
			instance_cutoff_shim(ctx, desync)
		end
		return VERDICT_MODIFY
	elseif fl==(TH_ACK+TH_RST) and ver_magic(false) then
		DLOG("synhide: client received magic. restore SYN, remove RST")
		desync.dis.tcp.th_flags = bitor(bitand(desync.dis.tcp.th_flags, bitnot(TH_RST)), TH_SYN)
		clear_magic()
		DLOG("synhide: mission complete")
		instance_cutoff_shim(ctx, desync)
		return VERDICT_MODIFY
	end

	DLOG("synhide: sequence failed")
	instance_cutoff_shim(ctx, desync)
end
