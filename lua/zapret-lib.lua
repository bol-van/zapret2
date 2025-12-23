HEXDUMP_DLOG_MAX = HEXDUMP_DLOG_MAX or 32
NOT3=bitnot(3)
NOT7=bitnot(7)
-- xor pid,tid,sec,nsec
math.randomseed(bitxor(getpid(),gettid(),clock_gettime()))

-- basic desync function
-- execute given lua code. "desync" is temporary set as global var to be accessible to the code
-- useful for simple fast actions without writing a func
-- arg: code=<lua_code>
function luaexec(ctx, desync)
	if not desync.arg.code then
		error("luaexec: no 'code' parameter")
	end
	local fname = desync.func_instance.."_luaexec_code"
	if not _G[fname] then
		_G[fname] = load(desync.arg.code, fname)
	end
	-- allow dynamic code to access desync
	_G.desync = desync
	_G[fname]()
	_G.desync = nil
end

-- basic desync function
-- does nothing just acknowledges when it's called
-- no args
function pass(ctx, desync)
	DLOG("pass")
end

-- basic desync function
-- prints desync to DLOG
function pktdebug(ctx, desync)
	DLOG("desync:")
	var_debug(desync)
end
-- basic desync function
-- prints function args
function argdebug(ctx, desync)
	var_debug(desync.arg)
end

-- basic desync function
-- prints conntrack positions to DLOG
function posdebug(ctx, desync)
	if not desync.track then
		DLOG("posdebug: no track")
		return
	end
	local s="posdebug: "..(desync.outgoing and "out" or "in").." time +"..desync.track.pos.dt.."s direct"
	for i,pos in pairs({'n','d','b','s','p'}) do
		s=s.." "..pos..pos_get(desync, pos, false)
	end
	s=s.." reverse"
	for i,pos in pairs({'n','d','b','s','p'}) do
		s=s.." "..pos..pos_get(desync, pos, true)
	end
	s=s.." payload "..#desync.dis.payload
	if desync.reasm_data then
		s=s.." reasm "..#desync.reasm_data
	end
	if desync.decrypt_data then
		s=s.." decrypt "..#desync.decrypt_data
	end
	if desync.replay_piece_count then
		s=s.." replay "..desync.replay_piece.."/"..desync.replay_piece_count
	end
	DLOG(s)
end

-- basic desync function
-- set l7payload to 'arg.payload' if reasm.data or desync.dis.payload contains 'arg.pattern' substring
-- NOTE : this does not set payload on C code side !
-- NOTE : C code will not see payload change. --payload args take only payloads known to C code and cause error if unknown.
-- arg: pattern - substring for search inside reasm_data or desync.dis.payload
-- arg: payload - set desync.l7payload to this if detected
-- arg: undetected - set desync.l7payload to this if not detected
-- test case : --lua-desync=detect_payload_str:pattern=1234:payload=my --lua-desync=fake:blob=0x1234:payload=my
function detect_payload_str(ctx, desync)
	if not desync.arg.pattern then
		error("detect_payload_str: missing 'pattern'")
	end
	local data = desync.reasm_data or desync.dis.payload
	local b = string.find(data,desync.arg.pattern,1,true)
	if b then
		DLOG("detect_payload_str: detected '"..desync.arg.payload.."'")
		if desync.arg.payload then desync.l7payload = desync.arg.payload end
	else
		DLOG("detect_payload_str: not detected '"..desync.arg.payload.."'")
		if desync.arg.undetected then desync.l7payload = desync.arg.undetected end
	end
end


-- this shim is needed then function is orchestrated. ctx services not available
-- have to emulate cutoff in LUA using connection persistent table track.lua_state
function instance_cutoff_shim(ctx, desync, dir)
	if ctx then
		instance_cutoff(ctx, dir)
	elseif not desync.track then
		DLOG("instance_cutoff_shim: cannot cutoff '"..desync.func_instance.."' because conntrack is absent")
	else
		if not desync.track.lua_state.cutoff_shim then
			desync.track.lua_state.cutoff_shim = {}
		end
		if not desync.track.lua_state.cutoff_shim[desync.func_instance] then
			desync.track.lua_state.cutoff_shim[desync.func_instance] = {}
		end
		if type(dir)=="nil" then
			-- cutoff both directions by default
			desync.track.lua_state.cutoff_shim[desync.func_instance][true] = true
			desync.track.lua_state.cutoff_shim[desync.func_instance][false] = true
		else
			desync.track.lua_state.cutoff_shim[desync.func_instance][dir] = true
		end
		if b_debug then DLOG("instance_cutoff_shim: cutoff '"..desync.func_instance.."' in="..tostring(type(dir)=="nil" and true or not dir).." out="..tostring(type(dir)=="nil" or dir)) end
	end
end
function cutoff_shim_check(desync)
	if not desync.track then
		DLOG("cutoff_shim_check: cannot check '"..desync.func_instance.."' cutoff because conntrack is absent")
		return false
	else
		local b=desync.track.lua_state.cutoff_shim and
			desync.track.lua_state.cutoff_shim[desync.func_instance] and
			desync.track.lua_state.cutoff_shim[desync.func_instance][desync.outgoing]
		if b and b_debug then 
			DLOG("cutoff_shim_check: '"..desync.func_instance.."' "..(desync.outgoing and "out" or "in").." cutoff")
		end
		return b
	end
end


-- applies # and $ prefixes. #var means var length, %var means var value
function apply_arg_prefix(desync)
	for a,v in pairs(desync.arg) do
		local c = string.sub(v,1,1)
		if c=='#' then
			local blb = blob(desync,string.sub(v,2))
			desync.arg[a] = (type(blb)=='string' or type(blb)=='table') and #blb or 0
		elseif c=='%' then
			desync.arg[a] = blob(desync,string.sub(v,2))
		elseif c=='\\' then
			c = string.sub(v,2,2);
			if c=='#' or c=='%' then
				desync.arg[a] = string.sub(v,2)
			end
		end
	end
end
-- copy instance identification and args from execution plan to desync table
-- NOTE : to not lose VERDICT_MODIFY dissect changes pass original desync table
-- NOTE : if a copy was passed and VERDICT_MODIFY returned you must copy modified dissect back to desync table or resend it and return VERDICT_DROP
-- NOTE : args and some fields are substituted. if you need them - make a copy before calling this.
function apply_execution_plan(desync, instance)
	desync.func = instance.func
	desync.func_n = instance.func_n
	desync.func_instance = instance.func_instance
	desync.arg = deepcopy(instance.arg)
	apply_arg_prefix(desync)
end
-- produce resulting verdict from 2 verdicts
function verdict_aggregate(v1, v2)
	local v
	v1 = v1 or VERDICT_PASS
	v2 = v2 or VERDICT_PASS
	if v1==VERDICT_DROP or v2==VERDICT_DROP then
		v=VERDICT_DROP
	elseif v1==VERDICT_MODIFY or v2==VERDICT_MODIFY then
		v=VERDICT_MODIFY
	else
		v=VERDICT_PASS
	end
	return v
end
function plan_instance_execute(desync, verdict, instance)
	apply_execution_plan(desync, instance)
	if cutoff_shim_check(desync) then
		DLOG("plan_instance_execute: not calling '"..desync.func_instance.."' because of voluntary cutoff")
	elseif not payload_match_filter(desync.l7payload, instance.payload_filter) then
		DLOG("plan_instance_execute: not calling '"..desync.func_instance.."' because payload '"..desync.l7payload.."' does not match filter '"..instance.payload_filter.."'")
	elseif not pos_check_range(desync, instance.range) then
		DLOG("plan_instance_execute: not calling '"..desync.func_instance.."' because pos "..pos_str(desync,instance.range.from).." "..pos_str(desync,instance.range.to).." is out of range '"..pos_range_str(instance.range).."'")
	else
		DLOG("plan_instance_execute: calling '"..desync.func_instance.."'")
		verdict = verdict_aggregate(verdict,_G[instance.func](nil, desync))
	end
	return verdict
end
function plan_instance_pop(desync)
	return (desync.plan and #desync.plan>0) and table.remove(desync.plan, 1) or nil
end
function plan_clear(desync)
	while table.remove(desync.plan) do end
end
-- this approach allows nested orchestrators
function orchestrate(ctx, desync)
	if not desync.plan then
		execution_plan_cancel(ctx)
		desync.plan = execution_plan(ctx)
	end
end
-- copy desync preserving lua_state
function desync_copy(desync)
	local dcopy = deepcopy(desync)
	if desync.track then
		-- preserve lua state
		dcopy.track.lua_state = desync.track.lua_state
	end
	if desync.plan then
		-- preserve execution plan
		dcopy.plan = desync.plan
	end
	return dcopy
end
-- redo what whould be done without orchestration
function replay_execution_plan(desync)
	local verdict = VERDICT_PASS
	while true do
		local instance = plan_instance_pop(desync)
		if not instance then break end
		verdict = plan_instance_execute(desync, verdict, instance)
	end
	return verdict
end
-- this function demonstrates how to stop execution of upcoming desync instances and take over their job
-- this can be used, for example, for orchestrating conditional processing without modifying of desync functions code
-- test case : --lua-desync=desync_orchestrator_example --lua-desync=pass --lua-desync=pass
function desync_orchestrator_example(ctx, desync)
	DLOG("orchestrator: taking over upcoming desync instances")
	orchestrate(ctx, desync)
	return replay_execution_plan(desync)
end

-- if seq is over 2G s and p position comparision can be wrong
function pos_counter_overflow(desync, mode, reverse)
	if not desync.track or not desync.track.tcp or (mode~='s' and mode~='p') then return false end
	local track_pos = reverse and desync.track.pos.reverse or desync.track.pos.direct
	return track_pos.tcp.rseq_over_2G
end
-- these functions duplicate range check logic from C code
-- mode must be n,d,b,s,x,a
-- pos is {mode,pos}
-- range is {from={mode,pos}, to={mode,pos}, upper_cutoff}
-- upper_cutoff = true means non-inclusive upper boundary
function pos_get_pos(track_pos, mode)
	if track_pos then
		if mode=='n' then
			return track_pos.pcounter
		elseif mode=='d' then
			return track_pos.pdcounter
		elseif mode=='b' then
			return track_pos.pbcounter
		elseif track_pos.tcp then
			if mode=='s' then
				return track_pos.tcp.rseq
			elseif mode=='p' then
				return track_pos.tcp.pos
			end
		end
	end
	return 0
end
function pos_get(desync, mode, reverse)
	if desync.track then
		local track_pos = reverse and desync.track.pos.reverse or desync.track.pos.direct
		return pos_get_pos(track_pos,mode)
	end
	return 0
end
function pos_check_from(desync, range)
	if range.from.mode == 'x' or pos_counter_overflow(desync, range.from.mode) then return false end
	if range.from.mode ~= 'a' then
		if desync.track then
			return pos_get(desync, range.from.mode) >= range.from.pos
		else
			return false
		end
	end
	return true;
end
function pos_check_to(desync, range)
	local ps
	if range.to.mode == 'x' or pos_counter_overflow(desync, range.to.mode) then return false end
	if range.to.mode ~= 'a' then
		if desync.track then
			ps = pos_get(desync, range.to.mode)
			return (ps < range.to.pos) or not range.upper_cutoff and (ps == range.to.pos)
		else
			return false
		end
	end
	return true;
end
function pos_check_range(desync, range)
	return pos_check_from(desync,range) and pos_check_to(desync,range)
end
function pos_range_str(range)
	return range.from.mode..range.from.pos..(range.upper_cutoff and '<' or '-')..range.to.mode..range.to.pos
end
function pos_str(desync, pos)
	return pos.mode..pos_get(desync, pos.mode)
end

-- sequence comparision functions. they work only within 2G interval
-- seq1>=seq2
function seq_ge(seq1, seq2)
	return 0==bitand(u32add(seq1, -seq2), 0x80000000)
end
-- seq1>seq2
function seq_gt(seq1, seq2)
	return seq1~=seq2 and seq_ge(seq1, seq2)
end
-- seq1<seq2
function seq_lt(seq1, seq2)
	return 0~=bitand(u32add(seq1, -seq2), 0x80000000)
end
-- seq1<=seq2
function seq_le(seq1, seq2)
	return seq1==seq2 or 0~=bitand(u32add(seq1, -seq2), 0x80000000)
end
-- seq_low<=seq<=seq_hi
function seq_within(seq, seq_low, seq_hi)
	return seq_ge(seq, seq_low) and seq_le(seq, seq_hi)
end

function is_retransmission(desync)
	return desync.track and desync.track.pos.direct.tcp and seq_ge(desync.track.pos.direct.tcp.uppos_prev, desync.track.pos.direct.tcp.pos)
end

-- prepare standard rawsend options from desync
-- repeats - how many time send the packet
-- ifout - override outbound interface (if --bind_fix4, --bind-fix6 enabled)
-- fwmark - override fwmark. desync mark bit(s) will be set unconditionally
function rawsend_opts(desync)
	return {
		repeats = desync.arg.repeats,
		ifout = desync.arg.ifout or desync.ifout,
		fwmark = desync.arg.fwmark or desync.fwmark
	}
end
-- only basic options. no repeats
function rawsend_opts_base(desync)
	return {
		ifout = desync.arg.ifout or desync.ifout,
		fwmark = desync.arg.fwmark or desync.fwmark
	}
end

-- prepare standard reconstruct options from desync
-- badsum - make L4 checksum invalid
-- ip6_preserve_next - use next protocol fields from dissect, do not auto fill values. can be set from code only, not from args
-- ip6_last_proto - last ipv6 "next" protocol. used only by "reconstruct_ip6hdr". can be set from code only, not from args
function reconstruct_opts(desync)
	return {
		badsum = desync.arg.badsum
	}
end

-- combined desync opts
function desync_opts(desync)
	return {
		rawsend = rawsend_opts(desync),
		reconstruct = reconstruct_opts(desync),
		ipfrag = desync.arg,
		ipid = desync.arg,
		fooling = desync.arg
	}
end


-- convert binary string to hex data
function string2hex(s)
	local ss = ""
	for i = 1, #s do
		if i>1 then
			ss = ss .. " "
		end
		ss = ss .. string.format("%02X", string.byte(s, i))
	end
	return ss
end
function has_nonprintable(s)
	return s:match("[^ -\\r\\n\\t]")
end
function make_readable(v)
	if type(v)=="string" then
		return string.gsub(v,"[^ -]",".");
	else
		return tostring(v)
	end
end
-- return hex dump of a binary string if it has nonprintable characters or string itself otherwise
function str_or_hex(s)
	if has_nonprintable(s) then
		return string2hex(s)
	else
		return s
	end
end
function logical_xor(a,b)
	return a and not b or not a and b
end
-- print to DLOG any variable. tables are expanded in the tree form, unprintables strings are hex dumped
function var_debug(v)
	local function dbg(v,level)
		if type(v)=="table" then
			for key, value in pairs(v) do
				DLOG(string.rep(" ",2*level).."."..tostring(key))
				dbg(v[key],level+1)
			end
		elseif type(v)=="string" then
			DLOG(string.rep(" ",2*level)..type(v).." "..str_or_hex(v))
		else
			DLOG(string.rep(" ",2*level)..type(v).." "..make_readable(v))
		end
	end
	dbg(v,0)
end

-- make hex dump
function hexdump(s,max)
	local l = max<#s and max or #s
	local ss = string.sub(s,1,l)
	return string2hex(ss)..(#s>max and " ... " or "  " )..make_readable(ss)..(#s>max and " ... " or "" )
end
-- make hex dump limited by HEXDUMP_DLOG_MAX chars
function hexdump_dlog(s)
	return hexdump(s,HEXDUMP_DLOG_MAX)
end

-- make copy of an array recursively
function deepcopy(orig, copies)
    copies = copies or {}
    local orig_type = type(orig)
    local copy
    if orig_type == 'table' then
        if copies[orig] then
            copy = copies[orig]
        else
            copy = {}
            copies[orig] = copy
            for orig_key, orig_value in next, orig, nil do
                copy[deepcopy(orig_key, copies)] = deepcopy(orig_value, copies)
            end
            setmetatable(copy, deepcopy(getmetatable(orig), copies))
        end
    else -- number, string, boolean, etc
        copy = orig
    end
    return copy
end

-- check if string 'v' in comma separated list 's'
function in_list(s, v)
	if s then
		for elem in string.gmatch(s, "[^,]+") do
			if elem==v then
				return true
			end
		end
	end
	return false
end

-- blobs can be 0xHEX, field name in desync or global var
-- if name is nil - return def
function blob(desync, name, def)
	if not name or #name==0 then
		if def then
			return def
		else
			error("empty blob name")
		end
	end
	local blob
	if string.sub(name,1,2)=="0x" then
		blob = parse_hex(string.sub(name,3))
		if not blob then
			error("invalid hex string : "..name)
		end
	else
		blob = desync[name]
		if not blob then
			-- use global var if no field in dissect table
			blob = _G[name]
			if not blob then
				error("blob  '"..name.."' unavailable")
			end
		end
	end
	return blob
end
function blob_or_def(desync, name, def)
	return name and blob(desync,name,def) or def
end

-- repeat pattern as needed to extract part of it with any length
-- pat="12345" len=10 offset=4 => "4512345123"
function pattern(pat, offset, len)
	if not pat or #pat==0 then
		error("pattern: bad or empty pattern")
	end
	local off = (offset-1) % #pat
	local pats = divint((len + #pat - 1), #pat) + (off==0 and 0 or 1)
	return string.sub(string.rep(pat,pats),off+1,off+len)
end

-- decrease by 1 all number values in the array
function zero_based_pos(a)
	if not a then return nil end
	local b={}
	for i,v in ipairs(a) do
		b[i] = type(a[i])=="number" and a[i] - 1 or a[i]
	end
	return b
end

-- delete elements with number value 1
function delete_pos_1(a)
	local i=1
	while i<=#a do
		if type(a[i])=="number" and a[i] == 1 then
			table.remove(a,i)
		else
			i = i+1
		end
	end
	return a
end

-- find pos of the next eol and pos of the next non-eol character after eol
function find_next_line(s, pos)
	local p1, p2
	p1 = string.find(s,"[\r\n]",pos)
	if p1 then
		p2 = p1
		p1 = p1-1
		if string.sub(s,p2,p2)=='\r' then p2=p2+1 end
		if string.sub(s,p2,p2)=='\n' then p2=p2+1 end
		if p2>#s then p2=nil end
	else
		p1 = #s
	end
	return p1,p2
end

function http_dissect_header(header)
	local p1,p2
	p1,p2 = string.find(header,":")
	if p1 then
		p2=string.find(header,"[^ \t]",p2+1)
		return string.sub(header,1,p1-1), p2 and string.sub(header,p2) or "", p1-1, p2 or #header
	end
	return nil
end
-- make table with structured http header representation
function http_dissect_headers(http, pos)
	local eol,pnext,header,value,idx,headers,pos_endheader,pos_startvalue
	headers={}
	while pos do
		eol,pnext = find_next_line(http,pos)
		header = string.sub(http,pos,eol)
		if #header == 0 then break end
		header,value,pos_endheader,pos_startvalue = http_dissect_header(header)
		if header then
			headers[string.lower(header)] = { header = header, value = value, pos_start = pos, pos_end = eol, pos_header_end = pos+pos_endheader-1, pos_value_start = pos+pos_startvalue-1 }
		end
		pos=pnext
	end
	return headers
end
-- make table with structured http request representation
function http_dissect_req(http)
	if not http then return nil; end
	local eol,pnext,req,hdrpos
	local pos=1
	-- skip methodeol empty line(s)
	while pos do
		eol,pnext = find_next_line(http,pos)
		req = string.sub(http,pos,eol)
		pos=pnext
		if #req>0 then break end
	end
	hdrpos = pos
	if not req or #req==0 then return nil end
	pos = string.find(req,"[ \t]")
	if not pos then return nil end
	local method = string.sub(req,1,pos-1);
	pos = string.find(req,"[^ \t]",pos+1)
	if not pos then return nil end
	pnext = string.find(req,"[ \t]",pos+1)
	if not pnext then pnext = #http + 1 end
	local uri = string.sub(req,pos,pnext-1)
	return { method = method, uri = uri, headers = http_dissect_headers(http,hdrpos) }
end
function http_dissect_reply(http)
	if not http then return nil; end
	local s, pos, code
	s = string.sub(http,1,8)
	if s~="HTTP/1.1" and s~="HTTP/1.0" then return nil end
	pos = string.find(http,"[ \t\r\n]",10)
	code = tonumber(string.sub(http,10,pos-1))
	if not code then return nil end
	pos = find_next_line(http,pos)
	return { code = code, headers = http_dissect_headers(http,pos) }
end
function dissect_url(url)
	local p1,pb,pstart,pend
	local proto, creds, domain, port, uri
	p1 = string.find(url,"[^ \t]")
	if not p1 then return nil end
	pb = p1
	pstart,pend = string.find(url,"[a-z]+://",p1)
	if pend then
		proto = string.sub(url,pstart,pend-3)
		p1 = pend+1
	end
	pstart,pend = string.find(url,"[@/]",p1)
	if pend and string.sub(url,pstart,pend)=='@' then
		creds = string.sub(url,p1,pend-1)
		p1 = pend+1
	end
	pstart,pend = string.find(url,"/",p1,true)
	if pend then
		if pend==pb then
			uri = string.sub(url,pb)
		else
			uri = string.sub(url,pend)
			domain = string.sub(url,p1,pend-1)
		end
	else
		if proto then
			domain = string.sub(url,p1)
		else
			uri = string.sub(url,p1)
		end
	end
	if domain then
		pstart,pend = string.find(domain,':',1,true)
		if pend then
			port = string.sub(domain, pend+1)
			domain = string.sub(domain, 1, pstart-1)
		end
	end
	return { proto = proto, creds = creds, domain = domain, port = port, uri=uri }
end
function dissect_nld(domain, level)
	if domain then
		local n=1
		for pos=#domain,1,-1 do
			if string.sub(domain,pos,pos)=='.' then
				if n==level then
					return string.sub(domain, pos+1)
				end
				n=n+1
			end
		end
		if n==level then
			return domain
		end
	end
	return nil
end

-- support sni=%var
function tls_mod_shim(desync, blob, modlist, payload)
	local p1,p2 = string.find(modlist,"sni=%%[^,]+")
	if p1 then
		local var = string.sub(modlist,p1+5,p2)
		local val = desync[var] or _G[var]
		if not val then
			error("tls_mod_shim: non-existent var '"..var.."'")
		end
		modlist = string.sub(modlist,1,p1+3)..val..string.sub(modlist,p2+1)
	end
	return tls_mod(blob,modlist,payload)
end

-- convert comma separated list of tcp flags to tcp.th_flags bit field
function parse_tcp_flags(s)
	local flags={FIN=TH_FIN, SYN=TH_SYN, RST=TH_RST, PSH=TH_PUSH, PUSH=TH_PUSH, ACK=TH_ACK, URG=TH_URG, ECE=TH_ECE, CWR=TH_CWR}
	local f=0
	local s_upper = string.upper(s)
	for flag in string.gmatch(s_upper, "[^,]+") do
		if flags[flag] then
 			f = bitor(f,flags[flag])
		else
			error("tcp flag '"..flag.."' is invalid")
		end
	end
	return f
end	

-- find first tcp options of specified kind in dissect.tcp.options
function find_tcp_option(options, kind)
	if options then
		for i, opt in pairs(options) do
			if opt.kind==kind then return i end
		end
	end
	return nil
end

-- find first ipv6 extension header of specified protocol in dissect.ip6.exthdr
function find_ip6_exthdr(exthdr, proto)
	if exthdr then
		for i, hdr in pairs(exthdr) do
			if hdr.type==proto then return i end
		end
	end
	return nil
end

-- insert ipv6 extension header at specified index. fix next proto chain
function insert_ip6_exthdr(ip6, idx, header_type, data)
	local prev
	if not ip6.exthdr then ip6.exthdr={} end
	if not idx then
		-- insert to the end
		idx = #ip6.exthdr+1
	elseif idx<0 or idx>(#ip6.exthdr+1) then
		error("insert_ip6_exthdr: invalid index "..idx)
	end
	if idx==1 then
		prev = ip6.ip6_nxt
		ip6.ip6_nxt = header_type
	else
		prev = ip6.exthdr[idx-1].next
		ip6.exthdr[idx-1].next = header_type
	end
	table.insert(ip6.exthdr, idx, {type = header_type, data = data, next = prev})
end
-- delete ipv6 extension header at specified index. fix next proto chain
function del_ip6_exthdr(ip6, idx)
	if idx<=0 or idx>#ip6.exthdr then
		error("delete_ip6_exthdr: nonexistent index "..idx)
	end
	local nxt = ip6.exthdr[idx].next
	if idx==1 then
		ip6.ip6_nxt = nxt
	else
		ip6.exthdr[idx-1].next = nxt
	end
	table.remove(ip6.exthdr, idx)
end
-- fills next proto fields in ipv6 header and extension headers
function fix_ip6_next(ip6, last_proto)
	if ip6.exthdr and #ip6.exthdr>0 then
		for i=1,#ip6.exthdr do
			if i==1 then
				-- first header
				ip6.ip6_nxt = ip6.exthdr[i].type
			end
			ip6.exthdr[i].next = i==#ip6.exthdr and (last_proto or IPPROTO_NONE) or ip6.exthdr[i+1].type
		end
	else
		-- no headers
		ip6.ip6_nxt = last_proto or IPPROTO_NONE
	end
end

-- reverses ip addresses, ports and seq/ack
function dis_reverse(dis)
	if dis.ip then
		dis.ip.ip_src, dis.ip.ip_dst = dis.ip.ip_dst, dis.ip.ip_src
	end
	if dis.ip6 then
		dis.ip6.ip6_src, dis.ip6.ip6_dst = dis.ip6.ip6_dst, dis.ip6.ip6_src
	end
	if dis.tcp then
		dis.tcp.th_sport, dis.tcp.th_dport = dis.tcp.th_dport, dis.tcp.th_sport
		dis.tcp.th_ack, dis.tcp.th_seq = dis.tcp.th_seq, dis.tcp.th_ack
	end
	if dis.udp then
		dis.udp.uh_sport, dis.udp.uh_dport = dis.udp.uh_dport, dis.udp.uh_sport
	end
end

-- parse autottl : delta,min-max
function parse_autottl(s)
	if s then
		local delta,min,max = string.match(s,"([-+]?%d+),(%d+)-(%d+)")
		min = tonumber(min)
		max = tonumber(max)
		delta = tonumber(delta)
		if not delta or min>max then
			error("parse_autottl: invalid value '"..s.."'")
		end
		return {delta=delta,min=min,max=max}
	else
		return nil
	end
end

-- calculate ttl value based on incoming_ttl and parsed attl definition (delta,min-max)
function autottl(incoming_ttl, attl)
	local function hop_count_guess(incoming_ttl)
		-- 18.65.168.125 ( cloudfront ) 	255
		-- 157.254.246.178 			128
		-- 1.1.1.1				 64
		-- guess original ttl. consider path lengths less than 32 hops

		local orig

		if incoming_ttl>223 then
			orig=255
		elseif incoming_ttl<128 and incoming_ttl>96 then
			orig=128
		elseif incoming_ttl<64 and incoming_ttl>32 then
			orig=64
		else
			return nil
		end

		return orig-incoming_ttl
	end
	-- return guessed fake ttl value. 0 means unsuccessfull, should not perform autottl fooling
	local function autottl_eval(hop_count, attl)
		local d,fake

		d = hop_count + attl.delta

		if d<attl.min then fake=attl.min
		elseif d>attl.max then fake=attl.max
		else fake=d
		end

		if attl.delta<0 and fake>=hop_count or attl.delta>=0 and fake<hop_count then return nil end
		return fake
	end
	local hops = hop_count_guess(incoming_ttl)
	if not hops then return nil end
	return autottl_eval(hops,attl)
end

-- apply standard header mods :

-- ip_ttl=N - set ipv.ip_ttl to N
-- ip6_ttl=N - set ip6.ip6_hlim to N
-- ip_autottl=delta,min-max - set ip.ip_ttl to auto discovered ttl
-- ip6_autottl=delta,min-max - set ip.ip_ttl to auto discovered ttl

-- ip6_hopbyhop[=hex] - add hopbyhop ipv6 header with optional data. data size must be 6+N*8. all zero by default.
-- ip6_hopbyhop2[=hex] - add second hopbyhop ipv6 header with optional data. data size must be 6+N*8. all zero by default.
-- ip6_destopt[=hex] - add destopt ipv6 header with optional data. data size must be 6+N*8. all zero by default.
-- ip6_destopt2[=hex] - add second destopt ipv6 header with optional data. data size must be 6+N*8. all zero by default.
-- ip6_routing[=hex] - add routing ipv6 header with optional data. data size must be 6+N*8. all zero by default.
-- ip6_ah[=hex] - add authentication ipv6 header with optional data. data size must be 6+N*4. 0000 + 4 random bytes by default.

-- tcp_seq=N - add N to tcp.th_seq
-- tcp_ack=N - add N to tcp.th_ack
-- tcp_ts=N - add N to timestamp value
-- tcp_md5[=hex] - add MD5 header with optional 16-byte data. all zero by default.
-- tcp_flags_set=<list> - set tcp flags in comma separated list
-- tcp_flags_unset=<list> - unset tcp flags in comma separated list
-- tcp_ts_up - move timestamp tcp option to the top if it's present. this allows linux not to accept badack segments without badseq. this is very strange discovery but it works.

-- fool - custom fooling function : fool_func(dis, fooling_options)
function apply_fooling(desync, dis, fooling_options)
	local function prepare_bin(hex,def)
		local bin = parse_hex(hex)
		if not bin then error("apply_fooling: invalid hex string '"..hex.."'") end
		return #bin>0 and bin or def
	end
	local function ttl_discover(arg_ttl,arg_autottl)
		local ttl
		if arg_autottl and desync.track then
			if desync.track.incoming_ttl then
				-- use lua_cache to store discovered autottl
				if type(desync.track.lua_state.autottl_cache)~="table" then desync.track.lua_state.autottl_cache={} end
				if type(desync.track.lua_state.autottl_cache[desync.func_instance])~="table" then desync.track.lua_state.autottl_cache[desync.func_instance]={} end
				if not desync.track.lua_state.autottl_cache[desync.func_instance].autottl_found then
					desync.track.lua_state.autottl_cache[desync.func_instance].autottl = autottl(desync.track.incoming_ttl,parse_autottl(arg_autottl))
					if desync.track.lua_state.autottl_cache[desync.func_instance].autottl then
						desync.track.lua_state.autottl_cache[desync.func_instance].autottl_found = true
							DLOG("apply_fooling: discovered autottl "..desync.track.lua_state.autottl_cache[desync.func_instance].autottl)
					else
						DLOG("apply_fooling: could not discover autottl")
					end
				elseif desync.track.lua_state.autottl_cache[desync.func_instance].autottl then
					DLOG("apply_fooling: using cached autottl "..desync.track.lua_state.autottl_cache[desync.func_instance].autottl)
				end
				ttl=desync.track.lua_state.autottl_cache[desync.func_instance].autottl
			else
				DLOG("apply_fooling: cannot apply autottl because incoming ttl unknown")
			end
		end
		if not ttl and tonumber(arg_ttl) then
			ttl = tonumber(arg_ttl)
		end
		--io.stderr:write("TTL "..tostring(ttl).."\n")
		return ttl
	end
	local function move_ts_top()
		local tsidx = find_tcp_option(dis.tcp.options, TCP_KIND_TS)
		if tsidx and tsidx>1 then
			table.insert(dis.tcp.options, 1, dis.tcp.options[tsidx])
			table.remove(dis.tcp.options, tsidx + 1)
		end
	end
	-- take default fooling from desync.arg
	if not fooling_options then fooling_options = desync.arg end
	-- use current packet if dissect not given
	if not dis then dis = desync.dis end
	if dis.tcp then
		if tonumber(fooling_options.tcp_seq) then
			dis.tcp.th_seq = u32add(dis.tcp.th_seq, fooling_options.tcp_seq)
		end
		if tonumber(fooling_options.tcp_ack) then
			dis.tcp.th_ack = u32add(dis.tcp.th_ack, fooling_options.tcp_ack)
		end
		if fooling_options.tcp_flags_unset then
			dis.tcp.th_flags = bitand(dis.tcp.th_flags, bitnot(parse_tcp_flags(fooling_options.tcp_flags_unset)))
		end
		if fooling_options.tcp_flags_set then
			dis.tcp.th_flags = bitor(dis.tcp.th_flags, parse_tcp_flags(fooling_options.tcp_flags_set))
		end
		if tonumber(fooling_options.tcp_ts) then
			local idx = find_tcp_option(dis.tcp.options,TCP_KIND_TS)
			if idx and (dis.tcp.options[idx].data and #dis.tcp.options[idx].data or 0)==8 then
				dis.tcp.options[idx].data = bu32(u32add(u32(dis.tcp.options[idx].data),fooling_options.tcp_ts))..string.sub(dis.tcp.options[idx].data,5)
			else
				DLOG("apply_fooling: timestamp tcp option not present or invalid")
			end
		end
		if fooling_options.tcp_md5 then
			if find_tcp_option(dis.tcp.options,TCP_KIND_MD5) then
				DLOG("apply_fooling: md5 option already present")
			else
				table.insert(dis.tcp.options,{kind=TCP_KIND_MD5, data=prepare_bin(fooling_options.tcp_md5,brandom(16))})
			end
		end
		if fooling_options.tcp_ts_up then
			move_ts_top(dis.tcp.options)
		end
	end
	if dis.ip6 then
		local bin
		if fooling_options.ip6_hopbyhop then
			bin = prepare_bin(fooling_options.ip6_hopbyhop,"\x00\x00\x00\x00\x00\x00")
			insert_ip6_exthdr(dis.ip6,nil,IPPROTO_HOPOPTS,bin)
		end
		if fooling_options.ip6_hopbyhop2 then
			bin = prepare_bin(fooling_options.ip6_hopbyhop2,"\x00\x00\x00\x00\x00\x00")
			insert_ip6_exthdr(dis.ip6,nil,IPPROTO_HOPOPTS,bin)
		end
		-- for possible unfragmentable part
		if fooling_options.ip6_destopt then
			bin = prepare_bin(fooling_options.ip6_destopt,"\x00\x00\x00\x00\x00\x00")
			insert_ip6_exthdr(dis.ip6,nil,IPPROTO_DSTOPTS,bin)
		end
		if fooling_options.ip6_routing then
			bin = prepare_bin(fooling_options.ip6_routing,"\x00\x00\x00\x00\x00\x00")
			insert_ip6_exthdr(dis.ip6,nil,IPPROTO_ROUTING,bin)
		end
		-- for possible fragmentable part
		if fooling_options.ip6_destopt2 then
			bin = prepare_bin(fooling_options.ip6_destopt2,"\x00\x00\x00\x00\x00\x00")
			insert_ip6_exthdr(dis.ip6,nil,IPPROTO_DSTOPTS,bin)
		end
		if fooling_options.ip6_ah then
			-- by default truncated authentication header - only 6 bytes
			bin = prepare_bin(fooling_options.ip6_ah,"\x00\x00"..brandom(4))
			insert_ip6_exthdr(dis.ip6,nil,IPPROTO_AH,bin)
		end
	end
	if dis.ip then
		local ttl = ttl_discover(fooling_options.ip_ttl,fooling_options.ip_autottl)
		if ttl then dis.ip.ip_ttl = ttl end
	end
	if dis.ip6 then
		local ttl = ttl_discover(fooling_options.ip6_ttl,fooling_options.ip6_autottl)
		if ttl then dis.ip6.ip6_hlim = ttl end
	end

	if fooling_options.fool and #fooling_options.fool>0 then
		if type(_G[fooling_options.fool])=="function" then
			DLOG("apply_fooling: calling '"..fooling_options.fool.."'")
			_G[fooling_options.fool](dis, fooling_options)
		else
			error("apply_fooling: fool function '"..tostring(fooling_options.fool).."' does not exist")
		end
	end
end


-- assign dis.ip.ip_id value according to policy in ipid_options or desync.arg. apply def or "seq" policy if no ip_id options
-- ip_id=seq|rnd|zero|none
-- ip_id_conn - in 'seq' mode save current ip_id in track.lua_state to use it between packets
-- remember ip_id in desync
function apply_ip_id(desync, dis, ipid_options, def)
	-- use current packet if dissect not given
	if not dis then dis = desync.dis end
	if dis.ip then -- ip_id is ipv4 only, ipv6 doesn't have it
		-- take default ipid options from desync.arg
		if not ipid_options then ipid_options = desync.arg end
		local mode = ipid_options.ip_id or def or "seq"
		if mode == "seq" then
			if desync.track and ipid_options.ip_id_conn then
				dis.ip.ip_id = desync.track.lua_state.ip_id or dis.ip.ip_id
				desync.track.lua_state.ip_id = dis.ip.ip_id + 1
			else
				dis.ip.ip_id = desync.ip_id or dis.ip.ip_id
				desync.ip_id = dis.ip.ip_id + 1
			end
		elseif mode == "zero" then
			dis.ip.ip_id = 0
		elseif mode == "rnd" then
			dis.ip.ip_id = math.random(1,0xFFFF)
		end
	end
end


-- return length of ipv4 or ipv6 header without options and extension headers. should be 20 for ipv4 and 40 for ipv6.
function l3_base_len(dis)
	if dis.ip then
		return IP_BASE_LEN
	elseif dis.ip6 then
		return IP6_BASE_LEN
	else
		return 0
	end
end
-- return length of ipv4 options or summary length of all ipv6 extension headers
-- ip6_exthdr_last_idx - count lengths for headers up to this index
function l3_extra_len(dis, ip6_exthdr_last_idx)
	local l=0
	if dis.ip then
		if dis.ip.options then
			l = bitand(#dis.ip.options+3,NOT3)
		end
	elseif dis.ip6 and dis.ip6.exthdr then
		local ct
		if ip6_exthdr_last_idx and ip6_exthdr_last_idx<=#dis.ip6.exthdr then
			ct = ip6_exthdr_last_idx
		else
			ct = #dis.ip6.exthdr
		end
		for i=1, ct do
			if dis.ip6.exthdr[i].type == IPPROTO_AH then
				-- length in 32-bit words
				l = l + bitand(3+2+#dis.ip6.exthdr[i].data,NOT3)
			else
				-- length in 64-bit words
				l = l + bitand(7+2+#dis.ip6.exthdr[i].data,NOT7)
			end
		end
	end
	return l
end
-- return length of ipv4/ipv6 header with options/extension headers
function l3_len(dis)
	return l3_base_len(dis)+l3_extra_len(dis)
end
-- return length of tcp/udp headers without options. should be 20 for tcp and 8 for udp.
function l4_base_len(dis)
	if dis.tcp then
		return TCP_BASE_LEN
	elseif dis.udp then
		return UDP_BASE_LEN
	else
		return 0
	end
end
-- return length of tcp options or 0 if not tcp
function l4_extra_len(dis)
	local l=0
	if dis.tcp and dis.tcp.options then
		for i=1, #dis.tcp.options do
			l = l + 1
			if dis.tcp.options[i].kind~=TCP_KIND_NOOP and dis.tcp.options[i].kind~=TCP_KIND_END then
				l = l + 1
				if dis.tcp.options[i].data then l = l + #dis.tcp.options[i].data end
			end
		end
		-- 4 byte aligned
		l = bitand(3+l,NOT3)
	end
	return l
end
-- return length of tcp header with options or base length of udp header - 8 bytes
function l4_len(dis)
	return l4_base_len(dis)+l4_extra_len(dis)
end
-- return summary extra length of ipv4/ipv6 and tcp headers. 0 if no options, no ext headers
function l3l4_extra_len(dis)
	return l3_extra_len(dis)+l4_extra_len(dis)
end
-- return summary length of ipv4/ipv6 and tcp/udp headers
function l3l4_len(dis)
	return l3_len(dis)+l4_len(dis)
end
-- return summary length of ipv4/ipv6 , tcp/udp headers and payload
function packet_len(dis)
	return l3l4_len(dis) + #dis.payload
end

-- option : ipfrag.ipfrag_disorder - send fragments from last to first
function rawsend_dissect_ipfrag(dis, options)
	if options and options.ipfrag and options.ipfrag.ipfrag then
		local frag_func = options.ipfrag.ipfrag=="" and "ipfrag2" or options.ipfrag.ipfrag
		if type(_G[frag_func]) ~= "function" then
			error("rawsend_dissect_ipfrag: ipfrag function '"..tostring(frag_func).."' does not exist")
		end
		local fragments = _G[frag_func](dis, options.ipfrag)

		-- allow ipfrag function to do extheader magic with non-standard "next protocol"
		-- NOTE : dis.ip6 must have valid next protocol fields !!!!!
		local reconstruct_frag = options.reconstruct and deepcopy(options.reconstruct) or {}
		reconstruct_frag.ip6_preserve_next = true

		if fragments then
			if options.ipfrag.ipfrag_disorder then
				for i=#fragments,1,-1 do
					DLOG("sending ip fragment "..i)
					-- C function
					if not rawsend_dissect(fragments[i], options.rawsend, reconstruct_frag) then return false end
				end
			else
				for i, d in pairs(fragments) do
					DLOG("sending ip fragment "..i)
					-- C function
					if not rawsend_dissect(d, options.rawsend, reconstruct_frag) then return false end
				end
			end
			return true
		end
		-- ipfrag failed. send unfragmented
	end
	-- C function
	return rawsend_dissect(dis, options and options.rawsend, options and options.reconstruct)
end

-- send dissect with tcp segmentation based on mss value. appply specified rawsend options.
function rawsend_dissect_segmented(desync, dis, mss, options)
	local discopy = deepcopy(dis)
	apply_fooling(desync, discopy, options and options.fooling)

	if dis.tcp then
		local extra_len = l3l4_extra_len(discopy)
		if extra_len >= mss then return false end
		local max_data = mss - extra_len
		if #discopy.payload > max_data then
			local pos=1
			local len
			local payload=discopy.payload

			while pos <= #payload do
				len = #payload - pos + 1
				if len > max_data then len = max_data end
				discopy.payload = string.sub(payload,pos,pos+len-1)
				apply_ip_id(desync, discopy, options and options.ipid)
				if not rawsend_dissect_ipfrag(discopy, options) then
					-- stop if failed
					return false
				end
				discopy.tcp.th_seq = discopy.tcp.th_seq + len
				pos = pos + len
			end
			return true
		end
	end
	apply_ip_id(desync, discopy, options and options.ipid)
	-- no reason to segment
	return rawsend_dissect_ipfrag(discopy, options)
end

-- send specified payload based on existing L3/L4 headers in the dissect. add seq to tcp.th_seq.
function rawsend_payload_segmented(desync, payload, seq, options)
	options = options or desync_opts(desync)
	local dis = deepcopy(desync.dis)
	if payload then dis.payload = payload end
	if dis.tcp and seq then
		dis.tcp.th_seq = dis.tcp.th_seq + seq
	end
	return rawsend_dissect_segmented(desync, dis, desync.tcp_mss, options)
end


-- check if desync.outgoing comply with arg.dir or def if it's not present or "out" of they are not present both. dir can be "in","out","any"
function direction_check(desync, def)
	local dir = desync.arg.dir or def or "out"
	return desync.outgoing and desync.arg.dir~="in" or not desync.outgoing and dir~="out"
end
-- if dir "in" or "out" cutoff current desync function from opposite direction
function direction_cutoff_opposite(ctx, desync, def)
	local dir = desync.arg.dir or def or "out"
	if dir=="out" then
		-- cutoff in
		instance_cutoff_shim(ctx, desync, false)
	elseif dir=="in" then
		-- cutoff out
		instance_cutoff_shim(ctx, desync, true)
	end
end

-- return true if l7payload matches filter l7payload_filter - comma separated list of payload types
function payload_match_filter(l7payload, l7payload_filter, def)
	local argpl = l7payload_filter or def or "known"
	local neg = string.sub(argpl,1,1)=="~"
	local pl = neg and string.sub(argpl,2) or argpl
	return neg ~= (in_list(pl, "all") or in_list(pl, l7payload) or in_list(pl, "known") and l7payload~="unknown" and l7payload~="empty")
end
-- check if desync payload type comply with payload type list in arg.payload
-- if arg.payload is not present - check for known payload - not empty and not unknown (nfqws1 behavior without "--desync-any-protocol" option)
-- if arg.payload is prefixed with '~' - it means negation
function payload_check(desync, def)
	local b = payload_match_filter(desync.l7payload, desync.arg.payload, def)
	if not b and b_debug then
		local argpl = desync.arg.payload or def or "known"
		DLOG("payload_check: payload '"..desync.l7payload.."' does not pass '"..argpl.."' filter")
	end
	return b
end

-- return name of replay drop field in track.lua_state for the current desync function instance
function replay_drop_key(desync)
	return desync.func_instance .. "_replay_drop"
end
-- set/unset replay drop flag in track.lua_state for the current desync function instance
function replay_drop_set(desync, v)
	if desync.track then
		if v == nil then v=true end
		local rdk = replay_drop_key(desync)
		if v then
			if desync.replay then desync.track.lua_state[replay_drop_key] = true end
		else
			desync.track.lua_state[replay_drop_key] = nil
		end
	end
end
-- auto unset replay drop flag if desync is not replay or it's the last replay piece
-- return true if the caller should return VERDICT_DROP
function replay_drop(desync)
	if desync.track then
		local drop = desync.replay and desync.track.lua_state[replay_drop_key]
		if not desync.replay or desync.replay_piece_last then
			-- replay stopped or last piece of reasm
			replay_drop_set(desync, false)
		end
		if drop then
			DLOG("dropping replay packet because reasm was already sent")
			return true
		end
	end
	return false
end
-- true if desync is not replay or it's the first replay piece
function replay_first(desync)
	return not desync.replay or desync.replay_piece==1
end

-- generate random host
-- template "google.com", len=16 : h82aj.google.com
-- template "google.com", len=11 : .google.com
-- template "google.com", len=10 : google.com
-- template "google.com", len=7 : gle.com
-- no template, len=6 : b8c54a
-- no template, len=7 : u9a.edu
-- no template, len=10 : jgha7c.com
function genhost(len, template)
	if template and #template>0 then
		if len <= #template then
			return string.sub(template,#template-len+1)
		elseif len==(#template+1) then
			return "."..template
		else
			return brandom_az(1)..brandom_az09(len-#template-2).."."..template
		end
	else
		if len>=7 then
			local tlds = {"com","org","net","edu","gov","biz"}
			local tld = tlds[math.random(#tlds)]
			return brandom_az(1)..brandom_az09(len-#tld-1-1).."."..tld
		else
			return brandom_az(1)..brandom_az09(len-1)
		end
	end
end

-- return ip addr of target host in text form
function host_ip(desync)
	return desync.target.ip and ntop(desync.target.ip) or desync.target.ip6 and ntop(desync.target.ip6)
end
-- return hostname of target host if present or ip address in text form otherwise
function host_or_ip(desync)
	if desync.track and desync.track.hostname then
		return desync.track.hostname
	end
	return host_ip(desync)
end

function is_absolute_path(path)
	if string.sub(path,1,1)=='/' then return true end
	local un = uname()
	return string.sub(un.sysname,1,6)=="CYGWIN" and string.sub(path,2,2)==':'
end
function append_path(path,file)
	return string.sub(path,#path,#path)=='/' and path..file or path.."/"..file
end
function writeable_file_name(filename)
	if is_absolute_path(filename) then return filename end
	local writedir = os.getenv("WRITEABLE")
	if not writedir then return filename end
	return append_path(writedir, filename)
end

-- arg : wsize=N . tcp window size
-- arg : scale=N . tcp option scale factor
-- return : true of changed anything
function wsize_rewrite(dis, arg)
	local b = false
	if arg.wsize then
		local wsize = tonumber(arg.wsize)
		DLOG("wsize_rewrite: window size "..dis.tcp.th_win.." => "..wsize)
		dis.tcp.th_win = tonumber(arg.wsize)
		b = true
	end
	if arg.scale then
		local scale = tonumber(arg.scale)
		local i = find_tcp_option(dis.tcp.options, TCP_KIND_SCALE)
		if i then
			local oldscale = u8(dis.tcp.options[i].data)
			if scale>oldscale then
				DLOG("wsize_rewrite: not increasing scale factor")
			elseif scale<oldscale then
				DLOG("wsize_rewrite: scale factor "..oldscale.." => "..scale)
				dis.tcp.options[i].data = bu8(scale)
				b = true
			end
		end
	end
	return b
end

-- standard fragmentation to 2 ip fragments
-- function returns 2 dissects with fragments
-- option : ipfrag_pos_udp - udp frag position. ipv4 : starting from L4 header. ipb6: starting from fragmentable part. must be multiple of 8. default 8
-- option : ipfrag_pos_tcp - tcp frag position. ipv4 : starting from L4 header. ipb6: starting from fragmentable part. must be multiple of 8. default 32
-- option : ipfrag_next - next protocol field in ipv6 fragment extenstion header of the second fragment. same as first by default.
function ipfrag2(dis, ipfrag_options)
	local function frag_idx(exthdr)
		-- fragment header after hopbyhop, destopt, routing
		-- allow second destopt header to be in fragmentable part
		-- test case : --lua-desync=send:ipfrag:ipfrag_pos_tcp=40:ip6_hopbyhop:ip6_destopt:ip6_destopt2
		-- WINDOWS may not send second ipv6 fragment with next protocol 60 (destopt)
		-- test case windows : --lua-desync=send:ipfrag:ipfrag_pos_tcp=40:ip6_hopbyhop:ip6_destopt:ip6_destopt2:ipfrag_next=255
		if exthdr then
			local first_destopts
			for i=1,#exthdr do
				if exthdr[i].type==IPPROTO_DSTOPTS then
					first_destopts = i
					break
				end
			end
			for i=#exthdr,1,-1 do
				if exthdr[i].type==IPPROTO_HOPOPTS or exthdr[i].type==IPPROTO_ROUTING or (exthdr[i].type==IPPROTO_DSTOPTS and i==first_destopts) then
					return i+1
				end
			end
		end
		return 1
	end

	local pos
	local dis1, dis2
	local l3

	if dis.tcp then
		pos = ipfrag_options.ipfrag_pos_tcp or 32
	elseif dis.udp then
		pos = ipfrag_options.ipfrag_pos_udp or 8
	else
		pos = ipfrag_options.ipfrag_pos or 32
	end

	DLOG("ipfrag2")

	if not pos then
		error("ipfrag2: no frag position")
	end
	l3 = l3_len(dis)
	if bitand(pos,7)~=0 then
		error("ipfrag2: frag position must be multiple of 8")
	end
	if (pos+l3)>0xFFFF then
		error("ipfrag2: too high frag offset")
	end
	local plen = l3 + l4_len(dis) + #dis.payload
	if (pos+l3)>=plen then
		DLOG("ipfrag2: ip frag pos exceeds packet length. ipfrag cancelled.")
		return nil
	end

	if dis.ip then
		-- ipv4 frag is done by both lua and C part
		-- lua code must correctly set ip_len, IP_MF and ip_off and provide full unfragmented payload
		-- ip_len must be set to valid value as it would appear in the fragmented packet
		-- ip_off must be set to fragment offset and IP_MF bit must be set if it's not the last fragment
		-- C code constructs unfragmented packet then moves everything after ip header according to ip_off and ip_len

		-- ip_id must not be zero or fragment will be dropped
		local ip_id = dis.ip.ip_id==0 and math.random(1,0xFFFF) or dis.ip.ip_id
		dis1 = deepcopy(dis)
		-- ip_len holds the whole packet length starting from the ip header. it includes ip, transport headers and payload
		dis1.ip.ip_len = l3 + pos -- ip header + first part up to frag pos
		dis1.ip.ip_off = IP_MF -- offset 0, IP_MF - more fragments
		dis1.ip.ip_id = ip_id
		dis2 = deepcopy(dis)
		dis2.ip.ip_off = bitrshift(pos,3) -- offset = frag pos, IP_MF - not set
		dis2.ip.ip_len = plen - pos -- unfragmented packet length - frag pos
		dis2.ip.ip_id = ip_id
	end

	if dis.ip6 then
		-- ipv6 frag is done by both lua and C part
		-- lua code must insert fragmentation extension header at any desirable position, fill fragment offset, more fragments flag and ident
		-- lua must set up ip6_plen as it would appear in the fragmented packet
		-- C code constructs unfragmented packet then moves fragmentable part as needed

		local idxfrag = frag_idx(dis.ip6.exthdr)
		local l3extra = l3_extra_len(dis, idxfrag-1) + 8 -- all ext headers before frag + 8 bytes for frag header
		local ident = math.random(1,0xFFFFFFFF)

		dis1 = deepcopy(dis)
		insert_ip6_exthdr(dis1.ip6, idxfrag, IPPROTO_FRAGMENT, bu16(IP6F_MORE_FRAG)..bu32(ident))
		dis1.ip6.ip6_plen = l3extra + pos
		dis2 = deepcopy(dis)
		insert_ip6_exthdr(dis2.ip6, idxfrag, IPPROTO_FRAGMENT, bu16(pos)..bu32(ident))
		-- only next proto of the first fragment is considered by standard
		-- fragments with non-zero offset can have different "next protocol" field
		-- this can be used to evade protection systems
		if ipfrag_options.ipfrag_next then
			dis2.ip6.exthdr[idxfrag].next = tonumber(ipfrag_options.ipfrag_next)
		end
		dis2.ip6.ip6_plen = plen - IP6_BASE_LEN + 8 - pos -- packet len without frag + 8 byte frag header - ipv6 base header
	end

	return {dis1,dis2}
end
