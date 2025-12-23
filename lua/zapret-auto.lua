-- standard automation/orchestration code
-- this is related to making dynamic strategy decisions without rewriting or altering strategy function code
-- orchestrators can decide which instances to call or not to call or pass them dynamic arguments
-- failure and success detectors test potential block conditions for orchestrators

-- standard host key generator for per-host storage
-- arg: reqhost - require hostname, do not work with ip
-- arg: nld=N - cut hostname to N level domain. NLD=2 static.intranet.microsoft.com => microsoft.com
function standard_hostkey(desync)
	local hostkey = desync.track and desync.track.hostname
	if hostkey then
		if desync.arg.nld and tonumber(desync.arg.nld)>0 and not (desync.track and desync.track.hostname_is_ip) then
			-- dissect_nld returns nil if domain is invalid or does not have this NLD
			-- fall back to original hostkey if it fails
			local hktemp = dissect_nld(hostkey, tonumber(desync.arg.nld))
			if hktemp then
				hostkey = hktemp
			end
		end
	elseif not desync.arg.reqhost then
		hostkey = host_ip(desync)
	end
	return hostkey
end

-- per-host storage
-- arg: key - a string - table name inside autostate table. to allow multiple orchestrator instances to use single host storage
-- arg: hostkey - hostkey generator function name
function automate_host_record(desync)
	local hostkey, hkf, askey

	if desync.arg.hostkey then
		if type(_G[desync.arg.hostkey])~="function" then
			error("automate: invalid hostkey function '"..desync.arg.hostkey.."'")
		end
		hkf = _G[desync.arg.hostkey]
	else
		hkf = standard_hostkey
	end
	hostkey = hkf(desync)
	if not hostkey then
		DLOG("automate: host record key unavailable")
		return nil
	end

	askey = (desync.arg.key and #desync.arg.key>0) and desync.arg.key or desync.func_instance
	DLOG("automate: host record key 'autostate."..askey.."."..hostkey.."'")
	if not autostate then
		autostate = {}
	end
	if not autostate[askey] then
		autostate[askey] = {}
	end
	if not autostate[askey][hostkey] then
		autostate[askey][hostkey] = {}
	end
	return autostate[askey][hostkey]
end
-- per-connection storage
function automate_conn_record(desync)
	if not desync.track.lua_state.automate then
		desync.track.lua_state.automate = {}
	end
	return desync.track.lua_state.automate
end

-- counts failure, optionally (if crec is given) prevents dup failure counts in a single connection
-- if 'maxtime' between failures is exceeded then failure count is reset
-- return true if threshold ('fails') is reached
-- hres is host record. host or ip bound table
-- cres is connection record. connection bound table
function automate_failure_counter(hrec, crec, fails, maxtime)
	if crec and crec.failure then
		DLOG("automate: duplicate failure in the same connection. not counted")
	else
		if crec then crec.failure = true end
		local tnow=os.time()
		if not hrec.failure_time_last then
			hrec.failure_time_last = tnow
		end
		if not hrec.failure_counter then
			hrec.failure_counter = 0
		elseif tnow>(hrec.failure_time_last + maxtime) then
			DLOG("automate: failure counter reset because last failure was "..(tnow - hrec.failure_time_last).." seconds ago")
			hrec.failure_counter = 0
		end
		hrec.failure_counter = hrec.failure_counter + 1
		hrec.failure_time_last = tnow
		if b_debug then DLOG("automate: failure counter "..hrec.failure_counter..(fails and ('/'..fails) or '')) end
		if fails and hrec.failure_counter>=fails then
			hrec.failure_counter = nil -- reset counter
			return true
		end
	end
	return false
end
-- resets failure counter if it has started counting
function automate_failure_counter_reset(hrec)
	if hrec.failure_counter then
		DLOG("automate: failure counter reset")
		hrec.failure_counter = nil
	end
end

-- location is url compatible with Location: header
-- hostname is original hostname
function is_dpi_redirect(hostname, location)
	local ds = dissect_url(location)
	if ds.domain then
		local sld1 = dissect_nld(hostname,2)
		local sld2 = dissect_nld(ds.domain,2)
		return sld2 and sld1~=sld2
	end
	return false
end

function standard_detector_defaults(arg)
	return {
		inseq = tonumber(arg.inseq) or 4096,
		retrans = tonumber(arg.retrans) or 3,
		maxseq = tonumber(arg.maxseq) or 32768,
		udp_in = tonumber(arg.udp_in) or 1,
		udp_out = tonumber(arg.udp_out) or 4,
		no_http_redirect = arg.no_http_redirect,
		no_rst = arg.no_rst
	}
end

-- standard failure detector
-- works with tcp and udp
-- detected failures:
--   incoming RST
--   incoming http redirection
--   outgoing retransmissions
--   udp too much out with too few in
-- arg: maxseq=<rseq> - tcp: test retransmissions only within this relative sequence. default is 32K
-- arg: retrans=N - tcp: retrans count threshold. default is 3
-- arg: reset - send RST to retransmitter to break long wait
-- arg: inseq=<rseq> - tcp: maximum relative sequence number to treat incoming RST as DPI reset. default is 4K
-- arg: no_http_redirect - tcp: disable http_reply dpi redirect trigger
-- arg: no_rst - tcp: disable incoming RST trigger
-- arg: udp_out - udp: >= outgoing udp packets. default is 4
-- arg: udp_in - udp: with <= incoming udp packets. default is 1
function standard_failure_detector(desync, crec)
	local arg = standard_detector_defaults(desync.arg)
	local trigger = false
	if desync.dis.tcp then
		local seq = pos_get(desync,'s')
		if desync.outgoing then
			if #desync.dis.payload>0 and arg.retrans and arg.maxseq>0 and seq<=arg.maxseq and (crec.retrans or 0)<arg.retrans then
				if is_retransmission(desync) then
					crec.retrans = crec.retrans and (crec.retrans+1) or 1
					DLOG("standard_failure_detector: retransmission "..crec.retrans.."/"..arg.retrans)
					trigger = crec.retrans>=arg.retrans
					if trigger and desync.arg.reset then
						local dis = deepcopy(desync.dis)
						dis.payload = nil
						dis_reverse(dis)
						dis.tcp.th_flags = TH_RST
						dis.tcp.th_win = desync.track and desync.track.pos.reverse.tcp.winsize or 64
						dis.tcp.options = {}
						if dis.ip6 then
							dis.ip6.ip6_flow = desync.track.pos.reverse.ip6_flow
						end
						DLOG("standard_failure_detector: sending RST to retransmitter")
						rawsend_dissect(dis)
					end
				end
			end
		else
			if not arg.no_rst and arg.inseq>0 and bitand(desync.dis.tcp.th_flags, TH_RST)~=0 and seq>=1 then
				trigger = seq<=arg.inseq
				if b_debug then
					if trigger then
						DLOG("standard_failure_detector: incoming RST s"..seq.." in range s"..arg.inseq)
					else
						DLOG("standard_failure_detector: not counting incoming RST s"..seq.." beyond s"..arg.inseq)
					end
				end
			elseif not arg.no_http_redirect and desync.l7payload=="http_reply" and desync.track.hostname then
				local hdis = http_dissect_reply(desync.dis.payload)
				if hdis and (hdis.code==302 or hdis.code==307) and hdis.headers.location and hdis.headers.location then
					trigger = is_dpi_redirect(desync.track.hostname, hdis.headers.location.value)
					if b_debug then
						if trigger then
							DLOG("standard_failure_detector: http redirect "..hdis.code.." to '"..hdis.headers.location.value.."'. looks like DPI redirect.")
						else
							DLOG("standard_failure_detector: http redirect "..hdis.code.." to '"..hdis.headers.location.value.."'. NOT a DPI redirect.")
						end
					end
				end
			end
		end
	elseif desync.dis.udp then
		if desync.outgoing then
			if arg.udp_out>0 then
				local pos_out = pos_get(desync,'n',false)
				local pos_in = pos_get(desync,'n',true)
				trigger = pos_out>=arg.udp_out and pos_in<=arg.udp_in
				if trigger then
					if b_debug then
						DLOG("standard_failure_detector: arg.udp_out "..pos_out..">="..arg.udp_out.." arg.udp_in "..pos_in.."<="..arg.udp_in)
					end
				end
			end
		end
	end
	return trigger
end

-- standard success detector
-- success means previous failures were temporary and counter should be reset
-- detected successes:
--   tcp: outgoing seq is beyond 'maxseq' and maxseq>0
--   tcp: incoming seq is beyond 'inseq' and inseq>0
--   udp: incoming packets count > `udp_in` and `udp_out`>0
-- arg: maxseq=<rseq> - tcp: success if outgoing relative sequence is beyond this value. default is 32K
-- arg: inseq=<rseq> - tcp: success if incoming relative sequence is beyond this value. default is 4K
-- arg: udp_out - udp : must be nil or >0 to test udp_in
-- arg: udp_in - udp: if number if incoming packets > udp_in it means success
function standard_success_detector(desync, crec)
	local arg = standard_detector_defaults(desync.arg)
	if desync.dis.tcp then
		local seq = pos_get(desync,'s')
		if desync.outgoing then
			if arg.maxseq>0 and seq>arg.maxseq then
				DLOG("standard_success_detector: outgoing s"..seq.." is beyond s"..arg.maxseq..". treating connection as successful")
				return true
			end
		else
			if arg.inseq>0 and seq>arg.inseq then
				DLOG("standard_success_detector: incoming s"..seq.." is beyond s"..arg.inseq..". treating connection as successful")
				return true
			end
		end
	elseif desync.dis.udp then
		if not desync.outgoing then
			local pos = pos_get(desync,'n')
			if arg.udp_out>0 and pos>arg.udp_in then
				if b_debug then
					DLOG("standard_success_detector: arg.udp_in "..pos..">"..arg.udp_in)
				end
				return true
			end
		end
	end

	return false
end

-- calls success and failure detectors
-- resets counter if success is detected
-- increases counter if failure is detected
-- returns true if failure counter exceeds threshold
function automate_failure_check(desync, hrec, crec)
	if crec.nocheck then return false end

	local failure_detector, success_detector
	if desync.arg.failure_detector then
		if type(_G[desync.arg.failure_detector])~="function" then
			error("automate: invalid failure detector function '"..desync.arg.failure_detector.."'")
		end
		failure_detector = _G[desync.arg.failure_detector]
	else
		failure_detector = standard_failure_detector
	end
	if desync.arg.success_detector then
		if type(_G[desync.arg.success_detector])~="function" then
			error("automate: invalid success detector function '"..desync.arg.success_detector.."'")
		end
		success_detector = _G[desync.arg.success_detector]
	else
		success_detector = standard_success_detector
	end

	if success_detector(desync, crec) then
		crec.nocheck = true
		DLOG("automate: success detected")
		automate_failure_counter_reset(hrec)
		return false
	end
	if failure_detector(desync, crec) then
		crec.nocheck = true
		DLOG("automate: failure detected")
		local fails = tonumber(desync.arg.fails) or 3
		local maxtime = tonumber(desync.arg.time) or 60
		return automate_failure_counter(hrec, crec, fails, maxtime)
	end

	return false
end


-- circularily change strategy numbers when failure count reaches threshold ('fails')
-- this orchestrator requires redirection of incoming traffic to cache RST and http replies !
-- each orchestrated instance must have strategy=N arg, where N starts from 1 and increment without gaps
-- if 'final' arg is present in an orchestrated instance it stops rotation
-- arg: fails=N - failture count threshold. default is 3
-- arg: time=<sec> - if last failure happened earlier than `maxtime` seconds ago - reset failure counter. default is 60.
-- arg: success_detector - success detector function name
-- arg: failure_detector - failure detector function name
-- arg: hostkey - hostkey generator function name
-- args for failure detector - see standard_failure_detector or your own detector
-- args for success detector - see standard_success_detector or your own detector
-- args for hostkey generator - see standard_hostkey or your own generator
-- test case: --in-range=-s34228 --lua-desync=circular --lua-desync=argdebug:strategy=1 --lua-desync=argdebug:strategy=2
function circular(ctx, desync)
	local function count_strategies(hrec)
		if not hrec.ctstrategy then
			local uniq={}
			local n=0
			for i,instance in pairs(desync.plan) do
				if instance.arg.strategy then
					n = tonumber(instance.arg.strategy)
					if not n or n<1 then
						error("circular: strategy number '"..tostring(instance.arg.strategy).."' is invalid")
					end
					uniq[tonumber(instance.arg.strategy)] = true
					if instance.arg.final then
						hrec.final = n
					end
				end
			end
			n=0
			for i,v in pairs(uniq) do
				n=n+1
			end
			if n~=#uniq then
				error("circular: strategies numbers must start from 1 and increment. gaps are not allowed.")
			end
			hrec.ctstrategy = n
		end
	end

	-- take over execution. prevent further instance execution in case of error
	orchestrate(ctx, desync)

	if not desync.track then
		DLOG_ERR("circular: conntrack is missing but required")
		return
	end

	local hrec = automate_host_record(desync)
	if not hrec then
		DLOG("circular: passing with no tampering")
		return
	end

	count_strategies(hrec)
	if hrec.ctstrategy==0 then
		error("circular: add strategy=N tag argument to each following instance ! N must start from 1 and increment")
	end
	if not hrec.nstrategy then
		DLOG("circular: start from strategy 1")
		hrec.nstrategy = 1
	end

	local verdict = VERDICT_PASS
	if hrec.final~=hrec.nstrategy then
		local crec = automate_conn_record(desync)
		if automate_failure_check(desync, hrec, crec) then
			hrec.nstrategy = (hrec.nstrategy % hrec.ctstrategy) + 1
			DLOG("circular: rotate strategy to "..hrec.nstrategy)
			if hrec.nstrategy == hrec.final then
				DLOG("circular: final strategy "..hrec.final.." reached. will rotate no more.")
			end
		end
	end

	DLOG("circular: current strategy "..hrec.nstrategy)
	while true do
		local instance = plan_instance_pop(desync)
		if not instance then break end
		if instance.arg.strategy and tonumber(instance.arg.strategy)==hrec.nstrategy then
			verdict = plan_instance_execute(desync, verdict, instance)
		end
	end

	return verdict
end

-- test iff functions
function cond_true(desync)
	return true
end
function cond_false(desync)
	return false
end
-- arg: percent - of true . 50 by default
function cond_random(desync)
	return math.random(0,99)<(tonumber(desync.arg.percent) or 50)
end
-- this iif function detects packets having 'arg.pattern' string in their payload
-- test case : --lua-desync=condition:iff=cond_payload_str:pattern=1234 --lua-desync=argdebug:testarg=1 --lua-desync=argdebug:testarg=2:morearg=xyz
-- test case (true)  : echo aaz1234zzz | ncat -4u 1.1.1.1 443
-- test case (false) : echo aaze124zzz | ncat -4u 1.1.1.1 443
function cond_payload_str(desync)
	if not desync.arg.pattern then
		error("cond_payload_str: missing 'pattern'")
	end
	return string.find(desync.dis.payload,desync.arg.pattern,1,true)
end
-- check iff function available. error if not
function require_iff(desync, name)
	if not desync.arg.iff then
		error(name..": missing 'iff' function")
	end
	if type(_G[desync.arg.iff])~="function" then
		error(name..": invalid 'iff' function '"..desync.arg.iff.."'")
	end
end
-- execute further desync instances only if user-provided 'iff' function returns true
-- for example, this can be used by custom protocol detectors
-- arg: iff - condition function. takes desync as arg and returns bool. (cant use 'if' because of reserved word)
-- arg: neg - invert condition function result
-- test case : --lua-desync=condition:iff=cond_random --lua-desync=argdebug:testarg=1 --lua-desync=argdebug:testarg=2:morearg=xyz
function condition(ctx, desync)
	require_iff(desync, "condition")
	orchestrate(ctx, desync)
	if logical_xor(_G[desync.arg.iff](desync), desync.arg.neg) then
		DLOG("condition: true")
		return replay_execution_plan(desync)
	else
		DLOG("condition: false")
		plan_clear(desync)
	end
end
-- clear execution plan if user provided 'iff' functions returns true
-- can be used with other orchestrators to stop execution conditionally
-- arg: iff - condition function. takes desync as arg and returns bool. (cant use 'if' because of reserved word)
-- arg: neg - invert condition function result
-- test case : --in-range=-s1 --lua-desync=circular --lua-desync=stopif:iff=cond_random:strategy=1 --lua-desync=argdebug:strategy=1 --lua-desync=argdebug:strategy=2
function stopif(ctx, desync)
	require_iff(desync, "stopif")
	orchestrate(ctx, desync)
	if logical_xor(_G[desync.arg.iff](desync), desync.arg.neg) then
		DLOG("stopif: true")
		plan_clear(desync)
	else
		-- do not do anything. allow other orchestrator to finish the plan
		DLOG("stopif: false")
	end
end

-- repeat following 'instances' 'repeats' times, execute others with no tampering
-- arg: instances - number of following instances to be repeated. 1 by default
-- arg: repeats - number of repeats
-- arg: iff - condition function to continue execution. takes desync as arg and returns bool. (cant use 'if' because of reserved word)
-- arg: neg - invert condition function result
-- arg: stop - do not replay remaining execution plan after 'instances'
-- arg: clear - clear execution plan after 'instances'
-- test case : --lua-desync=repeater:repeats=2:instances=2 --lua-desync=argdebug:v=1 --lua-desync=argdebug:v=2 --lua-desync=argdebug:v=3
function repeater(ctx, desync)
	local repeats = tonumber(desync.arg.repeats)
	if not repeats then
		error("repeat: missing 'repeats'")
	end
	local iff = desync.arg.iff or "cond_true"
	if type(_G[iff])~="function" then
		error(name..": invalid 'iff' function '"..iff.."'")
	end
	orchestrate(ctx, desync)
	local neg = desync.arg.neg
	local stop = desync.arg.stop
	local clear = desync.arg.clear
	local verdict = VERDICT_PASS
	local instances = tonumber(desync.arg.instances) or 1
	local repinst = desync.func_instance
	if instances>#desync.plan then
		instances = #desync.plan
	end
	-- save plan copy
	local plancopy = deepcopy(desync.plan)
	for r=1,repeats do
		if not logical_xor(_G[iff](desync), neg) then
			DLOG("repeater: break by iff")
			break
		end
		DLOG("repeater: "..repinst.." "..r.."/"..repeats)
		-- nested orchestrators can also pop
		local ct_end = #desync.plan - instances
		repeat
			local instance = plan_instance_pop(desync)
			verdict = plan_instance_execute(desync, verdict, instance)
		until #desync.plan <= ct_end
		-- rollback desync plan
		desync.plan = deepcopy(plancopy)
	end
	-- remove repeated instances from desync plan
	for i=1,instances do
		table.remove(desync.plan,1)
	end
	if clear then
		plan_clear(desync)
		return verdict
	elseif stop then
		return verdict
	end
	-- replay the rest
	return verdict_aggregate(verdict, replay_execution_plan(desync))
end
