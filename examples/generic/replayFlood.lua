local log    = require "log"
local memory = require "memory"
local pcap   = require "pcap"
local ffi = require "ffi"

local libmoon = require "libmoon"

local attack = require "attack"

local table_utils = require "utils.table_utils"

function configure(parser)
	attack.configure_pars(parser)
	parser:description("Replay packet flooding.")
	parser:option("--replayPcap", "Pcap file to be replayed."):args(1)
	parser:option("--replayMix", "The number of each packet in the pcap file to be sent relatively to each other."):args('*'):default(1)
	parser:option("--replaySingle", "The number of the packet in the pcap file to be sent. Overwrites the replayMix arguments."):args(1):convert(tonumber)

	parser:option("--flows", "Number of flows used in the flood by using different source ports. 0 results in 65535 flows (max port count)."):args(1):convert(tonumber):default(1)
	parser:option("--ipFlows", "Number of flows used in the flood by using different destination ip."):args(1):convert(tonumber):default(1)

	parser:option("--amount", ""):args(1):convert(tonumber)
	return parser:parse()
end

master = attack.main

local createPktBufs

function txTask(threadId, queue, args)
	log:info("Start txTask.")

	if not (type(args.replayMix) == "table") then
		local tmp = args.replayMix
		args.replayMix = {}
		args.replayMix[1] = tmp
	end

	local slowRate = false
	local lastSent = 0
	if args.rate < 100 then
		slowRate = args.queueRate
	end

	-- translate replaySingle to replayMix
	if args.replaySingle then
		args.replayMix = {}
		for i=1, args.replaySingle do
			args.replayMix[i] = 0
		end
		args.replayMix[args.replaySingle] = 1
	end

	local mempool = args.mempool or memory:createMemPool()
	local bufs = mempool:bufArray()

	local replayBufs = createPktBufs(args, mempool)

	local packetSchedule = {}
	for pkt, weight in ipairs(args.replayMix) do
		for i = 1, weight do
			packetSchedule[#packetSchedule+1] = pkt
		end
	end
	-- randominze packet schedule a bit
	packetSchedule = table_utils.shuffle(packetSchedule)

	local replayCounter = 0;
	local replayCounterMax = #packetSchedule

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

	attack.txTask_sync_start(args)
	while attack.taskRunning(args) do

		if slowRate then
			bufs:allocN(512, 1)
		else
			bufs:alloc(512)
		end
		local sizeSum = 0

		for i, buf in ipairs(bufs) do
			if replayCounter == 0 and args.amount then
				args.amount = args.amount - 1
				if args.amount < 0 then
					goto send
				end
			end

			local replayBuf = replayBufs[packetSchedule[replayCounter+1]]
			buf:setSize(replayBuf:getSize())
			ffi.copy(buf:getData(), replayBuf:getData(), replayBuf:getSize())
			
			sizeSum = sizeSum + replayBuf:getSize()

			replayCounter = (replayCounter + 1) % (replayCounterMax)

			if srcPortCounter then
				local pkt = buf:getUdpPacket()
				-- srcPort = given port + counter
				-- the other parts are to ensure 0 < port <= 65535
				local srcPort = (pkt.udp:getSrcPort() + srcPortCounter  - 1) % 65535 + 1
				pkt.udp:setSrcPort(srcPort)
				srcPortCounter = (srcPortCounter + 1) % srcPortCounterMax
			end

			if srcIPCounter then
				local pkt = buf:getIP4Packet()
				pkt.ip4.src.uint8[3] = (pkt.ip4.src.uint8[3] + srcIPCounter)
				srcIPCounter = (srcIPCounter + 1) % srcIPCounterMax
			end

			attack.txTask_setChecksumOffloading(buf, args)
		end
		::send::

		if slowRate then
			local now = libmoon.getTime()
			local sizeBit = sizeSum * 8

			while (sizeBit / (now - lastSent)) > slowRate * 1000000 do
				now = libmoon.getTime()
			end
			lastSent = now
		end
		
		attack.txTask_send(queue, bufs)
		
		if args.amount and args.amount < 0 then
			goto done
		end
	
	end
	
	::done::

	for _, buf in ipairs(replayBufs) do
		buf:free()
	end

	log:info("Terminate txTask.")
end

function createPktBufs(args, mempool)
	local pcapReader = pcap:newReader(args.replayPcap)
	local bufs = {}
	for i, _ in ipairs(args.replayMix) do
		bufs[i] = pcapReader:readSingle(mempool)
		attack.modifyPkt(bufs[i], args)
	end
	pcapReader:close()
	return bufs
end

rxTask = attack.rxTask