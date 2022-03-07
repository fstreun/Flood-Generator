local lm = require "libmoon"
local log = require "log"
local stats = require "stats"
local device = require "device"
local memory = require "memory"
local arp = require "proto.udp"
local arp = require "proto.arp"
local eth = require "proto.ethernet"
local pcap = require "pcap"

local barrier = require "barrier"

local ip = require "proto.ip4"

local mod = {}

-- the configure function is called on startup with a pre-initialized command line parser
function mod.configure_pars(parser)
    parser:description("Generic attack interface.")
    parser:argument("dev", "Devices to use."):args("+"):convert(tonumber)
    parser:option("--threads", "Number of threads per device."):args(1):convert(tonumber):default(1)
    parser:option("--rate", "Transmit rate in Mbit/s per device."):args(1):convert(tonumber)
    parser:option("--seconds", "Stop after n seconds.")

    -- ARP
    parser:option("--arp", "Run also the ARP protocol. Requires a source IP to be specified."):args(1)
    parser:option("--ipGw",
        "Gateway IP to resolve ethernet destination mac address using arp. Requires arp to be activated."):args(1)

    -- packet manipulations
    parser:option("--l4", "Level 4 protocol used (udp, tcp, auto). Default: udp"):args(1):default("udp")
    parser:option("--tcpSrc", "Source TCP port to be used."):args(1):convert(tonumber)
    parser:option("--tcpDst", "Destination TCP port to be used."):args(1):convert(tonumber)
    parser:option("--udpSrc", "Source UDP port to be used."):args(1):convert(tonumber)
    parser:option("--udpDst", "Destination UDP port to be used."):args(1):convert(tonumber)
    parser:option("--ip4Src", "Source IP address to be used."):args(1)
    parser:option("--ip4Dst", "Destination IP address to be used."):args(1)
    parser:option("--ethSrc", "Source MAC address to be used. If not given the real MAC address is used."):args(1)
    parser:option("--ethDst",
        "Destination MAC address to be used (gateway mac address). If not given and ARP is activated then the ipGw is used to resolve a ethDst.")
        :args(1)

    -- NIC offloading options
    parser:flag("--notUpdateIPChecksum", "Avoid calculation/offloading of IP checksum.")
    parser:flag("--notUpdateUDPChecksum", "Avoid calculation/offloading of UDP checksum.")
    parser:flag("--notUpdateTCPChecksum", "Avoid calculation/offloading of TCP checksum.")

    -- output options
    parser:option("--outputDevStats", "Write device statistics to file."):args("1")
    parser:option("--outputPcap", "Write captured packets to file rx_I.pcap (I: dev). Optionally a prefix can be given.")
        :args("?")

    -- control options
    parser:flag("--syncStart", "Wait for all tasks to be prepared before any thread starts transfering.")
    parser:flag("--startConfirmation",
        "After all threads are prepared and ready to transfer, ask for confitmation to continue.")

    return
end

--- Perform all main tasks.
function mod.main(args)
    mod.main_parse_args(args)
    local devs = mod.main_devs(args)
    mod.main_arp(devs, args)
    mod.main_rx_start(devs, args)
    mod.main_tx_start(devs, args)
    mod.main_sync_start(args)
    mod.main_termination(args)
end

--- Parse the given arguments if required.
function mod.main_parse_args(args)
    local function tostring(arg)
        return arg and (arg[1] or "")
    end

    args.outputTxStats = tostring(args.outputTxStats)
    args.outputRxStats = tostring(args.outputRxStats)
    args.outputPcap = tostring(args.outputPcap)

    args.syncStart = args.syncStart or args.startConfirmation
    if args.syncStart then
        local b = {
            sync = barrier:new(#args.dev * args.threads + 1),
            start = barrier:new(#args.dev * args.threads + 1)
        }
        args.syncStart = b
    end

    if args.rate then
        args.queueRate = args.rate / args.threads
    end
end

--- Setup devices
function mod.main_devs(args)
    local devs = {}
    -- configure all devices and ARP queues
    for i, dev in ipairs(args.dev) do
        -- arp needs extra queues
        local dev = device.config {
            port = dev,
            txQueues = args.threads + (args.arp and 1 or 0),
            rxQueues = 1
        }
        devs[i] = dev

    end
    device.waitForLinks()

    if args.outputDevStats then
        -- print device statistics
        stats.startStatsTask {
            devices = devs,
            file = args.outputDevStats,
            "csv"
        }
    end

    return devs
end

--- Configure ARP and perform ARP request.
function mod.main_arp(devs, args)
    -- start ARP task
    if args.arp then
        local arpQueues = {}
        for i, dev in ipairs(devs) do
            table.insert(arpQueues, {
                rxQueue = dev:getRxQueue(0),
                txQueue = dev:getTxQueue(args.threads),
                ips = args.arp
            })
        end

        arp.startArpTask(arpQueues)
        -- do ARP lookup (if not given as argument above)
        if args.ipGw and not args.ethDst then
            log:info("Performing ARP lookup on %s, timeout 3 seconds.", args.ipGw)
            local ethDst = arp.blockingLookup(args.ipGw, 3)
            if not ethDst then
                log:info("ARP lookup failed, using default destination mac address")
                ethDst = "01:23:45:67:89:ab"
            end
            args.ethDst = ethDst
        end
        arp.stopArpTask()
        log:info("Destination mac: %s", args.ethDst)
        lm.sleepMicrosIdle(1000000)

        -- restart arp task but without rx queue.
        local newArpQueues = {}
        for i, dev in ipairs(devs) do
            table.insert(newArpQueues, {
                rxQueue = nil,
                txQueue = dev:getTxQueue(args.threads),
                ips = args.arp
            })
        end
        arp.startArpTask(newArpQueues)
        arp.waitForStartup() -- race condition with arp.handlePacket() otherwise
    end
end

--- Start all rxTasks.
function mod.main_rx_start(devs, args)

    for i, dev in ipairs(devs) do

        local queue = dev:getRxQueue(0)
        local taskId = "rx_" .. i

        -- arpID corresponds to the nic ID used in the arp application to indentify the NIC
        if args.arp then
            args.arpID = i
        end

        lm.startTask("rxTask", taskId, queue, args)
    end
end

--- Start all txTasks.
function mod.main_tx_start(devs, args)

    for i, dev in ipairs(devs) do

        for j = 1, args.threads do
            local queue = dev:getTxQueue(j - 1)
            local taskId = "tx_" .. i .. "_" .. j

            if args.rate then
                if args.rate <= 50 then
                    dev:setRate(50)
                else
                    dev:setRate(args.rate)
                end
            end

            args.ethSrc = args.ethSrc or queue -- MAC of the tx device

            lm.startTask("txTask", taskId, queue, args)
        end
    end
end

--- Wait for all txTask and ask for start confirmation.
function mod.main_sync_start(args)
    if args.syncStart then
        local answer
        args.syncStart.sync:wait()
        if args.startConfirmation then
            repeat
                lm.sleepMillisIdle(2000)
                print("Attack Prepared. Start attack (y/n)?")
                io.flush()
                answer = io.read()
            until answer == "y" or answer == "n"
            io.flush()
        end
        if answer == "n" then
            lm.stop()
        end
        args.syncStart.start:wait()
    end
    -- signal that the attack should have started by now.
    print("Attack Started")
    io.flush()
end

--- Set termination criterion.
function mod.main_termination(args)
    if args.seconds then
        lm.setRuntime(tonumber(args.seconds))
    end

    lm.waitForTasks()
end

-- check for stop singal sent to txTask
function mod.taskRunning(args)
    return lm.running()
end

--- Transmition task to be run.
--- This is just a sample function.
--- But it also shows the required calles to be done.
---@param threadId string identifies all threads spawned by libmoon
---@param queue txQueue to send packets
---@param args table contains all relevant arguments (includes controllers e.g. syncStart)
function mod.txTask(threadId, queue, args)
    log:info("Started txTask.")

    -- REQUIRED: sync all running tasks
    mod.txTask_sync_start(args)

    -- REQUIRED: running condition
    while mod.taskRunning(args) do
        lm.sleepMicrosIdle(2000)
    end

    log:info("Terminate txTask.")
end

--- Receiving task to be run.
--- This is just a sample function.
--- But it also shows the required calles to be done.
---@param threadId string identifies all threads spawned by libmoon
---@param queue rxQueue to receive packets
---@param args table contains all relevant arguments
function mod.rxTask(threadId, queue, args)
    log:info("Started rxTask.")
    local bufs = memory.bufArray()

    -- REQUIRED for outputPcap
    local pcapWriter
    if args.outputPcap then
        pcapWriter = pcap:newWriter(args.outputPcap .. threadId .. ".pcap")
    end

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

            -- REQUIRED for ARP
            if args.arpID and buf:getEthernetPacket().eth:getType() == eth.TYPE_ARP then
                -- inject arp packets to the ARP task
                -- this is done this way instead of using filters to also dump ARP packets here
                arp.handlePacket(buf, args.arpID)
            else
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

---------------------------------------------------------------------------------
---- txTask Helper Functions
---------------------------------------------------------------------------------

--- REQUIRED to be called in the txTask if ready to perform the attack.
function mod.txTask_sync_start(args)
    if args.syncStart then
        args.syncStart.sync:wait()
        args.syncStart.start:wait()
    end
end

function mod.modifyPkt(buf, args)

    local pkt
    if args.l4 == "udp" then
        pkt = buf:getUdpPacket()

        -- UDP fields
        if args.udpSrc then
            pkt.udp:setSrcPort(args.udpSrc)
        end
        if args.udpDst then
            pkt.udp:setDstPort(args.udpDst)
        end

    elseif args.l4 == "tcp" then
        pkt = buf:getTcpPacket()

        -- TCP fields
        if args.tcpSrc then
            pkt.tcp:setSrcPort(args.tcpSrc)
        end
        if args.tcpDst then
            pkt.tcp:setDstPort(args.tcpDst)
        end

    end

    -- IP fields
    if args.ip4Src then
        pkt.ip4:setSrcString(args.ip4Src)
    end

    if args.ip4Dst then
        pkt.ip4:setDstString(args.ip4Dst)
    end

    -- Ethernet fields
    if args.ethSrc then
        local src = "ethSrc"
        if type(args[src]) == "string" then
            pkt.eth:setSrcString(args[src])
        elseif type(args[src]) == "table" and args[src].id then
            pkt.eth:setSrcString((args[src].dev or args[src]):getMacString())
        else
            log:Error("Wrong ethSrc type.")
        end
    end
    if args.ethDst then
        local dst = "ethDst"
        if type(args[dst]) == "string" then
            pkt.eth:setDstString(args[dst])
        elseif type(args[dst]) == "table" and args[dst].id then
            pkt.eth:setDstString((args[dst].dev or args[dst]):getMacString())
        else
            log:Error("Wrong ethDst type.")
        end
    end

    return buf
end

--- REQUIRED to be called for each buffer to configure checksum offloading:
--- notUpdateIPChecksum, notUpdateUDPChecksum, notUpdateTCPChecksum
function mod.txTask_setChecksumOffloading(buf, args)
    local updateIPChecksum = not args.notUpdateIPChecksum
    local updateUDPChecksum = not args.notUpdateUDPChecksum
    local updateTCPChecksum = not args.notUpdateTCPChecksum

    if updateIPChecksum then
        -- Offload IP checksum calculation
        -- Must be set to zero!
        buf:getIPPacket().ip4:setChecksum()
        buf:offloadIPChecksum()
    end

    local l4 = args.l4
    if l4 == "auto" then
        local protocol = buf:getIPPacket().ip4:getProtocol()
        if protocol == ip.PROTO_UDP then
            l4 = "udp"
        end
        if protocol == ip.PROTO_TCP then
            l4 = "tcp"
        end
    end

    if updateUDPChecksum and l4 == "udp" then
        buf:offloadUdpChecksum()
    end

    if updateTCPChecksum and l4 == "tcp" then
        buf:offloadTcpChecksum()
    end
end

--- reliably send n packets. Similar to queue:sendN(bufArray, n).
--- But using the provided function sometimes causes a segmentation fault.
--- By pausing the process when no packets were sent seems to fix the problem.
function mod.txTask_send(queue, bufArray, n)
    n = n or bufArray.size
    local sent = 0
    repeat
        local newSent = queue:trySend(bufArray, sent, n - sent)
        sent = sent + newSent

        -- pause process if no packets were sent
        if newSent < 1 then
            lm.sleepMicrosIdle(0)
        end
    until (sent >= n)
end

---------------------------------------------------------------------------------
---- Required Global Variables (with possible defaults)
---------------------------------------------------------------------------------
-- required by libmoon
configure = mod.configure_pars
master = mod.main

-- required global variables if mod.txTaskRunner is used
txTask = mod.txTask
-- required global variables if mod.rxTaskRunner is used
rxTask = mod.rxTask

return mod
