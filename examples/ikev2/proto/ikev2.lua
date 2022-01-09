------------------------------------------------------------------------
--- @file ikev2.lua
--- @brief (IKEv2) utility.
--- Utility functions for the IKEv2 structs 
--- Includes:
--- TODO
---
--- The newProtocolTemplate.lua was used.
------------------------------------------------------------------------

local ffi = require "ffi"
require "proto.template"
local initHeader = initHeader

---------------------------------------------------------------------------
---- IKEv2 constants 
---------------------------------------------------------------------------

local ikev2 = {}

---------------------------------------------------------------------------
---- IKEv2 header 
---------------------------------------------------------------------------

ikev2.default = {}
ikev2.default.headerFormat = [[
	uint64_t initiatorSPI;
	uint64_t responderSPI;
	uint8_t nextPayload;
	uint8_t version;
	uint8_t type;
	uint8_t flags;
	uint32_t messageID;
	uint32_t length;
]]
ikev2.default.headerVariableMember = nil

ikev2.payload = {}
ikev2.payload.headerFormat = [[
	uint8_t nextPayload;
	uint8_t critical;
	uint8_t reserved;
	uint16_t length;
]]
ikev2.payload.headerVariableMember = nil

ikev2.defaultType = "default"

local ikev2Header = initHeader(ikev2.default.headerFormat)
local ikev2PayloadHeader = initHeader(ikev2.payload.headerFormat)
ikev2Header.__index = ikev2Header
ikev2PayloadHeader.__index = ikev2PayloadHeader


function ikev2Header:fill(args, pre)
		args = args or {}
		pre = pre or "ikev2"

		-- TODO
end

function ikev2PayloadHeader:fill(args, pre)
	args = args or {}
	-- no default pre
	-- TODO
end

function ikev2Header:resolveNextHeader()
	if self.nextPayload == 0 then
		return nil
	else 
		return 'ikev2payload'
	end 
end


function ikev2PayloadHeader:resolveNextHeader()
	if self.nextPayload == 0 then
		return nil
	else
		return 'ikev2payload'
	end
end

function ikev2Header:setDefaultNamedArgs(pre, namedArgs, nextHeader, accumulatedLength)
	if not namedArgs[pre .. "Length"] and namedArgs["pktLength"] then
		namedArgs[pre .. "Length"] = namedArgs["pktLength"] - accumulatedLength
	end
end

function ikev2PayloadHeader:setDefaultNamedArgs(pre, namedArgs, nextHeader, accumulatedLength)
	return namedArgs
end


------------------------------------------------------------------------
---- Metatypes
------------------------------------------------------------------------

ikev2.default.metatype = ikev2Header
ikev2.payload.metatype = ikev2PayloadHeader

------------------------------------------------------------------------
---- Changes to other modules
------------------------------------------------------------------------

local proto = require "proto.proto"
proto.ikev2 = ikev2

local pkt = require "packet"

pkt.getIKEv24Packet = createStack('eth', 'ip4', 'udp', 'ikev2')
pkt.getIKEv26Packet = createStack('eth', 'ip6', 'udp', 'ikev2')
pkt.getIKEv2Packet = function(self, ip4)
	ip4 = ip4 == nil or ip4
	if ip4 then 
		return pkt.getIKEv24Packet(self) 
	else 
		return pkt.getIKEv26Packet(self) 
	end
end

pkt.getIKEv2Payload4Packet = createStack('eth', 'ip4', 'udp', 'ikev2', {'ikev2', subType = 'payload', name = 'payload1'})
pkt.getIKEv2Payload6Packet = createStack('eth', 'ip6', 'udp', 'ikev2', {'ikev2', subType = 'payload', name = 'payload1'})
pkt.getIKEv2PayloadPacket = function(self, ip4)
	ip4 = ip4 == nil or ip4
	if ip4 then 
		return pkt.getIKEv2Payload4Packet(self) 
	else 
		return pkt.getIKEv2Payload6Packet(self) 
	end
end