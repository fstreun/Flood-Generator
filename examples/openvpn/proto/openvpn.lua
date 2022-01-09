------------------------------------------------------------------------
--- @file openvpn.lua
--- @brief (openvpn) utility.
--- Utility functions for the openvpn_header structs 
--- Includes:
--- - openvpn constants
--- - openvpn header utility
--- - Definition of openvpn packets
---
--- The newProtocolTemplate.lua was used.
------------------------------------------------------------------------

local ffi = require "ffi"
require "proto.template"
local initHeader = initHeader

local ns = require "namespaces"

local format = string.format

local fields = require "proto.fields"
fields.load_field_nbyte(8)

---------------------------------------------------------------------------
---- openvpn constants 
---------------------------------------------------------------------------

--- openvpn protocol constants
local openvpn = {}

---------------------------------------------------------------------------
---- openvpn header
---------------------------------------------------------------------------

openvpn.default = {}
openvpn.default.headerFormat = [[
	uint8_t		opcodeKeyId;
]]

openvpn.P_CONTROL_HARD_RESET_CLIENT_V2 = {}
openvpn.P_CONTROL_HARD_RESET_CLIENT_V2.headerFormat = [[
	uint8_t		opcodeKeyId;
	field_8byte	sessionId;
	uint8_t		ackPacketIdArraySize;
	// uint31_t	ackPacketIdArray[];
	uint32_t	msgPacketId;
]]


openvpn.defaultType = "default"

local openvpnHeader = initHeader(openvpn.default.headerFormat)
openvpnHeader.__index = openvpnHeader
local openvpn_P_CONTROL_HARD_RESET_CLIENT_V2 = initHeader(openvpn.P_CONTROL_HARD_RESET_CLIENT_V2.headerFormat)
openvpn_P_CONTROL_HARD_RESET_CLIENT_V2.__index = openvpn_P_CONTROL_HARD_RESET_CLIENT_V2


function openvpn_P_CONTROL_HARD_RESET_CLIENT_V2:fill(args, pre)
	
	-- (Opcode (0x07) << 3) || Key ID (0x0))
	self:setOpcodeKeyId(0x38)

	self:setSessionId(args[pre .. "SessionId"] or 0x123456789ABCDEF)
	self:setAckPacketIdArraySize(0)
	self:setMsgPacketId(args[pre .. "MsgPacketId"] or 0)
end

function openvpn_P_CONTROL_HARD_RESET_CLIENT_V2:getSessionId()
	return self.sessionId:get()
end

function openvpn_P_CONTROL_HARD_RESET_CLIENT_V2:setSessionId(val)
	-- TODO check if val is a number and convert it to a field
	return self.sessionId:set(val)
end

function openvpn_P_CONTROL_HARD_RESET_CLIENT_V2:getSessionIdString()
	return self.sessionId:getString()
end


function openvpn_P_CONTROL_HARD_RESET_CLIENT_V2:getSubType()
	return "P_CONTROL_HARD_RESET_CLIENT_V2"
end


------------------------------------------------------------------------
---- Metatypes
------------------------------------------------------------------------

openvpn.default.metatype = openvpnHeader
openvpn.P_CONTROL_HARD_RESET_CLIENT_V2.metatype = openvpn_P_CONTROL_HARD_RESET_CLIENT_V2


------------------------------------------------------------------------
---- Changes to other modules
------------------------------------------------------------------------

local proto = require "proto.proto"
proto.openvpn = openvpn

local pkt = require "packet"

pkt.getOpenVPN4Packet = createStack('eth', 'ip4', 'udp', 'openvpn')
pkt.getOpenVPN6Packet = createStack('eth', 'ip6', 'udp', 'openvpn')
pkt.getOpenVPNPacket = function(self, ip4)
	ip4 = ip4 == nil or ip4 
	if ip4 then 
		return pkt.getOpenVPN4Packet(self) 
	else 
		return pkt.getOpenVPN6Packet(self) 
	end
end

pkt.getOpenVPN_P_CONTROL_HARD_RESET_CLIENT_V2_4Packet = createStack('eth', 'ip4', 'udp', {'openvpn', subType = "P_CONTROL_HARD_RESET_CLIENT_V2"})
pkt.getOpenVPN_P_CONTROL_HARD_RESET_CLIENT_V2_6Packet = createStack('eth', 'ip6', 'udp', {'openvpn', subType = "P_CONTROL_HARD_RESET_CLIENT_V2"})
pkt.getOpenVPN_P_CONTROL_HARD_RESET_CLIENT_V2_Packet = function(self, ip4)
	ip4 = ip4 == nil or ip4 
	if ip4 then 
		return pkt.getOpenVPN_P_CONTROL_HARD_RESET_CLIENT_V2_4Packet(self) 
	else 
		return pkt.getOpenVPN_P_CONTROL_HARD_RESET_CLIENT_V2_6Packet(self) 
	end
end

return openvpn