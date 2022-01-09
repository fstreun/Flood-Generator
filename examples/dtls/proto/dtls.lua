------------------------------------------------------------------------
--- @file dtls.lua
--- @brief (DTLS) utility.
--- Utility functions for the DTLS structs 
--- Includes:
--- TODO
---
--- The newProtocolTemplate.lua was used.
------------------------------------------------------------------------


local ffi = require "ffi"
require "proto.template"
local initHeader = initHeader

local fields = require "proto.fields"
fields.load_field_nbyte(3)
fields.load_field_nbyte(6)
fields.load_field_nbyte(32)

---------------------------------------------------------------------------
---- DTLS constants 
---------------------------------------------------------------------------

local dtls = {}

---------------------------------------------------------------------------
---- DTLS header 
---------------------------------------------------------------------------


dtls.default = {}
dtls.default.headerFormat = [[
	uint8_t content_type;
	uint16_t version;
	uint16_t epoch;
	field_6byte sequence_number;
	uint16_t length;
]]
dtls.default.headerVariableMember = nil

dtls.handshake = {}
dtls.handshake.headerFormat = [[
	uint8_t msg_type;
	field_3byte length;
	uint16_t message_seq;
	field_3byte fragment_offset;
	field_3byte fragment_length;
	uint16_t version;
	field_32byte random;
	uint8_t session_id_length;
	field_32byte session_id;
	uint8_t cookie_length;
]]
dtls.handshake.headerVariableMember = nil

dtls.defaultType = "default"

local dtlsHeader = initHeader(dtls.default.headerFormat)
dtlsHeader.__index = dtlsHeader
local dtls_Handshake = initHeader(dtls.handshake.headerFormat)
dtls_Handshake.__index = dtls_Handshake


------------------------------------------------------------------------
---- Metatypes
------------------------------------------------------------------------

dtls.default.metatype = dtlsHeader
dtls.handshake.metatype = dtls_Handshake

------------------------------------------------------------------------
---- Changes to other modules
------------------------------------------------------------------------

local proto = require "proto.proto"
proto.dtls = dtls

local pkt = require "packet"

pkt.getDTLS4Packet = createStack('eth', 'ip4', 'udp', 'dtls')
pkt.getDTLS6Packet = createStack('eth', 'ip6', 'udp', 'dtls')
pkt.getDTLSPacket = function(self, ip4)
	ip4 = ip4 == nil or ip4
	if ip4 then
		return pkt.getDTLS4Packet(self)
	else
		return pkt.getDTLS6Packet(self)
	end
end

pkt.getDTLS_Handshake_4Packet = createStack('eth', 'ip4', 'udp', 'dtls', {'dtls', subType = "handshake", name = "dtls_handshake"})
pkt.getDTLS_Handshake_6Packet = createStack('eth', 'ip6', 'udp', 'dtls', {'dtls', subType = "handshake", name = "dtls_handshake"})
pkt.getDTLS_Handshake_Packet = function(self, ip4)
	ip4 = ip4 == nil or ip4
	if ip4 then
		return pkt.getDTLS_Handshake_4Packet(self)
	else
		return pkt.getDTLS_Handshake_6Packet(self)
	end
end