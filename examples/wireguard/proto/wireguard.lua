------------------------------------------------------------------------
--- @file wireguard.lua
--- @brief (wireguard) utility.
--- Utility functions for the wireguard_header structs 
--- Includes:
--- - wireguard constants
--- - wireguard header utility
--- - Definition of wireguard packets
---
--- The newProtocolTemplate.lua was used.
------------------------------------------------------------------------


local ffi = require "ffi"
require "proto.template"
local initHeader = initHeader

local ns = require "namespaces"

local format = string.format

local fields = require "proto.fields"
fields.load_field_nbyte(16)
fields.load_field_nbyte(24)
fields.load_field_nbyte(28)
fields.load_field_nbyte(32)
fields.load_field_nbyte(48)

---------------------------------------------------------------------------
---- wireguard constants 
---------------------------------------------------------------------------

--- wireguard protocol constants
local wireguard = {}

wireguard.TYPE_INITIATION = 0x01
wireguard.TYPE_RESPONSE = 0x02
wireguard.TYPE_COOKIE = 0x03
wireguard.TYPE_TRANSPORT = 0x04

wireguard.MSG1_LENGTH = 116	-- length of message up to mac1
wireguard.MSG2_LENGTH = 132	-- length of message up to mac2


---------------------------------------------------------------------------
---- wireguard utils
---------------------------------------------------------------------------
local wireguard_crypto = ffi.load("./proto/wireguard-crypto")

ffi.cdef[[
	int wg_decode_pubkey(uint8_t out[32], const char in_base64[44]);
	void wg_mac1(uint8_t mac1[16], uint8_t pubkey[32], const void *msg, int len);
	void wg_mac2(uint8_t mac2[16], const uint8_t cookie[16], const void *msg, int len);

	int wg_cookie_decrypt(uint8_t cookie[16], uint8_t pubkey[32], uint8_t nonce[24], uint8_t cookie_enc[32], uint8_t mac1[16]);
]]


---------------------------------------------------------------------------
---- wireguard header
---------------------------------------------------------------------------

--- Default header only contains the first two fields
--- which are also used in all the other wireguard headers and can be used to further check the type of the header.
wireguard.default = {}
wireguard.default.headerFormat = [[
	uint8_t 	type;
	uint8_t		reserved[3];
]]

--- Variable sized member
wireguard.default.headerVariableMember = nil

--- Handshake Initiation Message
wireguard.initiation = {}
wireguard.initiation.headerFormat = [[
	uint8_t 	type;
	uint8_t		reserved[3];
	uint32_t 	sender;
	field_32byte 	ephemeral;
	field_48byte 	stc;		/* static is a keyword and cannot be used */
	field_28byte 	timestamp;
	field_16byte 	mac1;
	field_16byte 	mac2;
]]

--- Variable sized member
wireguard.initiation.headerVariableMember = nil

--- Handshake Response Message
wireguard.response = {}
wireguard.response.headerFormat = [[
	uint8_t 	type;
	uint8_t 	reserved[3];
	uint32_t 	sender;
	uint32_t 	receiver;
	field_32byte 	ephemeral;
	field_16byte 	empty;
	field_16byte 	mac1;
	field_16byte 	mac2;
]]

--- Variable sized member
wireguard.response.headerVariableMember = nil

--- Cookie Reply Message
wireguard.cookie = {}
wireguard.cookie.headerFormat = [[
	uint8_t 	type;
	uint8_t 	reserved[3];
	uint32_t 	receiver;
	field_24byte 	nonce;
	field_32byte 	cookie;
]]

--- Variable sized member
wireguard.headerVariableMember = nil


--- Transport Data Message Header
wireguard.transport = {}
wireguard.transport.headerFormat = [[
	uint8_t 	type;
	uint8_t 	reserved[3];
	uint32_t 	receiver;
	uint64_t 	counter;
]]

--- Variable sized member
wireguard.transport.headerVariableMember = nil

wireguard.defaultType = "default"

--- Module for wireguard_address struct
local wireguardHeader = initHeader(wireguard.default.headerFormat)
local wireguardInitiationHeader = initHeader(wireguard.initiation.headerFormat)
local wireguardResponseHeader = initHeader(wireguard.response.headerFormat)
local wireguardCookieHeader = initHeader(wireguard.cookie.headerFormat)
local wireguardTransportHeader = initHeader(wireguard.transport.headerFormat)
wireguardHeader.__index = wireguardHeader
wireguardInitiationHeader.__index = wireguardInitiationHeader
wireguardResponseHeader.__index = wireguardResponseHeader
wireguardCookieHeader.__index = wireguardCookieHeader
wireguardTransportHeader.__index = wireguardTransportHeader


--- Set all members of the wireguard initiation header.
--- Per default, all members are set to default values specified in the respective set function.
--- Optional named arguments can be used to set a member to a user-provided value.
--- @param args Table of named arguments. Available arguments: type, receiver,
--- @param pre prefix for namedArgs. Default 'wireguard'.
--- @code
--- fill() -- only default values
--- fill{ xyz=1 } -- all members are set to default values with the exception of xyz, ...
--- @endcode
function wireguardHeader:fill(args, pre)
	args = args or {}
	pre = pre or "wg"

	self:setType(args[pre .. "Type"])
	
	self.reserved[0] = 0
	self.reserved[1] = 0
	self.reserved[2] = 0

	--[[
	self:setSender(args[pre .. "Sender"])
	self:setReceiver(args[pre .. "Receiver"])

	self:setCounter(args[pre .. "Counter"])

	self:setEphemeral(args[pre .. "Ephemeral"])
	self:setStc(args[pre .. "Stc"])
	self:setTimestamp(args[pre .. "Timestamp"])
	self:setEmpty(args[pre .. "Empty"])
	self:setMac1(args[pre .. "Mac1"])
	self:setMac2(args[pre .. "Mac2"])

	self:setNonce(args[pre .. "Nonce"])
	self:setCookie(args[pre .. "Cookie"])
	]]
end

function wireguardInitiationHeader:fill(args, pre)
	args = args or {}
	pre = pre or "wg"

	self:setType(1)
	
	self.reserved[0] = 0
	self.reserved[1] = 0
	self.reserved[2] = 0

	self:setSender(args[pre .. "Sender"] or 123456)

	if args[pre .. "Ephemeral"] then
		self:setEphemeral(args[pre .. "Ephemeral"])
	else
		local field = fields.field32byteType()
		field.uint64[0] = 123456
		field.uint64[1] = 123456
		field.uint64[2] = 123456
		field.uint64[3] = 123456
		self:setEphemeral(field)
	end

	if args[pre .. "Stc"] then
		self:setEphemeral(args[pre .. "Stc"])
	else
		local field = fields.field48byteType()
		field.uint64[0] = 123456
		field.uint64[1] = 123456
		field.uint64[2] = 123456
		field.uint64[3] = 123456
		field.uint64[4] = 123456
		field.uint64[5] = 123456
		self:setStc(field)
	end

	if args[pre .. "Timestamp"] then
		self:setTimestamp(args[pre .. "Timestamp"])
	else
		local field = fields.field28byteType()
		field.uint32[0] = 123456
		field.uint32[1] = 123456
		field.uint32[2] = 123456
		field.uint32[3] = 123456
		field.uint32[4] = 123456
		field.uint32[5] = 123456
		field.uint32[6] = 123456
		self:setTimestamp(field)
	end

	if args[pre .. "Mac1"] then
		self:setMac1(args[pre .. "Mac1"])
	else
		local field = fields.field16byteType()
		field.uint64[0] = 123456
		field.uint64[1] = 123456
		self:setMac1(field)
	end

	if args[pre .. "Mac2"] then
		self:setMac1(args[pre .. "Mac2"])
	else
		local field = fields.field16byteType()
		field.uint64[0] = 0
		field.uint64[1] = 0
		self:setMac2(field)
	end
end


--- Retrieve the wireguard type.
--- @return WireguardType as string.
function wireguardHeader:getTypeString()
	local type = self:getType()
	local cleartext = ""
	
	if type == wireguard.TYPE_TRANSPORT then
		cleartext = "(TRANSPORT)"
	elseif type == wireguard.TYPE_INITIATION then
		cleartext = "(INITIATION)"
	elseif type == wireguard.TYPE_RESPONSE then
		cleartext = "(RESPONSE)"
	elseif type == wireguard.TYPE_COOKIE then
		cleartext = "(COOKIE)"
	else
		cleartext = "(unknown)"
	end

	return format("0x%02x %s", type, cleartext)
end

wireguardInitiationHeader.getTypeString = wireguardHeader.getTypeString
wireguardResponseHeader.getTypeString = wireguardHeader.getTypeString
wireguardCookieHeader.getTypeString = wireguardHeader.getTypeString
wireguardTransportHeader.getTypeString = wireguardHeader.getTypeString

--- Resolve which header comes after this one (in a packet)
--- For instance: in tcp/udp based on the ports
--- This function must exist and is only used when get/dump is executed on 
--- an unknown (mbuf not yet casted to e.g. tcpv6 packet) packet (mbuf)
--- @return String next header (e.g. 'eth', 'ip4', nil)
function wireguardHeader:resolveNextHeader()
	return nil
end	

wireguardInitiationHeader.resolveNextHeader = wireguardHeader.resolveNextHeader
wireguardResponseHeader.resolveNextHeader = wireguardHeader.resolveNextHeader
wireguardCookieHeader.resolveNextHeader = wireguardHeader.resolveNextHeader
wireguardTransportHeader.resolveNextHeader = wireguardHeader.resolveNextHeader

--- Change the default values for namedArguments (for fill/get)
--- This can be used to for instance calculate a length value based on the total packet length
--- See proto/ip4.setDefaultNamedArgs as an example
--- This function must exist and is only used by packet.fill
--- @param pre The prefix used for the namedArgs, e.g. 'PROTO'
--- @param namedArgs Table of named arguments (see See more)
--- @param nextHeader The header following after this header in a packet
--- @param accumulatedLength The so far accumulated length for previous headers in a packet
--- @return Table of namedArgs
--- @see PROTOHeader:fill
function wireguardHeader:setDefaultNamedArgs(pre, namedArgs, nextHeader, accumulatedLength)
	return namedArgs
end

wireguardInitiationHeader.setDefaultNamedArgs = wireguardHeader.setDefaultNamedArgs
wireguardResponseHeader.setDefaultNamedArgs = wireguardHeader.setDefaultNamedArgs
wireguardCookieHeader.setDefaultNamedArgs = wireguardHeader.setDefaultNamedArgs
wireguardTransportHeader.setDefaultNamedArgs = wireguardHeader.setDefaultNamedArgs

--- Special setter/getter which are not defined by default

--- Taken from the ethernet.lua example:

function wireguardInitiationHeader:getSubType()
	return "initiation"
end

function wireguardResponseHeader:getSubType()
	return "response"
end

function wireguardCookieHeader:getSubType()
	return "cookie"
end

function wireguardTransportHeader:getSubType()
	return "transport"
end


function wireguardInitiationHeader:setEphemeral(val)
 	self.ephemeral:set(val)
 end
function wireguardInitiationHeader:getEphemeral()
	return self.ephemeral:get()
end
function wireguardInitiationHeader:setStc(val)
	self.stc:set(val)
end
function wireguardInitiationHeader:getStc()
	return self.stc:get()
end
function wireguardInitiationHeader:setTimestamp(val)
	self.timestamp:set(val)
end
function wireguardInitiationHeader:getTimestamp()
	return self.timestamp:get()
end
function wireguardInitiationHeader:setMac1(val)
	self.mac1:set(val)
end
function wireguardInitiationHeader:getMac1()
	return self.mac1:get()
end
function wireguardInitiationHeader:setMac2(val)
	self.mac2:set(val)
end
function wireguardInitiationHeader:getMac2()
	return self.mac2:get()
end

function wireguardInitiationHeader:calculateMac1(pubkey_in)
	local pubkey = fields.field32byteType()
	local res = wireguard_crypto.wg_decode_pubkey(pubkey.uint8, pubkey_in)
	
	local mac1 = fields.field16byteType()
	wireguard_crypto.wg_mac1(mac1.uint8, pubkey.uint8, self, wireguard.MSG1_LENGTH)

	ffi.copy(self.mac1, mac1, 16)
end

function wireguardInitiationHeader:calculateMac2(cookie)
	local mac2 = fields.field16byteType()
	wireguard_crypto.wg_mac2(mac2.uint8, cookie.uint8, self, wireguard.MSG2_LENGTH)

	ffi.copy(self.mac2, mac2, 16)
end

function wireguardResponseHeader:setEphemeral(val)
	self.ephemeral:set(val)
end
function wireguardResponseHeader:getEphemeral()
   return self.ephemeral:get()
end
function wireguardResponseHeader:setEmpty(val)
	self.empty:set(val)
end
function wireguardResponseHeader:getEmpty()
	return self.empty:get()
end
function wireguardResponseHeader:setMac1(val)
	self.mac1:set(val)
end
function wireguardResponseHeader:getMac1()
	return self.mac1:get()
end
function wireguardResponseHeader:setMac2(val)
	self.mac2:set(val)
end
function wireguardResponseHeader:getMac2()
	return self.mac2:get()
end


function wireguardCookieHeader:setNonce(val)
	self.nonce:set(val)
end
function wireguardCookieHeader:getNonce()
	return self.nonce:get()
end
function wireguardCookieHeader:setCookie(val)
	self.cookie:set(val)
end
function wireguardCookieHeader:getCookie()
	return self.cookie:get()
end

------------------------------------------------------------------------
---- Metatypes
------------------------------------------------------------------------

wireguard.initiation.metatype = wireguardInitiationHeader
wireguard.response.metatype = wireguardResponseHeader
wireguard.cookie.metatype = wireguardCookieHeader
wireguard.transport.metatype = wireguardTransportHeader
wireguard.default.metatype = wireguardHeader

------------------------------------------------------------------------
---- Changes to other modules
------------------------------------------------------------------------

--- This part was not taken from the template!
--- Not sure if this is a good (modular) approach to add another protocol to libmoon.
--- But it seems to work.

local proto = require "proto.proto"
proto.wireguard = wireguard

local pkt = require "packet"

pkt.getWireguard4InitiationPacket = createStack('eth', 'ip4', 'udp', {'wireguard', subType = "initiation"})
pkt.getWireguard6InitiationPacket = createStack('eth', 'ip6', 'udp', {'wireguard', subType = "initiation"})
pkt.getWireguardInitiationPacket = function(self, ip4) 
	ip4 = ip4 == nil or ip4 
	if ip4 then 
		return pkt.getWireguard4InitiationPacket(self) 
	else 
		return pkt.getWireguard6InitiationPacket(self) 
	end 
end

pkt.getWireguard4ResponsePacket = createStack('eth', 'ip4', 'udp', {'wireguard', subType = "response"})
pkt.getWireguard6ResponsePacket = createStack('eth', 'ip6', 'udp', {'wireguard', subType = "response"})
pkt.getWireguardResponsePacket = function(self, ip4) 
	ip4 = ip4 == nil or ip4 
	if ip4 then 
		return pkt.getWireguard4ResponsePacket(self) 
	else 
		return pkt.getWireguard6ResponsePacket(self) 
	end 
end

pkt.getWireguard4CookiePacket = createStack('eth', 'ip4', 'udp', {'wireguard', subType = "cookie"})
pkt.getWireguard6CookiePacket = createStack('eth', 'ip6', 'udp', {'wireguard', subType = "cookie"})
pkt.getWireguardCookiePacket = function(self, ip4) 
	ip4 = ip4 == nil or ip4 
	if ip4 then 
		return pkt.getWireguard4CookiePacket(self) 
	else 
		return pkt.getWireguard6CookiePacket(self) 
	end 
end

pkt.getWireguard4TransportPacket = createStack('eth', 'ip4', 'udp', {'wireguard', subType = "transport"})
pkt.getWireguard6TransportPacket = createStack('eth', 'ip6', 'udp', {'wireguard', subType = "transport"})
pkt.getWireguardTransportPacket = function(self, ip4) 
	ip4 = ip4 == nil or ip4 
	if ip4 then 
		return pkt.getWireguard4TransportPacket(self) 
	else 
		return pkt.getWireguard6TransportPacket(self) 
	end 
end

pkt.getWireguard4Packet = createStack('eth', 'ip4', 'udp', 'wireguard')
pkt.getWireguard6Packet = createStack('eth', 'ip6', 'udp', 'wireguard')
pkt.getWireguardPacket = function(self, ip4)
	ip4 = ip4 == nil or ip4 
	if ip4 then 
		return pkt.getWireguard4Packet(self) 
	else 
		return pkt.getWireguard6Packet(self) 
	end
end


------------------------------------------------------------------------
---- WireGuard Handler Task
------------------------------------------------------------------------


local cookieTable = ns:get()
local mac1Table = ns:get()

-- A responder creates cookie values depending on the ip and port address of the initiator
-- Hence, cookie values can be keyed by the initiator's ip and port address
function wireguard.getCookieKey(init_ip, init_port)
	local key = format("%s_%s", tostring(init_ip), tostring(init_port))
	return key
end

-- store mac1 and pubkey with the sender id as key
function wireguard.storeMac1(buf)
	local pkt = buf:getWireguardInitiationPacket()

	local key = wireguard.getCookieKey(pkt.ip4:getSrc(), pkt.udp:getSrcPort())

	local mac1 = fields.field16byteType()
	ffi.copy(mac1, pkt.wireguard.mac1.uint8, 16)

	mac1Table.lock(function()
		mac1Table[key] = {
			mac1 = mac1,
			timestamp = time()
		}
	end)
end

-- decrypts cookie value
-- requires mac1 of responder to be stored in mac1Table
function wireguard.handleCookiePacket(buf, pubkey_in)
	local pkt = buf:getWireguardCookiePacket()
	local pubkey = fields.field32byteType()
	local res = wireguard_crypto.wg_decode_pubkey(pubkey.uint8, pubkey_in)

	local key = wireguard.getCookieKey(pkt.ip4:getDst(), pkt.udp:getDstPort())

	local mac1, timestamp = wireguard.lookupMac1(key)
	if mac1 then

		local cookie_enc = fields.field32byteType()
		ffi.copy(cookie_enc, pkt.wireguard.cookie, 32)
		local nonce = fields.field24byteType()
		ffi.copy(nonce, pkt.wireguard.nonce, 24)

		local cookie = fields.field16byteType()
		wireguard_crypto.wg_cookie_decrypt(cookie.uint8, pubkey.uint8, nonce.uint8, cookie_enc.uint8, mac1.uint8)

		cookieTable.lock(function()
			cookieTable[key] = {
				cookie = cookie,
				timestamp = time()
			}
		end)
	end
end

function wireguard.lookupCookie(key)
		local val = cookieTable[key]
		if type(val) == "table" then
			return val.cookie, val.timestamp
		end
		return nil
end

function wireguard.lookupMac1(key)
		local val = mac1Table[key]
		if type(val) == "table" then
			return val.mac1, val.timestamp
		end
	return nil
end

return wireguard