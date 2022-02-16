
-- libmoon
require "utils" -- incAndWrap

local mod = {}

function mod.setUdpSrc(pkt, val)
	pkt.udp:setSrc(val)
end

function mod.setIP4Src_3(pkt, val)
	pkt.ip4.src.uint8[3] = val
end

function mod.setEthSrc_5(pkt, val)
	pkt.eth.src.uint8[5] = val
end

local field_inc = {}
mod.field_inc = field_inc

function field_inc:new(start_val, max_val, set_field)
	local o = {}
	o.val = start_val
	o.max_val = max_val
	o.set_field_func = set_field
	setmetatable(o, self)
	self.__index = self
	return o
end

function field_inc:set_field(buf)
	self.set_field_func(buf, self.val)
	self.val = incAndWrap(self.val, self.max_val)
end

function field_inc.udpSrc(max_val)
	if max_val == 0 then
		-- 65535 is the highest port used
		return field_inc:new(0, 65535, mod.setUdpSrc)
	else
		return field_inc:new(0, math.min(max_val, 65535), mod.setUdpSrc)
	end
end

function field_inc.ipSrc_3(max_val)
	if max_val == 0 then
		return field_inc:new(0, 255, mod.setIP4Src_3)
	else
		return field_inc:new(0, math.min(max_val, 255), mod.setIP4Src_3)
	end
end

function field_inc.ethSrc_5(max_val)
	if max_val == 0 then
		return field_inc:new(0, 255, mod.setEthSrc_5)
	else
		return field_inc:new(0, math.min(max_val, 255), mod.setEthSrc_5)
	end
end

return mod