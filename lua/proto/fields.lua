
local ffi = require "ffi"

local istype = ffi.istype
local format = string.format

-- Host to network endian conversion
local ntoh, hton = ntoh, hton
local bor, band, bnot, rshift, lshift= bit.bor, bit.band, bit.bnot, bit.rshift, bit.lshift

-- Module for n byte fields
local mod = {}
mod.fieldnByte = {}

-- base object for each field
local field = {}

function mod.load_field_nbyte(n)
	local fieldTypeName = format("field%dbyteType", n)

	-- memoization
	if mod[fieldTypeName] then
		return
	end

	-- check possible format
	local int32 = ((n*8) % 32) == 0 and n / 32
	local int64 = ((n*8) % 64) == 0 and n / 64

	-- define union
	local defName = format("field_%dbyte", n)
	local cdef = format([[typedef union %s_u {
				uint8_t uint8[%d];
			]], defName, n)
	if int32 then
		cdef = cdef .. format("uint32_t uint32[%d];\n", int32)
	end
	if int64 then
		cdef = cdef .. format("uint64_t uint64[%d];\n", int64)
	end
	cdef = cdef .. format("} %s;", defName)
	ffi.cdef(cdef)

	-- add ctype to module
	local ctype = ffi.typeof(defName)
	mod[fieldTypeName] = ctype

	-- create lua object of field
	local fieldnbyte = {}
	fieldnbyte.__index = fieldnbyte
	fieldnbyte.size = n
	fieldnbyte.ctype = ctype

	-- set field object as base class
	setmetatable(fieldnbyte, field)

	-- bind the c struct to the lua object
	ffi.metatype(defName, fieldnbyte)
end

function field:get()
	local field = self.ctype()
	for i = 0, self.size - 1 do
		field.uint8[i] = self.uint8[self.size-1-i]
	end
	return field
end

function field:set(field)
	for i = 0, self.size - 1 do
		self.uint8[i] = field.uint8[self.size-1-i]
	end
end

function field.__eq(lhs, rhs)
	local res = lhs.ctype == rhs.ctype
	if res then
		for i = 0, lhs.size - 1 do
			lhs.uint8[i] = rhs.uint8[i]
		end
	end
	return res
end

function field:getString()
	res = format("%02x", self.uint8[0])
	for i = 1, self.size - 1 do
		res = res .. format(" %02x", self.uint8[i])
	end
	return res
end

field.__index = field


return mod