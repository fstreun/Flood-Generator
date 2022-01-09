
local mod = {}

function mod.shuffle(input)
	local output = {}
	for i, v in ipairs(input) do
		local pos = math.random(1, #output+1)
		table.insert(output, pos, v)
	end
	return output
end

return mod