--[[
qtextract.lua
5/17/2018

Tool for extracting Qt resources from a x86/x64 Windows binary (.exe/.dll)
by Austin
]]

local zlib_available, zlib = pcall(require, "zlib")
local peparser = require"peparser"

local usage = [[
usage: lua qtextract.lua filename [options]
  options:
    --help                   Print this help
    --chunk chunk_id         The chunk to dump. Exclude this to see a list of chunks (if any can be found) and use 1 to dump all chunks
    --output directory       For specifying an output directory
    --scanall                Scan the entire file (instead of the first executable section)
    --section section        For scanning a specific section
    --data, --datarva info   [Advanced] Use these options to manually provide offsets to a qt resource in the binary
                             (e.g. if no chunks were found automatically by qtextract).
                             'info' should use the following format: %x,%x,%x,%d
                             where the first 3 hexadecimal values are offsets to data, names, and tree
                             and the last decimal value is the version (usually always 1).

                             If '--datarva' is used, provide RVA values (offsets from the image base) instead of file offsets.
                             See checkdataopt() in qtextract.lua for an example on finding these offsets using IDA.
]]

local filename = arg[1]
local file

local function sleep(seconds)
	local start = os.clock()
	while os.clock() - start < seconds do end
end

local function inspect(t, indent)
	assert(type(t) == "table", "table expected")
	if not indent then indent = 0 end

	for i, v in next, t do
		if type(v) == "table" then
			print(("    "):rep(indent) .. tostring(i) .. " = table")
			inspect(v, indent + 1)
		else
			print(("    "):rep(indent) .. tostring(i) .. " = " .. tostring(v) .. " (" .. type(v) .. ")")
		end
	end
end

local function checkopt(opt, num)
	for i = 1, #arg do
		if arg[i] == opt then
			local n = arg[i + 1]
			if num then n = tonumber(n) end
			return true, n
		end
	end

	return false, nil
end

local function choose(numopts)
	print()

	while true do
		io.write('>')
		local selection = tonumber(io.read())

		if selection and selection >= 1 and selection <= numopts then
			return selection 
		else
			print("Invalid selection, try again (enter a number between 1 and " .. numopts .. ")")
		end
	end
end

local function ashex(n)
	return "0x" .. string.format("%X", tonumber(n))
end

-- efficient file I/O
local seek, read, readbytes, readchar, readshort, readint, scan, scanall, file_offset do
	local CHUNK_MAX = 1024 * 1024

	file_offset = 0 -- current file read offset
	local chunk, chunk_start = nil, 0

	function seek(whence, offset)
		local new_position, message = file:seek(whence, offset)
		if not new_position then return nil, message end
		file_offset = new_position
		return file_offset
	end

	function read(bytes)
		local chunk_offset = file_offset - chunk_start

		if not chunk or chunk_offset < 0 or chunk_offset >= #chunk then
			assert(seek("set", file_offset)) -- make sure we're in the right spot
			chunk = file:read(CHUNK_MAX)
			collectgarbage() -- luajit wasn't collecting automatically for some reason...

			if not chunk then return nil end

			chunk_offset = 0
			chunk_start = file_offset
		end

		local result = chunk:sub(chunk_offset + 1, chunk_offset + bytes)
		local bytes_read = #result

		assert(bytes_read > 0, "read zero bytes") -- we shouldn't ever read nothing?

		file_offset = file_offset + bytes_read

		if bytes_read < bytes then
			-- we didn't read everything (because we are at the end of the chunk or file)
			return result .. (read(bytes - bytes_read) or "")
		end

		return result
	end

	function readbytes(n)
		local data = read(n)
		if not data then return nil end
		return data:byte(1, #data)
	end

	function readchar(signed)
		local b1 = readbytes(1)
		local n = b1
		if signed and n > 2^(8 - 1) - 1 then n = n - 2^8 end
		return n
	end

	function readshort(signed, bigendian)
		local b1, b2 = readbytes(2)
		local n = bigendian and (b2 + b1 * 2^8) or (b1 + b2 * 2^8)
		if signed and n > 2^(16 - 1) - 1 then n = n - 2^16 end
		return n
	end

	function readint(signed, bigendian)
		local b1, b2, b3, b4 = readbytes(4)
		local n = bigendian and (b4 + b3 * 2^8 + b2 * 2^16 + b1 * 2^24) or (b1 + b2 * 2^8 + b3 * 2^16 + b4 * 2^24)
		if signed and n > 2^(32 - 1) - 1 then n = n - 2^32 end
		return n
	end

	function scan(signature, start, limit)
		if not start then start = 0 end
		if not limit then limit = math.huge end
		seek("set", start)

		local sigbytes = {}

		for hex in signature:gmatch("%S+") do
			if hex:find'?' then
				hex = '?'
			else
				hex = tonumber(hex, 16)
			end

			sigbytes[#sigbytes + 1] = hex
		end

		local size = #sigbytes

		while file_offset <= limit - size do
			local old_offset = file_offset
			local data = read(size)
			local nomatch = false

			if not data or #data < size then break end

			for i = 1, size do
				local a, b = data:sub(i, i):byte(), sigbytes[i]

				if b ~= '?' and a ~= b then
					nomatch = true
					break
				end
			end

			if nomatch then
				file_offset = old_offset + 1
			else
				return old_offset
			end
		end

		return nil
	end

	function scanall(signature, start, limit)
		local results = {}
		local last = start or 0

		while true do
			local result = scan(signature, last, limit)
			if not result then break end
			results[#results + 1] = result
			last = result + 1
		end

		return results
	end
end

if checkopt("--help") then
	print(usage)
	return
end

file = assert(io.open(filename, "rb"))
local pe = assert(peparser.parse(filename))
local imagebase = peparser.toDec(pe.ImageBase)

local archs do
	-- file offset to RVA
	local function fo2rva(o)
		for i, v in next, pe.Sections do
			local prd = peparser.toDec(v.PointerToRawData)
			local srd = peparser.toDec(v.SizeOfRawData)
			local va = peparser.toDec(v.VirtualAddress)

			if o >= prd and o < prd + srd then
				return (o - prd) + va
			end
		end
	end

	local function x86extract(loc)
		file_offset = loc

		local offsets = {}

		for i = 1, 3 do
			file_offset = file_offset + 1 -- skip 0x68 (push)
			offsets[#offsets + 1] = assert(pe:get_fileoffset(readint() - imagebase)) -- readint() = VA, readint() - base = RVA
		end

		file_offset = file_offset + 1 -- skip 0x6A (push)
		offsets[4] = readchar() -- read version

		return offsets
	end

	archs = {
		[0x14c] = {
			signatures = {
				{ "68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A ?? E8 ?? ?? ?? ?? 83 C4 10 B8 01 00 00 00 C3", x86extract },
				{ "68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A ?? FF 15 ?? ?? ?? ?? 83 C4 10 B8 01 00 00 00 C3", x86extract }
			}
		},

		[0x8664] = {
			signatures = { 
				{ "48 83 EC 28 4C 8D 0D ?? ?? ?? ?? 4C 8D 05 ?? ?? ?? ?? 48 8D 15 ?? ?? ?? ?? B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? B8 01 00 00 00 48 83 C4 28 C3",
					function(loc)
						file_offset = loc + 4
						local offsets = {}

						for i = 1, 3 do
							file_offset = file_offset + 3 -- skip lea
							local rel = readint()
							offsets[#offsets + 1] = assert(pe:get_fileoffset(fo2rva(file_offset) + rel)) 
						end

						file_offset = file_offset + 1
						offsets[4] = readint()

						return offsets
					end
				},
				{ "48 83 EC 28 4C 8D 0D ?? ?? ?? ?? B9 ?? ?? ?? ?? 4C 8D 05 ?? ?? ?? ?? 48 8D 15 ?? ?? ?? ?? E8",
					function(loc)
						file_offset = loc + 4
						local offsets = {} -- data, name, tree, version

						file_offset = file_offset + 3
						offsets[1] = assert(pe:get_fileoffset(readint() + fo2rva(file_offset)))
						file_offset = file_offset + 1
						offsets[4] = readint()
						file_offset = file_offset + 3
						offsets[2] = assert(pe:get_fileoffset(readint() + fo2rva(file_offset)))
						file_offset = file_offset + 3
						offsets[3] = assert(pe:get_fileoffset(readint() + fo2rva(file_offset)))

						return offsets
					end
				}
			}
		}
	}
end

local function checkdataopt()
	-- For providing resource chunk information that couldn't be found automatically
	-- If using IDA: The offsets can be found by setting the image base in IDA to 0 ( Edit->Segments->Rebase program... https://i.imgur.com/XWIzhEf.png ) 
	-- and then looking at calls to qRegisterResourceData ( https://i.imgur.com/D0gjkbH.png ) to extract the offsets.
	-- The chunk can then be dumped with this script using --datarva data,name,tree,version

	local rva = false
	local _, datastr = checkopt("--data")
	if not datastr then _, datastr = checkopt("--datarva") rva = true end

	if datastr then
		local offsets = { datastr:match("(%x+),(%x+),(%x+),(%d+)") }

		if #offsets == 4 then
			if rva then
				for i = 1, 3 do
					offsets[i] = pe:get_fileoffset(offsets[i])
				end
			else
				for i = 1, 3 do
					offsets[i] = tonumber(offsets[i], 16)
				end
			end

			offsets[4] = tonumber(offsets[4])

			return { { register = 0, offsets = offsets } }
		else
			error("invalid input for " .. (rva and "--datarva" or "--data"))
		end
	end

	return nil
end

-- returns a pointer to a function like this: https://i.imgur.com/ilfgGPG.png
local function askresourcedata()
	local results = {}
	local hash = {} -- for checking duplicates
	
	local start, limit, section_name
	if not checkopt("--scanall") then
		local _, target = checkopt("--section")

		if target then 
			for i, v in next, pe.Sections do
				if v.Name == target then
					local prd = peparser.toDec(v.PointerToRawData)
					local srd = peparser.toDec(v.SizeOfRawData)
					
					start = prd
					limit = prd + srd
					section_name = v.Name

					break
				end
			end

			if not start then
				print("WARNING: Unable to find section " .. target)
			end
		else
			for i, v in next, pe.Sections do
				local flags = peparser.toDec(v.Characteristics)
				local is_code = math.floor(flags / 2^5) % 2 ~= 0 -- IMAGE_SCN_CNT_CODE (0x00000020)
				local is_executable = math.floor(flags / 2^29) % 2 ~= 0 -- IMAGE_SCN_MEM_EXECUTE (0x20000000)

				if is_code and is_executable then
					local prd = peparser.toDec(v.PointerToRawData)
					local srd = peparser.toDec(v.SizeOfRawData)
					
					start = prd
					limit = prd + srd
					section_name = v.Name
					
					break
				end
			end
		end
	end

	if start then
		print(string.format("Scanning section %s (0x%08X-0x%08X)...", section_name, start, limit))
	else
		print("Scanning file...")
	end

	local clock = os.clock()

	local arch = archs[peparser.toDec(pe.Machine)]
	assert(arch ~= nil, "unknown architecture")

	for i, v in next, arch.signatures do
		for j, k in next, scanall(v[1], start, limit) do
			-- extract 
			local offsets = v[2](k)
			if not hash[offsets[1]] then 
				hash[offsets[1]] = true
				results[#results + 1] = { register = k, offsets = offsets} 
			end
		end
	end

	print("Done in " .. (os.clock() - clock) .. "s\n")

	if #results > 0 then
		local _, choice = checkopt("--chunk", true)

		if not choice then
			print("Select a resource chunk to dump:")

			print("1 - Dump All")
			for i, v in next, results do
				print(i + 1 .. " - " .. ashex(v.register))
			end

			choice = choose(#results + 1)
		end

		assert(choice > 0 and choice <= #results + 1, "invalid chunk selection")

		if choice == 1 then
			return results 
		else
			return { results[choice - 1] }
		end
	else 
		error("unable to find any resource chunks")
	end
end

local function dumpresourcedata(outputdir, data, names, tree, version)
	assert(version == 1 or version == 2, "version " .. tostring(version) .. " not supported")

	-- https://github.com/qt/qtbase/blob/5.11/src/corelib/io/qresource.cpp#L96
	local function findoffset(node)
		return node * (14 + (version >= 2 and 8 or 0))
	end

	local node_cache = {}

	-- https://github.com/qt/qtbase/blob/5.11/src/corelib/io/qresource.cpp#L776
	-- returns node info
	-- a node parameter of 0 will parse every node that exists as node 0 is the root node
	local function getnodeinfo(node)
		local result = {}

		if node == -1 then 
			return result
		end

		if node_cache[node] then
			return node_cache[node]
		end

		--[[
		tree element structure:
		14 bytes

		directory:
		00: int32 name_offset
		04: int16 flags
		06: int32 child_count
		10: int32 child_offset
		14: int64 last_modified // version == 2 ONLY

		non-directory:
		00: int32 name_offset
		04: int16 flags
		06: int32 locale
		10: int32 data_offset
		14: int64 last_modified // version == 2 ONLY


		]]
		
		file_offset = tree + findoffset(node)
		result.name_offset = readint(false, true)

		-- read name 
		local before = file_offset
		file_offset = names + result.name_offset
		result.name_length = readshort(false, true)
		result.name_hash = readint(false, true)
		result.name_raw = read(result.name_length * 2)
		result.name = ""
		for i = 1, result.name_length * 2, 2 do
			result.name = result.name .. result.name_raw:sub(i+1, i+1) -- i+1 cause big endian unicode
		end
		file_offset = before

		-- read flags
		result.flags = readshort(false, true)
		result.directory = result.flags == 2 or result.flags == 3
		result.compressed = result.flags == 1 or result.flags == 3

		-- read etc
		if result.directory then
			result.child_count = readint(false, true)
			result.child_offset = readint(false, true)
			result.children = {}

			for i = result.child_offset, result.child_offset + result.child_count - 1 do
				local before = file_offset
				result.children[#result.children + 1] = getnodeinfo(i)
				file_offset = before
			end
		else
			result.locale = readint(false, true)
			result.data_offset = readint(false, true)

			local before = file_offset
			file_offset = data + result.data_offset
			result.size = readint(false, true)
			result.data = read(result.size)
			file_offset = before
		end

		if version >= 2 then
			-- TODO: read last_modified (8 bytes)
			file_offset = file_offset + 8
		end

		node_cache[node] = result

		return result
	end
	
	local function dump(path, info, c)
		if not info then info = getnodeinfo(0) end
		if not c then c = 0 end

		local indent = ("  "):rep(c)
		print(indent .. info.name .. (info.compressed and " (COMPRESSED)" or ""))

		path = path .. "/" .. info.name

		if info.directory then
			os.execute("mkdir \"" .. path .. "\"")

			for i, v in next, info.children do
				dump(path, v, c + 1)
			end
		else
			local content = info.data 
			if info.compressed then
				if zlib_available then
					print(indent .. "Decompressing...")
					content = zlib.decompress(content:sub(5))
				else
					path = path .. ".zlibcompressed"
				end
			end

			local f = assert(io.open(path, "wb"))
			f:write(content)
			f:close()
		end
	end

	dump(outputdir)
end

local list = checkdataopt() or askresourcedata()

local _, outputdir = checkopt("--output")

if not outputdir then
	io.write("Enter a directory to write to: ")
	outputdir = io.read()
end

for i, v in next, list do
	print("\nExtracting chunk #1 (" .. ashex(v.register) .. ")")
	dumpresourcedata(outputdir .. (#list > 1 and "/" .. i or ""), unpack(v.offsets))
end



