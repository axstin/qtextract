## About
QtExtract is a tool for extracting Qt resources from x86/x64 Windows binaries (.exe/.dll)

## Requirements
- Lua 5.1+ or LuaJIT installed and in your PATH
- (optional) lzlib module (look [here](https://github.com/LuaDist/lzlib) or [here](https://luarocks.org/modules/hisham/lzlib))

## Usage

```
usage: lua qtextract.lua filename [options]
  options:
    --help                   Print this help
    --chunk chunk_id         The chunk to dump. Exclude this to see a list of chunks (if any can be found) and use 1 to dump all chunks
    --output directory       For specifying an output directory
    --data, --datarva info   [Advanced] Use these options to manually provide offsets to a qt resource in the binary
                             (e.g. if no chunks were found automatically by qtextract).
                             'info' should use the following format: %x,%x,%x,%d
                             where the first 3 hexadecimal values are offsets to data, names, and tree
                             and the last decimal value is the version (usually always 1).

                             If '--datarva' is used, provide RVA values (offsets from the image base) instead of file offsets.
                             See checkdataopt() in qtextract.lua for an example on finding these offsets using IDA.```
