## About
QtExtract is a tool for extracting Qt resources from x86/x64 Windows binaries (.exe/.dll)

It works by scanning for compiler generated calls to [qRegisterResourceData](https://wiki.qt.io/QtResources#How_it_works). The signatures used by QtExtract are not all-encompassing, and may result in false positives or false negatives. If you find a Qt application that doesn't work with QtExtract, feel free to open an issue. 

![Running qtextract on Wireshark](./img/usage.gif)

## Usage

```
usage: qtextract filename [options]
options:
  --help                   Print this help
  --chunk chunk_id         The chunk to dump. Exclude this to see a list of chunks (if any can be found) and use 0 to dump all chunks
  --output directory       For specifying an output directory
  --scanall                Scan the entire file (instead of the first executable section)
  --section section        For scanning a specific section
  --data, --datarva info   [Advanced] Use these options to manually provide offsets to a qt resource in the binary
                           (e.g. if no chunks were found automatically by qtextract).
                           'info' should use the following format: %x,%x,%x,%d
                           where the first 3 hexadecimal values are offsets to data, names, and tree
                           and the last decimal value is the version (usually 1-3).

                           If '--datarva' is used, provide RVA values (offsets from the image base) instead of file offsets.
                           See check_data_opt() in main.rs for an example on finding these offsets using IDA.
```

