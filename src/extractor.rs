use std::fs;
use std::io::{Read, Write};
use std::path::Path;
use libflate::zlib;
use filetime::{FileTime, set_file_times};
use crate::binary_stream::BinaryReader;

pub enum QtNodeAux {
    Directory(Vec<QtNode>),
    Resource {
        locale: u32,
        is_compressed: bool,
        file_offset: usize,
        data: Vec<u8>
    }
}

pub struct QtNode {
    id: i32,
    name: String,
    name_hash: u32,
    flags: u16,
    aux: QtNodeAux,
    last_modified: u64
}

impl QtNode {
    fn dump_impl(&self, path: &Path, c: usize) -> std::io::Result<()> {
        let indent = "  ".repeat(c);
        let node_path = path.join(self.name.as_str());

        print!("{}{}", indent, self.name);

        // https://github.com/qt/qtbase/blob/5.11/src/corelib/io/qresource.cpp#L538
        let maybe_last_modified = if self.last_modified != 0 {
            Some(std::time::UNIX_EPOCH + std::time::Duration::from_millis(self.last_modified))
        } else {
            None
        };
        
        match &self.aux {
            QtNodeAux::Directory(children) => {
                // don't think this is ever the case but /shrug
                if let Some(time) = maybe_last_modified {
                    print!(" (last modified {})", time::OffsetDateTime::from(time));
                }
                println!();

                fs::create_dir_all(&node_path)?;

                for child in children {
                    child.dump_impl(&node_path, c + 1)?;
                }
            },
            QtNodeAux::Resource { is_compressed, file_offset, data, .. } => {
                print!(" @ {:#08X} ({} bytes)", *file_offset, data.len());
                if let Some(time) = maybe_last_modified {
                    print!(" (last modified {})", time::OffsetDateTime::from(time));
                }
                if *is_compressed {
                    print!(" [compressed]");
                }

                let mut tmp = Vec::new();

                fs::File::create(&node_path)?.write_all(if *is_compressed {
                    if data.len() > 4 {
                        println!();
                        print!("{indent}  decompressing... ");
                        let mut decoder = zlib::Decoder::new(&data[4..])?;
                        decoder.read_to_end(&mut tmp)?;
                        print!("ok, {} bytes", tmp.len());
                    }
                    &tmp
                } else {
                    data
                })?;

                if let Some(last_modified) = maybe_last_modified {
                    let ft = FileTime::from_system_time(last_modified);
                    _ = set_file_times(&node_path, ft, ft);
                }

                println!();
            }
        };

        Ok(())
    }

    pub fn dump(&self, path: &Path) -> std::io::Result<()> {
        self.dump_impl(path, 0)
    }
}

#[derive(Default, Clone, Copy, Debug)]
pub struct QtResourceInfo {
    pub signature_id: i32,
    pub registrar: usize,
    pub data: usize,
    pub name: usize,
    pub tree: usize,
    pub version: usize
}

impl QtResourceInfo {
    // https://github.com/qt/qtbase/blob/5.11/src/corelib/io/qresource.cpp#L105
    fn find_offset(&self, node: i32) -> i32 {
        let m = if self.version >= 2 { 22 } else { 14 };
        node * m
    }

    fn read_name(&self, buffer: &[u8], name_offset: i32) -> Option<(String, u32)> {
        let mut stream = BinaryReader::new_at(buffer, self.name.wrapping_add_signed(name_offset as isize));
        let name_length = stream.read_u16::<true>()?;
        let name_hash = stream.read_u32::<true>()?;
        let name = stream.read_u16_string::<true>(name_length as usize)?;
        Some((name, name_hash))
    }

    fn read_data(&self, buffer: &[u8], data_offset: i32) -> Option<Vec<u8>> {
        let mut stream = BinaryReader::new_at(buffer, self.data.wrapping_add_signed(data_offset as isize));
        let data_size = stream.read_u32::<true>()?;
        let data = stream.read_bytes(data_size as usize)?;
        Some(Vec::from(data))
    }

    #[must_use] pub fn parse_node(&self, buffer: &[u8], node: i32) -> Option<QtNode> {
        if node == -1 {
            return None;
        }

        let mut stream = BinaryReader::new(buffer);

        /*
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
        */

        let node_offset = self.tree.wrapping_add_signed(self.find_offset(node) as isize);

        stream.seek(node_offset);
        let name_offset = stream.read_i32::<true>()?;
        let flags = stream.read_u16::<true>()?;
        let is_directory = flags & 2 != 0;
        let is_compressed = flags & 1 != 0;

        // read name
        let (name, name_hash) = self.read_name(buffer, name_offset)?;

        // read etc
        let aux = if is_directory {
            let child_count = stream.read_i32::<true>()?;
            let child_offset = stream.read_i32::<true>()?;
            let mut children = Vec::new();

            for i in child_offset..child_offset + child_count {
                children.push(self.parse_node(buffer, i)?);
            }

            QtNodeAux::Directory(children)
        } else {
            let locale = stream.read_u32::<true>()?;
            let data_offset = stream.read_i32::<true>()?;

            QtNodeAux::Resource { locale, is_compressed, file_offset: self.data.wrapping_add_signed(data_offset as isize), data: self.read_data(buffer, data_offset)? }
        };

        let last_modified = if self.version >= 2 {
            stream.read_u64::<true>()?
        } else {
            0u64
        };

        Some(QtNode { id: node, name, name_hash, flags, aux, last_modified })
    }
}

