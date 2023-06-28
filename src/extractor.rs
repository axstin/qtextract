use std::fs;
use std::io::{Read, Write};
use std::path::PathBuf;
use libflate::zlib;
use crate::binary_stream::*;

pub enum QtNodeAux {
    Directory(Vec<QtNode>),
    Resource {
        locale: u32,
        is_compressed: bool,
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
    pub fn is_compressed(&self) -> bool {
        if let QtNodeAux::Resource { is_compressed, .. } = self.aux {
            is_compressed
        } else {
            false
        }
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

    pub fn parse_node(&self, buffer: &[u8], node: i32) -> Option<QtNode> {
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

        let node_offset = self.tree + self.find_offset(node) as usize;

        stream.seek(node_offset);
        let name_offset = stream.read_i32::<true>()?;
        let flags = stream.read_u16::<true>()?;
        let is_directory = flags & 2 != 0;
        let is_compressed = flags & 1 != 0;

        // read name
        let (name, name_hash) = {
            let mut stream = BinaryReader::new_at(buffer, self.name + name_offset as usize);
            let name_length = stream.read_u16::<true>()?;
            let name_hash = stream.read_u32::<true>()?;
            let name = stream.read_u16_string::<true>(name_length as usize)?;
            (name, name_hash)
        };

        // read etc
        let aux = if is_directory {
            let child_count = stream.read_u32::<true>()?;
            let child_offset = stream.read_u32::<true>()?;
            let mut children = Vec::new();

            for i in child_offset..child_offset + child_count {
                children.push(self.parse_node(buffer, i as i32)?);
            }

            QtNodeAux::Directory(children)
        } else {
            let locale = stream.read_u32::<true>()?;
            let data_offset = stream.read_i32::<true>()?;

            let mut stream = BinaryReader::new_at(buffer, self.data + data_offset as usize);
            let data_size = stream.read_u32::<true>()?;
            let data = stream.read_bytes(data_size as usize)?;

            QtNodeAux::Resource { locale, is_compressed, data: Vec::from(data) }
        };

        let last_modified = if self.version >= 2 {
            stream.read_u64::<true>()?
        } else {
            0u64
        };

        Some(QtNode { id: node, name, name_hash, flags, aux, last_modified })
    }

    fn dump_impl(&self, node: &QtNode, path: &PathBuf, c: usize) -> std::io::Result<()> {
        let indent = "  ".repeat(c);
        let node_path = path.join(node.name.as_str());

        print!("{}{}", indent, node.name);

        // https://github.com/qt/qtbase/blob/5.11/src/corelib/io/qresource.cpp#L538
        let last_modified = if node.last_modified != 0 {
            let time = std::time::UNIX_EPOCH + std::time::Duration::from_millis(node.last_modified);
            print!(" (last modified {})", time::OffsetDateTime::from(time));
            Some(time)
        } else {
            None
        };
        
        match &node.aux {
            QtNodeAux::Directory(children) => {
                println!();

                fs::create_dir_all(&node_path)?;

                for child in children {
                    self.dump_impl(child, &node_path, c + 1)?;
                }
            },
            QtNodeAux::Resource { is_compressed, data, .. } => {
                print!(" ({} bytes)", data.len());
                if *is_compressed {
                    print!(" [compressed]");
                }

                let mut tmp = Vec::new();

                fs::File::create(node_path)?.write_all(if *is_compressed {
                    if data.len() > 4 {
                        println!();
                        print!("{}  decompressing... ", indent);
                        let mut decoder = zlib::Decoder::new(&data[4..])?;
                        decoder.read_to_end(&mut tmp)?;
                        print!("ok, {} bytes", tmp.len());
                    }
                    &tmp
                } else {
                    data
                })?;

                println!();

                // todo: set last modified attribute on disk
            }
        };

        Ok(())
    }

    pub fn dump_node(&self, node: &QtNode, path: &PathBuf) -> std::io::Result<()> {
        self.dump_impl(node, path, 0)
    }
}

