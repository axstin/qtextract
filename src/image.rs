use goblin::{self, pe, elf, mach};
use std::fmt;

// goblin::Object without fat mach
pub enum ImageBinary<'a> {
    PE(goblin::pe::PE<'a>),
    ELF(goblin::elf::Elf<'a>),
    MachO(goblin::mach::MachO<'a>),
    Unknown()
}

pub const IM_TYPE_PE: u32 = 1 << 0;
pub const IM_TYPE_ELF: u32 = 1 << 1;
pub const IM_TYPE_MACHO: u32 = 1 << 2;

pub const IM_FLAGS_32BIT: u32 = 1 << 8;
pub const IM_FLAGS_64BIT: u32 = 1 << 9;

pub const IM_ARCH_X86: u32 = 1 << 16;
pub const IM_ARCH_X86_64: u32 = 1 << 17;
pub const IM_ARCH_ARM: u32 = 1 << 18;
pub const IM_ARCH_ARM64: u32 = 1 << 19;

impl ImageBinary<'_> {
    #[must_use]
    pub const fn variant_name(&self) -> &str {
        match &self {
            ImageBinary::ELF(_) => "Elf",
            ImageBinary::PE(_) => "PE",
            ImageBinary::MachO(_) => "MachO",
            ImageBinary::Unknown() => "Other"
        }
    }
}

#[derive(Debug)]
pub struct ImageSection {
    pub name: Option<String>,
    pub file_offset: u64,
    pub size: u64,
    pub virtual_address: u64,
    pub is_writable: bool,
    pub is_code: bool
}

pub struct Image<'a> {
    pub binary: ImageBinary<'a>,
    pub flags: u32,
    pub base: u64,
    pub sections: Vec<ImageSection>,
    pub buffer: &'a [u8]
}

impl fmt::Debug for Image<'_> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_struct("Image")
            .field("binary.variant_name()", &self.binary.variant_name())
            .field("flags", &self.flags)
            .field("base", &self.base)
            .field("sections", &self.sections)
            .finish()
    }
}

impl Image<'_> {
    #[must_use]
    pub fn from(buffer: &'_ [u8], mach_hint: Option<mach::cputype::CpuType>) -> Option<Image<'_>> {
        let mut macho_base: u32 = 0;

        let binary = match goblin::Object::parse(buffer).ok()? {
            goblin::Object::PE(pe) => ImageBinary::PE(pe),
            goblin::Object::Elf(elf) => ImageBinary::ELF(elf),
            goblin::Object::Mach(mach) => {
                ImageBinary::MachO(match mach {
                    mach::Mach::Fat(fat) => {
                        let arches = fat.iter_arches().filter_map(|a| a.ok()).collect::<Vec<mach::fat::FatArch>>();
                        let index = arches.iter().position(|x| mach_hint.map_or(x.cputype & !mach::cputype::CPU_ARCH_MASK == mach::cputype::CPU_TYPE_X86, |hint| x.cputype == hint)).unwrap_or(0);
                        macho_base = arches[index].offset;
                        let macho = fat.get(index).ok()?;
                        println!("NOTICE: Using binary #{}/{} (arch: {}, offset: {}) in fat Mach binary", index + 1, fat.narches, mach::cputype::get_arch_name_from_types(macho.header.cputype, macho.header.cpusubtype).unwrap_or("unknown"), macho_base);
                        macho
                    },
                    mach::Mach::Binary(bin) => bin
                })
            },
            _ => {
                return None;
            }
        };

        let mut sections: Vec<ImageSection> = Vec::new();
        let mut flags: u32 = 0;

        match &binary {
            ImageBinary::PE(pe) => {
                flags |= IM_TYPE_PE;
                flags |= if pe.is_64 { IM_FLAGS_64BIT } else { IM_FLAGS_32BIT };

                flags |= match pe.header.coff_header.machine {
                    0x14c => IM_ARCH_X86,
                    0x8664 => IM_ARCH_X86_64,
                    0x1c0 => IM_ARCH_ARM,
                    0xaa64 => IM_ARCH_ARM64,
                    _ => { return None; }
                };

                for section in &pe.sections {
                    sections.push(ImageSection {
                        name: section.name().ok().map(|s| s.to_string()),
                        file_offset: u64::from(section.pointer_to_raw_data),
                        size: u64::from(section.size_of_raw_data),
                        virtual_address: u64::from(section.virtual_address) + pe.image_base as u64,
                        is_writable: (section.characteristics & pe::section_table::IMAGE_SCN_MEM_WRITE) != 0,
                        is_code: (section.characteristics & (pe::section_table::IMAGE_SCN_CNT_CODE | pe::section_table::IMAGE_SCN_MEM_EXECUTE)) != 0
                    });
                }
            },
            ImageBinary::ELF(elf) => {
                // for now
                if !elf.little_endian {
                    return None;
                }

                flags |= IM_TYPE_ELF;
                flags |= if elf.is_64 { IM_FLAGS_64BIT } else { IM_FLAGS_32BIT };

                flags |= match elf.header.e_machine {
                    3 => IM_ARCH_X86,
                    62 => IM_ARCH_X86_64,
                    40 => IM_ARCH_ARM,
                    183 => IM_ARCH_ARM64,
                    _ => { return None; }
                };                

                for segment in &elf.program_headers {
                    if segment.p_type == elf::program_header::PT_LOAD {
                        sections.push(ImageSection {
                            name: Some(format!("PHDR_{:08X}", segment.p_offset)),
                            file_offset: segment.p_offset,
                            size: segment.p_filesz,
                            virtual_address: segment.p_vaddr,
                            is_writable: segment.is_write(),
                            is_code: segment.is_executable()
                        });
                    }
                }
            },
            ImageBinary::MachO(macho) => {
                // for now
                if !macho.little_endian {
                    return None;
                }

                flags |= IM_TYPE_MACHO;
                flags |= if macho.is_64 { IM_FLAGS_64BIT } else { IM_FLAGS_32BIT };

                flags |= match macho.header.cputype {
                    mach::cputype::CPU_TYPE_X86 => IM_ARCH_X86,
                    mach::cputype::CPU_TYPE_X86_64 => IM_ARCH_X86_64,
                    mach::cputype::CPU_TYPE_ARM => IM_ARCH_ARM,
                    mach::cputype::CPU_TYPE_ARM64 => IM_ARCH_ARM64,
                    _ => {return None; }
                };

                for segment in &macho.segments {
                    sections.push(ImageSection {
                        name: segment.name().ok().map(|s| s.to_string()),
                        file_offset: macho_base as u64 + segment.fileoff,
                        size: segment.filesize,
                        virtual_address: segment.vmaddr,
                        is_writable: segment.maxprot & mach::constants::VM_PROT_WRITE != 0,
                        is_code: segment.maxprot & mach::constants::VM_PROT_EXECUTE != 0
                    });
                }                
            },
            ImageBinary::Unknown() => {
                return None;
            }
        };

        let base: u64 = match &binary {
            ImageBinary::PE(pe) => pe.image_base as u64,
            _ => 0
        };

        Some(Image {
            binary,
            flags,
            base,
            sections,
            buffer
        })
    }

    pub fn rva2fo(&self, rva: u64) -> Option<u64> {
        self.va2fo(self.base + rva)
    }

    pub fn fo2rva(&self, offset: u64) -> Option<u64> {
        self.fo2va(offset).map(|va| va - self.base)
    }

    pub fn fo2va(&self, offset: u64) -> Option<u64> {
        for section in &self.sections {
            if offset >= section.file_offset && offset < section.file_offset + section.size {
                return Some((offset - section.file_offset) + section.virtual_address)
            }
        }
        None
    }

    pub fn va2fo(&self, va: u64) -> Option<u64> {
        for section in &self.sections {
            if va >= section.virtual_address && va < section.virtual_address + section.size {
                return Some((va - section.virtual_address) + section.file_offset)
            }
        }
        None
    }

    pub const fn is_x64(&self) -> bool {
        self.flags & IM_FLAGS_64BIT != 0
    }

    pub fn read_at_u8(&self, offset: u64) -> Option<u8> {
        let len = self.buffer.len();
        if offset >= len as u64  {
            return None
        }

        return Some(self.buffer[offset as usize])
    }

    pub fn read_at_u32(&self, offset: u64) -> Option<u32> {
        let offset_us = offset as usize;
        let size = size_of::<u32>() as usize;
        let len = self.buffer.len();
        if offset_us + size >= len.into()  {
            return None
        }

        let mut arr = [0u8; 4];
        arr[0] = self.buffer[offset_us + 0];
        arr[1] = self.buffer[offset_us + 1];
        arr[2] = self.buffer[offset_us + 2];
        arr[3] = self.buffer[offset_us + 3];

        return Some(u32::from_le_bytes(arr));
    }
}
