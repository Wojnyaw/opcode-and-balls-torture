use crate::error::DisasmError;
use std::convert::TryInto;
use super::utils::{read_u32_le, read_u64_le};

// ELF64 section header constants
const SECTION_HEADER_SIZE: usize = 16;

// section types (sh_type field values)
const SHT_NULL: u32 = 0;
const SHT_PROGBITS: u32 = 1;
const SHT_SYMTAB: u32 = 2;
const SHT_STRTAB: u32 = 3;
const SHT_NOBITS: u32 = 8;

// section attribute flags (sh_flags field bit flags)
const SHF_WRITE : u64 = 0x1;
const SHF_ALLOC : u64 = 0x2;
const SHF_EXECINSTR : u64 = 0x4;

// section header structure matching ELF64 specification. Represents metadata about a section in the ELF file.
pub struct SectionHeader{
    pub sh_name: u32,
    pub sh_type: u32,
    pub sh_flags: u64,
    pub sh_addr: u64,
    pub sh_offset: u64,
    pub sh_size: u64,
    pub sh_link: u32,
    pub sh_info: u32,
    pub sh_addralign: u64,
    pub sh_entsize: u64,
}

// structure to return .text section information. Contains both metadata and a reference to the actual section bytes.
pub struct TextSection<'a> {
    pub offset: u64,
    pub size: u64,
    pub virtual_addr: u64,
    pub data: &'a [u8],
}

// parse section header at specific offset in file.
// helper function to extract one section header from byte buffer.
pub fn parse_single_header(bytes: &[u8], offset: usize) -> Result<SectionHeader, DisasmError> {
    if offset + SECTION_HEADER_SIZE > bytes.len() {
        return Err(DisasmError::InvalidSectionHeader);
    }

    let section_bytes = &bytes[offset..(offset + SECTION_HEADER_SIZE)];

    // ELF64 section header layout...
    // Offset | Field         | Size | Type
    // -------|---------------|------|------
    // 0-3    | sh_name       | 4    | u32
    // 4-7    | sh_type       | 4    | u32
    // 8-15   | sh_flags      | 8    | u64
    // 16-23  | sh_addr       | 8    | u64
    // 24-31  | sh_offset     | 8    | u64
    // 32-39  | sh_size       | 8    | u64
    // 40-43  | sh_link       | 4    | u32
    // 44-47  | sh_info       | 4    | u32
    // 48-55  | sh_addralign  | 8    | u64
    // 56-63  | sh_entsize    | 8    | u64

    let header = SectionHeader{
        sh_name: read_u32_le(section_bytes, 0)?,
        sh_type: read_u32_le(section_bytes, 4)?,
        sh_flags: read_u64_le(section_bytes, 8)?,
        sh_addr: read_u64_le(section_bytes, 16)?,
        sh_offset: read_u64_le(section_bytes, 24)?,
        sh_size: read_u64_le(section_bytes, 32)?,
        sh_link:  read_u32_le(section_bytes, 40)?,
        sh_info: read_u32_le(section_bytes, 44)?,
        sh_addralign: read_u64_le(section_bytes, 48)?,
        sh_entsize: read_u64_le(section_bytes, 56)?,
    };

    return Ok(header)
}