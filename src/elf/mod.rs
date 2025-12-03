pub mod header;
pub mod section;

use header::parse_header;
use section::find_text_section;
use crate::error::DisasmError;

pub struct TextSection<'a> {
    pub offset: usize,
    pub size: usize,
    pub data: &'a [u8],
}

pub fn parse_elf<'a>(bytes: &'a [u8]) -> Result<TextSection<'a>, DisasmError> {
    if bytes.len() < 64 {
        return Err(DisasmError::TruncatedHeader);
    }

    let elf_header = parse_header(bytes)?;

    // e_shoff: offset to section header table.
    // e_shnum: number of section headers.
    let section_header_offset = elf_header.e_shoff;
    let section_header_count = elf_header.e_shnum;

    // each ELF64 section header is exactly 64 bytes.
    const SECTION_HEADER_SIZE: usize = 64;
    let required_size = section_header_offset + (section_header_count * SECTION_HEADER_SIZE);

    if required_size > bytes.len() {
        return Err(DisasmError::TruncatedHeader);
    }

    // this searches for executable code section and extracts its location. returns TextSection struct with offset, size, and data slice.
    let text_section = find_text_section(
        bytes,
        section_header_offset as u64,
        section_header_count as u16,
    )?;

    // return successfully parsed .text section.
    Ok(text_section)
}