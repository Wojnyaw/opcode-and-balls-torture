use crate::error::DisasmError;
use std::convert::TryInto;
use super::utils::{read_u16_le, read_u32_le, read_u64_le};

// ELF64 header constants.
const ELF_MAGIC_0: u8 = 0x7f;
const ELF_MAGIC_1: u8 = 0x45;
const ELF_MAGIC_2: u8 = 0x4c;
const ELF_MAGIC_3: u8 = 0x46;

const ELF_CLASS_64: u8 = 0x02;
const ELF_DATA_2LSB: u8 = 0x01; // little endian encoding.

// byte offsets with e_ident array (16 bytes total.)
const EI_MAG0: usize = 0;
const EI_MAG1: usize = 1;
const EI_MAG2: usize = 2;
const EI_MAG3: usize = 3;
const EI_CLASS: usize = 4;
const EI_DATA: usize = 5;

// minimum size requirements
const ELF_HEADER_SIZE: usize = 64;
const E_IDENT_SIZE: usize = 16;

// ELF64 header structure matching specification layout. AAANd i have migraine. good night. will continue tomorrow.
pub struct ElfHeader {
    pub e_ident: [u8; E_IDENT_SIZE],
    pub e_type: u16,
    pub e_machine: u16,
    pub e_version: u32,
    pub e_entry: u64,
    pub e_phoff: u64,
    pub e_shoff: u64,
    pub e_flags: u32,
    pub e_ehsize: u16,
    pub e_phentsize: u16,
    pub e_phnum: u16,
    pub e_shentsize: u16,
    pub e_shnum: u16,
    pub e_shstrndx: u16,
}

pub fn parse_header(bytes: &[u8]) -> Result<ElfHeader, DisasmError> {
    if bytes.len() < ELF_HEADER_SIZE {
        return Err(DisasmError::TruncatedHeader);
    }

    if bytes[EI_MAG0] != ELF_MAGIC_0 {
        return Err(DisasmError::InvalidElfMagic);
    }

    if bytes[EI_MAG1] != ELF_MAGIC_1 {
        return Err(DisasmError::InvalidElfMagic);
    }

    if bytes[EI_MAG2] != ELF_MAGIC_2 {
        return Err(DisasmError::InvalidElfMagic);
    }

    if bytes[EI_MAG3] != ELF_MAGIC_3 {
        return Err(DisasmError::InvalidElfMagic);
    }

    // verify 64 bit class
    if bytes[EI_CLASS] != ELF_CLASS_64 {
        return Err(DisasmError::InvalidElfClass);
    }

    // verify little endian encoding.
    if bytes[EI_DATA] != ELF_DATA_2LSB {
        return Err(DisasmError::InvalidEndianness);
    }

    // extract e_ident array (first 16 bytes)
    let e_ident_array: [u8; 16] = bytes[0..16]
        .try_into()
        .expect("Slice with incorrect length");

    // extract multi byte fields using little endian byte order.
    // Offset | Field        | Size | Type
    // -------|--------------|------|------
    // 0-15   | e_ident      | 16   | array
    // 16-17  | e_type       | 2    | u16
    // 18-19  | e_machine    | 2    | u16
    // 20-23  | e_version    | 4    | u32
    // 24-31  | e_entry      | 8    | u64
    // 32-39  | e_phoff      | 8    | u64
    // 40-47  | e_shoff      | 8    | u64
    // 48-51  | e_flags      | 4    | u32
    // 52-53  | e_ehsize     | 2    | u16
    // 54-55  | e_phentsize  | 2    | u16
    // 56-57  | e_phnum      | 2    | u16
    // 58-59  | e_shentsize  | 2    | u16
    // 60-61  | e_shnum      | 2    | u16
    // 62-63  | e_shstrndx   | 2    | u16
    // i might later forget to delete this lmao but whatever i need this



    // extract all header fields at their specified byte offsets.
    let e_type = read_u16_le(bytes, 16)?;
    let e_machine = read_u16_le(bytes, 18)?;
    let e_version = read_u32_le(bytes, 20)?;
    let e_entry = read_u64_le(bytes, 24)?;
    let e_phoff = read_u64_le(bytes, 32)?;
    let e_shoff = read_u64_le(bytes, 40)?;
    let e_flags = read_u32_le(bytes, 48)?;
    let e_ehsize = read_u16_le(bytes, 52)?;
    let e_phentsize = read_u16_le(bytes, 54)?;
    let e_phnum = read_u16_le(bytes, 56)?;
    let e_shentsize = read_u16_le(bytes, 58)?;
    let e_shnum = read_u16_le(bytes, 60)?;
    let e_shstrndx = read_u16_le(bytes, 62)?;

    // verify e_shnum within reasonable bounds.
    // prevent potential DoS from malicious files claiming millions of sections.
    const MAX_REASONABLE_SECTIONS: u16 = 65535;
    if e_shnum > MAX_REASONABLE_SECTIONS {
        return Err(DisasmError::InvalidSectionHeader);
    }

    // construct and return the parsed header structure.
    let header = ElfHeader {
        e_ident: e_ident_array, // TODO for later lmao
        e_type,
        e_machine,
        e_version,
        e_entry,
        e_phoff,
        e_shoff,
        e_flags,
        e_ehsize,
        e_phentsize,
        e_phnum,
        e_shentsize,
        e_shnum,
        e_shstrndx,
    };

    Ok(header)
}