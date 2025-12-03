use crate::error::DisasmError;
use std::convert::TryInto;

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
    e_ident: [usize; ELF_HEADER_SIZE],
    e_type: u16,
    e_machine: u16,
    e_version: u32,
    e_entry: u64,
    e_phoff: u64,
    e_shoff: u64,
    e_flags: u32,
    e_ehsize: u16,
    e_phentsize: u16,
    e_phnum: u16,
    e_shentsize: u16,
    e_shnum: u16,
    e_shstrndx: u16,
}

fn parse_header(bytes: &[u8]) -> Result<ElfHeader, DisasmError> {
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

    // TODO extract e_ident array (first 16 bytes)
}