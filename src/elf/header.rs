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
const E_IDENT_SIZE: usize = 64;

// ELF64 header structure matching specification layout. AAANd i have migraine. good night. will continue tomorrow.
pub struct ElfHeader {
    
}