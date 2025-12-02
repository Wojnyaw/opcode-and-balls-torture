use std::io;
use std::fmt;

#[derive(Debug)]
pub enum DisasmError{
    // i/o related error.
    IoError(io::Error),

    // elf parsing error.
    InvalidElfMagic,
    InvalidElfClass,
    InvalidEndianness,
    SectionNotFound,
    InvalidSectionHeader,
    FileTooLarge,
    TruncatedHeader,

    // decoding errors.
    UnknownOpcode(u8),
    TruncatedInstruction,
    InvalidModRM,
    InvalidRexPrefix,
    InvalidOperand,
    InstructionTooLong
}

// implement display trait for human readable error messages.
impl fmt::Display for DisasmError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            DisasmError::IoError(err) => write!(f, "I/O error: {}", err),
            DisasmError::InvalidElfMagic => write!(f, "Invalid ELF magic number - not a valid ELF file"),
            DisasmError::InvalidElfClass => write!(f, "Invalid ELF class - only 64-bit ELF files supported"),
            DisasmError::InvalidEndianness => write!(f, "Invalid endianness - only little-endian supported"),
            DisasmError::SectionNotFound => write!(f, ".text section not found in ELF file"),
            DisasmError::InvalidSectionHeader => write!(f, "Invalid or corrupted section header"),
            DisasmError::FileTooLarge => write!(f, "File exceeds maximum size limit (100MB)"),
            DisasmError::TruncatedHeader => write!(f, "ELF header is truncated or incomplete"),
            DisasmError::UnknownOpcode(byte) => write!(f, "Unknown opcode: 0x{:02x}", byte),
            DisasmError::TruncatedInstruction => write!(f, "Instruction extends beyond available bytes"),
            DisasmError::InvalidModRM => write!(f, "Invalid ModR/M byte encoding"),
            DisasmError::InvalidRexPrefix => write!(f, "Invalid REX prefix position or encoding"),
            DisasmError::InvalidOperand => write!(f, "Invalid operand encoding"),
            DisasmError::InstructionTooLong => write!(f, "Instruction exceeds maximum length of 15 bytes"),
        }
    }
}

impl std::error::Error for DisasmError{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            DisasmError::IoError(err) => Some(err),
            _ => None
        }
    }
}

impl From<io::Error> for DisasmError {
    fn from (err: io::Error) -> DisasmError {
        DisasmError::IoError(err)
    }
}