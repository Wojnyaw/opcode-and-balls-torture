use crate::error::DisasmError;

// helper functions to read little endian u16, u32, u64 from byte slice at offset
pub fn read_u16_le(data: &[u8], offset: usize) -> Result<u16, DisasmError> {
    let end = offset.checked_add(2)
        .ok_or(DisasmError::TruncatedInstruction)?;

    if end > data.len(){
        return Err(DisasmError::TruncatedInstruction);
    }

    let slice = &data[offset..end];
    let array: [u8; 2] = slice
        .try_into()
        .map_err(|_| DisasmError::TruncatedInstruction)?;

    Ok(u16::from_le_bytes(array))
}

pub fn read_u32_le(data: &[u8], offset: usize) -> Result<u32, DisasmError> {
    let end = offset.checked_add(4)
        .ok_or(DisasmError::TruncatedInstruction)?;

    if end > data.len(){
        return Err(DisasmError::TruncatedInstruction);
    }

    let slice = &data[offset..end];
    let array: [u8; 4] = slice
        .try_into()
        .map_err(|_| DisasmError::TruncatedInstruction)?;

    Ok(u32::from_le_bytes(array))
}

pub fn read_u64_le(data: &[u8], offset: usize) -> Result<u64, DisasmError> {
    let end = offset.checked_add(8)
        .ok_or(DisasmError::TruncatedInstruction)?;

    if end > data.len(){
        return Err(DisasmError::TruncatedInstruction);
    }

    let slice = &data[offset..end];
    let array: [u8; 8] = slice
        .try_into()
        .map_err(|_| DisasmError::TruncatedInstruction)?;

    Ok(u64::from_le_bytes(array))
}