pub fn bigendian_u16(b: &[u8]) -> u16 {
    return bigendian(b, 2) as u16;
}

pub fn bigendian_u32(b: &[u8]) -> u32 {
    return bigendian(b, 4) as u32;
}

fn bigendian(b: &[u8], len: u8) -> u128 {
    let mut shift: u128 = (len - 1) as u128 * 8;
    let mut result: u128 = 0;
    let mut idx = 0;
    loop {
        result += (b[idx] as u128) << shift;
        if idx == b.len() - 1 {
            break;
        }
        idx += 1;
        shift -= 8;
    }
    return result;
}