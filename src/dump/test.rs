#[cfg(test)]
mod test_endian {
    use crate::dump::endian::{bigendian_u16, bigendian_u32};

    #[test]
    fn test_bigendian() {
        let b16 = bigendian_u16(&[1, 2]);
        assert_eq!(b16, ((1 as u16) << 8) + 2);
        let b32 = bigendian_u32(&[1, 2, 3, 4]);
        assert_eq!(b32, ((1 as u32) << 24) + ((2 as u32) << 16) + ((3 as u32) << 8) + 4 as u32);
    }
}