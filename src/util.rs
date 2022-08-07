
macro_rules! err {
    ($reason:expr) => {
        {
            log::error!($reason);
            Err(std::io::Error::new(std::io::ErrorKind::Other, $reason))
        }
    }
}

pub(crate) use err;

pub fn str_from_nul_bytes_buf(buf: &[u8]) -> Result<&str, std::io::Error> {
    let buf = std::str::from_utf8(buf).map_err(|_|
        std::io::Error::new(std::io::ErrorKind::Other, "failed to encode utf8 string"))?;
    Ok(buf.trim_end_matches('\0'))
}

#[cfg(test)]
mod tests {

    use super::str_from_nul_bytes_buf;

    #[test]
    fn test_str_conversion() {
        let buf = b"ustar\0\0\0\0\0";
        let value = str_from_nul_bytes_buf(buf).unwrap();
        assert_eq!(value, "ustar");
    }


}
