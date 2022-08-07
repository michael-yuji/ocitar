
use std::io::Read;

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

pub struct PrebufferedSource< R: Read> {
    buffer: Vec<u8>,
    source: R
}

impl<R: Read> PrebufferedSource<R> {
    pub fn new(buffer: &[u8], source: R) -> PrebufferedSource<R> {
        PrebufferedSource {
            buffer: buffer.to_vec(),
            source
        }
    }
}

impl<R: Read> Read for PrebufferedSource<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let from_buf = self.buffer.len().min(buf.len());

        if !self.buffer.is_empty() {
            buf[..from_buf].copy_from_slice(&self.buffer[..from_buf]);
            self.buffer = self.buffer[from_buf..].to_vec();
        }

        eprintln!("from_buf: {from_buf}");
        eprintln!("required_buf_size: {}", buf.len());
        let cnt = self.source.read(&mut buf[from_buf..])?;
        Ok(cnt + from_buf)
        /*
        self.source.read_exact(&mut buf[from_buf..])?;
        Ok(buf.len())
        */
    }
}


#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_str_conversion() {
        let buf = b"ustar\0\0\0\0\0";
        let value = str_from_nul_bytes_buf(buf).unwrap();
        assert_eq!(value, "ustar");
    }

    #[test]
    fn test_prebuffered_read() -> std::io::Result<()> {
        let source = b"0123456789";
        let mut pbs = PrebufferedSource::new(b"01234", source.as_slice());
        let mut sink = [0u8; 15];
        pbs.read_exact(&mut sink[0..2])?;
        pbs.read_exact(&mut sink[2..5])?;
        pbs.read_exact(&mut sink[5..10])?;
        pbs.read_exact(&mut sink[10..15])?;
        assert_eq!(&sink, b"012340123456789");
        Ok(())
    }
}
