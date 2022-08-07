use std::io::{Read, Write};
use crate::util::{err, str_from_nul_bytes_buf};
use serde::{Serialize, Deserialize};

const WHITEOUT_VERSION: u32 = 1;
const EMPTY_TAR_HEADER: [u8;512] = [0u8; 512];

#[derive(Debug, Serialize, Deserialize)]
struct WhiteoutExtension {
    version: u32,
    whiteouts: Vec<String>
}

impl WhiteoutExtension {
    fn new(paths: &[String]) -> WhiteoutExtension {
        WhiteoutExtension { version: WHITEOUT_VERSION, whiteouts: paths.to_vec() }
    }
}

/// ustar header
#[repr(C, packed)]
#[derive(Debug, Clone)]
struct RawTarHeader {
    name:      [u8; 100],
    mode:      [u8; 8],
    uid:       [u8; 8],
    gid:       [u8; 8],
    size:      [u8; 12],
    lastmod:   [u8; 12],
    cksum:     [u8; 8],
    tpe:       [u8; 1],
    link:      [u8; 100],
    ustar:     [u8; 6],
    ver:       [u8; 2],
    usr_name:  [u8; 32],
    grp_name:  [u8; 32],
    devmj_n:   [u8; 8],
    devmi_n:   [u8; 8],
    prefix:    [u8; 155],
    pad:       [u8; 12]
}


impl RawTarHeader
{
    /// Create a zerod tar header block
    pub fn empty() -> RawTarHeader {
        unsafe { std::mem::zeroed::<RawTarHeader>() }
    }

    /// Create a tar header with ustar specific fields filled
    pub fn empty_ustar() -> RawTarHeader {
        let mut header = RawTarHeader::empty();
        header.ustar = *b"ustar\0";
        header.ver = *b"00";
        header.devmi_n = *b"0000000 ";
        header.devmj_n = *b"0000000 ";
        header
    }

    /// Get the path of this header, if the header is *not* a ustar header, this
    /// is same of `name`, otherwise if the header is a ustar header and this prefix
    /// is not null, this is {prefix}/{name}
    pub fn file_path(&self) -> std::io::Result<std::path::PathBuf> {
        let mut path = str_from_nul_bytes_buf(&self.name)?.to_string();
        if self.is_ustar_header() && self.prefix != [0u8; 155] {
            path.insert(0, '/');
            path.insert_str(0, str_from_nul_bytes_buf(&self.prefix)?);
        }
        Ok(std::path::PathBuf::from(path))
    }

    /// Get the content length of this header
    pub fn content_length(&self) -> std::io::Result<u128> {
        // If the size field starts with 0xff, the size is encoded in base256
        if self.size[0] == 0xff {
            let mut buf = [0u8; 16];
            buf[5..].copy_from_slice(&self.size[1..]);
            Ok(u128::from_be_bytes(buf))
        } else {
            let mut value = 0u128;

            // loop thru the buffer but skip the Nul terminator
            for i in 0 .. self.size.len() - 1 {
                let byte = self.size[self.size.len() - 2 - i];

                if !(b'0'..=b'7').contains(&byte) {
                    return err!("Invalid octal digit")
                }

                let digit = byte - b'0';
                value += (digit as u128) << (3 * i);
            }

            Ok(value)
        }
    }
    pub fn set_mode(&mut self, mode: u32) {
        self.mode.copy_from_slice(format!("{:0>6o} \0", mode).as_bytes());
    }

    /// Set the content length of the file
    pub fn set_size(&mut self, size: usize) {
        self.size.copy_from_slice(format!("{size:0>11o} ").as_bytes());
    }

    pub fn set_path(&mut self, prefix: Option<String>, name: String)
    {
        let prefix_len = prefix.as_ref().map(|p| p.len()).unwrap_or(0);
        
        if prefix_len > 155 {
            panic!("prefix len too long")
        }

        if name.len() > 100 {
            panic!("file name too long")
        }

        match prefix {
            None => self.name[..name.len()].copy_from_slice(name.as_bytes()),
            Some(prefix) => {
                let path = format!("{prefix}/{name}");
                if path.len() > 100 {
                    self.prefix[..prefix_len].copy_from_slice(prefix.as_bytes());
                    self.name[..name.len()].copy_from_slice(name.as_bytes())
                } else {
                    self.name[..path.len()].copy_from_slice(path.as_bytes())
                }
            }
        }
    }

    /// set the uid, gid, username and group name by the euid and guid of the current process
    pub fn set_uid_gid(&mut self) {
        unsafe {
            let gid = libc::getegid();
            let uid = libc::geteuid();
            let group = libc::getgrgid(gid);
            let user = libc::getpwuid(uid);

            let user_name = std::ffi::CStr::from_ptr((*user).pw_name).to_bytes();
            let name_len = user_name.len().min(31);
            let ouid = format!("{:0>6o}\0 ", uid);
            self.uid = ouid.as_bytes().try_into().unwrap();
            self.usr_name[..name_len].copy_from_slice(&user_name[..name_len]);

            let group_name = std::ffi::CStr::from_ptr((*group).gr_name).to_bytes();
            let gname_len = group_name.len().min(31);
            let ogid = format!("{:0>6o}\0 ", gid);
            self.gid = ogid.as_bytes().try_into().unwrap();
            self.grp_name[..gname_len].copy_from_slice(&group_name[..gname_len]);
        }
    }

    /// Calculate and set the checksum of this header
    pub fn set_checksum(&mut self) {
        self.cksum = self.checksum();
    }

    /// Set last modified to the timestamp
    pub fn set_lastmod(&mut self, timestamp: u64) {
        self.lastmod.copy_from_slice(format!("{:0>11o} ", timestamp).as_bytes());
    }

    /// Calcuate the expected checksum
    pub fn checksum(&self) -> [u8; 8]
    {
        macro_rules! add_sum {
            ($sum:expr, $this:expr, $field:ident) => {
                for byte in $this.$field {
                    $sum += (byte as u64);
                }
            }
        }

        let mut sum = 0u64;
        add_sum!(sum, self, name);
        add_sum!(sum, self, mode);
        add_sum!(sum, self, uid);
        add_sum!(sum, self, gid);
        add_sum!(sum, self, size);
        add_sum!(sum, self, lastmod);
        // checksum field are treated as 4 space byte
        sum += 0x20u64 * 8;
        add_sum!(sum, self, tpe);
        add_sum!(sum, self, link);
        add_sum!(sum, self, ustar);
        add_sum!(sum, self, ver);
        add_sum!(sum, self, usr_name);
        add_sum!(sum, self, grp_name);
        add_sum!(sum, self, devmj_n);
        add_sum!(sum, self, devmi_n);
        add_sum!(sum, self, prefix);
        add_sum!(sum, self, pad);

        let string = format!("{:0>6o}\0 ", sum);
        string.as_bytes().try_into().unwrap()
    }

    pub fn is_valid_tar_header(&self) -> bool {
        self.checksum() == self.cksum
    }

    pub fn is_ustar_header(&self) -> bool {
        self.is_valid_tar_header() && self.ustar == *b"ustar\0"
    }

    pub fn is_extension(&self) -> bool {
        self.is_ustar_header() && (self.tpe[0] == b'x' || self.tpe[0] == b'g')
    }

    pub fn is_whiteout_extension(&self) -> bool {
        let whiteout_identifier = b"PaxHeader/WhiteOuts";
        self.is_ustar_header() && 
            self.tpe[0] == b'g' && 
            &self.name[..19] == whiteout_identifier.as_slice()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Extension {
    key: String,
    value: String
}

impl Extension {
    pub fn new(key: String, value: String) -> Extension {
        Extension { key, value }
    }

    #[allow(dead_code)]
    fn encoded(&self) -> String {
        format!("{} {}={}", self.key.len() + self.value.len() + 1, self.key, self.value)
    }

    pub fn read_from_stream<R: Read>(reader: &mut R, length: usize) -> std::io::Result<Vec<Extension>> {
        let blocks = (length + 511) / 512;
        let rem = (blocks * 512) - length;
        let mut v = vec![0u8; length];
        let mut sink = [0u8; 512];
        reader.read_exact(&mut v)?;
        reader.read_exact(&mut sink[0..rem])?;
        let mut string = std::str::from_utf8(&v).unwrap();
        
        let mut extensions = vec![];
        while !string.is_empty() {
            let (sizestr, rem) = string.split_once(' ').unwrap();
            let size = sizestr.parse::<usize>().unwrap();
            let (pairbuf, rem) = rem.split_at(size);
            let (key, value) = pairbuf.split_once('=').unwrap();
            extensions.push(Extension::new(key.to_string(), value.to_string()));

            string = rem;
        }

        Ok(extensions)
    }
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct Summary {
    files: Vec<String>,
    whiteouts: Vec<String>
}

pub fn remove_path(p: std::path::PathBuf) -> std::io::Result<()>
{
    log::warn!("removing: {p:?}");

    let path = std::path::PathBuf::from(&p);
    if path.exists() {
        if path.is_dir() {
            std::fs::remove_dir_all(path)
        } else {
            std::fs::remove_file(path)
        }
    } else {
        Ok(())
    }
}

pub fn write_oci_whiteouts<W: Write>(path: String, output: &mut W) -> std::io::Result<()> {
    let path = std::path::PathBuf::from(path);
    let parent = path.parent().map(|p| p.to_string_lossy().to_string());
    let mut file_name = path.file_name().unwrap().to_string_lossy().to_string();
    file_name.insert_str(0, ".wh.");

    let mut header = RawTarHeader::empty_ustar();
    header.set_mode(0o644);
    header.set_uid_gid();
    header.set_size(0);
    header.set_lastmod(unsafe { libc::time(std::ptr::null_mut()) } as u64);
    header.set_path(parent, file_name);
    header.tpe = *b"0";
    header.set_checksum();

    output.write_all(&unsafe {
        std::mem::transmute::<RawTarHeader, [u8;512]>(header) })?;
    Ok(())
}

pub fn tap_create_tar<R: Read, W: Write>(
    without_oci: bool, without_ext: bool, whiteouts: &[String], tar: &mut R, output: &mut W) -> std::io::Result<()>
{
    let whiteout_ext = WhiteoutExtension::new(whiteouts);
    let content_str = serde_json::to_string(&whiteout_ext)?;
    
    let mut buf = [0u8; 512 * 20];

    if !without_oci {
        for whiteout in whiteouts {
            write_oci_whiteouts(whiteout.to_string(), output)?;
        }
    }

    if !without_ext {
        write_extended_header(output, "whiteouts", &content_str)?;
    }

    loop {
        let bytes = tar.read(&mut buf)?;
        if bytes == 0 {
            break
        } else {
            output.write_all(&buf[..bytes])?;
        }
    }

    Ok(())
}


// read from a tar and pass to stdin of a real tar process
pub fn tap_extract_tar<R: Read, W: Write>(reader: &mut R, writer: &mut W) -> std::io::Result<()>
{
    // tar files ends with 2 or more continuous empty records
    let mut empty_records = 0;
    let mut buf = [0u8; 512];

    loop {
        log::debug!("reading next entry");
        reader.read_exact(&mut buf)?;
        log::trace!("finished reading entry");

        let header = unsafe { std::mem::transmute::<[u8;512], RawTarHeader>(buf) };

        if header.is_valid_tar_header() {
            // reset empty record counter as we encountered a vaild tar header
            empty_records = 0;
            let content_length = header.content_length()?;
            let blocks = (content_length + 511)/512;

            if header.is_whiteout_extension() {
                log::debug!("encountered whiteout extension");
                // read the extension details
                let extensions = Extension::read_from_stream(reader, content_length as usize)?;

                for extension in extensions.iter() {
                    if extension.key == *"whiteouts".to_string() {
                        let meta: WhiteoutExtension = serde_json::from_str(&extension.value).unwrap();
                        for path in meta.whiteouts {
                            log::info!("whiteout(ext): {path}");
                            remove_path(std::path::PathBuf::from(path))?;
                        }
                    }
                }
            } else {
                let path = header.file_path()?;
                let filename = path.file_name().unwrap().to_str().unwrap();

                if let Some(name) = filename.strip_prefix(".wh.") {
                    log::debug!("encountered oci whiteout file: {filename}");
                    if name == ".wh..opq" {

                        /*
                        let parent = match path.parent() {
                            Some(parent) => {
                                eprintln!("some:parent:({})", parent.to_string_lossy());
                                parent.to_path_buf()}
                            ,
                            None => std::path::PathBuf::from(".")
                        };
                        */

                        let mut parent = path.parent().unwrap().to_path_buf();
                        if parent.to_string_lossy() == "" {
                            parent  = std::path::PathBuf::from(".")
                        }

                        log::info!("whiteout(oci): {}/*", parent.to_string_lossy());

                        for dirent in std::fs::read_dir(parent)? {

                            let path = dirent?.path();
                            remove_path(path)?;
                        }
                    } else {
                        let to_delete = match path.parent() {
                            Some(parent) => parent.join(&name),
                            None => std::path::PathBuf::from(name)
                        };

                        log::info!("whiteout(oci): {}", to_delete.to_string_lossy());
                        remove_path(to_delete)?;
                    }

                    log::debug!("skipping {blocks} whiteout file content");
                    for _ in 0..blocks {
                        reader.read_exact(&mut buf)?;
                    }
                } else {
                    log::info!("extracting: {}", header.file_path()?.to_string_lossy());
                    writer.write_all(&buf)?;
                    log::debug!("written file header");
                    for i in 0..blocks {
                        reader.read_exact(&mut buf)?;
                        log::debug!("finished reading file content block {}", i);
                        writer.write_all(&buf)?;
                        log::debug!("written block {}", i);
                    }
                }
            }
        } else if buf == EMPTY_TAR_HEADER {
            log::debug!("empty block encountered");
            empty_records += 1;
            writer.write_all(&buf)?;

            if empty_records == 2 {
                break;
            }
        } else {
            return err!("unknown format");
        }
    }

    // write everything to tar
    loop {
        let n = reader.read(&mut buf)?;
        writer.write_all(&buf[0..n])?;
        if n == 0 {
            break
        }
    }

    Ok(())
}

pub fn list_tar<R: Read>(reader: &mut R) -> std::io::Result<Summary>
{
    // until RFC 1210 is stable we are stuck with this
    fn seek<R: Read>(reader: &mut R, buf: &mut [u8;512], blocks: u128) -> std::io::Result<()> {
        for _ in 0..blocks {
            reader.read_exact(buf)?;
        }
        Ok(())
    }

    let mut files = vec![];
    let mut whiteouts = vec![];
    let mut buf = [0u8; 512];
    let mut empty_records = 0;

    loop {
        log::debug!("reading next entry");
        reader.read_exact(&mut buf)?;
        log::trace!("finished reading entry");

        let header = unsafe { std::mem::transmute::<[u8;512], RawTarHeader>(buf) };
        log::trace!("header: {header:x?}");

        if header.is_valid_tar_header() {
            // reset empty records counter
            empty_records = 0;

            let content_length = header.content_length()?;
            let blocks = (content_length + 511) / 512;

            if header.is_whiteout_extension() {
                log::debug!("encountered whiteout extension");
                // read the extension details
                let extensions = Extension::read_from_stream(reader, content_length as usize)?;
                log::trace!("extensions: {extensions:?}");

                for extension in extensions.iter() {
                    if extension.key == *"whiteouts".to_string() {
                        let meta: WhiteoutExtension = serde_json::from_str(&extension.value).unwrap();
                        whiteouts.extend(meta.whiteouts)
                    }
                }
            } else if header.is_extension() {
                log::debug!("skiping pax header and its content ({blocks} blocks)");
                // skip the pax entension records
                seek(reader, &mut buf, blocks)?;
            } else {

                let path = header.file_path()?;
                let filename = path.file_name().unwrap().to_str().unwrap();

                log::debug!("entry is file: {:?}", path.to_string_lossy());

                // OCI layer whiteout files
                if let Some(name) = filename.strip_prefix(".wh.") {
                    if name == ".wh..opq" {
                        whiteouts.push(path.to_string_lossy().to_string());
                    } else {
                        let path = match path.parent() {
                            Some(parent) => parent.join(name),
                            None => std::path::PathBuf::from(name)
                        };

                        whiteouts.push(path.to_string_lossy().to_string());
                    }
                } else {
                    files.push(path.to_string_lossy().to_string());
                }

                log::debug!("skiping file blocks ({blocks} blocks)");
                seek(reader, &mut buf, blocks)?;
            }
        } else if buf == EMPTY_TAR_HEADER {
            log::debug!("encountered empty tar header ({empty_records})");
            empty_records += 1;
            if empty_records == 2 {
                log::trace!("break from list loop");
                break;
            }
        } else {
            return err!("Unknown format")
        }
    }

    Ok(Summary { files, whiteouts })
}

pub fn write_extended_header<W: Write>(writer: &mut W, key: &str, value: &str) -> std::io::Result<usize>
{
    let value = format!("{} {key}={value}", key.len() + value.len() + 1);
    let timestamp = unsafe { libc::time(std::ptr::null_mut()) };
    let mut header = RawTarHeader::empty_ustar();
    header.set_path(Some("PaxHeader".to_string()), "WhiteOuts".to_string()); 
    header.set_mode(0o644);
    header.set_uid_gid();
    header.set_lastmod(timestamp.try_into().unwrap());
    header.set_size(value.len());
    header.tpe = *b"g";
    header.set_checksum();

    writer.write_all(&unsafe {std::mem::transmute::<RawTarHeader, [u8;512]>(header)})?;

    let mut bytes = value.as_bytes();
    let mut buf = [0u8;512];

    // We have already written a block of header
    let mut written = 1;

    while !bytes.is_empty() {
        let length = usize::min(bytes.len(), 512);
        buf[..length].copy_from_slice(&bytes[..length]);
        buf[length..].fill(0);
        writer.write_all(&buf)?;
        bytes = &bytes[length..];
        written += 1;
    }

    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::{Extension, RawTarHeader};

    #[test]
    fn header_set_file_short_path() {
        let mut header = RawTarHeader::empty_ustar();
        header.set_path(Some("PaxHeader".to_string()), "emptyfile".to_string());
        assert!(header.name.starts_with(b"PaxHeader/emptyfile\0"));
    }

    #[test]
    fn header_set_file_long_path() {
        let prefix = "p".repeat(101);
        let name = "file";

        let mut header = RawTarHeader::empty_ustar();
        header.set_path(Some(prefix.to_string()), name.to_string());
        assert!(header.name.starts_with(b"file\0"));
        assert!(header.prefix.starts_with(prefix.as_str().as_bytes()));
    }

    #[test]
    fn test_extension_decode() {
        let mut data = [0u8; 512];
        data[..29].copy_from_slice(b"11 hello=world12 hello=world1");
        let exts = Extension::read_from_stream(&mut data.as_slice(), 29).unwrap();
        assert_eq!(exts, vec![Extension::new("hello".to_string(), "world".to_string()), Extension::new("hello".to_string(), "world1".to_string())])
    }
}
