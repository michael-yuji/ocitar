mod util;
mod tar;

use clap::{Parser, Subcommand};
use crate::util::*;
use std::fs::File;
use std::io::{Read, Write};
use std::process::Command;
use zstd::{Decoder, Encoder};

const ZSTD_MAGIC: [u8;4] = [0x28, 0xb5, 0x2f, 0xfd];

#[derive(Parser, Debug)]
#[clap(author, version, about)]
struct Args {
    #[clap(short, parse(from_occurrences))]
    verbosity: usize,
    #[clap(subcommand)]
    command: Commands
}


#[derive(Subcommand, Debug)]
enum Commands {
    #[clap(short_flag = 'c')]
    Create(CreateArgs),
    #[clap(short_flag = 't')]
    List(ListArgs),
    #[clap(short_flag = 'x')]
    Extract(ExtractArgs)
}

#[derive(Parser, Debug)]
pub struct CreateArgs
{
    /// path to the output file, or '-' for stdout
    #[clap(short = 'f', long)]
    file: String,

    /// paths to whiteout from the parent layers
    #[clap(long, multiple_occurrences = true)]
    remove: Vec<String>,

    /// paths to include in the layer archive
    #[clap(multiple = true)]
    paths: Vec<String>,

    /// create ZStandard compressed tar archive
    #[clap(long)]
    zstd: bool,

    /// Do not create OCI whiteout files. Use this program's custom tar extension only
    #[clap(long = "no-oci")]
    without_oci: bool,

    /// Do not include this program's custom tar extension to the archive
    #[clap(long = "no-ext")]
    without_ext: bool
}

#[derive(Parser, Debug)]
pub struct ListArgs {
    /// path to the tar file, or '-' for stdin
    #[clap(short)]
    file: String,

    /// use if the archive is zstd compressed
    #[clap(long)]
    zstd: bool
}

#[derive(Parser, Debug)]
pub struct ExtractArgs {

    /// use if the archive is zstd compressed
    #[clap(long)]
    zstd: bool,

    /// change directory to the location before extracting
    #[clap(short = 'C')]
    chdir: Option<String>,

    #[clap(short)]
    /// path to the archive file or '-' for stdin
    file: String
}

pub fn do_list(args: ListArgs) -> Result<(), std::io::Error>
{
    let mut input: Box<dyn Read> = match args.file.as_str() {
        "-" => Box::new(std::io::stdin()),
        path => Box::new(File::open(path)?)
    };

    if args.zstd {
        input = Box::new(Decoder::new(input)?);
    } else {
        let mut check_magic = [0u8; 4];
        input.read_exact(&mut check_magic)?;
        if check_magic == ZSTD_MAGIC {
            input = Box::new(Decoder::new(PrebufferedSource::new(&check_magic, input))?);
        } else {
            input = Box::new(PrebufferedSource::new(&check_magic, input));
        }
    }

    let summary = tar::list_tar(&mut input)?;

    for whiteout in summary.whiteouts.iter() {
        println!("-\t{whiteout}");
    }

    for file in summary.files.iter() {
        println!("+\t{file}");
    }

    Ok(())
}

pub fn do_create(args: CreateArgs) -> Result<(), std::io::Error> {

    let mut output: Box<dyn Write> = match args.file.as_str() {
        "-" => Box::new(std::io::stdout()),
        path => Box::new(File::create(path)?)
    };

    if args.zstd {
        output = Box::new(Encoder::new(output, 3)?.auto_finish());
    }

    create_tar(args.without_oci, args.without_ext, &args.paths, &args.remove, &mut output)
}

pub fn do_extract(args: ExtractArgs) -> Result<(), std::io::Error>
{
    let mut input: Box<dyn Read> = match args.file.as_str() {
        "-" => Box::new(std::io::stdin()),
        path => Box::new(File::open(path)?)
    };

    if args.zstd {
        input = Box::new(Decoder::new(input)?);
    } else {
        let mut check_magic = [0u8; 4];
        input.read_exact(&mut check_magic)?;
        if check_magic == ZSTD_MAGIC {
            input = Box::new(Decoder::new(PrebufferedSource::new(&check_magic, input))?);
        } else {
            input = Box::new(PrebufferedSource::new(&check_magic, input));
        }
    }

    if let Some(dir) = args.chdir {
        std::env::set_current_dir(dir)?;
    }
println!("148");
    extract(&mut input)
}

fn extract<R: Read>(reader: &mut R) -> Result<(), std::io::Error>
{
    let mut child = Command::new("tar").arg("-xf-").stdin(std::process::Stdio::piped())
        .spawn()?;

    let tar_stdin = child.stdin.as_mut().unwrap();

    tar::tap_extract_tar(reader, tar_stdin)?;

    match child.wait()?.code() {
        Some(ec) if ec != 0 => {
            err!("tar return non-zero exit code")
        },
        _ => Ok(())
    }
}

fn create_tar<W: Write>(
    without_oci: bool, without_ext: bool, 
    paths: &[String], whiteouts: &[String], output: &mut W) -> Result<(), std::io::Error>
{
    let mut child = Command::new("tar").arg("-cf-").args(paths)
        .stdout(std::process::Stdio::piped())
        .spawn()?;
    let tar_stdout = child.stdout.as_mut().unwrap();

    tar::tap_create_tar(without_oci, without_ext, whiteouts, tar_stdout, output)?;

    match child.wait()?.code() {
        Some(code) if code != 0 => {
            err!("tar returns non-zero exit code")
        },
        _ => Ok(())
    }
}


fn main() -> Result<(), std::io::Error> {
    // to not ignore SIGPIPE so cli can run properly when piped
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }

    let args = Args::parse();

    // setup logging facility
    stderrlog::new().module(module_path!()).verbosity(args.verbosity).init().unwrap();


    log::debug!("main args: {args:?}");

    match args.command {
        Commands::Create(c) => do_create(c)?,
        Commands::List(c)   => do_list(c)?,
        Commands::Extract(c) => do_extract(c)?
    };
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    #[test]
    #[serial]
    fn test_extract_auto_zstd() {
        let current_dir = std::env::current_dir().unwrap();
        _ = std::fs::remove_dir_all("test-materials/stagez");

        let result = std::panic::catch_unwind(|| {
            println!("{}", std::env::current_dir().unwrap().to_string_lossy());
            std::process::Command::new("cp").arg("-r")
                .arg("test-materials/stage_template")
                .arg("test-materials/stagez")
                .output().unwrap();
            let extract_arg = ExtractArgs { chdir: Some("test-materials/stagez".to_string())
                                          , file: "test-materials/base.tar.zst".to_string()
                                          , zstd: false };
            do_extract(extract_arg).unwrap();

            let output = std::process::Command::new("diff").arg("-r")
                .arg("../stagez")
                .arg("../stage-expected").output().unwrap();
            println!("stdout: {:?}", std::str::from_utf8(&output.stdout));
            println!("stderr: {:?}", std::str::from_utf8(&output.stderr));

            assert!(output.stdout.is_empty());
            assert!(output.stderr.is_empty());
        });

        _ = std::env::set_current_dir(current_dir);
        _ = std::fs::remove_dir_all("test-materials/stagez");
        assert!(result.is_ok())
    }

    #[test]
    #[serial]
    fn test_extract() {
        let current_dir = std::env::current_dir().unwrap();
        _ = std::fs::remove_dir_all("test-materials/stage");

        let result = std::panic::catch_unwind(|| {
            println!("{}", std::env::current_dir().unwrap().to_string_lossy());
            std::process::Command::new("cp").arg("-r")
                .arg("test-materials/stage_template")
                .arg("test-materials/stage")
                .output().unwrap();
            let extract_arg = ExtractArgs { chdir: Some("test-materials/stage".to_string())
                                          , file: "test-materials/base.tar".to_string()
                                          , zstd: false };
            do_extract(extract_arg).unwrap();

            let output = std::process::Command::new("diff").arg("-r")
                .arg("../stage")
                .arg("../stage-expected").output().unwrap();
            println!("stdout: {:?}", std::str::from_utf8(&output.stdout));
            println!("stderr: {:?}", std::str::from_utf8(&output.stderr));

            assert!(output.stdout.is_empty());
            assert!(output.stderr.is_empty());
        });

        _ = std::env::set_current_dir(current_dir);
        _ = std::fs::remove_dir_all("test-materials/stage");
        assert!(result.is_ok())
    }
}

