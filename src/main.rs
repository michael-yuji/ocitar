mod util;
mod tar;

use crate::util::*;
use clap::{Parser, Subcommand};
use std::fs::File;
use std::io::{Read, Write};
use std::process::Command;
use zstd::Encoder;

fn do_extract(args: ExtractArgs) -> Result<(), std::io::Error>
{
    let mut input: Box<dyn Read> = match args.file.as_str() {
        "-" => Box::new(std::io::stdin()),
        path => Box::new(File::open(path)?)
    };

    if let Some(dir) = args.chdir {
        std::env::set_current_dir(dir)?;
    }

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

#[derive(Parser, Debug)]
#[clap(author, version, about)]
struct Args {
    #[clap(short, parse(from_occurrences))]
    verbosity: usize,
    #[clap(subcommand)]
    command: Commands
}

#[derive(Parser, Debug)]
struct CreateArgs
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
struct ListArgs {
    /// path to the tar file, or '-' for stdin
    #[clap(short)]
    file: String,

    /// use if the archive is zstd compressed
    #[clap(long)]
    zstd: bool
}

#[derive(Parser, Debug)]
struct ExtractArgs {

    /// use if the archive is zstd compressed
    #[clap(long)]
    zstd: bool,

    /// change directory to the location before extracting
    #[clap(short = 'C')]
    chdir: Option<String>,

    /// path to the archive file or '-' for stdin
    file: String
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

fn do_list(args: ListArgs) -> Result<(), std::io::Error> {
    let summary = match args.file.as_str() {
        "-" => tar::list_tar(&mut std::io::stdin()),
        path => tar::list_tar(&mut File::open(path)?)
    }?;

    println!("{summary:#?}");
    Ok(())
}

fn do_create(args: CreateArgs) -> Result<(), std::io::Error> {

    let mut output: Box<dyn Write> = match args.file.as_str() {
        "-" => Box::new(std::io::stdout()),
        path => Box::new(File::create(path)?)
    };

    if args.zstd {
        output = Box::new(Encoder::new(output, 3)?.auto_finish());
    }

    create_tar(args.without_oci, args.without_ext, &args.paths, &args.remove, &mut output)
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

