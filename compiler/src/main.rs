use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process;

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err}");
        process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut args = env::args().skip(1);
    let mut input: Option<PathBuf> = None;
    let mut out: Option<PathBuf> = None;
    let mut stdout = false;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                print_usage();
                return Ok(());
            }
            "--version" | "-V" => {
                println!("weftc {}", env!("CARGO_PKG_VERSION"));
                return Ok(());
            }
            "--stdout" => {
                stdout = true;
            }
            "-o" | "--out" => {
                let value = args
                    .next()
                    .ok_or_else(|| "expected a path after --out".to_string())?;
                out = Some(PathBuf::from(value));
            }
            _ if arg.starts_with('-') => {
                return Err(format!("unknown option: {arg}"));
            }
            _ => {
                if input.is_some() {
                    return Err(format!("unexpected extra positional argument: {arg}"));
                }
                input = Some(PathBuf::from(arg));
            }
        }
    }

    let input = input.ok_or_else(|| "missing input file".to_string())?;
    if stdout && out.is_some() {
        return Err("cannot use --stdout with --out".to_string());
    }

    let source = fs::read_to_string(&input)
        .map_err(|err| format!("failed to read {}: {err}", input.display()))?;
    let output = weftc::compile_weft(&source);

    if stdout {
        print!("{}", output.html);
        return Ok(());
    }

    let out_path = out.unwrap_or_else(|| default_output_path(&input));
    fs::write(&out_path, output.html)
        .map_err(|err| format!("failed to write {}: {err}", out_path.display()))?;

    eprintln!("compiled {} -> {}", input.display(), out_path.display());
    Ok(())
}

fn default_output_path(input: &Path) -> PathBuf {
    let mut out = input.to_path_buf();
    out.set_extension("html");
    out
}

fn print_usage() {
    println!(
        "Weft compiler (Rust)\n\n\
Usage:\n  weftc <input.weft> [-o output.html]\n  weftc <input.weft> --stdout\n\n\
Options:\n  -o, --out <file>   Output path (default: input with .html extension)\n  --stdout           Print compiled HTML to stdout\n  -h, --help         Show this help message\n  -V, --version      Show compiler version"
    );
}
