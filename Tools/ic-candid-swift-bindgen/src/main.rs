use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;

#[derive(Parser)]
#[command(version, about)]
struct Arguments {
    #[arg(long)]
    build_info: bool,
    #[arg(long, required_unless_present = "build_info")]
    manifest: Option<PathBuf>,
    #[arg(long, required_unless_present = "build_info")]
    output: Option<PathBuf>,
    #[arg(long, default_value = ".")]
    project_root: PathBuf,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let arguments = Arguments::parse();
    if arguments.build_info {
        println!("{}", ic_candid_swift_bindgen::build_info());
        return Ok(());
    }
    ic_candid_swift_bindgen::generate_to_file(
        arguments.manifest.as_deref().unwrap(),
        arguments.output.as_deref().unwrap(),
        &arguments.project_root,
    )
}
