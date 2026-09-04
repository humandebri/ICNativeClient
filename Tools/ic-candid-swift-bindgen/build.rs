use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

fn main() {
    let crate_directory = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let mut files = vec![
        crate_directory.join("Cargo.toml"),
        crate_directory.join("Cargo.lock"),
        crate_directory.join("build.rs"),
        crate_directory.join("scripts/build-artifact-bundle.sh"),
    ];
    collect_rust_sources(&crate_directory.join("src"), &mut files);
    files.sort();

    let mut hasher = Sha256::new();
    for path in files {
        println!("cargo:rerun-if-changed={}", path.display());
        let relative = path.strip_prefix(&crate_directory).unwrap();
        let contents = fs::read(&path)
            .unwrap_or_else(|error| panic!("cannot read source input {}: {error}", path.display()));
        hasher.update(relative.as_os_str().as_encoded_bytes());
        hasher.update([0]);
        hasher.update((contents.len() as u64).to_le_bytes());
        hasher.update(contents);
    }
    println!(
        "cargo:rustc-env=IC_BINDGEN_SOURCE_HASH={:x}",
        hasher.finalize()
    );
}

fn collect_rust_sources(directory: &Path, files: &mut Vec<PathBuf>) {
    let mut entries: Vec<_> = fs::read_dir(directory)
        .unwrap_or_else(|error| {
            panic!(
                "cannot read source directory {}: {error}",
                directory.display()
            )
        })
        .map(|entry| entry.unwrap().path())
        .collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            collect_rust_sources(&path, files);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            files.push(path);
        }
    }
}
