mod manifest;
mod model;
mod swift;

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

pub use manifest::{CanisterManifest, Manifest};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const SOURCE_HASH: &str = env!("IC_BINDGEN_SOURCE_HASH");

pub fn build_info() -> String {
    format!("version={VERSION}\nsource_hash={SOURCE_HASH}")
}

pub fn generate(manifest_path: &Path, project_root: &Path) -> Result<String> {
    let root = canonical_directory(project_root).context("invalid project root")?;
    let manifest_path = resolve_inside(&root, manifest_path).context("invalid manifest path")?;
    let manifest = Manifest::load(&manifest_path)?;
    let program = model::Program::load(&manifest, &root)?;
    swift::render(&program)
}

pub fn generate_to_file(manifest_path: &Path, output: &Path, project_root: &Path) -> Result<()> {
    let source = generate(manifest_path, project_root)?;
    if fs::read_to_string(output).ok().as_deref() == Some(source.as_str()) {
        return Ok(());
    }
    let parent = output.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)
        .with_context(|| format!("failed to create output directory {}", parent.display()))?;
    let temporary = temporary_path(output);
    fs::write(&temporary, source)
        .with_context(|| format!("failed to write temporary output {}", temporary.display()))?;
    if let Err(error) = fs::rename(&temporary, output) {
        let _ = fs::remove_file(&temporary);
        return Err(error)
            .with_context(|| format!("failed to replace output {}", output.display()));
    }
    Ok(())
}

fn canonical_directory(path: &Path) -> Result<PathBuf> {
    path.canonicalize()
        .with_context(|| format!("cannot resolve {}", path.display()))
}

pub(crate) fn resolve_inside(root: &Path, path: &Path) -> Result<PathBuf> {
    let candidate = if path.is_absolute() {
        path.to_path_buf()
    } else {
        root.join(path)
    };
    let resolved = candidate
        .canonicalize()
        .with_context(|| format!("cannot resolve {}", candidate.display()))?;
    if !resolved.starts_with(root) {
        anyhow::bail!(
            "{} resolves outside project root {}",
            path.display(),
            root.display()
        );
    }
    Ok(resolved)
}

fn temporary_path(output: &Path) -> PathBuf {
    let mut name = output.file_name().unwrap_or_default().to_os_string();
    name.push(format!(".tmp.{}", std::process::id()));
    output.with_file_name(name)
}
