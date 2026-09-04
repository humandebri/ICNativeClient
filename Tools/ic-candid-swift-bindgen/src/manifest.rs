use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use candid_parser::Principal;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub canister: Vec<CanisterManifest>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanisterManifest {
    pub name: String,
    pub did: String,
    pub canister_id: Option<String>,
    pub methods: Vec<String>,
}

impl Manifest {
    pub fn load(path: &Path) -> Result<Self> {
        let contents = fs::read_to_string(path)
            .with_context(|| format!("cannot read manifest {}", path.display()))?;
        let manifest: Self = toml::from_str(&contents)
            .with_context(|| format!("cannot parse manifest {}", path.display()))?;
        manifest.validate()?;
        Ok(manifest)
    }

    fn validate(&self) -> Result<()> {
        if self.canister.is_empty() {
            anyhow::bail!("manifest must contain at least one [[canister]] entry");
        }
        let mut names = std::collections::BTreeSet::new();
        let mut swift_names = std::collections::BTreeSet::new();
        for canister in &self.canister {
            if canister.name.trim().is_empty() {
                anyhow::bail!("canister name must not be empty");
            }
            if canister.did.trim().is_empty() {
                anyhow::bail!("canister {} has an empty did path", canister.name);
            }
            if canister.methods.is_empty() {
                anyhow::bail!("canister {} must select at least one method", canister.name);
            }
            if !names.insert(&canister.name) {
                anyhow::bail!("duplicate canister name {}", canister.name);
            }
            let swift_name = crate::swift::type_identifier(&canister.name);
            if !swift_names.insert(swift_name.clone()) {
                anyhow::bail!("canister names collide as Swift identifier {swift_name}");
            }
            let mut methods = std::collections::BTreeSet::new();
            for method in &canister.methods {
                if !methods.insert(method) {
                    anyhow::bail!(
                        "canister {} selects method {} more than once",
                        canister.name,
                        method
                    );
                }
            }
            if let Some(id) = &canister.canister_id {
                Principal::from_text(id).with_context(|| {
                    format!("canister {} has invalid canister_id {id}", canister.name)
                })?;
            }
        }
        Ok(())
    }
}
