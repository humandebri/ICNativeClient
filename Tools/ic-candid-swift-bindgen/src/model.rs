use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use candid_parser::syntax::Dec;
use candid_parser::types::{FuncMode, Label, Type, TypeInner};
use candid_parser::{check_file, IDLProg, TypeEnv};

use crate::manifest::Manifest;
use crate::resolve_inside;
use crate::swift::{member_identifier, type_identifier};

#[derive(Debug)]
pub struct Program {
    pub canisters: Vec<Canister>,
}

#[derive(Debug)]
pub struct Canister {
    pub name: String,
    pub client_name: String,
    pub canister_id: Option<String>,
    pub definitions: Vec<Definition>,
    pub methods: Vec<Method>,
}

#[derive(Debug, Clone)]
pub struct Definition {
    pub name: String,
    pub kind: DefinitionKind,
    pub recursive: bool,
}

#[derive(Debug, Clone)]
pub enum DefinitionKind {
    Alias(SwiftType),
    Record(Vec<Field>),
    Variant(Vec<Case>),
}

#[derive(Debug, Clone)]
pub struct Field {
    pub label: FieldLabel,
    pub swift_name: String,
    pub ty: SwiftType,
}

#[derive(Debug, Clone)]
pub enum FieldLabel {
    Named(String),
    Numeric(u32),
}

impl FieldLabel {
    pub fn id(&self) -> u32 {
        match self {
            Self::Named(value) => candid_parser::idl_hash(value),
            Self::Numeric(value) => *value,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Case {
    pub label: FieldLabel,
    pub swift_name: String,
    pub payload: Option<SwiftType>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SwiftType {
    Bool,
    Nat,
    Int,
    Nat8,
    Nat16,
    Nat32,
    Nat64,
    Int8,
    Int16,
    Int32,
    Int64,
    Text,
    Blob,
    Principal,
    Null,
    Optional(Box<SwiftType>),
    Vector(Box<SwiftType>),
    Named(String),
}

#[derive(Debug)]
pub struct Method {
    pub candid_name: String,
    pub swift_name: String,
    pub kind: MethodKind,
    pub arguments: Vec<SwiftType>,
    pub returns: Vec<SwiftType>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MethodKind {
    Query,
    Update,
}

impl Program {
    pub fn load(manifest: &Manifest, root: &Path) -> Result<Self> {
        let mut canisters = Vec::with_capacity(manifest.canister.len());
        for entry in &manifest.canister {
            let did = resolve_inside(root, Path::new(&entry.did))?;
            validate_imports(&did, root, &mut BTreeSet::new())?;
            let (env, actor, _) = check_file(&did).with_context(|| {
                format!(
                    "cannot type-check {} for canister {}",
                    did.display(),
                    entry.name
                )
            })?;
            let actor =
                actor.with_context(|| format!("{} does not declare a service", did.display()))?;
            let prefix = type_identifier(&entry.name);
            let mut lowerer = Lowerer::new(&env, &prefix);
            let mut methods = Vec::with_capacity(entry.methods.len());
            let method_symbols = allocate_symbols(
                entry
                    .methods
                    .iter()
                    .map(|name| (member_identifier(name), candid_parser::idl_hash(name))),
                &["client", "canisterId"],
                &format!("canister {} methods", entry.name),
            )?;

            for (method_name, swift_name) in entry.methods.iter().zip(method_symbols) {
                let function = env.get_method(&actor, method_name).with_context(|| {
                    format!("canister {} has no method {method_name}", entry.name)
                })?;
                if function.modes.contains(&FuncMode::Oneway) {
                    anyhow::bail!(
                        "canister {} method {method_name}: oneway methods are unsupported",
                        entry.name
                    );
                }
                let method_type = format!("{}{}", prefix, type_identifier(method_name));
                let mut arguments = Vec::with_capacity(function.args.len());
                for (index, ty) in function.args.iter().enumerate() {
                    let suggested = if function.args.len() == 1 {
                        format!("{method_type}Args")
                    } else {
                        format!("{method_type}Argument{}", index + 1)
                    };
                    arguments.push(lowerer.lower_type(ty, &suggested)?);
                }
                let mut returns = Vec::with_capacity(function.rets.len());
                for (index, ty) in function.rets.iter().enumerate() {
                    let suggested = if function.rets.len() == 1 {
                        format!("{method_type}Result")
                    } else {
                        format!("{method_type}ResultValue{}", index + 1)
                    };
                    returns.push(lowerer.lower_type(ty, &suggested)?);
                }
                methods.push(Method {
                    candid_name: method_name.clone(),
                    swift_name,
                    kind: if function.is_query() {
                        MethodKind::Query
                    } else {
                        MethodKind::Update
                    },
                    arguments,
                    returns,
                });
            }

            lowerer.validate_recursion()?;
            let definitions = lowerer.finish();
            canisters.push(Canister {
                client_name: format!("{prefix}Canister"),
                name: prefix,
                canister_id: entry.canister_id.clone(),
                definitions,
                methods,
            });
        }
        validate_global_names(&canisters)?;
        Ok(Self { canisters })
    }
}

fn validate_global_names(canisters: &[Canister]) -> Result<()> {
    let mut names: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for canister in canisters {
        for definition in &canister.definitions {
            names
                .entry(definition.name.clone())
                .or_default()
                .push(format!("canister {} Candid type", canister.name));
        }
        names
            .entry(canister.client_name.clone())
            .or_default()
            .push(format!("canister {} client", canister.name));
        for method in &canister.methods {
            let base = format!("{}{}", canister.name, type_identifier(&method.candid_name));
            if method.arguments.len() > 1 {
                names
                    .entry(format!("{base}Arguments"))
                    .or_default()
                    .push(format!(
                        "canister {} method {} arguments",
                        canister.name, method.candid_name
                    ));
            }
            if method.returns.len() > 1 {
                names
                    .entry(format!("{base}Result"))
                    .or_default()
                    .push(format!(
                        "canister {} method {} result",
                        canister.name, method.candid_name
                    ));
            }
        }
    }
    let collisions: Vec<String> = names
        .into_iter()
        .filter(|(_, origins)| origins.len() > 1)
        .map(|(name, origins)| format!("{name}: {}", origins.join(", ")))
        .collect();
    if !collisions.is_empty() {
        anyhow::bail!(
            "generated top-level Swift type names collide:\n{}",
            collisions.join("\n")
        );
    }
    Ok(())
}

fn allocate_symbols(
    entries: impl IntoIterator<Item = (String, u32)>,
    reserved: &[&str],
    context: &str,
) -> Result<Vec<String>> {
    let entries: Vec<(String, u32)> = entries.into_iter().collect();
    let mut counts = BTreeMap::new();
    for (base, _) in &entries {
        *counts.entry(base.clone()).or_insert(0usize) += 1;
    }
    let reserved: BTreeSet<&str> = reserved.iter().copied().collect();
    let mut used = BTreeSet::new();
    let mut result = Vec::with_capacity(entries.len());
    for (base, field_id) in entries {
        let candidate = if reserved.contains(base.as_str()) || counts[&base] > 1 {
            format!("{base}_{field_id}")
        } else {
            base
        };
        if !used.insert(candidate.clone()) {
            anyhow::bail!("{context} cannot allocate unique Swift identifier {candidate}");
        }
        result.push(candidate);
    }
    Ok(result)
}

fn validate_imports(path: &Path, root: &Path, visited: &mut BTreeSet<PathBuf>) -> Result<()> {
    let canonical = path
        .canonicalize()
        .with_context(|| format!("cannot resolve Candid file {}", path.display()))?;
    if !canonical.starts_with(root) {
        anyhow::bail!(
            "Candid import {} resolves outside project root {}",
            path.display(),
            root.display()
        );
    }
    if !visited.insert(canonical.clone()) {
        return Ok(());
    }
    let source = fs::read_to_string(&canonical)
        .with_context(|| format!("cannot read Candid file {}", canonical.display()))?;
    let program: IDLProg = source
        .parse()
        .with_context(|| format!("cannot parse Candid file {}", canonical.display()))?;
    let directory = canonical.parent().unwrap_or(root);
    for declaration in program.decs {
        let import = match declaration {
            Dec::ImportType(path) | Dec::ImportServ(path) => path,
            Dec::TypD(_) => continue,
        };
        validate_imports(&directory.join(import), root, visited)?;
    }
    Ok(())
}

struct Lowerer<'a> {
    env: &'a TypeEnv,
    prefix: &'a str,
    definitions: BTreeMap<String, Definition>,
    processing: BTreeSet<String>,
    named_origins: BTreeMap<String, String>,
}

impl<'a> Lowerer<'a> {
    fn new(env: &'a TypeEnv, prefix: &'a str) -> Self {
        Self {
            env,
            prefix,
            definitions: BTreeMap::new(),
            processing: BTreeSet::new(),
            named_origins: BTreeMap::new(),
        }
    }

    fn finish(self) -> Vec<Definition> {
        self.definitions.into_values().collect()
    }

    fn lower_type(&mut self, ty: &Type, suggested_name: &str) -> Result<SwiftType> {
        match ty.as_ref() {
            TypeInner::Null => Ok(SwiftType::Null),
            TypeInner::Bool => Ok(SwiftType::Bool),
            TypeInner::Nat => Ok(SwiftType::Nat),
            TypeInner::Int => Ok(SwiftType::Int),
            TypeInner::Nat8 => Ok(SwiftType::Nat8),
            TypeInner::Nat16 => Ok(SwiftType::Nat16),
            TypeInner::Nat32 => Ok(SwiftType::Nat32),
            TypeInner::Nat64 => Ok(SwiftType::Nat64),
            TypeInner::Int8 => Ok(SwiftType::Int8),
            TypeInner::Int16 => Ok(SwiftType::Int16),
            TypeInner::Int32 => Ok(SwiftType::Int32),
            TypeInner::Int64 => Ok(SwiftType::Int64),
            TypeInner::Text => Ok(SwiftType::Text),
            TypeInner::Principal => Ok(SwiftType::Principal),
            TypeInner::Opt(child) => Ok(SwiftType::Optional(Box::new(
                self.lower_type(child, &format!("{suggested_name}Value"))?,
            ))),
            TypeInner::Vec(child) if matches!(child.as_ref(), TypeInner::Nat8) => {
                Ok(SwiftType::Blob)
            }
            TypeInner::Vec(child) => Ok(SwiftType::Vector(Box::new(
                self.lower_type(child, &format!("{suggested_name}Element"))?,
            ))),
            TypeInner::Var(name) => self.lower_named(name),
            TypeInner::Record(fields) => {
                let name = self.unique_type_name(suggested_name)?;
                let fields = self.lower_fields(fields, &name)?;
                self.definitions.insert(
                    name.clone(),
                    Definition {
                        name: name.clone(),
                        kind: DefinitionKind::Record(fields),
                        recursive: false,
                    },
                );
                Ok(SwiftType::Named(name))
            }
            TypeInner::Variant(fields) => {
                let name = self.unique_type_name(suggested_name)?;
                let cases = self.lower_cases(fields, &name)?;
                self.definitions.insert(
                    name.clone(),
                    Definition {
                        name: name.clone(),
                        kind: DefinitionKind::Variant(cases),
                        recursive: false,
                    },
                );
                Ok(SwiftType::Named(name))
            }
            TypeInner::Float32 => {
                anyhow::bail!("{suggested_name}: float32 is unsupported in bindgen 0.1.0")
            }
            TypeInner::Float64 => {
                anyhow::bail!("{suggested_name}: float64 is unsupported in bindgen 0.1.0")
            }
            TypeInner::Reserved => {
                anyhow::bail!("{suggested_name}: reserved is unsupported in bindgen 0.1.0")
            }
            TypeInner::Empty => {
                anyhow::bail!("{suggested_name}: empty is unsupported in bindgen 0.1.0")
            }
            TypeInner::Func(_) => {
                anyhow::bail!("{suggested_name}: func values are unsupported in bindgen 0.1.0")
            }
            TypeInner::Service(_) | TypeInner::Class(_, _) => {
                anyhow::bail!("{suggested_name}: service values are unsupported in bindgen 0.1.0")
            }
            TypeInner::Knot(_) => {
                anyhow::bail!("{suggested_name}: Rust-internal recursive knots are unsupported")
            }
            TypeInner::Unknown | TypeInner::Future => {
                anyhow::bail!("{suggested_name}: unresolved Candid type is unsupported")
            }
        }
    }

    fn lower_named(&mut self, candid_name: &str) -> Result<SwiftType> {
        let name = format!("{}{}", self.prefix, type_identifier(candid_name));
        if let Some(existing) = self.named_origins.get(&name) {
            if existing != candid_name {
                anyhow::bail!(
                    "named Candid types {existing} and {candid_name} collide as Swift type {name}"
                );
            }
        } else if self.definitions.contains_key(&name) || self.processing.contains(&name) {
            anyhow::bail!(
                "named Candid type {candid_name} collides with generated Swift type {name}"
            );
        } else {
            self.named_origins
                .insert(name.clone(), candid_name.to_owned());
        }
        if self.definitions.contains_key(&name) || self.processing.contains(&name) {
            return Ok(SwiftType::Named(name));
        }
        self.processing.insert(name.clone());
        let raw = self
            .env
            .find_type(candid_name)
            .with_context(|| format!("cannot resolve named type {candid_name}"))?
            .clone();
        let kind = match raw.as_ref() {
            TypeInner::Record(fields) => DefinitionKind::Record(self.lower_fields(fields, &name)?),
            TypeInner::Variant(fields) => DefinitionKind::Variant(self.lower_cases(fields, &name)?),
            _ => DefinitionKind::Alias(self.lower_type(&raw, &format!("{name}Value"))?),
        };
        self.processing.remove(&name);
        let recursive = kind.references(&name);
        if recursive && matches!(kind, DefinitionKind::Alias(_)) {
            anyhow::bail!("named recursive alias {candid_name} is unsupported");
        }
        self.definitions.insert(
            name.clone(),
            Definition {
                name: name.clone(),
                kind,
                recursive,
            },
        );
        Ok(SwiftType::Named(name))
    }

    fn lower_fields(
        &mut self,
        fields: &[candid_parser::types::Field],
        owner: &str,
    ) -> Result<Vec<Field>> {
        let symbols = allocate_symbols(
            fields.iter().map(|field| {
                let label = field_label(field.id.as_ref());
                (label.swift_member(), label.id())
            }),
            &["candidType", "candidValue", "fields"],
            &format!("record {owner} fields"),
        )?;
        let mut result = Vec::with_capacity(fields.len());
        for (field, swift_name) in fields.iter().zip(symbols) {
            let label = field_label(field.id.as_ref());
            let child_name = format!("{}{}", owner, type_identifier(&swift_name));
            result.push(Field {
                label,
                swift_name,
                ty: self.lower_type(&field.ty, &child_name)?,
            });
        }
        result.sort_by_key(|field| field.label.id());
        Ok(result)
    }

    fn lower_cases(
        &mut self,
        fields: &[candid_parser::types::Field],
        owner: &str,
    ) -> Result<Vec<Case>> {
        let symbols = allocate_symbols(
            fields.iter().map(|field| {
                let label = field_label(field.id.as_ref());
                (label.swift_member(), label.id())
            }),
            &["candidType", "candidValue", "fields"],
            &format!("variant {owner} cases"),
        )?;
        let mut result = Vec::with_capacity(fields.len());
        for (field, swift_name) in fields.iter().zip(symbols) {
            let label = field_label(field.id.as_ref());
            let payload = if matches!(field.ty.as_ref(), TypeInner::Null) {
                None
            } else {
                Some(self.lower_type(
                    &field.ty,
                    &format!("{}{}", owner, type_identifier(&swift_name)),
                )?)
            };
            result.push(Case {
                label,
                swift_name,
                payload,
            });
        }
        result.sort_by_key(|case| case.label.id());
        Ok(result)
    }

    fn unique_type_name(&self, suggested: &str) -> Result<String> {
        let name = type_identifier(suggested);
        if self.definitions.contains_key(&name) || self.processing.contains(&name) {
            anyhow::bail!("anonymous Candid types collide as Swift type {name}");
        }
        Ok(name)
    }

    fn validate_recursion(&self) -> Result<()> {
        for definition in self.definitions.values() {
            let mut reachable = BTreeSet::new();
            definition.kind.collect_references(&mut reachable);
            for dependency in reachable {
                if dependency == definition.name {
                    continue;
                }
                if self.reaches(&dependency, &definition.name, &mut BTreeSet::new()) {
                    anyhow::bail!(
                        "mutually recursive types {} and {} are unsupported in bindgen 0.1.0",
                        definition.name,
                        dependency
                    );
                }
            }
        }
        Ok(())
    }

    fn reaches(&self, from: &str, target: &str, visited: &mut BTreeSet<String>) -> bool {
        if !visited.insert(from.to_owned()) {
            return false;
        }
        let Some(definition) = self.definitions.get(from) else {
            return false;
        };
        let mut dependencies = BTreeSet::new();
        definition.kind.collect_references(&mut dependencies);
        dependencies.contains(target)
            || dependencies
                .into_iter()
                .any(|next| self.reaches(&next, target, visited))
    }
}

impl DefinitionKind {
    fn references(&self, name: &str) -> bool {
        let mut references = BTreeSet::new();
        self.collect_references(&mut references);
        references.contains(name)
    }

    fn collect_references(&self, result: &mut BTreeSet<String>) {
        match self {
            Self::Alias(ty) => ty.collect_references(result),
            Self::Record(fields) => fields
                .iter()
                .for_each(|field| field.ty.collect_references(result)),
            Self::Variant(cases) => cases
                .iter()
                .filter_map(|case| case.payload.as_ref())
                .for_each(|ty| ty.collect_references(result)),
        }
    }
}

impl SwiftType {
    fn collect_references(&self, result: &mut BTreeSet<String>) {
        match self {
            Self::Optional(child) | Self::Vector(child) => child.collect_references(result),
            Self::Named(name) => {
                result.insert(name.clone());
            }
            _ => {}
        }
    }
}

impl FieldLabel {
    pub fn swift_member(&self) -> String {
        match self {
            Self::Named(value) => member_identifier(value),
            Self::Numeric(value) => format!("field{value}"),
        }
    }
}

fn field_label(label: &Label) -> FieldLabel {
    match label {
        Label::Named(value) => FieldLabel::Named(value.clone()),
        Label::Id(value) | Label::Unnamed(value) => FieldLabel::Numeric(*value),
    }
}
