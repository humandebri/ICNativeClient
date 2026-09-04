use std::fs;
use std::path::{Path, PathBuf};

use ic_candid_swift_bindgen::generate;

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
fn generates_selected_typed_bindings_deterministically() {
    let root = repository_root();
    let manifest = root.join("Tools/ic-candid-swift-bindgen/tests/fixtures/bindings.toml");
    let first = generate(&manifest, &root).unwrap();
    let second = generate(&manifest, &root).unwrap();

    assert_eq!(first.as_bytes(), second.as_bytes());
    assert!(first.contains("public struct LedgerTokens: CandidConvertible"));
    assert!(first.contains("public final class LedgerNode: CandidConvertible"));
    assert!(first.contains("public func accountBalance("));
    assert!(first.contains("public func transfer("));
    assert!(first.contains("effectiveCanisterId: String? = nil"));
    assert!(first.contains("identity: ICAuthSession? = nil, effectiveCanisterId: String? = nil"));
    assert!(first.contains("queryCandid(\n            method: \"account_balance\","));
    assert!(first.contains("effectiveCanisterId: effectiveCanisterId"));
    assert!(first.contains("public struct LedgerStatusResult: Sendable"));
    assert!(first.contains("public let field0: UInt64"));
    assert!(first.contains("public let field7: String"));
    assert!(first.contains("enum _ICBindgenSupport"));
    assert!(first.contains("LedgerCanister._ICBindgenSupport.decode"));
    assert!(!first.contains("\nfunc _icBindgenDecode"));
    assert!(!first.contains("func ignored("));
}

#[test]
fn reachable_field_addition_changes_output() {
    let temporary = tempfile::tempdir().unwrap();
    let manifest =
        "[[canister]]\nname = \"Example\"\ndid = \"service.did\"\nmethods = [\"read\"]\n";
    fs::write(temporary.path().join("bindings.toml"), manifest).unwrap();
    fs::write(
        temporary.path().join("service.did"),
        "type Item = record { id : nat64 }; service : { read : () -> (Item) query };",
    )
    .unwrap();
    let first = generate(&temporary.path().join("bindings.toml"), temporary.path()).unwrap();
    fs::write(
        temporary.path().join("service.did"),
        "type Item = record { id : nat64; label : text }; service : { read : () -> (Item) query };",
    )
    .unwrap();
    let second = generate(&temporary.path().join("bindings.toml"), temporary.path()).unwrap();

    assert_ne!(first.as_bytes(), second.as_bytes());
    assert!(second.contains("public let label: String"));
}

#[test]
fn rejects_unsupported_types_without_writing_output() {
    let temporary = tempfile::tempdir().unwrap();
    fs::write(
        temporary.path().join("unsupported.did"),
        "service : { unsupported : (float64) -> (); };",
    )
    .unwrap();
    fs::write(
        temporary.path().join("bindings.toml"),
        "[[canister]]\nname = \"Other\"\ndid = \"unsupported.did\"\nmethods = [\"unsupported\"]\n",
    )
    .unwrap();

    let error = generate(&temporary.path().join("bindings.toml"), temporary.path()).unwrap_err();
    assert!(format!("{error:#}").contains("float64 is unsupported"));
}

#[test]
fn rejects_swift_identifier_collisions() {
    let temporary = tempfile::tempdir().unwrap();
    fs::write(
        temporary.path().join("collision.did"),
        "type foo_bar = record { first : nat64 }; type FooBar = record { second : text }; service : { one : () -> (foo_bar) query; two : () -> (FooBar) query };",
    )
    .unwrap();
    fs::write(
        temporary.path().join("bindings.toml"),
        "[[canister]]\nname = \"Collision\"\ndid = \"collision.did\"\nmethods = [\"one\", \"two\"]\n",
    )
    .unwrap();

    let error = generate(&temporary.path().join("bindings.toml"), temporary.path()).unwrap_err();
    assert!(format!("{error:#}").contains("collide as Swift type"));
}

#[test]
fn deterministically_renames_reserved_and_colliding_members() {
    let temporary = tempfile::tempdir().unwrap();
    fs::write(
        temporary.path().join("reserved.did"),
        "type Item = record { candid_value : text; foo_bar : nat64; fooBar : nat64 }; service : { client : () -> (); canister_id : (Item) -> (Item) query };",
    )
    .unwrap();
    fs::write(
        temporary.path().join("bindings.toml"),
        "[[canister]]\nname = \"Reserved\"\ndid = \"reserved.did\"\nmethods = [\"client\", \"canister_id\"]\n",
    )
    .unwrap();

    let generated = generate(&temporary.path().join("bindings.toml"), temporary.path()).unwrap();
    let candid_value = candid_parser::idl_hash("candid_value");
    let foo_bar = candid_parser::idl_hash("foo_bar");
    let foo_bar_camel = candid_parser::idl_hash("fooBar");
    let client = candid_parser::idl_hash("client");
    let canister_id = candid_parser::idl_hash("canister_id");

    assert!(generated.contains(&format!("public let candidValue_{candid_value}: String")));
    assert!(generated.contains(&format!("public let fooBar_{foo_bar}: UInt64")));
    assert!(generated.contains(&format!("public let fooBar_{foo_bar_camel}: UInt64")));
    assert!(generated.contains(&format!("public func client_{client}(")));
    assert!(generated.contains(&format!("public func canisterId_{canister_id}(")));
    assert!(generated.contains("method: \"client\""));
    assert!(generated.contains("method: \"canister_id\""));
    assert!(generated.contains(&format!(
        "{candid_value}: self.candidValue_{candid_value}.candidValue"
    )));
}

#[test]
fn escapes_only_the_completed_canister_client_name() {
    let temporary = tempfile::tempdir().unwrap();
    fs::write(
        temporary.path().join("service.did"),
        "service : { read : () -> (nat64) query };",
    )
    .unwrap();
    fs::write(
        temporary.path().join("bindings.toml"),
        "[[canister]]\nname = \"Self\"\ndid = \"service.did\"\nmethods = [\"read\"]\n",
    )
    .unwrap();

    let generated = generate(&temporary.path().join("bindings.toml"), temporary.path()).unwrap();

    assert!(generated.contains("public struct SelfCanister: Sendable"));
    assert!(generated.contains("SelfCanister._ICBindgenSupport.decode"));
    assert!(!generated.contains("`Self`Canister"));
}

#[test]
fn rejects_top_level_collisions_across_canisters_with_origins() {
    let scenarios = [
        (
            "type BarCanister = record { value : nat64 }; service : { read : () -> (BarCanister) query };",
            "service : { read : () -> (nat64) query };",
            "Foo",
            "FooBar",
            "FooBarCanister",
        ),
        (
            "type BarBaz = record { value : nat64 }; service : { read : () -> (BarBaz) query };",
            "type Baz = record { value : text }; service : { read : () -> (Baz) query };",
            "Foo",
            "FooBar",
            "FooBarBaz",
        ),
        (
            "service : { bar : (nat64, text) -> () query };",
            "type Arguments = record { value : nat64 }; service : { read : () -> (Arguments) query };",
            "Foo",
            "FooBar",
            "FooBarArguments",
        ),
    ];

    for (index, (first_did, second_did, first_name, second_name, collision)) in
        scenarios.into_iter().enumerate()
    {
        let temporary = tempfile::tempdir().unwrap();
        fs::write(temporary.path().join("first.did"), first_did).unwrap();
        fs::write(temporary.path().join("second.did"), second_did).unwrap();
        let first_method = if index == 2 { "bar" } else { "read" };
        fs::write(
            temporary.path().join("bindings.toml"),
            format!(
                "[[canister]]\nname = \"{first_name}\"\ndid = \"first.did\"\nmethods = [\"{first_method}\"]\n\n[[canister]]\nname = \"{second_name}\"\ndid = \"second.did\"\nmethods = [\"read\"]\n"
            ),
        )
        .unwrap();

        let error =
            generate(&temporary.path().join("bindings.toml"), temporary.path()).unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("generated top-level Swift type names collide"));
        assert!(message.contains(collision));
        assert!(message.contains(first_name));
        assert!(message.contains(second_name));
    }
}
