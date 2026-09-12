//! WBS-802: JNI contract parity test.
//!
//! The JNI contract has exactly one source of truth per side:
//! - Kotlin:  `external fun` declarations in `com.sentinelpass.VaultBridge`
//!   (android/SentinelPass/app/src/main/java/com/sentinelpass/VaultBridge.kt)
//! - Rust:    `Java_com_sentinelpass_VaultBridge_<name>` exports in
//!   sentinelpass-mobile-bridge/src/jni.rs
//!
//! This test parses both sources and fails on ANY divergence in name set,
//! argument arity, argument types, or return types. It runs on the host
//! (no `jni` feature required) so `cargo test --workspace` always enforces
//! it. CI additionally runs an all-ABI `llvm-nm` symbol check over the built
//! `.so` (WBS-811) proving the compiled artifact honors the same contract.

use std::fs;
use std::path::{Path, PathBuf};

const JNI_CLASS_PREFIX: &str = "Java_com_sentinelpass_VaultBridge_";

fn repo_root() -> PathBuf {
    // tests/ sits directly under the crate dir; the repo root is one level up.
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crate dir has a parent (repo root)")
        .to_path_buf()
}

fn kotlin_source() -> String {
    let path =
        repo_root().join("android/SentinelPass/app/src/main/java/com/sentinelpass/VaultBridge.kt");
    fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("Kotlin contract source missing at {:?}: {}", path, e))
}

fn rust_source() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/jni.rs");
    fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("Rust JNI source missing at {:?}: {}", path, e))
}

/// A parsed native method declaration.
#[derive(Debug, PartialEq, Eq)]
struct NativeDecl {
    name: String,
    params: Vec<String>,
    ret: String,
}

/// Parse Kotlin `private external fun name(...): Ret?` declarations,
/// including single-line and multi-line signatures.
fn parse_kotlin_externals(src: &str) -> Vec<NativeDecl> {
    let mut decls = Vec::new();
    let mut chars_rest = src;
    while let Some(pos) = chars_rest.find("external fun ") {
        let after = &chars_rest[pos + "external fun ".len()..];
        let name: String = after
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        let after_name = &after[name.len()..];
        // Find the parameter list and (optionally) the return type.
        if let Some(open) = after_name.find('(') {
            // Scan to the matching close paren.
            let mut depth = 0usize;
            let mut end = None;
            for (i, c) in after_name[open..].char_indices() {
                if c == '(' {
                    depth += 1;
                } else if c == ')' {
                    depth -= 1;
                    if depth == 0 {
                        end = Some(open + i);
                        break;
                    }
                }
            }
            let close =
                end.unwrap_or_else(|| panic!("unbalanced parens after external fun {name}"));
            let params_src = &after_name[open + 1..close];
            let rest = after_name[close + 1..].trim_start();
            let ret = if let Some(stripped) = rest.strip_prefix(':') {
                let ret: String = stripped
                    .trim()
                    .chars()
                    .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '?')
                    .collect();
                ret
            } else {
                "Unit".to_string()
            };
            let params = params_src
                .split(',')
                .map(|p| p.trim())
                .filter(|p| !p.is_empty())
                .map(|p| {
                    p.rsplit(':')
                        .next()
                        .unwrap_or_default()
                        .trim()
                        .trim_end_matches('?')
                        .to_string()
                })
                .collect();
            decls.push(NativeDecl { name, params, ret });
        }
        chars_rest = after_name;
    }
    decls
}

/// Parse Rust `extern "system" fn Java_com_sentinelpass_VaultBridge_<name>(...) -> Ret`
/// exports, including multi-line signatures.
fn parse_rust_jni_exports(src: &str) -> Vec<NativeDecl> {
    let mut decls = Vec::new();
    let needle = format!("extern \"system\" fn {}", JNI_CLASS_PREFIX);
    let mut chars_rest = src;
    while let Some(pos) = chars_rest.find(&needle) {
        let after = &chars_rest[pos + needle.len()..];
        let name: String = after
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        let after_name = &after[name.len()..];
        if let Some(open) = after_name.find('(') {
            let mut depth = 0usize;
            let mut end = None;
            for (i, c) in after_name[open..].char_indices() {
                if c == '(' {
                    depth += 1;
                } else if c == ')' {
                    depth -= 1;
                    if depth == 0 {
                        end = Some(open + i);
                        break;
                    }
                }
            }
            let close = end.unwrap_or_else(|| panic!("unbalanced parens after export {name}"));
            let params_src = &after_name[open + 1..close];
            let rest = after_name[close + 1..].trim_start();
            let ret = if let Some(stripped) = rest.strip_prefix("->") {
                let ret: String = stripped
                    .trim()
                    .chars()
                    .take_while(|c| c.is_alphanumeric() || *c == '_')
                    .collect();
                ret
            } else {
                "()".to_string()
            };
            // Drop the JNI receiver pair (JNIEnv, jobject/JClass) — the test
            // compares Kotlin's view (no receiver) against the remainder.
            let params: Vec<String> = params_src
                .split(',')
                .map(|p| p.trim())
                .filter(|p| !p.is_empty())
                .map(|p| {
                    p.rsplit(':')
                        .next()
                        .unwrap_or_default()
                        .trim()
                        .trim_end_matches('?')
                        .to_string()
                })
                .skip(2)
                .collect();
            decls.push(NativeDecl { name, params, ret });
        }
        chars_rest = after_name;
    }
    decls
}

/// Kotlin type → expected JNI type in the Rust export.
fn expected_jni_type(kotlin_type: &str) -> &'static str {
    match kotlin_type {
        "Long" => "jlong",
        "Int" => "jint",
        "Boolean" => "jboolean",
        "String" => "JString",
        other => panic!("unmapped Kotlin native param type `{other}` — extend the contract map"),
    }
}

/// Kotlin return type → expected JNI return type in the Rust export.
fn expected_jni_ret(kotlin_ret: &str) -> &'static str {
    match kotlin_ret {
        "Long" => "jlong",
        "Int" => "jint",
        "Boolean" => "jboolean",
        "Unit" => "()",
        "String?" => "jstring",
        other => panic!("unmapped Kotlin native return type `{other}` — extend the contract map"),
    }
}

#[test]
fn kotlin_declarations_and_rust_exports_match_exactly() {
    let kotlin = parse_kotlin_externals(&kotlin_source());
    let rust = parse_rust_jni_exports(&rust_source());

    assert!(
        !kotlin.is_empty(),
        "parsed zero Kotlin external fun declarations — parser desynced from VaultBridge.kt"
    );
    assert!(
        !rust.is_empty(),
        "parsed zero Rust JNI exports — parser desynced from jni.rs"
    );

    let mut kotlin_sorted: Vec<&NativeDecl> = kotlin.iter().collect();
    kotlin_sorted.sort_by(|a, b| a.name.cmp(&b.name));
    let mut rust_sorted: Vec<&NativeDecl> = rust.iter().collect();
    rust_sorted.sort_by(|a, b| a.name.cmp(&b.name));

    for side in [(&kotlin_sorted, "Kotlin"), (&rust_sorted, "Rust")] {
        let names: Vec<&str> = side.0.iter().map(|d| d.name.as_str()).collect();
        let mut dedup = names.clone();
        dedup.sort_unstable();
        dedup.dedup();
        assert_eq!(
            names.len(),
            dedup.len(),
            "{} side declares a native more than once: {names:?}",
            side.1
        );
    }

    let kotlin_names: Vec<&str> = kotlin_sorted.iter().map(|d| d.name.as_str()).collect();
    let rust_names: Vec<&str> = rust_sorted.iter().map(|d| d.name.as_str()).collect();
    assert_eq!(
        kotlin_names, rust_names,
        "JNI contract diverged — Kotlin `external fun` set and Rust `Java_{JNI_CLASS_PREFIX}*` export set must be identical"
    );

    for (k, r) in kotlin_sorted.iter().zip(rust_sorted.iter()) {
        assert_eq!(
            k.params.len(),
            r.params.len(),
            "`{}` arity mismatch: Kotlin takes {} arg(s), Rust export takes {} (after the env+receiver pair)",
            k.name,
            k.params.len(),
            r.params.len()
        );
        for (i, (kp, rp)) in k.params.iter().zip(r.params.iter()).enumerate() {
            let want = expected_jni_type(kp);
            assert_eq!(
                want,
                rp,
                "`{}` param #{} type mismatch: Kotlin `{}` maps to `{want}`, Rust declares `{rp}`",
                k.name,
                i + 1,
                kp
            );
        }
        let want_ret = expected_jni_ret(&k.ret);
        assert_eq!(
            want_ret, r.ret,
            "`{}` return type mismatch: Kotlin `{}` maps to `{want_ret}`, Rust declares `{}`",
            k.name, k.ret, r.ret
        );
    }
}

#[test]
fn rust_exports_no_undeclared_jni_symbols() {
    // Guards against re-adding native exports without a Kotlin declaration
    // (the pre-802 failure mode: Rust exported five natives Kotlin never
    // declared, several of them dangerous placeholders).
    let rust = parse_rust_jni_exports(&rust_source());
    let kotlin = parse_kotlin_externals(&kotlin_source());
    let kotlin_names: Vec<&str> = kotlin.iter().map(|d| d.name.as_str()).collect();
    for decl in &rust {
        assert!(
            kotlin_names.contains(&decl.name.as_str()),
            "Rust exports `Java_{JNI_CLASS_PREFIX}{}` but VaultBridge.kt declares no such external fun",
            decl.name
        );
    }
}

/// WBS-805: every JNI export body must run inside `catch_jni` — a Rust panic
/// unwinding through an `extern "system"` frame aborts the JVM. Parsed from
/// source so a new export cannot skip containment.
#[test]
fn every_jni_export_is_panic_contained() {
    let src = rust_source();
    let export_region = src
        .split("#[cfg(all(test, feature = \"jni\"))]")
        .next()
        .expect("export region");
    let needle = "pub extern \"system\" fn ";
    let mut checked = 0usize;
    let mut rest = export_region;
    while let Some(pos) = rest.find(needle) {
        let after = &rest[pos + needle.len()..];
        let name: String = after
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        let brace = after.find('{').expect("export body brace");
        let first_stmt = after[brace + 1..].trim_start();
        assert!(
            first_stmt.starts_with("catch_jni("),
            "JNI export `{name}` is not panic-contained (body must open with catch_jni)"
        );
        checked += 1;
        rest = after;
    }
    assert!(
        checked >= 15,
        "parsed {checked} exports — parser desynced from jni.rs"
    );
}
