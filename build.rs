//! Build script for `turn-rs`.
//!
//! TURN itself adds no new native dependencies beyond what `stun-rs` and
//! `networkframework` already link. The `Security` framework is linked so that
//! the underlying transaction-ID RNG (`SecRandomCopyBytes`, reused from
//! `stun-rs`) resolves when `turn-rs` is built as the top-level crate.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=DOCS_RS");

    if std::env::var("DOCS_RS").is_ok() {
        return;
    }

    // SecRandomCopyBytes / kSecRandomDefault (pulled in transitively via stun-rs).
    println!("cargo:rustc-link-lib=framework=Security");
}
