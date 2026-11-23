use std::env;

fn main() {
    napi_build::setup();

    if env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        give_addon_a_loader_relative_rpath();
        let_unit_tests_link_without_node();
    }
}

/// The `napi_*` functions live in the Node process that loads the addon.
/// napi-build lets the cdylib leave them undefined, but the unit-test binary
/// links them too, and Apple's linker refuses an executable with undefined
/// symbols even when nothing calls them (GNU ld drops the unused references).
/// The tests never reach N-API, so the symbols are left to bind lazily.
fn let_unit_tests_link_without_node() {
    println!("cargo:rustc-link-arg=-Wl,-undefined,dynamic_lookup");
}

/// msquic builds as a dylib whose install name is `@rpath/libmsquic.2.dylib`, and a Node addon is
/// opened with dlopen from wherever the consumer resolved it, so there is no ambient search path to
/// fall back on. Without an rpath the addon only loaded when the caller had already exported
/// DYLD_LIBRARY_PATH pointing into cargo's build tree, which every consumer had to arrange for
/// itself and which is lost across re-exec, hardened runtimes and service managers.
///
/// `@loader_path` resolves against the directory the addon was loaded from, so the addon and the
/// dylib stay a self-describing pair wherever the package is installed. `build-native.mjs` is what
/// puts the dylib there, because a build script runs before the regular dependencies are built and
/// cannot see msquic's cmake output yet.
fn give_addon_a_loader_relative_rpath() {
    println!("cargo:rustc-link-arg-cdylib=-Wl,-rpath,@loader_path");
}
