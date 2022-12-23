extern crate bindgen;

use std::env;
use std::path::Path;
use std::path::PathBuf;

fn main() {
    let olm_includes = Path::new("vendor/include/");
    let crypto_includes = Path::new("vendor/lib/");

    let mut cmd = cc::Build::new();

    cmd.warnings(false)
        .cpp(true)
        .cpp_link_stdlib("stdc++")
        .include(olm_includes)
        .include(crypto_includes)
        .define("OLMLIB_VERSION_MAJOR", "1")
        .define("OLMLIB_VERSION_MINOR", "0")
        .define("OLMLIB_VERSION_PATCH", "0")
        .file("vendor/src/account.cpp")
        .file("vendor/src/base64.cpp")
        .file("vendor/src/cipher.cpp")
        .file("vendor/src/crypto.cpp")
        .file("vendor/src/memory.cpp")
        .file("vendor/src/message.cpp")
        .file("vendor/src/pickle.cpp")
        .file("vendor/src/ratchet.cpp")
        .file("vendor/src/session.cpp")
        .file("vendor/src/utility.cpp")
        .file("vendor/src/pk.cpp")
        .file("vendor/src/olm.cpp");

    cmd.compile("olm++");

    let mut cmd = cc::Build::new();

    cmd.warnings(false)
        .include(olm_includes)
        .include(crypto_includes)
        .define("OLMLIB_VERSION_MAJOR", "1")
        .define("OLMLIB_VERSION_MINOR", "0")
        .define("OLMLIB_VERSION_PATCH", "0")
        .file("vendor/src/sas.c")
        .file("vendor/src/ed25519.c")
        .file("vendor/src/error.c")
        .file("vendor/src/inbound_group_session.c")
        .file("vendor/src/megolm.c")
        .file("vendor/src/outbound_group_session.c")
        .file("vendor/src/pickle_encoding.c")
        .file("vendor/lib/crypto-algorithms/aes.c")
        .file("vendor/lib/crypto-algorithms/sha256.c")
        .file("vendor/lib/curve25519-donna/curve25519-donna.c");

    cmd.compile("olm");

    // generate the bindings for olm headers
    let builder = bindgen::Builder::default();
    let bindings = builder
        .clang_arg("-Ivendor/")
        .clang_arg("-Ivendor/include/")
        .allowlist_type(r"olm.*")
        .allowlist_type(r"Olm.*")
        .allowlist_type(r"OLM.*")
        .allowlist_function(r"olm.*")
        .allowlist_function(r"Olm.*")
        .allowlist_function(r"OLM.*")
        .allowlist_var(r"olm.*")
        .allowlist_var(r"Olm.*")
        .allowlist_var(r"OLM.*")
        .header("vendor/include/olm/olm.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .generate()
        .expect("Unable to generate olm bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());

    // output the bindings
    bindings
        .write_to_file(out_path.join("olm.rs"))
        .expect("Couldn't write olm bindings!");
}
