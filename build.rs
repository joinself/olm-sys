extern crate bindgen;

use std::env;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;

fn main() {
    let olm_includes = Path::new("vendor/include/");
    let crypto_includes = Path::new("vendor/lib/");

    /* SELF SPECIFIC PATCHES */

    // increase the maximum amount of one time keys
    let account_header = std::fs::read_to_string("vendor/include/olm/account.hh").unwrap();
    let mut updated_account_header = account_header.replace(
        "const MAX_ONE_TIME_KEYS = 100;",
        "const MAX_ONE_TIME_KEYS = 10000;",
    );

    // add function to allow importing key material into an olm account
    if !account_header.contains("import_account") {
        updated_account_header = updated_account_header.replace(
            "std::size_t new_account_random_length() const;",
            "std::size_t new_account_random_length() const;\n\n\tstd::size_t import_account(\n\t\tuint8_t const * ed25519_secret_key,\n\t\tuint8_t const * ed25519_public_key,\n\t\tuint8_t const * curve25519_secret_key,\n\t\tuint8_t const * curve25519_public_key\n\t);"
        );
    }

    let mut account_header_file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open("vendor/include/olm/account.hh")
        .unwrap();

    account_header_file
        .write(updated_account_header.as_bytes())
        .unwrap();

    // add a function to allow importing key material into an olm account
    let account_cpp = std::fs::read_to_string("vendor/src/account.cpp").unwrap();
    if !account_cpp.contains("import_account") {
        let updated_account_cpp = account_cpp.replace(
            "std::size_t olm::Account::new_account(",
            "std::size_t olm::Account::import_account(\n\tuint8_t const * ed25519_secret_key,\n\tuint8_t const * ed25519_public_key,\n\tuint8_t const * curve25519_secret_key,\n\tuint8_t const * curve25519_public_key\n) {\n\tvoid *ed25519_secret_key_converted = std::malloc(ED25519_PRIVATE_KEY_LENGTH);\n\n\t_olm_crypto_ed25519_ref10_to_nightcracker(\n\t\t((uint8_t *)ed25519_secret_key_converted),\n\t\ted25519_secret_key\n\t);\n\n\tstd::memcpy(\n\t\tidentity_keys.ed25519_key.private_key.private_key, ed25519_secret_key_converted,\n\t\tED25519_PRIVATE_KEY_LENGTH\n\t);\n\n\tstd::memcpy(\n\t\tidentity_keys.ed25519_key.public_key.public_key, ed25519_public_key,\n\t\tED25519_PUBLIC_KEY_LENGTH\n\t);\n\n\tstd::memcpy(\n\t\tidentity_keys.curve25519_key.private_key.private_key, curve25519_secret_key,\n\t\tCURVE25519_KEY_LENGTH\n\t);\n\n\tstd::memcpy(\n\t\tidentity_keys.curve25519_key.public_key.public_key, curve25519_public_key,\n\t\tCURVE25519_KEY_LENGTH\n\t);\n\n\treturn 0;\n}\n\nstd::size_t olm::Account::new_account("
        );

        let mut account_cpp_file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open("vendor/src/account.cpp")
            .unwrap();

        account_cpp_file
            .write(updated_account_cpp.as_bytes())
            .unwrap();
    }

    // add function to allow importing key material into an olm account
    let olm_header = std::fs::read_to_string("vendor/include/olm/olm.h").unwrap();
    if !olm_header.contains("olm_import_account") {
        let updated_olm_header = olm_header.replace(
            "OLM_EXPORT size_t olm_create_account(",
            "OLM_EXPORT size_t olm_import_account(\n\tOlmAccount * account,\n\tvoid * ed25519_secret_key,\n\tvoid * ed25519_public_key,\n\tvoid * curve25519_secret_key,\n\tvoid * curve25519_public_key\n);\n\nOLM_EXPORT size_t olm_create_account(",
        );

        let mut olm_header_file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open("vendor/include/olm/olm.h")
            .unwrap();

        olm_header_file
            .write(updated_olm_header.as_bytes())
            .unwrap();
    }

    // add a function to allow importing key material into an olm account
    let olm_cpp = std::fs::read_to_string("vendor/src/olm.cpp").unwrap();
    if !olm_cpp.contains("olm_import_account") {
        let updated_olm_cpp = olm_cpp.replace(
            "size_t olm_create_account(",
            "size_t olm_import_account(\n\tOlmAccount * account,\n\tvoid * ed25519_secret_key,\n\tvoid * ed25519_public_key,\n\tvoid * curve25519_secret_key,\n\tvoid * curve25519_public_key\n) {\n\tsize_t result = from_c(account)->import_account(\n\t\tfrom_c(ed25519_secret_key),\n\t\tfrom_c(ed25519_public_key),\n\t\tfrom_c(curve25519_secret_key),\n\t\tfrom_c(curve25519_public_key)\n\t);\n\treturn result;\n}\n\nsize_t olm_create_account("
        );

        let mut olm_cpp_file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open("vendor/src/olm.cpp")
            .unwrap();

        olm_cpp_file.write(updated_olm_cpp.as_bytes()).unwrap();
    }

    // add function for converting ref10 ed25519 keys to hashed representation used by the nightcracker implemetation
    let ed25519_header = std::fs::read_to_string("vendor/lib/ed25519/src/ed25519.h").unwrap();
    if !ed25519_header.contains("_olm_crypto_ed25519_ref10_to_nightcracker") {
        let updated_ed25519_header = ed25519_header.replace(
            "void ED25519_DECLSPEC ed25519_key_exchange(unsigned char *shared_secret, const unsigned char *public_key, const unsigned char *private_key);",
            "void ED25519_DECLSPEC ed25519_ref10_to_nightcracker(\n\tuint8_t *secret_key,\n\tconst uint8_t *ref10_secret_key\n);\n\nvoid ED25519_DECLSPEC ed25519_key_exchange(unsigned char *shared_secret, const unsigned char *public_key, const unsigned char *private_key);"
        );

        let mut ed25519_header_file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open("vendor/lib/ed25519/src/ed25519.h")
            .unwrap();

        ed25519_header_file
            .write(updated_ed25519_header.as_bytes())
            .unwrap();
    }

    // add function for converting ref10 ed25519 keys to hashed representation used by the nightcracker implemetation
    let keypair_cpp = std::fs::read_to_string("vendor/lib/ed25519/src/keypair.c").unwrap();
    if !keypair_cpp.contains("ed25519_ref10_to_nightcracker") {
        let updated_keypair_cpp = keypair_cpp.replace(
            "void ed25519_create_keypair(unsigned char *public_key, unsigned char *private_key, const unsigned char *seed) {",
            "void ed25519_ref10_to_nightcracker(\n\tuint8_t *secret_key,\n\tconst uint8_t *ref10_secret_key\n) {\n\tsha512(ref10_secret_key, 32, secret_key);\n\tsecret_key[0] &= 248;\n\tsecret_key[31] &= 63;\n\tsecret_key[31] |= 64;\n}\n\nvoid ed25519_create_keypair(unsigned char *public_key, unsigned char *private_key, const unsigned char *seed) {"
        );

        let mut keypair_cpp_file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open("vendor/lib/ed25519/src/keypair.c")
            .unwrap();

        keypair_cpp_file
            .write(updated_keypair_cpp.as_bytes())
            .unwrap();
    }

    let crypto_header = std::fs::read_to_string("vendor/include/olm/crypto.h").unwrap();
    if !crypto_header.contains("_olm_crypto_ed25519_ref10_to_nightcracker") {
        let updated_crypto_header = crypto_header.replace(
            "OLM_EXPORT void _olm_crypto_ed25519_generate_key(",
            "OLM_EXPORT void _olm_crypto_ed25519_ref10_to_nightcracker(\n\tuint8_t *secret_key,\n\tconst uint8_t *ref10_secret_key\n);\n\nOLM_EXPORT void _olm_crypto_ed25519_generate_key("
        );

        let mut crypto_header_file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open("vendor/include/olm/crypto.h")
            .unwrap();

        crypto_header_file
            .write(updated_crypto_header.as_bytes())
            .unwrap();
    }

    let crypto_cpp = std::fs::read_to_string("vendor/src/crypto.cpp").unwrap();
    if !crypto_cpp.contains("_olm_crypto_ed25519_ref10_to_nightcracker") {
        let updated_crypto_cpp = crypto_cpp.replace(
            "void _olm_crypto_ed25519_generate_key(",
            "void _olm_crypto_ed25519_ref10_to_nightcracker(\n\tuint8_t *secret_key,\n\tconst uint8_t *ref10_secret_key\n) {\n\t::ed25519_ref10_to_nightcracker(\n\t\tsecret_key,\n\t\tref10_secret_key\n\t);\n}\n\nvoid _olm_crypto_ed25519_generate_key(",
        );

        let mut crypto_cpp_file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open("vendor/src/crypto.cpp")
            .unwrap();

        crypto_cpp_file
            .write(updated_crypto_cpp.as_bytes())
            .unwrap();
    }

    // TODO get major, min and patch levels from vendor

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
        .size_t_is_usize(true)
        .generate()
        .expect("Unable to generate olm bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());

    // output the bindings
    bindings
        .write_to_file(out_path.join("olm.rs"))
        .expect("Couldn't write olm bindings!");
}
