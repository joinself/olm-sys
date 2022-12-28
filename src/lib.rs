#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(deref_nullptr)]
#![allow(improper_ctypes)]

include!(concat!(env!("OUT_DIR"), "/olm.rs"));

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_account() {
        unsafe {
            let account_len = olm_account_size() as usize;
            let account_buf = Box::into_raw(vec![0; account_len].into_boxed_slice());
            let account = olm_account(account_buf as *mut libc::c_void);

            let seed_len = olm_create_account_random_length(account);
            let mut seed = vec![0 as u8; (seed_len) as usize];

            let status =
                olm_create_account(account, seed.as_mut_ptr() as *mut libc::c_void, seed_len);
            assert_eq!(status, 0);

            let random_len =
                olm_account_generate_one_time_keys_random_length(account, 100) as usize;
            let mut random_buf = vec![0 as u8; random_len].into_boxed_slice();

            let status = olm_account_generate_one_time_keys(
                account,
                100,
                random_buf.as_mut_ptr() as *mut libc::c_void,
                random_len as u64,
            );
            assert_eq!(status, 100);

            drop(Box::from_raw(account_buf));
        }
    }

    #[test]
    fn import_account() {
        let signature: Box<[u8]> = vec![
            10, 96, 85, 53, 167, 107, 127, 191, 158, 192, 147, 77, 148, 230, 252, 212, 213, 246,
            236, 183, 31, 40, 149, 208, 216, 228, 52, 37, 119, 20, 173, 5, 189, 160, 48, 19, 119,
            106, 169, 93, 126, 100, 176, 20, 11, 25, 55, 130, 126, 18, 228, 87, 23, 72, 9, 3, 109,
            56, 14, 18, 47, 112, 66, 4,
        ]
        .into_boxed_slice();

        let mut ed25519_secret_key: Box<[u8]> = vec![
            66, 206, 15, 222, 212, 234, 58, 255, 124, 60, 173, 108, 167, 250, 98, 62, 174, 167,
            255, 47, 101, 178, 174, 194, 230, 110, 170, 241, 171, 125, 187, 11, 15, 54, 224, 29,
            250, 158, 151, 109, 233, 103, 79, 236, 217, 43, 83, 44, 156, 31, 15, 111, 155, 227,
            255, 120, 107, 79, 241, 55, 179, 85, 0, 131,
        ]
        .into_boxed_slice();

        let mut ed25519_public_key: Box<[u8]> = vec![
            15, 54, 224, 29, 250, 158, 151, 109, 233, 103, 79, 236, 217, 43, 83, 44, 156, 31, 15,
            111, 155, 227, 255, 120, 107, 79, 241, 55, 179, 85, 0, 131,
        ]
        .into_boxed_slice();

        let mut curve25519_secret_key: Box<[u8]> = vec![
            56, 46, 191, 61, 229, 250, 220, 104, 37, 3, 127, 106, 113, 169, 41, 202, 24, 244, 7,
            181, 224, 221, 91, 29, 167, 81, 30, 13, 144, 222, 144, 104,
        ]
        .into_boxed_slice();

        let mut curve25519_public_key: Box<[u8]> = vec![
            146, 45, 24, 41, 116, 219, 58, 105, 179, 86, 243, 17, 26, 157, 128, 171, 182, 13, 42,
            89, 188, 112, 127, 77, 198, 254, 201, 99, 156, 218, 42, 27,
        ]
        .into_boxed_slice();

        unsafe {
            let account_len = olm_account_size() as usize;
            let account_buf = Box::into_raw(vec![0; account_len].into_boxed_slice());
            let account = olm_account(account_buf as *mut libc::c_void);

            let status = olm_import_account(
                account,
                ed25519_secret_key.as_mut_ptr() as *mut libc::c_void,
                ed25519_public_key.as_mut_ptr() as *mut libc::c_void,
                curve25519_secret_key.as_mut_ptr() as *mut libc::c_void,
                curve25519_public_key.as_mut_ptr() as *mut libc::c_void,
            );

            assert_eq!(status, 0);

            let olm_signature_len = olm_account_signature_length(account);
            let mut olm_signature = vec![0 as u8; olm_signature_len as usize].into_boxed_slice();

            let message = "test".as_bytes();
            let message_len = message.len() as u64;

            let status = olm_account_sign(
                account,
                message.as_ptr() as *const libc::c_void,
                message_len,
                olm_signature.as_mut_ptr() as *mut libc::c_void,
                olm_signature_len,
            );

            assert_eq!(status, olm_signature_len);

            println!("--- SIGNATURE: {:?}", signature);
            println!("OLM SIGNATURE: {:?}", olm_signature);

            let util_len = olm_utility_size() as usize;
            let util_buf = Box::into_raw(vec![0; util_len].into_boxed_slice());
            let util = olm_utility(util_buf as *mut libc::c_void);

            let encoded_public_key = "DzbgHfqel23pZ0/s2StTLJwfD2+b4/94a0/xN7NVAIM".as_bytes();

            let status = olm_ed25519_verify(
                util,
                encoded_public_key.as_ptr() as *const libc::c_void,
                encoded_public_key.len() as u64,
                message.as_ptr() as *const libc::c_void,
                message_len,
                signature.as_ptr() as *mut libc::c_void,
                signature.len() as u64,
            );

            assert_eq!(status, 0);
        }
    }
}
