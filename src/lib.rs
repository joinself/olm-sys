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
            67, 109, 66, 86, 78, 97, 100, 114, 102, 55, 43, 101, 119, 74, 78, 78, 108, 79, 98, 56,
            49, 78, 88, 50, 55, 76, 99, 102, 75, 74, 88, 81, 50, 79, 81, 48, 74, 88, 99, 85, 114,
            81, 87, 57, 111, 68, 65, 84, 100, 50, 113, 112, 88, 88, 53, 107, 115, 66, 81, 76, 71,
            84, 101, 67, 102, 104, 76, 107, 86, 120, 100, 73, 67, 81, 78, 116, 79, 65, 52, 83, 76,
            51, 66, 67, 66, 65,
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
                olm_signature.as_ptr() as *mut libc::c_void,
                olm_signature_len as u64,
            );

            assert_eq!(status, 0);
            assert_eq!(signature, olm_signature);
        }
    }
}
