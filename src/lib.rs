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
}
