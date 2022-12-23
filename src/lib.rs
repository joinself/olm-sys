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
            let account_buf =
                Box::into_raw(Box::new(vec![0 as u8; olm_account_size() as usize * 10]));
            let account = olm_account(account_buf as *mut libc::c_void);

            let seed_len = olm_create_account_random_length(account);
            let seed = Box::into_raw(Box::new(vec![0 as u8; seed_len as usize]));

            let status = olm_create_account(account, seed as *mut libc::c_void, seed_len);

            assert_eq!(status, 0);
        }
    }
}
