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
            
            let account_buf: Vec<u8> = vec![0; olm_account_size() as usize];
            let account_buf_ptr = Box::into_raw(Box::new(account_buf));
            let account = olm_account(account_buf_ptr as *mut libc::c_void);
            
            let seed_len = olm_create_account_random_length(account);
            
            let mut seed: Vec<u8> = vec![0; seed_len as usize];
            let status = olm_create_account(account, seed.as_mut_ptr() as *mut libc::c_void, seed.len() as u64);
            assert_eq!(status, 0);
        }
    }
}

