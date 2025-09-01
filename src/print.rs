use core::ffi::c_char;

unsafe extern "C" {
    fn println_str(s:*const c_char);
}
#[cfg(not(feature = "no_tboot_loglvl"))]
mod log_levels {
    pub const TBOOT_NONE: &str = "<0>";
    pub const TBOOT_ERR: &str = "<1>";
    pub const TBOOT_WARN: &str = "<2>";
    pub const TBOOT_INFO: &str = "<3>";
    pub const TBOOT_DETA: &str = "<4>";
    pub const TBOOT_ALL: &str = "<5>";
}

#[cfg(feature = "no_tboot_loglvl")]
mod log_levels {
    pub const TBOOT_NONE: &str = "";
    pub const TBOOT_ERR: &str = "";
    pub const TBOOT_WARN: &str = "";
    pub const TBOOT_INFO: &str = "";
    pub const TBOOT_DETA: &str = "";
    pub const TBOOT_ALL: &str = "";
}
pub use log_levels::*;

const MAX_LOG_MASSAGE_LEN:usize = 256;

pub fn printk(s: &str) {
    let mut buffer:[u8; MAX_LOG_MASSAGE_LEN] = [0; MAX_LOG_MASSAGE_LEN];
    let s_bytes = s.as_bytes();
    let len_to_copy = core::cmp::min(s_bytes.len(), MAX_LOG_MASSAGE_LEN - 1);
    buffer[..len_to_copy].copy_from_slice(&s_bytes[..len_to_copy]);
    buffer[len_to_copy] = 0;
    unsafe {
        println_str(buffer.as_ptr() as *const c_char);
    }
}