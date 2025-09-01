use crate::crb::constants::*;

use core::cell::OnceCell;

use spin::Mutex;

pub fn TPM_LOCALITY_BASE_N(locality:u32) -> u64 {
    (TPM_LOCALITY_BASE | ((locality) << 12) as u64)
}

pub fn TPM_REG_ADDRESS(locality:u32, reg:u32) -> u64 {
    TPM_LOCALITY_BASE_N(locality) | reg as u64
}

static TPM_IF_INSTANCE: OnceCell<Mutex<TpmIf>> = OnceCell::new();
pub fn get_tpm_if() -> &'static Mutex<TpmIf> {
    TPM_IF_INSTANCE.get_or_init(|| {
        Mutex::new(TpmIf::default())
    })
}
