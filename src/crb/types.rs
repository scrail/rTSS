use bitfield::bitfield;

use super::constants::*;
use super::crb_core::get_tpm_if;

pub trait ToBytes {
    type Bytes;
    fn to_le_bytes(&self) -> Self::Bytes;
}

pub trait FromBytes {
    type Bytes;
    fn from_le_bytes(bytes: Self::Bytes) -> Self;
}

pub enum TpmTimeoutType {
    ActiveLocalityTimeout,
    CmdReadyTimeout,
    CmdWriteTimeout,
    DataAvailTimeout,
    RspReadTimeout,
}
pub fn get_tpm_time_out(timeout_type: TpmTimeoutType) -> u64 {
    let tpm_if_guard = get_tpm_if().lock();
    let timeout;
    match timeout_type {
        TpmTimeoutType::ActiveLocalityTimeout => timeout = tpm_if_guard.timeout_a,
        TpmTimeoutType::CmdReadyTimeout => timeout = tpm_if_guard.timeout_b,
        TpmTimeoutType::CmdWriteTimeout => timeout = tpm_if_guard.timeout_d,
        TpmTimeoutType::DataAvailTimeout => timeout = tpm_if_guard.timeout_c,
        TpmTimeoutType::RspReadTimeout => timeout = tpm_if_guard.timeout_d,
    }
    drop(tpm_if_guard);
    TIMEOUT_UNIT * timeout
}
#[derive(Debug, Clone, Copy)]
pub struct TpmTimeout{
    pub timeout_a:u64, 
    pub timeout_b:u64,
    pub timeout_c:u64,
    pub timeout_d:u64,
}

impl Default for TpmTimeout {
    fn default() -> Self {
        Self { timeout_a: TIMEOUT_A, timeout_b: TIMEOUT_B, timeout_c: TIMEOUT_C, timeout_d: TIMEOUT_D }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u8)]
pub enum TpmExtPolicy{
    Agile = 0,
    Embedded = 1,
    Fixed = 2,
    Unknown(u8),
}

impl From<u8> for TpmExtPolicy {
    fn from(val: u8) -> Self {
        match val {
            0 => TpmExtPolicy::Agile,
            1 => TpmExtPolicy::Embedded,
            2 => TpmExtPolicy::Fixed,
            _ => TpmExtPolicy::Unknown(val),
        }
    }
}

impl From<TpmExtPolicy> for u8 {
    fn from(policy: TpmExtPolicy) -> Self {
        match policy {
            TpmExtPolicy::Agile => 0,
            TpmExtPolicy::Embedded => 1,
            TpmExtPolicy::Fixed => 2,
            TpmExtPolicy::Unknown(val) => val,
        }
    }
}

#[derive(Debug)]
pub struct TpmIf {
    pub major: u8,
    pub minor: u8,
    pub family: u16,

    pub timeout: TpmTimeout,

    pub error: u32,                  /* last reported error */
    pub cur_loc: u32,

    pub banks: u16,
    pub algs_banks: [u16; TPM_ALG_MAX_NUM],
    pub alg_count: u16,
    pub algs: [u16; TPM_ALG_MAX_NUM],

    pub extpol: TpmExtPolicy,
    pub cur_alg: u16,
    pub sig_scheme: u16,
    pub cert_size: u16,

    pub lcp_own_index: u32,
    pub tb_policy_index: u32,
    pub tb_err_index: u32,
    pub sgx_svn_index: u32,
}

impl Default for TpmIf {
    fn default() -> Self {
        // 模拟 C 代码中 g_tpm 的初始化
        Self {
            major: 0, 
            minor: 0,
            family: 0,
            timeout: TpmTimeout::default(), 
            error: 0,
            cur_loc: 0,
            banks: 0,
            algs_banks: [0; TPM_ALG_MAX_NUM], 
            alg_count: 0,
            algs: [0; TPM_ALG_MAX_NUM],
            extpol: TpmExtPolicy::Unknown(u8::MAX), 
            cur_alg: 0,
            sig_scheme: 0,
            cert_size: 0,
            lcp_own_index: 0,
            tb_policy_index: 0,
            tb_err_index: 0,
            sgx_svn_index: 0,
        }
    }
}


bitfield! {
    pub struct TpmRegLocState(u32);
    pub tpm_establishment, _: 0,0;
    pub loc_assigned, _: 1,1;
    pub active_locality, _:4,2;
    pub reserved, _:7,5;
    pub tpm_reg_valid_sts, _:8,8; /* RO, 1=other bits are valid */
    pub reserved1, _:16,9;
    pub reserved2, _:31,17;
}

impl FromBytes for TpmRegLocState {
    type Bytes = [u8;4];
    fn from_le_bytes(bytes:Self::Bytes) ->Self {
        let raw_value = u32::from_le_bytes(bytes);
        TpmRegLocState(raw_value)
    }
}


bitfield! {
    pub struct TpmRegCtrlRequest(u32);
    pub cmd_ready, set_cmd_ready: 0,0;
    pub go_idle, set_go_idle: 1,1;  
}

impl ToBytes for TpmRegCtrlRequest {
    type Bytes = [u8;4];

    fn to_le_bytes(&self) -> Self::Bytes {
        self.0.to_le_bytes()
    }
}

impl FromBytes for TpmRegCtrlRequest {
    type Bytes = [u8;4];

    fn from_le_bytes(bytes: Self::Bytes) -> Self {
        todo!()
    }
}

bitfield! {
    pub struct TpmRegCtrlStatus(u32);
    pub error, _: 0, 0;
    pub tpm_idle, _: 1, 1;

}

impl ToBytes for TpmRegCtrlStatus {
    type Bytes = [u8;4];

    fn to_le_bytes(&self) -> Self::Bytes {
        self.0.to_le_bytes()
    }
}

impl FromBytes for TpmRegCtrlStatus {
    type Bytes = [u8;4];

    fn from_le_bytes(bytes: Self::Bytes) -> Self {
        todo!()
    }
}


bitfield! {
    pub struct TpmRegCtrlCancel(u32);
    pub cancel, set_cancel: 0,0;
}

impl ToBytes for TpmRegCtrlCancel {
    type Bytes = [u8;4];

    fn to_le_bytes(&self) -> Self::Bytes {
        self.0.to_le_bytes()
    }
}

bitfield! {
    pub struct TpmRegCtrlStart(u32);
    pub start, set_start: 0,0;
}

impl ToBytes for TpmRegCtrlStart {
    type Bytes = [u8;4];

    fn to_le_bytes(&self) -> Self::Bytes {
        self.0.to_le_bytes()
    }
}

pub struct TpmRegCtrlCmdSize(u32);

impl ToBytes for TpmRegCtrlCmdSize {
    type Bytes = [u8;4];

    fn to_le_bytes(&self) -> Self::Bytes {
        self.0.to_le_bytes()
    }
}

pub struct TpmRegCtrlCmdAddr(pub u64);

impl ToBytes for TpmRegCtrlCmdAddr {
    type Bytes = [u8;8];

    fn to_le_bytes(&self) -> Self::Bytes {
        self.0.to_le_bytes()
    }
}

pub struct TpmRegCtrlRspSize(u32);

impl ToBytes for TpmRegCtrlRspSize {
    type Bytes = [u8;4];

    fn to_le_bytes(&self) -> Self::Bytes {
        self.0.to_le_bytes()
    }
}

pub struct TpmRegCtrlRspAddr(u64);

impl ToBytes for TpmRegCtrlRspAddr {
    type Bytes = [u8;8];

    fn to_le_bytes(&self) -> Self::Bytes {
        self.0.to_le_bytes()
    }
}

impl FromBytes for TpmRegCtrlRspAddr {
    type Bytes = [u8;8];

    fn from_le_bytes(bytes: Self::Bytes) -> Self {
        todo!()
    }
}