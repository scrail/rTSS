use core::{cell::OnceCell, hint::spin_loop, ptr};

use spin::Mutex;

use bitfield::bitfield;

/*
 * Command Header Fields:
 *       0   1   2   3   4   5   6   7   8   9   10  ...
 *       -------------------------------------------------------------
 *       | TAG  |     SIZE      | COMMAND CODE  |    other ...
 *       -------------------------------------------------------------
 *
 * Response Header Fields:
 *       0   1   2   3   4   5   6   7   8   9   10  ...
 *       -------------------------------------------------------------
 *       | TAG  |     SIZE      |  RETURN CODE  |    other ...
 *       -------------------------------------------------------------
 */
const CMD_HEAD_SIZE  :usize         =10;
const RSP_HEAD_SIZE  :usize         =10;
const CMD_SIZE_OFFSET:u64         =2;
const CMD_CC_OFFSET  :u64         =6;
const RSP_SIZE_OFFSET:u64         =2;
const RSP_RST_OFFSET :u64         =6;

/*
 * The term timeout applies to timings between various states
 * or transitions within the interface protocol.
 */
const TIMEOUT_UNIT:u64    =(0x100000 / 330);	/* ~1ms, 1 tpm r/w need > 330ns */
const TIMEOUT_A   :u64    =750;     /* 750ms */
const TIMEOUT_B   :u64    =2000;    /* 2s */
const TIMEOUT_C   :u64    =75000;   /* 750ms */
const TIMEOUT_D   :u64    =750;     /* 750ms */

const TPM_VALIDATE_LOCALITY_TIME_OUT:u64 =  0x100;

enum TpmTimeoutType {
    ActiveLocalityTimeout,
    CmdReadyTimeout,
    CmdWriteTimeout,
    DataAvailTimeout,
    RspReadTimeout,
}
fn get_tpm_time_out(timeout_type: TpmTimeoutType) -> u64 {
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

/*
 * The TCG maintains a registry of all algorithms that have an
 * assigned algorithm ID. That registry is the definitive list
 * of algorithms that may be supported by a TPM.
 */
const TPM_ALG_ERROR         :u64    =0x0000;
const TPM_ALG_FIRST         :u64    =0x0001;
const TPM_ALG_RSA           :u64    =0x0001;
const TPM_ALG_DES           :u64    =0x0002;
const TPM_ALG__3DES         :u64    =0x0003;
const TPM_ALG_SHA           :u64    =0x0004;
const TPM_ALG_SHA1          :u64    =0x0004;
const TPM_ALG_HMAC          :u64    =0x0005;
const TPM_ALG_AES           :u64    =0x0006;
const TPM_ALG_MGF1          :u64    =0x0007;
const TPM_ALG_KEYEDHASH     :u64    =0x0008;
const TPM_ALG_XOR           :u64    =0x000A;
const TPM_ALG_SHA256        :u64    =0x000B;
const TPM_ALG_SHA384        :u64    =0x000C;
const TPM_ALG_SHA512        :u64    =0x000D;
const TPM_ALG_WHIRLPOOL512  :u64    =0x000E;
const TPM_ALG_NULL          :u64    =0x0010;
const TPM_ALG_SM3_256       :u64    =0x0012;
const TPM_ALG_SM4           :u64    =0x0013;
const TPM_ALG_RSASSA        :u64    =0x0014;
const TPM_ALG_RSAES         :u64    =0x0015;
const TPM_ALG_RSAPSS        :u64    =0x0016;
const TPM_ALG_OAEP          :u64    =0x0017;
const TPM_ALG_ECDSA         :u64    =0x0018;
const TPM_ALG_ECDH          :u64    =0x0019;
const TPM_ALG_ECDAA         :u64    =0x001A;
const TPM_ALG_SM2           :u64    =0x001B;
const TPM_ALG_ECSCHNORR     :u64    =0x001C;
const TPM_ALG_KDF1_SP800_56a:u64    =0x0020;
const TPM_ALG_KDF2          :u64    =0x0021;
const TPM_ALG_KDF1_SP800_108:u64    =0x0022;
const TPM_ALG_ECC           :u64    =0x0023;
const TPM_ALG_SYMCIPHER     :u64    =0x0025;
const TPM_ALG_CTR           :u64    =0x0040;
const TPM_ALG_OFB           :u64    =0x0041;
const TPM_ALG_CBC           :u64    =0x0042;
const TPM_ALG_CFB           :u64    =0x0043;
const TPM_ALG_ECB           :u64    =0x0044;
const TPM_ALG_LAST          :u64    =0x0044;
const TPM_ALG_MAX_NUM       :usize    =(TPM_ALG_LAST - TPM_ALG_ERROR) as usize;

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

/* Const Definition */
const TPM_NR_LOCALITIES:u32      = 5;
const TPM_LOCALITY_BASE:u64      = 0xfed40000;
const TPM_LOCALITY_0:u64         = TPM_LOCALITY_BASE;
const TPM_LOCALITY_1:u64         = TPM_LOCALITY_BASE | 0x1000;
const TPM_LOCALITY_2:u64         = TPM_LOCALITY_BASE | 0x2000;
const TPM_LOCALITY_3:u64         = TPM_LOCALITY_BASE | 0x3000;
const TPM_LOCALITY_4:u64         = TPM_LOCALITY_BASE | 0x4000;


fn TPM_LOCALITY_BASE_N(locality:u32) -> u64 {
    (TPM_LOCALITY_BASE | ((locality) << 12) as u64)
}

fn TPM_REG_ADDRESS(locality:u32, reg:u32) -> u64 {
    TPM_LOCALITY_BASE_N(locality) | reg as u64
}

//-----------------------------------------------------------------------------
// CRB I/F related definitions, see TCG PC Client Platform TPM Profile (PTP) Specification, Level 00 Revision 00.43
//-----------------------------------------------------------------------------
const TPM_REG_LOC_STATE:u32       =   0x00;
const TPM_REG_LOC_CTRL:u32        =    0x8;
const TPM_LOCALITY_STS:u32        =   0x0C;
const TPM_INTERFACE_ID:u32        =   0x30;
const TPM_CONTROL_AREA:u32        =   0x40;
const TPM_CRB_CTRL_REQ:u32        =   0x40;
const TPM_CRB_CTRL_STS:u32        =   0x44;
const TPM_CRB_CTRL_CANCEL:u32     =   0x48;
const TPM_CRB_CTRL_START:u32      =   0x4C;
const TPM_CRB_CTRL_CMD_SIZE:u32   =   0x58;
const TPM_CRB_CTRL_CMD_ADDR:u32   =   0x5C;
const TPM_CRB_CTRL_CMD_HADDR:u32  =   0x60;
const TPM_CRB_CTRL_RSP_SIZE:u32   =   0x64;
const TPM_CRB_CTRL_RSP_ADDR:u32   =   0x68;
const TPM_CRB_DATA_BUFFER:u32     =   0x80;
const TPMCRBBUF_LEN:u32           =  0xF80;     //3968 Bytes

trait ToBytes {
    type Bytes;
    fn to_le_bytes(&self) -> Self::Bytes;
}

bitfield! {
    struct Request(u32);
    pub _, set_cmd_ready: 0,0;
    pub _, set_go_idle: 1,1;  
}

impl ToBytes for Request {
    type Bytes = [u8;4];

    fn to_le_bytes(&self) -> Self::Bytes {
        self.0.to_le_bytes()
    }
}

bitfield! {
    pub struct Status(u32);
    pub error, _: 0, 0;
    pub tpm_idle, _: 1, 1;

}

impl ToBytes for Status {
    type Bytes = [u8;4];

    fn to_le_bytes(&self) -> Self::Bytes {
        self.0.to_le_bytes()
    }
}


bitfield! {
    pub struct Cancel(u32);
    pub cancel, set_cancel: 0,0;
}

impl ToBytes for Cancel {
    type Bytes = [u8;4];

    fn to_le_bytes(&self) -> Self::Bytes {
        self.0.to_le_bytes()
    }
}

bitfield! {
    pub struct Start(u32);
    pub start, set_start: 0,0;
}

impl ToBytes for Start {
    type Bytes = [u8;4];

    fn to_le_bytes(&self) -> Self::Bytes {
        self.0.to_le_bytes()
    }
}

pub struct CmdSize(u32);

impl ToBytes for CmdSize {
    type Bytes = [u8;4];

    fn to_le_bytes(&self) -> Self::Bytes {
        self.0.to_le_bytes()
    }
}

pub struct CmdAddr(u64);

impl ToBytes for CmdAddr {
    type Bytes = [u8;8];

    fn to_le_bytes(&self) -> Self::Bytes {
        self.0.to_le_bytes()
    }
}

pub struct RspSize(u32);

impl ToBytes for RspSize {
    type Bytes = [u8;4];

    fn to_le_bytes(&self) -> Self::Bytes {
        self.0.to_le_bytes()
    }
}

pub struct RspAddr(u64);

impl ToBytes for RspAddr {
    type Bytes = [u8;8];

    fn to_le_bytes(&self) -> Self::Bytes {
        self.0.to_le_bytes()
    }
}


#[repr(C,packed)]
pub struct CrbControlArea {
    request: Request,
    status: Status,
    cancel: Cancel,
    start: Start,
    _reserved: u64,
    cmdsize: CmdSize,
    cmdaddr: CmdAddr,
    rspsize: RspSize,
    rspaddr: RspAddr,
}

enum Locality {

}

enum TpmCrbError {
    InvalidLocality,
    InvalidParameter,
    InvalidBufferSize,
    LocalityNotOpen,
    TpmNotReady,
    Timeout,
}

static TPM_IF_INSTANCE: OnceCell<Mutex<TpmIf>> = OnceCell::new();
pub fn get_tpm_if() -> &'static Mutex<TpmIf> {
    TPM_IF_INSTANCE.get_or_init(|| {
        Mutex::new(TpmIf::default())
    })
}


pub fn tpm_submit_cmd_crb(locality:u32, in_value: &[u8], in_size:u32, out_value:&mut [u8], out_size:u32) -> Result<(), TpmCrbError> {

    //locality range check
    if locality >= TPM_NR_LOCALITIES {
        print();
        return Err(TpmCrbError::InvalidLocality)
    }

    // in out data check
    if in_value.len() < CMD_HEAD_SIZE || out_value.len() < RSP_HEAD_SIZE {
        print();
        return Err(TpmCrbError::InvalidBufferSize);
    }

    // locality validation check
    if !tpm_validate_locality_crb(locality) {
        print();
        return Err(TpmCrbError::LocalityNotOpen);
    }

    // TPM ready check
    if !tpm_wait_cmd_ready_crb(locality) {
        return Err(TpmCrbError::LocalityNotOpen);
    }


    // write command to TPM CRB buffer
    let cmdaddr = CmdAddr(TPM_LOCALITY_BASE_N(locality) | TPM_CRB_DATA_BUFFER as u64);
    let rspaddr = RspAddr(TPM_LOCALITY_BASE_N(locality) | TPM_CRB_DATA_BUFFER as u64);
    let cmdsize = CmdSize(TPMCRBBUF_LEN);
    let rspsize = RspSize(TPMCRBBUF_LEN);

    write_tpm_reg(locality, TPM_CRB_CTRL_CMD_ADDR, &cmdaddr.to_le_bytes());
    write_tpm_reg(locality, TPM_CRB_CTRL_CMD_SIZE, &cmdsize.to_le_bytes());
    write_tpm_reg(locality, TPM_CRB_CTRL_RSP_ADDR, &rspaddr.to_le_bytes());
    write_tpm_reg(locality, TPM_CRB_CTRL_RSP_SIZE, &rspsize.to_le_bytes());

    //write command to buffer
    write_tpm_reg(locality, TPM_CRB_DATA_BUFFER, in_value);

    // set start to execute the command
    let start = Start(0);
    start.set_start(1);
    write_tpm_reg(locality, TPM_CRB_CTRL_START, &start.to_le_bytes());
    // print tpm Start reg information

    // check for data available
    let mut i = 0;
    while i <= get_tpm_time_out(TpmTimeoutType::DataAvailTimeout) {
        read_tpm_reg(locality, TPM_CRB_CTRL_START, &start.to_le_bytes());
        if (start.start() == 0) {
            break;
        }
        else {
            // cpu_relax(); //TODO: 底层系统接口是什么？
            spin_loop();
        }
        i += 1;
    }
    
    if(i > get_tpm_time_out(TpmTimeoutType::DataAvailTimeout)) {
        // print error message
        // TODO: RelinquishControl ??
    }

    read_tpm_reg(locality, TPM_CRB_DATA_BUFFER, out_value);

    Ok(())

}

fn write_tpm_reg(locality:u32, reg:u32, data:&[u8]) {
    let address = TPM_LOCALITY_BASE_N(locality) | reg as u64;
    let mut current_ptr = address as *mut u8;
    unsafe {
        for &byte in data {
            ptr::write_volatile(current_ptr, byte);
            current_ptr = current_ptr.add(1);
        }
    }
}

fn read_tpm_reg(locality:u32, reg:u32, data:&mut [u8]) {
    let address = TPM_LOCALITY_BASE_N(locality) | reg as u64;
    let mut current_ptr = address as *mut u8;
    unsafe {
        for byte in data.iter_mut() {
            *byte = ptr::read_volatile(current_ptr);
            current_ptr = current_ptr.add(1);
        }
    }
}