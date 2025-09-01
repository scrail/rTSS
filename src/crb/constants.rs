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
pub const CMD_HEAD_SIZE  :usize         =10;
pub const RSP_HEAD_SIZE  :usize         =10;
pub const CMD_SIZE_OFFSET:u64         =2;
pub const CMD_CC_OFFSET  :u64         =6;
pub const RSP_SIZE_OFFSET:u64         =2;
pub const RSP_RST_OFFSET :u64         =6;

/*
 * The term timeout applies to timings between various states
 * or transitions within the interface protocol.
 */
pub const TIMEOUT_UNIT:u64    =(0x100000 / 330);	/* ~1ms, 1 tpm r/w need > 330ns */
pub const TIMEOUT_A   :u64    =750;     /* 750ms */
pub const TIMEOUT_B   :u64    =2000;    /* 2s */
pub const TIMEOUT_C   :u64    =75000;   /* 750ms */
pub const TIMEOUT_D   :u64    =750;     /* 750ms */

pub const TPM_VALIDATE_LOCALITY_TIME_OUT:u64 =  0x100;


/*
 * The TCG maintains a registry of all algorithms that have an
 * assigned algorithm ID. That registry is the definitive list
 * of algorithms that may be supported by a TPM.
 */
pub const TPM_ALG_ERROR         :u64    =0x0000;
pub const TPM_ALG_FIRST         :u64    =0x0001;
pub const TPM_ALG_RSA           :u64    =0x0001;
pub const TPM_ALG_DES           :u64    =0x0002;
pub const TPM_ALG_3DES          :u64    =0x0003;
pub const TPM_ALG_SHA           :u64    =0x0004;
pub const TPM_ALG_SHA1          :u64    =0x0004;
pub const TPM_ALG_HMAC          :u64    =0x0005;
pub const TPM_ALG_AES           :u64    =0x0006;
pub const TPM_ALG_MGF1          :u64    =0x0007;
pub const TPM_ALG_KEYEDHASH     :u64    =0x0008;
pub const TPM_ALG_XOR           :u64    =0x000A;
pub const TPM_ALG_SHA256        :u64    =0x000B;
pub const TPM_ALG_SHA384        :u64    =0x000C;
pub const TPM_ALG_SHA512        :u64    =0x000D;
pub const TPM_ALG_WHIRLPOOL512  :u64    =0x000E;
pub const TPM_ALG_NULL          :u64    =0x0010;
pub const TPM_ALG_SM3_256       :u64    =0x0012;
pub const TPM_ALG_SM4           :u64    =0x0013;
pub const TPM_ALG_RSASSA        :u64    =0x0014;
pub const TPM_ALG_RSAES         :u64    =0x0015;
pub const TPM_ALG_RSAPSS        :u64    =0x0016;
pub const TPM_ALG_OAEP          :u64    =0x0017;
pub const TPM_ALG_ECDSA         :u64    =0x0018;
pub const TPM_ALG_ECDH          :u64    =0x0019;
pub const TPM_ALG_ECDAA         :u64    =0x001A;
pub const TPM_ALG_SM2           :u64    =0x001B;
pub const TPM_ALG_ECSCHNORR     :u64    =0x001C;
pub const TPM_ALG_KDF1_SP800_56a:u64    =0x0020;
pub const TPM_ALG_KDF2          :u64    =0x0021;
pub const TPM_ALG_KDF1_SP800_108:u64    =0x0022;
pub const TPM_ALG_ECC           :u64    =0x0023;
pub const TPM_ALG_SYMCIPHER     :u64    =0x0025;
pub const TPM_ALG_CTR           :u64    =0x0040;
pub const TPM_ALG_OFB           :u64    =0x0041;
pub const TPM_ALG_CBC           :u64    =0x0042;
pub const TPM_ALG_CFB           :u64    =0x0043;
pub const TPM_ALG_ECB           :u64    =0x0044;
pub const TPM_ALG_LAST          :u64    =0x0044;
pub const TPM_ALG_MAX_NUM       :usize    =(TPM_ALG_LAST - TPM_ALG_ERROR) as usize;


/* Const Definition */
pub const TPM_NR_LOCALITIES:u32      = 5;
pub const TPM_LOCALITY_BASE:u64      = 0xfed40000;
pub const TPM_LOCALITY_0:u64         = TPM_LOCALITY_BASE;
pub const TPM_LOCALITY_1:u64         = TPM_LOCALITY_BASE | 0x1000;
pub const TPM_LOCALITY_2:u64         = TPM_LOCALITY_BASE | 0x2000;
pub const TPM_LOCALITY_3:u64         = TPM_LOCALITY_BASE | 0x3000;
pub const TPM_LOCALITY_4:u64         = TPM_LOCALITY_BASE | 0x4000;


//-----------------------------------------------------------------------------
// CRB I/F related definitions, see TCG PC Client Platform TPM Profile (PTP) Specification, Level 00 Revision 00.43
//-----------------------------------------------------------------------------
pub const TPM_REG_LOC_STATE:u32       =   0x00;
pub const TPM_REG_LOC_CTRL:u32        =    0x8;
pub const TPM_LOCALITY_STS:u32        =   0x0C;
pub const TPM_INTERFACE_ID:u32        =   0x30;
pub const TPM_CONTROL_AREA:u32        =   0x40;
pub const TPM_CRB_CTRL_REQ:u32        =   0x40;
pub const TPM_CRB_CTRL_STS:u32        =   0x44;
pub const TPM_CRB_CTRL_CANCEL:u32     =   0x48;
pub const TPM_CRB_CTRL_START:u32      =   0x4C;
pub const TPM_CRB_CTRL_CMD_SIZE:u32   =   0x58;
pub const TPM_CRB_CTRL_CMD_ADDR:u32   =   0x5C;
pub const TPM_CRB_CTRL_CMD_HADDR:u32  =   0x60;
pub const TPM_CRB_CTRL_RSP_SIZE:u32   =   0x64;
pub const TPM_CRB_CTRL_RSP_ADDR:u32   =   0x68;
pub const TPM_CRB_DATA_BUFFER:u32     =   0x80;
pub const TPMCRBBUF_LEN:u32           =  0xF80;     //3968 Bytes
