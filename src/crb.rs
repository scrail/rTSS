use core::ptr;

use bitfield::bitfield;


/* Const Definition */
const TPM_LOCALITY_BASE:u64     = 0xfed40000;
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



bitfield! {
    struct Request(u32);
    pub _, set_cmd_ready: 0,0;
    pub _, set_go_idle: 1,1;  
}

// impl Request {
//     fn new(raw:u32) -> Self {
//         Self (raw)
//     }

//     fn is_cmd_ready(&self) -> bool {
//         self.0 & (1 << 0) != 0
//     }

//     fn set_cmd_ready(&mut self, value:bool) {
//         if value {
//             self.0 |= (1 << 0); 
//         } else {
//             self.0 &= !(1 << 0); 
//         }
//     }

//     fn is_go_idle(&self) -> bool {
//         self.0 & (1 << 1) != 0
//     }

//     fn set_go_idle(&mut self, value:bool) {
//         if value {
//             self.0 |= (1 << 1); 
//         } else {
//             self.0 &= !(1 << 1); 
//         }
//     }
// }

bitfield! {
    pub struct Status(u32);
    pub error, _: 0, 0;
    pub tpm_idle, _: 1, 1;

}

bitfield! {
    pub struct Cancel(u32);
    pub cancel, set_cancel: 0,0;
}

bitfield! {
    pub struct Start(u32);
    pub start, set_start: 0,0;
}

pub struct CmdSize(u32);
pub struct CmdAddr(u64);
pub struct RspSize(u32);
pub struct RspAddr(u64);

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

pub fn tpm_submit_cmd_crb(locality:u32, in_value:&[u8], in_size:u32, out_value:&mut [u8], out_size:u32) -> Result<(), TpmCrbError> {

    //locality range check

    // in out data check

    // locality validation check

    // TPM ready check


    // write command to TPM CRB buffer
    let cmdaddr = CmdAddr(TPM_LOCALITY_BASE_N(locality) | TPM_CRB_DATA_BUFFER as u64);
    let rspaddr = RspAddr(TPM_LOCALITY_BASE_N(locality) | TPM_CRB_DATA_BUFFER as u64);
    let cmdsize = CmdSize(TPMCRBBUF_LEN);
    let rspsize = RspSize(TPMCRBBUF_LEN);

    write_tpm_reg(locality, TPM_CRB_CTRL_CMD_ADDR, cmdaddr);
    write_tpm_reg(locality, TPM_CRB_CTRL_CMD_SIZE, cmdsize);
    write_tpm_reg(locality, TPM_CRB_CTRL_RSP_ADDR, rspaddr);
    write_tpm_reg(locality, TPM_CRB_CTRL_RSP_SIZE, rspsize);

    //write command to buffer
    write_tpm_reg(locality, TPM_CRB_DATA_BUFFER, in_value);

    // set start to execute the command
    let start = Start(0);
    start.set_start(1);
    write_tpm_reg(locality, TPM_CRB_CTRL_START, start);
    // print tpm Start reg information

    // check for data available
    let mut i = 0;
    while i <= TPM_DATA_AVAIL_TIME_OUT {
        read_tpm_reg(locality, TPM_CRB_CTRL_START, start);
        if (start.start() == 0) {
            break;
        }
        else {
            cpu_relax(); //TODO: 底层系统接口是什么？
        }
        i += 1;
    }
    
    if(i > TPM_DATA_AVAIL_TIME_OUT) {
        // print error message
        // TODO: RelinquishControl ??
    }

    read_tpm_reg(locality, TPM_CRB_DATA_BUFFER, out_value);

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