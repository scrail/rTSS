mod constants;
mod types;
mod crb_core;

use core::{hint::spin_loop, ptr::{self, read}};

use constants::*;

use types::*;

use crate::print::*; 

#[repr(C,packed)]
pub struct CrbControlArea {
    request: TpmRegCtrlRequest,
    status: TpmRegCtrlStatus,
    cancel: TpmRegCtrlCancel,
    start: TpmRegCtrlStart,
    _reserved: u64,
    cmdsize: TpmRegCtrlCmdSize,
    cmdaddr: TpmRegCtrlCmdAddr,
    rspsize: TpmRegCtrlRspSize,
    rspaddr: TpmRegCtrlRspAddr,
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

fn tpm_validate_locality_crb(locality:u32) -> bool {
    
    let mut i = TPM_VALIDATE_LOCALITY_TIME_OUT;
    let reg_loc_state_bytes = [0u8;4];
    while i > 0 {
        read_tpm_reg(locality, TPM_REG_LOC_STATE, &mut reg_loc_state_bytes);
        let reg_loc_state = TpmRegLocState::from_le_bytes(reg_loc_state_bytes);
        if reg_loc_state.tpm_reg_valid_sts() == 1
            && reg_loc_state.loc_assigned() == 1
            && reg_loc_state.active_locality() == locality 
        {
            printk("TPM: reg_loc_state._raw[0]"); //?
            return true;
        }
        spin_loop();
        i -= 1;
    }

    printk(concat!(TBOOT_ERR,"TPM: tpm_validate_locality_crb timeout\n"));
    return false;
}

fn tpm_send_cmd_ready_status_crb(locality:u32) -> bool {
    let mut raw_bytes = [0u8;4]; //TODO
    read_tpm_reg(locality, TPM_CRB_CTRL_STS, &mut raw_bytes);
    let status = TpmRegCtrlStatus::from_le_bytes(raw_bytes);

    if status.tpm_idle() == 1 {
        let request:TpmRegCtrlRequest = TpmRegCtrlRequest::new();//tb_memset?
        request.set_cmd_ready(1);
        write_tpm_reg(locality, TPM_CRB_CTRL_REQ, request.to_le_bytes());
        return true;
    }

    let request:TpmRegCtrlRequest = TpmRegCtrlRequest::new();//tb_memset?
    request.set_go_idle(1);
    write_tpm_reg(locality, TPM_CRB_CTRL_REQ, request.to_le_bytes());

    let i = 0;
    while i <= get_tpm_time_out(TpmTimeoutType::DataAvailTimeout) {
        read_tpm_reg(locality, TPM_CRB_CTRL_REQ, &mut raw_bytes);
        if request.go_idle() == 0 {
            break;
        } else {
            spin_loop();
            read_tpm_reg(locality, TPM_CRB_CTRL_REQ, &mut raw_bytes);// TODO:又读一遍？
        }
        i += 1;
    }
    if i > get_tpm_time_out(TpmTimeoutType::DataAvailTimeout) {
        printk(TBOOT_ERR "TPM: reg_ctrl_request.goidle timeout!\n");
        return false;
    }

    read_tpm_reg(locality, TPM_CRB_CTRL_STS, &mut raw_bytes);
    let status = TpmRegCtrlStatus::from_le_bytes(raw_bytes);

    let request:TpmRegCtrlRequest = TpmRegCtrlRequest::new();//tb_memset?
    request.set_cmd_ready(1);
    write_tpm_reg(locality, TPM_CRB_CTRL_REQ, request.to_le_bytes());

    read_tpm_reg(locality, TPM_CRB_CTRL_STS, &mut raw_bytes);
    let status = TpmRegCtrlStatus::from_le_bytes(raw_bytes);
    true
}

fn tpm_wait_cmd_ready_crb(locality:u32) -> bool {

    tpm_send_cmd_ready_status_crb(locality);
    let mut i = 0;
    while i <= get_tpm_time_out(TpmTimeoutType::CmdReadyTimeout) {
        if tpm_check_cmd_ready_status_crb(locality) {
            break;
        } else {
            spin_loop();
        }
        i += 1;
    }

    if i > get_tpm_time_out(TpmTimeoutType::CmdReadyTimeout) {
        printk(TBOOT_INFO "TPM: tpm timeout for command_ready\n");
        return false;
    }
    true
}

pub fn tpm_submit_cmd_crb(locality:u32, in_value: &[u8], in_size:u32, out_value:&mut [u8], out_size:u32) -> Result<(), TpmCrbError> {

    //locality range check
    if locality >= TPM_NR_LOCALITIES {
        printk();
        return Err(TpmCrbError::InvalidLocality)
    }

    // in out data check
    if in_value.len() < CMD_HEAD_SIZE || out_value.len() < RSP_HEAD_SIZE {
        printk();
        return Err(TpmCrbError::InvalidBufferSize);
    }

    // locality validation check
    if !tpm_validate_locality_crb(locality) {
        printk();
        return Err(TpmCrbError::LocalityNotOpen);
    }

    // TPM ready check
    if !tpm_wait_cmd_ready_crb(locality) {
        return Err(TpmCrbError::LocalityNotOpen);
    }


    // write command to TPM CRB buffer
    let cmdaddr = TpmRegCtrlCmdAddr(TPM_LOCALITY_BASE_N(locality) | TPM_CRB_DATA_BUFFER as u64);
    let rspaddr = TpmRegCtrlRspAddr(TPM_LOCALITY_BASE_N(locality) | TPM_CRB_DATA_BUFFER as u64);
    let cmdsize = TpmRegCtrlCmdSize(TPMCRBBUF_LEN);
    let rspsize = TpmRegCtrlRspSize(TPMCRBBUF_LEN);

    write_tpm_reg(locality, TPM_CRB_CTRL_CMD_ADDR, &cmdaddr.to_le_bytes());
    write_tpm_reg(locality, TPM_CRB_CTRL_CMD_SIZE, &cmdsize.to_le_bytes());
    write_tpm_reg(locality, TPM_CRB_CTRL_RSP_ADDR, &rspaddr.to_le_bytes());
    write_tpm_reg(locality, TPM_CRB_CTRL_RSP_SIZE, &rspsize.to_le_bytes());

    //write command to buffer
    write_tpm_reg(locality, TPM_CRB_DATA_BUFFER, in_value);

    // set start to execute the command
    let start = TpmRegCtrlStart(0);
    start.set_start(1);
    write_tpm_reg(locality, TPM_CRB_CTRL_START, &start.to_le_bytes());
    // print tpm Start reg information

    // check for data available
    let mut i = 0;
    while i <= get_tpm_time_out(TpmTimeoutType::DataAvailTimeout) {
        read_tpm_reg(locality, TPM_CRB_CTRL_START, &mut start.to_le_bytes());
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