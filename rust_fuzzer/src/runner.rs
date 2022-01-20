use libnyx::NyxProcess;
use libnyx::NyxReturnValue;

use std::error::Error;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ExitReason {
    Normal(i32),
    Timeout,
    Crash(Vec<u8>),
    FuzzerError,
    InvalidWriteToPayload(Vec<u8>),
}

impl ExitReason {
    pub fn name(&self) -> &str{
        use ExitReason::*;
        match self {
            Normal(_) => return "normal",
            Timeout => return "timeout",
            Crash(_) => return "crash",
            InvalidWriteToPayload(_) => return "invalid_write_to_payload_buffer",
            FuzzerError => unreachable!(),
        }
    }
}


#[derive(Debug, Copy, Clone)]
#[repr(C, packed(1))]
pub struct InterpreterData{
    pub executed_opcode_num: u32
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct IjonData {
    pub max_data: [u64;256],
}

#[derive(Copy, Clone)]
#[repr(C, packed(1))]
pub struct SharedFeedbackData{
    pub interpreter: InterpreterData,
    pad: [u8; 0x1000/2-std::mem::size_of::<InterpreterData>()],
    pub ijon: IjonData,
}


#[derive(Debug,Clone,Eq,PartialEq,Hash)]
pub struct TestInfo { 
    pub ops_used: u32,
    pub exitreason: ExitReason 
}

#[derive(Debug,Clone,Eq,PartialEq,Hash)]
pub enum RedqueenBPType{
    Str,
    Cmp,
    Sub,
}

impl RedqueenBPType{
    pub fn new(data:&str) -> Self {
        match data {
            "STR" => return Self::Str,
            "CMP" => return Self::Cmp,
            "SUB" => return Self::Sub,
            _ => panic!("unknown reqdueen bp type {}",data),
        }
    }
}

#[derive(Debug,Clone,Eq,PartialEq,Hash)]
pub struct RedqueenEvent{
    pub addr: u64,
    pub bp_type: RedqueenBPType,
    pub lhs: Vec<u8>,
    pub rhs: Vec<u8>,
    pub imm: bool,
}

impl RedqueenEvent{
    pub fn new(line: &str) -> Self{
        lazy_static! {
            static ref RE : regex::Regex = regex::Regex::new(r"([0-9a-fA-F]+)\s+(CMP|SUB|STR)\s+(\d+)\s+([0-9a-fA-F]+)-([0-9a-fA-F]+)(\sIMM)?").unwrap();
        }
        if let Some(mat) = RE.captures(line){
            let addr_s = mat.get(1).unwrap().as_str();
            let type_s = mat.get(2).unwrap().as_str();
            //let bits_s =mat.get(3);
            let lhs = mat.get(4).unwrap().as_str();
            let rhs = mat.get(5).unwrap().as_str();
            let imm = mat.get(6).map(|_x| true).unwrap_or(false);
            return Self{addr: u64::from_str_radix(addr_s, 16).unwrap(), bp_type: RedqueenBPType::new(type_s), lhs: hex::decode(lhs).unwrap(), rhs: hex::decode(rhs).unwrap(), imm};
        }
        panic!("couldn't parse redqueen line {}",line); 
    }
}

#[derive(Debug,Clone,Eq,PartialEq,Hash)]
pub struct RedqueenInfo {pub bps: Vec<RedqueenEvent>}

pub struct CFGInfo {}

pub trait FuzzRunner {
    fn run_test(&mut self) -> Result<TestInfo, Box<dyn Error>>;
    fn run_redqueen(&mut self, workdir: &str, qemu_id: usize) -> Result<RedqueenInfo, Box<dyn Error>>;
    fn run_cfg(&mut self) -> Result<CFGInfo, Box<dyn Error>>;

    fn run_create_snapshot(&mut self) -> bool;
    fn delete_snapshot(&mut self) -> Result<(), Box<dyn Error>>;

    fn shutdown(&mut self) -> Result<(), Box<dyn Error>>;

    fn input_buffer(&mut self) -> &mut [u8];
    fn bitmap_buffer(&self) -> &[u8];
    fn bitmap_buffer_size(&self) -> usize;
    fn ijon_max_buffer(&self) -> &[u64];

    fn set_timeout(&mut self, timeout: std::time::Duration);

    fn parse_redqueen_data(&self, data: &str) -> RedqueenInfo{
        let bps = data.lines().map(|line| RedqueenEvent::new(line)).collect::<Vec<_>>();
        return RedqueenInfo{bps}
    }
    fn parse_redqueen_file(&self, path: &str) -> RedqueenInfo{
        self.parse_redqueen_data(&std::fs::read_to_string(path).unwrap())
    }
}

fn ijon_buffer(process: &NyxProcess) -> &SharedFeedbackData{
    /* FML */
    unsafe {
        (process.ijon_buffer().as_ptr() as *mut SharedFeedbackData).as_mut().unwrap()
    }
}

impl FuzzRunner for NyxProcess {
    fn run_test(&mut self) -> Result<TestInfo, Box<dyn Error>>{
        
        let res = match self.exec(){
            NyxReturnValue::Normal                  => ExitReason::Normal(0),
            NyxReturnValue::Crash                   => ExitReason::Crash(self.aux_misc()),
            NyxReturnValue::Timeout                 => ExitReason::Timeout,
            NyxReturnValue::InvalidWriteToPayload   => ExitReason::InvalidWriteToPayload(self.aux_misc()),
            NyxReturnValue::Abort                   => panic!("Abort called!\n"),
            _                                       => ExitReason::FuzzerError,
        };

        let feedback_buffer = ijon_buffer(self);
        let ops_used = feedback_buffer.interpreter.executed_opcode_num;
        Ok(TestInfo {ops_used, exitreason: res})
    }

    fn run_redqueen(&mut self, workdir: &str, qemu_id: usize) -> Result<RedqueenInfo, Box<dyn Error>>{
        self.option_set_redqueen_mode(true);
        self.option_apply();
        self.exec();
        self.option_set_redqueen_mode(false);
        self.option_apply();

        let rq_file = format!("{}/redqueen_workdir_{}/redqueen_results.txt", workdir, qemu_id);
        return Ok(self.parse_redqueen_file(&rq_file));
    }

    fn run_cfg(&mut self) -> Result<CFGInfo, Box<dyn Error>> {
        self.option_set_trace_mode(true);
        self.option_apply();
        self.exec();
        self.option_set_trace_mode(false);
        self.option_apply();

        return Ok(CFGInfo {});
    }

    fn run_create_snapshot(&mut self) -> bool{
        assert_eq!(self.aux_tmp_snapshot_created(), false);
        self.exec();
        //println!("=======> CREATED {}", self.aux_tmp_snapshot_created());
        self.aux_tmp_snapshot_created()
    }

    fn delete_snapshot(&mut self) -> Result<(), Box<dyn Error>>{
        //println!("=======> DELETE");
        if self.aux_tmp_snapshot_created() {
            self.option_set_delete_incremental_snapshot(true);
            self.option_apply();
            self.exec();
            if self.aux_tmp_snapshot_created() {
                println!("=======> ???");
                assert!(false);
                //println!("AUX BUFFER {:#?}",self.aux);
            }
            assert_eq!(self.aux_tmp_snapshot_created(), false);
        }
        return Ok(());
    }

    fn shutdown(&mut self) -> Result<(), Box<dyn Error>>{
        self.shutdown();
        return Ok(());
    }

    fn input_buffer(&mut self) -> &mut [u8]{
        self.input_buffer_mut()
    }

    fn bitmap_buffer(&self) -> &[u8]{
        self.bitmap_buffer()
    }

    fn bitmap_buffer_size(&self) -> usize{
        self.bitmap_buffer_size()
    }

    fn ijon_max_buffer(&self) -> &[u64]{
        let feedback_buffer = ijon_buffer(self);
        &feedback_buffer.ijon.max_data
    }

    fn parse_redqueen_data(&self, data: &str) -> RedqueenInfo{
        let bps = data.lines().map(|line| RedqueenEvent::new(line)).collect::<Vec<_>>();
        return RedqueenInfo{bps}
    }

    fn parse_redqueen_file(&self, path: &str) -> RedqueenInfo{
        self.parse_redqueen_data(&std::fs::read_to_string(path).unwrap())
    }

    fn set_timeout(&mut self, timeout: std::time::Duration){
        self.option_set_timeout(timeout.as_secs() as u8, timeout.subsec_micros() as u32);
        self.option_apply();
    }

}