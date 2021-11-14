use crate::fuzz_runner::ExitReason;

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum StorageReason{
    Bitmap(BitmapStorageReason),
    IjonMax(IjonMaxStorageReason),
    Imported,
}

impl StorageReason{
    pub fn still_valid(&self, bitmap: &[u8], ijon_max: &[u64]) -> bool{
        match self{
            Self::Bitmap(r) => bitmap[r.index] > r.old,
            Self::IjonMax(r) => ijon_max[r.index] > r.old,
            Self::Imported => true,
        }
    }

    pub fn has_new_byte(&self) -> bool {
        match self{
            Self::Bitmap(r) => r.old == 0,
            Self::IjonMax(_r) => true,
            Self::Imported => false,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct BitmapStorageReason {
    pub index: usize,
    pub old: u8,
    pub new: u8,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct IjonMaxStorageReason {
    pub index: usize,
    pub old: u64,
    pub new: u64,
}


pub struct BitmapHandler {
    normal: Bitmap,
    crash: Bitmap,
    timeout: Bitmap,
    invalid_write_to_payload: Bitmap,
    size: usize,
}

impl BitmapHandler {
    pub fn new(size: usize) -> Self {
        return Self {
            normal: Bitmap::new(size),
            crash: Bitmap::new(size),
            timeout: Bitmap::new(size),
            invalid_write_to_payload: Bitmap::new(size),
            size,
        };
    }

    pub fn check_new_bytes(
        &mut self,
        run_bitmap: &[u8],
        ijon_max_map: &[u64],
        etype: &ExitReason,
    ) -> Option<Vec<StorageReason>> {
        match etype {
            ExitReason::Normal(_) => return self.normal.check_new_bytes(run_bitmap, ijon_max_map),
            ExitReason::Crash(_) => return self.crash.check_new_bytes(run_bitmap, ijon_max_map),
            ExitReason::Timeout => return self.timeout.check_new_bytes(run_bitmap, ijon_max_map),
            ExitReason::InvalidWriteToPayload(_) => {
                return self.invalid_write_to_payload.check_new_bytes(run_bitmap, ijon_max_map)
            }
            _ => return None,
        }
    }

    pub fn size(&self) -> usize {
        self.size
    }
    
    pub fn normal_bitmap(&self) -> &Bitmap{
        return &self.normal
    }
}

#[derive(Clone)]
pub struct Bitmap {
    bits: Vec<u8>,
    ijon_max: Vec<u64>,
}

impl Bitmap {
    pub fn new(size: usize) -> Self {
        const IJON_MAX_SIZE: usize=256usize; 
        return Self {
            bits: vec![0; size],
            ijon_max: vec![0; IJON_MAX_SIZE],
        };
    }

    pub fn new_from_buffer(buff: &[u8], ijon_buff: &[u64]) -> Self {
        return Self {
            bits: buff.to_vec(),
            ijon_max: ijon_buff.to_vec(),
        };
    }

    pub fn check_new_bytes(&mut self, run_bitmap: &[u8], run_ijon: &[u64]) -> Option<Vec<StorageReason>> {
        assert_eq!(self.bits.len(), run_bitmap.len());
        let mut res = None;
        for (i, (old, new)) in self.bits.iter_mut().zip(run_bitmap.iter()).enumerate() {
            if *new > *old && *old == 0{
                if res.is_none() {
                    res = Some(vec![]);
                }
                res.as_mut().unwrap().push(StorageReason::Bitmap(BitmapStorageReason {
                    index: i,
                    old: *old,
                    new: *new,
                }));
                *old = *new;
            }
        }
        for (i, (old, new)) in self.ijon_max.iter_mut().zip(run_ijon.iter()).enumerate() {
            if *new > *old {
                if res.is_none() {
                    res = Some(vec![]);
                }
                res.as_mut().unwrap().push(StorageReason::IjonMax(IjonMaxStorageReason {
                    index: i,
                    old: *old,
                    new: *new,
                }));
                *old = *new;
            }
        }
        return res;
    }

    pub fn bits(&self) -> &[u8] {
        return &self.bits;
    }

    pub fn ijon_max_vals(&self) -> &[u64] {
        return &self.ijon_max;
    }
}
