use crate::bitmap::{BitmapHandler, StorageReason};
use crate::config::FuzzerConfig;
use crate::fuzz_runner::ExitReason;
use crate::structured_fuzzer::custom_dict::CustomDict;
use crate::input::{Input, InputID, InputState};
use crate::structured_fuzzer::graph_mutator::graph_storage::{GraphStorage, VecGraph};
use crate::structured_fuzzer::mutator::InputQueue;
use crate::structured_fuzzer::random::distributions::Distributions;
use crate::structured_fuzzer::mutator::MutationStrategy;
use crate::structured_fuzzer::GraphSpec;

use std::collections::HashMap;

use std::sync::Arc;
use std::sync::RwLock;

#[derive(Serialize)]
pub struct QueueStats {
    num_inputs: usize,
    favqueue: Vec<usize>,
}

pub struct QueueData {
    bitmap_index_to_min_example: HashMap<usize, InputID>,
    //bitmap_index_to_max_example: HashMap<usize, InputID>,
    //ijon_index_to_max: HashMap<usize, InputID>,
    favqueue: Vec<InputID>,
    inputs: Vec<Arc<RwLock<Input>>>,
    input_to_iters_no_finds: Vec<usize>,
    bitmap_bits: Vec<usize>,
    bitmaps: BitmapHandler,
    next_input_id: usize,
}

#[derive(Clone)]
pub struct Queue {
    workdir: String,
    start_time: std::time::Instant,
    total_execs: Arc<RwLock<u64>>,
    data: Arc<RwLock<QueueData>>,
}

impl<'a> InputQueue for Queue {
    fn sample_for_splicing(&self, dist: &Distributions) -> Arc<VecGraph> {
        let data_lock = self.data.read().unwrap();
        let inputs = &data_lock.inputs;
        let i = dist.gen_range(0, inputs.len());
        let inp = inputs[i].read().unwrap().data.clone();
        return inp;
    }
}

impl Queue {
    pub fn new(config: &FuzzerConfig) -> Self {
        return Self {
            workdir: config.workdir_path.clone(),
            start_time: std::time::Instant::now(),
            total_execs: Arc::new(RwLock::new(0_u64)),
            data: Arc::new(RwLock::new(QueueData {
                bitmap_index_to_min_example: HashMap::new(),
                //bitmap_index_to_max_example: HashMap::new(),
                //ijon_index_to_max: HashMap::new(),
                inputs: vec![],
                favqueue: vec![],
                input_to_iters_no_finds: vec![],
                bitmap_bits: vec![],
                bitmaps: BitmapHandler::new(config.bitmap_size),
                next_input_id: 0,
            })),
        };
    }

    pub fn update_total_execs(&self, update: u64){
        let mut w = self.total_execs.write().unwrap();
        *w += update; 
    }

    pub fn get_total_execs(&self) -> u64 {
        *self.total_execs.read().unwrap()
    }

    pub fn get_runtime_as_secs_f32(&self) -> f32 {
        (std::time::Instant::now() - self.start_time).as_secs_f32()
    }

    pub fn write_stats(&self) {
        use std::fs::File;
        use std::fs::OpenOptions;
        use std::io::prelude::*;
        let dat = self.data.read().unwrap();
        let ser = QueueStats {
            num_inputs: dat.inputs.len(),
            favqueue: dat
                .favqueue
                .iter()
                .map(|id| id.as_usize())
                .collect::<Vec<_>>(),
        };
        let mut file = File::create(format!("{}/queue_stats.msgp", &self.workdir)).unwrap();
        rmp_serde::encode::write_named(&mut file, &ser).unwrap();

        let mut file = OpenOptions::new()
            .append(true)
            .create(true)
            .open(format!("{}/bitmap_stats.txt", &self.workdir))
            .unwrap();
        file.write_fmt(format_args!(
            "{},{}\n",
            (std::time::Instant::now() - self.start_time).as_secs_f32(),
            dat.bitmaps.normal_bitmap().bits().iter().filter(|b| **b > 0).count()
        ))
        .unwrap();
    }

    pub fn num_bits(&self) -> usize {
        return self.data.read().unwrap().bitmaps.normal_bitmap().bits().iter().filter(|b| **b > 0).count()
    }

    pub fn len(&self) -> usize {
        return self.data.read().unwrap().inputs.len();
    }

    pub fn num_crashes(&self) -> usize{
        self.data.read().unwrap().inputs.iter().filter(|i| matches!(i.read().unwrap().exit_reason, ExitReason::Crash(_)) ).count()
    }

    pub fn should_minimize(&self, inp: &Input) -> bool {
        // We generally don't want to minimize imported inputs - they might contain interesting state that's not obvious in coverage!
        if inp.found_by == MutationStrategy::SeedImport {
            return false;
        }
        match inp.exit_reason {
            ExitReason::Normal(_) => return inp.storage_reasons.iter().any(|rea| rea.has_new_byte() ),
            _ => return false,
        }
    }

    pub fn check_new_bytes(
        &mut self,
        run_bitmap: &[u8],
        ijon_max_map: &[u64],
        etype: &ExitReason,
        strat: MutationStrategy
    ) -> Option<Vec<StorageReason>> {
        let mut res = self.data
            .write()
            .unwrap()
            .bitmaps
            .check_new_bytes(run_bitmap, ijon_max_map, etype);
        if strat == MutationStrategy::SeedImport && *etype != ExitReason::Timeout{
            let mut reasons = res.take().unwrap_or(vec!());
            reasons.push(StorageReason::Imported);
            res = Some(reasons);
        }
        return res;
    }

    pub fn set_state(&mut self, inp: &Input, state: InputState) {
        let data = self.data.write().unwrap();
        assert!(inp.id.as_usize() < data.inputs.len());
        data.inputs[inp.id.as_usize()].write().unwrap().state = state;
    }

    pub fn set_custom_dict(&mut self, inp: &Input, custom_dict: CustomDict){
        let data = self.data.write().unwrap();
        assert!(inp.id.as_usize() < data.inputs.len());
        data.inputs[inp.id.as_usize()].write().unwrap().custom_dict = custom_dict;
    }

    pub fn register_best_input_for_bitmap(data: &mut std::sync::RwLockWriteGuard<QueueData>, bitmap_index: usize, input_id: InputID, spec: &GraphSpec, new_len: usize){
        if !data.bitmap_index_to_min_example.contains_key(&bitmap_index) {
            data.bitmap_bits.push(bitmap_index);
            data.bitmap_index_to_min_example.insert(bitmap_index, input_id);
        }
        let old_entry = data
            .bitmap_index_to_min_example
            .get_mut(&bitmap_index)
            .unwrap()
            .as_usize();
        if data.inputs[old_entry].read().unwrap().data.node_len(&spec) > new_len {
            data.bitmap_index_to_min_example.insert(bitmap_index, input_id);
        }
    }

    pub fn register_best_input_for_ijon_max(data: &mut std::sync::RwLockWriteGuard<QueueData>, ijon_index: usize, input_id: InputID){
        data.bitmap_index_to_min_example.insert(ijon_index, input_id);
    }

    pub fn add(&mut self, mut input: Input, spec: &GraphSpec) -> Option<InputID> {
        assert_eq!(input.id, InputID::invalid());
        if input.data.node_len(spec) == 0 {
            return None;
        }
        let id;
        match input.exit_reason {
            ExitReason::Normal(_) | ExitReason::Crash(_) => {
                //let has_new_bytes = input.storage_reasons.iter().any(|r| r.has_new_byte() );
                //let should_update_favs;
                {
                    let mut data = self.data.write().unwrap();
                    //should_update_favs = has_new_bytes;
                    id = InputID::new(data.inputs.len());
                    input.id = id;
                    let new_len = input.data.node_len(&spec);
                    let input = Arc::new(RwLock::new(input));
                    data.inputs.push(input.clone());
                    data.input_to_iters_no_finds.push(0);

                    for r in input.read().unwrap().storage_reasons.iter() {
                        match r {
                            StorageReason::Bitmap(reason) => Self::register_best_input_for_bitmap(&mut data, reason.index, id, spec, new_len),
                            StorageReason::IjonMax(reason) => Self::register_best_input_for_ijon_max(&mut data,reason.index, id),
                            StorageReason::Imported => {},
                        }
                    }
                }
                //if should_update_favs {
                    self.calc_fav_bits();
                //}
                self.write_stats();
            }
            /*
            ExitReason::Crash(_) => return None, //println!("NEW crash found!"),
            */
            _ => {
                //println!("ignoring input {:?}", input.exit_reason);
                return None;
            }
        }
        return Some(id);
    }

    pub fn calc_fav_bits(&mut self) {
        let mut favids = vec![];
        let mut ijon_slot_to_fav = HashMap::<usize,(u64,InputID)>::new();
        //println!("==== update favbit queue store ====");
        {
            //const IJON_MAX_SIZE: usize = 256;
            let data = self.data.read().unwrap();
            let mut bits = vec![0u8; data.bitmaps.size()];
            for input in data.inputs.iter().rev() {
                let inp = input.read().unwrap();
                if inp.storage_reasons.iter().any(|s| s.has_new_byte() ) {
                    //found new bytes
                    let has_new_bits = inp
                    .bitmap
                    .bits()
                    .iter()
                    .enumerate()
                    .any(|(i, v)| bits[i] == 0 && *v > 0);
                    if  has_new_bits {
                        for (i, v) in inp.bitmap.bits().iter().enumerate() {
                            if *v != 0 {
                                bits[i] = 1;
                            }
                        }
                        favids.push(inp.id);
                    }
                    for (i, v) in inp.bitmap.ijon_max_vals().iter().enumerate() {
                        if *v != 0 && (!ijon_slot_to_fav.contains_key(&i) ||  ijon_slot_to_fav[&i].0<*v) {
                            ijon_slot_to_fav.insert(i,(*v,inp.id));
                        }
                    }
                } else if inp.found_by == MutationStrategy::SeedImport{
                    favids.push(inp.id);
                }
            }
        }
        for (i,(_val,id)) in ijon_slot_to_fav.iter(){
            //use std::time::SystemTime;
            println!("[!] store ijon {:?} for {} => {:x}",
                //SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs(),
                id,i,_val);
            if !favids.contains(id) { //TODO FIX O(n)
                favids.push(*id); 
            }
        }
        {
            let mut data = self.data.write().unwrap();
            /* 
            println!(
                "calc favbits ({}) out of {}",
                favids.len(),
                data.inputs.len()
            );
            */
            data.favqueue = favids;
        }
    }

    pub fn schedule(&self, rng: &Distributions) -> Arc<RwLock<Input>> {
        let data = self.data.read().unwrap();
        let id: usize;
        
        if data.favqueue.len() > 0 && rng.gen::<u32>() % 10 <= 6 {
            id = data.favqueue[rng.gen_range(0, data.favqueue.len())].as_usize();
        } else if rng.gen::<u32>() % 8 <= 5 && data.bitmap_bits.len() != 0 {
            let bit = &data.bitmap_bits[rng.gen_range(0, data.bitmap_bits.len())];
            id = data
                .bitmap_index_to_min_example
                .get(bit)
                .unwrap()
                .as_usize();
        } else {
            id = rng.gen_range(0, data.inputs.len());
        }
        
        //id = rng.gen_range(0, data.inputs.len());
        data.inputs[id].clone()
    }

    pub fn next_id(&mut self) -> usize {
        let mut data = self.data.write().unwrap();
        data.next_input_id += 1;
        return data.next_input_id;
    }

    pub fn get_input(&self, id: InputID) -> Arc<RwLock<Input>> {
        let data = self.data.read().unwrap();
        return data.inputs[id.as_usize()].clone();
    }

    pub fn update_iters_no_finds(&self, id: InputID, has_new_finds: bool) -> usize {
        let mut data = self.data.write().unwrap();
        let value = &mut data.input_to_iters_no_finds[id.as_usize()];
        if has_new_finds {
            *value = 0;
        } else {
            *value += 1;
        }
        *value
    }
}
