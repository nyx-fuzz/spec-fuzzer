use crate::bitmap::StorageReason;
use crate::bitmap::{Bitmap, BitmapHandler};
use crate::fuzz_runner::FuzzRunner;
use crate::fuzz_runner::{ExitReason, RedqueenInfo, TestInfo};
use crate::fuzz_runner::{RedqueenEvent,RedqueenBPType};
use crate::helpers;
use crate::input::{Input, InputID, InputState};
use crate::queue::Queue;
use crate::romu::*;
use crate::structured_fuzzer::custom_dict::{CustomDict,DictEntry};
use crate::structured_fuzzer::graph_mutator::graph_storage::{RefGraph, VecGraph};
use crate::structured_fuzzer::graph_mutator::spec::GraphSpec;
use crate::structured_fuzzer::mutator::MutationStrategy;
use crate::structured_fuzzer::mutator::{Mutator, MutatorSnapshotState};
use crate::structured_fuzzer::random::distributions::Distributions;
use crate::structured_fuzzer::GraphStorage;

use crate::config::{FuzzerConfig, SnapshotPlacement};

use std::collections::{HashMap,HashSet};
//use std::error::Error;
use std::rc::Rc;
use std::fs::OpenOptions;
//use std::io::Write;
use std::str;

extern crate colored; // not needed in Rust 2018

use colored::*;

/*
pub struct StructuredForkServer {
    srv: ForkServer,
    input_mmap: &'static mut [u8],
}

impl StructuredForkServer {
    pub fn new(cfg: &ForkServerConfig, fuzz_cfg: &FuzzerConfig) -> Self {
        let input_path = "/dev/shm/input_data";
        let mut cfg = (*cfg).clone();
        cfg.env.push(format!("STRUCT_INPUT_PATH={}", input_path));
        let input_mmap = helpers::make_shared_data_from_path(input_path, cfg.input_size);
        let srv = ForkServer::new(&cfg, &fuzz_cfg);

        return Self { srv, input_mmap };
    }
}

impl FuzzRunner for StructuredForkServer {
    fn run_test(&mut self) -> Result<TestInfo, Box<dyn Error>> {
        self.srv.run_test()
    }

    fn run_redqueen(&mut self) -> Result<RedqueenInfo, Box<dyn Error>> {
        self.srv.run_redqueen()
    }
    fn run_cfg(&mut self) -> Result<CFGInfo, Box<dyn Error>> {
        self.srv.run_cfg()
    }
    fn run_create_snapshot(&mut self) -> bool {
        unreachable!();
    }
    fn delete_snapshot(&mut self) -> Result<(), Box<dyn Error>> { 
        unreachable!(); 
    }

    fn shutdown(self) -> Result<(), Box<dyn Error>> {
        self.srv.shutdown()
    }
    fn input_buffer(&mut self) -> &mut [u8] {
        return &mut self.input_mmap;
    }
    fn bitmap_buffer(&self) -> &[u8] {
        self.srv.bitmap_buffer()
    }
    fn ijon_max_buffer(&self) -> &[u64] {
        unreachable!()
    }
    fn set_input_size(&mut self, _size: usize) {}
}
*/
pub trait GetStructStorage {
    fn get_struct_storage(&mut self, checksum: u64) -> RefGraph;
}

impl<T: FuzzRunner> GetStructStorage for T {
    fn get_struct_storage(&mut self, checksum: u64) -> RefGraph {
        return RefGraph::new_from_slice(self.input_buffer(), checksum);
    }
}

pub struct FuzzStats{
    execs: usize,
    start_time: std::time::Instant,
    last_dump_time: std::time::Instant,
}

#[derive(Serialize)]
struct SerFuzzStats{
    execs: usize,
    uptime: f64,
    overall_execs_per_sec: f64,
    last_1000_execs_time: f64,
    last_1000_execs_per_sec: f64,
}

impl FuzzStats{
    pub fn new()->Self{
        return Self{
            execs: 0, 
            start_time: std::time::Instant::now(),
            last_dump_time: std::time::Instant::now(),
        }
    }

    pub fn add_execution(&mut self, cfg: &FuzzerConfig, queue: &Queue){
        if self.execs % 1000 == 0{
            self.write_stats(cfg);
            queue.update_total_execs(1000);
        }
        self.execs += 1;
    }

    pub fn write_stats(&mut self, cfg: &FuzzerConfig){
        let mut file = std::fs::File::create(format!("{}/thread_stats_{}.msgp", cfg.workdir_path, cfg.thread_id)).unwrap();
        let uptime = self.start_time.elapsed().as_secs_f64();
        let last_1000_execs_time = self.last_dump_time.elapsed().as_secs_f64();
        let ser = SerFuzzStats{
            execs: self.execs, 
            uptime,
            last_1000_execs_time,
            overall_execs_per_sec: (self.execs as f64) / uptime,
            last_1000_execs_per_sec: 1000.0/last_1000_execs_time,
        };
        self.last_dump_time = std::time::Instant::now();
        rmp_serde::encode::write_named(&mut file, &ser).unwrap();
    }
}

pub struct StructFuzzer<Fuzz: FuzzRunner + GetStructStorage> {
    fuzzer: Fuzz,
    queue: Queue,
    master_rng: RomuPrng,
    rng: Distributions,
    mutator: Mutator,
    bitmaps: BitmapHandler,
    config: FuzzerConfig,
    stats: FuzzStats,
    //mutation_log: File,
    snapshot_cutoffs: HashMap<InputID, usize>,
}

impl<Fuzz: FuzzRunner + GetStructStorage> StructFuzzer<Fuzz> {
    pub fn new(fuzzer: Fuzz, config: FuzzerConfig, spec: GraphSpec, queue: Queue, seed: u64) -> Self {
        let rng = Distributions::new(config.dict.clone());

        let mutator = Mutator::new(spec);

        let bitmaps = BitmapHandler::new(fuzzer.bitmap_buffer_size());
        let master_rng = RomuPrng::new_from_u64(seed);
        let stats = FuzzStats::new();

        
        let mut option = OpenOptions::new();
        option.read(true);
        option.write(true);
        option.create(true);
        //let mutation_log = option.open(format!("{}/mutation_log_{}", config.workdir_path, config.thread_id)).unwrap(); 


        return Self {
            fuzzer,
            queue,
            master_rng,
            rng,
            mutator,
            bitmaps,
            config,
            stats,
            //mutation_log,
            snapshot_cutoffs: HashMap::new(),
        };
    }

    fn perform_run<F>(&mut self, f: F) -> Option<(TestInfo, MutationStrategy, bool)>
    where
        F: Fn(&mut Mutator, &Queue, &Distributions, &mut RefGraph) -> MutationStrategy,
    {
        self.stats.add_execution(&self.config, &self.queue);
        let (seed_x, seed_y) = (self.master_rng.next_u64(), self.master_rng.next_u64());
        self.rng.set_full_seed(seed_x, seed_y);
        let strategy = {
            let mut storage = self.fuzzer.get_struct_storage(self.mutator.spec.checksum);
            let strat = f(&mut self.mutator, &self.queue, &self.rng, &mut storage);
            //write!(&mut self.mutation_log, "RUN {:?} by {:?}\n",storage.as_vec_graph().data_as_slice(), strat);
            //println!("RUN {:?} by {:?}\n",storage.as_vec_graph().data_as_slice(), strat);
            //println!("====== EXECUTE INPUT OF LENGTH {} =======",storage.as_vec_graph().node_len(&self.mutator.spec));
            strat
        };
        let res = self.fuzzer.run_test();

        let mut has_new_finds = false;
        if let Ok(exec_res) = res {
            if self
                .bitmaps
                .check_new_bytes(self.fuzzer.bitmap_buffer(), self.fuzzer.ijon_max_buffer(), &exec_res.exitreason).is_some() || strategy == MutationStrategy::SeedImport
            {
                if let Some(new_bytes) = self
                    .queue
                    .check_new_bytes(self.fuzzer.bitmap_buffer(),self.fuzzer.ijon_max_buffer(), &exec_res.exitreason, strategy)
                {
                    let data = {
                        let storage =
                            self.fuzzer.get_struct_storage(self.mutator.spec.checksum);
                        //let strategy = f(&self.mutator, &self.queue, &self.rng, &mut storage);
                        self.mutator.dump_graph(&storage)
                    };

                    let node_len = data.node_len(&self.mutator.spec);
                    let ops_used = std::cmp::min(exec_res.ops_used as usize, node_len);
                    let mut input = Input::new(
                        data,
                        strategy,
                        new_bytes,
                        Bitmap::new_from_buffer(self.fuzzer.bitmap_buffer(), self.fuzzer.ijon_max_buffer(), self.fuzzer.bitmap_buffer_size()),
                        exec_res.exitreason.clone(),
                        ops_used,
                        std::time::Duration::from_millis(0),
                    );

                    self.filter_nondet_storage_reasons(&mut input);

                    if input.storage_reasons.len() > 0 {
                        self.new_input(&input);
                        if let Some(new_id) = self.queue.add(input, &self.mutator.spec) {
                            self.snapshot_cutoffs.insert(new_id, node_len.saturating_sub(1));
                            has_new_finds = true;
                        }
                    }
                }
            }
            return Some((exec_res, strategy, has_new_finds));
        }
        return None;
    }

    fn new_input(&mut self, input: &Input) {
        use std::fs;
        //use std::time::SystemTime;
        //let t = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
        //let t = 1;

        let input_type_colored = match input.exit_reason{
            ExitReason::Crash(_) => {
                input.exit_reason.name().red().bold()
            },
            ExitReason::InvalidWriteToPayload(_) => {
                input.exit_reason.name().yellow().bold()
            },
            ExitReason::Timeout => {
                input.exit_reason.name().yellow().bold()
            }
            _ => {
                input.exit_reason.name().clear()
            },
        };

        println!(
            //"[{}] Thread {} Found input {} (len:{}) {}/{} new bytes by {:?}",
            //t,
            "[{}] fuzzer: found input {} (len:{}) {}/{} new bytes by {:?}",
            self.config.thread_id,
            input_type_colored,
            input.data.node_len(&self.mutator.spec),
            input.storage_reasons.iter().filter(|r| r.has_new_byte()).count(),
            input.storage_reasons.len(),
            input.found_by
        );

        fs::create_dir_all(&format!(
            "{}/corpus/{}",
            self.config.workdir_path,
            input.exit_reason.name()
        ))
        .unwrap();

        if !self.queue.should_minimize(&input) {
            //println!(
            //    "writing to {}",
            //    &format!(
            //        "{}/corpus/{}/cnt_{}.py",
            //        self.config.workdir_path,
            //        input.exit_reason.name(),
            //        self.others
            //    )
            //);
            let id = self.queue.next_id();
            input.data.write_to_file(
                &format!(
                    "{}/corpus/{}/cnt_{}.bin",
                    self.config.workdir_path,
                    input.exit_reason.name(),
                    id
                ),
                &self.mutator.spec,
            );
            /*
            input.data.write_to_script_file(
                &format!(
                    "{}/corpus/{}/cnt_{}.py",
                    self.config.workdir_path,
                    input.exit_reason.name(),
                    id
                ),
                &self.mutator.spec,
            );
            */
            match &input.exit_reason {
                ExitReason::Crash(desc) => {
                    std::fs::write(
                        &format!(
                            "{}/corpus//{}/{}.log",
                            self.config.workdir_path,
                            input.exit_reason.name(),
                            id,
                        ),
                        &format!("{}\n", str::from_utf8(&desc).unwrap()),
                    )
                    .unwrap();
                }
                ExitReason::InvalidWriteToPayload(desc) => {
                    std::fs::write(
                        &format!(
                            "{}/corpus//{}/{}.log",
                            self.config.workdir_path,
                            input.exit_reason.name(),
                            id
                        ),
                        desc,
                    )
                    .unwrap();
                }
                _ => {}
            }
        }
    }

    fn perform_gen(&mut self) {
        self.perform_run(|mutator, _queue, rng, storage| {
            mutator.generate(15, &MutatorSnapshotState::none(), storage, &rng);
            MutationStrategy::Generate
        });
    }

    fn perform_min(&mut self, input: &Input) {
        //println!(
        //    "Thread {} performs min on {:?}",
        //    self.config.thread_id, input.id
        //);
        self.queue.set_state(input, InputState::Havoc);

        let num_new_bytes = input.storage_reasons.iter().filter(|r| r.has_new_byte()).count();
        //let num_new_bits = input.storage_reasons.len();
        //let mut num_splits = 0;

        if num_new_bytes > 0 {
            //println!(
            //    "splitting: new bytes: {:?}",
            //    input
            //        .storage_reasons
            //        .iter()
            //        .filter(|r| r.old == 0)
            //        .map(|r| r.index)
            //        .collect::<Vec<_>>()
            //);
            let inputs = self.minimize_new_bytes(&input);
            //num_splits = inputs.len();
            //write!(self.mutation_log,"AFTER MIN, got {} graphs\n", num_splits);
            for inp in inputs.into_iter().map(|inp| inp.into_rc()) {
                //println!(
                //    "new bytes for input (size {} ) {:?}",
                //    inp.data.node_len(&self.mutator.spec),
                //    inp.storage_reasons
                //        .iter()
                //        .filter(|r| r.old == 0)
                //        .map(|r| r.index)
                //        .collect::<Vec<_>>()
                //);
                let id;
                if let Ok(input) = Rc::try_unwrap(inp) {
                    //write!(&mut self.mutation_log,"trying to store {:?}\n", input.data.data_as_slice());
                    id = self.queue.add(input, &self.mutator.spec);
                } else {
                    unreachable!();
                }
                if let Some(id) = id {
                    let inp = self.queue.get_input(id);
                    let data = &inp.read().unwrap().data;
                    self.get_trace(&data);
                    data.write_to_file(
                        &format!(
                            "{}/corpus/normal/cov_{}.bin",
                            self.config.workdir_path,
                            id.as_usize(),
                        ),
                        &self.mutator.spec,
                    );

                    /*
                    data.write_to_script_file(
                        &format!(
                            "{}/corpus/normal/cov_{}.py",
                            self.config.workdir_path,
                            id.as_usize(),
                        ),
                        &self.mutator.spec,
                    );
                    */
                    let src = format!(
                        "{}/redqueen_workdir_{}/pt_trace_results.txt",
                        self.config.workdir_path,
                        self.config.thread_id
                    );
                    let dst = &format!(
                        "{}/corpus/normal/cov_{}.trace",
                        self.config.workdir_path,
                        id.as_usize(),
                    );
                    std::fs::copy(&src, &dst)
                    .expect(&format!("couldn't copy trace from {} to {}", src,dst));

                    let info = self.get_rq_trace(&data);
                    let dict = Self::custom_dict_from_rq_data(&info.bps);
                    self.queue.set_custom_dict(&input, dict);
                    std::fs::copy(
                        &format!(
                            "{}/redqueen_workdir_{}/redqueen_results.txt",
                            self.config.workdir_path,
                            self.config.thread_id
                        ),
                        &format!(
                            "{}/corpus/normal/cov_{}.rq",
                            self.config.workdir_path,
                            id.as_usize(),
                        ),
                    )
                    .unwrap();
                    //write!(&mut self.mutation_log,"stored input\n");
                }else{
                    //write!(&mut self.mutation_log,"didn't store input\n");
                }
            }
        }
        //if num_new_bits > 0 || num_splits > 1 {
        //    let min_input = self.minimize_new_bits(&input);
        //    self.queue.add(Rc::new(min_input), &self.mutator.spec);
        //}
    }


    pub fn custom_dict_from_rq_data(data: &[RedqueenEvent]) -> CustomDict{
        let mut groups = HashMap::new();
        for ev in data.iter(){
            let group = groups.entry(ev.addr).or_insert_with(|| vec!());
            match ev.bp_type{
             RedqueenBPType::Cmp | RedqueenBPType::Sub =>{
                 group.push(DictEntry::Replace(ev.lhs.clone(), ev.rhs.clone()));
                 if !ev.imm {
                    group.push(DictEntry::Replace(ev.rhs.clone(), ev.lhs.clone()));
                 }
            },
             RedqueenBPType::Str => {},
            }
        }
        let groups = groups.into_iter().map(|(_k,v)| v).filter(|v| v.len() > 0 ).collect::<Vec<_>>();
        return CustomDict::new_from_groups(groups);
    }

    fn perform_havoc(&mut self, inp: &Input, snapshot_state: &MutatorSnapshotState) -> bool {
        //println!(
        //    "Thread {} performs havoc on {:?}",
        //    self.config.thread_id, inp.id
        //);
        self.perform_run(|mutator, queue, rng, storage| {
            mutator.mutate(&inp.data, inp.ops_used as usize, &inp.custom_dict, snapshot_state, queue, storage, rng)
        })
        .map(|(_, _, has_new_finds)| has_new_finds).unwrap_or(false)
    }

    fn perform_import(&mut self, seed_import: bool){
        use glob::glob;
        use std::fs;


        let search_path = if !seed_import {
                format!("{}/imports/*.bin",self.config.workdir_path)
        }
        else {
            format!("{}/seeds/*.bin",self.config.workdir_path)
        };

        for entry in glob(&search_path).expect("Failed to read glob pattern") {
            if let Ok(path) = entry {
                    println!("[!] fuzzer: Trying to import {:?}", path.to_str());
                    let orig = VecGraph::new_from_bin_file(path.to_str().unwrap(), &self.mutator.spec);

                    if !seed_import{
                        self.perform_run(|mutator, _queue, rng, storage| {
                            mutator.copy_all(&orig, storage, &rng);
                            MutationStrategy::Import
                        });
                    }
                    else{
                        println!("[!] fuzzer: loaded file, got: {} nodes", orig.node_iter(&self.mutator.spec).count());
                        //println!("script: ================\n{}\n ================", orig.to_script(&self.mutator.spec));
                        self.perform_run(|mutator, _queue, rng, storage| {
                            mutator.copy_all(&orig, storage, &rng);
                            MutationStrategy::SeedImport
                        });
                    }
                fs::remove_file(path).expect("couldn't remove import file");
            }
        }
    }

    pub fn iter(&mut self) {
        if self.queue.len() == 0 {
            self.perform_gen();
        } else {
            let entry = self.queue.schedule(&mut self.rng).read().unwrap().clone();
            match entry.state {
                InputState::Minimize => self.perform_min(&entry),
                InputState::Havoc => {
                    match self.config.snapshot_placement {
                        SnapshotPlacement::None => {
                            self.havoc_no_snap(&entry)
                        }
                        SnapshotPlacement::Balanced => {
                            self.havoc_snap_balanced(&entry);
                        }
                        SnapshotPlacement::Aggressive => {
                            self.havoc_snap_aggressive(&entry);
                        }
                    }
                }
            }
        }
    }

    #[inline]
    fn havoc_no_snap(&mut self, entry: &Input) {
        for _ in 0..10 {
            self.perform_havoc(entry, &MutatorSnapshotState::none());
        }
    }

    #[inline]
    fn havoc_with_snap(&mut self, entry: &Input, snapshot_cutoff: usize) -> bool {
        let mut storage = self.fuzzer.get_struct_storage(self.mutator.spec.checksum);

        //writes the first snapshot_cutoff nodes from entry to the storage, appends a snapstho instruction
        //and returns the graph state that contains all known available data values in the graph
        let mutator_state = self.mutator.prepare_snapshot(snapshot_cutoff, &entry.data, &mut storage, &self.rng);
        //create the snapshot
        //println!("fuzz with snapshot");
        //let payload = storage.as_vec_graph();
        //println!("input: {}",payload.to_script(&self.mutator.spec));
        //write!(&mut self.mutation_log, "MUTATE SNAPSHOT {:?} skipping first {:?} bytes\n",entry.data.data_as_slice(), mutator_state.skip_data);
        //println!("MUTATE SNAPSHOT {:?} skipping first {:?} bytes\n",entry.data.data_as_slice(), mutator_state.skip_data);
        let mut has_new_finds = false;
        if self.fuzzer.run_create_snapshot() {
            for _ in 0..50 {
                has_new_finds |= self.perform_havoc(entry, &mutator_state);
            }
            //println!("delete snapshot");
            self.fuzzer.delete_snapshot().unwrap();
        }
        has_new_finds
    }

    fn havoc_snap_balanced(&mut self, entry: &Input) {
        let mut num_nodes = entry.ops_used as usize;
        //write!(&mut self.mutation_log, "MUTATE INPUT with used_ops: {} and len: {}\n",entry.ops_used , entry.data.node_len(&self.mutator.spec));
        if entry.data.node_len(&self.mutator.spec) < num_nodes{
            num_nodes = entry.data.node_len(&self.mutator.spec);
        }
        if num_nodes > 4 && self.rng.gen_range(0, 25) < 24 {
            //let snapshot_cutoff = num_nodes-3;
            let snapshot_cutoff = if self.rng.gen_range(0,100) < 50 {
                //self.rng.gen_range(num_nodes-5,num_nodes)
                self.rng.gen_range(num_nodes*0.5 as usize,num_nodes)

            } else {
                self.rng.gen_range(0,num_nodes)
            };

            //snapshot_cutoff = num_nodes-3;

            self.havoc_with_snap(&entry, snapshot_cutoff);
        } else {
            //write!(&mut self.mutation_log, "MUTATE {:?}\n",entry.data.data_as_slice());
            //println!("MUTATE {:?}\n",entry.data.data_as_slice());
            self.havoc_no_snap(&entry);
        }
    }

    fn havoc_snap_aggressive(&mut self, entry: &Input) {
        const MIN_CUTOFF: usize = 4;
        let max_cutoff = entry.data.node_len(&self.mutator.spec).saturating_sub(1);
        let cutoff = *self.snapshot_cutoffs.entry(entry.id).or_insert(max_cutoff);
        if cutoff < MIN_CUTOFF {
            self.havoc_no_snap(&entry);
        } else {
            let has_new_finds = self.havoc_with_snap(&entry, cutoff);
            if self.queue.update_iters_no_finds(entry.id, has_new_finds) > 50 {
                self.snapshot_cutoffs.insert(entry.id, if cutoff == MIN_CUTOFF {
                    max_cutoff
                } else {
                    cutoff - 1
                });
            }
        }
    }

    fn filter_nondet_storage_reasons(&mut self, input: &mut Input) {
        let mut res = input.storage_reasons.clone();
        let mut bits = vec![];
        for _i in 0..10 {
            self.fuzzer.run_test().unwrap();
            let bitmap = self.fuzzer.bitmap_buffer();
            let ijon_max = self.fuzzer.ijon_max_buffer();
            bits.push(bitmap.iter().filter(|e| **e > 0).count());
            res = res
                .into_iter()
                .filter(|r| r.still_valid(bitmap, ijon_max) )
                .collect::<Vec<_>>();
        }
        //println!("nondet pass: {:?}", bits);
        input.storage_reasons = res;
    }

    fn get_trace(&mut self, graph: &VecGraph) {
        let mut storage = self.fuzzer.get_struct_storage(self.mutator.spec.checksum);
        storage.copy_from(graph);
        self.fuzzer.run_cfg().unwrap();
    }

    fn get_rq_trace(&mut self, graph: &VecGraph) -> RedqueenInfo {
        let mut storage = self.fuzzer.get_struct_storage(self.mutator.spec.checksum);
        storage.copy_from(graph);
        return self.fuzzer.run_redqueen().unwrap();
    }

    fn update_min_graphs(
        &mut self,
        new_bytes: &Vec<StorageReason>,
        exec_res: TestInfo,
        graphs: &mut Vec<Rc<Input>>,
    ) -> bool {
        let mut res = false;
        let dumped_graph = {
            let storage = self.fuzzer.get_struct_storage(self.mutator.spec.checksum);
            self.mutator.dump_graph(&storage)
        };
        let bitmap = self.fuzzer.bitmap_buffer();
        let ijon_max = self.fuzzer.ijon_max_buffer();
        let new_len = dumped_graph.node_len(&self.mutator.spec);
        let mut ops_used = exec_res.ops_used as usize;
        if ops_used > dumped_graph.node_len(&self.mutator.spec){
            ops_used = dumped_graph.node_len(&self.mutator.spec);
            //exceeded_capacity = true;
        }
        let mut input = Input::new(
            dumped_graph,
            MutationStrategy::MinimizeSplit,
            vec![],
            Bitmap::new_from_buffer(bitmap, ijon_max, self.fuzzer.bitmap_buffer_size()),
            exec_res.exitreason,
            ops_used,
            std::time::Duration::from_millis(0),
        );
        input.state = InputState::Havoc;

        for (graph_i, storage) in new_bytes.iter().enumerate() {
            if storage.still_valid(bitmap, ijon_max)
                && graphs[graph_i].data.node_len(&self.mutator.spec) > new_len
            {
                input.storage_reasons.push(storage.clone());
                res = true;
            }
        }
        let rc = Rc::new(input);
        for (graph_i, storage) in new_bytes.iter().enumerate() {
            if storage.still_valid(bitmap, ijon_max)
                && graphs[graph_i].data.node_len(&self.mutator.spec) > new_len
            {
                graphs[graph_i] = rc.clone()
            }
        }
        return res;
    }

    pub fn minimize_new_bytes(&mut self, input: &Input) -> HashSet<helpers::HashAsRef<Input>> {
        //write!(&mut self.mutation_log, "MINIMIZE INPUT {:?}\n", input.data.data_as_slice());
        //println!("MINIMIZE INPUT {:?}\n", input.data.data_as_slice());
        use std::iter::FromIterator;
        let mut min = input.clone();
        min.id = InputID::invalid();
        min.state = InputState::Havoc;
        let rc = Rc::new(min);
        let new_bytes = rc
            .storage_reasons
            .iter()
            .filter(|r| r.has_new_byte() )
            .cloned()
            .collect::<Vec<_>>();
        let mut graphs = new_bytes.iter().map(|_| rc.clone()).collect::<Vec<_>>();
        drop(rc);

        let res = self.perform_run(|mutator, _queue, rng, storage| {
            let drop_range = (input.ops_used as usize)..input.data.node_len(&mutator.spec);
            mutator.drop_range(&input.data, drop_range, storage, rng);
            MutationStrategy::Minimize
        });
        if let Some((info, _strategy, _)) = res {
            self.update_min_graphs(&new_bytes, info, &mut graphs);
        }


        for i in 0..graphs.len() {
            //println!("Thread {} minimize for {}", self.config.thread_id, i);
            if !self.minimize_one_byte(i, &new_bytes, &mut graphs){
                break;
            }
        }
        let res = HashSet::from_iter(graphs.into_iter().map(|g| helpers::HashAsRef::new(g)));
        return res;
    }

    //pub fn minimize_new_bits(&mut self, input: &Input) -> Input {
    //    let num_iters = 1000;
    //    let mut res = input.clone();
    //    let mut remaining = num_iters;
    //    while res.data.node_len(&self.mutator.spec) > 5 && remaining > 0 {
    //        remaining -= 1;
    //        let range = self
    //            .rng
    //            .gen_minimization_block_size(remaining, num_iters, res.data.node_len(&self.mutator.spec));
    //        self.set_input_drop_range(&res.data, range);
    //        let info = self.fuzzer.run_test().unwrap();
    //        let bitmap = self.fuzzer.bitmap_buffer();
    //        if input.storage_reasons.iter().all(|r| r.new >= bitmap[r.index]){
    //            res = self.dump_input(info.exitreason, input.storage_reasons.clone());
    //            println!("minimized input to {}", res.data.node_len(&self.mutator.spec));
    //        }
    //    }
    //    return res;
    //}

    fn minimize_one_byte(
        &mut self,
        i: usize,
        new_bytes: &Vec<StorageReason>,
        graphs: &mut Vec<Rc<Input>>,
    ) -> bool {
        let num_iters = 1000;
        let mut remaining = num_iters as i32;
        let mut random_failures = 0;
        let mut updated = false;
        //write!(self.mutation_log, "MINIMIZE BYTE {}\n",i);
        while remaining > 0 &&
            graphs[i].data.node_len(&self.mutator.spec) > remaining as usize
            && random_failures < 10
        {
            remaining -= 1;
            //println!(
            //    "Thread {} minimize random {}/1000",
            //    self.config.thread_id, remaining
            //);
            let res = self.perform_run(|mutator, _queue, rng, storage| {
                let range = rng.gen_minimization_block_size(
                    remaining as usize,
                    num_iters,
                    graphs[i].data.node_len(&mutator.spec),
                );
                //println!("drop {:?}", range);
                mutator.drop_range(&graphs[i].data, range, storage, rng);
                MutationStrategy::Minimize
            });

            if let Some((info, _strategy, _)) = res {
                if self.update_min_graphs(&new_bytes, info, graphs) {
                    updated = true;
                    random_failures = 0;
                } else {
                    random_failures += 1;
                }
            } else {
                unreachable!();
            }
            
        }
        //println!(
        //    "after minimized random {}",
        //    graphs[i].data.node_len(&self.mutator.spec)
        //);
        for idx in (0..graphs[i].data.node_len(&self.mutator.spec)).rev() {
            if remaining <= 0 {
                break;
            }
            remaining -= 1;
            //self.set_input_drop_range(&graphs[i].data, idx..idx + 1);
            let res = self.perform_run(|mutator, _queue, rng, storage| {
                mutator.drop_range(&graphs[i].data, idx..idx + 1, storage, rng);
                MutationStrategy::Minimize
            });
            if let Some((info, _strategy, _)) = res {
                updated = updated||self.update_min_graphs(new_bytes, info, graphs);
            }
        }
        //println!(
        //    "after minimized stepwise {}",
        //    graphs[i].data.node_len(&self.mutator.spec)
        //);
        return updated;
    }

    pub fn run(&mut self) {
        //use std::io::{self, Write};
        use glob::glob;
        //use std::thread;
        use std::time::Duration;

        if self.config.thread_id == 0 {
            self.perform_import(true);
        }
        else{
            while glob(&format!("{}/seeds/*.bin",self.config.workdir_path)).expect("Failed to read glob pattern").count() != 0{
                std::thread::sleep(Duration::from_millis(1000));
            }
        }

        let mut i = 0;
        loop {
            
            if self.config.thread_id == 0  && i % 500 == 0 {
                self.perform_import(false);
            }
            if self.config.exit_after_first_crash && self.queue.num_crashes() > 0{
                return;
            }
            i += 1;
            self.iter();
        }
    }

    pub fn shutdown(&mut self) {
        self.fuzzer.shutdown().unwrap();
    }
}
