extern crate config;
extern crate core_affinity;
extern crate fuzz_runner;
extern crate helpers;
extern crate serde;
extern crate structured_fuzzer;
#[macro_use]
extern crate serde_derive;
extern crate rmp_serde;
extern crate ron;
extern crate rand;
extern crate glob;
extern crate colored; 

use clap::{value_t, App, Arg};

use crate::queue::Queue;

use std::fs::File;
use std::thread;
use std::time::Duration;

mod bitmap;
mod fuzzer;
mod input;
mod queue;
mod romu;

use rand::thread_rng;
use crate::rand::Rng;

use fuzzer::StructFuzzer;

use structured_fuzzer::graph_mutator::spec_loader;
use crate::romu::*;
use fuzz_runner::nyx::qemu_process_new_from_kernel;
use fuzz_runner::nyx::qemu_process_new_from_snapshot;

use fuzz_runner::nyx::qemu_process::QemuProcess;

use config::{Config, FuzzRunnerConfig};
use colored::*;

fn main() {
    let matches = App::new("nyx")
        .about("Fuzz EVERYTHING!")
        .arg(
            Arg::with_name("sharedir")
                .short("s")
                .long("sharedir")
                .value_name("SHAREDIR_PATH")
                .takes_value(true)
                .help("path to the sharedir"),
        )
        .arg(
            Arg::with_name("workdir")
                .short("w")
                .long("workdir")
                .value_name("WORKDIR_PATH")
                .takes_value(true)
                .help("overrides the workdir path in the config"),
        )
        .arg(
            Arg::with_name("cpu_start")
                .short("c")
                .long("cpu")
                .value_name("CPU_START")
                .takes_value(true)
                .help("overrides the config value for the first CPU to pin threads to"),
        )
        .arg(
            Arg::with_name("threads")
                .short("t")
                .long("threads")
                .value_name("THREADS")
                .takes_value(true)
                .help("overrides the config value for the number of parallel fuzzing threads to run"),
        )
        .arg(
            Arg::with_name("seed")
                .long("seed")
                .value_name("SEED")
                .takes_value(true)
                .help("runs the fuzzer with a specific seed, if not give, a seed is generated from a secure prng"),
        )
        .arg(
            Arg::with_name("snapshot_placement")
                .short("p")
                .long("placement")
                .value_name("SNAPSHOT_PLACEMENT")
                .takes_value(true)
                .help("overrides the config value for snapshot placement strategy (options: aggressive / balanced)")
        )
        .arg(
            Arg::with_name("exit_after_first_crash")
                .long("exit_after_first_crash")
                .help("terminate fuzzing after the first crash was found")
        )
        .get_matches();

    let sharedir = matches
        .value_of("sharedir")
        .expect("need to specify sharedir (-s)")
        .to_string();

    let cfg: Config = Config::new_from_sharedir(&sharedir);

    let mut config = cfg.fuzz;
    let runner_cfg = cfg.runner;


    if let Some(path) = matches.value_of("workdir") {
        config.workdir_path = path.to_string();
    }
    if let Ok(start_cpu_id) = value_t!(matches, "cpu_start", usize) {
        config.cpu_pin_start_at = start_cpu_id;
    }
    if let Ok(threads) = value_t!(matches, "threads", usize) {
        config.threads = threads;
    }
    if matches.is_present("exit_after_first_crash") {
        config.exit_after_first_crash = true;
    }

    if let Some(snapshot_placement) = matches.value_of("snapshot_placement") {
        config.snapshot_placement = snapshot_placement.parse().unwrap();
    }

    let file = File::open(&config.spec_path).expect(&format!(
        "couldn't open spec (File not found: {}",
        config.spec_path
    ));
    let spec = spec_loader::load_spec_from_read(file);
    let queue = Queue::new(&config);

    let mut thread_handles = vec![];
    let core_ids = core_affinity::get_core_ids().unwrap();
    let seed = value_t!(matches, "cpu_start", u64).unwrap_or(thread_rng().gen());
    let mut rng = RomuPrng::new_from_u64(seed);

    /* prepare workdir */
    QemuProcess::prepare_workdir(&config.workdir_path, config.seed_path.clone());

    for i in 0..config.threads {
        let mut cfg = config.clone();
        cfg.thread_id = i;

        let spec1 = spec.clone();
        let queue1 = queue.clone();
        let core_id = core_ids[(i + cfg.cpu_pin_start_at) % core_ids.len()].clone();
        let thread_seed = rng.next_u64();
        let sdir = sharedir.clone();


        match runner_cfg.clone() {
            FuzzRunnerConfig::QemuSnapshot(run_cfg) => {
                thread_handles.push(thread::spawn(move || {
                    core_affinity::set_for_current(core_id);
                    let mut runner = qemu_process_new_from_snapshot(sdir, &run_cfg, &cfg);
                    runner.set_timeout(cfg.time_limit);
                    let mut fuzzer = StructFuzzer::new(runner, cfg, spec1, queue1, thread_seed);
                    fuzzer.run();
                }));
                //if i == 0 {
                    std::thread::sleep(Duration::from_millis(100));
                //}
            },
            FuzzRunnerConfig::QemuKernel(run_cfg) => {
                thread_handles.push(thread::spawn(move || {
                    println!("[!] fuzzer: spawning qemu instance #{}", i);
                    core_affinity::set_for_current(core_id);
                    let mut runner = qemu_process_new_from_kernel(sdir, &run_cfg, &cfg);
                    runner.set_timeout(cfg.time_limit);
                    let mut fuzzer = StructFuzzer::new(runner, cfg, spec1, queue1, thread_seed);

                    fuzzer.run();
                    fuzzer.shutdown();
                }));
                //if i == 0 {
                    std::thread::sleep(Duration::from_millis(100));
                //}
            }
            //FuzzRunnerConfig::ForkServer(ref run_cfg) => {
            //    let runner = StructuredForkServer::new(run_cfg, &cfg);
            //    let mut fuzzer = StructFuzzer::new(runner, cfg, spec.clone(), queue.clone());
            //    fuzzer.run();
            //}
            //_ => unreachable!(), 
        }
    }
    thread_handles.push(thread::spawn(move || {
        let mut num_bits_last = 0;
        
        loop {
            let total_execs = queue.get_total_execs();

            if total_execs > 0 {
                let num_bits = queue.num_bits();

                if num_bits != num_bits_last {
                    println!("[!] {}", format!("Execs/sec: {} / Bitmap: {}", total_execs as f32 / queue.get_runtime_as_secs_f32(), num_bits).yellow().bold());   
                    num_bits_last = num_bits;
                }
    
            }
            std::thread::sleep(Duration::from_millis(1000*60));
        }
    }));
    for t in thread_handles.into_iter() {
        t.join().unwrap();
    }
}
