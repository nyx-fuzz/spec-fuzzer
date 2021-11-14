extern crate config;
extern crate core_affinity;
extern crate fuzz_runner;
extern crate helpers;
extern crate serde;
extern crate structured_fuzzer;
extern crate serde_derive;
extern crate rmp_serde;
extern crate ron;
extern crate rand;
extern crate glob;

use walkdir::{WalkDir};

use clap::{value_t, App, Arg, ArgMatches};

use std::fs::File;

use fuzz_runner::nyx::qemu_process_new_from_kernel;
use fuzz_runner::nyx::qemu_process_new_from_snapshot;
use fuzz_runner::nyx::qemu_process::QemuProcess;

use std::io::Read;
use std::fs;

use config::{Config, FuzzRunnerConfig};

use std::str;

extern crate colored; // not needed in Rust 2018

use colored::*;

use std::path::Path;
use filetime::FileTime;


fn print_result(runner: &mut fuzz_runner::QemuProcess, target_file: &String){
    println!("\n{} {} {}", "**************", target_file.green().bold(), "**************");
    print!("{}", format!("{:#?}", runner.aux.result).yellow());
    if runner.aux.result.crash_found != 0 || runner.aux.result.asan_found != 0 || runner.aux.result.hprintf != 0 { 
        println!("{}", str::from_utf8(&runner.aux.misc.data).unwrap().red());
    }
    println!("");
}

fn execute_path(runner: &mut fuzz_runner::QemuProcess, target_path: String, dump_payload_folder: &Option<String>, quite_mode: bool, workdir: &String) {
    runner.aux.config.timeout_sec += 1;
    //runner.aux.config.timeout_usec = 100_000;
    runner.aux.config.changed = 1;

    for entry in WalkDir::new(target_path)
                    .max_depth(2)
                    .into_iter()
                    .filter_map(|v| v.ok()) {
        let final_path = entry.path();
        let path_str = final_path.to_str().unwrap();
        if path_str.ends_with("bin"){
            //println!("path: {:?}", final_path);
            let mut f = File::open(path_str).expect("no file found");
            f.read(runner.payload).expect("buffer overflow");

            runner.send_payload();
            
            if !quite_mode{
                print_result(runner, &format!("{:?}", final_path));
            }

            match dump_payload_folder{
                Some(x) => {
                    let target = final_path.file_stem().unwrap().to_str().unwrap();
                    let target_str = format!("{}/{}.py", x, target);
                    let source_str = format!("{}/dump/reproducer.py", workdir);
                    println!("COPY: {} -> {}", source_str, target_str);
                    fs::copy(source_str, target_str).expect("COPY FAILED!");

                    /* copy mtime */
                    let metadata = fs::metadata(final_path).unwrap();
                    let mtime = FileTime::from_last_modification_time(&metadata);
                    filetime::set_file_mtime(format!("{}/{}.py", x, target), mtime).expect("cannot set mtime");
                },
                None => {}
            }        
        }
    }

    runner.shutdown();
}

fn execute_file(runner: &mut fuzz_runner::QemuProcess, target_file: &String, dump_payload_folder: &Option<String>, quite_mode: bool, workdir: &String) {
    runner.aux.config.timeout_sec += 1;
    //runner.aux.config.timeout_usec = 100_000;
    runner.aux.config.changed = 1;

    let mut f = File::open(target_file).expect("no file found");
    f.read(runner.payload).expect("buffer overflow");
    runner.send_payload();

    if !quite_mode{
        print_result(runner, target_file);
    }

    match dump_payload_folder{
        Some(x) => {
            let target_path = Path::new(target_file);
            let target = target_path.file_stem().unwrap().to_str().unwrap();
            let target_str = format!("{}/{}.py", x, target);
            let source_str = format!("{}/dump/reproducer.py", workdir);
            
            println!("COPY: {} -> {}", source_str, target_str);
            fs::copy(source_str, target_str).expect("COPY FAILED!");

            /* copy mtime */
            let metadata = fs::metadata(target_file).unwrap();
            let mtime = FileTime::from_last_modification_time(&metadata);
            filetime::set_file_mtime(format!("{}/{}.py", x, target), mtime).expect("cannot set mtime");
        },
        None => {},
    };

    runner.shutdown();
}

fn execute(runner: &mut fuzz_runner::QemuProcess, matches: &ArgMatches<'_>, quite_mode: bool, workdir: &String){

    let dump_path = if matches.value_of("dump_payload_folder").is_none(){
        None
    }
    else{
        Some(matches.value_of("dump_payload_folder").unwrap().to_string())
    };

    if matches.value_of("target_file").is_some() {
        execute_file(runner, &matches.value_of("target_file").unwrap().to_string(), &dump_path, quite_mode, workdir);
    }
    if matches.value_of("target_path").is_some() {
        execute_path(runner, matches.value_of("target_path").unwrap().to_string(), &dump_path, quite_mode, workdir);
    }
}

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
            Arg::with_name("cpu_start")
                .short("c")
                .long("cpu")
                .value_name("CPU_START")
                .takes_value(true)
                .help("overrides the config value for the first CPU to pin threads to"),
        )
        .arg(
            Arg::with_name("target_file")
                .short("f")
                .long("target_file")
                .value_name("TARGET")
                .takes_value(true)
                .help("specifies one target file"),
        )
        .arg(
            Arg::with_name("target_path")
                .short("d")
                .long("target_path")
                .value_name("TARGET_PATH")
                .takes_value(true)
                .help("specifies path to a target folder"),
        )
        .arg(
            Arg::with_name("dump_payload_folder")
                .short("t")
                .long("dump_payload_folder")
                .value_name("DUMP_PAYLOAD_PATH")
                .takes_value(true)
                .help("dump payload files to folder"),
        )
        .arg(
            Arg::with_name("quiet")
                .short("q")
                .long("quiet")
                .takes_value(false)
                .help("quite mode - don't output aux buffer results"),
        )
        .after_help("Example: cargo run --release -- -s <SHAREDIR> -d <FUZZER_WORKDIR>/corpus/normal/ -t <OUTPUT_FOLDER>\n")
        .get_matches();

    //println!("{:?}", matches);

    let sharedir = matches
        .value_of("sharedir")
        .expect("need to specify sharedir (-s)")
        .to_string();
    
    if !matches.value_of("target_file").is_some() && !matches.value_of("target_path").is_some() {
        panic!("Neither a target_file nor a target_path has been specififed!");
    }

    let cfg: Config = Config::new_from_sharedir(&sharedir);


    let mut config = cfg.fuzz;
    let runner_cfg = cfg.runner;

    if let Ok(start_cpu_id) = value_t!(matches, "cpu_start", usize) {
        config.cpu_pin_start_at = start_cpu_id;
    }

    let quite_mode = matches.is_present("quiet");

    //println!("DUMP: {}", matches.value_of("dump_payload_folder").is_some());
    config.dump_python_code_for_inputs = Some(matches.value_of("dump_payload_folder").is_some());

    if config.dump_python_code_for_inputs.unwrap(){
        fs::create_dir_all(matches.value_of("dump_payload_folder").unwrap()).unwrap();
    }

    config.workdir_path = format!("/tmp/debug_workdir_{}/", config.cpu_pin_start_at);

    let sdir = sharedir.clone();

    QemuProcess::prepare_workdir(&config.workdir_path, config.seed_path.clone());


    match runner_cfg.clone() {
        FuzzRunnerConfig::QemuSnapshot(cfg) => {
            let mut runner = qemu_process_new_from_snapshot(sdir, &cfg, &config);
            execute(&mut runner, &matches, quite_mode, &config.workdir_path);
        }
        FuzzRunnerConfig::QemuKernel(cfg) => {
            let mut runner = qemu_process_new_from_kernel(sdir, &cfg, &config);
            //runner.aux.config.page_dump_mode = 1;
            //runner.aux.config.changed = 1;

            execute(&mut runner, &matches, quite_mode, &config.workdir_path);
        }
        //_ => unreachable!(),
    }
}
