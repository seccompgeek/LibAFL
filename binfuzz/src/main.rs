use std::{path::Path, fs, process::{Command, Stdio}, env, collections::HashMap};
use libafl_cc::{cfg, HasWeight, ControlFlowGraph};
use libafl_qemu::{Emulator, elf::EasyElf};
use std::error::Error;
use libafl::observers::binfuzz::DistancesMapObserver;

mod cfgbuilder;
mod distance_feedback;

use cfgbuilder::ICFG;

fn is_64(binary: &[u8]) ->Result<bool, Box<dyn Error>> {
    use goblin::Object;
     match Object::parse(binary)? {
        Object::Elf(elf) => {
            Ok(elf.is_64)
        },
        _ => Err("File is not ELF".into())
     }
}

fn preprocess(binary: String, targets: String) -> Result<ICFG, String> {

    let bin_path = Path::new(binary.as_str());
    if !bin_path.exists() {
        panic!("Binary {binary} not found!");
    }

    let mut cwd = std::env::current_dir().unwrap();
    let cwd_str = cwd.to_str().unwrap();
    let mut cwd_str = cwd_str.to_string();

    let binary_path = cwd_str.clone()+"/"+&binary;
    let targets_path = cwd_str.clone()+"/"+&targets;
    cwd_str.push_str("/tmp");
    let cwd = Path::new(&cwd_str);

    if cwd.exists() {
        fs::remove_dir_all(&cwd_str).expect("Unable to remove tmp directory");
    }
    fs::create_dir(&cwd_str).expect("Unable to create tmp directory");
    let _ = fs::copy(binary_path, cwd_str.clone()+"/"+&binary);
    let _ = fs::copy(targets_path, cwd_str.clone()+"/"+&targets);


    std::env::set_current_dir(&cwd_str).expect("Unable to change working directory");


    let bin_path = cwd_str.clone()+"/"+&binary;

    let idapro_path_str = std::env::var("IDA_PATH").unwrap_or("/opt/idapro-7.7/".to_string());
    let idapro_path = Path::new(&idapro_path_str);
    if !idapro_path.exists() {
        panic!("idapro not found! Please set IDA_PATH environment variable");
    }

    let mut ida_cmd = String::from(idapro_path.to_str().unwrap());
    let mut idb_file = binary.clone();
    if is_64(&fs::read(bin_path).unwrap()).unwrap() {
        ida_cmd.push_str("/idat64");
        idb_file.push_str(".i64")
    }else{
        ida_cmd.push_str("/idat");
        idb_file.push_str(".idb");
    }
    Command::new(&ida_cmd)
            .arg("-B")
            .arg("-A")
            .arg(&binary)
            .output()
            .expect("Failed to run idapro");
    
    if !Path::new(&idb_file).exists() {
        panic!("No idb file created! something went wrong");
    }

    let ida_script_cmd = ida_cmd.clone()+" -S\"../ida.py -cg=True\" "+&idb_file;
    let call_graph = cwd_str.clone()+"/callgraph.gdl";
    let call_graph_path = Path::new(&call_graph);
    println!("Please execute: {}", &ida_script_cmd);
    println!("Looking for {}",&call_graph);
    while !call_graph_path.exists() {}

    let graph_easy_path = std::env::var("GRAPH_EASY_PATH").expect("No graph-easy path found! Please set the GRAPH_EASY_PATH environment variable");

    Command::new(graph_easy_path)
            .arg("--input=callgraph.gdl")
            .arg("--output=callgraph.dot")    
            .stderr(Stdio::null())
            .output()
            .expect("Failed to run graph-easy");
    
    let binsec_path = std::env::var("BINSEC_PATH").expect("No binsec path found! Please set the BINSEC_PATH environment variable");
    println!("Executing: {}", &binsec_path);
    let mut ida_file = binary.clone();
    ida_file.push_str(".ida");
    Command::new(binsec_path)
            .args(["-ida", "-isa", "x86", "-quiet", "-ida-cfg-dot", "-ida-o-ida", &ida_file])
            .output()
            .expect("Failed to run binsec");

    let funcs_file = binary.clone() + ".funcs";
    let funcs_path = Path::new(funcs_file.as_str());
    if !funcs_path.exists() {
        panic!("No funcs file found!");
    }
    let lines = fs::read_to_string(&funcs_file).unwrap();
    let lines = lines.lines();
    let mut functions = Vec::new();

    let mut graph_string = "".to_string();

    for line in lines {
        let t: Vec<&str> = line.split(",").collect();
        let (addr, func_name) = (t[0],t[1]);
        let addr = addr.trim_start_matches("0x");
        let addr = usize::from_str_radix(addr, 16).unwrap();
        let more = "$$".to_string()+func_name+"+"+addr.to_string().as_str()+"\n";
        graph_string.push_str(&more);
        functions.push(func_name);
    }

    let cfgs = fs::read_dir(cwd_str.clone() + "/cfgs/").expect("Unable to read cfgs folder");

    for func in functions {
        let path = cwd_str.clone()+"/cfgs/" + func;
        let cfg_path = Path::new(&path);
        if cfg_path.exists() {
            let lines = fs::read_to_string(cfg_path).unwrap();
            let lines = lines.lines();
            let mut ids_map: HashMap<&str, &str> = HashMap::default();
            let mut edges_map: HashMap<&str, Vec<&str>> = HashMap::default();
            for line in lines {
                if let Some(label) = line.find("[label=") {
                    let id = &line[0..label];
                    let addr_pat = &line[label+"[label=\"".len()..];
                    let addr = &addr_pat[0..addr_pat.find("\"").unwrap()];
                    ids_map.insert(id.trim(), addr.trim());
                    edges_map.insert(addr.trim(), Vec::new());
                }else if let Some(edge) = line.find(" -> ") {
                    let from = line[0..edge].trim();
                    let to = line[edge+" -> ".len()..line.len()-1].trim();
                    let from_addr = ids_map.get(&from).unwrap();
                    let to_addr = ids_map.get(&to).unwrap();
                    edges_map.get_mut(from_addr).unwrap().push(*to_addr);
                }
                
            }

            for entry in edges_map {
                if !entry.1.is_empty() {
                    let from_addr = entry.0.trim_start_matches("0x");
                    let from_addr = usize::from_str_radix(from_addr, 16).unwrap();
                    let mut more = "%%".to_string()+func+"+"+from_addr.to_string().as_str()+"\n";
                    for end in entry.1 {
                        let end_addr = end.trim_start_matches("0x");
                        let end_addr = usize::from_str_radix(end_addr, 16).unwrap();
                        more.push_str(&("->".to_string()+end_addr.to_string().as_str()+"\n"));
                    }
                    graph_string.push_str(&more);
                }
            }
        }
    }

    let cg_path_str = cwd_str.clone()+"/"+binary.as_str()+".cg";
    let cg_path = Path::new(&cg_path_str);
    println!("{}", &cg_path_str);
    if cg_path.exists() {
        let calls_str = fs::read_to_string(cg_path).unwrap();
        let calls = calls_str.lines();
        for line in calls {
            let entries: Vec<&str> = line.split('(').collect();
            let caller_info: Vec<&str> = entries[1].trim_end_matches(")-").split(';').collect();
            let caller_name = caller_info[0];
            let caller_block = usize::from_str_radix(caller_info[1].trim_start_matches("0x"), 16).unwrap();

            let callee_info: Vec<&str> = entries[2].trim_end_matches(")").split(';').collect();
            let callee_name = callee_info[0];
            let callee_block = usize::from_str_radix(callee_info[1].trim_start_matches("0x"), 16).unwrap();
            let more = "%%".to_string() + caller_name + "+" + caller_block.to_string().as_str() + "\n->" + callee_block.to_string().as_str()+"\n";
            graph_string.push_str(&more);
        }
    }

    let mut icfg = ICFG::new(&graph_string);
    let target_funcs_ps = cwd_str.clone()+"/"+&targets;
    let target_func_path = Path::new(&target_funcs_ps);
    if target_func_path.exists() {
        let lines = fs::read_to_string(target_func_path).unwrap();
        let lines = lines.lines();
        for line in lines {
            let splits: Vec<&str> = line.split(',').collect();
            let target_func_name = splits[0];
            let target_func_weight = splits[1].parse().unwrap();
            icfg.add_target_func(target_func_name, target_func_weight);
        }
    }

    for func in functions {
        icfg.compute_distances(func);
    }

    return Ok(icfg);
}

fn usage(){
    println!("Usage:");
    println!("cargo run /path-to-binary-file");
    std::process::exit(-1);
}


fn main() {
    if std::env::args().len() < 2 {
        usage();
    }
    let binary_file = std::env::args().nth(1).unwrap();
    let mut icfg = preprocess(binary_file, "racecar.tgt".to_string()).unwrap();
}
