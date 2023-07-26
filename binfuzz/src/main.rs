use std::{path::Path, fs, process::{Command, Stdio}};
use libafl_qemu::{Emulator, elf::EasyElf};
use std::error::Error;

mod cfgbuilder;

fn is_64(binary: &[u8]) ->Result<bool, Box<dyn Error>> {
    use goblin::Object;
     match Object::parse(binary)? {
        Object::Elf(elf) => {
            Ok(elf.is_64)
        },
        _ => Err("File is not ELF".into())
     }
}

fn preprocess(binary: String) {

    let bin_path = Path::new(binary.as_str());
    if !bin_path.exists() {
        panic!("Binary {binary} not found!");
    }

    let mut cwd = std::env::current_dir().unwrap();
    let cwd_str = cwd.to_str().unwrap();
    let mut cwd_str = cwd_str.to_string();

    let binary_path = cwd_str.clone()+"/"+&binary;
    cwd_str.push_str("/tmp");
    let cwd = Path::new(&cwd_str);

    if cwd.exists() {
        fs::remove_dir_all(&cwd_str).expect("Unable to remove tmp directory");
    }
    fs::create_dir(&cwd_str).expect("Unable to create tmp directory");
    fs::copy(binary_path, cwd_str.clone()+"/"+&binary);
    std::env::set_current_dir(&cwd_str).expect("Unable to change working directory");

    let bin_path = cwd_str+"/"+&binary;

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

    let cmd = Command::new(&ida_cmd)
            .arg("-S\"../ida.py -cg=True\"")
            .arg(&idb_file)
            .output()
            .expect("Failed to run ida.py script analysis on idb file");

    println!("Running ida-script: {}",cmd.stdout);
    let graph_easy_path = std::env::var("GRAPH_EASY_PATH").expect("No graph-easy path found! Please set the GRAPH_EASY_PATH environment variable");

    Command::new(graph_easy_path)
            .arg("--input=callgraph.gdl")
            .arg("--output=callgraph.dot")    
            .stderr(Stdio::null())
            .output()
            .expect("Failed to run graph-easy");
    
    let binsec_path = std::env::var("BINSEC_PATH").expect("No binsec path found! Please set the BINSEC_PATH environment variable");

    let mut ida_file = binary.clone();
    ida_file.push_str(".ida");
    Command::new(binsec_path)
            .args(["-ida", "-isa", "x86", "-quiet", "-ida-cfg-dot", "-ida-o-ida", &ida_file])
            .output()
            .expect("Failed to run binsec");
    
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
    preprocess(binary_file);
}
