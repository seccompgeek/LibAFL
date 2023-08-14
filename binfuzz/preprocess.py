import sys
import os
import shutil
import subprocess

def is_64bit_elf(filename):
    with open(filename, "rb") as f:
        return f.read(5)[-1] == 2

def get_file_kind(filename) -> dict:
    file_info = subprocess.run(["file", filename], stdout=subprocess.PIPE).stdout.decode('utf-8')
    result = {"BITS": None, "ISA": None}
    
    if "32-bit" in file_info:
        result["BITS"] = 32
    elif "64-bit" in file_info:
        result["BITS"] = 64

    if "Intel" in file_info or "x86" in file_info:
        result["ISA"] = "x86"
    elif "ARM" in file_info or "aarch64" in file_info or "aarch32" in file_info:
        result["ISA"] = "aarch"

    return result

def main():
    args = sys.argv
    if len(args) < 2:
        print("No binary file given")
        exit(-1)
    
    binary_file = args[1]
    print("BINARY: ", binary_file)

    file_info = get_file_kind(binary_file)

    if file_info["BITS"] is None or file_info["ISA"] is None:
        print("Failed to obtain file info, exiting ...")
        exit()

    ida_path = os.environ.get("IDA_PATH", "/opt/idapro-7.7/")

    is_64bit = file_info["BITS"] == 64
    ida_path = ida_path + "idat64" if is_64bit else ida_path + "idat"
    
    print("IDA-PATH: ", ida_path)

    print("Deleting existing tmp folder...")
    try:
        shutil.rmtree("tmp")
    except:
        print("tmp folder not found")

    print("Creating new tmp folder...")
    os.mkdir("tmp")
    
    print("Copying binary to tmp folder...")
    shutil.copy(binary_file, "./tmp")
    
    print("Changing working directory to ./tmp ...")
    os.chdir("tmp")
    print("CWD: ", os.getcwd())

    binary_file = os.path.basename(binary_file)

    print("Executing ida ...")
    subprocess.run([ida_path, "-B", "-A", binary_file])
    
    print("Current ./tmp status ...")
    subprocess.run(["ls"])
    
    idb_file = binary_file + ".i64" if is_64bit else binary_file + ".idb"

    print("IDB_FILE: ", idb_file)
    print("Analyzing idb file...")
    subprocess.run([ida_path, "-S\"../ida.py\"", idb_file])

    print("Current ./tmp status ...")
    subprocess.run(["ls"])

    graph_easy_path = os.environ.get("GRAPH_EASY_PATH", "/usr/bin/graph-easy")
    print("GRAPH_EASY_PATH:", graph_easy_path)
    print("Running graph-easy...")
    subprocess.run([graph_easy_path, "--input=callgraph.gdl", "--output=callgraph.dot"])

    print("Current ./tmp status ...")
    subprocess.run(["ls"])

    binsec_path = os.environ.get("BINSEC_PATH", "")
    if len(binsec_path) == 0:
        print("No BINSEC_PATH set, exiting ...")
        exit()
    else:
        print("BINSEC_PATH: ", binsec_path) 

    ida_file = binary_file + ".ida"
    print("IDA_FILE: ", ida_file)

    isa = "x86" if file_info["ISA"] == "x86" else file_info["ISA"] + str(file_info["BITS"])
    print("ISA:", isa)

    print("Running binsec ...")
    subprocess.run([binsec_path, "-ida", "-isa", isa, "-quiet", "-ida-cfg-dot", "-ida-o-ida", ida_file])

    print("Current ./tmp status ...")
    subprocess.run(["ls"])

    print("Performing final checks ...")
    print("Checking cfgs: ", "OK" if os.path.exists("cfgs") else "Failed")
    print("Checking funcs: ", "OK" if os.path.exists(binary_file+".funcs") else "Failed")
    print("Checking callgraph: ", "OK" if os.path.exists("callgraph.dot") else "Failed")
    print("Done here, goodbye :)")

main()
