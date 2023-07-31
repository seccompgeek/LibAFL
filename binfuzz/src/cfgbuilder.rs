use std::collections::{HashMap, HashSet};
use std::hash::Hash;
use libafl_cc::cfg::ControlFlowGraph;

enum InEdge {
    Foreign(usize, usize),
    Local(usize)
}

pub struct BasicBlock {
    id: usize, //the id of a BB == its address in the elf file
    parent: usize, //the function to which this block belongs
    incoming: HashSet<InEdge>, //incoming block ids
    target_distances: HashMap<usize, usize>
}

impl BasicBlock {
    pub fn new(id: usize, parent: usize) -> Self{
        Self{
            id,
            parent,
            incoming: HashSet::default(),
            target_distances: HashMap::default()
        }
    }

    pub fn add_local_incoming(&mut self, id: usize) {
        self.incoming.insert(InEdge::Local(id));
    }

    pub fn add_foreign_incoming(&mut self, from_func: usize, id: usize) {
        self.incoming.insert(InEdge::Foreign(from_func,id));
    }

}


pub struct Function {
    entry_block: usize,
    name: String,
    basic_blocks: HashMap<usize, BasicBlock>,
    incoming_callers: Vec<usize>,
    is_target: bool
}

impl Function {
    pub fn new(name: &str, id: usize, is_target: bool) -> Self{
        Self {
            entry_block: id,
            name: String::from(name),
            basic_blocks: HashMap::default(),
            incoming_callers: Vec::new(),
            is_target
        }
    }

    pub fn add_block(&mut self, block_id: usize) {
        let bb = BasicBlock::new(block_id, self.entry_block);
        self.basic_blocks.insert(block_id, bb);
    }

    pub fn add_incoming_caller(&mut self, caller_id: usize) {
        self.incoming_callers.push(caller_id);
    }

    pub fn add_edge(&mut self, from: usize, to: usize, from_func: Option<usize>) -> Result<(), Err(String)>{
        if let Some(block) = self.basic_blocks.get_mut(&to) {
            if from_func.is_some() {
                block.add_foreign_incoming(from_func.unwrap(), from);
            }else{
                block.add_local_incoming(from);
            }
            Ok(())
        }else{
            Err("Adding incoming edge to non-existent block!".to_string())
        }
    }
}

pub struct ICFG {
    prog_name: String,
    func_names_map: HashMap<String, usize>,
    func_ids_map: HashMap<usize, Function>,
    target_funcs: Vec<usize>
}

impl ICFG {
    pub fn new(name: &str) -> Self {
        Self {
            prog_name: String::from(name),
            func_names_map: HashMap::default(),
            func_ids_map: HashMap::default(),
            target_funcs: Vec::new()
        }
    }

    pub fn add_func(&mut self, func_id: usize, func_name: &str, is_target: bool) {
        let func_name = String::from(func_name);
        self.func_names_map.insert(func_name, func_id);
        let mut function = Function::new(func_name.as_str(), func_id, is_target);
        function.add_block(func_id);
        self.func_ids_map.insert(func_id, function);
        if is_target {
            self.target_funcs.push(func_id);
        }
    }

    pub fn add_target_func(&mut self, func_id: usize) {
        self.func_ids_map.entry(func_id).and_modify(|f|{
            f.is_target = true
        });
        self.target_funcs.push(func_id);
    }

    pub fn add_block(&mut self, block_id: usize, block_parent: String) -> Result<(),Err(String)>{
        if let Some(func_id) = self.func_names_map.get(&block_parent) {
            self.func_ids_map.entry(*func_id).and_modify(|f|{
                f.add_block(block_id);
            });
            Ok(())
        }else {
            Err("No such function exists".to_string())
        }
    }

    pub fn add_edge(&mut self, func: String, from: usize, to: usize, from_func: Option<String>) -> Result<(),Err(String)> {
        if let Some(func_id) = self.func_names_map.get(&func) {
            if let Some(from_func) = self.func_names_map.get(from_func.as_ref().unwrap()) {
                self.func_ids_map.entry(*func_id).and_modify(|f|{
                    f.add_edge(from, to, Some(*from_func))?;
                });
            }else{
                return Err("From function does not exist!".to_string());
            }
            Ok(())
        }else {
            Err("No such function exists".to_string())
        }
    }
}

