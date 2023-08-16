/// This is the CFG builder module for PFuzz.
/// We need to compute df(n,Tf), db(m,Tb) and prepare the data for
/// f = 2^(10(p(s,Tb)-0.5) as defined by AFLGo.
/// For these, we need to compute the function and basic block distances to target functions.

use std::collections::{BinaryHeap, HashMap, HashSet};
use goblin::mach::Mach::Binary;
use libafl::prelude::set_distance;
use libafl_cc::cfg::ControlFlowGraph;
use libafl_cc::HasWeight;

pub struct ICFGMetadata {}

impl HasWeight<ICFGMetadata> for ICFGMetadata {
    fn compute(metadata: Option<&ICFGMetadata>) -> u32 {
        1
    }
}

pub struct BasicBlock {
    address: usize,
    function: usize,
    successors: HashSet<usize>,
    calls: HashSet<usize>
}

impl BasicBlock {
    pub fn new(addr: usize, func: usize) -> Self {
        Self { address: addr, function: func, successors: HashSet::default(), calls: HashSet::default() }
    }

    pub fn add_successor(&mut self, succ: usize) {
        self.successors.insert(succ);
    }

    pub fn add_call(&mut self, callee: usize) {
        self.calls.insert(callee);
    }
}

pub struct Function {
    address: usize,
    name: String,
    basic_blocks: HashMap<usize, BasicBlock>
}

impl Function {
    pub fn new(addr: usize, name: &str) -> Self {
        let mut this = Self { address: addr, name: name.to_string(), basic_blocks: HashMap::default() };
        this.add_basic_block(addr);
        this
    }

    pub fn add_basic_block(&mut self, addr: usize) {
        if self.basic_blocks.contains_key(&addr) {return;}
        self.basic_blocks.insert(addr, BasicBlock::new(addr, self.address));
    }

    pub fn get_basic_block(&self, addr: usize) -> Option<&BasicBlock> {
        self.basic_blocks.get(&addr)
    }

    pub fn get_basic_block_mut(&mut self, addr: usize) -> Option<&mut BasicBlock> {
        self.basic_blocks.get_mut(&addr)
    }
}

pub struct Program {
    name: String,
    funcs: HashMap<usize, Function>,
    func_names: HashMap<String, usize>,
    targets: HashMap<String, f64>
}

impl Program {
    pub fn new(name: &str) -> Self {
        Self { name: name.to_string(), func_names: HashMap::default(), funcs: HashMap::default(), targets: HashMap::default() }
    }

    pub fn add_function(&mut self, addr: usize, name: &str) {
        if self.funcs.contains_key(&addr) {return;}
        self.func_names.insert(name.to_string(), addr);
        self.funcs.insert(addr, Function::new(addr, name));
    }

    pub fn get_func(&self, addr: usize) -> Option<&Function> {
        self.funcs.get(&addr)
    }

    pub fn get_func_mut(&mut self, addr: usize) -> Option<&mut Function> {
        self.funcs.get_mut(&addr)
    }

    pub fn get_func_addr(&mut self, name: &str) -> Option<&usize> {
        self.func_names.get(&name.to_string())
    }

    pub fn add_target_func(&mut self, func_name: &str, score: f64) {
        if self.targets.contains_key(&func_name.to_string()) {return;}
        self.targets.insert(func_name.to_string(), score);
    }

    fn compute_target_distances(&self, block: &BasicBlock, default_map: &HashMap<usize, u32>, visited: &mut HashSet<usize>, target_distances: &mut HashMap<usize, HashMap<usize, u32>>) {
        if visited.contains(&block.address) {
            return;
        }

        visited.insert(block.address);
        target_distances.insert(block.address, default_map.clone());


        let mut distance = 0;
        let func = self.funcs.get(&block.function).unwrap();

        if default_map.contains_key(&block.function) {
            target_distances.entry(block.address).and_modify(|map|{
                map.entry(block.address).and_modify(|e|{
                    *e = 0;
                });
            });
        }

        let mut self_distances = target_distances.get(&block.address).unwrap().clone();
        for next in &block.successors {
            let next_block = func.get_basic_block(*next).unwrap();
            self.compute_target_distances(next_block, default_map, visited, target_distances);
            for dists in target_distances.get(next).unwrap() {
                let comp = self_distances.get_mut(dists.0).unwrap();
                let new_dist = dists.1.saturating_add(1);
                if new_dist < *comp {
                    *comp = new_dist;
                }
            }
        }

        for callee in &block.calls {
            let target_func = self.funcs.get(callee).unwrap();
            let next_block = target_func.get_basic_block(*callee).unwrap();
            self.compute_target_distances(next_block, default_map, visited, target_distances);
            for dists in target_distances.get(callee).unwrap() {
                let comp = self_distances.get_mut(dists.0).unwrap();
                let new_dist = dists.1.saturating_add(1);
                if new_dist < *comp {
                    *comp = new_dist;
                }
            }
        }

        target_distances.insert(block.address, self_distances);
    }

    pub fn compute_distances(&mut self) {
        let mut target_distances: HashMap<usize, HashMap<usize, u32>> = HashMap::default();
        let mut func2dist: HashMap<usize, f64> = HashMap::default();
        let mut default_map = HashMap::default();
        for func in &self.targets {
            let func_entry = self.func_names.get(func.0).unwrap();
            default_map.insert(*func_entry, u32::MAX);
            func2dist.insert(*func_entry, *func.1);
        };

        for (entry, function) in &self.funcs {
            let mut visited = HashSet::new();
            let entry_block = function.basic_blocks.get(entry).unwrap();
            self.compute_target_distances(entry_block, &default_map, &mut visited, &mut target_distances);
        }

        for (_,func) in &self.funcs {
            for (_,block) in &func.basic_blocks {
                for next in &block.successors {
                    let edge = (block.address >> 1) ^ next;
                    let distances = target_distances.get(next).unwrap();
                    let mut distance = 0.0;
                    for (func,dist) in distances {
                        distance += dist.saturating_add(1) as f64 * func2dist.get(func).unwrap();
                    }
                    set_distance(edge, distance);
                }
            }
        }
    }


}