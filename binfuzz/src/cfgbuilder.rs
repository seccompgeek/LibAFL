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

    fn compute_target_distances(&self, block: &BasicBlock, edge: usize, default_map: &HashMap<usize, u32>, visited: &mut HashSet<usize>, target_distances: &mut HashMap<usize, HashMap<usize, u32>>, loops: &mut HashSet<usize>) {
        let next = (block.address >> 1) ^ edge;
        let function = self.funcs.get(&next)
    }

    pub fn compute_distances(&mut self, entry_func: &str) {
        if let Some(entry) = self.func_names.get(&entry_func.to_string()) {
            let mut target_distances: HashMap<usize, HashMap<usize, u32>> = HashMap::default();
            let mut default_map = HashMap::default();
            for func in &self.targets {
                let func_entry = self.func_names.get(&func.0).unwrap();
                default_map.insert(*func_entry, u32::MAX);
            };
            let mut visited = HashSet::new();
            let function = self.funcs.get(entry).unwrap();
            let entry_block = function.basic_blocks.get(entry).unwrap();
            for next in &entry_block.successors {
                let edge = (*entry >> 1) ^ *next;
                if self.cached_distances.contains_key(&edge) {
                    continue;
                }
                let mut loops = HashSet::new();
                self.compute_target_distances(entry_block, edge, &default_map, &mut visited, &mut target_distances, &mut loops);
                for id in &loops {
                    visited.remove(id);
                    self.compute_target_distances(*id, &default_map, &mut visited, &mut target_distances, &mut HashSet::default());
                }
                let distances = target_distances.get(edge).unwrap();
                let mut distance = 0.0;
                for dist in distances {
                    let temp_distance = (*default_map.get(dist.0).unwrap() as f64) * (*dist.1 as f64);
                    if distance == 0.0 || temp_distance < distance{
                        distance = temp_distance;
                    }
                }
                self.cached_distances.insert(*edge, distance);
                set_distance(*edge, distance);
            }
        }
    }


}

pub struct ICFG {
    cfg: ControlFlowGraph<ICFGMetadata>,
    targets: HashMap<String, f64>,
    cached_distances: HashMap<usize, f64>,
}

impl ICFG {
    pub fn new(cfg_str: &str) -> Self {
        let cfg = ControlFlowGraph::from_content(cfg_str);
        Self {
            cfg,
            targets: HashMap::default(),
            cached_distances: HashMap::default()
        }
    }

    pub fn add_target_func(&mut self, func: &str, weight: f64) {
        self.targets.insert(func.to_string(), weight);
    }

    fn compute_target_distances(&self, edge_id: usize, default_distances: &HashMap<usize, u32>, visited: &mut HashSet<usize>, distances: &mut HashMap<usize, HashMap<usize, u32>>, loops: &mut HashSet<usize>) -> bool {
        if !visited.insert(edge_id) {
            return true;
        }

        distances.insert(edge_id, default_distances.clone());
        let edge = self.cfg.get_edge(edge_id).unwrap();

        if default_distances.contains_key(&edge.bottom_node_loc) {
            distances.entry(edge_id).and_modify(|map| {
                map.entry(edge.bottom_node_loc).and_modify(|distance| {
                    *distance = 1;
                });
            });
        }


        let mut prev_distances = distances.get(&edge_id).unwrap().clone();
        let mut changed = false;
        for succ in &edge.successor_edges {
            if self.compute_target_distances(*succ, default_distances, visited, distances, loops) {
                loops.insert(edge_id);
            }
            let succ_distances = distances.get(succ).unwrap();
            for (func,dist) in &mut prev_distances {
                let succ_dist = succ_distances.get(func).unwrap();
                if succ_dist < dist {
                    *dist = succ_dist.saturating_add(1);
                    changed = true;
                }
            }
        }

        if changed {
            distances.insert(edge_id, prev_distances);
        }
        false
    }

    pub fn compute_distances(&mut self, entry_func: &str) {
        if let Some(entry) = self.cfg.get_entry(entry_func) {
            let mut target_distances: HashMap<usize, HashMap<usize, u32>> = HashMap::default();
            let mut default_map = HashMap::default();
            for func in &self.targets {
                let func_entry = self.cfg.get_entry(&func.0).unwrap();
                default_map.insert(func_entry.node_loc, u32::MAX);
            };
            let mut visited = HashSet::new();
            for edge in &entry.successor_edges {
                if self.cached_distances.contains_key(&edge) {
                    continue;
                }
                let mut loops = HashSet::new();
                self.compute_target_distances(*edge, &default_map, &mut visited, &mut target_distances, &mut loops);
                for id in &loops {
                    visited.remove(id);
                    self.compute_target_distances(*id, &default_map, &mut visited, &mut target_distances, &mut HashSet::default());
                }
                let distances = target_distances.get(edge).unwrap();
                let mut distance = 0.0;
                for dist in distances {
                    let temp_distance = (*default_map.get(dist.0).unwrap() as f64) * (*dist.1 as f64);
                    if distance == 0.0 || temp_distance < distance{
                        distance = temp_distance;
                    }
                }
                self.cached_distances.insert(*edge, distance);
                set_distance(*edge, distance);
            }
        }
    }
}