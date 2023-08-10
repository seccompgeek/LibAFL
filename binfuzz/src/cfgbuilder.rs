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
                    *dist = succ_dist + 1;
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
                    println!("{}->{}: {}", edge, dist.0, dist.1);
                    distance += (default_map.get(dist.0).unwrap() * dist.1) as f64;
                }
                self.cached_distances.insert(*edge, distance);
                set_distance(*edge, distance);
            }
        }
    }
}