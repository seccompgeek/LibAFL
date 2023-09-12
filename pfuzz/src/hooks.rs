use hashbrown::{HashMap, hash_map::Entry};
use libafl::{self, prelude::UsesInput, state::HasMetadata};
use libafl_qemu::{QemuHelper, QemuHooks, GuestAddr, QemuHelperTuple, QemuEdgeCoverageHelper, edges::QemuEdgesMapMetadata};
use libafl_targets::{coverage::{EDGES_MAP, MAX_EDGES_NUM}, EDGES_MAP_SIZE};
use serde::{Serialize, Deserialize};
use core::cmp::max;
use std::cell::UnsafeCell;

use crate::observer::{set_distance, get_distance, distance_map_mut, set_distance_with_id, DISTANCE_MAP, get_distance_with_id, get_distances_map};

#[derive(Debug)]
pub struct QemuDistanceCoverageHelper;

impl Default for QemuDistanceCoverageHelper {
    fn default() -> Self {
        QemuDistanceCoverageHelper
    }
}

impl<S> QemuHelper<S> for QemuDistanceCoverageHelper
where
    S: UsesInput + HasMetadata
{
    fn first_exec<QT>(&self, hooks: &libafl_qemu::QemuHooks<'_, QT, S>)
        where
            QT: libafl_qemu::QemuHelperTuple<S>, {
        hooks.edges_raw(
            Some(gen_unique_edge_ids), 
            Some(trace_edge_hitcount)
        );
    }
}

/*static mut DISTANCES: *const std::collections::HashMap<usize, f64> = std::ptr::null();

fn get_distances() -> &'static std::collections::HashMap<usize,f64> {
    unsafe {
        &*DISTANCES
    }
}*/

pub fn gen_unique_edge_ids<QT, S> (
    hooks: &mut QemuHooks<'_,QT,S>,
    state: Option<&mut S>,
    src: GuestAddr,
    dest: GuestAddr
) -> Option<u64>
where  
    S: HasMetadata,
    S: UsesInput,
    QT: QemuHelperTuple<S>
{
    let state = state.expect("The gen_unique_edge_ids hook works only for in-process fuzzing");
    if state.metadata_map().get::<QemuEdgesMapMetadata>().is_none() {
        state.add_metadata(QemuEdgesMapMetadata::new());
        /*unsafe {
            DISTANCES = Box::leak(Box::new(get_distances_map())) as *const std::collections::HashMap<usize, f64>;
        }*/
    }
    let meta = state
        .metadata_map_mut()
        .get_mut::<QemuEdgesMapMetadata>()
        .unwrap();

    let id = match meta.map.entry((src, dest)) {
        Entry::Occupied(e) => {
            let id = *e.get();
            let nxt = (id as usize + 1) & (EDGES_MAP_SIZE - 1);
            unsafe {
                MAX_EDGES_NUM = max(MAX_EDGES_NUM, nxt);
            }
            id
        }
        Entry::Vacant(e) => {
            let id = meta.current_id;
            e.insert(id);
            meta.current_id = (id + 1) & (EDGES_MAP_SIZE as u64 - 1);
            unsafe {
                MAX_EDGES_NUM = meta.current_id as usize;
            }
            // GuestAddress is u32 for 32 bit guests
            //#[allow(clippy::unnecessary_cast)]
            let id = id as u64;
            id
        }
    };

    let edge_id = (src as usize >> 1) ^ (dest as usize);
    let distance = get_distance(edge_id);
    //println!("Distances: {}", distances.len());
    match distance {
        Some(dist) => {
            set_distance_with_id(id, dist);
        },
        None => {
            set_distance_with_id(id, f64::MAX);
        }
    }
    Some(id)
}

pub extern "C" fn trace_edge_hitcount(id: u64, _data: u64) {
    unsafe {
        EDGES_MAP[id as usize] = EDGES_MAP[id as usize].wrapping_add(1);
        let dist = get_distance_with_id(id);
        /*if dist != f64::MAX {
            eprintln!("Distance: ID {} = {}", id, dist);
        }*/
        DISTANCE_MAP[id as usize] = dist;
    }
}