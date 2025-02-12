use hashbrown::{HashMap, hash_map::Entry};
use libafl::{self, prelude::UsesInput, state::HasMetadata, impl_serdeany};
use libafl_qemu::{QemuHelper, QemuHooks, GuestAddr, QemuHelperTuple, QemuEdgeCoverageHelper, edges::QemuEdgesMapMetadata, hash_me};
use libafl_targets::{coverage::{EDGES_MAP, MAX_EDGES_NUM, EDGES_MAP_PTR_NUM, EDGES_MAP_PTR}, EDGES_MAP_SIZE};
use serde::{Serialize, Deserialize};
use shared_hashmap::SharedMemoryHashMap;
use core::cmp::max;
use std::cell::UnsafeCell;

use crate::observer::{set_static_distance, get_static_distance, distance_map_mut, get_inter_distance, set_inter_distance, DYNAMIC_DISTANCE_MAP, set_inter_ptr_distance, get_inter_ptr_distance, MAX_STATIC_DISTANCE_MAP_SIZE, DYNAMIC_DISTANCE_MAP_PTR, MAX_DYNAMIC_DISTANCE_MAP_SIZE, INTER_DISTANCE_MAP_PTR};

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
    let distance = get_static_distance(edge_id % MAX_STATIC_DISTANCE_MAP_SIZE);
    set_inter_distance(id as usize, distance);
    Some(id)
}

pub extern "C" fn trace_edge_hitcount(id: u64, _data: u64) {
    unsafe {
        EDGES_MAP[id as usize] = EDGES_MAP[id as usize].wrapping_add(1);
        DYNAMIC_DISTANCE_MAP[id as usize] = get_inter_distance(id as usize); 
    }
}

pub extern "C" fn trace_edge_hitcount_ptr(id: u64, _data: u64) {
    unsafe {
        let ptr = EDGES_MAP_PTR.add(id as usize);
        *ptr = (*ptr).wrapping_add(1);
        let ptr = DYNAMIC_DISTANCE_MAP_PTR.add(id as usize % MAX_DYNAMIC_DISTANCE_MAP_SIZE);
        *ptr = get_inter_ptr_distance(id as usize % MAX_DYNAMIC_DISTANCE_MAP_SIZE);
    }
}

#[derive(Debug)]
pub struct QemuDistanceCoverageChildHelper;


pub fn gen_hashed_edge_ids<QT, S>(
    hooks: &mut QemuHooks<'_, QT, S>,
    _state: Option<&mut S>,
    src: GuestAddr,
    dest: GuestAddr
) -> Option<u64>
where
    S: UsesInput,
    QT: QemuHelperTuple<S>
{
    #[allow(clippy::unnecessary_cast)]
    let id = (hash_me(src as u64) ^ hash_me(dest as u64)) & (unsafe {EDGES_MAP_PTR_NUM} as u64 - 1);
    let edge_id = ((src as usize >> 1) ^ (dest as usize)) % MAX_STATIC_DISTANCE_MAP_SIZE;
    let distance = get_static_distance(edge_id);
    set_inter_ptr_distance(id as usize % MAX_DYNAMIC_DISTANCE_MAP_SIZE, distance);
    Some(id)
}


impl Default for QemuDistanceCoverageChildHelper {
    fn default() ->  Self {
        QemuDistanceCoverageChildHelper
    }
}

impl<S> QemuHelper<S> for QemuDistanceCoverageChildHelper
where
    S: UsesInput,
    S: HasMetadata
{
    const HOOKS_DO_SIDE_EFFECTS: bool = false;

    fn first_exec<QT>(&self, hooks: &QemuHooks<'_, QT, S>)
        where
            QT: QemuHelperTuple<S>, {
        hooks.edges_raw(Some(gen_hashed_edge_ids::<QT,S>), Some(trace_edge_hitcount_ptr));
    }
}