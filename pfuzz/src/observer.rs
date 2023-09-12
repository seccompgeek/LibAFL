use std::{sync::Mutex, collections::HashMap};

use libafl::state::HasMetadata;
use libafl_qemu::QemuHooks;
use libafl::observers::{MapObserver, Observer, DifferentialObserver, ObserversTuple, HitcountsMapObserver};
use libafl::bolts::{AsMutSlice, AsIter, AsSlice, AsIterMut, HasLen, Truncate};
use libafl::bolts::tuples::Named;
use libafl::inputs::UsesInput;
use libafl::executors::ExitKind;
use libafl::Error;

use libafl_qemu::edges::QemuEdgesMapMetadata;
use serde::{Deserialize, Serialize};

use lazy_static::lazy_static;
use shared_hashmap::SharedMemoryHashMap;

lazy_static! {
    static ref DISTANCES: Mutex<HashMap<usize, f64>> = Mutex::new(HashMap::default());
    static ref DISTANCE_ID_MAP: Mutex<HashMap<u64, f64>> = Mutex::new(HashMap::default());
}

pub const MAX_DISTANCE_MAP_SIZE: usize = 65536;
pub static mut DISTANCE_MAP: [f64; MAX_DISTANCE_MAP_SIZE] = [f64::MAX; MAX_DISTANCE_MAP_SIZE];

pub fn get_distance(edge_id: usize) -> Option<f64>{
    let lock = DISTANCES.lock();
    let distances = lock.as_ref().unwrap();
    match distances.get(&edge_id) {
        Some(d) => Some(*d),
        _ => None
    }
}

pub fn get_distances_map() -> HashMap<usize, f64> {
    let lock = DISTANCES.lock();
    let distances = lock.as_ref().unwrap();
    let mut clone = HashMap::default();
    clone.extend(distances.iter());
    clone
}

pub fn set_distance(edge_id: usize, distance: f64) {
    let mut lock = DISTANCES.lock();
    let distances = lock.as_mut().unwrap();
    distances.insert(edge_id, distance);
}

pub fn distance_map_mut() ->&'static mut [f64] {
    unsafe {
        DISTANCE_MAP.as_mut()
    }
}

pub fn distance_map_size() -> usize {
    MAX_DISTANCE_MAP_SIZE
}

pub fn set_distance_with_id(id: u64, dist: f64) {
    let mut lock = DISTANCE_ID_MAP.lock();
    let distances = lock.as_mut().unwrap();
    distances.insert(id, dist);
}

pub fn get_distance_with_id(id: u64) -> f64 {
    let mut lock = DISTANCE_ID_MAP.lock();
    let distances = lock.as_ref().unwrap();
    *distances.get(&id).unwrap()
}


#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(bound = "M: serde::de::DeserializeOwned")]
pub struct DistanceMapObserver<M>
where M: Serialize
{
    base: M
}

impl<S, M> Observer<S> for DistanceMapObserver<M>
where
    M: MapObserver<Entry = f64> + Observer<S> + AsMutSlice<Entry = f64>,
    S: UsesInput + HasMetadata,
{
    #[inline]
    fn pre_exec(&mut self, state: &mut S, input: &S::Input) -> Result<(), Error> {
        self.base.pre_exec(state, input)
    }

    #[inline]
    #[allow(clippy::cast_ptr_alignment)]
    fn post_exec(
        &mut self,
        state: &mut S,
        input: &S::Input,
        exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        self.base.post_exec(state, input, exit_kind)
    }
}

impl<M> Named for DistanceMapObserver<M>
where
    M: Named + Serialize + serde::de::DeserializeOwned,
{
    #[inline]
    fn name(&self) -> &str {
        self.base.name()
    }
}

impl<M> HasLen for DistanceMapObserver<M>
where
    M: MapObserver,
{
    #[inline]
    fn len(&self) -> usize {
        self.base.len()
    }
}

impl<M> MapObserver for DistanceMapObserver<M>
where
    M: MapObserver<Entry = f64>,
{
    type Entry = f64;

    #[inline]
    fn initial(&self) -> f64 {
        self.base.initial()
    }

    #[inline]
    fn usable_count(&self) -> usize {
        self.base.usable_count()
    }

    #[inline]
    fn get(&self, idx: usize) -> &f64 {
        self.base.get(idx)
    }

    #[inline]
    fn get_mut(&mut self, idx: usize) -> &mut f64 {
        self.base.get_mut(idx)
    }

    /// Count the set bytes in the map
    fn count_bytes(&self) -> u64 {
        self.base.count_bytes()
    }

    /// Reset the map
    #[inline]
    fn reset_map(&mut self) -> Result<(), Error> {
        self.base.reset_map()
    }

    fn hash(&self) -> u64 {
        self.base.hash()
    }
    fn to_vec(&self) -> Vec<f64> {
        distance_map_mut().to_vec()
    }

    fn how_many_set(&self, indexes: &[usize]) -> usize {
        self.base.how_many_set(indexes)
    }
}

impl<M> Truncate for DistanceMapObserver<M>
where
    M: Named + Serialize + serde::de::DeserializeOwned + Truncate,
{
    fn truncate(&mut self, new_len: usize) {
        self.base.truncate(new_len);
    }
}

impl<M> AsSlice for DistanceMapObserver<M>
where
    M: MapObserver + AsSlice,
{
    type Entry = <M as AsSlice>::Entry;
    #[inline]
    fn as_slice(&self) -> &[Self::Entry] {
        self.base.as_slice()
    }
}

impl<M> AsMutSlice for DistanceMapObserver<M>
where
    M: MapObserver + AsMutSlice,
{
    type Entry = <M as AsMutSlice>::Entry;
    #[inline]
    fn as_mut_slice(&mut self) -> &mut [Self::Entry] {
        self.base.as_mut_slice()
    }
}

impl<M> DistanceMapObserver<M>
where
    M: Serialize + serde::de::DeserializeOwned,
{
    /// Creates a new [`MapObserver`]
    pub fn new(base: M) -> Self {
        Self { base }
    }
}

impl<'it, M> AsIter<'it> for DistanceMapObserver<M>
where
    M: Named + Serialize + serde::de::DeserializeOwned + AsIter<'it, Item = f64>,
{
    type Item = f64;
    type IntoIter = <&'it [f64] as IntoIterator>::IntoIter;

    fn as_iter(&'it self) -> Self::IntoIter {
        distance_map_mut().as_slice().into_iter()
    }
}

impl<'it, M> AsIterMut<'it> for DistanceMapObserver<M>
where
    M: Named + Serialize + serde::de::DeserializeOwned + AsIterMut<'it, Item = f64>,
{
    type Item = f64;
    type IntoIter = <&'it mut [f64] as IntoIterator>::IntoIter;

    fn as_iter_mut(&'it mut self) -> Self::IntoIter {
        distance_map_mut().into_iter()
    }
}

impl<'it, M> IntoIterator for &'it DistanceMapObserver<M>
where
    M: Named + Serialize + serde::de::DeserializeOwned,
    &'it M: IntoIterator<Item = &'it f64>,
{
    type Item = &'it f64;
    type IntoIter = <&'it [f64] as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        distance_map_mut().as_slice().into_iter()
    }
}

impl<'it, M> IntoIterator for &'it mut DistanceMapObserver<M>
where
    M: Named + Serialize + serde::de::DeserializeOwned,
    &'it mut M: IntoIterator<Item = &'it mut f64>,
{
    type Item = &'it mut f64;
    type IntoIter = <&'it mut [f64] as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        distance_map_mut().into_iter()
    }
}

impl<M, OTA, OTB, S> DifferentialObserver<OTA, OTB, S> for DistanceMapObserver<M>
where
    M: DifferentialObserver<OTA, OTB, S>
        + MapObserver<Entry = f64>
        + Serialize
        + AsMutSlice<Entry = f64>,
    OTA: ObserversTuple<S>,
    OTB: ObserversTuple<S>,
    S: UsesInput + HasMetadata,
{
    fn pre_observe_first(&mut self, observers: &mut OTA) -> Result<(), Error> {
        self.base.pre_observe_first(observers)
    }

    fn post_observe_first(&mut self, observers: &mut OTA) -> Result<(), Error> {
        self.base.post_observe_first(observers)
    }

    fn pre_observe_second(&mut self, observers: &mut OTB) -> Result<(), Error> {
        self.base.pre_observe_second(observers)
    }

    fn post_observe_second(&mut self, observers: &mut OTB) -> Result<(), Error> {
        self.base.post_observe_second(observers)
    }
}
