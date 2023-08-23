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

lazy_static! {
    static ref DISTANCES: Mutex<HashMap<usize, f64>> = Mutex::new(HashMap::default());
}

static mut DISTANCE_MAP: [f64; 65000] = [f64::MAX; 65000];

pub fn get_distance(edge_id: usize) -> Option<f64>{
    let lock = DISTANCES.lock();
    let distances = lock.as_ref().unwrap();
    match distances.get(&edge_id) {
        Some(d) => Some(*d),
        _ => None
    }
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
    65000
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(bound = "M: serde::de::DeserializeOwned")]
pub struct DistanceMapObserver<M>
where M: Serialize
{
    base: HitcountsMapObserver<M>
}

impl<S, M> Observer<S> for DistanceMapObserver<M>
where
    M: MapObserver<Entry = u8> + Observer<S> + AsMutSlice<Entry = u8>,
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
        let _ = self.base.post_exec(state, input, exit_kind);
        if let Some(id_map) = state.metadata_map().get::<QemuEdgesMapMetadata>() {
            let hit_map = self.base.as_mut_slice();
            let dist_map = distance_map_mut();
            for (addr_tuple, id) in &id_map.map {
                let id = *id as usize;
                if hit_map[id] != u8::default() {
                    let edge_id = ((addr_tuple.0 >> 1) ^ addr_tuple.1) as usize;
                    if let Some(d) = get_distance(edge_id) {
                        dist_map[id] = d;
                    }
                }
            }
        }
        
        Ok(())
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
    M: MapObserver<Entry = u8>,
{
    type Entry = f64;

    #[inline]
    fn initial(&self) -> f64 {
        f64::MAX
    }

    #[inline]
    fn usable_count(&self) -> usize {
        self.base.usable_count()
    }

    #[inline]
    fn get(&self, idx: usize) -> &f64 {
        &distance_map_mut()[idx]
    }

    #[inline]
    fn get_mut(&mut self, idx: usize) -> &mut f64 {
        &mut distance_map_mut()[idx]
    }

    /// Count the set bytes in the map
    fn count_bytes(&self) -> u64 {
        self.base.count_bytes()
    }

    /// Reset the map
    #[inline]
    fn reset_map(&mut self) -> Result<(), Error> {
        let  _ =self.base.reset_map();
        let _ = distance_map_mut().iter_mut().map(|d|{
            *d = f64::MAX
        });
        Ok(())
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
    pub fn new(base: HitcountsMapObserver<M>) -> Self {
        Self { base }
    }
}

impl<'it, M> AsIter<'it> for DistanceMapObserver<M>
where
    M: Named + Serialize + serde::de::DeserializeOwned + AsIter<'it, Item = u8>,
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
        + MapObserver<Entry = u8>
        + Serialize
        + AsMutSlice<Entry = u8>,
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
