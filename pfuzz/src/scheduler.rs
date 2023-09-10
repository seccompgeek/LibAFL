use std::collections::btree_map::Entry;
use std::marker::PhantomData;

use libafl::schedulers::powersched::{PowerQueueScheduler, N_FUZZ_SIZE, SchedulerMetadata};
use libafl::schedulers::testcase_score::CorpusPowerTestcaseScore;
use libafl::schedulers::{Scheduler, RemovableScheduler, MinimizerScheduler};
use libafl::prelude::{CorpusId, ObserversTuple, HasTestcase, MapObserver, UsesInput, TestcaseScore, Testcase, Corpus, SchedulerTestcaseMetadata, current_time, MapIndexesMetadata};
use libafl::Error;
use libafl::stages::PowerMutationalStage;
use libafl::state::{HasCorpus, HasMetadata, UsesState};
use serde::{Serialize, Deserialize};

libafl::impl_serdeany!(DistanceSchedulerMetadata);

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DistanceSchedulerMetadata {
    start_time: u64,
    max_distance: f64,
    min_distance: f64,
    distances: Vec<f64>
}

impl DistanceSchedulerMetadata{
    pub fn new() -> Self {
        Self {start_time: current_time().as_secs(), max_distance: f64::MAX, min_distance: f64::MAX, distances: vec![f64::MAX; N_FUZZ_SIZE] }
    }

    pub fn max_distance(&self) -> f64 {
        self.max_distance
    }

    pub fn min_distance(&self) -> f64 {
        self.min_distance
    }

    pub fn set_max_distance(&mut self, dist: f64) {
        self.max_distance = dist;
    }

    pub fn set_min_distance(&mut self, dist: f64) {
        self.min_distance = dist;
    }

    pub fn distances(&self) -> &[f64]{
        &self.distances
    }

    pub fn distances_mut(&mut self) -> &mut [f64]{
        &mut self.distances
    }

    pub fn start_time(&self) -> u64 {
        self.start_time
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DistanceTestcaseMetadata {
    distance: f64,
    distance_entry: usize
}

impl DistanceTestcaseMetadata {
    pub fn new(distance: f64) -> Self {
        Self{
            distance,
            distance_entry: 0
        }
    }

    pub fn with_distance_entry(distance: f64, distance_entry: usize) -> Self {
        Self { distance, distance_entry }
    }

    pub fn set_distance(&mut self, distance: f64) {
        self.distance = distance;
    }

    pub fn set_distance_entry(&mut self, distance_entry: usize) {
        self.distance_entry = distance_entry;
    }

    pub fn distance_entry(&self) -> usize {
        self.distance_entry
    }

    pub fn distance(&self) -> f64 {
        self.distance
    }
}

libafl::impl_serdeany!(DistanceTestcaseMetadata);

#[derive(Debug, Clone)]
pub struct DistancePowerScheduler<O,S> {
    power_scheduler: PowerQueueScheduler<O,S>,
    observer_name: String,
    last_hash: usize,
}

impl<O,S> UsesState for DistancePowerScheduler<O,S>
where
    S: UsesInput
{
    type State = S;
}

impl<O,S> RemovableScheduler for DistancePowerScheduler<O,S>
where
    S: HasCorpus + HasMetadata + HasTestcase,
    O: MapObserver<Entry = f64>,
{
    fn on_remove(
            &mut self,
            state: &mut Self::State,
            idx: CorpusId,
            prev: &Option<Testcase<<Self::State as UsesInput>::Input>>,
        ) -> Result<(), Error> {
        let _ = self.power_scheduler.on_remove(state, idx, prev);
        
        let prev = prev.as_ref().ok_or_else(||{
            Error::illegal_argument("Distance schedulers need the removed corpus entry for recalibration",)
        })?;

        let prev_meta = prev.metadata::<DistanceTestcaseMetadata>()?;
        let dsmeta = state.metadata_mut::<DistanceSchedulerMetadata>()?;
        dsmeta.distances_mut()[prev_meta.distance_entry] = f64::MAX;
        let mut min_distance = f64::MAX;
        let mut max_distance = f64::MIN;
        for dist in dsmeta.distances() {
            if *dist > max_distance && *dist != f64::MAX {
                max_distance = *dist;
            }

            if *dist < min_distance {
                min_distance = *dist;
            }
        }
        if prev_meta.distance() == dsmeta.max_distance() {
            
            if max_distance > f64::MIN {
                dsmeta.set_max_distance(max_distance);
            }else{
                dsmeta.set_max_distance(f64::MAX);
            }
        }

        if prev_meta.distance() == dsmeta.min_distance() {
            dsmeta.set_min_distance(min_distance);
        }

        Ok(())
    }

    fn on_replace(
            &mut self,
            state: &mut Self::State,
            idx: CorpusId,
            prev: &Testcase<<Self::State as UsesInput>::Input>,
        ) -> Result<(), Error> {
        let _ = self.power_scheduler.on_replace(state, idx, prev);

        //TODO! really not sure how to handle the distance here
        let prev_meta = prev.metadata::<DistanceTestcaseMetadata>()?;
        let dsmeta = state.metadata_mut::<DistanceSchedulerMetadata>()?;
        dsmeta.distances_mut()[prev_meta.distance_entry()] = f64::MAX;

        state.testcase_mut(idx)?
            .add_metadata(DistanceTestcaseMetadata::new(f64::MAX));
        Ok(())
    }
}

impl<O,S> Scheduler for DistancePowerScheduler<O,S>
where 
    S: HasCorpus + HasMetadata + HasTestcase,
    O: MapObserver<Entry = f64>,
{
    fn next(&mut self, state: &mut Self::State) -> Result<CorpusId, libafl::Error> {
        self.power_scheduler.next(state)
    }

    fn on_add(&mut self, state: &mut Self::State, idx: CorpusId) -> Result<(), Error> {
        
        let _ = self.power_scheduler.on_add(state, idx);

        let current_idx = *state.corpus().current();
        let distance = match current_idx {
            Some(parent_idx) => state
                        .testcase(parent_idx)?
                        .metadata::<DistanceTestcaseMetadata>()?
                        .distance(),
            _ => f64::MAX
        };

        let mut testcase = state.testcase_mut(idx)?;
        testcase.add_metadata(DistanceTestcaseMetadata::with_distance_entry(distance, self.last_hash));
        Ok(())
    }

    fn on_evaluation<OT>(
            &mut self,
            state: &mut Self::State,
            input: &<Self::State as UsesInput>::Input,
            observers: &OT,
        ) -> Result<(), Error>
        where
            OT: ObserversTuple<Self::State>, {
        
        let observer = observers
                        .match_name::<O>(&self.observer_name)
                        .ok_or_else(|| Error::key_not_found("MapObserver not found".to_string()))?;
        
        let mut hash = observer.hash() as usize;

        let dsmeta = state.metadata_mut::<DistanceSchedulerMetadata>()?;
        hash %= dsmeta.distances().len();

        // update the distance
        let mut distance = 0.0;
        let strace = observer.count_bytes();

        /* This is a computation of AFLGO's normalized distance */
        let distances: Vec<f64> = observer.to_vec();
        let mut new_min = dsmeta.min_distance();
        let mut new_max = dsmeta.max_distance();
        for elem in &distances {
            if elem != &f64::default() {
                if elem > &new_max || new_max == f64::MAX {
                    new_max = *elem;
                }

                if elem < &new_min {
                    new_min = *elem;
                }

                if elem != &f64::MAX {
                    distance += *elem;
                }
            }
        }

        if distance == 0.0 && strace != 0 {
            distance = f64::MAX;
        }

        distance /= strace as f64;

        if dsmeta.min_distance() != dsmeta.max_distance() {
            distance = (distance - dsmeta.min_distance())/(dsmeta.max_distance() - dsmeta.min_distance());
            dsmeta.distances_mut()[hash] = distance;
        }else if distance != 0.0 {
            dsmeta.distances_mut()[hash] = 1.0;
        }

        if distance > new_max || new_max == f64::MAX {
            new_max = distance;
        }

        if distance < new_min {
            new_min = distance;
        }

        //panic!("Evaluation: distance {} strace {} newmin {} newmax {}",distance, strace, new_min, new_max);
        dsmeta.set_min_distance(new_min);
        dsmeta.set_max_distance(new_max);
        
        self.last_hash = hash;
        self.power_scheduler.on_evaluation(state, input, observers)
    }

    fn set_current_scheduled(
            &mut self,
            state: &mut Self::State,
            next_idx: Option<CorpusId>,
        ) -> Result<(), Error> {
        self.power_scheduler.set_current_scheduled(state, next_idx)
    }

}

impl<O,S> DistancePowerScheduler<O,S>
where
    S: HasMetadata,
    O: MapObserver,
{
    pub fn new(state: &mut S, map_observer_name: &str, power_scheduler: PowerQueueScheduler<O,S>) -> Self {
        if !state.has_metadata::<DistanceSchedulerMetadata>() {
            state.add_metadata::<DistanceSchedulerMetadata>(DistanceSchedulerMetadata::new());
        }
        Self { power_scheduler, observer_name: map_observer_name.to_string(), last_hash: 0}
    }
}


#[derive(Debug, Clone)]
pub struct DistanceTestcaseScore<S> {
    phantom: PhantomData<S>
}

impl<S> TestcaseScore<S> for DistanceTestcaseScore<S> 
where 
    S: HasCorpus + HasMetadata
{
    #[allow(
        clippy::cast_precision_loss,
        clippy::too_many_lines,
        clippy::cast_sign_loss,
        clippy::cast_lossless
    )]
    fn compute(state: &S, entry: &mut Testcase<<S>::Input>) -> Result<f64, Error> {
        let tcmeta = entry.metadata::<DistanceTestcaseMetadata>()?;
        let dsmeta = state.metadata::<DistanceSchedulerMetadata>()?;
        let psmeta = state.metadata::<SchedulerMetadata>()?;
        let distance = dsmeta.distances()[tcmeta.distance_entry()];
        Ok(distance)
    }
}

#[derive(Debug, Clone)]
pub struct DistancePowerTestcaseScore<S> {
    phantom: PhantomData<S>
}

impl<S> TestcaseScore<S> for DistancePowerTestcaseScore<S>
where
    S: HasCorpus + HasMetadata
{
    #[allow(
        clippy::cast_precision_loss,
        clippy::too_many_lines,
        clippy::cast_sign_loss,
        clippy::cast_lossless
    )]
    fn compute(state: &S, entry: &mut Testcase<<S>::Input>) -> Result<f64, Error> {
        let pafl = CorpusPowerTestcaseScore::compute(state, entry)?;
        let tcmeta = entry.metadata::<DistanceTestcaseMetadata>()?;
        let dsmeta = state.metadata::<DistanceSchedulerMetadata>()?;
        let psmeta = state.metadata::<SchedulerMetadata>()?;
        let distance = dsmeta.distances()[tcmeta.distance_entry()];
        let exp = (current_time().as_secs() - dsmeta.start_time()) as f64/2400.0;
        let t_exp = f64::powf(20.0, -exp);
        let ps = (1.0 - distance)*(1.0 - t_exp) + 0.5*t_exp;
        let power = f64::powf(2.0, 10.0*ps - 5.0);
        //panic!("Annealing power: exp {}  t_exp {} distance {} ps {} pafl {} power {}", exp, t_exp, distance, ps, pafl, power);
        Ok(power*pafl)
    }
}

/// The standard powerscheduling stage
pub type StdDistancePowerMutationalStage<E, EM, I, M, Z> = PowerMutationalStage<E, DistancePowerTestcaseScore<<E as UsesState>::State>, EM, I, M, Z>;
pub type DistanceMinimizerScheduler<CS> = MinimizerScheduler<CS, DistanceTestcaseScore<<CS as UsesState>::State>, MapIndexesMetadata>;