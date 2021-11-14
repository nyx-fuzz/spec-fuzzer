use std::rc::Rc;
//use std::borrow::Borrow;
use std::sync::Arc;

use crate::graph_mutator::graph_builder::{GraphBuilder,GraphState};
use crate::graph_mutator::graph_iter::GraphNode;
use crate::graph_mutator::graph_storage::GraphStorage;
use crate::graph_mutator::graph_storage::VecGraph;
use crate::graph_mutator::spec::GraphSpec;
use crate::primitive_mutator::mutator::PrimitiveMutator;
use crate::random::distributions::Distributions;
use crate::custom_dict::CustomDict;

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub enum MutationStrategy{
    GenerateTail(GenerateTail),
    SpliceRandom,
    Splice,
    DataOnly,
    Generate,
    Repeat,
    Minimize,
    MinimizeSplit,
    Import,
    SeedImport,
}

impl MutationStrategy{
    pub fn name(&self) -> &str{
        match self{
            MutationStrategy::GenerateTail(_) => "generate_tail",
            MutationStrategy::SpliceRandom => "splice_random",
            MutationStrategy::Splice => "splice",
            MutationStrategy::DataOnly => "data_only",
            MutationStrategy::Generate => "generate",
            MutationStrategy::Repeat => "repeat",
            MutationStrategy::Minimize => "minimize",
            MutationStrategy::MinimizeSplit => "minimize_split",
            MutationStrategy::Import=>"import",
            MutationStrategy::SeedImport=>"seed_import"
        }
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub struct GenerateTail{ pub drop_last: usize, pub generate: usize }

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub enum NodeMutationType {
    CopyNode,
    MutateNodeData,
    DropNode,
    SkipAndGenerate,
}

pub struct MutatorSnapshotState{
    pub skip_nodes: usize,
    pub skip_ops: usize,
    pub skip_data: usize,
    pub prefix_graph_state: Option<GraphState>,
}

impl MutatorSnapshotState{
    pub fn none() -> Self {
        return Self{skip_data:0, skip_nodes: 0, skip_ops:0, prefix_graph_state: None}
    }
}

pub struct Mutator {
    pub spec: Rc<GraphSpec>,
    builder: GraphBuilder,
    mutator: PrimitiveMutator,
}

pub trait InputQueue {
    fn sample_for_splicing(&self, dist: &Distributions) -> Arc<VecGraph>;
}

impl InputQueue for Vec<VecGraph>{
    fn sample_for_splicing(&self, dist: &Distributions) -> Arc<VecGraph>{
        assert!(self.len() > 0);
        return Arc::new(self[dist.gen_range(0,self.len())].clone());
    }
}

impl Mutator {
    pub fn new(spec: GraphSpec) -> Self {
        let spec = Rc::new(spec);
        let mutator = PrimitiveMutator::new();
        let builder = GraphBuilder::new(spec.clone());

        return Self {
            spec,
            builder,
            mutator,
        };
    }

    pub fn mutate<S: GraphStorage, Q: InputQueue>(&mut self, orig: &VecGraph, ops_used: usize, dict: &CustomDict, snapshot: &MutatorSnapshotState, queue: &Q, storage: &mut S, dist: &Distributions) -> MutationStrategy{
        let orig_len =  ops_used as usize-snapshot.skip_nodes;

        if orig.op_len()== 0 || orig_len == 0 || ops_used == 0 {
            self.generate(50, snapshot, storage, dist);
            return MutationStrategy::Generate;
        }

        let strategy = dist.gen_mutation_strategy(orig_len);
        match strategy{
            MutationStrategy::GenerateTail(args) => self.generate_tail(orig, ops_used, snapshot, args, storage, dist),
            MutationStrategy::SpliceRandom => self.splice_random(orig, ops_used, snapshot, dict, storage, dist),
            MutationStrategy::Splice => self.splice(orig, ops_used, snapshot,queue, storage, dist),
            MutationStrategy::DataOnly => self.mutate_data(orig, ops_used, snapshot, dict, storage, dist),
            MutationStrategy::Generate => self.generate(50, snapshot, storage, dist),
            MutationStrategy::Repeat => self.repeat(orig, ops_used, snapshot, dict, storage, dist),
            MutationStrategy::Minimize => unreachable!(),
            MutationStrategy::MinimizeSplit => unreachable!(),
            MutationStrategy::Import => unreachable!(),
            MutationStrategy::SeedImport => unreachable!(),
        }
        return strategy;
    }

    pub fn prepare_snapshot<S: GraphStorage>(&mut self, snapshot_cutoff: usize, data: &VecGraph, storage: &mut S, dist: &Distributions) -> MutatorSnapshotState{
        self.builder.start(storage, &MutatorSnapshotState::none());
        for n in data.node_iter(&self.spec).take(snapshot_cutoff){
            self.builder.append_node(&n, storage, dist);
        }
        let prefix_graph_state = Some(self.builder.get_graph_state());
        let skip_ops =storage.op_len();
        let skip_data = storage.data_len();
        storage.append_op(self.spec.snapshot_node_id.unwrap().as_u16());
        return MutatorSnapshotState{skip_nodes: snapshot_cutoff, skip_ops, skip_data, prefix_graph_state};
    }

    pub fn repeat<S: GraphStorage>(&mut self, orig: &VecGraph, ops_used: usize, snapshot: &MutatorSnapshotState, dict: &CustomDict, storage: &mut S, dist: &Distributions) {
        self.builder.start(storage, snapshot);

        let fragment_nodes = dist.gen_range(2, 16);
        let repeats = dist.gen_range(2, 6);
        let insert_pos = if ops_used-snapshot.skip_nodes-1 > 0 {
         dist.gen_range(0, ops_used-snapshot.skip_nodes-1)
        } else { 0 };
        //println!("REPEAT {}..{} (out of {} with {} skipped) for {} times",insert_pos, insert_pos+fragment_nodes, orig.node_len(&self.spec), snapshot.skip_nodes, repeats);
        for n in orig.node_iter(&self.spec.clone()).skip(snapshot.skip_nodes).take(insert_pos) {
            if self.builder.is_full(storage){return;}
            self.builder.append_node(&n, storage, dist); 
        }

        let origs = orig.node_iter(&self.spec).skip(snapshot.skip_nodes+insert_pos).take(fragment_nodes).collect::<Vec<_>>();
        assert!(origs.len() > 0);
        assert!(repeats > 1);
        for _ in 0..repeats {
            for n in origs.iter() {
                if self.builder.is_full(storage){return;}
                self.builder.append_node_mutated(&n, dict, &self.mutator, storage, dist);
            }
        }

        for n in orig.node_iter(&self.spec.clone()).skip(snapshot.skip_nodes+insert_pos) {
            if self.builder.is_full(storage){return;}
            self.builder.append_node(&n, storage, dist); 
        }
    }

    pub fn generate_tail<S: GraphStorage>(&mut self,  orig: &VecGraph, ops_used: usize, snapshot: &MutatorSnapshotState, args: GenerateTail, storage: &mut S, dist: &Distributions){
        let orig_len =  ops_used-snapshot.skip_nodes;

        self.builder.start(storage, snapshot);
        for n in orig.node_iter(&self.spec).skip(snapshot.skip_nodes).take(orig_len-args.drop_last) {
            if self.builder.is_full(storage){return;}
            self.builder.append_node(&n, storage, dist);
        }
        
        self.builder.append_random(args.generate, &self.mutator, storage, dist).unwrap();
    }

    pub fn mutate_data<S: GraphStorage>(&mut self, orig: &VecGraph, ops_used: usize, snapshot: &MutatorSnapshotState, dict: &CustomDict,  storage: &mut S, dist: &Distributions) {
        self.builder.start(storage, snapshot);
        for n in orig.node_iter(&self.spec.clone()).skip(snapshot.skip_nodes) {
            if self.builder.is_full(storage){return;}
            if dist.should_mutate_data(ops_used-snapshot.skip_nodes){ //TODO fix this with probability based on length
                self.builder.append_node_mutated(&n, dict, &self.mutator,  storage, dist);
            } else {
                self.builder.append_node(&n, storage, dist); 
            }
        }
    }


    pub fn splice_random<S: GraphStorage>(&mut self, orig: &VecGraph, ops_used: usize,  snapshot: &MutatorSnapshotState, dict: &CustomDict, storage: &mut S, dist: &Distributions) {
        self.builder.start(storage, snapshot);
        for n in orig.node_iter(&self.spec.clone()).skip(snapshot.skip_nodes).take(ops_used) {
            if self.builder.is_full(storage){return;}
            let mutation = self.pick_op(&n, dist);
            self.apply_graph_node(mutation, &n, dict, storage, dist);
        }
    }

    pub fn pick_splice_points(&self, len: usize, dist: &Distributions) -> Vec<usize>{
        use std::cmp::Reverse;
        let num = match len{
            0 => unreachable!(),
            1..=3 => dist.gen_range(1,3),
            4..=15 => dist.gen_range(1,5),
            _ => dist.gen_range(4,16),
        };
        let mut res = (0..num).map(|_| dist.gen_range(0,len) ).collect::<Vec<_>>();
        res.sort_unstable();
        res.sort_by_key(|x| (*x, Reverse(*x))); 
        res.dedup();
        return res;
    }

    pub fn splice< S: GraphStorage, Q:InputQueue >(&mut self, orig: &VecGraph, ops_used: usize, snapshot: &MutatorSnapshotState, queue: &Q, storage: &mut S, dist: &Distributions) {

        let orig_len = ops_used-snapshot.skip_nodes;
        let mut splice_points = self.pick_splice_points(orig_len, dist);
        //println!("splice with {:?} on graph with {}..{}/{}", splice_points, snapshot.skip_nodes, ops_used,orig.node_len(&self.spec));
        self.builder.start(storage, snapshot);
        let mut spliced = false;
        for (i,n) in orig.node_iter(&self.spec.clone()).skip(snapshot.skip_nodes).enumerate() {
            if self.builder.is_full(storage){return;}
            if splice_points.len()>0{
                //println!("{} vs {}",i,*splice_points.last().unwrap());
            }
            if splice_points.len() > 0 && i == *splice_points.last().unwrap(){
                splice_points.pop();
                let other_lock = queue.sample_for_splicing(&dist);
                let other = other_lock.as_ref();
                let other_len = other.node_len(&self.spec);
                let start = dist.gen_range(0,other_len);
                let mut len = dist.gen_range(1,16);
                if len > other_len-start { len = other_len-start }
                assert!(len>0);
                for nn in other.node_iter(&self.spec.clone()).skip(start).take(len){
                    self.builder.append_node(&nn, storage, dist);
                }
                spliced=true;
            }
            self.builder.append_node(&n, storage, dist);
        }
        assert!(spliced);
    }

    pub fn copy_all<S: GraphStorage>(&mut self, orig: &VecGraph,  storage: &mut S, dist: &Distributions){
        self.builder.start(storage, &MutatorSnapshotState::none());
        for n in orig.node_iter(&self.spec){
            self.builder.append_node(&n, storage, dist);
        }
    }

    pub fn generate<S: GraphStorage>(&mut self, n: usize, snapshot: &MutatorSnapshotState,  storage: &mut S, dist: &Distributions) {
        self.builder.start(storage, snapshot);
        self.builder
            .append_random(n, &self.mutator, storage, dist)
            .unwrap();
    }

    pub fn drop_range<S: GraphStorage>(
        &mut self,
        orig: &VecGraph,
        range: std::ops::Range<usize>,
        storage: &mut S,
        dist: &Distributions
    ) {
        self.builder.start(storage, &MutatorSnapshotState::none());
        for (i, n) in orig.node_iter(&self.spec.clone()).enumerate() {
            if range.start <= i && i < range.end {
                continue;
            }
            self.builder.append_node(&n, storage, dist);
        }
    }

    //pub fn drop_node_at<S: GraphStorage>(&mut self, orig: &VecGraph, i: usize, storage: &mut S, dist: &Distributions) {
    //    self.drop_range(orig, i..i + 1, storage, dist);
    //}

    pub fn dump_graph<S: GraphStorage>(&self, storage: &S) -> VecGraph {
        storage.as_vec_graph()
    }

    fn apply_graph_node<S: GraphStorage>(
        &mut self,
        op: NodeMutationType,
        n: &GraphNode,
        dict: &CustomDict,
        storage: &mut S,
        dist: &Distributions
    ) {
        use NodeMutationType::*;

        match op {
            CopyNode => {
                self.builder.append_node(&n, storage, dist);
            }
            MutateNodeData => self.builder.append_node_mutated(&n, dict, &self.mutator, storage, dist),
            DropNode => {}
            SkipAndGenerate => {
                let len = dist.gen_number_of_random_nodes();
                self.builder
                    .append_random(len, &self.mutator, storage, dist)
                    .unwrap();
            }
        }
    }

    fn pick_op(&self, _n: &GraphNode, dist: &Distributions) -> NodeMutationType {
        return dist.gen_graph_mutation_type();
    }

    pub fn num_ops_used<S: GraphStorage>(&self, storage: &S) -> usize {
        return self.builder.num_ops_used(storage);
    }
}