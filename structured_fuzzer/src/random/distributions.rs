use crate::mutator::NodeMutationType;
use crate::mutator::{GenerateTail, MutationStrategy};
use crate::primitive_mutator::inplace_mutation::InplaceMutationType;
use crate::primitive_mutator::size_changing_mutation::SizeChangingMutationType;
use crate::random::choices::Choices;
use crate::random::romu::RomuPrng;

use rand::distributions::uniform::SampleBorrow;
use rand::distributions::uniform::SampleUniform;
use rand::distributions::{Distribution, Standard};
use rand::prelude::*;
use std::cell::RefCell;
use std::ops::Range;

pub struct Distributions {
    rng: RefCell<RomuPrng>,
    pub block_size: Choices<(usize, usize)>,
    pub inplace_mutations: Choices<InplaceMutationType>,
    pub size_changing_mutations: Choices<SizeChangingMutationType>,
    pub graph_mutations: Choices<NodeMutationType>,
    pub endianess: f64,
    pub dict: Vec<Vec<u8>>,
}

impl Distributions {
    pub fn new(dict: Vec<Vec<u8>>) -> Self {
        let block_size = Choices::new(vec![10, 4, 1], vec![(1, 32), (32, 128), (128, 1500)]);

        use InplaceMutationType::*;
        let mut prob = vec![1; 13];
        let opts = vec![
            OverwriteRandomT,
            FlipBitT,
            AddU8T,
            AddU16T,
            AddU32T,
            AddU64T,
            InterestingU8T,
            InterestingU16T,
            InterestingU32T,
            InterestingU64T,
            OverwriteRandomByteT,
            OverwriteChunkT,
            OverwriteFixedT,
        ];
        if !dict.is_empty() {
            assert_eq!(opts[0], OverwriteRandomT);
            prob[0] = 2;
        }
        let inplace_mutations = Choices::new(prob, opts);

        use SizeChangingMutationType::*;
        let size_changing_mutations = Choices::new(
            vec![1; 4],
            vec![DeleteT, InsertChunkT, InsertFixedT, InsertRandomT],
        );

        use NodeMutationType::*;
        let graph_mutations = Choices::new(
            vec![10, 4, 1, 1],
            vec![CopyNode, MutateNodeData, DropNode, SkipAndGenerate],
        );

        return Self {
            rng: RefCell::new(RomuPrng::from_entropy()),
            block_size,
            inplace_mutations,
            graph_mutations,
            size_changing_mutations,
            endianess: 0.5,
            dict,
        };
    }

    pub fn set_seed(&mut self, seed: u64) {
        self.rng = RefCell::new(RomuPrng::seed_from_u64(seed));
    }

    pub fn set_full_seed(&mut self, x: u64, y: u64) {
        self.rng = RefCell::new(RomuPrng::new(x, y));
    }

    pub fn gen_inplace_mutation_type(&self) -> &InplaceMutationType {
        return self.inplace_mutations.sample(&mut *self.rng.borrow_mut());
    }

    pub fn gen_size_changing_mutation_type(&self) -> &SizeChangingMutationType {
        return self
            .size_changing_mutations
            .sample(&mut *self.rng.borrow_mut());
    }

    pub fn gen_block_size(&self) -> &(usize, usize) {
        let mut rng = self.rng.borrow_mut();
        return self.block_size.sample(&mut *rng);
    }
    pub fn gen_endianess(&self) -> bool {
        self.rng.borrow_mut().gen_bool(self.endianess)
    }

    //Graph Muation Related stuff
    pub fn gen_number_of_random_nodes(&self) -> usize {
        return self.gen_range(1, 64);
    }

    fn gen_change_percentage(&self) -> usize {
        return 1 << self.gen_range(0, 6);
    }

    pub fn gen_random_overwrite_data(&self, dst: &Range<usize>) -> Vec<u8> {
        if !self.dict.is_empty() && self.gen::<u8>()&1 == 0{
            let i = self.gen_range(0, self.dict.len());
            if self.dict[i].len() <= (dst.end-dst.start){
                return self.dict[i].clone();
            } 
        }
        return dst.clone().map(|_| self.gen()).collect();
    }

    pub fn gen_mutation_strategy(&self, old_size: usize) -> MutationStrategy {
        return match self.gen_range(0, 15) {
            0 => MutationStrategy::GenerateTail(self.gen_tail_generation_strategy(old_size)),
            1 | 2 => MutationStrategy::Splice,
            3 => MutationStrategy::SpliceRandom,
            4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 => MutationStrategy::DataOnly,
            13 | 14 => MutationStrategy::Repeat,
            _ => unreachable!(),
        };
    }

    pub fn gen_tail_generation_strategy(&self, old_size: usize) -> GenerateTail {
        let mut drop_last = (self.gen_change_percentage() * old_size) / 100;
        let gen_size_range = self.gen_block_size();
        let mut generate = self.gen_range(gen_size_range.0, gen_size_range.1);
        if drop_last >= old_size {
            drop_last = 0;
        }
        if generate + old_size - drop_last < 16 && self.gen_range(0, 100) < 98 {
            generate += 16;
        }
        return GenerateTail {
            drop_last,
            generate,
        };
    }

    pub fn gen_graph_mutation_type(&self) -> NodeMutationType {
        let mut rng = self.rng.borrow_mut();
        return *self.graph_mutations.sample(&mut *rng);
    }

    pub fn gen_minimization_block_size(
        &self,
        i: usize,
        max_i: usize,
        graph_len: usize,
    ) -> std::ops::Range<usize> {
        let mut len = self.rng.borrow_mut().gen_range(0, graph_len / 2);
        if i > max_i / 4 {
            len = len / 2;
        }
        if i > max_i / 2 {
            len = len / 2;
        }
        if i > 3 * (max_i / 4) {
            len = len / 4;
        }
        if len < 1 {
            len = 1;
        }

        if graph_len == len {
            return 0..len;
        }

        let start = self.gen_range(0, graph_len - len);
        return start..start + len;
    }

    pub fn gen<T>(&self) -> T
    where
        Standard: Distribution<T>,
    {
        self.rng.borrow_mut().gen()
    }

    pub fn gen_range<T: SampleUniform, B1, B2>(&self, low: B1, high: B2) -> T
    where
        B1: SampleBorrow<T> + Sized,
        B2: SampleBorrow<T> + Sized,
    {
        self.rng.borrow_mut().gen_range(low, high)
    }

    pub fn choose_from_iter<T, I: Iterator<Item = T>>(&self, iter: I) -> Option<T> {
        iter.choose(&mut *self.rng.borrow_mut())
    }

    pub fn should_mutate_splice_generator(&self) -> bool {
        return self.gen_range(0, 2) < 1;
    }

    pub fn should_mutate_data(&self, num_nodes: usize) -> bool {
        return self.gen_range(0, num_nodes + 1) <= 2;
    }

    pub fn should_mutate_dict(&self) -> bool {
        return self.gen_range(0, 3) == 0; // a change of 1/3
    }
}
