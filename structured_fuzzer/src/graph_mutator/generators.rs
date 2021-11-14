use crate::random::distributions::Distributions;
use crate::graph_mutator;
use crate::graph_mutator::regex_generator;
//use crate::data_buff::DataBuff;

extern crate regex_syntax;

use regex_syntax::hir::{
    //Class, ClassBytesRange, ClassUnicodeRange, 
    Hir, 
    //Literal, RepetitionKind, RepetitionRange,
};

#[derive(Debug, PartialEq, Deserialize, Serialize, Clone)]
#[serde(tag = "type")]
pub enum IntGenerator{
    Options{opts: Vec<u64>},
    Flags{opts: Vec<u64>},
    Limits{range:(u64, u64), align: u64},
}

impl IntGenerator{
    pub fn generate(&self, dist: &Distributions) -> (u64,bool){
        use IntGenerator::*;
        match self {
            Options{opts} => (opts[dist.gen_range(0,opts.len())],false),
            Flags{opts} => (opts[dist.gen_range(0,opts.len())],false),
            Limits{range,align} => {
                let mut val = dist.gen_range(range.0,range.1);
                val = val-(val%align);
                if val < range.0 {val+=align}
                if val > range.1 {val-=align}
                (val,false)
            },
        }
    }
}
#[derive(Debug, PartialEq, Deserialize, Serialize, Clone)]
#[serde(tag = "type")]
pub enum VecGeneratorLoader{
    Regex{r: String},
}
impl VecGeneratorLoader{
    pub fn load(&self, data: &graph_mutator::spec::AtomicSpec) -> VecGenerator {
        match self{
            VecGeneratorLoader::Regex{r} => {
                assert!(data.atomic_type.is_u8(),"Regex Generators are only valid for Vec<u8>");
                use regex_syntax::ParserBuilder;

                let mut parser = ParserBuilder::new()
                    .unicode(false)
                    .allow_invalid_utf8(true)
                    .build();
        
                let hir = parser.parse(r).unwrap();
                VecGenerator::Regex(hir)
            }
        }
    }
}

pub enum VecGenerator{
    Regex(Hir)
}

impl VecGenerator{
    pub fn generate(&self, max_len: u64, dist: &Distributions) -> Vec<u8>{
        use VecGenerator::*;
        match self {
            Regex(hir) => {
                let mut vec = regex_generator::generate(hir, max_len, dist);
                if vec.len() > max_len as usize {
                    vec.resize(max_len as usize,0);
                }
                return vec;
            },
        }
    }
}