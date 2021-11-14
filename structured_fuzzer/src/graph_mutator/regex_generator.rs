extern crate regex_syntax;

//use crate::data_buff::DataBuff;
use crate::random::distributions::Distributions;

use regex_syntax::hir::{
    Class, ClassBytesRange, ClassUnicodeRange, Hir, Literal, RepetitionKind, RepetitionRange,
};

pub struct RegexScript<'a> {
    rng: &'a Distributions,
    remaining: usize,
}

impl<'a> RegexScript<'a> {
    pub fn new(max_len: u64, rng: &'a Distributions) -> Self {
        let len: u64 = if rng.gen::<u64>() % 256 == 0 {
            (rng.gen::<u64>() % 0xffff) % max_len
        } else {
            let len = 1 << (rng.gen::<u64>() % 8);
            (rng.gen::<u64>() % len) % max_len
        };
        RegexScript {
            rng,
            remaining: len as usize,
        }
    }

    pub fn get_mod(&mut self, val: usize) -> usize {
        if self.remaining == 0 {
            return 0;
        }
        return self.rng.gen::<usize>() % val;
    }

    pub fn get_range(&mut self, min: usize, max: usize) -> usize {
        return self.get_mod(max - min) + min;
    }
}

fn append_char(res: &mut Vec<u8>, chr: char) {
    let mut buf = [0; 4];
    res.extend_from_slice(chr.encode_utf8(&mut buf).as_bytes())
}

fn append_lit(res: &mut Vec<u8>, lit: &Literal) {
    use regex_syntax::hir::Literal::*;

    match lit {
        Unicode(chr) => append_char(res, *chr),
        Byte(b) => res.push(*b),
    }
}

fn append_unicode_range(res: &mut Vec<u8>, scr: &mut RegexScript, cls: &ClassUnicodeRange) {
    let mut chr_a_buf = [0; 4];
    let mut chr_b_buf = [0; 4];
    cls.start().encode_utf8(&mut chr_a_buf);
    cls.end().encode_utf8(&mut chr_b_buf);
    let a = u32::from_le_bytes(chr_a_buf);
    let b = u32::from_le_bytes(chr_b_buf);
    let c = scr.get_range(a as usize, (b + 1) as usize) as u32;
    append_char(res, std::char::from_u32(c).unwrap());
}

fn append_byte_range(res: &mut Vec<u8>, scr: &mut RegexScript, cls: &ClassBytesRange) {
    res.push(scr.get_range(cls.start() as usize, cls.end() as usize + 1) as u8);
}

fn append_class(res: &mut Vec<u8>, scr: &mut RegexScript, cls: &Class) {
    use regex_syntax::hir::Class::*;
    match cls {
        Unicode(cls) => {
            let rngs = cls.ranges();
            let rng = rngs[scr.get_mod(rngs.len())];
            append_unicode_range(res, scr, &rng);
        }
        Bytes(cls) => {
            let rngs = cls.ranges();
            let rng = rngs[scr.get_mod(rngs.len())];
            append_byte_range(res, scr, &rng);
        }
    }
}

fn get_length(scr: &mut RegexScript) -> usize {
    let bits = scr.get_mod(8);
    return scr.get_mod(2 << bits);
}

fn get_repetition_range(rep: &RepetitionRange, scr: &mut RegexScript) -> usize {
    use regex_syntax::hir::RepetitionRange::*;
    match rep {
        Exactly(a) => return *a as usize,
        AtLeast(a) => return get_length(scr) + (*a as usize),
        Bounded(a, b) => return scr.get_range(*a as usize, *b as usize),
    }
}

fn get_repetitions(rep: &RepetitionKind, scr: &mut RegexScript) -> usize {
    use regex_syntax::hir::RepetitionKind::*;
    match rep {
        ZeroOrOne => return scr.get_mod(2),
        ZeroOrMore => return get_length(scr),
        OneOrMore => return 1 + get_length(scr),
        Range(rng) => get_repetition_range(rng, scr),
    }
}

pub fn generate(hir: &Hir, max_len: u64, dist: &Distributions) -> Vec<u8> {
    use regex_syntax::hir::HirKind::*;
    //println!("generating on {:?}",hir);
    let mut scr = RegexScript::new(max_len, dist);
    let mut stack = vec![hir];
    let mut res = vec![];
    while stack.len() > 0 {
        match stack.pop().unwrap().kind() {
            Empty => {}
            Literal(lit) => append_lit(&mut res, lit),
            Class(cls) => append_class(&mut res, &mut scr, cls),
            Anchor(_) => {}
            WordBoundary(_) => {}
            Repetition(rep) => {
                let num = get_repetitions(&rep.kind, &mut scr);
                for _ in 0..num {
                    stack.push(&rep.hir);
                }
            }
            Group(grp) => stack.push(&grp.hir),
            Concat(hirs) => hirs.iter().rev().for_each(|h| stack.push(h)),
            Alternation(hirs) => stack.push(&hirs[scr.get_mod(hirs.len())]),
        }
    }
    return res;
}
