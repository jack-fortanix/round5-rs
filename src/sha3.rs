
extern crate keccak;

use std::cmp;

fn absorb(mut state: &mut [u64; 25], state_idx: usize, rate: usize, input: &[u8]) -> usize {

    fn u64_from_le(b: &[u8]) -> u64 {
        let mut r : u64 = 0;

        for i in 0..8 {
            r <<= 8;
            r += b[7-i] as u64;
        }
        r
    }

    let mut spos = state_idx;
    let mut ipos = 0;
    let input_len = input.len();

    if input_len == 0 {
        return spos;
    }

    while ipos < input_len {
        // how many bytes can we xor into the state?
        let mut avail = cmp::min(input_len - ipos, rate / 8 - spos);

        while avail > 0 && spos % 8 != 0 {
            state[spos/8] ^= (input[ipos] as u64) << (8 * (spos % 8));
            spos += 1;
            ipos += 1;
            avail -= 1;
        }

        while avail >= 8 {
            state[spos/8] ^= u64_from_le(&input[ipos..ipos+8]);
            spos += 8;
            ipos += 8;
            avail -= 8;
        }

        while avail > 0 {
            state[spos/8] ^= (input[ipos] as u64) << (8 * (spos % 8));
            spos += 1;
            ipos += 1;
            avail -= 1;
        }

        if spos == rate / 8 {
            keccak::f1600(&mut state);
            spos = 0;
        }
    }

    spos
}

fn finish(mut state: &mut [u64; 25], idx: usize, rate: usize, init: u8, fini: u8) {
    state[idx/8] ^= (init as u64) << (8 * (idx % 8));
    state[(rate/64)-1] ^= (fini as u64) << 56;
    keccak::f1600(&mut state);
}

pub struct Sha3 {
    state: [u64; 25],
    idx: usize, // byte index
    rate: usize,
}

impl Sha3 {
    pub fn new(outlen: usize) -> Result<Sha3, String> {
        if outlen != 224 && outlen != 256 && outlen != 384 && outlen != 512 {
            return Err("Unknown SHA-3 digest len".into());
        }

        let rate = 1600 - 2*outlen;

        Ok(Sha3 {
            state: [0u64; 25],
            idx: 0,
            rate: rate
        })
    }

    pub fn update(&mut self, data: &[u8]) {
        let new_idx = absorb(&mut self.state, self.idx, self.rate, data);
        self.idx = new_idx;
    }

    pub fn finalize(&mut self) -> Vec<u8> {
        finish(&mut self.state, self.idx, self.rate, 0x06, 0x80);

        let outbits = (1600 - self.rate) / 2;
        let mut out = vec![0u8; outbits/8];

        for i in 0..out.len() {
            out[i] = (self.state[i / 8] >> (8*(i % 8))) as u8;
        }

        *self = Sha3::new(outbits).unwrap();

        out
    }
}

fn expand(mut state: &mut [u64; 25], rate: usize, out: &mut [u8]) {
    assert!(rate % 64 == 0); // valid SHAKE bitrate
    let rate = rate / 8; // convert to byte rate

    for chunk in out.chunks_mut(rate) {
        for i in 0..chunk.len() {
            chunk[i] = (state[i / 8] >> (8*(i % 8))) as u8;
        }

        keccak::f1600(&mut state);
    }
}

pub struct Shake {
    state: [u64; 25],
    idx: usize, // byte index
    rate: usize,
}

#[cfg(feature = "shake")]
impl Shake {
    pub fn new(level: usize) -> Result<Shake, String> {
        if level != 128 && level != 256 {
            return Err("Unknown SHAKE output length".into());
        }

        Ok(Shake {
            state: [0u64; 25],
            idx: 0,
            rate: 1600-2*level
        })
    }

    pub fn update(&mut self, data: &[u8]) {
        let new_idx = absorb(&mut self.state, self.idx, self.rate, data);
        self.idx = new_idx;
    }

    pub fn finalize(&mut self, outlen: usize) -> Vec<u8> {
        finish(&mut self.state, self.idx, self.rate, 0x1F, 0x80);

        let mut out = vec![0u8; outlen];
        expand(&mut self.state, self.rate, &mut out);

        let level = (1600 - self.rate) / 2;
        *self = Shake::new(level).unwrap();

        out
    }
}

pub struct ShakeXof {
    state: [u64; 25],
    idx: usize, // byte index
    rate: usize,
}

impl ShakeXof {
    pub fn new(level: usize, input: &[u8]) -> Result<ShakeXof, String> {
        if level != 128 && level != 256 {
            return Err("Unknown SHAKE security level".into());
        }

        let mut shake = ShakeXof {
            state: [0u64; 25],
            idx: 0,
            rate: 1600-2*level
        };

        let new_idx = absorb(&mut shake.state, shake.idx, shake.rate, input);
        shake.idx = new_idx;
        finish(&mut shake.state, shake.idx, shake.rate, 0x1F, 0x80);

        Ok(shake)
    }

    pub fn expand(&mut self, output: &mut [u8]) {
        assert!(self.rate % 64 == 0); // valid SHAKE bitrate
        let rate = self.rate / 8; // convert to byte rate

        for chunk in output.chunks_mut(rate) {
            for i in 0..chunk.len() {
                chunk[i] = (self.state[i / 8] >> (8*(i % 8))) as u8;
            }

            keccak::f1600(&mut self.state);
        }

    }
}

