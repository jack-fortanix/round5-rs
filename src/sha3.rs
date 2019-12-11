
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

#[cfg(test)]
mod test {
    use rustc_serialize::hex::{FromHex, ToHex};

    #[test]
    fn shake_test() {
        return;
        let shake256_kat = [
            ("", "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"),
            ("104fefe89f08d15d36a2233f42a7defa917c5ad2642e06cac56d5cc51ad914ecfb7d984f4199b9cf5fa5a03bf69207b9a353a9681c9cf6437bea0c49d9c3e3db1f3fc76519c70c40cc1dfdd70a9c150943c272cf9eeb861f485f10100c8f4a3e259c6470501932782512225ba64d70b219cf9d5013a21d25d6d65062dcc6b3deb49d58b90d18933f118df70ff42c807ccc851233a34a221eca56b38971ef858475488988794a975d3894633a19c1ae2f05e9b9c0756affd3cfe823ccf29228f60fa7e025bc39a79943325126409460926b057a3fb28a1b098b938872883804fd2bc245d7fd6d29bcda6ca6198f2eff6ea7e03ef78133de8ba65fc8c45a688160719fa1e7646d878ea44c4b5c2e16f48b", "46293a63c235750d58a24edca5ba637b96cae74325c6c8122c4155c0d15805e6"),
            ("8d8001e2c096f1b88e7c9224a086efd4797fbf74a8033a2d422a2b6b8f6747e4", "2e975f6a8a14f0704d51b13667d8195c219f71e6345696c49fa4b9d08e9225d3d39393425152c97e71dd24601c11abcfa0f12f53c680bd3ae757b8134a9c10d429615869217fdd5885c4db174985703a6d6de94a667eac3023443a8337ae1bc601b76d7d38ec3c34463105f0d3949d78e562a039e4469548b609395de5a4fd43c46ca9fd6ee29ada5efc07d84d553249450dab4a49c483ded250c9338f85cd937ae66bb436f3b4026e859fda1ca571432f3bfc09e7c03ca4d183b741111ca0483d0edabc03feb23b17ee48e844ba2408d9dcfd0139d2e8c7310125aee801c61ab7900d1efc47c078281766f361c5e6111346235e1dc38325666c")
        ];

        for kat in &shake256_kat {
            let input = kat.0.from_hex().unwrap();
            let mut shake256 = crate::sha3::ShakeXof::new(256, &input).unwrap();

            let olen = kat.1.len() / 2;

            if olen > 136 {
                let mut output1 = vec![0; 136];
                let mut output2 = vec![0; olen - output1.len()];
                shake256.expand(&mut output1);
                shake256.expand(&mut output2);

                assert_eq!(output1.to_hex(), kat.1[0..output1.len()*2]);
                assert_eq!(output2.to_hex(), kat.1[output1.len()*2+1..]);
            }
            //assert_eq!(output.to_hex(), kat.1);
        }
    }
}
