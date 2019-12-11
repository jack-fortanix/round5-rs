use rustc_serialize::hex::{ToHex, FromHex};
use core::str::FromStr;
use round5_rs::*;

#[derive(Debug)]
struct Round5Kat {
    count: usize,
    keygen_coins: Vec<u8>,
    enc_coins: Vec<u8>,
    mlen: usize,
    msg: Vec<u8>,
    pk: Vec<u8>,
    sk: Vec<u8>,
    clen: usize,
    ctext: Vec<u8>,
}

impl FromStr for Round5Kat {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Round5Kat, Self::Err> {

        let mut count = None;
        let mut keygen_coins = None;
        let mut enc_coins = None;
        let mut mlen = None;
        let mut msg = None;
        let mut pk = None;
        let mut sk = None;
        let mut clen = None;
        let mut ctext = None;

        for line in s.split("\n") {
            let kv = line.split(" = ").collect::<Vec<_>>();

            if kv.len() == 2 {
                match kv[0] {
                    "count" => { count = Some(kv[1].parse::<usize>().unwrap()); }
                    "mlen" => { mlen = Some(kv[1].parse::<usize>().unwrap()); }
                    "clen" => { clen = Some(kv[1].parse::<usize>().unwrap()); }
                    "keygen_coins" => { keygen_coins = Some(kv[1].from_hex().unwrap()); }
                    "enc_coins" => { enc_coins = Some(kv[1].from_hex().unwrap()); }
                    "pk" => { pk = Some(kv[1].from_hex().unwrap()); }
                    "sk" => { sk = Some(kv[1].from_hex().unwrap()); }
                    "msg" => { msg = Some(kv[1].from_hex().unwrap()); }
                    "c" => { ctext = Some(kv[1].from_hex().unwrap()); }
                    x => { panic!(format!("unknown field {}", x)); }
                }
            }
        }

        Ok(Round5Kat {
            count: count.unwrap(),
            keygen_coins: keygen_coins.unwrap(),
            enc_coins: enc_coins.unwrap(),
            mlen: mlen.unwrap(),
            msg: msg.unwrap(),
            pk: pk.unwrap(),
            sk: sk.unwrap(),
            clen: clen.unwrap(),
            ctext: ctext.unwrap()
        })
    }
}

#[test]
pub fn all_kats() {
    let kats = String::from_utf8(include_bytes!("data/PQCencryptKAT_1413.rsp").to_vec()).unwrap();

    for kat in kats.split("\n\n") {
        let kat = Round5Kat::from_str(kat).unwrap();

        println!("Round5 count {}", kat.count);

        let (sk,pk) = gen_keypair(&kat.keygen_coins);

        assert_eq!(sk.to_hex(), kat.sk.to_hex());
        assert_eq!(pk.to_hex(), kat.pk.to_hex());

        let ctext = encrypt(&kat.msg, &kat.pk, &kat.enc_coins);

        assert_eq!(ctext.len(), kat.clen);
        assert_eq!(ctext.to_hex(), kat.ctext.to_hex());

        let recovered = decrypt(&ctext, &kat.sk);

        assert_eq!(recovered.to_hex(), kat.msg.to_hex());

        /*
        let mut invalid_ctext = ctext.clone();

        let idx = ((ctext[30] as usize)*239+ctext[32] as usize) % ctext.len();
        invalid_ctext[idx] ^= 1;

        let result = decrypt(&invalid_ctext, &kat.sk);

        match result {
            Err(Error::DecryptionFailed) => { }
            Err(_) => { panic!("Unexpected error") }
            Ok(r) => { assert_eq!(r.to_hex(), kat.msg.to_hex()); }

        assert_eq!(result.len(), 0);

        if result.len() > 0 {
            assert_eq!(result.to_hex(), kat.msg.to_hex());
        } else {
            assert_eq!(result.len(), 0);
        }
         */
    }
}
