use libzkbob_rs::{address::format_address, keys::reduce_sk as reduce_sk_native};
use libzkbob_rs::libzeropool::{
    constants,
    fawkes_crypto::{ff_uint::Uint, rand::Rng},
    native::{boundednum::BoundedNum, key::derive_key_p_d},
    POOL_PARAMS,
};
use wasm_bindgen::prelude::*;

use crate::{Fs, PoolParams};

#[wasm_bindgen(js_name = reduceSpendingKey)]
pub fn reduce_sk(seed: &[u8]) -> Vec<u8> {
    reduce_sk_native::<Fs>(seed).to_uint().0.to_little_endian()
}

#[wasm_bindgen(js_name = gen_burner_address)]
pub fn gen_burner_address(pool_id: u64, seed: &[u8]) -> Result<String, JsValue> {
    if pool_id >= 1 << 24 {
        return Err(js_err!("PoolID should be less than {}", 1 << 24));
    }
    let mut rng = libzkbob_rs::random::CustomRng;

    let sk = reduce_sk_native::<Fs>(seed);

    let keys = libzkbob_rs::keys::Keys::derive(sk, &*POOL_PARAMS);

    let d: BoundedNum<_, { constants::DIVERSIFIER_SIZE_BITS }> = rng.gen();

    let pk_d = derive_key_p_d(d.to_num(), keys.eta, &*POOL_PARAMS);

    Ok(format_address::<PoolParams>(d, pk_d.x))
}
