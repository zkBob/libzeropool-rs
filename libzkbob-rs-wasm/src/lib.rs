use std::str::FromStr;

use libzkbob_rs::libzeropool::{
    constants,
    fawkes_crypto::{backend::bellman_groth16::engines::Bn256, ff_uint::Num},
    native::{
        boundednum::BoundedNum,
        params::{PoolBN256, PoolParams as PoolParamsTrait},
    },
    POOL_PARAMS,
};
use libzkbob_rs::address::{format_address, parse_address};
use serde::Serialize;
use wasm_bindgen::{prelude::*, JsCast};

pub use crate::{
    client::*,
    proof::*,
    state::{Transaction, UserState},
    ts_types::*,
};

#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

#[macro_use]
mod utils;
mod client;
mod database;
mod helpers;
mod keys;
mod params;
mod proof;
mod state;
mod ts_types;

pub type PoolParams = PoolBN256;
pub type Fr = <PoolParams as PoolParamsTrait>::Fr;
pub type Fs = <PoolParams as PoolParamsTrait>::Fs;
pub type Engine = Bn256;

lazy_static::lazy_static! {
    static ref CONSTANTS: SerConstants = SerConstants::new();
}

#[allow(non_snake_case)]
#[derive(Clone, Serialize)]
pub struct SerConstants {
    pub IN: usize,
    pub OUT: usize,
    pub OUTLOG: usize,
    pub HEIGHT: usize,
}

impl SerConstants {
    fn new() -> Self {
        SerConstants {
            IN: constants::IN,
            OUT: constants::OUT,
            OUTLOG: constants::OUTPLUSONELOG,
            HEIGHT: constants::HEIGHT,
        }
    }
}

#[cfg(feature = "multicore")]
pub use wasm_bindgen_rayon::init_thread_pool;

#[wasm_bindgen(js_name = "getConstants")]
pub fn get_constants() -> Constants {
    serde_wasm_bindgen::to_value(&*CONSTANTS)
        .unwrap()
        .unchecked_into::<Constants>()
}

#[wasm_bindgen(js_name = "validateAddress")]
pub fn validate_address(address: &str) -> bool {
    parse_address::<PoolParams>(address, &POOL_PARAMS).is_ok()
}

#[wasm_bindgen(js_name = "assembleAddress")]
pub fn assemble_address(d: &str, p_d: &str) -> String {
    let d = Num::from_str(d).unwrap();
    let d = BoundedNum::new(d);
    let p_d = Num::from_str(p_d).unwrap();

    format_address::<PoolParams>(d, p_d)
}

#[wasm_bindgen(js_name = "parseAddress")]
pub fn parse_address_(address: &str) -> IAddressComponents {
    let (d, p_d) = parse_address::<PoolParams>(address, &POOL_PARAMS).unwrap();

    #[derive(Serialize)]
    struct Address {
        d: String,
        p_d: String,
    }

    let address = Address {
        d: d.to_num().to_string(),
        p_d: p_d.to_string(),
    };

    serde_wasm_bindgen::to_value(&address)
        .unwrap()
        .unchecked_into::<IAddressComponents>()
}