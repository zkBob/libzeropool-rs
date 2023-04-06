use fawkes_crypto::backend::bellman_groth16::PrecomputedData;
use libzkbob_rs::libzeropool::fawkes_crypto::backend::bellman_groth16::Parameters;
use wasm_bindgen::prelude::*;

use crate::{Engine, Fr};

#[wasm_bindgen]
pub struct Params {
    #[wasm_bindgen(skip)]
    pub inner: Parameters<Engine>,
    #[wasm_bindgen(skip)]
    pub precomputed: Option<PrecomputedData<Fr>>
}

impl From<Parameters<Engine>> for Params {
    fn from(params: Parameters<Engine>) -> Self {
        Params { inner: params, precomputed: None }
    }
}

impl From<Params> for Parameters<Engine> {
    fn from(params: Params) -> Self {
        params.inner
    }
}

#[wasm_bindgen]
impl Params {
    #[wasm_bindgen(js_name = "fromBinary")]
    pub fn from_binary(input: &[u8], precompute: bool) -> Result<Params, JsValue> {
        Self::from_binary_ext(input, true, true, precompute)
    }

    #[wasm_bindgen(js_name = "fromBinaryExtended")]
    pub fn from_binary_ext(input: &[u8], disallow_points_at_infinity: bool, checked: bool, precompute: bool) -> Result<Params, JsValue> {
        let mut input = input;
        let inner = Parameters::read(&mut input, disallow_points_at_infinity, checked).map_err(|err| js_err!("{}", err))?;
        let mut precomputed = None;

        if precompute {
            if let Ok(precompute_memory_size) = inner.precompute_memory_size() {
                {
                    // WebAssembly.Memory.grow(..) is extremely slow on iOS 
                    // so it's much better to allocate necessary memory with one call 
                    // than to do it multiple times in precompute.
                    let mut v: Vec<u8> = Vec::new();
                    v.reserve(precompute_memory_size);
                    v.shrink_to_fit()
                }
                precomputed = Some(inner.precompute());
            }
        }

        Ok(Params { inner, precomputed })  
    }
}
