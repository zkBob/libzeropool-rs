use std::path::PathBuf;
use std::sync::Arc;

use fawkes_crypto::backend::bellman_groth16::PrecomputedData;
use libzkbob_rs::libzeropool::fawkes_crypto::backend::bellman_groth16::Parameters;
use neon::{prelude::*, types::buffer::TypedArray};

use crate::{Engine, Fr};

pub type BoxedParams = JsBox<Arc<Params>>;
pub struct Params {
    pub inner: Parameters<Engine>,
    pub precomputed: Option<PrecomputedData<Fr>>,
}

pub fn from_binary(mut cx: FunctionContext) -> JsResult<BoxedParams> {
    let input = cx.argument::<JsBuffer>(0)?;

    let mut data = input.as_slice(&cx);
    let inner = Parameters::read(&mut data, true, true).unwrap();
    let precompute = cx.argument::<JsBoolean>(1)?.value(&mut cx);
    let precomputed = precompute.then(|| inner.precompute());
    Ok(cx.boxed(Arc::new(Params { inner, precomputed })))
}

pub fn from_file(mut cx: FunctionContext) -> JsResult<BoxedParams> {
    let path: PathBuf = {
        let path = cx.argument::<JsValue>(0)?;
        neon_serde::from_value(&mut cx, path).unwrap()
    };

    let data = std::fs::read(path).unwrap();
    let inner = Parameters::read(&mut data.as_slice(), true, true).unwrap();
    let precompute = cx.argument::<JsBoolean>(1)?.value(&mut cx);
    let precomputed = precompute.then(|| inner.precompute());
    Ok(cx.boxed(Arc::new(Params { inner, precomputed })))
}

impl Finalize for Params {}
