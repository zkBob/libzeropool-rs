use std::collections::HashMap;
use std::sync::RwLock;
use std::vec::Vec;
use libzkbob_rs::libzeropool::fawkes_crypto::borsh::{BorshSerialize, BorshDeserialize};
use libzkbob_rs::libzeropool::fawkes_crypto::ff_uint::Num;
use libzkbob_rs::libzeropool::{
    constants::{HEIGHT, OUT, OUTPLUSONELOG},
    POOL_PARAMS,
};
use libzkbob_rs::merkle::NativeMerkleTree;
use neon::prelude::*;
use neon::types::buffer::TypedArray;
//use serde::Serialize;
use hex;

use crate::PoolParams;

pub struct MerkleTree {
    inner: NativeMerkleTree<PoolParams>,
}

pub type BoxedMerkleTree = JsBox<RwLock<MerkleTree>>;

impl Finalize for MerkleTree {}

pub fn merkle_new(mut cx: FunctionContext) -> JsResult<BoxedMerkleTree> {
    let path_js = cx.argument::<JsString>(0)?;
    let path = path_js.value(&mut cx);
    let inner =
        NativeMerkleTree::new_native(Default::default(), &path, POOL_PARAMS.clone()).unwrap();

    Ok(cx.boxed(RwLock::new(MerkleTree { inner })))
}

pub fn merkle_add_hash(mut cx: FunctionContext) -> JsResult<JsUndefined> {
    let tree = cx.argument::<BoxedMerkleTree>(0)?;
    let index = {
        let num = cx.argument::<JsNumber>(1)?;
        num.value(&mut cx) as u64
    };

    let hash = {
        let buffer = cx.argument::<JsBuffer>(2)?;
        Num::try_from_slice(buffer.as_slice(&cx)).unwrap()
    };

    tree.write().unwrap().inner.add_hash(index, hash, false);

    Ok(cx.undefined())
}

pub fn merkle_add_commitment(mut cx: FunctionContext) -> JsResult<JsUndefined> {
    let tree = cx.argument::<BoxedMerkleTree>(0)?;
    let index = {
        let num = cx.argument::<JsNumber>(1)?;
        num.value(&mut cx) as u64
    };

    let hash = {
        let buffer = cx.argument::<JsBuffer>(2)?;
        Num::try_from_slice(buffer.as_slice(&cx)).unwrap()
    };

    tree.write()
        .unwrap()
        .inner
        .add_hash_at_height(OUTPLUSONELOG as u32, index, hash, false);

    Ok(cx.undefined())
}

pub fn merkle_append_hash(mut cx: FunctionContext) -> JsResult<JsNumber> {
    let tree = cx.argument::<BoxedMerkleTree>(0)?;

    let hash = {
        let buffer = cx.argument::<JsBuffer>(1)?;
        Num::try_from_slice(buffer.as_slice(&cx)).unwrap()
    };

    let index = tree.write().unwrap().inner.append_hash(hash, false) as f64;

    Ok(cx.number(index))
}

pub fn merkle_get_leaf_proof(mut cx: FunctionContext) -> JsResult<JsValue> {
    let tree = cx.argument::<BoxedMerkleTree>(0)?;
    let index = {
        let num = cx.argument::<JsNumber>(1)?;
        num.value(&mut cx) as u64
    };

    let proof = tree
        .read()
        .unwrap()
        .inner
        .get_leaf_proof(index)
        .map(|proof| neon_serde::to_value(&mut cx, &proof).unwrap())
        .unwrap();

    Ok(proof)
}

pub fn merkle_get_commitment_proof(mut cx: FunctionContext) -> JsResult<JsValue> {
    let tree = cx.argument::<BoxedMerkleTree>(0)?;
    let index = {
        let num = cx.argument::<JsNumber>(1)?;
        num.value(&mut cx) as u64
    };

    let proof = tree
        .read()
        .unwrap()
        .inner
        .get_proof_unchecked::<{ HEIGHT - OUTPLUSONELOG }>(index);

    let result = neon_serde::to_value(&mut cx, &proof).unwrap();

    Ok(result)
}

pub fn merkle_get_root(mut cx: FunctionContext) -> JsResult<JsValue> {
    let tree = cx.argument::<BoxedMerkleTree>(0)?;

    let root = tree.read().unwrap().inner.get_root();

    let result = neon_serde::to_value(&mut cx, &root).unwrap();

    Ok(result)
}

pub fn merkle_get_node(mut cx: FunctionContext) -> JsResult<JsValue> {
    let tree = cx.argument::<BoxedMerkleTree>(0)?;
    let height = {
        let num = cx.argument::<JsNumber>(1)?;
        num.value(&mut cx) as u32
    };
    let index = {
        let num = cx.argument::<JsNumber>(2)?;
        num.value(&mut cx) as u64
    };

    let hash = tree.read().unwrap().inner.get(height, index);

    let result = neon_serde::to_value(&mut cx, &hash).unwrap();

    Ok(result)
}

pub fn merkle_get_next_index(mut cx: FunctionContext) -> JsResult<JsValue> {
    let tree = cx.argument::<BoxedMerkleTree>(0)?;

    let root = tree.read().unwrap().inner.next_index();

    let result = neon_serde::to_value(&mut cx, &root).unwrap();

    Ok(result)
}

pub fn merkle_get_all_nodes(mut cx: FunctionContext) -> JsResult<JsValue> {
    let tree = cx.argument::<BoxedMerkleTree>(0)?;

    let nodes: Vec<(u64, u32)> = tree
        .read()
        .unwrap()
        .inner
        .get_all_nodes()
        .iter()
        .map(|n| (n.index, n.height))
        .collect();

    let result = neon_serde::to_value(&mut cx, &nodes).unwrap();

    Ok(result)
}

pub fn merkle_get_virtual_node(mut cx: FunctionContext) -> JsResult<JsValue> {
    let tree = cx.argument::<BoxedMerkleTree>(0)?;
    let height = {
        let num = cx.argument::<JsNumber>(1)?;
        num.value(&mut cx) as u32
    };
    let index = {
        let num = cx.argument::<JsNumber>(2)?;
        num.value(&mut cx) as u64
    };
    let mut virtual_nodes: HashMap<(u32, u64), Num<_>> = {
        let nodes = cx.argument::<JsValue>(3)?;
        let array: Vec<((u32, u64), Num<_>)> = neon_serde::from_value(&mut cx, nodes).unwrap();
        array.into_iter().collect()
    };
    let new_hashes_left_index = {
        let num = cx.argument::<JsNumber>(4)?;
        num.value(&mut cx) as u64
    };
    let new_hashes_right_index = {
        let num = cx.argument::<JsNumber>(5)?;
        num.value(&mut cx) as u64
    };

    let node = tree.read().unwrap().inner.get_virtual_node(
        height,
        index,
        &mut virtual_nodes,
        new_hashes_left_index,
        new_hashes_right_index,
    );

    let result = neon_serde::to_value(&mut cx, &node).unwrap();

    Ok(result)
}

pub fn merkle_rollback(mut cx: FunctionContext) -> JsResult<JsUndefined> {
    let tree = cx.argument::<BoxedMerkleTree>(0)?;
    let rollback_index = {
        let num = cx.argument::<JsNumber>(1)?;
        num.value(&mut cx) as u64
    };

    let mut a = tree.write().unwrap();
    a.inner.rollback(rollback_index);

    Ok(cx.undefined())
}

pub fn merkle_get_left_siblings(mut cx: FunctionContext) -> JsResult<JsValue> {
    let tree = cx.argument::<BoxedMerkleTree>(0)?;
    let index = {
        let num = cx.argument::<JsNumber>(1)?;
        num.value(&mut cx) as u64
    };

    if index & OUTPLUSONELOG as u64 != 0 {
        return cx.throw_error(format!("Index to get sibling from should be multiple of {}", OUT + 1));
    }

    let siblings = tree.read().unwrap().inner.get_left_siblings(index);    
    let array = match siblings {
        Some(val) => {
            let result: Result<Vec<String>, String> = val
                .into_iter()
                .map(|node| {
                    let height = format!("{:#04x}", node.height);
                    let index = format!("{:#014x}", node.index);

                    let mut node_bytes = vec![];
                    node.value.serialize(&mut node_bytes).unwrap();
                    let node_string = hex::encode(node_bytes);


                    let res = format!("{}{}{}",
                        height.strip_prefix("0x").unwrap_or(&height),
                        index.strip_prefix("0x").unwrap_or(&index),
                        node_string
                    );

                    if res.len() != 78 {
                        return Err(format!("Internal error (sibling length {} is invalid)", res.len()));
                    }

                    Ok(res)
                })
                .collect();
            
            result
        },
        None => Err(format!("Tree is undefined at index {}", index)) //cx.throw_error(&format!("Tree is undefined at index {}", index))
    };

    match array {
        Ok(val) => Ok(neon_serde::to_value(&mut cx, &val).unwrap()),
        Err(e) => cx.throw_error(e),
    }
}