use std::str::FromStr;

use libzkbob_rs::libzeropool::native::tx::nullifier_outer_hash;
use wasm_bindgen::prelude::*;
use libzkbob_rs::libzeropool::{fawkes_crypto::ff_uint::Num, native::tx::out_commitment_hash};
use libzkbob_rs::{
  merkle::Hash,
  libzeropool::fawkes_crypto::borsh::{BorshSerialize, BorshDeserialize},
  libzeropool::POOL_PARAMS,
  libzeropool::native::account::Account as NativeAccount
};
use crate::ts_types::Hash as JsHash;
use crate::Fr;
use crate::ts_types::RawHashes;

#[cfg(feature = "multicore")]
use rayon::prelude::*;


#[wasm_bindgen]
pub struct Helpers {
}

#[wasm_bindgen]
impl Helpers {
    #[wasm_bindgen(js_name = "strToNum")]
    pub fn str_to_num(num_str: String) -> Vec<u8> {
      let num: Num<Fr> = Num::from_str(num_str.as_str()).unwrap();
  
      let mut vec = vec![];
      num.serialize(&mut vec).unwrap();

      vec
    }

    #[wasm_bindgen(js_name = "numToStr")]
    pub fn num_to_str(num: Vec<u8>) -> String {
      let num: Num<Fr> = Num::try_from_slice(num.as_slice()).unwrap();
      num.to_string()
    }

    #[wasm_bindgen(js_name = "outCommitmentHash")]
    pub fn out_commitment(hashes: RawHashes) -> String {
      let hashes = serde_wasm_bindgen::from_value::<Vec<Vec<u8>>>(hashes.into()).unwrap();
      let hashes: Vec<Num<Fr>> = hashes
        .iter()
        .map(|h| Num::try_from_slice(h).unwrap())
        .collect();
      let commitment = out_commitment_hash(&hashes, &*POOL_PARAMS);

      commitment.to_string()
    }

    #[wasm_bindgen(js_name = "nullifierOuterHash")]
    pub fn nullifier_outer_hash(account: crate::Account, intermediate_nullifier_hash: JsHash)-> Result<String, JsValue>{
        let in_account: NativeAccount<Fr> = serde_wasm_bindgen::from_value(account.into())?;
        let in_account_hash = in_account.hash(&*POOL_PARAMS);
        let intermediate_hash_native: Hash<Fr> = serde_wasm_bindgen::from_value(intermediate_nullifier_hash.unchecked_into())?;
        Ok(nullifier_outer_hash(in_account_hash, intermediate_hash_native,&*POOL_PARAMS).to_uint().to_string())
    }
}

#[cfg(feature = "multicore")]
pub fn vec_into_iter<T: Send>(col: Vec<T>) -> rayon::vec::IntoIter<T> {
    col.into_par_iter()
}

#[cfg(not(feature = "multicore"))]
pub fn vec_into_iter<T: Send>(col: Vec<T>) -> <Vec<T> as IntoIterator>::IntoIter {
    col.into_iter()
}