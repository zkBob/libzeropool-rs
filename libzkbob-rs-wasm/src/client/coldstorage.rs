use serde::{Deserialize, Serialize};
use libzkbob_rs::libzeropool::fawkes_crypto::ff_uint::Num;
use crate::Fr;

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct TxInputData {
    pub index: u64,
    pub memo: Vec<u8>,
    pub commitment: Vec<u8>,
    pub tx_hash: Vec<u8>,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct BulkData {
    pub bulk_version: u8,
    pub index_from: u64,
    pub root_before: Num<Fr>,
    pub root_after: Num<Fr>,
    pub txs: Vec<TxInputData>,
}