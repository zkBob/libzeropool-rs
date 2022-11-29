use serde::{Deserialize, Serialize};
use libzeropool::fawkes_crypto::ff_uint::Num;
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

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BulkInfo {
    pub index_from: u64,
    pub next_index: u64,
    pub filename: String,
    pub bytes: usize,
    pub tx_count: usize,
    pub timestamp: u64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ColdStorageConfig {
    pub network: String,
    pub index_from: u64,
    pub next_index: u64,
    pub total_txs_count: usize,
    pub bulks: Vec<BulkInfo>,
}