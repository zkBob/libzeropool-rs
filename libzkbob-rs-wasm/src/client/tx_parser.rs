use byteorder::{LittleEndian, ReadBytesExt};
use libzkbob_rs::{libzeropool::{native::{account::Account, note::Note, cipher, key::{self, derive_key_p_d}}, fawkes_crypto::ff_uint::{Num, NumRepr, Uint}, constants}, delegated_deposit::{MEMO_DELEGATED_DEPOSIT_SIZE, MemoDelegatedDeposit}, utils::zero_account};
use libzkbob_rs::{merkle::Hash, keys::Keys, delegated_deposit::DELEGATED_DEPOSIT_MAGIC};
use wasm_bindgen::{prelude::*, JsCast};
use serde::{Serialize, Deserialize};
use std::iter::IntoIterator;
use thiserror::Error;

#[cfg(feature = "multicore")]
use rayon::prelude::*;

use crate::{PoolParams, Fr, IndexedNote, IndexedTx, Fs, ParseTxsResult, POOL_PARAMS, helpers::vec_into_iter}; 

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("Incorrect memo length at index {0}: no prefix")]
    NoPrefix(u64),
    #[error("Incorrect memo prefix at index {0}: got {1} items, max allowed {2}")]
    IncorrectPrefix(u64, u32, u32),
}

impl ParseError {
    pub fn index(&self) -> u64 {
        match *self {
            ParseError::NoPrefix(idx)  => idx,
            ParseError::IncorrectPrefix(idx,  _, _)  => idx,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Default, Debug)]
pub struct StateUpdate {
    #[serde(rename = "newLeafs")]
    pub new_leafs: Vec<(u64, Vec<Hash<Fr>>)>,
    #[serde(rename = "newCommitments")]
    pub new_commitments: Vec<(u64, Hash<Fr>)>,
    #[serde(rename = "newAccounts")]
    pub new_accounts: Vec<(u64, Account<Fr>)>,
    #[serde(rename = "newNotes")]
    pub new_notes: Vec<Vec<(u64, Note<Fr>)>>
}

#[derive(Serialize, Deserialize, Clone, Default, Debug)]
pub struct DecMemo {
    pub index: u64,
    pub acc: Option<Account<Fr>>,
    #[serde(rename = "inNotes")]
    pub in_notes: Vec<IndexedNote>,
    #[serde(rename = "outNotes")]
    pub out_notes: Vec<IndexedNote>,
    #[serde(rename = "txHash")]
    pub tx_hash: Option<String>,
}

#[derive(Serialize, Default, Debug)]
pub struct ParseResult {
    #[serde(rename = "decryptedMemos")]
    pub decrypted_memos: Vec<DecMemo>,
    #[serde(rename = "stateUpdate")]
    pub state_update: StateUpdate
}
#[derive(Serialize, Default)]
pub struct ParseColdStorageResult {
    #[serde(rename = "decryptedMemos")]
    pub decrypted_memos: Vec<DecMemo>,
    #[serde(rename = "txCnt")]
    pub tx_cnt: usize,
    #[serde(rename = "decryptedLeafsCnt")]
    pub decrypted_leafs_cnt: usize,
}

#[wasm_bindgen]
pub struct TxParser {
    #[wasm_bindgen(skip)]
    pub params: PoolParams,
}

#[wasm_bindgen]
impl TxParser {
    #[wasm_bindgen(js_name = "new")]
    pub fn new() -> Result<TxParser, JsValue> {
        Ok(TxParser{
            params: POOL_PARAMS.clone()
        })
    }

    #[wasm_bindgen(js_name = "parseTxs")]
    pub fn parse_txs(&self, sk: &[u8], txs: &JsValue) -> Result<ParseTxsResult, JsValue> {
        let sk = Num::<Fs>::from_uint(NumRepr(Uint::from_little_endian(sk)))
            .ok_or_else(|| js_err!("Invalid spending key"))?;
        let params = &self.params;
        let eta = Keys::derive(sk, params).eta;

        let txs: Vec<IndexedTx> = txs.into_serde().map_err(|err| js_err!(&err.to_string()))?;

        let (parse_results, parse_errors): (Vec<_>, Vec<_>) = vec_into_iter(txs)
            .map(|tx| -> Result<ParseResult, ParseError> {
                let IndexedTx{index, memo, commitment} = tx;
                let memo = hex::decode(memo).unwrap();
                let commitment = hex::decode(commitment).unwrap();
                
                parse_tx(index, &commitment, &memo, None, &eta, params)
            })
            .partition(Result::is_ok);

        if parse_errors.is_empty() {
            let parse_result = parse_results
                .into_iter()
                .map(Result::unwrap)
                .fold(Default::default(), |acc: ParseResult, parse_result| {
                    ParseResult {
                        decrypted_memos: vec![acc.decrypted_memos, parse_result.decrypted_memos].concat(),
                        state_update: StateUpdate {
                            new_leafs: vec![acc.state_update.new_leafs, parse_result.state_update.new_leafs].concat(),
                            new_commitments: vec![acc.state_update.new_commitments, parse_result.state_update.new_commitments].concat(),
                            new_accounts: vec![acc.state_update.new_accounts, parse_result.state_update.new_accounts].concat(),
                            new_notes: vec![acc.state_update.new_notes, parse_result.state_update.new_notes].concat()
                        }
                    }
            });

            let parse_result = serde_wasm_bindgen::to_value(&parse_result)
                .unwrap()
                .unchecked_into::<ParseTxsResult>();
            Ok(parse_result)
        } else {
            let errors: Vec<u64> = parse_errors
                .into_iter()
                .map(|err| -> u64 {
                    let err = err.unwrap_err();
                    err.index()
                })
                .collect();

            Err(js_err!("The following txs cannot be processed: {:?}", errors))
        }
    }
}

pub fn parse_tx(
    index: u64,
    commitment: &Vec<u8>,
    memo: &Vec<u8>,
    tx_hash: Option<&Vec<u8>>,
    eta: &Num<Fr>,
    params: &PoolParams
) -> Result<ParseResult, ParseError> {
    if memo.len() < 4 {
        return Err(ParseError::NoPrefix(index))
    }

    // Special case: transaction contains delegated deposits
    if memo[0..4] == DELEGATED_DEPOSIT_MAGIC {
        let num_deposits =
            (memo.len() - DELEGATED_DEPOSIT_MAGIC.len()) / MEMO_DELEGATED_DEPOSIT_SIZE;

        let delegated_deposits = memo[4..]
            .chunks(MEMO_DELEGATED_DEPOSIT_SIZE)
            .take(num_deposits)
            .map(|data| MemoDelegatedDeposit::read(data))
            .collect::<std::io::Result<Vec<_>>>()
            .unwrap();

        let in_notes_indexed = delegated_deposits
            .iter()
            .enumerate()
            .filter_map(|(i, d)| {
                let p_d = derive_key_p_d(d.receiver_d.to_num(), eta.clone(), params).x;
                if d.receiver_p == p_d {
                    Some(IndexedNote {
                        index: index + 1 + (i as u64),
                        note: d.to_delegated_deposit().to_note(),
                    })
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        let in_notes = in_notes_indexed.iter().map(|n| (n.index, n.note)).collect();

        let hashes = [zero_account().hash(params)]
            .iter()
            .copied()
            .chain(
                delegated_deposits
                    .iter()
                    .map(|d| d.to_delegated_deposit().to_note().hash(params)),
            )
            .collect();

        let parse_result = ParseResult {
            decrypted_memos: vec![DecMemo {
                index,
                in_notes: in_notes_indexed,
                ..Default::default()
            }],
            state_update: StateUpdate {
                new_leafs: vec![(index, hashes)],
                new_notes: vec![in_notes],
                ..Default::default()
            },
        };

        return Ok(parse_result);
    }

    // regular case: simple transaction memo
    let num_hashes = (&memo[0..4]).read_u32::<LittleEndian>().unwrap();
    if num_hashes <= (constants::OUT + 1) as u32 {
        let hashes = (&memo[4..])
            .chunks(32)
            .take(num_hashes as usize)
            .map(|bytes| Num::from_uint_reduced(NumRepr(Uint::from_little_endian(bytes))));
    
        let pair = cipher::decrypt_out(*eta, &memo, params);

        match pair {
            Some((account, notes)) => {        
                let mut in_notes = Vec::new();
                let mut out_notes = Vec::new();
                notes.into_iter()
                    .enumerate()
                    .for_each(|(i, note)| {
                        out_notes.push((index + 1 + (i as u64), note));

                        if note.p_d == key::derive_key_p_d(note.d.to_num(), *eta, params).x {
                            in_notes.push((index + 1 + (i as u64), note));   
                        }
                    });

                Ok(ParseResult {
                    decrypted_memos: vec![ DecMemo {
                        index,
                        acc: Some(account),
                        in_notes: in_notes.iter().map(|(index, note)| IndexedNote{index: *index, note: *note}).collect(), 
                        out_notes: out_notes.into_iter().map(|(index, note)| IndexedNote{index, note}).collect(), 
                        tx_hash: match tx_hash {
                            Some(bytes) => Some(format!("0x{}", hex::encode(bytes))),
                            _ => None,
                        },
                        ..Default::default()
                    }],
                    state_update: StateUpdate {
                        new_leafs: vec![(index, hashes.collect())],
                        new_accounts: vec![(index, account)],
                        new_notes: vec![in_notes],
                        ..Default::default()
                    }
                })
            },
            None => {
                let in_notes: Vec<(_, _)> = cipher::decrypt_in(*eta, &memo, params)
                    .into_iter()
                    .enumerate()
                    .filter_map(|(i, note)| {
                        match note {
                            Some(note) if note.p_d == key::derive_key_p_d(note.d.to_num(), *eta, params).x => {
                                Some((index + 1 + (i as u64), note))
                            }
                            _ => None,
                        }
                    })
                    .collect();
                

                if !in_notes.is_empty() {
                    Ok(ParseResult {
                        decrypted_memos: vec![ DecMemo{
                            index, 
                            in_notes: in_notes.iter().map(|(index, note)| IndexedNote{index: *index, note: *note}).collect(), 
                            tx_hash: match tx_hash {
                                Some(bytes) => Some(format!("0x{}", hex::encode(bytes))),
                                None        => None,
                            },
                            ..Default::default()
                        }],
                        state_update: StateUpdate {
                            new_leafs: vec![(index, hashes.collect())],
                            new_notes: vec![in_notes],
                            ..Default::default()
                        }
                    })
                } else {
                    Ok(ParseResult {
                        state_update: StateUpdate {
                            new_commitments: vec![(index, Num::from_uint_reduced(NumRepr(Uint::from_big_endian(&commitment))))],
                            ..Default::default()
                        },
                        ..Default::default()
                    })
                }
            }
        }
    } else {
        Err(ParseError::IncorrectPrefix(index, num_hashes, (constants::OUT + 1) as u32))
    }
}