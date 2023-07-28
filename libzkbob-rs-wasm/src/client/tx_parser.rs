use crate::{Account, Note};
use byteorder::{LittleEndian, ReadBytesExt};
use fawkes_crypto::{
    core::sizedvec::SizedVec,
    engines::{bn256::Fr, U256},
    BorshSerialize,
};
use libzkbob_rs::{
    delegated_deposit::{
        MemoDelegatedDeposit, DELEGATED_DEPOSIT_FLAG, MEMO_DELEGATED_DEPOSIT_SIZE,
    },
    keys::Keys,
    merkle::Hash,
    utils::zero_account,
};
use libzkbob_rs::{
    libzeropool::{
        constants,
        fawkes_crypto::ff_uint::{Num, NumRepr, Uint},
        native::{
            account::Account as NativeAccount,
            boundednum::BoundedNum,
            cipher::{
                self, decrypt_account_no_validate, decrypt_note_no_validate,
                symcipher_decryption_keys,
            },
            key::{self, derive_key_p_d},
            note::Note as NativeNote,
            tx::out_commitment_hash,
        },
    },
    utils::zero_note,
};
use serde::{Deserialize, Serialize};
use std::{iter::IntoIterator, str::FromStr};
use thiserror::Error;
use wasm_bindgen::{prelude::*, JsCast};
use web_sys::console;

#[cfg(feature = "multicore")]
use rayon::prelude::*;

use crate::{
    helpers::vec_into_iter, Fs, IndexedNote, IndexedTx, ParseTxsResult, PoolParams, TxMemoChunk,
    POOL_PARAMS,
};

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
            ParseError::NoPrefix(idx) => idx,
            ParseError::IncorrectPrefix(idx, _, _) => idx,
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
    pub new_accounts: Vec<(u64, NativeAccount<Fr>)>,
    #[serde(rename = "newNotes")]
    pub new_notes: Vec<Vec<(u64, NativeNote<Fr>)>>,
}

#[derive(Serialize, Deserialize, Clone, Default, Debug)]
pub struct DecMemo {
    pub index: u64,
    pub acc: Option<NativeAccount<Fr>>,
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
    pub state_update: StateUpdate,
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

/// Describes one memo chunk (account\note) along with decryption key
#[derive(Serialize, Deserialize, Clone, Default)]
pub struct MemoChunk {
    pub index: u64,
    pub encrypted: Vec<u8>,
    pub key: Vec<u8>,
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
        Ok(TxParser {
            params: POOL_PARAMS.clone(),
        })
    }

    #[wasm_bindgen(js_name = "parseTxs")]
    pub fn parse_txs(&self, sk: &[u8], txs: &JsValue) -> Result<ParseTxsResult, JsValue> {
        let sk = Num::<Fs>::from_uint(NumRepr(Uint::from_little_endian(sk)))
            .ok_or_else(|| js_err!("Invalid spending key"))?;
        let params = &self.params;
        let eta = Keys::derive(sk, params).eta;

        let txs: Vec<IndexedTx> = serde_wasm_bindgen::from_value(txs.to_owned())
            .map_err(|err| js_err!(&err.to_string()))?;

        let (parse_results, parse_errors): (Vec<_>, Vec<_>) = vec_into_iter(txs)
            .map(|tx| -> Result<ParseResult, ParseError> {
                let IndexedTx {
                    index,
                    memo,
                    commitment,
                } = tx;
                let memo = hex::decode(memo).unwrap();
                let commitment = hex::decode(commitment).unwrap();

                parse_tx(index, &commitment, &memo, None, &eta, params)
            })
            .partition(Result::is_ok);

        if parse_errors.is_empty() {
            let parse_result = parse_results.into_iter().map(Result::unwrap).fold(
                Default::default(),
                |acc: ParseResult, parse_result| ParseResult {
                    decrypted_memos: vec![acc.decrypted_memos, parse_result.decrypted_memos]
                        .concat(),
                    state_update: StateUpdate {
                        new_leafs: vec![
                            acc.state_update.new_leafs,
                            parse_result.state_update.new_leafs,
                        ]
                        .concat(),
                        new_commitments: vec![
                            acc.state_update.new_commitments,
                            parse_result.state_update.new_commitments,
                        ]
                        .concat(),
                        new_accounts: vec![
                            acc.state_update.new_accounts,
                            parse_result.state_update.new_accounts,
                        ]
                        .concat(),
                        new_notes: vec![
                            acc.state_update.new_notes,
                            parse_result.state_update.new_notes,
                        ]
                        .concat(),
                    },
                },
            );

            let parse_result = serde_wasm_bindgen::to_value(&parse_result)
                .unwrap()
                .unchecked_into::<ParseTxsResult>();
            Ok(parse_result)
        } else {
            let errors: Vec<_> = parse_errors
                .into_iter()
                .map(|err| -> ParseError {
                    let err = err.unwrap_err();
                    console::log_1(&format!("[WASM TxParser] ERROR: {}", err.to_string()).into());
                    err
                })
                .collect();
            let all_errs: Vec<u64> = errors.into_iter().map(|err| err.index()).collect();
            Err(js_err!(
                "The following txs cannot be processed: {:?}",
                all_errs
            ))
        }
    }

    #[wasm_bindgen(js_name = "extractDecryptKeys")]
    pub fn extract_decrypt_keys(
        &self,
        sk: &[u8],
        index: u64,
        memo: &[u8],
    ) -> Result<Vec<TxMemoChunk>, JsValue> {
        let sk = Num::<Fs>::from_uint(NumRepr(Uint::from_little_endian(sk)))
            .ok_or_else(|| js_err!("Invalid spending key"))?;
        let eta = Keys::derive(sk, &self.params).eta;
        //(index, chunk, key)
        let result = symcipher_decryption_keys(eta, memo, &self.params).unwrap_or(vec![]);

        let chunks = result
            .iter()
            .map(|(chunk_idx, chunk, key)| {
                let res = MemoChunk {
                    index: index + chunk_idx,
                    encrypted: chunk.clone(),
                    key: key.clone(),
                };

                serde_wasm_bindgen::to_value(&res)
                    .unwrap()
                    .unchecked_into::<TxMemoChunk>()
            })
            .collect();

        Ok(chunks)
    }

    #[wasm_bindgen(js_name = "symcipherDecryptAcc")]
    pub fn symcipher_decrypt_acc(
        &self,
        sym_key: &[u8],
        encrypted: &[u8],
    ) -> Result<Account, JsValue> {
        let acc = decrypt_account_no_validate(sym_key, encrypted, &self.params)
            .ok_or_else(|| js_err!("Unable to decrypt account"))?;

        Ok(serde_wasm_bindgen::to_value(&acc)
            .unwrap()
            .unchecked_into::<Account>())
    }

    #[wasm_bindgen(js_name = "symcipherDecryptNote")]
    pub fn symcipher_decrypt_note(
        &self,
        sym_key: &[u8],
        encrypted: &[u8],
    ) -> Result<Note, JsValue> {
        let note = decrypt_note_no_validate(sym_key, encrypted, &self.params)
            .ok_or_else(|| js_err!("Unable to decrypt note"))?;

        Ok(serde_wasm_bindgen::to_value(&note)
            .unwrap()
            .unchecked_into::<Note>())
    }

    #[wasm_bindgen(js_name = "check_out_commitment")]
    pub fn check_out_commitment(
        commitment: &str,
        memo: &str,
        account: Account,
    ) -> Result<bool, JsValue> {
        let account: NativeAccount<Fr> = serde_wasm_bindgen::from_value(account.into())?;

        let memo = hex::decode(memo)
            .map_err(|_| wasm_bindgen::JsError::new("failed to decode memo from hex"))?;

        // let commitment = Num::from_str(commitment)?;

        Ok(check_commitment(account, commitment, memo))
    }
}

pub fn check_commitment(account: NativeAccount<Fr>, commitment: &str, memo: Vec<u8>) -> bool {
    let (_is_delegated_deposit, num_items) = parse_prefix(&memo);

    let out_acc_hash_hex = &memo[4..36];
    let out_acc_memo =
        Num::<Fr>::from_uint_reduced(NumRepr(Uint::from_little_endian(out_acc_hash_hex)));

    println!("found {} items",num_items);
    let out_note_hashes =
        (&memo[36..])
            .chunks(32)
            .take((num_items -1 as u32)  as usize)
            .map(|out_note_hash_bytes| {
                let hex = hex::encode(out_note_hash_bytes);
                println!("found note: {}", hex);
                Num::<Fr>::from_uint_reduced(NumRepr(Uint::from_little_endian(out_note_hash_bytes)))
            });
    let out_account_hash = account.hash(&*POOL_PARAMS);

    let mut out_account_hash_bytes = [0; 32];
    BorshSerialize::serialize(&out_account_hash, &mut &mut out_account_hash_bytes[0..32]).unwrap();

    println!(
        "out_account_hash_hex {}",
        hex::encode(out_account_hash_bytes)
    );

    println!(
        "out_acc_memo==out_acc_hash: {}",
        out_acc_memo.eq(&out_account_hash)
    );

    let out_hashes: SizedVec<Num<Fr>, { constants::OUT + 1 }> = [out_account_hash]
        .iter()
        .copied()
        .chain(out_note_hashes)
        .chain((0..).map(|_| zero_note().hash(&*POOL_PARAMS)))
        .take(constants::OUT + 1)
        .collect();

    let out_commit = out_commitment_hash(out_hashes.as_slice(), &*POOL_PARAMS);

    let mut out_commit_bytes = [0; 32];

    BorshSerialize::serialize(&out_commit, &mut &mut out_commit_bytes[0..32]).unwrap();

    let out_commit_hex = hex::encode(out_commit_bytes);
    println!("out commit hex0 = {}", out_commit_hex);
    println!("out commit hex1 = {}", commitment);

    out_commit_hex == commitment
}

pub fn parse_tx(
    index: u64,
    commitment: &Vec<u8>,
    memo: &Vec<u8>,
    tx_hash: Option<&Vec<u8>>,
    eta: &Num<Fr>,
    params: &PoolParams,
) -> Result<ParseResult, ParseError> {
    if memo.len() < 4 {
        return Err(ParseError::NoPrefix(index));
    }

    let (is_delegated_deposit, num_items) = parse_prefix(&memo);
    // Special case: transaction contains delegated deposits
    if is_delegated_deposit {
        let num_deposits = num_items as usize;

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

        let in_notes: Vec<_> = in_notes_indexed.iter().map(|n| (n.index, n.note)).collect();

        let hashes = [zero_account().hash(params)]
            .iter()
            .copied()
            .chain(
                delegated_deposits
                    .iter()
                    .map(|d| d.to_delegated_deposit().to_note().hash(params)),
            )
            .collect();

        let parse_result = {
            if !in_notes.is_empty() {
                ParseResult {
                    decrypted_memos: vec![DecMemo {
                        index,
                        in_notes: in_notes_indexed,
                        tx_hash: match tx_hash {
                            Some(bytes) => Some(format!("0x{}", hex::encode(bytes))),
                            _ => None,
                        },
                        ..Default::default()
                    }],
                    state_update: StateUpdate {
                        new_leafs: vec![(index, hashes)],
                        new_notes: vec![in_notes],
                        ..Default::default()
                    },
                }
            } else {
                ParseResult {
                    state_update: StateUpdate {
                        new_commitments: vec![(
                            index,
                            Num::from_uint_reduced(NumRepr(Uint::from_big_endian(&commitment))),
                        )],
                        ..Default::default()
                    },
                    ..Default::default()
                }
            }
        };

        return Ok(parse_result);
    }

    // regular case: simple transaction memo
    let num_hashes = num_items;
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
                notes.into_iter().enumerate().for_each(|(i, note)| {
                    out_notes.push((index + 1 + (i as u64), note));

                    if note.p_d == key::derive_key_p_d(note.d.to_num(), *eta, params).x {
                        in_notes.push((index + 1 + (i as u64), note));
                    }
                });

                Ok(ParseResult {
                    decrypted_memos: vec![DecMemo {
                        index,
                        acc: Some(account),
                        in_notes: in_notes
                            .iter()
                            .map(|(index, note)| IndexedNote {
                                index: *index,
                                note: *note,
                            })
                            .collect(),
                        out_notes: out_notes
                            .into_iter()
                            .map(|(index, note)| IndexedNote { index, note })
                            .collect(),
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
                    },
                })
            }
            None => {
                let in_notes: Vec<(_, _)> = cipher::decrypt_in(*eta, &memo, params)
                    .into_iter()
                    .enumerate()
                    .filter_map(|(i, note)| match note {
                        Some(note)
                            if note.p_d == key::derive_key_p_d(note.d.to_num(), *eta, params).x =>
                        {
                            Some((index + 1 + (i as u64), note))
                        }
                        _ => None,
                    })
                    .collect();

                if !in_notes.is_empty() {
                    Ok(ParseResult {
                        decrypted_memos: vec![DecMemo {
                            index,
                            in_notes: in_notes
                                .iter()
                                .map(|(index, note)| IndexedNote {
                                    index: *index,
                                    note: *note,
                                })
                                .collect(),
                            tx_hash: match tx_hash {
                                Some(bytes) => Some(format!("0x{}", hex::encode(bytes))),
                                None => None,
                            },
                            ..Default::default()
                        }],
                        state_update: StateUpdate {
                            new_leafs: vec![(index, hashes.collect())],
                            new_notes: vec![in_notes],
                            ..Default::default()
                        },
                    })
                } else {
                    Ok(ParseResult {
                        state_update: StateUpdate {
                            new_commitments: vec![(
                                index,
                                Num::from_uint_reduced(NumRepr(Uint::from_big_endian(&commitment))),
                            )],
                            ..Default::default()
                        },
                        ..Default::default()
                    })
                }
            }
        }
    } else {
        Err(ParseError::IncorrectPrefix(
            index,
            num_hashes,
            (constants::OUT + 1) as u32,
        ))
    }
}

fn parse_prefix(memo: &[u8]) -> (bool, u32) {
    let prefix = (&memo[0..4]).read_u32::<LittleEndian>().unwrap();
    let is_delegated_deposit = prefix & DELEGATED_DEPOSIT_FLAG > 0;
    match is_delegated_deposit {
        true => (true, (prefix ^ DELEGATED_DEPOSIT_FLAG)),
        false => (false, prefix),
    }
}

#[test]
fn test_commitment_check() {
    // Account
    // Commitment: 20689024675149686951279403287851465204172304813867744345869859151717603361249
    // memo: 02000000a745fdc2bd71a2d9b1e8cc4b7c54ba2b4b28031c4cc16329253483e5b9acb229f98830e2eb5ccdf67bd414d8deeac0956ba796b66764a7972125bd6d2acaf501ad45b95ffdfcb464d9cd7ce84e7506a5d066cfd77cdf1e44b7209deea8a9721ba7408a996d46d595f3f6dd17b5700f6f675f782637b721b5265a23aa59a8d3463d37f636a8427ff9f6753603a21e2ffad4f342bb5fed5698f955411d5a73033e9a9efb66fea6c85aeb6fad7855611f847973108a0f15fc786c7a1d5aa0e54d9d9bbeb3d71c4e5b5dda1191b7cb0b1f4b7d25e8b39f9b0125de706756f9a7197e26eab7bd4e61e3fc8e3cf7bbb36471255ae11660c8b62b0509be1f040794c975c8eb53b4b878d3f9c0bb94a8b750a659f2f46bebd0ca8d35f1facffd69e35f274bb821886b04cd96c16107b277f034aba0b68524ae664cb0a2e258a7fbcd88b84ee2806d7651aad69c86ddca5b2f3287d4cf46aa09b0017986fcc765498911ed48cc9b05ab8cd9490b3668f0b94aba0efa4d
    //      num items:    02000000
    //      out acc hash: a745fdc2bd71a2d9b1e8cc4b7c54ba2b4b28031c4cc16329253483e5b9acb229f98830e2
    //      out note hash:eb5ccdf67bd414d8deeac0956ba796b66764a7972125bd6d2acaf501ad45b95ffdfcb464

    // "acc": {
    //     "d": "436372288118041506794638",
    //     "p_d": "8358364411001943365602355457890490687636973061216977207618248472133619894302",
    //     "i": "71043",
    //     "b": "189004460000",
    //     "e": "49498963978000"
    // }

    let d: Num<Fr> = Num::from_str("436372288118041506794638").unwrap();
    let p_d: Num<Fr> = Num::from_str(
        "8358364411001943365602355457890490687636973061216977207618248472133619894302",
    )
    .unwrap();
    // let p_d = Num::<Fr>::from_uint(NumRepr(Uint::from_little_endian( &hex::decode("127AAAA6D46AA9A9F316503DF79E52B6B59EA158AF23D6C5A96D462258C7481E").unwrap() ))).unwrap();
    let i: BoundedNum<Fr, { constants::HEIGHT }> =
        BoundedNum::new(Num::<Fr>::from_uint(NumRepr(Uint::from_u64(71043 as u64))).unwrap());
    let b: BoundedNum<Fr, { constants::BALANCE_SIZE_BITS }> =
        BoundedNum::new(Num::from_str("189004460000").unwrap());
    let e: BoundedNum<Fr, { constants::ENERGY_SIZE_BITS }> =
        BoundedNum::new(Num::from_str("49498963978000").unwrap());
    let account = NativeAccount {
        d: BoundedNum::<Fr, { constants::DIVERSIFIER_SIZE_BITS }>::new(d),
        p_d,
        i,
        b,
        e,
    };
    // let commitment =
        // "20689024675149686951279403287851465204172304813867744345869859151717603361249";
    // let commitment = Num::from_str(commitment).unwrap();
    let memo = "02000000a745fdc2bd71a2d9b1e8cc4b7c54ba2b4b28031c4cc16329253483e5b9acb229f98830e2eb5ccdf67bd414d8deeac0956ba796b66764a7972125bd6d2acaf501ad45b95ffdfcb464d9cd7ce84e7506a5d066cfd77cdf1e44b7209deea8a9721ba7408a996d46d595f3f6dd17b5700f6f675f782637b721b5265a23aa59a8d3463d37f636a8427ff9f6753603a21e2ffad4f342bb5fed5698f955411d5a73033e9a9efb66fea6c85aeb6fad7855611f847973108a0f15fc786c7a1d5aa0e54d9d9bbeb3d71c4e5b5dda1191b7cb0b1f4b7d25e8b39f9b0125de706756f9a7197e26eab7bd4e61e3fc8e3cf7bbb36471255ae11660c8b62b0509be1f040794c975c8eb53b4b878d3f9c0bb94a8b750a659f2f46bebd0ca8d35f1facffd69e35f274bb821886b04cd96c16107b277f034aba0b68524ae664cb0a2e258a7fbcd88b84ee2806d7651aad69c86ddca5b2f3287d4cf46aa09b0017986fcc765498911ed48cc9b05ab8cd9490b3668f0b94aba0efa4d";
    let commitment_hex = "2dbd92afc494789e664a766df0adbd553bc0578c23966146c9e50fde83fe41e1";
    let memo = hex::decode(memo).unwrap();
    assert!(check_commitment(account, commitment_hex, memo), "not equal");
}


#[test]
fn test_note_hash() {

    // {"d":"767694975897984814558431",
    // "p_d":"3782770200184127351480907975336572973775453363074048756321201309572765091453",
    // "b":"4000000000",
    // "t":"789715337429486340186206"}

    let note: NativeNote<Fr> = NativeNote {
        d: BoundedNum::new(Num::from_str("767694975897984814558431").unwrap()),
        p_d: Num::from_str("3782770200184127351480907975336572973775453363074048756321201309572765091453").unwrap(),
        b: BoundedNum::new(Num::from_str("4000000000").unwrap()),
        t: BoundedNum::new(Num::from_str("789715337429486340186206").unwrap()),
    };

    let mut  note_hash_bytes = [0;32];
    
    BorshSerialize::serialize(&note.hash(&*POOL_PARAMS), &mut &mut note_hash_bytes[0..32]).unwrap();
    
    println!("note hash = {}",hex::encode(note_hash_bytes));

    let memo = "02000000a745fdc2bd71a2d9b1e8cc4b7c54ba2b4b28031c4cc16329253483e5b9acb229f98830e2eb5ccdf67bd414d8deeac0956ba796b66764a7972125bd6d2acaf501ad45b95ffdfcb464d9cd7ce84e7506a5d066cfd77cdf1e44b7209deea8a9721ba7408a996d46d595f3f6dd17b5700f6f675f782637b721b5265a23aa59a8d3463d37f636a8427ff9f6753603a21e2ffad4f342bb5fed5698f955411d5a73033e9a9efb66fea6c85aeb6fad7855611f847973108a0f15fc786c7a1d5aa0e54d9d9bbeb3d71c4e5b5dda1191b7cb0b1f4b7d25e8b39f9b0125de706756f9a7197e26eab7bd4e61e3fc8e3cf7bbb36471255ae11660c8b62b0509be1f040794c975c8eb53b4b878d3f9c0bb94a8b750a659f2f46bebd0ca8d35f1facffd69e35f274bb821886b04cd96c16107b277f034aba0b68524ae664cb0a2e258a7fbcd88b84ee2806d7651aad69c86ddca5b2f3287d4cf46aa09b0017986fcc765498911ed48cc9b05ab8cd9490b3668f0b94aba0efa4d";
    let memo = hex::decode(memo).unwrap();
    let out_note_hashes:Vec<String> =
        (&memo[36..])
            .chunks(32)
            .take(1)
            .map(|v| hex::encode(v))
            .collect();
    println!("note hash = {}",out_note_hashes[0]);
    
    assert_eq!(out_note_hashes[0],hex::encode(note_hash_bytes));

}
