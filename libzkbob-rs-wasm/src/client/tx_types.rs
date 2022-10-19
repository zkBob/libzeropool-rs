use crate::{Fr, IDepositData, IDepositPermittableData, ITransferData, IWithdrawData, IMultiTransferData, IMultiWithdrawData};
use libzkbob_rs::client::{TokenAmount, TurnoverLimit, TokenLimit, TxOutput, TxType as NativeTxType, Limits as TxLimits};
use serde::Deserialize;
use wasm_bindgen::prelude::*;

#[allow(clippy::manual_non_exhaustive)]
#[wasm_bindgen]
pub enum TxType {
    Transfer = "transfer",
    Deposit = "deposit",
    DepositPermittable = "deposit_permittable",
    Withdraw = "withdraw",
}

pub trait JsTxType {
    fn to_native(&self) -> Result<NativeTxType<Fr>, JsValue>;
}

pub trait JsMultiTxType {
    fn to_native_array(&self) -> Result<Vec<NativeTxType<Fr>>, JsValue>;
}

#[wasm_bindgen]
#[derive(Deserialize)]
pub struct TxBaseFields {
    fee: TokenAmount<Fr>,
    data: Option<Vec<u8>>,
}

#[derive(Deserialize)]
pub struct Limits {
    pub daily_limit: TurnoverLimit<Fr>,
    pub transfer_limit: TokenLimit<Fr>,
    pub out_note_min: TokenLimit<Fr>,
}

impl Limits {
    fn to_native(&self) -> TxLimits<Fr> {
        TxLimits {
            daily_limit: self.daily_limit,
            transfer_limit: self.transfer_limit,
            out_note_min: self.out_note_min,
        }
    }
}

#[wasm_bindgen]
#[derive(Deserialize)]
pub struct DepositData {
    #[serde(flatten)]
    base_fields: TxBaseFields,
    amount: TokenAmount<Fr>,
    limits: Limits,
}

impl JsTxType for IDepositData {
    fn to_native(&self) -> Result<NativeTxType<Fr>, JsValue> {
        let DepositData {
            base_fields,
            amount,
            limits,
        } = serde_wasm_bindgen::from_value(self.into())?;

        Ok(NativeTxType::Deposit(
            base_fields.fee,
            base_fields.data.unwrap_or_default(),
            amount,
            limits.to_native(),
        ))
    }
}

#[wasm_bindgen]
#[derive(Deserialize)]
pub struct DepositPermittableData {
    #[serde(flatten)]
    base_fields: TxBaseFields,
    amount: TokenAmount<Fr>,
    deadline: String,
    holder: Vec<u8>,
    limits: Limits,
}

impl JsTxType for IDepositPermittableData {
    fn to_native(&self) -> Result<NativeTxType<Fr>, JsValue> {
        let DepositPermittableData {
            base_fields,
            amount,
            deadline,
            holder,
            limits,
        } = serde_wasm_bindgen::from_value(self.into())?;

        Ok(NativeTxType::DepositPermittable(
            base_fields.fee,
            base_fields.data.unwrap_or_default(),
            amount,
            deadline.parse::<u64>().unwrap_or(0),
            holder,
            limits.to_native(),
        ))
    }
}

#[derive(Deserialize)]
pub struct Output {
    to: String,
    amount: TokenAmount<Fr>,
}

#[wasm_bindgen]
#[derive(Deserialize)]
pub struct TransferData {
    #[serde(flatten)]
    base_fields: TxBaseFields,
    outputs: Vec<Output>,
    limits: Limits,
}

impl JsTxType for ITransferData {
    fn to_native(&self) -> Result<NativeTxType<Fr>, JsValue> {
        let TransferData {
            base_fields,
            outputs,
            limits,
        } = serde_wasm_bindgen::from_value(self.into())?;

        let outputs = outputs
            .into_iter()
            .map(|out| TxOutput {
                to: out.to,
                amount: out.amount,
            })
            .collect::<Vec<_>>();

        Ok(NativeTxType::Transfer(
            base_fields.fee,
            base_fields.data.unwrap_or_default(),
            outputs,
            limits.to_native(),
        ))
    }
}

impl JsMultiTxType for IMultiTransferData {
    fn to_native_array(&self) -> Result<Vec<NativeTxType<Fr>>, JsValue> {
        let array: Vec<TransferData> = serde_wasm_bindgen::from_value(self.into())?;

        let tx_array = array.into_iter().map(|tx| {
            let outputs = tx.outputs
            .into_iter()
            .map(|out| TxOutput {
                to: out.to,
                amount: out.amount,
            })
            .collect::<Vec<_>>();

            NativeTxType::Transfer(
                tx.base_fields.fee,
                tx.base_fields.data.unwrap_or_default(),
                outputs,
                tx.limits.to_native(),
            )
        }).collect();

        Ok(tx_array)
    }
}

#[wasm_bindgen]
#[derive(Deserialize)]
pub struct WithdrawData {
    #[serde(flatten)]
    base_fields: TxBaseFields,
    amount: TokenAmount<Fr>,
    to: Vec<u8>,
    native_amount: TokenAmount<Fr>,
    energy_amount: TokenAmount<Fr>,
    limits: Limits,
}

impl JsTxType for IWithdrawData {
    fn to_native(&self) -> Result<NativeTxType<Fr>, JsValue> {
        let WithdrawData {
            base_fields,
            amount,
            to,
            native_amount,
            energy_amount,
            limits,
        } = serde_wasm_bindgen::from_value(self.into())?;

        Ok(NativeTxType::Withdraw(
            base_fields.fee,
            base_fields.data.unwrap_or_default(),
            amount,
            to,
            native_amount,
            energy_amount,
            limits.to_native(),
        ))
    }
}

impl JsMultiTxType for IMultiWithdrawData {
    fn to_native_array(&self) -> Result<Vec<NativeTxType<Fr>>, JsValue> {
        let array: Vec<WithdrawData> = serde_wasm_bindgen::from_value(self.into())?;

        let tx_array = array.into_iter().map(|tx| {
            NativeTxType::Withdraw(
                tx.base_fields.fee,
                tx.base_fields.data.unwrap_or_default(),
                tx.amount,
                tx.to,
                tx.native_amount,
                tx.energy_amount,
                tx.limits.to_native(),
            )
        }).collect();

        Ok(tx_array)
    }
}
