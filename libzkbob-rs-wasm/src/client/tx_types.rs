use crate::{Fr, IDepositData, IDepositPermittableData, ITransferData, IWithdrawData, IMultiTransferData, IMultiWithdrawData};
use libzkbob_rs::client::{TokenAmount, TxOutput, TxType as NativeTxType, ExtraItem, TxOperator};
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
    proxy: Vec<u8>,
    proxy_fee: TokenAmount<Fr>,
    prover_fee: TokenAmount<Fr>,
    data: Vec<ExtraItem>,
}

#[wasm_bindgen]
#[derive(Deserialize)]
pub struct DepositData {
    #[serde(flatten)]
    base_fields: TxBaseFields,
    amount: TokenAmount<Fr>,
}

impl JsTxType for IDepositData {
    fn to_native(&self) -> Result<NativeTxType<Fr>, JsValue> {
        let DepositData {
            base_fields,
            amount,
        } = serde_wasm_bindgen::from_value(self.into())?;

        let operator = TxOperator {
            proxy_address: base_fields.proxy,
            proxy_fee: base_fields.proxy_fee,
            prover_fee: base_fields.prover_fee,
        };

        Ok(NativeTxType::Deposit(
            operator,
            base_fields.data,
            amount,
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
}

impl JsTxType for IDepositPermittableData {
    fn to_native(&self) -> Result<NativeTxType<Fr>, JsValue> {
        let DepositPermittableData {
            base_fields,
            amount,
            deadline,
            holder,
        } = serde_wasm_bindgen::from_value(self.into())?;

        let operator = TxOperator {
            proxy_address: base_fields.proxy,
            proxy_fee: base_fields.proxy_fee,
            prover_fee: base_fields.prover_fee,
        };

        Ok(NativeTxType::DepositPermittable(
            operator,
            base_fields.data,
            amount,
            deadline.parse::<u64>().unwrap_or(0),
            holder
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
}

impl JsTxType for ITransferData {
    fn to_native(&self) -> Result<NativeTxType<Fr>, JsValue> {
        let TransferData {
            base_fields,
            outputs,
        } = serde_wasm_bindgen::from_value(self.into())?;

        let outputs = outputs
            .into_iter()
            .map(|out| TxOutput {
                to: out.to,
                amount: out.amount,
            })
            .collect::<Vec<_>>();
        
        let operator = TxOperator {
            proxy_address: base_fields.proxy,
            proxy_fee: base_fields.proxy_fee,
            prover_fee: base_fields.prover_fee,
        };

        Ok(NativeTxType::Transfer(
            operator,
            base_fields.data,
            outputs,
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

            let operator = TxOperator {
                proxy_address: tx.base_fields.proxy,
                proxy_fee: tx.base_fields.proxy_fee,
                prover_fee: tx.base_fields.prover_fee,
            };

            NativeTxType::Transfer(
                operator,
                tx.base_fields.data,
                outputs,
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
}

impl JsTxType for IWithdrawData {
    fn to_native(&self) -> Result<NativeTxType<Fr>, JsValue> {
        let WithdrawData {
            base_fields,
            amount,
            to,
            native_amount,
            energy_amount,
        } = serde_wasm_bindgen::from_value(self.into())?;

        let operator = TxOperator {
            proxy_address: base_fields.proxy,
            proxy_fee: base_fields.proxy_fee,
            prover_fee: base_fields.prover_fee,
        };

        Ok(NativeTxType::Withdraw(
            operator,
            base_fields.data,
            amount,
            to,
            native_amount,
            energy_amount,
        ))
    }
}

impl JsMultiTxType for IMultiWithdrawData {
    fn to_native_array(&self) -> Result<Vec<NativeTxType<Fr>>, JsValue> {
        let array: Vec<WithdrawData> = serde_wasm_bindgen::from_value(self.into())?;

        let tx_array = array.into_iter().map(|tx| {
            let operator = TxOperator {
                proxy_address: tx.base_fields.proxy,
                proxy_fee: tx.base_fields.proxy_fee,
                prover_fee: tx.base_fields.prover_fee,
            };

            NativeTxType::Withdraw(
                operator,
                tx.base_fields.data,
                tx.amount,
                tx.to,
                tx.native_amount,
                tx.energy_amount,
            )
        }).collect();

        Ok(tx_array)
    }
}
