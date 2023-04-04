use crate::utils::keccak256;
use crate::client::POOL_ID_BITS;
use libzeropool::{
    constants,
    fawkes_crypto::{
        borsh::{BorshDeserialize, BorshSerialize},
        ff_uint::Num, native::ecc::EdwardsPoint,
    },
    native::boundednum::BoundedNum,
    native::params::PoolParams,
};
use thiserror::Error;

const ADDR_LEN: usize = 46;

#[derive(Error, Debug)]
pub enum AddressParseError {
    #[error("Invalid checksum")]
    InvalidChecksum,
    #[error("Pd does not belongs prime subgroup")]
    InvalidNumber,
    #[error("Decode error: {0}")]
    Base58DecodeError(#[from] bs58::decode::Error),
    #[error("Deserialization error: {0}")]
    DeserializationError(#[from] std::io::Error),
}

pub fn parse_address<P: PoolParams>(
    address: &str,
    params: &P,
) -> Result<
    (
        BoundedNum<P::Fr, { constants::DIVERSIFIER_SIZE_BITS }>,
        Num<P::Fr>,
    ),
    AddressParseError,
>{
    let mut bytes = [0; ADDR_LEN];
    bs58::decode(address).into(&mut bytes)?;

    let checksum = &bytes[42..=45];

    let hash = keccak256(&bytes[0..=41]);

    if &hash[0..=3] != checksum {
        return Err(AddressParseError::InvalidChecksum);
    }

    let d = BoundedNum::try_from_slice(&bytes[0..10])?;
    let p_d = Num::try_from_slice(&bytes[10..42])?;

    match EdwardsPoint::subgroup_decompress(p_d, params.jubjub()) {
        Some(_) => Ok((d, p_d)),
        None => Err(AddressParseError::InvalidNumber)
    }
}

pub fn format_address<P: PoolParams>(
    d: BoundedNum<P::Fr, { constants::DIVERSIFIER_SIZE_BITS }>,
    p_d: Num<P::Fr>,
    pool_id: Option<BoundedNum<P::Fr, { POOL_ID_BITS }>>,
) -> String {
    let mut buf: [u8; ADDR_LEN] = [0; ADDR_LEN];

    d.serialize(&mut &mut buf[0..10]).unwrap();
    p_d.serialize(&mut &mut buf[10..42]).unwrap();

    let raw_addr_hash = keccak256(&buf[0..42]);

    let checksum_hash = match pool_id {
        // pool-specific format
        Some(pool_id) => {
            let mut hash_src: [u8; POOL_ID_BITS + 32] = [0; POOL_ID_BITS + 32];
            pool_id.serialize(& mut &mut hash_src[0..(POOL_ID_BITS >> 3)]).unwrap();
            hash_src[(POOL_ID_BITS >> 3)..POOL_ID_BITS + 32].clone_from_slice(&keccak256(&buf[0..42]));
            keccak256(&hash_src)
        },
        // generic format
        None => keccak256(&buf[0..42]),
    };
    buf[42..ADDR_LEN].clone_from_slice(&checksum_hash[0..4]);



    bs58::encode(buf).into_string()
}
