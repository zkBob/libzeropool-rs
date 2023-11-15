use std::convert::{TryInto};

use crate::{utils::keccak256};
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
const POOL_ID_BITS: usize = 24;

#[derive(Error, Debug)]
pub enum AddressParseError {
    #[error("Invalid format")]
    InvalidFormat,
    #[error("Invalid prefix {0}")]
    InvalidPrefix(String),
    #[error("Invalid checksum")]
    InvalidChecksum,
    #[error("Pd does not belongs prime subgroup")]
    InvalidNumber,
    #[error("Decode error: {0}")]
    Base58DecodeError(#[from] bs58::decode::Error),
    #[error("Deserialization error: {0}")]
    DeserializationError(#[from] std::io::Error),
}

pub enum AddressFormat {
    Old,
    PoolSpecific,
    Generic,
}

impl AddressFormat {
    pub fn name(&self) -> &str {
        match self {
            AddressFormat::Old => "old",
            AddressFormat::PoolSpecific => "pool",
            AddressFormat::Generic => "generic",
        }
    }
}

pub fn parse_address<P: PoolParams>(
    address: &str,
    params: &P,
    pool_id: u32,
    prefix: &str,
    generic_prefix: &str
) -> Result<
    (
        BoundedNum<P::Fr, { constants::DIVERSIFIER_SIZE_BITS }>, // d
        Num<P::Fr>, // p_d
        Option<Pool>,   // None for generic addresses
    ),
    AddressParseError,
>{
    let (d, p_d, pool, _, _) = parse_address_ext(address, params)?;
    Ok((d, p_d, pool))
}

pub fn parse_address_ext<P: PoolParams>(
    address: &str,
    params: &P,
) -> Result<
    (
        BoundedNum<P::Fr, { constants::DIVERSIFIER_SIZE_BITS }>, // d
        Num<P::Fr>, // p_d
        Option<Pool>,   // None for generic addresses
        AddressFormat,
        [u8; 4],    // checksum
    ),
    AddressParseError,
>{
    if address.find(':').is_some() {
        // address with prefix
        let addr_components: Vec<&str> = address.split(':').collect();  
        if addr_components.len() == 2 {
            let pool = Pool::from_prefix(addr_components[0]);
            let (d,
                p_d,
                addr_hash,
                checksum) = parse_address_raw(addr_components[1], params)?;

            match pool {
                Some(pool) => {
                    // pool-specific address
                    const POOL_ID_BYTES: usize = POOL_ID_BITS >> 3;
                    let mut hash_src: [u8; POOL_ID_BYTES + 32] = [0; POOL_ID_BYTES + 32];
                    pool.pool_id_bytes_be::<P::Fr>().serialize(& mut &mut hash_src[0..POOL_ID_BYTES]).unwrap();
                    hash_src[POOL_ID_BYTES..POOL_ID_BYTES + 32].clone_from_slice(&addr_hash);

                    if keccak256(&hash_src)[0..=3] != checksum {
                        return Err(AddressParseError::InvalidChecksum);
                    }
                    return Ok((d, p_d, Some(pool), AddressFormat::PoolSpecific, checksum));
                },
                None => {
                    if addr_components[0].to_lowercase() == GENERIC_ADDRESS_PREFIX {
                        // generic address
                        if addr_hash[0..=3] != checksum {
                            return Err(AddressParseError::InvalidChecksum);
                        }
                        return Ok((d, p_d, None, AddressFormat::Generic, checksum));
                    } else {
                        return Err(AddressParseError::InvalidPrefix(addr_components[0].to_string()))
                    }
                },
            };
        }

        Err(AddressParseError::InvalidFormat)
    } else {
        // old format without prefix
        let (d,
            p_d,
            addr_hash,
            checksum) = parse_address_raw(address, params)?;
        
        if addr_hash[0..=3] != checksum {
            return Err(AddressParseError::InvalidChecksum);
        }

        // the old format should be acceptable on the Polygon BOB pool only
        Ok((d, p_d, Some(Pool::PolygonUSDC), AddressFormat::Old, checksum))
    }
}

fn parse_address_raw<P: PoolParams>(
    raw_address: &str,
    params: &P,
) -> Result<
    (
        BoundedNum<P::Fr, { constants::DIVERSIFIER_SIZE_BITS }>, // d
        Num<P::Fr>, // p_d
        [u8; 32],   // keccak256(d ++ p_d)
        [u8; 4],    // checksum (not checked, just extracted)
    ),
    AddressParseError,
>{
    let mut bytes = [0; ADDR_LEN];
    bs58::decode(raw_address).into(&mut bytes)?;

    let d = BoundedNum::try_from_slice(&bytes[0..10])?;
    let p_d = Num::try_from_slice(&bytes[10..42])?;
    let checksum = bytes[42..=45].try_into().unwrap();

    match EdwardsPoint::subgroup_decompress(p_d, params.jubjub()) {
        Some(_) => Ok((d, p_d, keccak256(&bytes[0..=41]), checksum)),
        None => Err(AddressParseError::InvalidNumber)
    }
}

// generates shielded address in format "pool_prefix:base58(d ++ p_d ++ checksum)"
pub fn format_address<P: PoolParams>(
    d: BoundedNum<P::Fr, { constants::DIVERSIFIER_SIZE_BITS }>,
    p_d: Num<P::Fr>,
    pool: Option<Pool>, // set pool to None to generate universal address for all pools
) -> String {
    let mut buf: [u8; ADDR_LEN] = [0; ADDR_LEN];

    d.serialize(&mut &mut buf[0..10]).unwrap();
    p_d.serialize(&mut &mut buf[10..42]).unwrap();

    // there are two ways for checksum calculation
    let (checksum_hash, address_prefix) = match pool {
        // pool-specific format
        Some(pool) => {
            const POOL_ID_BYTES: usize = POOL_ID_BITS >> 3;
            let mut hash_src: [u8; POOL_ID_BYTES + 32] = [0; POOL_ID_BYTES + 32];
            //let pool_id = pool.pool_id_num::<P::Fr>().to_num().to_uint().0.to_big_endian();
            //let pool_id_be: [u8; POOL_ID_BYTES] = pool_id[32 - POOL_ID_BYTES..32].try_into().unwrap();
            pool.pool_id_bytes_be::<P::Fr>().serialize(& mut &mut hash_src[0..POOL_ID_BYTES]).unwrap();
            hash_src[POOL_ID_BYTES..POOL_ID_BYTES + 32].clone_from_slice(&keccak256(&buf[0..42]));
            (keccak256(&hash_src), pool.address_prefix().to_owned())
        },
        // generic format (for all pools, when pool_id isn't specified)
        None => (keccak256(&buf[0..42]), GENERIC_ADDRESS_PREFIX.to_string()),
    };
    buf[42..ADDR_LEN].clone_from_slice(&checksum_hash[0..4]);

    let address_part = bs58::encode(buf).into_string();

    format!("{}:{}", address_prefix, address_part)

}
