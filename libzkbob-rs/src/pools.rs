use std::fmt;

use libzeropool::native::boundednum::BoundedNum;
use libzeropool::fawkes_crypto::ff_uint::{PrimeField, Uint, NumRepr, Num};



pub const POOL_ID_BITS: usize = 24;
pub const GENERIC_ADDRESS_PREFIX: &str = "zkbob";


// Here is a pool reference enum
// It used to support multipool shielded addresses
#[derive(Copy, Clone, PartialEq, Debug)]
pub enum Pool {
    Polygon = 0,
    Optimism,
    Sepolia,
    Goerli,
    GoerliOptimism,
}

impl Pool {
    pub fn from_pool_id(pool_id: u32) -> Option<Pool> {
        match pool_id {
            0x000000 => Some(Pool::Polygon),
            0x000001 => Some(Pool::Optimism),
            0x000002 => Some(Pool::Sepolia),
            0xffff02 => Some(Pool::Goerli),
            0xffff03 => Some(Pool::GoerliOptimism),
            _ => None,
        }
    }

    pub fn from_prefix(address_prefix: &str) -> Option<Pool> {
        match address_prefix.to_lowercase().as_str() {
            "zkbob_polygon" => Some(Pool::Polygon),
            "zkbob_optimism" => Some(Pool::Optimism),
            "zkbob_sepolia" => Some(Pool::Sepolia),
            "zkbob_goerli" => Some(Pool::Goerli),
            "zkbob_goerli_optimism" => Some(Pool::GoerliOptimism),
            _ => None,
        }
    }

    pub fn pool_id(&self) -> u32 {
        match self {
            Pool::Polygon => 0x00000,
            Pool::Optimism => 0x00000,
            Pool::Sepolia => 0x00000,
            Pool::Goerli => 0xffff02,
            Pool::GoerliOptimism => 0xffff03,
        }
    }

    pub fn pool_id_num<Fr: PrimeField>(&self) -> BoundedNum<Fr, POOL_ID_BITS> {
        let pool_id = self.pool_id();
        let pool_id_num = Num::<Fr>::from_uint(NumRepr(Uint::from_u64(pool_id as u64))).unwrap();

        BoundedNum::new(pool_id_num)
    }

    pub fn address_prefix(&self) -> &str {
        match self {
            Pool::Polygon => "zkbob_polygon",
            Pool::Optimism => "zkbob_optimism",
            Pool::Sepolia => "zkbob_sepolia",
            Pool::Goerli => "zkbob_goerli",
            Pool::GoerliOptimism => "zkbob_goerli_optimism",
        }
    }
}

impl fmt::Display for Pool {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Pool::Polygon => write!(f, "BOB on Polygon"),
            Pool::Optimism => write!(f, "BOB on Optimism"),
            Pool::Sepolia => write!(f, "BOB on Sepolia testnet"),
            Pool::Goerli => write!(f, "BOB on Goerli testnet"),
            Pool::GoerliOptimism => write!(f, "BOB on Goerli Optimism testnet"),
        }
    }
}