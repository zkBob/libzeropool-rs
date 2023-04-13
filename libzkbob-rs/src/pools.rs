use std::fmt;

use libzeropool::native::boundednum::BoundedNum;
use libzeropool::fawkes_crypto::ff_uint::{PrimeField, Uint, NumRepr, Num};



pub const POOL_ID_BITS: usize = 24;
pub const GENERIC_ADDRESS_PREFIX: &str = "zkbob";


// Here is a pool reference enum
// It used to support multipool shielded addresses
#[derive(Copy, Clone, PartialEq, Debug)]
pub enum Pool {
    PolygonBOB,
    OptimismBOB,
    OptimismETH,
    SepoliaBOB,
    GoerliBOB,
    GoerliOptimismBOB,
}

impl Pool {
    pub fn from_pool_id(pool_id: u32) -> Option<Pool> {
        match pool_id {
            0x000000 => Some(Pool::PolygonBOB),
            0x000001 => Some(Pool::OptimismBOB),
            0x000002 => Some(Pool::OptimismETH),
            // pool_id duplication, use this method with caution
            // (it will never produce Pool::SepoliaBOB object)
            //0x000000 => Some(Pool::SepoliaBOB),
            0xffff02 => Some(Pool::GoerliBOB),
            0xffff03 => Some(Pool::GoerliOptimismBOB),
            _ => None,
        }
    }

    pub fn from_prefix(address_prefix: &str) -> Option<Pool> {
        match address_prefix.to_lowercase().as_str() {
            "zkbob_polygon" => Some(Pool::PolygonBOB),
            "zkbob_optimism" => Some(Pool::OptimismBOB),
            "zkbob_optimism_eth" => Some(Pool::OptimismETH),
            "zkbob_sepolia" => Some(Pool::SepoliaBOB),
            "zkbob_goerli" => Some(Pool::GoerliBOB),
            "zkbob_goerli_optimism" => Some(Pool::GoerliOptimismBOB),
            _ => None,
        }
    }

    pub fn pool_id(&self) -> u32 {
        match self {
            Pool::PolygonBOB => 0x000000,
            Pool::OptimismBOB => 0x000001,
            Pool::OptimismETH => 0x000002,
            // here is an issue with Sepolia pool deployment
            Pool::SepoliaBOB => 0x000000, 
            Pool::GoerliBOB => 0xffff02,
            Pool::GoerliOptimismBOB => 0xffff03,
        }
    }

    pub fn pool_id_num<Fr: PrimeField>(&self) -> BoundedNum<Fr, POOL_ID_BITS> {
        let pool_id = self.pool_id();
        let pool_id_num = Num::<Fr>::from_uint(NumRepr(Uint::from_u64(pool_id as u64))).unwrap();

        BoundedNum::new(pool_id_num)
    }

    pub fn address_prefix(&self) -> &str {
        match self {
            Pool::PolygonBOB => "zkbob_polygon",
            Pool::OptimismBOB => "zkbob_optimism",
            Pool::OptimismETH => "zkbob_optimism_eth",
            Pool::SepoliaBOB => "zkbob_sepolia",
            Pool::GoerliBOB => "zkbob_goerli",
            Pool::GoerliOptimismBOB => "zkbob_goerli_optimism",
        }
    }

    pub fn human_readable(&self) -> &str {
        match self {
            Pool::PolygonBOB => "BOB on Polygon",
            Pool::OptimismBOB => "BOB on Optimism",
            Pool::OptimismETH => "ETH on Optimism",
            Pool::SepoliaBOB => "BOB on Sepolia testnet",
            Pool::GoerliBOB => "BOB on Goerli testnet",
            Pool::GoerliOptimismBOB => "BOB on Goerli Optimism testnet",
        }
    }
}

impl fmt::Display for Pool {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.human_readable())
    }
}