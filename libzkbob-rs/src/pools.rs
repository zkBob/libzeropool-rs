use std::convert::TryInto;
use std::fmt;

use libzeropool::native::boundednum::BoundedNum;
use libzeropool::fawkes_crypto::ff_uint::{PrimeField, Uint, NumRepr, Num};



pub const POOL_ID_BITS: usize = 24;
pub const GENERIC_ADDRESS_PREFIX: &str = "zkbob";


// Here is a pool reference enum
// It used to support multipool shielded addresses
#[derive(Copy, Clone, PartialEq, Debug)]
pub enum Pool {
    PolygonUSDC,
    OptimismUSDC,
    OptimismETH,
    TronUSDT,
    SepoliaBOB,
    GoerliBOB,
    GoerliOptimismUSDC,
    GoerliETH,
    GoerliUSDC,
    ShastaUSDT,
}

impl Pool {
    pub fn from_pool_id(pool_id: u32) -> Option<Pool> {
        match pool_id {
            0x000000 => Some(Pool::PolygonUSDC),
            0x000001 => Some(Pool::OptimismUSDC),
            0x000002 => Some(Pool::OptimismETH),
            0x000003 => Some(Pool::TronUSDT),
            // pool_id duplication, use this method with caution
            // (it will never produce Pool::SepoliaBOB object)
            //0x000000 => Some(Pool::SepoliaBOB),
            0xffff02 => Some(Pool::GoerliBOB),
            0xffff03 => Some(Pool::GoerliOptimismUSDC),
            0xffff04 => Some(Pool::GoerliETH),
            0xffff05 => Some(Pool::GoerliUSDC),
            0xffff06 => Some(Pool::ShastaUSDT),
            _ => None,
        }
    }

    pub fn from_prefix(address_prefix: &str) -> Option<Pool> {
        match address_prefix.to_lowercase().as_str() {
            "zkbob_polygon" => Some(Pool::PolygonUSDC),
            "zkbob_optimism" => Some(Pool::OptimismUSDC),
            "zkbob_optimism_eth" => Some(Pool::OptimismETH),
            "zkbob_tron" => Some(Pool::TronUSDT),
            "zkbob_sepolia" => Some(Pool::SepoliaBOB),
            "zkbob_goerli" => Some(Pool::GoerliBOB),
            "zkbob_goerli_optimism" => Some(Pool::GoerliOptimismUSDC),
            "zkbob_goerli_eth" => Some(Pool::GoerliETH),
            "zkbob_goerli_usdc" => Some(Pool::GoerliUSDC),
            "zkbob_shasta" => Some(Pool::ShastaUSDT),
            _ => None,
        }
    }

    pub fn pool_id(&self) -> u32 {
        match self {
            Pool::PolygonUSDC => 0x000000,
            Pool::OptimismUSDC => 0x000001,
            Pool::OptimismETH => 0x000002,
            Pool::TronUSDT => 0x000003,
            // here is an issue with Sepolia pool deployment
            Pool::SepoliaBOB => 0x000000, 
            Pool::GoerliBOB => 0xffff02,
            Pool::GoerliOptimismUSDC => 0xffff03,
            Pool::GoerliETH => 0xffff04,
            Pool::GoerliUSDC => 0xffff05,
            Pool::ShastaUSDT => 0xffff06,
        }
    }

    pub fn pool_id_num<Fr: PrimeField>(&self) -> BoundedNum<Fr, POOL_ID_BITS> {
        let pool_id = self.pool_id();
        let pool_id_num = Num::<Fr>::from_uint(NumRepr(Uint::from_u64(pool_id as u64))).unwrap();

        BoundedNum::new(pool_id_num)
    }

    pub fn pool_id_bytes_be<Fr: PrimeField>(&self) -> [u8; POOL_ID_BITS >> 3] {
        const POOL_ID_BYTES: usize = POOL_ID_BITS >> 3;
        let pool_id = self.pool_id();
        let pool_id_num = Num::<Fr>::from_uint(NumRepr(Uint::from_u64(pool_id as u64))).unwrap();
        
        let pool_id_bytes = pool_id_num.to_uint().0.to_big_endian();
        let pool_id_be: [u8; POOL_ID_BYTES] = pool_id_bytes[32 - POOL_ID_BYTES..32].try_into().unwrap();

        pool_id_be
    }

    pub fn address_prefix(&self) -> &str {
        match self {
            Pool::PolygonUSDC => "zkbob_polygon",
            Pool::OptimismUSDC => "zkbob_optimism",
            Pool::OptimismETH => "zkbob_optimism_eth",
            Pool::TronUSDT => "zkbob_tron",
            Pool::SepoliaBOB => "zkbob_sepolia",
            Pool::GoerliBOB => "zkbob_goerli",
            Pool::GoerliOptimismUSDC => "zkbob_goerli_optimism",
            Pool::GoerliETH => "zkbob_goerli_eth",
            Pool::GoerliUSDC => "zkbob_goerli_usdc",
            Pool::ShastaUSDT => "zkbob_shasta",
        }
    }

    pub fn human_readable(&self) -> &str {
        match self {
            Pool::PolygonUSDC => "BOB on Polygon",
            Pool::OptimismUSDC => "USDC on Optimism",
            Pool::OptimismETH => "WETH on Optimism",
            Pool::TronUSDT => "USDT on Tron",
            Pool::SepoliaBOB => "BOB on Sepolia testnet",
            Pool::GoerliBOB => "BOB on Goerli testnet",
            Pool::GoerliOptimismUSDC => "USDC on Goerli Optimism testnet",
            Pool::GoerliETH => "WETH on Goerli testnet",
            Pool::GoerliUSDC => "USDC on Goerli testnet",
            Pool::ShastaUSDT => "USDT on Shasta testnet",
        }
    }
}

impl fmt::Display for Pool {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.human_readable())
    }
}