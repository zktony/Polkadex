//! Autogenerated weights for `thea_message_handler`
//!
//! THIS FILE WAS AUTO-GENERATED USING THE SUBSTRATE BENCHMARK CLI VERSION 4.0.0-dev
//! DATE: 2023-10-24, STEPS: `100`, REPEAT: `200`, LOW RANGE: `[]`, HIGH RANGE: `[]`
//! WORST CASE MAP SIZE: `1000000`
//! HOSTNAME: `ip-172-31-41-122`, CPU: `AMD EPYC 7571`
//! WASM-EXECUTION: `Compiled`, CHAIN: `None`, DB CACHE: 1024

// Executed Command:
// ./polkadex-node
// benchmark
// pallet
// --pallet
// thea-message-handler
// --steps
// 100
// --repeat
// 200
// --extrinsic
// *
// --output
// weights.rs

#![cfg_attr(rustfmt, rustfmt_skip)]
#![allow(unused_parens)]
#![allow(unused_imports)]
#![allow(missing_docs)]

use frame_support::{traits::Get, weights::Weight};
use core::marker::PhantomData;

/// Weight functions for `thea_message_handler`.
pub struct WeightInfo<T>(PhantomData<T>);
impl<T: frame_system::Config> crate::WeightInfo for WeightInfo<T> {
    /// Storage: `TheaMH::Authorities` (r:0 w:1)
    /// Proof: `TheaMH::Authorities` (`max_values`: None, `max_size`: None, mode: `Measured`)
    /// Storage: `TheaMH::ValidatorSetId` (r:0 w:1)
    /// Proof: `TheaMH::ValidatorSetId` (`max_values`: Some(1), `max_size`: None, mode: `Measured`)
    /// The range of component `b` is `[0, 4294967295]`.
    fn insert_authorities(_b: u32, ) -> Weight {
        // Proof Size summary in bytes:
        //  Measured:  `0`
        //  Estimated: `0`
        // Minimum execution time: 21_551_000 picoseconds.
        Weight::from_parts(22_623_815, 0)
            .saturating_add(Weight::from_parts(0, 0))
            .saturating_add(T::DbWeight::get().writes(2))
    }
    /// Storage: `TheaMH::ValidatorSetId` (r:1 w:0)
    /// Proof: `TheaMH::ValidatorSetId` (`max_values`: Some(1), `max_size`: None, mode: `Measured`)
    /// Storage: `TheaExecutor::ApprovedDeposits` (r:1 w:1)
    /// Proof: `TheaExecutor::ApprovedDeposits` (`max_values`: None, `max_size`: None, mode: `Measured`)
    /// Storage: `TheaMH::IncomingNonce` (r:0 w:1)
    /// Proof: `TheaMH::IncomingNonce` (`max_values`: Some(1), `max_size`: None, mode: `Measured`)
    /// Storage: `TheaMH::IncomingMessages` (r:0 w:1)
    /// Proof: `TheaMH::IncomingMessages` (`max_values`: None, `max_size`: None, mode: `Measured`)
    fn incoming_message() -> Weight {
        // Proof Size summary in bytes:
        //  Measured:  `147`
        //  Estimated: `3612`
        // Minimum execution time: 78_662_000 picoseconds.
        Weight::from_parts(80_103_000, 0)
            .saturating_add(Weight::from_parts(0, 3612))
            .saturating_add(T::DbWeight::get().reads(2))
            .saturating_add(T::DbWeight::get().writes(3))
    }
    /// Storage: `TheaMH::IncomingNonce` (r:0 w:1)
    /// Proof: `TheaMH::IncomingNonce` (`max_values`: Some(1), `max_size`: None, mode: `Measured`)
    /// The range of component `b` is `[1, 4294967295]`.
    fn update_incoming_nonce(_b: u32, ) -> Weight {
        // Proof Size summary in bytes:
        //  Measured:  `0`
        //  Estimated: `0`
        // Minimum execution time: 16_351_000 picoseconds.
        Weight::from_parts(17_317_871, 0)
            .saturating_add(Weight::from_parts(0, 0))
            .saturating_add(T::DbWeight::get().writes(1))
    }
    /// Storage: `TheaMH::OutgoingNonce` (r:0 w:1)
    /// Proof: `TheaMH::OutgoingNonce` (`max_values`: Some(1), `max_size`: None, mode: `Measured`)
    /// The range of component `b` is `[1, 4294967295]`.
    fn update_outgoing_nonce(_b: u32, ) -> Weight {
        // Proof Size summary in bytes:
        //  Measured:  `0`
        //  Estimated: `0`
        // Minimum execution time: 16_281_000 picoseconds.
        Weight::from_parts(17_369_250, 0)
            .saturating_add(Weight::from_parts(0, 0))
            .saturating_add(T::DbWeight::get().writes(1))
    }
}
