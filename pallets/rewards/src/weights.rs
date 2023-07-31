
//! Autogenerated weights for `pallet_rewards`
//!
//! THIS FILE WAS AUTO-GENERATED USING THE SUBSTRATE BENCHMARK CLI VERSION 4.0.0-dev
//! DATE: 2023-06-15, STEPS: `100`, REPEAT: `200`, LOW RANGE: `[]`, HIGH RANGE: `[]`
//! WORST CASE MAP SIZE: `1000000`
//! HOSTNAME: `Ubuntu-2204-jammy-amd64-base`, CPU: `Intel(R) Core(TM) i7-7700 CPU @ 3.60GHz`
//! EXECUTION: None, WASM-EXECUTION: Compiled, CHAIN: None, DB CACHE: 1024

// Executed Command:
// ./polkadex-node
// benchmark
// pallet
// --pallet
// pallet-rewards
// --steps
// 100
// --repeat
// 200
// --extrinsic
// *
// --output
// rewards_weights.rs

#![cfg_attr(rustfmt, rustfmt_skip)]
#![allow(unused_parens)]
#![allow(unused_imports)]
#![allow(missing_docs)]

use frame_support::{traits::Get, weights::Weight};
use core::marker::PhantomData;

/// Weight functions for `pallet_rewards`.
pub struct WeightInfo<T>(PhantomData<T>);
impl<T: frame_system::Config> crate::WeightInfo for WeightInfo<T> {
	/// Storage: Rewards InitializeRewards (r:1 w:1)
	/// Proof Skipped: Rewards InitializeRewards (max_values: None, max_size: None, mode: Measured)
	/// The range of component `b` is `[0, 4838400]`.
	/// The range of component `i` is `[1, 100]`.
	/// The range of component `r` is `[0, 10]`.
	fn create_reward_cycle(_b: u32, _i: u32, _r: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `76`
		//  Estimated: `3541`
		// Minimum execution time: 8_301_000 picoseconds.
		Weight::from_parts(8_987_679, 0)
			.saturating_add(Weight::from_parts(0, 3541))
			.saturating_add(T::DbWeight::get().reads(1))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	/// Storage: Rewards InitializeRewards (r:1 w:0)
	/// Proof Skipped: Rewards InitializeRewards (max_values: None, max_size: None, mode: Measured)
	/// Storage: Rewards Distributor (r:1 w:1)
	/// Proof Skipped: Rewards Distributor (max_values: None, max_size: None, mode: Measured)
	/// Storage: System Account (r:2 w:2)
	/// Proof: System Account (max_values: None, max_size: Some(128), added: 2603, mode: MaxEncodedLen)
	/// Storage: Balances Locks (r:1 w:1)
	/// Proof: Balances Locks (max_values: None, max_size: Some(1299), added: 3774, mode: MaxEncodedLen)
	/// Storage: Balances Freezes (r:1 w:0)
	/// Proof: Balances Freezes (max_values: None, max_size: Some(49), added: 2524, mode: MaxEncodedLen)
	fn initialize_claim_rewards() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `1010`
		//  Estimated: `6196`
		// Minimum execution time: 55_534_000 picoseconds.
		Weight::from_parts(56_476_000, 0)
			.saturating_add(Weight::from_parts(0, 6196))
			.saturating_add(T::DbWeight::get().reads(6))
			.saturating_add(T::DbWeight::get().writes(4))
	}
	/// Storage: Rewards Distributor (r:1 w:1)
	/// Proof Skipped: Rewards Distributor (max_values: None, max_size: None, mode: Measured)
	/// Storage: Rewards InitializeRewards (r:1 w:0)
	/// Proof Skipped: Rewards InitializeRewards (max_values: None, max_size: None, mode: Measured)
	/// Storage: Balances Locks (r:1 w:1)
	/// Proof: Balances Locks (max_values: None, max_size: Some(1299), added: 3774, mode: MaxEncodedLen)
	/// Storage: Balances Freezes (r:1 w:0)
	/// Proof: Balances Freezes (max_values: None, max_size: Some(49), added: 2524, mode: MaxEncodedLen)
	/// Storage: System Account (r:1 w:1)
	/// Proof: System Account (max_values: None, max_size: Some(128), added: 2603, mode: MaxEncodedLen)
	fn claim() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `1016`
		//  Estimated: `4764`
		// Minimum execution time: 32_010_000 picoseconds.
		Weight::from_parts(32_581_000, 0)
			.saturating_add(Weight::from_parts(0, 4764))
			.saturating_add(T::DbWeight::get().reads(5))
			.saturating_add(T::DbWeight::get().writes(3))
	}
}