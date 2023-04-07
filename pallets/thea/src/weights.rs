
//! Autogenerated weights for `thea`
//!
//! THIS FILE WAS AUTO-GENERATED USING THE SUBSTRATE BENCHMARK CLI VERSION 4.0.0-dev
//! DATE: 2023-03-31, STEPS: `100`, REPEAT: 200, LOW RANGE: `[]`, HIGH RANGE: `[]`
//! HOSTNAME: `Ubuntu-2204-jammy-amd64-base`, CPU: `Intel(R) Core(TM) i7-7700 CPU @ 3.60GHz`
//! EXECUTION: None, WASM-EXECUTION: Compiled, CHAIN: None, DB CACHE: 1024

// Executed Command:
// ./polkadex-node
// benchmark
// pallet
// --pallet
// thea
// --steps
// 100
// --repeat
// 200
// --extrinsic
// *
// --output
// thea_weights.rs

#![cfg_attr(rustfmt, rustfmt_skip)]
#![allow(unused_parens)]
#![allow(unused_imports)]

use frame_support::{traits::Get, weights::Weight};
use sp_std::marker::PhantomData;

/// Weight functions for `thea`.
pub struct TheaWeightInfo<T>(PhantomData<T>);
impl<T: frame_system::Config> crate::WeightInfo for TheaWeightInfo<T> {
	// Storage: Thea DepositNonce (r:1 w:1)
	// Storage: AssetHandler TheaAssets (r:1 w:0)
	// Storage: Thea RelayersBLSKeyVector (r:1 w:0)
	// Storage: Thea ApprovedDeposits (r:1 w:1)
	// Storage: Thea AccountWithPendingDeposits (r:1 w:1)
	fn approve_deposit() -> Weight {
		(735_235_000 as Weight)
			.saturating_add(T::DbWeight::get().reads(5 as Weight))
			.saturating_add(T::DbWeight::get().writes(3 as Weight))
	}
	// Storage: Thea ApprovedDeposits (r:1 w:1)
	// Storage: AssetHandler TheaAssets (r:1 w:0)
	// Storage: Assets Asset (r:1 w:1)
	// Storage: Assets Account (r:1 w:1)
	// Storage: System Account (r:1 w:1)
	// Storage: Thea AccountWithPendingDeposits (r:1 w:1)
	/// The range of component `a` is `[0, 255]`.
	/// The range of component `m` is `[100, 4294967295]`.
	fn claim_deposit(_a: u32, _m: u32, ) -> Weight {
		(627_490_000 as Weight)
			.saturating_add(T::DbWeight::get().reads(6 as Weight))
			.saturating_add(T::DbWeight::get().writes(5 as Weight))
	}
	// Storage: Thea WithdrawalNonces (r:1 w:0)
	// Storage: Thea RelayersBLSKeyVector (r:1 w:0)
	// Storage: Thea ReadyWithdrawls (r:1 w:0)
	fn batch_withdrawal_complete() -> Weight {
		(726_534_000 as Weight)
			.saturating_add(T::DbWeight::get().reads(3 as Weight))
	}
	// Storage: AssetHandler TheaAssets (r:1 w:0)
	// Storage: Thea TheaKeyRotation (r:1 w:0)
	// Storage: Thea WithdrawalNonces (r:1 w:1)
	// Storage: Thea PendingWithdrawals (r:1 w:1)
	// Storage: Thea WithdrawalFees (r:1 w:0)
	// Storage: Assets Asset (r:1 w:1)
	// Storage: Assets Account (r:1 w:1)
	// Storage: Thea ReadyWithdrawls (r:0 w:1)
	fn withdraw() -> Weight {
		(48_057_000 as Weight)
			.saturating_add(T::DbWeight::get().reads(7 as Weight))
			.saturating_add(T::DbWeight::get().writes(5 as Weight))
	}
	// Storage: Thea WithdrawalFees (r:0 w:1)
	fn set_withdrawal_fee() -> Weight {
		(12_180_000 as Weight)
			.saturating_add(T::DbWeight::get().writes(1 as Weight))
	}
	// Storage: Thea ForeignChainAckTxns (r:1 w:1)
	// Storage: Thea RelayersBLSKeyVector (r:1 w:1)
	// Storage: Thea AuthorityListVector (r:1 w:1)
	// Storage: Thea QueuedRelayersBLSKeyVector (r:1 w:0)
	// Storage: Thea QueuedAuthorityListVector (r:1 w:0)
	// Storage: Thea QueuedTheaPublicKey (r:1 w:0)
	// Storage: Thea TheaSessionId (r:1 w:1)
	// Storage: Thea IngressMessages (r:1 w:1)
	// Storage: TheaStaking CurrentIndex (r:1 w:0)
	// Storage: TheaStaking EraRewardPoints (r:1 w:1)
	// Storage: Thea TheaPublicKey (r:0 w:1)
	// Storage: Thea TheaKeyRotation (r:0 w:1)
	fn thea_key_rotation_complete() -> Weight {
		(749_428_000 as Weight)
			.saturating_add(T::DbWeight::get().reads(10 as Weight))
			.saturating_add(T::DbWeight::get().writes(8 as Weight))
	}
	// Storage: Thea TheaPublicKey (r:1 w:1)
	// Storage: Thea RelayersBLSKeyVector (r:1 w:0)
	// Storage: Thea AuthorityListVector (r:1 w:0)
	// Storage: Thea TheaSessionId (r:1 w:1)
	// Storage: TheaStaking CurrentIndex (r:1 w:0)
	// Storage: TheaStaking EraRewardPoints (r:1 w:1)
	// Storage: Thea TheaKeyRotation (r:0 w:1)
	fn set_thea_key_complete() -> Weight {
		(736_381_000 as Weight)
			.saturating_add(T::DbWeight::get().reads(6 as Weight))
			.saturating_add(T::DbWeight::get().writes(4 as Weight))
	}
	// Storage: Thea QueuedQueuedTheaPublicKey (r:1 w:1)
	// Storage: TheaStaking QueuedRelayers (r:1 w:0)
	fn thea_queued_queued_public_key() -> Weight {
		(717_719_000 as Weight)
			.saturating_add(T::DbWeight::get().reads(2 as Weight))
			.saturating_add(T::DbWeight::get().writes(1 as Weight))
	}
	// Storage: Thea TheaPublicKey (r:1 w:0)
	// Storage: Thea QueuedTheaPublicKey (r:1 w:0)
	// Storage: Thea QueuedQueuedTheaPublicKey (r:1 w:0)
	// Storage: Thea QueuedAuthorityListVector (r:0 w:1)
	// Storage: Thea RelayersBLSKeyVector (r:0 w:1)
	// Storage: Thea QueuedRelayersBLSKeyVector (r:0 w:1)
	// Storage: Thea AuthorityListVector (r:0 w:1)
	// Storage: Thea TheaSessionId (r:0 w:1)
	fn thea_relayers_reset_rotation() -> Weight {
		(12_385_000 as Weight)
			.saturating_add(T::DbWeight::get().reads(3 as Weight))
			.saturating_add(T::DbWeight::get().writes(5 as Weight))
	}
}
