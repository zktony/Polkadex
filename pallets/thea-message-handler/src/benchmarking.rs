// This file is part of Polkadex.
//
// Copyright (c) 2022-2023 Polkadex oü.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//! Benchmarking setup for pallet thea-message-handler
#![cfg(feature = "runtime-benchmarks")]

use super::*;
use frame_benchmarking::benchmarks;
use frame_system::RawOrigin;
use parity_scale_codec::Decode;

const KEY: [u8; 33] = [
	2, 10, 16, 145, 52, 31, 229, 102, 75, 250, 23, 130, 213, 224, 71, 121, 104, 144, 104, 201, 22,
	176, 76, 179, 101, 236, 49, 83, 117, 86, 132, 217, 161,
];

const SIG: [u8; 65] = [
	246, 101, 246, 156, 149, 156, 74, 60, 188, 84, 236, 77, 232, 165, 102, 241, 137, 124, 100, 143,
	230, 195, 58, 177, 5, 110, 241, 31, 205, 215, 173, 147, 127, 75, 174, 69, 64, 193, 140, 26, 76,
	97, 172, 196, 168, 187, 140, 17, 202, 250, 175, 232, 160, 108, 251, 114, 152, 227, 249, 255,
	186, 113, 211, 53, 0,
];

fn generate_deposit_payload<T: Config>() -> Vec<Deposit<T::AccountId>> {
	sp_std::vec![Deposit {
		id: H256::zero().0.to_vec(),
		recipient: T::AccountId::decode(&mut &[0u8; 32][..]).unwrap(),
		asset_id: 0,
		amount: 0,
		extra: Vec::new(),
	}]
}

benchmarks! {
	insert_authorities {
		let b in 0 .. u32::MAX;
		let public = <T as Config>::TheaId::decode(&mut KEY.as_ref()).unwrap();
		let authorities = BoundedVec::truncate_from(vec![public]);
		let b = b as u64;
	}: _(RawOrigin::Root, authorities.clone(), b)
	verify {
		assert_eq!(<Authorities<T>>::get(b), authorities);
		assert_eq!(<ValidatorSetId<T>>::get(), b);
	}

	incoming_message {
		let bitmap = vec!(u128::MAX);
		let public = <T as Config>::TheaId::decode(&mut KEY.as_ref()).unwrap();
		<Authorities<T>>::insert(0, BoundedVec::truncate_from(vec![public]));
		<ValidatorSetId<T>>::put(0);
		let message = Message { block_no: 11, nonce: 1, data: generate_deposit_payload::<T>().encode(),
			network: 1, is_key_change: false, validator_set_id: 0 };
	}: _(RawOrigin::None, message, vec!((0, <T as crate::Config>::Signature::decode(&mut SIG.as_ref()).unwrap())))
	verify {
		assert_eq!(1, <IncomingNonce<T>>::get());
	}

	update_incoming_nonce {
		let b in 1 .. u32::MAX;
		let b = b as u64;
	}: _(RawOrigin::Root, b)
	verify {
		assert_eq!(b, <IncomingNonce<T>>::get());
	}

	update_outgoing_nonce {
		let b in 1 .. u32::MAX;
		let b = b as u64;
	}: _(RawOrigin::Root, b)
	verify {
		assert_eq!(b, <OutgoingNonce<T>>::get());
	}
}

#[cfg(test)]
use frame_benchmarking::impl_benchmark_test_suite;
use sp_core::H256;
use thea_primitives::types::Deposit;

#[cfg(test)]
impl_benchmark_test_suite!(TheaMH, crate::mock::new_test_ext(), crate::mock::Test);
