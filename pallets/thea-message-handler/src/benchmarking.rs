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
#[cfg(test)]
use crate::Pallet as TheaMH;
use frame_benchmarking::benchmarks;
use frame_system::RawOrigin;
use parity_scale_codec::Decode;

const KEY: [u8; 33] = [
	2, 10, 16, 145, 52, 31, 229, 102, 75, 250, 23, 130, 213, 224, 71, 121, 104, 144, 104, 201, 22,
	176, 76, 179, 101, 236, 49, 83, 117, 86, 132, 217, 161,
];
use sp_core::H160;

fn generate_deposit_payload<T: Config>() -> Vec<Deposit<T::AccountId>> {
	sp_std::vec![Deposit {
		id: H160::zero(),
		recipient: T::AccountId::decode(&mut &[0u8; 32][..]).unwrap(),
		asset_id: AssetId::Asset(0),
		amount: 0,
		extra: ExtraData::None,
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
		let message = Message { block_no: 11, nonce: 1, data: generate_deposit_payload::<T>().encode(),
			network: 1, payload_type: PayloadType::L1Deposit };
		let signature: T::Signature = sp_core::ecdsa::Signature::default().into();
		let signed_message = SignedMessage::new(message,0,0,signature.into());
	}: _(RawOrigin::None, signed_message)
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

	send_thea_message {
		let public = <T as Config>::TheaId::decode(&mut KEY.as_ref()).unwrap();
		let authorities = BoundedVec::truncate_from(vec![public]);
		let validator_set_id = 1;
		<ValidatorSetId<T>>::put(validator_set_id);
		<Authorities<T>>::insert(validator_set_id, authorities);
		let message = vec![1u8;10];
	}: _(RawOrigin::Root, message)
}

#[cfg(test)]
use frame_benchmarking::impl_benchmark_test_suite;
use polkadex_primitives::AssetId;
use thea_primitives::extras::ExtraData;
use thea_primitives::types::Deposit;

#[cfg(test)]
impl_benchmark_test_suite!(TheaMH, crate::mock::new_test_ext(), crate::mock::Test);
