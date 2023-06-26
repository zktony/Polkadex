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

use super::{fixtures::*, *};
use frame_benchmarking::benchmarks;
use frame_system::RawOrigin;
use parity_scale_codec::Decode;

// Check if last event generated by pallet is the one we're expecting
fn assert_last_event<T: Config>(generic_event: <T as Config>::RuntimeEvent) {
	frame_system::Pallet::<T>::assert_last_event(generic_event.into());
}

lazy_static::lazy_static! {
	static ref M: Message = Message {
		block_no: u64::MAX,
		nonce: 1,
		data: [255u8; 576].into(), //10 MB
		network: 0u8,
		is_key_change: false,
		validator_set_id: 0,
		validator_set_len: 1,
	};
}

benchmarks! {
	insert_authorities {
		let b in 0 .. u32::MAX;
		let authorities = produce_authorities::<T>();
		let b = b as u64;
	}: _(RawOrigin::Root, authorities.clone(), b)
	verify {
		assert_eq!(<Authorities<T>>::get(b), authorities);
		assert_eq!(<ValidatorSetId<T>>::get(), b);
	}

	incoming_message {
		let bitmap = vec!(u128::MAX);
		let authorities = produce_authorities::<T>();
		<ValidatorSetId<T>>::put(0);
	}: _(RawOrigin::None, bitmap, M.clone(), <T as crate::Config>::Signature::decode(&mut SIG.as_ref()).unwrap())
	verify {
		assert_last_event::<T>(Event::TheaMessageExecuted { message: M.clone() }.into());
		assert_eq!(1, <IncomingNonce<T>>::get());
		assert_eq!(M.clone(), <IncomingMessages<T>>::get(1).unwrap());
	}

	update_incoming_nonce {
		let b in 1 .. u32::MAX;
		let b = b as u64;
	}: _(RawOrigin::Root, b)
	verify {
		assert_eq!(b, <IncomingNonce<T>>::get());
	}
}

#[cfg(test)]
use frame_benchmarking::impl_benchmark_test_suite;

#[cfg(test)]
impl_benchmark_test_suite!(TheaMH, crate::mock::new_test_ext(), crate::mock::Test);
