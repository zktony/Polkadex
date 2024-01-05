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

use crate::{
	pallet::{ActiveNetworks, Authorities, OutgoingMessages, SignedOutgoingNonce, ValidatorSetId},
	Config, Pallet,
};
use frame_system::pallet_prelude::BlockNumberFor;
use parity_scale_codec::Encode;
use sp_application_crypto::RuntimeAppPublic;
use thea_primitives::Network;

impl<T: Config> Pallet<T> {
	/// Starts the offchain worker instance that checks for finalized next incoming messages
	/// for both solochain and parachain, signs it and submits to aggregator
	pub fn run_thea_validation(_blk: BlockNumberFor<T>) -> Result<(), &'static str> {
		if !sp_io::offchain::is_validator() {
			return Ok(())
		}

		let id = <ValidatorSetId<T>>::get();
		let authorities = <Authorities<T>>::get(id).to_vec();

		let local_keys = T::TheaId::all();

		let mut available_keys = authorities
			.iter()
			.enumerate()
			.filter_map(move |(auth_index, authority)| {
				local_keys
					.binary_search(authority)
					.ok()
					.map(|location| (auth_index, local_keys[location].clone()))
			})
			.collect::<Vec<(usize, T::TheaId)>>();
		available_keys.sort();

		let (auth_index, signer) = available_keys.first().ok_or("No active keys available")?;

		let active_networks = <ActiveNetworks<T>>::get();
		log::debug!(target:"thea","List of active networks: {:?}",active_networks);

		let mut signed_messages: Vec<(Network, u64, T::Signature)> = Vec::new();
		// 2. Check for new nonce to process for all networks
		for network in active_networks {
			// Sign message for each network
			let next_outgoing_nonce = <SignedOutgoingNonce<T>>::get(network).saturating_add(1);
			let message = match <OutgoingMessages<T>>::get(network, next_outgoing_nonce) {
				None => continue,
				Some(msg) => msg,
			};
			let msg_hash = sp_io::hashing::sha2_256(message.encode().as_slice());
			// Note: this is a double hash signing
			let signature = signer.sign(&msg_hash).ok_or("Expected signature to be returned")?;
			signed_messages.push((network, next_outgoing_nonce, signature.into()));
			//TODO: Later we should batch these signatures into a single extrinsic ( not in this
			// release) submit on-chain
		}

		log::debug!(target:"thea","Thea offchain worker exiting..");
		Ok(())
	}
}
