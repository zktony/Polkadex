use crate::{
	pallet::{Accounts, SnapshotNonce, UserActionsBatches, ValidatorSetId},
	settlement::process_trade,
	snapshot::AccountsMap,
	Call, Config, Pallet,
};
use frame_system::offchain::{SubmitTransaction};
use orderbook_primitives::{
	types::{Trade, UserActions, WithdrawalRequest},
	SnapshotSummary,
};
use parity_scale_codec::{Decode, Encode};
use polkadex_primitives::{ingress::IngressMessages, withdrawal::Withdrawal};
use sp_application_crypto::RuntimeAppPublic;
use sp_core::H256;
use sp_runtime::{offchain::storage::StorageValueRef, SaturatedConversion};
use sp_std::vec::Vec;

pub const WORKER_STATUS: [u8; 28] = *b"offchain-ocex::worker_status";
const ACCOUNTS: [u8; 23] = *b"offchain-ocex::accounts";

impl<T: Config> Pallet<T> {
	pub fn run_on_chain_validation(_block_num: T::BlockNumber) -> Result<(), &'static str> {
		// Check if we are a validator
		if !sp_io::offchain::is_validator() {
			// This is not a validator
			return Ok(())
		}

		let local_keys = T::AuthorityId::all();
		let authorities = Self::validator_set().validators;
		let mut available_keys = authorities
			.into_iter()
			.enumerate()
			.filter_map(move |(_index, authority)| {
				local_keys
					.binary_search(&authority)
					.ok()
					.map(|location| local_keys[location].clone())
			})
			.collect::<Vec<T::AuthorityId>>();
		available_keys.sort();

		if available_keys.is_empty() {
			return Err("No active keys available")
		}

		// Check if another worker is already running or not
		let s_info = StorageValueRef::persistent(&WORKER_STATUS);
		match s_info.get::<bool>().map_err(|_err| "Unable to load worker status")? {
			Some(true) => {
				// Another worker is online, so exit
				return Ok(())
			},
			None => {},
			Some(false) => {},
		}
		s_info.set(&true.encode()); // Set WORKER_STATUS to true
							// Check the next ObMessages to process
		let next_nonce = <SnapshotNonce<T>>::get().saturating_add(1);
		// Load the next ObMessages
		let batch = match <UserActionsBatches<T>>::get(next_nonce) {
			None => return Ok(()),
			Some(batch) => batch,
		};

		// Load the trie to memory
		let s_info = StorageValueRef::persistent(&ACCOUNTS);
		let mut accounts =
			match s_info.get::<AccountsMap>().map_err(|_err| "Unable to get accounts map")? {
				None => AccountsMap::default(),
				Some(acounts) => acounts,
			};

		if accounts.stid >= batch.stid {
			return Err("Invalid stid")
		}

		if accounts.worker_nonce >= batch.worker_nonce {
			return Err("Invalid worker nonce")
		}

		let mut withdrawals = Vec::new();
		// Process Ob messages
		for action in batch.actions {
			match action {
				UserActions::Trade(trades) => Self::trades(trades, &mut accounts)?,
				UserActions::Withdraw(request) => {
					let withdrawal =
						Self::withdraw(request, &mut accounts, batch.stid, batch.worker_nonce)?;
					withdrawals.push(withdrawal);
				},
				UserActions::BlockImport(blk) =>
					Self::import_blk(blk.saturated_into(), &mut accounts)?,
			}
		}
		// Create state hash.
		let state_hash: H256 = H256::from(sp_io::hashing::blake2_256(&accounts.encode()));

		match available_keys.get(0) {
			None => return Err("No active keys found"),
			Some(key) => {
				// Prepare summary
				let summary = SnapshotSummary {
					validator_set_id: <ValidatorSetId<T>>::get(),
					snapshot_id: next_nonce,
					state_hash,
					worker_nonce: batch.worker_nonce,
					state_change_id: batch.stid,
					last_processed_blk: accounts.last_block.saturated_into(),
					withdrawals,
					public: key.clone(),
				};

				let signature = key.sign(&summary.encode()).ok_or("Private key not found")?;

				let call = Call::submit_snapshot { summary, signature };
				SubmitTransaction::<T, Call<T>>::submit_unsigned_transaction(call.into())
					.map_err(|_| "Error sending unsigned txn")?;
			},
		}

		Ok(())
	}

	fn import_blk(blk: T::BlockNumber, state: &mut AccountsMap) -> Result<(), &'static str> {
		if blk <= state.last_block.saturated_into() {
			return Err("BlockOutofSequence")
		}

		let messages = Self::ingress_messages(blk);

		for message in messages {
			// We don't care about any other message
			match message {
				IngressMessages::Deposit(main, asset, amt) => {
					let balances = state
						.balances
						.get_mut(&Decode::decode(&mut &main.encode()[..]).unwrap()) // this conversion will not fail
						.ok_or("Main account not found")?;

					balances
						.entry(asset)
						.and_modify(|total| {
							*total = total.saturating_add(amt);
						})
						.or_insert(amt);
				},
				_ => {},
			}
		}

		state.last_block = blk.saturated_into();

		Ok(())
	}

	fn trades(trades: Vec<Trade>, state: &mut AccountsMap) -> Result<(), &'static str> {
		for trade in trades {
			let config = Self::trading_pairs(trade.maker.pair.base, trade.maker.pair.quote)
				.ok_or("TradingPairNotFound")?;
			process_trade(state, trade, config)?
		}

		Ok(())
	}

	fn withdraw(
		request: WithdrawalRequest<T::AccountId>,
		state: &mut AccountsMap,
		stid: u64,
		worker_nonce: u64,
	) -> Result<Withdrawal<T::AccountId>, &'static str> {
		let amount = request.amount().map_err(|_| "decimal conversion error")?;
		let account_info = <Accounts<T>>::get(&request.main).ok_or("Main account not found")?;

		if !account_info.proxies.contains(&request.proxy) {
			// TODO: Check Race condition
			return Err("Proxy not found")
		}
		if !request.verify() {
			return Err("SignatureVerificationFailed")
		}

		let balances = state
			.balances
			.get_mut(&Decode::decode(&mut &request.main.encode()[..]).unwrap()) // This conversion will not fail
			.ok_or("Main account not found")?;

		let total = balances.get_mut(&request.asset()).ok_or("Asset Not found")?;

		if *total < amount {
			return Err("Insufficient Balance")
		}

		*total = total.saturating_sub(amount);

		let withdrawal =
			request.convert(stid, worker_nonce).map_err(|_| "Withdrawal conversion error")?;

		Ok(withdrawal)
	}
}
