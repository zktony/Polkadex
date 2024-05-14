// This file is part of Polkadex.
//
// Copyright (c) 2023 Polkadex oü.
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

//! Common traits and its stub implementation.
use frame_support::dispatch::DispatchResult;
use xcm::latest::MultiLocation;
use crate::AssetId;

pub trait CrossChainWithdraw<AccountId> {
    fn parachain_withdraw(
        user: AccountId,
        asset_id: AssetId,
        amount: u128,
        beneficiary: xcm::latest::MultiLocation,
        fee_asset_id: Option<AssetId>,
        fee_amount: Option<u128>,
        id: Vec<u8>
    ) -> DispatchResult;
}

// Stub for CrossChainWithdraw
impl<AccountId> CrossChainWithdraw<AccountId> for () {
    fn parachain_withdraw(
        _user: AccountId,
        _asset_id: AssetId,
        _amount: u128,
        _beneficiary: MultiLocation,
        _fee_asset_id: Option<AssetId>,
        _fee_amount: Option<u128>,
        _id: Vec<u8>
    ) -> DispatchResult {
        Ok(())
    }
}