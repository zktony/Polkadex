// Copyright (C) Parity Technologies (UK) Ltd.
// This file is part of Polkadot.

// Polkadot is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Polkadot is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Polkadot.  If not, see <http://www.gnu.org/licenses/>.

//! Parachain runtime mock.

use codec::{Decode, Encode};
use core::marker::PhantomData;
use frame_support::traits::AsEnsureOriginWithArg;
use frame_support::{
	construct_runtime, parameter_types,
	traits::{EnsureOrigin, EnsureOriginWithArg, Everything, EverythingBut, Nothing},
	weights::{constants::WEIGHT_REF_TIME_PER_SECOND, Weight},
	PalletId,
};
use frame_system::{EnsureRoot, EnsureSigned};
use orml_traits::location::AbsoluteReserveProvider;
use orml_traits::parameter_type_with_key;
use pallet_xcm::XcmPassthrough;
use polkadot_core_primitives::BlockNumber as RelayBlockNumber;
use polkadot_parachain_primitives::primitives::{
	DmpMessageHandler, Id as ParaId, Sibling, XcmpMessageFormat, XcmpMessageHandler,
};
use sp_core::{ConstU32, H256};
use sp_runtime::traits::Convert;
use sp_runtime::{
	traits::{Get, Hash, IdentityLookup},
	AccountId32, Perbill, SaturatedConversion,
};
use sp_std::prelude::*;
use thea::ecdsa::AuthorityId;
use thea::ecdsa::AuthoritySignature;
use xcm::{latest::prelude::*, VersionedXcm};
use xcm_builder::{
	Account32Hash, AccountId32Aliases, AllowUnpaidExecutionFrom, EnsureXcmOrigin,
	FixedRateOfFungible, FixedWeightBounds, NativeAsset, ParentIsPreset,
	SiblingParachainConvertsVia, SignedAccountId32AsNative, SignedToAccountId32,
	SovereignSignedViaLocation, TakeRevenue,
};
use xcm_executor::traits::WeightTrader;
use xcm_executor::{traits::ConvertLocation, Config, XcmExecutor};
use xcm_helper::{AssetIdConverter, WhitelistedTokenHandler};

pub type SovereignAccountOf = (
	SiblingParachainConvertsVia<Sibling, AccountId>,
	AccountId32Aliases<RelayNetwork, AccountId>,
	ParentIsPreset<AccountId>,
);

pub type AccountId = AccountId32;
pub type Balance = u128;

parameter_types! {
	pub const BlockHashCount: u64 = 250;
}

pub mod currency {
	pub type Balance = u128;
	pub const PDEX: Balance = 1_000_000_000_000;
	pub const DOLLARS: Balance = PDEX; // 1_000_000_000_000
	pub const CENTS: Balance = DOLLARS / 100; // 10_000_000_000
}

impl frame_system::Config for Runtime {
	type RuntimeOrigin = RuntimeOrigin;
	type RuntimeCall = RuntimeCall;
	type Nonce = u64;
	type Hash = H256;
	type Hashing = ::sp_runtime::traits::BlakeTwo256;
	type AccountId = AccountId;
	type Lookup = IdentityLookup<Self::AccountId>;
	type Block = Block;
	type RuntimeEvent = RuntimeEvent;
	type BlockHashCount = BlockHashCount;
	type BlockWeights = ();
	type BlockLength = ();
	type Version = ();
	type PalletInfo = PalletInfo;
	type AccountData = pallet_balances::AccountData<Balance>;
	type OnNewAccount = ();
	type OnKilledAccount = ();
	type DbWeight = ();
	type BaseCallFilter = Everything;
	type SystemWeightInfo = ();
	type SS58Prefix = ();
	type OnSetCode = ();
	type MaxConsumers = ConstU32<16>;
}

parameter_types! {
	pub ExistentialDeposit: Balance = 1;
	pub const MaxLocks: u32 = 50;
	pub const MaxReserves: u32 = 50;
}

impl pallet_balances::Config for Runtime {
	type MaxLocks = MaxLocks;
	type Balance = Balance;
	type RuntimeEvent = RuntimeEvent;
	type DustRemoval = ();
	type ExistentialDeposit = ExistentialDeposit;
	type AccountStore = System;
	type WeightInfo = ();
	type MaxReserves = MaxReserves;
	type ReserveIdentifier = [u8; 8];
	type RuntimeHoldReason = RuntimeHoldReason;
	type FreezeIdentifier = ();
	type MaxHolds = ConstU32<0>;
	type MaxFreezes = ConstU32<0>;
}

#[cfg(feature = "runtime-benchmarks")]
pub struct UniquesHelper;
#[cfg(feature = "runtime-benchmarks")]
impl pallet_uniques::BenchmarkHelper<MultiLocation, AssetInstance> for UniquesHelper {
	fn collection(i: u16) -> MultiLocation {
		GeneralIndex(i as u128).into()
	}
	fn item(i: u16) -> AssetInstance {
		AssetInstance::Index(i as u128)
	}
}

impl pallet_uniques::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type CollectionId = MultiLocation;
	type ItemId = AssetInstance;
	type Currency = Balances;
	type CreateOrigin = ForeignCreators;
	type ForceOrigin = frame_system::EnsureRoot<AccountId>;
	type CollectionDeposit = frame_support::traits::ConstU128<1_000>;
	type ItemDeposit = frame_support::traits::ConstU128<1_000>;
	type MetadataDepositBase = frame_support::traits::ConstU128<1_000>;
	type AttributeDepositBase = frame_support::traits::ConstU128<1_000>;
	type DepositPerByte = frame_support::traits::ConstU128<1>;
	type StringLimit = ConstU32<64>;
	type KeyLimit = ConstU32<64>;
	type ValueLimit = ConstU32<128>;
	type Locker = ();
	type WeightInfo = ();
	#[cfg(feature = "runtime-benchmarks")]
	type Helper = UniquesHelper;
}

// `EnsureOriginWithArg` impl for `CreateOrigin` which allows only XCM origins
// which are locations containing the class location.
pub struct ForeignCreators;
impl EnsureOriginWithArg<RuntimeOrigin, MultiLocation> for ForeignCreators {
	type Success = AccountId;

	fn try_origin(
		o: RuntimeOrigin,
		a: &MultiLocation,
	) -> sp_std::result::Result<Self::Success, RuntimeOrigin> {
		let origin_location = pallet_xcm::EnsureXcm::<Everything>::try_origin(o.clone())?;
		if !a.starts_with(&origin_location) {
			return Err(o);
		}
		SovereignAccountOf::convert_location(&origin_location).ok_or(o)
	}

	#[cfg(feature = "runtime-benchmarks")]
	fn try_successful_origin(a: &MultiLocation) -> Result<RuntimeOrigin, ()> {
		Ok(pallet_xcm::Origin::Xcm(a.clone()).into())
	}
}

parameter_types! {
	pub const ReservedXcmpWeight: Weight = Weight::from_parts(WEIGHT_REF_TIME_PER_SECOND.saturating_div(4), 0);
	pub const ReservedDmpWeight: Weight = Weight::from_parts(WEIGHT_REF_TIME_PER_SECOND.saturating_div(4), 0);
}

parameter_types! {
	pub const KsmLocation: MultiLocation = MultiLocation::parent();
	pub const RelayNetwork: NetworkId = NetworkId::Kusama;
	pub UniversalLocation: InteriorMultiLocation = Parachain(MsgQueue::parachain_id().into()).into();
}

pub type LocationToAccountId = (
	ParentIsPreset<AccountId>,
	SiblingParachainConvertsVia<Sibling, AccountId>,
	AccountId32Aliases<RelayNetwork, AccountId>,
	Account32Hash<(), AccountId>,
);

pub type XcmOriginToCallOrigin = (
	SovereignSignedViaLocation<LocationToAccountId, RuntimeOrigin>,
	SignedAccountId32AsNative<RelayNetwork, RuntimeOrigin>,
	XcmPassthrough<RuntimeOrigin>,
);

parameter_types! {
	pub const UnitWeightCost: Weight = Weight::from_parts(1, 1);
	pub KsmPerSecondPerByte: (AssetId, u128, u128) = (Concrete(Parent.into()), 1, 1);
	pub const MaxInstructions: u32 = 100;
	pub const MaxAssetsIntoHolding: u32 = 64;
	pub ForeignPrefix: MultiLocation = (Parent,).into();
	pub const RelayLocation: MultiLocation = MultiLocation::parent();
	pub PdexLocation: MultiLocation = Here.into();
}

// Can be used later
// pub type LocalAssetTransactor = CurrencyAdapter<
// 	// Use this currency:
// 	Balances,
// 	// Use this currency when it is a fungible asset matching the given location or name:
// 	IsConcrete<RelayLocation>,
// 	// Do a simple punn to convert an AccountId32 MultiLocation into a native chain account ID:
// 	LocationToAccountId,
// 	// Our chain's account ID type (we can't get away without mentioning it explicitly):
// 	AccountId,
// 	// We don't track any teleports.
// 	(),
// >;

pub type XcmRouter = super::ParachainXcmRouter<MsgQueue>;
pub type Barrier = AllowUnpaidExecutionFrom<Everything>;

parameter_types! {
	pub NftCollectionOne: MultiAssetFilter
		= Wild(AllOf { fun: WildNonFungible, id: Concrete((Parent, GeneralIndex(1)).into()) });
	pub NftCollectionOneForRelay: (MultiAssetFilter, MultiLocation)
		= (NftCollectionOne::get(), (Parent,).into());
}
pub type TrustedTeleporters = xcm_builder::Case<NftCollectionOneForRelay>;
pub type TrustedReserves = EverythingBut<xcm_builder::Case<NftCollectionOneForRelay>>;

use smallvec::smallvec;

pub struct WeightToFee;
impl WeightToFeePolynomial for WeightToFee {
	type Balance = Balance;
	fn polynomial() -> WeightToFeeCoefficients<Self::Balance> {
		// Extrinsic base weight (smallest non-zero weight) is mapped to 1/10 CENT:
		let p = CENTS;
		let q = 10 * Balance::from(ExtrinsicBaseWeight::get().ref_time());
		smallvec![WeightToFeeCoefficient {
			degree: 1,
			negative: false,
			coeff_frac: Perbill::from_rational(p % q, q),
			coeff_integer: p / q,
		}]
	}
}

pub struct XcmConfig;
impl Config for XcmConfig {
	type RuntimeCall = RuntimeCall;
	type XcmSender = XcmRouter;
	type AssetTransactor = XcmHelper;
	type OriginConverter = XcmOriginToCallOrigin;
	type IsReserve = (NativeAsset, TrustedReserves);
	type IsTeleporter = TrustedTeleporters;
	type UniversalLocation = UniversalLocation;
	type Barrier = Barrier;
	type Weigher = FixedWeightBounds<UnitWeightCost, RuntimeCall, MaxInstructions>;
	type Trader = (
		// If the XCM message is paying the fees in PDEX ( the native ) then
		// it will go to the author of the block as rewards
		//UsingComponents<WeightToFee, PdexLocation, AccountId, Balances, ToAuthor<Runtime>>,
		FixedRateOfFungible<KsmPerSecondPerByte, ()>,
		ForeignAssetFeeHandler<
			//TODO: Should we go for FixedRateOfForeignAsset
			WeightToFee,
			RevenueCollector,
			XcmHelper,
			XcmHelper,
		>,
	);
	type ResponseHandler = ();
	type AssetTrap = ();
	type AssetLocker = PolkadotXcm;
	type AssetExchanger = ();
	type AssetClaims = ();
	type SubscriptionService = ();
	type PalletInstancesInfo = ();
	type FeeManager = ();
	type MaxAssetsIntoHolding = MaxAssetsIntoHolding;
	type MessageExporter = ();
	type UniversalAliases = Nothing;
	type CallDispatcher = RuntimeCall;
	type SafeCallFilter = Everything;
	type Aliasers = Nothing;
}

#[frame_support::pallet]
#[allow(unused_imports)]
pub mod mock_msg_queue {
	use super::*;
	use frame_support::pallet_prelude::*;

	#[pallet::config]
	pub trait Config: frame_system::Config {
		type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
		type XcmExecutor: ExecuteXcm<Self::RuntimeCall>;
	}

	// #[pallet::call]
	impl<T: Config> Pallet<T> {}

	#[pallet::pallet]
	#[pallet::without_storage_info]
	pub struct Pallet<T>(_);

	#[pallet::storage]
	#[pallet::getter(fn parachain_id)]
	pub(super) type ParachainId<T: Config> = StorageValue<_, ParaId, ValueQuery>;

	#[pallet::storage]
	#[pallet::getter(fn received_dmp)]
	/// A queue of received DMP messages
	pub(super) type ReceivedDmp<T: Config> = StorageValue<_, Vec<Xcm<T::RuntimeCall>>, ValueQuery>;

	impl<T: Config> Get<ParaId> for Pallet<T> {
		fn get() -> ParaId {
			Self::parachain_id()
		}
	}

	pub type MessageId = [u8; 32];

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		// XCMP
		/// Some XCM was executed OK.
		Success(Option<T::Hash>),
		/// Some XCM failed.
		Fail(Option<T::Hash>, XcmError),
		/// Bad XCM version used.
		BadVersion(Option<T::Hash>),
		/// Bad XCM format used.
		BadFormat(Option<T::Hash>),

		// DMP
		/// Downward message is invalid XCM.
		InvalidFormat(MessageId),
		/// Downward message is unsupported version of XCM.
		UnsupportedVersion(MessageId),
		/// Downward message executed with the given outcome.
		ExecutedDownward(MessageId, Outcome),
	}

	impl<T: Config> Pallet<T> {
		pub fn set_para_id(para_id: ParaId) {
			ParachainId::<T>::put(para_id);
		}

		fn handle_xcmp_message(
			sender: ParaId,
			_sent_at: RelayBlockNumber,
			xcm: VersionedXcm<T::RuntimeCall>,
			max_weight: Weight,
		) -> Result<Weight, XcmError> {
			let hash = Encode::using_encoded(&xcm, T::Hashing::hash);
			let message_hash = Encode::using_encoded(&xcm, sp_io::hashing::blake2_256);
			let (result, event) = match Xcm::<T::RuntimeCall>::try_from(xcm) {
				Ok(xcm) => {
					let location = (Parent, Parachain(sender.into()));
					match T::XcmExecutor::execute_xcm(location, xcm, message_hash, max_weight) {
						Outcome::Error(e) => (Err(e), Event::Fail(Some(hash), e)),
						Outcome::Complete(w) => (Ok(w), Event::Success(Some(hash))),
						// As far as the caller is concerned, this was dispatched without error, so
						// we just report the weight used.
						Outcome::Incomplete(w, e) => (Ok(w), Event::Fail(Some(hash), e)),
					}
				},
				Err(()) => (Err(XcmError::UnhandledXcmVersion), Event::BadVersion(Some(hash))),
			};
			Self::deposit_event(event);
			result
		}
	}

	impl<T: Config> XcmpMessageHandler for Pallet<T> {
		fn handle_xcmp_messages<'a, I: Iterator<Item = (ParaId, RelayBlockNumber, &'a [u8])>>(
			iter: I,
			max_weight: Weight,
		) -> Weight {
			for (sender, sent_at, data) in iter {
				let mut data_ref = data;
				let _ = XcmpMessageFormat::decode(&mut data_ref)
					.expect("Simulator encodes with versioned xcm format; qed");

				let mut remaining_fragments = data_ref;
				while !remaining_fragments.is_empty() {
					if let Ok(xcm) =
						VersionedXcm::<T::RuntimeCall>::decode(&mut remaining_fragments)
					{
						let _ = Self::handle_xcmp_message(sender, sent_at, xcm, max_weight);
					} else {
						debug_assert!(false, "Invalid incoming XCMP message data");
					}
				}
			}
			max_weight
		}
	}

	impl<T: Config> DmpMessageHandler for Pallet<T> {
		fn handle_dmp_messages(
			iter: impl Iterator<Item = (RelayBlockNumber, Vec<u8>)>,
			limit: Weight,
		) -> Weight {
			for (_sent_at, data) in iter {
				let id = sp_io::hashing::blake2_256(&data[..]);
				let maybe_versioned = VersionedXcm::<T::RuntimeCall>::decode(&mut &data[..]);
				match maybe_versioned {
					Err(_) => {
						Self::deposit_event(Event::InvalidFormat(id));
					},
					Ok(versioned) => match Xcm::try_from(versioned) {
						Err(()) => Self::deposit_event(Event::UnsupportedVersion(id)),
						Ok(x) => {
							let outcome = T::XcmExecutor::execute_xcm(Parent, x.clone(), id, limit);
							<ReceivedDmp<T>>::append(x);
							Self::deposit_event(Event::ExecutedDownward(id, outcome));
						},
					},
				}
			}
			limit
		}
	}
}

impl mock_msg_queue::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type XcmExecutor = XcmExecutor<XcmConfig>;
}

pub type LocalOriginToLocation = SignedToAccountId32<RuntimeOrigin, AccountId, RelayNetwork>;

#[cfg(feature = "runtime-benchmarks")]
parameter_types! {
	pub ReachableDest: Option<MultiLocation> = Some(Parent.into());
}

parameter_types! {
	pub RelayTokenForRelay: (MultiLocation, MultiAssetFilter) = (Parent.into(), Wild(AllOf { id: Concrete(Parent.into()), fun: WildFungible }));
}

impl pallet_xcm::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type SendXcmOrigin = EnsureXcmOrigin<RuntimeOrigin, LocalOriginToLocation>;
	type XcmRouter = XcmRouter;
	type ExecuteXcmOrigin = EnsureXcmOrigin<RuntimeOrigin, LocalOriginToLocation>;
	type XcmExecuteFilter = Everything;
	type XcmExecutor = XcmExecutor<XcmConfig>;
	type XcmTeleportFilter = Nothing;
	type XcmReserveTransferFilter = Everything;
	type Weigher = FixedWeightBounds<UnitWeightCost, RuntimeCall, MaxInstructions>;
	type UniversalLocation = UniversalLocation;
	type RuntimeOrigin = RuntimeOrigin;
	type RuntimeCall = RuntimeCall;
	const VERSION_DISCOVERY_QUEUE_SIZE: u32 = 100;
	type AdvertisedXcmVersion = pallet_xcm::CurrentXcmVersion;
	type Currency = Balances;
	type CurrencyMatcher = ();
	type TrustedLockers = ();
	type SovereignAccountOf = ();
	type MaxLockers = ConstU32<8>;
	type MaxRemoteLockConsumers = ConstU32<0>;
	type RemoteLockConsumerIdentifier = ();
	type WeightInfo = pallet_xcm::TestWeightInfo;
	#[cfg(feature = "runtime-benchmarks")]
	type ReachableDest = ReachableDest;
	type AdminOrigin = EnsureRoot<AccountId>;
}

type Block = frame_system::mocking::MockBlock<Runtime>;

parameter_types! {
	pub const AssetDeposit: Balance = 100 * currency::DOLLARS;
	pub const ApprovalDeposit: Balance = currency::DOLLARS;
	pub const StringLimit: u32 = 50;
	pub const MetadataDepositBase: Balance = 10 * currency::DOLLARS;
	pub const MetadataDepositPerByte: Balance = currency::DOLLARS;
}
impl pallet_assets::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type Balance = Balance;
	type RemoveItemsLimit = ConstU32<1000>;
	type AssetId = u128;
	type AssetIdParameter = codec::Compact<u128>;
	type Currency = Balances;
	type CreateOrigin = AsEnsureOriginWithArg<EnsureSigned<AccountId>>;
	type ForceOrigin = EnsureRoot<AccountId>;
	type AssetDeposit = AssetDeposit;
	type AssetAccountDeposit = AssetDeposit;
	type MetadataDepositBase = MetadataDepositBase;
	type MetadataDepositPerByte = MetadataDepositPerByte;
	type ApprovalDeposit = ApprovalDeposit;
	type StringLimit = StringLimit;
	type Freezer = ();
	type Extra = ();
	type CallbackHandle = ();
	type WeightInfo = ();
	#[cfg(feature = "runtime-benchmarks")]
	type BenchmarkHelper = AssetU128;
}

#[cfg(feature = "runtime-benchmarks")]
pub struct AssetU128;
#[cfg(feature = "runtime-benchmarks")]
use pallet_assets::BenchmarkHelper;

#[cfg(feature = "runtime-benchmarks")]
impl BenchmarkHelper<codec::Compact<u128>> for AssetU128 {
	fn create_asset_id_parameter(id: u32) -> codec::Compact<u128> {
		codec::Compact::from(id as u128)
	}
}

pub const POLKADEX_NATIVE_ASSET_ID: u128 = 0;

parameter_types! {
	pub const AssetHandlerPalletId: PalletId = PalletId(*b"XcmHandl");
	pub const WithdrawalExecutionBlockDiff: u32 = 1;
	pub ParachainId: u32 =  MsgQueue::parachain_id().into();
	pub const ParachainNetworkId: u8 = 1; // Our parachain's thea id is one.
	pub const PolkadexAssetid: u128 = POLKADEX_NATIVE_ASSET_ID;
}

impl xcm_helper::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type AccountIdConvert = LocationToAccountId;
	type Assets = Assets;
	type AssetId = u128;
	type Currency = Balances;
	type AssetCreateUpdateOrigin = EnsureRoot<AccountId>;
	type Executor = TheaMessageHandler;
	type AssetHandlerPalletId = AssetHandlerPalletId;
	type WithdrawalExecutionBlockDiff = WithdrawalExecutionBlockDiff;
	type ParachainId = ParachainId;
	type SubstrateNetworkId = ParachainNetworkId;
	type NativeAssetId = PolkadexAssetid;
	type WeightInfo = xcm_helper::weights::WeightInfo<Runtime>;
	type SiblingAddressConverter = SiblingParachainConvertsVia<Sibling, AccountId>;
}

parameter_types! {
	pub SelfLocation: MultiLocation = MultiLocation::new(1, X1(Parachain(MsgQueue::parachain_id().into())));
	pub BaseXcmWeight: Weight =  Weight::from_parts(100_000_000, 0);
	pub const MaxAssetsForTransfer: usize = 2;
}

parameter_type_with_key! {
	pub ParachainMinFee: |_location: MultiLocation| -> Option<u128> {
		Some(1u128)
	};
}

pub struct AccountIdToMultiLocation;
impl Convert<AccountId, MultiLocation> for AccountIdToMultiLocation {
	fn convert(account: AccountId) -> MultiLocation {
		X1(xcm::prelude::AccountId32 { network: None, id: account.into() }).into()
	}
}

impl orml_xtokens::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type Balance = Balance;
	type CurrencyId = polkadex_primitives::AssetId;
	type CurrencyIdConvert = XcmHelper;
	type AccountIdToMultiLocation = AccountIdToMultiLocation;
	type SelfLocation = SelfLocation;
	type MinXcmFee = ParachainMinFee;
	type XcmExecutor = XcmExecutor<XcmConfig>;
	type MultiLocationsFilter = Everything;
	type Weigher = FixedWeightBounds<UnitWeightCost, RuntimeCall, MaxInstructions>;
	type BaseXcmWeight = BaseXcmWeight;
	type MaxAssetsForTransfer = MaxAssetsForTransfer;
	type ReserveProvider = AbsoluteReserveProvider;
	type UniversalLocation = UniversalLocation;
}

parameter_types! {
	pub const TheaMaxAuthorities: u32 = 200;
}

impl thea_message_handler::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type TheaId = AuthorityId;
	type Signature = AuthoritySignature;
	type MaxAuthorities = TheaMaxAuthorities;
	type Executor = XcmHelper;
	type WeightInfo = thea_message_handler::weights::WeightInfo<Runtime>;
}

construct_runtime!(
	pub enum Runtime
	{
		System: frame_system::{Pallet, Call, Storage, Config<T>, Event<T>},
		Balances: pallet_balances::{Pallet, Call, Storage, Config<T>, Event<T>},
		MsgQueue: mock_msg_queue::{Pallet, Storage, Event<T>},
		PolkadotXcm: pallet_xcm::{Pallet, Call, Event<T>, Origin},
		ForeignUniques: pallet_uniques::{Pallet, Call, Storage, Event<T>},
		Assets: pallet_assets::{Pallet, Call, Storage, Event<T>},
		XTokens: orml_xtokens::{Pallet, Call, Storage, Event<T>},
		XcmHelper: xcm_helper::{Pallet, Call, Storage, Event<T>},
		TheaMessageHandler: thea_message_handler::{Pallet, Call, Storage, Event<T>}
	}
);

pub struct ForeignAssetFeeHandler<T, R, AC, WH>
where
	T: WeightToFeeT<Balance = u128>,
	R: TakeRevenue,
	AC: AssetIdConverter,
	WH: WhitelistedTokenHandler,
{
	/// Total used weight
	weight: Weight,
	/// Total consumed assets
	consumed: u128,
	/// Asset Id (as MultiLocation) and units per second for payment
	asset_location_and_units_per_second: Option<(MultiLocation, u128)>,
	_pd: PhantomData<(T, R, AC, WH)>,
}

impl<T, R, AC, WH> WeightTrader for ForeignAssetFeeHandler<T, R, AC, WH>
where
	T: WeightToFeeT<Balance = u128>,
	R: TakeRevenue,
	AC: AssetIdConverter,
	WH: WhitelistedTokenHandler,
{
	fn new() -> Self {
		Self {
			weight: Weight::zero(),
			consumed: 0,
			asset_location_and_units_per_second: None,
			_pd: PhantomData,
		}
	}

	/// NOTE: If the token is allowlisted by AMM pallet ( probably using governance )
	/// then it will be allowed to execute for free even if the pool is not there.
	/// If pool is not there and token is not present in allowlisted then it will be rejected.
	fn buy_weight(
		&mut self,
		weight: Weight,
		payment: xcm_executor::Assets,
		_context: &XcmContext,
	) -> sp_std::result::Result<xcm_executor::Assets, XcmError> {
		let _fee_in_native_token = T::weight_to_fee(&weight);
		let payment_asset = payment.fungible_assets_iter().next().ok_or(XcmError::Trap(1000))?;
		if let AssetId::Concrete(location) = payment_asset.id {
			// let foreign_currency_asset_id =
			// AC::convert_location_to_asset_id(location).ok_or(XcmError::Trap(1001))?;
			// let _path = [PolkadexAssetid::get(), foreign_currency_asset_id.into()];
			//WILL BE RESTORED LATER
			// let (unused, expected_fee_in_foreign_currency) =
			// 	if WH::check_whitelisted_token(foreign_currency_asset_id) {
			// 		(payment, 0u128)
			// 	} else {
			// 		return Err(XcmError::Trap(1004));
			// 	};
			let (unused, expected_fee_in_foreign_currency) = (payment, 0u128);
			self.weight = self.weight.saturating_add(weight);
			if let Some((old_asset_location, _)) = self.asset_location_and_units_per_second {
				if old_asset_location == location {
					self.consumed = self
						.consumed
						.saturating_add((expected_fee_in_foreign_currency).saturated_into());
				}
			} else {
				self.consumed = self
					.consumed
					.saturating_add((expected_fee_in_foreign_currency).saturated_into());
				self.asset_location_and_units_per_second = Some((location, 0));
			}
			Ok(unused)
		} else {
			Err(XcmError::Trap(1005))
		}
	}
}

use crate::parachain::currency::CENTS;
use frame_support::weights::constants::ExtrinsicBaseWeight;
use frame_support::weights::WeightToFee as WeightToFeeT;
use frame_support::weights::{
	WeightToFeeCoefficient, WeightToFeeCoefficients, WeightToFeePolynomial,
};

impl<T, R, AC, WH> Drop for ForeignAssetFeeHandler<T, R, AC, WH>
where
	T: WeightToFeeT<Balance = u128>,
	R: TakeRevenue,
	AC: AssetIdConverter,
	WH: WhitelistedTokenHandler,
{
	fn drop(&mut self) {
		if let Some((asset_location, _)) = self.asset_location_and_units_per_second {
			if self.consumed > 0 {
				R::take_revenue((asset_location, self.consumed).into());
			}
		}
	}
}

pub struct RevenueCollector;

impl TakeRevenue for RevenueCollector {
	fn take_revenue(_revenue: MultiAsset) {}
}
