use frame_support::pallet_prelude::TypeInfo;
use parity_scale_codec::{Decode, Encode};

/// Extra data fields in Thea message, this can be extended
/// with new variants for future features

#[derive(Encode, Decode, Clone, TypeInfo, PartialEq, Debug)]
pub enum ExtraData {
    None,
    DirectDeposit
}