#[cfg(feature = "std")]
use crate::{Error, Pair as BLSPair};
use crate::{Public, Seed, Signature, BLS_DEV_PHRASE, DEV_PHRASE, DST, KeyStore};
#[cfg(feature = "std")]
use blst::min_sig::*;
#[cfg(feature = "std")]
use blst::BLST_ERROR;

#[cfg(feature = "std")]
use sp_core::crypto::{ExposeSecret, SecretUri};
#[cfg(feature = "std")]
use sp_core::Pair;
use sp_runtime_interface::runtime_interface;

use sp_std::vec::Vec;

pub const BLS_KEYSTORE_PATH: &str = "polkadex/.keystore/";

#[runtime_interface]
pub trait BlsExt {
	fn add_signature(agg_signature: &Signature, new: &Signature) -> Result<Signature, ()> {
		let agg_signature = match crate::BLSSignature::from_bytes(agg_signature.0.as_ref()) {
			Ok(sig) => sig,
			Err(_) => return Err(()),
		};
		let new = match crate::BLSSignature::from_bytes(new.0.as_ref()) {
			Ok(sig) => sig,
			Err(_) => return Err(()),
		};
		let mut agg_signature = AggregateSignature::from_signature(&agg_signature);
		if let Err(_) = agg_signature.add_signature(&new, true) {
			return Err(())
		}
		Ok(Signature::from(crate::BLSSignature::from_aggregate(&agg_signature)))
	}

	fn all() -> Vec<Public> {
		// Load all available bls public keys from filesystem
		match get_all_public_keys() {
			Ok(keys) => keys,
			Err(_) => Vec::new(),
		}
	}

	fn generate_pair(phrase: Option<Vec<u8>>) -> Public {
		// generate a pair
		let (pair, _seed, derive_junctions) = generate_pair_(phrase);
		pair.public()
	}

	fn generate_pair_and_store(phrase: Option<Vec<u8>>) -> Public {
		let (pair, seed, derive_junctions) = generate_pair_(phrase);
		// create keystore
		let keystore: KeyStore = KeyStore::new(seed, derive_junctions);
		// store the private key in filesystem
		let file_path = key_file_path(pair.public().as_ref());
		write_to_file(file_path, keystore.encode().as_ref()).expect("Unable to write seed to file");
		pair.public()
	}

	fn sign(pubkey: &Public, msg: &[u8]) -> Option<Signature> {
		// load the private key from filesystem and sign with it
		sign(pubkey, msg)
	}

	fn verify(pubkey: &Public, msg: &[u8], signature: &Signature) -> bool {
		println!("pubkey: {:?}", pubkey.0);
		println!("Signature: {:?}", signature.0);
		let pubkey = match PublicKey::uncompress(pubkey.0.as_ref()) {
			Ok(pubkey) => pubkey,
			Err(_) => return false,
		};
		let signature = match crate::BLSSignature::uncompress(signature.0.as_ref()) {
			Ok(sig) => sig,
			Err(_) => return false,
		};
		// verify the signature
		let err = signature.verify(true, msg, DST.as_ref(), &[], &pubkey, true);
		return if err == BLST_ERROR::BLST_SUCCESS { true } else { false }
	}

	fn verify_aggregate(pubkey: &Vec<Public>, msg: &[u8], signature: &Signature) -> bool {
		let mut pubkeys = vec![];
		for key in pubkey {
			let agg_pubkey = match PublicKey::uncompress(key.0.as_ref()) {
				Ok(pubkey) => pubkey,
				Err(_) => return false,
			};
			pubkeys.push(agg_pubkey);
		}
		let pubkeys_ref = pubkeys.iter().collect::<Vec<&PublicKey>>();

		let agg_signature = match crate::BLSSignature::uncompress(signature.0.as_ref()) {
			Ok(sig) => sig,
			Err(_) => return false,
		};
		// verify the signature
		let err = agg_signature.fast_aggregate_verify(true, msg, DST.as_ref(), &pubkeys_ref);
		return if err == BLST_ERROR::BLST_SUCCESS { true } else { false }
	}
}

#[cfg(feature = "std")]
use std::fs::File;
#[cfg(feature = "std")]
use std::io::Write;

#[cfg(feature = "std")]
use std::path::PathBuf;
#[cfg(feature = "std")]
use std::str::FromStr;
use parity_scale_codec::Encode;
use sp_core::DeriveJunction;

#[cfg(feature = "std")]
fn generate_pair_(phrase: Option<Vec<u8>>) -> (BLSPair, Seed, Vec<DeriveJunction>) {
	// println!("Generating pair... Phrase: {:?}",phrase);
	let (pair, seed, derive_junctions) = match phrase {
		None => {
			let (pair, seed) = BLSPair::generate();
			(pair, seed, vec![])
		},
		Some(phrase) => {
			let phrase = String::from_utf8(phrase).expect("Invalid phrase");
			let mut uri = SecretUri::from_str(phrase.as_ref()).expect("expected a valid phrase");
			let (pair, seed) = BLSPair::from_phrase(uri.phrase.expose_secret(), None)
				.expect("Phrase is not valid; qed");

			let (pair, seed) = pair
				.derive(uri.junctions.iter().cloned(), Some(seed))
				.expect("Expected to derive the pair here.");
			(pair, seed.unwrap(), uri.junctions)
		},
	};
	// println!("Seed: {:?}, public key; {:?}",seed,hex::encode(pair.public.0.as_ref()));
	(pair, seed, derive_junctions)
}

#[cfg(feature = "std")]
#[allow(dead_code)]
pub fn sign(pubkey: &Public, msg: &[u8]) -> Option<Signature> {
	let path = key_file_path(pubkey.as_ref());
	match std::fs::read(&path) {
		Err(err) => {
			log::error!(target:"bls","Error while reading keystore file: {:?}",err);
			return None
		},
		Ok(data) => match serde_json::from_slice::<Seed>(&data) {
			Ok(seed) =>
				return match SecretKey::key_gen(&seed, &[]) {
					Ok(secret_key) => {
						let pk = secret_key.sk_to_pk().compress();
						if pk != pubkey.0 {
							return None
						}
						Some(Signature::from(secret_key.sign(msg, DST.as_ref(), &[])))
					},
					Err(err) => {
						log::error!(target:"bls","Error while loading secret key from seed {:?}",err);
						None
					},
				},
			Err(_) => None,
		},
	}
}

#[cfg(feature = "std")]
#[allow(dead_code)]
fn get_all_public_keys() -> Result<Vec<Public>, Error> {
	let mut public_keys = vec![];
	for entry in std::fs::read_dir(&BLS_KEYSTORE_PATH)? {
		let entry = entry?;
		let path = entry.path();

		// skip directories and non-unicode file names (hex is unicode)
		if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
			match hex::decode(name) {
				Ok(ref hex) if hex.len() == 96 => {
					let public = hex.to_vec();

					match PublicKey::uncompress(public.as_ref()) {
						Ok(public) => public_keys.push(Public::from(public.to_bytes())),
						Err(_) => continue,
					}
				},
				_ => continue,
			}
		}
	}
	Ok(public_keys)
}

/// Write the given `data` to `file`.
#[cfg(feature = "std")]
#[allow(dead_code)]
fn write_to_file(path: PathBuf, data: &[u8]) -> Result<(), Error> {
	std::fs::create_dir_all(BLS_KEYSTORE_PATH)?;
	let mut file = std::fs::OpenOptions::new().write(true).create(true).open(path)?;
	use std::os::unix::fs::PermissionsExt;
	file.metadata()?.permissions().set_mode(0o600);
	serde_json::to_writer(&file, data)?;
	file.flush()?;
	Ok(())
}

/// Get the file path for the given public key and key type.
///
/// Returns `None` if the keystore only exists in-memory and there isn't any path to provide.
#[cfg(feature = "std")]
#[allow(dead_code)]
fn key_file_path(public: &[u8]) -> PathBuf {
	let mut buf = PathBuf::from(BLS_KEYSTORE_PATH);
	let key = hex::encode(public);
	buf.push(key.as_str());
	buf
}

/// Get the key phrase for a given public key and key type.
#[cfg(feature = "std")]
#[allow(dead_code)]
fn key_phrase_by_type(public: &[u8]) -> Result<Option<String>, Error> {
	let path = key_file_path(public);

	if path.exists() {
		let file = File::open(path)?;

		serde_json::from_reader(&file).map_err(Into::into).map(Some)
	} else {
		Ok(None)
	}
}
