mod error;
mod keystore;

use crate::{error::Error, keystore::OcexKeystore};
use futures::{executor::block_on, FutureExt, StreamExt};
use ias::{
	api::{IasAdvisoryId, IasVersion, QuoteStatus, Unverified},
	client::ClientBuilder,
	verifier::{crypto::Mbedtls, AttestationEmbeddedIasReport, PlatformVerifier},
};
use log::{debug, error};
use ocex_primitives::{AuthorityId, ConsensusLog, OcexApi, ValidatorSet, OCEX_ENGINE_ID};
use once_cell::sync::Lazy;
use pkix::{pem, pem::PEM_CERTIFICATE};
use sc_client_api::{
	Backend, BlockchainEvents, FinalityNotification, FinalityNotifications, Finalizer,
	HeaderBackend,
};
use sp_api::{Encode, HeaderT, ProvideRuntimeApi};
use sp_keystore::SyncCryptoStorePtr;
use sp_runtime::{
	codec::Codec,
	generic::{BlockId, OpaqueDigestItemId},
	traits::Block,
};
use std::{collections::HashSet, marker::PhantomData, sync::Arc};
use ias::client::IasVerificationResult;

/// Intel remote certification service production url
pub(crate) const IAS_PROD_URL: &'static str = "https://api.trustedservices.intel.com/sgx/";

/// Intel remote certification service dev/test url
pub(crate) const IAS_DEV_URL: &'static str = "https://api.trustedservices.intel.com/sgx/dev/";

static IAS_REPORT_SIGNING_CERTIFICATE: Lazy<Vec<u8>> = Lazy::new(|| {
	pem::pem_to_der(include_str!("../Intel_SGX_Attestation_RootCA.pem"), Some(PEM_CERTIFICATE))
		.unwrap()
});

struct IgnorePlatformState;

impl IgnorePlatformState {
	fn new() -> IgnorePlatformState {
		IgnorePlatformState {}
	}
}

impl PlatformVerifier for IgnorePlatformState {
	fn verify(
		&self,
		_for_self: bool,
		_nonce: &Option<String>,
		_isv_enclave_quote_status: QuoteStatus,
		_advisories: &Vec<IasAdvisoryId>,
	) -> Result<(), ias::verifier::Error> {
		Ok(())
	}
}
/// OCEX client
pub struct OCEXParams<C, BE, R> {
	/// THEA client
	pub client: Arc<C>,
	pub backend: Arc<BE>,
	pub runtime: Arc<R>,
	/// Local key store
	pub key_store: Option<SyncCryptoStorePtr>,
}

/// A convenience OCEX client trait that defines all the type bounds a THEA client
/// has to satisfy. Ideally that should actually be a trait alias. Unfortunately as
/// of today, Rust does not allow a type alias to be used as a trait bound. Tracking
/// issue is <https://github.com/rust-lang/rust/issues/41517>.
pub trait Client<B, BE>:
	BlockchainEvents<B> + HeaderBackend<B> + Finalizer<B, BE> + ProvideRuntimeApi<B> + Send + Sync
where
	B: Block,
	BE: Backend<B>,
{
	// empty
}

impl<B, BE, T> Client<B, BE> for T
where
	B: Block,
	BE: Backend<B>,
	T: BlockchainEvents<B>
		+ HeaderBackend<B>
		+ Finalizer<B, BE>
		+ ProvideRuntimeApi<B>
		+ Send
		+ Sync,
{
	// empty
}

/// OCEX worker
pub struct OCEXWorker<B, C, BE, R>
where
	B: Block,
	BE: Backend<B>,
	C: Client<B, BE>,
	R: ProvideRuntimeApi<B>,
	R::Api: OcexApi<B>,
{
	_client: Arc<C>,
	#[allow(dead_code)]
	backend: Arc<BE>,
	runtime: Arc<R>,
	wait_for_keys: u8,
	finality_notifications: FinalityNotifications<B>,
	/// Local key store
	keystore: OcexKeystore,
	signed_reports: HashSet<Vec<u8>>,
	_be: PhantomData<BE>,
}

impl<B, C, BE, R> OCEXWorker<B, C, BE, R>
where
	B: Block,
	BE: Backend<B>,
	C: Client<B, BE>,
	R: ProvideRuntimeApi<B>,
	R::Api: OcexApi<B>,
{
	pub fn new(params: OCEXParams<C, BE, R>) -> Self {
		let finality_notifications = params.client.finality_notification_stream();
		OCEXWorker {
			_client: params.client,
			backend: params.backend,
			runtime: params.runtime,
			wait_for_keys: 0,
			finality_notifications,
			keystore: params.key_store.into(),
			signed_reports: HashSet::new(),
			_be: Default::default(),
		}
	}

	/// Check if we have session keys for any of the current validators
	fn has_key(&self, validator_set: &ValidatorSet<AuthorityId>) -> Option<(usize, AuthorityId)> {
		if let Some(authority_id) = self.keystore.authority_id(&validator_set.validators[..]) {
			validator_set
				.validators
				.iter()
				.position(|id| &authority_id == id)
				.map(|auth_idx| (auth_idx, authority_id))
		} else {
			None
		}
	}

	fn handle_finality_notification(
		&mut self,
		notification: FinalityNotification<B>,
	) -> Result<bool, Error> {
		log::info!(target:"ocex","New finality event: {:?}", notification.header.number());
		let at = BlockId::hash(notification.hash);
		// Check for ocex keys in storage and if it is not found, wait for another 10 finalized
		// blocks and panic
		if let Some(active) = self.validator_set(&notification.header) {
			if let Some((_, authority)) = self.has_key(&active) {
				for unapproved in self
					.runtime
					.runtime_api()
					.get_unapproved_enclave_reports(&at, &authority)?
					.into_iter()
				{
					// skip if already signed by us but not synced yet
					if self.signed_reports.contains(&unapproved[..]) {
						debug!(target: "ocex", "no new unapproved reports.");
						continue
					}
					debug!(target: "ocex", "processing report: {:?}", &unapproved);
					/*    let url = if cfg!(debug_assertions) {
							IAS_DEV_URL
						} else {
							IAS_PROD_URL
						};
					*/
					/*					let url = IAS_DEV_URL;
										// FIXME: this might require subscription ID
										let builder = ClientBuilder::new()
											.subscription_key("aca0ef9937f8413c8c07e1e8236e977f".into());
										let ias_client = builder
											.ias_version(IasVersion::V4)
											.build(url)
											.map_err(|e| Error::Other(format!("{}", e)))?;
					*/
					// actual verification
					let verify_result: IasVerificationResult = IasVerificationResult::
					match block_on(ias_client.verify_quote(&unapproved)) {
						Ok(response) => {
							let to_ver: AttestationEmbeddedIasReport<Unverified> =
								response.clone().into();
							to_ver
								.verify::<Mbedtls>(&[IAS_REPORT_SIGNING_CERTIFICATE.as_slice()])
								.and_then(|r| {
									r.to_attestation_evidence_reponse()
										.unwrap()
										.verify(&IgnorePlatformState::new())
								})
								.map_err(|e| Error::Other(format!("{}", e)))
						},
						Err(e) => Err(Error::Other(format!("{}", e))),
					}?;

					// sign it
					let signature = self.keystore.sign(&authority, &unapproved)?;

					// send approvals to OCEX pallet
					match self.runtime.runtime_api().submit_approve_enclave_report(
						&at,
						authority.clone(),
						signature,
						unapproved.clone(),
					) {
						Ok(res) => match res {
							Ok(()) => {
								// TODO: Keep track of signed reports so you don't send approvals
								// again. tracking on pallet side - should do it on client too?
								self.signed_reports.insert(unapproved);
								debug!(target: "ocex", "successfully submitted the enclave report approval");
							},
							Err(err) => {
								error!(target: "ocex", "Unable to sign transaction; {:?}", err);
							},
						},
						Err(err) => {
							error!(target: "ocex", "Error in runtime api call: {:?}", err);
						},
					};
				}
				debug!(target: "ocex", "Done processing unsigned reports");
			} else {
				self.wait_for_keys = self.wait_for_keys.saturating_add(1);
				log::error!(target:"ocex", "Ocex Session keys are not inserted, validator will stop in {:?} blocks", 50u8.saturating_sub(self.wait_for_keys));
				if self.wait_for_keys == 50 {
					// We cannot proceed without keys so we are instructing the worker loop to stop
					return Ok(false)
				}
			}
		} else {
			debug!(target:"ocex", "OCEX pallet is not yet deployed, skipping ocex logic.")
		}
		Ok(true)
	}

	/// Return the current active validator set at header `header`.
	///
	/// Note that the validator set could be `None`. This is the case if we don't find
	/// a OCEX authority set change and we can't fetch the authority set from the
	/// on-chain state.
	///
	/// Such a failure is usually an indication that the OCEX pallet has not been deployed (yet).
	fn validator_set(&self, header: &B::Header) -> Option<ValidatorSet<AuthorityId>> {
		find_authorities_change::<B, AuthorityId>(header).or_else(|| {
			let at = BlockId::hash(header.hash());
			self.runtime.runtime_api().validator_set(&at).ok()
		})
	}

	pub async fn run(mut self) {
		loop {
			futures::select! {
				notification = self.finality_notifications.next().fuse() => {
					if let Some(notification) = notification {
						match self.handle_finality_notification(notification) {
							Ok(flag) if !flag => break,
							Ok(_) => {},
							Err(err) => {
								log::error!(target:"ocex","Error while processing enclave report approvals: {:?}",err);
							}
						}
					}
				},
			}
		}
	}
}

async fn validate(report: impl AsRef<[u8]>) -> bool {
	let url = IAS_DEV_URL;
	// FIXME: this might require subscription ID
	let builder = ClientBuilder::new();
	let ias_client = match builder.ias_version(IasVersion::V4).build(url) {
		Ok(c) => c,
		Err(_) => return false,
	};

	// actual verification
	match ias_client.verify_quote(report.as_ref()).await {
		Ok(response) => {
			let to_ver: AttestationEmbeddedIasReport<Unverified> = response.clone().into();
			to_ver
				.verify::<Mbedtls>(&[IAS_REPORT_SIGNING_CERTIFICATE.as_slice()])
				.and_then(|r| {
					r.to_attestation_evidence_reponse().unwrap().verify(&IgnorePlatformState::new())
				})
				.map_err(|e| Error::Other(format!("{}", e)))
		},
		Err(e) => Err(Error::Other(format!("{}", e))),
	}
	.is_ok()
}

/// Scan the `header` digest log for a OCEX validator set change. Return either the new
/// validator set or `None` in case no validator set change has been signaled.
pub fn find_authorities_change<B, Id>(header: &B::Header) -> Option<ValidatorSet<Id>>
where
	B: Block,
	Id: Codec,
{
	let id = OpaqueDigestItemId::Consensus(&OCEX_ENGINE_ID);

	let filter = |log: ConsensusLog<Id>| match log {
		ConsensusLog::AuthoritiesChange(validator_set) => Some(validator_set),
		_ => None,
	};

	header.digest().convert_first(|l| l.try_to(id).and_then(filter))
}

#[tokio::test]
async fn report_verification_test() {
	let quote: [u8; 757] = [
		123, 34, 99, 112, 117, 115, 118, 110, 34, 58, 91, 49, 57, 44, 49, 57, 44, 50, 44, 55, 44,
		50, 53, 53, 44, 49, 50, 56, 44, 54, 44, 48, 44, 48, 44, 48, 44, 48, 44, 48, 44, 48, 44, 48,
		44, 48, 44, 48, 93, 44, 34, 109, 105, 115, 99, 115, 101, 108, 101, 99, 116, 34, 58, 123,
		34, 98, 105, 116, 115, 34, 58, 48, 125, 44, 34, 97, 116, 116, 114, 105, 98, 117, 116, 101,
		115, 34, 58, 123, 34, 102, 108, 97, 103, 115, 34, 58, 123, 34, 98, 105, 116, 115, 34, 58,
		55, 125, 44, 34, 120, 102, 114, 109, 34, 58, 55, 125, 44, 34, 109, 114, 101, 110, 99, 108,
		97, 118, 101, 34, 58, 91, 49, 54, 50, 44, 49, 56, 48, 44, 49, 54, 50, 44, 49, 48, 48, 44,
		49, 55, 52, 44, 49, 52, 54, 44, 49, 52, 52, 44, 55, 54, 44, 54, 50, 44, 53, 57, 44, 56, 53,
		44, 49, 53, 53, 44, 49, 51, 57, 44, 57, 56, 44, 49, 57, 55, 44, 50, 51, 51, 44, 49, 48, 52,
		44, 50, 49, 56, 44, 49, 50, 50, 44, 50, 48, 54, 44, 49, 57, 51, 44, 56, 53, 44, 54, 51, 44,
		51, 52, 44, 54, 55, 44, 54, 53, 44, 50, 51, 54, 44, 49, 50, 56, 44, 50, 52, 51, 44, 49, 48,
		55, 44, 50, 48, 50, 44, 49, 57, 53, 93, 44, 34, 109, 114, 115, 105, 103, 110, 101, 114, 34,
		58, 91, 57, 53, 44, 49, 56, 51, 44, 49, 52, 49, 44, 53, 55, 44, 55, 53, 44, 49, 48, 49, 44,
		49, 52, 57, 44, 50, 52, 54, 44, 56, 53, 44, 50, 50, 55, 44, 50, 49, 57, 44, 55, 49, 44, 49,
		52, 44, 49, 52, 51, 44, 49, 52, 51, 44, 55, 57, 44, 50, 44, 50, 48, 57, 44, 49, 50, 55, 44,
		49, 54, 53, 44, 49, 49, 55, 44, 50, 48, 54, 44, 49, 56, 53, 44, 55, 51, 44, 56, 49, 44, 50,
		50, 56, 44, 49, 44, 50, 50, 53, 44, 49, 53, 48, 44, 49, 49, 54, 44, 50, 52, 50, 44, 51, 56,
		93, 44, 34, 105, 115, 118, 112, 114, 111, 100, 105, 100, 34, 58, 48, 44, 34, 105, 115, 118,
		115, 118, 110, 34, 58, 48, 44, 34, 114, 101, 112, 111, 114, 116, 100, 97, 116, 97, 34, 58,
		91, 49, 53, 48, 44, 55, 56, 44, 49, 50, 52, 44, 49, 49, 49, 44, 55, 50, 44, 53, 44, 49, 48,
		50, 44, 50, 50, 55, 44, 52, 49, 44, 54, 54, 44, 51, 53, 44, 57, 56, 44, 49, 56, 51, 44, 55,
		56, 44, 49, 56, 52, 44, 49, 53, 57, 44, 50, 48, 57, 44, 49, 55, 49, 44, 50, 52, 51, 44, 55,
		53, 44, 50, 44, 49, 52, 53, 44, 50, 52, 53, 44, 50, 51, 49, 44, 50, 52, 56, 44, 49, 48, 49,
		44, 49, 51, 55, 44, 56, 57, 44, 49, 48, 44, 53, 48, 44, 50, 48, 44, 52, 52, 44, 48, 44, 48,
		44, 48, 44, 48, 44, 48, 44, 48, 44, 48, 44, 48, 44, 48, 44, 48, 44, 48, 44, 48, 44, 48, 44,
		48, 44, 48, 44, 48, 44, 48, 44, 48, 44, 48, 44, 48, 44, 48, 44, 48, 44, 48, 44, 48, 44, 48,
		44, 48, 44, 48, 44, 48, 44, 48, 44, 48, 44, 48, 44, 48, 93, 44, 34, 107, 101, 121, 105,
		100, 34, 58, 91, 49, 55, 55, 44, 50, 48, 52, 44, 52, 49, 44, 55, 54, 44, 50, 49, 54, 44,
		51, 52, 44, 50, 51, 49, 44, 52, 51, 44, 50, 51, 52, 44, 50, 50, 48, 44, 49, 57, 54, 44, 51,
		55, 44, 50, 48, 51, 44, 49, 49, 55, 44, 49, 49, 54, 44, 53, 44, 48, 44, 48, 44, 48, 44, 48,
		44, 48, 44, 48, 44, 48, 44, 48, 44, 48, 44, 48, 44, 48, 44, 48, 44, 48, 44, 48, 44, 48, 44,
		48, 93, 44, 34, 109, 97, 99, 34, 58, 91, 49, 52, 56, 44, 50, 49, 56, 44, 49, 56, 57, 44,
		49, 57, 52, 44, 50, 48, 52, 44, 54, 44, 49, 51, 56, 44, 50, 50, 44, 50, 51, 49, 44, 49, 55,
		51, 44, 51, 50, 44, 50, 51, 51, 44, 49, 52, 49, 44, 49, 54, 48, 44, 49, 51, 52, 44, 57, 50,
		93, 125,
	];
	assert!(validate(quote).await);
}
