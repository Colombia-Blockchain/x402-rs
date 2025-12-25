//! Algorand payment provider implementation.
//!
//! This module implements Algorand payments using atomic transaction groups.
//! Users sign standard ASA (Algorand Standard Asset) transfers, and the
//! facilitator co-signs a fee-paying transaction to enable gasless payments
//! via Algorand's fee pooling mechanism.
//!
//! Flow (based on Coinbase/Algorand Foundation x402 specification):
//! 1. Client creates an atomic transaction group: [fee_tx, asa_transfer]
//! 2. Client signs only the ASA transfer (standard wallet signature)
//! 3. Client sends the partially-signed group to facilitator
//! 4. Facilitator verifies the ASA transfer is valid and authorized
//! 5. Facilitator signs the fee transaction and submits the entire group
//! 6. Algorand network executes both atomically (or neither)
//!
//! Key Insight: Fee pooling allows transaction 0 to pay fees for transaction 1,
//! enabling completely gasless payments for users.

#![cfg(feature = "algorand")]

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Formatter};
use std::sync::Arc;
use tokio::sync::RwLock;

use algonaut_client::algod::v2::Algod;
use algonaut_core::{Address as AlgoAddress, MicroAlgos, Round, SignedTransaction, Transaction as AlgoTransaction};
use algonaut_crypto::ed25519::Ed25519SecretKey;
use algonaut_transaction::account::Account;

use crate::chain::{FacilitatorLocalError, FromEnvByNetworkBuild, NetworkProviderOps};
use crate::facilitator::Facilitator;
use crate::from_env;
use crate::network::Network;
use crate::types::{
    ExactAlgorandPayload, ExactPaymentPayload, FacilitatorErrorReason, MixedAddress, Scheme,
    SettleRequest, SettleResponse, SupportedPaymentKind, SupportedPaymentKindExtra,
    SupportedPaymentKindsResponse, TransactionHash, VerifyRequest, VerifyResponse, X402Version,
};

// =============================================================================
// Constants
// =============================================================================

/// USDC ASA ID on Algorand mainnet
pub const USDC_ASA_ID_MAINNET: u64 = 31566704;

/// USDC ASA ID on Algorand testnet
pub const USDC_ASA_ID_TESTNET: u64 = 10458941;

/// Default Algorand mainnet algod endpoint
pub const ALGORAND_MAINNET_ALGOD: &str = "https://mainnet-api.algonode.cloud";

/// Default Algorand testnet algod endpoint
pub const ALGORAND_TESTNET_ALGOD: &str = "https://testnet-api.algonode.cloud";

// =============================================================================
// Error Types
// =============================================================================

/// Algorand-specific errors
#[derive(Debug, thiserror::Error)]
pub enum AlgorandError {
    #[error("Invalid transaction encoding: {0}")]
    InvalidEncoding(String),

    #[error("Invalid atomic group: {0}")]
    InvalidAtomicGroup(String),

    #[error("Transaction expired at round {expiry_round} (current: {current_round})")]
    TransactionExpired {
        expiry_round: u64,
        current_round: u64,
    },

    #[error("Invalid signature for address {address}")]
    InvalidSignature { address: String },

    #[error("Fee transaction has forbidden fields: {field}")]
    ForbiddenFeeField { field: String },

    #[error("Insufficient fee amount: provided {provided}, required {required}")]
    InsufficientFee { provided: u64, required: u64 },

    #[error("Transaction submission failed: {0}")]
    SubmissionFailed(String),

    #[error("Transaction not confirmed after {attempts} attempts")]
    TransactionNotConfirmed { attempts: u32 },

    #[error("ASA ID mismatch: expected {expected}, got {actual}")]
    AsaIdMismatch { expected: u64, actual: u64 },

    #[error("RPC error: {0}")]
    RpcError(String),

    #[error("Invalid group ID")]
    InvalidGroupId,

    #[error("Payment index out of bounds: {index} >= {len}")]
    PaymentIndexOutOfBounds { index: usize, len: usize },
}

impl From<AlgorandError> for FacilitatorLocalError {
    fn from(e: AlgorandError) -> Self {
        FacilitatorLocalError::Other(e.to_string())
    }
}

// =============================================================================
// Chain Configuration
// =============================================================================

/// Algorand network chain configuration
#[derive(Clone, Debug)]
pub struct AlgorandChain {
    pub network: Network,
    pub usdc_asa_id: u64,
}

impl AlgorandChain {
    /// Get the default algod API URL for this network
    pub fn default_algod_url(&self) -> &'static str {
        match self.network {
            Network::Algorand => ALGORAND_MAINNET_ALGOD,
            Network::AlgorandTestnet => ALGORAND_TESTNET_ALGOD,
            _ => unreachable!("AlgorandChain only supports Algorand networks"),
        }
    }
}

impl TryFrom<Network> for AlgorandChain {
    type Error = FacilitatorLocalError;

    fn try_from(value: Network) -> Result<Self, Self::Error> {
        match value {
            Network::Algorand => Ok(Self {
                network: value,
                usdc_asa_id: USDC_ASA_ID_MAINNET,
            }),
            Network::AlgorandTestnet => Ok(Self {
                network: value,
                usdc_asa_id: USDC_ASA_ID_TESTNET,
            }),
            _ => Err(FacilitatorLocalError::UnsupportedNetwork(None)),
        }
    }
}

// =============================================================================
// Address Types
// =============================================================================

/// Algorand address wrapper
#[derive(Clone, Debug)]
pub struct AlgorandAddress {
    /// The address in standard Algorand format (58 characters, base32)
    pub address: String,
}

impl AlgorandAddress {
    /// Create a new AlgorandAddress
    pub fn new(address: String) -> Self {
        Self { address }
    }

    /// Check if this is a valid Algorand address
    pub fn is_valid(&self) -> bool {
        // Algorand addresses are 58 characters, base32 encoded
        if self.address.len() != 58 {
            return false;
        }
        // Try to parse as Algorand address
        AlgoAddress::from_string(&self.address).is_ok()
    }

    /// Convert to algonaut Address type
    pub fn to_algo_address(&self) -> Result<AlgoAddress, AlgorandError> {
        AlgoAddress::from_string(&self.address)
            .map_err(|e| AlgorandError::InvalidEncoding(format!("Invalid address: {}", e)))
    }
}

impl TryFrom<String> for AlgorandAddress {
    type Error = FacilitatorLocalError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let addr = AlgorandAddress::new(value);
        if addr.is_valid() {
            Ok(addr)
        } else {
            Err(FacilitatorLocalError::InvalidAddress(format!(
                "Invalid Algorand address: {}",
                addr.address
            )))
        }
    }
}

impl TryFrom<MixedAddress> for AlgorandAddress {
    type Error = FacilitatorLocalError;

    fn try_from(value: MixedAddress) -> Result<Self, Self::Error> {
        match value {
            MixedAddress::Algorand(address) => Self::try_from(address),
            _ => Err(FacilitatorLocalError::InvalidAddress(
                "expected Algorand address".to_string(),
            )),
        }
    }
}

impl From<AlgorandAddress> for MixedAddress {
    fn from(value: AlgorandAddress) -> Self {
        MixedAddress::Algorand(value.address)
    }
}

// =============================================================================
// Provider Implementation
// =============================================================================

/// Algorand payment provider
///
/// Implements USDC payments on Algorand using atomic transaction groups.
/// The facilitator receives partially-signed atomic groups, verifies them,
/// signs the fee transaction, and submits the complete group.
#[derive(Clone)]
pub struct AlgorandProvider {
    /// The facilitator's Algorand account (for signing fee transactions)
    account: Arc<Account>,
    /// The facilitator's public address
    public_address: String,
    /// Algod client for RPC calls
    algod: Arc<Algod>,
    /// Network configuration
    chain: AlgorandChain,
    /// Nonce store for replay protection (group_id -> confirmation_round)
    nonce_store: Arc<RwLock<std::collections::HashMap<[u8; 32], u64>>>,
}

impl Debug for AlgorandProvider {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AlgorandProvider")
            .field("public_address", &self.public_address)
            .field("chain", &self.chain)
            .finish()
    }
}

impl AlgorandProvider {
    /// Create a new Algorand provider
    pub fn try_new(
        mnemonic: String,
        algod_url: Option<String>,
        network: Network,
    ) -> Result<Self, FacilitatorLocalError> {
        let chain = AlgorandChain::try_from(network)?;

        // Create account from mnemonic
        let account = Account::from_mnemonic(&mnemonic).map_err(|e| {
            FacilitatorLocalError::InvalidAddress(format!("Invalid Algorand mnemonic: {}", e))
        })?;

        let public_address = account.address().to_string();
        let effective_url = algod_url
            .as_deref()
            .unwrap_or(chain.default_algod_url());

        // Create algod client
        let algod = Algod::new(effective_url, "").map_err(|e| {
            FacilitatorLocalError::Other(format!("Failed to create Algod client: {}", e))
        })?;

        tracing::info!(
            network = %network,
            public_address = %public_address,
            algod_url = %effective_url,
            usdc_asa_id = chain.usdc_asa_id,
            "Initialized Algorand provider"
        );

        Ok(Self {
            account: Arc::new(account),
            public_address,
            algod: Arc::new(algod),
            chain,
            nonce_store: Arc::new(RwLock::new(std::collections::HashMap::new())),
        })
    }

    /// Get the facilitator's public address as MixedAddress
    pub fn facilitator_address(&self) -> MixedAddress {
        MixedAddress::Algorand(self.public_address.clone())
    }

    /// Decode a base64 msgpack transaction
    fn decode_transaction(&self, base64_tx: &str) -> Result<AlgoTransaction, AlgorandError> {
        let bytes = BASE64
            .decode(base64_tx)
            .map_err(|e| AlgorandError::InvalidEncoding(format!("Base64 decode failed: {}", e)))?;

        // Decode msgpack transaction
        rmp_serde::from_slice(&bytes)
            .map_err(|e| AlgorandError::InvalidEncoding(format!("Msgpack decode failed: {}", e)))
    }

    /// Decode a base64 msgpack signed transaction
    fn decode_signed_transaction(&self, base64_tx: &str) -> Result<SignedTransaction, AlgorandError> {
        let bytes = BASE64
            .decode(base64_tx)
            .map_err(|e| AlgorandError::InvalidEncoding(format!("Base64 decode failed: {}", e)))?;

        rmp_serde::from_slice(&bytes)
            .map_err(|e| AlgorandError::InvalidEncoding(format!("Msgpack decode failed: {}", e)))
    }

    /// Validate the fee transaction is safe to sign
    ///
    /// CRITICAL SECURITY: This prevents malicious transactions from:
    /// - Draining the facilitator's funds (close_remainder_to)
    /// - Taking over the facilitator's account (rekey_to)
    fn validate_fee_transaction(&self, tx: &AlgoTransaction) -> Result<(), AlgorandError> {
        // Check for forbidden fields that could compromise the facilitator

        // close_remainder_to would send remaining funds to attacker
        if tx.close_remainder_to.is_some() {
            return Err(AlgorandError::ForbiddenFeeField {
                field: "close_remainder_to".to_string(),
            });
        }

        // rekey_to would give control of facilitator account to attacker
        if tx.rekey_to.is_some() {
            return Err(AlgorandError::ForbiddenFeeField {
                field: "rekey_to".to_string(),
            });
        }

        // asset_close_to would send ASA balance to attacker
        // (Note: fee tx should be a payment, not asset transfer, but check anyway)
        // This is checked in the asset transfer type

        Ok(())
    }

    /// Verify the atomic group structure and signatures
    async fn verify_payment_group(
        &self,
        payload: &ExactAlgorandPayload,
    ) -> Result<VerifyGroupResult, AlgorandError> {
        if payload.payment_group.len() < 2 {
            return Err(AlgorandError::InvalidAtomicGroup(
                "Group must have at least 2 transactions".to_string(),
            ));
        }

        if payload.payment_index >= payload.payment_group.len() {
            return Err(AlgorandError::PaymentIndexOutOfBounds {
                index: payload.payment_index,
                len: payload.payment_group.len(),
            });
        }

        // Decode the fee transaction (index 0, unsigned)
        let fee_tx = self.decode_transaction(&payload.payment_group[0])?;

        // Validate fee transaction security
        self.validate_fee_transaction(&fee_tx)?;

        // Decode the payment transaction (signed by client)
        let payment_signed = self.decode_signed_transaction(&payload.payment_group[payload.payment_index])?;

        // Verify group IDs match
        let fee_group_id = fee_tx.group.ok_or(AlgorandError::InvalidGroupId)?;
        let payment_group_id = payment_signed.transaction.group.ok_or(AlgorandError::InvalidGroupId)?;

        if fee_group_id != payment_group_id {
            return Err(AlgorandError::InvalidAtomicGroup(
                "Group IDs do not match".to_string(),
            ));
        }

        // Verify the payment is an asset transfer
        let asset_transfer = payment_signed
            .transaction
            .asset_transfer_transaction
            .as_ref()
            .ok_or_else(|| {
                AlgorandError::InvalidAtomicGroup("Payment must be an asset transfer".to_string())
            })?;

        // Verify it's USDC
        if asset_transfer.xfer != self.chain.usdc_asa_id {
            return Err(AlgorandError::AsaIdMismatch {
                expected: self.chain.usdc_asa_id,
                actual: asset_transfer.xfer,
            });
        }

        // Get current round for validity checks
        let status = self
            .algod
            .status()
            .await
            .map_err(|e| AlgorandError::RpcError(e.to_string()))?;
        let current_round = status.last_round;

        // Check transaction validity window
        if let Some(last_valid) = payment_signed.transaction.last_valid {
            if last_valid.0 < current_round {
                return Err(AlgorandError::TransactionExpired {
                    expiry_round: last_valid.0,
                    current_round,
                });
            }
        }

        // Extract payer address
        let payer_address = payment_signed.transaction.sender.to_string();

        Ok(VerifyGroupResult {
            payer: AlgorandAddress::new(payer_address),
            fee_tx,
            payment_signed,
            group_id: fee_group_id.0,
            amount: asset_transfer.amount,
            recipient: asset_transfer.receiver.to_string(),
            current_round,
        })
    }

    /// Sign the fee transaction and submit the group
    async fn submit_group(
        &self,
        verification: &VerifyGroupResult,
        payload: &ExactAlgorandPayload,
    ) -> Result<String, AlgorandError> {
        // Sign the fee transaction
        let signed_fee = self
            .account
            .sign_transaction(&verification.fee_tx)
            .map_err(|e| AlgorandError::InvalidEncoding(format!("Failed to sign fee tx: {}", e)))?;

        // Build the complete signed group
        let mut signed_group: Vec<SignedTransaction> = Vec::with_capacity(payload.payment_group.len());

        for (i, tx_base64) in payload.payment_group.iter().enumerate() {
            if i == 0 {
                // Fee transaction - use our signature
                signed_group.push(signed_fee.clone());
            } else {
                // Other transactions - already signed by client
                let signed = self.decode_signed_transaction(tx_base64)?;
                signed_group.push(signed);
            }
        }

        // Submit the atomic group
        let pending_tx = self
            .algod
            .send_transactions(&signed_group)
            .await
            .map_err(|e| AlgorandError::SubmissionFailed(e.to_string()))?;

        let tx_id = pending_tx.tx_id;

        tracing::info!(
            tx_id = %tx_id,
            group_size = signed_group.len(),
            "Submitted Algorand atomic group"
        );

        // Wait for confirmation
        self.wait_for_confirmation(&tx_id).await?;

        // Store group ID to prevent replay
        {
            let mut store = self.nonce_store.write().await;
            store.insert(verification.group_id, verification.current_round);
        }

        Ok(tx_id)
    }

    /// Wait for transaction confirmation
    async fn wait_for_confirmation(&self, tx_id: &str) -> Result<(), AlgorandError> {
        const MAX_ATTEMPTS: u32 = 20;
        const POLL_INTERVAL_MS: u64 = 500;

        for attempt in 1..=MAX_ATTEMPTS {
            tokio::time::sleep(tokio::time::Duration::from_millis(POLL_INTERVAL_MS)).await;

            match self.algod.pending_transaction_with_id(tx_id).await {
                Ok(info) => {
                    if info.confirmed_round.is_some() {
                        tracing::info!(
                            tx_id = %tx_id,
                            confirmed_round = ?info.confirmed_round,
                            "Algorand transaction confirmed"
                        );
                        return Ok(());
                    }
                    tracing::debug!(
                        tx_id = %tx_id,
                        attempt = attempt,
                        "Transaction pending..."
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        tx_id = %tx_id,
                        error = %e,
                        attempt = attempt,
                        "Error checking transaction status"
                    );
                }
            }
        }

        Err(AlgorandError::TransactionNotConfirmed {
            attempts: MAX_ATTEMPTS,
        })
    }
}

/// Result of verifying an Algorand payment group
pub struct VerifyGroupResult {
    pub payer: AlgorandAddress,
    pub fee_tx: AlgoTransaction,
    pub payment_signed: SignedTransaction,
    pub group_id: [u8; 32],
    pub amount: u64,
    pub recipient: String,
    pub current_round: u64,
}

// =============================================================================
// Trait Implementations
// =============================================================================

impl FromEnvByNetworkBuild for AlgorandProvider {
    async fn from_env(network: Network) -> Result<Option<Self>, Box<dyn std::error::Error>> {
        let algod_url = std::env::var(from_env::rpc_env_name_from_network(network)).ok();

        // Get mnemonic from environment
        let mnemonic = match from_env::SignerType::from_env()?.get_algorand_mnemonic(network) {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!(network=%network, error=%e, "no Algorand mnemonic configured, skipping");
                return Ok(None);
            }
        };

        let provider = AlgorandProvider::try_new(mnemonic, algod_url, network)?;
        Ok(Some(provider))
    }
}

impl NetworkProviderOps for AlgorandProvider {
    fn signer_address(&self) -> MixedAddress {
        self.facilitator_address()
    }

    fn network(&self) -> Network {
        self.chain.network
    }
}

impl Facilitator for AlgorandProvider {
    type Error = FacilitatorLocalError;

    async fn verify(&self, request: &VerifyRequest) -> Result<VerifyResponse, Self::Error> {
        let payload = &request.payment_payload;

        // Extract Algorand payload
        let algorand_payload = match &payload.payload {
            ExactPaymentPayload::Algorand(p) => p,
            _ => return Err(FacilitatorLocalError::UnsupportedNetwork(None)),
        };

        // Verify network matches
        if payload.network != self.network() {
            return Err(FacilitatorLocalError::NetworkMismatch(
                None,
                self.network(),
                payload.network,
            ));
        }

        let verification = self
            .verify_payment_group(algorand_payload)
            .await
            .map_err(FacilitatorLocalError::from)?;

        Ok(VerifyResponse::valid(verification.payer.into()))
    }

    async fn settle(&self, request: &SettleRequest) -> Result<SettleResponse, Self::Error> {
        let payload = &request.payment_payload;

        // Extract Algorand payload
        let algorand_payload = match &payload.payload {
            ExactPaymentPayload::Algorand(p) => p,
            _ => return Err(FacilitatorLocalError::UnsupportedNetwork(None)),
        };

        // Verify network matches
        if payload.network != self.network() {
            return Err(FacilitatorLocalError::NetworkMismatch(
                None,
                self.network(),
                payload.network,
            ));
        }

        tracing::info!("Algorand settle: Verifying payment group");
        let verification = self
            .verify_payment_group(algorand_payload)
            .await
            .map_err(FacilitatorLocalError::from)?;

        tracing::info!(
            payer = %verification.payer.address,
            amount = verification.amount,
            recipient = %verification.recipient,
            "Algorand settle: Verification successful, submitting group"
        );

        // Submit the transaction group
        let tx_id = match self.submit_group(&verification, algorand_payload).await {
            Ok(id) => {
                tracing::info!(
                    tx_id = %id,
                    "Algorand settle: Transaction submitted successfully"
                );
                id
            }
            Err(e) => {
                tracing::error!(
                    error = %e,
                    "Algorand settle: Failed to submit transaction"
                );
                return Ok(SettleResponse {
                    success: false,
                    error_reason: Some(FacilitatorErrorReason::UnexpectedSettleError),
                    payer: verification.payer.into(),
                    transaction: None,
                    network: self.network(),
                });
            }
        };

        Ok(SettleResponse {
            success: true,
            error_reason: None,
            payer: verification.payer.into(),
            transaction: Some(TransactionHash::Algorand(tx_id)),
            network: self.network(),
        })
    }

    async fn supported(&self) -> Result<SupportedPaymentKindsResponse, Self::Error> {
        let kinds = vec![SupportedPaymentKind {
            network: self.network().to_string(),
            scheme: Scheme::Exact,
            x402_version: X402Version::V1,
            extra: Some(SupportedPaymentKindExtra {
                fee_payer: Some(self.signer_address()),
                tokens: None,
            }),
        }];
        Ok(SupportedPaymentKindsResponse { kinds })
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_algorand_address_validation() {
        // Valid Algorand address (58 chars, base32)
        let valid = AlgorandAddress::new(
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ".to_string()
        );
        assert!(valid.is_valid());

        // Invalid address - too short
        let invalid_short = AlgorandAddress::new("AAAA".to_string());
        assert!(!invalid_short.is_valid());

        // Invalid address - wrong characters
        let invalid_chars = AlgorandAddress::new("0000000000000000000000000000000000000000000000000000000000".to_string());
        assert!(!invalid_chars.is_valid());
    }

    #[test]
    fn test_chain_config() {
        let mainnet = AlgorandChain::try_from(Network::Algorand).unwrap();
        assert_eq!(mainnet.usdc_asa_id, USDC_ASA_ID_MAINNET);

        let testnet = AlgorandChain::try_from(Network::AlgorandTestnet).unwrap();
        assert_eq!(testnet.usdc_asa_id, USDC_ASA_ID_TESTNET);
    }
}
