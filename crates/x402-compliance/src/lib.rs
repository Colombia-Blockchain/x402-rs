pub mod audit_logger;
pub mod checker;
pub mod config;
pub mod error;
pub mod extractors;
pub mod lists;

// Re-export main types for convenience
pub use audit_logger::{AuditLogger, ComplianceEvent, Decision, EventType};
pub use checker::{
    AddressType, ComplianceChecker, ComplianceCheckerBuilder, MatchedEntity, ScreeningDecision,
    ScreeningResult, TransactionContext,
};
pub use config::{Config, ListConfig};
pub use error::{ComplianceError, Result};

// Re-export extractors
pub use extractors::evm::EvmExtractor;
#[cfg(feature = "solana")]
pub use extractors::solana::SolanaExtractor;
