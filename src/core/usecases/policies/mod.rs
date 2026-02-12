//! Policy configuration and business rules for authentication use cases.
//!
//! This module defines injectable policy objects for lockout, token lifetime, and session rotation.
//!
//! Policies are configuration objects, not hardcoded values.

pub mod lockout_policy;
pub mod token_policy;

pub use lockout_policy::LockoutPolicy;
pub use token_policy::TokenPolicy;
