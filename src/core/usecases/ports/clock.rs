//! Port for time abstraction.
//!
//! Abstracts time access for authentication use cases (e.g., for lockout, token expiry).
//!
//! Adapters must implement this trait to provide concrete time sources.

use chrono::{DateTime, Utc};

/// Contract for time abstraction.
pub trait Clock {
	/// Returns the current UTC time.
	fn now(&self) -> DateTime<Utc>;
}
