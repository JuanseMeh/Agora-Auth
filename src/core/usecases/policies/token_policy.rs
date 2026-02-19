//! Token lifetime policy configuration and logic for authentication use cases.
//!
//! This struct encapsulates access and refresh token TTL rules.
//!
//! Policy is injected as a configuration object, not hardcoded.

/// Token lifetime policy configuration.
#[derive(Debug, Clone)]
pub struct TokenPolicy {
	pub access_ttl_secs: u64,
	pub refresh_ttl_secs: u64,
	pub one_time_refresh: bool,
}

impl TokenPolicy {
	/// Create a new token policy.
	pub fn new(access_ttl_secs: u64, refresh_ttl_secs: u64, one_time_refresh: bool) -> Self {
		Self {
			access_ttl_secs,
			refresh_ttl_secs,
			one_time_refresh,
		}
	}

	/// Returns the access token TTL in seconds.
	pub fn access_ttl(&self) -> u64 {
		self.access_ttl_secs
	}

	/// Returns the refresh token TTL in seconds.
	pub fn refresh_ttl(&self) -> u64 {
		self.refresh_ttl_secs
	}

	/// Returns true if refresh tokens are one-time use only.
	pub fn is_one_time_refresh(&self) -> bool {
		self.one_time_refresh
	}
}
