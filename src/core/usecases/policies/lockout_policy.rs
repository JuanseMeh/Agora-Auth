//! Lockout policy configuration and logic for authentication use cases.
//!
//! This struct encapsulates lockout rules: max attempts, lock duration, reset rules.
//!
//! Policy is injected as a configuration object, not hardcoded.

/// Lockout policy configuration.
#[derive(Debug, Clone)]
pub struct LockoutPolicy {
	pub max_attempts: u32,
	pub lock_duration_secs: u64,
	pub reset_on_success: bool,
}

impl LockoutPolicy {
	/// Create a new lockout policy.
	pub fn new(max_attempts: u32, lock_duration_secs: u64, reset_on_success: bool) -> Self {
		Self {
			max_attempts,
			lock_duration_secs,
			reset_on_success,
		}
	}

	/// Returns true if the failed attempts exceed the max allowed.
	pub fn is_locked(&self, failed_attempts: u32) -> bool {
		failed_attempts >= self.max_attempts
	}

	/// Returns the lock duration in seconds.
	pub fn lock_duration(&self) -> u64 {
		self.lock_duration_secs
	}

	/// Returns true if failed attempts should be reset on successful login.
	pub fn should_reset_on_success(&self) -> bool {
		self.reset_on_success
	}
}
