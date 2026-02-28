// Internal handlers module
pub mod credentials;

pub use credentials::create_credential;

#[cfg(test)]
pub mod tests;