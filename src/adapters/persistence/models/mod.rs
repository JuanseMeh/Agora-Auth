// Database row models — raw representations of persisted data.

/*
These models represent raw database rows before mapping to domain entities.

Important distinctions:
 - Models are NOT domain entities
 - Models use database column names and types directly
 - Models are only used internally in the persistence adapter
 - Mapping to domain entities happens in repository implementations

All row types must implement `sqlx::FromRow` for direct deserialization.
*/

pub mod identity_row;
pub mod session_row;

pub use identity_row::IdentityRow;
pub use session_row::SessionRow;

#[cfg(test)]
mod tests;