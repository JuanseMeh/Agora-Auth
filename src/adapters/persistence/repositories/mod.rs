// SQL-backed repository implementations.

/*
Repositories implement the port interfaces defined in `core::ports`.

Each repository:
 - Uses the database connection pool
 - Maps database rows to domain entities
 - Translates database errors to persistence errors
 - Does NOT contain business logic
*/

pub mod identity_repository_sql;
pub mod credential_repository_sql;
pub mod session_repository_sql;

pub use identity_repository_sql::IdentityRepositorySql;
pub use credential_repository_sql::CredentialRepositorySql;
pub use session_repository_sql::SessionRepositorySql;

#[cfg(test)]
mod tests;