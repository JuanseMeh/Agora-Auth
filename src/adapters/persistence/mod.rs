// Persistence adapter — SQL-backed repositories for domain entities.

/*
This module implements the infrastructure layer for data persistence.

It is responsible for:
 - Connecting to the database and managing the connection pool
 - Mapping database rows to domain entities
 - Executing queries and mutations
 - Supporting transactions for coordinated operations

It is NOT responsible for:
 - Business logic or policy enforcement
 - Cryptography or hashing
 - Token parsing or validation
 - HTTP or network concerns

All modules in this adapter implement ports defined in `core::ports`.
Database errors are mapped to domain-level errors defined in `error`.
*/

pub mod database;
pub mod error;
pub mod models;
pub mod repositories;

pub use database::Database;
pub use error::PersistenceError;
pub use repositories::{CredentialRepositorySql, IdentityRepositorySql, SessionRepositorySql};

