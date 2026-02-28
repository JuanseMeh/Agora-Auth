/// Errors related to data mapping and serialization between database rows and domain entities.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MappingError {
    /// Row data could not be deserialized/parsed
    DeserializationFailed { entity_type: String, reason: String },
    /// Domain entity could not be serialized for storage
    SerializationFailed { entity_type: String, reason: String },
    /// Row data structure does not match expected schema
    SchemaMismatch { entity_type: String, reason: String },
    /// Required column is missing or NULL when not allowed
    MissingRequired { entity_type: String, field: String },
    /// Column value is of unexpected type
    TypeMismatch {
        entity_type: String,
        field: String,
        expected: String,
        actual: String,
    },
}

impl MappingError {
    pub fn deserialization_failed(
        entity_type: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self::DeserializationFailed {
            entity_type: entity_type.into(),
            reason: reason.into(),
        }
    }

    pub fn serialization_failed(
        entity_type: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self::SerializationFailed {
            entity_type: entity_type.into(),
            reason: reason.into(),
        }
    }

    pub fn schema_mismatch(
        entity_type: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self::SchemaMismatch {
            entity_type: entity_type.into(),
            reason: reason.into(),
        }
    }

    pub fn missing_required(
        entity_type: impl Into<String>,
        field: impl Into<String>,
    ) -> Self {
        Self::MissingRequired {
            entity_type: entity_type.into(),
            field: field.into(),
        }
    }

    pub fn type_mismatch(
        entity_type: impl Into<String>,
        field: impl Into<String>,
        expected: impl Into<String>,
        actual: impl Into<String>,
    ) -> Self {
        Self::TypeMismatch {
            entity_type: entity_type.into(),
            field: field.into(),
            expected: expected.into(),
            actual: actual.into(),
        }
    }

    /// Returns true if this error indicates the transaction should be rolled back
    pub fn is_transaction_compromised(&self) -> bool {
        true // Mapping errors always compromise the transaction
    }
}

impl std::fmt::Display for MappingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MappingError::DeserializationFailed {
                entity_type,
                reason,
            } => {
                write!(
                    f,
                    "failed to deserialize {} from database: {}",
                    entity_type, reason
                )
            }
            MappingError::SerializationFailed {
                entity_type,
                reason,
            } => {
                write!(
                    f,
                    "failed to serialize {} for database: {}",
                    entity_type, reason
                )
            }
            MappingError::SchemaMismatch {
                entity_type,
                reason,
            } => {
                write!(
                    f,
                    "schema mismatch for {}: {}",
                    entity_type, reason
                )
            }
            MappingError::MissingRequired {
                entity_type,
                field,
            } => {
                write!(
                    f,
                    "missing required field '{}' for {}",
                    field, entity_type
                )
            }
            MappingError::TypeMismatch {
                entity_type,
                field,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "type mismatch in {}.{}: expected {}, got {}",
                    entity_type, field, expected, actual
                )
            }
        }
    }
}

impl std::error::Error for MappingError {}
