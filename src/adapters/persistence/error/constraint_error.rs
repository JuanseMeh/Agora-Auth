/// Errors related to data constraints and integrity violations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConstraintError {
    /// A unique constraint was violated (e.g., duplicate identifier)
    UniqueViolation { reason: String },
    /// A foreign key constraint was violated
    ForeignKeyViolation { reason: String },
    /// A check constraint was violated
    CheckViolation { reason: String },
    /// A NOT NULL constraint was violated
    NotNullViolation { reason: String },
    /// Generic constraint violation
    ConstraintViolation { reason: String },
}

impl ConstraintError {
    pub fn unique_violation(reason: impl Into<String>) -> Self {
        Self::UniqueViolation {
            reason: reason.into(),
        }
    }

    pub fn foreign_key_violation(reason: impl Into<String>) -> Self {
        Self::ForeignKeyViolation {
            reason: reason.into(),
        }
    }

    pub fn check_violation(reason: impl Into<String>) -> Self {
        Self::CheckViolation {
            reason: reason.into(),
        }
    }

    pub fn not_null_violation(reason: impl Into<String>) -> Self {
        Self::NotNullViolation {
            reason: reason.into(),
        }
    }

    pub fn constraint_violation(reason: impl Into<String>) -> Self {
        Self::ConstraintViolation {
            reason: reason.into(),
        }
    }
}

impl std::fmt::Display for ConstraintError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConstraintError::UniqueViolation { reason } => {
                write!(f, "unique constraint violated: {}", reason)
            }
            ConstraintError::ForeignKeyViolation { reason } => {
                write!(f, "foreign key constraint violated: {}", reason)
            }
            ConstraintError::CheckViolation { reason } => {
                write!(f, "check constraint violated: {}", reason)
            }
            ConstraintError::NotNullViolation { reason } => {
                write!(f, "not null constraint violated: {}", reason)
            }
            ConstraintError::ConstraintViolation { reason } => {
                write!(f, "constraint violated: {}", reason)
            }
        }
    }
}

impl std::error::Error for ConstraintError {}
