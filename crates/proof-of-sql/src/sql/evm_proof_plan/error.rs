use crate::{base::math::decimal::DecimalError, sql::AnalyzeError};
use snafu::Snafu;

/// Represents errors that can occur in the EVM proof plan module.
#[derive(Snafu, Debug, PartialEq)]
pub(crate) enum EVMProofPlanError {
    /// Error indicating that the plan is not supported.
    #[snafu(display("plan not yet supported"))]
    NotSupported,
    /// Error indicating that the column was not found.
    #[snafu(display("column not found"))]
    ColumnNotFound,
    /// Error indicating that the table was not found.
    #[snafu(display("table not found"))]
    TableNotFound,
    /// Error indicating that table name can not be parsed into `TableRef`.
    #[snafu(display("table name can not be parsed into TableRef"))]
    InvalidTableName,
    /// Error indicating that the output column name is invalid or missing.
    #[snafu(display("invalid or missing output column name"))]
    InvalidOutputColumnName,
    /// Error indicating an invalid time unit was provided.
    #[snafu(display("invalid time unit"))]
    InvalidTimeUnit,
    /// Decimal error
    #[snafu(transparent)]
    DecimalError {
        /// The underlying source error
        source: DecimalError,
    },
    /// Analyze error
    #[snafu(transparent)]
    AnalyzeError {
        /// The underlying source error
        source: AnalyzeError,
    },
}

/// Result type for EVM proof plan operations.
pub(crate) type EVMProofPlanResult<T> = core::result::Result<T, EVMProofPlanError>;
