use super::{EVMProofPlanError, EVMProofPlanResult};
use crate::{
    base::{
        database::{ColumnRef, LiteralValue},
        map::IndexSet,
        math::{decimal::Precision, i256::I256},
        posql_time::{PoSQLTimeUnit, PoSQLTimeZone},
    },
    sql::proof_exprs::{
        AddExpr, AndExpr, ColumnExpr, DynProofExpr, EqualsExpr, LiteralExpr, MultiplyExpr, NotExpr,
        OrExpr, SubtractExpr,
    },
};
use alloc::{boxed::Box, string::String, vec::Vec};
use serde::{Deserialize, Serialize};

/// Represents an expression that can be serialized for EVM.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub(crate) enum EVMDynProofExpr {
    Column(EVMColumnExpr),
    Literal(EVMLiteralExpr),
    Equals(EVMEqualsExpr),
    Add(EVMAddExpr),
    Subtract(EVMSubtractExpr),
    Multiply(EVMMultiplyExpr),
    And(EVMAndExpr),
    Or(EVMOrExpr),
    Not(EVMNotExpr),
}
impl EVMDynProofExpr {
    /// Try to create an `EVMDynProofExpr` from a `DynProofExpr`.
    pub(crate) fn try_from_proof_expr(
        expr: &DynProofExpr,
        column_refs: &IndexSet<ColumnRef>,
    ) -> EVMProofPlanResult<Self> {
        match expr {
            DynProofExpr::Column(column_expr) => {
                EVMColumnExpr::try_from_proof_expr(column_expr, column_refs).map(Self::Column)
            }
            DynProofExpr::Literal(literal_expr) => Ok(Self::Literal(
                EVMLiteralExpr::try_from_proof_expr(literal_expr),
            )),
            DynProofExpr::Equals(equals_expr) => {
                EVMEqualsExpr::try_from_proof_expr(equals_expr, column_refs).map(Self::Equals)
            }
            DynProofExpr::Add(add_expr) => {
                EVMAddExpr::try_from_proof_expr(add_expr, column_refs).map(Self::Add)
            }
            DynProofExpr::Subtract(subtract_expr) => {
                EVMSubtractExpr::try_from_proof_expr(subtract_expr, column_refs).map(Self::Subtract)
            }
            DynProofExpr::Multiply(multiply_expr) => {
                EVMMultiplyExpr::try_from_proof_expr(multiply_expr, column_refs).map(Self::Multiply)
            }
            DynProofExpr::And(and_expr) => {
                EVMAndExpr::try_from_proof_expr(and_expr, column_refs).map(Self::And)
            }
            DynProofExpr::Or(or_expr) => {
                EVMOrExpr::try_from_proof_expr(or_expr, column_refs).map(Self::Or)
            }
            DynProofExpr::Not(not_expr) => {
                EVMNotExpr::try_from_proof_expr(not_expr, column_refs).map(Self::Not)
            }
            _ => Err(EVMProofPlanError::NotSupported),
        }
    }

    pub(crate) fn try_into_proof_expr(
        &self,
        column_refs: &IndexSet<ColumnRef>,
    ) -> EVMProofPlanResult<DynProofExpr> {
        match self {
            EVMDynProofExpr::Column(column_expr) => Ok(DynProofExpr::Column(
                column_expr.try_into_proof_expr(column_refs)?,
            )),
            EVMDynProofExpr::Equals(equals_expr) => Ok(DynProofExpr::Equals(
                equals_expr.try_into_proof_expr(column_refs)?,
            )),
            EVMDynProofExpr::Literal(literal_expr) => {
                Ok(DynProofExpr::Literal(literal_expr.try_to_proof_expr()?))
            }
            EVMDynProofExpr::Add(add_expr) => Ok(DynProofExpr::Add(
                add_expr.try_into_proof_expr(column_refs)?,
            )),
            EVMDynProofExpr::Subtract(subtract_expr) => Ok(DynProofExpr::Subtract(
                subtract_expr.try_into_proof_expr(column_refs)?,
            )),
            EVMDynProofExpr::Multiply(multiply_expr) => Ok(DynProofExpr::Multiply(
                multiply_expr.try_into_proof_expr(column_refs)?,
            )),
            EVMDynProofExpr::And(and_expr) => Ok(DynProofExpr::And(
                and_expr.try_into_proof_expr(column_refs)?,
            )),
            EVMDynProofExpr::Or(or_expr) => {
                Ok(DynProofExpr::Or(or_expr.try_into_proof_expr(column_refs)?))
            }
            EVMDynProofExpr::Not(not_expr) => Ok(DynProofExpr::Not(
                not_expr.try_into_proof_expr(column_refs)?,
            )),
        }
    }
}

/// Represents a column expression.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub(crate) struct EVMColumnExpr {
    column_number: usize,
}

impl EVMColumnExpr {
    #[cfg_attr(not(test), expect(dead_code))]
    pub(crate) fn new(column_number: usize) -> Self {
        Self { column_number }
    }

    /// Try to create a `EVMColumnExpr` from a `ColumnExpr`.
    pub(crate) fn try_from_proof_expr(
        expr: &ColumnExpr,
        column_refs: &IndexSet<ColumnRef>,
    ) -> EVMProofPlanResult<Self> {
        Ok(Self {
            column_number: column_refs
                .get_index_of(expr.column_ref())
                .ok_or(EVMProofPlanError::ColumnNotFound)?,
        })
    }

    pub(crate) fn try_into_proof_expr(
        &self,
        column_refs: &IndexSet<ColumnRef>,
    ) -> EVMProofPlanResult<ColumnExpr> {
        Ok(ColumnExpr::new(
            column_refs
                .get_index(self.column_number)
                .ok_or(EVMProofPlanError::ColumnNotFound)?
                .clone(),
        ))
    }
}

/// Represents a literal expression that can be serialized for EVM.
///
/// This enum corresponds to the variants in `LiteralValue` that can be represented in EVM.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub(crate) enum EVMLiteralExpr {
    /// Boolean literals
    Boolean(bool),
    /// u8 literals
    Uint8(u8),
    /// i8 literals
    TinyInt(i8),
    /// i16 literals
    SmallInt(i16),
    /// i32 literals
    Int(i32),
    /// i64 literals
    BigInt(i64),
    /// String literals (stored with its string value)
    VarChar(String),
    /// Binary data literals
    VarBinary(Vec<u8>),
    /// i128 literals
    Int128(i128),
    /// Decimal literals with precision (max 75), scale, and 256-bit value as limbs
    Decimal75(u8, i8, [u64; 4]),
    /// Scalar literals
    Scalar([u64; 4]),
    /// `TimeStamp` defined over a unit and timezone with backing store
    /// For `TimeStampTZ`, we store:
    /// - `unit_value`: 0 for Second, 3 for Millisecond, 6 for Microsecond, 9 for Nanosecond
    /// - `timezone_offset`: offset in seconds
    /// - timestamp: time units since unix epoch
    TimeStampTZ(u64, i32, i64),
}

impl EVMLiteralExpr {
    /// Try to create a `EVMLiteralExpr` from a `LiteralExpr`.
    pub(crate) fn try_from_proof_expr(expr: &LiteralExpr) -> Self {
        match expr.value() {
            LiteralValue::Boolean(value) => EVMLiteralExpr::Boolean(*value),
            LiteralValue::Uint8(value) => EVMLiteralExpr::Uint8(*value),
            LiteralValue::TinyInt(value) => EVMLiteralExpr::TinyInt(*value),
            LiteralValue::SmallInt(value) => EVMLiteralExpr::SmallInt(*value),
            LiteralValue::Int(value) => EVMLiteralExpr::Int(*value),
            LiteralValue::BigInt(value) => EVMLiteralExpr::BigInt(*value),
            LiteralValue::VarChar(value) => EVMLiteralExpr::VarChar(value.clone()),
            LiteralValue::VarBinary(value) => EVMLiteralExpr::VarBinary(value.clone()),
            LiteralValue::Int128(value) => EVMLiteralExpr::Int128(*value),
            LiteralValue::Decimal75(precision, scale, value) => {
                // Convert I256 to [u64; 4] for serialization
                let limbs = value.raw(); // Access the internal [u64; 4] representation
                EVMLiteralExpr::Decimal75(precision.value(), *scale, limbs)
            }
            LiteralValue::Scalar(limbs) => EVMLiteralExpr::Scalar(*limbs),
            LiteralValue::TimeStampTZ(unit, timezone, value) => {
                // Convert unit to u64 (its precision value)
                let unit_value: u64 = (*unit).into();
                // Get timezone offset in seconds
                let timezone_offset = timezone.offset();
                EVMLiteralExpr::TimeStampTZ(unit_value, timezone_offset, *value)
            }
        }
    }

    /// Convert back to a `LiteralExpr`
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The time unit is invalid
    /// - The decimal precision is invalid
    pub(crate) fn try_to_proof_expr(&self) -> EVMProofPlanResult<LiteralExpr> {
        match self {
            EVMLiteralExpr::Boolean(value) => Ok(LiteralExpr::new(LiteralValue::Boolean(*value))),
            EVMLiteralExpr::Uint8(value) => Ok(LiteralExpr::new(LiteralValue::Uint8(*value))),
            EVMLiteralExpr::TinyInt(value) => Ok(LiteralExpr::new(LiteralValue::TinyInt(*value))),
            EVMLiteralExpr::SmallInt(value) => Ok(LiteralExpr::new(LiteralValue::SmallInt(*value))),
            EVMLiteralExpr::Int(value) => Ok(LiteralExpr::new(LiteralValue::Int(*value))),
            EVMLiteralExpr::BigInt(value) => Ok(LiteralExpr::new(LiteralValue::BigInt(*value))),
            EVMLiteralExpr::VarChar(value) => {
                Ok(LiteralExpr::new(LiteralValue::VarChar(value.clone())))
            }
            EVMLiteralExpr::VarBinary(value) => {
                Ok(LiteralExpr::new(LiteralValue::VarBinary(value.clone())))
            }
            EVMLiteralExpr::Int128(value) => Ok(LiteralExpr::new(LiteralValue::Int128(*value))),
            EVMLiteralExpr::Decimal75(precision, scale, limbs) => {
                // Convert [u64; 4] back to I256
                let value = I256::new(*limbs);
                // Create precision, propagating any error
                let precision_obj = Precision::new(*precision)
                    .map_err(|e| EVMProofPlanError::DecimalError { source: e })?;
                Ok(LiteralExpr::new(LiteralValue::Decimal75(
                    precision_obj,
                    *scale,
                    value,
                )))
            }
            EVMLiteralExpr::Scalar(limbs) => Ok(LiteralExpr::new(LiteralValue::Scalar(*limbs))),
            EVMLiteralExpr::TimeStampTZ(unit_value, timezone_offset, value) => {
                // Convert u64 back to PoSQLTimeUnit based on precision
                let unit = match *unit_value {
                    0 => PoSQLTimeUnit::Second,
                    3 => PoSQLTimeUnit::Millisecond,
                    6 => PoSQLTimeUnit::Microsecond,
                    9 => PoSQLTimeUnit::Nanosecond,
                    _ => return Err(EVMProofPlanError::InvalidTimeUnit),
                };
                // Create timezone from offset
                let timezone = PoSQLTimeZone::new(*timezone_offset);
                Ok(LiteralExpr::new(LiteralValue::TimeStampTZ(
                    unit, timezone, *value,
                )))
            }
        }
    }
}

/// Represents an equals expression.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub(crate) struct EVMEqualsExpr {
    lhs: Box<EVMDynProofExpr>,
    rhs: Box<EVMDynProofExpr>,
}

impl EVMEqualsExpr {
    #[cfg_attr(not(test), expect(dead_code))]
    pub(crate) fn new(lhs: EVMDynProofExpr, rhs: EVMDynProofExpr) -> Self {
        Self {
            lhs: Box::new(lhs),
            rhs: Box::new(rhs),
        }
    }

    /// Try to create an `EVMEqualsExpr` from a `EqualsExpr`.
    pub(crate) fn try_from_proof_expr(
        expr: &EqualsExpr,
        column_refs: &IndexSet<ColumnRef>,
    ) -> EVMProofPlanResult<Self> {
        Ok(EVMEqualsExpr {
            lhs: Box::new(EVMDynProofExpr::try_from_proof_expr(
                expr.lhs(),
                column_refs,
            )?),
            rhs: Box::new(EVMDynProofExpr::try_from_proof_expr(
                expr.rhs(),
                column_refs,
            )?),
        })
    }

    pub(crate) fn try_into_proof_expr(
        &self,
        column_refs: &IndexSet<ColumnRef>,
    ) -> EVMProofPlanResult<EqualsExpr> {
        Ok(EqualsExpr::try_new(
            Box::new(self.lhs.try_into_proof_expr(column_refs)?),
            Box::new(self.rhs.try_into_proof_expr(column_refs)?),
        )?)
    }
}

/// Represents an addition expression.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub(crate) struct EVMAddExpr {
    lhs: Box<EVMDynProofExpr>,
    rhs: Box<EVMDynProofExpr>,
}

impl EVMAddExpr {
    #[cfg_attr(not(test), expect(dead_code))]
    pub(crate) fn new(lhs: EVMDynProofExpr, rhs: EVMDynProofExpr) -> Self {
        Self {
            lhs: Box::new(lhs),
            rhs: Box::new(rhs),
        }
    }

    /// Try to create an `EVMAddExpr` from a `AddExpr`.
    pub(crate) fn try_from_proof_expr(
        expr: &AddExpr,
        column_refs: &IndexSet<ColumnRef>,
    ) -> EVMProofPlanResult<Self> {
        Ok(EVMAddExpr {
            lhs: Box::new(EVMDynProofExpr::try_from_proof_expr(
                expr.lhs(),
                column_refs,
            )?),
            rhs: Box::new(EVMDynProofExpr::try_from_proof_expr(
                expr.rhs(),
                column_refs,
            )?),
        })
    }

    pub(crate) fn try_into_proof_expr(
        &self,
        column_refs: &IndexSet<ColumnRef>,
    ) -> EVMProofPlanResult<AddExpr> {
        Ok(AddExpr::try_new(
            Box::new(self.lhs.try_into_proof_expr(column_refs)?),
            Box::new(self.rhs.try_into_proof_expr(column_refs)?),
        )?)
    }
}

/// Represents a subtraction expression.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub(crate) struct EVMSubtractExpr {
    lhs: Box<EVMDynProofExpr>,
    rhs: Box<EVMDynProofExpr>,
}

impl EVMSubtractExpr {
    #[cfg_attr(not(test), expect(dead_code))]
    pub(crate) fn new(lhs: EVMDynProofExpr, rhs: EVMDynProofExpr) -> Self {
        Self {
            lhs: Box::new(lhs),
            rhs: Box::new(rhs),
        }
    }

    /// Try to create an `EVMSubtractExpr` from a `SubtractExpr`.
    pub(crate) fn try_from_proof_expr(
        expr: &SubtractExpr,
        column_refs: &IndexSet<ColumnRef>,
    ) -> EVMProofPlanResult<Self> {
        Ok(EVMSubtractExpr {
            lhs: Box::new(EVMDynProofExpr::try_from_proof_expr(
                expr.lhs(),
                column_refs,
            )?),
            rhs: Box::new(EVMDynProofExpr::try_from_proof_expr(
                expr.rhs(),
                column_refs,
            )?),
        })
    }

    pub(crate) fn try_into_proof_expr(
        &self,
        column_refs: &IndexSet<ColumnRef>,
    ) -> EVMProofPlanResult<SubtractExpr> {
        Ok(SubtractExpr::try_new(
            Box::new(self.lhs.try_into_proof_expr(column_refs)?),
            Box::new(self.rhs.try_into_proof_expr(column_refs)?),
        )?)
    }
}

/// Represents a multiplication expression.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub(crate) struct EVMMultiplyExpr {
    lhs: Box<EVMDynProofExpr>,
    rhs: Box<EVMDynProofExpr>,
}

impl EVMMultiplyExpr {
    #[cfg_attr(not(test), expect(dead_code))]
    pub(crate) fn new(lhs: EVMDynProofExpr, rhs: EVMDynProofExpr) -> Self {
        Self {
            lhs: Box::new(lhs),
            rhs: Box::new(rhs),
        }
    }

    /// Try to create an `EVMMultiplyExpr` from a `MultiplyExpr`.
    pub(crate) fn try_from_proof_expr(
        expr: &MultiplyExpr,
        column_refs: &IndexSet<ColumnRef>,
    ) -> EVMProofPlanResult<Self> {
        Ok(EVMMultiplyExpr {
            lhs: Box::new(EVMDynProofExpr::try_from_proof_expr(
                expr.lhs(),
                column_refs,
            )?),
            rhs: Box::new(EVMDynProofExpr::try_from_proof_expr(
                expr.rhs(),
                column_refs,
            )?),
        })
    }

    pub(crate) fn try_into_proof_expr(
        &self,
        column_refs: &IndexSet<ColumnRef>,
    ) -> EVMProofPlanResult<MultiplyExpr> {
        Ok(MultiplyExpr::try_new(
            Box::new(self.lhs.try_into_proof_expr(column_refs)?),
            Box::new(self.rhs.try_into_proof_expr(column_refs)?),
        )?)
    }
}

/// Represents an AND expression.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub(crate) struct EVMAndExpr {
    lhs: Box<EVMDynProofExpr>,
    rhs: Box<EVMDynProofExpr>,
}

impl EVMAndExpr {
    #[cfg_attr(not(test), expect(dead_code))]
    pub(crate) fn new(lhs: EVMDynProofExpr, rhs: EVMDynProofExpr) -> Self {
        Self {
            lhs: Box::new(lhs),
            rhs: Box::new(rhs),
        }
    }

    /// Try to create an `EVMAndExpr` from a `AndExpr`.
    pub(crate) fn try_from_proof_expr(
        expr: &AndExpr,
        column_refs: &IndexSet<ColumnRef>,
    ) -> EVMProofPlanResult<Self> {
        Ok(EVMAndExpr {
            lhs: Box::new(EVMDynProofExpr::try_from_proof_expr(
                expr.lhs(),
                column_refs,
            )?),
            rhs: Box::new(EVMDynProofExpr::try_from_proof_expr(
                expr.rhs(),
                column_refs,
            )?),
        })
    }

    pub(crate) fn try_into_proof_expr(
        &self,
        column_refs: &IndexSet<ColumnRef>,
    ) -> EVMProofPlanResult<AndExpr> {
        Ok(AndExpr::try_new(
            Box::new(self.lhs.try_into_proof_expr(column_refs)?),
            Box::new(self.rhs.try_into_proof_expr(column_refs)?),
        )?)
    }
}

/// Represents an OR expression.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub(crate) struct EVMOrExpr {
    lhs: Box<EVMDynProofExpr>,
    rhs: Box<EVMDynProofExpr>,
}

impl EVMOrExpr {
    #[cfg_attr(not(test), expect(dead_code))]
    pub(crate) fn new(lhs: EVMDynProofExpr, rhs: EVMDynProofExpr) -> Self {
        Self {
            lhs: Box::new(lhs),
            rhs: Box::new(rhs),
        }
    }

    /// Try to create an `EVMOrExpr` from a `OrExpr`.
    pub(crate) fn try_from_proof_expr(
        expr: &OrExpr,
        column_refs: &IndexSet<ColumnRef>,
    ) -> EVMProofPlanResult<Self> {
        Ok(EVMOrExpr {
            lhs: Box::new(EVMDynProofExpr::try_from_proof_expr(
                expr.lhs(),
                column_refs,
            )?),
            rhs: Box::new(EVMDynProofExpr::try_from_proof_expr(
                expr.rhs(),
                column_refs,
            )?),
        })
    }

    pub(crate) fn try_into_proof_expr(
        &self,
        column_refs: &IndexSet<ColumnRef>,
    ) -> EVMProofPlanResult<OrExpr> {
        Ok(OrExpr::try_new(
            Box::new(self.lhs.try_into_proof_expr(column_refs)?),
            Box::new(self.rhs.try_into_proof_expr(column_refs)?),
        )?)
    }
}

/// Represents a NOT expression.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub(crate) struct EVMNotExpr {
    expr: Box<EVMDynProofExpr>,
}

impl EVMNotExpr {
    #[cfg_attr(not(test), expect(dead_code))]
    pub(crate) fn new(expr: EVMDynProofExpr) -> Self {
        Self {
            expr: Box::new(expr),
        }
    }

    /// Try to create an `EVMNotExpr` from a `NotExpr`.
    pub(crate) fn try_from_proof_expr(
        expr: &NotExpr,
        column_refs: &IndexSet<ColumnRef>,
    ) -> EVMProofPlanResult<Self> {
        Ok(EVMNotExpr {
            expr: Box::new(EVMDynProofExpr::try_from_proof_expr(
                expr.input(),
                column_refs,
            )?),
        })
    }

    pub(crate) fn try_into_proof_expr(
        &self,
        column_refs: &IndexSet<ColumnRef>,
    ) -> EVMProofPlanResult<NotExpr> {
        Ok(NotExpr::try_new(Box::new(
            self.expr.try_into_proof_expr(column_refs)?,
        ))?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        base::{
            database::{ColumnType, TableRef},
            map::indexset,
            math::{
                decimal::{DecimalError, Precision},
                i256::I256,
            },
            posql_time::{PoSQLTimeUnit, PoSQLTimeZone},
        },
        sql::proof_exprs::test_utility::*,
    };

    // EVMColumnExpr
    #[test]
    fn we_can_put_a_column_expr_in_evm() {
        let table_ref: TableRef = TableRef::try_from("namespace.table").unwrap();
        let ident = "a".into();
        let column_ref = ColumnRef::new(table_ref.clone(), ident, ColumnType::BigInt);

        let evm_column_expr = EVMColumnExpr::try_from_proof_expr(
            &ColumnExpr::new(column_ref.clone()),
            &indexset! {column_ref.clone()},
        )
        .unwrap();
        assert_eq!(evm_column_expr.column_number, 0);

        // Roundtrip
        let roundtripped_column_expr = evm_column_expr
            .try_into_proof_expr(&indexset! {column_ref.clone()})
            .unwrap();
        assert_eq!(*roundtripped_column_expr.column_ref(), column_ref);
    }

    #[test]
    fn we_cannot_put_a_column_expr_in_evm_if_column_not_found() {
        let table_ref: TableRef = TableRef::try_from("namespace.table").unwrap();
        let ident = "a".into();
        let column_ref = ColumnRef::new(table_ref.clone(), ident, ColumnType::BigInt);

        assert_eq!(
            EVMColumnExpr::try_from_proof_expr(&ColumnExpr::new(column_ref.clone()), &indexset! {}),
            Err(EVMProofPlanError::ColumnNotFound)
        );
    }

    #[test]
    fn we_cannot_get_a_column_expr_from_evm_if_column_number_out_of_bounds() {
        let evm_column_expr = EVMColumnExpr { column_number: 0 };
        let column_refs = IndexSet::<ColumnRef>::default();
        assert_eq!(
            evm_column_expr
                .try_into_proof_expr(&column_refs)
                .unwrap_err(),
            EVMProofPlanError::ColumnNotFound
        );
    }

    // EVMLiteralExpr
    #[test]
    fn we_can_put_an_integer_literal_expr_in_evm() {
        // Test Uint8
        let evm_literal_expr =
            EVMLiteralExpr::try_from_proof_expr(&LiteralExpr::new(LiteralValue::Uint8(42)));
        assert_eq!(evm_literal_expr, EVMLiteralExpr::Uint8(42));
        let roundtripped = evm_literal_expr.try_to_proof_expr().unwrap();
        assert_eq!(*roundtripped.value(), LiteralValue::Uint8(42));

        // Test TinyInt
        let evm_literal_expr =
            EVMLiteralExpr::try_from_proof_expr(&LiteralExpr::new(LiteralValue::TinyInt(-42)));
        assert_eq!(evm_literal_expr, EVMLiteralExpr::TinyInt(-42));
        let roundtripped = evm_literal_expr.try_to_proof_expr().unwrap();
        assert_eq!(*roundtripped.value(), LiteralValue::TinyInt(-42));

        // Test SmallInt
        let evm_literal_expr =
            EVMLiteralExpr::try_from_proof_expr(&LiteralExpr::new(LiteralValue::SmallInt(1234)));
        assert_eq!(evm_literal_expr, EVMLiteralExpr::SmallInt(1234));
        let roundtripped = evm_literal_expr.try_to_proof_expr().unwrap();
        assert_eq!(*roundtripped.value(), LiteralValue::SmallInt(1234));

        // Test Int
        let evm_literal_expr =
            EVMLiteralExpr::try_from_proof_expr(&LiteralExpr::new(LiteralValue::Int(-12345)));
        assert_eq!(evm_literal_expr, EVMLiteralExpr::Int(-12345));
        let roundtripped = evm_literal_expr.try_to_proof_expr().unwrap();
        assert_eq!(*roundtripped.value(), LiteralValue::Int(-12345));

        // Test BigInt
        let evm_literal_expr =
            EVMLiteralExpr::try_from_proof_expr(&LiteralExpr::new(LiteralValue::BigInt(5)));
        assert_eq!(evm_literal_expr, EVMLiteralExpr::BigInt(5));
        let roundtripped = evm_literal_expr.try_to_proof_expr().unwrap();
        assert_eq!(*roundtripped.value(), LiteralValue::BigInt(5));

        // Test Int128
        let evm_literal_expr = EVMLiteralExpr::try_from_proof_expr(&LiteralExpr::new(
            LiteralValue::Int128(1_234_567_890_123_456_789),
        ));
        assert_eq!(
            evm_literal_expr,
            EVMLiteralExpr::Int128(1_234_567_890_123_456_789)
        );
        let roundtripped = evm_literal_expr.try_to_proof_expr().unwrap();
        assert_eq!(
            *roundtripped.value(),
            LiteralValue::Int128(1_234_567_890_123_456_789)
        );
    }

    #[test]
    fn we_can_put_a_boolean_literal_expr_in_evm() {
        let evm_literal_expr =
            EVMLiteralExpr::try_from_proof_expr(&LiteralExpr::new(LiteralValue::Boolean(true)));
        assert_eq!(evm_literal_expr, EVMLiteralExpr::Boolean(true));

        // Roundtrip
        let roundtripped_literal_expr = evm_literal_expr.try_to_proof_expr().unwrap();
        assert_eq!(
            *roundtripped_literal_expr.value(),
            LiteralValue::Boolean(true)
        );
    }

    #[test]
    fn we_can_put_a_string_literal_expr_in_evm() {
        // Test VarChar
        let test_string = "Hello, SQL World!".to_string();
        let evm_literal_expr = EVMLiteralExpr::try_from_proof_expr(&LiteralExpr::new(
            LiteralValue::VarChar(test_string.clone()),
        ));
        assert_eq!(
            evm_literal_expr,
            EVMLiteralExpr::VarChar(test_string.clone())
        );
        let roundtripped = evm_literal_expr.try_to_proof_expr().unwrap();
        assert_eq!(
            *roundtripped.value(),
            LiteralValue::VarChar(test_string.clone())
        );
    }

    #[test]
    fn we_can_put_a_binary_literal_expr_in_evm() {
        // Test VarBinary
        let test_bytes = vec![0x01, 0x02, 0x03, 0xFF];
        let evm_literal_expr = EVMLiteralExpr::try_from_proof_expr(&LiteralExpr::new(
            LiteralValue::VarBinary(test_bytes.clone()),
        ));
        assert_eq!(
            evm_literal_expr,
            EVMLiteralExpr::VarBinary(test_bytes.clone())
        );
        let roundtripped = evm_literal_expr.try_to_proof_expr().unwrap();
        assert_eq!(
            *roundtripped.value(),
            LiteralValue::VarBinary(test_bytes.clone())
        );
    }

    #[test]
    fn we_can_put_a_decimal_literal_expr_in_evm() {
        // Test Decimal75
        let precision = Precision::new(10).unwrap();
        let scale: i8 = 2;
        let value = I256::from(12345i32); // 123.45 with scale 2

        let evm_literal_expr = EVMLiteralExpr::try_from_proof_expr(&LiteralExpr::new(
            LiteralValue::Decimal75(precision, scale, value),
        ));

        if let EVMLiteralExpr::Decimal75(p, s, limbs) = evm_literal_expr {
            assert_eq!(p, precision.value());
            assert_eq!(s, scale);
            // Use the raw() method to access the private field
            assert_eq!(limbs, value.raw());

            let roundtripped = EVMLiteralExpr::Decimal75(p, s, limbs)
                .try_to_proof_expr()
                .unwrap();
            if let LiteralValue::Decimal75(rp, rs, rv) = *roundtripped.value() {
                assert_eq!(rp.value(), precision.value());
                assert_eq!(rs, scale);
                assert_eq!(rv.raw(), value.raw());
            } else {
                panic!("Expected Decimal75 value after roundtrip");
            }
        } else {
            panic!("Expected Decimal75 variant");
        }
    }

    #[test]
    fn we_can_put_a_scalar_literal_expr_in_evm() {
        // Test Scalar
        let limbs: [u64; 4] = [1, 2, 3, 4];
        let evm_literal_expr =
            EVMLiteralExpr::try_from_proof_expr(&LiteralExpr::new(LiteralValue::Scalar(limbs)));
        assert_eq!(evm_literal_expr, EVMLiteralExpr::Scalar(limbs));
        let roundtripped = evm_literal_expr.try_to_proof_expr().unwrap();
        assert_eq!(*roundtripped.value(), LiteralValue::Scalar(limbs));
    }

    #[test]
    fn we_can_put_a_timestamp_literal_expr_in_evm() {
        // Test TimeStampTZ
        let unit = PoSQLTimeUnit::Millisecond;
        let timezone = PoSQLTimeZone::new(3600); // UTC+1
        let value: i64 = 1_619_712_000_000; // Some timestamp

        let evm_literal_expr = EVMLiteralExpr::try_from_proof_expr(&LiteralExpr::new(
            LiteralValue::TimeStampTZ(unit, timezone, value),
        ));

        if let EVMLiteralExpr::TimeStampTZ(u, tz, ts) = evm_literal_expr {
            assert_eq!(u, 3); // Millisecond = 3
            assert_eq!(tz, 3600); // UTC+1 = 3600 seconds
            assert_eq!(ts, value);

            let roundtripped = EVMLiteralExpr::TimeStampTZ(u, tz, ts)
                .try_to_proof_expr()
                .unwrap();
            if let LiteralValue::TimeStampTZ(ru, rtz, rts) = *roundtripped.value() {
                assert_eq!(ru, PoSQLTimeUnit::Millisecond);
                assert_eq!(rtz.offset(), 3600);
                assert_eq!(rts, value);
            } else {
                panic!("Expected TimeStampTZ value after roundtrip");
            }
        } else {
            panic!("Expected TimeStampTZ variant");
        }

        // Test another TimeStampTZ with different unit and timezone
        let unit2 = PoSQLTimeUnit::Nanosecond;
        let timezone2 = PoSQLTimeZone::new(-7200); // UTC-2
        let value2: i64 = 1_619_712_000_000_000_000; // Some timestamp in nanoseconds

        let evm_literal_expr2 = EVMLiteralExpr::try_from_proof_expr(&LiteralExpr::new(
            LiteralValue::TimeStampTZ(unit2, timezone2, value2),
        ));

        if let EVMLiteralExpr::TimeStampTZ(u, tz, ts) = evm_literal_expr2 {
            assert_eq!(u, 9); // Nanosecond = 9
            assert_eq!(tz, -7200); // UTC-2 = -7200 seconds
            assert_eq!(ts, value2);
        } else {
            panic!("Expected TimeStampTZ variant");
        }
    }

    #[test]
    fn we_cannot_put_an_invalid_time_unit_in_evm() {
        // Create an EVMLiteralExpr with an invalid time unit value
        let invalid_unit_value: u64 = 2; // Not one of the valid units: 0, 3, 6, 9
        let timezone_offset = 0;
        let timestamp_value: i64 = 1_619_712_000_000;

        let evm_literal_expr =
            EVMLiteralExpr::TimeStampTZ(invalid_unit_value, timezone_offset, timestamp_value);

        // This should return an InvalidTimeUnit error
        let result = evm_literal_expr.try_to_proof_expr();
        assert_eq!(result, Err(EVMProofPlanError::InvalidTimeUnit));
    }

    #[test]
    fn we_cannot_put_an_invalid_decimal_precision_in_evm() {
        // Case 1: Precision 0 (too small)
        let invalid_precision: u8 = 0;
        let scale: i8 = 2;
        let limbs = [1234, 0, 0, 0]; // Some valid limbs

        let evm_literal_expr = EVMLiteralExpr::Decimal75(invalid_precision, scale, limbs);

        // This should return a DecimalError
        let result = evm_literal_expr.try_to_proof_expr();
        assert!(
            matches!(result, Err(EVMProofPlanError::DecimalError { source }) if source == DecimalError::InvalidPrecision { error: "0".to_string() })
        );

        // Case 2: Precision 76 (too large)
        let invalid_precision: u8 = 76;
        let evm_literal_expr = EVMLiteralExpr::Decimal75(invalid_precision, scale, limbs);

        // This should also return a DecimalError
        let result = evm_literal_expr.try_to_proof_expr();
        assert!(
            matches!(result, Err(EVMProofPlanError::DecimalError { source }) if source == DecimalError::InvalidPrecision { error: "76".to_string() })
        );
    }

    // EVMEqualsExpr
    #[test]
    fn we_can_put_an_equals_expr_in_evm() {
        let table_ref: TableRef = TableRef::try_from("namespace.table").unwrap();
        let ident_a = "a".into();
        let ident_b = "b".into();
        let column_ref_a = ColumnRef::new(table_ref.clone(), ident_a, ColumnType::BigInt);
        let column_ref_b = ColumnRef::new(table_ref.clone(), ident_b, ColumnType::BigInt);

        let equals_expr = EqualsExpr::try_new(
            Box::new(DynProofExpr::new_column(column_ref_b.clone())),
            Box::new(DynProofExpr::new_literal(LiteralValue::BigInt(5))),
        )
        .unwrap();

        let evm_equals_expr = EVMEqualsExpr::try_from_proof_expr(
            &equals_expr,
            &indexset! {column_ref_a.clone(), column_ref_b.clone()},
        )
        .unwrap();
        assert_eq!(
            evm_equals_expr,
            EVMEqualsExpr {
                lhs: Box::new(EVMDynProofExpr::Column(EVMColumnExpr { column_number: 1 })),
                rhs: Box::new(EVMDynProofExpr::Literal(EVMLiteralExpr::BigInt(5)))
            }
        );

        // Roundtrip
        let roundtripped_equals_expr = evm_equals_expr
            .try_into_proof_expr(&indexset! {column_ref_a.clone(), column_ref_b.clone()})
            .unwrap();
        assert_eq!(roundtripped_equals_expr, equals_expr);
    }

    // EVMAddExpr
    #[test]
    fn we_can_put_an_add_expr_in_evm() {
        let table_ref: TableRef = TableRef::try_from("namespace.table").unwrap();
        let ident_a = "a".into();
        let ident_b = "b".into();
        let column_ref_a = ColumnRef::new(table_ref.clone(), ident_a, ColumnType::BigInt);
        let column_ref_b = ColumnRef::new(table_ref.clone(), ident_b, ColumnType::BigInt);

        let add_expr = AddExpr::try_new(
            Box::new(DynProofExpr::new_column(column_ref_b.clone())),
            Box::new(DynProofExpr::new_literal(LiteralValue::BigInt(5))),
        )
        .unwrap();

        let evm_add_expr = EVMAddExpr::try_from_proof_expr(
            &add_expr,
            &indexset! {column_ref_a.clone(), column_ref_b.clone()},
        )
        .unwrap();
        assert_eq!(
            evm_add_expr,
            EVMAddExpr::new(
                EVMDynProofExpr::Column(EVMColumnExpr { column_number: 1 }),
                EVMDynProofExpr::Literal(EVMLiteralExpr::BigInt(5))
            )
        );

        // Roundtrip
        let roundtripped_add_expr = evm_add_expr
            .try_into_proof_expr(&indexset! {column_ref_a.clone(), column_ref_b.clone()})
            .unwrap();
        assert_eq!(roundtripped_add_expr, add_expr);
    }

    // EVMSubtractExpr
    #[test]
    fn we_can_put_a_subtract_expr_in_evm() {
        let table_ref: TableRef = TableRef::try_from("namespace.table").unwrap();
        let ident_a = "a".into();
        let ident_b = "b".into();
        let column_ref_a = ColumnRef::new(table_ref.clone(), ident_a, ColumnType::BigInt);
        let column_ref_b = ColumnRef::new(table_ref.clone(), ident_b, ColumnType::BigInt);

        let subtract_expr = SubtractExpr::try_new(
            Box::new(DynProofExpr::new_column(column_ref_b.clone())),
            Box::new(DynProofExpr::new_literal(LiteralValue::BigInt(5))),
        )
        .unwrap();

        let evm_subtract_expr = EVMSubtractExpr::try_from_proof_expr(
            &subtract_expr,
            &indexset! {column_ref_a.clone(), column_ref_b.clone()},
        )
        .unwrap();
        assert_eq!(
            evm_subtract_expr,
            EVMSubtractExpr::new(
                EVMDynProofExpr::Column(EVMColumnExpr { column_number: 1 }),
                EVMDynProofExpr::Literal(EVMLiteralExpr::BigInt(5))
            )
        );

        // Roundtrip
        let roundtripped_subtract_expr = evm_subtract_expr
            .try_into_proof_expr(&indexset! {column_ref_a.clone(), column_ref_b.clone()})
            .unwrap();
        assert_eq!(roundtripped_subtract_expr, subtract_expr);
    }

    // EVMMultiplyExpr
    #[test]
    fn we_can_put_a_multiply_expr_in_evm() {
        let table_ref: TableRef = TableRef::try_from("namespace.table").unwrap();
        let ident_a = "a".into();
        let ident_b = "b".into();
        let column_ref_a = ColumnRef::new(table_ref.clone(), ident_a, ColumnType::BigInt);
        let column_ref_b = ColumnRef::new(table_ref.clone(), ident_b, ColumnType::BigInt);

        // b * 10 so we see column_number = 1
        let multiply_expr = MultiplyExpr::try_new(
            Box::new(DynProofExpr::new_column(column_ref_b.clone())),
            Box::new(DynProofExpr::new_literal(LiteralValue::BigInt(10))),
        )
        .unwrap();

        let evm_multiply_expr = EVMMultiplyExpr::try_from_proof_expr(
            &multiply_expr,
            &indexset! { column_ref_a.clone(), column_ref_b.clone() },
        )
        .unwrap();
        assert_eq!(
            evm_multiply_expr,
            EVMMultiplyExpr::new(
                EVMDynProofExpr::Column(EVMColumnExpr { column_number: 1 }),
                EVMDynProofExpr::Literal(EVMLiteralExpr::BigInt(10))
            )
        );

        // Roundtrip
        let roundtripped = evm_multiply_expr
            .try_into_proof_expr(&indexset! { column_ref_a, column_ref_b })
            .unwrap();
        assert_eq!(roundtripped, multiply_expr);
    }

    #[test]
    fn we_cannot_get_a_multiply_expr_from_evm_if_column_number_out_of_bounds() {
        let evm_column_expr = EVMMultiplyExpr::new(
            EVMDynProofExpr::Column(EVMColumnExpr { column_number: 0 }),
            EVMDynProofExpr::Column(EVMColumnExpr { column_number: 1 }),
        );
        let column_refs = IndexSet::<ColumnRef>::default();
        assert_eq!(
            evm_column_expr
                .try_into_proof_expr(&column_refs)
                .unwrap_err(),
            EVMProofPlanError::ColumnNotFound
        );
    }

    // EVMAndExpr
    #[test]
    fn we_can_put_an_and_expr_in_evm() {
        let table_ref: TableRef = TableRef::try_from("namespace.table").unwrap();
        let ident_x = "x".into();
        let ident_y = "y".into();
        let column_ref_x = ColumnRef::new(table_ref.clone(), ident_x, ColumnType::Boolean);
        let column_ref_y = ColumnRef::new(table_ref.clone(), ident_y, ColumnType::Boolean);

        let and_expr = AndExpr::try_new(
            Box::new(DynProofExpr::new_column(column_ref_x.clone())),
            Box::new(DynProofExpr::new_column(column_ref_y.clone())),
        )
        .unwrap();

        let evm_and_expr = EVMAndExpr::try_from_proof_expr(
            &and_expr,
            &indexset! { column_ref_x.clone(), column_ref_y.clone() },
        )
        .unwrap();
        assert_eq!(
            evm_and_expr,
            EVMAndExpr::new(
                EVMDynProofExpr::Column(EVMColumnExpr { column_number: 0 }),
                EVMDynProofExpr::Column(EVMColumnExpr { column_number: 1 })
            )
        );

        // Roundtrip
        let roundtripped = evm_and_expr
            .try_into_proof_expr(&indexset! { column_ref_x, column_ref_y })
            .unwrap();
        assert_eq!(roundtripped, and_expr);
    }

    #[test]
    fn we_cannot_get_an_and_expr_from_evm_if_column_number_out_of_bounds() {
        let evm_and_expr = EVMAndExpr::new(
            EVMDynProofExpr::Column(EVMColumnExpr { column_number: 0 }),
            EVMDynProofExpr::Column(EVMColumnExpr { column_number: 1 }),
        );
        let column_refs = IndexSet::<ColumnRef>::default();
        assert_eq!(
            evm_and_expr.try_into_proof_expr(&column_refs).unwrap_err(),
            EVMProofPlanError::ColumnNotFound
        );
    }

    // EVMOrExpr
    #[test]
    fn we_can_put_an_or_expr_in_evm() {
        let table_ref: TableRef = TableRef::try_from("namespace.table").unwrap();
        let ident_x = "x".into();
        let ident_y = "y".into();
        let column_ref_x = ColumnRef::new(table_ref.clone(), ident_x, ColumnType::Boolean);
        let column_ref_y = ColumnRef::new(table_ref.clone(), ident_y, ColumnType::Boolean);

        let or_expr = OrExpr::try_new(
            Box::new(DynProofExpr::new_column(column_ref_x.clone())),
            Box::new(DynProofExpr::new_column(column_ref_y.clone())),
        )
        .unwrap();

        let evm_or_expr = EVMOrExpr::try_from_proof_expr(
            &or_expr,
            &indexset! { column_ref_x.clone(), column_ref_y.clone() },
        )
        .unwrap();
        assert_eq!(
            evm_or_expr,
            EVMOrExpr::new(
                EVMDynProofExpr::Column(EVMColumnExpr { column_number: 0 }),
                EVMDynProofExpr::Column(EVMColumnExpr { column_number: 1 })
            )
        );

        // Roundtrip
        let roundtripped = evm_or_expr
            .try_into_proof_expr(&indexset! { column_ref_x, column_ref_y })
            .unwrap();
        assert_eq!(roundtripped, or_expr);
    }

    #[test]
    fn we_cannot_get_an_or_expr_from_evm_if_column_number_out_of_bounds() {
        let evm_or_expr = EVMOrExpr::new(
            EVMDynProofExpr::Column(EVMColumnExpr { column_number: 0 }),
            EVMDynProofExpr::Column(EVMColumnExpr { column_number: 1 }),
        );
        let column_refs = IndexSet::<ColumnRef>::default();
        assert_eq!(
            evm_or_expr.try_into_proof_expr(&column_refs).unwrap_err(),
            EVMProofPlanError::ColumnNotFound
        );
    }

    // EVMNotExpr
    #[test]
    fn we_can_put_a_not_expr_in_evm() {
        let table_ref: TableRef = TableRef::try_from("namespace.table").unwrap();
        let ident_flag = "flag".into();
        let column_ref_flag = ColumnRef::new(table_ref.clone(), ident_flag, ColumnType::Boolean);

        let not_expr =
            NotExpr::try_new(Box::new(DynProofExpr::new_column(column_ref_flag.clone()))).unwrap();

        let evm_not_expr =
            EVMNotExpr::try_from_proof_expr(&not_expr, &indexset! { column_ref_flag.clone() })
                .unwrap();
        assert_eq!(
            evm_not_expr,
            EVMNotExpr::new(EVMDynProofExpr::Column(EVMColumnExpr { column_number: 0 }))
        );

        // Roundtrip
        let roundtripped = evm_not_expr
            .try_into_proof_expr(&indexset! { column_ref_flag })
            .unwrap();
        assert_eq!(roundtripped, not_expr);
    }

    #[test]
    fn we_cannot_get_a_not_expr_from_evm_if_column_number_out_of_bounds() {
        let evm_not_expr =
            EVMNotExpr::new(EVMDynProofExpr::Column(EVMColumnExpr { column_number: 0 }));
        let column_refs = IndexSet::<ColumnRef>::default();
        assert_eq!(
            evm_not_expr.try_into_proof_expr(&column_refs).unwrap_err(),
            EVMProofPlanError::ColumnNotFound
        );
    }

    // EVMDynProofExpr
    #[test]
    fn we_can_put_into_evm_a_dyn_proof_expr_equals_expr() {
        let table_ref = TableRef::try_from("namespace.table").unwrap();
        let column_b = ColumnRef::new(table_ref.clone(), "b".into(), ColumnType::BigInt);

        let expr = equal(
            DynProofExpr::new_literal(LiteralValue::BigInt(5)),
            DynProofExpr::new_column(column_b.clone()),
        );
        let evm =
            EVMDynProofExpr::try_from_proof_expr(&expr, &indexset! { column_b.clone() }).unwrap();
        let expected = EVMDynProofExpr::Equals(EVMEqualsExpr {
            lhs: Box::new(EVMDynProofExpr::Literal(EVMLiteralExpr::BigInt(5))),
            rhs: Box::new(EVMDynProofExpr::Column(EVMColumnExpr { column_number: 0 })),
        });
        assert_eq!(evm, expected);
        assert_eq!(
            evm.try_into_proof_expr(&indexset! { column_b }).unwrap(),
            expr
        );
    }

    #[test]
    fn we_can_put_into_evm_a_dyn_proof_expr_add_expr() {
        let table_ref = TableRef::try_from("namespace.table").unwrap();
        let column_b = ColumnRef::new(table_ref.clone(), "b".into(), ColumnType::BigInt);

        let expr = add(
            DynProofExpr::new_column(column_b.clone()),
            DynProofExpr::new_literal(LiteralValue::BigInt(3)),
        );
        let evm =
            EVMDynProofExpr::try_from_proof_expr(&expr, &indexset! { column_b.clone() }).unwrap();
        let expected = EVMDynProofExpr::Add(EVMAddExpr::new(
            EVMDynProofExpr::Column(EVMColumnExpr { column_number: 0 }),
            EVMDynProofExpr::Literal(EVMLiteralExpr::BigInt(3)),
        ));
        assert_eq!(evm, expected);
        assert_eq!(
            evm.try_into_proof_expr(&indexset! { column_b }).unwrap(),
            expr
        );
    }

    #[test]
    fn we_can_put_into_evm_a_dyn_proof_expr_subtract_expr() {
        let table_ref = TableRef::try_from("namespace.table").unwrap();
        let column_b = ColumnRef::new(table_ref.clone(), "b".into(), ColumnType::BigInt);

        let expr = subtract(
            DynProofExpr::new_column(column_b.clone()),
            DynProofExpr::new_literal(LiteralValue::BigInt(2)),
        );
        let evm =
            EVMDynProofExpr::try_from_proof_expr(&expr, &indexset! { column_b.clone() }).unwrap();
        let expected = EVMDynProofExpr::Subtract(EVMSubtractExpr::new(
            EVMDynProofExpr::Column(EVMColumnExpr { column_number: 0 }),
            EVMDynProofExpr::Literal(EVMLiteralExpr::BigInt(2)),
        ));
        assert_eq!(evm, expected);
        assert_eq!(
            evm.try_into_proof_expr(&indexset! { column_b }).unwrap(),
            expr
        );
    }

    #[test]
    fn we_can_put_into_evm_a_dyn_proof_expr_multiply_expr() {
        let table_ref = TableRef::try_from("namespace.table").unwrap();
        let column_b = ColumnRef::new(table_ref.clone(), "b".into(), ColumnType::BigInt);

        let expr = multiply(
            DynProofExpr::new_column(column_b.clone()),
            DynProofExpr::new_literal(LiteralValue::BigInt(4)),
        );
        let evm =
            EVMDynProofExpr::try_from_proof_expr(&expr, &indexset! { column_b.clone() }).unwrap();
        let expected = EVMDynProofExpr::Multiply(EVMMultiplyExpr::new(
            EVMDynProofExpr::Column(EVMColumnExpr { column_number: 0 }),
            EVMDynProofExpr::Literal(EVMLiteralExpr::BigInt(4)),
        ));
        assert_eq!(evm, expected);
        assert_eq!(
            evm.try_into_proof_expr(&indexset! { column_b }).unwrap(),
            expr
        );
    }

    #[test]
    fn we_can_put_into_evm_a_dyn_proof_expr_and_expr() {
        let table_ref = TableRef::try_from("namespace.table").unwrap();
        let c = ColumnRef::new(table_ref.clone(), "c".into(), ColumnType::Boolean);
        let d = ColumnRef::new(table_ref.clone(), "d".into(), ColumnType::Boolean);

        let expr = and(
            DynProofExpr::new_column(c.clone()),
            DynProofExpr::new_column(d.clone()),
        );
        let evm = EVMDynProofExpr::try_from_proof_expr(&expr, &indexset! { c.clone(), d.clone() })
            .unwrap();
        let expected = EVMDynProofExpr::And(EVMAndExpr::new(
            EVMDynProofExpr::Column(EVMColumnExpr { column_number: 0 }),
            EVMDynProofExpr::Column(EVMColumnExpr { column_number: 1 }),
        ));
        assert_eq!(evm, expected);
        assert_eq!(evm.try_into_proof_expr(&indexset! { c, d }).unwrap(), expr);
    }

    #[test]
    fn we_can_put_into_evm_a_dyn_proof_expr_or_expr() {
        let table_ref = TableRef::try_from("namespace.table").unwrap();
        let c = ColumnRef::new(table_ref.clone(), "c".into(), ColumnType::Boolean);
        let d = ColumnRef::new(table_ref.clone(), "d".into(), ColumnType::Boolean);

        let expr = or(
            DynProofExpr::new_column(c.clone()),
            DynProofExpr::new_column(d.clone()),
        );
        let evm = EVMDynProofExpr::try_from_proof_expr(&expr, &indexset! { c.clone(), d.clone() })
            .unwrap();
        let expected = EVMDynProofExpr::Or(EVMOrExpr::new(
            EVMDynProofExpr::Column(EVMColumnExpr { column_number: 0 }),
            EVMDynProofExpr::Column(EVMColumnExpr { column_number: 1 }),
        ));
        assert_eq!(evm, expected);
        assert_eq!(evm.try_into_proof_expr(&indexset! { c, d }).unwrap(), expr);
    }

    #[test]
    fn we_can_put_into_evm_a_dyn_proof_expr_not_expr() {
        let table_ref = TableRef::try_from("namespace.table").unwrap();
        let c = ColumnRef::new(table_ref.clone(), "c".into(), ColumnType::Boolean);

        let expr = not(DynProofExpr::new_column(c.clone()));
        let evm = EVMDynProofExpr::try_from_proof_expr(&expr, &indexset! { c.clone() }).unwrap();
        let expected =
            EVMDynProofExpr::Not(EVMNotExpr::new(EVMDynProofExpr::Column(EVMColumnExpr {
                column_number: 0,
            })));
        assert_eq!(evm, expected);
        assert_eq!(evm.try_into_proof_expr(&indexset! { c }).unwrap(), expr);
    }

    // Unsupported expressions
    #[test]
    fn we_cannot_put_a_proof_expr_in_evm_if_not_supported() {
        let table_ref: TableRef = TableRef::try_from("namespace.table").unwrap();
        let ident_a = "a".into();
        let ident_b = "b".into();
        let column_ref_a = ColumnRef::new(table_ref.clone(), ident_a, ColumnType::Boolean);
        let column_ref_b = ColumnRef::new(table_ref.clone(), ident_b, ColumnType::Boolean);

        assert!(matches!(
            EVMDynProofExpr::try_from_proof_expr(
                &DynProofExpr::try_new_inequality(
                    DynProofExpr::new_column(column_ref_a.clone()),
                    DynProofExpr::new_column(column_ref_b.clone()),
                    false,
                )
                .unwrap(),
                &indexset! {column_ref_a.clone(), column_ref_b.clone()}
            ),
            Err(EVMProofPlanError::NotSupported)
        ));
    }
}
