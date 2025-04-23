use indexmap::IndexMap;
use proof_of_sql::base::{
    commitment::CommitmentEvaluationProof,
    database::{Table, TableRef, TableTestAccessor, TestAccessor},
};

/// Get a new `TableTestAccessor` with the provided tables
pub fn new_test_accessor<'a, CP: CommitmentEvaluationProof>(
    tables: &IndexMap<TableRef, Table<'a, CP::Scalar>>,
    prover_setup: CP::ProverPublicSetup<'a>,
) -> TableTestAccessor<'a, CP> {
    let mut accessor = TableTestAccessor::<CP>::new_empty_with_setup(prover_setup);
    for (table_ref, table) in tables {
        accessor.add_table(table_ref.clone(), table.clone(), 0);
    }
    accessor
}
