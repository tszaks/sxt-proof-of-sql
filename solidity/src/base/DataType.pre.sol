// SPDX-License-Identifier: UNLICENSED
// This is licensed under the Cryptographic Open Software License 1.0
pragma solidity ^0.8.28;

import "./Constants.sol";
import "./SwitchUtil.pre.sol";

/// @title DataType
/// @dev Library providing parsing utilities for different data types
library DataType {
    /// @notice Reads a data entry based on the data type variant
    /// @custom:as-yul-wrapper
    /// #### Wrapped Yul Function
    /// ##### Signature
    /// ```yul
    /// function read_entry(result_ptr, data_type_variant) -> result_ptr_out, entry
    /// ```
    /// ##### Parameters
    /// * `result_ptr` - the pointer to the result data
    /// * `data_type_variant` - the data type variant
    /// @dev Returns the entry value and updated result pointer
    /// @param __expr The pointer to the result data
    /// @param __dataTypeVariant The data type variant
    /// @return __exprOut The updated result pointer
    /// @return __entry The entry value
    function __readEntry(bytes calldata __expr, uint256 __dataTypeVariant)
        external
        pure
        returns (bytes calldata __exprOut, uint256 __entry)
    {
        assembly {
            // IMPORT-YUL Errors.sol
            function err(code) {
                revert(0, 0)
            }
            // IMPORT-YUL SwitchUtil.pre.sol
            function case_const(lhs, rhs) {
                revert(0, 0)
            }
            function read_entry(result_ptr, data_type_variant) -> result_ptr_out, entry {
                result_ptr_out := result_ptr
                switch data_type_variant
                case 0 {
                    case_const(0, DATA_TYPE_BOOLEAN_VARIANT)
                    entry := shr(BOOLEAN_PADDING_BITS, calldataload(result_ptr))
                    if shr(1, entry) { err(ERR_INVALID_BOOLEAN) }
                    result_ptr_out := add(result_ptr, BOOLEAN_SIZE)
                }
                case 2 {
                    case_const(2, DATA_TYPE_TINYINT_VARIANT)
                    entry :=
                        add(MODULUS, signextend(INT8_SIZE_MINUS_ONE, shr(INT8_PADDING_BITS, calldataload(result_ptr))))
                    result_ptr_out := add(result_ptr, INT8_SIZE)
                }
                case 3 {
                    case_const(3, DATA_TYPE_SMALLINT_VARIANT)
                    entry :=
                        add(MODULUS, signextend(INT16_SIZE_MINUS_ONE, shr(INT16_PADDING_BITS, calldataload(result_ptr))))
                    result_ptr_out := add(result_ptr, INT16_SIZE)
                }
                case 4 {
                    case_const(4, DATA_TYPE_INT_VARIANT)
                    entry :=
                        add(MODULUS, signextend(INT32_SIZE_MINUS_ONE, shr(INT32_PADDING_BITS, calldataload(result_ptr))))
                    result_ptr_out := add(result_ptr, INT32_SIZE)
                }
                case 5 {
                    case_const(5, DATA_TYPE_BIGINT_VARIANT)
                    entry :=
                        add(MODULUS, signextend(INT64_SIZE_MINUS_ONE, shr(INT64_PADDING_BITS, calldataload(result_ptr))))
                    result_ptr_out := add(result_ptr, INT64_SIZE)
                }
                case 8 {
                    case_const(8, DATA_TYPE_DECIMAL75_VARIANT)
                    entry := calldataload(result_ptr)
                    result_ptr_out := add(result_ptr, WORD_SIZE)
                }
                case 9 {
                    case_const(9, DATA_TYPE_TIMESTAMP_VARIANT)
                    entry :=
                        add(MODULUS, signextend(INT64_SIZE_MINUS_ONE, shr(INT64_PADDING_BITS, calldataload(result_ptr))))
                    result_ptr_out := add(result_ptr, INT64_SIZE)
                }
                default { err(ERR_UNSUPPORTED_DATA_TYPE_VARIANT) }
                entry := mod(entry, MODULUS)
            }
            let __exprOutOffset
            __exprOutOffset, __entry := read_entry(__expr.offset, __dataTypeVariant)
            __exprOut.offset := __exprOutOffset
            // slither-disable-next-line write-after-write
            __exprOut.length := sub(__expr.length, sub(__exprOutOffset, __expr.offset))
        }
    }

    /// @notice Reads data type from the input bytes
    /// @custom:as-yul-wrapper
    /// #### Wrapped Yul Function
    /// ##### Signature
    /// ```yul
    /// function read_data_type(ptr) -> ptr_out, data_type
    /// ```
    /// ##### Parameters
    /// * `ptr` - the pointer to the input data
    /// @dev Returns the data type and updated pointer
    /// @param __expr The input bytes containing the data type
    /// @return __exprOut The remaining bytes after reading the data type
    /// @return __dataType The extracted data type value
    function __readDataType(bytes calldata __expr)
        external
        pure
        returns (bytes calldata __exprOut, uint32 __dataType)
    {
        assembly {
            // IMPORT-YUL Errors.sol
            function err(code) {
                revert(0, 0)
            }
            // IMPORT-YUL SwitchUtil.pre.sol
            function case_const(lhs, rhs) {
                revert(0, 0)
            }
            function read_data_type(ptr) -> ptr_out, data_type {
                data_type := shr(UINT32_PADDING_BITS, calldataload(ptr))
                ptr_out := add(ptr, UINT32_SIZE)
                switch data_type
                case 0 { case_const(0, DATA_TYPE_BOOLEAN_VARIANT) }
                case 2 { case_const(2, DATA_TYPE_TINYINT_VARIANT) }
                case 3 { case_const(3, DATA_TYPE_SMALLINT_VARIANT) }
                case 4 { case_const(4, DATA_TYPE_INT_VARIANT) }
                case 5 { case_const(5, DATA_TYPE_BIGINT_VARIANT) }
                case 8 {
                    case_const(8, DATA_TYPE_DECIMAL75_VARIANT)
                    ptr_out := add(ptr_out, UINT8_SIZE) // Skip precision
                    ptr_out := add(ptr_out, INT8_SIZE) // Skip scale
                }
                case 9 {
                    case_const(9, DATA_TYPE_TIMESTAMP_VARIANT)
                    ptr_out := add(ptr_out, UINT32_SIZE) // Skip timeunit
                    ptr_out := add(ptr_out, INT32_SIZE) // Skip timezone
                }
                default { err(ERR_UNSUPPORTED_DATA_TYPE_VARIANT) }
            }

            let __exprOutOffset
            __exprOutOffset, __dataType := read_data_type(__expr.offset)
            __exprOut.offset := __exprOutOffset
            // slither-disable-next-line write-after-write
            __exprOut.length := sub(__expr.length, sub(__exprOutOffset, __expr.offset))
        }
    }
}
