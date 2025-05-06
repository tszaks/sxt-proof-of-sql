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
                case 5 {
                    case_const(5, DATA_TYPE_BIGINT_VARIANT)
                    entry :=
                        add(MODULUS, signextend(INT64_SIZE_MINUS_ONE, shr(INT64_PADDING_BITS, calldataload(result_ptr))))
                    result_ptr_out := add(result_ptr, INT64_SIZE)
                    entry := mod(entry, MODULUS)
                }
                default { err(ERR_UNSUPPORTED_DATA_TYPE_VARIANT) }
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
                case 5 { case_const(5, DATA_TYPE_BIGINT_VARIANT) }
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
