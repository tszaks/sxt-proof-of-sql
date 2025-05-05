// SPDX-License-Identifier: UNLICENSED
// This is licensed under the Cryptographic Open Software License 1.0
pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import "../../src/base/DataType.pre.sol";
import "../base/Constants.t.sol";
import {FF, F} from "../base/FieldUtil.sol";

contract DataTypeTest is Test {
    function testVariantsMatchEnum() public pure {
        assert(uint32(DataType.DataTypeKind.BigInt) == DATA_TYPE_BIGINT_VARIANT);
    }

    function testReadNonnegativeEntryExpr() public pure {
        bytes memory exprIn = abi.encodePacked(int64(9223372036854775807), hex"abcdef");
        bytes memory expectedExprOut = hex"abcdef";
        (bytes memory exprOut, uint256 entry) = DataType.__readEntry(exprIn, DATA_TYPE_BIGINT_VARIANT);
        assert(entry == 9223372036854775807);
        assert(exprOut.length == expectedExprOut.length);
        uint256 exprOutLength = exprOut.length;
        for (uint256 i = 0; i < exprOutLength; ++i) {
            assert(exprOut[i] == expectedExprOut[i]);
        }
    }

    function testReadNegativeEntryExpr() public pure {
        bytes memory exprIn = abi.encodePacked(int64(-9223372036854775808), hex"abcdef");
        bytes memory expectedExprOut = hex"abcdef";
        (bytes memory exprOut, uint256 entry) = DataType.__readEntry(exprIn, DATA_TYPE_BIGINT_VARIANT);
        assert(entry == MODULUS - 9223372036854775808);
        assert(exprOut.length == expectedExprOut.length);
        uint256 exprOutLength = exprOut.length;
        for (uint256 i = 0; i < exprOutLength; ++i) {
            assert(exprOut[i] == expectedExprOut[i]);
        }
    }

    function testFuzzReadEntryExpr(int64 literalValue, bytes memory trailingExpr) public pure {
        bytes memory exprIn = abi.encodePacked(literalValue, trailingExpr);
        (bytes memory exprOut, uint256 entry) = DataType.__readEntry(exprIn, DATA_TYPE_BIGINT_VARIANT);
        uint256 expected = F.from(literalValue).into();
        assert(entry == expected);
        assert(exprOut.length == trailingExpr.length);
        uint256 exprOutLength = exprOut.length;
        for (uint256 i = 0; i < exprOutLength; ++i) {
            assert(exprOut[i] == trailingExpr[i]);
        }
    }

    function testReadEntryWithInvalidVariant() public {
        bytes memory exprIn = abi.encodePacked(int64(9223372036854775807), hex"abcdef");
        vm.expectRevert(Errors.UnsupportedDataTypeVariant.selector);
        DataType.__readEntry(exprIn, INVALID_VARIANT);
    }

    function testReadDataType() public pure {
        bytes memory exprIn = abi.encodePacked(DATA_TYPE_BIGINT_VARIANT, hex"abcdef");
        bytes memory expectedExprOut = hex"abcdef";
        (bytes memory exprOut, uint32 dataType) = DataType.__readDataType(exprIn);
        assert(dataType == DATA_TYPE_BIGINT_VARIANT);
        assert(exprOut.length == expectedExprOut.length);
        uint256 exprOutLength = exprOut.length;
        for (uint256 i = 0; i < exprOutLength; ++i) {
            assert(exprOut[i] == expectedExprOut[i]);
        }
    }

    function testReadDataTypeWithInvalidVariant() public {
        bytes memory exprIn = abi.encodePacked(INVALID_VARIANT, hex"abcdef");
        vm.expectRevert(Errors.UnsupportedDataTypeVariant.selector);
        DataType.__readDataType(exprIn);
    }
}
