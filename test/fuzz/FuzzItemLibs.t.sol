// SPDX-License-Identifier: MIT
pragma solidity 0.8.33;

import "forge-std/Test.sol";
import {ItemDetail, ItemSpec, ItemDetailLib, ItemSpecLib, MatchingLib} from "../../src/JJSKIN.sol";

/// @title FuzzItemLibs
/// @notice Fuzz tests for ItemDetail, ItemSpec, and MatchingLib bit-packing round-trips
contract FuzzItemLibs is Test {
    using ItemDetailLib for ItemDetail;
    using ItemSpecLib for ItemSpec;

    // ========== ItemDetail Standard Round-Trip ==========

    /// @notice All 6 standard-mode fields survive encode -> decode
    function testFuzz_ItemDetail_roundTrip(
        uint16 paintIndex,
        uint32 floatValue,
        uint16 defindex,
        uint16 paintSeed,
        uint8 patternTier,
        uint8 quality
    ) public pure {
        // Bound to actual bit widths
        floatValue = uint32(bound(floatValue, 0, 0xFFFFF));   // 20 bits
        defindex = uint16(bound(defindex, 0, 0x1FFF));         // 13 bits
        paintSeed = uint16(bound(paintSeed, 0, 0x3FF));        // 10 bits
        patternTier = uint8(bound(patternTier, 0, 7));         // 3 bits
        quality = uint8(bound(quality, 0, 3));                 // 2 bits

        // Skip extended mode marker
        vm.assume(paintSeed != 1023);

        ItemDetail detail = ItemDetailLib.encode(
            paintIndex, floatValue, defindex, paintSeed, patternTier, quality
        );

        ItemDetailLib.Decoded memory d = ItemDetailLib.decode(detail);

        assertEq(d.paintIndex, paintIndex, "paintIndex mismatch");
        assertEq(d.floatValue, floatValue, "floatValue mismatch");
        assertEq(d.defindex, defindex, "defindex mismatch");
        assertEq(d.paintSeed, paintSeed, "paintSeed mismatch");
        assertEq(d.patternTier, patternTier, "patternTier mismatch");
        assertEq(d.quality, quality, "quality mismatch");
    }

    // ========== ItemDetail Extended Round-Trip ==========

    /// @notice 28-bit defindex + tintId survive extended mode round-trip
    function testFuzz_ItemDetail_extendedRoundTrip(
        uint32 defindex,
        uint8 tintId,
        uint8 quality
    ) public pure {
        defindex = uint32(bound(defindex, 0, ItemDetailLib.MAX_EXTENDED_DEFINDEX));
        tintId = uint8(bound(tintId, 0, 31));  // 5 bits
        quality = uint8(bound(quality, 0, 3));  // 2 bits

        ItemDetail detail = ItemDetailLib.encodeExtended(defindex, tintId, quality);

        assertTrue(ItemDetailLib.isExtendedMode(detail), "should be extended mode");

        ItemDetailLib.ExtendedDecoded memory d = ItemDetailLib.decodeExtended(detail);

        assertEq(d.defindex, defindex, "extended defindex mismatch");
        assertEq(d.tintId, tintId, "tintId mismatch");
        assertEq(d.quality, quality, "extended quality mismatch");
    }

    // ========== ItemDetail Extended Boundary ==========

    /// @notice defindex > 8191 works correctly in extended mode
    function testFuzz_ItemDetail_extendedBoundary(uint32 defindex) public pure {
        defindex = uint32(bound(defindex, 8192, ItemDetailLib.MAX_EXTENDED_DEFINDEX));

        ItemDetail detail = ItemDetailLib.encodeExtended(defindex, 0, 0);

        assertTrue(ItemDetailLib.isExtendedMode(detail), "should be extended mode");
        assertEq(ItemDetailLib.getExtendedDefindex(detail), defindex, "boundary defindex mismatch");
    }

    // ========== ItemSpec Round-Trip ==========

    /// @notice All spec fields survive encode -> decode
    function testFuzz_ItemSpec_roundTrip(
        uint16 paintIndex,
        uint16 minFloat,
        uint16 maxFloat,
        uint16 defindex,
        uint8 patternTier,
        uint8 quality
    ) public pure {
        minFloat = uint16(bound(minFloat, 0, 0x3FF));     // 10 bits
        maxFloat = uint16(bound(maxFloat, 0, 0x3FF));     // 10 bits
        defindex = uint16(bound(defindex, 0, 0x1FFF));    // 13 bits
        patternTier = uint8(bound(patternTier, 0, 7));    // 3 bits
        quality = uint8(bound(quality, 0, 3));             // 2 bits

        ItemSpec spec = ItemSpecLib.encode(
            paintIndex, minFloat, maxFloat, defindex, patternTier, quality
        );

        ItemSpecLib.Decoded memory s = ItemSpecLib.decode(spec);

        assertEq(s.paintIndex, paintIndex, "spec paintIndex mismatch");
        assertEq(s.minFloat, minFloat, "spec minFloat mismatch");
        assertEq(s.maxFloat, maxFloat, "spec maxFloat mismatch");
        assertEq(s.defindex, defindex, "spec defindex mismatch");
        assertEq(s.patternTier, patternTier, "spec patternTier mismatch");
        assertEq(s.quality, quality, "spec quality mismatch");
    }

    // ========== MatchingLib Float Precision ==========

    /// @notice 20-bit -> 10-bit shift matches expected range for matching
    function testFuzz_MatchingLib_floatPrecision(
        uint32 floatValue20,
        uint16 minFloat10,
        uint16 maxFloat10
    ) public pure {
        floatValue20 = uint32(bound(floatValue20, 0, 0xFFFFF));
        minFloat10 = uint16(bound(minFloat10, 0, 0x3FF));
        maxFloat10 = uint16(bound(maxFloat10, minFloat10, 0x3FF));

        // The matching conversion: shift right 10 bits
        uint256 converted = uint256(floatValue20) >> 10;

        // Build matching pair
        uint16 paintIndex = 1;
        uint16 defindex = 7;
        uint8 quality = 0;

        ItemDetail detail = ItemDetailLib.encode(
            paintIndex, floatValue20, defindex, 500, 0, quality
        );

        ItemSpec spec = ItemSpecLib.encode(
            paintIndex, minFloat10, maxFloat10, defindex, 0, quality
        );

        bool matches = MatchingLib.validateMatch(detail, spec);

        // Verify consistency: match iff converted float is in range
        bool expectedMatch = (converted >= minFloat10 && converted <= maxFloat10);
        assertEq(matches, expectedMatch, "matching inconsistent with float conversion");
    }

    // ========== MatchingLib Exact Float ==========

    /// @notice minFloat == maxFloat works correctly (exact float matching)
    function testFuzz_MatchingLib_exactFloat(uint16 targetFloat) public pure {
        targetFloat = uint16(bound(targetFloat, 0, 0x3FF));

        uint16 paintIndex = 1;
        uint16 defindex = 7;
        uint8 quality = 0;

        // Create a detail whose 20-bit float converts exactly to targetFloat
        uint32 floatValue20 = uint32(targetFloat) << 10;

        ItemDetail detail = ItemDetailLib.encode(
            paintIndex, floatValue20, defindex, 500, 0, quality
        );

        ItemSpec spec = ItemSpecLib.encode(
            paintIndex, targetFloat, targetFloat, defindex, 0, quality
        );

        assertTrue(MatchingLib.validateMatch(detail, spec), "exact float should match");

        // Verify off-by-one: targetFloat+1 should NOT match (unless at boundary)
        if (targetFloat < 0x3FF) {
            ItemSpec specHigher = ItemSpecLib.encode(
                paintIndex, targetFloat + 1, targetFloat + 1, defindex, 0, quality
            );
            assertFalse(MatchingLib.validateMatch(detail, specHigher), "off-by-one should not match");
        }
    }
}
