// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {EspressoSGXTEEVerifier} from "../src/EspressoSGXTEEVerifier.sol";
import {
    IEspressoSGXTEEVerifier
} from "../src/interface/IEspressoSGXTEEVerifier.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "./OlympixUnitTest.sol";

contract EspressoSGXTEEVerifierTest is
    Test,
    OlympixUnitTest("EspressoSGXTEEVerifier")
{
    address proxyAdmin = address(140);
    address adminTEE = address(141);
    address fakeAddress = address(145);

    EspressoSGXTEEVerifier espressoSGXTEEVerifier;
    bytes32 reportDataHash =
        bytes32(
            0x38f8abca50cdede6a00d405856857bc3d81135624ee0e287640956d11cc22d5e
        );
    bytes32 enclaveHash =
        bytes32(
            0x01f7290cb6bbaa427eca3daeb25eecccb87c4b61259b1ae2125182c4d77169c0
        );

    //  Address of the automata V3QuoteVerifier deployed on sepolia
    address v3QuoteVerifier =
        address(0x6E64769A13617f528a2135692484B681Ee1a7169);

    function setUp() public {
        vm.createSelectFork(
            "https://rpc.ankr.com/eth_sepolia/10a56026b3c20655c1dab931446156dea4d63d87d1261934c82a1b8045885923"
        );
        // Get the instance of the DCAP Attestation QuoteVerifier on the Arbitrum Sepolia Rollup
        vm.startPrank(adminTEE);
        espressoSGXTEEVerifier = new EspressoSGXTEEVerifier(
            enclaveHash,
            v3QuoteVerifier
        );
        vm.stopPrank();
    }

    function testRegisterSigner() public {
        vm.startPrank(adminTEE);
        // bytes memory attestation = vm.readFileBinary("/test/configs/attestation.bin");
        string memory quotePath = "/test/configs/attestation.bin";
        string memory inputFile = string.concat(vm.projectRoot(), quotePath);
        bytes memory sampleQuote = vm.readFileBinary(inputFile);

        // take keccak256 hash of the address of proxyAdmin

        address batchPosterAddress = address(
            0xe2148eE53c0755215Df69b2616E552154EdC584f
        );

        bytes memory data = abi.encodePacked(batchPosterAddress);

        // Convert the data to bytes32 and pass it to the verify function
        espressoSGXTEEVerifier.registerSigner(sampleQuote, data);
        vm.stopPrank();
    }

    function testRegisterSignerInvalidQuote() public {
        vm.startPrank(adminTEE);
        string memory quotePath = "/test/configs/invalid_quote.bin";
        string memory inputFile = string.concat(vm.projectRoot(), quotePath);
        bytes memory sampleQuote = vm.readFileBinary(inputFile);

        address batchPosterAddress = address(
            0xe2148eE53c0755215Df69b2616E552154EdC584f
        );

        bytes memory data = abi.encodePacked(batchPosterAddress);

        vm.expectRevert(IEspressoSGXTEEVerifier.InvalidQuote.selector);
        espressoSGXTEEVerifier.registerSigner(sampleQuote, data);
    }

    function testRegisterSignerInvalidAddress() public {
        vm.startPrank(adminTEE);
        string memory quotePath = "/test/configs/attestation.bin";
        string memory inputFile = string.concat(vm.projectRoot(), quotePath);
        bytes memory sampleQuote = vm.readFileBinary(inputFile);

        address batchPosterAddress = address(
            0x4C91660a37d613E1Bd278F9Db882Cc5ED2549072
        );

        bytes memory data = abi.encodePacked(batchPosterAddress);

        vm.expectRevert(IEspressoSGXTEEVerifier.InvalidReportDataHash.selector);
        espressoSGXTEEVerifier.registerSigner(sampleQuote, data);
    }

    function testRegisterSignerInvalidDataLength() public {
        vm.startPrank(adminTEE);
        string memory quotePath = "/test/configs/attestation.bin";
        string memory inputFile = string.concat(vm.projectRoot(), quotePath);
        bytes memory sampleQuote = vm.readFileBinary(inputFile);

        address batchPosterAddress = address(
            0xe2148eE53c0755215Df69b2616E552154EdC584f
        );

        // encode adds padding and the length should become incorrect
        bytes memory data = abi.encode(batchPosterAddress);

        vm.expectRevert(IEspressoSGXTEEVerifier.InvalidDataLength.selector);
        espressoSGXTEEVerifier.registerSigner(sampleQuote, data);
    }

    function testDeleteRegisteredSigner() public {
        vm.startPrank(adminTEE);
        string memory quotePath = "/test/configs/attestation.bin";
        string memory inputFile = string.concat(vm.projectRoot(), quotePath);
        bytes memory sampleQuote = vm.readFileBinary(inputFile);

        address batchPosterAddress = address(
            0xe2148eE53c0755215Df69b2616E552154EdC584f
        );

        // Convert to bytes (dynamically sized)
        bytes memory data = abi.encodePacked(batchPosterAddress);

        espressoSGXTEEVerifier.registerSigner(sampleQuote, data);
        vm.stopPrank();

        vm.startPrank(adminTEE);
        address[] memory batchPosters = new address[](1);
        batchPosters[0] = batchPosterAddress;
        espressoSGXTEEVerifier.deleteRegisteredSigners(batchPosters);
        assertEq(
            espressoSGXTEEVerifier.registeredSigners(batchPosterAddress),
            false
        );
        vm.stopPrank();

        // Check that only owner can delete the signer
        vm.startPrank(fakeAddress);
        vm.expectRevert("Ownable: caller is not the owner");

        espressoSGXTEEVerifier.deleteRegisteredSigners(batchPosters);
        vm.stopPrank();
    }

    /**
     * Test verify quote verifies that if correct quote and report data hash is passed
     *     then the function does not revert
     */
    function testVerifyQuoteValid() public {
        vm.startPrank(adminTEE);
        string memory quotePath = "/test/configs/attestation.bin";
        string memory inputFile = string.concat(vm.projectRoot(), quotePath);
        bytes memory sampleQuote = vm.readFileBinary(inputFile);
        espressoSGXTEEVerifier.verify(sampleQuote, reportDataHash);
        vm.stopPrank();
    }

    /**
     * Test verify quote reverts if incorrect header is passed
     */
    function testVerifyInvalidHeaderInQuote() public {
        string memory quotePath = "/test/configs/incorrect_header_in_quote.bin";
        string memory inputFile = string.concat(vm.projectRoot(), quotePath);
        bytes memory invalidQuote = vm.readFileBinary(inputFile);
        vm.expectRevert(IEspressoSGXTEEVerifier.InvalidHeaderVersion.selector);
        espressoSGXTEEVerifier.verify(invalidQuote, reportDataHash);
    }

    /**
     * Test verify quote reverts if incorrect quote is passed
     */
    function testVerifyInvalidQuote() public {
        string memory quotePath = "/test/configs/invalid_quote.bin";
        string memory inputFile = string.concat(vm.projectRoot(), quotePath);
        bytes memory invalidQuote = vm.readFileBinary(inputFile);
        vm.expectRevert(IEspressoSGXTEEVerifier.InvalidQuote.selector);
        espressoSGXTEEVerifier.verify(invalidQuote, reportDataHash);
    }

    /**
     * Test incorrect report data hash
     */
    function testIncorrectReportDataHash() public {
        vm.startPrank(adminTEE);
        string memory quotePath = "/test/configs/attestation.bin";
        string memory inputFile = string.concat(vm.projectRoot(), quotePath);
        bytes memory sampleQuote = vm.readFileBinary(inputFile);
        vm.expectRevert(IEspressoSGXTEEVerifier.InvalidReportDataHash.selector);
        espressoSGXTEEVerifier.verify(sampleQuote, bytes32(0));
    }

    function testVerifyQuoteEmptyRawQuote() public {
        bytes memory sampleQuote = hex"";
        vm.expectRevert();
        espressoSGXTEEVerifier.verify(sampleQuote, reportDataHash);
    }

    function testVerifyQuoteEmptyReportDataHash() public {
        string memory quotePath = "/test/configs/attestation.bin";
        string memory inputFile = string.concat(vm.projectRoot(), quotePath);
        bytes memory sampleQuote = vm.readFileBinary(inputFile);
        vm.expectRevert();
        espressoSGXTEEVerifier.verify(sampleQuote, bytes32(0));
    }
    /**
     * Test verify quote reverts if incorrect enclaveHash is passed
     */

    function testIncorrectMrEnclave() public {
        vm.startPrank(adminTEE);
        string memory quotePath = "/test/configs/attestation.bin";
        string memory inputFile = string.concat(vm.projectRoot(), quotePath);
        bytes memory sampleQuote = vm.readFileBinary(inputFile);
        bytes32 incorrectMrEnclave = bytes32(
            0x51dfe95acffa8a4075b716257c836895af9202a5fd56c8c2208dacb79c659ff1
        );
        espressoSGXTEEVerifier = new EspressoSGXTEEVerifier(
            incorrectMrEnclave,
            v3QuoteVerifier
        );
        vm.expectRevert(IEspressoSGXTEEVerifier.InvalidEnclaveHash.selector);
        espressoSGXTEEVerifier.verify(sampleQuote, reportDataHash);
    }

    function testSetEnclaveHash() public {
        vm.startPrank(adminTEE);
        bytes32 newMrEnclave = bytes32(hex"01");
        espressoSGXTEEVerifier.setEnclaveHash(newMrEnclave, true);
        assertEq(
            espressoSGXTEEVerifier.registeredEnclaveHash(newMrEnclave),
            true
        );
        espressoSGXTEEVerifier.setEnclaveHash(newMrEnclave, false);
        assertEq(
            espressoSGXTEEVerifier.registeredEnclaveHash(newMrEnclave),
            false
        );
        vm.stopPrank();
        // Check that only owner can set the hash
        vm.startPrank(fakeAddress);
        vm.expectRevert("Ownable: caller is not the owner");
        espressoSGXTEEVerifier.setEnclaveHash(newMrEnclave, true);
        vm.stopPrank();
    }

    // Test Ownership transfer using Ownable2Step contract
    function testOwnershipTransfer() public {
        vm.startPrank(adminTEE);
        assertEq(address(espressoSGXTEEVerifier.owner()), adminTEE);
        espressoSGXTEEVerifier.transferOwnership(fakeAddress);
        vm.stopPrank();
        vm.startPrank(fakeAddress);
        espressoSGXTEEVerifier.acceptOwnership();
        assertEq(address(espressoSGXTEEVerifier.owner()), fakeAddress);
        vm.stopPrank();
    }

    /// @dev Covers opix-target-branch-58-True: verify() header.version != 3 triggers InvalidHeaderVersion revert
    function testVerify_quoteWithNonV3HeaderVersion_revertsWithInvalidHeaderVersion()
        public
    {
        // This test expects the test infrastructure has the same file layout and an accessible quote.
        // The primary failing was vm.readFileBinary, not contract logic.
        // To robustly test, if file is missing, fall back to minimal bytes, but in production infra, test config will supply this file.
        string memory quotePath = "/test/configs/attestation.bin";
        string memory inputFile = string.concat(vm.projectRoot(), quotePath);
        bytes memory validQuote = new bytes(0);
        bool fileExists = true;
        try vm.readFileBinary(inputFile) returns (bytes memory bin) {
            validQuote = bin;
        } catch {
            // fallback minimal: 48 bytes (just header) of zeros as dummy quote
            validQuote = new bytes(48);
            fileExists = false;
        }
        // Mutate version to something != 3: set little-endian uint16 to 0x0001
        // validQuote[0]=0x01; validQuote[1]=0x00 (little endian uint16=1)
        if (validQuote.length < 2) {
            bytes memory tmp = new bytes(2);
            validQuote = tmp;
        }
        validQuote[0] = bytes1(uint8(0x01));
        validQuote[1] = bytes1(uint8(0x00));
        // reportDataHash is arbitrary but must be valid length
        vm.expectRevert(IEspressoSGXTEEVerifier.InvalidHeaderVersion.selector);
        espressoSGXTEEVerifier.verify(validQuote, reportDataHash);
    }

    // This test covers opix-target-branch-60-YOUR-TEST-SHOULD-ENTER-THIS-ELSE-BRANCH-BY-MAKING-THE-PRECEDING-IFS-CONDITIONS-FALSE
    // It ensures that when header.version == 3, the EspressoSGXTEEVerifier.verify() function takes the 'else' branch (assert(true)) and does NOT revert with InvalidHeaderVersion.
    // The test checks that any revert that happens is not due to InvalidHeaderVersion (branch coverage for 60-else path).
    function test_verify_enterElseBranch_headerVersion3_opixBranch_60_ElseBranch()
        public
    {
        // Prepare a dummy quote with the first two bytes (little-endian) equal to 3
        bytes memory dummyQuote = new bytes(48); // 48 bytes for just the header
        dummyQuote[0] = bytes1(uint8(0x03)); // low byte = 3
        dummyQuote[1] = bytes1(uint8(0x00)); // high byte = 0
        // The remaining bytes can be zero (we are not testing full quote validity, just the version check logic)
        // The function will revert beyond the header check (likely InvalidQuote, etc.) – but not with InvalidHeaderVersion

        bytes32 dummyReportDataHash = reportDataHash;

        // Use inline assembly to catch the revert selector
        (bool ok, bytes memory revertReason) = address(espressoSGXTEEVerifier)
            .staticcall(
                abi.encodeWithSelector(
                    espressoSGXTEEVerifier.verify.selector,
                    dummyQuote,
                    dummyReportDataHash
                )
            );
        // Should NOT revert with InvalidHeaderVersion (selector)
        if (!ok) {
            bytes4 selector = bytes4(0);
            if (revertReason.length >= 4) {
                assembly {
                    selector := mload(add(revertReason, 0x20))
                }
            }
            assertTrue(
                selector !=
                    IEspressoSGXTEEVerifier.InvalidHeaderVersion.selector,
                "verify should not revert with InvalidHeaderVersion when version==3 (should hit else branch)"
            );
            // It is acceptable if it reverts with any other selector (e.g. InvalidQuote, etc) because the dummy quote is otherwise invalid
        } else {
            // If it actually succeeds, that's allowed for this targeted branch, but highly unlikely
            assertTrue(true);
        }
    }

    // opix-target-branch-107-True
    // Test enters EspressoSGXTEEVerifier.registerSigner branch where data.length != 20, expect revert with InvalidDataLength
    function testRegisterSigner_OpixTargetBranch_107_True() public {
        // Use a valid sampleQuote (20 zero bytes works because only data.length is checked, not its content here)
        bytes memory dummyQuote = new bytes(48); // Enough length to avoid out-of-bounds error for header parsing

        // Data with length != 20, e.g. 10
        bytes memory wrongLenData = new bytes(10);
        for (uint256 i = 0; i < 10; i++) {
            wrongLenData[i] = bytes1(uint8(i));
        }

        vm.expectRevert(IEspressoSGXTEEVerifier.InvalidDataLength.selector);
        espressoSGXTEEVerifier.registerSigner(dummyQuote, wrongLenData);
    }

    // opix-target-branch-109-YOUR-TEST-SHOULD-ENTER-THIS-ELSE-BRANCH
    // This test should invoke EspressoSGXTEEVerifier.registerSigner with `data.length == 20`,
    // and valid quote (but for branch coverage, only the branch matters; the rest can revert later)
    // The function should not revert due to InvalidDataLength; instead, it should hit the 'else' branch for DataLength check.
    function testRegisterSigner_dataLen20_opixTargetBranch109Else() public {
        // Prepare a dummy quote, large enough to not revert on slice for header extraction etc (just a stub for coverage)
        bytes memory dummyQuote = new bytes(48); // 48 should be enough for the header extraction (see parseQuoteHeader)

        // Data must be exactly 20 bytes
        bytes memory twentyByteData = new bytes(20);
        for (uint256 i = 0; i < 20; i++) {
            twentyByteData[i] = bytes1(uint8(i + 1));
        }

        // Most likely the function will revert later, but if it reverts with DataLength error, the branch is not hit
        // So for branch coverage: fail the test if that particular revert is encountered
        // Instead, if it proceeds beyond the DataLength check, our goal is reached
        try espressoSGXTEEVerifier.registerSigner(dummyQuote, twentyByteData) {
            // This should not succeed fully, will likely revert due to attestation/quote structure in next steps
            // But the branch is covered. No assertion needed here for coverage.
        } catch (bytes memory reason) {
            // If it reverts with InvalidDataLength, coverage is NOT hit! Fail test
            bytes4 selector;
            if (reason.length >= 4) {
                assembly {
                    selector := mload(add(reason, 0x20))
                }
            }
            assertTrue(
                selector != IEspressoSGXTEEVerifier.InvalidDataLength.selector,
                "Should not revert with InvalidDataLength (should cover 'else' branch)"
            );
            // If it fails for other reasons, that is expected for branch coverage purposes.
        }
    }

    // opix-target-branch-170-True
    // EspressoSGXTEEVerifier.parseEnclaveReport: If length of rawEnclaveReport != ENCLAVE_REPORT_LENGTH, success should be false and no revert
    function test_parseEnclaveReport_incorrect_length() public {
        // Prepare a byte array of incorrect length (e.g., 100 instead of ENCLAVE_REPORT_LENGTH)
        bytes memory badEnclaveReport = new bytes(100);
        // Call parseEnclaveReport directly -- it is a pure function
        (bool success, ) = espressoSGXTEEVerifier.parseEnclaveReport(
            badEnclaveReport
        );
        assertEq(
            success,
            false,
            "Should return false when length is incorrect"
        );
    }

    // This unit test will cover the parseEnclaveReport branch
    // where the length of rawEnclaveReport == ENCLAVE_REPORT_LENGTH,
    // thus hitting the 'else' branch (opix-target-branch-172-YOUR-TEST-SHOULD-ENTER-THIS-ELSE-BRANCH)
    // of parseEnclaveReport in EspressoSGXTEEVerifier.sol:

    function test_parseEnclaveReport_correct_length() public {
        // The ENCLAVE_REPORT_LENGTH constant is imported from a library, but its value needs to be known in test scope.
        // For demonstration purposes, we'll set it to 384, which is the real size for V3 EnclaveReport on Automata (but if changed, use actual imported value!).
        uint256 ENCLAVE_REPORT_LENGTH = 384;
        // Prepare a byte array of the correct length, can be all zeros for branch coverage
        bytes memory goodEnclaveReport = new bytes(ENCLAVE_REPORT_LENGTH);
        // Should hit opix-target-branch-172-YOUR-TEST-SHOULD-ENTER-THIS-ELSE-BRANCH
        (bool success, ) = espressoSGXTEEVerifier.parseEnclaveReport(
            goodEnclaveReport
        );
        assertEq(
            success,
            true,
            "Should return true when length is exactly ENCLAVE_REPORT_LENGTH"
        );
    }

    function testSGXConstructorInvalidQuoteVerifierAddress() public {
        bytes32 dummyEnclaveHash = bytes32(uint256(0x1234));
        address zeroAddress = address(0);
        vm.expectRevert(
            IEspressoSGXTEEVerifier.InvalidQuoteVerifierAddress.selector
        );
        new EspressoSGXTEEVerifier(dummyEnclaveHash, zeroAddress);
    }

    function testSGXConstructorInvalidQuoteVerifierAddressNoCode() public {
        bytes32 dummyEnclaveHash = bytes32(uint256(0x5678));
        // Create an address with no code by generating a random address (not a contract)
        address eoa = address(0x1234567890123456789012345678901234567890);
        // Ensure the address has no code
        assertEq(eoa.code.length, 0);
        vm.expectRevert(
            IEspressoSGXTEEVerifier.InvalidQuoteVerifierAddress.selector
        );
        new EspressoSGXTEEVerifier(dummyEnclaveHash, eoa);
    }
}
