// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {
    VerifierJournal,
    VerificationResult,
    ZkCoProcessorType,
    Pcr,
    Bytes48
} from "aws-nitro-enclave-attestation/interfaces/INitroEnclaveVerifier.sol";
import {EspressoNitroTEEVerifier} from "../src/EspressoNitroTEEVerifier.sol";
import {ITEEHelper} from "../src/interface/ITEEHelper.sol";

/// Returns the journal encoded in `output` without checking a proof.
contract MockNitroEnclaveVerifier {
    function verify(bytes calldata output, ZkCoProcessorType, bytes calldata)
        external
        virtual
        returns (VerifierJournal memory)
    {
        return abi.decode(output, (VerifierJournal));
    }
}

/// Calls back into registerService once from inside verify(), as a malicious or buggy verifier
/// could. Without the guard, the nested registration would succeed.
contract ReenteringNitroEnclaveVerifier is MockNitroEnclaveVerifier {
    EspressoNitroTEEVerifier public target;
    bytes public reentryOutput;
    bool internal reentered;

    function setTarget(EspressoNitroTEEVerifier target_, bytes calldata reentryOutput_) external {
        target = target_;
        reentryOutput = reentryOutput_;
    }

    function verify(bytes calldata output, ZkCoProcessorType coprocessor, bytes calldata proof)
        external
        override
        returns (VerifierJournal memory)
    {
        if (!reentered) {
            reentered = true;
            target.registerService(reentryOutput, proof);
        }
        return this.decode(output, coprocessor);
    }

    function decode(bytes calldata output, ZkCoProcessorType)
        external
        pure
        returns (VerifierJournal memory)
    {
        return abi.decode(output, (VerifierJournal));
    }
}

contract EspressoNitroTEEVerifierReentrancyTest is Test {
    Bytes48 internal pcr0 = Bytes48(bytes32(uint256(1)), bytes16(uint128(2)));
    bytes32 internal pcr0Hash = keccak256(abi.encodePacked(pcr0.first, pcr0.second));

    function _output(uint256 seed) internal view returns (bytes memory) {
        VerifierJournal memory j;
        j.result = VerificationResult.Success;
        j.pcrs = new Pcr[](1);
        j.pcrs[0] = Pcr(0, pcr0);
        j.publicKey = abi.encodePacked(bytes1(0x04), keccak256(abi.encode(seed)), bytes32(seed));
        return abi.encode(j);
    }

    function _signer(uint256 seed) internal pure returns (address) {
        return address(
            uint160(
                uint256(keccak256(abi.encodePacked(keccak256(abi.encode(seed)), bytes32(seed))))
            )
        );
    }

    function _deploy(address verifier) internal returns (EspressoNitroTEEVerifier nitro) {
        // This test contract acts as the TEE verifier, so it may set enclave hashes.
        nitro = new EspressoNitroTEEVerifier(address(this), verifier);
        nitro.setEnclaveHash(pcr0Hash, true);
    }

    function test_RegisterService_WorksWithGuard() public {
        EspressoNitroTEEVerifier nitro = _deploy(address(new MockNitroEnclaveVerifier()));

        vm.expectEmit(address(nitro));
        emit ITEEHelper.ServiceRegistered(_signer(1), pcr0Hash);
        nitro.registerService(_output(1), "");

        assertTrue(nitro.isSignerValid(_signer(1)));
    }

    function test_RegisterService_RevertsOnReentryFromVerifier() public {
        ReenteringNitroEnclaveVerifier verifier = new ReenteringNitroEnclaveVerifier();
        EspressoNitroTEEVerifier nitro = _deploy(address(verifier));
        verifier.setTarget(nitro, _output(2));

        vm.expectRevert(ReentrancyGuard.ReentrancyGuardReentrantCall.selector);
        nitro.registerService(_output(1), "");

        assertFalse(nitro.isSignerValid(_signer(1)));
        assertFalse(nitro.isSignerValid(_signer(2)));
    }
}
