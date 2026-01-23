# Cross-Chain Security Considerations

## ⚠️ IMPORTANT: TEE Verifier Contracts Should NOT Be Shared Across Chains

### The Issue

Each TEE Verifier contract maintains **on-chain state** for registered enclaves and signers:

```solidity
// These mappings are stored ON-CHAIN:
mapping(ServiceType => mapping(bytes32 => bool)) public registeredEnclaveHashes;
mapping(ServiceType => mapping(address => bool)) public registeredServices;
```

**State is local to each chain** - not synchronized across chains!

---

## Why Sharing Contracts Across Chains is Dangerous

### Scenario 1: Different Security Models Per Chain

```
Ethereum Mainnet:
  - High security requirements
  - Owner approves: hash_v2.0 (latest, secure)
  
Arbitrum:
  - Different owner/governance
  - Approves: hash_v1.0 (old, vulnerable)
  
If contracts are shared (same code, different deployments):
  - Each chain has different approved hashes
  - Each chain has different registered signers
  - Security policies are independent
  
Good: Each chain manages its own security ✅
```

### Scenario 2: Attestation Replay Across Chains

```
Problem:
  1. TEE generates attestation once
  2. Used to register on Ethereum
  3. SAME attestation replayed on Arbitrum
  4. Same address registered on both chains
  
Is this a vulnerability?
  - If TEE intended to operate on one chain: YES
  - If TEE can operate on multiple chains: NO (depends on design)
```

**Current contract does NOT prevent cross-chain replay!**

---

## Attack Scenarios

### Attack 1: Hash Approved on One Chain, Not Another

```
Attacker's Strategy:
  1. Get enclave hash approved on Chain A (easier governance)
  2. Use attestation from Chain A
  3. Try to register on Chain B
  
Result:
  ❌ BLOCKED - Hash not approved on Chain B
  
Protection: ✅ Works correctly (each chain independent)
```

### Attack 2: Compromised on One Chain, Valid on Another

```
Timeline:
  Day 1: Hash approved on Ethereum and Arbitrum
  Day 30: Vulnerability found
  Day 31: Hash revoked on Ethereum only
  
Attacker:
  - Blocked on Ethereum ✅
  - Still valid on Arbitrum ❌
  
Problem: Uncoordinated revocation across chains
```

### Attack 3: Attestation Reuse

```
TEE generates one attestation:
  - Registers on Ethereum
  - REUSES same attestation on Arbitrum
  - REUSES same attestation on Optimism
  
All registrations succeed (if hash is approved)

Is this intended?
  - Depends on your security model
  - TEE should probably generate chain-specific attestations
```

---

## Recommendations

### 1. Deploy Separate Contracts Per Chain ✅

```
✅ GOOD: Independent deployments
  - Ethereum: 0xABC...  (EspressoNitroTEEVerifier)
  - Arbitrum: 0xDEF...  (EspressoNitroTEEVerifier)
  - Different addresses, different owners, different state
  
❌ BAD: Same address via CREATE2
  - All chains: 0x123...  (Same address)
  - Could create confusion
  - State is still separate but addresses match
```

### 2. Include Chain ID in Attestation UserData

**Best Practice: TEE should encode chain ID in attestation**

```rust
// In TEE code:
let user_data = encode({
    chain_id: 1,  // Ethereum mainnet
    service: "BatchPoster",
    timestamp: now(),
    nonce: random()
});

attestation.user_data = user_data;
```

**Then validate in contract:**

```solidity
function registerService(...) external {
    // ... existing validation ...
    
    // Decode userData
    (uint256 chainId, string memory service, ...) = 
        abi.decode(journal.userData, (uint256, string, ...));
    
    // Validate chain ID matches current chain
    require(chainId == block.chainid, "Wrong chain");
    
    // ... rest of registration
}
```

### 3. Document Per-Chain Deployment

```
# Deployments

## Ethereum Mainnet (Chain ID: 1)
- EspressoNitroTEEVerifier: 0x...
- Approved Hashes: [...]
- Owner: 0x...

## Arbitrum One (Chain ID: 42161)  
- EspressoNitroTEEVerifier: 0x...
- Approved Hashes: [...]
- Owner: 0x...

⚠️ WARNING: Do NOT reuse attestations across chains!
⚠️ Each chain has independent security configuration!
```

### 4. Warn Users About Cross-Chain Replay

**Add to contract documentation:**

```solidity
/**
 * @title EspressoNitroTEEVerifier
 * @notice Verifies AWS Nitro Enclave attestations
 * 
 * ⚠️ SECURITY: Cross-Chain Considerations
 * 
 * This contract maintains chain-specific state. Do not assume:
 * - Attestations are chain-specific (they're not!)
 * - Approvals on one chain apply to another (they don't!)
 * - Revocations are coordinated (they're not!)
 * 
 * Best Practice:
 * - Deploy separate contracts per chain
 * - TEE should encode chain ID in userData
 * - Coordinate security policies across chains
 */
contract EspressoNitroTEEVerifier { ... }
```

---

## Current Status

### What Your Contract Does

✅ **Each chain has independent state** (correct)  
❌ **No chain ID validation in attestation** (potential issue)  
❌ **No documentation about cross-chain security** (should add)

### Is This a Vulnerability?

**Depends on your security model:**

**If TEEs should be chain-specific:**
- ⚠️ YES - Need chain ID validation

**If TEEs can operate on multiple chains:**
- ✅ NO - Current behavior is acceptable
- But should document this clearly!

---

## Recommendation

**Add to `VULNERABILITY_REPORT.md`:**

```markdown
## Operational Guidance: Cross-Chain Deployment

⚠️ **TEE Verifier contracts should be deployed independently on each chain.**

- Each chain has separate state (approved hashes, registered signers)
- Attestations are NOT chain-specific by default
- Revoking a hash on one chain does NOT affect other chains
- Consider validating chain ID in TEE userData for chain-specific attestations

For production: Ensure your TEE encodes `block.chainid` in userData!
```

**Would you like me to add this warning to the documentation?**
