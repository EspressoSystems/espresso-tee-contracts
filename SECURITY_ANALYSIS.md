# Security Analysis: EspressoNitroTEEVerifier

## ZK Verifier Key Tampering

### The Problem

The `EspressoNitroTEEVerifier` contract relies on an external `NitroEnclaveVerifier` contract deployed by Automata Network. This external contract contains ZK verification configuration that can be changed by its owner:

```solidity
// In NitroEnclaveVerifier.sol (external library)
function setZkConfiguration(ZkCoProcessorType _zkCoProcessor, ZkCoProcessorConfig memory _config)
    external
    onlyOwner  // ← Automata's owner can call this
{
    zkConfig[_zkCoProcessor] = _config;
}
```

**Attack Scenario:**
1. Automata's owner (or compromised admin key) changes the `verifierId` to a malicious ZK program
2. The malicious program generates "valid" proofs for fake attestations
3. EspressoNitroTEEVerifier accepts these fake attestations
4. PCR hash checks become meaningless

### The Solution Implemented

We added **runtime validation** that verifies the external contract's configuration hasn't changed from what was expected at deployment.

## Implementation Details

### 1. Cache Expected Configuration at Deployment

```solidity
// Storage variables (immutable - cannot be changed after deployment)
bytes32 public immutable expectedVerifierId;
address public immutable expectedZkVerifier;

constructor(INitroEnclaveVerifier nitroEnclaveVerifier) TEEHelper() {
    require(address(nitroEnclaveVerifier) != address(0), "NitroEnclaveVerifier cannot be zero");
    _nitroEnclaveVerifier = nitroEnclaveVerifier;
    
    // Read and cache the configuration from the external contract
    ZkCoProcessorConfig memory config = nitroEnclaveVerifier.getZkConfig(ZkCoProcessorType.Succinct);
    require(config.verifierId != bytes32(0), "Verifier ID not configured");
    require(config.zkVerifier != address(0), "ZK Verifier not configured");
    
    // Store as immutable (cannot be modified)
    expectedVerifierId = config.verifierId;
    expectedZkVerifier = config.zkVerifier;
}
```

**Current Production Values (Sepolia):**
- Expected Verifier ID: `0x00326cc10dc6dbcf4249c7adb4d515b9bdbff20f541da85921fc9ddf930e7bb0`
- Expected ZK Verifier: `0x397A5f7f3dBd538f23DE225B51f532c34448dA9B`

### 2. Validate Before Every Use

```solidity
function registerService(bytes calldata output, bytes calldata proofBytes, ServiceType service)
    external
{
    // ✅ SECURITY: Verify configuration hasn't been tampered with
    _validateZkConfiguration();
    
    VerifierJournal memory journal = _nitroEnclaveVerifier.verify(
        output,
        ZkCoProcessorType.Succinct,
        proofBytes
    );
    // ... rest of logic
}

function _validateZkConfiguration() internal view {
    ZkCoProcessorConfig memory currentConfig = _nitroEnclaveVerifier.getZkConfig(ZkCoProcessorType.Succinct);
    
    // Revert if verifier ID has changed
    if (currentConfig.verifierId != expectedVerifierId) {
        revert VerifierConfigurationChanged("Verifier ID changed");
    }
    
    // Revert if ZK verifier address has changed
    if (currentConfig.zkVerifier != expectedZkVerifier) {
        revert VerifierConfigurationChanged("ZK Verifier address changed");
    }
}
```

### 3. Protect Against Malicious Verifier Swaps

```solidity
function setNitroEnclaveVerifier(address nitroEnclaveVerifier) external onlyOwner {
    if (nitroEnclaveVerifier == address(0)) {
        revert InvalidNitroEnclaveVerifierAddress();
    }
    
    // ✅ SECURITY: Verify new verifier has same configuration
    INitroEnclaveVerifier newVerifier = INitroEnclaveVerifier(nitroEnclaveVerifier);
    ZkCoProcessorConfig memory newConfig = newVerifier.getZkConfig(ZkCoProcessorType.Succinct);
    
    if (newConfig.verifierId != expectedVerifierId) {
        revert VerifierConfigurationChanged("New verifier has different verifier ID");
    }
    
    if (newConfig.zkVerifier != expectedZkVerifier) {
        revert VerifierConfigurationChanged("New verifier has different ZK verifier address");
    }
    
    _nitroEnclaveVerifier = newVerifier;
    emit NitroEnclaveVerifierSet(nitroEnclaveVerifier);
}
```

## Protection Guarantees

### Before the Fix ❌
```
Automata changes config → Your contract uses it → Services bypass security
```

### After the Fix ✅
```
Automata changes config → Validation fails → Transaction reverts → You are alerted
```

## What This DOES Protect Against

1. ✅ **External verifier configuration changes**
   - Automata cannot change the `verifierId` without your contract rejecting all subsequent registrations
   
2. ✅ **Verifier contract swap attacks**
   - Your owner cannot swap to a malicious verifier contract
   
3. ✅ **ZK verifier address changes**
   - Detection if the SP1 verifier address is changed
   
4. ✅ **Fail-safe behavior**
   - Contract stops accepting registrations rather than accepting fake ones

## What This DOES NOT Protect Against

1. ⚠️ **Initial deployment with malicious configuration**
   - If the external verifier already has a malicious config at deployment time, it will be cached as "expected"
   - **Mitigation:** Manually verify the configuration before deployment
   
2. ⚠️ **Compromised verifier program itself**
   - If the ZK program at `verifierId` has a vulnerability, we can't detect it
   - **Mitigation:** Audit the ZK program code
   
3. ⚠️ **Other vulnerabilities identified**
   - Missing userData validation
   - Missing nonce validation  
   - Missing timestamp freshness
   - Public key format assumptions
   - No PCR array bounds check


## Testing

Security tests are provided in `test/EspressoNitroTEEVerifier_SecurityTest.t.sol`:

```bash
forge test --match-contract EspressoNitroTEEVerifierSecurityTest -vv
```

**Test Results:**
- ✅ Configuration is stored at deployment
- ✅ Normal registration works when configuration unchanged
- ✅ Rejects verifier change when configuration differs
- ✅ Allows verifier change when configuration matches

## Monitoring Recommendations

1. **Set up alerts** to monitor the external verifier configuration:
   ```javascript
   // Off-chain monitoring
   const config = await nitroVerifier.getZkConfig(ZkCoProcessorType.Succinct);
   if (config.verifierId !== EXPECTED_VERIFIER_ID) {
     alert("CRITICAL: Verifier configuration changed!");
   }
   ```

2. **Event monitoring** for configuration-related errors:
   - Watch for `VerifierConfigurationChanged` reverts
   - Alert if multiple users report registration failures

3. **Regular verification** of the external contract owner:
   ```bash
   cast call $NITRO_VERIFIER "owner()" --rpc-url $RPC_URL
   ```

## Deployment Checklist

- [ ] Verify external `NitroEnclaveVerifier` configuration before deployment
- [ ] Confirm `verifierId` corresponds to audited ZK program
- [ ] Verify `zkVerifier` is legitimate SP1 verifier contract
- [ ] Set up off-chain monitoring for configuration changes
- [ ] Document expected configuration values
- [ ] Test with actual attestations before production use

## Summary

The implemented solution provides **runtime protection** against verifier key tampering by:
1. Caching the expected configuration at deployment (immutable)
2. Validating every operation against the cached values
3. Rejecting any configuration that differs from what was expected

This transforms the attack from **silent compromise** to **fail-safe shutdown**, giving you time to respond to threats.

