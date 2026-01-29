# Espresso TEE Contracts

This repository contains Solidity contracts for verifying attestations from Trusted Execution Environments (TEEs), including AWS Nitro Enclaves and Intel SGX. It is used in our integration projects including [optimism-espresso-integration](https://github.com/EspressoSystems/optimism-espresso-integration) and [nitro-espresso-integration](https://github.com/EspressoSystems/nitro-espresso-integration).

## Foundry

**Foundry is a blazing fast, portable and modular toolkit for Ethereum application development written in Rust.**

Foundry consists of:

- **Forge**: Ethereum testing framework (like Truffle, Hardhat and DappTools).
- **Cast**: Swiss army knife for interacting with EVM smart contracts, sending transactions and getting chain data.
- **Anvil**: Local Ethereum node, akin to Ganache, Hardhat Network.
- **Chisel**: Fast, utilitarian, and verbose solidity REPL.

## Documentation

Download foundry at `https://book.getfoundry.sh/`

## Usage

### Build

```shell
forge build
```

### Test

```shell
forge test
```

### Format

```shell
forge fmt
```

### Gas Snapshots

```shell
forge snapshot
```

### Anvil

```shell
anvil
```

### Cast

```shell
cast <subcommand>
```

### Help

```shell
forge --help
anvil --help
cast --help
```

# Development

For ease of development in go projects, we have included a small utility in this repo to generate go bindings for the TEEVerifier contracts present here.

This utility uses the bind v2 implementation from github.com/ethereum/go-ethereum/abi/abigen/bind.go

To generate these bindings for use in a go project, simply run `go run bindings/gen.go` from the root of this repo.
Afterwards the bindings should appear in bindings/go/espressogen/espressogen.go and can be linked into your project easily if you are using this repo as a git submodule.

## TEE Verifier Deployment

All TEE contracts are deployed using the **OpenZeppelin v5.x Transparent Proxy pattern**. In this pattern, each `TransparentUpgradeableProxy` automatically deploys its own `ProxyAdmin` contract internally. The `ProxyAdmin` owner controls upgrade capabilities.

### 1. Clean Build Environment

Start with a fresh build to ensure contracts are built with proper profiles for gas optimizations:

```bash
forge clean
```

### 2. **Environment Setup**

Create a `.env` file in the project root with the following variables.
The `ETHERSCAN_API_KEY` should be generated from your account on [etherscan.io](https://etherscan.io/myapikey) and works across all supported chains via the V2 API.

```text
# Variables for script command
RPC_URL=<your-rpc-url>
PRIVATE_KEY=<your-private-key>
CHAIN_ID=<your-chain-id>

# Etherscan V2 API Key from etherscan.io (works for all chains)
ETHERSCAN_API_KEY=<your-etherscan-v2-api-key>

# Variables for deployment
SGX_QUOTE_VERIFIER_ADDRESS=<quote_verifier_address_from_automata>  # From: https://github.com/automata-network/automata-dcap-attestation
NITRO_ENCLAVE_VERIFIER=<nitro_enclave_verifier_address>  # From: https://github.com/automata-network/aws-nitro-enclave-attestation

# To be updated after individual deployment (not needed for DeployAllTEEVerifiers)
TEE_VERIFIER_ADDRESS=""
NITRO_VERIFIER_ADDRESS=""
SGX_VERIFIER_ADDRESS=""
```

Save the file then source it:

```bash
source .env
```

### 3. **Deployment Options**

You can deploy the TEE contracts in two ways:

#### Option A: Deploy All Contracts Together (Recommended)

This deploys all three TEE verifier contracts in a single script, handling the circular dependency automatically:

```bash
forge script scripts/DeployAllTEEVerifiers.s.sol:DeployAllTEEVerifiers \
    --rpc-url "$RPC_URL" \
    --private-key "$PRIVATE_KEY" \
    --broadcast \
    --verify --verifier etherscan --chain "$CHAIN_ID"
```

This script will:
1. Deploy `EspressoTEEVerifier` proxy (with placeholder SGX/Nitro addresses)
2. Deploy `EspressoSGXTEEVerifier` proxy (linked to TEEVerifier)
3. Deploy `EspressoNitroTEEVerifier` proxy (linked to TEEVerifier)
4. Update `EspressoTEEVerifier` with the actual SGX and Nitro addresses

#### Option B: Deploy Contracts Individually

If you prefer to deploy contracts separately:

1. **Deploy Espresso TEE Verifier First**

   First, deploy the main TEEVerifier with placeholder addresses:

   ```bash
   # Set placeholder addresses for individual deployment
   export SGX_VERIFIER_ADDRESS=0x0000000000000000000000000000000000000000
   export NITRO_VERIFIER_ADDRESS=0x0000000000000000000000000000000000000000

   forge script scripts/DeployTEEVerifier.s.sol:DeployTEEVerifier \
       --rpc-url "$RPC_URL" \
       --private-key "$PRIVATE_KEY" \
       --broadcast \
       --verify --verifier etherscan --chain "$CHAIN_ID"
   ```

   Update your `.env` with the deployed TEEVerifier proxy address:
   ```text
   TEE_VERIFIER_ADDRESS=<deployed_tee_verifier_proxy>
   ```

2. **Deploy SGX Verifier**

   ```bash
   source .env
   FOUNDRY_PROFILE=sgx forge script scripts/DeploySGXTEEVerifier.s.sol:DeploySGXTEEVerifier \
       --rpc-url "$RPC_URL" \
       --private-key "$PRIVATE_KEY" \
       --broadcast \
       --verify --verifier etherscan --chain "$CHAIN_ID"
   ```

3. **Deploy Nitro Verifier**

   ```bash
   FOUNDRY_PROFILE=nitro forge script scripts/DeployNitroTEEVerifier.s.sol:DeployNitroTEEVerifier \
       --rpc-url "$RPC_URL" \
       --private-key "$PRIVATE_KEY" \
       --broadcast \
       --verify --verifier etherscan --chain "$CHAIN_ID"
   ```

4. **Update TEEVerifier with actual addresses**

   After deploying SGX and Nitro verifiers, call `setEspressoSGXTEEVerifier` and `setEspressoNitroTEEVerifier` on the TEEVerifier proxy using cast:

   ```bash
   cast send $TEE_VERIFIER_ADDRESS "setEspressoSGXTEEVerifier(address)" $SGX_VERIFIER_ADDRESS \
       --rpc-url "$RPC_URL" --private-key "$PRIVATE_KEY"

   cast send $TEE_VERIFIER_ADDRESS "setEspressoNitroTEEVerifier(address)" $NITRO_VERIFIER_ADDRESS \
       --rpc-url "$RPC_URL" --private-key "$PRIVATE_KEY"
   ```

### 4. Post-Deployment

- Verify all contracts on Block Explorer
- Deployment artifacts are saved in `deployments/<chain_id>/`
- Each deployment JSON contains:
  - `proxy`: The proxy address (this is what users interact with)
  - `implementation`: The implementation contract address


### Transferring ownership of the TEEVerifier contracts to a multi-sig wallet

The script located at `scripts/MultiSigTransfer.s.sol` is meant to assist with this.

When run the script will first initiate transfer of the TEEVerifier contracts to the multi-sig wallet with the original owner wallet.
Then, the script will batch the `acceptOwnership()` transactions that need to be executed on the multi-sig wallet. It will require the user to sign
the proposal to the multi-sig wallet with a ledger containing an account that is a designated `signer` or `delegate`.

If the ledger signature fails, or is invalid, the entire script will revert, meaning that the initial ownership transfer will not be reflected on chain.

#### Compatibility:
Currently this script is *NOT* compatible with ARB Sepolia, only ETH, ETH Sepolia, and ARB One. We hope to extend compatibility to ARB Sepolia in the future.

#### Usage

 1. Prepare your .env file.

  Your .env file will need to contain the following items.

  ```bash
  # Env vars required by the script
  LEDGER_DERIVATION_PATH="m/44'/60'/0'/0/0" #Note, depending on what keys your ledger holds, this may be different.
  TEE_VERIFIER_ADDRESS="EspressoTEEVerifier contract address" #
  PROPOSER_ADDRESS="Your Multi-sig signer address" #Note, this must be the same as the one provided by the derivation path.
  PRIVATE_KEY="insert original EspressoTEEVerifier contract owner's private key here" #This is required by the script to run, but is never parsed by the script itself.

  # Does not need to be supplied if you are using `SAFE_MODE=true`
  MULTISIG_CONTRACT_ADDRESS="Your Multi-Sig address"
  #If you are using the following option, you do not need to supply the MULTISIG_CONTRACT_ADDRESS
  SAFE_MODE="boolean representing wether to use the script in safe mode" #if toggled on, the script will use cannonical espresso multi-sig addresses for the newOwner

  # Env vars that are only necessarty for the forge script command
  RPC_URL="RPC URL for the chain you wish to execute on"
  CHAIN_ID="Chain ID of the network to execute transactions on" 
  ```

  - LEDGER_DERIVATION_PATH: This is the derivation path of the account you wish to propose the multi-sig transaction with. It is mandatory that this account is a `signer`, or `delegate`, in the multi-sig contract.

    You can obtain this by first opening Ledger Wallet and going to the accounts section. Then you should right click on the account you wish to use for signing, and select edit account.
    Finally, click on the `Advanced` dropdown menu. For ethereum addresses you can expect the path to be listed in the freshAddressPath like so.

```json
{
  "index": 0,
  "freshAddressPath": "44'/60'/0'/0/0",
  "id": "js:2:ethereum:0x0000000000000000000000000000000000000000:",
  "blockHeight": 00000001
}
```

    NOTE: you will need to prepend the `m/` to this path for foundry to correctly locate the account.

  - MULTISIG_CONTRACT_ADDRESS: The address of your Multi-sig wallet on the chain you wish this transaction to occur on.

  - SAFE_MODE: Run the script in a manner such that it's impossible to propose the transaction to a non espresso controlled multi-sig wallet.

  - TEE_VERIFIER_ADDRESS: The address of the outer EspressoTEEVerifier contract.
    Note: this must be the outer TEEVerifier contract. The script locates the inner contracts by calling espressoNitroVerifier and espressoSGXVerifier on the outer contract.

  - PROPOSER_ADDRESS: The address used to propose the transaction to the multi-sig wallet.
    Note: This must be the address associated with the account located at the wallets provided derivation path.

  - ORIGINAL_OWNER_KEY: The private key of the account that owns the TEEVerifier contracts before the transfer of ownership.

  - RPC_URL: Used for the `forge script` command for specifying the network to send the transaction to.
  - CHAIN_ID: This is used for the `forge script` command for specifying the network to send the transaction to.

 2. Run the MultiSigTransfer script.

  Note: it is important to pass the --ffi flag, otherwise due to some restrictions in forge, the script will not be able to use the ledger for signing the proposal.

  Before running the script, make sure your ledger is plugged into your machine, unlocked, and has the Ethereum app open.  
  
```bash  
forge script scripts/MultiSigTransfer.s.sol:MultiSigTransfer --rpc-url "$RPC_URL" --sender $PROPOSER_ADDRESS --broadcast --verify --verifier etherscan --chain "$CHAIN_ID" --ffi
```

  You may run into errors like the following:

  ```
  Error: Could not connect to Ledger device.
  Make sure it's connected and unlocked, with no other desktop wallet apps open.

  Context:
  - Sequence mismatch. Got 1 from device. Expected 0
  ```

  or

  ```
  Error: Ledger device: APDU Response error `Code 6985 ([APDU_CODE_CONDITIONS_NOT_SATISFIED] Conditions of use not satisfied)`
  ```

  Or even

  ```

  Error: Could not connect to Ledger device.
  Make sure it's connected and unlocked, with no other desktop wallet apps open.

  Context:
  - Ledger device: APDU Response error `Code 6983 ([APDU_CODE_OUTPUT_BUFFER_TOO_SMALL])`
    
  ```

  If you encounter any of these, it's best to try quitting the Ethereum app and lock your ledger. Then re-unlock the ledger, open the Ethereum app, and try the script again.

  I'm not entirely sure why these happen, but it seems to be related to when the ledger was unlocked and opened the Ethereum app. The first error related to a sequence mismatch also just goes away sometimes.

#### During script execution.
  After running this script you will be asked to create one signature with your ledger. Given this is a batch transaction the signature will have a large number of parameters to verify. This is expected.

  After you complete the signature with your ledger, forge will broadcast the appropriate transactions on chain starting the ownership transfer.
  
  To finish this ownership transfer, you should go to the web UI for your Safe wallet, and note that a new transaction should be present with a signature from your ledger device!

  The final step is to gather the other signatures required to reach your wallets threshold, and execute the transaction with the web UI.



# Security considerations

## Deployment

### Cross-Chain Security

⚠️ **CRITICAL: Each chain MUST have its own separate contract deployments.**

**Required separate deployments per chain:**

1. **`EspressoTEEVerifier`** - Your main TEE verifier contract
2. **`EspressoNitroTEEVerifier`** - Nitro-specific verifier  
3. **`EspressoSGXTEEVerifier`** - SGX-specific verifier
4. **Automata `NitroEnclaveVerifier`** - ⚠️ **MUST be chain-specific!**
5. **Automata `V3QuoteVerifier`** (for SGX) - ⚠️ **MUST be chain-specific!**

**Why separate deployments are CRITICAL:**

1. **Independent State Management**
   - Each contract maintains on-chain state (approved enclave hashes, registered signers)
   - State is NOT synchronized across chains
   - Revoking a hash on one chain does NOT affect other chains

2. **ZK Configuration Control**
   - Each Automata contract has its own ZK verifier configuration
   - You validate against specific verifier IDs per chain
   - Shared Automata contracts would create single point of failure across all chains

3. **Security Isolation**
   - Different chains may have different threat models
   - Security policies can be chain-specific  
   - Compromise on one chain should NOT affect others
   - Prevents cross-chain authorization bypass

4. **Governance Independence**
   - Each chain can have different owners/multisigs
   - Approval workflows can differ per chain
   - No single entity controls all chains
   - Distributed trust model

**⚠️ IMPORTANT: Automata Dependencies Must Be Chain-Specific**

Do NOT use the same Automata contract across multiple chains! Each chain needs:

```
For Nitro TEE:
  ✅ Chain A: NitroEnclaveVerifier at 0xAAA...
  ✅ Chain B: NitroEnclaveVerifier at 0xBBB... (different!)
  ❌ DO NOT: Use same NitroEnclaveVerifier on both chains

For SGX TEE:
  ✅ Chain A: V3QuoteVerifier at 0xCCC...
  ✅ Chain B: V3QuoteVerifier at 0xDDD... (different!)
  ❌ DO NOT: Use same V3QuoteVerifier on both chains
```

**Why this matters:**
- Each Automata contract has mutable ZK configuration
- Your security validation caches the expected config per deployment
- Shared Automata = single point of configuration control across chains
- Separate Automata = isolated security boundaries

**Verify Automata deployments:**

Check Automata's documentation for chain-specific addresses:
- Nitro: https://github.com/automata-network/aws-nitro-enclave-attestation
- SGX: https://github.com/automata-network/automata-dcap-attestation

**Example: Current Mainnet Deployments**

```
EspressoTEEVerifier Contracts (Our Deployments):
  ApeChain (33139):      0x4fd6D0995B3016726D5674992c1Ec1bDe0989cF5
  AppChain (466):        0xcC758349CBd99bAA7fAD0558634dAaB176c777D0
  Huddle01:              0x2E01FA49cB3C3Ff09a5908165A5b5cB7f5cDF271
  NodeOps:               0xE0032d5a83f082aC05E66C31dcAbd84bc461b767
  Rufus:                 0xFcb6371757DE81DeaDbE8c13e36bFD7A261dD263
  T3rn:                  0xf252DDe41C679B2959d7C3a2Ea0bC2fA9dE7Eab7

✅ Each chain has unique address (correct!)
✅ Each references chain-specific Automata contracts
```

### Pre-Deployment Checklist

Before deploying to production, verify:

- [ ] **External dependencies verified:**
  - [ ] Automata `NitroEnclaveVerifier` address confirmed for target chain
  - [ ] ⚠️ **Verify NitroEnclaveVerifier is DIFFERENT for each chain** (do not reuse!)
  - [ ] Automata `V3QuoteVerifier` address confirmed for target chain (SGX)
  - [ ] ⚠️ **Verify V3QuoteVerifier is DIFFERENT for each chain** (do not reuse!)
  - [ ] Verify external contracts on block explorer
  - [ ] Check Automata contract owner and governance model
  
- [ ] **Initial configuration prepared:**
  - [ ] SGX mrEnclave hashes computed and documented
  - [ ] Initial approved hashes ready
  
- [ ] **Governance setup:**
  - [ ] Owner address configured (recommend multisig)
  - [ ] Ownership transfer process documented
  - [ ] Emergency response procedures established

### Post-Deployment Actions

**Immediately after deployment:**

1. **Verify contracts on block explorer**
   ```bash
   forge verify-contract <address> EspressoNitroTEEVerifier --chain <chain-id>
   ```

2. **Register initial enclave hashes**
   ```bash
   cast send <verifier-address> \
     "setEnclaveHash(bytes32,bool,uint8)" \
     <pcr0-hash> true 0 \
     --private-key $PRIVATE_KEY
   ```

3. **Transfer ownership to multisig** (recommended)
   ```bash
   forge script scripts/MultiSigTransfer.s.sol --broadcast
   ```

4. **Test with actual TEE attestation**
   - Generate test attestation from your TEE
   - Call registerService() with real data
   - Verify signer is registered correctly

5. **Set up monitoring**
   - Monitor Automata contract configuration changes
   - Alert on unexpected registration patterns
   - Track signer counts per enclave hash