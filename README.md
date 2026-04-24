# Espresso TEE Contracts

This repository contains Solidity contracts for verifying attestations from AWS Nitro Enclaves. It is used in our integration projects including [optimism-espresso-integration](https://github.com/EspressoSystems/optimism-espresso-integration) and [nitro-espresso-integration](https://github.com/EspressoSystems/nitro-espresso-integration).

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

## Development

For ease of development in go projects, we have included a small utility in this repo to generate go bindings for the TEEVerifier contracts present here.

This utility uses the bind v2 implementation from github.com/ethereum/go-ethereum/abi/abigen/bind.go

To generate these bindings for use in a go project, simply run `go run bindings/gen.go` from the root of this repo.
Afterwards the bindings should appear in bindings/go/espressogen/espressogen.go and can be linked into your project easily if you are using this repo as a git submodule.

## TEE Verifier Deployment

`EspressoTEEVerifier` is deployed using the **OpenZeppelin v5.x Transparent Proxy pattern**, where the `TransparentUpgradeableProxy` automatically deploys its own `ProxyAdmin` contract internally and the `ProxyAdmin` owner controls upgrade capabilities.

`EspressoNitroTEEVerifier` is deployed as a non-proxy contract. To upgrade its logic, deploy a new implementation and call `setEspressoNitroTEEVerifier` on the `EspressoTEEVerifier` proxy (owner-only).

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
```

### 3. Deploying NitroEnclaveVerifier required for AWS Nitro
Deploy the verifier contract to your target network:

```bash
./scripts/deploy-nitro-enclave-verifier.sh --force
```

This script navigates into `lib/aws-nitro-enclave-attestation/contracts/` and runs both `deployVerifier()` and `deploySP1Verifier()` from the `NitroEnclaveVerifier.s.sol` forge script. It requires `RPC_URL` and `PRIVATE_KEY` to be set in your environment.


### 4. **Environment Setup** after NitroEnclaveVerifier deployment

```
# Variables for deployment
NITRO_ENCLAVE_VERIFIER=<nitro_enclave_verifier_address>

# To be updated after deployment (not needed before running DeployAllTEEVerifiers)
TEE_VERIFIER_ADDRESS=""
NITRO_VERIFIER_ADDRESS=""
```

Save the file then source it:

```bash
source .env
```

### 5. **Deployment Options**

You can deploy the verifier contracts in two ways:

#### Option A: Deploy All Contracts Together (Recommended)

This deploys the full Nitro verifier stack in a single script, handling the circular dependency automatically:

```bash
forge script scripts/DeployAllTEEVerifiers.s.sol:DeployAllTEEVerifiers \
    --rpc-url "$RPC_URL" \
    --private-key "$PRIVATE_KEY" \
    --broadcast \
    --verify --verifier etherscan --chain "$CHAIN_ID"
```

This script will:

1. Deploy `EspressoTEEVerifier` proxy (with a zero placeholder Nitro verifier address)
2. Deploy `EspressoNitroTEEVerifier` (linked to `EspressoTEEVerifier`)
3. Update `EspressoTEEVerifier` with the actual Nitro verifier address

#### Option B: Deploy Contracts Individually

If you prefer to deploy contracts separately, use the standalone scripts once the other side of the dependency is already known:

1. **Deploy Espresso TEE Verifier**

   Use this when you already know the Nitro verifier address and have set `NITRO_VERIFIER_ADDRESS` in your environment:

   ```bash
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

2. **Deploy Nitro Verifier**

   Use this when `TEE_VERIFIER_ADDRESS` already points to a deployed `EspressoTEEVerifier` proxy:

   ```bash
   FOUNDRY_PROFILE=nitro forge script scripts/DeployNitroTEEVerifier.s.sol:DeployNitroTEEVerifier \
       --rpc-url "$RPC_URL" \
       --private-key "$PRIVATE_KEY" \
       --broadcast \
       --verify --verifier etherscan --chain "$CHAIN_ID"
   ```

3. **Update `EspressoTEEVerifier` with the actual Nitro verifier address**

   If `EspressoTEEVerifier` was deployed before the Nitro verifier was wired, update it with:

   ```bash
   cast send $TEE_VERIFIER_ADDRESS "setEspressoNitroTEEVerifier(address)" $NITRO_VERIFIER_ADDRESS \
       --rpc-url "$RPC_URL" --private-key "$PRIVATE_KEY"
   ```

   Note: This step is not needed when using `DeployAllTEEVerifiers.s.sol`, which wires everything in a single script.

### 6. Post-Deployment

- Verify all contracts on Block Explorer
- Deployment artifacts are saved in `deployments/<chain_id>/`
- Each deployment JSON contains:
  - `EspressoTEEVerifier`: `proxy` (what users interact with) and `implementation` addresses
  - `EspressoNitroTEEVerifier`: single `nitroVerifier` address (no proxy)

### Transferring ownership of the TEEVerifier contracts to a multi-sig wallet

The script located at `scripts/MultiSigTransfer.s.sol` is meant to assist with this.

When run the script will first initiate transfer of the TEEVerifier contracts to the multi-sig wallet with the original owner wallet.
Then, the script will batch the `acceptOwnership()` transactions that need to be executed on the multi-sig wallet. It will require the user to sign
the proposal to the multi-sig wallet with a ledger containing an account that is a designated `signer` or `delegate`.

If the ledger signature fails, or is invalid, the entire script will revert, meaning that the initial ownership transfer will not be reflected on chain.

#### Compatibility

Currently this script is *NOT* compatible with ARB Sepolia, only ETH, ETH Sepolia, and ARB One. We hope to extend compatibility to ARB Sepolia in the future.

#### Usage

 1. Prepare your .env file.

  Your .env file will need to contain the following items.

  ```bash
  LEDGER_DERIVATION_PATH="m/44'/60'/0'/0/0" #Note, depending on what keys your ledger holds, this may be different.
  MULTISIG_CONTRACT_ADDRESS="Your Multi-Sig address"
  TEE_VERIFIER_ADDRESS="EspressoTEEVerifier contract address" #
  PROPOSER_ADDRESS="Your Multi-sig signer address" #Note, this must be the same as the one provided by the derivation path.

  ORIGINAL_OWNER_KEY="insert original EspressoTEEVerifier contract owner's private key here"
  RPC_URL="RPC URL for the chain you wish to execute on"
  CHAIN_ID="Chain ID of the network to execute transactions on"
  ````

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

- MULTISIG_CONTRACT_ADDRESS: The address of your Multi-sig wallet on the chain you wish this transaction to occurr on.

- TEE_VERIFIER_ADDRESS: The address of the outer EspressoTEEVerifier contract.
  Note: this must be the outer TEEVerifier contract that owns the Nitro verifier wiring.

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

  ```bash
  Error: Could not connect to Ledger device.
  Make sure it's connected and unlocked, with no other desktop wallet apps open.

  Context:
  - Sequence mismatch. Got 1 from device. Expected 0
  ```

  or

  ```bash
  Error: Ledger device: APDU Response error `Code 6985 ([APDU_CODE_CONDITIONS_NOT_SATISFIED] Conditions of use not satisfied)`
  ```

  Or even

  ```bash
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

## Security considerations

### Deployment

#### Cross-Chain Security

⚠️ **CRITICAL: Each chain MUST have its own separate contract deployments.**

**Required separate deployments per chain:**

1. **`EspressoTEEVerifier`** - Your main TEE verifier contract
2. **`EspressoNitroTEEVerifier`** - Nitro-specific verifier
3. **Automata `NitroEnclaveVerifier`** - ⚠️ **MUST be chain-specific!**

**Why separate deployments are CRITICAL:**

1. **Independent State Management**
   - Each contract maintains on-chain state (approved enclave hashes, registered signers)
   - State is NOT synchronized across chains
   - Revoking a hash on one chain does NOT affect other chains

2. **ZK Configuration Control**
   - Each Nitro verifier dependency has its own ZK verifier configuration
   - You validate against specific verifier IDs per chain
   - Shared verifier dependencies would create a single point of failure across all chains

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

```bash
For Nitro TEE:
  ✅ Chain A: NitroEnclaveVerifier at 0xAAA...
  ✅ Chain B: NitroEnclaveVerifier at 0xBBB... (different!)
  ❌ DO NOT: Use same NitroEnclaveVerifier on both chains
```

**Why this matters:**

- Each Automata contract has mutable ZK configuration
- Your security validation caches the expected config per deployment
- Shared Automata = single point of configuration control across chains
- Separate Automata = isolated security boundaries

**Verify Automata deployments:**

Check Automata's documentation for chain-specific addresses:

- Nitro: https://github.com/automata-network/aws-nitro-enclave-attestation

**Example: Current Mainnet Deployments**

```bash
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
  - [ ] Verify external contracts on block explorer
  - [ ] Check Automata contract owner and governance model

- [ ] **Initial configuration prepared:**
  - [ ] Nitro PCR0 hashes computed and documented
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


## License
Copyright (c) 2022 Espresso Systems. espresso-tee-contracts was developed by Espresso Systems. While we plan to adopt an open source license, we have not yet selected one. As such, all rights are reserved for the time being. Please reach out to us if you have thoughts on licensing.
