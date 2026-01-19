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

### Cast

```shell
cast <subcommand>
```

### Help

```shell
forge --help
cast --help
```

# Development

For ease of development in go projects, we have included a small utility in this repo to generate go bindings for the TEEVerifier contracts present here.

This utility uses the bind v2 implementation from github.com/ethereum/go-ethereum/abi/abigen/bind.go

To generate these bindings for use in a go project, simply run `go run bindings/gen.go` from the root of this repo.
Afterwards the bindings should appear in bindings/go/espressogen/espressogen.go and can be linked into your project easily if you are using this repo as a git submodule.

## TEE Verifier Deployment

### 1. Clean Build Environment

Start with a fresh build to ensure as we need to build contracts with proper profiles for gas optimizations:

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
NITRO_ENCLAVE_HASH=<aws_nitro_pcr0_hash>
SGX_ENCLAVE_HASH=<sgx_enclave_measurement>
SGX_QUOTE_VERIFIER_ADDRESS=<quote_verifier_address_from_automata>  # From: https://github.com/automata-network/automata-dcap-attestation

# To be updated after deployment
NITRO_VERIFIER_ADDRESS=""
SGX_VERIFIER_ADDRESS=""
<!-- From https://github.com/automata-network/aws-nitro-enclave-attestation -->
NITRO_ENCLAVE_VERIFIER=""
```

Save the file then source it:

```bash
source .env
```

### 3. **Deployment Process**

1. **Deploy Nitro Verifier**
   Update the `.env` file with the Nitro Enclave Verifier address, which can be obtained from: https://github.com/automata-network/aws-nitro-enclave-attestation

   ```text
   NITRO_ENCLAVE_VERIFIER=<address of nitro verifier>
   ```

   then execute:

   ```bash
   FOUNDRY_PROFILE=nitro forge script scripts/DeployNitroTEEVerifier.s.sol:DeployNitroTEEVerifier \
       --rpc-url "$RPC_URL" \
       --private-key "$PRIVATE_KEY" \
       --broadcast \
       --verify --verifier etherscan --chain "$CHAIN_ID"
   ```

2. **Deploy SGX Verifier**

   ```bash
   FOUNDRY_PROFILE=sgx forge script scripts/DeploySGXTEEVerifier.s.sol:DeploySGXTEEVerifier \
       --rpc-url "$RPC_URL" \
       --private-key "$PRIVATE_KEY" \
       --broadcast \
       --verify --verifier etherscan --chain "$CHAIN_ID"
   ```

3. **Update Environment Variables**

   After successful AWS Nitro and SGX deployments update the `.env` file with:

   ```text
   NITRO_VERIFIER_ADDRESS=<deployed_nitro_address>
   SGX_VERIFIER_ADDRESS=<deployed_sgx_address>
   ```

4. **Deploy Espresso TEE Verifier**

   ```bash
   forge script scripts/DeployTEEVerifier.s.sol:DeployTEEVerifier \
       --rpc-url "$RPC_URL" \
       --private-key "$PRIVATE_KEY" \
       --broadcast \
       --verify --verifier etherscan --chain "$CHAIN_ID"
   ```

### 4. Post-Deployment

Verify all contracts on Block Explorer and ensure deployment artifacts are in deployments/<chain_id>/

### Transferring ownership of the TEEVerifier contracts to a multi-sig wallet

The script located at `scripts/MultiSigTransfer.s.sol` is meant to assist with this.

When run the script will first initiate transfer of the TEEVerifier contracts to the multi-sig wallet with the original owner wallet.
Then, the script will batch the `acceptOwnership()` transactions that need to be executed on the multi-sig wallet. It will require the user to sign
the proposal to the multi-sig wallet with a ledger containing an account that is a designated `signer` or `delegate`.

If the ledger signature fails, or is invalid, the entire script will revert, meaning that the initial ownership transfer will not be reflected on chain.

#### Compatibility:

Currently this script is _NOT_ compatible with ARB Sepolia, only ETH, ETH Sepolia, and ARB One. We hope to extend compatibility to ARB Sepolia in the future.

#### Usage

1.  Prepare your .env file.

Your .env file will need to contain the following items.

```bash
LEDGER_DERIVATION_PATH="m/44'/60'/0'/0/0" #Note, depending on what keys your ledger holds, this may be different.
MULTISIG_CONTRACT_ADDRESS="Your Multi-Sig address"
TEE_VERIFIER_ADDRESS="EspressoTEEVerifier contract address" #
PROPOSER_ADDRESS="Your Multi-sig signer address" #Note, this must be the same as the one provided by the derivation path.

ORIGINAL_OWNER_KEY="insert original EspressoTEEVerifier contract owner's private key here"
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

- MULTISIG_CONTRACT_ADDRESS: The address of your Multi-sig wallet on the chain you wish this transaction to occurr on.

- TEE_VERIFIER_ADDRESS: The address of the outer EspressoTEEVerifier contract.
  Note: this must be the outer TEEVerifier contract. The script locates the inner contracts by calling espressoNitroVerifier and espressoSGXVerifier on the outer contract.

- PROPOSER_ADDRESS: The address used to propose the transaction to the multi-sig wallet.
  Note: This must be the address associated with the account located at the wallets provided derivation path.

- ORIGINAL_OWNER_KEY: The private key of the account that owns the TEEVerifier contracts before the transfer of ownership.

- RPC_URL: Used for the `forge script` command for specifying the network to send the transaction to.
- CHAIN_ID: This is used for the `forge script` command for specifying the network to send the transaction to.

2.  Run the MultiSigTransfer script.

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
