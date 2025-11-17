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
CERT_MANAGER_ADDRESS=""
NITRO_VERIFIER_ADDRESS=""
SGX_VERIFIER_ADDRESS=""
```

Save the file then source it:

```bash
source .env
```

### 3. **Deployment Process**

1. If CertManager is not deployed on the given chain, deploy it first:

   ```bash
    forge script scripts/DeployCertManager.sol:DeployCertManager \
       --rpc-url "$RPC_URL" \
       --private-key "$PRIVATE_KEY" \
       --broadcast \
       --verify --verifier etherscan --chain "$CHAIN_ID"
   ```

2. **Deploy Nitro Verifier**
   After CertManager deployment update the `.env` file with:

   ```text
   CERT_MANAGER_ADDRESS=<deployed_cert_manager_address>
   ```

   then execute:

   ```bash
   FOUNDRY_PROFILE=nitro forge script scripts/DeployNitroTEEVerifier.s.sol:DeployNitroTEEVerifier \
       --rpc-url "$RPC_URL" \
       --private-key "$PRIVATE_KEY" \
       --broadcast \
       --verify --verifier etherscan --chain "$CHAIN_ID"
   ```

3. **Deploy SGX Verifier**

   ```bash
   FOUNDRY_PROFILE=sgx forge script scripts/DeploySGXTEEVerifier.s.sol:DeploySGXTEEVerifier \
       --rpc-url "$RPC_URL" \
       --private-key "$PRIVATE_KEY" \
       --broadcast \
       --verify --verifier etherscan --chain "$CHAIN_ID"
   ```

4. **Update Environment Variables**

   After successful AWS Nitro and SGX deployments update the `.env` file with:

   ```text
   NITRO_VERIFIER_ADDRESS=<deployed_nitro_address>
   SGX_VERIFIER_ADDRESS=<deployed_sgx_address>
   ```

5. **Deploy Espresso TEE Verifier**

   ```bash
   forge script scripts/DeployTEEVerifier.s.sol:DeployTEEVerifier \
       --rpc-url "$RPC_URL" \
       --private-key "$PRIVATE_KEY" \
       --broadcast \
       --verify --verifier etherscan --chain "$CHAIN_ID"
   ```

### 4. Post-Deployment

Verify all contracts on Block Explorer and ensure deployment artifacts are in deployments/<chain_id>/
