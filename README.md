## Foundry

**Foundry is a blazing fast, portable and modular toolkit for Ethereum application development written in Rust.**

Foundry consists of:

- **Forge**: Ethereum testing framework (like Truffle, Hardhat and DappTools).
- **Cast**: Swiss army knife for interacting with EVM smart contracts, sending transactions and getting chain data.
- **Anvil**: Local Ethereum node, akin to Ganache, Hardhat Network.
- **Chisel**: Fast, utilitarian, and verbose solidity REPL.

## Documentation

https://book.getfoundry.sh/

## Usage

### Build

```shell
$ forge build
```

### Test

```shell
$ forge test
```

### Format

```shell
$ forge fmt
```

### Gas Snapshots

```shell
$ forge snapshot
```

### Anvil

```shell
$ anvil
```

### Cast

```shell
$ cast <subcommand>
```

### Help

```shell
$ forge --help
$ anvil --help
$ cast --help
```

## TEE Verifier Deployment

### 1. Clean Build Environment

Start with a fresh build to ensure as we need to build contracts with proper profiles for gas optimizations:

```bash
forge clean
```

### 2. **Environment Setup**

Create a `.env` file in the project root with the following variables:

```text
# Variables for script command
RPC_URL=<your-rpc-url>
PRIVATE_KEY=<your-private-key>
CHAIN_ID=<your-chain-id>
ETHERSCAN_API_KEY=<your-api-key>

# Variables for deployment
CERT_MANAGER_SALT=<your_salt_here>
NITRO_ENCLAVE_HASH=<aws_nitro_pcr0_hash>
SGX_ENCLAVE_HASH=<sgx_enclave_measurement>
SGX_QUOTE_VERIFIER_ADDRESS=<quote_verifier_address_from_automata>  # From: https://github.com/automata-network/automata-dcap-attestation

# To be updated after deployment
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
   FOUNDRY_PROFILE=nitro forge script scripts/DeployCertManager.sol:DeployCertManager \
       --rpc-url "$RPC_URL" \
       --private-key "$PRIVATE_KEY" \
       --chain-id "$CHAIN_ID" \
       --etherscan-api-key "$ETHERSCAN_API_KEY"  \
       --broadcast \
       --verify
   ```
1. **Deploy Nitro Verifier**
   After CertManager deployment update the `.env` file with:
   ```text
   CERT_MANAGER_ADDRESS=<deployed_cert_manager_address>
   ```
   then execute:
   ```bash
   FOUNDRY_PROFILE=nitro forge script scripts/DeployNitroTEEVerifier.s.sol:DeployNitroTEEVerifier \
       --contracts src/EspressoNitroTEEVerifier.sol \
       --rpc-url "$RPC_URL" \
       --private-key "$PRIVATE_KEY" \
       --chain-id "$CHAIN_ID" \
       --etherscan-api-key "$ETHERSCAN_API_KEY"  \
       --broadcast \
       --verify
   ```
1. **Deploy SGX Verifier**

   ```bash
   FOUNDRY_PROFILE=sgx forge script scripts/DeploySGXTEEVerifier.s.sol:DeploySGXTEEVerifier \
       --contracts src/EspressoSGXTEEVerifier.sol \
       --skip src/EspressoNitroTEEVerifier.sol \
       --rpc-url "$RPC_URL" \
       --private-key "$PRIVATE_KEY" \
       --chain-id "$CHAIN_ID" \
       --etherscan-api-key "$ETHERSCAN_API_KEY"  \
       --broadcast \
       --verify
   ```

1. **Update Environment Variables**

   After successful AWS Nitro and SGX deployments update the `.env` file with:

   ```text
   NITRO_VERIFIER_ADDRESS=<deployed_nitro_address>
   SGX_VERIFIER_ADDRESS=<deployed_sgx_address>
   ```

1. **Deploy Espresso TEE Verifier**
   ```bash
   forge script scripts/DeployTEEVerifier.s.sol:DeployTEEVerifier \
       --contracts src/EspressoTEEVerifier.sol \
       --rpc-url "$RPC_URL" \
       --private-key "$PRIVATE_KEY" \
       --chain-id "$CHAIN_ID" \
       --etherscan-api-key "$ETHERSCAN_API_KEY"  \
       --broadcast \
       --verify
   ```

### 4. Post-Deployment

Verify all contracts on Block Explorer and ensure deployment artifacts are in deployments/<chain_id>/
