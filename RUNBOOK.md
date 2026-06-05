# TEE Verifier Deployment Runbook

Ops guide for deploying / upgrading the on-chain TEE attestation stack and wiring it into rollups via the prover service. Companion to the architectural docs in [`README.md`](./README.md).

## Mental model

- **Parent chain** (Eth Sepolia, Arb One, …): hosts one shared `NitroEnclaveVerifier` + `SP1Verifier` pair. One prover service per `(parent, env)` serves all rollups on that parent.
- **Rollup ("chain")**: has its own `EspressoTEEVerifier` + `EspressoNitroTEEVerifier` deployed on the parent it settles to, pointing at the shared `NitroEnclaveVerifier`. Adding a rollup does **not** create a new `.tf`.

`attestation-verifier-deploy` layout: branches `main`/`nitro-testnets`/`nitro-mainnets` = devnet/testnet/mainnet envs. Files `verifier.tf` (eth) and `arb-verifier.tf` (arb) hold the parent-chain `NITRO_VERIFIER_ADDRESS` — the single source of truth.

## Pick your scenario

| Case | Trigger | On-chain | Deploy-repo |
|---|---|---|---|
| **A. SP1 version bump** on a parent chain (e.g. v5 → v6) | Roll out across every rollup using that parent. | Deploy new `SP1Verifier`, call `setZkConfiguration` on existing `NitroEnclaveVerifier`. | **None** — `NITRO_VERIFIER_ADDRESS` unchanged. |
| **B. Add a new chain (rollup)** | "Spin up Rollup-X that settles to Eth Sepolia." | Deploy this rollup's own `EspressoTEEVerifier` + `EspressoNitroTEEVerifier` on the parent, pointing at the parent's existing `NitroEnclaveVerifier`. Register the rollup's enclave hashes. | **None** — the existing prover service for that parent already serves it. |
| **C. Redeploy `NitroEnclaveVerifier`** on a parent chain | Owner key lost, or bytecode no longer matches the current Automata release. Rare. | Redeploy `NitroEnclaveVerifier`, repoint every affected Espresso wrapper via `setNitroEnclaveVerifier`. | Update `NITRO_VERIFIER_ADDRESS` in the parent's `.tf`. |

Espresso wrappers (`EspressoTEEVerifier`, `EspressoNitroTEEVerifier`) are never redeployed for A or C — enclave hashes and signer registry live in `EspressoNitroTEEVerifier` storage and survive inner-verifier swaps. They *are* deployed fresh for B (one set per new rollup).

## Reference deployment (Arbitrum Sepolia, 2026-06-05)

Known-good Case-A pipeline result, useful as a debugging baseline:
- NitroEnclaveVerifier: `0xe8Ad5DAE5508adb3f52e689Ce77abEeE2C8D16c1`
- SP1Verifier v6.1.0: `0x50a24cc21Fa35054179Ebcc7611CC8E29fd70aDB`
- Real-proof verify tx: _(fill in after smoke test)_

## Prerequisites

```bash
brew install foundry jq openssl protobuf
git submodule update --init --recursive
```

`.env` at repo root:
- `RPC_URL`, `CHAIN_ID` — parent chain RPC + id.
- `PRIVATE_KEY` — single EOA used as deployer **and** as contract owner for `setZkConfiguration` / `setNitroEnclaveVerifier`. For Safe-owned contracts, skip the `cast send` lines below and propose via Safe UI instead.
- `ETHERSCAN_API_KEY` — Etherscan V2.
- `NETWORK_PRIVATE_KEY` — Succinct prover-network key (smoke test only, ~0.5 PROVE per run). Separate account from `PRIVATE_KEY`.

## A — SP1 version bump on an existing parent chain

This is the flow for the current SP1 v5→v6 migration on each parent already in `attestation-verifier-deploy`.

1. **Pull the latest Automata release.** Pick the tag this SP1 version targets from [automata-network/aws-nitro-enclave-attestation/releases](https://github.com/automata-network/aws-nitro-enclave-attestation/releases), bump the submodule, commit, and rebuild. Skip only if it's already at the intended release.
   ```bash
   git -C lib/aws-nitro-enclave-attestation fetch --tags
   git -C lib/aws-nitro-enclave-attestation checkout <release-tag>
   git submodule update --init --recursive
   forge build
   ```

2. **Find the existing `NitroEnclaveVerifier`.** Check out the deploy-repo branch matching the environment, open the parent's `.tf`, copy `NITRO_VERIFIER_ADDRESS` → `$NITRO`.

3. **Sanity-check the deployed bytecode matches the current Automata release.** If this fails, the source changed and you actually need Case C.
   ```bash
   forge build
   cast code $NITRO --rpc-url "$RPC_URL" | shasum -a 256
   jq -r '.deployedBytecode.object' \
     lib/aws-nitro-enclave-attestation/contracts/out/NitroEnclaveVerifier.sol/NitroEnclaveVerifier.json \
     | shasum -a 256
   # The two hashes must match.
   ```

4. **Deploy a fresh `SP1Verifier`** (currently v6.1.0):
   ```bash
   ./scripts/deploy-sp1-verifier.sh
   ```
   The script runs from inside the Automata project so verification succeeds (running `forge create` from this repo's root deploys un-verifiable bytecode). Record the printed address as `$NEW_SP1`. ("Could not detect deployment" is a slow-RPC false negative — `cast code` to confirm.)

5. **Reconfigure the existing `NitroEnclaveVerifier`** (owner tx; via Safe UI if multisig):
   ```bash
   SAMPLES=lib/aws-nitro-enclave-attestation/samples
   V_ID=$(jq -r .program_id.verifier_id        "$SAMPLES/sp1_program_id.json")
   A_ID=$(jq -r .program_id.aggregator_id      "$SAMPLES/sp1_program_id.json")
   VP_ID=$(jq -r .program_id.verifier_proof_id "$SAMPLES/sp1_program_id.json")

   cast send "$NITRO" \
     "setZkConfiguration(uint8,(bytes32,bytes32,address),bytes32)" \
     2 "($V_ID,$A_ID,$NEW_SP1)" "$VP_ID" \
     --rpc-url "$RPC_URL" --private-key "$PRIVATE_KEY"
   ```
   Verify the update landed:
   ```bash
   cast call "$NITRO" "getZkConfig(uint8)" 2 --rpc-url "$RPC_URL"
   ```
   Returns the tuple `(verifierId, aggregatorId, zkVerifier)`. The `zkVerifier` field (third / last) must equal `$NEW_SP1`.

6. **Bump the prover image** in `attestation-verifier-deploy` if the prover SDK version moved with this SP1 release (e.g. v5→v6). Update `image = "ghcr.io/espressosystems/attestation-verifier-zk:sha-<NEW>"` in both `verifier.tf` and `arb-verifier.tf` (current target: `sha-1c58c71`). `terraform apply` after merge.

   `NITRO_VERIFIER_ADDRESS` itself is unchanged, but the prover binary must produce proofs matching the new on-chain `VERIFIER_HASH`. **Sequence to minimize outage**: deploy new `SP1Verifier` → bump image + `terraform apply` → call `setZkConfiguration` (step 5). The bump-then-config order keeps the gap (during which `verify()` reverts) to a single block.

7. Smoke test against the deployed prover URL.

## B — Add a new chain (rollup)

Deploy Espresso TEE wrapper contracts for the new rollup on the parent chain it settles to. The `NitroEnclaveVerifier` and `SP1Verifier` are reused from the parent — do **not** deploy new ones.

1. **Look up the parent's `NitroEnclaveVerifier`.** In `attestation-verifier-deploy`, on the branch matching the environment (`main`/`nitro-testnets`/`nitro-mainnets`), open the parent's `.tf` (`verifier.tf` for eth, `arb-verifier.tf` for arb) and read `NITRO_VERIFIER_ADDRESS`.

2. **Sanity-check the bytecode matches the current Automata release** (same check as Case A step 3). If it doesn't, do Case C first.

3. **Deploy this rollup's Espresso TEE wrappers** using the existing `DeployTEEVerifier.s.sol` script, which takes the inner verifier from env:
   ```bash
   export NITRO_VERIFIER_ADDRESS=<parent's address from step 1>
   forge clean
   FOUNDRY_PROFILE=nitro forge script scripts/DeployTEEVerifier.s.sol:DeployTEEVerifier \
     --rpc-url "$RPC_URL" --private-key "$PRIVATE_KEY" --broadcast \
     --verify --verifier etherscan --chain "$CHAIN_ID"
   ```
   This deploys a new `EspressoTEEVerifier` proxy + `EspressoNitroTEEVerifier` for this rollup, wired to the shared `NitroEnclaveVerifier`.

4. **Register the rollup's initial enclave hashes** (PCR0 values from its TEE) on the new `EspressoNitroTEEVerifier`. See `src/EspressoNitroTEEVerifier.sol` for the setter.

5. **No `attestation-verifier-deploy` change** — the existing prover service for that parent already serves the new rollup. Hand the rollup's integration the new `EspressoTEEVerifier` proxy address.

6. Smoke test.

## C — Redeploy `NitroEnclaveVerifier` on a parent chain

Only when Case A's bytecode check fails or you've lost the owner key. Affects every rollup whose Espresso wrapper points at the old address.

1. Deploy both inner verifiers. The script prints addresses on its last two lines:
   ```bash
   forge clean
   ./scripts/deploy-nitro-enclave-verifier.sh --force | tee /tmp/deploy.log
   NEW_NITRO=$(awk -F': ' '/NitroEnclaveVerifier: /{print $2}' /tmp/deploy.log | tail -1)
   NEW_SP1=$(awk -F': '   '/SP1Verifier: /{print $2}'         /tmp/deploy.log | tail -1)
   echo "$NEW_NITRO $NEW_SP1"
   ```

2. **Repoint every affected rollup's Espresso wrapper** (owner tx on each `EspressoTEEVerifier`; Safe UI if multisig). Enumerate them from the README's "Current Mainnet Deployments" table for the parent in question:
   ```bash
   cast send "$ESPRESSO_TEE_VERIFIER" \
     "setNitroEnclaveVerifier(address)" "$NEW_NITRO" \
     --rpc-url "$RPC_URL" --private-key "$PRIVATE_KEY"
   ```

3. In the deploy repo, update `NITRO_VERIFIER_ADDRESS` in the parent's `.tf` to `$NEW_NITRO`. `terraform apply` after merge.

4. Smoke test.

## Smoke test (all cases)

Confirms prover ↔ on-chain version pair actually verifies. ~0.5 PROVE per run.

Set the addresses you're testing against. `$NITRO` is the `NitroEnclaveVerifier` (Case C → `$NEW_NITRO`; A/B → the parent's existing one). `$SP1` is the inner SP1Verifier (Case A/C → `$NEW_SP1`; B → read the `zkVerifier` field from `getZkConfig(2)` on `$NITRO`):
```bash
NITRO="${NEW_NITRO:-$NITRO}"
SP1="${NEW_SP1:?set NEW_SP1 to the on-chain SP1Verifier address}"
```

1. Run the prover service locally pointed at the deployment under test. `$NETWORK_PRIVATE_KEY` is the Succinct prover-network key (separate from `$PRIVATE_KEY`):
   ```bash
   cd ../attestation-verifier-zk
   cat > .env <<EOF
   NITRO_VERIFIER_ADDRESS=$NITRO
   RPC_URL=$RPC_URL
   NETWORK_PRIVATE_KEY=$NETWORK_PRIVATE_KEY
   NETWORK_RPC_URL=https://rpc.mainnet.succinct.xyz
   SP1_PROVER=network
   SKIP_TIME_VALIDITY_CHECK=true
   RUST_LOG=info
   HOST=127.0.0.1
   PORT=8080
   EOF
   cargo run --release
   ```

2. Verify the version handshake before broadcasting (cheap):
   ```bash
   curl -s -X POST http://127.0.0.1:8080/generate_proof \
     --data-binary @sample_reports/nitro_attestation_data.bin -o /tmp/proof.json
   jq -r '.zkvm_version, .program_id.verifier_id' /tmp/proof.json
   cast call "$NITRO" "getZkConfig(uint8)" 2 --rpc-url "$RPC_URL"   # zkVerifier (3rd field) must equal $SP1
   cast call "$SP1"   "VERIFIER_HASH()"     --rpc-url "$RPC_URL"    # bytes32 hash baked into proofs
   ```
   `VERIFIER_HASH()` returns a `bytes32`. Its first 4 bytes must equal the first 4 bytes of `onchain_proof` in `/tmp/proof.json` — that prefix is the SP1 verifier selector the prover embeds.

3. Dry-run verify on-chain (no gas):
   ```bash
   OUTPUT=$(jq -r .raw_proof.journal /tmp/proof.json)
   PROOF=$(jq -r .onchain_proof /tmp/proof.json)
   cast call "$NITRO" "verify(bytes,uint8,bytes)" "$OUTPUT" 2 "$PROOF" --rpc-url "$RPC_URL"
   ```
   Returns a decoded `VerifierJournal` on success; reverts with a typed selector on mismatch.

4. Broadcast for the record:
   ```bash
   cast send "$NITRO" "verify(bytes,uint8,bytes)" "$OUTPUT" 2 "$PROOF" \
     --rpc-url "$RPC_URL" --private-key "$PRIVATE_KEY"
   ```
   Expect `status: 1` and an `AttestationSubmitted` event.

5. Promote: in the deploy repo, `terraform apply` for the affected task(s) and rerun step 2 against the deployed service URL.

## Troubleshooting

- **`Could not find protoc`** during `cargo run`: `brew install protobuf`.
- **`ResourceExhausted insufficient balance N PROVE`**: fund the prover-network account behind `NETWORK_PRIVATE_KEY`, or swap to a funded key (restart `cargo run` — env read at startup).
- **`forge create` says "Could not detect deployment"**: false negative on slow RPCs. `cast code <predicted address>` — if non-empty, contract is deployed.
- **`WrongVerifierSelector(received, expected)`** on `verify`: SP1Verifier and prover ELF on different versions. Recheck step 2 of the smoke test.
- **`verify` reverts with no clear selector**: stale or malformed `output`/`proofBytes`. Regenerate the proof; don't reuse a proof across reconfigs.
- **Multisig owner**: `setZkConfiguration`, `setNitroEnclaveVerifier`, `setRootCert`, `setEspressoNitroTEEVerifier` all go through Safe UI as proposals. `scripts/MultiSigTransfer.s.sol` only covers the initial *transfer to* multisig, not subsequent ops.

