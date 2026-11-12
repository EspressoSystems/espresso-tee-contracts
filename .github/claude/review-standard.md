# PR review

Goal: find every real defect in the PR. Recall over precision.

- Steps 2-10 each collect up to 6 candidates. Do not judge them until Findings.

## Procedure

1. Map the change: what it touches (contracts in `src/`, deploy scripts in `scripts/`, tests in `test/`, Go bindings in
   `bindings/`, CI in `.github/`), and what it claims to fix or add.
2. Hunks. For each hunk, Read the whole enclosing function. Per line: which caller, input or state makes it wrong:
   wrong conditions or arithmetic, an inverted or missing `require`/`revert`, a check after the state change it should
   guard, a loop or array bounded by caller input.
3. Removed behavior and parity.
   - For each deleted or replaced line: name the invariant it enforced; find where the new code re-establishes it. Not
     found: candidate.
   - If the PR adds a path for something an existing path already does (another TEE type, another register or delete
     function, a sibling setter): Read the existing path. List its checks, state updates and events in order. For each,
     find the same in the new path. Missing or reordered: candidate. Example: `setEnclaveHash(false)` and
     `deleteEnclaveHashes` must leave the same state.
4. Failure paths. For each external call or early return between two state changes:
   - Does a revert leave nothing changed, or can a partial update persist (a `try`/`catch`, a low-level call whose
     result is ignored)?
   - Can the external call re-enter this contract before state is final?
5. Callers and callees. Grep every changed symbol in `src/`, `scripts/`, `test/` and `bindings/`. Per call site: new
   precondition, changed return value, revert or event. Per callee changed in the same PR: still safe here?
   - For each new or changed check: list every value its inputs take, including zero, `address(0)`, empty bytes, an
     unset mapping entry, and state written before an upgrade. A real value that now fails or passes: candidate.
6. Upgrade safety (contracts behind a proxy, `OwnableWithGuardiansUpgradeable` and its users):
   - Storage: no reordering, removal, type change or insertion before existing variables; new variables only appended
     or in a namespaced (ERC-7201) slot. If `.storage-layouts/` changed, explain why the change is safe.
   - Initializers: `initializer`/`reinitializer(n)` used correctly, constructor calls `_disableInitializers()`, every
     parent initializer called once, no initializer callable by anyone after deployment.
   - A change that existing deployed proxies need: an upgrade or migration step in the PR or the README.
7. Access control and verification (this repo decides which TEE signers are trusted):
   - Every function that changes trusted state (enclave hashes, signers, verifier addresses, owner, guardians) has the
     right modifier. Compare with sibling functions.
   - Signatures: digest covers everything the signer intends (chain id, contract address, TEE type, nonce or expiry
     where replay matters); `ECDSA.recover` result checked against the registered signer and not `address(0)`;
     malleable or zero signatures rejected.
   - Attestations and proofs: every field used from the verifier journal (`JournalValidation`, the Nitro verifier
     result) is checked before it is trusted: enclave measurement against the allowed hashes, timestamps and freshness,
     user data binding to the signer being registered. A field used but not validated: candidate.
   - Enclave hash and signer lifecycle: removing a hash or signer actually stops it verifying; re-adding cannot revive
     stale state; deletion cannot be bypassed by another path.
   - Events emitted for every trusted-state change, with the values off-chain monitoring needs.
   - External calls: return values checked, no reentrancy into trusted-state updates, untrusted contract addresses
     validated (non-zero, has code where it matters).
8. Deploy and ops scripts (`scripts/*.s.sol`, `scripts/*.sh`): contracts initialized in the same transaction as
   deployment, owner and guardians set to the intended addresses, verifier addresses match the chain (see the README's
   canonical `NitroEnclaveVerifier` table), no private keys or RPC secrets printed or committed.
9. Tests and docs.
   - Would any test fail without the change? Changed behavior without a test that pins it: candidate. Access control
     and revert paths need negative tests, not only the happy path.
   - NatSpec on new or changed public and external functions, events and errors matches their behavior (who may call
     it, what it reverts on, what it emits). Missing or now wrong: candidate.
10. Cleanup, only with a concrete cost: code duplicating an existing helper (name it); dead code; redundant storage
    reads or writes in a frequently called function; a special case where fixing the shared mechanism is simpler (name
    the change). Also `.github/`: PR controlled content (titles, branch names, bodies, files) reaching a shell or a
    prompt run with write tokens, `pull_request_target`, actions missing from `.github/workflows/actions.lock`.
