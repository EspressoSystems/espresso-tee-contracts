## Inputs

- PR description: `pr_view`. Diff: `pr_diff`, also in `./tmp/pr.diff`. The diff is the scope.
- Checkout: the PR head. Read and Grep it for surrounding code, callers, tests.
- Earlier review comments: `./tmp/pr-review-comments.json`.

## Scope

Perform static review only; CI runs `forge build --deny warnings`, `forge fmt --check`, `forge test`, Slither and the
storage layout snapshot check separately. Review whether tests are adequate, not whether they pass.

## Prior threads

Read `./tmp/pr-review-comments.json` before anything else.

- Skip findings any reviewer already raised.
- Own threads: author `claude`, or author `github-actions` with a root body starting with `<!-- claude-gh -->`. For each
  unresolved one: `reply` (comment_id = root comment `databaseId`) on what changed; `resolve_thread` if fixed, explained
  or answered. Never resolve others' threads.

## Findings

- Call `candidate` the moment a possible defect is noticed, before investigating further.
- Keep every candidate with a nameable failure scenario, including half-believed ones. Dropping those is the main cause
  of missed bugs.
- Before posting, call `verdict` for every candidate: `wrong` only when quoted code shows the candidate misreads it;
  `duplicate` when another candidate covers it; otherwise `kept`.
- Low impact, "not a regression", "acceptable", "unlikely" or "probably fine" are not grounds to discard: keep the
  candidate and lower its severity to concern or nit.
- Post every kept candidate: max 10, most severe first, correctness before cleanup.
- Each: `path`, `line` (RIGHT side of the diff), one-line summary, failure scenario (inputs/state -> wrong result).
- Severity:
  - **blocking**: security or verification correctness (a signer, enclave hash or attestation accepted that should
    not be, or rejected that should be), missing or wrong access control, funds or ownership at risk, upgrade safety
    (storage layout, initializers, `_disableInitializers`), breaking a public interface, event or error that callers
    or the Go bindings rely on. A state update or check the existing path performs and the new path skips or can skip
    is blocking. Also blocking: a deploy script that leaves a contract uninitialized, unowned or owned by the wrong
    address.
  - **should fix**: bugs, missing tests for changed behavior, missing event for a state change, Go bindings or README
    deployment steps not updated for a changed interface.
  - **concern**: design or architecture trade-off.
  - **nit**: small cleanup.
- Do not report: intentional TODOs, micro-optimizations, anything CI checks.

## Output

1. One `inline_comment` per finding:

   ```markdown
   **<severity>**: <title>

   <Failure scenario, 1-3 sentences.>

   <Fix: `suggestion` block if it replaces the line, else one sentence.>
   ```

2. Last, one `comment`:

   ```markdown
   <1-3 lines: what the PR does.>

   - **<severity>**: <few words> ([path:line](https://github.com/<repo>/blob/<head sha>/<path>#L<line>))

   Checked: <what was verified, e.g. callers of X, failure paths of Y, storage round trip>.
   ```

   No findings: `No issues found.` plus the `Checked:` line. No praise, no restating the diff.
