# Claude on GitHub

Ported from `EspressoSystems/espresso-network` (`.github/claude` at commit `51254487`). `claude_gh.py`, `mention.md`,
`code-review.md`, `pyproject.toml` and `uv.lock` are unchanged copies, so fixes there can be copied over directly.
`review-standard.md` and the severity list in `review.md` are written for this repo's contracts. Backport review mode
and the offline eval were left out. `claude_gh.py` still picks `review-backport.md` (not shipped here) when
`<workdir>/tmp/is-backport` exists. That branch is unreachable only because `claude-job.yml` runs `rm -rf pr/tmp`
before the review, so keep that step.

## Files

| File                 | Purpose                                                                    |
| -------------------- | -------------------------------------------------------------------------- |
| `claude_gh.py`       | The CLI the workflows call.                                                |
| `review.md`          | Shared part of the `review` job: inputs, prior threads, findings, output.  |
| `review-standard.md` | Review procedure for this repo, placed before `review.md`.                 |
| `mention.md`         | Prompt for `@claude` mentions.                                             |
| `code-review.md`     | Appended to the system prompt of the `/code-review` comment command.       |
| `tests/`             | Unit tests for `claude_gh.py`. No network.                                 |

## How it runs

Three workflows use it:

- `.github/workflows/claude-review.yml`: reviews non-draft PRs from branches in this repo (not forks, not Dependabot)
  when they are opened, reopened or marked ready for review.
- `.github/workflows/claude.yml`: comment commands, for org owners, members and collaborators.
  - `@claude <question>` on an issue or PR: Claude replies in the thread. It never edits files, commits or pushes.
  - `/review` (owners and members): re-runs the review on the PR's current head.
  - `/code-review [low|medium|high|xhigh|max] [opus|sonnet|haiku|fable|claude-<id>]` (owners and members): runs Claude
    Code's built-in code review. Defaults: `high`, `opus`.
- `.github/workflows/claude-job.yml`: the shared job both of the above call. It has three jobs:

| Job     | GitHub token                   | Runs Claude | What it does                                                          |
| ------- | ------------------------------ | ----------- | --------------------------------------------------------------------- |
| `start` | write (PRs, issues)            | No          | Posts a status comment.                                               |
| `run`   | read only, plus the API key    | Yes         | Claude reads the PR and records the comments it wants to post to a file (`tmp/actions.json`). It cannot post anything itself. |
| `apply` | write (contents, PRs, issues)  | No          | Validates each recorded action and posts it, then edits the status comment with the summary and cost. |

Claude never holds a write token. It has no Bash: only Read, Grep and Glob on the checkout, and a fixed set of GitHub
tools (`pr_diff`, `pr_view`, `inline_comment`, `reply`, `comment`, `resolve_thread`) bound to the triggering PR or
issue. A tool call whose text contains the GitHub token or the API key is refused. `apply` only resolves threads that
Claude started on the same PR. `contents: write` on `apply` is there because GitHub refuses `resolveReviewThread` with
`contents: read`.

Comments are posted as `github-actions[bot]` and start with the hidden marker `<!-- claude-gh -->`, which is how
`scripts/fetch-pr-team-comments` and `claude_gh.py` tell Claude's comments apart from other bot output.

## Development

Requires [uv](https://docs.astral.sh/uv/) (Python 3.11 or newer is installed by uv if needed). From `.github/claude/`:

```sh
uv run --locked pytest           # unit tests
uv run --locked ruff check .     # lint
uv run --locked ruff format .    # format
```
