# ArgusCloud — Contributor & AI Assistant Guidelines

This file is read by Claude Code (and other AI coding assistants) at the start of every session in this repository. Human contributors should follow the same rules.

## Author / commit policy

**All commits in this repository must be authored by `jeremylaratro`.**

- `user.name` = `jeremylaratro`
- `user.email` = `62393443+jeremylaratro@users.noreply.github.com`

The repo-local git config is already set. If you are an AI assistant or use a tool that overrides git author (e.g., GitHub Codespaces, Claude Code), verify with `git config user.email` before committing. If the value differs, run:

```bash
git config --local user.name "jeremylaratro"
git config --local user.email "62393443+jeremylaratro@users.noreply.github.com"
```

**Never** override these to `Claude <noreply@anthropic.com>`, `dependabot[bot]`, or any other identity unless explicitly instructed in writing for a specific commit.

## Commit message policy

Commit messages **must not** contain any of the following:

- `https://claude.ai/code/session_...` URLs
- `Generated with [Claude Code](https://claude.com/claude-code)` or similar attribution lines
- `Co-Authored-By: Claude <noreply@anthropic.com>` trailers
- Any other AI-tool attribution links or signatures

A `commit-msg` hook at `.githooks/commit-msg` rejects commits containing these patterns. To activate the hook locally, run once per clone:

```bash
git config core.hooksPath .githooks
```

This is also the first step performed by `make install`.

## Pull request policy

PR titles and bodies must follow the same rule: **no AI session links, no AI attribution lines.** When opening a PR from an AI-assisted change, strip any auto-generated footer before submitting.

## For AI assistants (Claude Code, Copilot, etc.)

1. **Read this file before your first commit.** The harness may have its own defaults; this file overrides them for this repo.
2. **Do not add session URLs to commit messages.** The `commit-msg` hook will reject them; you will waste time and produce a confused error.
3. **Use focused, descriptive commit messages.** Subject ≤ 72 chars; body wraps at 72; explain the *why*, not the *what*.
4. **Do not create commits that mix unrelated changes.** Group logically.
5. **Do not push directly to `main`.** Always use a feature branch and open a PR for review.
6. **Branch protection is enabled on `main`.** Force-pushes will be rejected.

## Development workflow

```bash
# First-time setup
make install         # installs dev deps + activates git hooks

# Day to day
make lint            # ruff check
make format          # ruff format + black
make typecheck       # mypy
make test            # pytest (cov-fail-under=40)
```

See `Makefile` for the full target list.

## History rewrite (one-time, by owner only)

To purge legacy AI session URLs from existing main history, temporarily lift branch protection on `main` and run:

```bash
./tools/rewrite-history.sh
```

That script is documented in-file. It only rewrites commits in a fixed range and only changes commit messages and author/committer of those specific SHAs — never anything outside that range. Re-enable branch protection immediately after pushing.
