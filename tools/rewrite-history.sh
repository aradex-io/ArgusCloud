#!/usr/bin/env bash
# scripts/rewrite-history.sh
#
# One-time rewrite of the 9 application-review commits on `main` to:
#   (1) strip lines matching `https://claude.ai/code/session_*`
#   (2) strip AI-attribution footers and Co-Authored-By: Claude trailers
#   (3) set author/committer of those 9 commits to jeremylaratro
#
# The merge commit `aedc00e` is preserved (already authored correctly).
#
# Pre-flight:
#   1. Temporarily disable branch protection on `main` (admin only).
#   2. Make sure no one else is pushing to `main`.
#   3. Run from a clean working tree on `main`, synced with origin/main.
#
# After running:
#   1. Inspect: `git log --oneline -15`
#   2. Force-push: `git push --force-with-lease origin main`
#   3. Re-enable branch protection.
#   4. Notify any collaborator who may have cloned to re-clone or rebase.

set -euo pipefail

REWRITE_RANGE_START="6412f0f05b6553f11ce8ab4a0ced0c8ff46e52c2"
MERGE_COMMIT_TO_PRESERVE="aedc00ec51477deaa29fbda60730d7ddf8557824"

if [ "$(git rev-parse --abbrev-ref HEAD)" != "main" ]; then
    echo "error: must run on 'main' branch" >&2
    exit 1
fi

if [ -n "$(git status --porcelain)" ]; then
    echo "error: working tree is dirty; commit or stash first" >&2
    exit 1
fi

git fetch origin main
if [ "$(git rev-parse HEAD)" != "$(git rev-parse origin/main)" ]; then
    echo "error: local main is not aligned with origin/main; reset --hard origin/main first" >&2
    exit 1
fi

# Sanity: the start SHA must be reachable.
if ! git cat-file -e "${REWRITE_RANGE_START}^{commit}"; then
    echo "error: commit ${REWRITE_RANGE_START} not reachable; aborting" >&2
    exit 1
fi

echo "Rewriting ${REWRITE_RANGE_START}^..HEAD ..." >&2

FILTER_BRANCH_SQUELCH_WARNING=1 git filter-branch -f \
    --env-filter "
        if [ \"\$GIT_COMMIT\" != \"${MERGE_COMMIT_TO_PRESERVE}\" ]; then
            export GIT_AUTHOR_NAME='jeremylaratro'
            export GIT_AUTHOR_EMAIL='62393443+jeremylaratro@users.noreply.github.com'
            export GIT_COMMITTER_NAME='jeremylaratro'
            export GIT_COMMITTER_EMAIL='62393443+jeremylaratro@users.noreply.github.com'
        fi
    " \
    --msg-filter '
        sed -E \
            -e "/^https:\/\/claude\.ai\/code\/session_/d" \
            -e "/^Generated with .*Claude Code/d" \
            -e "/^Co-Authored-By: Claude/d" \
        | awk "BEGIN{blank=0} /^\$/{blank++; next} {while(blank-->0)print \"\"; blank=0; print}"
    ' \
    "${REWRITE_RANGE_START}^..HEAD"

# Drop filter-branch's safety backup so subsequent runs are clean.
git update-ref -d "refs/original/refs/heads/main" 2>/dev/null || true

echo "" >&2
echo "Rewrite complete. Verify with:" >&2
echo "  git log --format='%h %an %s' -12" >&2
echo "  git log --format='%B' ${REWRITE_RANGE_START}^..HEAD | grep -c 'claude.ai/code/session'    # should print 0" >&2
echo "" >&2
echo "Then push:" >&2
echo "  git push --force-with-lease origin main" >&2
