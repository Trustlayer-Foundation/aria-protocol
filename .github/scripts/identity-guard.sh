#!/usr/bin/env bash
# Every commit carries a DCO sign-off and no tool trailer. Contributors are
# people with names; the credit belongs to whoever wrote the change.
set -euo pipefail

BASE="${1:-}"; HEAD="${2:-HEAD}"; fail=0

# On a first push or after a force push the base is the zero SHA, or an object
# this clone does not have. Fall back to the head commit alone.
if [[ -z "$BASE" || "$BASE" =~ ^0+$ ]] || ! git cat-file -e "$BASE^{commit}" 2>/dev/null; then
  RANGE="$HEAD -n 1"
else
  RANGE="$BASE..$HEAD"
fi

# shellcheck disable=SC2086
for c in $(git rev-list $RANGE); do
  msg=$(git log -1 --format=%B "$c")
  an=$(git log -1 --format='%an <%ae>' "$c")

  if ! grep -qE "^Signed-off-by: .+ <.+@.+>" <<<"$msg"; then
    echo "::error::$c ($an) lacks a DCO Signed-off-by trailer — commit with git commit -s"
    fail=1
  fi

  if grep -qiE '^(Co-Authored-By|Generated-By|Assisted-By):' <<<"$msg"; then
    echo "::error::$c ($an) carries a tool trailer — not accepted"
    fail=1
  fi

  if [[ "$an" =~ users\.noreply\.github\.com ]]; then
    echo "::warning::$c uses a noreply email; the contributor will show as anonymous"
  fi
done

exit $fail
