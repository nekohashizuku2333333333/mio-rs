#!/usr/bin/env bash
# Compare upstream mio with the last fully verified revision in upstream.lock.toml.
#
# Exit codes:
#   0  upstream main exactly matches the locked revision
#   10 upstream changed and needs review/porting
#   2  local setup or lock-file error
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
UPSTREAM_URL="${UPSTREAM_URL:-https://github.com/orgmio/mio.git}"
UPSTREAM_DIR="${UPSTREAM_DIR:-$ROOT/.research/upstream-mio}"
LOCK_FILE="$ROOT/upstream.lock.toml"

if [[ ! -f "$LOCK_FILE" ]]; then
  echo "missing $LOCK_FILE" >&2
  exit 2
fi

if [[ -d "$UPSTREAM_DIR/.git" ]]; then
  origin_url="$(git -C "$UPSTREAM_DIR" remote get-url origin)"
  if [[ "$origin_url" != "$UPSTREAM_URL" ]]; then
    echo "unexpected origin in $UPSTREAM_DIR: $origin_url" >&2
    echo "expected $UPSTREAM_URL; remove the cache or set UPSTREAM_DIR" >&2
    exit 2
  fi
  if ! git -C "$UPSTREAM_DIR" fetch --tags --prune origin \
    '+refs/heads/*:refs/remotes/origin/*'; then
    echo "failed to fetch $UPSTREAM_URL" >&2
    exit 2
  fi
  git -C "$UPSTREAM_DIR" switch --detach origin/main >/dev/null 2>&1
else
  mkdir -p "$(dirname "$UPSTREAM_DIR")"
  if ! git clone --filter=blob:none --branch main \
    "$UPSTREAM_URL" "$UPSTREAM_DIR"; then
    echo "failed to clone $UPSTREAM_URL" >&2
    exit 2
  fi
fi

read_lock() {
  local key="$1"
  awk -v key="$key" '
    $1 == key && $2 == "=" {
      value = $3
      gsub(/^"|"$/, "", value)
      print value
      exit
    }
  ' "$LOCK_FILE"
}

locked_commit="$(read_lock commit)"
locked_tag="$(read_lock tag)"
head_commit="$(git -C "$UPSTREAM_DIR" rev-parse HEAD)"
head_tag="$(git -C "$UPSTREAM_DIR" describe --tags --exact-match 2>/dev/null || echo untagged)"
latest_tag="$(git -C "$UPSTREAM_DIR" tag --list 'v[0-9]*' --sort=-version:refname | head -n 1)"
if [[ -n "$latest_tag" ]]; then
  latest_tag_commit="$(git -C "$UPSTREAM_DIR" rev-list -n 1 "$latest_tag")"
else
  latest_tag_commit=""
fi
protocol_version="$(awk -F'"' '/^const Version =/ { print $2; exit }' "$UPSTREAM_DIR/protocol/version.go")"
binary_version="$(awk -F'"' '/^[[:space:]]*const Version =/ && $2 ~ /^[0-9]+\.[0-9]+\.[0-9]+$/ { print $2; exit }' "$UPSTREAM_DIR/cmd/version.go")"

printf 'locked_commit=%s\n' "$locked_commit"
printf 'upstream_head=%s\n' "$head_commit"
printf 'locked_tag=%s\n' "$locked_tag"
printf 'upstream_head_tag=%s\n' "$head_tag"
printf 'latest_tag=%s\n' "$latest_tag"
printf 'latest_tag_commit=%s\n' "$latest_tag_commit"
printf 'binary_version=%s\n' "$binary_version"
printf 'protocol_version=%s\n' "$protocol_version"

if [[ -z "$locked_commit" || -z "$head_commit" ]]; then
  echo "could not resolve lock or upstream commit" >&2
  exit 2
fi

if [[ "$head_commit" == "$locked_commit" ]]; then
  echo "status=up-to-date"
  exit 0
fi

echo "status=changed"
echo
echo "commits since locked revision:"
git -C "$UPSTREAM_DIR" log --oneline --decorate "$locked_commit..HEAD"
echo
echo "changed files:"
git -C "$UPSTREAM_DIR" diff --stat "$locked_commit..HEAD"
exit 10