#!/usr/bin/env bash
# Asserts a tag is a semver version and that a stable release has a section in
# CHANGELOG.md. composer.json carries no version field, so the tag is the only
# number there is to check. The release workflow runs this before publishing;
# run it yourself before tagging.
#
#   ./scripts/check-release.sh v0.2.0

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [ $# -ne 1 ]; then
  echo "usage: $(basename "$0") <tag>" >&2
  exit 2
fi

TAG="$1"
SEMVER='^v([0-9]+\.[0-9]+\.[0-9]+)(-[0-9A-Za-z.-]+)?$'

if ! [[ "$TAG" =~ $SEMVER ]]; then
  echo "error: '$TAG' is not a version tag (expected vX.Y.Z or vX.Y.Z-suffix)" >&2
  exit 1
fi

VERSION="${BASH_REMATCH[1]}"

# A prerelease is not announced in the changelog; the stable one that follows is.
if [ -n "${BASH_REMATCH[2]}" ]; then
  echo "ok   $TAG is a prerelease, CHANGELOG.md not required"
  exit 0
fi

if ! grep -q "^## \[$VERSION\] - [0-9]\{4\}-[0-9]\{2\}-[0-9]\{2\}$" "$REPO_ROOT/CHANGELOG.md"; then
  echo "FAIL CHANGELOG.md: no '## [$VERSION] - YYYY-MM-DD' section" >&2
  exit 1
fi

echo "ok   CHANGELOG.md has a [$VERSION] section"
