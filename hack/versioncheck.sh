#!/usr/bin/env bash
# Version single-source-of-truth gate.
#
# version.go is the only place a version is defined in this module. Every
# consumer (mcp server advertisement, evidence generator, ...) derives from
# it. This gate enforces that the in-code version is never BEHIND the latest
# release tag:
#
#   - tag vx.y.z && version.go x.y.z        -> clean release state (OK)
#   - tag vx.y.z && version.go > latest tag -> bump already staged for the
#     next release (OK, expected before cutting a tag)
#   - tag vx.y.z && version.go < latest tag -> drift: someone published a tag
#     without bumping version.go (FAIL)
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo_root"

ver="$(sed -n 's/^var Version = "\(.*\)"/\1/p' version.go)"
if [ -z "$ver" ]; then
	echo "FAIL: cannot read Version from version.go" >&2
	exit 1
fi

latest="$(git tag --list 'v[0-9]*' --sort=-v:refname | head -n1 || true)"
if [ -z "$latest" ]; then
	echo "versioncheck: no release tags yet, Version=$ver (OK)"
	exit 0
fi

# strip "v" and any prerelease/meta (e.g. v0.2.0-rc1 -> 0.2.0)
latest="${latest#v}"

semver_left() { echo "$1" | sed 's/[^0-9]*\([0-9]*\.[0-9]*\.[0-9]*\).*/\1/'; }
read -ra a <<<"$(semver_left "$ver" | tr '.' ' ')"
read -ra b <<<"$(semver_left "$latest" | tr '.' ' ')"

for i in 0 1 2; do
	ai="${a[$i]:-0}"
	bi="${b[$i]:-0}"
	if [ "$((10#$ai))" -lt "$((10#$bi))" ]; then
		echo "FAIL: version.go has Version=$ver but latest tag is v$latest" >&2
		echo "      bump version.go (and CHANGELOG) to the version you are releasing" >&2
		exit 1
	fi
	if [ "$((10#$ai))" -gt "$((10#$bi))" ]; then
		break
	fi
done

echo "versioncheck: OK — version.go Version=$ver, latest tag v$latest"