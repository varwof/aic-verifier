#!/usr/bin/env bash
# Consumer-view gate.
#
# A production SDK must build the way a downstream user builds it: every
# dependency resolved from the module proxy, no local paths. Two failure modes
# this catches that `go build ./...` in-repo does not:
#
#   1. go.mod replaces a dependency with a local filesystem path. A replace in
#      the SDK's go.mod is ignored by downstream modules, so an in-repo build
#      can be green while every consumer resolves a different (older) version.
#   2. go.mod requires a version that is not actually published on the proxy.
#
# It builds a throwaway module that replaces *this* module with the checkout
# (so the PR's code is under test) but leaves the module's own dependencies to
# the proxy (so their pinning is under test).
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo_root"

module="$(go list -m)"
local_replace='^replace[[:space:]].*=>[[:space:]]+(\.|/|~|[A-Za-z]:[\\/])'
if grep -nE "$local_replace" go.mod; then
	echo "FAIL: go.mod replaces a dependency with a local path; consumers cannot resolve it" >&2
	exit 1
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

cat >"$work/go.mod" <<EOF
module example.com/consumer

go 1.26

require $module v0.0.0

replace $module => $repo_root
EOF

cat >"$work/main.go" <<EOF
package main

import _ "$module"

func main() {}
EOF

(cd "$work" && go mod tidy && go build ./...)
echo "consumer-view: OK — $module resolves its dependencies from the module proxy"
