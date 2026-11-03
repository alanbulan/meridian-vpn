#!/bin/sh
set -eu
: "${MERIDIAN_MFA_HELPER_TEST_BINARY:?Set the absolute path to the trusted built authentication helper}"
GO=${GO:-go}
repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$repo"
CGO_ENABLED=0 "$GO" test -count=1 -v ./internal/core -run '^(TestMFA|TestRealMFA)'
