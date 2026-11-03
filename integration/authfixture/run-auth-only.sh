#!/bin/sh
# Opt-in authentication only. Never runs NetworkManager or a VPN tunnel.
set -eu
: "${MERIDIAN_OPENCONNECT_TEST_BINARY:?Set an absolute path to the trusted OpenConnect test executable}"
GO=${GO:-go}
repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$repo"
CGO_ENABLED=0 "$GO" test -v -count=1 ./internal/core -run '^TestRealOpenConnect(AuthenticationOnly|RejectsBadPassword|RejectsUntrustedCertificate|Cancellation|ClientCertificate|RejectsClientCertificate|RejectsKeyPassphrase|ClientCertificateCancellation|EncryptedPKCS8|PKCS12)$'
