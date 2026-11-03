GO ?= go
export CGO_ENABLED=0
.PHONY: build test check cross clean
build:
	$(GO) build -buildvcs=false -trimpath -tags mygo_noinspector -ldflags '-s -w -X github.com/egoist/mygo.production=1' -o build/meridian ./cmd/meridian
	$(GO) build -buildvcs=false -trimpath -ldflags '-s -w' -o build/meridianctl ./cmd/meridianctl
test:
	$(GO) test ./...
check: test
	$(GO) vet ./...
cross:
	GOOS=windows GOARCH=amd64 $(GO) build -buildvcs=false -trimpath -tags mygo_noinspector -ldflags '-s -w' -o build/meridian-windows-amd64.exe ./cmd/meridian
	GOOS=darwin GOARCH=arm64 $(GO) build -buildvcs=false -trimpath -tags mygo_noinspector -ldflags '-s -w' -o build/meridian-darwin-arm64 ./cmd/meridian
clean:
	rm -f build/meridian build/meridianctl build/meridian-auth-helper build/meridian-ui-fixture build/meridian-windows-amd64.exe build/meridian-darwin-arm64
