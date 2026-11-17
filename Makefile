GO ?= go
GO_PACKAGES := ./server ./internal/...
export CGO_ENABLED = 1
export CGO_CPPFLAGS += -D_GNU_SOURCE

.PHONY: build test check bundle-client browser-test-build release
build:
	$(GO) build -trimpath -ldflags '-s -w' -o bin/sshserver ./server

test:
	$(GO) test -race -count=1 -timeout 90s $(GO_PACKAGES)

check:
	$(GO) vet $(GO_PACKAGES)
	node --check client/ssh.js
	node --check client/terminal.js
	node --check client/app.js

bundle-client:
	python3 scripts/bundle_client.py

browser-test-build:
	$(GO) test -c -o bin/sshd.test ./internal/sshd

release: build bundle-client
	GO="$(GO)" python3 scripts/package_release.py
