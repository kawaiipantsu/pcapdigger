APP        := pcapdigger
MODULE     := pcapdigger
DIST       := dist
GO         := go
NFPM       := github.com/goreleaser/nfpm/v2/cmd/nfpm@v2.47.0

VERSION    := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT     := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE       := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
DEB_VERSION := $(shell echo $(VERSION) | sed -e 's/^v//' -e 's/-/+/g')

LDFLAGS := -s -w \
	-X $(MODULE)/internal/version.Version=$(VERSION) \
	-X $(MODULE)/internal/version.Commit=$(COMMIT) \
	-X $(MODULE)/internal/version.Date=$(DATE)

# goarch:goarm pairs to cross-compile for. GOARM is only honored by the Go
# toolchain when GOARCH=arm, so leaving it empty for the other three is safe.
TARGETS := amd64: arm64: 386: arm:7

.PHONY: all build build-all checksums deb clean test vet fmt install uninstall

all: build

$(DIST):
	mkdir -p $(DIST)

## build: compile a binary for the host platform into dist/
build: $(DIST)
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(DIST)/$(APP) ./cmd/$(APP)

## build-all: cross-compile Linux binaries for amd64, arm64, i386 (386), and armhf (arm/GOARM=7)
build-all: $(DIST)
	@set -e; for pair in $(TARGETS); do \
		goarch=$${pair%%:*}; goarm=$${pair##*:}; \
		if [ "$$goarch" = "arm" ]; then out=$(DIST)/$(APP)_$(VERSION)_linux_armv7; \
		else out=$(DIST)/$(APP)_$(VERSION)_linux_$$goarch; fi; \
		echo "==> building $$out (GOARCH=$$goarch GOARM=$$goarm)"; \
		CGO_ENABLED=0 GOOS=linux GOARCH=$$goarch GOARM=$$goarm \
			$(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $$out ./cmd/$(APP); \
	done

## checksums: write dist/SHA256SUMS covering every build-all artifact
checksums:
	@cd $(DIST) && sha256sum $(APP)_$(VERSION)_* > SHA256SUMS
	@echo "wrote $(DIST)/SHA256SUMS"

## deb: build every arch (build-all) then package each as a .deb via nfpm
deb: build-all
	@command -v envsubst >/dev/null 2>&1 || { echo "envsubst not found (install gettext-base)"; exit 1; }
	@set -e; for pair in $(TARGETS); do \
		goarch=$${pair%%:*}; \
		case $$goarch in \
			amd64) nfpmarch=amd64; bin=$(DIST)/$(APP)_$(VERSION)_linux_amd64 ;; \
			arm64) nfpmarch=arm64; bin=$(DIST)/$(APP)_$(VERSION)_linux_arm64 ;; \
			386)   nfpmarch=386;   bin=$(DIST)/$(APP)_$(VERSION)_linux_386 ;; \
			arm)   nfpmarch=arm7;  bin=$(DIST)/$(APP)_$(VERSION)_linux_armv7 ;; \
		esac; \
		echo "==> packaging .deb for $$nfpmarch"; \
		ARCH=$$nfpmarch VERSION=$(DEB_VERSION) BINARY=$$bin PROJECT_ROOT=$(CURDIR) \
			envsubst '$${ARCH} $${VERSION} $${BINARY} $${PROJECT_ROOT}' \
			< packaging/debian/nfpm.yaml.tmpl > $(DIST)/nfpm-$$nfpmarch.yaml; \
		$(GO) run $(NFPM) package -f $(DIST)/nfpm-$$nfpmarch.yaml -p deb -t $(DIST)/; \
	done
	@rm -f $(DIST)/nfpm-*.yaml

## test: run the Go test suite
test:
	$(GO) test ./...

## vet: run go vet
vet:
	$(GO) vet ./...

## fmt: verify gofmt has been applied (fails if any file needs formatting)
fmt:
	@out=$$($(GO) fmt ./... 2>&1); if [ -n "$$out" ]; then echo "$$out"; exit 1; fi

## install: install the host-platform binary to /usr/local/bin
install: build
	install -Dm755 $(DIST)/$(APP) $(DESTDIR)/usr/local/bin/$(APP)

## uninstall: remove the binary installed by `make install`
uninstall:
	rm -f $(DESTDIR)/usr/local/bin/$(APP)

## clean: remove all build output
clean:
	rm -rf $(DIST)
