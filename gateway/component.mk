# gateway/component.mk - targets of the Schild Gateway `schild` (MVP-02, MVP-09
# server side) and the Schild Agent `schild-agent` (MVP-11), both built from
# this module. Included by the root Makefile; targets are prefixed "gateway-".
#
#   make gateway-test        vet + tests (dev and release tags)
#   make gateway-race        tests with the race detector (needs cgo; short mode like make test)
#   make gateway-bench       B01-style overhead benchmarks (gate, WAF, full Caddy path)
#   make gateway-coraza      Coraza conformance of all valid SecLang vectors
#   make gateway-run         run schild locally (proxy :8080 -> 127.0.0.1:8081, dashboard 127.0.0.1:8788), test profile
#   make gateway-image       docker build of schild:$(TAG), a dev build (test keys and test profile allowed, labelled
#                           de.deutschland-schild.build=dev, never published); GATEWAY_GEO=dbip|fixture, TAGS=release
#                           for a local release build; schild only, AGENT=1 adds schild-agent for the test lab
#                           (not part of the first version, D60b). The dashboard is built inside the image
#   make gateway-smoke       the quickstart (deploy/quickstart) against schild:$(TAG): hardened start, health,
#                           dashboard on 127.0.0.1:8788 (needs the host ports 8080 and 8788)
#   make gateway-tarball     the release tarball of the builder's platform into bin/ (as the release workflow builds it)
#   make gateway-deb         the Debian package of that tarball into bin/ (needs make gateway-tarball first)
#   make gateway-pkgtest     package, apt repository (TEST ONLY key) and installer in containers of Debian 12 and 13,
#                           Ubuntu 22.04 and 24.04: install, upgrade, changed signature, channel, remove, purge
#   make gateway-geo-pin     print the sha256 of DB-IP Lite GEO_MONTH=YYYY-MM for the pins in gateway/Dockerfile
#   make gateway-agent       bin/schild-agent only (GOOS/GOARCH as usual, e.g. GOOS=linux GOARCH=arm64)
#   make gateway-agent-deps  prove schild-agent links no Caddy, Coraza, WAF or dashboard (go list -deps)
#   make bot-snapshot       rebuild internal/bots/catalogue.json (MVP-22) at build time: ai.robots.txt, own entries
#                           and the operators' published bot ranges, fetched now (network), checked with
#                           contract/bots.Parse before writing; check the result in (alias: gateway-bot-snapshot)
#   make crowdsec-snapshot  rebuild internal/hub/snapshot.json (MVP-26) at build time: the virtual patching rules of
#                           the head of the public CrowdSec Hub (network), run through the update rules before
#                           writing; check the result in (alias: gateway-crowdsec-snapshot)

# Default fixture (set in the root Makefile); dbip downloads DB-IP Lite at build time (stage 3).
GATEWAY_GEO ?= fixture
# Use a local docker-driver builder so the image lands in the local image
# store (e.g. GATEWAY_BUILDER=desktop-linux when the default buildx builder is
# a remote or docker-container builder). Empty: docker's default.
GATEWAY_BUILDER ?= $(BUILDX_BUILDER)

.PHONY: gateway-smoke gateway-tarball gateway-deb gateway-pkgtest gateway-geo-pin
.PHONY: gateway-test gateway-race gateway-bench gateway-coraza gateway-run gateway-image gateway-agent gateway-agent-deps gateway-bot-snapshot bot-snapshot gateway-crowdsec-snapshot crowdsec-snapshot

gateway-test:
	cd gateway && $(GO) vet ./... && $(GO) vet -tags release ./... && $(GO) test $(GO_TEST_FLAGS) ./... && $(GO) test $(GO_TEST_FLAGS) -tags release ./internal/app

gateway-race:
	# The tests of a group of gateways start several gateways each; under the race detector on a hosted
	# runner the package internal/app needs about ten minutes, which is go test's limit. 25 minutes stay
	# below the limit of the CI job (go-race, 30 minutes).
	cd gateway && CGO_ENABLED=1 $(GO) test -race -timeout 25m $(GO_TEST_FLAGS) ./...

gateway-bench:
	cd gateway && $(GO) test -run '^$$' -bench . -benchtime 3s ./internal/gate ./internal/waf ./internal/caddymod

gateway-coraza:
	cd gateway && $(GO) test -count=1 -run 'TestCoraza|TestCRSLoadsAndScores|TestArgumentsLimit' -v ./internal/waf

GATEWAY_DEV_DIR := /tmp/schild-dev
gateway-run:
	mkdir -p $(GATEWAY_DEV_DIR)/geo $(GATEWAY_DEV_DIR)/rules.d
	cp gateway/deploy/rules.d/*.conf $(GATEWAY_DEV_DIR)/rules.d/
	cd gateway && $(GO) run ./cmd/schild geo-fixture -out $(GATEWAY_DEV_DIR)/geo/geo.mmdb
	cd gateway && SCHILD_LOG_FORMAT=text $(GO) run ./cmd/schild run -config deploy/dev.schild.yaml

gateway-agent:
	@mkdir -p $(BIN_DIR)
	cd gateway && $(GO) build -trimpath $(if $(TAGS),-tags $(TAGS)) -ldflags "-s -w" -o ../$(BIN_DIR)/schild-agent ./cmd/schild-agent
	@ls -l $(BIN_DIR)/schild-agent

gateway-bot-snapshot bot-snapshot:
	cd gateway && $(GO) run ./internal/bots/gen -out internal/bots/catalogue.json

gateway-crowdsec-snapshot crowdsec-snapshot:
	cd gateway && $(GO) run ./internal/hub/gen -out internal/hub/snapshot.json

gateway-agent-deps:
	cd gateway && $(GO) test -count=1 -run TestNoProxyDependencies -v ./cmd/schild-agent

gateway-image:
	$(DOCKER) build $(if $(GATEWAY_BUILDER),--builder $(GATEWAY_BUILDER)) -f gateway/Dockerfile --build-arg GEO=$(GATEWAY_GEO) --build-arg VERSION=$(VERSION) --build-arg TAGS=$(TAGS) $(if $(AGENT),--build-arg AGENT=$(AGENT)) -t schild:$(TAG) .

gateway-smoke:
	SMOKE_TMPDIR=$${SMOKE_TMPDIR:-$(CURDIR)/$(BIN_DIR)} gateway/deploy/release/smoke.sh schild:$(TAG)

gateway-tarball:
	$(if $(GATEWAY_BUILDER),BUILDX_BUILDER=$(GATEWAY_BUILDER) )gateway/deploy/release/tarball.sh $(VERSION) $$($(DOCKER) version -f '{{.Server.Arch}}') $(BIN_DIR) --build-arg GEO=$(GATEWAY_GEO)

gateway-deb:
	arch=$$($(DOCKER) version -f '{{.Server.Arch}}'); gateway/deploy/release/deb.sh $(VERSION) $$arch $(BIN_DIR)/schild_$(VERSION)_linux_$$arch.tar.gz $(BIN_DIR)

gateway-pkgtest:
	arch=$$($(DOCKER) version -f '{{.Server.Arch}}'); PKGTEST_TMPDIR=$${PKGTEST_TMPDIR:-$(CURDIR)/$(BIN_DIR)} gateway/deploy/release/pkgtest.sh $(BIN_DIR)/schild_$(VERSION)_linux_$$arch.tar.gz

GEO_MONTH ?=
gateway-geo-pin:
	@if [ -z "$(GEO_MONTH)" ]; then echo "gateway-geo-pin: set GEO_MONTH=YYYY-MM"; exit 1; fi
	@tmp=$$(mktemp -d); trap 'rm -rf "$$tmp"' EXIT; \
	for k in country asn; do \
	  curl -fsSL -o "$$tmp/$$k.mmdb.gz" "https://download.db-ip.com/free/dbip-$$k-lite-$(GEO_MONTH).mmdb.gz" && gunzip "$$tmp/$$k.mmdb.gz" || exit 1; \
	done; \
	echo "ARG GEO_MONTH=$(GEO_MONTH)"; \
	echo "ARG GEO_COUNTRY_SHA256=$$(shasum -a 256 "$$tmp/country.mmdb" | cut -d' ' -f1)"; \
	echo "ARG GEO_ASN_SHA256=$$(shasum -a 256 "$$tmp/asn.mmdb" | cut -d' ' -f1)"

TEST_TARGETS += gateway-test
