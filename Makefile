# Deutschland-Schild - root Makefile.
#
# Components add their own targets in <dir>/component.mk and tests/<dir>/component.mk (included below);
# they never edit this file. See contracts/conventions.md, section Makefile.
#
#   make contracts-test        Go + Python check of all golden vectors (MVP-01 done)
#   make contracts-fuzz        differential fuzz Go vs Python (SEED, FUZZ_N, FUZZ_VECTORS)
#   make test                  contracts-test + go test of every module + component tests, in short mode
#                              (as in CI: the load and performance tests skip themselves)
#   make test-full             the same with the load and performance tests (10k-client burst, fan-out, floods);
#                              needs a quiet machine, their bounds do not hold on a busy one
#   make build                 binaries into bin/, incl. schild and schild-agent (TAGS=release for release builds;
#                              schild-agent is not part of the first gateway version, D60b)
#   make ui                    pnpm build of both dashboards (dashboard/), copied into the Go embed dirs
#   make images                docker images (schild, schild-lab, schild-relay, schild-testlab-*; AGENT=1 adds schild-agent to schild).
#                              schild:dev is a dev build (test keys and test profile allowed) and is never published;
#                              published images and tarballs come from .github/workflows/release.yml only
#   make testlab-up PROFILE=t0|t1 / make testlab-down PROFILE=t0|t1
#   make smoke PROFILE=t0|t1   end-to-end proof against the running test lab
#   make eval SPEC=MVP-0x      run one measurement, writes tests/results/<spec>.json
#   make selftest              evaluator self-test (planted faults)

SHELL        := /bin/bash
.SHELLFLAGS  := -eu -o pipefail -c   # GNU make >= 3.82; loops also exit explicitly for make 3.81 (macOS)
.DEFAULT_GOAL := help
MAKEFLAGS    += --no-print-directory

PROFILE ?= t0
SPEC    ?=
SEED    ?= 42
TAGS    ?=
TAG     ?= dev
# What `schild version` reports: the image tag, 0.0.0-dev for the default tag (a release gets its version from the git tag).
VERSION ?= $(if $(filter dev,$(TAG)),0.0.0-dev,$(TAG))
FUZZ_N  ?= 100000
# Extra flags for every go test of make test. Default -short: load and performance tests (10k-client burst,
# fan-out, floods, latency guards) skip themselves, a shared runner or a busy laptop cannot hold their bounds.
# make test-full runs them (GO_TEST_FLAGS empty).
GO_TEST_FLAGS ?= -short
# The limit of one package. The tests of a group of gateways (gateway/internal/app) start several gateways
# each and need more than go test's ten minutes on a hosted runner; the CI job (go) has 45 minutes.
GO_TEST_TIMEOUT ?= 25m
FUZZ_VECTORS ?= 2000
GO      ?= go
PNPM    ?= pnpm
DOCKER  ?= docker
# Geo data baked into the schild image: fixture (TEST ONLY documentation ranges,
# no download, default for the local test lab) or dbip (downloads DB-IP Lite at
# build time; use for stage 3: make images GATEWAY_GEO=dbip).
GATEWAY_GEO ?= fixture

export CGO_ENABLED := 0

GO_MODULES := $(patsubst %/go.mod,%,$(wildcard */go.mod tests/*/go.mod))
CHECK_DIR  := contracts/.check
BIN_DIR    := bin

# Hooks filled by component.mk files.
TEST_TARGETS        :=
BUILD_TARGETS       :=
IMAGE_TARGETS       :=
EVAL_TARGETS        := eval-MVP-01
SELFTEST_TARGETS    :=
UI_TARGETS          :=
TESTLAB_UP_TARGET   :=
TESTLAB_DOWN_TARGET :=
TRAFFIC_TARGET      :=
SMOKE_TARGET        :=

-include $(sort $(wildcard */component.mk tests/*/component.mk))

# Python for the independent cross-check: system python3 in isolated mode if
# it has jsonschema, otherwise a venv in .venv (gitignored).
PY := $(shell python3 -I -c 'import jsonschema, referencing, yaml' >/dev/null 2>&1 && echo 'python3 -I' || echo '.venv/bin/python -I')

.PHONY: help
help:
	@awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' Makefile
	@echo "Go modules: $(GO_MODULES)"
	@echo "Component hooks: test=[$(TEST_TARGETS)] build=[$(BUILD_TARGETS)] images=[$(IMAGE_TARGETS)] eval=[$(EVAL_TARGETS)]"

# ------------------------------------------------------------------ contracts

.venv/bin/python:
	python3 -m venv .venv
	.venv/bin/python -m pip install --quiet 'jsonschema>=4.18,<5' 'PyYAML>=6,<7'

.PHONY: py-deps
py-deps:
	@if [ "$(PY)" = ".venv/bin/python -I" ]; then $(MAKE) .venv/bin/python; fi

.PHONY: contracts-sync
contracts-sync: ## copy contracts/*.schema.json into the Go embed dir, bundle the agent API document
	mkdir -p contract/schema/files/config
	rm -f contract/schema/files/*.schema.json contract/schema/files/config/*.schema.json
	cp contracts/*.schema.json contract/schema/files/
	cp contracts/config/*.schema.json contract/schema/files/config/
	cd contract && $(GO) run ./cmd/genagentspec

.PHONY: contracts-vectors
contracts-vectors: contracts-sync ## regenerate golden vectors and test keys (deterministic)
	cd contract && $(GO) run ./cmd/genvectors -out ../contracts

.PHONY: contracts-test
contracts-test: py-deps ## Go and Python must agree on every vector
	cd contract && $(GO) test ./schema ./testkeys ./vectors
	@mkdir -p $(CHECK_DIR)
	cd contract && $(GO) run ./cmd/contracts-check -contracts ../contracts -out ../$(CHECK_DIR)/go.json
	$(PY) contracts/tools/crosscheck.py --contracts contracts --go $(CHECK_DIR)/go.json --out $(CHECK_DIR)/python.json
	@echo "contracts-test: OK (Go and Python agree on all vectors)"

.PHONY: contracts-fuzz
contracts-fuzz: py-deps ## differential fuzz of the SecLang subset, Go vs Python (FUZZ_N rules)
	@mkdir -p $(CHECK_DIR)
	$(PY) contracts/tools/seclang_fuzz.py --contracts contracts --seed $(SEED) --n $(FUZZ_N) --out $(CHECK_DIR)/seclang_fuzz.json
	set -o pipefail; cd contract && SCHILD_SECLANG_DIFF=$(abspath $(CHECK_DIR))/seclang_fuzz.json $(GO) test -count=1 -run TestDifferential -v ./seclang | tail -3
	$(PY) contracts/tools/vector_fuzz.py --contracts contracts --seed $(SEED) --n $(FUZZ_VECTORS) --out $(CHECK_DIR)/fuzz
	cd contract && ($(GO) run ./cmd/contracts-check -contracts ../$(CHECK_DIR)/fuzz -out ../$(CHECK_DIR)/fuzz/go.json >/dev/null || true)
	$(PY) contracts/tools/crosscheck.py --contracts $(CHECK_DIR)/fuzz --go $(CHECK_DIR)/fuzz/go.json --agreement-only

.PHONY: eval-MVP-01
eval-MVP-01: contracts-test

# ------------------------------------------------------------------ Go

.PHONY: go-test
go-test: ## go test in every module (dev and release tags for contract)
	@for m in $(GO_MODULES); do \
	  if [ -z "$$(find $$m -name '*.go' -not -path '*/node_modules/*' -print -quit)" ]; then echo "== $$m: no Go files yet, skipped"; continue; fi; \
	  echo "== go test $$m"; (cd $$m && $(GO) vet ./... && $(GO) test -timeout $(GO_TEST_TIMEOUT) $(GO_TEST_FLAGS) ./...) || exit 1; \
	done
	cd contract && $(GO) test $(GO_TEST_FLAGS) -tags release ./...

.PHONY: test test-full
test: contracts-test go-test $(TEST_TARGETS)
test-full: ## make test with the load and performance tests (quiet machine)
	$(MAKE) test GO_TEST_FLAGS=

.PHONY: build
build: $(BUILD_TARGETS) ## build all main packages of all modules into bin/
	@mkdir -p $(BIN_DIR)
	@if [ -n "$(filter release,$(TAGS))" ] && [ ! -s gateway/internal/webui/dist/index.html ]; then \
	  echo "build: TAGS=release without a dashboard build (schild would serve a placeholder page), run make ui first"; exit 1; fi
	@for m in $(GO_MODULES); do \
	  if [ -d $$m/cmd ]; then echo "== build $$m"; (cd $$m && $(GO) build -trimpath $(if $(TAGS),-tags $(TAGS)) -o $(CURDIR)/$(BIN_DIR)/ ./cmd/...) || exit 1; fi; \
	done

# ------------------------------------------------------------------ UI

UI_DIR := dashboard
.PHONY: ui
ui: $(UI_TARGETS) ## build dashboards and copy dist into the Go embed dirs
	@if [ ! -f $(UI_DIR)/package.json ]; then echo "ui: $(UI_DIR)/package.json missing (owned by the UI agent)"; exit 1; fi
	cd $(UI_DIR) && $(PNPM) install --frozen-lockfile && $(PNPM) -r build
	@for pair in client-dashboard:gateway lab-dashboard:lab; do \
	  app=$${pair%%:*}; mod=$${pair##*:}; src=$(UI_DIR)/apps/$$app/dist; dst=$$mod/internal/webui/dist; \
	  if [ -d $$src ]; then rm -rf $$dst && mkdir -p $$dst && cp -R $$src/. $$dst/ && touch $$dst/.gitkeep || exit 1; echo "ui: $$src -> $$dst"; \
	  else echo "ui: $$src missing, skipped"; fi; \
	done

# ------------------------------------------------------------------ images

COMPONENT_IMAGES := gateway:schild lab:schild-lab relay:schild-relay
# gateway/Dockerfile builds the gateway dashboard itself (Node stage), so schild needs no make ui first.
# TAGS is always passed: empty means a dev build (the Dockerfile's own default is a release build).
.PHONY: images
images: $(IMAGE_TARGETS) ## docker build of every component that has a Dockerfile
	@for pair in $(COMPONENT_IMAGES); do \
	  dir=$${pair%%:*}; img=$${pair##*:}; \
	  args=""; if [ "$$dir" = gateway ]; then args="--build-arg GEO=$(GATEWAY_GEO) --build-arg VERSION=$(VERSION) --build-arg TAGS=$(TAGS)"; fi; \
	  if [ -f $$dir/Dockerfile ]; then echo "== $$img:$(TAG)"; $(DOCKER) build -f $$dir/Dockerfile $$args -t $$img:$(TAG) . || exit 1; \
	  else echo "images: $$dir/Dockerfile missing, $$img skipped"; fi; \
	done

# ------------------------------------------------------------------ test lab and measurements

define dispatch
	@if [ -z "$(2)" ]; then echo "$(1): not provided yet (hook $(3) in tests/$(4)/component.mk)"; exit 1; fi
	$(MAKE) $(2) PROFILE=$(PROFILE) SEED=$(SEED)
endef

.PHONY: testlab-up testlab-down traffic smoke
testlab-up:
	$(call dispatch,testlab-up,$(TESTLAB_UP_TARGET),TESTLAB_UP_TARGET,testlab)
testlab-down:
	$(call dispatch,testlab-down,$(TESTLAB_DOWN_TARGET),TESTLAB_DOWN_TARGET,testlab)
traffic:
	$(call dispatch,traffic,$(TRAFFIC_TARGET),TRAFFIC_TARGET,testlab)
smoke:
	$(call dispatch,smoke,$(SMOKE_TARGET),SMOKE_TARGET,testlab)

.PHONY: eval
eval: ## make eval SPEC=MVP-0x
	@if [ -z "$(SPEC)" ]; then echo "eval: set SPEC=MVP-0x (available: $(EVAL_TARGETS))"; exit 1; fi
	@if [ -z "$(filter eval-$(SPEC),$(EVAL_TARGETS))" ]; then echo "eval: no eval-$(SPEC) registered (available: $(EVAL_TARGETS))"; exit 1; fi
	$(MAKE) eval-$(SPEC) PROFILE=$(PROFILE) SEED=$(SEED)

.PHONY: selftest testlab-selftest
selftest: $(SELFTEST_TARGETS)
	@if [ -z "$(SELFTEST_TARGETS)" ]; then echo "selftest: no SELFTEST_TARGETS registered yet (owner: MVP-05)"; exit 1; fi
testlab-selftest: selftest

# ------------------------------------------------------------------ housekeeping

.PHONY: clean
clean:
	rm -rf $(BIN_DIR) $(CHECK_DIR)
