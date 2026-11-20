# Adversaries / red team (MVP-07). Registers hooks with the root Makefile
# (conventions.md §10). Targets are prefixed adversaries-* / adversary and
# never redefine root targets.

ADVERSARY_IMAGE   := schild-adversary
ADVERSARY_RESULTS := tests/results
SCENARIO ?= all

# Register hooks.
TEST_TARGETS  += adversaries-test
BUILD_TARGETS += adversaries-build
IMAGE_TARGETS += adversary-image
EVAL_TARGETS  += eval-MVP-07

.PHONY: adversaries-test
adversaries-test: ## vet + unit tests + a short SecLang differential fuzz
	cd tests/adversaries && $(GO) vet ./... && $(GO) test $(GO_TEST_FLAGS) ./...

.PHONY: adversaries-build
adversaries-build: ## build the red-team binaries into bin/
	@mkdir -p $(BIN_DIR)
	cd tests/adversaries && $(GO) build -trimpath -o $(CURDIR)/$(BIN_DIR)/ ./cmd/...

.PHONY: adversary-image
adversary-image: ## build schild-adversary:dev (all red-team binaries)
	$(DOCKER) build -f tests/adversaries/Dockerfile -t $(ADVERSARY_IMAGE):$(TAG) .

.PHONY: seclang-fuzz
seclang-fuzz: ## SecLang validator fuzzer vs the independent third checker (FUZZ_N rules)
	cd tests/adversaries && $(GO) run ./cmd/seclang-fuzzer -seed $(SEED) -n $(FUZZ_N)

# make adversary SCENARIO=T06|T07|T08|T10|T11|T24|K6|all
# Runs the red-team scenarios against the real acceptance code and writes a
# result per contracts/results.schema.json to tests/results/MVP-07[-<scenario>].json.
.PHONY: adversary
adversary: ## run MVP-07 red-team scenarios (SCENARIO=... PROFILE=t1)
	cd tests/adversaries && $(GO) run ./cmd/adversary -scenario $(SCENARIO) -profile $(PROFILE) -seed $(SEED) -out $(CURDIR)/$(ADVERSARY_RESULTS)

.PHONY: eval-MVP-07
eval-MVP-07: ## MVP-07: every scenario, aggregated result
	cd tests/adversaries && $(GO) run ./cmd/adversary -scenario all -profile $(PROFILE) -seed $(SEED) -out $(CURDIR)/$(ADVERSARY_RESULTS)
