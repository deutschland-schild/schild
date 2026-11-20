# Test lab (MVP-05). Registers the test-lab hooks with the root Makefile.
# Targets are prefixed testlab-* and never redefine root targets.
# Traffic (MVP-06) hooks are included from tests/testlab/traffic/component.mk.

TESTLAB_COMPOSE_T0 := tests/testlab/compose/docker-compose.t0.yaml
TESTLAB_COMPOSE_T1 := tests/testlab/compose/docker-compose.t1.yaml
TESTLAB_COMPOSE_T1_AGENTS := tests/testlab/compose/docker-compose.t1.agents.yaml
TESTLAB_PROJECT     = schild-testlab-$(PROFILE)
TESTLAB_RESULTS    := tests/results

# A default TEST ONLY label secret so the make targets run without setup. Any
# real run overrides SCHILD_LABEL_SECRET; this value never leaves the test lab.
export SCHILD_LABEL_SECRET ?= schild-testlab-dev-secret

# Register hooks (see conventions.md §10).
IMAGE_TARGETS    += testlab-image testlab-app-vm-image
SELFTEST_TARGETS += testlab-selftest-run
EVAL_TARGETS     += eval-MVP-05
TESTLAB_UP_TARGET   := testlab-up-run
TESTLAB_DOWN_TARGET := testlab-down-run
SMOKE_TARGET        := testlab-smoke-run

# Compose file for the active profile (default t0).
testlab_compose = $(if $(filter t1,$(PROFILE)),$(TESTLAB_COMPOSE_T1) -f $(TESTLAB_COMPOSE_T1_AGENTS) --profile agents,$(TESTLAB_COMPOSE_T0))

.PHONY: testlab-image
testlab-image: ## build the schild-testlab image (all test-lab binaries)
	$(DOCKER) build -f tests/testlab/dockerfiles/testlab.Dockerfile -t schild-testlab:$(TAG) .

.PHONY: testlab-compose-config
testlab-compose-config: ## validate every compose file (docker compose config)
	$(DOCKER) compose -f $(TESTLAB_COMPOSE_T0) config >/dev/null
	$(DOCKER) compose -f $(TESTLAB_COMPOSE_T1) config >/dev/null
	$(DOCKER) compose -f $(TESTLAB_COMPOSE_T1) -f $(TESTLAB_COMPOSE_T1_AGENTS) --profile agents --profile jobs config >/dev/null
	$(DOCKER) compose -f $(TESTLAB_COMPOSE_T0) -f tests/testlab/traffic/compose/docker-compose.traffic.yaml config >/dev/null
	@echo "testlab: compose config OK (t0, t1, t1+agents, t0+traffic)"

.PHONY: testlab-secrets
testlab-secrets: ## TEST ONLY keys, test CA, TLS certs and geo fixture into tests/testlab/compose/secrets (FORCE=1 regenerates)
	tests/testlab/scripts/gen-secrets.sh

.PHONY: testlab-up-run
testlab-up-run: ## secrets, lab users, then the stack for PROFILE (t0|t1), waiting for health
	DOCKER=$(DOCKER) tests/testlab/scripts/up.sh $(PROFILE)

.PHONY: testlab-down-run
testlab-down-run: ## tear down the stack for PROFILE (incl. one-shot jobs and the t12 front-proxy services) and remove its volumes
	$(DOCKER) compose -p $(TESTLAB_PROJECT) -f $(testlab_compose) --profile jobs --profile t12 down -v --remove-orphans

.PHONY: testlab-t12
testlab-t12: ## T12 fail-open live: front proxy + schild kill/pause under load on a running t0 (tests/results/runs/t12/t12.json)
	DOCKER=$(DOCKER) tests/testlab/scripts/t12.sh

.PHONY: testlab-smoke-run
testlab-smoke-run: ## end-to-end smoke test against the running stack for PROFILE
	DOCKER=$(DOCKER) tests/testlab/scripts/smoke.sh $(PROFILE)

.PHONY: testlab-selftest-run
testlab-selftest-run: ## evaluator planted-fault self-test (MVP-05 kill criterion)
	cd tests/testlab && $(GO) run ./cmd/evaluator -selftest

# eval-MVP-05: writes a reproducible tests/results/MVP-05.json. With a live stack,
# pass EVENTS/GT via the evaluator directly; here it emits the synthetic clean
# run so the target always produces a valid artifact.
.PHONY: eval-MVP-05
eval-MVP-05: testlab-selftest-run
	@mkdir -p $(TESTLAB_RESULTS)
	cd tests/testlab && $(GO) run ./cmd/evaluator -synthetic -spec MVP-05 -profile $(PROFILE) -seed $(SEED) -out $(CURDIR)/$(TESTLAB_RESULTS)

.PHONY: testlab-app-vm-image
testlab-app-vm-image: ## MVP-11: build the TEST ONLY app VM image (Debian 13, PHP 8.1, MariaDB, sshd; schild comes from schild:dev at runtime)
	$(DOCKER) build -f tests/testlab/dockerfiles/app-vm.Dockerfile -t schild-testlab-app-vm:$(TAG) tests/testlab/dockerfiles/app-vm

.PHONY: testlab-agent-smoke
testlab-agent-smoke: ## MVP-11: agent steps alone against a running t1 (also part of make smoke PROFILE=t1)
	DOCKER=$(DOCKER) tests/testlab/scripts/agent-smoke.sh

.PHONY: testlab-readonly-proof
testlab-readonly-proof: ## MVP-11: `schild check` in a disposable app VM container changes nothing but the report dir
	DOCKER=$(DOCKER) tests/testlab/scripts/readonly-proof.sh

.PHONY: testlab-readonly-proof-selftest
testlab-readonly-proof-selftest: ## MVP-11: the read-only proof passes a clean fake check and catches a writing one (no backend needed)
	DOCKER=$(DOCKER) tests/testlab/scripts/readonly-proof-selftest.sh

.PHONY: testlab-keys
testlab-keys: testlab-secrets ## old name of testlab-secrets

-include tests/testlab/traffic/component.mk
