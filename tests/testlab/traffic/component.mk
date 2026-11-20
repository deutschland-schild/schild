# Traffic (MVP-06). Included by tests/testlab/component.mk. Targets are prefixed
# traffic-* / testlab-traffic-*; it registers the TRAFFIC_TARGET and the
# eval-MVP-06 hook.

SCENARIO ?= T01

IMAGE_TARGETS += traffic-image
EVAL_TARGETS  += eval-MVP-06
TRAFFIC_TARGET := traffic-run

.PHONY: traffic-image
traffic-image: ## build the schild-traffic image (Go generator)
	$(DOCKER) build -f tests/testlab/traffic/dockerfiles/traffic.Dockerfile -t schild-traffic:$(TAG) .

# make traffic SCENARIO=T0x SEED=42: build the plan and print labelled counts
# (deterministic, no network). The plan and its canaries are written under
# tests/results/runs so a later send/evaluate can reuse them. Sending to the live
# stack is done by the traffic-runner compose service (profile legit).
.PHONY: traffic-run
traffic-run: ## build and count the plan for SCENARIO (reproducibility)
	@mkdir -p $(TESTLAB_RESULTS)/runs
	cd tests/testlab && $(GO) run ./traffic/cmd/traffic -scenario $(SCENARIO) -seed $(SEED) -profile $(PROFILE) \
		-count -plan-out $(CURDIR)/$(TESTLAB_RESULTS)/runs/plan-$(SCENARIO).json \
		-canary-out $(CURDIR)/$(TESTLAB_RESULTS)/runs/canaries-$(SCENARIO).txt

.PHONY: eval-MVP-06
eval-MVP-06: ## write tests/results/MVP-06.json proving SCENARIO is reproducible
	@mkdir -p $(TESTLAB_RESULTS)
	cd tests/testlab && $(GO) run ./traffic/cmd/traffic -scenario $(SCENARIO) -seed $(SEED) -profile $(PROFILE) \
		-results-out $(CURDIR)/$(TESTLAB_RESULTS) -spec MVP-06

# make traffic-ftw: the go-ftw CRS regression subset (traffic/compose/ftw)
# against the running t1 stack's autoblock shop. The corpus is first copied to
# tests/results/runs/ftw/corpus with a signed ground-truth label on every request
# (malicious for attacks, benign for the negatives), so the stripper records
# go-ftw traffic like any other generator's. JSON report in
# tests/results/runs/ftw/ftw.json; non-zero exit on any failed test.
.PHONY: traffic-ftw
traffic-ftw: ## go-ftw CRS regression subset vs the t1 autoblock shop (needs make testlab-up PROFILE=t1)
	@rm -rf $(TESTLAB_RESULTS)/runs/ftw/corpus && mkdir -p $(TESTLAB_RESULTS)/runs/ftw
	cd tests/testlab && $(GO) run ./traffic/cmd/traffic -ftw-render traffic/compose/ftw -ftw-out $(CURDIR)/$(TESTLAB_RESULTS)/runs/ftw/corpus -label-scenario T03
	FTW_CORPUS=$(CURDIR)/$(TESTLAB_RESULTS)/runs/ftw/corpus $(DOCKER) compose -p schild-testlab-t1 -f $(TESTLAB_COMPOSE_T1) -f tests/testlab/traffic/compose/docker-compose.traffic.yaml \
		--profile attack run --rm --no-deps attack-ftw > $(TESTLAB_RESULTS)/runs/ftw/ftw.json; \
		status=$$?; cat $(TESTLAB_RESULTS)/runs/ftw/ftw.json; echo; \
		jq -e '.run > 0 and (.failed | length) == 0 and (.skipped | length) == 0' $(TESTLAB_RESULTS)/runs/ftw/ftw.json >/dev/null || status=1; exit $$status
