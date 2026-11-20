# lab/component.mk - schild-lab (MVP-03 lab core, MVP-10 server side).
#
#   make lab-test          gofmt, vet, release build (test keys/profile refused), short tests
#   make lab-bench         B13 locally: 10,000 clients, burst x20 open loop, full queue, saturation
#   make lab-smoke         native smoke: 3 labs (TLS, peers) + relay + TEST ONLY client + watcher
#   make lab-docker-smoke  same with the images schild-lab:dev and schild-relay:dev (internal network 10.66.33.0/24)
#
# The full test suite (including the 10k-client burst) runs in `make test-full`; `make test` is short mode.
# Measurements (eval-MVP-03, eval-MVP-10) belong to the evaluator (MVP-05), not to this component.

.PHONY: lab-test lab-bench lab-smoke lab-docker-smoke
TEST_TARGETS += lab-test

lab-test:
	@cd lab && test -z "$$(gofmt -l .)" || { echo "lab: gofmt needed:"; gofmt -l .; exit 1; }
	cd lab && $(GO) vet ./... && $(GO) build -tags release ./... && $(GO) test -short -count=1 ./...

lab-bench:
	cd lab && $(GO) test -count=1 -run TestBurstAckLatency -v ./internal/ingest

lab-smoke:
	lab/dev/smoke-native.sh

lab-docker-smoke:
	lab/dev/smoke-docker.sh
