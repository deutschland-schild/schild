# relay/component.mk - schild-relay (MVP-04).
#
#   make relay-test   gofmt, vet, release build, tests (resume without gaps, full sync,
#                     frozen relay detection, forgery rejected by clients, per-IP limits)
#   make relay-bench  in-process fan-out to SCHILD_FANOUT_CLIENTS (default 10,000) clients
#
# Measurements (eval-MVP-04: B05, B06, B10, B12, T10, T11) belong to the evaluator (MVP-05).

.PHONY: relay-test relay-bench
TEST_TARGETS += relay-test

relay-test:
	@cd relay && test -z "$$(gofmt -l .)" || { echo "relay: gofmt needed:"; gofmt -l .; exit 1; }
	cd relay && $(GO) vet ./... && $(GO) build -tags release ./... && $(GO) test $(GO_TEST_FLAGS) -count=1 ./...

relay-bench:
	cd relay && $(GO) test -count=1 -run TestFanout10k -v ./hub
