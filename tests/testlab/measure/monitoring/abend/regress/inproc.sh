#!/bin/bash
# TEST ONLY: evening re-measurement 2026-10-29 (commit c54de1b), items 9b (in-process memory) and 9c (Record cost).
# Copies testlab/measure/monitoring/inproc/zz_measure_test.go as zz_k_measure_test.go (build tag abendk) into a scratch copy
# of the repository (never the product tree) and runs it there. Records load before and after.
#   SCRATCH=/tmp/abend/scratch OUT=/tmp/abend/k/inproc.txt inproc.sh
set -u
U=$(cd "$(dirname "$0")" && pwd); SCRATCH=${SCRATCH:-/tmp/abend/scratch}; OUT=${OUT:-/tmp/abend/k/inproc.txt}
M=$SCRATCH/client/internal/monitoring
sed -e 's#^//go:build spec21measure#//go:build abendk#' $U/../../inproc/zz_measure_test.go > $M/zz_k_measure_test.go
cd $SCRATCH/client
{
  echo "load before: $(uptime)"
  go test -tags abendk -count=1 -run 'TestMeasureAllocs|TestMeasureMemoryFlood' -v ./internal/monitoring/ 2>&1 | grep -E 'zz_k_measure|zz_measure|PASS|FAIL|ok'
  echo "load between: $(uptime)"
  go test -tags abendk -count=3 -run XXX -bench 'BenchmarkMeasureRecord|BenchmarkRecordCommon|BenchmarkRecordMixedUA' -benchmem ./internal/monitoring/ 2>&1
  echo "load after: $(uptime)"
} > $OUT
