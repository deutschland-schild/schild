# Build context is the repository root (see conventions.md §2). One image holds every test-lab
# binary; compose selects the binary per service with `command`.
#
#   docker build -f tests/testlab/dockerfiles/testlab.Dockerfile -t schild-testlab:dev .
FROM golang:1.27.4-alpine@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 AS build
WORKDIR /src
# Workspace and every module's go.mod (the non-built ones are tiny but must
# exist because go.work references their directories).
COPY go.work ./
COPY go.work.sum ./
COPY contract/ contract/
COPY tests/testlab/ tests/testlab/
COPY gateway/go.mod gateway/go.mod
COPY lab/go.mod lab/go.mod
COPY relay/go.mod relay/go.mod
COPY tests/adversaries/go.mod tests/adversaries/go.mod
ENV CGO_ENABLED=0 GOTOOLCHAIN=local
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    cd tests/testlab && go build -trimpath -o /out/bin/ ./cmd/... \
 && mkdir -p /out/var/lib/testlab /out/results/runs /out/export

FROM gcr.io/distroless/static-debian13:nonroot@sha256:aafe993665bf6200db38a02c11a9351e782a84b6a45e7f33b6695638c88e3931
COPY --from=build /out/bin/ /usr/local/bin/
# Mount points of named volumes, owned by the runtime user: a fresh volume
# copies this ownership, so the nonroot (65532) services can write to it.
COPY --from=build --chown=65532:65532 /out/var/lib/testlab /var/lib/testlab
COPY --from=build --chown=65532:65532 /out/results /results
COPY --from=build --chown=65532:65532 /out/export /export
USER 65532:65532
# No ENTRYPOINT: each compose service sets `command` to one of
# /usr/local/bin/{label-stripper,evaluator,egress-check,site-api,groundtruth,
# gateway,smoke,healthcheck}.
