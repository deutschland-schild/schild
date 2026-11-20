# schild-relay: untrusted public SSE fan-out (MVP-04). Build context: repository root
#
#   docker build -f relay/Dockerfile -t schild-relay:dev .
#   docker build -f relay/Dockerfile --build-arg TAGS=release -t schild-relay:alpha .
#
# The relay holds no keys and verifies nothing that matters: clients verify
# every envelope; a relay can only delay or withhold.

ARG GO_IMAGE=golang:1.27.4-alpine@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280
ARG RUN_IMAGE=gcr.io/distroless/static-debian13:nonroot@sha256:aafe993665bf6200db38a02c11a9351e782a84b6a45e7f33b6695638c88e3931

FROM ${GO_IMAGE} AS build
ARG TAGS=
WORKDIR /src
ENV CGO_ENABLED=0 GOFLAGS=-trimpath GOTOOLCHAIN=local
# A workspace of just the modules this image needs (keeps other modules'
# dependencies out of the build).
RUN printf 'go 1.27.0\n\nuse (\n\t./contract\n\t./relay\n)\n' > go.work
COPY contract/go.mod contract/go.sum contract/
COPY relay/go.mod relay/
RUN --mount=type=cache,target=/go/pkg/mod cd relay && go mod download
COPY contract/ contract/
COPY relay/ relay/
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    cd relay && go build -tags "${TAGS}" -ldflags "-s -w" -o /out/schild-relay ./cmd/schild-relay

FROM ${RUN_IMAGE}
COPY --from=build /out/schild-relay /usr/local/bin/schild-relay
ENV SCHILD_RELAY_LISTEN=:7480 \
    SCHILD_RELAY_METRICS=:9103 \
    SCHILD_RELAY_BUFFER=256 \
    SCHILD_LOG_FORMAT=json
USER 65532:65532
EXPOSE 7480 9103
HEALTHCHECK --interval=15s --timeout=4s --start-period=10s --retries=3 CMD ["/usr/local/bin/schild-relay", "health"]
ENTRYPOINT ["/usr/local/bin/schild-relay"]
