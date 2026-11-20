# schild-lab: lab core (MVP-03) and lab dashboard (MVP-10). Build context: repository root
#
#   make ui                                              # embeds the dashboard (optional)
#   docker build -f lab/Dockerfile -t schild-lab:dev .
#   docker build -f lab/Dockerfile --build-arg TAGS=release -t schild-lab:alpha .  # no test keys/profile
#
# Prototype images for stage 2 and 3 are built without TAGS=release (contracts/DECISIONS.md D05).
# Mount /etc/schild-lab (lab.yaml, keys/, tls/) read-only and a volume on /var/lib/schild-lab.

ARG GO_IMAGE=golang:1.27.4-alpine@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280
ARG RUN_IMAGE=gcr.io/distroless/static-debian13:nonroot@sha256:aafe993665bf6200db38a02c11a9351e782a84b6a45e7f33b6695638c88e3931

FROM ${GO_IMAGE} AS build
ARG TAGS=
ARG VERSION=0.1.0-alpha
WORKDIR /src
ENV CGO_ENABLED=0 GOFLAGS=-trimpath GOTOOLCHAIN=local
RUN printf 'go 1.27.0\n\nuse (\n\t./contract\n\t./lab\n\t./relay\n)\n' > go.work
COPY contract/go.mod contract/go.sum contract/
COPY relay/go.mod relay/
COPY lab/go.mod lab/go.sum lab/
RUN --mount=type=cache,target=/go/pkg/mod cd lab && go mod download
COPY contract/ contract/
COPY relay/ relay/
COPY lab/ lab/
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    cd lab && go build -tags "${TAGS}" -ldflags "-s -w -X main.version=${VERSION}" -o /out/schild-lab ./cmd/schild-lab \
 && /out/schild-lab version \
 && mkdir -p /out/var/lib/schild-lab /out/etc/schild-lab

FROM ${RUN_IMAGE}
COPY --from=build /out/schild-lab /usr/local/bin/schild-lab
COPY --from=build --chown=65532:65532 /out/var/lib/schild-lab /var/lib/schild-lab
ENV SCHILD_LAB_CONFIG=/etc/schild-lab/lab.yaml \
    SCHILD_LAB_DATA_DIR=/var/lib/schild-lab \
    SCHILD_LOG_FORMAT=json
USER 65532:65532
VOLUME ["/var/lib/schild-lab"]
EXPOSE 7443 7444 8789 9102
HEALTHCHECK --interval=15s --timeout=4s --start-period=20s --retries=3 CMD ["/usr/local/bin/schild-lab", "health"]
ENTRYPOINT ["/usr/local/bin/schild-lab"]
CMD ["run"]
