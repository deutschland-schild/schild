# Build context is the repository root (see conventions.md §2).
#
#   docker build -f tests/testlab/traffic/dockerfiles/traffic.Dockerfile -t schild-traffic:dev .
FROM golang:1.27.4-alpine@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 AS build
WORKDIR /src
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
    cd tests/testlab/traffic && go build -trimpath -o /out/traffic ./cmd/traffic

FROM gcr.io/distroless/static-debian13:nonroot
COPY --from=build /out/traffic /usr/local/bin/traffic
ENTRYPOINT ["/usr/local/bin/traffic"]
