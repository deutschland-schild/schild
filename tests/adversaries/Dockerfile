# Red-team / adversary tools (MVP-07). TEST ONLY: these build on the public
# TEST ONLY keys and only ever run against our own containers on the internal
# test networks. Build context is the repository root (see contracts/conventions.md §2).
FROM golang:1.27.4-alpine@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 AS build
WORKDIR /src
COPY go.work ./
COPY contract/ contract/
COPY tests/adversaries/ tests/adversaries/
COPY gateway/go.mod gateway/go.mod
COPY lab/go.mod lab/go.mod
COPY relay/go.mod relay/go.mod
COPY tests/testlab/go.mod tests/testlab/go.mod
RUN cd tests/adversaries && CGO_ENABLED=0 go build -trimpath -o /out/ ./cmd/...

FROM gcr.io/distroless/static-debian13:nonroot@sha256:aafe993665bf6200db38a02c11a9351e782a84b6a45e7f33b6695638c88e3931
COPY --from=build /out/ /usr/local/bin/
# Default entrypoint is the scenario runner; compose overrides the command for
# the misbehaving lab and the Sybil tool.
ENTRYPOINT ["/usr/local/bin/adversary"]
