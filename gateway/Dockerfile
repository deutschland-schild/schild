# schild: the Schild Gateway, proxy with WAF (Caddy + Coraza + OWASP CRS),
# CrowdSec Hub rules, local events and the gateway dashboard. Build
# context: repository root. The build needs only contract/, gateway/ and
# dashboard/ (no lab, no relay): it builds the dashboard in a Node stage and
# compiles in a workspace of its own.
#
# A plain build is a release build with real geo data, the same as the
# published image ghcr.io/deutschland-schild/schild:
#
#   docker build -f gateway/Dockerfile --build-arg VERSION=0.1.0-alpha.1 -t schild:local .
#
# Development and test lab images are asked for on purpose (make gateway-image
# and make images do that). They accept test keys and the test profile, say so
# in `schild version` and in the label de.deutschland-schild.build, and are
# never published:
#
#   docker build -f gateway/Dockerfile --build-arg TAGS= --build-arg GEO=fixture -t schild:dev .
#
# Build arguments:
#   TAGS     release (default) or empty for a dev build
#   VERSION  what `schild version` reports (the release workflow passes the tag)
#   GEO      dbip (default: DB-IP Lite of GEO_MONTH, sha256 checked) or
#            fixture (TEST ONLY documentation ranges, no download)
#   AGENT    1 adds /usr/local/bin/schild-agent for the test lab (MVP-11; not
#            part of the first gateway version, D60b; never run in this container)
#
# Targets: the default is the runtime image. `--target dist --output DIR`
# writes the files of the release tarball (the same binary as in the image).
#
# Run it locked down. schild writes only below /var/lib/schild (events,
# metrics, Caddy storage and the temp files of request bodies), so the root
# file system can be read-only and no capability is needed for the proxy port:
#
#   docker run -d --name schild --read-only --cap-drop ALL \
#     --security-opt no-new-privileges:true \
#     -v /etc/schild/schild.yaml:/etc/schild/schild.yaml:ro \
#     -v schild-data:/var/lib/schild -p 8080:8080 schild:local
#
# Dashboard (8788) and metrics (9101) listen on 127.0.0.1 by default, so they
# are not reachable from outside the container's network namespace. With
# network_mode host that is the host's loopback (SSH tunnel). On a bridge
# network set listen.dashboard to 0.0.0.0:8788 and publish it on loopback
# only (-p 127.0.0.1:8788:8788), never on a public address; the quickstart in
# deploy/quickstart does exactly that. The HEALTHCHECK
# asks http://127.0.0.1:9101/readyz; if you move listen.metrics, override it.
# In ingress mode (ingress.caddyfile) also mount the Caddy storage and the log
# directories the Caddyfile writes to.
#
# All base images are pinned by digest; bump the digests on purpose.

ARG GO_IMAGE=golang:1.27.4-alpine@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280
ARG NODE_IMAGE=node:22.23.5-alpine@sha256:1314fb30ec37592d5845e5a160d522c0e680972aa534549940b8d73bde88481a
ARG RUN_IMAGE=gcr.io/distroless/static-debian13:nonroot@sha256:aafe993665bf6200db38a02c11a9351e782a84b6a45e7f33b6695638c88e3931

# The gateway dashboard (dashboard/apps/client-dashboard). Built here, so the
# image never depends on what lies in gateway/internal/webui/dist on the build
# machine (the .dockerignore keeps that directory out). The output is the same
# for every platform, so the stage runs on the build platform.
FROM --platform=$BUILDPLATFORM ${NODE_IMAGE} AS ui
WORKDIR /ui
ENV CI=1
COPY dashboard/package.json dashboard/pnpm-lock.yaml dashboard/pnpm-workspace.yaml dashboard/.npmrc ./
COPY dashboard/apps/client-dashboard/package.json apps/client-dashboard/
COPY dashboard/apps/lab-dashboard/package.json apps/lab-dashboard/
COPY dashboard/packages/app-kit/package.json packages/app-kit/
COPY dashboard/packages/ui/package.json packages/ui/
# pnpm in the version package.json names (packageManager), fetched by corepack, which checks the npm registry
# signature.
ENV COREPACK_ENABLE_DOWNLOAD_PROMPT=0
RUN corepack enable pnpm \
 && pnpm install --frozen-lockfile --filter '@schild/client-dashboard...'
COPY dashboard/ ./
RUN pnpm --filter @schild/client-dashboard build \
 && test -s apps/client-dashboard/dist/index.html \
 && node scripts/third-party-licenses.mjs /ui/THIRD_PARTY_LICENSES.ui \
 && test -s /ui/THIRD_PARTY_LICENSES.ui

FROM ${GO_IMAGE} AS build
ARG TAGS=release
ARG VERSION=0.0.0-dev
ARG AGENT=0
WORKDIR /src
ENV CGO_ENABLED=0 GOFLAGS=-trimpath GOTOOLCHAIN=local
RUN case "${TAGS}" in release|"") ;; *) echo "TAGS must be release or empty, got: ${TAGS}" >&2; exit 1;; esac
# A workspace of contract and gateway only: the repository's go.work also
# lists lab, relay and the test modules, which this build does not need.
# go.work.sum carries the checksums the workspace adds to the go.sum files.
# The cache mounts keep Go's module and build cache between local builds; a
# fresh builder (CI, release) starts with empty ones. go build fetches the
# modules the binary links, each checked against go.sum; a "go mod download"
# of the whole module graph took many times longer and added nothing.
COPY go.work.sum ./
COPY contract/ contract/
COPY gateway/ gateway/
RUN go work init ./contract ./gateway
# The dashboard from the ui stage. Without it schild would serve a placeholder
# page, so a missing index.html stops the build.
COPY --from=ui /ui/apps/client-dashboard/dist/ gateway/internal/webui/dist/
RUN test -s gateway/internal/webui/dist/index.html \
 || { echo "dashboard build missing: gateway/internal/webui/dist/index.html" >&2; exit 1; }
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    cd gateway && go build -tags "${TAGS}" \
      -ldflags "-s -w -X github.com/deutschland-schild/schild/gateway/internal/buildinfo.Version=${VERSION}" \
      -o /out/bin/schild ./cmd/schild \
 && /out/bin/schild version \
 && if [ "${TAGS}" = release ]; then /out/bin/schild version | head -n 1 | grep -qxF "schild ${VERSION} (release)" \
      || { echo "release build does not report itself as a release" >&2; exit 1; }; fi \
 && if [ "${AGENT}" = 1 ]; then go build -tags "${TAGS}" \
      -ldflags "-s -w -X github.com/deutschland-schild/schild/gateway/internal/buildinfo.Version=${VERSION}" \
      -o /out/bin/schild-agent ./cmd/schild-agent && /out/bin/schild-agent version; fi \
 && mkdir -p /out/var/lib/schild/export /out/etc/schild/rules.d /out/usr/share/schild/geo

# The license of every module linked into the binaries (Caddy, Coraza and the
# OWASP CRS are Apache-2.0) plus the third-party packages bundled into the
# embedded dashboard. A module without a license file stops the build.
COPY --from=ui /ui/THIRD_PARTY_LICENSES.ui /tmp/THIRD_PARTY_LICENSES.ui
RUN --mount=type=cache,target=/go/pkg/mod \
    cd gateway && go list -tags "${TAGS}" -deps \
      -f '{{with .Module}}{{if .Version}}{{.Path}} {{.Version}} {{.Dir}}{{end}}{{end}}' \
      ./cmd/schild $(if [ "${AGENT}" = 1 ]; then echo ./cmd/schild-agent; fi) | sort -u > /tmp/modules \
 && while read -r path version dir; do \
      files=$(ls "$dir" | grep -iE '^(licen[cs]e|copying|notice)' || true); \
      if [ -z "$files" ]; then echo "no license file: $path $version" >&2; exit 1; fi; \
      for f in $files; do printf '%s\n%s %s: %s\n%s\n\n' "==============================================================================" "$path" "$version" "$f" "=============================================================================="; cat "$dir/$f"; printf '\n'; done; \
    done < /tmp/modules > /out/THIRD_PARTY_LICENSES \
 && printf '\n' >> /out/THIRD_PARTY_LICENSES \
 && cat /tmp/THIRD_PARTY_LICENSES.ui >> /out/THIRD_PARTY_LICENSES \
 && test -s /out/THIRD_PARTY_LICENSES

# Geo data: DB-IP Lite country + ASN (CC BY 4.0), pinned to one month and
# checked against the sha256 of the unpacked files, so the image is
# reproducible and a changed download stops the build. A new month is a change
# to GEO_MONTH and both checksums (make gateway-geo-pin GEO_MONTH=YYYY-MM
# prints them). GEO=fixture writes the TEST ONLY documentation-range database
# instead (no download).
FROM ${GO_IMAGE} AS geo
ARG GEO=dbip
ARG GEO_MONTH=2026-11
ARG GEO_COUNTRY_SHA256=145ce5dfb812d8de28547e6289bb5c5f8b3df2f1dea21d324d5b575e0431311f
ARG GEO_ASN_SHA256=81565a450281c949fc83745f5ec9cfea70b035163b1152b055645884765d153d
COPY --from=build /out/bin/schild /usr/local/bin/schild
WORKDIR /geo
RUN set -eu; \
    if [ "$GEO" = "fixture" ]; then \
      schild geo-fixture -out country.mmdb; \
      echo "schild geo fixture (TEST ONLY): documentation ranges, no real data" > ATTRIBUTION.txt; \
    elif [ "$GEO" = "dbip" ]; then \
      if [ -z "$GEO_COUNTRY_SHA256" ] || [ -z "$GEO_ASN_SHA256" ]; then \
        echo "GEO=dbip needs GEO_COUNTRY_SHA256 and GEO_ASN_SHA256" >&2; exit 1; fi; \
      base=https://download.db-ip.com/free; \
      wget -q -O country.mmdb.gz "$base/dbip-country-lite-${GEO_MONTH}.mmdb.gz"; \
      wget -q -O asn.mmdb.gz "$base/dbip-asn-lite-${GEO_MONTH}.mmdb.gz"; \
      gunzip country.mmdb.gz asn.mmdb.gz; \
      test -s country.mmdb && test -s asn.mmdb; \
      echo "$GEO_COUNTRY_SHA256  country.mmdb" | sha256sum -c -; \
      echo "$GEO_ASN_SHA256  asn.mmdb" | sha256sum -c -; \
      printf '%s\n' \
        "IP Geolocation by DB-IP (https://db-ip.com)" \
        "dbip-country-lite-${GEO_MONTH} and dbip-asn-lite-${GEO_MONTH}," \
        "licensed under the Creative Commons Attribution 4.0 International License" \
        "(https://creativecommons.org/licenses/by/4.0/)." > ATTRIBUTION.txt; \
    else \
      echo "GEO must be dbip or fixture, got: $GEO" >&2; exit 1; \
    fi; \
    sha256sum *.mmdb > SHA256SUMS; cat SHA256SUMS

# The files of the release tarball schild_<version>_linux_<arch>.tar.gz
# (.github/workflows/release.yml): docker build --target dist --output DIR.
FROM scratch AS dist
COPY --from=build /out/bin/schild /schild
COPY docs/ops/systemd/schild.service /schild.service
COPY docs/ops/systemd/schild-firewall.service /schild-firewall.service
COPY LICENSE /LICENSE
COPY gateway/NOTICE /NOTICE
COPY --from=build /out/THIRD_PARTY_LICENSES /THIRD_PARTY_LICENSES
COPY gateway/deploy/release/README.txt /README.txt
COPY --from=geo /geo/ /geo/

FROM ${RUN_IMAGE}
ARG VERSION=0.0.0-dev
ARG TAGS=release
ARG GEO=dbip
LABEL org.opencontainers.image.title="schild" \
      org.opencontainers.image.description="Schild Gateway: reverse proxy with WAF (Caddy, Coraza, OWASP CRS)" \
      org.opencontainers.image.source="https://github.com/deutschland-schild/schild" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.url="https://deutschland-schild.de" \
      org.opencontainers.image.version="${VERSION}" \
      de.deutschland-schild.build="${TAGS:-dev (TEST ONLY: test keys and test profile allowed)}" \
      de.deutschland-schild.geo="${GEO}"
COPY --from=build /out/bin/ /usr/local/bin/
COPY --from=build --chown=65532:65532 /out/var/lib/schild /var/lib/schild
COPY --from=build /out/etc/schild /etc/schild
COPY --from=geo /geo/ /usr/share/schild/geo/
COPY gateway/NOTICE /usr/share/doc/schild/NOTICE
COPY --from=build /out/THIRD_PARTY_LICENSES /usr/share/doc/schild/THIRD_PARTY_LICENSES
ENV SCHILD_CONFIG=/etc/schild/schild.yaml \
    SCHILD_DATA_DIR=/var/lib/schild \
    SCHILD_LOG_FORMAT=json
USER 65532:65532
VOLUME ["/var/lib/schild"]
# Only the proxy port. Dashboard and metrics stay on loopback (see the top).
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=4s --start-period=20s --retries=3 CMD ["/usr/local/bin/schild", "health"]
ENTRYPOINT ["/usr/local/bin/schild"]
CMD ["run"]
