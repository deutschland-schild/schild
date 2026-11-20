# TEST ONLY: MVP-21 measurement runtime (arm64 local test image)
FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2
RUN apt-get update && apt-get install -y --no-install-recommends iproute2 procps curl ca-certificates sysstat && rm -rf /var/lib/apt/lists/*
