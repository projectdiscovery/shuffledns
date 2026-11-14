FROM alpine:latest

LABEL org.opencontainers.image.authors="ProjectDiscovery"
LABEL org.opencontainers.image.description="shuffleDNS is a high-throughput DNS bruteforcer and resolver with wildcard handling, built on a native massdns-compatible Go resolver."
LABEL org.opencontainers.image.licenses="GPL-3.0-only"
LABEL org.opencontainers.image.title="shuffledns"
LABEL org.opencontainers.image.url="https://github.com/projectdiscovery/shuffledns"

ARG TARGETPLATFORM
COPY $TARGETPLATFORM/shuffledns /usr/bin/shuffledns
ENV HOME=/
ENTRYPOINT ["/usr/bin/shuffledns"]
