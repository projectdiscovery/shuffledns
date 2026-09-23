# Benchmark image: builds massdns from source and the dnsbench harness, then
# benchmarks the native resolver against massdns using a battery of loopback
# resolvers. No DNS traffic leaves the container (resolvers are 127.0.0.1).
#
# Build (context must be the repository root):
#   docker build -f bench/Dockerfile -t shuffledns-dnsbench .
#
# Run:
#   docker run --rm shuffledns-dnsbench -names 200000 -resolvers 16 -hit 5
#
# The container needs no network at runtime; everything is loopback.

FROM golang:1.24-bookworm AS build

# --- build massdns from source -------------------------------------------------
RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates gcc make libc6-dev \
    && rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 https://github.com/blechschmidt/massdns.git /opt/massdns \
    && make -C /opt/massdns

# --- build the dnsbench harness ------------------------------------------------
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /usr/local/bin/dnsbench ./cmd/dnsbench

# --- runtime image -------------------------------------------------------------
FROM debian:bookworm-slim
COPY --from=build /opt/massdns/bin/massdns /usr/local/bin/massdns
COPY --from=build /usr/local/bin/dnsbench /usr/local/bin/dnsbench

ENTRYPOINT ["/usr/local/bin/dnsbench", "-massdns", "/usr/local/bin/massdns"]
CMD ["-names", "100000", "-resolvers", "8", "-hit", "5"]
