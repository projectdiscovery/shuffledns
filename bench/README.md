# DNS resolver benchmark

Benchmarks the native Go resolver (`pkg/resolve`) against the external
`massdns` binary using a battery of **loopback** DNS servers that simulate
remote recursive resolvers (`internal/simdns`).

No DNS traffic ever leaves the host: every resolver an engine talks to is a
`127.0.0.1:<ephemeral>` UDP server started in-process. The simulated resolvers
model real remote conditions:

- response latency + jitter
- packet loss (exercises the timeout/retransmit path)
- SERVFAIL rate (exercises retry-on-rotation)
- per-resolver QPS cap (models throttling public resolvers)
- a deterministic, mostly-NXDOMAIN hit ratio (realistic bruteforce workload)

The answered/NXDOMAIN decision and synthetic A record are deterministic per
name, so both engines resolve the exact same workload under identical
conditions.

## Scenarios

| scenario      | latency      | loss | servfail | per-resolver QPS |
|---------------|--------------|------|----------|------------------|
| `lan-fast`    | ~0.5 ms      | -    | -        | unlimited        |
| `wan-typical` | 15 ± 10 ms   | 0.5% | -        | unlimited        |
| `wan-lossy`   | 25 ± 20 ms   | 5%   | 2%       | unlimited        |
| `rate-limited`| 10 ± 10 ms   | -    | -        | 3000 / resolver  |

## Running with Docker (recommended)

`massdns` is Linux-only (epoll), so the benchmark runs in a container that
builds massdns from source. The build context must be the repository root:

```bash
docker build -f bench/Dockerfile -t shuffledns-dnsbench .
docker run --rm shuffledns-dnsbench -names 200000 -resolvers 16 -hit 5
```

Useful flags (`dnsbench -h`):

- `-names`        names to resolve per scenario (default 50000)
- `-resolvers`    number of simulated loopback resolvers (default 8)
- `-hit`          percent of names that resolve, rest NXDOMAIN (default 5)
- `-concurrency`  in-flight concurrency / massdns hashmap size (default 10000)
- `-retries`      retry budget per name, applied to both engines (default 5)
- `-sockets`      native udp socket count (0 = scale to cores)
- `-batch-mode`   native batching: `off` (default) | `on` | `adaptive`
- `-engines`      `native,massdns` (default both)
- `-scenarios`    comma-separated scenario names or `all`

### A note on `-batch-mode` (sendmmsg/recvmmsg)

The native resolver can batch datagrams per syscall using Linux
`sendmmsg`/`recvmmsg` (via `golang.org/x/net/ipv4`, IPv4-only resolver sets).
Batching is workload-dependent, so there are three modes:

- `off` (default): always one datagram per syscall — the proven, lowest-latency
  path. Best on loopback / low-RTT links.
- `on`: always batch. Helps on **high-latency / bursty** links, where many
  in-flight responses arrive clustered in time and fill batches, amortizing the
  syscall cost. **Counterproductive on loopback / low-RTT** links: batches stay
  tiny (1–2 datagrams), so the per-call message-array setup costs more than a
  plain `sendto`/`recvfrom`, and it adds first-response latency.
- `adaptive`: start in single mode and let a lightweight controller toggle
  batching at runtime based on observed conditions (see below).

On this loopback benchmark you can see both effects: `-batch-mode on` roughly
halves `lan-fast` throughput but modestly improves the higher-latency scenarios,
while `-batch-mode adaptive` stays near single-path performance on `lan-fast`
and ramps batching up only on the latency-/loss-bound scenarios.

#### How `adaptive` decides

A controller goroutine samples every 200ms and toggles batching with hysteresis:

- **Smoothed RTT** (EWMA of observed round-trip times): batching needs latency
  for packets to cluster. Engage above ~3ms, disengage below ~1ms.
- **In-flight depth** (`len(sem)`): batches can only fill if the pipeline is
  deep. Engage only when depth ≥ 2×batch size; disengage when it falls below a
  batch.
- **Interval packet loss** (retransmits ÷ sends per tick): rising loss often
  means a resolver or kernel buffer is already saturated, and bursty `sendmmsg`
  makes that worse — so loss above ~15% forces batching **off** to spread sends
  out.

Toggling only changes the send/recv strategy; results are identical either way.
When batching is disengaged the send path uses plain `sendto` (it also falls
back to single sends for batches smaller than 4 datagrams) and the read path
uses single `recvfrom`, so "adaptive-off" costs the same as the default path.

Cross-platform behaviour of the batch API (`ReadBatch`/`WriteBatch`):

- **Linux**: real `recvmmsg`/`sendmmsg` (batched).
- **macOS, Windows, *BSD, others**: the same calls transparently fall back to a
  single `recvmsg`/`sendmsg` per call, so the code is portable and correct
  everywhere; only Linux gets the kernel batch syscalls.

### Read-path parallelism (the client-side equivalent of `SO_REUSEPORT`)

`SO_REUSEPORT` is a *server* mechanism for sharing one well-known port across
sockets so the kernel fans incoming packets out to multiple readers. A stub
resolver is a *client*: it already opens N independent sockets on distinct
ephemeral ports, each drained by its own reader goroutine, which delivers the
same per-core receive parallelism without a shared in-flight map or port
juggling. The socket pool therefore scales with `GOMAXPROCS` by default
(`-sockets 0`); binding those sockets to a single port via `SO_REUSEPORT` would
yield identical queue/reader counts with no throughput gain, so it is
deliberately not used.

Both engines are given matching timeout/interval and retry budgets so the
comparison is fair; the exact massdns flags used are documented in
`cmd/dnsbench/main.go`.

## Native-only (no Docker)

The native engine is pure Go and runs anywhere:

```bash
go run ./cmd/dnsbench -engines native -names 200000 -resolvers 16
```

The same battery is also wired into a Go test, which can toggle the adaptive
resolver features so you can see their effect per scenario:

```bash
# baseline
RESOLVE_BENCH=1 go test ./pkg/resolve -run TestResolverBenchmark -v \
    -bench.names 100000 -bench.resolvers 16

# adaptive batching (helps deep/high-latency pipelines)
RESOLVE_BENCH=1 go test ./pkg/resolve -run TestResolverBenchmark -v \
    -bench.names 100000 -bench.resolvers 16 -bench.batch adaptive

# health scoring + adaptive concurrency (helps lossy / rate-limited resolvers)
RESOLVE_BENCH=1 go test ./pkg/resolve -run TestResolverBenchmark -v \
    -bench.names 100000 -bench.resolvers 16 -bench.health -bench.adaptconc
```

## Resolver capabilities (parity with / beyond massdns)

Core massdns stub features plus several massdns TODOs. Main shuffledns flags:

| Capability | shuffledns flag | Notes |
|---|---|---|
| Record type | `-rt A\|AAAA\|CNAME\|NS\|PTR\|MX\|TXT\|SOA` | massdns `-t`; bruteforce store is A/AAAA-oriented |
| In-flight cap | `-t` | massdns `-s` |
| Send-rate cap | `-qps` | token bucket; 0 = unlimited |
| Non-recursive | `-norecurse` | massdns `--norecurse` (RD=0) |
| Sticky resolver | `-sticky` | massdns `--sticky` |
| EDNS0 UDP size | `-udp-size N` | OPT advertised payload (default 1232) |
| Source-IP verify | on by default, `-no-verify-ip` to disable | massdns `--verify-ip` (opt-out here) |
| TCP fallback | on by default, `-no-tcp-fallback` to disable | follows truncated (TC) answers |
| Batching | `-bm off\|on\|adaptive` | sendmmsg/recvmmsg (Linux) |
| Socket count | `-sc N` | massdns `--socket-count` |
| Per-resolver health | `-rhz` | de-weights failing resolvers (massdns TODO) |
| Adaptive concurrency | `-acy` | AIMD in-flight cap on loss (massdns TODO) |
| Cross-resolver check | `-cc` | poisoning/spam detection (massdns TODO) |
| Extended input | `-ei` | `name [resolver ...]` lines (massdns `--extended-input`) |
| Iterative from roots | `-it` | no public resolver list |

### Privilege drop & raw IPv6 source (cmd/resolve)

| Feature | Flags | Notes |
|---|---|---|
| Drop root after open | `--drop-user` / `--drop-group` / `--root` | Unix; defaults to `nobody` when euid=0 unless `--root` |
| Random IPv6 source | `--rand-src-ipv6 PREFIX` / `--rand-src-ipv6-file` | Linux `SOCK_RAW` + `IPV6_HDRINCL`; needs `CAP_NET_RAW`; IPv6 resolvers only; incompatible with `--bindto` |

### Intentionally ignored (accepted for CLI drop-in)

`--processes`, `--busy-poll`.

`-o B`, `--bindto`, `--rcvbuf`/`--sndbuf`, `--predictable`, `--flush` are
implemented on `cmd/resolve`. Full `-o` formatting lives there, not in the
shuffledns hostname-list output.

### QPS notes

- Effective throughput ≈ `min(-t / RTT, -qps, Σ resolver capacity)`.
- Default `-bm off` is correct for low-RTT; forced `on` often hurts lan-fast.
- Public-resolver runs are usually RTT/rate-limit bound, not CPU bound.

Example native-only numbers (50k names, 8 sim resolvers, `-t 10000`):

| scenario | ~qps |
|---|---|
| lan-fast | ~90k |
| wan-typical | ~40k |
| wan-lossy | ~27k |
| rate-limited (3k/resolver) | ~40k |

Retry rcode policy matches massdns (retry everything except NOERROR / NXDOMAIN).
Progress is available via `OnProgress` / `Stats` on the resolver client.
