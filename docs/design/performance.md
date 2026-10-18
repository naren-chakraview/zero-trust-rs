# Performance Baselines

Informational criterion benchmarks for the gateway's token-validation
pipeline (`obo::validate`), added in Task 4 (F17) to measure the cost of
On-Behalf-Of (OBO) delegation. These are baselines, not regression gates —
there is no pass/fail performance requirement attached to them.

Benchmark source: [`benches/gateway_benches.rs`](../../benches/gateway_benches.rs).
Run `cargo bench --bench gateway_benches` to measure on your own system; HTML
reports are generated under `target/criterion/`.

## Measured baseline

Measured on a 13th Gen Intel Core i9-13900KF (WSL2 / Linux 6.18,
`rustc 1.90.0`, release profile) with criterion 0.5:

| Operation | Latency |
|-----------|---------|
| Token signature verification + validation checks (`validate_token_signature_and_checks`) | ~14.5 µs |
| Three-hop delegation chain validation (`validate_three_hop_delegation_chain`) | ~15.3 µs |

Both benchmarks exercise `obo::validate()` against a real RS256 issuer
keypair and a real `Registry` (no mocks) — the first with a plain,
non-delegated OBO token, the second with a token whose signed `act` claim
carries a three-hop delegation chain
(`api-gateway -> gw1 -> gw2 -> orders-svc`).

As expected, the three-hop case costs only marginally more than the
single-hop case (roughly +0.8 µs, ~5%): the delegation chain is carried
entirely inside the one signed token, so verifying it is still a single
RS256 signature check plus a handful of extra in-memory SPIFFE-ID parses for
the additional chain entries — not a chain of independent signature
verifications.

Note: both numbers are well under the ~1-5ms planning estimate used when
this benchmark was scoped. In practice RS256 verification with the
`jsonwebtoken` crate, in a release build, on modern hardware, lands in the
tens-of-microseconds range — the 1-5ms figure should be treated as a loose
upper bound, not the expected result.

Run `cargo bench` (or `cargo bench --bench gateway_benches`) to measure on
your system.

## Token Exchange Performance

Added in Task 15 (N14, review 0002): three more benchmarks, measuring the
cost `obo::validate` alone doesn't capture — re-minting a token at exchange
time (`token_exchange::exchange_token`), and the full network round trip
through a chain of gateways that each do so.

| Benchmark | What it measures |
|-----------|-------------------|
| `exchange_token_rs256_signature` | One `exchange_token` call: verify the inbound token's RS256 signature, sign a freshly re-minted token with the new hop prepended to `act`. No network. |
| `three_hop_proxy_round_trip_with_exchange` | One HTTP request through `client -> gw1 (exchange) -> gw2 (exchange) -> gw3 (validate+forward) -> backend` — three real axum servers on real loopback TCP, wired with real `reqwest` calls, two real `exchange_token` calls, one real `validate` call. |
| `proxy_round_trip_without_delegation` | The same shape of request through a single, non-delegated gateway (`client -> gw (validate) -> backend`) — the baseline the delegated case is compared against. |

### Measured costs

Measured on the same machine as the baseline above (13th Gen Intel Core
i9-13900KF, WSL2 / Linux 6.18, `rustc 1.90.0`, release/bench profile),
across multiple separate `cargo bench` runs:

| Operation | Observed range |
|-----------|-----------------|
| `exchange_token_rs256_signature` (one exchange) | ~0.4-1.4 ms |
| `three_hop_proxy_round_trip_with_exchange` (3 hops, 2 exchanges) | ~1.0-2.2 ms |
| `proxy_round_trip_without_delegation` (1 hop, no exchange) | ~0.2-0.3 ms |

These vary noticeably more, run to run, than the single-function
`validate` benchmarks above — expected, since they now include real
RSA-2048 **signing** (not just verification) and real loopback network
I/O, both of which are far more sensitive to OS scheduling noise on a
shared/virtualized host (WSL2) than a tight in-process microbenchmark. As
the benchmark harness itself notes, baseline absolute numbers will vary by
hardware; the relative comparison below is the actionable signal, and it
holds across every run observed.

**Why exchange costs so much more than validation.** RS256 verification
is a cheap public-key operation (modular exponentiation with a small
public exponent) — that's the ~15-35 µs `validate` benchmarks measure.
Signing is the expensive private-key operation (full-width modular
exponentiation with the private exponent), and `exchange_token` does both
(verify the inbound token, then sign the re-minted one): roughly
10-40x the cost of verification alone, which is exactly the ~0.4-1.4 ms
range observed. This is inherent to RS256/RSA, not specific to this
implementation — switching the signing algorithm (e.g. to ES256) would
reduce it, but is out of scope here.

**Overhead of delegation vs. baseline.** The three-hop, double-exchange
case costs roughly 4-9x the single-hop, no-exchange baseline
(~1.0-2.2 ms vs. ~0.2-0.3 ms) — consistent with the extra work it's
actually doing: two additional network hops, two `exchange_token` calls
(each dominated by one RSA signature), and one more token to parse and
verify at the final hop. None of that cost is per-user-request
boilerplate that could be trivially cut; it's the price of a verifiable,
re-signed delegation chain at every hop rather than one hop blindly
trusting the next.

**Production recommendation.** At roughly 1-2 ms per three-hop delegated
request, a single CPU core has throughput headroom for several hundred
such requests/second before exchange cost becomes the bottleneck (RSA
signing is the dominant, parallelizable cost — it scales with cores, not
request concurrency). For a deployment target in the low hundreds of
req/s per gateway replica — a reasonable range for an internal service
mesh's OBO-delegated traffic — this exchange cost is comfortably
acceptable without further optimization. Deployments targeting higher
sustained throughput per replica should consider: switching gateway
signing keys from RSA to an elliptic-curve algorithm (ES256), which has a
much cheaper private-key signing operation; or horizontally scaling
gateway replicas, since exchange cost is CPU-bound and parallelizes
cleanly across them.

Run `cargo bench --bench gateway_benches` to measure these three on your
own system; HTML reports land under `target/criterion/<benchmark name>/`.
