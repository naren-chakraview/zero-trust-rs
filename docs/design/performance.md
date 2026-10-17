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
