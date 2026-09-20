# Changelog

## Unreleased — Identifier 8/9-byte boundary and parse–display–eval invariants

No product code or public API is changed. This entry adds a single
independently nameable integration-test target, `tests/test_invariants.rs`
(run with `cargo test --test test_invariants`), that pins the coupled
invariants between the `Identifier` small-string optimization, the parser,
`Display`, SemVer precedence, and `VersionReq` evaluation.

### Implementation choices

- **Test-only change.** Nothing under `src/` is modified on the committed
  branch; all work goes through existing public entry points
  (`Version::parse`, `Prerelease::new`, `BuildMetadata::new`,
  `VersionReq::parse`, `Comparator::parse`, `Display`, `Ord`, `Hash`), so the
  tests describe contract behavior rather than representation internals.
- **Boundary matrix instead of spot checks.** Lengths are chosen to surround
  every representation transition in `src/identifier.rs`: `0` (sentinel), `1`
  (smallest inline), `8` (largest inline — the whole pointer-sized word), `9`
  (smallest heap allocation, 1-byte varint length header), `10`, `127/128`
  (1- vs 2-byte varint header), and `16383/16384` (2- vs 3-byte header,
  skipped under Miri for speed). Five deterministic monotonic string families
  (alphabetic, all-ones, mixed alphanumeric, dotted alphabetic, dotted
  numeric) are generated purely from the requested length — no randomness,
  sleeps, network, absolute paths, or fixture-name special cases.
- **Generative cross-check with an independent oracle.** A from-spec
  reimplementation of the dot-component order (numeric length-then-ASCII,
  numeric-vs-nonnumeric, build metadata's leading-zero tie-break) is compared
  pairwise against the crate over every length in `0..=40` plus the varint
  boundaries. Because each operand is independently generated, the pair space
  covers inline-inline, inline-heap, and heap-heap comparisons in both
  directions; equal pairs are additionally checked for `Hash` agreement.
- **Three verification directions requested by the task.**
  - *Both sides of every boundary*: each `8` case is paired with its `9`
    counterpart (and `127` with `128`, `16383` with `16384`).
  - *Symmetric entry points*: identical text is built through
    `Prerelease::new`/`BuildMetadata::new`, full `Version` parsing,
    `VersionReq`/`Comparator` parsing, and `Display` round trips;
    `Comparator::matches` and `VersionReq::matches` are asserted to agree.
  - *Failure recovery*: malformed inputs are asserted to fail with their
    position-bearing diagnostic message, and unrelated parsing is shown to
    remain usable afterward.
- **Diagnostics retained.** Negative cases assert the exact error text
  (`"invalid leading zero in pre-release identifier"`,
  `"value of major version number exceeds u64::MAX"`,
  `"empty identifier segment in build metadata"`, etc.), so a change that
  silently routed an error to the wrong `Position` is a failure, not merely an
  `is_err`.

### Coverage gaps the new tests close

- No prior test compared an **inline length-8 numeric identifier against a
  heap length-9 numeric identifier**. Existing tests (`test_identifier.rs`,
  `test_spec_order`) use either short ASCII labels or same-representation
  pairs, so a representation-based comparison (comparing the 8 stored bytes)
  would pass them.
- The **varint header boundaries at 127/128 and 16383/16384** were exercised
  only by a 20000-byte stress string, never on both sides of a boundary where
  a one-byte header-size error flips decoding.
- Build metadata's own order versus its invisibility from precedence was
  documented (including in the `cmp_precedence` doctest) but had no test
  pairing **cross-SSO build strings** with `cmp_precedence` and
  `VersionReq::matches` in one matrix.
- The prerelease admission rule
  ("a comparator with the same **major.minor.patch** and a nonempty
  prerelease") lacked the sharp *higher-patch candidate* direction:
  `1.5.2-alpha` numerically satisfies `>=1.5.1-alpha` yet must be rejected.
  Existing tests only had candidates that fail the numeric test too, which
  cannot distinguish the exact-triple clause from a weaker same-minor rule.
- Leading-zero, overflow, and empty-segment matrices now pin both the
  pre-release/build asymmetry (leading zeros legal only in build metadata) and
  u64-overflow-adjacent behavior (19-digit vs 20-digit all-numeric pre-release
  segments remain legal strings and compare numerically).

### Most dangerous counterexample and its regression test

The single most dangerous pair in this codebase is

```text
99999999   (8 ASCII digits -> inline representation)
100000000  (9 ASCII digits -> heap representation)
```

Across the SSO boundary the two identifiers live in *different
representations*. A comparison keyed on the inline bytes (or on the rotated
pointer word) sees first bytes `'9'` versus `'1'` and concludes
`99999999 > 100000000`; the SemVer numeric rule requires
`99_999_999 < 100_000_000`. Worse, the *same digits* as build metadata must
keep that numeric order for `BuildMetadata`'s own total order while remaining
completely invisible to `Version` precedence and requirement matching. That
three-way requirement — reverse direction across representations, honored in
pre ordering, honored in build ordering, ignored in precedence — is
regression-locked by `danger_inline_8_vs_heap_9_numeric_direction` and backed
by `prerelease_cross_sso_ord_matrix`,
`build_metadata_own_order_but_ignored_by_precedence`,
`build_total_order_without_precedence`, and the generative oracle test
`generative_ord_eq_hash_matches_reference`.

### Deliberate mutations and the tests that detect them

Each mutation below was applied to a temporary working copy of the product
code, the new test target was run, and the change was then reverted; the
committed `src/` is byte-for-byte the original implementation.

1. **Numeric pre-release order reduced to ASCII**
   (`src/impls.rs`, `(true, true)` arm dropping length-first comparison):
   `danger_inline_8_vs_heap_9_numeric_direction` and
   `prerelease_cross_sso_ord_matrix` fail.
2. **Leading-zero length predicate shifted** (`segment_len > 1` -> `> 2` in
   `src/parse.rs`): `leading_zero_matrix_with_diagnostics` and
   `parse_failure_recovery` fail on the two-digit `01` segment.
3. **u64 overflow made wrapping** (`checked_mul/checked_add` ->
   `wrapping_*` in `src/parse.rs`):
   `overflow_and_oversized_numeric_segment` fails.
4. **Prerelease admission weakened** to same major.minor
   (dropping `cmp.patch == Some(ver.patch)` in `src/eval.rs`):
   `prerelease_admission_requires_exact_triple` fails on `1.5.2-alpha` vs
   `>=1.5.1-alpha`. (The first draft of this test missed the mutation; the
   higher-patch candidate direction was added specifically so the exact-triple
   clause is what kills the mutant, not the numeric comparison.)
5. **Build metadata leaked into precedence** (`cmp_precedence` tuple extended
   with `build` in `src/lib.rs`):
   `build_metadata_own_order_but_ignored_by_precedence`,
   `build_total_order_without_precedence`, and
   `danger_inline_8_vs_heap_9_numeric_direction` fail.

### Regression protection for adjacent semantics

- Pre-release vs build-metadata grammar asymmetry (leading zeros, segment
  emptiness) is pinned in `leading_zero_matrix_with_diagnostics` and
  `empty_and_illegal_segment_diagnostics`.
- Build metadata dropped from comparator parsing is pinned by
  `version_req_display_round_trip_and_dropped_build` (`=1.5.0+b` re-displays
  as `=1.5.0`).
- The independent `Display` length computation used by width/fill padding is
  checked across the boundary in `display_width_around_sso_boundary`.
- Clone/Drop pairing for heap identifiers is covered by
  `heap_clone_outlives_original` (clone outlives the dropped original) and
  `sso_length_repr_matrix` at every length including multi-byte varint
  headers.

### Verification

```sh
cargo fetch
cargo test --test test_invariants   # 18 tests, individually nameable
cargo test                          # full suite + doctests: all pass
```
