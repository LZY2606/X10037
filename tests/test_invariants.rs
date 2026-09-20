#![allow(
    clippy::eq_op,
    clippy::needless_pass_by_value,
    clippy::uninlined_format_args
)]

//! Boundary-matrix and generative tests for the coupled invariants between
//! the Identifier small-string optimization (the 8/9-byte inline/heap split),
//! SemVer precedence rules, and the parse -> display -> parse round trip.
//!
//! The tests deliberately straddle the SSO boundary from both sides (lengths
//! 8 inline and 9 heap), exercise symmetric public entry points
//! (Version/Prerelease/BuildMetadata/VersionReq/Comparator parsing and
//! display), and verify recovery after parse failures. Every test in this
//! file is independently nameable, for example:
//!
//!     cargo test --test test_invariants sso_length_repr_matrix

mod util;

use crate::util::*;
use semver::{BuildMetadata, Prerelease, Version, VersionReq};
use std::cmp::Ordering;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

// Lengths that surround every representation transition in Identifier:
//   0        -> sentinel
//   1        -> smallest inline
//   8        -> largest inline (uses every byte of pointer-sized storage)
//   9        -> smallest heap allocation (1-byte varint length header)
//   10       -> first length that is merely "another heap" length
//   127/128  -> 1-byte vs 2-byte varint header boundary
//   16383/16384 (non-miri only) -> 2-byte vs 3-byte varint header boundary
const VARINT_BOUNDARY_LENGTHS: [usize; 6] = [0, 1, 7, 8, 9, 10];
const VARINT_HEADER_BOUNDARY_LENGTHS: [usize; 2] = [127, 128];

// Deterministic, monotonic string families. No randomness, sleeps, or fixture
// name special-casing: every byte is derived from the requested length.
fn alpha(n: usize) -> String {
    "abcdefghijklmnop".chars().cycle().take(n).collect()
}

fn ones(n: usize) -> String {
    "1".repeat(n)
}

// Letters interspersed with digits so every segment is non-numeric but the
// first byte keeps it lexical-looking (exposes length-then-ASCII tie breaks).
fn mixed(n: usize) -> String {
    "a1b2c3d4e5f6g7h8"
        .chars()
        .chain("0123456789".chars())
        .cycle()
        .take(n)
        .collect()
}

// Valid non-numeric dotted string of exactly n bytes for every n >= 1.
fn dotted_alpha(n: usize) -> String {
    let mut s = String::with_capacity(n);
    for i in 0..n {
        if i + 1 < n && (i + 1) % 3 == 0 {
            s.push('.');
        } else {
            s.push('a');
        }
    }
    s
}

// Valid all-numeric dotted string of exactly n bytes for every n >= 1; no
// segment carries a leading zero.
fn dotted_ones(n: usize) -> String {
    let mut s = String::with_capacity(n);
    for i in 0..n {
        if i + 1 < n && (i + 1) % 3 == 0 {
            s.push('.');
        } else {
            s.push('1');
        }
    }
    s
}

fn zeros(n: usize) -> String {
    "0".repeat(n)
}

fn all_lengths() -> Vec<usize> {
    let mut lengths = Vec::new();
    lengths.extend(VARINT_BOUNDARY_LENGTHS);
    lengths.extend(VARINT_HEADER_BOUNDARY_LENGTHS);
    if !cfg!(miri) {
        lengths.push(16383);
        lengths.push(16384);
    }
    lengths
}

fn check_identifier_basics(pre: &Prerelease, text: &str) {
    assert_eq!(pre.is_empty(), text.is_empty());
    assert_eq!(pre.len(), text.len());
    assert_eq!(pre.as_str(), text);
    assert_eq!(pre, pre);
    assert_eq!(pre, &pre.clone());
    assert_eq!(pre.to_string(), text);
}

fn check_build_basics(build: &BuildMetadata, text: &str) {
    assert_eq!(build.is_empty(), text.is_empty());
    assert_eq!(build.len(), text.len());
    assert_eq!(build.as_str(), text);
    assert_eq!(build, build);
    assert_eq!(build, &build.clone());
    assert_eq!(build.to_string(), text);
}

fn hash_of<T: Hash>(value: &T) -> u64 {
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish()
}

// Symmetric entry points, both sides of the 0/1 and 8/9 boundaries, and the
// varint-header 127/128 (and 16383/16384) boundaries: construct through both
// the dedicated constructors and full Version parsing, then check Clone/Eq/
// Display and that the inline vs heap choice is invisible to callers.
#[test]
fn sso_length_repr_matrix() {
    let families: &[fn(usize) -> String] = &[alpha, ones, mixed, dotted_alpha, dotted_ones];

    for &len in &all_lengths() {
        for family in families {
            let text = family(len);

            let pre = prerelease(&text);
            check_identifier_basics(&pre, &text);

            let build = build_metadata(&text);
            check_build_basics(&build, &text);

            // The same text must reach Identifier from all parsing entrances.
            // Empty identifiers are only valid through the standalone EMPTY
            // values, never as an explicit `-` or `+` segment.
            if len > 0 {
                let whole = format!("1.2.3-{text}+{text}");
                let parsed = version(&whole);
                assert_eq!(parsed.pre, pre, "{whole}");
                assert_eq!(parsed.build, build, "{whole}");
                assert_eq!(parsed.pre.as_str(), text);
                assert_eq!(parsed.build.as_str(), text);

                // Cloning at every length must duplicate (or share inline)
                // the representation and compare equal to the original.
                assert_eq!(parsed.pre.clone(), parsed.pre);
                assert_eq!(parsed.build.clone(), parsed.build);

                // Equal content hashes equal regardless of inline/heap repr.
                assert_eq!(hash_of(&parsed.pre), hash_of(&pre));
                assert_eq!(hash_of(&parsed.build), hash_of(&build));
            }
        }

        // Build metadata additionally admits all-zero segments, including
        // leading zeros that are illegal in pre-release identifiers.
        let zero_text = zeros(len);
        let zero_build = build_metadata(&zero_text);
        check_build_basics(&zero_build, &zero_text);
        if len > 0 {
            let whole = format!("1.2.3+{zero_text}");
            assert_eq!(version(&whole).build, zero_build, "{whole}");
        }
    }
}

// Failure recovery: a heap identifier dropped before its clone must leave the
// clone intact, guarding the Clone/Drop pairing across the 8/9 boundary.
#[test]
fn heap_clone_outlives_original() {
    for &len in &[9usize, 10, 127, 128, 16384] {
        let text = alpha(len);
        let original = prerelease(&text);
        let detached = original.clone();
        drop(original);
        assert_eq!(detached.as_str(), text);
        assert_eq!(detached.len(), len);

        let original_build = build_metadata(&text);
        let detached_build = original_build.clone();
        drop(original_build);
        assert_eq!(detached_build.as_str(), text);
    }
}

// A long string and its short prefix must never compare equal even though
// their first 8 inline-capacity bytes coincide.
#[test]
fn sso_prefix_is_not_equal() {
    for &len in &[9usize, 10, 127, 128] {
        let long = alpha(len);
        let short = alpha(8);
        assert_ne!(prerelease(&long), prerelease(&short));
        assert_ne!(prerelease(&short), prerelease(&long));
        assert_ne!(build_metadata(&long), build_metadata(&short));
    }
}

// THE most dangerous SSO boundary counterexample.
//
// "99999999" (8 digits) is inline; "100000000" (9 digits) is heap. Raw 8-byte
// representation ordering compares ASCII and says '9' > '1', but the SemVer
// numeric rule requires 99_999_999 < 100_000_000. The same pair in build
// metadata must also be ordered numerically while (critically) build metadata
// must leave Version precedence untouched.
#[test]
fn danger_inline_8_vs_heap_9_numeric_direction() {
    let inline = prerelease("99999999");
    let heap = prerelease("100000000");

    assert_eq!(inline.cmp(&heap), Ordering::Less);
    assert_eq!(heap.cmp(&inline), Ordering::Greater);
    assert!(inline < heap);

    let v_inline = version("1.0.0-99999999");
    let v_heap = version("1.0.0-100000000");
    assert!(v_inline < v_heap);

    let b_inline = build_metadata("99999999");
    let b_heap = build_metadata("100000000");
    assert_eq!(b_inline.cmp(&b_heap), Ordering::Less);

    // Build metadata alone differentiates the total order on Version...
    let with_inline = version("1.0.0+99999999");
    let with_heap = version("1.0.0+100000000");
    assert_ne!(with_inline, with_heap);
    assert!(with_inline < with_heap);

    // ...but never SemVer precedence, and never requirement matching.
    assert_eq!(with_inline.cmp_precedence(&with_heap), Ordering::Equal,);
    let requirement = req("^1.0.0");
    assert!(requirement.matches(&with_inline));
    assert!(requirement.matches(&with_heap));
}

// Cross-representation ordering matrix for pre-release identifiers: every
// pair is checked in both directions so an asymmetric Ord cannot slip by.
#[test]
fn prerelease_cross_sso_ord_matrix() {
    // (inline candidate, heap candidate, required ordering of inline vs heap)
    let cases: &[(&str, &str, Ordering)] = &[
        // Numeric on each side: magnitude wins over ASCII on both sides.
        ("99999999", "100000000", Ordering::Less),
        ("8", "10000000", Ordering::Less),
        ("10000000", "10000001", Ordering::Less),
        ("10000001", "10000000", Ordering::Greater),
        // Alphanumeric prefix that straddles the boundary in both directions.
        ("abcdefgh", "abcdefghi", Ordering::Less),
        ("abcdefghi", "abcdefgh", Ordering::Greater),
        // Numeric segment always loses to a non-numeric segment, across the
        // boundary, in either direction.
        ("99999999", "aaaaaaaaa", Ordering::Less),
        ("aaaaaaaa", "999999999", Ordering::Greater),
        ("100000000", "aaaaaaa1", Ordering::Less),
        // Dotted chains whose first differing segment is across the split.
        ("aaa.bbb", "aaa.bbbb", Ordering::Less),
        ("aaa.bbbb", "aaa.bbb", Ordering::Greater),
        ("1.2", "1.10", Ordering::Less),
        // Fewer segments loses when all preceding segments are equal.
        ("aaa.bbb", "aaa.bbb.c", Ordering::Less),
    ];

    for (lhs, rhs, expected) in cases {
        let lhs = prerelease(lhs);
        let rhs = prerelease(rhs);
        assert_eq!(lhs.cmp(&rhs), *expected, "{lhs:?} vs {rhs:?}");
        assert_eq!(
            rhs.cmp(&lhs),
            expected.reverse(),
            "asymmetry in {rhs:?} vs {lhs:?}",
        );
        assert_eq!(lhs.eq(&rhs), *expected == Ordering::Equal);
    }
}

// BuildMetadata has its own total order (including a leading-zero rule), but
// that order is invisible to Version precedence and VersionReq matching.
#[test]
fn build_metadata_own_order_but_ignored_by_precedence() {
    let ordered: &[&str] = &[
        // Cross-boundary numeric ordering, including leading zeros.
        "00000001",  // 8 bytes inline; numeric value 1
        "000000001", // 9 bytes heap; same numeric value, longer original wins
        "99999999",
        "100000000",
        // Cross-boundary ASCII ordering.
        "abcdefgh",
        "abcdefghi",
    ];

    for (i, lhs) in ordered.iter().enumerate() {
        for (j, rhs) in ordered.iter().enumerate() {
            let lhs = build_metadata(lhs);
            let rhs = build_metadata(rhs);
            assert_eq!(
                lhs.cmp(&rhs),
                i.cmp(&j),
                "{lhs:?} vs {rhs:?} expected index {i} vs {j}",
            );
        }
    }

    // Every one of those build strings attaches to versions of identical
    // precedence, and a requirement either matches all or none.
    let requirement = req(">=1.0.0, <2.0.0");
    let baseline = Version::new(1, 5, 0);
    for text in ordered {
        let version = version(&format!("1.5.0+{text}"));
        assert_eq!(version.cmp_precedence(&baseline), Ordering::Equal);
        assert!(requirement.matches(&version));
    }
}

// Independent re-implementation of the SemVer dot-component order, used to
// check the crate's Ord over identifiers generated at every SSO length.
fn reference_segment_cmp(lhs: &str, rhs: &str) -> Ordering {
    let lhs_numeric = lhs.bytes().all(|b| b.is_ascii_digit());
    let rhs_numeric = rhs.bytes().all(|b| b.is_ascii_digit());
    match (lhs_numeric, rhs_numeric) {
        (true, true) => lhs.len().cmp(&rhs.len()).then_with(|| lhs.cmp(rhs)),
        (true, false) => Ordering::Less,
        (false, true) => Ordering::Greater,
        (false, false) => lhs.cmp(rhs),
    }
}

fn reference_prerelease_cmp(lhs: &str, rhs: &str) -> Ordering {
    match (lhs.is_empty(), rhs.is_empty()) {
        (true, true) => Ordering::Equal,
        (true, false) => Ordering::Greater,
        (false, true) => Ordering::Less,
        (false, false) => {
            let mut lhs_parts = lhs.split('.');
            let mut rhs_parts = rhs.split('.');
            loop {
                match (lhs_parts.next(), rhs_parts.next()) {
                    (None, None) => return Ordering::Equal,
                    (None, Some(_)) => return Ordering::Less,
                    (Some(_), None) => return Ordering::Greater,
                    (Some(l), Some(r)) => {
                        let ordering = reference_segment_cmp(l, r);
                        if ordering != Ordering::Equal {
                            return ordering;
                        }
                    }
                }
            }
        }
    }
}

fn reference_build_cmp(lhs: &str, rhs: &str) -> Ordering {
    let mut lhs_parts = lhs.split('.');
    let mut rhs_parts = rhs.split('.');
    loop {
        match (lhs_parts.next(), rhs_parts.next()) {
            (None, None) => return Ordering::Equal,
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
            (Some(l), Some(r)) => {
                let lhs_numeric = l.bytes().all(|b| b.is_ascii_digit());
                let rhs_numeric = r.bytes().all(|b| b.is_ascii_digit());
                let ordering = match (lhs_numeric, rhs_numeric) {
                    (true, true) => {
                        let l_trimmed = l.trim_start_matches('0');
                        let r_trimmed = r.trim_start_matches('0');
                        l_trimmed
                            .len()
                            .cmp(&r_trimmed.len())
                            .then_with(|| l_trimmed.cmp(r_trimmed))
                            .then_with(|| l.len().cmp(&r.len()))
                    }
                    (true, false) => Ordering::Less,
                    (false, true) => Ordering::Greater,
                    (false, false) => l.cmp(r),
                };
                if ordering != Ordering::Equal {
                    return ordering;
                }
            }
        }
    }
}

// Generative total-order / Eq / Hash property over identifiers at every
// length, checked pairwise against the independent reference ordering. The
// matrix is constructed so both operands of each pair are generated, which
// exercises inline-inline, inline-heap, and heap-heap comparisons.
#[test]
fn generative_ord_eq_hash_matches_reference() {
    let lengths = {
        let mut lengths: Vec<usize> = (0..=40).collect();
        lengths.extend(VARINT_HEADER_BOUNDARY_LENGTHS);
        if !cfg!(miri) {
            lengths.push(16383);
            lengths.push(16384);
        }
        lengths
    };

    let mut pre_texts: Vec<String> = Vec::new();
    let mut build_texts: Vec<String> = Vec::new();
    let pre_families: &[fn(usize) -> String] = &[alpha, ones, mixed, dotted_alpha, dotted_ones];
    let build_families: &[fn(usize) -> String] =
        &[alpha, ones, mixed, zeros, dotted_alpha, dotted_ones];

    for &len in &lengths {
        for family in pre_families {
            pre_texts.push(family(len));
        }
        for family in build_families {
            build_texts.push(family(len));
        }
    }

    pre_texts.sort();
    pre_texts.dedup();
    build_texts.sort();
    build_texts.dedup();

    let pres: Vec<Prerelease> = pre_texts.iter().map(|s| prerelease(s)).collect();
    let builds: Vec<BuildMetadata> = build_texts.iter().map(|s| build_metadata(s)).collect();

    for (i, lhs_text) in pre_texts.iter().enumerate() {
        for (j, rhs_text) in pre_texts.iter().enumerate() {
            let expected = reference_prerelease_cmp(lhs_text, rhs_text);
            assert_eq!(
                pres[i].cmp(&pres[j]),
                expected,
                "pre {lhs_text:?} {rhs_text:?}"
            );
            assert_eq!(pres[i].partial_cmp(&pres[j]), Some(expected));
            assert_eq!(pres[i] == pres[j], expected == Ordering::Equal);
            if expected == Ordering::Equal {
                assert_eq!(hash_of(&pres[i]), hash_of(&pres[j]));
            }
        }
    }

    for (i, lhs_text) in build_texts.iter().enumerate() {
        for (j, rhs_text) in build_texts.iter().enumerate() {
            let expected = reference_build_cmp(lhs_text, rhs_text);
            assert_eq!(
                builds[i].cmp(&builds[j]),
                expected,
                "build {lhs_text:?} {rhs_text:?}",
            );
            assert_eq!(builds[i] == builds[j], expected == Ordering::Equal);
            if expected == Ordering::Equal {
                assert_eq!(hash_of(&builds[i]), hash_of(&builds[j]));
            }
        }
    }
}

// parse -> display -> parse must be identity at every SSO/varint boundary and
// through both Version and the standalone Prerelease/BuildMetadata entries.
#[test]
fn parse_display_parse_version_matrix() {
    let pre_families: &[fn(usize) -> String] = &[alpha, ones, mixed, dotted_alpha, dotted_ones];
    let build_families: &[fn(usize) -> String] =
        &[alpha, ones, mixed, zeros, dotted_alpha, dotted_ones];

    for &len in &all_lengths() {
        for family in pre_families {
            let pre_text = family(len);
            let direct = prerelease(&pre_text);
            assert_eq!(prerelease(&direct.to_string()), direct);

            if len > 0 {
                let whole = format!("1.2.3-{pre_text}");
                let parsed = version(&whole);
                assert_eq!(parsed.pre, direct);
                assert_eq!(parsed.to_string(), whole);
                assert_eq!(version(&parsed.to_string()), parsed);
            }
        }

        for family in build_families {
            let build_text = family(len);
            let direct = build_metadata(&build_text);
            assert_eq!(build_metadata(&direct.to_string()), direct);

            if len > 0 {
                let whole = format!("1.2.3+{build_text}");
                let parsed = version(&whole);
                assert_eq!(parsed.build, direct);
                assert_eq!(parsed.to_string(), whole);
                assert_eq!(version(&parsed.to_string()), parsed);

                // Leading zeros survive the round trip in build metadata.
                let with_pre = format!("1.2.3-alpha+{build_text}");
                let parsed = version(&with_pre);
                assert_eq!(parsed.to_string(), with_pre);
                assert_eq!(version(&parsed.to_string()), parsed);
            }
        }
    }
}

// The Display width/fill padding path computes its length independently; at
// the inline/heap boundary the reported length must still match the bytes
// written and the padded output must re-parse after trimming.
#[test]
fn display_width_around_sso_boundary() {
    for &len in &[7usize, 8, 9, 10, 127, 128] {
        let text = format!("1.0.0-{}", alpha(len));
        let parsed = version(&text);
        let width = len + 10;
        let padded = format!("{parsed:>width$}");
        assert_eq!(padded.len(), width);
        assert!(padded.trim_start() == text);

        let filled = format!("{parsed:-^width$}");
        assert_eq!(filled.len(), width);
        assert_eq!(filled.trim_matches('-'), text);
    }
}

// VersionReq parse/display round trip, including comparators whose pre-release
// straddles the SSO boundary. Build metadata is accepted by the parser but
// intentionally discarded (it can never influence matching).
#[test]
fn version_req_display_round_trip_and_dropped_build() {
    let cases = &[
        "*",
        ">=1.5.0, <2.0.0",
        "=1.5.0-abcdefgh",
        "=1.5.0-abcdefghi",
        "^1.5.0-aaa.bbb",
        "~1.5.9",
        "1.*",
    ];

    for text in cases {
        let requirement = req(text);
        assert_eq!(requirement.to_string(), *text);
        assert_eq!(req(&requirement.to_string()), requirement);
    }

    let with_build = req("=1.5.0+abcdefghi");
    let without_build = req("=1.5.0");
    assert_eq!(with_build, without_build);
    assert_eq!(with_build.to_string(), "=1.5.0");
}

// Fixed versions indexed 0..=9. Indices 0..2 are the prerelease admission
// probes (with and without build metadata), the rest are ordinary releases
// around the 1.5.0/2.0.0 boundary. Index 2 carries an 8-byte inline build and
// index 5 a 9-byte heap build, so build invariance straddles the SSO split.
fn truth_versions() -> Vec<Version> {
    vec![
        version("1.5.0-alpha"),
        version("1.5.0-alpha+aaaaaaaa"),
        version("1.5.0-alpha+aaaaaaaaa"),
        version("1.5.0"),
        version("1.5.0+aaaaaaaa"),
        version("1.5.0+aaaaaaaaa"),
        version("1.5.1"),
        version("1.6.0"),
        version("2.0.0"),
        version("1.4.9"),
    ]
}

// Full conjunction truth table. Each row is (requirement text, bitmask of the
// matching version indices from truth_versions).
#[test]
fn version_req_matches_truth_table() {
    let versions = truth_versions();
    let cases: &[(&str, &[usize])] = &[
        ("*", &[3, 4, 5, 6, 7, 8, 9]),
        ("1.5.0", &[3, 4, 5, 6, 7]),
        ("=1.5.0", &[3, 4, 5]),
        ("~1.5.0", &[3, 4, 5, 6]),
        (">=1.5.0, <2.0.0", &[3, 4, 5, 6, 7]),
        // Without an explicit prerelease comparator, prerelease versions are
        // not admitted even though the numeric range would contain them.
        (">=1.5.0-alpha, <2.0.0", &[0, 1, 2, 3, 4, 5, 6, 7]),
        ("^1.5.0-alpha", &[0, 1, 2, 3, 4, 5, 6, 7]),
        ("=1.5.0-alpha", &[0, 1, 2]),
        ("^1.5", &[3, 4, 5, 6, 7]),
        ("~1", &[3, 4, 5, 6, 7, 9]),
        ("1.*", &[3, 4, 5, 6, 7, 9]),
        ("=1.5", &[3, 4, 5, 6]),
        // The "-0" prerelease lives on a 2.0.0 comparator, not on a 1.5.0
        // comparator, so it cannot admit 1.5.0-alpha: admission requires a
        // nonempty pre on a comparator with the candidate's exact triple.
        (">=1.5.0, <2.0.0-0", &[3, 4, 5, 6, 7]),
        // ...whereas a -0 bound at the same triple does admit it.
        (">=1.5.0-0, <2.0.0", &[0, 1, 2, 3, 4, 5, 6, 7]),
    ];

    for (text, expected_indices) in cases {
        let requirement = req(text);
        for (index, candidate) in versions.iter().enumerate() {
            let expected = expected_indices.contains(&index);
            assert_eq!(
                requirement.matches(candidate),
                expected,
                "{text:?} vs {candidate} (index {index})",
            );
        }
    }
}

// Symmetric evaluation entry: Comparator::matches applies the same prerelease
// admission rule on its own, unlike a bare numeric comparison.
#[test]
fn comparator_matches_symmetry_truth_table() {
    let versions = truth_versions();
    let index_of = |text: &str| versions.iter().position(|v| *v == version(text)).unwrap();

    let cases: &[(&str, &[usize])] = &[
        ("^1.5.0", &[3, 4, 5, 6, 7]),
        ("=1.5.0", &[3, 4, 5]),
        ("=1.5.0-alpha", &[0, 1, 2]),
        ("^1.5.0-alpha", &[0, 1, 2, 3, 4, 5, 6, 7]),
    ];

    for (text, expected_indices) in cases {
        let comparator = comparator(text);
        for (index, candidate) in versions.iter().enumerate() {
            let expected = expected_indices.contains(&index);
            assert_eq!(
                comparator.matches(candidate),
                expected,
                "comparator {text:?} vs {candidate} (index {index})",
            );
        }

        // A requirement containing only this comparator agrees with it on
        // every prerelease-bearing and ordinary candidate.
        let singleton = req(text);
        for candidate in &versions {
            assert_eq!(singleton.matches(candidate), comparator.matches(candidate));
        }
    }

    // Build metadata on either side never changes the boolean.
    let comparator = comparator("=1.5.0");
    assert!(comparator.matches(&version("1.5.0+aaaaaaaa")));
    assert!(comparator.matches(&version("1.5.0+aaaaaaaaa")));
    assert!(!comparator.matches(&versions[index_of("1.5.1")]));
}

// Prerelease admission is stricter than the numeric range: a prerelease
// candidate is admitted only by a comparator whose prerelease is nonempty AND
// whose major.minor.patch is exactly the candidate's triple. In particular a
// bare-minor comparator (1.5) cannot admit 1.5.0-alpha, and a pre-bearing
// comparator at an adjacent patch cannot admit it either.
#[test]
fn prerelease_admission_requires_exact_triple() {
    let candidate = version("1.5.0-alpha");

    let admitted_req = &["=1.5.0-alpha", "^1.5.0-alpha", ">=1.5.0-alpha, <2.0.0"];
    for text in admitted_req {
        assert!(
            req(text).matches(&candidate),
            "{text} must admit {candidate}"
        );
    }

    let admitted_comparator = &[
        "=1.5.0-alpha",
        "^1.5.0-alpha",
        ">=1.5.0-alpha",
        "~1.5.0-alpha",
    ];
    for text in admitted_comparator {
        assert!(
            comparator(text).matches(&candidate),
            "{text} must admit {candidate}"
        );
    }

    let rejected = &[
        // Numerically in range, but no comparator carries a prerelease.
        ">=1.5.0, <2.0.0",
        "^1.5",
        "~1.5",
        "1.*",
        "*",
        // Carries a prerelease, but on a comparator at an adjacent patch or
        // with a wildcard patch, so the triple does not line up.
        ">=1.5.1-alpha, <2.0.0",
        ">=1.4.0-alpha, <2.0.0",
        // A prerelease comparator at a different triple combined with an
        // otherwise-satisfying exact numeric comparator still cannot admit.
        "=1.5.0, >=2.0.0-alpha",
    ];
    for text in rejected {
        assert!(
            !req(text).matches(&candidate),
            "{text} must reject {candidate}"
        );
    }

    // Build metadata on the candidate changes nothing about admission.
    for build in ["", "+aaaaaaaa", "+aaaaaaaaa"] {
        let with_build = version(&format!("1.5.0-alpha{build}"));
        assert!(req("=1.5.0-alpha").matches(&with_build));
        assert!(!req(">=1.5.0, <2.0.0").matches(&with_build));
    }

    // The sharp direction: a prerelease candidate at a HIGHER patch than the
    // pre-bearing comparator passes the numeric comparison but must still be
    // denied admission, because the comparator's triple is not identical.
    // Checked through both the conjunction entry and the standalone
    // Comparator entry, for every op whose numeric test succeeds.
    let higher = version("1.5.2-alpha");
    let numerically_satisfied = &[
        (">=1.5.1-alpha", true),
        ("^1.5.1-alpha", true),
        ("~1.5.1-alpha", true),
        ("=1.5.1-alpha", false), // exact fails numerically too
    ];
    for (text, numerically) in numerically_satisfied {
        let standalone = comparator(text);
        assert!(
            !standalone.matches(&higher),
            "standalone {text} must not admit {higher} despite numeric={numerically}",
        );
        let conjunction = req(&format!("{text}, <2.0.0"));
        assert!(
            !conjunction.matches(&higher),
            "conjunction {text}, <2.0.0 must not admit {higher}",
        );
    }

    // The same comparator DOES admit a prerelease at its own triple, proving
    // the denial is specifically the exact-triple requirement.
    assert!(comparator(">=1.5.1-alpha").matches(&version("1.5.1-alpha")));
    assert!(!comparator(">=1.5.1-alpha").matches(&version("1.5.2-alpha")));
}

// Versions differing only in build metadata are precedence-equal but still
// have a strict total order driven by BuildMetadata's own rules; a stable sort
// and Hash respect each of the two notions separately.
#[test]
fn build_total_order_without_precedence() {
    let no_build = version("1.5.0");
    let inline_zero = version("1.5.0+00000001"); // 8 bytes
    let heap_zero = version("1.5.0+000000001"); // 9 bytes

    assert_eq!(no_build.cmp_precedence(&inline_zero), Ordering::Equal);
    assert_eq!(inline_zero.cmp_precedence(&heap_zero), Ordering::Equal);

    assert!(no_build < inline_zero);
    assert!(inline_zero < heap_zero);
    assert!(no_build < heap_zero);

    // Hash (and Eq) include build, so these are distinguishable values.
    assert_ne!(no_build, inline_zero);
    assert_ne!(inline_zero, heap_zero);
    assert_ne!(hash_of(&inline_zero), hash_of(&heap_zero));

    // Stable total-order sort keeps precedence groups contiguous and ordered.
    let mut versions = [
        heap_zero.clone(),
        version("1.4.0+zzz"),
        no_build.clone(),
        inline_zero.clone(),
        version("1.5.0-alpha+abcdefghi"),
    ];
    versions.sort();
    let order: Vec<String> = versions.iter().map(ToString::to_string).collect();
    assert_eq!(
        order,
        vec![
            "1.4.0+zzz",
            "1.5.0-alpha+abcdefghi",
            "1.5.0",
            "1.5.0+00000001",
            "1.5.0+000000001",
        ],
    );
}

// Leading-zero boundary matrix across every position. The mutation of any
// single length predicate (`segment_len > 1`, `starts_with('0')`, or the
// pre-vs-build asymmetry) must make one of these fail.
#[test]
fn leading_zero_matrix_with_diagnostics() {
    // A single leading zero is the valid integer zero.
    for text in ["0.0.0", "1.0.0-0", "1.0.0+0", "1.0.0-0+00"] {
        assert!(Version::parse(text).is_ok(), "{text} must parse");
    }

    let version_cases: &[(&str, &str)] = &[
        ("01.0.0", "invalid leading zero in major version number"),
        ("1.01.0", "invalid leading zero in minor version number"),
        ("1.0.01", "invalid leading zero in patch version number"),
        ("1.0.0-01", "invalid leading zero in pre-release identifier"),
        (
            "1.0.0-1.01",
            "invalid leading zero in pre-release identifier",
        ),
        (
            "1.0.0-01.1",
            "invalid leading zero in pre-release identifier",
        ),
        // 8-vs-9 byte pre-release numeric segments around the SSO boundary.
        (
            "1.0.0-00000001",
            "invalid leading zero in pre-release identifier",
        ),
        (
            "1.0.0-000000001",
            "invalid leading zero in pre-release identifier",
        ),
    ];
    for (text, message) in version_cases {
        assert_to_string(version_err(text), message);
    }

    // The symmetric standalone entry points keep the same position context.
    assert_to_string(
        prerelease_err("1.01"),
        "invalid leading zero in pre-release identifier",
    );

    // Build metadata is the deliberate asymmetry: every zero-padded length is
    // legal, on both sides of the SSO split.
    for text in ["00", "001", "00000001", "000000001", "1.0.00000000"] {
        assert!(BuildMetadata::new(text).is_ok(), "build {text}");
        assert!(Version::parse(&format!("1.0.0+{text}")).is_ok());
    }
}

// Integer overflow boundaries for numeric components and for pre-release
// numeric segments that exceed u64 but remain valid ordered strings.
#[test]
fn overflow_and_oversized_numeric_segment() {
    let max = u64::MAX.to_string();
    let over = format!("{max}0");

    assert_eq!(version(&format!("{max}.0.0")).major, u64::MAX,);
    assert_to_string(
        version_err(&format!("{over}.0.0")),
        "value of major version number exceeds u64::MAX",
    );
    assert_to_string(
        version_err(&format!("0.{over}.0")),
        "value of minor version number exceeds u64::MAX",
    );
    assert_to_string(
        version_err(&format!("0.0.{over}")),
        "value of patch version number exceeds u64::MAX",
    );

    // A 19-digit prerelease segment fits u64; a 20-digit one does not, yet it
    // is a legal identifier compared numerically as a string of digits.
    let nineteen = "9".repeat(19);
    let twenty = "9".repeat(20);
    let shorter = version(&format!("1.0.0-{nineteen}"));
    let longer = version(&format!("1.0.0-{twenty}"));
    assert!(shorter < longer);
    assert_eq!(shorter.cmp_precedence(&longer), Ordering::Less);
}

// Empty-segment and illegal-character failures carry position context through
// both Version and the symmetric standalone entries, at SSO-adjacent offsets.
#[test]
fn empty_and_illegal_segment_diagnostics() {
    assert_to_string(
        version_err("1.0.0-"),
        "empty identifier segment in pre-release identifier",
    );
    assert_to_string(
        version_err("1.0.0-alpha."),
        "empty identifier segment in pre-release identifier",
    );
    assert_to_string(
        version_err("1.0.0+"),
        "empty identifier segment in build metadata",
    );
    assert_to_string(
        version_err("1.0.0+abc."),
        "empty identifier segment in build metadata",
    );
    assert_to_string(
        version_err("1.0.0-alpha_1"),
        "unexpected character '_' after pre-release identifier",
    );
    assert_to_string(
        prerelease_err("alpha_1"),
        "unexpected character in pre-release identifier",
    );
    let build_err = BuildMetadata::new("alpha_1").unwrap_err();
    assert_to_string(build_err, "unexpected character in build metadata");
}

// Recovery: consuming one parse error must not poison subsequent parsing, and
// a single malformed comparator fails the whole conjunction without leaking.
#[test]
fn parse_failure_recovery() {
    for bad in ["1.0.0-01", "01.0.0", "1.0.0+", ">=1.0.0, @2.0.0"] {
        assert!(VersionReq::parse(bad).is_err(), "{bad}");
        assert!(Version::parse("1.5.0-abcdefghi+aaaaaaaaa").is_ok());
        assert!(VersionReq::parse("^1.5.0-alpha").is_ok());
    }

    // One bad comparator fails the entire conjunction with position context.
    assert_to_string(
        req_err(">=1.5.0-alpha, ~2.0.0-"),
        "empty identifier segment in pre-release identifier",
    );
}
