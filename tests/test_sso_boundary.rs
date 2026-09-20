#![allow(
    clippy::needless_pass_by_value,
    clippy::too_many_lines,
    clippy::uninlined_format_args
)]

//! Invariants straddling the Identifier 8-byte inline / 9-byte heap boundary.
//!
//! The lengths 0, 1, 8, 9, and 127/128/129 (the 1- vs 2-byte length varint
//! boundary) are exercised from three directions:
//!
//!   * both sides of each boundary ("boundary matrix"),
//!   * symmetric entry points (Version::parse, Prerelease::new,
//!     BuildMetadata::new, Comparator::parse / VersionReq::parse),
//!   * failure recovery (a rejected parse leaves a diagnostic and never
//!     poisons a subsequent successful parse).
//!
//! In addition, generative (property-style) tests build every legal
//! identifier in a small finite alphabet and check total order, hash/eq, and
//! parse-display-parse consistency.

mod util;

use crate::util::*;
use semver::{BuildMetadata, Prerelease, Version};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

// The repr stores <= 8 ASCII bytes inline; 9 bytes is the shortest value that
// forces a heap allocation with a 1-byte length varint.
const SSO: usize = 8;

// Lengths immediately on either side of the inline/heap seam.
const SEAM_LENGTHS: [usize; 6] = [0, 1, 2, SSO - 1, SSO, SSO + 1];

// Lengths around the 127/128 1-byte/2-byte varint seam. Strings this long are
// slow under miri (and the allocation itself is what is being exercised), so
// they are skipped there, matching the cutoff used by test_identifier::test_new.
const VARINT_LENGTHS: [usize; 5] = [126, 127, 128, 129, 200];

fn tested_lengths() -> Vec<usize> {
    let mut lengths = SEAM_LENGTHS.to_vec();
    if !cfg!(miri) {
        lengths.extend(VARINT_LENGTHS);
    }
    lengths
}

fn hash_of(value: impl Hash) -> u64 {
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish()
}

// All-numeric identifier with no leading zero: legal as both prerelease and
// build metadata. Used to compare values whose length crosses the 8/9 seam.
fn numeric_no_zero(len: usize) -> String {
    let mut string = String::with_capacity(len.max(1));
    if len > 0 {
        string.push('1');
        string.extend(std::iter::repeat('0').take(len - 1));
    }
    string
}

// All-numeric identifier that *is* a leading zero at len >= 2. Legal only in
// build metadata, never as a prerelease component or numeric version field.
fn numeric_leading_zero(len: usize) -> String {
    "0".repeat(len)
}

fn alpha(len: usize) -> String {
    "a".repeat(len)
}

fn roundtrip_text(pre: &str, build: &str) -> String {
    let mut text = String::from("1.2.3");
    if !pre.is_empty() {
        text.push('-');
        text.push_str(pre);
    }
    if !build.is_empty() {
        text.push('+');
        text.push_str(build);
    }
    text
}

// A failed parse must carry enough context to diagnose what was rejected, and
// must not interfere with the next parse. Both halves are checked here because
// the identifier parser consumes its input by slicing, never by mutation.
fn assert_recovery(failing: &str, then_ok: &str, then_expected: &str) {
    let error = Version::parse(failing).expect_err(failing);
    let message = error.to_string();
    assert!(
        message.contains("pre-release") || message.contains("build metadata"),
        "error {message:?} does not identify the identifier position",
    );
    let recovered = Version::parse(then_ok)
        .unwrap_or_else(|err| panic!("recovery parse {then_ok:?} failed: {err}"));
    assert_eq!(recovered.to_string(), then_expected);
}

#[test]
fn sso_boundary_length_matrix() {
    // Length 0, 1, 8, 9, ... each roundtrip through both wrapper types and
    // report the same length/as_str whether stored inline or on the heap.
    for len in tested_lengths() {
        for text in [numeric_no_zero(len), alpha(len)] {
            let pre = prerelease(&text);
            assert_eq!(pre.len(), text.len(), "pre len for {text:?}");
            assert_eq!(pre.as_str(), text, "pre as_str for {text:?}");
            assert_eq!(pre.is_empty(), text.is_empty());

            let build = build_metadata(&text);
            assert_eq!(build.len(), text.len(), "build len for {text:?}");
            assert_eq!(build.as_str(), text, "build as_str for {text:?}");
            assert_eq!(build.is_empty(), text.is_empty());
        }
    }

    // The empty sentinel (-1i64 repr) is reachable through both constructors.
    assert!(Prerelease::new("").unwrap().is_empty());
    assert!(BuildMetadata::new("").unwrap().is_empty());
}

#[test]
fn sso_boundary_clone_is_independent() {
    for len in tested_lengths() {
        let text = alpha(len);
        let original = prerelease(&text);
        let cloned = original.clone();
        assert_eq!(original, cloned);
        assert_eq!(original.as_str(), cloned.as_str());
        // Dropping the clone first must not double-free or corrupt the
        // original heap allocation (9+ byte values live on the heap).
        drop(cloned);
        assert_eq!(original.as_str(), text);
        drop(original);

        // Repeated heap alloc/dealloc churn across the seam must keep
        // producing independent, intact identifiers.
        for _ in 0..16 {
            let short = build_metadata(&alpha(SSO));
            let long = build_metadata(&alpha(SSO + 1));
            assert_eq!(short.as_str(), &alpha(SSO));
            assert_eq!(long.as_str(), &alpha(SSO + 1));
        }
    }
}

#[test]
fn sso_boundary_numeric_ord_crosses_seam() {
    // The single most dangerous cross-seam case: 9 ASCII bytes "999999999"
    // compare numerically as 999999999 < 1000000000, even though ASCII order
    // (and raw byte order of the two reprs) puts the longer 9-digit value
    // first. One operand is inline, the other heap allocated.
    let short_pre = prerelease("99999999");
    let long_pre = prerelease("999999999");
    let ten_digits = prerelease("1000000000");
    assert!(short_pre < long_pre, "99,999,999 < 999,999,999");
    assert!(long_pre < ten_digits, "999,999,999 < 1,000,000,000 across heap/heap");

    // Generated at every seam-adjacent length: compare by numeric value, not
    // by storage representation or byte length.
    for &len in &tested_lengths() {
        if len < 2 {
            continue;
        }
        let smaller = prerelease(&numeric_no_zero(len));
        let bigger = prerelease(&numeric_no_zero(len + 1));
        assert!(
            smaller < bigger,
            "numeric prerelease {smaller:?} should be < {bigger:?}",
        );
        assert_eq!(smaller, smaller.clone());

        // Round trip the value through another constructor: same content must
        // remain equal whether it lands inline or on the heap.
        let again = Prerelease::new(smaller.as_str()).unwrap();
        assert_eq!(smaller, again);
    }

    // Numeric < alphanumeric regardless of which side of the seam each lives.
    assert!(prerelease("999999999") < prerelease("a"));
    assert!(prerelease("1") < prerelease("aaaaaaaaa"));
    assert!(prerelease("aaaaaaaaa") < prerelease("b"));

    // Prefix rule holds across the seam, and for dot-separated components.
    assert!(prerelease("aaaaaaaa") < prerelease("aaaaaaaaa"));
    assert!(prerelease("a.99999999") < prerelease("a.999999999"));
    assert!(prerelease("999999999.1") > prerelease("999999999"));

    // Empty (release) is greater than every prerelease, across the seam.
    for len in tested_lengths().into_iter().filter(|&n| n > 0) {
        assert!(prerelease(&alpha(len)) < Prerelease::EMPTY);
        assert!(Prerelease::EMPTY > prerelease(&alpha(len)));
        assert!(prerelease(&numeric_no_zero(len)) < Prerelease::EMPTY);
    }
}

#[test]
fn sso_boundary_build_metadata_leading_zero_ord() {
    // Build metadata permits leading zeros (prerelease does not), and orders
    // numeric components 0 < 00 < 1 < 01 < 001 < 2 ... . Exercise values whose
    // raw bytes land on opposite sides of the inline/heap boundary.
    let ordered: [&str; 8] = ["0", "00", "1", "01", "001", "2", "09", "009"];
    for (i, left) in ordered.iter().enumerate() {
        for right in &ordered[i + 1..] {
            assert!(
                build_metadata(left) < build_metadata(right),
                "build {left:?} should be < {right:?}",
            );
        }
    }

    // Same numeric value, different zero padding, straddling the seam.
    assert!(build_metadata("00000001") < build_metadata("000000001"));

    // Numeric component < alphanumeric across the seam.
    assert!(build_metadata("999999999") < build_metadata("a"));
    // Dot-separated ordering across the seam.
    assert!(build_metadata("x.00000008") < build_metadata("x.000000009"));
}

#[test]
fn sso_boundary_hash_matches_eq() {
    // Hash/eq must be driven by the string contents, never by the inline
    // versus heap representation.
    for len in tested_lengths() {
        let text = numeric_no_zero(len);
        let left = prerelease(&text);
        let right = Prerelease::new(left.as_str()).unwrap();
        assert_eq!(left, right);
        assert_eq!(hash_of(&left), hash_of(&right));

        let build_text = alpha(len);
        let build_left = build_metadata(&build_text);
        let build_right = BuildMetadata::new(build_left.as_str()).unwrap();
        assert_eq!(build_left, build_right);
        assert_eq!(hash_of(&build_left), hash_of(&build_right));

        // A Version parsed twice is equal and hash-equal even though its
        // identifier storage is separately allocated.
        let version_text = roundtrip_text(&text, "");
        let parsed_once = version(&version_text);
        let parsed_twice = version(&version_text);
        assert_eq!(parsed_once, parsed_twice);
        assert_eq!(hash_of(&parsed_once), hash_of(&parsed_twice));
    }
}

#[test]
fn generated_identifier_orders_are_total() {
    // Generated corpus covering numeric, alphanumeric, hyphenated and
    // dot-joined components at lengths that cross the 8/9 seam (and,
    // off-miri, the varint seam). Every pair is checked for the three
    // properties of a total order: antisymmetry (a < b iff b > a, and a == b
    // iff both comparisons are equal), totality (exactly one of <, ==, >
    // holds), and transitivity (sorting is consistent with pairwise cmp).
    fn corpus() -> Vec<String> {
        let mut values = vec![
            "1".to_owned(),
            "8".to_owned(),
            "9".to_owned(),
            "10".to_owned(),
            "0a".to_owned(),
            "a".to_owned(),
            "a0".to_owned(),
            "b".to_owned(),
            "beta".to_owned(),
            "1.2".to_owned(),
            "1.10".to_owned(),
            "a.b".to_owned(),
            "a.b.c".to_owned(),
        ];
        for len in tested_lengths().into_iter().filter(|&n| n > 0) {
            values.push(alpha(len));
            values.push(numeric_no_zero(len));
            values.push(format!("{}.{}", alpha(3), alpha(len)));
            values.push(format!("{}.{}", numeric_no_zero(1), numeric_no_zero(len)));
        }
        values.sort();
        values.dedup();
        values
    }

    fn assert_total_order<T, F>(corpus: &[String], label: &str, make: F)
    where
        T: Ord + Clone + std::fmt::Debug,
        F: Fn(&str) -> T,
    {
        let items: Vec<T> = corpus.iter().map(|s| make(s)).collect();

        // Totality + antisymmetry over the full pairwise matrix.
        for i in 0..items.len() {
            for j in 0..items.len() {
                let left = &items[i];
                let right = &items[j];
                let forward = left.cmp(right);
                let backward = right.cmp(left);
                assert_eq!(forward, backward.reverse(), "{label}: antisymmetry {i} {j}");
                if i == j {
                    assert_eq!(forward, std::cmp::Ordering::Equal);
                }
            }
        }

        // Sorting must agree with the pairwise Ord (transitivity).
        let mut indices: Vec<usize> = (0..items.len()).collect();
        indices.sort_by(|&i, &j| items[i].cmp(&items[j]));
        for pair in indices.windows(2) {
            let (i, j) = (pair[0], pair[1]);
            assert!(items[i] <= items[j], "{label}: sort disagrees with cmp");
        }

        // Sorting the same values rebuilt (fresh allocations) gives the same
        // permutation: ordering is independent of heap addresses.
        let mut rebuilt: Vec<T> = corpus.iter().map(|s| make(s)).collect();
        rebuilt.sort();
        for (idx, expected) in rebuilt.iter().enumerate() {
            assert_eq!(*expected, items[indices[idx]], "{label}: unstable order at {idx}");
        }
    }

    let legal_pre = corpus();
    assert_total_order(&legal_pre, "prerelease", |s| prerelease(s));

    // Build metadata additionally admits leading-zero numerics.
    let mut legal_build = legal_pre.clone();
    for len in [2usize, 8, 9, 10, 127, 128] {
        legal_build.push(numeric_leading_zero(len));
    }
    legal_build.sort();
    legal_build.dedup();
    assert_total_order(&legal_build, "build", |s| build_metadata(s));
}

#[test]
fn parse_display_parse_roundtrip_matrix() {
    // Cartesian combination of pre/build lengths around 0, 8, 9 (plus the
    // varint lengths off-miri): every legal version must survive
    // parse -> display -> parse with structurally identical fields.
    let pre_values: Vec<String> = tested_lengths()
        .into_iter()
        .filter(|&len| len != 0)
        .map(numeric_no_zero)
        .collect();
    let build_values: Vec<String> = tested_lengths()
        .into_iter()
        .filter(|&len| len != 0)
        .map(numeric_leading_zero)
        .collect();

    for pre in std::iter::once(String::new()).chain(pre_values.clone()) {
        for build in std::iter::once(String::new()).chain(build_values.clone()) {
            let text = roundtrip_text(&pre, &build);
            let parsed = version(&text);
            assert_eq!(parsed.to_string(), text, "display mismatch for {text}");

            let reparsed = Version::parse(&parsed.to_string())
                .unwrap_or_else(|err| panic!("second parse failed for {text}: {err}"));
            assert_eq!(parsed, reparsed, "parse-display-parse mismatch for {text}");
            assert_eq!(reparsed.to_string(), text);

            // Symmetric entry points: the same identifier text parsed via
            // Prerelease::new / BuildMetadata::new must match what the full
            // version parse produced.
            if !pre.is_empty() {
                assert_eq!(parsed.pre, Prerelease::new(&pre).unwrap());
            } else {
                assert!(parsed.pre.is_empty());
            }
            if !build.is_empty() {
                assert_eq!(parsed.build, BuildMetadata::new(&build).unwrap());
            } else {
                assert!(parsed.build.is_empty());
            }
        }
    }

    // u64 extreme values (20-digit max) display without overflow and
    // re-parse identically.
    let max_text = format!("{max}.{max}.{max}", max = u64::MAX);
    let max_version = version(&max_text);
    assert_eq!(max_version.to_string(), max_text);
    assert_eq!(Version::parse(&max_version.to_string()).unwrap(), max_version);
}

#[test]
fn build_metadata_invisible_to_precedence_visible_to_order() {
    // THE most dangerous SemVer/SSO-boundary counterexample: two versions
    // equal in major/minor/patch/pre but carrying build identifiers
    // "99999999" (inline, 8 bytes) and "999999999" (heap, 9 bytes). By
    // numeric value the 8-digit one is smaller than the 9-digit one, which is
    // the opposite of ASCII/raw-bytes order. SemVer precedence must ignore the
    // difference entirely; Identifier/BuildMetadata order and Version's total
    // order must NOT.
    let inline_build = version("1.0.0+99999999");
    let heap_build = version("1.0.0+999999999");

    // SemVer precedence: build metadata does not participate.
    assert_eq!(inline_build.cmp_precedence(&heap_build), std::cmp::Ordering::Equal);
    assert_eq!(heap_build.cmp_precedence(&inline_build), std::cmp::Ordering::Equal);

    // The Identifier ordering itself is numeric and thus sees 99,999,999 <
    // 999,999,999 even though one repr is inline and the other heap.
    assert!(inline_build.build < heap_build.build);

    // Version's total order therefore distinguishes them, in the same
    // direction as BuildMetadata.
    assert!(inline_build < heap_build);
    assert!(heap_build > inline_build);
    assert_ne!(inline_build, heap_build);
    assert_ne!(hash_of(&inline_build), hash_of(&heap_build));

    // Stability under sorting: precedence sort keeps input order; total sort
    // orders by the numeric build value.
    let pair = [heap_build.clone(), inline_build.clone()];
    let mut precedence_sorted = pair.clone();
    precedence_sorted.sort_by(Version::cmp_precedence);
    assert_eq!(
        precedence_sorted.iter().map(|v| v.to_string()).collect::<Vec<_>>(),
        ["1.0.0+999999999", "1.0.0+99999999"],
    );
    let mut total_sorted = pair;
    total_sorted.sort();
    assert_eq!(
        total_sorted.iter().map(|v| v.to_string()).collect::<Vec<_>>(),
        ["1.0.0+99999999", "1.0.0+999999999"],
    );

    // Same shape through the 127/128 varint seam off-miri: precedence equal,
    // numeric Identifier order intact.
    if !cfg!(miri) {
        let shorter = version(&format!("1.0.0+{}", "1".repeat(127)));
        let longer = version(&format!("1.0.0+{}", "1".repeat(128)));
        assert_eq!(shorter.cmp_precedence(&longer), std::cmp::Ordering::Equal);
        assert!(shorter.build < longer.build);
        assert!(shorter < longer);
    }
}

#[test]
fn leading_zero_asymmetry_at_pre_build_seam() {
    // Lengths exactly 8 and 9: leading zeros are rejected in prerelease
    // (every symmetric entry point) but accepted and preserved in build
    // metadata.
    for len in [SSO, SSO + 1] {
        let zero_text = numeric_leading_zero(len);

        let pre_error = prerelease_err(&zero_text);
        assert_to_string(pre_error, "invalid leading zero in pre-release identifier");

        let inline_error = version_err(&format!("1.0.0-{zero_text}"));
        assert_to_string(inline_error, "invalid leading zero in pre-release identifier");

        let req_error = req_err(&format!(">=1.0.0-{zero_text}"));
        assert_to_string(req_error, "invalid leading zero in pre-release identifier");

        let cmp_error = comparator_err(&format!("~1.0.0-{zero_text}"));
        assert_to_string(cmp_error, "invalid leading zero in pre-release identifier");

        // Same byte content is legal as build metadata through every entry.
        assert_eq!(build_metadata(&zero_text).as_str(), zero_text);
        let as_build = version(&format!("1.0.0+{zero_text}"));
        assert_eq!(as_build.to_string(), format!("1.0.0+{zero_text}"));

        // A multi-segment prerelease is rejected if ANY segment has a leading
        // zero, including a segment positioned past the 8-byte seam.
        let multi = format!("a.99999999.{zero_text}");
        assert_to_string(
            prerelease_err(&multi),
            "invalid leading zero in pre-release identifier",
        );
    }

    // A lone "0" is a valid numeric prerelease component; only multi-digit
    // leading zeros are forbidden.
    assert_eq!(prerelease("0").as_str(), "0");
    assert_eq!(version("1.0.0-0.0").to_string(), "1.0.0-0.0");
}

#[test]
fn overflow_and_recovery_keep_diagnostic_context() {
    // Integer overflow at each numeric position, one digit past u64::MAX.
    let too_big = "18446744073709551616";
    assert_to_string(
        version_err(&format!("{too_big}.0.0")),
        "value of major version number exceeds u64::MAX",
    );
    assert_to_string(
        version_err(&format!("0.{too_big}.0")),
        "value of minor version number exceeds u64::MAX",
    );
    assert_to_string(
        version_err(&format!("0.0.{too_big}")),
        "value of patch version number exceeds u64::MAX",
    );
    assert_to_string(
        req_err(&format!(">={too_big}.0.0")),
        "value of major version number exceeds u64::MAX",
    );

    // Leading-zero detection wins over the overflow accumulator.
    assert_to_string(
        version_err("000000000000000000000.0.0"),
        "invalid leading zero in major version number",
    );

    // Failure recovery across every identifier position and both seam sides:
    // a rejected parse must report position context, and the next parse works.
    for len in [SSO, SSO + 1] {
        assert_recovery(
            &format!("1.0.0-{}.", alpha(len)),
            &format!("1.0.0-{}", alpha(len)),
            &format!("1.0.0-{}", alpha(len)),
        );
        assert_recovery(
            &format!("1.0.0+{}.", alpha(len)),
            &format!("1.0.0+{}", alpha(len)),
            &format!("1.0.0+{}", alpha(len)),
        );
        assert_recovery(
            &format!("1.0.0-{}\0", alpha(len)),
            &format!("1.0.0-{}", alpha(len)),
            &format!("1.0.0-{}", alpha(len)),
        );
        assert_recovery(
            "1.0.0-",
            "1.0.0-aaaaaaaaa",
            "1.0.0-aaaaaaaaa",
        );
    }

    // Constructors reject illegal characters on both inline and heap paths
    // with the same kind of diagnostic.
    assert_to_string(
        prerelease_err(&format!("{}_", alpha(SSO))),
        "unexpected character in pre-release identifier",
    );
    assert_to_string(
        prerelease_err(&format!("{}_", alpha(SSO + 1))),
        "unexpected character in pre-release identifier",
    );
}

#[test]
fn prerelease_admission_truth_table_across_seam() {
    // Pre-release admission rule: a pre-release version only satisfies a req
    // if some comparator names the exact same major.minor.patch AND carries a
    // non-empty prerelease of its own. The rule must not depend on whether the
    // prerelease string is stored inline (8) or on the heap (9).
    let eight = "1.0.0-aaaaaaaa";
    let nine = "1.0.0-aaaaaaaaa";
    let other_mmp = "1.0.1-aaaaaaaa";
    let other_major = "2.0.0-aaaaaaaa";
    let release = "1.0.0";

    // STAR / wildcard never admit pre-releases.
    let star = req("*");
    for pre in [eight, nine, other_mmp, other_major] {
        assert!(!star.matches(&version(pre)), "* must not match {pre}");
    }
    assert!(star.matches(&version(release)));

    // Caret req with explicit prerelease: admits that prerelease, later
    // prereleases at the same mmp, and releases; not prereleases at other mmp.
    let caret_eight = req(&format!("^{eight}"));
    assert!(caret_eight.matches(&version(eight)));
    assert!(caret_eight.matches(&version(nine)));
    assert!(caret_eight.matches(&version("1.0.0-aaaaaaab")));
    assert!(caret_eight.matches(&version(release)));
    assert!(caret_eight.matches(&version("1.2.3")));
    assert!(!caret_eight.matches(&version("1.0.0-aaaaaaa")));
    assert!(!caret_eight.matches(&version(other_mmp)));
    assert!(!caret_eight.matches(&version(other_major)));

    // Symmetric: req carrying the 9-byte (heap) prerelease.
    let caret_nine = req(&format!("^{nine}"));
    assert!(caret_nine.matches(&version(nine)));
    assert!(!caret_nine.matches(&version(eight)));
    assert!(caret_nine.matches(&version("1.0.0-aaaaaaaaaa")));

    // Exact comparator with prerelease matches only that exact pre, but is
    // blind to build metadata (see next test for the full matrix).
    let exact = req(&format!("={nine}"));
    assert!(exact.matches(&version(nine)));
    assert!(!exact.matches(&version(eight)));
    assert!(!exact.matches(&version(release)));
    assert!(!exact.matches(&version(other_mmp)));

    // A req without an explicit prerelease never admits prereleases, even
    // when the comparator's range otherwise contains them.
    for req_text in [">=1.0.0", "^1.0.0", "~1.0.0", "1.0.0", ">=1.0.0, <2.0.0"] {
        let parsed = req(req_text);
        assert!(!parsed.matches(&version(eight)), "{req_text} matched {eight}");
        assert!(!parsed.matches(&version(nine)), "{req_text} matched {nine}");
        assert!(parsed.matches(&version(release)), "{req_text} rejected {release}");
    }

    // With an explicit prerelease on one comparator of a multi-comparator req,
    // admission turns on even for the range: both 8- and 9-byte prereleases at
    // 1.0.0 are admitted; prereleases at other mmp still are not. (The floor
    // "a" sorts below both aaaaaaaa and aaaaaaaaa; "alpha" would not, since
    // "aaa" < "alp" in ASCII.)
    let ranged = req(">=1.0.0-a, <2.0.0");
    assert!(ranged.matches(&version(eight)));
    assert!(ranged.matches(&version(nine)));
    assert!(!ranged.matches(&version(other_mmp)));
    assert!(!ranged.matches(&version(other_major)));
    assert!(ranged.matches(&version("1.5.0")));

    // Numeric prerelease ordering at the seam drives caret boundary behavior.
    let numeric = req("^1.0.0-99999999");
    assert!(numeric.matches(&version("1.0.0-99999999")));
    assert!(numeric.matches(&version("1.0.0-999999999")));
    assert!(numeric.matches(&version("1.0.0-1000000000")));
    assert!(!numeric.matches(&version("1.0.0-9999999")));
}

#[test]
fn build_metadata_ignored_by_matching_matrix() {
    // Whether the prerelease/build text is 8 or 9 bytes, build metadata on
    // either the requirement side or the version side never changes a match.
    let builds = ["99999999", "999999999", "000000009", "aaaaaaaa", "aaaaaaaaa"];
    let req_texts = [
        "*",
        "^1.0.0",
        "=1.0.0-aaaaaaaa",
        "=1.0.0-aaaaaaaaa",
        ">=1.0.0-alpha, <2.0.0",
        "~1.0.0-99999999",
    ];

    for req_text in req_texts {
        // Build metadata on a comparator parses but is discarded from eval;
        // display also omits it (build is not part of Comparator's repr). The
        // wildcard req has no comparator at all, so build metadata cannot even
        // be syntactically attached to it (that rejection is asserted below).
        let plain = req(req_text);

        if req_text != "*" {
            for req_build in builds {
                let decorated_text = format!("{req_text}+{req_build}");
                let decorated = req(&decorated_text);
                assert_eq!(
                    decorated.comparators, plain.comparators,
                    "build metadata {req_build} must be discarded from {decorated_text}",
                );
            }
        } else {
            assert_to_string(
                req_err("*+999999999"),
                "unexpected character after wildcard in version req",
            );
        }

        for ver_pre in ["", "-aaaaaaaa", "-aaaaaaaaa"] {
            for ver_build in builds {
                let text = format!("1.0.0{ver_pre}+{ver_build}");
                let without_build_text = format!("1.0.0{ver_pre}");
                let candidate = version(&text);
                assert_eq!(
                    plain.matches(&candidate),
                    plain.matches(&version(&without_build_text)),
                    "build {ver_build} changed matching for {text} against {req_text}",
                );
            }
        }
    }
}

#[test]
fn req_parse_display_preserves_matching_across_seam() {
    // parse -> display -> parse must preserve both text and the matching
    // truth table when prereleases sit on each side of the 8/9 seam.
    let cases = [
        "^1.0.0-aaaaaaaa",
        "=1.0.0-aaaaaaaaa",
        ">=1.0.0-alpha, <2.0.0",
        "~1.0.0-999999999",
        "*",
    ];

    let probed = [
        "1.0.0-aaaaaaaa",
        "1.0.0-aaaaaaaaa",
        "1.0.0-999999999+zzzzzzzz",
        "1.0.0-999999999+zzzzzzzzz",
        "1.0.0",
        "1.0.1-aaaaaaaa",
        "2.0.0",
    ];

    for case in cases {
        let original = req(case);
        let displayed = original.to_string();
        let reparsed = req(&displayed);
        assert_eq!(original, reparsed, "req changed on display roundtrip: {case}");
        for candidate_text in probed {
            let candidate = version(candidate_text);
            assert_eq!(
                original.matches(&candidate),
                reparsed.matches(&candidate),
                "matching diverged for {case} vs {candidate_text} after {displayed}",
            );
        }
    }
}
