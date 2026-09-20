use hegel::{TestCase, generators as gs};
use preflight::{cache::Cache, document, scanner::Scanner};
use std::collections::HashSet;

#[hegel::test]
fn generated_credentials_are_removed_without_changing_context(tc: TestCase) {
    let length = tc.draw(gs::integers::<usize>().min_value(0).max_value(100));
    let prefix = "λ ".repeat(length);
    let alphabet = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let digits = tc.draw(
        gs::vecs(
            gs::integers::<usize>()
                .min_value(0)
                .max_value(alphabet.len() - 1),
        )
        .min_size(36)
        .max_size(36),
    );
    let token = format!(
        "ghp_{}",
        digits
            .into_iter()
            .map(|i| alphabet[i] as char)
            .collect::<String>()
    );
    let scanner = Scanner::new(HashSet::new()).unwrap();
    let original = format!("{prefix}{token} trailing");
    let (clean, found) = scanner.redact(&original);
    assert!(!found.is_empty());
    assert!(!clean.contains(&token));
    assert!(clean.starts_with(&prefix));
    assert!(clean.ends_with(" trailing"));
    assert_eq!(scanner.redact(&clean).0, clean);
}

#[hegel::test]
fn arbitrary_unicode_redaction_is_total_and_idempotent(tc: TestCase) {
    let text = tc.draw(gs::text());
    let scanner = Scanner::new(HashSet::new()).unwrap();
    let clean = scanner.redact(&text).0;
    assert_eq!(scanner.redact(&clean).0, clean);
}

#[hegel::test]
fn purged_generation_cannot_repopulate(tc: TestCase) {
    let steps = tc.draw(gs::vecs(gs::integers::<u8>().min_value(0).max_value(2)).max_size(30));
    let dir = tempfile::tempdir().unwrap();
    let mut cache = Cache::open(dir.path()).unwrap();
    let mut expected = false;
    let mut generation = cache.generation();
    for step in steps {
        match step {
            0 => {
                cache.purge().unwrap();
                expected = false;
            }
            1 => {
                cache.insert("a", generation).unwrap();
                if generation == cache.generation() {
                    expected = true;
                }
            }
            _ => generation = cache.generation(),
        }
        assert_eq!(cache.contains("a"), expected);
    }
}

#[hegel::test]
fn json_string_roundtrip(tc: TestCase) {
    let text = tc.draw(gs::text());
    let value = serde_json::json!({"input":text,"stream":true});
    assert_eq!(
        document::parse(&serde_json::to_vec(&value).unwrap()).unwrap(),
        value
    );
}

#[test]
fn duplicate_keys_are_rejected() {
    assert!(document::parse(br#"{"input":"safe","input":"hidden"}"#).is_err());
}

#[test]
fn carnet_is_exact() {
    let token = format!("ghp_{}", "aB39".repeat(9));
    let scanner = Scanner::new(HashSet::from([preflight::digest(token.as_bytes())])).unwrap();
    assert!(scanner.scan(&token).is_empty());
    let other = format!("ghp_{}", "zY28".repeat(9));
    assert!(!scanner.scan(&other).is_empty());
}

#[hegel::test]
fn scaled_redaction_bounds_never_shrink_coverage(tc: TestCase) {
    let width = tc.draw(gs::integers::<u32>().min_value(1).max_value(5000));
    let target = tc.draw(gs::integers::<u32>().min_value(1).max_value(10000));
    let start = tc.draw(gs::integers::<u32>().min_value(0).max_value(width));
    let end = tc.draw(gs::integers::<u32>().min_value(start).max_value(width));
    let scaled = preflight::worker::scale_bounds([start, 0, end, 1], [width, 1], [target, 1]);
    assert!(u64::from(scaled[0]) * u64::from(width) <= u64::from(start) * u64::from(target));
    assert!(u64::from(scaled[2]) * u64::from(width) >= u64::from(end) * u64::from(target));
    assert!(scaled[2] <= target);
}

#[hegel::test]
fn scope_purge_preserves_other_scope(tc: TestCase) {
    let reverse = tc.draw(gs::integers::<u8>().min_value(0).max_value(1));
    let a = preflight::digest(b"scope-a");
    let b = preflight::digest(b"scope-b");
    let (purged, retained) = if reverse == 0 { (a, b) } else { (b, a) };
    let temp = tempfile::tempdir().unwrap();
    let mut cache = Cache::open(temp.path()).unwrap();
    let old = cache.generation();
    cache.insert(&format!("{purged}:item"), old).unwrap();
    cache.insert(&format!("{retained}:item"), old).unwrap();
    cache.purge_scope(&purged).unwrap();
    assert!(!cache.contains(&format!("{purged}:item")));
    assert!(cache.contains(&format!("{retained}:item")));
    cache.insert(&format!("{purged}:item"), old).unwrap();
    assert!(!cache.contains(&format!("{purged}:item")));
}

#[hegel::test]
fn rotated_full_page_maps_to_original_extent(tc: TestCase) {
    let width = tc.draw(gs::integers::<u32>().min_value(1).max_value(10000));
    let height = tc.draw(gs::integers::<u32>().min_value(1).max_value(10000));
    let rotation = tc.draw(gs::integers::<u8>().min_value(0).max_value(3));
    let bounds = if rotation.is_multiple_of(2) {
        [0, 0, width, height]
    } else {
        [0, 0, height, width]
    };
    assert_eq!(
        preflight::worker::unrotate_bounds(bounds, [width, height], rotation),
        [0, 0, width, height]
    );
}
