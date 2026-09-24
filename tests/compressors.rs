use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

const ALGOS: [&str; 4] = ["zstd", "deflate", "xz", "none"];

fn cryo_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_cryo"))
}

/// Returns a fresh temporary directory, unique even across tests running
/// concurrently in the same process.
fn tmp_dir(label: &str) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    let dir =
        std::env::temp_dir().join(format!("cryo_algo_{}_{}_{}", label, std::process::id(), n));
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn run(args: &[&str]) -> std::process::Output {
    Command::new(cryo_bin()).args(args).output().unwrap()
}

fn assert_ok(out: &std::process::Output, what: &str) {
    assert!(
        out.status.success(),
        "{what} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Writes a tree of differently sized files, forcing multiple blocks, both
/// compressible and incompressible payloads, and a non-empty index.
fn make_tree(src: &Path) {
    fs::create_dir_all(src.join("nested/deep")).unwrap();
    fs::write(src.join("empty.txt"), b"").unwrap();
    fs::write(src.join("small.txt"), b"hello world\n").unwrap();
    fs::write(
        src.join("repetitive.txt"),
        b"the quick brown fox. ".repeat(5000),
    )
    .unwrap();
    let noise: Vec<u8> = (0..300_000u32)
        .map(|i| (i.wrapping_mul(2654435761) >> 16) as u8)
        .collect();
    fs::write(src.join("nested/noise.bin"), &noise).unwrap();
    fs::write(src.join("nested/deep/leaf.txt"), b"leaf\n").unwrap();
}

/// Runs compress, verify and decompress for one algorithm and asserts every
/// file comes back byte for byte.
fn compress_verify_decompress(algo: &str, extra: &[&str]) {
    let tmp = tmp_dir(algo);
    let src = tmp.join("src");
    let dst = tmp.join("dst");
    let archive = tmp.join(format!("{algo}.cryo"));
    make_tree(&src);
    fs::create_dir_all(&dst).unwrap();

    let archive_s = archive.to_str().unwrap();
    let mut args: Vec<&str> = vec![
        "compress",
        archive_s,
        "-P",
        src.to_str().unwrap(),
        "-r",
        "-c",
        algo,
    ];
    args.extend_from_slice(extra);
    assert_ok(&run(&args), "compress");

    assert_ok(&run(&["verify", archive_s]), "verify");

    assert_ok(
        &run(&["decompress", archive_s, "-o", dst.to_str().unwrap()]),
        "decompress",
    );

    for rel in [
        "empty.txt",
        "small.txt",
        "repetitive.txt",
        "nested/noise.bin",
        "nested/deep/leaf.txt",
    ] {
        assert_eq!(
            fs::read(dst.join(rel)).unwrap_or_else(|e| panic!("{algo}: missing {rel}: {e}")),
            fs::read(src.join(rel)).unwrap(),
            "{algo}: contents of {rel} differ after round-trip"
        );
    }

    fs::remove_dir_all(&tmp).ok();
}

#[test]
fn zstd_archive_round_trips() {
    compress_verify_decompress("zstd", &[]);
}

#[test]
fn deflate_archive_round_trips() {
    compress_verify_decompress("deflate", &[]);
}

#[test]
fn xz_archive_round_trips() {
    compress_verify_decompress("xz", &[]);
}

#[test]
fn none_archive_round_trips() {
    compress_verify_decompress("none", &[]);
}

#[test]
fn small_blocks_round_trip_every_algo() {
    for algo in ALGOS {
        compress_verify_decompress(algo, &["--bs", "4KiB"]);
    }
}

#[test]
fn compress_works_without_explicit_compression_flag() {
    let tmp = tmp_dir("default_flag");
    let src = tmp.join("src");
    let dst = tmp.join("dst");
    let archive = tmp.join("default.cryo");
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("a.txt"), b"default algo\n").unwrap();
    fs::create_dir_all(&dst).unwrap();

    let archive_s = archive.to_str().unwrap();
    assert_ok(
        &run(&["compress", archive_s, "-P", src.to_str().unwrap(), "-r"]),
        "compress without -c",
    );
    assert_ok(
        &run(&["decompress", archive_s, "-o", dst.to_str().unwrap()]),
        "decompress",
    );
    assert_eq!(fs::read(dst.join("a.txt")).unwrap(), b"default algo\n");

    fs::remove_dir_all(&tmp).ok();
}

#[test]
fn every_advertised_algo_name_is_accepted() {
    for algo in ALGOS {
        let tmp = tmp_dir(&format!("accept_{algo}"));
        let src = tmp.join("src");
        fs::create_dir_all(&src).unwrap();
        fs::write(src.join("a.txt"), b"x").unwrap();

        let out = run(&[
            "compress",
            tmp.join("a.cryo").to_str().unwrap(),
            "-P",
            src.to_str().unwrap(),
            "-r",
            "-c",
            algo,
        ]);
        assert!(
            out.status.success(),
            "-c {algo} rejected: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        fs::remove_dir_all(&tmp).ok();
    }
}

#[test]
fn unknown_algo_is_rejected() {
    let tmp = tmp_dir("bad_algo");
    let src = tmp.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("a.txt"), b"x").unwrap();

    let out = run(&[
        "compress",
        tmp.join("a.cryo").to_str().unwrap(),
        "-P",
        src.to_str().unwrap(),
        "-r",
        "-c",
        "brotli",
    ]);
    assert!(!out.status.success(), "unknown algorithm must be rejected");

    fs::remove_dir_all(&tmp).ok();
}

#[test]
fn out_of_range_level_fails_cleanly() {
    let tmp = tmp_dir("bad_level");
    let src = tmp.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("a.txt"), b"x").unwrap();

    let out = run(&[
        "compress",
        tmp.join("a.cryo").to_str().unwrap(),
        "-P",
        src.to_str().unwrap(),
        "-r",
        "-c",
        "deflate",
        "--cl",
        "42",
    ]);
    assert!(!out.status.success(), "level 42 must fail for deflate");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        !err.contains("panicked"),
        "an invalid level must produce an error, not a panic: {err}"
    );

    fs::remove_dir_all(&tmp).ok();
}
