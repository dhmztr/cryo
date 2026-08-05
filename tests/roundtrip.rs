use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn cryo_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_cryo"))
}

fn tmp_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("cryo_test_{}_{}", label, std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn compress_and_decompress_single_file() {
    let tmp = tmp_dir("single");
    let src = tmp.join("src");
    let dst = tmp.join("dst");
    let archive = tmp.join("test.cryo");

    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("hello.txt"), b"hello world\n").unwrap();

    let compress = Command::new(cryo_bin())
        .args([
            "compress",
            archive.to_str().unwrap(),
            "-P",
            src.to_str().unwrap(),
            "-r",
        ])
        .output()
        .unwrap();
    assert!(
        compress.status.success(),
        "compress failed: {}",
        String::from_utf8_lossy(&compress.stderr)
    );

    fs::create_dir_all(&dst).unwrap();
    let decompress = Command::new(cryo_bin())
        .args([
            "decompress",
            archive.to_str().unwrap(),
            "-o",
            dst.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        decompress.status.success(),
        "decompress failed: {}",
        String::from_utf8_lossy(&decompress.stderr)
    );

    assert_eq!(fs::read(dst.join("hello.txt")).unwrap(), b"hello world\n");

    fs::remove_dir_all(&tmp).ok();
}

#[test]
fn compress_and_decompress_multiple_files() {
    let tmp = tmp_dir("multi");
    let src = tmp.join("src");
    let dst = tmp.join("dst");
    let archive = tmp.join("multi.cryo");

    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("a.txt"), b"file a").unwrap();
    fs::write(src.join("b.txt"), b"file b content here").unwrap();
    fs::write(src.join("c.bin"), vec![0u8, 1, 2, 3, 255, 254, 253]).unwrap();

    let status = Command::new(cryo_bin())
        .args([
            "compress",
            archive.to_str().unwrap(),
            "-P",
            src.to_str().unwrap(),
            "-r",
        ])
        .status()
        .unwrap();
    assert!(status.success());

    fs::create_dir_all(&dst).unwrap();
    let status = Command::new(cryo_bin())
        .args([
            "decompress",
            archive.to_str().unwrap(),
            "-o",
            dst.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(status.success());

    assert_eq!(fs::read(dst.join("a.txt")).unwrap(), b"file a");
    assert_eq!(fs::read(dst.join("b.txt")).unwrap(), b"file b content here");
    assert_eq!(
        fs::read(dst.join("c.bin")).unwrap(),
        vec![0u8, 1, 2, 3, 255, 254, 253]
    );

    fs::remove_dir_all(&tmp).ok();
}

#[test]
fn compress_empty_file() {
    let tmp = tmp_dir("empty");
    let src = tmp.join("src");
    let dst = tmp.join("dst");
    let archive = tmp.join("empty.cryo");

    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("empty.txt"), b"").unwrap();

    let status = Command::new(cryo_bin())
        .args([
            "compress",
            archive.to_str().unwrap(),
            "-P",
            src.to_str().unwrap(),
            "-r",
        ])
        .status()
        .unwrap();
    assert!(status.success());

    fs::create_dir_all(&dst).unwrap();
    let status = Command::new(cryo_bin())
        .args([
            "decompress",
            archive.to_str().unwrap(),
            "-o",
            dst.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(status.success());

    assert_eq!(fs::read(dst.join("empty.txt")).unwrap(), b"");

    fs::remove_dir_all(&tmp).ok();
}

#[test]
fn compress_binary_data() {
    let tmp = tmp_dir("binary");
    let src = tmp.join("src");
    let dst = tmp.join("dst");
    let archive = tmp.join("bin.cryo");

    fs::create_dir_all(&src).unwrap();
    let data: Vec<u8> = (0u8..=255).cycle().take(10_000).collect();
    fs::write(src.join("data.bin"), &data).unwrap();

    let status = Command::new(cryo_bin())
        .args([
            "compress",
            archive.to_str().unwrap(),
            "-P",
            src.to_str().unwrap(),
            "-r",
        ])
        .status()
        .unwrap();
    assert!(status.success());

    fs::create_dir_all(&dst).unwrap();
    let status = Command::new(cryo_bin())
        .args([
            "decompress",
            archive.to_str().unwrap(),
            "-o",
            dst.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(status.success());

    assert_eq!(fs::read(dst.join("data.bin")).unwrap(), data);

    fs::remove_dir_all(&tmp).ok();
}

#[test]
fn list_produces_output_with_filename() {
    let tmp = tmp_dir("list");
    let src = tmp.join("src");
    let archive = tmp.join("list.cryo");

    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("readme.txt"), b"some content").unwrap();

    Command::new(cryo_bin())
        .args([
            "compress",
            archive.to_str().unwrap(),
            "-P",
            src.to_str().unwrap(),
            "-r",
        ])
        .status()
        .unwrap();

    let out = Command::new(cryo_bin())
        .args(["list", archive.to_str().unwrap(), "--format", "plain"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("readme.txt"),
        "expected file name in plain output"
    );

    fs::remove_dir_all(&tmp).ok();
}

#[test]
fn list_json_starts_with_brace() {
    let tmp = tmp_dir("json");
    let src = tmp.join("src");
    let archive = tmp.join("json.cryo");

    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("data.txt"), b"hello").unwrap();

    Command::new(cryo_bin())
        .args([
            "compress",
            archive.to_str().unwrap(),
            "-P",
            src.to_str().unwrap(),
            "-r",
        ])
        .status()
        .unwrap();

    let out = Command::new(cryo_bin())
        .args(["list", archive.to_str().unwrap(), "--format", "json"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.trim_start().starts_with('{'));
    assert!(stdout.contains("\"files\""));

    fs::remove_dir_all(&tmp).ok();
}

#[test]
fn decompress_into_nonempty_dir_fails() {
    let tmp = tmp_dir("nonempty");
    let src = tmp.join("src");
    let dst = tmp.join("dst");
    let archive = tmp.join("test.cryo");

    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("x.txt"), b"x").unwrap();

    Command::new(cryo_bin())
        .args([
            "compress",
            archive.to_str().unwrap(),
            "-P",
            src.to_str().unwrap(),
            "-r",
        ])
        .status()
        .unwrap();

    fs::create_dir_all(&dst).unwrap();
    fs::write(dst.join("existing.txt"), b"existing").unwrap();

    let status = Command::new(cryo_bin())
        .args([
            "decompress",
            archive.to_str().unwrap(),
            "-o",
            dst.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(
        !status.success(),
        "should fail when output dir is not empty"
    );

    fs::remove_dir_all(&tmp).ok();
}

#[test]
fn compress_subdirectory_structure_preserved() {
    let tmp = tmp_dir("subdir");
    let src = tmp.join("src");
    let dst = tmp.join("dst");
    let archive = tmp.join("subdir.cryo");

    fs::create_dir_all(src.join("sub")).unwrap();
    fs::write(src.join("root.txt"), b"root").unwrap();
    fs::write(src.join("sub").join("nested.txt"), b"nested").unwrap();

    let status = Command::new(cryo_bin())
        .args([
            "compress",
            archive.to_str().unwrap(),
            "-P",
            src.to_str().unwrap(),
            "-r",
        ])
        .status()
        .unwrap();
    assert!(status.success());

    fs::create_dir_all(&dst).unwrap();
    let status = Command::new(cryo_bin())
        .args([
            "decompress",
            archive.to_str().unwrap(),
            "-o",
            dst.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(status.success());

    assert_eq!(fs::read(dst.join("root.txt")).unwrap(), b"root");
    assert_eq!(
        fs::read(dst.join("sub").join("nested.txt")).unwrap(),
        b"nested"
    );

    fs::remove_dir_all(&tmp).ok();
}

#[test]
fn large_file_spanning_multiple_blocks() {
    let tmp = tmp_dir("large");
    let src = tmp.join("src");
    let dst = tmp.join("dst");
    let archive = tmp.join("large.cryo");

    fs::create_dir_all(&src).unwrap();
    // 200 KiB of data with default 64 KiB block size -> at least 3 blocks
    let data: Vec<u8> = (0u8..=255).cycle().take(200 * 1024).collect();
    fs::write(src.join("big.bin"), &data).unwrap();

    let status = Command::new(cryo_bin())
        .args([
            "compress",
            archive.to_str().unwrap(),
            "-P",
            src.to_str().unwrap(),
            "-r",
        ])
        .status()
        .unwrap();
    assert!(status.success());

    fs::create_dir_all(&dst).unwrap();
    let status = Command::new(cryo_bin())
        .args([
            "decompress",
            archive.to_str().unwrap(),
            "-o",
            dst.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(status.success());

    assert_eq!(fs::read(dst.join("big.bin")).unwrap(), data);

    fs::remove_dir_all(&tmp).ok();
}
