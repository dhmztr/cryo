use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn cryo_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_cryo"))
}

fn tmp_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("cryo_mt_{}_{}", label, std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn run(args: &[&str]) -> std::process::Output {
    Command::new(cryo_bin()).args(args).output().unwrap()
}

#[test]
fn many_blocks_single_file_round_trips_in_order() {
    let tmp = tmp_dir("many_blocks");
    let src = tmp.join("src");
    let dst = tmp.join("dst");
    let archive = tmp.join("blocks.cryo");

    fs::create_dir_all(&src).unwrap();
    let data: Vec<u8> = (0u32..2_000_000).flat_map(|n| n.to_le_bytes()).collect();
    fs::write(src.join("big.bin"), &data).unwrap();

    let compress = run(&[
        "compress",
        archive.to_str().unwrap(),
        "-P",
        src.to_str().unwrap(),
        "-r",
        "--bs",
        "4KiB",
    ]);
    assert!(
        compress.status.success(),
        "compress failed: {}",
        String::from_utf8_lossy(&compress.stderr)
    );

    fs::create_dir_all(&dst).unwrap();
    let decompress = run(&[
        "decompress",
        archive.to_str().unwrap(),
        "-o",
        dst.to_str().unwrap(),
    ]);
    assert!(
        decompress.status.success(),
        "decompress failed: {}",
        String::from_utf8_lossy(&decompress.stderr)
    );

    assert_eq!(fs::read(dst.join("big.bin")).unwrap(), data);

    fs::remove_dir_all(&tmp).ok();
}

#[test]
fn many_files_across_many_blocks_verify_ok() {
    let tmp = tmp_dir("many_files");
    let src = tmp.join("src");
    let dst = tmp.join("dst");
    let archive = tmp.join("many.cryo");

    fs::create_dir_all(&src).unwrap();
    for i in 0..64 {
        let content: Vec<u8> = (0u8..=255).cycle().skip(i).take(20 * 1024).collect();
        fs::write(src.join(format!("file{i}.bin")), &content).unwrap();
    }

    let compress = run(&[
        "compress",
        archive.to_str().unwrap(),
        "-P",
        src.to_str().unwrap(),
        "-r",
        "--bs",
        "4KiB",
    ]);
    assert!(
        compress.status.success(),
        "compress failed: {}",
        String::from_utf8_lossy(&compress.stderr)
    );

    let verify = run(&["verify", archive.to_str().unwrap()]);
    assert!(
        verify.status.success(),
        "verify failed: {}",
        String::from_utf8_lossy(&verify.stderr)
    );

    fs::create_dir_all(&dst).unwrap();
    let decompress = run(&[
        "decompress",
        archive.to_str().unwrap(),
        "-o",
        dst.to_str().unwrap(),
    ]);
    assert!(
        decompress.status.success(),
        "decompress failed: {}",
        String::from_utf8_lossy(&decompress.stderr)
    );

    for i in 0..64 {
        let expected: Vec<u8> = (0u8..=255).cycle().skip(i).take(20 * 1024).collect();
        assert_eq!(
            fs::read(dst.join(format!("file{i}.bin"))).unwrap(),
            expected
        );
    }

    fs::remove_dir_all(&tmp).ok();
}

#[test]
fn mixed_dirs_symlinks_and_many_blocks() {
    let tmp = tmp_dir("mixed");
    let src = tmp.join("src");
    let dst = tmp.join("dst");
    let archive = tmp.join("mixed.cryo");

    fs::create_dir_all(src.join("sub/nested")).unwrap();
    let big: Vec<u8> = (0u8..=255).cycle().take(300 * 1024).collect();
    fs::write(src.join("sub/nested/big.bin"), &big).unwrap();
    fs::write(src.join("small.txt"), b"small file content").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink("small.txt", src.join("link.txt")).unwrap();

    let compress = run(&[
        "compress",
        archive.to_str().unwrap(),
        "-P",
        src.to_str().unwrap(),
        "-r",
        "--bs",
        "8KiB",
    ]);
    assert!(
        compress.status.success(),
        "compress failed: {}",
        String::from_utf8_lossy(&compress.stderr)
    );

    fs::create_dir_all(&dst).unwrap();
    let decompress = run(&[
        "decompress",
        archive.to_str().unwrap(),
        "-o",
        dst.to_str().unwrap(),
    ]);
    assert!(
        decompress.status.success(),
        "decompress failed: {}",
        String::from_utf8_lossy(&decompress.stderr)
    );

    assert_eq!(fs::read(dst.join("sub/nested/big.bin")).unwrap(), big);
    assert_eq!(
        fs::read(dst.join("small.txt")).unwrap(),
        b"small file content"
    );
    #[cfg(unix)]
    assert_eq!(
        fs::read_link(dst.join("link.txt")).unwrap(),
        PathBuf::from("small.txt")
    );

    fs::remove_dir_all(&tmp).ok();
}

#[test]
fn empty_files_among_many_blocks_do_not_break_ordering() {
    let tmp = tmp_dir("empties");
    let src = tmp.join("src");
    let dst = tmp.join("dst");
    let archive = tmp.join("empties.cryo");

    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("a_empty.bin"), b"").unwrap();
    let mid: Vec<u8> = (0u8..=255).cycle().take(100 * 1024).collect();
    fs::write(src.join("b_data.bin"), &mid).unwrap();
    fs::write(src.join("c_empty.bin"), b"").unwrap();

    let compress = run(&[
        "compress",
        archive.to_str().unwrap(),
        "-P",
        src.to_str().unwrap(),
        "-r",
        "--bs",
        "4KiB",
    ]);
    assert!(
        compress.status.success(),
        "compress failed: {}",
        String::from_utf8_lossy(&compress.stderr)
    );

    fs::create_dir_all(&dst).unwrap();
    let decompress = run(&[
        "decompress",
        archive.to_str().unwrap(),
        "-o",
        dst.to_str().unwrap(),
    ]);
    assert!(
        decompress.status.success(),
        "decompress failed: {}",
        String::from_utf8_lossy(&decompress.stderr)
    );

    assert_eq!(fs::read(dst.join("a_empty.bin")).unwrap(), Vec::<u8>::new());
    assert_eq!(fs::read(dst.join("b_data.bin")).unwrap(), mid);
    assert_eq!(fs::read(dst.join("c_empty.bin")).unwrap(), Vec::<u8>::new());

    fs::remove_dir_all(&tmp).ok();
}
