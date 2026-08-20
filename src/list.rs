use std::fs::File;
use std::io::IsTerminal;
use std::path::PathBuf;

use bytesize::ByteSize;

use crate::cli::{ListArgs, OutputFormat};
use crate::consts::Limits;
use crate::errors::CryoErrors;
use crate::format::{EncryptionType, FileType};
use crate::loader::FileStructs;

pub fn list_files(args: ListArgs) -> Result<(), CryoErrors> {
    check_read_only_args_for_errors(&args.archive)?;

    let archive_path = args.archive;
    let f = File::open(&archive_path).map_err(|e| CryoErrors::ReadFailed {
        p: archive_path.clone(),
        source: e,
    })?;
    let limits = Limits::default();
    let structs = FileStructs::retrieve(&f, &archive_path, &limits)?;
    let path_str = archive_path.display().to_string();

    match args.format {
        OutputFormat::Human => print_human(&structs, &path_str),
        OutputFormat::Plain => print_plain(&structs, &path_str),
        OutputFormat::Json => print_json(&structs, &path_str),
        OutputFormat::Auto => {
            if std::io::stdout().is_terminal() {
                print_human(&structs, &path_str);
            } else {
                print_plain(&structs, &path_str);
            }
        }
    }

    Ok(())
}

fn print_human(structs: &FileStructs, archive_path: &str) {
    let encryption_str = encryption_label(&structs.header.encryption);

    println!("\x1b[1mArchive:\x1b[0m  {}", archive_path);
    println!("  \x1b[2mversion:\x1b[0m     {}", structs.header.version);
    println!("  \x1b[2mencryption:\x1b[0m  {}", encryption_str);
    println!(
        "  \x1b[2mcompression:\x1b[0m zstd (level {})",
        structs.header.compression
    );
    println!(
        "  \x1b[2mblock size:\x1b[0m  {}",
        ByteSize(structs.header.block_size)
    );
    println!("  \x1b[2mfiles:\x1b[0m       {}", structs.index.files.len());
    println!();

    if structs.index.files.is_empty() {
        println!("  (empty archive)");
        return;
    }

    println!(
        "  \x1b[2m{:<9}  {:<4}  {:>10}  {:>5}  {:<19}  {}\x1b[0m",
        "Perms", "Type", "Size", "Ratio", "Modified", "Path"
    );
    println!("  {}", "\u{2500}".repeat(80));

    let mut total_size: u64 = 0;

    for entry in &structs.index.files {
        let perms = format_permissions(entry.permissions);
        let (type_label, color) = match entry.ftype {
            FileType::File => ("file", ""),
            FileType::Dir => ("dir", "\x1b[34m"),
            FileType::Symlink => ("link", "\x1b[36m"),
        };
        let (size_str, ratio_str) = match entry.ftype {
            FileType::File => {
                let compr = structs.index.file_compressed_size(entry);
                let ratio = if entry.size > 0 {
                    format!("{:>4}%", compr * 100 / entry.size)
                } else {
                    "  --".to_string()
                };
                (format!("{:>10}", ByteSize(entry.size)), ratio)
            }
            _ => (format!("{:>10}", "---"), "   --".to_string()),
        };
        let ts = format_timestamp(entry.timestamp);
        let path_str = match &entry.symlink_target {
            Some(target) => format!(
                "{} \x1b[2m->\x1b[0m {} {}",
                entry.path.display(),
                color,
                target.display()
            ),
            None => format!("{}{}\x1b[0m", color, entry.path.display()),
        };

        println!(
            "  {}  {}{:<4}\x1b[0m  {}  {}  {}  {}",
            perms, color, type_label, size_str, ratio_str, ts, path_str
        );

        if matches!(entry.ftype, FileType::File) {
            total_size += entry.size;
        }
    }

    let total_compressed = structs.index.total_compressed_size();
    let archive_ratio = if total_size > 0 {
        format!("{}%", total_compressed * 100 / total_size)
    } else {
        "--".to_string()
    };

    println!("  {}", "\u{2500}".repeat(80));
    println!(
        "  \x1b[1mTotal:\x1b[0m {} uncompressed  {} compressed  ({})  ({} entries)",
        ByteSize(total_size),
        ByteSize(total_compressed),
        archive_ratio,
        structs.index.files.len()
    );
}

fn print_plain(structs: &FileStructs, archive_path: &str) {
    let total_compressed = structs.index.total_compressed_size();

    println!(
        "# archive={}\tversion={}\tencryption={}\tcompression={}\tblock_size={}\ttotal_uncompressed={}\ttotal_compressed={}",
        archive_path,
        structs.header.version,
        encryption_label(&structs.header.encryption),
        structs.header.compression,
        structs.header.block_size,
        structs.index.total_stream_size,
        total_compressed,
    );

    for entry in &structs.index.files {
        let type_label = match entry.ftype {
            FileType::File => "file",
            FileType::Dir => "dir",
            FileType::Symlink => "link",
        };
        let perms = format_permissions(entry.permissions);
        let (size, compressed, ratio) = match entry.ftype {
            FileType::File => {
                let c = structs.index.file_compressed_size(entry);
                let r = if entry.size > 0 {
                    c * 100 / entry.size
                } else {
                    0
                };
                (entry.size, c, r)
            }
            _ => (0, 0, 0),
        };

        match &entry.symlink_target {
            Some(target) => println!(
                "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
                type_label,
                perms,
                size,
                compressed,
                ratio,
                entry.timestamp,
                entry.path.display(),
                target.display(),
            ),
            None => println!(
                "{}\t{}\t{}\t{}\t{}\t{}\t{}",
                type_label,
                perms,
                size,
                compressed,
                ratio,
                entry.timestamp,
                entry.path.display(),
            ),
        }
    }
}

fn print_json(structs: &FileStructs, archive_path: &str) {
    let total_compressed = structs.index.total_compressed_size();

    println!("{{");
    println!("  \"archive\": {},", js(&archive_path.to_string()));
    println!("  \"version\": {},", structs.header.version);
    println!(
        "  \"encryption\": {},",
        js(&encryption_label(&structs.header.encryption).to_string())
    );
    println!("  \"compression\": {},", structs.header.compression);
    println!("  \"block_size\": {},", structs.header.block_size);
    println!(
        "  \"total_uncompressed\": {},",
        structs.index.total_stream_size
    );
    println!("  \"total_compressed\": {},", total_compressed);
    println!("  \"files\": [");

    let last = structs.index.files.len().saturating_sub(1);
    for (i, entry) in structs.index.files.iter().enumerate() {
        let type_label = match entry.ftype {
            FileType::File => "file",
            FileType::Dir => "dir",
            FileType::Symlink => "link",
        };
        let perms = format_permissions(entry.permissions);
        let (size, compressed, ratio) = match entry.ftype {
            FileType::File => {
                let c = structs.index.file_compressed_size(entry);
                let r = if entry.size > 0 {
                    c * 100 / entry.size
                } else {
                    0
                };
                (entry.size, c, r)
            }
            _ => (0, 0, 0),
        };
        let target_field = match &entry.symlink_target {
            Some(t) => format!(",\n      \"target\": {}", js(&t.display().to_string())),
            None => String::new(),
        };
        let trailing = if i < last { "," } else { "" };
        println!("    {{");
        println!("      \"type\": {},", js(type_label));
        println!("      \"path\": {},", js(&entry.path.display().to_string()));
        println!("      \"permissions\": {},", js(&perms));
        println!("      \"size\": {},", size);
        println!("      \"compressed\": {},", compressed);
        println!("      \"ratio\": {},", ratio);
        println!("      \"modified\": {}{}", entry.timestamp, target_field);
        println!("    }}{}", trailing);
    }

    println!("  ]");
    println!("}}");
}

fn encryption_label(enc: &EncryptionType) -> &'static str {
    match enc {
        EncryptionType::AES => "AES-256-GCM",
        EncryptionType::ChaCha => "ChaCha20-Poly1305",
        EncryptionType::None => "none",
    }
}

fn js(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 32 => {
                let _ = std::fmt::Write::write_fmt(&mut out, format_args!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn format_permissions(perms: u32) -> String {
    [
        if perms & 0o400 != 0 { 'r' } else { '-' },
        if perms & 0o200 != 0 { 'w' } else { '-' },
        if perms & 0o100 != 0 { 'x' } else { '-' },
        if perms & 0o040 != 0 { 'r' } else { '-' },
        if perms & 0o020 != 0 { 'w' } else { '-' },
        if perms & 0o010 != 0 { 'x' } else { '-' },
        if perms & 0o004 != 0 { 'r' } else { '-' },
        if perms & 0o002 != 0 { 'w' } else { '-' },
        if perms & 0o001 != 0 { 'x' } else { '-' },
    ]
    .iter()
    .collect()
}

fn format_timestamp(secs: u64) -> String {
    let s = secs as i64;
    let time = s.rem_euclid(86400);
    let days = (s - time) / 86400;
    let (h, m, sec) = (time / 3600, (time % 3600) / 60, time % 60);
    let (y, mo, d) = days_to_ymd(days);
    format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02}", y, mo, d, h, m, sec)
}

fn days_to_ymd(days: i64) -> (i64, i64, i64) {
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if mo <= 2 { y + 1 } else { y };
    (y, mo, d)
}

pub fn check_read_only_args_for_errors(archive: &PathBuf) -> Result<(), CryoErrors> {
    if archive.extension().map_or(false, |e| e == "cryo") && archive.is_file() {
        Ok(())
    } else {
        Err(CryoErrors::InitializationError(
            "path is not a .cryo archive file".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permissions_all_set() {
        assert_eq!(format_permissions(0o777), "rwxrwxrwx");
    }

    #[test]
    fn permissions_none_set() {
        assert_eq!(format_permissions(0), "---------");
    }

    #[test]
    fn permissions_644() {
        assert_eq!(format_permissions(0o644), "rw-r--r--");
    }

    #[test]
    fn permissions_755() {
        assert_eq!(format_permissions(0o755), "rwxr-xr-x");
    }

    #[test]
    fn permissions_owner_readonly() {
        assert_eq!(format_permissions(0o400), "r--------");
    }

    #[test]
    fn timestamp_unix_epoch() {
        assert_eq!(format_timestamp(0), "1970-01-01 00:00:00");
    }

    #[test]
    fn timestamp_billion_seconds() {
        assert_eq!(format_timestamp(1_000_000_000), "2001-09-09 01:46:40");
    }

    #[test]
    fn timestamp_end_of_first_day() {
        assert_eq!(format_timestamp(86399), "1970-01-01 23:59:59");
    }

    #[test]
    fn timestamp_leap_day_2000() {
        assert_eq!(format_timestamp(951782400), "2000-02-29 00:00:00");
    }

    #[test]
    fn days_to_ymd_epoch() {
        assert_eq!(days_to_ymd(0), (1970, 1, 1));
    }

    #[test]
    fn days_to_ymd_one_year() {
        assert_eq!(days_to_ymd(365), (1971, 1, 1));
    }

    #[test]
    fn days_to_ymd_before_epoch() {
        assert_eq!(days_to_ymd(-1), (1969, 12, 31));
    }

    #[test]
    fn days_to_ymd_leap_day_2000() {
        let (y, m, d) = days_to_ymd(11016);
        assert_eq!((y, m, d), (2000, 2, 29));
    }

    #[test]
    fn days_to_ymd_march_after_leap() {
        let (y, m, d) = days_to_ymd(11017);
        assert_eq!((y, m, d), (2000, 3, 1));
    }

    #[test]
    fn js_escapes_quotes() {
        assert_eq!(js("a\"b"), "\"a\\\"b\"");
    }

    #[test]
    fn js_escapes_backslash() {
        assert_eq!(js("a\\b"), "\"a\\\\b\"");
    }

    #[test]
    fn js_escapes_newline() {
        assert_eq!(js("a\nb"), "\"a\\nb\"");
    }

    #[test]
    fn js_plain_string() {
        assert_eq!(js("hello"), "\"hello\"");
    }

    #[test]
    fn js_empty_string() {
        assert_eq!(js(""), "\"\"");
    }
}
