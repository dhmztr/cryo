use crate::codec::{Cipher, decrypt_block};
use crate::consts::{Limits, MAX_FILE_SIZE};
use crate::errors::CryoErrors;
use crate::format::{BlockEntry, EncryptedData, FileEntry, FileType, Header, Index};
use crate::loader::FileStructs;
use crate::path_safety::{normalize, safe_output_path};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use std::fs::{self, File, Permissions};
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, UNIX_EPOCH};
use tracing::{Level, event};

pub struct ArchiveReader {
    pub(crate) root: PathBuf,
    pub(crate) reader: BufReader<File>,
    pub(crate) index: Index,
    pub(crate) header: Header,
    pub(crate) cipher: Cipher,
    pub(crate) limits: Limits,
}

impl ArchiveReader {
    pub(crate) fn new(
        f: File,
        p: &PathBuf,
        out: PathBuf,
        limits: Limits,
    ) -> Result<Self, CryoErrors> {
        let structs = FileStructs::retrieve(&f, p, &limits)?;
        let reader = BufReader::new(f);

        Ok(ArchiveReader {
            root: out,
            reader,
            header: structs.header,
            cipher: structs.cipher,
            index: structs.index,
            limits,
        })
    }
    pub(crate) fn handle_files(
        &mut self,
        mp: Option<&MultiProgress>,
        pb_files: Option<&ProgressBar>,
    ) -> Result<(), CryoErrors> {
        let files = self.index.files.clone();
        event!(Level::DEBUG, count = files.len(), "extracting files");

        let pb_file_style = ProgressStyle::with_template(
            "  [{bar:40.blue/dim}] {percent:>3}%  {bytes}/{total_bytes}  {msg}",
        )
        .unwrap()
        .progress_chars("=>-");
        fs::create_dir_all(&self.root).map_err(|_| CryoErrors::WriteError)?;

        for f in &files {
            let name = f
                .path
                .file_name()
                .unwrap_or(f.path.as_os_str())
                .to_string_lossy()
                .into_owned();
            if let Some(pb) = pb_files {
                pb.set_message(name.clone());
            }
            event!(
                Level::DEBUG,
                path = %f.path.display(),
                ftype = ?f.ftype,
                size = f.size,
                "extracting entry"
            );

            let pb_file = if let (Some(mp), Some(pb_outer)) = (mp, pb_files) {
                if f.size > 0 && matches!(f.ftype, FileType::File) {
                    let pb = mp.insert_after(pb_outer, ProgressBar::new(f.size));
                    pb.set_style(pb_file_style.clone());
                    pb.set_message(name);
                    pb.enable_steady_tick(std::time::Duration::from_millis(100));
                    Some(pb)
                } else {
                    None
                }
            } else {
                None
            };
            let out_dir = safe_output_path(&self.root, f.path.as_path())?;
            let blocks = build_block_ranges(&self.index.block.as_slice());
            self.extract_file(f, out_dir.as_path(), &blocks, pb_file.as_ref())?;

            if let Some(pb) = pb_file {
                pb.finish_and_clear();
            }
            if let Some(pb) = pb_files {
                pb.inc(1);
            }
        }
        Ok(())
    }

    pub(crate) fn extract_file(
        &mut self,
        f: &FileEntry,
        out_dir: &Path,
        blocks: &[(u64, u64)],
        pb: Option<&ProgressBar>,
    ) -> Result<(), CryoErrors> {
        let eff_max_file = if self.limits.max_file_size == 0 {
            MAX_FILE_SIZE
        } else {
            self.limits.max_file_size
        };
        if f.size > eff_max_file {
            return Err(CryoErrors::FileTooLarge {
                size: f.size,
                limit: eff_max_file,
            });
        }
        let file_start = f.stream_offset;
        let file_end = file_start + f.size;
        if let Some(parent) = out_dir.parent() {
            fs::create_dir_all(parent).map_err(|_| CryoErrors::WriteError)?;
        }

        if matches!(f.ftype, FileType::Dir) {
            return fs::create_dir_all(out_dir).map_err(|_| CryoErrors::WriteError);
        }
        if matches!(f.ftype, FileType::Symlink) {
            let target = f.symlink_target.as_ref().ok_or(CryoErrors::WriteError)?;
            let link_dir = out_dir.parent().unwrap_or(Path::new(""));
            let resolved = normalize(&link_dir.join(target));
            let canonical_root = self
                .root
                .canonicalize()
                .map_err(|_| CryoErrors::InvalidPath)?;
            if !resolved.starts_with(&canonical_root) {
                return Err(CryoErrors::UnsafePath(target.clone()));
            }

            #[cfg(unix)]
            std::os::unix::fs::symlink(target, out_dir).map_err(|_| CryoErrors::WriteError)?;
            return Ok(());
        }
        let file = File::create(&out_dir).map_err(|_| CryoErrors::WriteError)?;
        let mut writer = BufWriter::with_capacity(self.header.block_size as usize, file);
        let system_time = UNIX_EPOCH + Duration::from_secs(f.timestamp);
        let first = blocks.partition_point(|(_, end)| *end <= file_start);

        event!(
            Level::DEBUG,
            path = %f.path.display(),
            file_start,
            file_end,
            first_block = first,
            total_blocks = blocks.len(),
            "extract filter"
        );

        for i in first..blocks.len() {
            let block = self.index.block[i].clone();
            let (start, end) = blocks[i];
            if end <= file_start || start >= file_end {
                event!(
                    Level::DEBUG,
                    block = i,
                    block_start = start,
                    block_end = end,
                    file_start,
                    file_end,
                    reason = if end <= file_start {
                        "block before file"
                    } else {
                        "block past file"
                    },
                    "block loop break"
                );
                break;
            }
            let take_start = file_start.saturating_sub(start) as usize;
            let take_end = (file_end.min(end) - start) as usize;
            event!(
                Level::DEBUG,
                block = i,
                block_start = start,
                block_end = end,
                take_start,
                take_end,
                bytes = take_end - take_start,
                "reading block slice"
            );
            let plain = self.read_block(&block, i)?;
            let calc_checksum = blake3::hash(&plain);
            if *calc_checksum.as_bytes() != block.checksum {
                return Err(CryoErrors::DecompressionError);
            }
            writer
                .write_all(&plain[take_start..take_end])
                .map_err(|_| CryoErrors::WriteError)?;
            if let Some(pb) = pb {
                pb.inc((take_end - take_start) as u64);
            }
        }

        match f.ftype {
            FileType::Dir | FileType::File => {
                fs::set_permissions(out_dir, Permissions::from_mode(f.permissions))
                    .map_err(|_| CryoErrors::WriteError)?;
            }
            FileType::Symlink => {}
        }

        writer
            .into_inner()
            .map_err(|_| CryoErrors::WriteError)?
            .set_modified(system_time)
            .map_err(|_| CryoErrors::WriteError)?;
        Ok(())
    }
    pub(crate) fn read_block(
        &mut self,
        block: &BlockEntry,
        block_num: usize,
    ) -> Result<Vec<u8>, CryoErrors> {
        if block.size_plain as u64 > self.header.block_size {
            return Err(CryoErrors::BlockTooLarge {
                size: block.size_plain as u64,
                limit: self.header.block_size,
            });
        }
        self.reader
            .seek(SeekFrom::Start(block.offset))
            .map_err(|e| CryoErrors::ReadFailed {
                p: PathBuf::from("./"),
                source: e,
            })?;
        let mut stored = vec![0u8; block.size_stored as usize];
        self.reader
            .read_exact(&mut stored)
            .map_err(|e| CryoErrors::ReadFailed {
                p: PathBuf::from("./"),
                source: e,
            })?;
        let decrypted = if !matches!(self.cipher, Cipher::None) {
            decrypt_block(
                EncryptedData::Block,
                &self.cipher,
                &self.header,
                &stored,
                block_num,
            )?
        } else {
            stored
        };
        let plain = if block.is_compressed {
            let mut decoder = zstd::Decoder::new(decrypted.as_slice())
                .map_err(|_| CryoErrors::DecompressionError)?;
            let mut out = Vec::with_capacity(block.size_plain as usize);
            let mut buf = [0u8; 8192];
            let mut total = 0u64;
            loop {
                let n = decoder
                    .read(&mut buf)
                    .map_err(|_| CryoErrors::DecompressionError)?;
                if n == 0 {
                    break;
                }
                total += n as u64;
                if total > self.header.block_size {
                    return Err(CryoErrors::BlockTooLarge {
                        size: total,
                        limit: self.header.block_size,
                    });
                }
                out.extend_from_slice(&buf[..n]);
            }
            out
        } else {
            decrypted
        };
        Ok(plain)
    }
    pub(crate) fn verify(&mut self, p: &PathBuf) -> Result<(), CryoErrors> {
        let blocks: Vec<BlockEntry> = self.index.block.clone();
        for (i, block) in blocks.iter().enumerate() {
            self.reader
                .seek(SeekFrom::Start(block.offset))
                .map_err(|e| CryoErrors::ReadFailed {
                    p: p.clone(),
                    source: e,
                })?;
            let mut stored = vec![0u8; block.size_stored as usize];
            self.reader
                .read_exact(&mut stored)
                .map_err(|e| CryoErrors::ReadFailed {
                    p: p.clone(),
                    source: e,
                })?;

            let decrypted =
                decrypt_block(EncryptedData::Block, &self.cipher, &self.header, &stored, i)?;

            let plain = if block.is_compressed {
                crate::codec::decompress_block(decrypted, &self.header, self.limits.max_block_size)?
            } else {
                decrypted
            };

            let calc = blake3::hash(&plain);
            if calc.as_bytes() != &block.checksum {
                return Err(CryoErrors::ChecksumMismatch);
            }
        }
        Ok(())
    }
}

pub(crate) fn build_block_ranges(blocks: &[BlockEntry]) -> Vec<(u64, u64)> {
    let mut out: Vec<(u64, u64)> = Vec::with_capacity(blocks.len());
    let mut streampos = 0u64;

    for block in blocks {
        let start = streampos;
        let end = start + block.size_plain as u64;

        out.push((start, end));
        streampos = end;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_block(size_plain: u32, size_stored: u32) -> BlockEntry {
        BlockEntry {
            offset: 0,
            size_stored,
            size_plain,
            is_compressed: false,
            checksum: [0u8; 32],
        }
    }

    #[test]
    fn build_block_ranges_empty() {
        assert!(build_block_ranges(&[]).is_empty());
    }

    #[test]
    fn build_block_ranges_single() {
        let ranges = build_block_ranges(&[make_block(100, 80)]);
        assert_eq!(ranges, vec![(0, 100)]);
    }

    #[test]
    fn build_block_ranges_contiguous() {
        let blocks = [
            make_block(100, 80),
            make_block(200, 150),
            make_block(50, 50),
        ];
        let ranges = build_block_ranges(&blocks);
        assert_eq!(ranges, vec![(0, 100), (100, 300), (300, 350)]);
    }

    #[test]
    fn build_block_ranges_no_gaps() {
        let blocks = [make_block(64, 40), make_block(64, 60), make_block(64, 30)];
        let ranges = build_block_ranges(&blocks);
        for i in 1..ranges.len() {
            assert_eq!(ranges[i - 1].1, ranges[i].0);
        }
    }

    #[test]
    fn block_filter_finds_first_overlapping_block() {
        let blocks = [
            make_block(100, 80),
            make_block(100, 60),
            make_block(100, 50),
        ];
        let ranges = build_block_ranges(&blocks);
        let first = ranges.partition_point(|(_, end)| *end <= 150);
        assert_eq!(first, 1);
    }

    #[test]
    fn block_filter_file_at_exact_block_boundary() {
        let blocks = [make_block(100, 80), make_block(100, 60)];
        let ranges = build_block_ranges(&blocks);
        let first = ranges.partition_point(|(_, end)| *end <= 100);
        assert_eq!(first, 1);
    }

    #[test]
    fn block_filter_file_at_start() {
        let blocks = [make_block(100, 80), make_block(100, 60)];
        let ranges = build_block_ranges(&blocks);
        let first = ranges.partition_point(|(_, end)| *end <= 0);
        assert_eq!(first, 0);
    }

    #[test]
    fn block_filter_file_in_last_block() {
        let blocks = [
            make_block(100, 80),
            make_block(100, 60),
            make_block(100, 40),
        ];
        let ranges = build_block_ranges(&blocks);
        let first = ranges.partition_point(|(_, end)| *end <= 250);
        assert_eq!(first, 2);
    }
}
