//! Prepare send inputs the way pTransfer does.
//!
//! A single regular file is deflated on the fly and travels as a `deflate-raw`
//! payload. Anything else (a folder, or multiple inputs) becomes a lazy ZIP
//! source whose entries are already deflated, so it travels as `identity` —
//! the no-recompress rule. Either way it writes directly into the transfer,
//! mirroring the web app's `createZipTransferSource`:
//! folder entries are keyed `<folderName>/sub/file.ext` (forward slashes),
//! loose files are keyed by bare basename, and the archive is named
//! `<folder>_<yyyymmddhhmmss>.zip` when exactly one folder is selected, else
//! `files_<yyyymmddhhmmss>.zip` — the local-time stamp (the web app's
//! `archiveTimestamp`) keeps repeated sends of the same selection from all
//! arriving under one file name.
//! Only file entries are written: empty directories are omitted and no
//! explicit directory entries are added. File symlinks are followed;
//! directory symlinks inside a walked folder are skipped (with a warning) so
//! the walk always terminates. ZIP output is produced on a blocking worker and
//! handed to the async transfer through a bounded channel, which applies
//! backpressure without ever materializing the complete archive.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use flate2::Compression;
use flate2::write::DeflateEncoder;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use zip::CompressionMethod;
use zip::write::SimpleFileOptions;

use crate::crypto::chunk::{ENCRYPTION_CHUNK_SIZE, MAX_MESSAGE_SIZE};
use crate::wire::WireEncoding;

/// What the transfer layer sends: either the original file untouched, or a
/// ZIP generated lazily as the transfer consumes it.
#[derive(Debug)]
pub struct SendSource {
    pub file_name: String,
    /// Input byte count. This is the size carried in signaling and used for
    /// the progress bar — never the wire length, which no source knows before
    /// it has been produced.
    pub estimated_size: u64,
    pub mime_type: &'static str,
    /// How the bytes travel; chosen by flow, never by sniffing content.
    pub wire_encoding: WireEncoding,
    kind: SendSourceKind,
}

#[derive(Debug, Clone)]
enum SendSourceKind {
    File(PathBuf),
    Zip(Vec<(String, PathBuf)>),
}

/// An opened source yielding transfer-sized wire chunks.
///
/// Both kinds run the same shape: a blocking worker produces the wire bytes
/// (deflating a file, or packaging a ZIP) into a [`ChunkWriter`], which hands
/// complete 128 KiB chunks across a bounded channel. The channel is the
/// backpressure boundary, so neither a whole archive nor a whole compressed
/// file is ever materialized.
pub(crate) struct SendStream {
    receiver: mpsc::Receiver<Result<Vec<u8>, String>>,
    task: Option<JoinHandle<Result<()>>>,
}

impl SendSource {
    /// Open this source. Compression and ZIP generation start here, after the
    /// data channel opens — never while the transfer is still being set up.
    pub(crate) async fn open(&self) -> Result<SendStream> {
        let kind = self.kind.clone();
        // Two queued chunks plus the writer's current chunk keep peak memory
        // bounded while allowing filesystem and crypto work to overlap.
        let (sender, receiver) = mpsc::channel(2);
        let error_sender = sender.clone();
        let task = tokio::task::spawn_blocking(move || {
            let result = produce_wire_bytes(&kind, ChunkWriter::new(sender));
            if let Err(error) = &result {
                let _ = error_sender.blocking_send(Err(format!("{error:#}")));
            }
            result
        });
        Ok(SendStream {
            receiver,
            task: Some(task),
        })
    }
}

/// Produce the source's wire bytes into `writer`, on a blocking worker.
fn produce_wire_bytes(kind: &SendSourceKind, writer: ChunkWriter) -> Result<()> {
    match kind {
        SendSourceKind::File(path) => {
            // Raw DEFLATE, no zlib header, matching the browser's
            // CompressionStream('deflate-raw'). Level 6 is flate2's default,
            // as it is the browser's.
            let mut encoder = DeflateEncoder::new(writer, Compression::default());
            let mut file =
                fs::File::open(path).with_context(|| format!("Cannot open {}", path.display()))?;
            std::io::copy(&mut file, &mut encoder)
                .with_context(|| format!("Cannot read {}", path.display()))?;
            encoder
                .finish()
                .context("Cannot finish the compressed stream")?
                .finish()
        }
        SendSourceKind::Zip(entries) => write_zip(entries, writer).and_then(ChunkWriter::finish),
    }
}

impl SendStream {
    /// Read the next non-empty chunk, coalesced to 128 KiB except at EOF.
    pub(crate) async fn next_chunk(&mut self) -> Result<Option<Vec<u8>>> {
        match self.receiver.recv().await {
            Some(Ok(chunk)) => Ok(Some(chunk)),
            Some(Err(message)) => Err(anyhow!(message)),
            None => {
                if let Some(task) = self.task.take() {
                    task.await.context("transfer source worker failed")??;
                }
                Ok(None)
            }
        }
    }
}

/// Prepare the send source for a selection of files and/or folders.
///
/// Blocking (walks directories and reads metadata); wrap in `spawn_blocking`
/// from async contexts. ZIP generation itself starts only when the returned
/// source is opened by the transfer layer.
pub fn prepare_send_source(inputs: &[PathBuf]) -> Result<SendSource> {
    prepare_send_source_with_cap(inputs, MAX_MESSAGE_SIZE)
}

/// As [`prepare_send_source`], with a transport-specific limit on the input
/// size — the Tor transport carries far less than a WebRTC data channel does.
pub fn prepare_send_source_with_cap(inputs: &[PathBuf], cap: u64) -> Result<SendSource> {
    if inputs.is_empty() {
        bail!("Nothing to send");
    }

    if let [single] = inputs {
        let metadata =
            fs::metadata(single).with_context(|| format!("Cannot read {}", single.display()))?;
        if metadata.is_file() {
            return single_file_source(single, metadata.len(), cap);
        }
    }

    let (entries, archive_name) = plan_entries(inputs)?;
    let estimated_size = entries.iter().try_fold(0u64, |total, (_, path)| {
        let size = fs::metadata(path)
            .with_context(|| format!("Cannot read {}", path.display()))?
            .len();
        total
            .checked_add(size)
            .context("Selected input size exceeds the supported range")
    })?;
    check_size_cap(estimated_size, cap)?;

    Ok(SendSource {
        file_name: archive_name,
        estimated_size,
        mime_type: "application/zip",
        // The ZIP's entries are already deflated, so the transfer layer must
        // not compress it again.
        wire_encoding: WireEncoding::Identity,
        kind: SendSourceKind::Zip(entries),
    })
}

fn single_file_source(path: &Path, file_size: u64, cap: u64) -> Result<SendSource> {
    if file_size == 0 {
        bail!("File is empty: {}", path.display());
    }
    check_size_cap(file_size, cap)?;

    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("file")
        .trim()
        .to_string();
    if file_name.is_empty() {
        bail!("Missing file name");
    }

    Ok(SendSource {
        file_name,
        estimated_size: file_size,
        mime_type: "application/octet-stream",
        wire_encoding: WireEncoding::DeflateRaw,
        kind: SendSourceKind::File(path.to_path_buf()),
    })
}

fn check_size_cap(file_size: u64, cap: u64) -> Result<()> {
    if file_size > cap {
        bail!(
            "File is {}, which exceeds the {} limit",
            crate::util::format_bytes(file_size),
            crate::util::format_bytes(cap)
        );
    }
    Ok(())
}

/// The wire file name a selection will travel under — minus the local-time
/// stamp appended at packaging time — without walking any directory tree
/// (cheap enough to call on every TUI redraw).
pub fn send_display_name(inputs: &[PathBuf]) -> String {
    match inputs {
        [single] if single.is_dir() => match input_name(single) {
            Ok(name) => format!("{name}.zip"),
            Err(_) => "files.zip".to_string(),
        },
        [single] => input_name(single).unwrap_or_else(|_| "file".to_string()),
        _ => "files.zip".to_string(),
    }
}

/// Local-time `yyyymmddhhmmss` stamp appended to archive names. Mirrors
/// pTransfer's `archiveTimestamp`.
fn archive_timestamp() -> String {
    chrono::Local::now().format("%Y%m%d%H%M%S").to_string()
}

/// Plan the ZIP: sorted `(entry_key, source_path)` pairs plus the archive's
/// file name. Errors on duplicate keys, non-UTF-8 names, and empty results.
fn plan_entries(inputs: &[PathBuf]) -> Result<(Vec<(String, PathBuf)>, String)> {
    let mut entries: BTreeMap<String, PathBuf> = BTreeMap::new();
    let mut folder_names = Vec::new();
    let mut file_count = 0usize;

    for input in inputs {
        let metadata =
            fs::metadata(input).with_context(|| format!("Cannot read {}", input.display()))?;
        if metadata.is_dir() {
            let name = input_name(input)?;
            collect_dir(input, &name, &mut entries)?;
            folder_names.push(name);
        } else if metadata.is_file() {
            let name = input_name(input)?;
            insert_entry(&mut entries, name, input.clone())?;
            file_count += 1;
        } else {
            bail!("Not a regular file or directory: {}", input.display());
        }
    }

    if entries.is_empty() {
        bail!("Nothing to send: the selection contains no files");
    }

    let stamp = archive_timestamp();
    let archive_name = match (folder_names.as_slice(), file_count) {
        ([folder], 0) => format!("{folder}_{stamp}.zip"),
        _ => format!("files_{stamp}.zip"),
    };

    Ok((entries.into_iter().collect(), archive_name))
}

/// Recursively add `dir`'s files under the `prefix/` key namespace.
fn collect_dir(dir: &Path, prefix: &str, entries: &mut BTreeMap<String, PathBuf>) -> Result<()> {
    let mut children: Vec<_> = fs::read_dir(dir)
        .with_context(|| format!("Cannot read directory {}", dir.display()))?
        .collect::<std::io::Result<_>>()
        .with_context(|| format!("Cannot read directory {}", dir.display()))?;
    children.sort_by_key(|e| e.file_name());

    for child in children {
        let path = child.path();
        let name = input_name(&path)?;
        let key = format!("{prefix}/{name}");
        let metadata = fs::symlink_metadata(&path)
            .with_context(|| format!("Cannot read {}", path.display()))?;

        if metadata.is_dir() {
            collect_dir(&path, &key, entries)?;
        } else if metadata.is_file() {
            insert_entry(entries, key, path)?;
        } else if metadata.is_symlink() {
            // Follow file symlinks; skip directory symlinks so the walk
            // cannot cycle.
            match fs::metadata(&path) {
                Ok(target) if target.is_file() => insert_entry(entries, key, path)?,
                Ok(target) if target.is_dir() => {
                    log::warn!("Skipping directory symlink: {}", path.display());
                }
                _ => log::warn!("Skipping unreadable symlink: {}", path.display()),
            }
        }
    }
    Ok(())
}

fn insert_entry(entries: &mut BTreeMap<String, PathBuf>, key: String, path: PathBuf) -> Result<()> {
    if entries.contains_key(&key) {
        bail!("Duplicate archive entry \"{key}\": rename one of the inputs");
    }
    entries.insert(key, path);
    Ok(())
}

/// UTF-8 basename of a path, resolving `.`-style paths through canonicalize.
fn input_name(path: &Path) -> Result<String> {
    let name = match path.file_name() {
        Some(name) => name.to_owned(),
        None => fs::canonicalize(path)
            .ok()
            .and_then(|p| p.file_name().map(|n| n.to_owned()))
            .with_context(|| format!("Cannot determine a name for {}", path.display()))?,
    };
    name.into_string()
        .map_err(|_| anyhow::anyhow!("File name is not valid UTF-8: {}", path.display()))
}

/// Write a standard ZIP without seeking, deflating each entry as pTransfer's
/// streamed archives do. Entry-at-a-time deflate keeps production bounded: no
/// entry, and no archive, is ever held whole.
fn write_zip<W: Write>(entries: &[(String, PathBuf)], output: W) -> Result<W> {
    let options = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
    let mut zip = zip::ZipWriter::new_stream(output);
    for (key, path) in entries {
        zip.start_file(key, options)
            .with_context(|| format!("Cannot add \"{key}\" to archive"))?;
        let mut file =
            fs::File::open(path).with_context(|| format!("Cannot open {}", path.display()))?;
        std::io::copy(&mut file, &mut zip)
            .with_context(|| format!("Cannot stream {} into archive", path.display()))?;
    }
    let output = zip.finish().context("Cannot finalize archive")?;
    Ok(output.into_inner())
}

/// Sync `Write` adapter that hands complete encryption-sized chunks to an
/// async consumer. `blocking_send` is the backpressure boundary.
struct ChunkWriter {
    sender: mpsc::Sender<Result<Vec<u8>, String>>,
    chunk: Vec<u8>,
}

impl ChunkWriter {
    fn new(sender: mpsc::Sender<Result<Vec<u8>, String>>) -> Self {
        Self {
            sender,
            chunk: Vec::with_capacity(ENCRYPTION_CHUNK_SIZE),
        }
    }

    fn send_chunk(&self, chunk: Vec<u8>) -> std::io::Result<()> {
        self.sender.blocking_send(Ok(chunk)).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::BrokenPipe, "archive transfer cancelled")
        })
    }

    fn finish(mut self) -> Result<()> {
        if !self.chunk.is_empty() {
            let chunk = std::mem::take(&mut self.chunk);
            self.send_chunk(chunk)?;
        }
        Ok(())
    }
}

impl Write for ChunkWriter {
    fn write(&mut self, mut input: &[u8]) -> std::io::Result<usize> {
        let input_len = input.len();
        while !input.is_empty() {
            let available = ENCRYPTION_CHUNK_SIZE - self.chunk.len();
            let copied = available.min(input.len());
            self.chunk.extend_from_slice(&input[..copied]);
            input = &input[copied..];
            if self.chunk.len() == ENCRYPTION_CHUNK_SIZE {
                let chunk =
                    std::mem::replace(&mut self.chunk, Vec::with_capacity(ENCRYPTION_CHUNK_SIZE));
                self.send_chunk(chunk)?;
            }
        }
        Ok(input_len)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::time::Duration;

    fn write(dir: &Path, rel: &str, content: &str) -> PathBuf {
        write_bytes(dir, rel, content.as_bytes())
    }

    /// Deterministic, poorly-compressible bytes. Deflate cannot shrink these,
    /// so an archive built from them still spans several chunks — which is
    /// what the streaming and backpressure assertions need.
    fn pseudo_random(seed: u64, len: usize) -> Vec<u8> {
        let mut state = seed | 1;
        let mut out = Vec::with_capacity(len);
        for _ in 0..len {
            // xorshift64
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            out.push((state >> 24) as u8);
        }
        out
    }

    fn write_bytes(dir: &Path, rel: &str, content: &[u8]) -> PathBuf {
        let path = dir.join(rel);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, content).unwrap();
        path
    }

    fn keys(entries: &[(String, PathBuf)]) -> Vec<&str> {
        entries.iter().map(|(k, _)| k.as_str()).collect()
    }

    /// Assert `name` is `<base>_<yyyymmddhhmmss>.zip`.
    fn assert_stamped_name(name: &str, base: &str) {
        let stamp = name
            .strip_prefix(&format!("{base}_"))
            .and_then(|rest| rest.strip_suffix(".zip"))
            .unwrap_or_else(|| panic!("unexpected archive name: {name}"));
        assert_eq!(stamp.len(), 14, "unexpected timestamp in {name}");
        assert!(
            stamp.bytes().all(|b| b.is_ascii_digit()),
            "unexpected timestamp in {name}"
        );
    }

    #[test]
    fn single_file_travels_deflated() {
        let dir = tempfile::tempdir().unwrap();
        let file = write(dir.path(), "report.pdf", "data");
        let source = prepare_send_source(std::slice::from_ref(&file)).unwrap();
        assert_eq!(source.file_name, "report.pdf");
        assert_eq!(source.estimated_size, 4);
        assert_eq!(source.wire_encoding, WireEncoding::DeflateRaw);
        assert_eq!(source.mime_type, "application/octet-stream");
        assert!(matches!(&source.kind, SendSourceKind::File(path) if path == &file));
    }

    #[tokio::test]
    async fn single_file_stream_is_a_raw_deflate_stream() {
        let dir = tempfile::tempdir().unwrap();
        // Highly compressible, so "the wire is shorter than the input" is a
        // real assertion rather than an accident of framing overhead.
        let plain = vec![b'z'; ENCRYPTION_CHUNK_SIZE * 3];
        let file = write_bytes(dir.path(), "big.log", &plain);
        let source = prepare_send_source(std::slice::from_ref(&file)).unwrap();

        let mut stream = source.open().await.unwrap();
        let mut wire = Vec::new();
        while let Some(chunk) = stream.next_chunk().await.unwrap() {
            assert!(!chunk.is_empty() && chunk.len() <= ENCRYPTION_CHUNK_SIZE);
            wire.extend_from_slice(&chunk);
        }

        assert!(
            wire.len() < plain.len() / 10,
            "expected the wire payload to be compressed, got {} bytes",
            wire.len()
        );

        // Raw deflate: it must inflate without a zlib header, which is what
        // the browser's DecompressionStream('deflate-raw') expects.
        let mut inflater = crate::wire::Inflater::new(MAX_MESSAGE_SIZE);
        let mut restored = Vec::new();
        restored.extend_from_slice(inflater.push(&wire).unwrap());
        restored.extend_from_slice(inflater.finish().unwrap());
        assert_eq!(restored, plain);
    }

    #[test]
    fn empty_single_file_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let file = write(dir.path(), "empty.bin", "");
        let err = prepare_send_source(&[file]).unwrap_err();
        assert!(err.to_string().contains("empty"));
    }

    #[test]
    fn one_folder_prefixes_keys_and_names_archive() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "photos/a.jpg", "a");
        write(dir.path(), "photos/albums/b.jpg", "b");
        let (entries, name) = plan_entries(&[dir.path().join("photos")]).unwrap();
        assert_stamped_name(&name, "photos");
        assert_eq!(keys(&entries), ["photos/a.jpg", "photos/albums/b.jpg"]);
    }

    #[test]
    fn loose_files_use_bare_keys() {
        let dir = tempfile::tempdir().unwrap();
        let a = write(dir.path(), "b.txt", "b");
        let b = write(dir.path(), "a.txt", "a");
        let (entries, name) = plan_entries(&[a, b]).unwrap();
        assert_stamped_name(&name, "files");
        assert_eq!(keys(&entries), ["a.txt", "b.txt"]); // sorted by key
    }

    #[test]
    fn mixed_selection_is_files_zip() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "docs/x.md", "x");
        let loose = write(dir.path(), "notes.txt", "n");
        let (entries, name) = plan_entries(&[dir.path().join("docs"), loose]).unwrap();
        assert_stamped_name(&name, "files");
        assert_eq!(keys(&entries), ["docs/x.md", "notes.txt"]);
    }

    #[test]
    fn empty_directories_are_omitted() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "proj/src/main.rs", "fn main() {}");
        fs::create_dir_all(dir.path().join("proj/empty/nested")).unwrap();
        let (entries, _) = plan_entries(&[dir.path().join("proj")]).unwrap();
        assert_eq!(keys(&entries), ["proj/src/main.rs"]);
    }

    #[test]
    fn folder_with_no_files_rejected() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("hollow/inside")).unwrap();
        let err = plan_entries(&[dir.path().join("hollow")]).unwrap_err();
        assert!(err.to_string().contains("no files"));
    }

    #[test]
    fn duplicate_keys_error() {
        let dir_a = tempfile::tempdir().unwrap();
        let dir_b = tempfile::tempdir().unwrap();
        let a = write(dir_a.path(), "same.txt", "1");
        let b = write(dir_b.path(), "same.txt", "2");
        let err = plan_entries(&[a, b]).unwrap_err();
        assert!(err.to_string().contains("same.txt"));
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_followed_for_files_skipped_for_dirs() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "root/real.txt", "real");
        write(dir.path(), "outside.txt", "out");
        fs::create_dir_all(dir.path().join("elsewhere")).unwrap();
        std::os::unix::fs::symlink(
            dir.path().join("outside.txt"),
            dir.path().join("root/link.txt"),
        )
        .unwrap();
        std::os::unix::fs::symlink(dir.path().join("elsewhere"), dir.path().join("root/loop"))
            .unwrap();
        let (entries, _) = plan_entries(&[dir.path().join("root")]).unwrap();
        assert_eq!(keys(&entries), ["root/link.txt", "root/real.txt"]);
    }

    #[tokio::test]
    async fn zip_stream_round_trips_with_forward_slash_deflated_entries() {
        let dir = tempfile::tempdir().unwrap();
        // Incompressible, so the deflated archive still spans several chunks
        // and the backpressure assertions below have something to hold.
        let a_data = pseudo_random(1, ENCRYPTION_CHUNK_SIZE * 2 + 17);
        let b_data = pseudo_random(2, ENCRYPTION_CHUNK_SIZE + 29);
        write_bytes(dir.path(), "bundle/a.bin", &a_data);
        write_bytes(dir.path(), "bundle/sub/b.bin", &b_data);
        let source = prepare_send_source(&[dir.path().join("bundle")]).unwrap();
        assert_stamped_name(&source.file_name, "bundle");
        assert_eq!(source.mime_type, "application/zip");
        assert_eq!(source.estimated_size, (a_data.len() + b_data.len()) as u64);
        assert!(source.estimated_size > (ENCRYPTION_CHUNK_SIZE * 3) as u64);
        // A ZIP is already compressed entry by entry, so it travels as-is.
        assert_eq!(source.wire_encoding, WireEncoding::Identity);

        let mut stream = source.open().await.unwrap();
        {
            let SendStream { receiver, task } = &stream;
            tokio::time::timeout(Duration::from_secs(5), async {
                while receiver.len() < 2 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("ZIP producer did not fill its bounded channel");
            assert_eq!(receiver.len(), 2);
            assert_eq!(receiver.capacity(), 0);
            assert!(!task.as_ref().unwrap().is_finished());
        }

        let first = stream.next_chunk().await.unwrap().unwrap();
        assert_eq!(first.len(), ENCRYPTION_CHUNK_SIZE);
        {
            let SendStream { receiver, task } = &stream;
            tokio::time::timeout(Duration::from_secs(5), async {
                while receiver.len() < 2 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("ZIP producer did not resume after backpressure was released");
            assert_eq!(receiver.len(), 2);
            assert_eq!(receiver.capacity(), 0);
            assert!(!task.as_ref().unwrap().is_finished());
        }

        let mut chunks = vec![first];
        while let Some(chunk) = stream.next_chunk().await.unwrap() {
            chunks.push(chunk);
        }
        assert!(chunks.len() > 3);
        assert!(
            chunks[..chunks.len() - 1]
                .iter()
                .all(|chunk| chunk.len() == ENCRYPTION_CHUNK_SIZE)
        );
        assert!(!chunks.last().unwrap().is_empty());
        assert!(chunks.last().unwrap().len() <= ENCRYPTION_CHUNK_SIZE);

        let bytes: Vec<u8> = chunks.into_iter().flatten().collect();
        // Deflate on incompressible input costs a few bytes per block, so the
        // archive is still larger than its input — the point is only that the
        // stream is intact, not that it shrank.
        assert!(bytes.len() > source.estimated_size as usize);

        let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes)).unwrap();
        assert_eq!(archive.len(), 2);
        let mut seen = Vec::new();
        for i in 0..archive.len() {
            let mut entry = archive.by_index(i).unwrap();
            assert!(!entry.is_dir());
            assert_eq!(entry.compression(), CompressionMethod::Deflated);
            let mut content = Vec::new();
            entry.read_to_end(&mut content).unwrap();
            seen.push((entry.name().to_string(), content));
        }
        seen.sort();
        assert_eq!(
            seen,
            [
                ("bundle/a.bin".to_string(), a_data),
                ("bundle/sub/b.bin".to_string(), b_data),
            ]
        );
    }

    #[tokio::test]
    async fn zip_stream_propagates_file_read_failure_and_worker_exits() {
        let dir = tempfile::tempdir().unwrap();
        let input = write(dir.path(), "bundle/unreadable.txt", "data");
        let source = prepare_send_source(&[dir.path().join("bundle")]).unwrap();
        fs::remove_file(&input).unwrap();

        let mut stream = source.open().await.unwrap();
        let consumer_error = stream.next_chunk().await.unwrap_err();
        assert!(consumer_error.to_string().contains("Cannot open"));

        let task = stream.task.take().expect("missing ZIP producer task");
        let producer_error = tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("ZIP producer did not terminate")
            .expect("ZIP producer panicked")
            .unwrap_err();
        assert!(producer_error.to_string().contains("Cannot open"));
        assert!(stream.next_chunk().await.unwrap().is_none());
    }

    #[test]
    fn zip_input_estimate_over_cap_rejected() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "big/a.bin", &"x".repeat(4096));
        write(dir.path(), "big/b.bin", "tiny");
        let err = prepare_send_source_with_cap(&[dir.path().join("big")], 64).unwrap_err();
        assert!(err.to_string().contains("exceeds"));
    }

    #[test]
    fn single_file_over_cap_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let file = write(dir.path(), "big.bin", &"x".repeat(4096));
        let err = prepare_send_source_with_cap(&[file], 64).unwrap_err();
        assert!(err.to_string().contains("exceeds"));
    }

    #[test]
    fn display_name_matches_naming_rules() {
        let dir = tempfile::tempdir().unwrap();
        let file = write(dir.path(), "solo.txt", "s");
        write(dir.path(), "photos/p.jpg", "p");
        assert_eq!(send_display_name(std::slice::from_ref(&file)), "solo.txt");
        assert_eq!(
            send_display_name(&[dir.path().join("photos")]),
            "photos.zip"
        );
        assert_eq!(
            send_display_name(&[file, dir.path().join("photos")]),
            "files.zip"
        );
    }
}
