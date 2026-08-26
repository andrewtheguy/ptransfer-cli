//! Small shared helpers: byte formatting, progress math, interrupt detection,
//! destination-filename sanitizing, and output path selection.

use std::path::{Path, PathBuf};

use anyhow::Result;

use crate::ui::{FileExistsChoice, prompt_file_exists};

/// Format a byte count as a human-readable string (e.g. `1.5 MB`).
pub fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} {}", UNITS[0])
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

/// Percentage of `bytes` out of `total`, clamped to `0..=100`.
pub fn calc_percent(bytes: u64, total: u64) -> f64 {
    if total == 0 {
        return 100.0;
    }
    ((bytes as f64 / total as f64) * 100.0).clamp(0.0, 100.0)
}

/// Whether an error originated from a user interrupt (Ctrl+C), so the process
/// can exit with the conventional code 130.
pub fn is_interrupted(err: &anyhow::Error) -> bool {
    err.chain().any(|e| {
        let s = e.to_string();
        s == "Interrupted" || s == "Cancelled"
    })
}

/// Reduce an untrusted, peer-supplied file name to a safe basename with no path
/// separators or traversal, falling back to `received.bin` if empty.
pub fn sanitize_filename(name: &str) -> String {
    let base = name
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(name)
        .trim()
        .trim_matches('.');
    if base.is_empty() || base == "." || base == ".." {
        "received.bin".to_string()
    } else {
        base.to_string()
    }
}

/// Policy for an already-existing destination file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnConflict {
    /// Ask the user (TUI modal, or plain o/r/c prompt in non-interactive mode).
    Prompt,
    /// Error out (non-interactive test mode without --overwrite).
    Fail,
    /// Replace the existing file (test mode with --overwrite).
    Overwrite,
}

/// Choose the output path for a received file, applying `on_conflict` if it
/// already exists. Returns `Ok(None)` if the user cancels.
pub async fn resolve_destination(
    output_dir: Option<PathBuf>,
    file_name: &str,
    on_conflict: OnConflict,
) -> Result<Option<PathBuf>> {
    let dir = output_dir.unwrap_or_else(|| PathBuf::from("."));
    let safe = sanitize_filename(file_name);
    let path = dir.join(&safe);

    if !path.exists() {
        return Ok(Some(path));
    }

    let choice = match on_conflict {
        OnConflict::Prompt => prompt_file_exists(&path).await?,
        OnConflict::Fail => anyhow::bail!(
            "Destination exists: {} (use --overwrite to replace)",
            path.display()
        ),
        OnConflict::Overwrite => FileExistsChoice::Overwrite,
    };
    match choice {
        FileExistsChoice::Overwrite => Ok(Some(path)),
        FileExistsChoice::Rename => Ok(Some(unique_path(&dir, &safe))),
        FileExistsChoice::Cancel => Ok(None),
    }
}

fn unique_path(dir: &Path, file_name: &str) -> PathBuf {
    let (stem, ext) = match file_name.rsplit_once('.') {
        Some((s, e)) if !s.is_empty() => (s.to_string(), format!(".{e}")),
        _ => (file_name.to_string(), String::new()),
    };
    for n in 1.. {
        let candidate = dir.join(format!("{stem} ({n}){ext}"));
        if !candidate.exists() {
            return candidate;
        }
    }
    unreachable!("infinite range yields a free name")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_bytes() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1536), "1.5 KB");
        assert_eq!(format_bytes(5 * 1024 * 1024), "5.0 MB");
    }

    #[test]
    fn sanitizes_paths() {
        assert_eq!(sanitize_filename("../../etc/passwd"), "passwd");
        assert_eq!(sanitize_filename("a/b/c.txt"), "c.txt");
        assert_eq!(sanitize_filename(r"C:\Windows\x.dll"), "x.dll");
        assert_eq!(sanitize_filename("   "), "received.bin");
        assert_eq!(sanitize_filename(".."), "received.bin");
    }
}
