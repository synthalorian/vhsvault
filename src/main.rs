//! vhsvault — content-addressed manifests and verification for local archives.
//!
//! v0: FNV-1a 64-bit hashing, VHS1 manifest format, create/verify/diff commands.
//! No external dependencies. Deterministic output. Fail closed.

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process;

// ---------------------------------------------------------------------------
// FNV-1a 64-bit hash
// ---------------------------------------------------------------------------

const FNV_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

/// Compute the FNV-1a 64-bit hash of a byte slice.
#[cfg(test)]
fn fnv1a_64(data: &[u8]) -> u64 {
    let mut hash = FNV_OFFSET_BASIS;
    for &byte in data {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

/// Compute the FNV-1a 64-bit hash of a file's contents, streaming in 64 KiB
/// chunks to avoid loading large files into memory.
fn fnv1a_64_file(path: &Path) -> io::Result<u64> {
    let file = fs::File::open(path)?;
    let mut reader = BufReader::with_capacity(65_536, file);
    let mut hash = FNV_OFFSET_BASIS;
    loop {
        let buf = reader.fill_buf()?;
        if buf.is_empty() {
            break;
        }
        for &byte in buf {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(FNV_PRIME);
        }
        let len = buf.len();
        reader.consume(len);
    }
    Ok(hash)
}

// ---------------------------------------------------------------------------
// Manifest types
// ---------------------------------------------------------------------------

/// A single entry in a VHS1 manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ManifestEntry {
    /// Relative path from the archive root (forward-slash separated).
    path: String,
    /// File size in bytes.
    size: u64,
    /// FNV-1a 64-bit hash of file contents.
    hash: u64,
}

impl fmt::Display for ManifestEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "VHS1|{}|{}|{:016x}", self.path, self.size, self.hash)
    }
}

/// An ordered collection of manifest entries (sorted by path).
#[derive(Debug, Clone)]
struct Manifest {
    entries: Vec<ManifestEntry>,
}

impl Manifest {
    fn new() -> Self {
        Manifest {
            entries: Vec::new(),
        }
    }

    fn push(&mut self, entry: ManifestEntry) {
        self.entries.push(entry);
    }

    /// Sort entries by path for deterministic output.
    fn sort(&mut self) {
        self.entries.sort_by(|a, b| a.path.cmp(&b.path));
    }

    /// Look up an entry by path.
    #[cfg(test)]
    fn get(&self, path: &str) -> Option<&ManifestEntry> {
        self.entries.iter().find(|e| e.path == path)
    }

    /// All paths in this manifest.
    #[cfg(test)]
    fn paths(&self) -> Vec<&str> {
        self.entries.iter().map(|e| e.path.as_str()).collect()
    }
}

impl fmt::Display for Manifest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "# vhsvault manifest v1 (FNV-1a 64-bit)")?;
        writeln!(f, "# format: VHS1|path|size|hash")?;
        for entry in &self.entries {
            writeln!(f, "{}", entry)?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Manifest parsing
// ---------------------------------------------------------------------------

/// Errors from parsing a manifest file.
#[derive(Debug)]
enum ParseError {
    Io(io::Error),
    BadVersion(String),
    BadLine(usize, String),
    BadSize(usize, String),
    BadHash(usize, String),
    EmptyPath(usize),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::Io(e) => write!(f, "I/O error: {}", e),
            ParseError::BadVersion(line) => {
                write!(f, "unsupported manifest version in line: {}", line)
            }
            ParseError::BadLine(n, line) => {
                write!(
                    f,
                    "line {}: malformed entry (expected VHS1|path|size|hash): {}",
                    n, line
                )
            }
            ParseError::BadSize(n, s) => {
                write!(f, "line {}: invalid size '{}': not a number", n, s)
            }
            ParseError::BadHash(n, s) => {
                write!(
                    f,
                    "line {}: invalid hash '{}': expected 16 hex digits",
                    n, s
                )
            }
            ParseError::EmptyPath(n) => {
                write!(f, "line {}: empty path field", n)
            }
        }
    }
}

/// Parse a manifest from a reader. Skips comments (#) and blank lines.
fn parse_manifest(reader: impl BufRead) -> Result<Manifest, ParseError> {
    let mut manifest = Manifest::new();
    let mut saw_entry = false;

    for (idx, line_result) in reader.lines().enumerate() {
        let line_num = idx + 1;
        let line = line_result.map_err(ParseError::Io)?;
        let trimmed = line.trim();

        // Skip comments and blank lines.
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let parts: Vec<&str> = trimmed.splitn(4, '|').collect();
        if parts.len() != 4 {
            return Err(ParseError::BadLine(line_num, trimmed.to_string()));
        }

        if parts[0] != "VHS1" {
            return Err(ParseError::BadVersion(trimmed.to_string()));
        }

        let path = parts[1];
        if path.is_empty() {
            return Err(ParseError::EmptyPath(line_num));
        }

        let size: u64 = parts[2]
            .parse()
            .map_err(|_| ParseError::BadSize(line_num, parts[2].to_string()))?;

        let hash = u64::from_str_radix(parts[3], 16)
            .map_err(|_| ParseError::BadHash(line_num, parts[3].to_string()))?;

        manifest.push(ManifestEntry {
            path: path.to_string(),
            size,
            hash,
        });
        saw_entry = true;
    }

    if !saw_entry {
        // An empty manifest is valid (empty directory), but let's note it.
    }

    manifest.sort();
    Ok(manifest)
}

/// Parse a manifest from a file path.
fn parse_manifest_file(path: &Path) -> Result<Manifest, ParseError> {
    let file = fs::File::open(path).map_err(ParseError::Io)?;
    parse_manifest(BufReader::new(file))
}

// ---------------------------------------------------------------------------
// Directory walking
// ---------------------------------------------------------------------------

/// Recursively collect all regular files under `root`, returning paths
/// relative to `root` with forward slashes.
fn collect_files(root: &Path) -> io::Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    collect_files_inner(root, root, &mut files)?;
    files.sort();
    Ok(files)
}

fn collect_files_inner(root: &Path, dir: &Path, files: &mut Vec<PathBuf>) -> io::Result<()> {
    let entries = fs::read_dir(dir)?;
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;

        if file_type.is_symlink() {
            // Skip symlinks in v0 — they can point outside the archive.
            continue;
        }

        if file_type.is_dir() {
            collect_files_inner(root, &path, files)?;
        } else if file_type.is_file() {
            let rel = path
                .strip_prefix(root)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
            files.push(rel.to_path_buf());
        }
        // Skip other file types (sockets, devices, etc.)
    }
    Ok(())
}

/// Convert a relative PathBuf to a forward-slash string for the manifest.
fn path_to_manifest_string(path: &Path) -> String {
    path.components()
        .map(|c| c.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

// ---------------------------------------------------------------------------
// Core operations (pure functions)
// ---------------------------------------------------------------------------

/// Build a manifest by walking `root` and hashing every regular file.
fn build_manifest(root: &Path) -> Result<Manifest, String> {
    if !root.is_dir() {
        return Err(format!("'{}' is not a directory", root.display()));
    }

    let files =
        collect_files(root).map_err(|e| format!("cannot walk '{}': {}", root.display(), e))?;

    let mut manifest = Manifest::new();
    for rel_path in &files {
        let full_path = root.join(rel_path);
        let metadata = fs::metadata(&full_path)
            .map_err(|e| format!("cannot stat '{}': {}", full_path.display(), e))?;
        let hash = fnv1a_64_file(&full_path)
            .map_err(|e| format!("cannot hash '{}': {}", full_path.display(), e))?;

        manifest.push(ManifestEntry {
            path: path_to_manifest_string(rel_path),
            size: metadata.len(),
            hash,
        });
    }

    manifest.sort();
    Ok(manifest)
}

/// Result of verifying a manifest against a directory.
#[derive(Debug)]
struct VerifyReport {
    /// Files whose hash or size changed.
    modified: Vec<ModifiedEntry>,
    /// Files in the manifest but missing from disk.
    missing: Vec<String>,
    /// Files on disk but not in the manifest.
    extra: Vec<String>,
    /// Total files checked (matched).
    ok_count: usize,
}

#[derive(Debug)]
struct ModifiedEntry {
    path: String,
    expected_size: u64,
    actual_size: u64,
    expected_hash: u64,
    actual_hash: u64,
}

impl VerifyReport {
    fn is_clean(&self) -> bool {
        self.modified.is_empty() && self.missing.is_empty() && self.extra.is_empty()
    }
}

/// Verify a manifest against a directory tree.
fn verify_manifest(manifest: &Manifest, root: &Path) -> Result<VerifyReport, String> {
    if !root.is_dir() {
        return Err(format!("'{}' is not a directory", root.display()));
    }

    let disk_files =
        collect_files(root).map_err(|e| format!("cannot walk '{}': {}", root.display(), e))?;

    let disk_map: BTreeMap<String, &PathBuf> = disk_files
        .iter()
        .map(|p| (path_to_manifest_string(p), p))
        .collect();

    let mut report = VerifyReport {
        modified: Vec::new(),
        missing: Vec::new(),
        extra: Vec::new(),
        ok_count: 0,
    };

    // Check manifest entries against disk.
    for entry in &manifest.entries {
        match disk_map.get(entry.path.as_str()) {
            Some(rel_path) => {
                let full_path = root.join(rel_path);
                let metadata = fs::metadata(&full_path)
                    .map_err(|e| format!("cannot stat '{}': {}", full_path.display(), e))?;
                let actual_size = metadata.len();
                let actual_hash = fnv1a_64_file(&full_path)
                    .map_err(|e| format!("cannot hash '{}': {}", full_path.display(), e))?;

                if actual_size != entry.size || actual_hash != entry.hash {
                    report.modified.push(ModifiedEntry {
                        path: entry.path.clone(),
                        expected_size: entry.size,
                        actual_size,
                        expected_hash: entry.hash,
                        actual_hash,
                    });
                } else {
                    report.ok_count += 1;
                }
            }
            None => {
                report.missing.push(entry.path.clone());
            }
        }
    }

    // Check for extra files on disk.
    let manifest_paths: std::collections::BTreeSet<&str> =
        manifest.entries.iter().map(|e| e.path.as_str()).collect();
    for disk_path_str in disk_map.keys() {
        if !manifest_paths.contains(disk_path_str.as_str()) {
            report.extra.push(disk_path_str.clone());
        }
    }

    Ok(report)
}

/// Result of diffing two manifests.
#[derive(Debug)]
struct DiffReport {
    /// Entries only in the first manifest.
    only_in_first: Vec<ManifestEntry>,
    /// Entries only in the second manifest.
    only_in_second: Vec<ManifestEntry>,
    /// Entries in both but with different size or hash.
    changed: Vec<DiffChanged>,
    /// Entries identical in both.
    unchanged_count: usize,
}

#[derive(Debug)]
struct DiffChanged {
    path: String,
    first_size: u64,
    first_hash: u64,
    second_size: u64,
    second_hash: u64,
}

/// Diff two manifests.
fn diff_manifests(first: &Manifest, second: &Manifest) -> DiffReport {
    let first_map: BTreeMap<&str, &ManifestEntry> =
        first.entries.iter().map(|e| (e.path.as_str(), e)).collect();
    let second_map: BTreeMap<&str, &ManifestEntry> = second
        .entries
        .iter()
        .map(|e| (e.path.as_str(), e))
        .collect();

    let mut report = DiffReport {
        only_in_first: Vec::new(),
        only_in_second: Vec::new(),
        changed: Vec::new(),
        unchanged_count: 0,
    };

    for (path, entry) in &first_map {
        match second_map.get(path) {
            Some(other) => {
                if entry.size != other.size || entry.hash != other.hash {
                    report.changed.push(DiffChanged {
                        path: path.to_string(),
                        first_size: entry.size,
                        first_hash: entry.hash,
                        second_size: other.size,
                        second_hash: other.hash,
                    });
                } else {
                    report.unchanged_count += 1;
                }
            }
            None => {
                report.only_in_first.push((*entry).clone());
            }
        }
    }

    for (path, entry) in &second_map {
        if !first_map.contains_key(path) {
            report.only_in_second.push((*entry).clone());
        }
    }

    report
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

const USAGE: &str = "\
vhsvault — content-addressed manifests for local archives

USAGE:
    vhsvault create <dir> [--out <file>]
    vhsvault verify <manifest> <dir>
    vhsvault diff <manifest1> <manifest2>
    vhsvault --help

COMMANDS:
    create   Walk a directory, hash every file, output a VHS1 manifest
    verify   Re-hash a directory and compare against a manifest
    diff     Show what changed between two manifests

OPTIONS:
    --out <file>   Write manifest to file instead of stdout (create only)
    --help         Show this help message

MANIFEST FORMAT:
    Line-oriented, versioned, human-readable.
    Each entry: VHS1|path|size|hash
    Lines starting with # are comments.

EXAMPLES:
    vhsvault create ~/archive --out archive.vhs
    vhsvault create ~/archive > archive.vhs
    vhsvault verify archive.vhs ~/archive
    vhsvault diff old.vhs new.vhs

EXIT CODES:
    0   Success (verify: no differences found)
    1   Error or verification/diff found differences

Made by synth with synthclaw 🎹🦞";

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        eprintln!("{}", USAGE);
        process::exit(1);
    }

    match args[1].as_str() {
        "--help" | "-h" | "help" => {
            println!("{}", USAGE);
        }
        "create" => cmd_create(&args[2..]),
        "verify" => cmd_verify(&args[2..]),
        "diff" => cmd_diff(&args[2..]),
        unknown => {
            eprintln!("error: unknown command '{}'\n", unknown);
            eprintln!("{}", USAGE);
            process::exit(1);
        }
    }
}

fn cmd_create(args: &[String]) {
    let mut dir: Option<&str> = None;
    let mut out_file: Option<&str> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--out" => {
                if i + 1 >= args.len() {
                    eprintln!("error: --out requires a file path");
                    process::exit(1);
                }
                out_file = Some(&args[i + 1]);
                i += 2;
            }
            "--help" | "-h" => {
                println!("Usage: vhsvault create <dir> [--out <file>]");
                println!();
                println!("Walk <dir>, hash every regular file with FNV-1a 64-bit,");
                println!("and output a VHS1 manifest (sorted, deterministic).");
                println!();
                println!("If --out is given, write to that file. Otherwise write to stdout.");
                process::exit(0);
            }
            s if s.starts_with('-') => {
                eprintln!("error: unknown flag '{}'", s);
                process::exit(1);
            }
            s => {
                if dir.is_some() {
                    eprintln!(
                        "error: unexpected argument '{}' (create takes one directory)",
                        s
                    );
                    process::exit(1);
                }
                dir = Some(s);
                i += 1;
            }
        }
    }

    let dir = match dir {
        Some(d) => d,
        None => {
            eprintln!("error: create requires a directory argument");
            eprintln!("usage: vhsvault create <dir> [--out <file>]");
            process::exit(1);
        }
    };

    let root = Path::new(dir);
    let manifest = match build_manifest(root) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("error: {}", e);
            process::exit(1);
        }
    };

    let output = format!("{}", manifest);

    match out_file {
        Some(path) => {
            if let Err(e) = fs::write(path, &output) {
                eprintln!("error: cannot write '{}': {}", path, e);
                process::exit(1);
            }
            eprintln!(
                "vhsvault: wrote {} entries to {}",
                manifest.entries.len(),
                path
            );
        }
        None => {
            let stdout = io::stdout();
            let mut handle = stdout.lock();
            if let Err(e) = handle.write_all(output.as_bytes()) {
                eprintln!("error: cannot write to stdout: {}", e);
                process::exit(1);
            }
        }
    }
}

fn cmd_verify(args: &[String]) {
    let mut positional: Vec<&str> = Vec::new();

    for arg in args {
        match arg.as_str() {
            "--help" | "-h" => {
                println!("Usage: vhsvault verify <manifest> <dir>");
                println!();
                println!("Re-hash every file in <dir> and compare against <manifest>.");
                println!("Reports modified, missing, and extra files.");
                println!();
                println!("Exit 0 if everything matches. Exit 1 if differences are found.");
                process::exit(0);
            }
            s if s.starts_with('-') => {
                eprintln!("error: unknown flag '{}'", s);
                process::exit(1);
            }
            s => positional.push(s),
        }
    }

    if positional.len() != 2 {
        eprintln!("error: verify requires exactly 2 arguments: <manifest> <dir>");
        eprintln!("usage: vhsvault verify <manifest> <dir>");
        process::exit(1);
    }

    let manifest_path = Path::new(positional[0]);
    let dir = Path::new(positional[1]);

    let manifest = match parse_manifest_file(manifest_path) {
        Ok(m) => m,
        Err(e) => {
            eprintln!(
                "error: cannot parse manifest '{}': {}",
                manifest_path.display(),
                e
            );
            process::exit(1);
        }
    };

    let report = match verify_manifest(&manifest, dir) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: {}", e);
            process::exit(1);
        }
    };

    if report.is_clean() {
        println!(
            "vhsvault: OK — {} files verified, 0 differences",
            report.ok_count
        );
    } else {
        if !report.modified.is_empty() {
            println!("MODIFIED ({}):", report.modified.len());
            for m in &report.modified {
                println!(
                    "  {} (size {}→{}, hash {:016x}→{:016x})",
                    m.path, m.expected_size, m.actual_size, m.expected_hash, m.actual_hash
                );
            }
        }
        if !report.missing.is_empty() {
            println!("MISSING ({}):", report.missing.len());
            for p in &report.missing {
                println!("  {}", p);
            }
        }
        if !report.extra.is_empty() {
            println!("EXTRA ({}):", report.extra.len());
            for p in &report.extra {
                println!("  {}", p);
            }
        }
        println!(
            "vhsvault: FAIL — {} ok, {} modified, {} missing, {} extra",
            report.ok_count,
            report.modified.len(),
            report.missing.len(),
            report.extra.len()
        );
        process::exit(1);
    }
}

fn cmd_diff(args: &[String]) {
    let mut positional: Vec<&str> = Vec::new();

    for arg in args {
        match arg.as_str() {
            "--help" | "-h" => {
                println!("Usage: vhsvault diff <manifest1> <manifest2>");
                println!();
                println!("Compare two manifests and show what changed.");
                println!("Reports added, removed, and modified entries.");
                println!();
                println!("Exit 0 if identical. Exit 1 if differences are found.");
                process::exit(0);
            }
            s if s.starts_with('-') => {
                eprintln!("error: unknown flag '{}'", s);
                process::exit(1);
            }
            s => positional.push(s),
        }
    }

    if positional.len() != 2 {
        eprintln!("error: diff requires exactly 2 arguments: <manifest1> <manifest2>");
        eprintln!("usage: vhsvault diff <manifest1> <manifest2>");
        process::exit(1);
    }

    let first = match parse_manifest_file(Path::new(positional[0])) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("error: cannot parse '{}': {}", positional[0], e);
            process::exit(1);
        }
    };

    let second = match parse_manifest_file(Path::new(positional[1])) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("error: cannot parse '{}': {}", positional[1], e);
            process::exit(1);
        }
    };

    let report = diff_manifests(&first, &second);

    let has_differences = !report.only_in_first.is_empty()
        || !report.only_in_second.is_empty()
        || !report.changed.is_empty();

    if !has_differences {
        println!(
            "vhsvault: identical — {} entries match",
            report.unchanged_count
        );
    } else {
        if !report.only_in_first.is_empty() {
            println!("REMOVED ({}):", report.only_in_first.len());
            for e in &report.only_in_first {
                println!("  {} ({} bytes, {:016x})", e.path, e.size, e.hash);
            }
        }
        if !report.only_in_second.is_empty() {
            println!("ADDED ({}):", report.only_in_second.len());
            for e in &report.only_in_second {
                println!("  {} ({} bytes, {:016x})", e.path, e.size, e.hash);
            }
        }
        if !report.changed.is_empty() {
            println!("CHANGED ({}):", report.changed.len());
            for c in &report.changed {
                println!(
                    "  {} (size {}→{}, hash {:016x}→{:016x})",
                    c.path, c.first_size, c.second_size, c.first_hash, c.second_hash
                );
            }
        }
        println!(
            "vhsvault: {} unchanged, {} removed, {} added, {} changed",
            report.unchanged_count,
            report.only_in_first.len(),
            report.only_in_second.len(),
            report.changed.len()
        );
        process::exit(1);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    /// Create a unique temporary directory with test files.
    fn setup_test_dir() -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("vhsvault-test-{}-{}", process::id(), id));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("sub")).unwrap();
        fs::write(dir.join("hello.txt"), b"hello world").unwrap();
        fs::write(dir.join("sub/nested.txt"), b"nested file content").unwrap();
        fs::write(dir.join("empty.bin"), b"").unwrap();
        dir
    }

    fn cleanup(dir: &Path) {
        let _ = fs::remove_dir_all(dir);
    }

    // -- FNV-1a tests --

    #[test]
    fn fnv1a_empty() {
        assert_eq!(fnv1a_64(b""), FNV_OFFSET_BASIS);
    }

    #[test]
    fn fnv1a_known_values() {
        // FNV-1a 64-bit test vectors from the FNV reference.
        assert_eq!(fnv1a_64(b"a"), 0xaf63_dc4c_8601_ec8c);
        assert_eq!(fnv1a_64(b"foobar"), 0x8594_4171_f739_67e8);
    }

    #[test]
    fn fnv1a_deterministic() {
        let data = b"the quick brown fox jumps over the lazy dog";
        assert_eq!(fnv1a_64(data), fnv1a_64(data));
    }

    // -- Manifest format tests --

    #[test]
    fn manifest_entry_display() {
        let entry = ManifestEntry {
            path: "foo/bar.txt".to_string(),
            size: 42,
            hash: 0x0123_4567_89ab_cdef,
        };
        assert_eq!(format!("{}", entry), "VHS1|foo/bar.txt|42|0123456789abcdef");
    }

    #[test]
    fn manifest_display_has_header() {
        let mut m = Manifest::new();
        m.push(ManifestEntry {
            path: "a.txt".to_string(),
            size: 1,
            hash: 0,
        });
        let output = format!("{}", m);
        assert!(output.starts_with("# vhsvault manifest v1"));
        assert!(output.contains("VHS1|a.txt|1|0000000000000000"));
    }

    // -- Parse tests --

    #[test]
    fn parse_valid_manifest() {
        let input = "# comment\nVHS1|a.txt|5|af63dc4c8601ec8c\n\nVHS1|b.txt|0|cbf29ce484222325\n";
        let m = parse_manifest(BufReader::new(input.as_bytes())).unwrap();
        assert_eq!(m.entries.len(), 2);
        assert_eq!(m.entries[0].path, "a.txt");
        assert_eq!(m.entries[0].size, 5);
        assert_eq!(m.entries[0].hash, 0xaf63_dc4c_8601_ec8c);
        assert_eq!(m.entries[1].path, "b.txt");
    }

    #[test]
    fn parse_rejects_bad_version() {
        let input = "VHS2|a.txt|5|af63dc4c8601ec8c\n";
        let err = parse_manifest(BufReader::new(input.as_bytes())).unwrap_err();
        assert!(matches!(err, ParseError::BadVersion(_)));
    }

    #[test]
    fn parse_rejects_malformed_line() {
        let input = "VHS1|a.txt|5\n"; // missing hash field
        let err = parse_manifest(BufReader::new(input.as_bytes())).unwrap_err();
        assert!(matches!(err, ParseError::BadLine(1, _)));
    }

    #[test]
    fn parse_rejects_bad_size() {
        let input = "VHS1|a.txt|abc|af63dc4c8601ec8c\n";
        let err = parse_manifest(BufReader::new(input.as_bytes())).unwrap_err();
        assert!(matches!(err, ParseError::BadSize(1, _)));
    }

    #[test]
    fn parse_rejects_bad_hash() {
        let input = "VHS1|a.txt|5|nothex\n";
        let err = parse_manifest(BufReader::new(input.as_bytes())).unwrap_err();
        assert!(matches!(err, ParseError::BadHash(1, _)));
    }

    #[test]
    fn parse_rejects_empty_path() {
        let input = "VHS1||5|af63dc4c8601ec8c\n";
        let err = parse_manifest(BufReader::new(input.as_bytes())).unwrap_err();
        assert!(matches!(err, ParseError::EmptyPath(1)));
    }

    #[test]
    fn parse_skips_comments_and_blanks() {
        let input = "# header\n\n# another comment\nVHS1|x|1|0000000000000001\n";
        let m = parse_manifest(BufReader::new(input.as_bytes())).unwrap();
        assert_eq!(m.entries.len(), 1);
    }

    #[test]
    fn parse_empty_manifest() {
        let input = "# only comments\n\n";
        let m = parse_manifest(BufReader::new(input.as_bytes())).unwrap();
        assert_eq!(m.entries.len(), 0);
    }

    // -- Roundtrip test --

    #[test]
    fn manifest_roundtrip() {
        let mut original = Manifest::new();
        original.push(ManifestEntry {
            path: "deep/nested/file.txt".to_string(),
            size: 12345,
            hash: 0xdead_beef_cafe_f00d,
        });
        original.push(ManifestEntry {
            path: "top.txt".to_string(),
            size: 0,
            hash: 0,
        });
        original.sort();

        let serialized = format!("{}", original);
        let parsed = parse_manifest(BufReader::new(serialized.as_bytes())).unwrap();

        assert_eq!(original.entries, parsed.entries);
    }

    // -- build_manifest tests --

    #[test]
    fn build_manifest_finds_all_files() {
        let dir = setup_test_dir();
        let m = build_manifest(&dir).unwrap();
        assert_eq!(m.entries.len(), 3);

        let paths = m.paths();
        assert!(paths.contains(&"hello.txt"));
        assert!(paths.contains(&"sub/nested.txt"));
        assert!(paths.contains(&"empty.bin"));

        cleanup(&dir);
    }

    #[test]
    fn build_manifest_deterministic() {
        let dir = setup_test_dir();
        let m1 = build_manifest(&dir).unwrap();
        let m2 = build_manifest(&dir).unwrap();
        assert_eq!(format!("{}", m1), format!("{}", m2));
        cleanup(&dir);
    }

    #[test]
    fn build_manifest_rejects_nonexistent_dir() {
        let result = build_manifest(Path::new("/nonexistent/path/that/does/not/exist"));
        assert!(result.is_err());
    }

    #[test]
    fn build_manifest_correct_hashes() {
        let dir = setup_test_dir();
        let m = build_manifest(&dir).unwrap();

        let hello = m.get("hello.txt").unwrap();
        assert_eq!(hello.size, 11);
        assert_eq!(hello.hash, fnv1a_64(b"hello world"));

        let empty = m.get("empty.bin").unwrap();
        assert_eq!(empty.size, 0);
        assert_eq!(empty.hash, FNV_OFFSET_BASIS);

        cleanup(&dir);
    }

    // -- verify tests --

    #[test]
    fn verify_clean_directory() {
        let dir = setup_test_dir();
        let manifest = build_manifest(&dir).unwrap();
        let report = verify_manifest(&manifest, &dir).unwrap();
        assert!(report.is_clean());
        assert_eq!(report.ok_count, 3);
        cleanup(&dir);
    }

    #[test]
    fn verify_detects_modification() {
        let dir = setup_test_dir();
        let manifest = build_manifest(&dir).unwrap();

        // Modify a file.
        fs::write(dir.join("hello.txt"), b"tampered content").unwrap();

        let report = verify_manifest(&manifest, &dir).unwrap();
        assert!(!report.is_clean());
        assert_eq!(report.modified.len(), 1);
        assert_eq!(report.modified[0].path, "hello.txt");
        assert_eq!(report.missing.len(), 0);
        assert_eq!(report.extra.len(), 0);

        cleanup(&dir);
    }

    #[test]
    fn verify_detects_missing_file() {
        let dir = setup_test_dir();
        let manifest = build_manifest(&dir).unwrap();

        fs::remove_file(dir.join("sub/nested.txt")).unwrap();

        let report = verify_manifest(&manifest, &dir).unwrap();
        assert!(!report.is_clean());
        assert_eq!(report.missing.len(), 1);
        assert_eq!(report.missing[0], "sub/nested.txt");

        cleanup(&dir);
    }

    #[test]
    fn verify_detects_extra_file() {
        let dir = setup_test_dir();
        let manifest = build_manifest(&dir).unwrap();

        fs::write(dir.join("extra.txt"), b"unexpected").unwrap();

        let report = verify_manifest(&manifest, &dir).unwrap();
        assert!(!report.is_clean());
        assert_eq!(report.extra.len(), 1);
        assert_eq!(report.extra[0], "extra.txt");

        cleanup(&dir);
    }

    // -- diff tests --

    #[test]
    fn diff_identical_manifests() {
        let dir = setup_test_dir();
        let m1 = build_manifest(&dir).unwrap();
        let m2 = build_manifest(&dir).unwrap();

        let report = diff_manifests(&m1, &m2);
        assert!(report.only_in_first.is_empty());
        assert!(report.only_in_second.is_empty());
        assert!(report.changed.is_empty());
        assert_eq!(report.unchanged_count, 3);

        cleanup(&dir);
    }

    #[test]
    fn diff_detects_added_file() {
        let dir = setup_test_dir();
        let m1 = build_manifest(&dir).unwrap();

        fs::write(dir.join("new.txt"), b"brand new").unwrap();
        let m2 = build_manifest(&dir).unwrap();

        let report = diff_manifests(&m1, &m2);
        assert!(report.only_in_first.is_empty());
        assert_eq!(report.only_in_second.len(), 1);
        assert_eq!(report.only_in_second[0].path, "new.txt");

        cleanup(&dir);
    }

    #[test]
    fn diff_detects_removed_file() {
        let dir = setup_test_dir();
        let m1 = build_manifest(&dir).unwrap();

        fs::remove_file(dir.join("hello.txt")).unwrap();
        let m2 = build_manifest(&dir).unwrap();

        let report = diff_manifests(&m1, &m2);
        assert_eq!(report.only_in_first.len(), 1);
        assert_eq!(report.only_in_first[0].path, "hello.txt");
        assert!(report.only_in_second.is_empty());

        cleanup(&dir);
    }

    #[test]
    fn diff_detects_changed_file() {
        let dir = setup_test_dir();
        let m1 = build_manifest(&dir).unwrap();

        fs::write(dir.join("hello.txt"), b"modified content here").unwrap();
        let m2 = build_manifest(&dir).unwrap();

        let report = diff_manifests(&m1, &m2);
        assert!(report.only_in_first.is_empty());
        assert!(report.only_in_second.is_empty());
        assert_eq!(report.changed.len(), 1);
        assert_eq!(report.changed[0].path, "hello.txt");

        cleanup(&dir);
    }

    // -- path_to_manifest_string tests --

    #[test]
    fn path_conversion_uses_forward_slashes() {
        let p = PathBuf::from("sub").join("nested").join("file.txt");
        assert_eq!(path_to_manifest_string(&p), "sub/nested/file.txt");
    }

    // -- Manifest lookup tests --

    #[test]
    fn manifest_get_finds_entry() {
        let mut m = Manifest::new();
        m.push(ManifestEntry {
            path: "a.txt".to_string(),
            size: 10,
            hash: 42,
        });
        assert!(m.get("a.txt").is_some());
        assert!(m.get("nonexistent").is_none());
    }

    #[test]
    fn manifest_sorted_output() {
        let mut m = Manifest::new();
        m.push(ManifestEntry {
            path: "z.txt".to_string(),
            size: 1,
            hash: 0,
        });
        m.push(ManifestEntry {
            path: "a.txt".to_string(),
            size: 1,
            hash: 0,
        });
        m.sort();
        assert_eq!(m.entries[0].path, "a.txt");
        assert_eq!(m.entries[1].path, "z.txt");
    }
}
