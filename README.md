# vhsvault

Content-addressed manifests and verification for local archives.

## Why this exists

The current project fleet already covers agent frameworks, music software, games, privacy, sync, mobile, and archival tooling. `vhsvault` fills a narrower gap: a small local-first utility that can be audited in one sitting and composed with OpenShark, OpenShield, shell scripts, or other agents.

## v0 scope

- No network access.
- No external Rust dependencies.
- Deterministic output where the filesystem allows it.
- Plain text formats that can be reviewed in Git.
- Real unit tests, not placeholder stubs.

## Commands

### Create a manifest

Walk a directory, hash every file with FNV-1a 64-bit, and output a VHS1 manifest.

```sh
# Write to stdout
vhsvault create ~/archive

# Write to a file
vhsvault create ~/archive --out archive.vhs
```

### Verify against a manifest

Re-hash every file in a directory and compare against a manifest. Reports modified, missing, and extra files. Exit 0 if clean, exit 1 if differences found.

```sh
vhsvault verify archive.vhs ~/archive
```

### Diff two manifests

Compare two manifests and show added, removed, and changed entries. Exit 0 if identical, exit 1 if different.

```sh
vhsvault diff old.vhs new.vhs
```

## Manifest format

Line-oriented, versioned, human-readable. Each entry is one line:

```
VHS1|path|size|hash
```

- `VHS1` — format version identifier
- `path` — relative path from archive root, forward-slash separated
- `size` — file size in bytes (decimal)
- `hash` — FNV-1a 64-bit hash (16 hex digits)

Lines starting with `#` are comments. Blank lines are ignored. Entries are sorted by path for deterministic output.

Example:

```
# vhsvault manifest v1 (FNV-1a 64-bit)
# format: VHS1|path|size|hash
VHS1|README.txt|14|0e644a3b38dcbfb0
VHS1|docs/design.txt|19|28e5c87981357cb9
VHS1|music/sunset.txt|10|b10a26d7cdb7499b
```

## Architecture

`src/main.rs` contains the complete v0 implementation: FNV-1a hashing, manifest parsing, directory walking, pure core functions (`build_manifest`, `verify_manifest`, `diff_manifests`), CLI dispatch, and 29 unit tests. The next extraction boundary is a `core` module once the format stabilizes; until then, keeping the tape on one reel makes audits cheap.

## Roadmap

- [x] Manifest create/verify/diff
- [ ] Chunked large-file hashing
- [ ] Optional BLAKE3 backend
- [ ] Cold-storage bundle writer

## Development

```sh
cargo fmt --check
cargo test
cargo run -- --help
```

## Safety

Local commits only. Never push or create remotes without explicit instruction. Do not weaken validation to make a failing test pass.

---
Made by [synth](https://github.com/synthalorian) with synthclaw 🎹🦞
