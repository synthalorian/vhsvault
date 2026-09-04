# vhsvault design

## Principle

Small surface, sharp edge. `vhsvault` starts as a dependency-free Rust binary with pure functions separated from CLI effects.

## Failure policy

Fail closed. Invalid input returns a precise error and a non-zero exit code. Mutating commands require explicit flags.

## Format policy

Formats are line-oriented, versioned, and human-readable. Add fields only at the end or bump the format version.
