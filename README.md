# molt-verify-go

A standalone Go implementation of the MOLT-CORE v1.0 Camp 1 package verifier.

## Build

```sh
go build -o molt-verify-go .
```

Go 1.23 or later. No external dependencies.

Usage

```sh
./molt-verify-go /absolute/path/to/package
```

The package directory must be absolute. The program prints exactly one JSON line:

```json
{"ok":true,"reason":null,"anchor":"none"}
```

or, on failure:

```json
{"ok":false,"check":"V-09","reason":"hash mismatch","anchor":"none"}
```

anchor is "present" only when manifest.anchor exists and is verified against the recomputed chain; otherwise it is "none".

Implementation notes

- Implements Camp 1: signed body is the five fields {seq, ts, type, payload, actor}.
- Event hash is sha256(prev_hash_hex_text || canonical_five_field_body).
- Ed25519 signs the 32 raw recomputed hash bytes, not the canonical body string.
- Canonical JSON follows the L1/RFC 8785 behavior: UTF-8 output for non-ASCII strings and object keys sorted by UTF-16 code units.
- The spec's non-ASCII canonicalization decision remains OPEN. This implementation follows the L1 reference behavior for canonicalization.
- Artifact paths must be relative, must not contain ./../empty path components or backslashes, must not traverse symlinks, and must remain inside the package root.
- The CLI emits the same V-01…V-10 check IDs and L1-compatible reason strings used by the conformance runner.
