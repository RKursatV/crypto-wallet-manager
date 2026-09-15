# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- PyPI publishing workflow (Trusted Publishing, runs on GitHub release).
- Project URLs in the package metadata.

## [0.1.0] - 2026-09-15

First public release.

### Added
- `wallet-manager` console script (`pip install .`), `--version` flag.
- Keystore format v3: the tamper seal now covers every wallet record
  including its ciphertext, so secrets cannot be swapped between wallets.
  A missing seal is treated as tampering.
- Clear errors for unreadable, malformed, or unsupported keystore files and
  for a corrupt encrypted secret (no tracebacks).
- Test suite (pytest) with BIP39/BIP44/BIP84 known-answer vectors, tamper
  and malformed-file cases, and mocked balance lookups; GitHub Actions CI on
  Python 3.10–3.13 including a wheel build + CLI smoke test.

### Changed
- scrypt cost raised to the OWASP minimum (N=2¹⁷, r=8, p=1, ~128 MiB).
  `change-password` re-derives with the current parameters and a fresh salt.
- Imported recovery phrases and private keys are normalised before storage
  (whitespace/case collapsed, `0x` prefix stripped).
- Keystore writes are fsync'd before the atomic rename.
- `balance` exits non-zero when any lookup fails.
- Pre-release keystore formats (v1, v2) are no longer read; recreate the
  keystore by importing each wallet from its recovery phrase.

### Fixed
- `import --eth-private-key` crashed with a `TypeError` on every input.
- `export` of an imported private key printed `0x0x…` when the key had been
  entered with a `0x` prefix.
- `change-password` skipped the short-password warning and did not rotate
  the KDF parameters.
