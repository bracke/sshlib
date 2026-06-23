# SFTP packet fuzzer seeds

Root-level `.bin` files target the version parser for backward-compatible one-argument harness runs. Subdirectories are named after harness modes and exercise packet-level reply parsers:

- `status`
- `handle`
- `data`
- `attrs-v3`
- `attrs-v6`
- `name-v3`
- `name-v6`
- `extended`
- `check-file`
- `limits`
- `statvfs`

Run all deterministic seeds with `../ssh_lib_build/bin/tools/run_sftp_fuzzer_seed_corpus`.
