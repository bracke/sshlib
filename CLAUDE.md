# CLAUDE.md

Guidance for AI agents working in the `ssh_lib` crate (Claude Code loads this;
other tools read the sibling `AGENTS.md`, which points here).

## What this is

`ssh_lib` is a pure Ada 2022 (Alire/GNAT) SSH client library — transport, key
exchange, userauth, channels, known_hosts, certificates, SFTP, and git-over-SSH.
Every package is `SSH_Lib.*`. It depends on `cryptolib` (primitives) and `zlib`,
and is consumed by `versionlib` / the `version` CLI. Project file: `SSH_Lib.gpr`.

Docs live in `docs/` (`SECURITY.md`, `SECURITY_REVIEW.md`, `THREAT_MODEL.md`,
`API.md`, `TESTING.md`, `RUNTIME_BOUNDARIES.md`, …). Several quote the **exact
advertised algorithm-list strings** and the security posture — keep them accurate
when you change negotiation or algorithms (the same strings also appear verbatim
in the test fixtures).

## Build, test, style

- Toolchain: use Alire GNAT 15 only. The root, tests, and tools crates require
  `gnat_native = "^15"`; validate with `alr exec -- gnatls --version`. Do not
  run plain system `gnat*`, `gnatmake`, `gnatls`, `gnatprove`, or `gprbuild`
  for this workspace, because PATH tools can bypass the enforced Alire compiler.
- Build: `alr build` (`-P SSH_Lib.gpr`).
- Unit/functional suite: `(cd tests && alr build) && ./tests/bin/main` — reports
  `Unexpected Errors: 0` / `Failed Assertions: 0`. Focused binaries also exist
  (`test_crypto_primitives`, `test_ecdsa_nistp256`, …). Test/CLI builds link
  OpenSSL (`-largs -lssl -lcrypto`).
- Style: Ada 2022, 3-space indent, 120 cols, `-gnatwa` + `-gnatVa`. **Keep
  warning-clean.** Warnings only surface when a file recompiles — after changing a
  widely-`with`ed spec, run a forced full build (`alr build -- -f`) to see them all.

## Correctness bar: match a real OpenSSH server

Compatibility means matching a real OpenSSH server on the wire, not internal
consistency. A live-test rig runs an isolated `sshd` on a nonstandard port (e.g.
2223) with a fake `$HOME`; a working transport is one that interoperates with
OpenSSH 9.x/10.x. When you touch KEX/cipher/MAC/negotiation, test across
`chacha20-poly1305@openssh.com`, `aes*-ctr` (Encrypt-then-MAC), and `aes*-gcm` —
sequence-dependent vs sequence-independent ciphers expose different bugs (if only
the seq-dependent ones fail, suspect a sequence mismatch **or a stale build**).

## Gotchas learned the hard way

- **Advertise vs recognize are two different functions.**
  `Algorithms.Default_Algorithm_List` is what the client *offers* by default;
  `Algorithms.Support_For` / `Contains_Name` is what is *recognized*/usable.
  Pruning an algorithm from the advertised list must NOT remove its recognition
  (users can re-enable it via config) and requires updating the expected-list
  constants in `tests/src/fixtures/ssh_lib-tests-fixtures-algorithm_security.adb`
  and `tests/src/ssh_lib-tests-legacy.adb`.
- **Strict kex / Terrapin (CVE-2023-48795)** is implemented: advertise
  `kex-strict-c-v00@openssh.com`; enable strict mode only when BOTH peers
  advertise their markers (checking only the server's desyncs); reset the packet
  sequence number to zero after NEWKEYS (in `Live_Transcript.Install_Protected_Keys`);
  and reject extraneous KEX messages (IGNORE/DEBUG/UNIMPLEMENTED/EXT_INFO).
- **Sequence numbers**: the cleartext handshake counter (`Clear_State`) is handed
  off to the encrypted counter (`Protected_State`) when protected keys install;
  strict kex reseeds it to 0 there instead of continuing the count.
- **Certificates**: host-cert validation (`Protocol.Certificates`) checks cert
  type, principals, validity window, critical options, and verifies the CA
  signature against the trusted `@cert-authority` key — only `@cert-authority`
  known_hosts lines are used as CAs. Do not weaken this.
- **Scrub secrets** (loaded private keys, session material) with
  `CryptoLib.Secure_Wipe` — a plain `:= [others => 0]` on a local is elided at `-O3`.
- **Repo/test infra**: this is a git repo with a single "Initial" commit and the
  entire tree uncommitted, so `git diff` cannot isolate a change. `sshd -d`/`-ddd`
  is **single-connection** (exits after one) — use it only for log capture, never
  for multi-iteration batch tests.

## When you change behavior

Update the affected `docs/` (advertised lists, threat model), the test fixtures'
expected strings, add/adjust tests, and re-run `./tests/bin/main` plus a live
handshake against the OpenSSH rig.
