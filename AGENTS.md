# AGENTS.md

Guidance for AI agents working in the `ssh_lib` crate. **This file is the
canonical copy** and applies to every AI coding tool; `CLAUDE.md` imports it so
Claude Code sees the same text. Edit this file, not that one.

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
- Unit/functional suite: `(cd tests && alr build) && ./tests/bin/main` — AUnit;
  reports `Unexpected Errors: 0` / `Failed Assertions: 0`. Focused binaries also
  exist (`test_crypto_primitives`, `test_ecdsa_nistp256`, …).
- **The main suite is not the whole suite.** Five further crates live under
  `tests/`, each with its own manifest and each built separately:
  `security/`, `fuzz/`, `api_stability/`, `package_smoke/` and
  `version_integration/`. A green `tests/bin/main` says nothing about them.
- **Nothing here links OpenSSL.** `ssh_lib` and `cryptolib` are pure Ada. The
  `-lssl -lcrypto` switches were removed as dead: they linked on Linux only
  because the libraries happened to be present, and Windows — which has
  neither — could not link the tests at all. Do not reintroduce them.
- Style: Ada 2022, 3-space indent, 120 cols. **Keep warning-clean.** Warnings
  only surface when a file recompiles — after changing a widely-`with`ed spec,
  run a forced full build (`alr build -- -f`) to see them all.
- **Which switches you get depends on the Alire build profile, not on the
  `.gpr` files.** Reading `SSH_Lib.gpr` alone is misleading: it names `-gnata`
  (assertions and contracts) and `-gnatVa`, and no `-gnatwa` — but `-gnatwa`
  arrives anyway, from the generated `config/ssh_lib_config.gpr`, which Alire
  rewrites on every build. `alire.toml` pins `"*" = "development"`, so an
  ordinary `alr build` compiles with `-gnatwa`, `-gnatVa` and the full `-gnaty`
  set. A `--release` build has none of them at all.
- `alr build --validation -- -f` adds `-gnatwe`, which turns every warning and
  style breach into an error. **Both the library and the suite are clean under
  it**, and should stay that way — run it before proposing a change:

  ```sh
  alr build --validation -- -f
  (cd tests && alr build --validation -- -f)
  ```

  One qualification: `ssh_lib-tests-legacy.adb` turns off the useless-assignment
  warning for itself, with the reason written at the top of the body. Those
  tests call an operation for its status alone and the out value is genuinely
  unobservable — `Session` is limited private to `SSH_Lib.Sessions` and the test
  is a sibling child, and `Close` is idempotent — so there is nothing to assert.
  That is a narrower suppression than a project switch, and it is the only one.
- The auxiliary crates (`tools/`, `tests/security`, `tests/fuzz`,
  `tests/api_stability`, `tests/package_smoke`, `tests/version_integration`,
  `examples/`) additionally name `-gnatwa` in their own project files, most
  with `-gnatwe`.

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
- **Test infra**: `sshd -d`/`-ddd` is **single-connection** (it exits after one)
  — use it only for log capture, never for multi-iteration batch tests.

## When you change behavior

Update the affected `docs/` (advertised lists, threat model), the test fixtures'
expected strings, add/adjust tests, and re-run `./tests/bin/main` plus a live
handshake against the OpenSSH rig.
