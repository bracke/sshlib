# Ada SSH 0.1.0 Release Notes

This release is the first release-readiness baseline for consuming SSH_Lib as an Alire dependency from `version`.

## Implemented

- Deterministic local SSH session fixture path with fail-closed public-runtime gates.
- Strict known_hosts verification by default.
- ssh-agent transport/client support plus identity-file parsing and public identity loading.
- Protected channel-boundary fixture coverage with binary `Ada.Streams.Stream_Element_Array` read/write APIs.
- Safe Git upload-pack and receive-pack command helpers.
- Git SSH remote-name parsing.
- Basic OpenSSH-style config resolution for Git-over-SSH use.
- Timeout, cancellation, and deterministic failure hygiene.
- Ada-only deterministic local fixture tests.
- API stability, packaging, examples, and release guard scaffolding.

## Still unsupported or not yet implemented

- Passphrase callback authentication.
- Password callback authentication.
- ProxyJump and ProxyCommand.
- Trust-on-first-use or add-known-host workflow.
- PTY, port forwarding, X11 forwarding. SFTP, SCP, and high-level file upload APIs are now in scope but not implemented yet.
- Git pkt-line parsing, packfile parsing, repository logic, or credential storage.
- Subprocess ssh fallback.
- C code or C bindings.

## Verification

Use the documented release sequence in `docs/TESTING.md`. The default suite is local and deterministic.

## Phase 17 completeness pass 2

- Added `docs/VERSION_INTEGRATION.md` to freeze the `version` consumer contract.
- Added `tools/check_release_manifest.adb` to guard public library interfaces, consumer call-shape coverage, package-smoke presence, and Version integration documentation.
- Strengthened package-tree checks for special files.
- Expanded public API guard coverage for all required status literals and core helper entry points.

## Phase 18 Integration Readiness

Phase 18 documents and compile-checks the intended `version -> SSH_Lib` consumption path. SSH_Lib remains a byte-transport library: Git pkt-line, packfile, refs, object database, credential storage, and working-tree behavior remain outside the crate.

## Phase 18 completeness pass 3

This pass closes the remaining integration-consumption gaps for `version`: explicit remote user/default-user precedence is covered, upload-pack and receive-pack flows are fixture-tested, and the local fixture example now keeps the public byte-stream call shape compile-checked without contacting the network by default.

## Phase 18 completeness pass 4

The Phase 18 integration checks now include explicit local status-mapping assertions for the SSH failures that version needs to report deterministically.


## Phase 18 completeness pass 5

The Phase 18 version-integration adapter shape and local fixture example have been tightened for warning-clean compilation under the crate's release compiler switches. No network behavior, Git protocol parsing, subprocess fallback, or public API breakage was introduced.

Phase 18 completeness pass 6 preserves the no-subprocess boundary by making matching unsupported SSH config dependencies fail deterministically as `Unsupported_Feature` during version transport preparation.

Phase 18 completeness pass 7 keeps integration checks deterministic by avoiding real user SSH config in default compile-shape tests.

### Phase 18 completeness pass 8

The optional manual upload-pack probe now demonstrates the full byte-stream lifecycle using `Ada.Streams.Stream_Element_Array`, keeps host-key verification enabled, requires explicit known-host/authentication setup, and prints only aggregate byte counts rather than raw Git protocol data. It remains excluded from default release checks.


Phase 18 completeness pass 9: direct Remote_Names + Config composition now has a text-aware `Resolve_Remote` overload and `Has_Explicit_Port` helper, preserving explicit `ssh://host:22/repo.git` overrides without changing `Parsed_Remote`.
- Phase 18 completeness pass 10 adds guarded receive-pack binary-probe and close-idempotence validation for version integration.
- Phase 18 pass 11 keeps version adapter coverage deterministic while adding parsed-remote missing-user regression checks.

- Phase 18 completeness pass 12: text-aware `Config.Resolve_Remote` now maps repository-path NUL/CR/LF control breaks to `Invalid_Command`, matching `Git_Transport.Prepare` for direct version-style composition.

## Phase 18 Completeness Pass 13

The default remote/config example now exercises the same text-aware resolver shape documented for `version`, avoiding stale host-only composition in release examples.

## Phase 18 Completeness Pass 14

Default test smoke coverage now avoids the user's real SSH config outside the explicit environment-isolated `Load_Default` tests, preserving deterministic local release checks.

## Phase 18 Completeness Pass 15

The legacy parsed-remote config composition path now preserves the same unsupported-routing status contract as the Phase 18 text-aware resolver: matching `ProxyJump` or `ProxyCommand` markers produce `Unsupported_Feature` and are never executed or ignored.


## Phase 19 — Security review and audit-grade regression coverage

- Added `SSH_Lib.Security_Audit`, `SSH_Lib.Diagnostics.Redaction`, and `SSH_Lib.Protocol.Negative_Tests` to centralize security review labels, deterministic failure mapping, binary redaction, and negative protocol case expectations.
- Added table-driven Phase 19 tests for status mapping, negative protocol classifications, binary safety byte-set preservation, and redaction behavior.
- Added `docs/THREAT_MODEL.md` and `docs/SECURITY_REVIEW.md`.
- Added release audit tools for security defaults, subprocess avoidance, binary-path text conversion heuristics, and sensitive logging checks.
- Updated release verification to include the new Phase 19 security guards.

## Phase 19 completeness pass

The security audit table source now covers the complete Phase 19 negative-path matrix while preserving the stable public API and default deterministic local test model. The logical `tests/security` suites are documented and mapped to the integrated default test runner.

## Phase 19 Completeness Pass 2

- Corrected the Phase 19 security matrix handling so explicit preservation cases remain `Ok` while hostile negative cases still require deterministic failure statuses.
- Added materialized `tests/security/*.adb` suite entry points for the required Phase 19 security areas.
- Extended the security guard tool to require the suite files and preservation-case classifier.

Additional Phase 19 split-runner support: `tests/security/security_tests.gpr` builds the materialized security suite entry points separately when desired.

## Phase 19 completeness pass 3

This pass broadens the security-audit regression surface without changing the public API. The split security tests now cover the complete `SSH_Lib.Protocol.Negative_Tests` matrix, including packet/MAC failure, authentication-order, config security, dirty-state, and resource-bound cases.

### Phase 19 completeness pass 4

The Phase 19 security matrix now has explicit negative-case categories and a split `test_phase19_matrix_coverage.adb` runner. New cases cover silent host-key bypass auditing, weak/unsupported algorithm selection, sequence-number and packet-bound invariants, MAC-failure dirty-state behavior, encrypted-before-userauth ordering, wrong signature payloads, session identifier binding, subprocess fallback prohibition, config/remote precedence, no Git byte text conversion, stdout/stderr/EOF separation, timeout accounting, ambiguous partial write handling, failed-open cleanup, and additional resource bounds.

### Phase 19 completeness pass 5

The security audit matrix now has explicit invariant coverage and enum-backed status mapping. This makes Phase 19 regressions harder to hide as status-only rows and keeps documented security outcomes synchronized with deterministic `Status` values.

### Phase 19 packet-protection hardening

The security suite now includes fixture-backed packet/MAC dirty-state tests. Packet protection failures dirty the protected state and later packets are rejected deterministically; valid protected packets preserve the exact binary payload and advance sequence counters exactly once.

## Phase 19 Completeness Pass 7

This pass converts binary-safety coverage from classification-only checks into concrete byte-for-byte tests across the main SSH/Git byte paths. The required byte set `00 0A 0D 7F 80 FF` is now exercised through production-adjacent packet, channel, agent, identity, known-host, and Git fixture paths.


## Phase 19 completeness pass 8

Added concrete resource-bound oversized-input fixtures covering packet length, packet buffers, agent message and identity limits, identity-file size, config and known_hosts line bounds, pending stdout/stderr buffers, channel count limits, command length, and Git repository path length. `known_hosts` reading is now bounded so overlong records are ignored rather than trusted.

## Phase 19 completeness pass 9

The no-subprocess release guard now covers source, examples, tests, and non-audit tools. It detects subprocess APIs and dangerous local command literals while preserving legitimate remote SSH/Git protocol strings. The release check continues to enforce that SSH_Lib never falls back to local `ssh`, `git`, `ssh-agent`, `ssh-add`, or shell execution.


## Phase 19 completeness pass 10

- Made the split Phase 19 security suite part of the default release verification path.
- Documented build/run commands for every `tests/security/security_tests.gpr` executable.
- Added release guards requiring `check_security`, `check_no_subprocess`, `check_binary_paths`, and `check_sensitive_logging` in the release command sequence.

## Phase 19 completeness pass 11

Phase 19 exception-mapping is no longer matrix-only: public API exception boundaries now have fixture-backed coverage for malformed sessions, channels, files, config, known-host records, identity files, remote names, and the documented Git command helper rejection behavior.

## Phase 19 completeness pass 12

The release security suite now includes `test_config_security`, which exercises the production config parser/resolver with command-like proxy and identity-file values and verifies they remain inert data. It also asserts that config cannot disable host-key verification and that `HostName` retargeting cannot mutate the repository path used for Git command construction.


## Phase 19 completeness pass 13

- Added `SSH_Lib.Protocol.Authentication_Guards`.
- Added `SSH_Lib.Tests.Fixtures.Auth_Security`.
- Added split security runner `test_auth_security`.
- Integrated fixture-backed authentication ordering and exact signature-payload checks into the main test runner and release/security guards.

- Phase 19 completeness pass 14 promotes host-key verification from matrix-only coverage to fixture-backed ordering and trust regression tests.

## Phase 19 Completeness Pass 15

This pass strengthens algorithm-negotiation hardening with fixture-backed checks for advertised-only implemented algorithms, client preference preservation, unsupported intersections, selected-algorithm validation, compression `none`, weak algorithm rejection, inconsistent KEX reply rejection, and cleared partial state after failed negotiation.

## Phase 19 completeness pass 16

Timeout and dirty-state coverage is now fixture-backed.  The security tests exercise real channel/session helper paths for silent channel reads, silent channel-open and exec-reply timeouts, partial-write timeout/failure ambiguity, dirty-channel retry rejection, dirty-session channel-open rejection, failed-open cleanup, and idempotent close after dirty state.

## Phase 19 completeness pass 17

The Phase 19 command-quoting coverage is now fixture-backed.  The security suite directly checks that `SSH_Lib.Git` emits a single shell-safe quoted repository argument, rejects unsafe repository paths, and that generated commands are accepted by the production `Open_Exec` command validation path without invoking a local shell or local git process.


## Phase 19 completeness pass 18

- Added fixture-backed malformed agent and identity-file authentication tests.
- Added split security runner `test_auth_malformed_inputs`.
- Integrated malformed agent/identity checks into the default test runner and release/security guards.


## Phase 19 completeness pass 19

- Added deterministic `SSH_Lib.Tests.Fixtures.Fuzz_Lite` malformed-input sweeps.
- Added mandatory split security executable `test_fuzz_lite`.
- Covered packet framing, SSH strings, known_hosts, config, agent framing, and identity-file section edge cases with bounded local fixtures.

## Phase 19 completeness pass 20

The Phase 19 release path now includes a stronger sensitive-logging guard. The guard scans production, example, fixture, test, and non-audit tool Ada sources while excluding only deliberate audit-policy tools. It rejects unredacted output/logging sinks that mention private key material, session/shared secrets, signature payloads, agent signatures, identity seeds, passwords, or passphrases.


## Phase 19 completeness pass 21

- Added mandatory `test_hostile_transcripts` security executable.
- Hostile peer transcript scenarios now verify session-open failure mapping and closed-state cleanup across identification, KEX, NEWKEYS/service, userauth, and channel-open gates.


## Phase 19 completeness pass 22

- Added mandatory `test_session_open_success_security` release coverage.
- `Sessions.Open` success is now guarded by an explicit all-gates-complete helper covering transport, KEX, encryption, host trust, and authentication.

## Phase 19 Completeness Pass 23

This pass makes the heuristic audit tools testable. `check_no_subprocess --self-test` and `check_sensitive_logging --self-test` now run representative blocked/allowed fixtures in process, then the release path runs the ordinary full-tree scans. The self-tests do not invoke local shells, ssh, git, or any subprocess.


### Phase 19 completeness pass 24

Added deterministic `version` adapter consumption coverage. The fixture resolves an SSH remote through `SSH_Lib.Git_Transport.Prepare`, keeps host-key verification enabled, opens a local authenticated SSH_Lib session fixture, executes both `git-upload-pack 'repo.git'` and `git-receive-pack 'repo.git'`, writes opaque `Ada.Streams.Stream_Element_Array` request bytes, reads opaque binary response bytes byte-for-byte, sends EOF, reads exit status, and closes the channel/session without Git protocol parsing or subprocess fallback.


## Phase 19 completeness pass 25

- Added `tools/check_compile_preflight.adb`.
- Wired compile-preflight source/GPR consistency checks into release verification.
- Documented that the preflight catches source-tree drift but does not replace Ada/GPR/Alire builds.

## Phase 19 completeness pass 26

This pass adds a release-package hygiene guard that checks mandatory files, docs, GPR projects, security executables, version integration tests, examples, fixtures, and audit tools before release acceptance. Manual examples remain explicitly optional and are not part of the default deterministic release path.


## Phase 19 completeness pass 27

Added `SSH_Lib.Sessions.Open_Runtime` and routed public `Sessions.Open` through it. The old unconditional missing-boundary call is gone; production open now has a centralized runtime driver that fails closed until required algorithm and encrypted-transport primitives are available.


## Phase 19 Completeness Pass 28

This pass replaces the group14 Diffie-Hellman and RSA SHA-256 verification stubs with native Ada implementations and adds deterministic fixture coverage under `test_crypto_primitives`. Live `Sessions.Open` still remains gated until the remaining production transport/userauth transcript backend is complete.

## Phase 19 completeness pass 29

The ssh-agent path now has an Ada Unix-domain socket transport backend and a high-level agent client. Agent protocol messages are length-framed, bounded, parsed, and fail closed with deterministic statuses. No subprocess fallback or C bridge was added.


## Phase 19 completeness pass 30

Added live channel transport-boundary wiring: `SSH_Lib.Sessions.Channel_IO`, protected open/exec packet emission, protected channel data/EOF emission, protected inbound channel-data decode, and the `test_live_channel_transport` security fixture.

## Phase 19 completeness pass 31

Release verification now includes non-networked guards for toolchain availability and post-build artifact presence. Missing Alire/GPR/GNAT tools or omitted test/tool executables are explicit release failures rather than undocumented assumptions.

The new guards are `check_release_toolchain` and `check_release_artifacts`.


## Phase 19 completeness pass 32

- Added `tools/check_release_sequence.adb` to guard the documented release command order.
- Registered the sequence guard in `tools/tools.gpr` and the mandatory release path.
- Updated release/security documentation to make manual examples remain optional and commented out.


## Phase 19 completeness pass 33

- Added an initial-context compliance guard and split test.
- Added explicit documentation that live SSH runtime paths remain fail-closed unless all security gates are complete.
- Wired the new guard into the release/security command sequence.

## Phase 19 completeness pass 34

- Added direct public `Sessions.Open` runtime-gate coverage through `test_open_runtime_security`.
- The deterministic local runtime verifies successful public-open state publication without public network access or user SSH state.
- Ordinary hosts still fail closed until the remaining live transport backend is implemented.


## Phase 19 completeness pass 35 - cipher primitive implementation

Implemented native Ada AES-CTR cipher support for `aes128-ctr` and `aes256-ctr`, updated cipher advertisement to `aes256-ctr,aes128-ctr`, initialized directional cipher state during NEWKEYS from derived keys/IVs, and added deterministic AES-CTR known-vector coverage. Unsupported legacy cipher names still fail closed with `Unsupported_Feature`.

## Phase 19 completeness pass 36

- Implemented bounded public identity loading in `SSH_Lib.Keys.Load_Public_Identity`.
- Added integrated tests for missing and valid OpenSSH `.pub` identity files.
- Updated status documentation to distinguish public identity discovery from the remaining private-key signing backend.

### Phase 19 completeness pass 37

Advertises the implemented algorithm set consistently: `diffie-hellman-group14-sha256` for KEX, `rsa-sha2-256` for server host keys, `aes256-ctr,aes128-ctr` for ciphers, `hmac-sha2-256` for MAC, and `none` for compression. Algorithm-security fixtures now include a positive full-negotiation path for that implemented set while unsupported/legacy algorithms continue to fail closed.

## Phase 19 completeness pass 38

Identity-file authentication is now guarded by an explicit signing-capability predicate. The runtime continues to fail closed for identity-file-only authentication until a real Ada-only private-key signing primitive is implemented, avoiding an overstated successful authentication state.


## Phase 19 completeness pass 39

Identity-file signing has moved from an unconditional unsupported boundary to a concrete deterministic signing backend for parsed unencrypted OpenSSH Ed25519 identity files. This removes the local runtime identity-authentication placeholder while preserving explicit unsupported status for RSA private-key signing and ordinary live network runtime limitations.


## Phase 19 completeness pass 40

- Added live protected channel exit-status/EOF/close fixture coverage.
- Encoded live channel close packets through the protected outbound boundary when live channel I/O is enabled.
- Strengthened release/security guards for the extended live channel fixture.


## Phase 19 completeness pass 41

- Added `scripts/run_release_verification.sh`, a deterministic release runner for the full build/test/audit sequence.
- Added `tools/check_release_runner.adb` and wired it into release, security, package, and manifest guards.
- The runner fails closed when required Ada/Alire tooling or expected post-build executables are missing and keeps manual/public-network examples out of the default release path.


## Phase 19 completeness pass 42

Adds a runtime-boundary inventory and guard so release verification distinguishes implemented deterministic runtime pieces from explicit fail-closed public-network SSH boundaries.
