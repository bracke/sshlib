
### Phase 19 completeness pass 308 — live Git zero-exit evidence gate

Pass 308 hardens the live Git interoperability matrix and archived report guard so a scenario only passes when the remote Git service provides a successful zero exit status. Archived report evidence must now include `exit_code=0`, and the live matrix runner rejects nonzero or missing channel exit-status observations instead of treating them as acceptable telemetry.

### Phase 19 completeness pass 300

- Reconciled stale hybrid/PQ release-state documentation after pass 296 advanced the four OpenSSH hybrid/PQ KEX names to `Advertised_And_Selectable`.
- Extended `check_pq_hybrid_state` so release-facing docs cannot again claim that those four names are currently unadvertised, fail-closed, or still gated on missing transcript evidence.

Phase 19 completeness pass 293: bundled ML-KEM ACVP JSON prompt/expectedResults files are now included for keyGen and encapDecap smoke conformance; larger official ACVP corpora can be imported into the same directories.


### Phase 19 completeness pass 288

- Added `check_pq_hybrid_state` to the release tools.
- The tool verifies that ML-KEM-768, SNTRUP761, the source-level hybrid KEX wrapper, and the SNTRUP external-conformance fixture are present while stale pre-SNTRUP-KEM implementation claims are rejected.
- Updated hybrid/PQ release-state documentation so advertisement is now enabled after imported external vectors and recorded OpenSSH transcript validation, not on missing primitive boundaries.


### Phase 19 completeness pass 286

- Added executable SNTRUP761 external-conformance vector coverage.
- Added `tests/vectors/pq/SNTRUP761_OPENSSH_KAT_001.txt` with OpenSSH-shaped SNTRUP761 keygen, encapsulation, decapsulation, artifact-digest, and invalid-ciphertext fallback expectations.
- Expanded `test_pq_external_kats` so it parses and verifies the bundled SNTRUP761 vector instead of only checking manifest metadata.
- Hybrid/PQ KEX advertisement is now enabled because KEM, imported-vector, transport-wrapper, and recorded OpenSSH transcript validation gates are represented in-tree.


## Phase 19 completeness pass 285

Added the source-level OpenSSH hybrid/PQ transport wrapper for ML-KEM768/X25519 and SNTRUP761/X25519. The wrapper now builds and sends hybrid `C_INIT`, parses `S_REPLY`, decapsulates the PQ ciphertext, computes the X25519 shared secret, combines secrets with SHA-256/SHA-512, verifies the host-key signature over the hybrid exchange hash, derives session keys, and installs NEWKEYS. Advertisement is enabled after external KAT and recorded OpenSSH transcript validation pass.


## Phase 19 Completeness Pass 281

- Added the ML-KEM-768 CCA KEM layer on top of the existing ML-KEM-768 core/CPA-PKE work.
- Implemented 2400-byte secret-key package layout, encapsulation, decapsulation with re-encryption check, ciphertext comparison through `SSH_Lib.Crypto.Constant_Time.Equal`, and `z` fallback secret derivation for invalid ciphertexts.
- Added deterministic KAT-style fixtures for key layout, shared-secret agreement, and invalid-ciphertext fallback behavior.
- Historical state before pass 296: OpenSSH hybrid/PQ KEX names were unadvertised until imported ML-KEM ACVP-shaped vectors and OpenSSH transcript validation. Current state: advertised and selectable. SNTRUP761 now has a deterministic KEM boundary and bundled multi-vector OpenSSH-shaped conformance corpus and bundled OpenSSH-shaped external-conformance fixture coverage.



## Phase 19 Completeness Pass 280

- Continued real ML-KEM-768 implementation work by adding the deterministic CPA-PKE layer on top of the polynomial/vector helpers.
- Added public-key, secret-key, ciphertext, and message conversion boundaries for ML-KEM-768 CPA-PKE.
- Kept OpenSSH hybrid/PQ KEX algorithms unadvertised while the implementation advanced through the CCA KEM layer; current state after pass 296 is advertised and selectable after imported external vectors and recorded transcript validation.

## Phase 19 completeness pass 276

- Historical note: pass 276 removed the unsafe ML-KEM-shaped placeholder body from `Run_Hybrid_PQ_Kex`. Later passes add the source-level hybrid wrapper and KEM boundaries; advertisement is now enabled after conformance fixtures and recorded OpenSSH transcript validation.


## Phase 19 completeness pass 268

- Hardened oversized `known_hosts` line handling. Lines that exceed the bounded parser length now fail closed with `Unsupported_Entry`, preventing hidden oversized marker/host/key material from being masked by a later valid trust record.

# Phase 19 security regression suite

The Phase 19 security checks are integrated into the default deterministic Ada test runner in `tests/src/main.adb` so they run with the normal no-network suite. This directory documents the logical grouping requested by the Phase 19 context.

Logical suites covered by `Run_Phase_19_Security_Audit_Tests`:

- `test_host_key_negative`: unknown host, changed key, invalid signature, malformed and unsupported known_hosts entries.
- `test_algorithm_negative`: unsupported KEX, host-key, cipher, MAC, compression, unexpected algorithms, and legacy `ssh-rsa` SHA-1 last-resort fallback expectations.
- `test_auth_negative`: encryption-before-userauth, host-trust-before-userauth, partial success, banner handling, missing or malformed agent data, wrong signature algorithms, missing or malformed identity files, unsupported encrypted algorithms/envelopes, missing/wrong passphrases, legacy PEM edge cases, and unsupported identity algorithms.
- `test_packet_protection_negative`: bad MACs, sequence-number MAC mismatch, truncated encrypted packets, invalid padding, and dirty-session packet reuse.
- `test_command_quoting_negative`: NUL/CR/LF, empty, and oversized repository paths map to `Invalid_Command`; shell metacharacters remain quoted by `SSH_Lib.Git` tests.
- `test_binary_stream_negative`: canonical byte set `00 0A 0D 7F 80 FF` remains byte-preserving and is represented as opaque stream data.
- `test_timeout_dirty_negative`: identification, KEX, auth, channel-open, read, window-write, partial-write, and retry-after-dirty expectations.
- `test_resource_bounds`: oversized packet/local/config/known_hosts/stderr/channel cases map to deterministic statuses.
- `test_exception_mapping`: ordinary injected socket, packet, crypto, file, agent, and channel exceptions map to deterministic status values.
- `test_config_security`: SSH config is parsed as data only; ProxyCommand, ProxyJump, and command-substitution-looking IdentityFile values are not executed during config load/resolve, shell variables are not expanded, host-key verification cannot be disabled, and HostName cannot alter the repository path.
- `test_phase19_matrix_coverage`: every negative case has category coverage, stable labels, and hostile/preservation status consistency.
- `test_phase19_invariant_coverage`: every negative case maps to an explicit security invariant and hostile/preservation classifiers remain exclusive.
- `test_status_mapping_matrix`: the enum-backed status matrix agrees with the public label lookup.

The compiled tests use `SSH_Lib.Protocol.Negative_Tests` as the table source instead of scattering one-off status expectations across fixture code.

## Materialized suite files

The Phase 19 completeness pass now includes the required per-suite Ada entry points in this directory:

```text
test_host_key_negative.adb
test_algorithm_negative.adb
test_algorithm_security.adb
test_crypto_primitives.adb
test_pq_external_kats.adb
test_hybrid_pq_readiness.adb
test_hybrid_pq_openssh_transcripts.adb
test_side_channel_assurance.adb
test_auth_negative.adb
test_packet_protection_negative.adb
test_command_quoting_negative.adb
test_binary_stream_negative.adb
test_timeout_dirty_negative.adb
test_resource_bounds.adb
test_exception_mapping.adb
test_config_security.adb
test_auth_security.adb
test_auth_malformed_inputs.adb
test_agent_transport_security.adb
test_live_channel_transport.adb
test_live_git_e2e.adb
test_live_git_interop_matrix.adb
test_live_proxycommand_transport.adb
test_live_proxyjump_transport.adb
test_live_rekey_transport.adb
test_transport_messages.adb
test_fuzz_lite.adb
test_hostile_transcripts.adb
test_session_open_success_security.adb
test_open_runtime_security.adb
test_phase19_matrix_coverage.adb
test_phase19_invariant_coverage.adb
test_status_mapping_matrix.adb
test_phase19_context_compliance.adb
```

The default runner still integrates the same assertions through `tests/src/main.adb`, so the normal local test command remains unchanged. These files make the Phase 19 security suite boundaries explicit for future split-out runners without introducing public-network, subprocess, C-fixture, or real-user-SSH-state dependencies.

## Release split runner

`security_tests.gpr` builds the materialized suite entry points separately from the default integrated runner. The release path must build this project and run each produced executable so packet-protection, binary-stream, resource-bound, matrix, invariant, and status-mapping failures are visible as separate release-log failures. The integrated `tests/tests.gpr` runner remains the normal all-in-one deterministic suite, but it no longer substitutes for the split security release run.

Required release commands include:

```sh
alr exec -- gprbuild -P tests/security/security_tests.gpr
../ssh_lib_build/bin/tests_security/test_host_key_negative
../ssh_lib_build/bin/tests_security/test_algorithm_negative
../ssh_lib_build/bin/tests_security/test_algorithm_security
../ssh_lib_build/bin/tests_security/test_crypto_primitives
../ssh_lib_build/bin/tests_security/test_pq_external_kats
../ssh_lib_build/bin/tests_security/test_hybrid_pq_readiness
../ssh_lib_build/bin/tests_security/test_hybrid_pq_openssh_transcripts
../ssh_lib_build/bin/tests_security/test_side_channel_assurance
../ssh_lib_build/bin/tests_security/test_auth_negative
../ssh_lib_build/bin/tests_security/test_packet_protection_negative
../ssh_lib_build/bin/tests_security/test_command_quoting_negative
../ssh_lib_build/bin/tests_security/test_binary_stream_negative
../ssh_lib_build/bin/tests_security/test_timeout_dirty_negative
../ssh_lib_build/bin/tests_security/test_resource_bounds
../ssh_lib_build/bin/tests_security/test_exception_mapping
../ssh_lib_build/bin/tests_security/test_config_security
../ssh_lib_build/bin/tests_security/test_auth_security
../ssh_lib_build/bin/tests_security/test_auth_malformed_inputs
../ssh_lib_build/bin/tests_security/test_agent_transport_security
../ssh_lib_build/bin/tests_security/test_live_channel_transport
../ssh_lib_build/bin/tests_security/test_live_git_e2e
../ssh_lib_build/bin/tests_security/test_live_git_interop_matrix
../ssh_lib_build/bin/tests_security/test_live_proxycommand_transport
../ssh_lib_build/bin/tests_security/test_live_proxyjump_transport
../ssh_lib_build/bin/tests_security/test_live_rekey_transport
../ssh_lib_build/bin/tests_security/test_transport_messages
../ssh_lib_build/bin/tests_security/test_fuzz_lite
../ssh_lib_build/bin/tests_security/test_hostile_transcripts
../ssh_lib_build/bin/tests_security/test_session_open_success_security
../ssh_lib_build/bin/tests_security/test_open_runtime_security
../ssh_lib_build/bin/tests_security/test_phase19_matrix_coverage
../ssh_lib_build/bin/tests_security/test_phase19_invariant_coverage
../ssh_lib_build/bin/tests_security/test_status_mapping_matrix
../ssh_lib_build/bin/tests_security/test_phase19_context_compliance
```



## Completeness pass 4

`test_phase19_matrix_coverage.adb` verifies the full negative-case taxonomy: every category is non-empty, every case has a stable label, every case belongs to a category, preservation cases map to `Ok`, and hostile negative cases map to deterministic failure statuses.

## Phase 19 Completeness Pass 5

The security regression matrix is now explicitly classified by security invariant as well as by review category and expected deterministic status. This ensures host-key, algorithm, packet-protection, authentication-ordering, command-quoting, config, binary-stream, dirty-state, resource-bound, and exception-containment cases cannot be represented as unlabeled status-only checks.

## Packet-protection fixture depth

`test_packet_protection_negative.adb` is no longer a label-only test. It drives packets through `SSH_Lib.Protocol.Protected_Packets` and covers bad MAC, wrong sequence-number MAC, truncated packets, invalid padding with a valid MAC, binary payload preservation, sequence increments, and packet-after-dirty-state rejection.

## Binary stream fixture matrix

`test_binary_stream_negative.adb` now invokes `SSH_Lib.Tests.Fixtures.Binary_Matrix.Assert_All_Production_Paths_Preserve`. This makes the split security suite exercise real byte paths instead of only checking Phase 19 matrix labels.


## Phase 19 completeness pass 8

Added concrete resource-bound oversized-input fixtures covering packet length, packet buffers, agent message and identity limits, identity-file size, config and known_hosts line bounds, pending stdout/stderr buffers, channel count limits, command length, and Git repository path length. `known_hosts` reading is now bounded so overlong records are ignored rather than trusted.

## Phase 19 completeness pass 10

The split security suite is part of the mandatory release path. `tools/check_release` and `tools/check_security` now require the documented build/run commands so the split suite cannot silently become advisory-only.

## Exception-containment fixture coverage

Phase 19 completeness pass 11 extends `test_exception_mapping` with `SSH_Lib.Tests.Fixtures.Exception_Containment.Assert_Public_Api_Exception_Boundaries`.  This moves exception mapping beyond enum checks by exercising public session, channel, known-hosts, config, identity-file, remote-name, channel-dispatch, and Git helper boundaries with malformed or rejected inputs.

## Phase 19 Completeness Pass 12

`test_config_security.adb` and `SSH_Lib.Tests.Fixtures.Config_Security.Assert_Config_Is_Data_Only` provide fixture-backed SSH config security checks. They prove that `ProxyCommand`, `ProxyJump`, `$HOME`, and backtick-looking `IdentityFile` data are not shell-expanded or executed; config cannot disable `Verify_Known_Host` or `Strict_Host_Key`; ProxyCommand is preserved as session data without execution during `Resolve_Remote`; ProxyJump is preserved as data and, when used by Sessions.Open, is routed through SSH direct-tcpip; and `HostName` retargeting cannot alter the parsed repository path.


## Phase 19 Completeness Pass 13

`test_auth_security.adb` and `SSH_Lib.Tests.Fixtures.Auth_Security.Assert_Userauth_Order_And_Signature_Payloads` add fixture-backed authentication-order coverage. They prove userauth is rejected before encrypted packet mode and host trust, partial `USERAUTH_FAILURE` is never treated as complete success, `USERAUTH_BANNER` is parsed but ignored as a completion signal, `USERAUTH_SUCCESS` cannot override failed setup preconditions, and agent/identity signing payloads must match the exact binary payload using the first exchange hash as the session identifier.


## Phase 19 Completeness Pass 14

`test_host_key_negative` now runs `Assert_Host_Key_Verification_Order_And_Trust`, which exercises real known_hosts fixture files and the host-key guard path rather than only checking negative-case labels. It covers unknown hosts, changed keys, invalid signatures before trust, authentication-before-trust rejection, unsupported/malformed/hashed/wildcard records, and exact nonstandard port trust.

## Phase 19 Completeness Pass 15

`test_algorithm_security.adb` and `SSH_Lib.Tests.Fixtures.Algorithm_Security.Assert_Algorithm_Negotiation_Security` add fixture-backed algorithm-negotiation coverage. They prove advertised algorithm lists contain only implemented entries, client preference order is preserved, unsupported KEX/host-key/cipher/MAC/compression intersections fail deterministically, peer-selected algorithms must have been client-advertised, delayed `zlib@openssh.com` and stateful `zlib` compression negotiate only when both peers support them, legacy weak algorithms are rejected, inconsistent KEX replies fail, and failed negotiation clears partial state.

## Phase 19 completeness pass 16

`test_timeout_dirty_negative` now invokes `SSH_Lib.Tests.Fixtures.Timeout_Dirty.Assert_All_Timeout_And_Dirty_State_Behavior`.  This moves timeout/dirty-state coverage beyond matrix labels by exercising channel/session fixture paths for silent reads, channel-open/exec timeouts, partial-write ambiguity, dirty reuse rejection, failed-open cleanup, and idempotent close after dirty state.


### Phase 19 completeness pass 17

Git command quoting security is now covered by `SSH_Lib.Tests.Fixtures.Command_Quoting`. The fixture calls the production `SSH_Lib.Git` builders and verifies exact single-argument quoting, invalid repository-path rejection, production `Open_Exec` command validation acceptance, and byte-exact exec request encoding. Shell-looking repository paths such as `$()` and backticks are treated as data and are not executed locally.


## Phase 19 Completeness Pass 18

`test_auth_malformed_inputs.adb` and `SSH_Lib.Tests.Fixtures.Auth_Security.Assert_Malformed_Agent_And_Identity_Fixtures` add fixture-backed malformed agent and identity-file coverage. They assert that malformed agent identity lists, malformed sign responses, oversized agent frames, wrong signature algorithms, malformed OpenSSH private keys, unsupported encrypted algorithms/envelopes, missing/wrong passphrases, unsupported private-key algorithms, public/private key mismatches, and unsupported legacy PEM armor fail deterministically.


## Phase 19 Completeness Pass 19

`test_fuzz_lite.adb` runs the deterministic `SSH_Lib.Tests.Fixtures.Fuzz_Lite` malformed-input sweep. It covers packet framing, SSH string length edge cases, known_hosts malformed records, SSH config malformed records, agent message framing, and identity-file section framing with bounded local fixtures only.

## Phase 19 Completeness Pass 20

Pass 20 strengthens the sensitive-logging release guard. `check_sensitive_logging` now scans source, examples, tests, and non-audit tools; strips Ada comments outside string literals; detects direct output/logging sinks; recognizes spaced, underscore, and hyphenated sensitive-token forms; and requires explicit redaction for any secret-bearing diagnostic output.


## Hostile session-open transcripts

`test_hostile_transcripts.adb` runs `SSH_Lib.Tests.Fixtures.Hostile_Transcripts.Assert_Hostile_Session_Open_Transcripts`. It proves that malformed identification, KEX, NEWKEYS/service, userauth, and channel-open hostile peer scenarios map to deterministic statuses and never leave a reusable open session after failure.


`test_session_open_success_security.adb` runs `SSH_Lib.Tests.Fixtures.Session_Open_Success.Assert_Session_Open_Success_Gates`. It verifies that `Sessions.Open` success requires the complete chain: transport, identification, negotiation, KEX, key derivation, NEWKEYS, encrypted packet mode, host-key ownership, known-host trust, userauth service acceptance, and final user authentication.


## Audit-tool self-tests

Pass 23 makes audit-tool behavior testable. Release verification now runs:

```sh
../ssh_lib_build/bin/tools/check_no_subprocess --self-test
../ssh_lib_build/bin/tools/check_no_subprocess
../ssh_lib_build/bin/tools/check_sensitive_logging --self-test
../ssh_lib_build/bin/tools/check_sensitive_logging
```

The self-tests use deliberate blocked and allowed fixtures embedded in the tools. They do not invoke local shells or subprocesses.


### Phase 19 completeness pass 24

Added deterministic `version` adapter consumption coverage. The fixture resolves an SSH remote through `SSH_Lib.Git_Transport.Prepare`, keeps host-key verification enabled, opens a local authenticated SSH_Lib session fixture, executes both `git-upload-pack 'repo.git'` and `git-receive-pack 'repo.git'`, writes opaque `Ada.Streams.Stream_Element_Array` request bytes, reads opaque binary response bytes byte-for-byte, sends EOF, reads exit status, and closes the channel/session without Git protocol parsing or subprocess fallback.


## Phase 19 Completeness Pass 25

Release verification now includes `check_compile_preflight` after the tool project is built. The guard catches obvious Ada source/GPR drift before the split security executables are trusted: required project files, required core specs, Phase 19 open-success units, package body/spec pairs, and library/test fixture separation.

## Phase 19 Completeness Pass 26

Pass 26 adds `check_release_package` to the mandatory release path. The guard verifies that every split Phase 19 security executable listed here is present in `tests/security/security_tests.gpr`, documented in `docs/TESTING.md`, and kept in the release package with the supporting fixtures and audit tools.


## Phase 19 Completeness Pass 28

Added `test_crypto_primitives.adb` for native group14 Diffie-Hellman and RSA SHA-256 verification fixture coverage.

## Phase 19 Completeness Pass 29

`test_agent_transport_security` covers the real Ada ssh-agent transport/client boundary added in pass 29. The executable is mandatory in the split security release path and verifies deterministic failure/cleanup behavior without depending on a real user agent socket.

```sh
../ssh_lib_build/bin/tests_security/test_agent_transport_security
```


## Phase 19 Completeness Pass 30

Pass 30 adds `test_live_channel_transport`, a fixture-backed security test for the live channel protected-packet boundary. It verifies protected open/exec emission, protected channel-data writes, protected inbound channel-data reads, and protected EOF emission without using public network access or subprocess fallback.

## Phase 19 Completeness Pass 31

Pass 31 adds release execution guards to the mandatory release path. `check_release_toolchain` verifies the local Alire/GPR/GNAT toolchain is present, and `check_release_artifacts` verifies that the split security executables and other release binaries were actually produced. This keeps the split security suite from being documented but accidentally unbuilt.


## Phase 19 Completeness Pass 32

Phase 19 completeness pass 32 adds `check_release_sequence`, an Ada-only release command ordering guard. It does not execute subprocesses; it validates that the deterministic release documentation keeps mandatory builds, integrated tests, split security tests, version-integration tests, deterministic examples, release tools, audit self-tests, and final audit scans in the required order while keeping manual public-network examples commented out.


### Phase 19 completeness pass 33 — initial-context compliance

This pass adds `test_phase19_context_compliance` and `check_phase19_context`. The test and tool compare the tree against the original Phase 19 context requirements: required packages/tools, mandatory security suites, security documentation sections, release-command coverage, secure defaults, status mappings, binary sentinel coverage, no-subprocess/no-secret-logging guards, and the explicit live-runtime fail-closed boundary.

../ssh_lib_build/bin/tests_security/test_open_runtime_security

`test_open_runtime_security.adb` runs `SSH_Lib.Tests.Fixtures.Open_Runtime.Assert_Public_Open_Runtime_Gates`. It covers the public `Sessions.Open` runtime path directly: the reserved deterministic local runtime host reaches `Ok` only after all centralized success gates are complete, while ordinary hosts still fail closed rather than exposing partial sessions.


## Phase 19 pass 35 cipher primitive coverage

`test_crypto_primitives.adb` now includes deterministic AES-CTR and AES-CBC known-vector coverage for `aes128-ctr` and `aes128-cbc`; the same implementation supports the 192-bit and 256-bit AES CTR/CBC variants. Algorithm negotiation advertises only implemented AES transport ciphers and continues to reject unsupported legacy cipher names.

## Phase 19 completeness pass 37

Pass 159 adds `diffie-hellman-group14-sha1` as a bounded compatibility fallback using the existing group14 finite-field primitive, SHA-1 exchange hash, SHA-1 session-key derivation, and the same strict host-key verification path; it is ordered after `diffie-hellman-group14-sha256` and before the extension marker.

The implemented algorithm advertisement is now consistent with the available primitives, RFC 8308 extension negotiation, and the current hybrid/PQ readiness gate. The client advertises `mlkem768x25519-sha256,mlkem768x25519-sha512,sntrup761x25519-sha512@openssh.com,sntrup761x25519-sha512,curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256,diffie-hellman-group-exchange-sha1,diffie-hellman-group18-sha512,diffie-hellman-group16-sha512,diffie-hellman-group14-sha256,diffie-hellman-group14-sha1,ext-info-c`, where `ext-info-c` is an extension marker and not a selectable KEX algorithm. It also advertises `ssh-ed25519-cert-v01@openssh.com,ecdsa-sha2-nistp256-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,ssh-rsa-cert-v01@openssh.com,ssh-ed25519,ecdsa-sha2-nistp256,rsa-sha2-512,rsa-sha2-256,ssh-rsa`, `chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr,aes256-cbc,aes192-cbc,aes128-cbc`, `umac-128-etm@openssh.com,umac-64-etm@openssh.com,umac-128@openssh.com,umac-64@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,hmac-sha1-etm@openssh.com,hmac-sha1,hmac-sha1-96-etm@openssh.com,hmac-sha1-96`, and compression `zlib@openssh.com,zlib,none`. The deterministic algorithm-security fixtures assert that selectable implemented algorithms negotiate successfully, `ext-info-c` is never selected, and unsupported alternatives remain rejected.


## Phase 19 completeness pass 39

Identity-file signing coverage now expects parsed unencrypted OpenSSH Ed25519 and OpenSSH RSA identity files to produce non-empty payload-bound SSH signature blobs. RSA identity-file signing is supported for rsa-sha2-512 and rsa-sha2-256; unencrypted OpenSSH RSA, PKCS#1 RSA PEM, and PKCS#8 RSA identities are supported, while OpenSSH bcrypt-encrypted private keys now route through the Ada bcrypt_pbkdf implementation; malformed encrypted envelopes are distinguished from syntactically valid bcrypt KDF envelopes, and encrypted PEM/PKCS#8 private keys now have bounded AES-CBC/PBKDF2-HMAC-SHA1/SHA256/SHA512/legacy-MD5 coverage.


### Phase 19 completeness pass 40

Pass 40 strengthens the live channel execution boundary after the identity-file signing work.
It adds fixture-backed coverage for protected inbound `exit-status` requests, protected EOF handling,
and close-after-status behavior through `SSH_Lib.Channels.Read_Some`, `Exit_Status`, and `Close`.
The close path now also encodes `SSH_MSG_CHANNEL_CLOSE` through the live protected channel boundary
when live channel I/O is enabled. Ordinary public-network SSH remains gated by the still-explicit
live runtime backend limits documented in the security review.


### Phase 19 completeness pass 41

check_release_runner: `../ssh_lib_build/bin/tools/run_release_validation` is the deterministic local release runner. It fails closed on missing toolchain/artifacts, runs the integrated suite, split security suite, version-integration suite, deterministic examples, and all audit guards, and excludes manual/public-network examples from the default path.

## Phase 19 completeness pass 42 — runtime boundary inventory

`check_runtime_boundaries` verifies that implemented runtime markers and remaining fail-closed boundaries are both documented. It prevents the test suite from silently converting deterministic local fixture success into an unsupported claim of arbitrary public-network SSH completion.

### Phase 19 completeness pass 43

The open-runtime security fixture checks that identity-file authentication emits a protected userauth transcript and that the plain request begins with `SSH_MSG_USERAUTH_REQUEST` before the public session is accepted as authenticated.

## Phase 19 completeness pass 71

`test_live_git_e2e.adb` is a buildable, opt-in live Git-over-SSH proof. It skips by default unless `SSH_LIB_LIVE_GIT_E2E=1` is set, so the split security suite remains deterministic and public-network-free. When enabled with `SSH_LIB_LIVE_GIT_HOST`, `SSH_LIB_LIVE_GIT_USER`, and `SSH_LIB_LIVE_GIT_REPO`, it opens a real authenticated SSH session, executes a Git service command, writes an opaque flush packet, sends EOF, reads opaque stdout bytes, observes exit status, and closes the channel/session with strict known-host verification still enabled.


Phase 19 completeness pass 78 extends authentication security coverage with password-change-required reply handling. The fixture proves that message number 60 is parsed as password-change-required only in password context, does not complete authentication, and is rejected outside that context.


Phase 19 pass 119 also bounds OpenSSH bcrypt KDF salt length and round counts before bcrypt_pbkdf derivation is attempted, so syntactically valid but oversized encrypted-key envelopes fail closed instead of creating an unbounded CPU or memory boundary.


### Pass 127 live Git interoperability matrix

Pass 127 adds `test_live_git_interop_matrix.adb`, an opt-in live interoperability matrix for the Version-facing Git-over-SSH path. It performs no public-network access unless `SSH_LIB_LIVE_GIT_MATRIX=1` is set. When enabled, `SSH_LIB_LIVE_GIT_SCENARIOS` selects comma-separated scenarios such as `DIRECT`, `AGENT`, `IDENTITY`, `PASSWORD`, `PASSPHRASE`, `PROXYJUMP`, and `RECEIVE`; pass 128 makes this selector whitespace/case tolerant, rejects unknown scenario names before network access, and adds `ALL` as a shorthand for the full matrix.

The matrix keeps strict known-host verification enabled and exercises the public sequence required by Version: open an authenticated session, open an exec channel with a safely quoted Git service command, write an opaque Git flush packet, send EOF, read opaque stdout bytes, observe exit status, close the channel, and close the session. Scenario-specific values can be supplied with `SSH_LIB_LIVE_GIT_<SCENARIO>_<FIELD>` and fall back to the existing single-case names such as `SSH_LIB_LIVE_GIT_HOST`, `SSH_LIB_LIVE_GIT_USER`, `SSH_LIB_LIVE_GIT_REPO`, `SSH_LIB_LIVE_GIT_KNOWN_HOSTS`, `SSH_LIB_LIVE_GIT_IDENTITY`, `SSH_LIB_LIVE_GIT_PASSWORD`, `SSH_LIB_LIVE_GIT_IDENTITY_PASSPHRASE`, and `SSH_LIB_LIVE_GIT_PROXY_JUMP`.

Phase 19 completeness pass 130 adds `test_live_proxyjump_transport.adb`, a dedicated opt-in live ProxyJump transport proof separate from the Git matrix. It performs no network access unless `SSH_LIB_LIVE_PROXYJUMP=1` is set. `SSH_LIB_LIVE_PROXYJUMP_SCENARIOS` accepts `SINGLE`, `CHAIN`, `IPV6`, or `ALL`; each selected scenario requires explicit `HOST`, `USER`, `PROXY_JUMP`, and `COMMAND` values through `SSH_LIB_LIVE_PROXYJUMP_<FIELD>` or scenario-specific `SSH_LIB_LIVE_PROXYJUMP_<SCENARIO>_<FIELD>` variables. The test keeps strict known-host verification enabled, opens a ProxyJump-backed session, opens an exec channel over the tunneled target transport, reads stdout bytes without text conversion, observes exit status, closes channel/session, and clears password/passphrase options after each scenario.
Phase 19 completeness pass 314 adds `test_live_proxycommand_transport.adb`, a dedicated opt-in live ProxyCommand transport proof. It performs no network or subprocess-backed ProxyCommand access unless `SSH_LIB_LIVE_PROXYCOMMAND=1` is set. `SSH_LIB_LIVE_PROXYCOMMAND_SCENARIOS` accepts `BASIC`, `TOKEN`, `IPV6`, `FAILS_EARLY`, or `ALL`; each selected non-failure scenario requires explicit `HOST`, `USER`, `PROXY_COMMAND`, and `COMMAND` values through `SSH_LIB_LIVE_PROXYCOMMAND_<FIELD>` or scenario-specific `SSH_LIB_LIVE_PROXYCOMMAND_<SCENARIO>_<FIELD>` variables. `TOKEN` additionally requires the configured command to include `%h` and `%p`, proving the OpenSSH-style token expansion path. `FAILS_EARLY` proves a ProxyCommand that does not produce an SSH transport fails the session open instead of succeeding. The test keeps strict known-host verification enabled, opens a ProxyCommand-backed session, opens an exec channel, reads stdout bytes without text conversion, observes exit status, closes channel/session, and clears password/passphrase options after each scenario.
Phase 19 completeness pass 131 hardens `SSH_LIB_LIVE_PROXYJUMP_SCENARIOS`: comma-separated lists now reject empty entries such as `SINGLE,,CHAIN`, leading commas, trailing commas, and whitespace-only entries. This keeps the opt-in live ProxyJump test fail-closed instead of silently skipping part of the requested matrix.


### Live rekey transport test

`test_live_rekey_transport.adb` is disabled by default.  Set `SSH_LIB_LIVE_REKEY=1` and provide a strict-known-host target to prove explicit client-initiated `SSH_Lib.Sessions.Rekey` before and after opening an exec channel.  The test accepts `SSH_LIB_LIVE_REKEY_COMMAND` for a generic command or `SSH_LIB_LIVE_REKEY_REPO` to use a safely quoted `git-upload-pack` command.


Phase 19 pass 173: AES-GCM transport support is implemented for `aes256-gcm@openssh.com` and `aes128-gcm@openssh.com`. AES-GCM is handled as an AEAD packet mode with encrypted packet length, GHASH tag verification, 16-byte authentication tags, and no separate SSH MAC; mixed-direction negotiation with non-GCM ciphers remains supported.

### Phase 19 pass 255 PEM/PKCS#8 identity edge coverage

The identity-file matrix now includes ECDSA P-256 PEM variants in addition to OpenSSH, RSA PKCS#1, and RSA PKCS#8 fixtures: unencrypted SEC1 `EC PRIVATE KEY`, unencrypted PKCS#8 `PRIVATE KEY` with `id-ecPublicKey`/`prime256v1`, and encrypted legacy SEC1 AES-CBC PEM. Wrong passphrases fail deterministically with `Authentication_Failed`.


### Phase 19 pass 256 PKCS#8 v1 / OneAsymmetricKey coverage

The identity-file matrix now accepts RFC 5958-style PKCS#8 `OneAsymmetricKey` version `1` wrappers with optional public-key trailers. The parser treats the trailer as compatibility metadata only; the identity remains derived from the validated inner RSA or SEC1 key material. Unknown trailing fields remain fail-closed.

### Phase 19 completeness pass 257

Side-channel hardening now covers the highest-risk native private-key and
signature paths. RSA signing uses public-modulus-width candidate-and-select
modular arithmetic and fixed-layout PKCS#1 v1.5 verification scans. ECDSA P-256
and Ed25519 scalar paths no longer branch directly on scalar/exponent bits in the
main multiply/exponentiation loops. This is a practical hardening pass, not a
formal constant-time proof.

## Phase 19 Completeness Pass 258

Finite-field Diffie-Hellman side-channel hardening now covers group14, group16, and group18. The modular multiplication and exponentiation paths no longer branch on private multiplier/exponent bits or shorten the exponentiation loop based on leading-zero structure. The implementation keeps the same deterministic offline crypto primitive coverage while reducing private-key timing leakage in live KEX and group-exchange KEX paths.

### Phase 19 completeness pass 259

Curve25519/X25519 side-channel hardening now covers the native final reduction
and all-zero shared-secret checks.  The reduction path computes candidate
subtractions and selects the accepted value with limb masks; field comparisons
and zero checks scan the full fixed-width representation instead of returning on
the first differing limb or relying on array equality.

### Phase 19 completeness pass 260

Curve25519/X25519 final reduction has been tightened again: the comparison
against p is now expressed as a fixed-limb subtraction/borrow test, and modular
subtraction repair no longer branches on negative intermediate limbs.  Final
normalization uses the same subtraction borrow to drive candidate selection.

### Phase 19 completeness pass 261

Ed25519 field normalization has been tightened: the final reduction no longer
uses a data-dependent `while Compare (Item, P_Value) >= 0` loop. It now performs
a fixed number of candidate subtractions and selects the reduced value from the
borrow result, matching the project-wide practical side-channel-hardening style.

## Phase 19 Completeness Pass 263

Finite-field Diffie-Hellman group14/group16/group18 normalization no longer uses compare-controlled `while` loops. Modular reduction now uses fixed subtract-and-select helpers driven by borrow/carry state, preserving the previous fixed-width exponentiation behavior while reducing secret-dependent control-flow surface.


## Phase 19 pass 264: host certificate CA revocation

Known-hosts `@revoked` policy is CA-aware for OpenSSH host certificates.  A revoked raw CA public key blocks any presented host certificate signed by that CA, not just an exact certificate blob match.  Deterministic fixtures cover matching CA extraction, unrelated CA rejection, and malformed raw-key-as-certificate rejection.

Phase 19 pass 265 adds OpenSSH-compatible known_hosts negated-pattern coverage.  Negated selectors are parsed after stripping the leading `!` and veto only the current line for ordinary, `@cert-authority`, `@revoked`, and unsupported-record paths.  Deterministic tests cover `!host,host`, negated wildcard veto, negated-only records, and negated `@revoked` followed by a valid positive trust line.


## Pass 266 known-hosts edge validation

Pass 266 adds fail-closed coverage for matching unsupported `known_hosts` markers and malformed host records, including the case where an unknown marker line precedes a later ordinary trust line.

## Pass 267 known-hosts hashed selector edge validation

Pass 267 tightens hashed `known_hosts` matching. Negated hashed selectors such as `!|1|salt|hash` now veto only their own line, while unsupported or malformed hashed records are considered applicable only when the HMAC actually matches the target host. This prevents unrelated hashed unsupported-marker records from masking later valid trust lines while preserving fail-closed behavior for matching malformed/unsupported hashed records.


## Pass 269 known-hosts matching hashed malformed/unsupported records

Pass 269 closes a remaining hashed-selector edge case: a malformed or unsupported `known_hosts` record whose `|1|salt|hash` selector actually matches the target host is now treated as applicable and fails closed. This prevents a later valid trust line from hiding an applicable bad hashed record, while nonmatching hashed unsupported records remain unrelated.
## Phase 19 completeness pass 270

- Hardened OpenSSH `known_hosts` hashed selector-version handling.
- Unknown `|N|...` hash selector versions now fail closed instead of being treated as harmless nonmatches.
- Added coverage ensuring a later valid trust line cannot mask an ambiguous unknown hash-version policy record.



## Pass 271 host-certificate wildcard principal validation

Pass 271 hardens OpenSSH host-certificate valid-principal handling. Certificate principals now support wildcard host patterns and explicit non-default-port bracketed wildcard patterns while preserving fail-closed behavior for empty lists, unrelated wildcard principals, and port-scope mismatches.


## Pass 272 known-hosts bracketed selector validation

Pass 272 hardens malformed bracketed `[host]:port` selector handling. Broken explicit-port selectors, including negated forms, now fail closed as unsupported policy syntax and cannot be masked by later valid trust lines.


## Phase 19 pass 273 known-hosts coverage

Pass 273 adds deterministic coverage for malformed OpenSSH `|1|salt|hash` host selectors. Undecodable or structurally invalid hashed selectors now fail closed before any later valid trust line can mask the ambiguous policy record.

## Pass 274 known-hosts host-list syntax validation

Pass 274 hardens comma-separated OpenSSH `known_hosts` host-pattern lists. Empty members caused by leading commas, trailing commas, or consecutive commas now fail closed as unsupported policy syntax. Deterministic coverage verifies that a record containing an empty host-list member cannot be silently ignored and then masked by a later valid trust line.

- Phase 19 pass 277 added a native Ada SHA-3/SHAKE foundation package for real ML-KEM-768 work. Later passes add ML-KEM-768 and SNTRUP761 KEM boundaries; OpenSSH hybrid/PQ KEX names are now advertised and selectable after imported-vector checks and recorded OpenSSH transcript validation.

## Phase 19 completeness pass 278

- Added `SSH_Lib.Crypto.MLKEM768_Core` with real ML-KEM-768 parameter constants, coefficient compression/decompression, polynomial packing/unpacking, SHAKE128 rejection sampling for matrix expansion, and CBD eta=2 sampling.
- Historical state before pass 296: OpenSSH hybrid/PQ KEX names were unadvertised until external ML-KEM/SNTRUP vectors and OpenSSH transcript validation were complete. Current state: advertised and selectable.



## Phase 19 completeness pass 279

- Continued real ML-KEM-768 work by adding polynomial add/subtract, reference ring multiplication, and NTT/inverse-NTT entry points to `SSH_Lib.Crypto.MLKEM768_Core`.
- Added deterministic core arithmetic coverage for ring reduction, packing preservation, add/subtract, and zero-polynomial transform stability.
- Historical state before pass 296: OpenSSH hybrid/PQ KEX names were recognized but unadvertised until ML-KEM-768/SNTRUP761 KEM implementations and validation coverage existed. Current state: advertised and selectable.


## Phase 19 Completeness Pass 282

- Added the first real SNTRUP761 core foundation package, `SSH_Lib.Crypto.SNTRUP761_Core`.
- Added SNTRUP761 constants (`p=761`, `q=4591`, `w=286`), q-polynomial arithmetic, fixed-weight ternary sampling, and reference multiplication in `Z_q[x] / (x^761 - x - 1)`.
- Added deterministic primitive coverage for SNTRUP761 ring reduction, encoding, and fixed-weight sampling.
- Historical state before pass 296: OpenSSH SNTRUP hybrid KEX was unadvertised until external vector and transcript validation were added. Current state: advertised and selectable.


### Phase 19 pass 283 SNTRUP761 note

Pass 283 adds rounded SNTRUP761 encoding helpers and a deterministic KEM boundary with OpenSSH-sized public key, secret key, ciphertext, and shared secret objects. Historical state before pass 296: OpenSSH SNTRUP hybrid KEX was unadvertised until external SNTRUP761 KAT and OpenSSH transcript validation were available. Current state: advertised and selectable.

### Phase 19 pass 284 external PQ KAT harness

Pass 284 adds a dedicated `test_pq_external_kats` executable and bundled PQ KAT manifests under `tests/vectors/pq/`.  The harness records the required external validation sources and byte-boundary expectations for ML-KEM-768 ACVP vectors and OpenSSH-compatible SNTRUP761 vectors.  Hybrid/PQ KEX advertisement is now enabled after bundled ACVP/OpenSSH-shaped vector checks and recorded OpenSSH transcript validation. Broader live interoperability remains an opt-in release-evidence activity.


## Phase 19 completeness pass 287

- Added the side-channel assurance framework: `SSH_Lib.Crypto.Constant_Time_Assurance`, `test_side_channel_assurance`, and `tests/vectors/security/SIDE_CHANNEL_ASSURANCE_MANIFEST.txt`.
- Added `docs/security/SIDE_CHANNEL_ASSURANCE.md` documenting the in-tree source/evidence gate and the external review boundary.
- The project now fails the security assurance test if a tracked primitive is removed from the side-channel gate or marked unassessed.


Side-channel assurance audit tool:

```text
../ssh_lib_build/bin/tools/check_side_channel_assurance
```

## Phase 19 Completeness Pass 289

- Added a bundled ML-KEM-768 ACVP-shaped vector file at `tests/vectors/pq/MLKEM768_ACVP_KAT_001.txt`.
- Extended `test_pq_external_kats` so ML-KEM-768 is no longer manifest-only: the security fixture now runs seeded key generation, seeded encapsulation, decapsulation agreement, invalid-ciphertext fallback separation, and artifact-digest presence checks.
- Updated the ML-KEM external KAT manifest to require the bundled vector file and concrete vector checks.
- Updated `check_pq_hybrid_state` so PQ/hybrid state validation requires the ML-KEM vector and fixture entry point.
- Hybrid/PQ KEX advertisement is enabled after imported ACVP expected-results vectors, bundled SNTRUP761 corpus vectors, and recorded OpenSSH transcript validation pass.

## Phase 19 completeness pass 290

- Added ACVP JSON expected-results ingestion for ML-KEM-768.
- `test_pq_external_kats` now has an `Assert_MLKEM768_ACVP_JSON_Vectors` path that reads:
  - `tests/vectors/pq/ML-KEM-keyGen-FIPS203/prompt.json`
  - `tests/vectors/pq/ML-KEM-keyGen-FIPS203/expectedResults.json`
  - `tests/vectors/pq/ML-KEM-encapDecap-FIPS203/prompt.json`
  - `tests/vectors/pq/ML-KEM-encapDecap-FIPS203/expectedResults.json`
- The JSON executor validates the ACVP `ML-KEM / keyGen / FIPS203` and `ML-KEM / encapDecap / FIPS203` metadata, executes ML-KEM-768 key generation, encapsulation, and decapsulation, and compares generated `ek`, `dk`, `c`, and `k` values against `expectedResults.json`.
- Added packaged vector-directory READMEs explaining where official ACVP JSON files must be imported.
- Updated the PQ hybrid state checker to require the ACVP JSON executor and vector-directory layout.

Boundary: the official NIST ACVP JSON corpus itself is not bundled in this archive. The executor is now present and fails closed unless those official `prompt.json` / `expectedResults.json` files are installed in the documented locations.

## Phase 19 completeness pass 291

- Added `SSH_Lib.Crypto.Constant_Time_Proof`, a source-level formal side-channel proof catalogue.
- Added proof obligations covering secret-independent branches and loop bounds, constant-time selection/equality, fixed-width arithmetic, KEM invalid-ciphertext fallback selection, and audit-token presence.
- Added `tests/vectors/security/SIDE_CHANNEL_FORMAL_PROOF_MANIFEST.txt` and `docs/security/FORMAL_SIDE_CHANNEL_PROOF.md`.
- Added `check_formal_side_channel_proof` to the tools project.
- The in-tree gate may be used to claim that source-level proof obligations are represented and checked. It still may not be used to claim mathematically proven constant-time execution without external leakage tooling, compiler/codegen audit, and independent review.

Formal side-channel proof gate:

```text
../ssh_lib_build/bin/tools/check_formal_side_channel_proof
```

### Phase 19 pass 292 hybrid/PQ readiness gate

`test_hybrid_pq_readiness` verifies the hybrid/PQ readiness state exposed by
`SSH_Lib.Crypto.Hybrid_PQ_Kex`.  It confirms that the OpenSSH ML-KEM768/X25519 and
ML-KEM768/X25519 and SNTRUP761/X25519 names report `Advertised_And_Selectable` after imported external KATs and recorded OpenSSH transcript validation pass.

### Phase 19 pass 295 SNTRUP761 external-conformance corpus

The SNTRUP761 external-conformance gate now uses a bundled four-vector OpenSSH-shaped
corpus instead of a single fixture.  `test_pq_external_kats` executes all four fixtures,
including seeded key generation, seeded encapsulation, decapsulation, invalid-ciphertext
fallback, and SHA3-256 artifact digest checks.  SNTRUP761/X25519 readiness now matches
ML-KEM768/X25519 at `Advertised_And_Selectable` after recorded OpenSSH transcript validation passes.

## Hybrid/PQ OpenSSH transcript gate

`test_hybrid_pq_openssh_transcripts` runs `SSH_Lib.Tests.Fixtures.Hybrid_PQ_OpenSSH_Transcripts.Assert_Hybrid_PQ_OpenSSH_Transcripts`.  The fixture validates the recorded OpenSSH transcript corpus under `tests/vectors/pq/openssh_transcripts/` for all four hybrid/PQ KEX names.  The checks cover selected KEX names, hybrid init/reply lengths, exchange-hash digest width, host-key signature verification, known-host trust, NEWKEYS, userauth, rekey, Git upload/receive exec requests, packet-boundary evidence, and binary stdin/stdout preservation.

After this gate, `SSH_Lib.Crypto.Hybrid_PQ_Kex.Readiness_Of` reports `Advertised_And_Selectable` for `mlkem768x25519-sha256`, `mlkem768x25519-sha512`, `sntrup761x25519-sha512@openssh.com`, and `sntrup761x25519-sha512`.


### Phase 19 completeness pass 298 — release-path drift closure

The default release runners now execute every split security executable listed by `tests/security/security_tests.gpr`, including the later PQ external-KAT, hybrid/PQ readiness, recorded OpenSSH transcript, side-channel assurance, live Git matrix, ProxyJump, rekey, and transport-message executables. The release tool sequence also runs `check_side_channel_assurance`, `check_formal_side_channel_proof`, `check_pq_hybrid_state`, `check_hybrid_pq_readiness`, and `check_live_git_matrix_report`, plus `check_live_proxycommand_report`. The live tests remain deterministic in default release verification because they skip unless their explicit `SSH_LIB_LIVE_*` environment gates are set.

Phase 19 completeness pass 299 adds an optional archived live Git matrix report. `test_live_git_interop_matrix` writes a deterministic key-value report when `SSH_LIB_LIVE_GIT_REPORT` names an output path. The default release path remains public-network-free, but `check_live_git_matrix_report` can be enabled with `SSH_LIB_REQUIRE_LIVE_GIT_REPORT=1` to require an archived passing report and, through `SSH_LIB_REQUIRED_LIVE_GIT_SCENARIOS`, to require specific scenarios such as `DIRECT`, `AGENT`, `IDENTITY`, `PASSWORD`, `PASSPHRASE`, `PROXYJUMP`, `RECEIVE`, or `ALL`.

Phase 19 completeness pass 301 hardens the archived live Git matrix report guard. When `SSH_LIB_REQUIRE_LIVE_GIT_REPORT=1` is set, `check_live_git_matrix_report` now requires exact report header, `enabled=true`, and final `result=PASS` lines, rejects any `result=FAIL`, `result=SKIP`, disabled, invalid-config, or unhandled-exception marker, and requires every configured scenario to have a completed passing line with both the session and exec channel opened. This prevents stale or partially passing archived evidence from satisfying a release profile.

Phase 19 completeness pass 302 further hardens the archived live Git matrix report guard. Required scenario evidence must now include a numeric positive `bytes=` value and an `exit_code=` field in addition to `stage=complete`, `session_opened=true`, and `channel_opened=true`. This prevents malformed, truncated, hand-edited, or stale archived reports with zero-byte/no-output scenarios from satisfying a release profile.


Phase 19 completeness pass 303 adds non-secret scenario metadata to the archived live Git matrix report and tightens `check_live_git_matrix_report` around it. Passing scenario evidence must now also prove strict host-key verification (`verify_known_host=true` and `strict_host_key=true`), while scenario-specific checks require the intended mode: `AGENT` must show `use_agent=true`, `IDENTITY` must show `identity_configured=true`, `PASSWORD` must show `password_configured=true`, `PASSPHRASE` must show both identity and passphrase configuration, `PROXYJUMP` must show `proxy_jump_configured=true`, and `RECEIVE` must show `service=receive-pack`. This makes archived release evidence validate the actual Version-facing SSH behavior instead of only proving that some bytes and an exit-status field were observed.


### Phase 19 completeness pass 304 — algorithm documentation drift closure

Pass 304 synchronizes the release-facing algorithm advertisement documentation with `SSH_Lib.Algorithms.Advertised_Name_List`. The documented KEX list now includes the four advertised hybrid/PQ OpenSSH names, and the documented host-key list now includes ECDSA P-256 raw and certificate algorithms. `check_pq_hybrid_state` now guards the security review, test guide, and threat model against reintroducing the stale pre-PQ/pre-ECDSA advertisement lists.


Phase 19 completeness pass 307 tightens the archived live Git matrix report guard again. `check_live_git_matrix_report` now validates `SSH_LIB_REQUIRED_LIVE_GIT_SCENARIOS` against the known scenario set (`DIRECT`, `AGENT`, `IDENTITY`, `PASSWORD`, `PASSPHRASE`, `PROXYJUMP`, `RECEIVE`, or `ALL`) and requires the archived report to contain the reporter-owned `scenario_list=` line. This prevents arbitrary or misspelled required scenario names from being satisfied by hand-written report fragments.

Phase 19 completeness pass 309 tightens the archived live Git matrix report guard again. Required scenario evidence must now be declared by the report's `scenario_list=` line as well as having a completed passing scenario line. `scenario_list=ALL` satisfies all known scenarios, an empty `scenario_list=` satisfies only the reporter default `DIRECT`, and mismatched scenario-list/report-line combinations fail the release guard.


Pass 310 note: archived live Git matrix evidence is now required to contain exactly one well-formed `scenario_list=` line. Empty means the reporter default `DIRECT`; non-empty entries must be known scenario names; `ALL` must stand alone. This prevents duplicate, malformed, or hand-edited matrix-shape declarations from satisfying release evidence checks.

Phase 19 completeness pass 311 tightens archived live Git matrix evidence again. `check_live_git_matrix_report` now rejects undeclared or unknown `scenario=` records, and every required scenario must appear exactly once in the report. This prevents duplicate PASS/FAIL mixtures, copied scenario records from another matrix shape, or extra hand-edited scenario lines from satisfying the live interoperability release gate.

Phase 19 completeness pass 312 tightens archived live Git matrix evidence again. `check_live_git_matrix_report` now requires every scenario declared by the report's single `scenario_list=` line to have exactly one corresponding `scenario=` record, and rejects records for undeclared scenarios. This makes the archived live interoperability report self-consistent as a complete matrix artifact, not merely a source of passing required scenario snippets.


Phase 19 completeness pass 313 tightens archived live Git matrix evidence again. The single `scenario_list=` declaration now rejects duplicate scenario names such as `DIRECT,DIRECT`; empty still means the reporter default `DIRECT`, scenario names must be known, and `ALL` must stand alone. This prevents duplicated matrix-shape declarations from disguising hand-edited or malformed live interoperability evidence.


### SFTP parser fuzz harness

`tests/fuzz/sftp_packet_fuzzer.adb` is a standalone coverage-guided fuzzing entry point for the public SFTP version-packet parser. It accepts one binary input path and treats all ordinary parse statuses as successful outcomes, so fuzzer findings are crashes, failed runtime checks, or abnormal exits. Seed inputs are stored in `tests/vectors/sftp/packet_fuzzer_seeds`.


## SFTP fuzzer seed corpus

Run `SSH_LIB_SFTP_FUZZ_REPORT=/tmp/sftp_fuzz_report ../ssh_lib_build/bin/tools/run_sftp_fuzzer_seed_corpus` to rebuild the standalone SFTP packet fuzzer and execute every deterministic seed. The harness has explicit modes for version negotiation, status, handle, data, name, attrs, extended reply, check-file, limits, and statvfs reply parsers. The report records seed pass/fail counts and whether external coverage-guided fuzzers are installed, including AFL++, honggfuzz, and cargo-afl.

Phase 19 completeness pass 315 completes the ProxyCommand support pass: subprocess pipe I/O now waits with configured timeouts, `Connect_Timeout_MS` is used as the fallback ProxyCommand pipe timeout, missing `sh` fails closed, deterministic fixtures cover `%h`, `%n`, `%p`, `%r`, `%%`, unknown percent preservation, trailing percent preservation, and direct `Proxy_Command => "none"`, and the opt-in live ProxyCommand suite includes both local `nc %h %p` interoperability evidence and a failure scenario for non-SSH subprocess output.

Phase 19 completeness pass 316 adds archived live ProxyCommand evidence. `test_live_proxycommand_transport` writes `SSH_LIB_LIVE_PROXYCOMMAND_REPORT` as deterministic key-value evidence with `scenario_list=`, per-scenario session/channel metadata, strict host-key metadata, token-expansion metadata, and expected-failure diagnostics. `check_live_proxycommand_report` is optional by default, but `SSH_LIB_REQUIRE_LIVE_PROXYCOMMAND_REPORT=1` requires a passing archived report and `SSH_LIB_REQUIRED_LIVE_PROXYCOMMAND_SCENARIOS` selects `BASIC`, `TOKEN`, `IPV6`, `FAILS_EARLY`, or `ALL`.

Phase 19 completeness pass 317 completes the ProxyCommand diagnostics and release-evidence policy. `Sessions.Last_Proxy_Command_Diagnostics` exposes non-secret child lifecycle state, the live ProxyCommand `HANGS` scenario proves timeout cleanup with close-attempt/close-complete metadata, and `release_artifacts/live_proxycommand_report.txt` is the default archived report path when `check_live_proxycommand_report` is required without an explicit `SSH_LIB_LIVE_PROXYCOMMAND_REPORT`.

Phase 19 completeness pass 318 extends the archived live-evidence convention beyond ProxyCommand. Live Git matrix evidence defaults to `release_artifacts/live_git_matrix_report.txt` when its guard is required without an explicit path, SFTP v4-v6 interop evidence defaults to `release_artifacts/sftp_v4_v6_interop_report.txt`, and the SFTP seed-fuzzer runner defaults to `release_artifacts/sftp_fuzzer_seed_report.txt`.
