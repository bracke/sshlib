
### Phase 19 completeness pass 308 — live Git zero-exit evidence gate

Pass 308 hardens the live Git interoperability matrix and archived report guard so a scenario only passes when the remote Git service provides a successful zero exit status. Archived report evidence must now include `exit_code=0`, and the live matrix runner rejects nonzero or missing channel exit-status observations instead of treating them as acceptable telemetry.

Phase 19 completeness pass 293: bundled ML-KEM ACVP JSON prompt/expectedResults files are now included for keyGen and encapDecap smoke conformance; larger official ACVP corpora can be imported into the same directories.


### Phase 19 completeness pass 288

- Added `check_pq_hybrid_state` to the release tools.
- The tool verifies that ML-KEM-768, SNTRUP761, the source-level hybrid KEX wrapper, and the SNTRUP external-conformance fixture are present while stale pre-SNTRUP-KEM implementation claims are rejected.
- Updated hybrid/PQ release-state documentation so advertisement is gated on imported external vectors and recorded OpenSSH validation, not on missing primitive boundaries.

# Testing and Release Verification

The default test suite is local, deterministic, and does not use the user’s real SSH state. It must not require public internet, real user SSH files, real `SSH_AUTH_SOCK`, real private keys, C fixtures, or real Git servers.

## Test organization

Suites are organized around:

- unit protocol tests
- unit crypto/key tests
- known_hosts tests
- config tests
- remote-name tests
- Git helper tests
- agent tests
- identity-file tests
- session fixture tests
- channel fixture tests
- timeout/failure tests
- API stability tests
- package hygiene tests

## Release verification runner

The preferred Ada-native release verification entry point is:

```sh
alr exec -- gprbuild -P ./tools/tools.gpr
../ssh_lib_build/bin/tools/run_release_validation
```

The Ada runner can also print the exact deterministic sequence without executing it:

```sh
../ssh_lib_build/bin/tools/run_release_validation --dry-run
```

The legacy shell wrapper remains available for POSIX environments:

```sh
../ssh_lib_build/bin/tools/run_release_validation
```

Both runners check the required Ada/Alire tools first, build every required GPR project, run the integrated and split security executables, then run all release/audit guards. They fail closed if the toolchain or an expected executable is missing. Neither runner enables public-network live tests; those remain controlled by their explicit environment gates. The expanded sequence below is the command-by-command form that the runners execute.

## Release command sequence

```sh
alr build
cd tests && alr exec -- gprbuild -P tests.gpr
../ssh_lib_build/bin/tests/main
cd tests && alr exec -- gprbuild -P security/security_tests.gpr
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
alr exec -- gprbuild -P tests/api_stability/api_stability.gpr
alr exec -- gprbuild -P tests/package_smoke/package_smoke.gpr
alr exec -- gprbuild -P tests/version_integration/version_integration.gpr
../ssh_lib_build/bin/version_integration/test_version_adapter_consumption
alr exec -- gprbuild -P examples/examples.gpr
# Optional only; may contact a user-supplied public SSH server.
# alr exec -- gprbuild -P examples/manual_examples.gpr
alr exec -- gprbuild -P tools/tools.gpr
../ssh_lib_build/bin/tools/check_release_toolchain
../ssh_lib_build/bin/tools/check_release_artifacts
../ssh_lib_build/bin/tools/check_release_sequence
../ssh_lib_build/bin/tools/check_release_runner
../ssh_lib_build/bin/tools/check_public_api
../ssh_lib_build/bin/tools/check_package_tree
../ssh_lib_build/bin/tools/check_release
../ssh_lib_build/bin/tools/check_compile_preflight
../ssh_lib_build/bin/tools/check_phase17_regressions
../ssh_lib_build/bin/tools/check_release_manifest
../ssh_lib_build/bin/tools/check_release_package
../ssh_lib_build/bin/tools/check_security
../ssh_lib_build/bin/tools/check_side_channel_assurance
../ssh_lib_build/bin/tools/check_formal_side_channel_proof
../ssh_lib_build/bin/tools/check_pq_hybrid_state
../ssh_lib_build/bin/tools/check_hybrid_pq_readiness
../ssh_lib_build/bin/tools/check_phase19_context
../ssh_lib_build/bin/tools/check_runtime_boundaries
../ssh_lib_build/bin/tools/check_live_git_matrix_report
../ssh_lib_build/bin/tools/check_live_proxycommand_report
../ssh_lib_build/bin/tools/check_binary_paths
../ssh_lib_build/bin/tools/check_no_subprocess --self-test
../ssh_lib_build/bin/tools/check_no_subprocess
../ssh_lib_build/bin/tools/check_sensitive_logging --self-test
../ssh_lib_build/bin/tools/check_sensitive_logging
```

If the local build directory is changed, adjust executable paths accordingly. The release guard checks public API text, secure defaults, documentation markers, absence of C/C-family sources, absence of subprocess fallback markers in library sources, obvious Ada keyword identifier violations, and Phase 19 security release-path integration.

## Phase 19 security release path

The split security project is no longer optional for release verification. `tests/security/security_tests.gpr` must be built and every executable it produces must be run before API stability, package smoke, version integration, examples, and audit tools are accepted. The integrated `tests/tests.gpr` runner still keeps the same assertions in the normal deterministic suite; the split security executables make each Phase 19 security area independently visible in release logs.

The release audit tool set is also mandatory: `check_security`, `check_side_channel_assurance`, `check_formal_side_channel_proof`, `check_pq_hybrid_state`, `check_hybrid_pq_readiness`, `check_runtime_boundaries`, `check_live_git_matrix_report`, `check_live_proxycommand_report`, `check_binary_paths`, `check_no_subprocess`, and `check_sensitive_logging` must run after `tools/tools.gpr` is built. `check_release` verifies that this command sequence remains documented, so security tests cannot silently drift back into optional status.


## Phase 17 release regressions

`check_phase17_regressions` is an Ada-only executable guard. It validates that:

- `Ok` remains the only success status.
- `Session_Options` secure defaults remain unchanged.
- Git command helpers keep rejecting NUL, LF, and CR.
- Git command helpers quote single quotes deterministically.
- common `git@example.com:repo.git` and `ssh://git@example.com:2222/group/repo.git` remote names keep their expected parse shape.
- the documented binary sentinel byte set, `0x00`, `0x0A`, `0x0D`, `0x7F`, `0x80`, and `0xFF`, remains represented through `Ada.Streams.Stream_Element_Array`.

This guard does not contact a network service and does not read the user’s real SSH files. It complements the fixture-backed channel/session tests rather than replacing them.

## Manifest guard

`check_release_manifest` verifies that the public `Library_Interface` list remains explicit, the API-stability consumer still contains the Version-facing call shape, the package smoke project is present, and the Version integration document remains discoverable.

Default automated tests require no public internet access. `examples/manual_examples.gpr` is intentionally excluded from the default release command sequence because `manual_git_upload_pack_probe.adb` is a user-driven real-server probe.

Phase 18 version-integration coverage is present in both places: `tests/version_integration/version_integration.gpr` compile-checks the adapter-shaped public API consumption, and the main deterministic fixture suite includes `Run_Phase_18_Version_Integration_Tests` for upload-pack, receive-pack, binary preservation, EOF, exit-status, and explicit-user/default-user merge behavior.

Phase 18 also includes explicit version-facing status-mapping checks for host-key unknown, host-key mismatch, authentication rejection, channel-open rejection, exec rejection, read timeout, and write timeout.

ProxyCommand entries are preserved by `SSH_Lib.Git_Transport.Prepare` as session transport data and are not executed during config resolution. `Sessions.Open` executes ProxyCommand only as the explicit subprocess-backed SSH transport. `ProxyJump` entries are resolved as data and routed by `Sessions.Open` through SSH direct-tcpip forwarding.

## Phase 18 manual Git-over-SSH probe

`examples/manual_examples.gpr` builds `manual_git_upload_pack_probe.adb` as an explicit opt-in example only. It is intentionally excluded from `examples/examples.gpr` and default release checks because it may contact a real SSH server. The probe requires the caller to provide a host, user, repository path, a trusted `known_hosts` entry, and working identity-file or ssh-agent authentication. It keeps host-key verification enabled, sends opaque request bytes with `Ada.Streams.Stream_Element_Array`, does not interpret pkt-line payloads or parse packfile data, and prints only status values plus an opaque byte count rather than raw protocol bytes.

Phase 18 pass 11 also verifies that API-stability executables keep session/channel call shapes compile-checked without performing default network operations, and that parsed-record remote resolution reports `Invalid_User` for no-user composition.

## Phase 18 completeness pass 14

Placeholder/public-package smoke tests must load explicit empty fixture config files rather than calling `Load_Default`. The only default-config reads in automated tests are the Phase 14 checks that first redirect the test environment provider to a temporary HOME.


Phase 19 completeness pass 14 keeps `test_host_key_negative` in the mandatory security release path and expands it with fixture-backed host-key ordering/trust assertions.


### Phase 19 completeness pass 17

Git command quoting security is now covered by `SSH_Lib.Tests.Fixtures.Command_Quoting`. The fixture calls the production `SSH_Lib.Git` builders and verifies exact single-argument quoting, invalid repository-path rejection, production `Open_Exec` command validation acceptance, and byte-exact exec request encoding. Shell-looking repository paths such as `$()` and backticks are treated as data and are not executed locally.


### Phase 19 completeness pass 19

`SSH_Lib.Tests.Fixtures.Fuzz_Lite` adds deterministic malformed-input sweeps for packet framing, SSH string length fields, known_hosts records, SSH config records, agent protocol framing, and identity-file section framing. The split executable `test_fuzz_lite` is part of the mandatory Phase 19 security release path and does not use public networks, real user SSH state, subprocesses, or random/unbounded fuzzing.


## Phase 19 hostile transcript fixture

`test_hostile_transcripts` runs deterministic scripted peer transcripts through the session-open lifecycle test support. It covers malformed identification, silent identification, unsupported algorithm intersections, bad KEX signatures, host-key trust failures, NEWKEYS/service-order failures, userauth failures, and channel-open failures. These tests are local and deterministic and are part of the mandatory Phase 19 security release path.


## Phase 19 Session.Open success-state fixture

`test_session_open_success_security` runs `SSH_Lib.Tests.Fixtures.Session_Open_Success.Assert_Session_Open_Success_Gates`. It proves the happy session-open transcript reaches public-open state only after every security gate is complete, and that removing any single gate maps to a non-`Ok` status and an inconsistent public-open state. This is part of the mandatory Phase 19 release path.


### Phase 19 completeness pass 24

Added deterministic `version` adapter consumption coverage. The fixture resolves an SSH remote through `SSH_Lib.Git_Transport.Prepare`, keeps host-key verification enabled, opens a local authenticated SSH_Lib session fixture, executes both `git-upload-pack 'repo.git'` and `git-receive-pack 'repo.git'`, writes opaque `Ada.Streams.Stream_Element_Array` request bytes, reads opaque binary response bytes byte-for-byte, sends EOF, reads exit status, and closes the channel/session without higher-level Git protocol interpretation or subprocess fallback.


### Phase 19 completeness pass 25 — compile preflight guard

`check_compile_preflight` is now part of release verification. It is not a replacement for `gprbuild` or `alr build`; it is a deterministic source-tree/GPR preflight that catches obvious drift before the real compiler is available: missing mandatory GPR projects, missing core specs/bodies, package bodies without same-unit specs, source-tree fixture leakage into library code, and accidental tab characters in Ada sources.

## Release-package hygiene guard

`check_release_package` is part of release verification. It is a deterministic release-package hygiene guard that verifies mandatory root files, documentation, GPR projects, split Phase 19 security executables, version integration tests, examples, and audit tools are present and named in the release command sequence. The guard also confirms that manual examples are optional and are not included in the default deterministic release test path.

The manual examples are optional and may require user-supplied SSH hosts or real SSH state. They remain in `examples/manual_examples.gpr`, while `examples/examples.gpr` stays deterministic.


### Phase 19 crypto primitive fixture

The split security suite includes:

```sh
../ssh_lib_build/bin/tests_security/test_crypto_primitives
```

This runner checks group14 Diffie-Hellman shared-secret agreement, group16 KEX selection/runtime guards, and RSA SHA-256/SHA-512 signature verification with deterministic vectors. Pass 70 extends this with a positive RSA SHA-512 vector and tamper-negative coverage. Later passes add SHA-1 compatibility coverage where it is deliberately ordered last.

### Phase 19 completeness pass 29 — ssh-agent transport backend

`test_agent_transport_security` is part of the mandatory Phase 19 security release path. It covers the Ada ssh-agent transport/client boundary: empty `SSH_AUTH_SOCK` rejection, zero-timeout mapping, closed-connection read/write failures, idempotent close, high-level identity and signature client cleanup, and pre-transport rejection of legacy `ssh-rsa` signing. The production transport backend uses GNAT.Sockets Unix-domain sockets and OpenSSH agent length framing; the test remains deterministic and does not require a real user agent.

```sh
../ssh_lib_build/bin/tests_security/test_agent_transport_security
../ssh_lib_build/bin/tests_security/test_live_channel_transport
```


### Phase 19 completeness pass 30

The mandatory security release path includes `test_live_channel_transport`. This deterministic fixture enables the live channel protected-packet boundary and verifies open/exec, write, read, and EOF packets cross that boundary without local `ssh`, `git`, or shell fallback.

## Phase 19 Completeness Pass 31 — release execution guards

`check_release_toolchain` and `check_release_artifacts` are part of the release command sequence. The toolchain guard reports missing `alr`, `gprbuild`, `gnatmake`, or `gcc` before the release run is trusted. The artifact guard runs after the project builds and verifies that the expected integrated test executable, split security executables, version-integration executables, examples, and audit tools exist in `../ssh_lib_build/bin/...`.

These guards are intentionally non-networked and deterministic. They do not invoke `ssh`, `git`, a shell fallback, or public-network fixtures. They also do not replace the actual test executions listed above; they make missing build outputs an explicit release failure.


### Phase 19 completeness pass 32

`check_release_sequence` is now part of release verification. It validates the documented command order without spawning processes: build first, integrated tests, split security tests, version integration, deterministic examples, tools build, toolchain/artifact guards, release-sequence guard, release/package/security guards, and audit self-tests. Manual examples remain commented and optional.


### Phase 19 completeness pass 33 — initial-context compliance

`test_phase19_context_compliance` and `check_phase19_context` compare the release tree against the original Phase 19 implementation context from this chat. They assert that required hardening packages, security suites, documentation sections, default-release commands, binary sentinel coverage, status mappings, and explicit live-runtime limitations remain present. This guard is intentionally deterministic and does not contact a network or read real user SSH state.

../ssh_lib_build/bin/tests_security/test_open_runtime_security

`test_open_runtime_security` runs `SSH_Lib.Tests.Fixtures.Open_Runtime.Assert_Public_Open_Runtime_Gates`. It calls the public `Sessions.Open` function for the deterministic local runtime host `transcript.example.test`, verifies that `Ok` publishes a fully open/encrypted/host-trusted/authenticated state, and verifies that ordinary non-fixture hosts enter the live DNS/TCP/identification/KEXINIT boundary. Later passes extend that path through KEX, known-host trust, userauth, and retained channel setup; remaining tests still mark channel-owned stream data as follow-up work.


## Phase 19 completeness pass 35 - cipher primitive implementation

Implemented native Ada chacha20-poly1305 AEAD, AES-GCM, plus AES-CTR and AES-CBC transport cipher support for `aes128-ctr`, `aes192-ctr`, `aes256-ctr`, `aes128-cbc`, `aes192-cbc`, and `aes256-cbc`, updated cipher advertisement to `chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr,aes256-cbc,aes192-cbc,aes128-cbc`, initialized directional cipher state during NEWKEYS from derived keys/IVs, and added deterministic AES-CTR and AES-CBC known-vector coverage. Unsupported legacy cipher names still fail closed with `Unsupported_Feature`.

## Phase 19 completeness pass 37

Pass 159 adds `diffie-hellman-group14-sha1` as a bounded compatibility fallback using the existing group14 finite-field primitive, SHA-1 exchange hash, SHA-1 session-key derivation, and the same strict host-key verification path; it is ordered after `diffie-hellman-group14-sha256` and before the extension marker.

The implemented algorithm advertisement is now consistent with the available primitives, RFC 8308 extension negotiation, and the current hybrid/PQ readiness gate. The client advertises `mlkem768x25519-sha256,mlkem768x25519-sha512,sntrup761x25519-sha512@openssh.com,sntrup761x25519-sha512,curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256,diffie-hellman-group-exchange-sha1,diffie-hellman-group18-sha512,diffie-hellman-group16-sha512,diffie-hellman-group14-sha256,diffie-hellman-group14-sha1,ext-info-c`, where `ext-info-c` is an extension marker and not a selectable KEX algorithm. It also advertises `ssh-ed25519-cert-v01@openssh.com,ecdsa-sha2-nistp256-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,ssh-rsa-cert-v01@openssh.com,ssh-ed25519,ecdsa-sha2-nistp256,rsa-sha2-512,rsa-sha2-256,ssh-rsa`, `chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr,aes256-cbc,aes192-cbc,aes128-cbc`, `umac-128-etm@openssh.com,umac-64-etm@openssh.com,umac-128@openssh.com,umac-64@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,hmac-sha1-etm@openssh.com,hmac-sha1,hmac-sha1-96-etm@openssh.com,hmac-sha1-96`, and compression `zlib@openssh.com,zlib,none`. The deterministic algorithm-security fixtures assert that selectable implemented algorithms negotiate successfully, `ext-info-c` is never selected, and unsupported alternatives remain rejected.


### Phase 19 completeness pass 40

Pass 40 strengthens the live channel execution boundary after the identity-file signing work.
It adds fixture-backed coverage for protected inbound `exit-status` requests, protected EOF handling,
and close-after-status behavior through `SSH_Lib.Channels.Read_Some`, `Exit_Status`, and `Close`.
The close path now also encodes `SSH_MSG_CHANNEL_CLOSE` through the live protected channel boundary
when live channel I/O is enabled. Ordinary public-network SSH remains gated by the still-explicit
live runtime backend limits documented in the security review.

## Phase 19 completeness pass 42 — runtime boundary inventory

`check_runtime_boundaries` is part of release verification. It checks `docs/RUNTIME_BOUNDARIES.md`, the deterministic public `Sessions.Open` runtime markers, AES-GCM/AES-CTR/AES-CBC cipher support, Ed25519 identity-file signing fixture support, live channel protected-packet markers, and the remaining explicit fail-closed runtime boundaries.

### Phase 19 completeness pass 43

`SSH_Lib.Tests.Fixtures.Open_Runtime.Assert_Public_Open_Runtime_Gates` now also verifies the identity-file userauth runtime boundary: the deterministic `Sessions.Open` identity path emits a protected `SSH_MSG_USERAUTH_REQUEST` transcript before authenticated state is published.

### Phase 19 completeness pass 44

The open-runtime fixture now checks both identity-file and agent authentication
through `SSH_Lib.Sessions.Userauth_IO`. Agent authentication must emit a plain
`SSH_MSG_USERAUTH_REQUEST`, encode protected userauth traffic, parse protected
`SSH_MSG_USERAUTH_SUCCESS`, and keep ordinary non-fixture hosts fail-closed.
`check_runtime_boundaries` also records the new agent userauth boundary.

### Phase 19 completeness pass 47

The open-runtime fixture now checks protected and decoded inbound service/userauth response transcripts for both agent-backed and identity-file-backed deterministic opens. These assertions complement the outbound transcript checks and help catch authentication paths that consume or skip replies without auditable packet evidence.

### Phase 19 completeness pass 48

Open-runtime coverage now includes protected userauth denial. The deterministic local fixture uses the reserved user `reject-auth` to force `SSH_MSG_USERAUTH_FAILURE` after the signed publickey request for both agent and identity-file authentication, and asserts `Authentication_Failed`, closed public session state, and no authenticated-state publication.

### Phase 19 completeness pass 49

`SSH_Lib.Tests.Fixtures.Open_Runtime.Assert_Public_Open_Runtime_Gates` now checks that an ordinary non-fixture host no longer returns the old top-level `Unsupported_Feature` gate. Non-fixture hosts enter the live DNS/TCP/SSH-identification/KEXINIT boundary and must still remain controlled by the live runtime gates; later passes connect known-host verification, production userauth, and retained channel setup. `check_runtime_boundaries` also verifies the new `SSH_Lib.Sessions.Live_Transport` source markers.


### Phase 19 completeness pass 50

The runtime-boundary guard now checks that `SSH_Lib.Sessions.Live_Transport` contains the live cleartext KEXINIT send/read/parse and algorithm-negotiation markers. The open-runtime fixture remains deterministic and non-networked; public-network success remains guarded by the implemented live KEX, known-host, userauth, retained channel setup, and remaining stream-data boundaries.

### Phase 19 completeness pass 51

The live public-network path now has a dedicated socket-backed transcript driver. Source-level checks should verify that non-fixture `Sessions.Open` reaches `Live_Transport.Connect_And_Run_Handshake`, that this routine uses `Live_Transcript` for connection, identification, cleartext packet write/read, and that public success remains impossible before the later KEX/NEWKEYS, host-key, and userauth gates complete.


### Phase 19 completeness pass 52

The live public-network runtime now reaches the full socket-backed open boundary using `SSH_Lib.Protocol.Kexdh`, `SSH_Lib.Protocol.Exchange_Hash`, `SSH_Lib.Protocol.Protected_Packets`, known-host/certificate validation, and protected userauth.  Fixtures and preflight guards now check that public `Ok` remains impossible unless the complete connected/encrypted/trusted/authenticated gate set is satisfied.

## Phase 19 completeness pass 53

- Added `SSH_Lib.Sessions.Live_Userauth` for socket-backed `ssh-userauth` service request and publickey authentication over `SSH_Lib.Sessions.Live_Transcript`.
- Live identity-file authentication now signs with the configured identity and sends `SSH_MSG_USERAUTH_REQUEST` over the protected transcript.
- Live ssh-agent authentication now uses `SSH_AUTH_SOCK`, requests identities/signatures from the agent, and sends the resulting publickey request over the protected transcript.
- Default known-host verification still blocks public-network authentication until known-host trust matching is wired; explicit `Verify_Known_Host => False` can exercise the live userauth boundary.


## Phase 19 completeness pass 54

`check_runtime_boundaries` now requires the live known-host trust markers in `SSH_Lib.Sessions.Live_Transport`: `Verify_Presented_Host_Key`, `SSH_Lib.Known_Hosts.Verify`, and host-key blob propagation from KEXDH into the known_hosts gate. This is a source-level guard because the default test suite remains non-networked.


Pass 56 adds native SHA-512 and RSA `rsa-sha2-512` verification/signing, allowing the live runtime to negotiate the preferred RSA SHA-512 host-key algorithm while retaining RSA SHA-256 fallback.


Phase 19 completeness pass 57 adds the retained live transcript boundary. Source guards now check for `SSH_Lib.Sessions.Live_Attachment`, for `Live_Transport` attaching rather than closing the transcript after authentication success, and for `Channel_IO` using the attached transcript for live channel open/exec protected packet reads and writes.

## Phase 19 completeness pass 66

Source-level coverage now requires live channel reads to keep global-request handling active after exec setup. This prevents post-authentication global notifications from being treated as malformed channel data during caller-driven `Read_Some` loops.

## Phase 19 completeness pass 69

Source-level coverage now requires the live userauth path to preserve the same banner semantics as the deterministic protocol fixtures: `USERAUTH_BANNER` is acceptable transient protocol data, not authentication completion.

## Phase 19 completeness pass 71

Added an opt-in live Git-over-SSH end-to-end test executable, `test_live_git_e2e.adb`. The default release suite still performs no public-network access: the executable exits successfully as skipped unless `SSH_LIB_LIVE_GIT_E2E=1` is set. When enabled, it requires `SSH_LIB_LIVE_GIT_HOST`, `SSH_LIB_LIVE_GIT_USER`, and `SSH_LIB_LIVE_GIT_REPO`, keeps known-host verification enabled, opens a real authenticated session, executes `git-upload-pack` by default or `git-receive-pack` when `SSH_LIB_LIVE_GIT_SERVICE=receive-pack`, writes an opaque Git flush packet, sends EOF, reads opaque stdout bytes, observes exit status, and closes the channel/session. This proves the public API sequence needed by `version` without adding higher-level Git protocol interpretation to the SSH library.

### Optional live Git-over-SSH proof command

This command is never required for deterministic release verification, but it is the explicit real-server proof for Phase 19 missing item nr 7:

```sh
export SSH_LIB_LIVE_GIT_E2E=1
export SSH_LIB_LIVE_GIT_HOST=example.com
export SSH_LIB_LIVE_GIT_USER=git
export SSH_LIB_LIVE_GIT_REPO=repo.git
# optional overrides:
export SSH_LIB_LIVE_GIT_PORT=22
export SSH_LIB_LIVE_GIT_KNOWN_HOSTS="$HOME/.ssh/known_hosts"
export SSH_LIB_LIVE_GIT_IDENTITY="$HOME/.ssh/id_ed25519"
export SSH_LIB_LIVE_GIT_SERVICE=upload-pack
../ssh_lib_build/bin/tests_security/test_live_git_e2e
```


### Phase 19 completeness pass 74 — explicit password userauth

Password authentication is now available only as an explicit caller-supplied `Session_Options` value. SSH_Lib does not prompt, persist, discover, or log passwords. The encoded `password` userauth request is emitted only over the protected packet transcript after transport encryption and host-key trust, and authenticated state is published only after a decoded `SSH_MSG_USERAUTH_SUCCESS`. Empty passwords and values containing NUL, CR, or LF fail closed before request emission.


### Phase 19 completeness pass 77: password material retention hardening

Explicit password authentication remains caller-supplied and protected-transport-only. The live authentication path now avoids retaining the caller-provided password in session-private stored options, clears the encoded password request buffer on all return paths, and records a structurally redacted plain userauth transcript for password requests. The encrypted protected outbound packet transcript is still retained for boundary inspection; no plaintext password is kept in the session diagnostic buffers.

## Phase 19 completeness pass 81

Pass 81 hardens default host-key verification for OpenSSH marker records.
`known_hosts` lines marked `@revoked` are now parsed instead of ignored; a
matching revoked key deterministically returns `Host_Key_Mismatch` and cannot be
re-enabled by a later ordinary trust line. `@cert-authority` records are used only for OpenSSH host-certificate CA trust and are never treated as ordinary raw host keys
because host certificates are outside the raw host-key trust model and must not
be treated as direct trust for a presented server key.


### Pass 127 live Git interoperability matrix

Pass 127 adds `test_live_git_interop_matrix.adb`, an opt-in live interoperability matrix for the Version-facing Git-over-SSH path. It performs no public-network access unless `SSH_LIB_LIVE_GIT_MATRIX=1` is set. When enabled, `SSH_LIB_LIVE_GIT_SCENARIOS` selects comma-separated scenarios such as `DIRECT`, `AGENT`, `IDENTITY`, `PASSWORD`, `PASSPHRASE`, `PROXYJUMP`, and `RECEIVE`; pass 128 makes this selector whitespace/case tolerant, rejects unknown scenario names before network access, and adds `ALL` as a shorthand for the full matrix.

The matrix keeps strict known-host verification enabled and exercises the public sequence required by Version: open an authenticated session, open an exec channel with a safely quoted Git service command, write an opaque Git flush packet, send EOF, read opaque stdout bytes, observe exit status, close the channel, and close the session. Scenario-specific values can be supplied with `SSH_LIB_LIVE_GIT_<SCENARIO>_<FIELD>` and fall back to the existing single-case names such as `SSH_LIB_LIVE_GIT_HOST`, `SSH_LIB_LIVE_GIT_USER`, `SSH_LIB_LIVE_GIT_REPO`, `SSH_LIB_LIVE_GIT_KNOWN_HOSTS`, `SSH_LIB_LIVE_GIT_IDENTITY`, `SSH_LIB_LIVE_GIT_PASSWORD`, `SSH_LIB_LIVE_GIT_IDENTITY_PASSPHRASE`, and `SSH_LIB_LIVE_GIT_PROXY_JUMP`.

Phase 19 completeness pass 130 adds `test_live_proxyjump_transport.adb`, a dedicated opt-in live ProxyJump transport proof separate from the Git matrix. It performs no network access unless `SSH_LIB_LIVE_PROXYJUMP=1` is set. `SSH_LIB_LIVE_PROXYJUMP_SCENARIOS` accepts `SINGLE`, `CHAIN`, `IPV6`, or `ALL`; each selected scenario requires explicit `HOST`, `USER`, `PROXY_JUMP`, and `COMMAND` values through `SSH_LIB_LIVE_PROXYJUMP_<FIELD>` or scenario-specific `SSH_LIB_LIVE_PROXYJUMP_<SCENARIO>_<FIELD>` variables. The test keeps strict known-host verification enabled, opens a ProxyJump-backed session, opens an exec channel over the tunneled target transport, reads stdout bytes without text conversion, observes exit status, closes channel/session, and clears password/passphrase options after each scenario.
Phase 19 completeness pass 314 adds `test_live_proxycommand_transport.adb`, a dedicated opt-in live ProxyCommand transport proof. It performs no network or subprocess-backed ProxyCommand access unless `SSH_LIB_LIVE_PROXYCOMMAND=1` is set. `SSH_LIB_LIVE_PROXYCOMMAND_SCENARIOS` accepts `BASIC`, `TOKEN`, `IPV6`, `FAILS_EARLY`, or `ALL`; each selected non-failure scenario requires explicit `HOST`, `USER`, `PROXY_COMMAND`, and `COMMAND` values through `SSH_LIB_LIVE_PROXYCOMMAND_<FIELD>` or scenario-specific `SSH_LIB_LIVE_PROXYCOMMAND_<SCENARIO>_<FIELD>` variables. `TOKEN` additionally requires the configured command to include `%h` and `%p`, proving the OpenSSH-style token expansion path. `FAILS_EARLY` proves a ProxyCommand that does not produce an SSH transport fails the session open instead of succeeding. The test keeps strict known-host verification enabled, opens a ProxyCommand-backed session, opens an exec channel, reads stdout bytes without text conversion, observes exit status, closes channel/session, and clears password/passphrase options after each scenario.
Phase 19 completeness pass 131 hardens `SSH_LIB_LIVE_PROXYJUMP_SCENARIOS`: comma-separated lists now reject empty entries such as `SINGLE,,CHAIN`, leading commas, trailing commas, and whitespace-only entries. This keeps the opt-in live ProxyJump test fail-closed instead of silently skipping part of the requested matrix.


## Opt-in live rekey transport proof

Phase 19 completeness pass 132 adds `test_live_rekey_transport.adb`.  It performs no network access unless `SSH_LIB_LIVE_REKEY=1` is set.  When enabled, it opens a strict-known-host live session, calls `SSH_Lib.Sessions.Rekey` before opening an exec channel, opens the command, calls `SSH_Lib.Sessions.Rekey` again while the channel exists, then drains stdout and closes the channel/session.  This proves explicit client-initiated rekeying without adding higher-level Git protocol interpretation.

Required variables are `SSH_LIB_LIVE_REKEY_HOST`, `SSH_LIB_LIVE_REKEY_USER`, and either `SSH_LIB_LIVE_REKEY_COMMAND` or `SSH_LIB_LIVE_REKEY_REPO`.  Optional variables include `SSH_LIB_LIVE_REKEY_KNOWN_HOSTS`, `SSH_LIB_LIVE_REKEY_IDENTITY`, `SSH_LIB_LIVE_REKEY_PASSWORD`, `SSH_LIB_LIVE_REKEY_IDENTITY_PASSPHRASE`, and `SSH_LIB_LIVE_REKEY_PROXY_JUMP`.

### Peer-initiated rekey source coverage

Phase 19 completeness pass 133 adds source-level support for protected `SSH_MSG_KEXINIT` dispatch during live channel reads.  A live server that initiates rekey while stdout/channel-control packets are being drained should now trigger `Rekey_With_Peer_Kexinit` instead of being treated as ordinary channel data.  This still requires live interoperability verification with a server configured to rekey aggressively.


### Phase 19 completeness pass 142

Pass 142 adds `tools/run_release_validation.adb`, an Ada-native release validation runner. It executes the same deterministic build/test/audit sequence as the POSIX shell runner without invoking a shell, supports `--dry-run`, honors `SSH_LIB_BUILD_ROOT`, fails closed when `alr`, `gprbuild`, `gnatmake`, or `gcc` is unavailable, and still leaves public-network live tests behind their existing opt-in gates.

## Phase 19 completeness pass 157

The auth-security fixture now verifies that parsed RSA identities can construct explicit rsa-sha2-256 userauth requests.  This guards the live retry path that tries rsa-sha2-512 first and then rsa-sha2-256 for RSA identity-file and ssh-agent authentication.


Phase 19 pass 172: protected-packet setup now handles `chacha20-poly1305@openssh.com` independently per direction. A server can negotiate ChaCha20-Poly1305 in only one direction and AES-CTR/CBC in the other direction; the AEAD direction uses a 16-byte Poly1305 tag while the AES direction keeps the negotiated SSH MAC. Deterministic fixtures cover both mixed per-direction chacha20-poly1305/AES negotiations.


Phase 19 pass 173: AES-GCM transport support is implemented for `aes256-gcm@openssh.com` and `aes128-gcm@openssh.com`. AES-GCM is handled as an AEAD packet mode with encrypted packet length, GHASH tag verification, 16-byte authentication tags, and no separate SSH MAC; mixed-direction negotiation with non-GCM ciphers remains supported.

### External PQ KAT validation

Phase 19 pass 284 adds `test_pq_external_kats` and the `tests/vectors/pq/` manifest directory.  This separates PQ conformance tracking from internal deterministic round-trip tests.  The manifest files identify the required ML-KEM-768 ACVP vector families and OpenSSH-compatible SNTRUP761 vector families that are validated together with the recorded OpenSSH transcript corpus before OpenSSH hybrid/PQ KEX advertisement is enabled.


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

## Phase 19 pass 295 SNTRUP761 corpus gate

The PQ external KAT executable now requires a bundled SNTRUP761 OpenSSH-shaped corpus:

- `tests/vectors/pq/SNTRUP761_OPENSSH_KAT_001.txt`
- `tests/vectors/pq/SNTRUP761_OPENSSH_KAT_002.txt`
- `tests/vectors/pq/SNTRUP761_OPENSSH_KAT_003.txt`
- `tests/vectors/pq/SNTRUP761_OPENSSH_KAT_004.txt`

Each vector is parsed and executed through seeded key generation, seeded encapsulation,
decapsulation, invalid-ciphertext fallback, and artifact digest checks.  This closes the
in-tree SNTRUP761 external-conformance gate; recorded OpenSSH transcript validation is
required before SNTRUP hybrid KEX advertisement can be enabled.

## Hybrid/PQ OpenSSH transcript validation

Phase 19 pass 296 adds `test_hybrid_pq_openssh_transcripts`.  It validates the recorded OpenSSH transcript corpus under `tests/vectors/pq/openssh_transcripts/` for all four hybrid/PQ KEX names before the readiness API reports `Advertised_And_Selectable`.  The fixture covers negotiation, hybrid byte lengths, exchange-hash width, host-key signature verification, known-host trust, userauth, channel exec requests for both Git service commands, rekey, packet-boundary evidence, and binary stdin/stdout preservation.


### Phase 19 completeness pass 298 — release-path drift closure

The default release runners now execute every split security executable listed by `tests/security/security_tests.gpr`, including the later PQ external-KAT, hybrid/PQ readiness, recorded OpenSSH transcript, side-channel assurance, live Git matrix, ProxyJump, rekey, and transport-message executables. The release tool sequence also runs `check_side_channel_assurance`, `check_formal_side_channel_proof`, `check_pq_hybrid_state`, `check_hybrid_pq_readiness`, and `check_live_git_matrix_report`, plus `check_live_proxycommand_report`. The live tests remain deterministic in default release verification because they skip unless their explicit `SSH_LIB_LIVE_*` environment gates are set.

Phase 19 completeness pass 299 adds an optional archived live Git matrix report. `test_live_git_interop_matrix` writes a deterministic key-value report when `SSH_LIB_LIVE_GIT_REPORT` names an output path. The default release path remains public-network-free, but `check_live_git_matrix_report` can be enabled with `SSH_LIB_REQUIRE_LIVE_GIT_REPORT=1` to require an archived passing report and, through `SSH_LIB_REQUIRED_LIVE_GIT_SCENARIOS`, to require specific scenarios such as `DIRECT`, `AGENT`, `IDENTITY`, `PASSWORD`, `PASSPHRASE`, `PROXYJUMP`, `RECEIVE`, or `ALL`.

Phase 19 completeness pass 301 hardens the archived live Git matrix report guard. When `SSH_LIB_REQUIRE_LIVE_GIT_REPORT=1` is set, `check_live_git_matrix_report` now requires exact report header, `enabled=true`, and final `result=PASS` lines, rejects any `result=FAIL`, `result=SKIP`, disabled, invalid-config, or unhandled-exception marker, and requires every configured scenario to have a completed passing line with both the session and exec channel opened. This prevents stale or partially passing archived evidence from satisfying a release profile.

Phase 19 completeness pass 302 further hardens the archived live Git matrix report guard. Required scenario evidence must now include a numeric positive `bytes=` value and an `exit_code=` field in addition to `stage=complete`, `session_opened=true`, and `channel_opened=true`. This prevents malformed, truncated, hand-edited, or stale archived reports with zero-byte/no-output scenarios from satisfying a release profile.


Phase 19 completeness pass 303 adds non-secret scenario metadata to the archived live Git matrix report and tightens `check_live_git_matrix_report` around it. Passing scenario evidence must now also prove strict host-key verification (`verify_known_host=true` and `strict_host_key=true`), while scenario-specific checks require the intended mode: `AGENT` must show `use_agent=true`, `IDENTITY` must show `identity_configured=true`, `PASSWORD` must show `password_configured=true`, `PASSPHRASE` must show both identity and passphrase configuration, `PROXYJUMP` must show `proxy_jump_configured=true`, and `RECEIVE` must show `service=receive-pack`. This makes archived release evidence validate the actual Version-facing SSH behavior instead of only proving that some bytes and an exit-status field were observed.


### Phase 19 completeness pass 304 — algorithm documentation drift closure

Pass 304 synchronizes the release-facing algorithm advertisement documentation with `SSH_Lib.Algorithms.Advertised_Name_List`. The documented KEX list now includes the four advertised hybrid/PQ OpenSSH names, and the documented host-key list now includes ECDSA P-256 raw and certificate algorithms. `check_pq_hybrid_state` now guards the security review, test guide, and threat model against reintroducing the stale pre-PQ/pre-ECDSA advertisement lists.


Phase 19 completeness pass 307 tightens the archived live Git matrix report guard again. `check_live_git_matrix_report` now validates `SSH_LIB_REQUIRED_LIVE_GIT_SCENARIOS` against the known scenario set (`DIRECT`, `AGENT`, `IDENTITY`, `PASSWORD`, `PASSPHRASE`, `PROXYJUMP`, `RECEIVE`, or `ALL`) and requires the archived report to contain the reporter-owned `scenario_list=` line. This prevents arbitrary or misspelled required scenario names from being satisfied by hand-written report fragments.

### Phase 19 completeness pass 309 — live Git scenario-list binding

The archived live Git matrix report guard now binds required scenarios to the reporter-owned `scenario_list=` line. `check_live_git_matrix_report` requires every scenario named through `SSH_LIB_REQUIRED_LIVE_GIT_SCENARIOS` to be declared by the archived report's `scenario_list=` line, or by `scenario_list=ALL`; the empty reporter list remains valid only for the default `DIRECT` scenario. This ensures archived evidence was produced for the intended live matrix shape, not assembled from unrelated passing scenario lines.


Pass 310 note: archived live Git matrix evidence is now required to contain exactly one well-formed `scenario_list=` line. Empty means the reporter default `DIRECT`; non-empty entries must be known scenario names; `ALL` must stand alone. This prevents duplicate, malformed, or hand-edited matrix-shape declarations from satisfying release evidence checks.

Phase 19 completeness pass 311 tightens archived live Git matrix evidence again. `check_live_git_matrix_report` now rejects undeclared or unknown `scenario=` records, and every required scenario must appear exactly once in the report. This prevents duplicate PASS/FAIL mixtures, copied scenario records from another matrix shape, or extra hand-edited scenario lines from satisfying the live interoperability release gate.

Phase 19 completeness pass 312 tightens archived live Git matrix evidence again. `check_live_git_matrix_report` now requires the complete report shape to match its single `scenario_list=` declaration: every declared scenario has exactly one `scenario=` record, and undeclared scenarios have none. This prevents `scenario_list=ALL` or other broad archived reports from hiding missing or duplicate non-required scenario evidence while still satisfying a narrower release profile.


Phase 19 completeness pass 313 tightens archived live Git matrix evidence again. The single `scenario_list=` declaration now rejects duplicate scenario names such as `DIRECT,DIRECT`; empty still means the reporter default `DIRECT`, scenario names must be known, and `ALL` must stand alone. This prevents duplicated matrix-shape declarations from disguising hand-edited or malformed live interoperability evidence.


### SFTP v4-v6 interop evidence

`../ssh_lib_build/bin/tools/run_sftp_v4_v6_interop` can write a deterministic report when `SSH_LIB_TEST_SFTP_V4_REPORT` is set. Default verification remains public-network-free, but release profiles that have access to a v4-v6 SFTP server can set `SSH_LIB_REQUIRE_SFTP_V4_REPORT=1` and run `../ssh_lib_build/bin/tools/check_sftp_v4_v6_interop_report` to require exactly one passing record for each version in `SSH_LIB_REQUIRED_SFTP_V4_VERSIONS` (default `4,5,6`).


### SFTP parser conformance and fuzzing

The deterministic Fuzz_Lite fixture now includes SFTP version-packet conformance cases for valid v3/v6 packets, advertised `versions`/`supported2` data, unknown extension skipping, invalid extension framing, unsupported versions, and malformed length fields. The standalone coverage-guided harness lives in `tests/fuzz/sftp_packet_fuzzer.adb`; build it with `cd tests && alr exec -- gprbuild -P fuzz/fuzz_tests.gpr` and seed AFL++/honggfuzz with `tests/vectors/sftp/packet_fuzzer_seeds`.


## SFTP fuzzer seed corpus

Run `SSH_LIB_SFTP_FUZZ_REPORT=/tmp/sftp_fuzz_report ../ssh_lib_build/bin/tools/run_sftp_fuzzer_seed_corpus` to rebuild the standalone SFTP packet fuzzer and execute every deterministic seed. The harness has explicit modes for version negotiation, status, handle, data, name, attrs, extended reply, check-file, limits, and statvfs reply parsers. The report records seed pass/fail counts and whether external coverage-guided fuzzers are installed, including AFL++, honggfuzz, and cargo-afl.

Phase 19 completeness pass 315 completes the ProxyCommand support pass: subprocess pipe I/O now waits with configured timeouts, `Connect_Timeout_MS` is used as the fallback ProxyCommand pipe timeout, missing `sh` fails closed, deterministic fixtures cover `%h`, `%n`, `%p`, `%r`, `%%`, unknown percent preservation, trailing percent preservation, and direct `Proxy_Command => "none"`, and the opt-in live ProxyCommand suite includes both local `nc %h %p` interoperability evidence and a failure scenario for non-SSH subprocess output.

Phase 19 completeness pass 316 adds archived live ProxyCommand evidence. `test_live_proxycommand_transport` writes `SSH_LIB_LIVE_PROXYCOMMAND_REPORT` as deterministic key-value evidence with `scenario_list=`, per-scenario session/channel metadata, strict host-key metadata, token-expansion metadata, and expected-failure diagnostics. `check_live_proxycommand_report` is optional by default, but `SSH_LIB_REQUIRE_LIVE_PROXYCOMMAND_REPORT=1` requires a passing archived report and `SSH_LIB_REQUIRED_LIVE_PROXYCOMMAND_SCENARIOS` selects `BASIC`, `TOKEN`, `IPV6`, `FAILS_EARLY`, or `ALL`.

Phase 19 completeness pass 317 completes the ProxyCommand diagnostics and release-evidence policy. `Sessions.Last_Proxy_Command_Diagnostics` exposes non-secret child lifecycle state, the live ProxyCommand `HANGS` scenario proves timeout cleanup with close-attempt/close-complete metadata, and `release_artifacts/live_proxycommand_report.txt` is the default archived report path when `check_live_proxycommand_report` is required without an explicit `SSH_LIB_LIVE_PROXYCOMMAND_REPORT`.

Phase 19 completeness pass 318 extends the archived live-evidence convention beyond ProxyCommand. Live Git matrix evidence defaults to `release_artifacts/live_git_matrix_report.txt` when its guard is required without an explicit path, SFTP v4-v6 interop evidence defaults to `release_artifacts/sftp_v4_v6_interop_report.txt`, and the SFTP seed-fuzzer runner defaults to `release_artifacts/sftp_fuzzer_seed_report.txt`.
