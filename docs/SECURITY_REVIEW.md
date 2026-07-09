# SSH_Lib Security Review

## Review checklist

- Host-key signature verification happens over the exact exchange hash.
- known_hosts trust is checked after signature verification and before authentication.
- `Verify_Known_Host`, `Strict_Host_Key`, and `Use_Agent` default to enabled.
- Unsupported or weak algorithms are not silently selected.
- Packet encryption and MAC protection are active before user authentication.
- Agent and identity-file signatures are over exact binary payloads.
- Git command helpers reject NUL, CR, LF, empty paths, and oversized paths.
- SSH config parsing never executes commands and cannot disable host-key verification.
- Channel data remains binary and opaque.
- Dirty sessions/channels are not reused after ambiguous or cryptographic failure.
- Resource limits are enforced for peer messages and local parser inputs.
- Public API calls map ordinary failures to `SSH_Lib.Errors.Status` values.

## Algorithm support

Implemented algorithm lists are advertised through `SSH_Lib.Algorithms`. Negotiation must select only implemented and advertised algorithms, preserve client preference order, reject unsupported intersections with `Unsupported_Feature`, select only implemented compression (`zlib@openssh.com`, `zlib`, or `none`), and place legacy SHA-1 `ssh-rsa` signing last as a bounded interoperability fallback. The default advertisement omits the broken/deprecated `hmac-md5*` MACs, `3des-cbc`, and `diffie-hellman-group1-sha1` (still recognized if a user re-enables them by configuration), and includes the `kex-strict-c-v00@openssh.com` marker.

The Terrapin countermeasure (CVE-2023-48795, strict key exchange) must be honored when both peers advertise their `kex-strict-*-v00@openssh.com` markers: the packet sequence number is reset to zero after NEWKEYS, and any extraneous transport message received during key exchange terminates the connection. This prevents undetected prefix truncation of the encrypted stream for `chacha20-poly1305@openssh.com` and Encrypt-then-MAC ciphers.

## Host-key verification

Unknown hosts return `Host_Key_Unknown`. Changed keys return `Host_Key_Mismatch`. An invalid KEX host-key signature returns `Handshake_Failed` even if known_hosts contains a matching blob. Hashed, wildcard, negated, unsupported, malformed, or wrong-port known_hosts entries are not accidentally trusted.

## Known-host trust

known_hosts is local policy input. It does not prove server key ownership. Trust is meaningful only after the server proves possession of the signed key through the exchange hash.

## Authentication

Authentication is attempted only after encrypted packet mode and host-key trust. `USERAUTH_SUCCESS` is required before a session is authenticated. Agent and identity-file parsers reject malformed, oversized, unsupported, wrongly encrypted, or mismatched key material deterministically, while supported encrypted identity envelopes require explicit non-retained passphrase input. Private material, signature payloads, signatures, and derived session keys must never be logged.

## Command quoting

`SSH_Lib.Git` constructs a single remote command string with the repository path as one single-quoted shell-safe argument. A single quote is emitted by closing the quoted argument, adding an escaped quote, and reopening the quoted argument. In source/tests the required form is `a'\''b.git`. The library validates commands for remote exec but does not invoke a local shell or local git.

## Remote/config parsing

Remote parsing returns deterministic `Invalid_Host`, `Invalid_Port`, `Invalid_User`, or `Invalid_Command` results for malformed input. Config resolution is data parsing only. `HostName` cannot alter the repository path. `ProxyCommand` is parsed as data during config resolution and executed only by `Sessions.Open` as the explicit subprocess-backed transport; `ProxyJump` is parsed as data and routed through SSH direct-tcpip forwarding. `IdentityFile $HOME/key` and backtick text are not shell-expanded.

## Binary stream preservation

The required binary safety set is `0x00`, `0x0A`, `0x0D`, `0x7F`, `0x80`, and `0xFF`. Regression tests cover packet buffers, channel queues, writes, agent messages, known_hosts blobs, identity-file fields, and Git fixture payloads where those paths exist. stdout and stderr remain distinct.

## Timeout and dirty-state behavior

Connect, read, and write timeouts are enforced across transport, handshake, authentication, and channel operations. Ambiguous partial writes do not return `Ok`; they mark the channel/session dirty and prevent automatic replay of Git request bytes. Close remains idempotent.

## Resource bounds

The audit guards packet length, agent message size, identity-file size, known_hosts line length, config line length, stderr buffers, channel pending buffers, open channel count, agent identity count, command length, and repository path length.

## Unsupported features

The crate intentionally keeps SSH server mode, SFTP server mode, C bindings, and default public-network tests unsupported. SCP upload is supported for regular files, while SFTP and the high-level file-transfer facade provide client-side upload/download, recursive tree, inventory, verify/delete/restore, resume, metadata, symlink, and modeled extension workflows. `SSH_Lib.Security_Keys` exposes a direct caller-supplied security-key signer boundary for hardware-backed SK userauth requests without ssh-agent. `SSH_Lib.Channels.Open_Shell` exposes non-PTY shell channels, `SSH_Lib.Channels.Open_PTY_Shell` exposes PTY-backed shell startup with optional terminal modes, `SSH_Lib.Channels.Resize_PTY` exposes PTY resize requests, `SSH_Lib.Channels.Open_Direct_TCPIP` exposes the SSH `direct-tcpip` channel primitive for caller-managed local forwarding, `SSH_Lib.Forwarding` exposes synchronous local and dynamic listeners, callback-based background accept services with optional accepted-connection caps, managed local/dynamic worker-pool services with bounded worker and accepted-connection caps, managed remote-forward services with request, accept, target-connect, bounded pump, and cancel-on-exit lifecycle, accepted-connection, one-connection SOCKS accept, X11 `DISPLAY` parsing and local X server connection helpers, SOCKS5 no-auth CONNECT, bounded `Pump_Once`, and bounded alternating `Pump_Bounded` primitives, `SSH_Lib.Git` exposes bounded pkt-line, capability-token/list, side-band, status-line, repository index/worktree model summaries, repository ref/object database summaries, explicit credential-helper execution, console credential prompting, bounded credential store management, repository tree traversal, pack header/object-at-offset with next-offset reporting, pack object-sequence validation, zlib object-data inflation with consumed-length reporting, delta and delta-chain/index metadata, caller-supplied delta application, complete v2 pack-index structural validation, pack-index object lookup, pack-index offset/pack, CRC/pack, and object-id/pack consistency validation for non-delta, immediate-delta, and bounded delta-chain entries, pack delta-base and dependency-graph validation, pack/index SHA-1 checksum verification, object-id, and ref-name helpers, `SSH_Lib.Git_Transport` exposes explicit local Git/SSH subprocess fallback helpers, `SSH_Lib.Sessions.Request_Remote_Forward` / `Cancel_Remote_Forward` expose remote-forward request primitives, and `SSH_Lib.Channels.Accept_Forwarded_TCPIP` drains the protected session stream to accept one pending server-opened forwarded channel; managed remote-forward orchestration is available through `Start_Managed_Remote_Forward_Service`; custom multi-client policy remains application responsibility. Non-interactive password, identity-passphrase, and password-change callbacks are implemented without storing returned secrets in session state; keyboard-interactive callbacks follow the same non-retention model. Explicit known_hosts append support is available for caller-controlled host-key acceptance, and `Trust_On_First_Use` can be enabled deliberately for unknown-host first-use writes; changed/revoked/malformed records still fail closed. ProxyJump is implemented internally as SSH direct-tcpip routing and has opt-in live tests only.

### Audit-tool self-tests

Phase 19 completeness pass 23 adds explicit self-test mode to the two heuristic source scanners that are most likely to drift: `check_no_subprocess --self-test` and `check_sensitive_logging --self-test`. These modes run deliberate blocked and allowed fixtures inside the tools without invoking subprocesses. The no-subprocess self-tests cover GNAT spawn calls, bare spawn/system/popen patterns, shell command literals, `ssh-agent`, `ssh-add`, and allowed remote `Open_Exec`/Git command strings. The sensitive-logging self-tests cover direct and multiline secret-bearing sinks, explicit redaction allowances, diagnostic status summaries, comments, and non-output labels.

Release verification must run each self-test before the corresponding full-tree scan.

## Security regression tests

Phase 19 adds audit packages, table-driven security status mapping, negative protocol case classification, binary byte-set checks, redaction checks, and release tools:

- `tools/check_security`
- `tools/check_no_subprocess`
- `tools/check_binary_paths`
- `tools/check_sensitive_logging`

Release verification must build and run `tests/security/security_tests.gpr` in addition to the integrated deterministic test runner. It must then run those tools after the ordinary build, security split tests, examples, API stability, package smoke, and version integration checks.


## Completeness pass 4 matrix hardening

The Phase 19 matrix is explicitly categorized so host-key, algorithm, packet-protection, authentication, command-quoting, remote/config, binary-stream, timeout/dirty-state, resource-bound, and exception-mapping cases cannot silently lose suite coverage. The matrix includes explicit guards for no subprocess fallback, no text conversion of Git protocol bytes, dirty-state non-reuse, timeout accounting, and bounded malformed input handling.

## Phase 19 Completeness Pass 5

The security regression matrix is now explicitly classified by security invariant as well as by review category and expected deterministic status. This ensures host-key, algorithm, packet-protection, authentication-ordering, command-quoting, config, binary-stream, dirty-state, resource-bound, and exception-containment cases cannot be represented as unlabeled status-only checks.

### Packet/MAC dirty-state fixture coverage

The Phase 19 packet-protection audit is backed by deterministic protected packet fixtures. Tests now construct protected packets with HMAC-SHA256 over the SSH sequence number and framed packet bytes, then verify valid decode, byte preservation, sequence increment behavior, bad-MAC rejection, wrong-sequence-MAC rejection, truncated packet rejection, invalid padding rejection after MAC verification, and deterministic rejection after the state is dirty.

### Binary byte-path matrix fixture

Phase 19 completeness pass 7 adds fixture-backed byte preservation coverage for packet buffers, SSH strings, cleartext packets, protected packets, channel data, pending stdout queues, stderr separation, agent protocol messages, identity-file decoded public fields, known-host/public-key raw blobs, and Git fixture payloads.


## Phase 19 completeness pass 8

Added concrete resource-bound oversized-input fixtures covering packet length, packet buffers, agent message and identity limits, identity-file size, config and known_hosts line bounds, pending stdout/stderr buffers, channel count limits, command length, and Git repository path length. `known_hosts` reading is now bounded so overlong records are ignored rather than trusted.

## No-subprocess audit scope

`tools/check_no_subprocess` is the primary no-subprocess regression guard. It scans `src`, `examples`, `tests`, and non-audit `tools` Ada/GPR sources. The audit intentionally excludes `check_no_subprocess`, `check_security`, and `check_release` because those tools must contain the forbidden token names they audit for.

The guard checks for subprocess APIs such as GNAT spawn/expect helpers, `system`, `popen`, `exec`, `execve`, `create_process`, and shell command paths. It also inspects Ada string literals for dangerous local command literals such as `ssh-agent`, `ssh-add`, `/bin/sh`, `cmd.exe`, and PowerShell. The library-source exceptions are `src/ssh_lib-sessions-live_transcript.adb`, where GNAT.Expect backs the explicit ProxyCommand transport, and `src/ssh_lib-git.adb`, where GNAT.Expect backs explicit Git credential-helper execution. Remote protocol strings including `git-upload-pack`, `git-receive-pack`, SSH URI parsing, and SSH config keywords are not local subprocess execution and are not rejected by this guard.


## Phase 19 completeness pass 10

Release verification now treats the split security suite as mandatory. The command sequence in `docs/TESTING.md` builds `tests/security/security_tests.gpr`, runs every materialized Phase 19 security executable, and then runs `check_security`, `check_no_subprocess`, `check_binary_paths`, and `check_sensitive_logging`. `check_release` guards those documentation markers.

## Exception-containment fixture coverage

Phase 19 completeness pass 11 adds fixture-backed exception-containment coverage.  The tests drive public API calls and malformed local file/config/remote inputs through production entry points and assert that ordinary malformed or rejected operations return deterministic `Status` values or documented rejection boundaries.  The fixture covers session open/close, channel open/read/write/eof/close/exit-status, known-host loading and verification, config loading and resolution, identity-file loading, remote-name parsing, channel dispatch failure, and safe Git command helper behavior.

## Phase 19 config-security fixture depth

Pass 12 adds `SSH_Lib.Tests.Fixtures.Config_Security.Assert_Config_Is_Data_Only` and split runner `test_config_security`. The fixture creates command-like `ProxyCommand`, `ProxyJump`, and `IdentityFile` values with marker paths and asserts that loading, resolving, unsupported-feature inspection, and `Resolve_Remote` never create those markers. It also asserts that `$HOME` is not shell-expanded, backtick command-substitution-looking identity data is preserved literally, host-key verification remains enabled, ProxyCommand is preserved by remote resolution without execution, while ProxyJump is preserved as data and routed by Sessions.Open through SSH direct-tcpip, and `HostName` cannot alter the parsed repository path.


## Authentication-order fixture depth

Phase 19 completeness pass 13 adds `SSH_Lib.Protocol.Authentication_Guards` and `SSH_Lib.Tests.Fixtures.Auth_Security.Assert_Userauth_Order_And_Signature_Payloads`. The fixture proves that user authentication cannot start before encrypted packet mode and host-key trust, that partial success and banner replies do not complete authentication, and that `USERAUTH_SUCCESS` is accepted only after setup preconditions pass. It also checks exact agent/identity signature-payload matching, including rejection of payloads built with a later rekey exchange hash, a different user, or a different public-key blob.


## Host-key verification fixture depth

Phase 19 completeness pass 14 adds fixture-backed host-key verification coverage. The tests prove that host-key signature failure is returned before local `known_hosts` trust is considered, valid signatures with absent hosts return `Host_Key_Unknown`, valid signatures with changed keys return `Host_Key_Mismatch`, unsupported/malformed/hashed/wildcard records are not accidentally trusted, `[host]:port` trust is exact, and authentication remains blocked until both signature verification and known-host trust have passed.

### Phase 19 Completeness Pass 15 — algorithm-negotiation fixture coverage

Algorithm negotiation now has fixture-backed security coverage in addition to the negative-case matrix. `SSH_Lib.Tests.Fixtures.Algorithm_Security.Assert_Algorithm_Negotiation_Security` exercises the production `SSH_Lib.Algorithms.Select_Algorithm` path, the KEX negotiation failure path, and explicit `SSH_Lib.Protocol.Algorithm_Guards` checks for malformed peer-selected algorithms. The fixture proves that only implemented algorithms are advertised, client preference order is preserved, unsupported intersections return `Unsupported_Feature`, selected algorithms must have been client-advertised, delayed `zlib@openssh.com` and stateful `zlib` compression negotiate only when both peers support them, legacy SHA-1/weak algorithms are rejected, inconsistent KEX replies fail, and failed negotiation clears partial result state.

## Timeout/dirty-state fixture depth

Phase 19 completeness pass 16 adds `SSH_Lib.Tests.Fixtures.Timeout_Dirty.Assert_All_Timeout_And_Dirty_State_Behavior`.  The fixture drives production channel/session helper paths for silent channel read timeout, channel-open timeout, exec-reply timeout, write timeout before any emitted bytes, partial-write timeout, partial-write socket failure, dirty-channel retry rejection, dirty-session channel-open rejection, failed `Open_Exec` cleanup, and idempotent close after dirty state.  Ambiguous partial Git request bytes dirty the channel and cannot be retried automatically.


### Phase 19 completeness pass 17

Git command quoting security is now covered by `SSH_Lib.Tests.Fixtures.Command_Quoting`. The fixture calls the production `SSH_Lib.Git` builders and verifies exact single-argument quoting, invalid repository-path rejection, production `Open_Exec` command validation acceptance, and byte-exact exec request encoding. Shell-looking repository paths such as `$()` and backticks are treated as data and are not executed locally.


## Malformed agent and identity-file fixture depth

Phase 19 completeness pass 18 adds fixture-backed malformed authentication-input coverage. `SSH_Lib.Tests.Fixtures.Auth_Security.Assert_Malformed_Agent_And_Identity_Fixtures` exercises agent frame length decoding, identity-list parsing, sign-response parsing, signature algorithm validation, and identity-file parsing with malformed, oversized, unsupported encrypted-algorithm/envelope, unsupported-key, and mismatched inputs. The checks are tied into the integrated runner and the split `test_auth_malformed_inputs` release executable.


## Fuzz_Lite fixture depth

Phase 19 completeness pass 19 adds `SSH_Lib.Tests.Fixtures.Fuzz_Lite`, a deterministic malformed-input sweep over packet framing, SSH string length fields, known_hosts records, SSH config records, agent protocol framing, and identity-file section framing. This is not coverage-guided fuzzing; it is a bounded regression fixture intended to make high-risk parser edge cases visible in default and split security release paths.

## Sensitive logging audit scope

Phase 19 completeness pass 20 expands `check_sensitive_logging` from a narrow source/example scan into a release-path guard over `src`, `examples`, `tests`, and non-audit `tools`. The guard strips Ada comments outside string literals, detects direct output and logging sinks, checks both spaced and identifier-style sensitive labels, and allows secret-related diagnostics only when the line is explicitly redacted or is a non-secret status/category/summary diagnostic. Audit-policy tools that must mention forbidden labels are excluded by name; the library, examples, fixtures, and normal tests remain scanned.


## Phase 19 hostile transcript coverage

Pass 21 adds deterministic hostile session-open transcript fixtures. The coverage drives the real private `Session` lifecycle flags through identification, KEX, host-key verification, NEWKEYS, service accept, userauth, and initial channel-open gates. Each hostile transcript returns the documented status and leaves the session closed; the successful transcript requires encrypted packet mode, host trust, and authentication before the session can be considered open.


### Session.Open success-state guard

Phase 19 pass 22 adds an explicit `SSH_Lib.Sessions.Open_Guards` postcondition helper. It centralizes the rule that `Sessions.Open` may return `Ok` only after every required security gate is complete: transport connected, identification complete, KEXINIT exchanged, algorithms negotiated, KEX complete, keys derived, NEWKEYS sent and received, encrypted inbound/outbound packet mode active, host-key signature verified, known-host trust established or explicitly bypassed, userauth service accepted, and user authenticated. `test_session_open_success_security` proves that clearing any single gate prevents a consistent public-open session.


### Phase 19 completeness pass 24

Added deterministic `version` adapter consumption coverage. The fixture resolves an SSH remote through `SSH_Lib.Git_Transport.Prepare`, keeps host-key verification enabled, opens a local authenticated SSH_Lib session fixture, executes both `git-upload-pack 'repo.git'` and `git-receive-pack 'repo.git'`, writes opaque `Ada.Streams.Stream_Element_Array` request bytes, reads opaque binary response bytes byte-for-byte, sends EOF, reads exit status, and closes the channel/session without higher-level Git protocol interpretation or subprocess fallback.


## Compile preflight guard

Phase 19 completeness pass 25 adds `check_compile_preflight` as an audit-grade source consistency guard. It verifies mandatory GPR projects, core public package specs, Phase 19 open-success guard units, package-body/spec pairing for package bodies, and the absence of test-fixture dependencies from library source. This guard is intentionally narrower than GNAT/GPR/Alire compilation and must run before, not instead of, the real build commands.

## Release-package hygiene guard

Phase 19 completeness pass 26 adds `check_release_package` as a Release-package hygiene guard. The guard verifies that required docs, GPR projects, split security tests, version-integration executables, examples, fixtures, and audit tools are present and documented in the release command sequence. It specifically prevents manual public-network examples from drifting into the default deterministic release path.


### Crypto primitive hardening fixture

Phase 19 completeness pass 28 adds deterministic coverage for native Ada group14 Diffie-Hellman shared-secret agreement and RSA SHA-256 PKCS#1 v1.5 host-key signature verification. Later passes added Ed25519 verification, RSA SHA-512/SHA-1 compatibility paths, and group18/group16 SHA-512 finite-field KEX coverage, so unsupported primitive failures are now limited to algorithm families that are not advertised.

### Phase 19 completeness pass 29 — ssh-agent transport hardening

`SSH_Lib.Agent.Transport` now owns a real Ada/GNAT.Sockets Unix-domain socket connection instead of returning `Unsupported_Feature` for every non-empty socket path. It frames outgoing agent payloads with the OpenSSH 32-bit length prefix, bounds incoming message sizes before allocation, reads exact payload bytes, closes and clears the connection after I/O failures, and maps ordinary socket errors to deterministic SSH statuses. `SSH_Lib.Agent.Client` is the high-level boundary for identity-list and signature requests and uses the existing agent protocol parser for malformed-input rejection.


## Phase 19 completeness pass 30: live channel transport boundary

Pass 30 introduces a protected-packet channel boundary used by session-owned open/exec traffic and channel-owned stream traffic. The new fixture proves that channel open, exec, stdin data, stdout data, and EOF are encoded or decoded at the encrypted packet boundary rather than remaining only retained plaintext fixture buffers.

## Release execution guard

Phase 19 completeness pass 31 adds two final release execution guards. `check_release_toolchain` records whether the local environment has the required Alire/GPR/GNAT toolchain before a release run is trusted. `check_release_artifacts` verifies that the documented build commands produced every expected deterministic test, split security test, version-integration executable, example, and audit tool. This closes the gap between source/package hygiene and actual release execution without adding subprocess fallback to the SSH library.


## Release sequence guard

Phase 19 completeness pass 32 adds `check_release_sequence`, an Ada-only release command ordering guard. It does not execute subprocesses; it validates that the deterministic release documentation keeps mandatory builds, integrated tests, split security tests, version-integration tests, deterministic examples, release tools, audit self-tests, and final audit scans in the required order while keeping manual public-network examples commented out.


### Phase 19 completeness pass 33 — initial-context compliance

This pass adds `test_phase19_context_compliance` and `check_phase19_context`. The test and tool compare the tree against the original Phase 19 context requirements: required packages/tools, mandatory security suites, security documentation sections, release-command coverage, secure defaults, status mappings, binary sentinel coverage, no-subprocess/no-secret-logging guards, and the explicit live-runtime fail-closed boundary.

## Public `Sessions.Open` runtime gate

Phase 19 pass 34 adds direct public-entry coverage for `Sessions.Open`. The deterministic local runtime path is reserved for `transcript.example.test`; it does not use public network access, user SSH state, subprocesses, or trust-on-first-use. It marks the session open only after transport, identification, KEX, key derivation, NEWKEYS, encrypted packet mode, host-key verification/trust, userauth service acceptance, and user authentication are all complete according to `SSH_Lib.Sessions.Open_Guards`. Non-fixture hosts now perform live DNS/TCP/identification/KEXINIT and continue to fail closed until the remaining live KEX/NEWKEYS/encrypted userauth backend is implemented.


## Phase 19 completeness pass 35 - cipher primitive implementation

Implemented native Ada chacha20-poly1305 AEAD, AES-GCM, plus AES-CTR and AES-CBC transport cipher support for `aes128-ctr`, `aes192-ctr`, `aes256-ctr`, `aes128-cbc`, `aes192-cbc`, `aes256-cbc`, and `3des-cbc`, updated cipher advertisement to `chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr,aes256-cbc,aes192-cbc,aes128-cbc`, initialized directional cipher state during NEWKEYS from derived keys/IVs, and added deterministic AES-CTR, AES-CBC, and 3DES-CBC coverage. Unsupported legacy cipher names still fail closed with `Unsupported_Feature`.


## Phase 19 completeness pass 36 public identity loading

`SSH_Lib.Keys.Load_Public_Identity` is no longer an unconditional placeholder. It performs bounded OpenSSH public-key line parsing, accepts only known SSH public-key algorithm names, preserves the canonical `algorithm encoded-key` identity text, and maps missing or malformed local public identity files to deterministic authentication failure. Private-key signing remains a separate fail-closed backend boundary.

## Phase 19 completeness pass 37

Pass 159 adds `diffie-hellman-group14-sha1` as a bounded compatibility fallback using the existing group14 finite-field primitive, SHA-1 exchange hash, SHA-1 session-key derivation, and the same strict host-key verification path; it is ordered after `diffie-hellman-group14-sha256` and before the extension marker.

The implemented algorithm advertisement is now consistent with the available primitives, RFC 8308 extension negotiation, and the current hybrid/PQ readiness gate. The client advertises `mlkem768x25519-sha256,mlkem768x25519-sha512,sntrup761x25519-sha512@openssh.com,sntrup761x25519-sha512,curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group18-sha512,diffie-hellman-group16-sha512,diffie-hellman-group14-sha256,diffie-hellman-group-exchange-sha256,diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha1,ext-info-c,kex-strict-c-v00@openssh.com`, where `ext-info-c` is an extension marker and not a selectable KEX algorithm. It also advertises `ssh-ed25519-cert-v01@openssh.com,ecdsa-sha2-nistp256-cert-v01@openssh.com,ecdsa-sha2-nistp384-cert-v01@openssh.com,ecdsa-sha2-nistp521-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,ssh-rsa-cert-v01@openssh.com,sk-ssh-ed25519-cert-v01@openssh.com,sk-ecdsa-sha2-nistp256-cert-v01@openssh.com,ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,rsa-sha2-512,rsa-sha2-256,sk-ssh-ed25519@openssh.com,sk-ecdsa-sha2-nistp256@openssh.com,ssh-rsa`, `chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr,aes256-cbc,aes192-cbc,aes128-cbc`, `umac-128-etm@openssh.com,umac-64-etm@openssh.com,umac-128@openssh.com,umac-64@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,hmac-sha1-etm@openssh.com,hmac-sha1,hmac-sha1-96-etm@openssh.com,hmac-sha1-96`, and compression `zlib@openssh.com,zlib,none`. The deterministic algorithm-security fixtures assert that selectable implemented algorithms negotiate successfully, `ext-info-c` is never selected, and unsupported alternatives remain rejected.

### Phase 19 completeness pass 38: identity-file signing capability gate

`SSH_Lib.Crypto.Private_Key_Signing.Can_Sign_Userauth` records whether an identity key can actually produce a userauth signature. The public open runtime uses this predicate before marking identity-file authentication successful. Unencrypted OpenSSH Ed25519, ECDSA P-256, ECDSA P-384, ECDSA P-521, and RSA identity files can sign userauth payloads; encrypted keys still fail closed with deterministic status values; unencrypted PKCS#1 RSA PEM keys are supported for RSA SHA-2 signing.


### Phase 19 completeness pass 39 identity-file signing

`SSH_Lib.Crypto.Private_Key_Signing` now produces payload-bound SSH signature blobs for validated unencrypted OpenSSH Ed25519, ECDSA P-256, ECDSA P-384, ECDSA P-521, and RSA identity files through `SSH_Lib.Identity_Files.Signing_Access`. RSA identity-file signing supports rsa-sha2-512 and rsa-sha2-256 PKCS#1 v1.5 signatures over the SSH userauth payload. P-384/P-521 ECDSA signing is backed by `CryptoLib.ECDSA` and has positive generated-signature verification coverage. The backend remains Ada-only and does not invoke local subprocesses or shells.


### Phase 19 completeness pass 40

Pass 40 strengthens the live channel execution boundary after the identity-file signing work.
It adds fixture-backed coverage for protected inbound `exit-status` requests, protected EOF handling,
and close-after-status behavior through `SSH_Lib.Channels.Read_Some`, `Exit_Status`, and `Close`.
The close path now also encodes `SSH_MSG_CHANNEL_CLOSE` through the live protected channel boundary
when live channel I/O is enabled. Ordinary public-network SSH remains gated by the still-explicit
live runtime backend limits documented in the security review.


### Phase 19 completeness pass 41

Release runner guard: `tools/run_release_validation.adb` is the Ada-native deterministic local release runner. It fails closed on missing toolchain/artifacts, run the integrated suite, split security suite, version-integration suite, deterministic examples, and all audit guards, and exclude manual/public-network examples from the default path.

## Runtime boundary inventory

Phase 19 completeness pass 42 adds `docs/RUNTIME_BOUNDARIES.md` and `check_runtime_boundaries`. The inventory keeps the review honest by separating implemented deterministic runtime pieces from remaining explicit fail-closed public-network boundaries.

### Phase 19 completeness pass 43

Identity-file userauth success now traverses `SSH_Lib.Sessions.Userauth_IO`, including publickey request construction, identity-backed signing, protected packet emission, success reply parsing, and authenticated-state publication after the reply.

### Phase 19 completeness pass 44

Agent authentication is no longer represented by a direct authenticated-state
assignment in the deterministic runtime. The reviewed boundary now includes an
ssh-agent-shaped sign request/response, protected userauth request emission,
protected success parsing, and delayed publication of authenticated session
state. This remains local deterministic fixture logic; live public-network agent
I/O remains fail-closed until the production transcript driver is connected.

### Phase 19 completeness pass 47

Review note: the userauth runtime boundary now exposes protected and decoded inbound response transcripts. Security review should treat direct mutation of `Userauth_Service_Accepted` or `User_Authenticated` without recorded `SERVICE_ACCEPT` / `USERAUTH_SUCCESS` traffic as a regression in the deterministic runtime path.

### Phase 19 completeness pass 48

Reviewed the deterministic publickey userauth boundary for negative server replies. Both agent and identity-file paths now exercise a protected `SSH_MSG_USERAUTH_FAILURE` fixture response and verify that denial does not publish `User_Authenticated` or public open state.

### Phase 19 completeness pass 49

The public-network `Sessions.Open` boundary is now socket-backed through identification, KEXINIT, Curve25519 or finite-field Diffie-Hellman KEX, NEWKEYS, host-key signature verification, known-host trust, protected userauth, and retained channel setup. Pass 65 hardens live channel setup by tolerating interleaved global requests while waiting for channel-open and exec replies; unsupported global requests with `want-reply` are answered with protected `REQUEST_FAILURE`, preserving stream synchronization without enabling optional forwarding or extension features.


### Phase 19 completeness pass 50

The public-network runtime boundary has advanced past the old KEXINIT/NEWKEYS stop point. Non-fixture hosts now proceed through live SSH identification, cleartext KEXINIT packet exchange, negotiated key exchange, NEWKEYS, protected-packet installation, host-key signature verification, known-host trust, protected userauth, and retained channel setup. Deterministic failure remains fail-closed at each boundary, so no unencrypted, unauthenticated, or untrusted public session can be published as `Ok`.


### Phase 19 completeness pass 52

The live public-network runtime now reaches the complete socket-backed open boundary: identification, KEXINIT, negotiated KEX including group-exchange, NEWKEYS, protected packet installation, strict host-key or host-certificate verification, known-host trust, protected userauth, and retained channel setup.  Public `Ok` remains a full security postcondition, not a partial-connect result.

## Phase 19 completeness pass 54

Live public-network host-key verification now calls the existing known_hosts verifier instead of returning the unconditional default-verification block. The live path maps trusted records to `Ok`, unknown records to `Host_Key_Unknown`, changed records to `Host_Key_Mismatch`, and unsupported/malformed trust material to deterministic fail-closed statuses before userauth.


Pass 56 adds native SHA-512 and RSA `rsa-sha2-512` verification/signing, allowing the live runtime to negotiate the preferred RSA SHA-512 host-key algorithm while retaining RSA SHA-256 fallback.

## Phase 19 completeness pass 66

The live read loop now keeps the global-request fail-closed policy active after channel setup. Unsupported protected global requests that ask for a reply are answered with protected `SSH_MSG_REQUEST_FAILURE`; ignorable transport/global response packets are skipped; unexpected non-channel packets still dirty the channel and fail the read.


### Phase 19 completeness pass 74 — explicit password userauth

Password authentication is now available only as an explicit caller-supplied `Session_Options` value. SSH_Lib does not prompt, persist, discover, or log passwords. The encoded `password` userauth request is emitted only over the protected packet transcript after transport encryption and host-key trust, and authenticated state is published only after a decoded `SSH_MSG_USERAUTH_SUCCESS`. Empty passwords and values containing NUL, CR, or LF fail closed before request emission.


### Phase 19 completeness pass 77: password material retention hardening

Explicit password authentication remains caller-supplied and protected-transport-only. The live authentication path now avoids retaining the caller-provided password in session-private stored options, clears the encoded password request buffer on all return paths, and records a structurally redacted plain userauth transcript for password requests. The encrypted protected outbound packet transcript is still retained for boundary inspection; no plaintext password is kept in the session diagnostic buffers.

## Phase 19 completeness pass 157: RSA SHA-2 publickey fallback

RSA publickey userauth is no longer pinned to a single SHA-2 signature algorithm.  For RSA identity-file and ssh-agent keys the live userauth path tries rsa-sha2-512 first and then rsa-sha2-256 before falling back to the next authentication method.  This improves interoperability with servers or agents that accept RSA keys only for one RSA/SHA-2 variant while placing legacy ssh-rsa/SHA-1 signatures last as a bounded interoperability fallback.  The signed identity request builder now accepts an explicit public-key algorithm so the preflight algorithm and the signed request algorithm remain bound to the same value.


Phase 19 pass 172: protected-packet setup now handles `chacha20-poly1305@openssh.com` independently per direction. A server can negotiate ChaCha20-Poly1305 in only one direction and AES-CTR/CBC in the other direction; the AEAD direction uses a 16-byte Poly1305 tag while the AES direction keeps the negotiated SSH MAC. Deterministic fixtures cover both mixed per-direction chacha20-poly1305/AES negotiations.


Phase 19 pass 173: AES-GCM transport support is implemented for `aes256-gcm@openssh.com` and `aes128-gcm@openssh.com`. AES-GCM is handled as an AEAD packet mode with encrypted packet length, GHASH tag verification, 16-byte authentication tags, and no separate SSH MAC; mixed-direction negotiation with non-GCM ciphers remains supported.
