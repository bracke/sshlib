# SSH_Lib Threat Model

## Assets

- SSH session confidentiality and integrity after key exchange.
- Server identity decisions derived from host-key signature verification and local known-host policy.
- User authentication material, including identity-file key material and agent signature payloads.
- Opaque Git protocol bytes sent over channel stdin/stdout.
- Deterministic public `SSH_Lib.Errors.Status` results for ordinary network, protocol, authentication, and file failures.

## Trusted inputs

- The compiled SSH_Lib library code.
- Explicit `Session_Options` chosen by the caller.
- The caller-owned destination remote name after it has been parsed and validated.
- Local known_hosts data as policy input only; it is not proof of key ownership by itself.

## Untrusted inputs

- Remote SSH server traffic is untrusted until authenticated and verified.
- SSH identification, KEXINIT, KEX replies, encrypted packets, channel messages, stderr data, and exit-status messages are untrusted peer input.
- known_hosts data is local policy input and may be malformed or stale.
- SSH config is local configuration input but must not execute commands.
- Repository path is untrusted command argument data.
- Channel bytes are opaque Git protocol data.
- Agent protocol replies and identity-file contents are untrusted parser input.

## Attacker capabilities

- A network attacker may drop, delay, truncate, reorder, or corrupt SSH transport bytes.
- A malicious server may offer unsupported algorithms, malformed packets, bad MACs, inconsistent KEX replies, oversized messages, invalid channel messages, or misleading stderr.
- A local configuration mistake may provide malformed known_hosts, unsupported config directives, invalid identity files, or unsafe repository names.
- A compromised or malicious agent may return malformed identities, oversized responses, or signatures with unexpected algorithms.

## Out-of-scope threats

- A user explicitly disabling host-key verification.
- Compromise of the local process, compiler, operating system, filesystem, or memory.
- Malicious code in the application consuming SSH_Lib.
- Git protocol object-format or full packfile validation; SSH_Lib exposes bounded pkt-line, capability-token/list, upload-pack negotiation line/request/ACK helpers, upload-pack fetch request composition, receive-pack update/request validation, protocol-v2 command request composition and validation, side-band, status-line, pack header/object-at-offset with next-offset reporting, pack object-sequence validation, zlib-object-data with consumed-length reporting, caller-supplied-delta and delta-chain/index metadata, complete v2 pack-index structural validation, pack-index object lookup, pack-index offset/pack, CRC/pack, and object-id/pack consistency validation for non-delta, immediate-delta, and bounded delta-chain entries, pack delta-base and dependency-graph validation, pack/index SHA-1 checksum verification, object-id, and ref-name helpers but does not interpret progress text, open SSH channels, maintain object databases, maintain ref databases, or track repository state.
- SSH server mode, SFTP server mode, C bindings, local `ssh`/`git` subprocess fallback, or higher-level Git protocol interpretation. Non-interactive password, identity-passphrase, password-change, and keyboard-interactive callbacks are implemented without retaining returned secrets. Explicit Git credential prompting/storage/helper APIs are caller-invoked and do not run during session open. `SSH_Lib.Security_Keys` exposes a direct caller-supplied security-key signer boundary for hardware-backed SK userauth requests without ssh-agent. `SSH_Lib.Channels.Open_Shell` exposes non-PTY shell channels, `SSH_Lib.Channels.Open_PTY_Shell` exposes PTY-backed shell startup with caller-provided terminal type, dimensions, and optional terminal modes, and `SSH_Lib.Channels.Resize_PTY` exposes PTY resize requests. ProxyJump is implemented as SSH `direct-tcpip` forwarding, including recursive comma-separated multi-hop routing and remains data-only until `Sessions.Open`. `SSH_Lib.Channels.Open_Direct_TCPIP` exposes the SSH `direct-tcpip` channel primitive for caller-managed local forwarding, `SSH_Lib.Forwarding` exposes synchronous local and dynamic listeners, callback-based background accept services with optional accepted-connection caps, managed local/dynamic worker-pool services with bounded worker and accepted-connection caps, accepted-connection, one-connection SOCKS accept, X11 `DISPLAY` parsing and local X server connection helpers, SOCKS5 no-auth CONNECT, bounded `Pump_Once`, and bounded alternating `Pump_Bounded` primitives, `SSH_Lib.Git` exposes bounded pkt-line, capability-token/list, side-band, status-line, credential-helper execution, console credential prompting, credential store management, pack header/object-at-offset with next-offset reporting, pack object-sequence validation, zlib-object-data with consumed-length reporting, caller-supplied-delta and delta-chain/index metadata, pack-index object lookup, pack-index offset/pack, CRC/pack, and object-id/pack consistency validation for non-delta, immediate-delta, and bounded delta-chain entries, pack delta-base and dependency-graph validation, pack/index SHA-1 checksum verification, object-id, and ref-name helpers, `SSH_Lib.Sessions.Request_Remote_Forward` / `Cancel_Remote_Forward` expose remote-forward request primitives, and `SSH_Lib.Channels.Accept_Forwarded_TCPIP` accepts pending server-opened forwarded channels; the application remains responsible for remote-forward fairness, cancellation, and policy across multiple active remote-forwarded connections. ProxyCommand is parsed as data during config resolution and is executed only by `Sessions.Open` as the explicit subprocess-backed SSH transport; Git credential helpers execute only through `Execute_Credential_Helper`. SCP upload is supported for regular files, while SFTP and the high-level file-transfer facade provide client-side upload/download, recursive tree, inventory, verify/delete/restore, resume, metadata, symlink, and modeled extension workflows.

## Security boundaries

- `SSH_Lib.Sessions.Open` is the boundary for creating a connected, encrypted, host-verified, authenticated session.
- `SSH_Lib.Channels.Open_Exec` is the boundary for opening a remote exec channel; it validates the command string but never invokes a local shell.
- `SSH_Lib.Channels.Read_Some` and `SSH_Lib.Channels.Write` are byte-stream boundaries and must not convert channel data to text.
- Config and known_hosts parsing are data-only boundaries.

## Host-key verification model

A valid host-key signature proves possession of the host private key for the exchange hash. A known_hosts match proves local trust policy. Both are required by default. `Verify_Known_Host` and `Strict_Host_Key` default to `True`, unknown hosts are rejected, changed keys are rejected, and automatic trust-on-first-use is not implemented. Callers that intentionally accept a key can use `SSH_Lib.Known_Hosts.Append_Trusted_Host`, which is separate from `Sessions.Open` and never runs implicitly.

SSH_Lib does not protect against a user explicitly disabling host-key verification.

## Authentication model

Authentication is permitted only after encrypted packet mode is active and host trust has passed or has been explicitly bypassed. `USERAUTH_SUCCESS` is required before the session is considered authenticated. Partial success is not complete success. Signature payloads are binary protocol data and must not be logged.

## Git command construction model

The library may construct remote exec command strings such as `git-upload-pack '<repo>'` and `git-receive-pack '<repo>'`. The repository path is rejected when empty or containing NUL, CR, or LF, and single quotes are escaped for one shell-safe remote argument. The library never invokes local `ssh`, `git`, `ssh-agent`, `ssh-add`, or shell commands.

## Binary stream model

Git protocol bytes are opaque. SSH_Lib must never parse, normalize, trim, validate as UTF-8, or line-convert them. Channel stdout and stdin use `Ada.Streams.Stream_Element_Array`, preserve NUL, CR/LF, 0x7F, 0x80, and 0xFF, and keep stderr separate from stdout.

## Failure/timeout model

Ordinary failures return deterministic status codes. Timeouts do not justify silent replay of ambiguous bytes. MAC/cipher failures, malformed encrypted packets, partial writes, and ambiguous transport failures dirty the affected session or channel so it cannot be reused unsafely. Close remains idempotent for cleanup.


## Completeness pass 4 matrix hardening

The Phase 19 matrix is explicitly categorized so host-key, algorithm, packet-protection, authentication, command-quoting, remote/config, binary-stream, timeout/dirty-state, resource-bound, and exception-mapping cases cannot silently lose suite coverage. The matrix includes explicit guards for no subprocess fallback, no text conversion of Git protocol bytes, dirty-state non-reuse, timeout accounting, and bounded malformed input handling.

## Phase 19 Completeness Pass 5

The security regression matrix is now explicitly classified by security invariant as well as by review category and expected deterministic status. This ensures host-key, algorithm, packet-protection, authentication-ordering, command-quoting, config, binary-stream, dirty-state, resource-bound, and exception-containment cases cannot be represented as unlabeled status-only checks.

## No local process boundary

SSH_Lib treats SSH, Git, agent, and config data as protocol/configuration input only. The library, examples, tests, and non-audit tools must not invoke local `ssh`, `git`, `ssh-agent`, `ssh-add`, shell, or process-spawn APIs. The only explicit audit exclusions are the audit tools that need to name forbidden tokens while scanning for them.


## Phase 19 release verification boundary

Security invariants are guarded in both the integrated deterministic suite and the split `tests/security/security_tests.gpr` release suite. The split suite is mandatory for release verification because it keeps host-key, algorithm, packet-protection, authentication, command-quoting, binary-stream, timeout/dirty-state, resource-bound, exception, matrix, invariant, and status-mapping failures visible as independent release gates.

## Exception-containment boundary

Ordinary network, authentication, protocol, malformed-file, malformed-config, and channel-dispatch failures are treated as controlled failure inputs.  Public APIs should return deterministic status values for those conditions, clean up transient state before returning, and reserve raised exceptions for programming errors outside the ordinary SSH failure model.  Phase 19 completeness pass 11 adds fixture-backed coverage for these public exception boundaries.

## Phase 19 config parsing boundary fixture

Pass 12 treats SSH config as hostile local data for the security boundary. Fixture-backed checks prove that command-like `ProxyJump` and `IdentityFile` values are parsed but never executed during config resolution, and `ProxyCommand` is preserved without execution until the explicit `Sessions.Open` transport boundary; `$HOME` and backtick syntax are not shell-expanded; config cannot disable host-key verification; and `HostName` affects only the connection target, not the untrusted repository path argument sent to the remote Git service.


## Phase 19 authentication-order fixture

Authentication is guarded as a post-encryption, post-host-trust protocol phase. The pass 13 fixture treats `USERAUTH_BANNER` as advisory text only, treats partial success as incomplete authentication, and requires signatures to cover the exact binary userauth payload whose session identifier is the first exchange hash, not a later rekey hash.


## Phase 19 host-key verification boundary fixture

Host-key ownership and local host trust are separate boundaries. Phase 19 completeness pass 14 adds fixture-backed checks proving that a known_hosts match cannot compensate for an invalid host-key signature, and a valid host-key signature cannot compensate for an unknown or changed known_hosts policy result. Authentication is not allowed to start until both boundaries pass, unless the caller explicitly disables known-host verification; that bypass still does not bypass signature verification.

### Algorithm negotiation boundary

Algorithm name-lists from a server are untrusted until validated and intersected with the client-advertised implementation set. A peer-selected or reply-implied algorithm is accepted only when it was advertised by the client for the matching class and is implemented by the crate. Compression supports delayed `zlib@openssh.com`, immediate stateful `zlib`, and `none` as a fallback through the Ada `zlib` dependency. Delayed compression is armed at NEWKEYS and activated only after USERAUTH_SUCCESS; legacy SHA-1 host-key signatures are last-resort only, while weak ciphers and unsupported compression names remain rejected rather than silently selected.

## Phase 19 timeout/dirty-state fixture

The timeout/dirty-state fixture treats silence and ambiguous partial I/O as hostile or synchronization-losing conditions.  Reads with no queued data return `Timeout` without exposing bytes.  Partial writes that time out or fail dirty the channel, and later writes/control requests are rejected so Git request bytes are never replayed ambiguously.  Channel-open and exec-reply timeouts release transient channel slots and leave returned channel handles unusable.


### Phase 19 completeness pass 17

Git command quoting security is now covered by `SSH_Lib.Tests.Fixtures.Command_Quoting`. The fixture calls the production `SSH_Lib.Git` builders and verifies exact single-argument quoting, invalid repository-path rejection, production `Open_Exec` command validation acceptance, and byte-exact exec request encoding. Shell-looking repository paths such as `$()` and backticks are treated as data and are not executed locally.


## Phase 19 malformed authentication-input fixture

Malformed agent messages and local identity files are treated as untrusted authentication inputs. The Phase 19 malformed-input fixture verifies that oversized or malformed agent replies and malformed private-key files, unsupported encrypted algorithms/envelopes, unsupported key algorithms, missing/wrong passphrases, and public/private mismatches fail deterministically and do not grant authentication or expose private key material.


## Phase 19 Fuzz_Lite malformed-input fixture

Malformed peer packets, agent replies, known_hosts records, SSH config records, and identity-file sections are treated as untrusted input. The deterministic Fuzz_Lite fixture asserts that representative malformed encodings are rejected or ignored safely with deterministic statuses and without executing local commands or reading real user SSH state.

## Phase 19 sensitive-logging audit boundary

Private keys, session keys, shared secrets, signature payloads, agent signatures, identity seeds, passwords, and passphrases are never safe diagnostic payloads. Phase 19 completeness pass 20 treats source, examples, tests, and non-audit tools as within the sensitive-logging boundary. Deliberate audit tools may contain policy token text, but production and fixture code must either avoid secret-bearing output entirely or use explicit redaction markers.


## Hostile transcript model

A malicious or malformed peer may stall or send invalid data at any session-open stage: identification, KEXINIT/algorithm negotiation, host-key signature verification, NEWKEYS, service accept, userauth, or channel open. Phase 19 hostile transcript tests require these failures to return deterministic statuses and leave no authenticated reusable session behind.


### Session open success boundary

The session-open boundary treats `Ok` as a security postcondition, not merely a connectivity result. A session is usable only after encrypted packet mode, server-key ownership, local host trust, and user authentication have all completed. Missing any one of those gates is a failure and must not expose a reusable session.


## Audit-tool self-test boundary

The subprocess and sensitive-logging scanners are heuristic release guards. Their self-test modes use in-process synthetic Ada lines rather than external command execution. These self-tests prove that the guards reject representative dangerous patterns and preserve allowed protocol/config text, but they do not replace compiler/test execution or manual security review.


### Phase 19 completeness pass 24

Added deterministic `version` adapter consumption coverage. The fixture resolves an SSH remote through `SSH_Lib.Git_Transport.Prepare`, keeps host-key verification enabled, opens a local authenticated SSH_Lib session fixture, executes both `git-upload-pack 'repo.git'` and `git-receive-pack 'repo.git'`, writes opaque `Ada.Streams.Stream_Element_Array` request bytes, reads opaque binary response bytes byte-for-byte, sends EOF, reads exit status, and closes the channel/session without higher-level Git protocol interpretation or subprocess fallback.


## Phase 19 compile-preflight boundary

`check_compile_preflight` is a local deterministic release guard. It protects against source-tree and project-file drift that could weaken security tests or omit required units, but it is not a compiler, linker, or semantic verifier. The trusted release boundary still requires GNAT/GPR/Alire builds and execution of the integrated, split security, version integration, examples, and audit-tool test suites.

## Phase 19 release-package hygiene boundary

The release-package hygiene boundary is enforced by `check_release_package`. The guard treats omitted security tests, missing docs, missing audit tools, missing version-integration executables, or accidental promotion of manual examples into the default deterministic path as release failures. This does not prove semantic correctness, but it prevents package assembly drift from weakening the security review surface.


### Cryptographic primitive boundary

Phase 19 completeness pass 28 narrows the primitive gap by implementing group14 Diffie-Hellman and RSA SHA-256 verification in Ada. Unsupported primitives must continue to fail closed; they must not be advertised or accepted silently.

### Phase 19 completeness pass 29 — agent transport boundary

`SSH_AUTH_SOCK` is local configuration input naming a Unix-domain socket. The path is treated as data only and is never shell-expanded or executed. The agent protocol peer is trusted only to hold private keys; all responses remain untrusted binary protocol data until size checks and parser validation succeed. The library never invokes `ssh-agent`, `ssh-add`, `ssh`, `git`, or a shell to obtain credentials.


## Phase 19 completeness pass 30: live channel boundary

Channel control and stream messages are security-boundary data once the session is authenticated and encrypted. Pass 30 adds explicit protected-packet hooks for those messages. The fixture remains deterministic and local; it does not weaken the rule that real public `Sessions.Open` must only return `Ok` after authenticated, encrypted, host-verified setup.

## Phase 19 release execution boundary

The release execution boundary is guarded by `check_release_toolchain` and `check_release_artifacts`. These tools treat missing build tools or missing post-build executables as release failures. They do not execute remote SSH, local Git, local ssh-agent commands, or shell fallbacks; they only verify local release prerequisites and local build artifacts. A release is not accepted until the documented commands have been run and the expected artifacts exist.


## release sequence boundary

Phase 19 completeness pass 32 adds `check_release_sequence`, an Ada-only release command ordering guard. It does not execute subprocesses; it validates that the deterministic release documentation keeps mandatory builds, integrated tests, split security tests, version-integration tests, deterministic examples, release tools, audit self-tests, and final audit scans in the required order while keeping manual public-network examples commented out.


### Phase 19 completeness pass 33 — initial-context compliance

This pass adds `test_phase19_context_compliance` and `check_phase19_context`. The test and tool compare the tree against the original Phase 19 context requirements: required packages/tools, mandatory security suites, security documentation sections, release-command coverage, secure defaults, status mappings, binary sentinel coverage, no-subprocess/no-secret-logging guards, and the explicit live-runtime fail-closed boundary.

## Deterministic local open-runtime fixture

The reserved host `transcript.example.test` is local deterministic test infrastructure. It exists to exercise the public `Sessions.Open` success-state gate without public network access or real user SSH state. It does not weaken normal host-key verification, does not add trust-on-first-use, and does not execute local ssh/git/shell commands. Ordinary hosts now enter the live DNS/TCP/identification/KEXINIT backend and still require live KEX/NEWKEYS plus encrypted packet/userauth before success.


## Phase 19 completeness pass 35 - cipher primitive implementation

Implemented native Ada chacha20-poly1305 AEAD, AES-GCM, plus AES-CTR and AES-CBC transport cipher support for `aes128-ctr`, `aes192-ctr`, `aes256-ctr`, `aes128-cbc`, `aes192-cbc`, and `aes256-cbc`, updated cipher advertisement to `chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr,aes256-cbc,aes192-cbc,aes128-cbc`, initialized directional cipher state during NEWKEYS from derived keys/IVs, and added deterministic AES-CTR and AES-CBC known-vector coverage. Unsupported legacy cipher names still fail closed with `Unsupported_Feature`.


## Phase 19 completeness pass 36 public identity loading

`SSH_Lib.Keys.Load_Public_Identity` is no longer an unconditional placeholder. It performs bounded OpenSSH public-key line parsing, accepts only known SSH public-key algorithm names, preserves the canonical `algorithm encoded-key` identity text, and maps missing or malformed local public identity files to deterministic authentication failure. Private-key signing remains a separate fail-closed backend boundary.

## Phase 19 completeness pass 37

Pass 159 adds `diffie-hellman-group14-sha1` as a bounded compatibility fallback using the existing group14 finite-field primitive, SHA-1 exchange hash, SHA-1 session-key derivation, and the same strict host-key verification path; it is ordered after `diffie-hellman-group14-sha256` and before the extension marker.

The implemented algorithm advertisement is now consistent with the available primitives, RFC 8308 extension negotiation, and the current hybrid/PQ readiness gate. The client advertises `mlkem768x25519-sha256,mlkem768x25519-sha512,sntrup761x25519-sha512@openssh.com,sntrup761x25519-sha512,curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256,diffie-hellman-group-exchange-sha1,diffie-hellman-group18-sha512,diffie-hellman-group16-sha512,diffie-hellman-group14-sha256,diffie-hellman-group14-sha1,ext-info-c`, where `ext-info-c` is an extension marker and not a selectable KEX algorithm. It also advertises `ssh-ed25519-cert-v01@openssh.com,ecdsa-sha2-nistp256-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,ssh-rsa-cert-v01@openssh.com,ssh-ed25519,ecdsa-sha2-nistp256,rsa-sha2-512,rsa-sha2-256,ssh-rsa`, `chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr,aes256-cbc,aes192-cbc,aes128-cbc`, `umac-128-etm@openssh.com,umac-64-etm@openssh.com,umac-128@openssh.com,umac-64@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,hmac-sha1-etm@openssh.com,hmac-sha1,hmac-sha1-96-etm@openssh.com,hmac-sha1-96`, and compression `zlib@openssh.com,zlib,none`. The deterministic algorithm-security fixtures assert that selectable implemented algorithms negotiate successfully, `ext-info-c` is never selected, and unsupported alternatives remain rejected.

### Identity-file signing boundary

Private-key material must not be treated as an authenticated login unless the library can produce the exact SSH userauth signature. Phase 19 pass 38 adds a signing capability gate so identity-file-only public open fails closed while signing remains unavailable.


### Phase 19 completeness pass 39 identity-file signing boundary

Identity-file private material remains local secret input. The signing backend consumes validated Ed25519 key material in memory, constructs a payload-bound signature blob, clears temporary seed/signature buffers where practical, and never logs private material or invokes external commands.


### Phase 19 completeness pass 40

Pass 40 strengthens the live channel execution boundary after the identity-file signing work.
It adds fixture-backed coverage for protected inbound `exit-status` requests, protected EOF handling,
and close-after-status behavior through `SSH_Lib.Channels.Read_Some`, `Exit_Status`, and `Close`.
The close path now also encodes `SSH_MSG_CHANNEL_CLOSE` through the live protected channel boundary
when live channel I/O is enabled. Ordinary public-network SSH remains gated by the still-explicit
live runtime backend limits documented in the security review.


### Phase 19 completeness pass 41

release runner boundary: `tools/run_release_validation.adb` is the Ada-native deterministic local release runner. It fails closed on missing toolchain/artifacts, run the integrated suite, split security suite, version-integration suite, deterministic examples, and all audit guards, and exclude manual/public-network examples from the default path.

## Runtime boundary inventory

The runtime boundary inventory is part of the security boundary. It documents where deterministic local runtime fixtures are accepted and where ordinary public-network SSH still fails closed until production transcript/userauth verification is complete.

### Phase 19 completeness pass 43

The userauth runtime boundary now separates key parsing/signing from authenticated session state. Protected `SSH_MSG_USERAUTH_REQUEST` handling and parsed success replies are required before identity-file, agent, password, or callback authentication can publish authenticated session state. The ordinary public-network path uses the same live encrypted transcript boundary instead of a fixture-only userauth shortcut.

### Phase 19 completeness pass 44

The ssh-agent threat boundary treats agent output as untrusted protocol data.
The deterministic runtime parses an agent-shaped signature response and still
requires a protected `SSH_MSG_USERAUTH_SUCCESS` before authentication state is
published. No local `ssh`, `ssh-agent`, `ssh-add`, `git`, shell, or real user
agent socket is invoked by the deterministic release path.

### Phase 19 completeness pass 47

The runtime boundary inventory now includes inbound userauth response transcript evidence. In the deterministic local runtime, an attacker model that attempts to force authenticated state without a protected `SERVICE_ACCEPT` / `USERAUTH_SUCCESS` response should be caught by fixture coverage and runtime-boundary review guards.

### Phase 19 completeness pass 48

Threat model note: a server-side `SSH_MSG_USERAUTH_FAILURE` after a valid signed publickey request is authoritative. The deterministic runtime now models that denial explicitly and maps it to `Authentication_Failed`, preserving the invariant that only decoded `SSH_MSG_USERAUTH_SUCCESS` may publish authenticated state.

### Phase 19 completeness pass 49

The old blanket `Unsupported_Feature` result for all ordinary public-network hosts has been replaced by a concrete live TCP/SSH-identification/KEXINIT boundary. This reduces placeholder scope without weakening the success gate: a public session still cannot open until KEX, NEWKEYS, host-key verification, and userauth complete over the live protected transcript.


### Phase 19 completeness pass 50

The live public-network peer can now influence the parsed server KEXINIT and negotiated algorithm set. That input is still bounded by the cleartext packet decoder and KEXINIT parser before any session state beyond `Kexinit_Exchanged` / `Algorithms_Negotiated` is marked, and the path remains fail-closed before public success.

### Phase 19 completeness pass 51

Live peer-controlled bytes now enter through `SSH_Lib.Sessions.Live_Transcript`, which centralizes packet length validation and transcript recording for cleartext and protected SSH packets. The live path remains fail-closed before exposing a session to callers, so a malicious peer can at most drive deterministic connection, identification, KEXINIT parsing, or handshake-failure outcomes until KEX and authentication are completed.


### Phase 19 completeness pass 52

The live public-network runtime now reaches the complete KEX/NEWKEYS/protected-packet/known-host/userauth/channel-publication boundary using the socket-backed transcript driver.  A reusable session is exposed only after the connected, encrypted, host-verified or certificate-verified, trusted, and user-authenticated gates all hold.

## Phase 19 completeness pass 53

- Added `SSH_Lib.Sessions.Live_Userauth` for socket-backed `ssh-userauth` service request and publickey authentication over `SSH_Lib.Sessions.Live_Transcript`.
- Live identity-file authentication now signs with the configured identity and sends `SSH_MSG_USERAUTH_REQUEST` over the protected transcript.
- Live ssh-agent authentication now uses `SSH_AUTH_SOCK`, requests identities/signatures from the agent, and sends the resulting publickey request over the protected transcript.
- Default known-host verification still blocks public-network authentication until known-host trust matching is wired; explicit `Verify_Known_Host => False` can exercise the live userauth boundary.


## Phase 19 completeness pass 54

The public-network handshake now separates three server-identity steps in order: parse the KEX host key, verify the server's KEX signature over the exchange hash, then match the presented host key against known_hosts before any userauth request is sent. The live runtime now retains the protected transcript for channel open/exec setup and channel I/O; the remaining runtime risk is real-server validation coverage for both the caller-driven and optional background-reader channel paths.


Pass 56 adds native SHA-512 and RSA `rsa-sha2-512` verification/signing, allowing the live runtime to negotiate the preferred RSA SHA-512 host-key algorithm while retaining RSA SHA-256 fallback.


Phase 19 completeness pass 57 reduced the live-runtime channel gap by retaining the authenticated socket-backed transcript on the session for channel open/exec setup traffic. Later passes route channel data, EOF, close, exit-status, and protected global/transport control handling through the retained transcript as well. The channel threat surface is now operational rather than structural: the default path remains caller-driven for Version, while the optional background reader can drain protected control/data packets into channel state for clients that prefer asynchronous demultiplexing.


### Phase 19 completeness pass 74 — explicit password userauth

Password authentication is now available only as an explicit caller-supplied `Session_Options` value. SSH_Lib does not prompt, persist, discover, or log passwords. The encoded `password` userauth request is emitted only over the protected packet transcript after transport encryption and host-key trust, and authenticated state is published only after a decoded `SSH_MSG_USERAUTH_SUCCESS`. Empty passwords and values containing NUL, CR, or LF fail closed before request emission.


### Phase 19 completeness pass 77: password material retention hardening

Explicit password authentication remains caller-supplied and protected-transport-only. The live authentication path now avoids retaining the caller-provided password in session-private stored options, clears the encoded password request buffer on all return paths, and records a structurally redacted plain userauth transcript for password requests. The encrypted protected outbound packet transcript is still retained for boundary inspection; no plaintext password is kept in the session diagnostic buffers.


Phase 19 pass 172: protected-packet setup now handles `chacha20-poly1305@openssh.com` independently per direction. A server can negotiate ChaCha20-Poly1305 in only one direction and AES-CTR/CBC in the other direction; the AEAD direction uses a 16-byte Poly1305 tag while the AES direction keeps the negotiated SSH MAC. Deterministic fixtures cover both mixed per-direction chacha20-poly1305/AES negotiations.


Phase 19 pass 173: AES-GCM transport support is implemented for `aes256-gcm@openssh.com` and `aes128-gcm@openssh.com`. AES-GCM is handled as an AEAD packet mode with encrypted packet length, GHASH tag verification, 16-byte authentication tags, and no separate SSH MAC; mixed-direction negotiation with non-GCM ciphers remains supported.
