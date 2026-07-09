# Security Model

SSH_Lib is a narrow Git-over-SSH transport library with client-side SCP/SFTP helpers, non-PTY and PTY shell channels, explicit env and X11 setup requests, PTY terminal modes, PTY resize requests, local-forward listener and dynamic/SOCKS one-connection primitives, callback-based forwarding accept services, managed local/dynamic forwarding worker-pool services, managed remote-forward services, remote-forward request/cancel and forwarded-channel accept primitives, and a public `direct-tcpip` channel primitive. Its public contract is authenticated encrypted SSH sessions, exec channels for Git commands, bounded Git protocol/pack helpers, a first bounded Git repository-state layer for `.git` initialization, loose objects, bounded tree/commit/tag object parsing, validated packfile and pack-index storage, bounded index/worktree file and staged-blob checkout/status primitives, bounded porcelain status policy, bounded fetch/push workflow policy, bounded pack-index generation and checksum discovery, loose-first object reads with caller-specified or listed-pack non-delta packed-object fallback, direct/symbolic/packed refs, bounded ref resolution, and atomic direct-ref updates, single-service Git upload-pack/receive-pack exchange orchestration, shell/subsystem channels, raw byte movement, forwarding primitives and managed local/dynamic/remote services, and bounded client-side file transfer; incomplete live backends remain fail-closed until every security gate is satisfied. It does not provide SSH server, SFTP server, or merge/conflict handling.

Managed remote forwarding is part of the public forwarding boundary. `Start_Managed_Remote_Forward_Service` performs the remote-forward request, accepts server-opened forwarded channels, connects them to the configured local target, pumps bounded chunks in both directions, and cancels the remote forward when its worker exits; the lower-level request/cancel/accept APIs remain available for custom policy.

## Defaults

- host-key verification is enabled by default.
- `Verify_Known_Host` defaults to `True`.
- `Trust_On_First_Use` defaults to `False`.
- `Strict_Host_Key` defaults to `True`.
- Unknown hosts fail by default with `Host_Key_Unknown`.
- Changed host keys fail by default with `Host_Key_Mismatch`.
- `Use_Agent` defaults to `True`.
- `Trust_On_First_Use = True` appends only unknown presented host keys to the caller-selected user known_hosts file; changed, revoked, malformed, and unsupported records still fail closed.
- `Verify_Known_Host = False` is an explicit unsafe bypass for callers that deliberately opt out.

## Shell and subprocess policy

SSH_Lib does not use implicit subprocess fallback for `ssh`, `git`, `ssh-agent`, or credential helpers during session open. The explicit subprocess boundaries are `ProxyCommand`, Git credential-helper execution, and caller-invoked `SSH_Lib.Git_Transport.Run_Service_With_Local_Git` / `Run_Service_With_Local_SSH`. `ProxyCommand` expands `%h`, `%p`, `%r`, and `%%` and carries SSH over that subprocess transport. `ProxyCommand none` is treated as disabled and is not executed. If a POSIX-style `sh` executable cannot be located, ProxyCommand fails closed with `Unsupported_Feature` rather than guessing a platform shell. Local Git/SSH fallback helpers pass direct argument vectors without a shell and reject empty/control-character command inputs before spawning. Config loading and remote resolution still never shell out. ssh-agent support is through protocol-level communication only. Git helper functions quote repository paths before constructing remote command strings and reject NUL, CR, and LF.

## Secret handling

Identity private-key material is not logged. Diagnostics should report statuses and safe context, not key material, signatures, decrypted payloads, or private paths from user SSH state.

## Known limitations

SSH_Lib supports non-interactive password, identity-passphrase, and password-change callbacks, plus keyboard-interactive callbacks. It provides both an explicit known_hosts append helper for caller-controlled host-key acceptance workflows and an opt-in `Trust_On_First_Use` session option. TOFU is disabled by default, handles only unknown keys, writes to the caller-selected user known_hosts file, and refuses changed, revoked, malformed, or unsupported records. It still does not implement SSH server mode, SFTP server mode, or C bindings. `SSH_Lib.Security_Keys` exposes a direct caller-supplied security-key signer boundary for hardware-backed SK userauth requests without ssh-agent. `SSH_Lib.Channels.Open_Shell` exposes non-PTY shell channels, `SSH_Lib.Channels.Open_PTY_Shell` exposes PTY-backed shell startup with optional terminal modes, `SSH_Lib.Channels.Resize_PTY` exposes PTY resize requests, `SSH_Lib.Channels.Request_X11_Forwarding` exposes explicit X11 setup requests, `SSH_Lib.Channels.Accept_X11` accepts server-opened X11 channels, `SSH_Lib.Channels.Valid_X11_MIT_Magic_Cookie` and `X11_MIT_Magic_Cookies_Match` expose bounded X11 cookie policy helpers, `SSH_Lib.Channels.Open_Direct_TCPIP` exposes the SSH channel primitive for caller-managed local forwarding, `SSH_Lib.Forwarding` exposes synchronous local and dynamic listeners, callback-based background accept services with optional accepted-connection caps, managed local/dynamic worker-pool services with bounded worker and accepted-connection caps, managed remote-forward services with request, accept, target-connect, bounded pump, and cancel-on-exit lifecycle, accepted-connection, one-connection SOCKS accept, X11 `DISPLAY` parsing and local X server connection helpers, SOCKS5 no-auth CONNECT, bounded `Pump_Once`, and bounded alternating `Pump_Bounded` primitives, `SSH_Lib.Git` exposes bounded local `.git` initialization, loose object store/read, validated packfile store/read, direct/symbolic/packed ref write/read and resolution, atomic direct-ref updates, repository tree traversal from root trees, commits, refs, HEAD, branch names, and tag names with pathspec filtering, explicit credential-helper execution, console credential prompting, credential store management, pkt-line frame/cursor helpers, ref advertisement and protocol-v2 `ls-refs` response parsing, protocol-v2 capability advertisement validation, capability-token/list, upload-pack negotiation/request/ACK stream/response, receive-pack request/report, protocol-v2 request/response, side-band packet/stream helpers, status-line, pack header/object-at-offset with next-offset reporting, pack object-sequence validation, zlib-object-data with consumed-length reporting, caller-supplied-delta and delta-chain/index metadata, complete v2 pack-index structural validation, pack-index object lookup, pack-index offset/pack, CRC/pack, and object-id/pack consistency validation for non-delta, immediate-delta, and bounded delta-chain entries, pack delta-base and dependency-graph validation, pack/index SHA-1 checksum verification, object-id, and ref-name helpers, `SSH_Lib.Git_Transport` exposes bounded single-service Git exchange orchestration and explicit local Git/SSH subprocess fallback helpers, `SSH_Lib.Sessions.Request_Remote_Forward` / `Cancel_Remote_Forward` expose remote-forward request primitives, `SSH_Lib.Channels.Accept_Forwarded_TCPIP` drains the protected session stream to accept one pending server-opened forwarded channel, and `SSH_Lib.Forwarding.Start_Managed_Remote_Forward_Service` provides managed remote-forward orchestration. SCP upload is supported for regular files, while SFTP and `SSH_Lib.File_Transfer` provide the broader client-side file-management surface documented in `docs/sftp.md` and `docs/API.md`. ProxyJump is implemented internally as SSH direct-tcpip routing; ProxyCommand, Git credential-helper execution, and Git_Transport local Git/SSH fallback are explicit subprocess-backed boundaries.


### Phase 19 completeness pass 45

The deterministic open runtime now enforces encrypted service-request ordering before authentication. `Userauth_Service_Accepted` is set only after a protected `SSH_MSG_SERVICE_ACCEPT` for `ssh-userauth`; publickey userauth cannot run before that gate.


### Phase 19 completeness pass 46

Agent-backed deterministic authentication now has an auditable sign boundary. The runtime stores the agent sign request and sign response transcripts before publishing SSH userauth state, while identity-file authentication is checked to avoid the agent boundary entirely. This prevents a regression where agent authentication could silently skip signature-request construction or blur identity-file and agent behavior.

### Phase 19 completeness pass 47

The deterministic authentication path now records inbound protected response packets and decoded payloads before changing service or authenticated state. This strengthens the public-open ordering invariant: `SERVICE_ACCEPT` must be parsed before the userauth-service gate is set, and `USERAUTH_SUCCESS` must be parsed before authenticated state is published.

### Phase 19 completeness pass 48

The userauth runtime boundary now has a denial regression guard. A protected `SSH_MSG_USERAUTH_FAILURE` decoded after a signed publickey request is mapped to `Authentication_Failed` and keeps the session closed. This prevents a class of regressions where authenticated state could be published merely because a signed request was emitted.

## Phase 19 completeness pass 51 — Live transcript safety boundary

The public-network path now centralizes live socket I/O in `SSH_Lib.Sessions.Live_Transcript`. This reduces the risk of bypassing packet-length checks or sequence-tracked packet state by forcing live identification, cleartext packets, and later protected packets through one runtime boundary. Public success remains fail-closed until the same boundary is used for complete KEX/NEWKEYS, verified host keys, and authenticated userauth.


### Phase 19 completeness pass 52

The live public-network runtime now runs through the socket-backed transcript driver for identification, negotiated KEX including Curve25519, fixed MODP, and RFC 4419 group-exchange, NEWKEYS, protected-packet installation, strict host-key verification, known-host or certificate-authority trust, protected userauth, and retained channel setup.  Public success remains gated on all of those checks; incomplete or malformed paths fail with deterministic `Status` values instead of publishing a usable session.

## Phase 19 completeness pass 53

- Added `SSH_Lib.Sessions.Live_Userauth` for socket-backed `ssh-userauth` service request and publickey authentication over `SSH_Lib.Sessions.Live_Transcript`.
- Live identity-file authentication now signs with the configured identity and sends `SSH_MSG_USERAUTH_REQUEST` over the protected transcript.
- Live ssh-agent authentication now uses `SSH_AUTH_SOCK`, requests identities/signatures from the agent, and sends the resulting publickey request over the protected transcript.
- Default known-host verification still blocks public-network authentication until known-host trust matching is wired; explicit `Verify_Known_Host => False` can exercise the live userauth boundary.


## Phase 19 completeness pass 54

- The public-network runtime now enforces local known-host trust after KEX signature verification and before userauth.
- Host-key ownership and local host trust remain separate gates: a matching known_hosts record cannot compensate for a bad KEX signature, and a valid KEX signature cannot compensate for an unknown or changed known_hosts record.
- The only known-host bypass remains explicit `Verify_Known_Host => False`; signature verification still remains mandatory.


Pass 56 adds native SHA-512 and RSA `rsa-sha2-512` verification/signing, allowing the live runtime to negotiate the preferred RSA SHA-512 host-key algorithm while retaining RSA SHA-256 fallback.


Phase 19 completeness pass 57 keeps the authenticated live transcript attached to the private session after successful userauth. This prevents live channel setup from falling back to a fixture-only channel boundary after the public open path has authenticated a real socket. The remaining stream-data pass must route channel-owned data/EOF/close packets through the same retained transcript.


### Phase 19 completeness pass 74 — explicit password userauth

Password authentication is now available only as an explicit caller-supplied `Session_Options` value. SSH_Lib does not prompt, persist, discover, or log passwords. The encoded `password` userauth request is emitted only over the protected packet transcript after transport encryption and host-key trust, and authenticated state is published only after a decoded `SSH_MSG_USERAUTH_SUCCESS`. Empty passwords and values containing NUL, CR, or LF fail closed before request emission.


### Phase 19 completeness pass 77: password material retention hardening

Explicit password authentication remains caller-supplied and protected-transport-only. The live authentication path now avoids retaining the caller-provided password in session-private stored options, clears the encoded password request buffer on all return paths, and records a structurally redacted plain userauth transcript for password requests. The encrypted protected outbound packet transcript is still retained for boundary inspection; no plaintext password is kept in the session diagnostic buffers.


Phase 19 completeness pass 78 hardens password authentication by distinguishing password-change-required replies from publickey `PK_OK`. Password-change-required is parsed only in password context and fails closed; the library still does not prompt for or store replacement credentials.

## Phase 19 completeness pass 81

Pass 81 hardens default host-key verification for OpenSSH marker records.
`known_hosts` lines marked `@revoked` are now parsed instead of ignored; a
matching revoked key deterministically returns `Host_Key_Mismatch` and cannot be
re-enabled by a later ordinary trust line. `@cert-authority` records are used only for OpenSSH host-certificate CA trust and are never treated as ordinary raw host keys
because host certificates are outside the raw host-key trust model and must not
be treated as direct trust for a presented server key.

## Phase 19 pass 92 default identity discovery

Default identity-file discovery is deliberately bounded to `$HOME/.ssh/id_ed25519` and `$HOME/.ssh/id_rsa` when no explicit identity file is configured. The implementation does not glob, expand shell syntax, execute helpers, or retain plaintext private-key material after the authentication attempt. Unsupported key algorithms, unsupported encrypted-key envelopes, and missing/wrong passphrases remain method failures and do not bypass host-key verification or encrypted transport requirements; supported encrypted OpenSSH, legacy PEM, and PKCS#8 identities use explicit non-retained passphrase input.


### Interactive credential callbacks

Credential callbacks are caller-provided function pointers, not built-in prompts. They are available for password auth, identity passphrase retrieval, and SSH password-change-required handling. SSH_Lib does not retain the returned secret in `Session`, does not log it, and does not call callbacks before the encrypted userauth phase. Invalid callback results fail closed.
