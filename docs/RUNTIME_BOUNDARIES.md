# Runtime Boundaries

This document is the Phase 19 runtime boundary inventory. It distinguishes implemented runtime pieces from the remaining explicit fail-closed boundaries. It is intentionally conservative: the crate must not claim a live SSH capability unless `Sessions.Open` can return `Ok` only after authenticated, encrypted, host-verified setup.

## Implemented runtime boundaries

### Deterministic public Sessions.Open runtime

The reserved host `transcript.example.test` exercises the public `SSH_Lib.Sessions.Open` entry point without public network access. It reaches `Ok` only after the centralized open gates are complete: transport, identification, KEXINIT, algorithm negotiation, KEX, key derivation, NEWKEYS, encrypted inbound/outbound packet mode, host-key ownership verification, known-host trust or explicit bypass, userauth service acceptance, and authenticated user state.

### AES-CTR and AES-CBC cipher primitives

The cipher package implements `chacha20-poly1305@openssh.com`, `aes256-gcm@openssh.com`, `aes128-gcm@openssh.com`, `aes256-ctr`, `aes192-ctr`, `aes128-ctr`, `aes256-cbc`, `aes192-cbc`, `aes128-cbc`, and `3des-cbc` for live transport. Directional AEAD, CTR, and CBC cipher state is initialized from derived SSH keys and IVs during NEWKEYS fixture coverage; CBC chaining state is updated per protected packet. Unsupported cipher names continue to fail closed rather than being advertised or silently accepted.

### Ed25519 identity-file signing fixture path

The identity-file signing backend can produce payload-bound SSH signature blobs for parsed OpenSSH Ed25519, ECDSA P-256, ECDSA P-384, ECDSA P-521, and RSA identities. RSA private-key signing and RSA identity-file signing support `rsa-sha2-512` and `rsa-sha2-256`, and live userauth falls back from SHA-512 to SHA-256 with legacy SHA-1 `ssh-rsa` only as a final interoperability fallback. Supported identity inputs include unencrypted OpenSSH RSA, OpenSSH Ed25519, OpenSSH ECDSA P-256/P-384/P-521, PKCS#1 RSA PEM, PKCS#8 `BEGIN PRIVATE KEY` RSA/EC, bcrypt-encrypted OpenSSH private keys, traditional AES/DES/3DES-CBC encrypted RSA/EC PEM, PBES1 MD5-DES/SHA1-DES encrypted PKCS#8 RSA, PKCS#12 SHA1-2DES/SHA1-3DES/SHA1-RC2-40/SHA1-RC2-128 encrypted PKCS#8 RSA, PBES2/scrypt encrypted PKCS#8 RSA, and PBES2/PBKDF2 AES/DES/3DES/RC2-40/64/128-CBC encrypted PKCS#8 RSA/EC with HMAC-SHA1/SHA256/SHA384/SHA512 PRFs. Unsupported algorithms, unsupported encrypted envelopes, malformed keys, and wrong or missing passphrases continue to fail closed.

### Identity-file userauth protected-packet boundary

The deterministic identity-file `Sessions.Open` path now builds the SSH publickey signature payload, signs it through the identity-file backend, sends `SSH_MSG_USERAUTH_REQUEST` through `SSH_Lib.Sessions.Userauth_IO`, parses `SSH_MSG_USERAUTH_SUCCESS`, and only then marks the session authenticated. This is still deterministic fixture-backed traffic, not a public-network claim.

### Live channel protected-packet boundary

The channel path can send open, exec, data, EOF, close, and parse inbound data/status/EOF through the protected packet boundary in deterministic fixtures.

## Remaining explicit fail-closed boundaries

### Encrypted and passphrase-protected private keys

Unencrypted OpenSSH RSA, PKCS#1 RSA PEM, and PKCS#8 RSA private keys are parsed into the RSA SHA-2 signing path; OpenSSH and PKCS#8 EC private keys route into the ECDSA identity path. OpenSSH bcrypt-encrypted private keys route through the Ada bcrypt_pbkdf derivation path and AES-CTR, AES-CBC, or 3DES-CBC private-section unwrap. Encrypted legacy PEM keys now support AES-128/192/256-CBC, DES-EDE3-CBC, and DES-CBC traditional PEM unwrap with the CryptoLib MD5 EVP_BytesToKey derivation, and encrypted PKCS#8 keys now support PBES1 PBKDF1 MD5-DES/SHA1-DES, PKCS#12 SHA1-2DES/SHA1-3DES/SHA1-RC2-40/SHA1-RC2-128 PBE, PBES2/scrypt, and PBES2/PBKDF2-HMAC-SHA1, HMAC-SHA256, HMAC-SHA384, or HMAC-SHA512 with AES-128/192/256-CBC, DES-CBC, des-EDE3-CBC, or RC2-40/64/128-CBC before routing into the RSA or EC private-key parser. Unsupported ciphers, unsupported KDFs, malformed padding, and wrong passphrases still fail closed. The explicit non-retained passphrase option is present and passphrase bytes are not retained in session diagnostics. RSA public host-key verification for SHA-512 and SHA-256 continues to use the separate host-key verification path.

Phase 19 pass 126 refreshes this runtime-boundary inventory after the later live-transport and ProxyJump work. The documentation now distinguishes historical pre-KEX notes from the current implementation state: the live path is source-wired through KEX, protected packets, host-key trust, userauth, retained channels, and jump-channel routing, but it is still not release-proven until GNAT/gprbuild and live-server verification are available.

### RSA SHA-512 verification

Ed25519, ECDSA P-256, ECDSA P-384, ECDSA P-521, RSA SHA-2, RSA SHA-1 fallback, and OpenSSH SK host-key/certificate verification are implemented. The runtime advertises `ssh-ed25519-cert-v01@openssh.com,ecdsa-sha2-nistp256-cert-v01@openssh.com,ecdsa-sha2-nistp384-cert-v01@openssh.com,ecdsa-sha2-nistp521-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,ssh-rsa-cert-v01@openssh.com,sk-ssh-ed25519-cert-v01@openssh.com,sk-ecdsa-sha2-nistp256-cert-v01@openssh.com,ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,rsa-sha2-512,rsa-sha2-256,sk-ssh-ed25519@openssh.com,sk-ecdsa-sha2-nistp256@openssh.com,ssh-rsa` and supports legacy SHA-1 `ssh-rsa` signatures only as a last-resort fallback. Positive host-key verification coverage includes RSA SHA-512, SK signature payload parsing, and signature/message tamper-negative checks.

Ed25519 host-key verification remains covered, along with the Ed25519, ECDSA P-256/P-384/P-521, and RSA identity-file signing fixture paths, and the Full production userauth transcript driver.

## Guard

`check_runtime_boundaries` verifies that this inventory is present, that implemented runtime markers remain present, and that stale generic placeholder wording does not reappear.

## Phase 19 completeness pass 44 — agent userauth protected-packet boundary

The deterministic agent path no longer marks a session authenticated directly.
`SSH_Lib.Sessions.Userauth_IO.Run_Agent_Userauth` builds the userauth signature
payload, constructs an ssh-agent-shaped sign request and response, converts the
validated agent signature into `SSH_MSG_USERAUTH_REQUEST`, emits that request
through the protected userauth packet boundary, parses protected
`SSH_MSG_USERAUTH_SUCCESS`, and only then sets the authenticated state.

This is still deterministic local fixture traffic. It does not contact the
user's real `SSH_AUTH_SOCK`, execute local programs, or claim arbitrary-host SSH
support. Ordinary public-network `Sessions.Open` now crosses the live DNS/TCP/identification/KEXINIT/algorithm-negotiation/KEX/NEWKEYS/known-host/userauth boundary and later passes retain the authenticated transcript for channel setup and channel data/EOF/close traffic; remaining key-interoperability work remains explicit.

## Phase 19 completeness pass 45 — service-request protected-packet boundary

The reserved local runtime no longer marks `Userauth_Service_Accepted` directly. `SSH_Lib.Sessions.Userauth_IO.Run_Userauth_Service_Request` emits a protected `SSH_MSG_SERVICE_REQUEST` for `ssh-userauth`, parses a protected `SSH_MSG_SERVICE_ACCEPT`, and only then enables the later identity-file or agent publickey userauth exchange. The fixture exposes both plain and protected service-request transcripts so regressions cannot silently reintroduce direct state publication.


## Phase 19 completeness pass 46 — agent sign transcript boundary

The reserved local runtime now exposes the ssh-agent sign exchange as part of the userauth runtime boundary. Agent-backed authentication records the exact `SSH_AGENTC_SIGN_REQUEST` and the parsed `SSH_AGENT_SIGN_RESPONSE` before converting the signature blob into the protected SSH `USERAUTH_REQUEST`. Identity-file authentication keeps these agent transcript buffers empty, so tests can distinguish the two authentication paths without public network or real user-agent state.

## Phase 19 completeness pass 47 — inbound service/userauth response transcripts

The userauth runtime boundary now records inbound traffic as well as outbound requests. The reserved local runtime stores protected and decoded `SSH_MSG_SERVICE_ACCEPT` before setting `Userauth_Service_Accepted`, and stores protected and decoded `SSH_MSG_USERAUTH_SUCCESS` before setting `User_Authenticated`. The open-runtime fixture asserts these transcripts for both agent and identity-file authentication, making direct state publication easier to detect.

## Phase 19 completeness pass 48 — protected userauth failure path

The reserved local runtime now validates server-side userauth denial through the same protected packet boundary used for successful authentication. When the fixture user is `reject-auth`, `SSH_Lib.Sessions.Userauth_IO` queues and decodes a protected `SSH_MSG_USERAUTH_FAILURE` after the signed publickey request. The result is `Authentication_Failed`; `User_Authenticated`, `Session_Open`, and public open state remain false. This keeps denial handling on the transcript path instead of relying on a pre-auth shortcut.

## Phase 19 completeness pass 49 — Live TCP identification boundary

Ordinary non-fixture hosts no longer stop at the old top-level `Unsupported_Feature` gate in `SSH_Lib.Sessions.Open_Runtime.Run`. The public-network path now enters `SSH_Lib.Sessions.Live_Transport.Connect_And_Run_Handshake`, resolves the host name, opens a TCP stream socket, sends the local SSH identification line, reads and parses the server SSH identification line, sends and reads cleartext KEXINIT packets, parses the server KEXINIT, and records the transport/identification/KEXINIT/algorithm-negotiation gates on the private session state.

Earlier passes failed closed after algorithm negotiation; later passes wire KEX, NEWKEYS, known-host trust, protected userauth, and retained channel setup to the same socket-backed transcript. DNS, connect, write, read, malformed identification, malformed KEXINIT, unsupported algorithm intersections, and timeout conditions are mapped to deterministic `Status` values. The remaining arbitrary-host risks are live interoperability breadth, live E2E validation, unsupported encrypted identity algorithms outside the bounded AES/PBKDF coverage, and live interoperability validation for both caller-driven and optional background channel reads.


## Phase 19 completeness pass 50 — Live cleartext KEXINIT boundary

The live non-fixture transport path now advances beyond SSH identification. `SSH_Lib.Sessions.Live_Transport` constructs the client `SSH_MSG_KEXINIT`, encodes it as a cleartext SSH packet, writes it to the live socket, reads exactly one cleartext server packet, decodes and parses the server `SSH_MSG_KEXINIT`, and runs the existing first-match algorithm negotiation logic. The private `Kexinit_Exchanged` and `Algorithms_Negotiated` gates are set only after those concrete socket-backed steps complete.

This historical pass originally stopped at the post-algorithm-negotiation boundary. Later Phase 19 passes wired live key exchange, exchange-hash verification, NEWKEYS, encrypted packet I/O, known-host verification, userauth, retained exec-channel setup, binary channel read/write, Curve25519 KEX, expanded AES/HMAC negotiation, and ProxyJump `direct-tcpip` routing into the same socket-backed transcript. The remaining risk is no longer an intentional pre-KEX placeholder; it is lack of GNAT build verification and lack of live interoperability runs in this environment.

## Phase 19 completeness pass 51 — Socket-backed transcript driver

`SSH_Lib.Sessions.Live_Transcript` is now the single live socket transcript boundary for ordinary non-fixture hosts. It owns DNS/TCP connection setup, SSH identification send/read, exact socket-backed cleartext packet emission, exact socket-backed cleartext packet reads, cleartext packet decoding, protected packet key installation, protected packet emission, and protected packet reads.

`SSH_Lib.Sessions.Live_Transport.Connect_And_Run_Handshake` now drives the public-network open path through this transcript object through KEX/NEWKEYS, encrypted packet mode, host-key verification, known-host trust, and publickey userauth. Live channel setup and channel data use the retained transcript; pass 65 adds bounded handling for interleaved global requests while channel-open and exec replies are being synchronized.


## Phase 19 completeness pass 52 — Live KEXDH/NEWKEYS boundary

`SSH_Lib.Sessions.Live_Transport` now drives the live public-network finite-field DH path through `SSH_MSG_KEXDH_INIT`, `SSH_MSG_KEXDH_REPLY`, group18/group16/group14 shared-secret computation, SHA-512/SHA-256/SHA-1 exchange-hash computation selected by the negotiated KEX name, host-key signature verification, session-key derivation, and `SSH_MSG_NEWKEYS` send/receive.  The private session gates for KEX completion, key derivation, NEWKEYS, encrypted outbound, encrypted inbound, and host-key signature verification are set only after those concrete socket-backed steps succeed.

Remaining explicit fail-closed boundaries are encrypted identity algorithms outside the implemented OpenSSH bcrypt AES-CTR/AES-CBC/3DES-CBC, legacy PEM AES/DES/3DES-CBC with MD5 EVP_BytesToKey, PKCS#8 PBES1 MD5-DES/SHA1-DES, PKCS#8 PKCS#12 SHA1-2DES/SHA1-3DES/SHA1-RC2-40/SHA1-RC2-128 PBE, PKCS#8 PBES2/scrypt, and PKCS#8 AES/DES/3DES/RC2-40/64/128-CBC PBES2/PBKDF2-HMAC-SHA1/SHA256/SHA384/SHA512 coverage, plus optional SSH algorithms that are not required for Version; RFC 8308 `ext-info-c` is advertised as an extension marker and skipped during KEX selection.

## Phase 19 completeness pass 53

- Added `SSH_Lib.Sessions.Live_Userauth` for socket-backed `ssh-userauth` service request and publickey authentication over `SSH_Lib.Sessions.Live_Transcript`.
- Live identity-file authentication now signs with the configured identity and sends `SSH_MSG_USERAUTH_REQUEST` over the protected transcript.
- Live ssh-agent authentication now uses `SSH_AUTH_SOCK`, requests identities/signatures from the agent, and sends the resulting publickey request over the protected transcript.
- Default known-host verification still blocks public-network authentication until known-host trust matching is wired; explicit `Verify_Known_Host => False` can exercise the live userauth boundary.


## Phase 19 completeness pass 54

- Added the live known-host trust boundary to `SSH_Lib.Sessions.Live_Transport`.
- `Run_Group14_Kex` now returns the presented server host-key blob after the KEX host-key signature has been verified.
- `Verify_Presented_Host_Key` parses that blob, converts it to `SSH_Lib.Known_Hosts.Host_Key`, and applies `SSH_Lib.Known_Hosts.Verify` before production userauth starts.
- Unknown hosts return `Host_Key_Unknown`; changed keys return `Host_Key_Mismatch`; unsupported/malformed host material remains fail-closed.
- Pass 57 retains the authenticated live transcript for production channel open/exec setup after `Sessions.Open` returns; pass 58 routes channel-owned read/write/EOF/close traffic through that retained transcript.


Pass 56 adds native SHA-512 and RSA `rsa-sha2-512` verification/signing, allowing the live runtime to negotiate the preferred RSA SHA-512 host-key algorithm while retaining RSA SHA-256 fallback.

## Phase 19 completeness pass 57 — retained live transcript for channel setup

`SSH_Lib.Sessions.Live_Attachment` now keeps the authenticated socket-backed `SSH_Lib.Sessions.Live_Transcript.Driver` alive after live `Sessions.Open` succeeds. `SSH_Lib.Sessions.Live_Transport` attaches the transcript to the private session state instead of closing it, and `SSH_Lib.Sessions.Channel_IO` sends and reads session-owned channel open/exec protected packets through the attached transcript when it is present. Close/reset cleanup releases the attached transcript.

Pass 58 routes channel-owned stdin/stdout/EOF/close packet traffic through the retained session transcript. Remaining explicit fail-closed boundaries are encrypted identity algorithms outside the implemented OpenSSH bcrypt AES-CTR/AES-CBC/3DES-CBC, legacy PEM AES/DES/3DES-CBC with MD5 EVP_BytesToKey, PKCS#8 PBES1 MD5-DES/SHA1-DES, PKCS#8 PKCS#12 SHA1-2DES/SHA1-3DES/SHA1-RC2-40/SHA1-RC2-128 PBE, PKCS#8 PBES2/scrypt, and PKCS#8 AES/DES/3DES/RC2-40/64/128-CBC PBES2/PBKDF2-HMAC-SHA1/SHA256/SHA384/SHA512 coverage, plus optional SSH algorithms that are not required for Version; RFC 8308 `ext-info-c` is advertised as an extension marker and skipped during KEX selection.


## Phase 19 completeness pass 60 — PKCS#8 RSA and EC identity files

PKCS#8 `BEGIN PRIVATE KEY` RSA and EC identities are accepted by the identity-file parser. The parser validates the RFC 5208 `PrivateKeyInfo` sequence, routes RSA payloads through the bounded PKCS#1 RSA parser added in pass 59, and routes EC payloads through the SEC1 EC parser. `BEGIN ENCRYPTED PRIVATE KEY` now unwraps bounded PBES1 MD5-DES/SHA1-DES, PKCS#12 SHA1-2DES/SHA1-3DES/SHA1-RC2-40/SHA1-RC2-128 PBE, PBES2/scrypt, and PBES2/PBKDF2 AES/DES/3DES/RC2-40/64/128-CBC envelopes for HMAC-SHA1, HMAC-SHA256, HMAC-SHA384, and HMAC-SHA512 PRFs before feeding the RSA or EC DER parser; unsupported KDF/cipher combinations still return deterministic fail-closed statuses.

### Phase 19 completeness pass 62: live channel control replies

Inbound channel events may require the client to send protocol control replies while the caller is reading. `SSH_Lib.Channels` now routes these internally generated replies through the retained protected transcript: `CHANNEL_SUCCESS` for `exit-status` with `want-reply`, `CHANNEL_FAILURE` for unsupported channel requests with `want-reply`, `CHANNEL_CLOSE` acknowledgements, and automatic `CHANNEL_WINDOW_ADJUST` messages. This keeps live channel control traffic on the authenticated encrypted socket instead of only retaining plaintext packets for tests.

## Phase 19 completeness pass 64 — live encrypted protected packets

The socket-backed protected packet driver now installs complete NEWKEYS material
instead of only retaining an HMAC key. `SSH_Lib.Protocol.Protected_Packets` can
hold directional AES-CTR or AES-CBC cipher state, distinct client-to-server and
server-to-client MAC keys, encrypt outbound SSH packets, decrypt inbound packet
length headers and bodies, and verify the MAC over the decrypted packet before
payload dispatch. `SSH_Lib.Sessions.Live_Transport` passes the derived cipher,
IV, and MAC buffers into `SSH_Lib.Sessions.Live_Transcript` after NEWKEYS.

The deterministic MAC-only protected packet API remains available for fixtures;
live userauth and channel traffic use the cipher-backed overload.

## Phase 19 completeness pass 66 — live read interleaved global requests

The pass 65 global-request handling is no longer limited to channel-open and exec-response synchronization. Caller-driven live `Read_Some` now handles interleaved protected `SSH_MSG_GLOBAL_REQUEST` packets after exec setup, sends protected `SSH_MSG_REQUEST_FAILURE` for unsupported global requests with `want-reply = True`, skips ignorable protected transport/global response packets, and continues waiting for channel stdout/status/EOF/close traffic. Unexpected non-channel packets still fail closed.



## Phase 19 completeness pass 88 — bounded live close drain

`SSH_Lib.Channels.Close` now uses the retained live transcript during cleanup, not only for the outbound close packet. After sending `SSH_MSG_CHANNEL_CLOSE`, the close path performs a bounded best-effort protected drain for peer close acknowledgements, late channel-control packets, and interleaved global/transport-control packets. The operation remains cleanup-only: timeout or malformed late data does not keep the channel open, and all queued stream/status buffers are cleared before the closed handle is returned to the caller.

## Phase 19 completeness pass 67 — live EOF/status drain

`SSH_Lib.Channels.Read_Some` now treats stdout EOF on an attached live transcript as a channel-completion boundary, not as permission to stop parsing all protected channel-control traffic immediately. When EOF is seen before `exit-status`, the caller-driven read loop or optional background reader continues to dispatch protected packets until it observes exit-status, close, stdout data, or the read boundary reports no immediately available packet. This keeps `Exit_Status` side-effect-free while still allowing the common SSH ordering `EOF -> exit-status -> close` to be captured.

## Phase 19 completeness pass 68 — exit-status observation status

`SSH_Lib.Channels.Exit_Status` remains side-effect-free: it does not read from the socket and it does not dispatch pending channel packets. If no remote `exit-status` channel request has been observed yet, the function now returns `Channel_Request_Failed` rather than `Unsupported_Feature`. This keeps the status model deterministic and makes the absence of a peer status request a channel-state outcome instead of a library-capability outcome.

## Phase 19 completeness pass 69

The live userauth reply loop now handles real `SSH_MSG_USERAUTH_BANNER` packets. A banner is decoded and recorded as protocol data, then ignored while the loop waits for `USERAUTH_SUCCESS` or `USERAUTH_FAILURE`. The loop is bounded and returns authentication failure if no terminal result arrives.

## Phase 19 completeness pass 71

Added an opt-in live Git-over-SSH end-to-end test executable, `test_live_git_e2e.adb`. The default release suite still performs no public-network access: the executable exits successfully as skipped unless `SSH_LIB_LIVE_GIT_E2E=1` is set. When enabled, it requires `SSH_LIB_LIVE_GIT_HOST`, `SSH_LIB_LIVE_GIT_USER`, and `SSH_LIB_LIVE_GIT_REPO`, keeps known-host verification enabled, opens a real authenticated session, executes `git-upload-pack` by default or `git-receive-pack` when `SSH_LIB_LIVE_GIT_SERVICE=receive-pack`, writes an opaque Git flush packet, sends EOF, reads opaque stdout bytes, observes exit status, and closes the channel/session. This proves the public API sequence needed by `version` without adding higher-level Git protocol interpretation to the SSH library.

## Phase 19 completeness pass 73 transport-control waits

The live protected transcript now classifies transport control packets through
`SSH_Lib.Protocol.Transport_Messages`. While waiting for service, userauth, or
channel replies, `IGNORE`, `UNIMPLEMENTED`, and `DEBUG` are bounded ignorable
transport messages; `DISCONNECT` is a deterministic connection failure. This
prevents real servers from desynchronizing the live Git-over-SSH flow by
interleaving transport-level packets before higher-level responses.


### Phase 19 completeness pass 74 — explicit password userauth

Password authentication is now available only as an explicit caller-supplied `Session_Options` value. SSH_Lib does not prompt, persist, discover, or log passwords. The encoded `password` userauth request is emitted only over the protected packet transcript after transport encryption and host-key trust, and authenticated state is published only after a decoded `SSH_MSG_USERAUTH_SUCCESS`. Empty passwords and values containing NUL, CR, or LF fail closed before request emission.

### Phase 19 completeness pass 75 — live protocol disconnect on close

`SSH_Lib.Protocol.Transport_Messages` now encodes bounded `SSH_MSG_DISCONNECT` payloads, and `SSH_Lib.Sessions.Live_Attachment.Close_Attached` sends one through the retained protected transcript before closing the socket. The disconnect send is best-effort: `Sessions.Close` stays idempotent and always completes local cleanup, but authenticated live sessions no longer rely solely on abrupt TCP teardown.


### Phase 19 completeness pass 76: userauth fallback hardening

Live userauth now distinguishes method-level unavailability from transport/protocol failure. `Authentication_Failed` and `Unsupported_Feature` from one configured method are fallback-eligible when a later method is explicitly enabled, so an encrypted unsupported identity file can fall through to ssh-agent or password authentication. Non-authentication failures still abort immediately. If no later method succeeds, the preserved deterministic failure remains the result; OpenSSH passphrase-protected key decryption is explicit and non-interactive; encrypted PEM/PKCS#8 identities use the same explicit non-retained passphrase path for the supported AES/3DES/PBKDF2/legacy-MD5 cases.


### Phase 19 completeness pass 77: password material retention hardening

Explicit password authentication remains caller-supplied and protected-transport-only. The live authentication path now avoids retaining the caller-provided password in session-private stored options, clears the encoded password request buffer on all return paths, and records a structurally redacted plain userauth transcript for password requests. The encrypted protected outbound packet transcript is still retained for boundary inspection; no plaintext password is kept in the session diagnostic buffers.

## Phase 19 completeness pass 78 — password change replies

RFC 4252 reuses message number 60 for both publickey `PK_OK` and password-change-required replies. `SSH_Lib.Protocol.Userauth` now carries reply context so publickey preflight and password authentication cannot confuse those packets. Live password authentication parses replies in password context; a password-change-required packet is recognized, never promoted to authentication success, and returns `Authentication_Failed` because the core library has no interactive password-change boundary.

## Phase 19 pass 79: known-host wildcard selectors

The live known-host trust path now accepts bounded OpenSSH-style wildcard selectors using `*` and `?`. Wildcard matching is case-insensitive for host names, works for bare default-port selectors and bracketed `[host-pattern]:port` selectors, and preserves changed-key detection. Negated wildcard selectors deny trust deterministically. Hashed OpenSSH known-host entries are now supported for matching trust records using bounded HMAC-SHA1 comparison; malformed hashed records remain fail-closed as unknown or unsupported records.


## Phase 19 completeness pass 81

Pass 81 hardens default host-key verification for OpenSSH marker records.
`known_hosts` lines marked `@revoked` are now parsed instead of ignored; a
matching revoked key deterministically returns `Host_Key_Mismatch` and cannot be
re-enabled by a later ordinary trust line. `@cert-authority` records are used only for OpenSSH host-certificate CA trust and are never treated as ordinary raw host keys
because host certificates are outside the raw host-key trust model and must not
be treated as direct trust for a presented server key.

## Phase 19 completeness pass 83: live I/O timeout wiring

The live transcript driver now accepts read/write timeout values from `Session_Options` and applies them to the socket before the public-network SSH path performs identification, KEX, protected userauth, and channel packet I/O. This closes the previous gap where the timeout fields were validated by the open pipeline but not carried into the live socket-backed transcript. Portable connect-deadline handling remains a separate boundary.

### Phase 19 completeness pass 84: live connect deadline guard

`Session_Options.Connect_Timeout_MS` now reaches `SSH_Lib.Sessions.Live_Transcript.Connect`. The live transcript records a deadline when DNS/TCP setup starts and refuses to continue into SSH identification/KEX if the configured connect deadline has elapsed. This keeps the public `Sessions.Open` status model deterministic: elapsed connect deadlines return `Timeout`, DNS failures return `DNS_Failed`, and ordinary socket connection failures return `Connection_Failed`.

## Phase 19 completeness pass 86 - hashed known_hosts host-case hardening

Hashed OpenSSH `known_hosts` selectors now match the exact OpenSSH host text and, when needed, the canonical lower-case host spelling. This keeps hashed entries aligned with ordinary and wildcard selector behavior, where host names are case-insensitive. The HMAC comparison remains bounded and constant-time, and malformed hashed entries remain fail-closed.

## Phase 19 pass 92: bounded default identity discovery

The live userauth path now follows the normal SSH-environment expectation more closely when the caller has not supplied `Identity_File`: after earlier methods fail to authenticate, it can try `$HOME/.ssh/id_ed25519` and `$HOME/.ssh/id_rsa`. Each candidate uses the same bounded identity parser, RFC 4252 publickey preflight, signature construction, protected userauth request, and protected auth-reply parser as an explicitly configured identity file. No globbing, shell expansion, subprocess execution, or credential storage is introduced. OpenSSH, encrypted legacy PEM, and encrypted PKCS#8 identities require an explicit non-retained identity passphrase; unsupported encrypted algorithms still fail closed unless another configured method succeeds.



Phase 19 pass 119 also bounds OpenSSH bcrypt KDF salt length and round counts before bcrypt_pbkdf derivation is attempted, so syntactically valid but oversized encrypted-key envelopes fail closed instead of creating an unbounded CPU or memory boundary.


### Pass 127 live Git interoperability matrix

Pass 127 adds `test_live_git_interop_matrix.adb`, an opt-in live interoperability matrix for the Version-facing Git-over-SSH path. It performs no public-network access unless `SSH_LIB_LIVE_GIT_MATRIX=1` is set. When enabled, `SSH_LIB_LIVE_GIT_SCENARIOS` selects comma-separated scenarios such as `DIRECT`, `AGENT`, `IDENTITY`, `PASSWORD`, `PASSPHRASE`, `PROXYJUMP`, and `RECEIVE`; pass 128 makes this selector whitespace/case tolerant, rejects unknown scenario names before network access, and adds `ALL` as a shorthand for the full matrix.

The matrix keeps strict known-host verification enabled and exercises the public sequence required by Version: open an authenticated session, open an exec channel with a safely quoted Git service command, write an opaque Git flush packet, send EOF, read opaque stdout bytes, observe exit status, close the channel, and close the session. Scenario-specific values can be supplied with `SSH_LIB_LIVE_GIT_<SCENARIO>_<FIELD>` and fall back to the existing single-case names such as `SSH_LIB_LIVE_GIT_HOST`, `SSH_LIB_LIVE_GIT_USER`, `SSH_LIB_LIVE_GIT_REPO`, `SSH_LIB_LIVE_GIT_KNOWN_HOSTS`, `SSH_LIB_LIVE_GIT_IDENTITY`, `SSH_LIB_LIVE_GIT_PASSWORD`, `SSH_LIB_LIVE_GIT_IDENTITY_PASSPHRASE`, and `SSH_LIB_LIVE_GIT_PROXY_JUMP`.

Phase 19 completeness pass 130 adds `test_live_proxyjump_transport.adb`, a dedicated opt-in live ProxyJump transport proof separate from the Git matrix. It performs no network access unless `SSH_LIB_LIVE_PROXYJUMP=1` is set. `SSH_LIB_LIVE_PROXYJUMP_SCENARIOS` accepts `SINGLE`, `CHAIN`, `IPV6`, or `ALL`; each selected scenario requires explicit `HOST`, `USER`, `PROXY_JUMP`, and `COMMAND` values through `SSH_LIB_LIVE_PROXYJUMP_<FIELD>` or scenario-specific `SSH_LIB_LIVE_PROXYJUMP_<SCENARIO>_<FIELD>` variables. The test keeps strict known-host verification enabled, opens a ProxyJump-backed session, opens an exec channel over the tunneled target transport, reads stdout bytes without text conversion, observes exit status, closes channel/session, and clears password/passphrase options after each scenario.
Phase 19 completeness pass 314 adds `test_live_proxycommand_transport.adb`, a dedicated opt-in live ProxyCommand transport proof. It performs no network or subprocess-backed ProxyCommand access unless `SSH_LIB_LIVE_PROXYCOMMAND=1` is set. `SSH_LIB_LIVE_PROXYCOMMAND_SCENARIOS` accepts `BASIC`, `TOKEN`, `IPV6`, `FAILS_EARLY`, or `ALL`; each selected non-failure scenario requires explicit `HOST`, `USER`, `PROXY_COMMAND`, and `COMMAND` values through `SSH_LIB_LIVE_PROXYCOMMAND_<FIELD>` or scenario-specific `SSH_LIB_LIVE_PROXYCOMMAND_<SCENARIO>_<FIELD>` variables. `TOKEN` additionally requires the configured command to include `%h` and `%p`, proving the OpenSSH-style token expansion path. `FAILS_EARLY` proves a ProxyCommand that does not produce an SSH transport fails the session open instead of succeeding. The test keeps strict known-host verification enabled, opens a ProxyCommand-backed session, opens an exec channel, reads stdout bytes without text conversion, observes exit status, closes channel/session, and clears password/passphrase options after each scenario.

## Live rekey boundary

Phase 19 completeness pass 132 adds explicit client-initiated live rekeying through `SSH_Lib.Sessions.Rekey`.  The live transport retains the first exchange hash as `Live_Session_Identifier`; later rekeys derive replacement keys from the new exchange hash while keeping that original identifier as the SSH session id.  Rekey KEX packets use the currently active protected packet layer after the initial NEWKEYS, then replacement keys are installed only after NEWKEYS is exchanged and the new host-key signature and known-host trust checks succeed.

The pass intentionally does not add automatic peer-initiated rekey dispatch while blocked inside channel reads.  The exposed operation is explicit client-initiated rekey on an already authenticated live session.

### Phase 19 completeness pass 133: peer-initiated rekey dispatch

Live channel reads now recognize a protected `SSH_MSG_KEXINIT` from the server while waiting for channel data or channel-control packets.  The channel retains an owning-session address and routes that already-read KEXINIT into `SSH_Lib.Sessions.Live_Transport.Rekey_With_Peer_Kexinit`, avoiding loss of the peer KEXINIT packet.  The rekey path sends the client KEXINIT over the currently protected transport, completes the negotiated KEX, verifies host-key signature and known-host trust again, preserves the original SSH session identifier, and installs replacement keys before channel reading continues.

## Automatic rekey boundary

The live transport tracks protected packet and protected wire-byte counts after NEWKEYS. Automatic rekeying is enabled by default and is checked before outbound channel/control packets. Inbound packets contribute to the counters, but reads do not initiate client-side rekey while peer data may already be buffered; peer-initiated KEXINIT during reads is handled by the channel rekey dispatch path.

### Pass 143 interactive credential callback boundary

SSH_Lib now exposes optional non-interactive credential callbacks on `Session_Options` for password authentication, identity-file passphrases, and password-change-required replies. The core library still never opens a UI prompt, shells out, discovers credentials, or stores returned secrets in the session object. Explicit `Password` and `Identity_Passphrase` values take precedence; callbacks are consulted only when the corresponding explicit value is absent and the authentication method is otherwise enabled. Callback secrets containing NUL, CR, or LF fail closed before any USERAUTH request is emitted. Returned password/passphrase material is used only inside the protected userauth path and is cleared from temporary option/session state after use.


## RFC 4419 group-exchange bounds

Live group-exchange KEX uses `Session_Options.Gex_Minimum_Bits`, `Gex_Preferred_Bits`, and `Gex_Maximum_Bits` when encoding `SSH_MSG_KEX_DH_GEX_REQUEST`. The default request is 2048/4096/8192 bits. Invalid request ranges fail closed before the packet is sent. Server-supplied groups are parsed and then accepted only if they match the implemented group14, group16, or group18 MODP groups; arbitrary server primes remain rejected.

Phase 19 completeness pass 315 completes the ProxyCommand support pass: subprocess pipe I/O now waits with configured timeouts, `Connect_Timeout_MS` is used as the fallback ProxyCommand pipe timeout, missing `sh` fails closed, deterministic fixtures cover `%h`, `%n`, `%p`, `%r`, `%%`, unknown percent preservation, trailing percent preservation, and direct `Proxy_Command => "none"`, and the opt-in live ProxyCommand suite includes both local `nc %h %p` interoperability evidence and a failure scenario for non-SSH subprocess output.

Phase 19 completeness pass 316 records ProxyCommand live evidence without moving public-network execution into default release validation. The runtime boundary remains explicit: live ProxyCommand scenarios run only behind `SSH_LIB_LIVE_PROXYCOMMAND=1`, and archived evidence is enforced only when `SSH_LIB_REQUIRE_LIVE_PROXYCOMMAND_REPORT=1` is set.

Phase 19 completeness pass 317 completes the ProxyCommand diagnostics and release-evidence policy. `Sessions.Last_Proxy_Command_Diagnostics` exposes non-secret child lifecycle state, the live ProxyCommand `HANGS` scenario proves timeout cleanup with close-attempt/close-complete metadata, and `release_artifacts/live_proxycommand_report.txt` is the default archived report path when `check_live_proxycommand_report` is required without an explicit `SSH_LIB_LIVE_PROXYCOMMAND_REPORT`.

Phase 19 completeness pass 318 extends the archived live-evidence convention beyond ProxyCommand. Live Git matrix evidence defaults to `release_artifacts/live_git_matrix_report.txt` when its guard is required without an explicit path, SFTP v4-v6 interop evidence defaults to `release_artifacts/sftp_v4_v6_interop_report.txt`, and the SFTP seed-fuzzer runner defaults to `release_artifacts/sftp_fuzzer_seed_report.txt`.
