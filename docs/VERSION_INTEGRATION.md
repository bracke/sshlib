# Version Integration

## Overview

SSH_Lib is the SSH transport substrate for `version`. It opens authenticated, encrypted SSH sessions, executes a remote Git service command, and moves opaque bytes over an exec channel. `version` owns Git protocol semantics.

SSH_Lib treats channel data as raw bytes. SSH_Lib.Git exposes bounded pkt-line frame and cursor helpers, ref advertisement and protocol-v2 `ls-refs` response parsing, protocol-v2 capability advertisement validation, capability-token parsing and list scanning, upload-pack negotiation line/request/ACK stream helpers, upload-pack fetch request composition, receive-pack update/request validation, bounded fetch/push workflow state machines, bounded fetch/push retry and pack policy decisions, protocol-v2 command request/response validation, side-band demultiplexing and stream validation, upload-pack response validation, receive-pack status-report/report validation, pack header/object-entry header, pack object-at-offset inflation with next-offset reporting, pack object-sequence validation, bounded zlib object-data inflation with consumed-length reporting, caller-supplied delta and delta-chain application, complete v2 pack-index structural validation, pack/index SHA-1 checksum verification, pack-index object lookup, pack-index offset/pack, CRC/pack, and object-id/pack consistency validation for non-delta, immediate-delta, and bounded delta-chain entries, pack delta-base and dependency-graph validation, pack-index layout/header/fanout/object-name/order/fanout-consistency/CRC/offset/large-offset/count/checksum, delta-base metadata parsers, object-id validation, ref-name validation/classification, and bounded local repository-state helpers for refs, loose/packed objects, index/worktree paths, porcelain status policy, branch checkout/reset primitives, and fetch/push ref update policy. SSH_Lib still does not interpret progress text or provide fully managed porcelain fetch, push, merge, rebase, cherry-pick, conflict resolution, or recursive checkout policy. SSH_Lib.Git_Transport can run one bounded upload-pack or receive-pack service exchange over an authenticated session. SSH_Lib does not invoke `git`. SSH_Lib does not invoke `ssh`. SSH_Lib does not invoke a local shell. SSH_Lib sends remote exec command strings over SSH. SSH_Lib.Git quotes repository path text for OpenSSH-compatible remote command handling. `Read_Some` and `Write` use `Ada.Streams.Stream_Element_Array`.

## Dependency direction

The dependency direction is always:

```text
version -> SSH_Lib
```

SSH_Lib must not depend on `version`, must not import `version` packages, and must not encode repository, index, ref, object, or working-tree semantics.

## Remote parsing

Use `SSH_Lib.Remote_Names.Parse` for common Git-over-SSH remote names. The package accepts scp-like names such as:

```text
git@github.com:owner/repo.git
```

and `ssh://` names such as:

```text
ssh://git@github.com/owner/repo.git
ssh://git@github.com:2222/owner/repo.git
```

Malformed hosts map to `Invalid_Host`. Malformed ports map to `Invalid_Port`. Credential-like userinfo is rejected; SSH_Lib does not store passwords or Git credentials.

## SSH config resolution

Use `SSH_Lib.Config.Load_Default` or `SSH_Lib.Config.Load`, then resolve by the parsed remote host. Callers using direct `Remote_Names` + `Config` composition should prefer the text-aware `SSH_Lib.Config.Resolve_Remote (Config, Remote_Text, Default_User, Options)` overload, or use `SSH_Lib.Remote_Names.Has_Explicit_Port` when applying port overrides manually. This preserves the distinction between implicit `ssh://host/repo.git` and explicit `ssh://host:22/repo.git`. The deterministic merge policy for `version` is:

* The parsed remote host is the SSH config lookup key.
* `HostName` may replace the connection host.
* An explicit remote user overrides config `User`.
* An explicit remote port overrides config `Port`.
* Config `User` is used when the remote has no user.
* `Default_User` is used only when neither remote nor config provides a user.
* Config `IdentityFile` applies unless the caller overrides it externally.
* Config `IdentitiesOnly` applies according to config policy.
* `Verify_Known_Host` remains `True`.
* `Trust_On_First_Use` remains `False` unless the integration deliberately opts into first-use writes.
* `Strict_Host_Key` remains `True`.
* `Use_Agent` remains `True` unless config `IdentitiesOnly` disables agent use.
* The repository path is never modified by config.

`SSH_Lib.Git_Transport.Prepare` implements this narrow merge and command-preparation shape without opening a network connection. `Open_Service`, `Complete_Service`, and `Run_Service` provide the bounded single-service channel sequence after a session is authenticated.

## Session opening

After preparation, call `SSH_Lib.Sessions.Open` with the returned `Session_Options`. The secure defaults remain enabled: host-key verification, strict host-key checking, and agent support unless `IdentitiesOnly` disables agent usage.

## Upload-pack flow

The intended fetch shape is:

```ada
Remote_Status := SSH_Lib.Remote_Names.Parse (Remote_Text, Remote);
Prepare_Status := SSH_Lib.Git_Transport.Prepare
  (Remote_Text, Config, Default_User,
   SSH_Lib.Git_Transport.Upload_Pack, Options, Command);
Status := SSH_Lib.Sessions.Open (Options, Session);
Status := SSH_Lib.Channels.Open_Exec
  (Session, Ada.Strings.Unbounded.To_String (Command), Channel);
Status := SSH_Lib.Channels.Write (Channel, Request_Bytes);
Status := SSH_Lib.Channels.Send_EOF (Channel);
loop
   Status := SSH_Lib.Channels.Read_Some (Channel, Buffer, Last);
   exit when Status = SSH_Lib.Errors.End_Of_Stream;
   exit when Status /= SSH_Lib.Errors.Ok;
   -- version consumes Buffer(Buffer'First .. Last) as raw Git protocol bytes.
end loop;
Status := SSH_Lib.Channels.Exit_Status (Channel, Exit_Code);
```

The equivalent bounded helper is `SSH_Lib.Git_Transport.Run_Service`, which opens the prepared exec channel, writes the request, sends EOF, reads into a caller-provided response buffer, validates the upload-pack response shape, attempts exit-status observation, closes the channel, and returns `Git_Workflow_Summary`.

## Receive-pack flow

For push, use `SSH_Lib.Git_Transport.Receive_Pack` or `SSH_Lib.Git.Build_Receive_Pack_Command`. The byte flow is identical: `version` writes one or more request chunks, sends EOF when the request stream is complete, reads opaque response bytes, then checks `Exit_Status`.

## Binary stream handling

Git protocol bytes are opaque binary data to SSH_Lib except for the optional bounded pkt-line frame/cursor, protocol-v2 capability advertisement, capability-token/list, ACK/NAK stream, side-band packet/stream, status-line, pack header, pack object-at-offset inflation with next-offset reporting, pack object-sequence validation, bounded zlib object-data inflation with consumed-length reporting, caller-supplied delta and delta-chain application, complete v2 pack-index structural validation, pack/index SHA-1 checksum verification, pack-index object lookup, pack-index offset/pack, CRC/pack, and object-id/pack consistency validation for non-delta, immediate-delta, and bounded delta-chain entries, pack delta-base and dependency-graph validation, pack-index layout/header/fanout/object-name/order/fanout-consistency/CRC/offset/large-offset/count/checksum, and delta-base metadata helpers in `SSH_Lib.Git`. Channel payloads must stay in `Ada.Streams.Stream_Element_Array`; helpers must not convert arbitrary payloads to `String`, validate UTF-8, normalize line endings, perform unrequested porcelain repository policy, or log raw packfile bytes by default.

Required binary preservation includes NUL, LF, CR, DEL, bytes above 127, and `16#FF#`.

## EOF and exit status

`Send_EOF` signals that the client request stream is complete. It does not mean the server has finished sending response bytes. Continue reading until `End_Of_Stream` or another deterministic status is returned, then query `Exit_Status`. A nonzero remote exit maps to `Remote_Exit_Nonzero` when represented by the channel/status path.

## Error/status mapping

| SSH_Lib status | version-facing meaning |
| --- | --- |
| `Invalid_Host` | invalid remote host |
| `Invalid_Port` | invalid remote port |
| `Invalid_User` | missing/invalid SSH user |
| `Invalid_Command` | invalid remote Git command or repository path |
| `DNS_Failed` | host lookup failed |
| `Connection_Failed` | TCP connection failed |
| `Timeout` | connection or SSH operation timed out |
| `Handshake_Failed` | SSH protocol handshake failed |
| `Host_Key_Unknown` | server host key is not trusted |
| `Host_Key_Mismatch` | server host key changed |
| `Authentication_Failed` | SSH authentication failed, including missing or wrong identity passphrases |
| `Channel_Open_Failed` | SSH session channel could not be opened |
| `Channel_Request_Failed` | remote Git command was rejected |
| `Read_Failed` | SSH channel read failed |
| `Write_Failed` | SSH channel write failed |
| `Remote_Exit_Nonzero` | remote Git command exited nonzero |
| `Cancelled` | operation cancelled |
| `Unsupported_Feature` | requested SSH feature is unsupported, unsupported algorithms, unsupported encrypted identity algorithms, or advanced SSH features outside the Version transport boundary |
| `Internal_Error` | implementation/internal failure |

## Security defaults

Integration helpers must not disable host-key verification, must not silently trust unknown hosts, must not use implicit subprocess fallback, and must not log private key material, signatures, session keys, or shared secrets. The explicit subprocess boundaries are `ProxyCommand`, Git credential helpers, and caller-invoked `SSH_Lib.Git_Transport.Run_Service_With_Local_Git` / `Run_Service_With_Local_SSH`.

## Unsupported behavior

SSH_Lib does not provide recursive porcelain checkout, three-way merge/conflict handling, rebase/cherry-pick sequencing, SSH server mode, SFTP server mode, C bindings, or public-network fallback examples in default tests. SCP upload is supported for regular files, while SFTP and `SSH_Lib.File_Transfer` provide client-side upload/download, recursive tree, inventory, verify/delete/restore, resume, metadata, symlink, and modeled extension workflows. `SSH_Lib.Channels.Open_Shell` exposes non-PTY shell channels, `SSH_Lib.Channels.Open_PTY_Shell` exposes PTY-backed shell startup with optional terminal modes, and `SSH_Lib.Channels.Resize_PTY` exposes PTY resize requests, though `version` normally uses exec channels for Git commands. ProxyJump is implemented internally for transport routing through SSH direct-tcpip forwarding. `SSH_Lib.Channels.Open_Direct_TCPIP` exposes the same channel type for caller-managed local forwarding; `SSH_Lib.Forwarding` exposes synchronous local and dynamic listeners, callback-based background accept services with optional accepted-connection caps, managed local/dynamic worker-pool services with bounded worker and accepted-connection caps, managed remote-forward services with request, accept, target-connect, bounded pump, and cancel-on-exit lifecycle, accepted-connection, one-connection SOCKS accept, X11 `DISPLAY` parsing and local X server connection helpers, SOCKS5 no-auth CONNECT, bounded `Pump_Once`, and bounded alternating `Pump_Bounded` primitives; `SSH_Lib.Git` exposes bounded pkt-line frame parsing/encoding/cursor iteration, protocol-v2 capability advertisement validation, capability-token parsing and list scanning, ACK/NAK stream validation, side-band demultiplexing and stream validation, status-report line parsing, bounded fetch/push workflow state machines, bounded fetch/push policy decisions, porcelain status policy, repository index/worktree model summaries, repository ref/object database summaries, repository tree traversal, pack header/object-entry header, pack object-at-offset inflation with next-offset reporting, pack object-sequence validation, zlib object-data inflation with consumed-length reporting, caller-supplied delta and delta-chain application, complete v2 pack-index structural validation, pack/index SHA-1 checksum verification, pack-index object lookup, pack-index offset/pack, CRC/pack, object-id/pack consistency validation for non-delta, immediate-delta, and bounded delta-chain entries, pack delta-base and dependency-graph validation, pack-index layout/header/fanout/object-name/order/fanout-consistency/CRC/offset/large-offset/count/checksum metadata, delta-base metadata helpers, object-id validation, ref-name validation/classification, bounded ref/object/index/worktree helpers, branch checkout/reset primitives, fetch/push ref update policy helpers, explicit credential-helper execution, console credential prompting, and bounded credential store management. `SSH_Lib.Git_Transport` also exposes explicit local Git/SSH subprocess fallback helpers for one bounded service exchange. `SSH_Lib.Sessions.Request_Remote_Forward` and `Cancel_Remote_Forward` expose remote-forward request primitives, `SSH_Lib.Channels.Accept_Forwarded_TCPIP` accepts pending server-opened forwarded channels, and `SSH_Lib.Forwarding.Start_Managed_Remote_Forward_Service` provides managed remote-forward orchestration, though `version` normally does not need forwarding APIs for Git-over-SSH remotes.

## Manual real-server probe

The optional `manual_git_upload_pack_probe.adb` example is excluded from default builds and tests. It exists only for explicit, user-supplied real-server checks and requires host, user, repository path, trusted `known_hosts` setup, and working identity-file or ssh-agent authentication. It writes and reads opaque `Ada.Streams.Stream_Element_Array` data, sends EOF, queries the remote exit status, and avoids printing raw pkt-line or packfile bytes.

### Parsed remote resolver note
The text-aware resolver maps repository control breaks (`NUL`, `CR`, or `LF` after the remote path separator) to `Invalid_Command`, matching `SSH_Lib.Git_Transport.Prepare`. This keeps direct Remote_Names + Config composition suitable for version-facing error messages without broadening SSH_Lib into Git protocol parsing.


`SSH_Lib.Config.Resolve_Remote` has a parsed-record overload for legacy direct composition and a text-aware overload for version-style integration. The text-aware overload is preferred because it preserves the distinction between an omitted port and an explicit `ssh://host:22/repo.git` override. Both overloads return `Invalid_User` when no remote, config, or default user can supply a usable SSH user, preserve matching `ProxyCommand` and `ProxyJump` as session data.


### Phase 19 completeness pass 24

Added deterministic `version` adapter consumption coverage. The fixture resolves an SSH remote through `SSH_Lib.Git_Transport.Prepare`, keeps host-key verification enabled, opens a local authenticated SSH_Lib session fixture, executes both `git-upload-pack 'repo.git'` and `git-receive-pack 'repo.git'`, writes opaque `Ada.Streams.Stream_Element_Array` request bytes, reads opaque binary response bytes byte-for-byte, sends EOF, reads exit status, and closes the channel/session without higher-level Git protocol interpretation or subprocess fallback.


## Deterministic adapter consumption fixture

`tests/version_integration/src/test_version_adapter_consumption.adb` runs `SSH_Lib.Tests.Fixtures.Version_Adapter_Consumption.Assert_Deterministic_Version_Adapter_Consumption`. It proves the intended `version` adapter flow without network access: resolve remote/config, prepare upload-pack and receive-pack commands, use an authenticated encrypted session fixture, call `Open_Exec`, `Write`, `Read_Some`, `Send_EOF`, `Exit_Status`, and `Close`, and assert all request/response payloads remain opaque binary bytes.

### Exit-status absence

After `Read_Some` returns `End_Of_Stream`, call `Exit_Status` as usual. If the server did not send a parseable `exit-status` request before the channel completed, SSH_Lib returns `Channel_Request_Failed`; this is distinct from `Unsupported_Feature` and should be treated as an incomplete/failed remote command status observation.

## Phase 19 completeness pass 71

Added an opt-in live Git-over-SSH end-to-end test executable, `test_live_git_e2e.adb`. The default release suite still performs no public-network access: the executable exits successfully as skipped unless `SSH_LIB_LIVE_GIT_E2E=1` is set. When enabled, it requires `SSH_LIB_LIVE_GIT_HOST`, `SSH_LIB_LIVE_GIT_USER`, and `SSH_LIB_LIVE_GIT_REPO`, keeps known-host verification enabled, opens a real authenticated session, executes `git-upload-pack` by default or `git-receive-pack` when `SSH_LIB_LIVE_GIT_SERVICE=receive-pack`, writes an opaque Git flush packet, sends EOF, reads opaque stdout bytes, observes exit status, and closes the channel/session. This proves the public API sequence needed by `version` without adding higher-level Git protocol interpretation to the SSH library.


### Pass 127 live Git interoperability matrix

Pass 127 adds `test_live_git_interop_matrix.adb`, an opt-in live interoperability matrix for the Version-facing Git-over-SSH path. It performs no public-network access unless `SSH_LIB_LIVE_GIT_MATRIX=1` is set. When enabled, `SSH_LIB_LIVE_GIT_SCENARIOS` selects comma-separated scenarios such as `DIRECT`, `AGENT`, `IDENTITY`, `PASSWORD`, `PASSPHRASE`, `PROXYJUMP`, and `RECEIVE`; pass 128 makes this selector whitespace/case tolerant, rejects unknown scenario names before network access, and adds `ALL` as a shorthand for the full matrix.

The matrix keeps strict known-host verification enabled and exercises the public sequence required by Version: open an authenticated session, open an exec channel with a safely quoted Git service command, write an opaque Git flush packet, send EOF, read opaque stdout bytes, observe exit status, close the channel, and close the session. Scenario-specific values can be supplied with `SSH_LIB_LIVE_GIT_<SCENARIO>_<FIELD>` and fall back to the existing single-case names such as `SSH_LIB_LIVE_GIT_HOST`, `SSH_LIB_LIVE_GIT_USER`, `SSH_LIB_LIVE_GIT_REPO`, `SSH_LIB_LIVE_GIT_KNOWN_HOSTS`, `SSH_LIB_LIVE_GIT_IDENTITY`, `SSH_LIB_LIVE_GIT_PASSWORD`, `SSH_LIB_LIVE_GIT_IDENTITY_PASSPHRASE`, and `SSH_LIB_LIVE_GIT_PROXY_JUMP`.

Phase 19 completeness pass 130 adds `test_live_proxyjump_transport.adb`, a dedicated opt-in live ProxyJump transport proof separate from the Git matrix. It performs no network access unless `SSH_LIB_LIVE_PROXYJUMP=1` is set. `SSH_LIB_LIVE_PROXYJUMP_SCENARIOS` accepts `SINGLE`, `CHAIN`, `IPV6`, or `ALL`; each selected scenario requires explicit `HOST`, `USER`, `PROXY_JUMP`, and `COMMAND` values through `SSH_LIB_LIVE_PROXYJUMP_<FIELD>` or scenario-specific `SSH_LIB_LIVE_PROXYJUMP_<SCENARIO>_<FIELD>` variables. The test keeps strict known-host verification enabled, opens a ProxyJump-backed session, opens an exec channel over the tunneled target transport, reads stdout bytes without text conversion, observes exit status, closes channel/session, and clears password/passphrase options after each scenario.

## Rekey integration note

`version` can call `SSH_Lib.Sessions.Rekey` on an already opened session when it wants to proactively rotate SSH transport keys before or between Git service channel operations.  The call preserves the original SSH session identifier and does not change the public Git byte-stream contract: Git pkt-line and packfile bytes remain caller-owned opaque channel data.
