# Git over SSH

SSH_Lib supports the SSH side of Git-over-SSH: host-key verification, authentication, remote exec-channel setup, binary-safe read/write, EOF, close, and remote exit-status reporting. It does not implement Git protocol semantics.

## Upload-pack command

`SSH_Lib.Git.Build_Upload_Pack_Command` builds:

```text
git-upload-pack '<repo>'
```

The command string is sent as a remote SSH exec request. SSH_Lib does not execute the command locally and does not invoke a local shell.

## Receive-pack command

`SSH_Lib.Git.Build_Receive_Pack_Command` builds:

```text
git-receive-pack '<repo>'
```

`version` uses this for push. SSH_Lib still treats all request and response bytes as opaque data.

## Repository path quoting

Repository paths are emitted as one POSIX-style single-quoted remote command argument. Embedded single quotes are safely represented using the OpenSSH-compatible sequence for ending the quote, emitting an escaped quote, and reopening the quote.

The Git helper rejects:

* empty repository paths
* NUL
* CR
* LF
* paths longer than the documented maximum

These checks prevent command-line ambiguity and accidental line-oriented interpretation. The helper does not decide whether a repository exists.

## scp-like remotes

`SSH_Lib.Remote_Names.Parse` accepts scp-like remotes such as:

```text
git@gh:repo.git
gh:owner/repo.git
```

The host part is the SSH config lookup key. The text after the colon is the repository path and is never modified by config resolution.

## ssh:// remotes

`SSH_Lib.Remote_Names.Parse` accepts `ssh://` remotes such as:

```text
ssh://git@gh/repo.git
ssh://git@gh:2222/repo.git
ssh://git@[::1]/repo.git
```

A malformed host returns `Invalid_Host`. A malformed port returns `Invalid_Port`. Query strings and fragments are rejected rather than interpreted.

## Config aliases

Use `SSH_Lib.Config.Resolve` or `SSH_Lib.Git_Transport.Prepare` with the parsed remote host. `HostName` may replace the connection host, while explicit remote user and explicit remote port override config values. Config does not alter the repository path.

## Raw byte flow

`SSH_Lib.Channels.Write` and `SSH_Lib.Channels.Read_Some` use `Ada.Streams.Stream_Element_Array`. `SSH_Lib.Git` exposes bounded pkt-line frame/cursor helpers, ref advertisement / protocol-v2 `ls-refs` response parsing, protocol-v2 capability advertisement validation, capability-token/list, upload-pack negotiation line/request/ACK stream helpers, upload-pack fetch request composition, receive-pack update/request validation, protocol-v2 command request/response validation, side-band packet/stream helpers, status-line, upload-pack response and receive-pack report validation, pack header/object-at-offset with next-offset reporting, pack object-sequence validation, zlib-object-data with consumed-length reporting, caller-supplied-delta and delta-chain/index metadata, complete v2 pack-index structural validation, pack-index object lookup, pack-index offset/pack, CRC/pack, and object-id/pack consistency validation for non-delta, immediate-delta, and bounded delta-chain entries, pack delta-base and dependency-graph validation, pack/index SHA-1 checksum verification, object-id, and ref-name helpers. `SSH_Lib.Git_Transport` can run one bounded upload-pack or receive-pack service exchange over an authenticated session, but SSH_Lib does not inspect progress text, maintain ref/object databases, or track repository state.

Example opaque payloads may look like pkt-line or packfile bytes, but they remain test data for binary preservation only.

## stderr handling

`Read_Some` returns stdout/channel data for the exec channel. `Read_Stderr` returns SSH extended-data type 1 separately for diagnostics. Stderr is never returned by `Read_Some`, so `version` does not confuse diagnostics with pkt-line or packfile data.

## EOF and exit status

Call `Send_EOF` after all request bytes have been written. Continue reading until `End_Of_Stream` or a failure status. Then call `Exit_Status` to map the remote Git command result into user-facing `version` diagnostics.

Callers that want the standard single-service sequence can use `SSH_Lib.Git_Transport.Open_Service` and `Complete_Service`, or `Run_Service` for a combined blocking exchange. The response buffer is caller-provided and bounded; oversized responses fail instead of being truncated.


For direct remote/config composition, preserve the original remote text until port override handling is complete. `ssh://gh/repo.git` has no explicit port and may inherit `Port` from SSH config, while `ssh://gh:22/repo.git` explicitly overrides config with port 22. Use `SSH_Lib.Remote_Names.Has_Explicit_Port` or the text-aware `SSH_Lib.Config.Resolve_Remote` overload to avoid losing this distinction.

Repository paths containing NUL, CR, or LF are unsafe for remote Git command construction and are reported as `Invalid_Command` by the Phase 18 preparation paths, including the direct text-aware config resolver.
