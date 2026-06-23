# SFTP support

SSH_Lib.SFTP supports the default SFTP v3 workflow and negotiated SFTP v4-v6 sessions through the persistent `Client` API.

## Basic transfer

```ada
Status := SSH_Lib.SFTP.Upload_Data
  (Session, "/tmp/file.txt", Bytes, "0644");
Status := SSH_Lib.SFTP.Download_Data
  (Session, "/tmp/file.txt", Buffer);
```

The one-shot session helpers open the `sftp` subsystem, perform the operation, and close the channel. Persistent clients keep one SFTP channel open and expose the negotiated version and extension data:

```ada
Status := SSH_Lib.SFTP.Open
  (Session, Client, SSH_Lib.SFTP.Maximum_Protocol_Version);
if Status = SSH_Lib.Errors.Ok then
   Extensions := SSH_Lib.SFTP.Extensions (Client);
   Version := SSH_Lib.SFTP.Version (Client);
end if;
```

Persistent clients also expose the high-level transfer and tree operations available through session helpers, including file/stream upload and download, resume, directory upload/download, remove/copy/sync tree, directory paging, symlink read/create, and raw typed extension requests. Use the persistent API when several operations should share one negotiated SFTP channel and one extension snapshot. Persistent file, stream, resume, and recursive tree transfers use the negotiated protocol version, `supported2` read caps, and cached `limits@openssh.com` write caps when available. Recursive upload/download/copy/sync paths keep the persistent channel and route file leaves through the client-aware transfer helpers.

## Extensions and capabilities

Use `Supports_Extension`, `Supports_Open_Mode`, `Supports_Attributes`, and `Supports_Block_Mask` before issuing optional operations when the application needs explicit feature decisions. Known extension checks can use the typed `Known_Extension` catalogue and `Extension_Name`, avoiding string literals for every modeled extension while leaving arbitrary vendor extensions on the raw string API. Persistent-client operations also perform their own preflight checks from negotiated extension data and the `supported2` capability block when a server advertises it. Handles opened through a persistent client carry the negotiated version and extension context, so handle-level FSTAT/FSETSTAT/fsync/text-seek/lock operations can use v4+ encodings and capability checks.

Relevant optional operations include:

- OpenSSH extensions: `posix-rename@openssh.com`, `fsync@openssh.com`, `statvfs@openssh.com`, `hardlink@openssh.com`, `lsetstat@openssh.com`, `limits@openssh.com`, and `expand-path@openssh.com`.
- Draft v4-v6 features: `versions`, `version-select`, `supported2`, native `LINK`, `BLOCK`, `UNBLOCK`, and `text-seek`.


## Remote status details

Most APIs return the coarse `SSH_Lib.Errors.Status` value used throughout the library. When a server returns `SSH_FXP_STATUS`, the exact SFTP status code and message are also retained for diagnostics:

```ada
Status := SSH_Lib.SFTP.Remove_File (Client, Remote_Path, Result);
if Status /= SSH_Lib.Errors.Ok then
   Code := Result.Remote_Status_Code;
   Name := Result.Remote_Status_Name;
   Message := Result.Remote_Status_Message;
end if;

Status := SSH_Lib.SFTP.Stat (Client, Remote_Path, Attributes);
SSH_Lib.SFTP.Capture_Result
  (Status, Result, SSH_Lib.SFTP.Stat_Operation);
```

`SFTP_Result` carries the operation tag, coarse library status, exact remote status code, status name, and server message together. Operation-specific overloads are available for common status/extension operations such as open/close, remove, rename, POSIX rename, persistent transfer helpers, tree/directory/link helpers, metadata setters, stat/realpath/list helpers, lock/unlock/text-seek, version-select, hardlink, fsync, expand-path, copy-data, lsetstat, check-file, statvfs, and limits. Dedicated extension result records are also available: `Check_File_Result`, `StatVFS_Result`, `Limits_Result`, and `Extended_Request_Result` bundle the operation diagnostics with the operation-specific values. For other operations, call `Capture_Result` immediately after the operation to freeze the status details before another SFTP call overwrites the diagnostic state. This preserves v4+ causes such as `SSH_FX_NO_SPACE_ON_FILESYSTEM`, `SSH_FX_BYTE_RANGE_LOCK_REFUSED`, and `SSH_FX_OWNER_INVALID` without changing the common return type.

```ada
Check_Info := SSH_Lib.SFTP.Check_File_Info
  (Client, Remote_Path, "sha1,sha256");
Stats_Info := SSH_Lib.SFTP.StatVFS_Info (Session, Remote_Path);
Limits_Info := SSH_Lib.SFTP.Limits_Info (Session);
Extended_Info := SSH_Lib.SFTP.Extended_Request_Info
  (Client, "vendor@example.com", Payload);
Snapshot := SSH_Lib.SFTP.Negotiated_Info (Client);
```

## Transfer sizing

`Transfer_Options` controls pipeline depth, retry/verification behavior, atomic uploads, and per-request read/write chunk caps. Persistent-client downloads honor `supported2.Max_Read_Size` when the server advertises it, and then apply `Read_Chunk_Size` as an application cap. Persistent-client uploads apply `Write_Chunk_Size` and also cap write chunks to `limits@openssh.com.Max_Write_Length` when the server advertises and returns limits. Channel-level one-shot helpers apply the caller's chunk cap but do not perform an extra limits probe.

```ada
Options.Read_Chunk_Size := 32 * 1024;
Options.Write_Chunk_Size := 64 * 1024;
Options.Retry_Count := 2;
Options.Adaptive_Chunking := True;
Options.Minimum_Adaptive_Chunk_Size := 4 * 1024;
Status := SSH_Lib.SFTP.Download_Data (Session, Remote_Path, Buffer, Options);
```

When `Adaptive_Chunking` is enabled, session-level upload/download retry paths reduce read/write chunk size and pipeline depth on later attempts, bounded by `Minimum_Adaptive_Chunk_Size`. Defaults preserve the previous static sizing behavior.


## Check-file

Servers that advertise `check-file` can hash a remote file or range without downloading the content:

```ada
Info := SSH_Lib.SFTP.Check_File_Info
  (Client, Remote_Path, "sha1,sha256");
if Info.Result.Status = SSH_Lib.Errors.Ok then
   --  Info.Algorithm is the selected server algorithm.
   --  Info.Digest contains the raw hash.
end if;
```

Use `Supports_Extension (Extensions (Client), Check_File_Extension)` when the application wants to decide before issuing the request.

## v4-v6 attributes

`File_Attributes` includes v4+ fields for allocation size, owner/group, create time, ACL, attribute bits, text hint, MIME type, link count, and untranslated name. Prefer the helper setters when constructing metadata for `Set_Attributes`:

```ada
SSH_Lib.SFTP.Set_Owner_Group (Attrs, "user", "group");
SSH_Lib.SFTP.Set_Mime_Type (Attrs, "text/plain");
SSH_Lib.SFTP.Set_Attribute_Bits (Attrs, Bits, Valid_Bits);
Status := SSH_Lib.SFTP.Set_Attributes (Client, Remote_Path, Attrs);
Status := SSH_Lib.SFTP.Set_Path_Mime_Type (Client, Remote_Path, "text/plain");
Status := SSH_Lib.SFTP.Set_Path_Owner_Group (Client, Remote_Path, "user", "group");
```

## Vendor extensions

Use the modeled wrappers for stable vendor extensions such as `hardlink@openssh.com`, `fsync@openssh.com`, `expand-path@openssh.com`, `copy-data`, and `lsetstat@openssh.com`; these wrappers include direct `SFTP_Result` overloads so callers do not need to capture diagnostics manually. Use the `Known_Extension` enum with `Extension_Name` and `Supports_Extension` for every extension modeled by the library, including passive extensions such as `versions`, `version-select`, and `supported2`. Use `Extended_Request_Info` for vendor-specific extensions that do not have a typed wrapper. It preserves the raw extended reply payload together with `SFTP_Result` diagnostics. First-class wrappers are intentionally reserved for extensions whose request and reply shapes are stable enough to model directly.

## v4-v6 live interop

The normal local OpenSSH fixture covers SFTP v3 because OpenSSH's server negotiates v3. To run the optional v4-v6 interop path, provide a server that supports SFTP v4-v6 and set:

```sh
export SSH_LIB_TEST_SFTP_V4_ENABLE=1
export SSH_LIB_TEST_SFTP_V4_HOST=127.0.0.1
export SSH_LIB_TEST_SFTP_V4_PORT=22
export SSH_LIB_TEST_SFTP_V4_USER=user
export SSH_LIB_TEST_SFTP_V4_IDENTITY_FILE=/path/to/key
export SSH_LIB_TEST_SFTP_V4_REQUEST_VERSIONS=4,5,6
export SSH_LIB_TEST_SFTP_V4_FILE=/tmp/ssh_lib_sftp_v4_v6.txt
```

Then run the interop script:

```sh
../ssh_lib_build/bin/tools/run_sftp_v4_v6_interop
```

The script builds the tests subcrate, enables the v4-v6 fixture path, and runs the AUnit suite once for each requested version, printing a pass/fail matrix summary. Use `SSH_LIB_TEST_SFTP_V4_REQUEST_VERSION=6` for a single version or `SSH_LIB_TEST_SFTP_V4_REQUEST_VERSIONS=4,5,6` for the matrix. Set `SSH_LIB_TEST_SFTP_V4_REPORT=/path/to/report` to archive deterministic evidence, then require it with `SSH_LIB_REQUIRE_SFTP_V4_REPORT=1 ../ssh_lib_build/bin/tools/check_sftp_v4_v6_interop_report`; `SSH_LIB_REQUIRED_SFTP_V4_VERSIONS` selects the required version list and defaults to `4,5,6`. When the external server advertises `statvfs`, `limits`, or `check-file`, the live fixture also exercises those semantic extension paths and validates the typed result operation tags. This is a real interop path, but it is only as complete as the external server configured for it; the local OpenSSH fixture remains v3-only.

## Server role

SSH_Lib.SFTP is a client implementation. It can connect to SFTP subsystems, negotiate protocol versions, and issue file operations, but it does not implement an SFTP server/subsystem. Server-side SFTP remains outside the implemented runtime surface; applications needing that role must provide their own subsystem and can reuse lower-level SSH channel/session pieces separately.

## Runnable examples

The examples project includes external SFTP programs:

- `sftp_upload_download.adb`: opens a session, uploads a small payload, and downloads it back.
- `sftp_v4_v6_metadata.adb`: negotiates the highest supported SFTP version and updates v4+ MIME and owner/group metadata.
- `sftp_status_diagnostics.adb`: demonstrates `SFTP_Result` diagnostics after a remote status reply.
- `sftp_check_file.adb`: calls the `check-file` extension and prints the selected digest algorithm and digest length when the server supports it.

Build them with:

```sh
alr exec -- gprbuild -P examples/examples.gpr
```

## Additional examples

Recursive sync:

```ada
Options.Delete_Extra := True;
Status := SSH_Lib.SFTP.Sync_Directory
  (Session, SSH_Lib.SFTP.Sync_Upload, "/srv/app", "./app",
   Options => Options);
```

Lock and unlock with a negotiated v4-v6 client:

```ada
Status := SSH_Lib.SFTP.Open
  (Session, Client, SSH_Lib.SFTP.Maximum_Protocol_Version);
if Status = SSH_Lib.Errors.Ok then
   Status := SSH_Lib.SFTP.Lock_Range
     (Client, "/tmp/data", 0, 4096, 1);
   if Status = SSH_Lib.Errors.Ok then
      Status := SSH_Lib.SFTP.Unlock_Range (Client, "/tmp/data", 0, 4096);
   end if;
end if;
```

Extension fallback:

```ada
Extensions := SSH_Lib.SFTP.Extensions (Client);
if Extensions.Posix_Rename then
   Status := SSH_Lib.SFTP.Posix_Rename (Session, Old_Path, New_Path);
else
   Status := SSH_Lib.SFTP.Rename (Session, Old_Path, New_Path);
end if;
```

## SFTP fuzzing

The default deterministic fuzz-lite fixture includes an SFTP parser conformance sweep for valid version packets, malformed length fields, unsupported versions, unknown extension skipping, invalid extension framing, and truncated `supported2` payloads. The standalone packet harness also covers reply parser modes for `status`, `handle`, `data`, `attrs-v3`, `attrs-v6`, `name-v3`, `name-v6`, `extended`, `check-file`, `limits`, and `statvfs` packets.

Build the harness and run the whole deterministic seed corpus with an evidence report:

```sh
SSH_LIB_SFTP_FUZZ_REPORT=/tmp/sftp_fuzz_report   ../ssh_lib_build/bin/tools/run_sftp_fuzzer_seed_corpus
```

Individual seeds can be run directly. Root-level seeds default to the `version` parser for backward compatibility; subdirectory seeds pass the mode explicitly:

```sh
ssh_lib_build/bin/tests_fuzz/sftp_packet_fuzzer version tests/vectors/sftp/packet_fuzzer_seeds/version3-minimal.bin
ssh_lib_build/bin/tests_fuzz/sftp_packet_fuzzer data tests/vectors/sftp/packet_fuzzer_seeds/data/data-abc.bin
```

AFL++/honggfuzz-style runners can use `tests/vectors/sftp/packet_fuzzer_seeds` as the initial corpus and invoke `ssh_lib_build/bin/tests_fuzz/sftp_packet_fuzzer MODE @@` for the mode under test. The harness treats every ordinary parser status as success; crashes, failed runtime checks, or abnormal exits are the findings. The seed-corpus report records whether `afl-fuzz`, `honggfuzz`, or `cargo-afl` is installed, but it is deterministic regression evidence rather than a substitute for a timed coverage-guided campaign.

Phase 19 completeness pass 318 extends the archived live-evidence convention beyond ProxyCommand. Live Git matrix evidence defaults to `release_artifacts/live_git_matrix_report.txt` when its guard is required without an explicit path, SFTP v4-v6 interop evidence defaults to `release_artifacts/sftp_v4_v6_interop_report.txt`, and the SFTP seed-fuzzer runner defaults to `release_artifacts/sftp_fuzzer_seed_report.txt`.
