
### Phase 19 completeness pass 308 — live Git zero-exit evidence gate

Pass 508 adds explicit credential storage helpers through `Write_Credential_Store`, `Read_Credential_Store`, and `Delete_Credential_Store`, using bounded `.git/credentials` records and preserving unrelated entries.

Pass 507 adds `Prompt_Credential_Password`, an opt-in console prompt helper built on the existing deterministic prompt text builder. It is never invoked implicitly by session open or Git transport helpers.

Pass 506 adds `Execute_Credential_Helper`, an explicit bounded Git credential-helper execution boundary that sends one helper-format request, reads one bounded helper response, applies a timeout, and parses username/password fields.

Pass 505 adds bounded repository model summaries through `Read_Porcelain_Index_Worktree_Model` and `Summarize_Repository_Database`, exposing index/worktree counts, HEAD/branch state, ref inventories, object inventories, pack-index counts, and missing-ref-target detection.
Pass 506 adds config-driven exec setup through `SSH_Lib.Config_Apply.Open_Configured_Exec`, which applies resolved `SetEnv` and `SendEnv` requests before opening the exec request and honors `RemoteCommand` as the configured command override. `SendEnv` wildcard patterns now expand over the bounded `SSH_Lib.Platform.Environment` listed environment hook while exact names still use `Getenv`.
Pass 507 adds deterministic ControlMaster helpers: `Control_Master_Mode_Of` classifies resolved `ControlMaster` policy values, and `Expand_Control_Path` expands validated OpenSSH-style `ControlPath` tokens including `%C` without executing shell or filesystem helpers.
Pass 508 adds `Control_Persist_Seconds`, a bounded parser for OpenSSH-style `ControlPersist` values such as `10m`, `1h30m`, `yes`, and `no`.
Pass 509 adds `Expand_Local_Command`, a data-only `LocalCommand` helper that honors `PermitLocalCommand`, expands bounded OpenSSH-style tokens, and leaves any local execution to explicit caller policy.
Pass 510 adds `Expand_Known_Hosts_Command`, a data-only `KnownHostsCommand` helper that expands bounded OpenSSH-style host, reason, key type, key blob, and fingerprint tokens without executing the command.
Pass 510 adds bounded `RequestTTY` and `SessionType` classifiers for config-apply callers that need deterministic OpenSSH-style session policy without stringly typed branching.
Pass 511 adds config-driven subsystem setup through `SSH_Lib.Config_Apply.Open_Configured_Subsystem`, which applies resolved `SetEnv` and `SendEnv` requests before the subsystem request, uses `RemoteCommand` as the configured subsystem name when present, and honors `SessionType none`.
Pass 512 adds config-driven shell setup through `Open_Configured_Shell`, mapping resolved `RequestTTY` policy to shell or PTY-shell channel setup after configured environment requests.
Pass 513 extends config-driven exec setup so `RequestTTY yes` and `RequestTTY force` send a PTY request before the configured exec command.
Pass 514 hardens `Plan_Control_Master` so `auto` and `autoask` reuse an existing `ControlPath` only after a mux alive-check over the Unix-domain control socket succeeds; stale regular files and non-mux sockets now plan a new master.
Pass 515 adds `SSH_Lib.Mux`, a bounded OpenSSH-style control mux layer with real `length + type + body` framing, version-4 hello exchange, ext-info/proxy opcodes, typed passenger new-session and forwarding payload helpers, Unix control client connect/send/receive helpers, Unix `SCM_RIGHTS` descriptor passing for passenger fds, OpenSSH-sequenced stdin/stdout/stderr fd helpers, master listener/accept lifecycle, a hello-negotiating control-client dispatcher with backend handler handoff and validated backend responses, bounded control-master serve loop, an owning single-client serve overload for mux proxy handoff, `Sessions.Open` reuse of verified non-ask masters through mux proxy mode, caller-approved ask/autoask ControlMaster actions through `Control_Master_Approval_Callback`, alive/terminate/stop-listening routing decisions, alive pid responses, typed session-opened/remote-port/exit/TTY-failure/ext-info/proxy responses, reason-bearing failure responses, and deterministic `ControlPersist` idle policy.
Pass 516 adds `SSH_Lib.Config_Apply.Start_Planned_Control_Master`, which turns a planned `ControlMaster` start action into a caller-owned mux listener, gates ask/autoask starts through `Control_Master_Approval_Callback`, records caller pid/persist metadata, and makes `Close_Master` unlink owned control socket paths.

Toolchain policy: ssh_lib must be built and validated with Alire GNAT 15 only.
The root, tests, and tools crates require `gnat_native = "^15"`. Confirm with
`alr exec -- gnatls --version`, and do not run plain system `gnat*`,
`gnatmake`, `gnatls`, `gnatprove`, or `gprbuild` in this workspace.

Pass 504 adds bounded porcelain status and fetch/push policy helpers: `Evaluate_Porcelain_Status`, `Decide_Fetch_Policy`, and `Decide_Push_Policy`.

Pass 503 adds bounded fetch and push workflow state machines through `Fetch_Workflow` / `Push_Workflow`, covering request build, response/report acceptance, optional ref-application steps, finish/fail states, and receive-pack remote-error handling.

Pass 502 makes repository tree traversal use resolved packed-object reads with shared bounded scratch, so recursive tree path APIs can traverse packed delta tree objects without per-depth scratch blowup.

Pass 501 adds tag-name repository tree traversal through `List_Tag_Tree_Paths_Hex` and `List_Tag_Tree_Paths_Matching_Hex`.

Pass 500 adds branch-name repository tree traversal through `List_Branch_Tree_Paths_Hex` and `List_Branch_Tree_Paths_Matching_Hex`.

Pass 499 adds HEAD repository tree traversal through `List_HEAD_Tree_Paths_Hex` and `List_HEAD_Tree_Paths_Matching_Hex`.

Pass 498 adds pathspec-filtered repository tree traversal through `List_Tree_Paths_Matching_Hex`, `List_Commit_Tree_Paths_Matching_Hex`, and `List_Ref_Commitish_Tree_Paths_Matching_Hex`, compacting bounded recursive path results in place.

Pass 497 adds managed repository tree traversal through `List_Tree_Paths_Hex`, `List_Commit_Tree_Paths_Hex`, and `List_Ref_Commitish_Tree_Paths_Hex`, returning bounded recursive paths, modes, and object ids.

Pass 496 adds `Build_Sequencer_Pick_Line`, a bounded data-only helper for caller-managed rebase/cherry-pick todo sequencing.

Pass 495 adds `Classify_Three_Way_Blob_Merge`, a bounded object-id decision helper for unchanged, use-ours, use-theirs, and conflict merge cases.

Pass 494 adds `Build_Merge_Conflict_File`, a bounded data-only helper that writes deterministic conflict-marker content into caller-provided buffers without taking over merge policy.

Pass 493 adds `Summarize_Worktree_Status_Matching`, a pathspec-filtered status summary over tracked and untracked worktree paths.

Pass 492 adds `Pathspec_Matches`, a bounded caller-policy helper for matching validated worktree paths against exact, directory-prefix, all-path, and single-wildcard pathspecs.

Pass 491 extends `Reset_Index_To_Commit_Root` and `Checkout_Branch` to walk bounded nested tree entries, allowing recursive blob paths such as `nested/file.txt` to be indexed and materialized.

Pass 490 adds `Clean_Worktree_Not_In_Index`, a bounded cleanup helper that removes ordinary worktree files absent from `.git/index` while preserving ignored files and indexed paths for caller-managed hard-reset/checkout flows.

Pass 489 adds `Detect_Worktree_Copy`, a bounded content-based status helper that reports the first tracked source path and untracked copy path with matching staged blob object IDs.

Pass 488 adds `Detect_Worktree_Rename`, a bounded content-based status helper that reports a missing tracked path and untracked replacement path when their blob object IDs match.

Pass 487 adds bounded ignored-file checks through `Worktree_Path_Ignored` and `Summarize_Worktree_Status_With_Ignored`, covering `.gitignore`, `.git/info/exclude`, and `core.excludesFile` with common exact, basename, directory-prefix, leading-slash, and single-asterisk patterns.

Pass 486 adds recursive worktree file inventory and status summary through `List_Worktree_Files` and `Summarize_Worktree_Status`, skipping `.git` and combining tracked index/worktree state with untracked file counts.

Pass 485 adds `Clear_Credential_Data`, an explicit in-place scrubber for caller-owned credential buffers used with helper responses, prompts, or passwords.

Pass 484 adds `Build_Credential_Password_Prompt`, a deterministic Git credential prompt-text builder for caller-owned UI/callback flows without terminal I/O or secret storage in SSH_Lib.

Pass 483 adds data-only Git credential helper protocol helpers: `Build_Credential_Helper_Request` and `Parse_Credential_Helper_Response` encode/decode line-oriented credential records without executing helpers or storing secrets.

Pass 482 updates `docs/VERSION_INTEGRATION.md` so the version-facing integration notes reflect the current bounded repository-state, checkout/reset, fetch/push policy, forwarding, and data-only credential config surfaces.

Pass 481 adds `Apply_Push_Branch_Update`, a branch update policy helper for push-style ref changes with expected-old verification, fast-forward enforcement, no-op detection, and caller-forced updates.

Pass 480 adds `Apply_Fetch_Ref_Update`, a remote-tracking ref update policy helper that creates, fast-forwards, rejects non-fast-forward updates by default, or allows forced updates when requested.

Pass 479 adds bounded first-parent ancestry and fast-forward merge primitives through `Is_Ancestor_First_Parent` and `Fast_Forward_Branch`.

Pass 478 adds root-tree reset and branch checkout helpers through `Reset_Index_To_Commit_Root` and `Checkout_Branch`, rebuilding the index from a commit root tree, attaching HEAD to a branch, and materializing staged blobs.

Pass 477 changes `Stage_Worktree_File` into an index-preserving upsert and adds `Remove_Index_Path` for checksum-safe staged path removal without dropping unrelated entries.

Pass 476 adds porcelain-style caller-supplied path classification through `Classify_Worktree_Path` and `Summarize_Worktree_Paths`, distinguishing absent, untracked, tracked-missing, tracked-unchanged, and tracked-modified paths.

Pass 475 adds validated `pull.rebase` config helpers and `Valid_Pull_Rebase_Mode` for boolean, merges, and interactive modes.

Pass 474 adds validated `push.default` config helpers and `Valid_Push_Default_Mode` for Git's standard push modes.

Pass 473 adds validated `init.defaultBranch` config helpers through `Write_Init_Default_Branch`, `Read_Init_Default_Branch`, and `Delete_Init_Default_Branch`.

Pass 472 adds bounded data-only `user.name` and `user.email` config helpers with line-safe validation.

Pass 471 adds `Create_Remote_Tracking_Branch_From_HEAD`, a validated helper that resolves HEAD and writes a remote-tracking branch ref at that object id.

Pass 470 adds `Create_Tag_Ref_From_HEAD`, a validated helper that resolves HEAD and writes a lightweight tag ref at that object id.

Pass 469 adds `Create_Branch_From_HEAD`, a validated helper that resolves HEAD and writes a branch at that object id.

Pass 468 adds `Attach_HEAD_To_Branch`, a validated short-branch-name wrapper for attaching HEAD to `refs/heads/<name>`.

Pass 467 adds `Read_Current_Branch`, returning the short branch name when HEAD is attached to `refs/heads/<name>`.

Pass 466 adds `Read_HEAD_Target`, a convenience helper that reports whether HEAD is attached and returns the symbolic target when present.

Pass 465 adds `Resolve_Branch`, `Resolve_Tag_Ref`, and `Resolve_Remote_Tracking_Branch` convenience wrappers for direct, symbolic, or packed ref resolution.

Pass 464 adds remote-tracking branch convenience helpers: `Write_Remote_Tracking_Branch`, `Read_Remote_Tracking_Branch`, `Delete_Remote_Tracking_Branch`, and `Remote_Tracking_Branch_Exists`.

Pass 463 adds `List_Remote_Tracking_Branches`, a bounded remote-tracking inventory helper that strips `refs/remotes/` while preserving loose/packed object ids.

Pass 462 adds `List_Tag_Refs`, a bounded lightweight-tag inventory helper that strips `refs/tags/` while preserving loose/packed object ids.

Pass 461 adds `List_Branches`, a bounded branch-name inventory helper that strips `refs/heads/` while preserving loose/packed object ids.

Pass 460 adds typed `core.logAllRefUpdates` config helpers through `Write_Core_Log_All_Ref_Updates`, `Read_Core_Log_All_Ref_Updates`, and `Delete_Core_Log_All_Ref_Updates`.

Pass 459 adds typed `core.filemode` config helpers through `Write_Core_Filemode`, `Read_Core_Filemode`, and `Delete_Core_Filemode`.

Pass 458 adds typed `core.bare` config helpers through `Write_Core_Bare`, `Read_Core_Bare`, and `Delete_Core_Bare`.

Pass 457 adds bounded data-only `credential.username` helpers through `Write_Credential_Username`, `Read_Credential_Username`, and `Delete_Credential_Username`.

Pass 456 adds ordered multi-value `credential.helper` helpers through `Append_Credential_Helper` and `Read_Credential_Helpers`.

Pass 455 adds bounded data-only `credential.helper` config helpers: `Write_Credential_Helper`, `Read_Credential_Helper`, and `Delete_Credential_Helper`.

Pass 454 makes `Commit_Index_To_Branch` parent-aware: an existing target branch becomes the new commit's parent, while a missing branch still creates a parentless first commit.

Pass 453 adds `Commit_Index_To_Branch`, a bounded root-level index commit helper that stores a tree and commit from the current index and updates a branch ref.

Pass 452 adds `Stage_Worktree_File`, a bounded one-file staging helper that stores a validated worktree file as a loose blob and writes a one-entry index for it.

Pass 451 adds `Summarize_Index_Worktree`, a bounded index/worktree status summary helper that counts missing, unchanged, and modified staged paths.

Pass 450 adds `Compare_Index_Path_To_Worktree`, a bounded single-path status helper that reports missing, unchanged, or modified worktree state relative to the staged blob.

Pass 449 updates the capability documentation now that SSH_Lib has bounded index/worktree primitives instead of no index/worktree surface.

Pass 448 adds `Checkout_Index_All`, a bounded helper that materializes every staged blob in `.git/index` and reports the number of paths written.

Pass 447 adds `Checkout_Index_Path`, a bounded staged-blob materialization helper that reads a staged index path and writes the referenced loose blob to the worktree.

Pass 446 adds `Delete_Worktree_File`, a validated repository-relative worktree delete helper that reports whether a file was actually removed.

Pass 445 adds `Worktree_File_Exists`, a validated repository-relative worktree file probe that reports missing files through `Found => False`.

Pass 444 adds `Read_Worktree_File`, a bounded helper that reads a validated repository-relative worktree path into a caller buffer.

Pass 443 adds `Write_Worktree_File`, a bounded helper that writes caller-provided bytes to a validated repository-relative worktree path and creates parent directories.

Pass 442 adds `Valid_Worktree_Path`, a public repository-relative path validator for index/worktree helpers that rejects absolute paths, control bytes, empty/current/parent components, repeated slashes, and trailing slashes.

Pass 441 adds `List_Index_Paths`, a bounded staged-path enumeration helper that returns concatenated index paths with per-path end offsets.

Pass 440 adds `Read_Index_Path_Object`, a staged-path object read helper that validates `.git/index`, resolves a staged path, and reads the referenced loose object.

Pass 439 adds `Find_Index_Entry`, a repository-level staged-path lookup helper that validates `.git/index`, scans entries, and reports missing paths through `Found => False`.

Pass 438 adds `Read_Index_Entry`, a repository-level helper that validates `.git/index` and reads one staged entry by zero-based entry index.

Pass 437 adds `Parse_Index_Entry`, a bounded parser for Git index entries that reports mode, path, raw object id, file size, and the next padded entry offset.

Pass 436 adds `Write_Index`, a bounded writer for checksum-protected DIRC v2 index files from caller-built entry bytes and an explicit entry count.

Pass 435 adds `Build_Index_Entry`, a bounded Git index v2 entry builder for canonical file modes, raw SHA-1 object ids, file sizes, worktree-relative paths, and 8-byte entry padding.

Pass 434 adds empty Git index helpers: `Write_Empty_Index` writes a checksum-protected DIRC v2 empty index, and `Read_Index_Header` reads and validates bounded index headers and entry counts.

Pass 433 adds `Build_Tag_Object`, a bounded annotated-tag construction helper for target id/type, tag name, tagger metadata, and message bytes.

Pass 432 adds `Build_Commit_Object`, a bounded commit object construction helper for tree id, optional parent id, author/committer metadata, and message bytes.

Pass 431 adds `Build_Tree_Entry`, a bounded tree-entry construction helper for serializing Git tree mode/name/raw-object-id entries before storing tree objects.

Pass 430 adds `Delete_Remote_URL` and `Delete_Branch_Upstream`, bounded deletion helpers for remote URL and branch upstream config entries.

Pass 429 adds `Delete_Remote_Fetch_Refspecs` and `Delete_Remote_Push_Refspecs`, bounded remote-specific helpers that clear repeated fetch/push refspec config entries.

Pass 428 adds `Delete_Config_Value`, a bounded config rewrite helper that removes all matching keys from a section while preserving unrelated config content.

Pass 427 adds remote-specific multi-refspec readers: `Read_Remote_Fetch_Refspecs` and `Read_Remote_Push_Refspecs` expose repeated fetch/push mappings without requiring callers to address raw config keys.

Pass 426 adds bounded multi-value config reads through `Read_Config_Values`, packing repeated matching values into a caller buffer with per-value end offsets.

Pass 425 adds append-only Git config helpers: `Append_Config_Value`, `Append_Remote_Fetch_Refspec`, and `Append_Remote_Push_Refspec` preserve existing entries while adding repeated remote refspec keys.

Pass 424 adds bounded remote push-refspec config helpers: `Write_Remote_Push_Refspec`, `Read_Remote_Push_Refspec`, and `Valid_Push_Refspec` cover force, delete, direct, and paired-wildcard `remote <name>.push` entries.

Pass 423 adds bounded remote fetch-refspec config helpers: `Write_Remote_Fetch_Refspec`, `Read_Remote_Fetch_Refspec`, and `Valid_Fetch_Refspec` cover simple and wildcard `remote <name>.fetch` entries.

Pass 422 adds branch upstream config helpers: `Write_Branch_Upstream` and `Read_Branch_Upstream` manage bounded `branch <name>.remote` and `branch <name>.merge` config entries.

Pass 421 adds remote URL config helpers: `Write_Remote_URL` and `Read_Remote_URL` map remote names to bounded `remote <name>.url` config entries.

Pass 420 adds bounded repository config writes through `Write_Config_Value`, updating an existing section key or appending a missing section/key while preserving unrelated config text.

Pass 419 adds bounded repository config reads through `Read_Config_Value` and initializes new repository state with a minimal `.git/config`.

Pass 418 adds `Read_Reflog_Last_Entry`, a bounded reflog read helper that returns the last `.git/logs/<ref>` entry line without the trailing newline.

Pass 417 adds `Append_Reflog_Entry`, a bounded low-level reflog append helper for `.git/logs/<ref>` files with validated old/new object ids and caller-supplied actor/message text.

Pass 416 adds lightweight tag-ref convenience helpers: `Write_Tag_Ref`, `Read_Tag_Ref`, `Delete_Tag_Ref`, and `Tag_Ref_Exists` manage `refs/tags/<tag>` above the raw direct-ref API.

Pass 415 adds branch convenience helpers: `Write_Branch`, `Read_Branch`, `Delete_Branch`, and `Branch_Exists` manage `refs/heads/<branch>` above the raw direct-ref API.

Pass 414 adds HEAD convenience helpers: `Attach_HEAD`, `Detach_HEAD`, and `Resolve_HEAD` wrap the existing symbolic, direct, and resolved ref primitives for common HEAD workflows.

Pass 413 adds `Read_Any_Stored_Object_Resolved_Validated`, combining loose/listed-pack lookup, bounded delta-chain resolution, and final object payload validation.

Pass 412 adds `Read_Stored_Object_Resolved_Validated`, combining loose-first storage lookup, caller-selected pack delta resolution, and final object payload validation.

Pass 411 adds `Read_Packed_Object_Resolved_Validated`, combining stored-pack delta-chain resolution with final object payload validation.

Pass 410 adds `Read_Any_Stored_Object_Resolved`, scanning stored pack indexes and resolving bounded pack delta chains without requiring callers to preselect the pack checksum.

Pass 409 adds `Read_Stored_Object_Resolved`, a loose-first stored-object read helper that falls back to `Read_Packed_Object_Resolved` for caller-selected stored packs.

Pass 408 adds `Read_Packed_Object_Resolved`, a stored-pack repository read helper that resolves bounded OFS/REF delta chains into final commit/tree/blob/tag payload bytes and rechecks the requested object id.

Pass 407 adds `Delete_Stored_Pack`, a paired stored-pack cleanup helper that validates a pack checksum, deletes the corresponding `.pack` and `.idx` files when present, and reports which files were removed.

Pass 406 adds `Delete_Pack_Index`, removing a checksum-validated stored pack index from `.git/objects/pack` while keeping packfile deletion explicit.

Pass 405 adds `Delete_Pack_File`, removing a checksum-validated stored packfile from `.git/objects/pack` while leaving pack-index management explicit.

Pass 404 adds `Delete_Loose_Object`, removing a validated loose object file from the managed `.git/objects` tree while preserving the pack/object read fallback model.

Pass 403 adds `Ref_Exists`, a bounded ref probe that resolves direct, symbolic, or packed refs when present and returns `Found => False` for missing refs without treating absence as an error.

Pass 402 adds `Delete_Direct_Ref_Atomic` and `Compare_And_Delete_Direct_Ref`, extending locked direct-ref operations to atomic deletion and expected-object guarded deletion.

Pass 401 adds `List_Stored_Object_IDs`, combining loose object-id enumeration with stored pack-index object-id enumeration into one bounded repository inventory helper.

Pass 400 adds `Delete_Symbolic_Ref`, validating and returning a symbolic ref target before deleting the loose symbolic-ref file.

Pass 399 adds `Delete_Packed_Ref`, removing one packed-ref entry while preserving unrelated entries and comments.

Pass 398 adds `Delete_Direct_Ref`, allowing callers to remove a loose direct ref after the same repository and ref-name validation used by direct ref read/write helpers.

Pass 397 adds `Stored_Object_Exists`, a bounded repository probe that checks loose objects first and then scans stored pack indexes without reading object payloads.

Pass 396 adds `List_Packed_Object_IDs`, a repository-level stored pack object-id enumeration helper that reads a checksum-validated `.idx` and returns bounded hex object ids.

Pass 395 adds `List_Pack_Index_Object_IDs`, a bounded pack-index object-id enumeration helper that returns sorted 40-byte hex ids from validated index data.

Pass 394 adds `List_Loose_Object_IDs`, a bounded loose-object database enumeration helper for object ids stored under `.git/objects`.

Pass 385 adds `Resolve_Path_Entry_Hex`, resolving a slash-separated tree path to the final entry mode and hex object id without reading the target object. Pass 384 adds `Read_Ref_Commitish_Tree_Entries_Hex`, resolving a ref to a commit or annotated tag, peeling tags when needed, and listing the root tree entries. Pass 383 adds `Read_Commit_Tree_Entries_Hex`, listing a commit's root tree entries while returning the commit, root tree id, and tree bytes. Pass 382 adds `List_Tree_Entries_Hex` and `Read_Tree_Entries_Hex`, giving callers bounded directory-style tree entry listing with modes, concatenated names, and hex object ids. Pass 381 adds `Read_Ref_Commitish_Tree_Object`, resolving a ref to a commit or annotated tag, peeling tags when needed, and returning the commit root tree and entry count. Pass 380 adds `Read_Commit_Tree_Object`, reading and validating a commit's root tree object and returning its entry count without requiring a path component. Pass 379 adds `Read_Ref_Commitish_Path_Object`, resolving a ref to either a commit or annotated tag, peeling tags when needed, then performing commit-root path traversal. Pass 378 adds `Read_Tag_Path_Object`, peeling bounded annotated tag chains to a commit before performing commit-root path traversal. Pass 377 adds `Read_Ref_Path_Object`, resolving a ref to a commit id before performing bounded commit-root path traversal. Pass 376 adds `Read_Commit_Path_Object`, a bounded commit-root path traversal helper that reads/validates a commit, extracts its root tree id, resolves a slash-separated path, and reads/validates the final object. Pass 375 adds `Read_Path_Object`, a bounded slash-separated tree path traversal helper that resolves components from a root tree id and reads/validates the final object. Pass 374 adds `Read_Tree_Entry_Object`, a bounded one-step tree traversal helper that reads a tree by object id, resolves an exact entry name, and reads/validates the referenced object. Pass 373 adds `Store_Loose_Object_Validated`, validating object payloads before writing loose objects. Pass 372 adds `Read_Loose_Object_Validated`, validating loose object payloads before returning success. Pass 371 adds `Read_Packed_Object_Validated`, validating inflated packed object payloads before returning success. Pass 370 adds `Read_Stored_Object_Validated`, validating loose or caller-specified packed object payloads before returning success. Pass 369 adds `Read_Any_Stored_Object_Validated`, combining loose/listed-pack object lookup with generic non-delta payload validation before returning data. Pass 368 adds `Validate_Object_Data`, a generic blob/tree/commit/tag payload validator that dispatches to the bounded object parsers and rejects packed delta kinds. Pass 367 adds `Parse_Tag_Message_Offset`, locating annotated-tag message bodies after validated tag headers. Pass 366 adds `Parse_Commit_Message_Offset`, locating the commit message body after validated metadata headers. Pass 365 adds `Parse_Commit_Committer_Line`, extracting the commit committer metadata line after validated tree, parent, and author headers. Pass 364 adds `Parse_Commit_Author_Line`, extracting the commit author metadata line after validated tree/parent headers. Pass 363 adds `Parse_Tag_Name`, extracting the required annotated-tag name header into a caller buffer. Pass 362 adds `Parse_Commit_Parent_ID`, a bounded 1-based parent-id extractor for commit objects. Pass 361 adds `Find_Tree_Entry_Hex`, returning exact tree-entry matches as 40-byte Git hex object ids for direct use with repository object-read helpers. Pass 360 adds `Find_Tree_Entry`, a bounded exact-name lookup helper over Git tree objects that returns the entry mode and raw object id. Pass 359 adds bounded annotated-tag object parsing through `Parse_Tag_Target` and `Validate_Tag_Object`, extracting the tagged object id and kind while validating required tag headers through the message separator. Pass 358 adds bounded commit-object metadata parsing through `Parse_Commit_Tree_ID` and `Validate_Commit_Object`, extracting the root tree id and validating/counting parent headers before author/committer metadata. Pass 357 adds bounded tree-object parsing through `Parse_Tree_Entry` and `Validate_Tree_Object`, covering canonical Git tree modes, path bytes, raw object ids, and entry counts. Pass 356 adds `Read_Any_Stored_Object`, which tries loose storage first and then scans listed pack indexes to find a non-delta object without requiring the caller to know the pack checksum upfront. Pass 355 adds `List_Pack_Index_Checksums`, a bounded repository helper that lists stored `pack-<checksum>.idx` names as fixed 40-byte checksum records. Pass 354 adds `Read_Stored_Object`, a loose-first object read helper that falls back to a caller-specified stored pack/index pair. Pass 353 adds `Read_Packed_Object`, a repository-level helper that reads a stored pack/index pair, locates an object by hex id, inflates non-delta objects, and rechecks the object id before returning bytes. Pass 352 adds `Store_Pack_Index` and `Read_Pack_Index`, storing and reading checksum-validated `pack-<checksum>.idx` files beside stored packfiles. Pass 351 adds `SSH_Lib.Git.Build_Pack_Index`, generating bounded v2 `.idx` data for validated non-delta packfiles and empty packs while preserving trailer/index checksum validation. Pass 350 adds packfile storage helpers: `Store_Pack_File` validates the PACK trailer checksum, stores `pack-<checksum>.pack` under `.git/objects/pack`, and `Read_Pack_File` reads it back by checksum. Pass 349 adds atomic direct-ref update helpers: `Write_Direct_Ref_Atomic` writes through `<ref>.lock` and rename, while `Compare_And_Swap_Direct_Ref` locks, verifies the current resolved object id, and updates only on match. Pass 348 adds `SSH_Lib.Git.Resolve_Ref`, resolving loose direct refs, symbolic refs, and packed refs into a 40-byte object id with bounded symbolic-depth protection. Pass 347 adds bounded packed-refs helpers to the managed Git repository-state layer: `Write_Packed_Ref` and `Read_Packed_Ref` manage direct entries in `.git/packed-refs` while preserving unrelated refs and comments. Pass 346 adds bounded symbolic-ref file helpers to the managed Git repository-state layer: `Write_Symbolic_Ref` and `Read_Symbolic_Ref` can manage `ref: ...` files such as `HEAD` under a caller-supplied `.git` tree. Pass 345 adds a first managed Git repository-state layer: `Initialize_Repository_State`, Git-compatible loose object store/read helpers, and direct ref write/read helpers for caller-supplied repository roots. Pass 344 adds `Has_Error_Line` to `SSH_Lib.Git.Protocol_V2_Response_Summary`, allowing callers to detect bounded protocol-v2 `ERR ...` response lines without reparsing payload text. Pass 343 adds `Has_Delimiter` to `SSH_Lib.Git.Protocol_V2_Response_Summary`, matching the existing delimiter count with a direct boolean for multi-section protocol-v2 responses. Pass 342 extends `SSH_Lib.Git.Validate_Protocol_V2_Command_Request` summaries with request-argument flags for `symrefs`, `peel`, `ref-prefix`, `want`, `have`, `done`, and `filter`. Pass 341 extends `SSH_Lib.Git.Validate_Protocol_V2_Command_Request` summaries with request-capability flags for `server-option`, `object-format`, `agent`, and `session-id`. Pass 340 extends `SSH_Lib.Git.Validate_Protocol_V2_Command_Request` summaries with command flags for `ls-refs`, `fetch`, `server-option`, and `object-info`. Pass 339 adds `SSH_Lib.Git.Validate_Protocol_V2_Capability_Advertisement`, a bounded parser for Git protocol-v2 server capability advertisements that counts capabilities and flags `ls-refs`, `fetch`, `server-option`, `object-format`, `agent`, `session-id`, and terminal flush. Pass 338 adds `SSH_Lib.Git.Validate_Upload_Pack_ACK_Stream`, a bounded ACK/NAK negotiation reply stream validator that reports NAK, plain ACK, continue, common, ready, and terminal flush counts. Pass 337 adds `SSH_Lib.Git.Validate_Side_Band_Stream`, a bounded side-band stream validator that reports data/progress/error frame counts, terminal flush presence, and PACK header object counts inside data frames. Pass 336 adds `SSH_Lib.Git.Pkt_Line_Cursor`, `Reset_Pkt_Line_Cursor`, `Next_Pkt_Line`, and `Pkt_Line_Cursor_Done`, giving callers a bounded public iterator over pkt-line streams with packet/payload spans and data/flush/delimiter/response-end counters. Pass 335 adds structured ref advertisement parsing through `SSH_Lib.Git.Parse_Ref_Advertisement_Packet` and `Validate_Ref_Advertisement_Stream`, covering v0/v1 advertised refs, first-line capabilities, peeled refs, symrefs, and protocol-v2 `ls-refs` response streams. Pass 334 adds bounded Git service orchestration in `SSH_Lib.Git_Transport`: callers can open an upload-pack or receive-pack exec channel, write a caller-built request, send EOF, drain a bounded response buffer, validate the response shape, attempt remote exit-status observation, and close the channel. Pass 333 completes the bounded smart-protocol workflow surface with upload-pack response validation, receive-pack report aggregation, and protocol-v2 response validation. Pass 332 adds bounded smart-protocol request orchestration helpers: callers can compose complete upload-pack fetch request streams, encode and validate receive-pack update/pack request streams, and build/validate protocol-v2 command requests such as `ls-refs` and `fetch` framing. Pass 331 adds bounded upload-pack negotiation helpers: callers can encode `want`, `have`, `done`, `deepen`, `shallow`, and `filter` pkt-lines, parse ACK/NAK negotiation replies, and validate a complete caller-composed negotiation request stream with capability flags and command counts. Pass 330 adds `SSH_Lib.Git.Find_Pack_Index_Object_Hex`, allowing callers with a 40-byte Git hex object name to look up the matching v2 pack-index object and offset without decoding the raw ID themselves. Pass 329 adds bounded raw/hex object-id conversion through `SSH_Lib.Git.Encode_Object_ID_Hex` and `Parse_Object_ID_Hex`, bridging raw 20-byte SHA-1 IDs and 40-byte Git hex object names. Pass 328 adds `SSH_Lib.Git.Compute_Object_ID`, a bounded public helper for computing raw Git SHA-1 object IDs for caller-supplied commit/tree/blob/tag bytes. Pass 327 adds bounded pack object-kind inventory through `SSH_Lib.Git.Inventory_Pack_Objects`, reporting commit/tree/blob/tag and OFS/REF delta counts after validating the caller-supplied pack sequence. Pass 326 adds a full pack/index integrity wrapper through `SSH_Lib.Git.Validate_Pack_Integrity`, combining pack trailer checksum, index trailer checksum, embedded pack checksum, offset/CRC consistency, and object-id consistency checks. Pass 325 adds a combined pack object-id consistency validator through `SSH_Lib.Git.Validate_Pack_Object_IDs`, checking non-delta objects plus bounded delta-chain resolutions through one public call. Pass 324 adds bounded delta-chain object-id validation through `SSH_Lib.Git.Validate_Pack_Delta_Chain_Object_IDs`, resolving REF/OFS delta chains up to the public chain limit and checking resolved object IDs against the v2 index. Pass 323 adds bounded immediate-delta object-id validation through `SSH_Lib.Git.Validate_Pack_Immediate_Delta_Object_IDs`, applying one-hop REF/OFS deltas whose base is a non-delta object and checking the resolved object ID against the v2 index. Pass 322 adds bounded non-delta pack object-id validation through `SSH_Lib.Git.Validate_Pack_Non_Delta_Object_IDs`, checking commit/tree/blob/tag index object IDs against Git object headers plus inflated pack bytes while leaving packed deltas to the existing delta-resolution helpers. Pass 321 adds bounded pack delta dependency-graph validation through `SSH_Lib.Git.Validate_Pack_Delta_Graph`, rejecting REF_DELTA cycles and chains beyond the public delta-chain limit. Pass 320 adds bounded pack delta-base validation through `SSH_Lib.Git.Validate_Pack_Delta_Bases`, checking REF_DELTA bases against the pack index and OFS_DELTA bases against earlier pack object starts. Pass 319 adds bounded pack-index CRC validation through `SSH_Lib.Git.Validate_Pack_Index_CRCs`, checking `.idx` CRC entries against caller-supplied pack object-entry byte spans. Pass 318 adds bounded pack-index offset validation through `SSH_Lib.Git.Validate_Pack_Index_Offsets`, checking that `.idx` offsets are unique and point at object starts in a caller-supplied pack.

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


- Phase 19 completeness pass 269 hardens hashed `known_hosts` failure semantics: when a hashed selector actually matches the target host, unsupported key types and malformed key material now fail closed even if a later ordinary trust line would otherwise match. Nonmatching hashed records remain non-applicable.

## Phase 19 completeness pass 268

- Hardened oversized `known_hosts` line handling. Lines that exceed the bounded parser length now fail closed with `Unsupported_Entry`, preventing hidden oversized marker/host/key material from being masked by a later valid trust record.

# SSH_Lib

SSH_Lib is an Ada 2022 SSH client library focused on the transport needs of `version`: authenticated encrypted sessions, remote exec channels for Git upload/receive commands, and binary-safe byte streams.

The library is intentionally narrow. It does not implement SSH server mode, SFTP server mode, or C bindings. The explicit subprocess boundaries are OpenSSH-style `ProxyCommand`, which is parsed as config data and used only by `Sessions.Open` as a caller-configured SSH transport, Git credential-helper execution through `Execute_Credential_Helper`, and caller-invoked `SSH_Lib.Git_Transport.Run_Service_With_Local_Git` / `Run_Service_With_Local_SSH` fallback helpers for one bounded upload-pack or receive-pack exchange. OpenSSH `ControlMaster`, `ControlPath`, `ControlPersist`, `LocalForward`, `RemoteForward`, `DynamicForward`, `SendEnv`, and `SetEnv` config directives are parsed into session options; `Sessions.Open` can reuse verified non-ask control masters through mux proxy mode and routes ask/autoask decisions through `Control_Master_Approval_Callback`, `SSH_Lib.Config_Apply` can start planned caller-owned control masters and applies configured local/dynamic/remote forwarding and channel environment requests through explicit caller-owned services/channels, and `SSH_Lib.Mux` exposes bounded control mux framing, version-4 hello exchange, typed new-session and forwarding payload helpers, ext-info/proxy opcodes, client/master Unix socket lifecycles with owned control-path unlinking on close, bounded Unix descriptor passing and OpenSSH-sequenced stdio fd helpers for passenger fds, validated backend-handoff request classification, hello-negotiating control-client processing, callback dispatch for passenger session/forward/proxy backends with validated backend responses, a bounded control-master serve loop, an owning single-client serve overload for mux proxy handoff, alive/terminate/stop-listening routing, alive pid, session-opened, remote-port, exit-message, TTY-failure, ext-info, proxy, and failure-reason responses, and deterministic persist-idle policy. `SSH_Lib.Security_Keys` exposes a direct security-key signer boundary for hardware-backed SK userauth requests without ssh-agent. `SSH_Lib.Channels.Open_Shell` opens non-PTY shell channels; `SSH_Lib.Channels.Open_PTY_Shell` opens a shell after an RFC 4254 `pty-req` using caller-provided terminal type, dimensions, and optional terminal modes, `SSH_Lib.Channels.Resize_PTY` sends `window-change` resize requests, `SSH_Lib.Channels.Set_Environment` exposes explicit RFC 4254 `env` requests for caller-ordered environment setup, `Open_Exec_With_Environment`, `Open_Subsystem_With_Environment`, `Open_Shell_With_Environment`, and `Open_PTY_Shell_With_Environment` open channels after accepted env requests, `SSH_Lib.Config_Apply.Open_Configured_Exec`, `Open_Configured_Subsystem`, and `Open_Configured_Shell` apply resolved config environment and `SessionType`/`RequestTTY` policy, `Request_X11_Forwarding` exposes explicit RFC 4254 `x11-req` setup, `Accept_X11` accepts server-opened X11 channels, and `Valid_X11_MIT_Magic_Cookie` / `X11_MIT_Magic_Cookies_Match` provide bounded MIT-MAGIC-COOKIE-1 policy helpers. Callers can use `Read_Some`, `Read_Stderr`, and `Write` for the byte streams. `SSH_Lib.Git` builds remote Git exec commands and exposes bounded pkt-line frame parsing/encoding and cursor iteration, local `.git` initialization, Git-compatible loose object store/read/delete/listing, validated packfile and pack-index store/read/delete/generation/listing, bounded DIRC index read/write/entry/path helpers, validated repository-relative worktree file read/write/delete/probe helpers, staged-path object reads, and bounded staged-blob checkout helpers, recursive repository tree traversal from root trees, commits, refs, HEAD, branch names, and tag names with pathspec filtering, non-delta, resolved-delta, and validated resolved-delta packed-object reads, loose-first resolved, validated resolved, or non-delta object reads with caller-specified or listed-pack fallback, direct, symbolic, packed, and atomic direct ref write/read/delete plus bounded ref resolution, HEAD attach/detach/resolve convenience, branch and lightweight tag-ref write/read/delete/existence convenience, reflog append/read-last helpers, bounded repository config single/multi reads, writes, appends, and key deletion, remote URL/fetch-refspec/push-refspec and branch upstream config helpers, credential-helper execution, console credential prompting, credential store read/write/delete, and existence probing, ref advertisement and protocol-v2 `ls-refs` response parsing, protocol-v2 capability advertisement validation, capability-token parsing and list scanning, upload-pack negotiation line encoding and request validation, upload-pack fetch request composition, receive-pack update/request validation, bounded fetch/push workflow state machines and policy decisions, bounded porcelain status and repository database summaries, protocol-v2 command request composition and validation, ACK/NAK negotiation reply parsing and stream validation, side-band demultiplexing and stream validation, receive-pack status-report line parsing, pack header/object-entry header, tree-entry, commit-object, and annotated-tag construction, tree-entry parsing, pack object-at-offset inflation with next-offset reporting, pack object-sequence validation, pack object-kind inventory, zlib object-data inflation with consumed-length reporting, repository-level bounded delta-chain resolution, caller-supplied delta and delta-chain application, complete v2 pack-index structural validation, bounded pack delta dependency-graph validation, pack/index SHA-1 checksum verification, pack-index object lookup, pack-index offset/pack, CRC/pack, and object-id/pack consistency validation for non-delta, immediate-delta, and bounded delta-chain entries, bounded pack delta-base validation, pack-index layout/header/fanout/object-name/order/fanout-consistency/CRC/offset/large-offset/count/checksum metadata, and delta-base metadata parsing, object-id validation, and ref-name/refspec validation/classification helpers without interpreting progress text. `SSH_Lib.Git_Transport` can prepare remote Git commands, run one bounded upload-pack or receive-pack service exchange over an authenticated session, or run the same bounded exchange through explicit local `git`/`ssh` subprocess fallback helpers. ProxyJump is implemented internally over SSH `direct-tcpip`; `SSH_Lib.Channels.Open_Direct_TCPIP` also exposes that channel primitive, and `SSH_Lib.Forwarding` provides synchronous local listener/accepted-connection lifecycles, a dynamic/SOCKS listener and one-connection SOCKS accept helper, callback-based local/dynamic background accept services with optional accepted-connection caps, managed local/dynamic worker-pool services with bounded worker and accepted-connection caps, managed remote-forward services with request, accept, target-connect, bounded pump, and cancel-on-exit lifecycle, X11 `DISPLAY` parsing and local X server connection helpers, SOCKS5 no-auth CONNECT parsing, bounded `Pump_Once` byte movement, and `Pump_Bounded` alternating pump policy for local, dynamic, remote, and X11 forwarding. `SSH_Lib.Sessions.Request_Remote_Forward` and `Cancel_Remote_Forward` remain available as RFC 4254 `tcpip-forward` request/cancel primitives, and `SSH_Lib.Channels.Accept_Forwarded_TCPIP` remains available for custom remote-forward policy. SCP upload is available through `SSH_Lib.SCP` for byte arrays and streamed local files, with high-level method selection in `SSH_Lib.File_Transfer`; SFTP has subsystem, v3-v6 negotiation, persistent clients, upload/download, recursive tree operations, directory listing, stat/lstat, permissions and richer v4+ attributes, mkdir/rmdir/remove/rename, symlink/readlink, resume, lock/text-seek, and modeled extension helpers.
For minimal index interoperability, `SSH_Lib.Git.Write_Empty_Index` writes a checksum-protected DIRC v2 empty index and `Read_Index_Header` reads and validates bounded index headers.
`Build_Index_Entry` builds canonical stage-zero index entries that callers can place into a managed index file.
`Write_Index` writes those caller-provided entries as a checksum-protected DIRC v2 `.git/index`.
`Parse_Index_Entry` reads individual index entries while rejecting malformed flags, truncation, missing NUL terminators, and non-zero padding.
`Read_Index_Entry` validates the on-disk index checksum/header before returning one requested staged entry.
`Find_Index_Entry` resolves a staged path directly from `.git/index` without requiring callers to scan entries manually.
`Read_Index_Path_Object` bridges staged index lookup to the local object store for loose-object reads.
`List_Index_Paths` enumerates staged paths from `.git/index` using the same packed-buffer pattern as the repository ref/tree list helpers.
`List_Tree_Paths_Hex`, `List_Commit_Tree_Paths_Hex`, `List_Ref_Commitish_Tree_Paths_Hex`, `List_HEAD_Tree_Paths_Hex`, `List_Branch_Tree_Paths_Hex`, and `List_Tag_Tree_Paths_Hex` provide bounded recursive repository tree traversal over root trees, commits, refs/commitishes, HEAD, branch names, and tag names. `List_Tree_Paths_Matching_Hex`, `List_Commit_Tree_Paths_Matching_Hex`, `List_Ref_Commitish_Tree_Paths_Matching_Hex`, `List_HEAD_Tree_Paths_Matching_Hex`, `List_Branch_Tree_Paths_Matching_Hex`, and `List_Tag_Tree_Paths_Matching_Hex` apply the public pathspec matcher to those traversal results.
`Valid_Worktree_Path` exposes the bounded relative-path policy used by index/worktree helpers.
`Pathspec_Matches` matches validated worktree paths against bounded exact, directory-prefix, all-path, and single-wildcard pathspecs for caller-owned porcelain filtering.
`Write_Worktree_File` provides the first bounded worktree materialization primitive for blob bytes.
`Read_Worktree_File` reads validated worktree files without exposing path traversal or unbounded allocation.
`Worktree_File_Exists` lets callers probe worktree paths without treating absence as an error.
`Delete_Worktree_File` removes validated worktree files idempotently and reports removal separately from absence.
`Checkout_Index_Path` checks out one staged blob path from `.git/index` into the worktree.
`Checkout_Index_All` checks out all staged blob paths from the current index.
`Compare_Index_Path_To_Worktree` gives callers a bounded status primitive for one staged blob path.
`Summarize_Index_Worktree` aggregates those single-path comparisons across the current index.
`Classify_Worktree_Path` and `Summarize_Worktree_Paths` extend that to caller-supplied porcelain-style path sets, including absent and untracked paths.
`List_Worktree_Files` recursively lists bounded worktree files outside `.git`, and `Summarize_Worktree_Status` combines that inventory with index/worktree comparison to count untracked, missing, unchanged, and modified paths.
`Summarize_Worktree_Status_Matching` applies the same tracked/untracked status counts to paths matching a bounded pathspec.
`Worktree_Path_Ignored` and `Summarize_Worktree_Status_With_Ignored` add bounded ignored-file handling for `.gitignore`, `.git/info/exclude`, and configured excludes files.
`Read_Porcelain_Index_Worktree_Model` returns a bounded combined index/worktree/HEAD/status model with staged path count, worktree file count, current branch presence, HEAD attachment/resolution flags, and `Evaluate_Porcelain_Status` counts.
`Summarize_Repository_Database` returns bounded ref/object inventory counts, branch/tag/remote-tracking counts, pack-index count, HEAD attachment/resolution flags, and missing ref-target detection.
`Detect_Worktree_Rename` reports the first exact content-based rename candidate between a missing tracked path and an untracked, non-ignored worktree file.
`Detect_Worktree_Copy` reports the first exact content-based copy candidate between a tracked path still present in the worktree and an untracked, non-ignored file.
`Clean_Worktree_Not_In_Index` removes ordinary worktree files that are neither indexed nor ignored, giving callers an explicit cleanup primitive for hard-reset/checkout-style flows.
`Stage_Worktree_File` provides a conservative add-style upsert for one validated worktree file while preserving unrelated index entries.
`Remove_Index_Path` removes one staged path while preserving unrelated index entries.
`Reset_Index_To_Commit_Root` rebuilds the index from a commit root tree, including bounded nested blob paths, and `Checkout_Branch` resolves a branch, resets the index to its commit root tree, attaches HEAD, and checks out staged blobs.
`Is_Ancestor_First_Parent` checks bounded first-parent ancestry, and `Fast_Forward_Branch` updates a branch only when the current branch tip is an ancestor of the requested commit.
`Apply_Fetch_Ref_Update` applies fetched commits to remote-tracking refs with create, no-op, fast-forward, rejected non-fast-forward, and caller-forced update policy.
`Apply_Push_Branch_Update` applies push-style branch updates with expected-old verification, no-op handling, fast-forward enforcement, and optional forced non-fast-forward updates.
`Fetch_Workflow` and `Push_Workflow` expose bounded request/response/report/ref-application state machines for caller-owned fetch and push orchestration.
`Commit_Index_To_Branch` provides a conservative commit primitive for root-level staged files.
When the target branch already exists, `Commit_Index_To_Branch` now records that branch tip as the parent commit.
`Build_Merge_Conflict_File` constructs caller-buffered conflict-marker file content for merge workflows while leaving merge-base selection, conflict detection, and resolution policy to callers.
`Classify_Three_Way_Blob_Merge` classifies base/ours/theirs blob object ids as unchanged, use-ours, use-theirs, or conflict.
`Build_Sequencer_Pick_Line` builds line-safe `pick <commit> <subject>` todo records for caller-managed rebase/cherry-pick sequencing.
Credential config helpers manage line-safe `credential.helper` values, including ordered repeated helper entries, and line-safe `credential.username` values without executing helper commands or storing secret material.
`Build_Credential_Helper_Request` and `Parse_Credential_Helper_Response` expose the line-oriented Git credential helper request/response format for caller-managed helper execution boundaries.
`Build_Credential_Password_Prompt` builds deterministic prompt text for caller-owned credential UI/callback flows without reading from a terminal or storing the resulting secret.
`Execute_Credential_Helper` runs one explicit helper command with a bounded request, timeout, and parsed response.
`Prompt_Credential_Password` performs explicit console password prompting using the deterministic prompt text; it is never automatic.
`Write_Credential_Store`, `Read_Credential_Store`, and `Delete_Credential_Store` manage bounded line-oriented `.git/credentials` records.
`Clear_Credential_Data` zeroes caller-owned credential buffers after use.



### Phase 19 completeness pass 267

Known-hosts hashed selector handling now distinguishes a hashed selector that merely parses from one that actually matches the target host. Negated hashed selectors (`!|1|salt|hash`) act as OpenSSH-style line-local vetoes, and nonmatching hashed unsupported/malformed records no longer block later valid trust records.

### Phase 19 completeness pass 253

OpenSSH UMAC MAC coverage is now implemented and advertised.  The MAC name-list includes `umac-128-etm@openssh.com`, `umac-64-etm@openssh.com`, `umac-128@openssh.com`, and `umac-64@openssh.com`; protected packet encode/decode supports the 64-bit and 128-bit tag sizes and the EtM variants.


## Phase 19 completeness pass 92

Session-open preflight now recognizes those bounded default identity candidates before failing for missing authentication configuration. Live userauth performs bounded default identity-file discovery when no explicit `Identity_File` is configured. After `none`, explicit identity-file, and ssh-agent handling fail to authenticate, the live path can try `$HOME/.ssh/id_ed25519` and `$HOME/.ssh/id_rsa` through the same publickey preflight, signing, protected request, and protected reply parser used for configured identity files. The discovery is data-only: no globbing, shell expansion, subprocess invocation, or persistent private-key storage is added.

## Phase 17 status

Implemented:

- authenticated encrypted `Sessions.Open`
- strict known_hosts verification
- ssh-agent and identity-file authentication
- exec channels and binary stream I/O
- safe Git command helpers and remote-name parsing
- basic SSH config resolution
- timeout/failure hygiene
- Ada-only local fixture integration tests
- API stability checks
- release/package hygiene checks
- examples and Version integration documentation

Still not implemented or intentionally out of scope:

- TOFU remains disabled by default; explicit known_hosts append/accept workflow is available through `SSH_Lib.Known_Hosts.Append_Trusted_Host`, and `Trust_On_First_Use` can be enabled deliberately for first-use writes
- SSH server mode and SFTP server/subsystem mode
- C bindings
- full OpenSSH config semantics beyond the implemented control-master, forwarding, environment, session-type, command, and trust helpers
- optional algorithm coverage is now broad; remaining gaps are live interoperability/build validation, not intentionally unadvertised core algorithm families; coverage is still not OpenSSH-complete and weak legacy families remain rejected
- live interoperability proof and full GNAT build proof in this environment

The default test suite is local, deterministic, and does not use the user’s real SSH state.

Remote forwarding now has both low-level request/cancel/channel-accept primitives and a managed remote-forward service. `Start_Managed_Remote_Forward_Service` requests `tcpip-forward`, accepts `forwarded-tcpip` channels, connects each accepted channel to the configured target, runs the bounded pump, and cancels the remote forward when the worker exits. `SSH_Lib.Config_Apply.Start_Configured_Remote_Forwards` starts those managed services from resolved `RemoteForward` config data; `Request_Configured_Remote_Forwards` remains available for callers that need custom accept policy.

### Phase 19 completeness pass 177

Pass 177 adds an explicit known_hosts trust-write helper: `SSH_Lib.Known_Hosts.Append_Trusted_Host`. This closes the usability gap for callers that want an opt-in “accept this verified host key” workflow while preserving strict-by-default behavior. `Sessions.Open` still never writes known_hosts automatically, unknown hosts still return `Host_Key_Unknown`, changed keys return `Host_Key_Mismatch`, and CA records remain distinct from raw host-key trust. The helper validates host text, port, key material, existing trusted/mismatching records, and appends only ordinary known_hosts key lines selected by the caller.

## Public packages

- `SSH_Lib.Errors`
- `SSH_Lib.Clients`
- `SSH_Lib.Sessions`
- `SSH_Lib.Channels`
- `SSH_Lib.Known_Hosts`
- `SSH_Lib.Keys`
- `SSH_Lib.Config`
- `SSH_Lib.Git`
- `SSH_Lib.SCP`
- `SSH_Lib.File_Transfer`
- `SSH_Lib.SFTP`
- `SSH_Lib.Remote_Names`

`SSH_Lib.Errors.Ok` is the only success status. Ordinary failures are reported with deterministic status values. `SSH_Lib.Channels.Open_Subsystem` supports SSH subsystem channels such as `sftp`; `SSH_Lib.SFTP` provides the SFTP v3 init/version handshake, upload, download, directory listing, stat/lstat, permissions, mkdir/rmdir/remove/rename, and symlink/readlink helpers. `SSH_Lib.File_Transfer` exposes facade-level filename, remote-path, and upload chunk-size limits for callers that want to preflight uploads, plus first-class exact-path workflows named `Upload`, `Verify`, `Delete`, `Restore`, and `Inventory` returning typed workflow/inventory results. Inventory manifests can be serialized, parsed, verified against a current remote tree, and restored with explicit overwrite/skip/fail conflict policy.

## Secure defaults

`Session_Options` defaults keep host-key verification enabled:

- `Port = 22`
- `Connect_Timeout_MS = 30_000`
- `Read_Timeout_MS = 30_000`
- `Write_Timeout_MS = 30_000`
- `Verify_Known_Host = True`
- `Trust_On_First_Use = False`
- `Use_Agent = True`
- `Strict_Host_Key = True`

Unknown host keys return `Host_Key_Unknown` by default. Changed host keys return `Host_Key_Mismatch`. `Trust_On_First_Use = True` appends a newly presented unknown host key to the caller-selected user known_hosts file during session open; mismatches, revoked keys, invalid records, and unsupported records still fail closed. `Verify_Known_Host = False` is an explicit unsafe bypass.

## Binary stream contract

Channel reads and writes use `Ada.Streams.Stream_Element_Array`. The library preserves raw bytes, including NUL, LF, CR, DEL, `0x80`, `0xFF`, pkt-line bytes, and packfile bytes. There is no UTF-8 validation, text conversion, or line-ending normalization on channel data.

## Git command helpers

`SSH_Lib.Git.Upload_Pack_Command` and `SSH_Lib.Git.Receive_Pack_Command` construct remote exec command strings such as:

```text
git-upload-pack 'repo.git'
git-receive-pack 'repo.git'
```

Repository paths reject NUL, CR, LF, empty paths, and oversized paths. Single quotes are escaped safely. No local shell is invoked.

## Config support

`SSH_Lib.Config` supports the Git-over-SSH subset of OpenSSH-style config:

- `Host`
- `HostName`
- `User`
- `Port`
- `IdentityFile`
- `IdentitiesOnly`

`ProxyJump` is parsed and resolved as data. `Sessions.Open` implements ProxyJump by opening authenticated jump sessions and carrying the target SSH transport over an SSH `direct-tcpip` channel. `ProxyCommand` is parsed as data during config resolution and executed only by `Sessions.Open` as the explicit subprocess-backed SSH transport. `ProxyCommand none` disables that transport instead of executing `none`; the subprocess transport uses timeout-aware pipe I/O and fails closed when no `sh` executable is available.

## Release verification

Preferred Ada-native runner:

```sh
(cd tools && alr build)
../ssh_lib_build/bin/tools/run_release_validation
```

Dry-run command listing:

```sh
../ssh_lib_build/bin/tools/run_release_validation --dry-run
```

Legacy POSIX shell wrapper:

```sh
../ssh_lib_build/bin/tools/run_release_validation
```

Expanded command sequence:

```sh
alr build
cd tests && alr exec -- gprbuild -P tests.gpr
../ssh_lib_build/bin/tests/main
cd tests && alr exec -- gprbuild -P security/security_tests.gpr
../ssh_lib_build/bin/tests_security/test_host_key_negative
../ssh_lib_build/bin/tests_security/test_algorithm_negative
../ssh_lib_build/bin/tests_security/test_algorithm_security
../ssh_lib_build/bin/tests_security/test_auth_negative
../ssh_lib_build/bin/tests_security/test_auth_security
../ssh_lib_build/bin/tests_security/test_auth_malformed_inputs
../ssh_lib_build/bin/tests_security/test_packet_protection_negative
../ssh_lib_build/bin/tests_security/test_command_quoting_negative
../ssh_lib_build/bin/tests_security/test_binary_stream_negative
../ssh_lib_build/bin/tests_security/test_timeout_dirty_negative
../ssh_lib_build/bin/tests_security/test_resource_bounds
../ssh_lib_build/bin/tests_security/test_exception_mapping
../ssh_lib_build/bin/tests_security/test_config_security
../ssh_lib_build/bin/tests_security/test_phase19_matrix_coverage
../ssh_lib_build/bin/tests_security/test_phase19_invariant_coverage
../ssh_lib_build/bin/tests_security/test_status_mapping_matrix
alr exec -- gprbuild -P tests/api_stability/api_stability.gpr
alr exec -- gprbuild -P tests/package_smoke/package_smoke.gpr
alr exec -- gprbuild -P tests/version_integration/version_integration.gpr
alr exec -- gprbuild -P examples/examples.gpr
(cd tools && alr build)
../ssh_lib_build/bin/tools/check_public_api
../ssh_lib_build/bin/tools/check_package_tree
../ssh_lib_build/bin/tools/check_release
../ssh_lib_build/bin/tools/check_phase17_regressions
../ssh_lib_build/bin/tools/check_release_manifest
../ssh_lib_build/bin/tools/check_security
../ssh_lib_build/bin/tools/check_no_subprocess --self-test
../ssh_lib_build/bin/tools/check_no_subprocess
../ssh_lib_build/bin/tools/check_binary_paths
../ssh_lib_build/bin/tools/check_sensitive_logging --self-test
../ssh_lib_build/bin/tools/check_sensitive_logging
```

See `docs/TESTING.md` for the full release command sequence and suite organization.

## Version integration

The exact consumption sequence for `version` is documented in `docs/VERSION_INTEGRATION.md`. SSH_Lib remains a transport crate with bounded pkt-line frame/cursor, protocol-v2 capability advertisement, capability-token/list, ACK/NAK stream, side-band packet/stream, status-line, local repository-state helpers for refs/objects/packs/indexes, bounded repository tree traversal, bounded fetch/push workflow and policy helpers, and bounded worktree file/index checkout/status primitives, pack header/object-at-offset/object-sequence/object-kind inventory/zlib-object-data/caller-supplied-delta and delta-chain/index-layout/header/fanout/object-name/order/fanout-consistency/CRC/offset/large-offset/count/checksum metadata, complete v2 index structural validation, pack/index SHA-1 checksum verification, pack-index object lookup, pack-index offset/pack, CRC/pack, and object-id/pack consistency validation for non-delta, immediate-delta, and bounded delta-chain entries, pack delta-base and dependency-graph validation, object-id, and ref-name helpers. It does not maintain merge/conflict resolution.

## Phase 18 status

The crate now includes narrow `SSH_Lib.Git_Transport` preparation, session-backed single-service orchestration helpers, explicit local `git`/`ssh` subprocess fallback helpers, bounded fetch/push workflow state machines, version-shaped compile checks, deterministic no-network examples, and integration documentation for Git-over-SSH consumers. The dependency direction remains `version -> SSH_Lib`; session open does not invoke local Git/SSH fallback implicitly, while explicit ProxyCommand is supported as a subprocess-backed SSH transport.

### Phase 18 completeness pass 3

The version-integration adapter shape now includes fixture-backed upload-pack and receive-pack coverage in the deterministic tests, explicit remote user precedence over invalid default-user fallback, and compile-checked example channel sequencing.

### Phase 18 completeness pass 4

The version-integration coverage now includes fixture-backed status-mapping checks for host-key, authentication, channel-open, exec, read-timeout, and write-timeout failures.


### Phase 18 completeness pass 5

The Phase 18 version-integration helper, compile-shape test, and local fixture example are kept warning-clean under the crate's warning-as-error policy while preserving the strict boundary that SSH_Lib transports opaque bytes and version owns Git semantics.

Phase 18 completeness pass 6 originally rejected matching `ProxyCommand` config dependencies; ProxyCommand is now preserved as session transport data, and `ProxyJump` is resolved as data. Phase 19 pass 101 routes `ProxyJump` through SSH `direct-tcpip` forwarding instead of subprocess execution.

Phase 18 completeness pass 7 removes real user SSH config dependence from version-shape compile checks.

### Phase 18 manual probe safety

The real-server upload-pack probe is opt-in through `examples/manual_examples.gpr`; it is not part of default examples or tests. It requires caller-provided host, user, repository path, trusted `known_hosts`, and identity-file or ssh-agent authentication, and it keeps Git protocol bytes opaque.


Phase 18 completeness pass 9: direct Remote_Names + Config composition now has a text-aware `Resolve_Remote` overload and `Has_Explicit_Port` helper, preserving explicit `ssh://host:22/repo.git` overrides without changing `Parsed_Remote`.
- Phase 18 completeness pass 10: receive-pack fixture now asserts exact binary probe bytes, response length, and idempotent close coverage.
- Phase 18 completeness pass 11: parsed-record `Resolve_Remote` now reports `Invalid_User` for missing-user composition, and API stability keeps network-shaped calls behind a non-default branch.

- Phase 18 completeness pass 12: text-aware `Config.Resolve_Remote` now maps repository-path NUL/CR/LF control breaks to `Invalid_Command`, matching `Git_Transport.Prepare` for direct version-style composition.

- Phase 18 completeness pass 13: `examples/git_remote_resolve.adb` now uses the text-aware `Config.Resolve_Remote` overload so the default example matches version-style remote/config merge semantics, including explicit `ssh://host:22/...` port preservation.
- Phase 18 completeness pass 14: placeholder/package smoke tests now load an explicit empty temporary config instead of the real user SSH config, keeping default tests deterministic outside the isolated `Load_Default` coverage.

- Phase 18 completeness pass 15: the parsed-record `Config.Resolve_Remote` overload preserves matching `ProxyCommand` config dependencies as session data; later pass 72 preserves `ProxyJump` as session data, matching the text-aware resolver and `Git_Transport.Prepare`.


## Phase 19 status — security review and negative-path hardening

Implemented:

- authenticated encrypted `Sessions.Open`
- strict host-key verification and known_hosts trust
- ssh-agent and identity-file authentication
- exec channels and binary stream I/O
- safe Git command helpers and remote-name parsing
- basic SSH config resolution
- timeout/failure hygiene
- Ada-only fixture integration tests
- version integration examples/tests
- security review documentation
- negative-path security regression tests
- subprocess/logging/binary-path audit tools

Still not implemented or intentionally out of scope:

- TOFU remains disabled by default; explicit known_hosts append/accept workflow is available through `SSH_Lib.Known_Hosts.Append_Trusted_Host`, and `Trust_On_First_Use` can be enabled deliberately for first-use writes
- SSH server mode and SFTP server/subsystem mode
- C bindings
- full OpenSSH config semantics beyond the implemented control-master, forwarding, environment, session-type, command, and trust helpers
- optional algorithm coverage is now broad; remaining gaps are live interoperability/build validation, not intentionally unadvertised core algorithm families; coverage is still not OpenSSH-complete and weak legacy families remain rejected
- live interoperability proof and full GNAT build proof in this environment

Security summary:

- Host-key verification is enabled by default.
- Unknown hosts are rejected by default.
- Changed host keys are rejected by default.
- Sessions.Open never invokes local ssh/git fallback implicitly; local Git/SSH fallback is available only through explicit Git_Transport APIs.
- Git protocol bytes remain opaque binary data.

### Phase 19 completeness pass

The Phase 19 negative-path table now covers host-key trust failures, unsupported algorithm intersections, encrypted packet/MAC failures, authentication and identity-file failures, unsafe Git repository path rejection, remote/config parsing failures, binary byte-preservation cases, timeout/dirty-state cases, resource bounds, and public exception mapping. The logical security suites are documented in `tests/security/README.md` while remaining integrated into the default deterministic test runner.

## Phase 19 Completeness Pass 2

- Corrected the Phase 19 security matrix handling so explicit preservation cases remain `Ok` while hostile negative cases still require deterministic failure statuses.
- Added materialized `tests/security/*.adb` suite entry points for the required Phase 19 security areas.
- Extended the security guard tool to require the suite files and preservation-case classifier.

Additional Phase 19 split-runner support: `tests/security/security_tests.gpr` builds the materialized security suite entry points separately when desired.

### Phase 19 completeness pass 3

The Phase 19 security matrix now includes explicit host-key ordering, encrypted-before-userauth, packet/MAC failure, config-security, dirty-state reuse, command-length, and identity-count bound cases. The materialized `tests/security` suite includes a packet-protection entry point and covers every `SSH_Lib.Protocol.Negative_Tests` case.

### Phase 19 completeness pass 4

The Phase 19 security matrix now has explicit negative-case categories and a split `test_phase19_matrix_coverage.adb` runner. New cases cover silent host-key bypass auditing, weak/unsupported algorithm selection, sequence-number and packet-bound invariants, MAC-failure dirty-state behavior, encrypted-before-userauth ordering, wrong signature payloads, session identifier binding, subprocess fallback prohibition, config/remote precedence, no Git byte text conversion, stdout/stderr/EOF separation, timeout accounting, ambiguous partial write handling, failed-open cleanup, and additional resource bounds.

### Phase 19 completeness pass 5

The Phase 19 security-audit matrix is now checked at category, invariant, case, and deterministic-status levels. Split security tests and the `check_security` guard verify that new negative-path cases remain attached to a security invariant and to the expected public `Status` mapping.

### Phase 19 packet/MAC dirty-state fixture coverage

Phase 19 now includes an internal protected-packet fixture path that signs framed SSH packets with deterministic HMAC-SHA256 test keys. The tests exercise bad MAC, wrong sequence-number MAC, truncated protected packet, invalid padding after successful MAC verification, byte-preserving payload recovery, sequence increments, and deterministic dirty-state rejection after packet protection failure.

### Phase 19 completeness pass 7

Binary stream safety is now covered by a reusable fixture matrix. The matrix pushes the Phase 19 byte set through packet framing, protected packets, channel read/write, pending stdout, stderr separation, agent protocol messages, identity-file decoded fields, known-host/public-key blobs, and Git fixture payloads, then checks byte-for-byte preservation.


## Phase 19 completeness pass 8

Added concrete resource-bound oversized-input fixtures covering packet length, packet buffers, agent message and identity limits, identity-file size, config and known_hosts line bounds, pending stdout/stderr buffers, channel count limits, command length, and Git repository path length. `known_hosts` reading is now bounded so overlong records are ignored rather than trusted.

## Phase 19 completeness pass 9

The no-subprocess audit is now scope-aware instead of source-only. `tools/check_no_subprocess` scans library, examples, tests, and non-audit tools for subprocess APIs and local command literals, while intentionally excluding the audit tools that must mention forbidden tokens and the explicit ProxyCommand transport implementation. The guard distinguishes allowed SSH/Git protocol strings such as `git-upload-pack` and `ssh://` parsing from local process execution patterns.


## Phase 19 completeness pass 10

The split Phase 19 security suite is now part of the default release verification path rather than an optional maintainer-only build. Release verification builds `tests/security/security_tests.gpr`, runs every materialized security executable, and then runs the security, no-subprocess, binary-path, and sensitive-logging audit tools. `tools/check_release` and `tools/check_security` both assert that these release-path commands remain documented and discoverable.

## Phase 19 completeness pass 11

Adds fixture-backed exception-containment coverage for public API boundaries.  The integrated and split security tests now exercise `Sessions.Open`, `Sessions.Close`, `Channels.Open_Exec`, `Channels.Read_Some`, `Channels.Write`, `Channels.Send_EOF`, `Channels.Close`, `Channels.Exit_Status`, `Known_Hosts.Load`, `Known_Hosts.Verify`, `Config.Load`, `Config.Resolve`, `Identity_Files.Load`, `Remote_Names.Parse`, and the documented Git helper rejection boundary to ensure ordinary malformed local inputs and rejected channel states return deterministic status values rather than leaking exceptions.

## Phase 19 completeness pass 12

Adds fixture-backed SSH config security coverage. The new `test_config_security` split runner and integrated fixture prove that `ProxyCommand`, `ProxyJump`, shell-variable `IdentityFile`, and backtick-looking `IdentityFile` values are parsed as data only; config cannot disable host-key verification; ProxyCommand is preserved by remote resolution without execution; ProxyJump is preserved as data and routed by Sessions.Open through SSH direct-tcpip; and `HostName` cannot alter the parsed repository path.


### Phase 19 completeness pass 13

Adds fixture-backed authentication-order and signature-payload coverage. The new `test_auth_security` runner and integrated fixture prove that userauth cannot start before encrypted packet mode and host-key trust, partial success and banners do not authenticate the session, `USERAUTH_SUCCESS` cannot override failed setup preconditions, and agent/identity signatures must cover the exact binary payload using the first exchange hash as the session identifier.

- Phase 19 completeness pass 14 adds fixture-backed host-key verification ordering and trust checks: invalid signatures fail before known_hosts trust, unknown/changed hosts map to deterministic statuses, and authentication remains blocked until signature and trust both pass.

### Phase 19 completeness pass 15

Adds fixture-backed algorithm-negotiation security coverage. The split `test_algorithm_security` runner and integrated fixture prove that only implemented algorithms are advertised, client preference order is preserved, unsupported intersections return deterministic failures, selected algorithms must have been client-advertised, delayed `zlib@openssh.com` and stateful `zlib` compression negotiate only when both peers support them, legacy weak algorithms are rejected, inconsistent KEX replies fail, and failed negotiation clears partial state.

### Phase 19 completeness pass 16

Phase 19 completeness pass 16 adds fixture-backed timeout/dirty-state coverage.  `SSH_Lib.Tests.Fixtures.Timeout_Dirty` is run by the default test runner and the split `test_timeout_dirty_negative` executable.  It checks silent channel read timeouts, channel-open and exec-reply timeout cleanup, partial-write ambiguity, dirty-session/channel reuse rejection, failed `Open_Exec` closed-channel behavior, and idempotent close after dirty state.


### Phase 19 completeness pass 17

Git command quoting security is now covered by `SSH_Lib.Tests.Fixtures.Command_Quoting`. The fixture calls the production `SSH_Lib.Git` builders and verifies exact single-argument quoting, invalid repository-path rejection, production `Open_Exec` command validation acceptance, and byte-exact exec request encoding. Shell-looking repository paths such as `$()` and backticks are treated as data and are not executed locally.


### Phase 19 completeness pass 18

Adds fixture-backed malformed agent and identity-file authentication coverage. The new `test_auth_malformed_inputs` runner and integrated `Assert_Malformed_Agent_And_Identity_Fixtures` fixture prove that malformed identity lists, malformed signature responses, oversized agent responses, wrong signature algorithms, malformed OpenSSH keys, encrypted identity envelopes with missing/wrong passphrases or unsupported algorithms, unsupported private-key algorithms, public/private key mismatches, and malformed legacy PEM identities are rejected through deterministic status values while valid OpenSSH, PKCS#1 RSA PEM, PKCS#8 RSA/EC, and supported encrypted OpenSSH bcrypt AES/3DES, legacy AES/DES/3DES-CBC MD5, and PKCS#8 AES/3DES-CBC PBES2/PBKDF2 identity files are parsed for identity-file signing without exposing key material.


### Phase 19 completeness pass 19

Pass 19 adds deterministic Fuzz_Lite coverage through `SSH_Lib.Tests.Fixtures.Fuzz_Lite` and the mandatory split security executable `test_fuzz_lite`. The sweep targets malformed packet framing, SSH strings, known_hosts records, config records, agent protocol messages, and identity-file sections without random, unbounded, public-network, real-user-state, or subprocess behavior.

### Phase 19 completeness pass 20

Pass 20 strengthens the mandatory sensitive-logging audit. `check_sensitive_logging` now scans `src`, `examples`, `tests`, and non-audit `tools`, strips Ada comments outside string literals before matching, recognizes output/logging sinks, requires explicit redaction markers for secret-bearing diagnostics, and checks underscore/hyphenated sensitive-token forms such as `private_key`, `shared_secret`, `signature_payload`, `agent_signature`, and `identity_seed`. Deliberate policy/audit files are excluded so the guard can mention forbidden labels without weakening the scan of production, example, and test code.

Phase 19 pass 23 adds self-test modes for the heuristic audit tools. Release verification now runs `check_no_subprocess --self-test` before the full no-subprocess tree scan and `check_sensitive_logging --self-test` before the full sensitive-logging tree scan. The self-tests use built-in blocked/allowed fixtures and do not execute local commands.


### Phase 19 completeness pass 21: hostile session-open transcripts

Adds fixture-backed hostile SSH peer transcript coverage through `SSH_Lib.Sessions.Test_Support.Run_Hostile_Open_Transcript_For_Test`, `SSH_Lib.Tests.Fixtures.Hostile_Transcripts`, and the mandatory split security executable `test_hostile_transcripts`. The scenarios drive the real `Session` lifecycle flags through malformed identification, silent identification, unsupported KEX/host-key/cipher negotiation, bad KEX signatures, unknown/changed host keys, missing NEWKEYS, service-accept-before-encryption, userauth-before-host-trust, partial/rejected userauth, and channel-open failures. Every hostile failure leaves the session closed and unable to open channels; the happy transcript opens only after encrypted packet mode, host-key trust, and user authentication are all established.


### Phase 19 completeness pass 22 — Session.Open success-state proof

Adds `SSH_Lib.Sessions.Open_Guards`, `SSH_Lib.Tests.Fixtures.Session_Open_Success`, and the mandatory split security executable `test_session_open_success_security`. The fixture asserts the complete `Sessions.Open` success postcondition: an `Ok` open state is consistent only after transport connection, server identification, KEXINIT, algorithm negotiation, KEX completion, key derivation, both NEWKEYS directions, encrypted inbound/outbound packet mode, host-key signature verification, known-host trust or explicit bypass, userauth service acceptance, and final user authentication all succeed. Clearing any one gate prevents `Ok` success classification and prevents a public-open session from being considered consistent.

### Phase 19 completeness pass 42 — Runtime boundary inventory

Adds `docs/RUNTIME_BOUNDARIES.md` and `check_runtime_boundaries`. The guard records which runtime pieces are implemented and which remain explicit fail-closed boundaries. This prevents stale placeholder wording or overstated arbitrary-host SSH support from re-entering the release docs.

### Phase 19 completeness pass 43 — userauth runtime boundary

Identity-file authentication in the deterministic `Sessions.Open` runtime now uses `SSH_Lib.Sessions.Userauth_IO` instead of directly marking authentication complete. The path builds the SSH publickey signature payload, signs it through the identity-file backend, emits `SSH_MSG_USERAUTH_REQUEST` through the protected userauth packet boundary, parses `SSH_MSG_USERAUTH_SUCCESS`, and only then publishes authenticated session state. Ordinary public-network hosts remain fail-closed until the socket-backed production transcript loop is connected.

### Phase 19 completeness pass 44

Agent authentication in the deterministic `Sessions.Open` runtime now uses the
protected userauth boundary instead of directly marking the session
authenticated. The local fixture constructs an ssh-agent-shaped sign
request/response, emits `SSH_MSG_USERAUTH_REQUEST` through
`SSH_Lib.Sessions.Userauth_IO`, parses protected `SSH_MSG_USERAUTH_SUCCESS`, and
only then publishes authenticated session state. Ordinary public-network SSH
remains fail-closed until the live transcript driver is connected.

### Phase 19 completeness pass 45 — userauth service-request boundary

The deterministic `Sessions.Open` runtime now performs the `ssh-userauth` service transition through protected packet I/O before publickey authentication. It emits `SSH_MSG_SERVICE_REQUEST`, parses protected `SSH_MSG_SERVICE_ACCEPT`, marks the userauth-service gate only after that accept, and then proceeds to identity-file or agent `SSH_MSG_USERAUTH_REQUEST`.

### Phase 19 completeness pass 46 — agent sign transcript boundary

The deterministic agent authentication path now records the concrete ssh-agent sign exchange before SSH userauth publication. `Run_Agent_Userauth` stores the `SSH_AGENTC_SIGN_REQUEST` and parsed `SSH_AGENT_SIGN_RESPONSE`, then builds and emits the protected SSH `USERAUTH_REQUEST`. The open-runtime fixture now proves that agent-backed authentication crosses this agent boundary, while identity-file authentication leaves the agent transcript empty.

### Phase 19 completeness pass 47 — inbound userauth response transcripts

The deterministic `Sessions.Open` runtime keeps both sides of the protected userauth boundary auditable. `SSH_Lib.Sessions.Userauth_IO` records outbound service/userauth requests and inbound protected plus decoded `SERVICE_ACCEPT` / `USERAUTH_SUCCESS` responses before updating the corresponding session gates. The public-network path now uses the live socket-backed transcript for protected userauth as well, so fixture and live paths share the same authenticated-session publication gate.

### Phase 19 completeness pass 48 — userauth failure denial path

The deterministic `Sessions.Open` runtime now exercises the negative server-authentication path as well as success. For the reserved local runtime user `reject-auth`, both agent-backed and identity-file publickey authentication build and emit the signed `SSH_MSG_USERAUTH_REQUEST`, decode a protected `SSH_MSG_USERAUTH_FAILURE`, map it to `Authentication_Failed`, and leave the public session closed and unauthenticated. This guards against accidentally publishing authenticated state after a server-side userauth denial.

### Phase 19 completeness pass 49 — live TCP identification boundary

Ordinary non-fixture `Sessions.Open` now enters a live public-network transport boundary instead of immediately returning the old top-level `Unsupported_Feature` status. The new `SSH_Lib.Sessions.Live_Transport` path resolves the host name, opens a TCP stream socket, sends the local SSH identification line, reads and parses the server SSH identification line, and records the private transport/identification gates.

The live public-network path now proceeds through identification, KEXINIT, Curve25519 or finite-field Diffie-Hellman KEX, NEWKEYS, host-key verification, known-host trust, publickey/callback/password userauth, retained protected channel setup, negotiated protected-packet cipher/MAC/compression handling, and caller-driven channel I/O with an optional background channel reader for clients that want protected channel/control packets drained asynchronously. Unsupported global requests are rejected rather than interpreted.

Phase 19 completeness pass 88 adds bounded live channel close cleanup: `Channels.Close` now sends the close packet when possible, then opportunistically drains protected peer close/control/global/transport packets before resetting the handle. The cleanup remains best-effort and idempotent, so late network errors do not expose stale Git bytes or leave the channel open.


### Phase 19 completeness pass 50 — live cleartext KEXINIT boundary

The live non-fixture `Sessions.Open` runtime now advances beyond the old identification/KEXINIT boundary: it performs cleartext KEXINIT negotiation, live Curve25519, group-exchange SHA-256/SHA-1, group18/group16 SHA-512, or group14 key exchange, NEWKEYS, protected-packet installation, host-key signature verification, known-host trust checks, protected userauth, and retained protected channel setup. Failures at each stage map to deterministic `Status` values.

The public success gate is unchanged: arbitrary hosts still cannot return `Ok` until live key exchange, host-key verification, encrypted packet mode, and user authentication are complete on the same socket-backed transcript.

### Phase 19 completeness pass 51 — socket-backed SSH transcript driver

The live non-fixture runtime now uses `SSH_Lib.Sessions.Live_Transcript` as the production socket-backed transcript driver instead of keeping ad hoc socket reads and writes inside the open routine. The driver owns DNS/TCP connection state, exact socket writes, exact packet reads, client/server identification exchange, cleartext SSH packet send/read, and the later protected packet send/read surface that KEX/NEWKEYS, host-key verification, userauth, and channel traffic must use.

This does not make arbitrary public-network `Sessions.Open` return `Ok` yet. The path still fails closed after live KEXDH/NEWKEYS until live key-exchange math, exchange-hash verification, NEWKEYS activation, real host-key verification, and real user authentication are wired through the same transcript driver.

### Phase 19 completeness pass 52 — live KEXDH/NEWKEYS boundary

The public-network runtime now advances beyond KEXINIT negotiation for supported finite-field DH paths: `diffie-hellman-group-exchange-sha256`, `diffie-hellman-group-exchange-sha1`, `diffie-hellman-group18-sha512`, `diffie-hellman-group16-sha512`, `diffie-hellman-group14-sha256`, and `diffie-hellman-group14-sha1`. It sends the matching live `SSH_MSG_KEXDH_INIT` or RFC 4419 group-exchange request/init packets, parses the corresponding KEXDH/GEX reply, computes the shared secret and negotiated exchange hash, verifies the host-key signature through the existing host-key boundary, derives session keys with the matching hash family, and crosses the live `SSH_MSG_NEWKEYS` send/receive boundary before protected userauth/channel handling.

Arbitrary-host `Sessions.Open` can now return `Ok` only after the encrypted, trusted, authenticated live path completes. Remaining release risks are interoperability breadth and live validation, not the old channel-owned stream routing boundary.

## Phase 19 completeness pass 53

- Added `SSH_Lib.Sessions.Live_Userauth` for socket-backed `ssh-userauth` service request and publickey authentication over `SSH_Lib.Sessions.Live_Transcript`.
- Live identity-file authentication now signs with the configured identity and sends `SSH_MSG_USERAUTH_REQUEST` over the protected transcript.
- Live ssh-agent authentication now uses `SSH_AUTH_SOCK`, requests identities/signatures from the agent, and sends the resulting publickey request over the protected transcript.
- Default known-host verification still blocks public-network authentication until known-host trust matching is wired; explicit `Verify_Known_Host => False` can exercise the live userauth boundary.


## Phase 19 completeness pass 54

- Live public-network `Sessions.Open` now performs known-host trust matching after KEX host-key signature verification and before production userauth.
- The live transport records the server host-key blob from `SSH_MSG_KEXDH_REPLY`, parses it through `SSH_Lib.Protocol.Host_Keys.Parse`, converts it to `SSH_Lib.Known_Hosts.Host_Key`, and checks it with `SSH_Lib.Known_Hosts.Verify`.
- Unknown hosts return `Host_Key_Unknown`; changed keys return `Host_Key_Mismatch`; malformed or unsupported host-key material remains fail-closed.
- `Verify_Known_Host => False` still explicitly bypasses local known_hosts trust only; it does not bypass host-key signature verification.


Pass 174 adds OpenSSH host-certificate validation for `ssh-ed25519-cert-v01@openssh.com`, `rsa-sha2-512-cert-v01@openssh.com`, `rsa-sha2-256-cert-v01@openssh.com`, and `ssh-rsa-cert-v01@openssh.com`. The client now advertises certificate host-key algorithms ahead of raw keys, parses host certificates, verifies the KEX signature with the certified host key, and validates the presented certificate against matching `@cert-authority` known_hosts records before authentication. Certificate validation is fail-closed: host certificates must be type 2, within their validity interval, explicitly name the target host, carry sorted/non-duplicated OpenSSH critical options, match a trusted CA key, and carry a verifiable CA signature. Host-certificate critical options are now parsed structurally: unknown critical options remain `Unsupported_Feature`, malformed option maps fail the handshake, and user-certificate-only options such as `source-address`, `force-command`, and `verify-required` are rejected as host-certificate policy mismatches rather than treated as raw parser gaps.

Pass 182 adds OpenSSH user-certificate authentication plumbing for identity files and ssh-agent identities. When an identity file has a sibling `<identity>-cert.pub`, the loader decodes the public certificate, checks that the certificate algorithm matches the private signing key, verifies that the certified public key matches the private key, and then uses the certificate blob and certificate algorithm in `publickey` preflight/signed requests while signing with the underlying raw Ed25519/RSA algorithm. Agent identities whose public-key blob is already an OpenSSH certificate use the certificate blob for userauth and request an agent signature with the raw underlying signing algorithm. Malformed or mismatched sibling certificate files fail closed only when they indicate an internal/protocol error; ordinary authentication mismatch falls back to the raw identity.


Pass 183 tightens the host-certificate critical-option parser. OpenSSH critical-option values that are themselves encoded SSH strings, including `source-address` and `force-command`, are now decoded structurally before the host-certificate policy decision is made. Empty-payload options such as `verify-required` and `no-touch-required` are checked for canonical empty data before they are rejected as user-certificate-only policy on host certificates. Malformed critical-option data maps to `Handshake_Failed`; valid but inapplicable user-certificate-only options map to `Host_Key_Mismatch`; unknown critical options remain fail-closed as `Unsupported_Feature`.

Pass 184 completes the local OpenSSH user-certificate sanity path. Sibling `<identity>-cert.pub` files are now checked for user-certificate type, validity interval, canonical sorted/non-duplicated critical-option and extension maps, known user-critical-option payload structure, CA-signature validity with the embedded CA key, and certified-public-key match before the certificate is offered for publickey authentication. Invalid user certificates fail closed as ordinary authentication fallback candidates rather than being sent to the server. Host-certificate validation also now applies canonical map checks to extensions, not only critical options.
Remaining live-runtime work before the arbitrary-host path is release-complete: real-server E2E validation still has to be performed outside deterministic fixtures, and the remaining release risks are real-server validation plus build/test validation. Implemented algorithm families now include Curve25519, group-exchange SHA-256/SHA-1, group18/group16 SHA-512, group14 SHA-256/SHA-1, RSA SHA-2/SHA-1 and Ed25519 host keys, chacha20-poly1305 AEAD and AES-GCM/AES-CTR/AES-CBC transport ciphers, SHA-2/SHA-1 MACs including SHA1-96 fallbacks, and zlib/zlib@openssh.com compression.

Phase 19 completeness pass 105: the group14 live KEX path now clears its private exponent, public exchange packet, KEXINIT/KEX reply payloads, and shared secret on success, deterministic failure, and exception containment paths, matching the cleanup discipline already added for Curve25519.

### Phase 19 pass 56 runtime note

RSA SHA-512 is implemented for host-key verification and RSA identity-file/agent userauth signatures. Pass 70 adds a deterministic positive RSA SHA-512 host-key verification vector with tamper-negative coverage. The advertised host-key order is `ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,ssh-rsa-cert-v01@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256,ssh-rsa`. Native Ada Ed25519 host-key verification is also implemented for `ssh-ed25519` server host keys.

### Phase 19 completeness pass 57

The live runtime retains the authenticated socket-backed transcript after successful `Sessions.Open`. `SSH_Lib.Sessions.Live_Attachment` attaches the `Live_Transcript` to the private session state, and both session-owned channel setup and channel-owned data/EOF/close traffic use that same protected packet stream for live writes and reads.

Phase 19 pass 58 update: live channel stdin/stdout/EOF/close packet operations now use the retained authenticated protected transcript after live session authentication and exec setup; deterministic protected fixtures remain available for tests.

## Phase 19 completeness pass 60

Identity-file interoperability now includes PKCS#8 RSA and EC PEM files using the `-----BEGIN PRIVATE KEY-----` armor and bounded encrypted identity-file unwrap paths. SSH_Lib validates the PKCS#8 wrapper, routes RSA payloads through the RSA SHA-2 signing backend, and routes EC payloads through the ECDSA identity backend. OpenSSH bcrypt-encrypted keys route through the explicit non-retained identity passphrase path, Ada bcrypt_pbkdf derivation, and AES-CTR, AES-CBC, or 3DES-CBC private-section unwrap. Traditional encrypted RSA PEM supports AES-128/192/256-CBC, DES-CBC, and DES-EDE3-CBC with CryptoLib MD5 EVP_BytesToKey. Encrypted PKCS#8 supports PBES1 MD5-DES/SHA1-DES, PKCS#12 SHA1-2DES/SHA1-3DES/SHA1-RC2-40/SHA1-RC2-128 PBE, PBES2/scrypt, and PBES2/PBKDF2 with HMAC-SHA1, HMAC-SHA256, HMAC-SHA384, or HMAC-SHA512 PRFs and AES-128/192/256-CBC, DES-CBC, DES-EDE3-CBC, or RC2-40/64/128-CBC encryption schemes.


## Phase 19 completeness pass 61

- Added native Ada Ed25519 signature verification for `ssh-ed25519` host keys, replacing the previous unsupported-feature gate.
- Live host-key verification can now accept Ed25519 server keys after known-host trust matching.

### Phase 19 completeness pass 62

Live channel-generated control replies now cross the retained protected transcript. `exit-status` requests with `want-reply`, unknown request failures, peer close acknowledgements, and automatic window-adjust packets are no longer merely retained as plaintext fixture payloads; they are sent through the same live protected channel boundary as data, EOF, and close traffic.

### Phase 19 completeness pass 64

Live protected packet I/O now uses the derived NEWKEYS cipher material, not just
fixture-style HMAC framing. `SSH_Lib.Protocol.Protected_Packets` installs
client-to-server and server-to-client AES-CTR or AES-CBC keys/IVs plus distinct MAC keys.
Live outbound packets are encrypted before being written to the socket; live
inbound packet-length headers and bodies are decrypted before MAC verification
and SSH payload decoding. The deterministic MAC-only protected packet path is
kept for local fixtures.

### Phase 19 completeness pass 66

Live channel reads now tolerate interleaved protected global/transport packets after exec setup. `SSH_Lib.Channels.Read_Some` can reject unsupported global requests with protected `SSH_MSG_REQUEST_FAILURE`, skip ignorable protected transport/global response packets, and continue waiting for binary stdout, exit-status, EOF, or close packets on the retained authenticated transcript.


### Phase 19 completeness pass 67

Live channel completion now drains protected channel-control packets after stdout EOF when the retained live transcript is attached. This allows `Read_Some` to observe a following `exit-status` request before returning the final end-of-stream result, preserving the public `Exit_Status (Item : Channel)` API as a non-I/O observation. The default model remains caller-driven, but callers may opt in to `Start_Background_Reader` or `Session_Options.Enable_Background_Channel_Reader` so a task drains protected packets into the channel pending/control state while `Read_Some` stays binary-safe and compatibility-preserving.

### Phase 19 completeness pass 68

`SSH_Lib.Channels.Exit_Status` now reports an unknown remote exit status as `Channel_Request_Failed`. A missing `exit-status` request is a channel-completion/state condition, not an unsupported feature. Known zero exit remains `Ok`; known nonzero exit remains `Remote_Exit_Nonzero`.

## Phase 19 completeness pass 69

Live publickey authentication now tolerates server-side `SSH_MSG_USERAUTH_BANNER` messages while waiting for the terminal `USERAUTH_SUCCESS` or `USERAUTH_FAILURE` reply. Banners are parsed and retained in the live userauth transcript buffers for diagnostics, but they are never treated as authentication success. The loop is bounded and remains fail-closed if a server sends banners without a terminal authentication result.

## Phase 19 completeness pass 71

Added an opt-in live Git-over-SSH end-to-end test executable, `test_live_git_e2e.adb`. The default release suite still performs no public-network access: the executable exits successfully as skipped unless `SSH_LIB_LIVE_GIT_E2E=1` is set. When enabled, it requires `SSH_LIB_LIVE_GIT_HOST`, `SSH_LIB_LIVE_GIT_USER`, and `SSH_LIB_LIVE_GIT_REPO`, keeps known-host verification enabled, opens a real authenticated session, executes `git-upload-pack` by default or `git-receive-pack` when `SSH_LIB_LIVE_GIT_SERVICE=receive-pack`, writes an opaque Git flush packet, sends EOF, reads opaque stdout bytes, observes exit status, and closes the channel/session. This proves the public API sequence needed by `version` without adding higher-level Git protocol interpretation to the SSH library.

### Phase 19 completeness pass 73

Live protected waits now classify SSH transport control packets explicitly. `SSH_MSG_IGNORE`, `SSH_MSG_UNIMPLEMENTED`, and `SSH_MSG_DEBUG` can be skipped while waiting for service, userauth, or channel replies; `SSH_MSG_DISCONNECT` fails closed with a deterministic connection failure. This keeps the live Git-over-SSH byte-stream path synchronized with real servers that interleave transport control packets.


## Phase 19 Completeness Pass 74

Pass 74 adds an explicit password-authentication option for callers that provide a password in `Session_Options`. The library still has no built-in UI prompt, password storage, or credential discovery: password auth is attempted only when `Use_Password` is true and either `Password` is non-empty or a caller-provided `Password_Callback` supplies a valid secret. The request is sent only after encrypted packet mode and host-key trust have completed. Password text containing NUL, CR, or LF is rejected before any network authentication request is emitted.

## Phase 19 Completeness Pass 75

Live session cleanup now sends a best-effort protected `SSH_MSG_DISCONNECT` before closing an attached socket-backed transcript. The close path remains idempotent and does not expose close-time network failures to callers, but real servers now receive a protocol-level disconnect instead of only a TCP close.

## Phase 19 Completeness Pass 76

Live userauth now falls through across explicitly configured authentication methods. An unsupported or failed identity-file attempt, including an encrypted identity with a missing/wrong passphrase or unsupported encrypted identity algorithm, does not prevent a later configured ssh-agent or password attempt on the same encrypted/trusted session. Unsupported agent identities are skipped while the bounded identity list is tried. Protocol, transport, malformed-packet, and internal errors still abort immediately, and authenticated session state is still published only after protected `USERAUTH_SUCCESS`.


### Phase 19 completeness pass 77: password material retention hardening

Explicit password authentication remains caller-supplied and protected-transport-only. The live authentication path now avoids retaining the caller-provided password in session-private stored options, clears the encoded password request buffer on all return paths, and records a structurally redacted plain userauth transcript for password requests. The encrypted protected outbound packet transcript is still retained for boundary inspection; no plaintext password is kept in the session diagnostic buffers.

### Phase 19 completeness pass 78

Password authentication now distinguishes the RFC 4252 password-change-required reply from publickey `PK_OK`, even though both use SSH message number 60. The parser treats message 60 as password-change-required only in password-auth reply context, and the live password path fails closed with `Authentication_Failed` because SSH_Lib still has no automatic password-change workflow. Credential prompting and storage are explicit caller-invoked Git helpers, not automatic session-open behavior.

### Phase 19 completeness pass 79

Known-host verification now supports bounded OpenSSH-style wildcard host selectors (`*` and `?`) for bare default-port entries and bracketed `[host-pattern]:port` entries. Matching wildcard entries can establish trust, changed wildcard entries report `Host_Key_Mismatch`, and negated wildcard selectors deny trust deterministically. Hashed OpenSSH known-host records (`|1|salt|hmac-sha1|`) are now matched using bounded HMAC-SHA1 over the exact host selector text, including `[host]:port` for non-default ports.


## Phase 19 completeness pass 81

Pass 81 hardens default host-key verification for OpenSSH marker records.
`known_hosts` lines marked `@revoked` are now parsed instead of ignored; a
matching revoked key deterministically returns `Host_Key_Mismatch` and cannot be
re-enabled by a later ordinary trust line. `@cert-authority` records are used only for OpenSSH host-certificate CA trust and are never treated as ordinary raw host keys
because host certificates are outside the raw host-key trust model and must not
be treated as direct trust for a presented server key.

### Phase 19 completeness pass 82

Live protected SSH packet framing now uses the installed cipher block size after NEWKEYS instead of assuming only the cleartext 8-byte minimum. This hardens the live encrypted transport used by session authentication and Git exec channels while preserving deterministic fixture defaults.

### Phase 19 completeness pass 83

Live socket-backed transcript setup now receives `Session_Options.Read_Timeout_MS` and `Session_Options.Write_Timeout_MS` and applies them as receive/send socket timeout options before the live identification/KEX/userauth/channel packet path proceeds. Timeout-option installation is best-effort and public failures still map through deterministic `Status` values. `Connect_Timeout_MS` remains preflighted but is not yet a portable nonblocking connect deadline.

### Phase 19 completeness pass 84

The live public-network transcript now receives `Session_Options.Connect_Timeout_MS` in addition to read/write timeouts. The connect boundary records a deadline from the start of DNS/TCP setup and fails closed with `Timeout` if that deadline has elapsed before the SSH identification/KEX path begins. DNS and ordinary socket failures continue to return deterministic `Status` values instead of raising exceptions.

### Phase 19 pass 85 note

The live authentication path now sends a bounded `none` userauth request after the protected `ssh-userauth` service is accepted. Most servers reject it and advertise remaining methods; that rejection is used only as fallback/discovery. If a server explicitly accepts `none`, the session is marked authenticated only after the protected `USERAUTH_SUCCESS` packet is received.

### Phase 19 completeness pass 86

OpenSSH hashed `known_hosts` matching now preserves case-insensitive host semantics. A `|1|salt|hash` entry generated for a lower-case host can still trust the same host when callers pass mixed-case text such as `GitHub.com`, while malformed hashed records remain fail-closed.

### Phase 19 completeness pass 87

Live publickey authentication now performs the RFC 4252 preflight check before signing. Identity-file and ssh-agent paths send an unsigned publickey test request first and only sign after receiving a matching `USERAUTH_PK_OK` for the same algorithm and key blob. Rejected keys fall through to configured later authentication methods without publishing success.
### Phase 19 completeness pass 89

Configuration resolution and version-facing Git transport preparation now keep pace with the explicit password-authentication fields in `Session_Options`. All named option aggregates in those paths initialize `Use_Password => False` and `Password => Null_Unbounded_String`, preserving the no-credential-storage default and avoiding stale aggregate shapes after the public record expansion. The public API guard now checks those fields explicitly.


### Phase 19 completeness pass 90

Live socket operation deadlines now propagate through the public status model. After `Read_Timeout_MS` or `Write_Timeout_MS` has configured the socket receive/send timeout, socket-level timeout exceptions in the live transcript map to `SSH_Lib.Errors.Timeout` instead of being collapsed into generic read/write failures. This applies to SSH identification reads and to later exact protected-packet reads/writes on the retained live transcript.


Phase 19 completeness pass 91 hardens public-network open cleanup: DNS/TCP/connect-timeout failures now destroy the allocated live transcript before returning the original deterministic status.

Phase 19 completeness pass 107 hardened single-hop `ProxyJump` parsing for bracketed IPv6 jump hosts such as `[2001:db8::1]:2222` and `user@[2001:db8::1]:2222`; unbracketed multi-colon values fail closed as ambiguous.

Phase 19 completeness pass 108 expands `ProxyJump` to comma-separated multi-hop chains. The implementation opens the final jump host through any preceding jump prefix recursively, then carries the target SSH transport over the final hop's SSH `direct-tcpip` channel. `ProxyCommand` is executed only by `Sessions.Open` as the explicit subprocess-backed SSH transport.


Phase 19 pass 119 bounds OpenSSH bcrypt KDF salt length and round counts before bcrypt_pbkdf derivation is attempted, so syntactically valid but oversized encrypted-key envelopes fail closed instead of creating an unbounded CPU or memory boundary.


### Pass 127 live Git interoperability matrix

Pass 127 adds `test_live_git_interop_matrix.adb`, an opt-in live interoperability matrix for the Version-facing Git-over-SSH path. It performs no public-network access unless `SSH_LIB_LIVE_GIT_MATRIX=1` is set. When enabled, `SSH_LIB_LIVE_GIT_SCENARIOS` selects comma-separated scenarios such as `DIRECT`, `AGENT`, `IDENTITY`, `PASSWORD`, `PASSPHRASE`, `PROXYJUMP`, and `RECEIVE`; pass 128 makes this selector whitespace/case tolerant, rejects unknown scenario names before network access, and adds `ALL` as a shorthand for the full matrix.

The matrix keeps strict known-host verification enabled and exercises the public sequence required by Version: open an authenticated session, open an exec channel with a safely quoted Git service command, write an opaque Git flush packet, send EOF, read opaque stdout bytes, observe exit status, close the channel, and close the session. Scenario-specific values can be supplied with `SSH_LIB_LIVE_GIT_<SCENARIO>_<FIELD>` and fall back to the existing single-case names such as `SSH_LIB_LIVE_GIT_HOST`, `SSH_LIB_LIVE_GIT_USER`, `SSH_LIB_LIVE_GIT_REPO`, `SSH_LIB_LIVE_GIT_KNOWN_HOSTS`, `SSH_LIB_LIVE_GIT_IDENTITY`, `SSH_LIB_LIVE_GIT_PASSWORD`, `SSH_LIB_LIVE_GIT_IDENTITY_PASSPHRASE`, and `SSH_LIB_LIVE_GIT_PROXY_JUMP`.

Phase 19 completeness pass 130 adds `test_live_proxyjump_transport.adb`, a dedicated opt-in live ProxyJump transport proof separate from the Git matrix. It performs no network access unless `SSH_LIB_LIVE_PROXYJUMP=1` is set. `SSH_LIB_LIVE_PROXYJUMP_SCENARIOS` accepts `SINGLE`, `CHAIN`, `IPV6`, or `ALL`; each selected scenario requires explicit `HOST`, `USER`, `PROXY_JUMP`, and `COMMAND` values through `SSH_LIB_LIVE_PROXYJUMP_<FIELD>` or scenario-specific `SSH_LIB_LIVE_PROXYJUMP_<SCENARIO>_<FIELD>` variables. The test keeps strict known-host verification enabled, opens a ProxyJump-backed session, opens an exec channel over the tunneled target transport, reads stdout bytes without text conversion, observes exit status, closes channel/session, and clears password/passphrase options after each scenario.
Phase 19 completeness pass 314 adds `test_live_proxycommand_transport.adb`, a dedicated opt-in live ProxyCommand transport proof. It performs no network or subprocess-backed ProxyCommand access unless `SSH_LIB_LIVE_PROXYCOMMAND=1` is set. `SSH_LIB_LIVE_PROXYCOMMAND_SCENARIOS` accepts `BASIC`, `TOKEN`, `IPV6`, `FAILS_EARLY`, or `ALL`; each selected non-failure scenario requires explicit `HOST`, `USER`, `PROXY_COMMAND`, and `COMMAND` values through `SSH_LIB_LIVE_PROXYCOMMAND_<FIELD>` or scenario-specific `SSH_LIB_LIVE_PROXYCOMMAND_<SCENARIO>_<FIELD>` variables. `TOKEN` additionally requires the configured command to include `%h` and `%p`, proving the OpenSSH-style token expansion path. `FAILS_EARLY` proves a ProxyCommand that does not produce an SSH transport fails the session open instead of succeeding. The test keeps strict known-host verification enabled, opens a ProxyCommand-backed session, opens an exec channel, reads stdout bytes without text conversion, observes exit status, closes channel/session, and clears password/passphrase options after each scenario.
Phase 19 completeness pass 131 hardens `SSH_LIB_LIVE_PROXYJUMP_SCENARIOS`: comma-separated lists now reject empty entries such as `SINGLE,,CHAIN`, leading commas, trailing commas, and whitespace-only entries. This keeps the opt-in live ProxyJump test fail-closed instead of silently skipping part of the requested matrix.


### Explicit live rekey

`SSH_Lib.Sessions.Rekey` repeats the negotiated SSH key exchange on an already authenticated live session.  The implementation preserves the first exchange hash as the SSH session identifier, derives replacement keys from the new exchange hash, verifies the new host-key signature, and reruns known-host trust verification before accepting the replacement keys.

The live rekey interoperability proof is disabled by default.  Enable it only in a prepared environment with a trusted `known_hosts` file:

```sh
SSH_LIB_LIVE_REKEY=1 \
SSH_LIB_LIVE_REKEY_HOST=example.org \
SSH_LIB_LIVE_REKEY_USER=git \
SSH_LIB_LIVE_REKEY_REPO=repo.git \
SSH_LIB_LIVE_REKEY_KNOWN_HOSTS=/path/to/known_hosts \
ssh_lib_build/bin/tests_security/test_live_rekey_transport
```

### Automatic rekey thresholds



RFC 4419 group-exchange KEX is configurable through `Session_Options.Gex_Minimum_Bits`, `Gex_Preferred_Bits`, and `Gex_Maximum_Bits`. The defaults request a 2048/4096/8192-bit range. Invalid ranges fail closed before the live GEX request is sent; server-supplied groups are still accepted only when they match the implemented safe MODP groups.

Live sessions enable automatic rekeying by default. `Session_Options.Automatic_Rekey` controls the policy, while `Rekey_After_Packets`, `Rekey_After_Bytes`, and `Rekey_After_Seconds` set protected-packet, protected-wire-byte, and elapsed-time thresholds. A zero threshold disables that trigger. The elapsed-time threshold is measured from successful NEWKEYS installation and is reset after each client- or peer-initiated rekey. When a threshold is reached, the next outbound channel/control packet performs a client-initiated rekey before sending; inbound packets are counted but reads do not start a client rekey in the middle of pending peer data.


### MAC interoperability fallback

The default MAC preference remains SHA-2-first: OpenSSH EtM SHA-2 MACs, then non-EtM SHA-2 MACs. `hmac-sha1-etm@openssh.com`, `hmac-sha1`, `hmac-sha1-96-etm@openssh.com`, and `hmac-sha1-96` are present only as lowest-priority interoperability fallbacks for older servers; MD5 MACs remain unsupported.

Phase 19 completeness pass 142 adds the Ada-native `run_release_validation` tool so release verification can be driven by Ada code instead of relying only on the POSIX shell wrapper. The runner does not enable opt-in public-network live tests; it fails closed when the Ada/Alire toolchain or expected build outputs are missing.

### Pass 143 credential callbacks

`Session_Options` now supports optional non-interactive credential callbacks for password authentication, identity-file passphrases, and password-change-required replies. Explicit option values still take precedence. The callbacks are never used as UI prompts by SSH_Lib itself; they are caller-supplied hooks whose returned secrets are used only for protected userauth and are not retained in the session object.

Phase 19 completeness pass 157: RSA publickey userauth fallback was expanded.  RSA identity-file and ssh-agent authentication now try rsa-sha2-512 first and then rsa-sha2-256 before falling back to the next authentication method, with ssh-rsa/SHA-1 as a last-resort fallback.


Phase 19 completeness pass 166: broader optional algorithm coverage now includes legacy `ssh-rsa`/RSA-SHA1 as a deliberately lowest-priority interoperability fallback for host-key signatures and RSA userauth. RSA SHA-2 remains preferred; `ssh-rsa` is advertised and attempted only after Ed25519 and RSA SHA-2 paths.


Phase 19 pass 173: AES-GCM transport support is implemented for `aes256-gcm@openssh.com` and `aes128-gcm@openssh.com`. AES-GCM is handled as an AEAD packet mode with encrypted packet length, GHASH tag verification, 16-byte authentication tags, and no separate SSH MAC; mixed-direction negotiation with non-GCM ciphers remains supported.

Pass 185 adds explicit OpenSSH `CertificateFile` integration for user-certificate authentication. `Session_Options.Certificate_File` can point at a specific public user certificate; `SSH_Lib.Config` now parses `CertificateFile` as inert path data with the same no-shell-expansion/no-command-execution behavior as `IdentityFile`. If no explicit certificate file is configured, identity-file authentication keeps the OpenSSH sibling convention and probes `<identity>-cert.pub`. Explicit missing certificate files fail closed for that identity attempt, while implicit sibling certificates remain optional fallback data. User certificates also now require a well-formed principals string list during local sanity validation before being offered to a server.

### Phase 19 pass186 certificate hardening

OpenSSH user certificates returned by ssh-agent are now locally sanity-checked before use. The client validates user-certificate type, validity time, canonical critical-option/extension maps, embedded CA signature, and known critical-option framing before publickey preflight. Invalid certificate identities are skipped fail-closed while other agent identities may still be attempted. The source-address critical option accepts IPv6 CIDR syntax and enforces mask bounds; force-command payloads are treated as SSH-string data and are not text-converted or executed.

### Phase 19 pass187 certificate completeness

Pass 187 extends deterministic OpenSSH certificate critical-option coverage to user certificates as well as host certificates. User-certificate critical options are now fixture-tested for canonical map parsing, valid `source-address`, valid `force-command` SSH-string framing, malformed `source-address`, and duplicate-name rejection. Unknown user critical options remain locally accepted after canonical parsing so the SSH server can enforce CA policy; SSH_Lib does not interpret or execute them. The pass also aligns ssh-agent RSA publickey authentication with identity-file auth by trying `ssh-rsa` as the final compatibility fallback after RSA SHA-2 attempts.

### Phase 19 pass188 certificate source-address hardening

Pass 188 tightens OpenSSH certificate `source-address` critical-option validation. The parser now treats `source-address` as a CIDR/address list rather than a loose character class: IPv4 octets are range-checked, IPv4 masks are limited to `0..32`, IPv6 masks are limited to `0..128`, empty list entries are rejected, and DNS-like names or arbitrary hex-like text are no longer accepted as source-address values. Host certificates still reject syntactically valid `source-address` as user-certificate-only policy, while malformed source-address data fails closed as `Handshake_Failed`. The identity-file authentication cleanup path also had a duplicate unreachable `return Internal_Error` removed.

### Phase 19 pass189 certificate embedded-key sanity

Pass 189 completes another OpenSSH user-certificate sanity pass. User certificates validated for authentication now also parse the embedded certified public key before the certificate is offered to the server. This matters especially for ssh-agent certificate identities, where the client cannot compare the certificate to a locally loaded private-key object. The check is deliberately local and structural: it verifies that the certified public key has a supported raw Ed25519/RSA shape, while authorization principals and unknown critical user-certificate policy remain server-enforced.

### Phase 19 pass190 certificate validity boundary

Pass 190 corrects OpenSSH certificate `valid_before` handling. Host and user certificates now treat `valid_before` as an exclusive upper bound and fail closed when the current Unix time is greater than or equal to that timestamp, unless the certificate uses the OpenSSH forever value. The existing inclusive `valid_after` behavior is unchanged.

### Phase 19 pass191 explicit CertificateFile fail-closed behavior

Pass 191 tightens OpenSSH user-certificate authentication when `Session_Options.Certificate_File` is explicitly configured. If the explicit certificate file exists but fails local attachment/validation because it is malformed, expired, unsupported, or does not match the private identity key, SSH_Lib now fails closed for that identity attempt instead of silently falling back to the raw private key. The implicit `<Identity_File>-cert.pub` sibling convention remains optional fallback data.

### Phase 19 pass192 certificate source-address IPv6 edge-case hardening

Pass 192 tightens OpenSSH certificate `source-address` validation for IPv6 literals. The parser now rejects addresses ending in a single trailing colon, such as `2001:db8:1:2:3:4:5:`, while preserving valid double-colon compression such as `2001:db8::/32`. Fixture coverage was added for both host-certificate and user-certificate critical-option paths so malformed IPv6 source-address data fails closed before certificate policy decisions are applied.

### Phase 19 pass193 ssh-agent certificate algorithm-name hardening

Pass 193 tightens ssh-agent publickey/certificate identity handling. The algorithm name decoded from an agent public-key blob must now be a valid ASCII SSH protocol name and must be one of SSH_Lib's supported raw publickey or OpenSSH certificate algorithms before it is used for publickey preflight, signing, or certificate validation. Empty, non-ASCII, malformed, or unsupported agent identity algorithms are skipped fail-closed, which prevents malformed agent-supplied certificate blobs from reaching userauth request construction.

## Phase 19 completeness pass 194

Host-certificate CA-signature verification now maps failed verification to
`Host_Key_Mismatch` while preserving `Internal_Error` and `Unsupported_Feature`
for true defects and unsupported algorithms.  The host-certificate signature
buffer is explicitly cleared before returning from validation.


## Phase 19 completeness pass 195

Pass 195 adds an explicit OpenSSH certificate-signature algorithm allow-list at the certificate validation layer. Parsed certificate signature blobs must use one of the supported SSH signature algorithms before verification is attempted. Host certificates return `Unsupported_Feature` for unsupported certificate-signature algorithms while preserving `Host_Key_Mismatch` for failed verification. User certificates reject unsupported certificate-signature algorithms as authentication failures before publickey auth continues. Signature buffers are cleared on these early exits.

### Phase 19 pass196 certificate hardening

OpenSSH certificate validation now checks both the certificate signature algorithm allow-list and the CA-key/signature family relationship before invoking low-level signature verification. Ed25519 CA keys only accept `ssh-ed25519` certificate signatures. RSA CA keys accept the supported RSA signature algorithms (`rsa-sha2-512`, `rsa-sha2-256`, and `ssh-rsa`). Cross-family signatures fail closed deterministically: host certificates report `Host_Key_Mismatch`, while user certificates report `Authentication_Failed`.

### Phase 19 pass197 certificate hardening

OpenSSH host and user certificate validation now rejects non-canonical validity windows before time-of-use checks. A certificate with finite `valid_before` and `valid_after >= valid_before` fails closed. The existing semantics remain unchanged: `valid_after` is inclusive, `valid_before` is exclusive, and the OpenSSH forever value is accepted.

### Phase 19 pass 198 certificate hardening

OpenSSH certificate parsing now rejects non-empty reserved certificate fields
with `Handshake_Failed`. The reserved SSH string is treated as future protocol
semantics rather than ignorable metadata, so host certificates, identity-file
user certificates, and ssh-agent certificate identities all fail closed when the
field is not empty.

### Phase 19 completeness pass 199

Pass199 tightens ssh-agent publickey/certificate identity handling. Agent identities whose public-key blob decodes to an empty, malformed, non-ASCII, or unsupported algorithm name are now explicitly skipped before publickey preflight or signing. This reinforces the existing algorithm allow-list at the live userauth control-flow boundary and removes a duplicate unreachable return in the agent post-auth compression path.

### Phase 19 pass 200 ECDSA support

Pass 200 adds native Ada ECDSA P-256 support for SSH host-key verification,
OpenSSH certificate parsing/validation, ssh-agent publickey authentication, and
OpenSSH-format ECDSA identity-file authentication.  The implemented SSH
algorithm is `ecdsa-sha2-nistp256`, with certificate form
`ecdsa-sha2-nistp256-cert-v01@openssh.com`.

The implementation now covers raw OpenSSH ECDSA NIST P-256, P-384, and P-521
host-key/certificate verification, key exchange, ssh-agent userauth signature
structure checks, OpenSSH-format identity parsing, and SEC1/PKCS#8 PEM EC
private-key parsing. Local ECDSA identity-file signing is enabled for P-256,
P-384, and P-521; P-384/P-521 signing is backed by `CryptoLib.ECDSA` and has
positive generated-signature verification coverage. FIDO/security-key ECDSA
remains the OpenSSH standard P-256 `sk-ecdsa-sha2-nistp256@openssh.com` form.

### Phase 19 pass201 ECDSA hardening

Pass201 tightens the ECDSA P-256 support added in pass200.  ECDSA host-key
parsing now validates the public point against the NIST P-256 curve before the
key is accepted.  OpenSSH ECDSA identity-file loading also verifies that the
stored private scalar derives the public point in the OpenSSH public key blob,
so mismatched or malformed ECDSA private-key records fail closed before
publickey authentication.
### Phase 19 completeness pass 202

- Hardened ECDSA P-256 validation semantics after pass201.
- Public point coordinates are now validated as field elements in `0 .. p - 1`, while private scalars and signature `r`/`s` remain restricted to `1 .. n - 1`.
- This prevents valid SEC1/RFC 5656 public points with a zero coordinate from being rejected solely because scalar-range checks were reused for field coordinates.



### Phase 19 pass 203 ECDSA signature parsing hardening

Pass 203 validates `ecdsa-sha2-nistp256` SSH signature blobs structurally during signature parsing. ECDSA signatures must decode as the OpenSSH/RFC5656 nested `r`/`s` mpint pair with no trailing data, non-negative/minimal mpints, and `r`/`s` in `1 .. n - 1`. Malformed ECDSA signatures now fail closed before lower-level verification.

### Phase 19 completeness pass 204

ECDSA P-256 identity-file signing now uses RFC 6979-style deterministic HMAC-SHA256 nonce generation instead of an ad-hoc private-key/message/counter hash. This hardens local `ecdsa-sha2-nistp256` userauth signing while preserving existing P-256 scalar and signature range validation.

### Phase 19 pass 205

- Canonicalized locally generated `ecdsa-sha2-nistp256` identity-file signatures to low-S form.
- Verification remains permissive for high-S peer/agent/certificate signatures; only local ECDSA signing output is normalized.

### Phase 19 completeness pass 206

ECDSA P-256 signing and verification now share an explicit SHA-256 `bits2int mod n` message-scalar helper.  Local identity-file signatures, host-key verification, certificate verification, and ssh-agent ECDSA verification paths no longer rely on the modular arithmetic layer to accept an unreduced SHA-256 digest as the ECDSA message representative.

### Phase 19 completeness pass 207

ECDSA P-256 user-certificate identity-file attachment was completed. The identity-file certificate allow-list now includes `ecdsa-sha2-nistp256-cert-v01@openssh.com`, so explicit `CertificateFile` and implicit `<identity>-cert.pub` ECDSA certificates can reach the existing ECDSA certificate validation path. All existing fail-closed certificate checks remain in force.

### Phase 19 completeness pass 208

Raw `ecdsa-sha2-nistp256` known_hosts records are now accepted by the known-hosts format gate. This completes the raw ECDSA host-key trust path so normal ECDSA known_hosts entries can reach the existing ECDSA host-key parser, curve validation, and trust comparison logic. Malformed ECDSA blobs still fail closed, and host certificates continue to use the certificate validation path.

### Phase 19 completeness pass 209

`ecdsa-sha2-nistp256` is now included in the default userauth public-key
algorithm classification helper.  This closes a remaining ECDSA integration
edge where the live identity-file and agent paths could handle ECDSA, but the
shared public-key-blob helper still classified only Ed25519/RSA algorithms as
normal default userauth algorithms.  Fixture coverage now asserts the ECDSA
classification alongside the existing Ed25519/RSA cases.


### Phase 19 completeness pass 210

ECDSA ssh-agent signature responses are now locally structure-checked before use. `ecdsa-sha2-nistp256` agent signatures must decode as the RFC5656/OpenSSH nested `(r, s)` signature payload with canonical positive mpints in range. Ed25519 agent signatures are also checked for the required 64-byte payload size at the agent boundary.


### Phase 19 completeness pass 211

Pass 211 added native Ada `ecdh-sha2-nistp256` key exchange support. Later passes extend the same RFC5656 ECDH path to `ecdh-sha2-nistp384` with SHA-384 and `ecdh-sha2-nistp521` with SHA-512. The client now advertises all three NIST ECDH curves after Curve25519 and before finite-field DH fallbacks, validates SEC1 uncompressed peer points, computes the x-coordinate shared secret, and routes the algorithms through initial handshake and rekey paths.

### Phase 19 completeness pass 212

NIST P-256 ECDH KEX packet handling was hardened. `ecdh-sha2-nistp256` client and server public values are now validated as full SEC1 uncompressed P-256 curve points at the `SSH_Lib.Protocol.Kexdh` packet boundary, not merely checked for 65-byte length and `0x04` prefix. The live transport still recomputes/uses the validated point for shared-secret derivation, but malformed peer points now fail closed earlier and consistently with the rest of the ECDSA/P-256 validation stack.

### Phase 19 completeness pass 213 — ECDH exchange-hash boundary hardening

The `ecdh-sha2-nistp256` exchange-hash helper now revalidates both RFC 5656 public point inputs (`Q_C` and `Q_S`) as SEC1 uncompressed NIST P-256 points before hashing. The live KEX path already validates these values at packet parse time, but this pass makes the lower exchange-hash boundary fail closed as well so direct callers and future fixtures cannot compute an exchange hash over malformed or cross-curve ECDH point material.


### Phase 19 pass 214

- Hardened `ecdh-sha2-nistp256` shared-secret computation.
- The NIST P-256 ECDH path now rejects a computed point at infinity or an all-zero shared x-coordinate before exchange-hash/key derivation.
- The ECDH shared x-coordinate remains fixed-width internally and is canonicalized as an SSH `mpint` by the existing exchange-hash/key-derivation code.

### Phase 19 completeness pass 215

Added deterministic fixture coverage for the native Ada `ecdh-sha2-nistp256`
primitive path.  The fixture generates two seeded NIST P-256 ECDH keypairs,
validates both SEC1 uncompressed public points, confirms that both directions
compute the same non-zero shared secret, and verifies that a malformed peer point
fails closed before exchange-hash or key-derivation logic can use it.

### Phase 19 completeness pass 216

Hardened the direct `ecdh-sha2-nistp256` exchange-hash boundary. `SSH_Lib.Protocol.Exchange_Hash.Compute_ECDH_SHA256` now validates that the raw shared-secret input is exactly the 32-octet NIST P-256 x-coordinate and is not all zero before canonical SSH `mpint` encoding and hashing. The live KEX path already receives this value from the native ECDH primitive, but this pass prevents future direct callers or fixtures from hashing malformed or degenerate ECDH shared-secret material.

### Phase 19 completeness pass 217

The `ecdh-sha2-nistp256` packet boundary now uses dedicated RFC 5656 ECDH
encoding/parsing instead of delegating to the finite-field KEXDH helper.  The
message numbers remain the shared SSH KEXDH/ECDH values, but `Q_C` and `Q_S`
are handled explicitly as SSH strings containing SEC1 uncompressed NIST P-256
points.  This keeps elliptic-curve framing independent from finite-field mpint
helper semantics while preserving the existing fail-closed point validation.


### Phase 19 completeness pass 218

Centralized `ecdh-sha2-nistp256` shared-secret boundary validation.  The native
P-256 ECDH primitive now exposes `Validate_ECDH_Nistp256_Shared_Secret`, and
both the shared-secret computation path and the direct exchange-hash helper use
that single fail-closed validator.  This prevents future drift between live KEX
and direct exchange-hash callers for the 32-octet non-zero ECDH x-coordinate
requirement.

### Phase 19 completeness pass 219

Added OpenSSH hybrid/PQ KEX recognition and fail-closed guardrails.  Historical
state for pass 219: the crate explicitly recognized
`sntrup761x25519-sha512@openssh.com`, `sntrup761x25519-sha512`,
`mlkem768x25519-sha256`, and the guarded `mlkem768x25519-sha512` spelling as
hybrid/PQ key exchange names, but intentionally left them unadvertised until
real SNTRUP761 and ML-KEM768 primitive boundaries plus validation evidence were
added.  Current state: after the KEM layers, external vectors, source-level
hybrid wrapper, and recorded OpenSSH transcript gate, all four names are
advertised and selectable.  The original guardrail avoided an unsafe placeholder
implementation where the PQ component was replaced by hashes, zeros, or
X25519-only material.

### Phase 19 pass 220

- Hardened the KEX reply consistency guard for unsupported OpenSSH hybrid/PQ KEX names.
- `sntrup761x25519-sha512@openssh.com` and `mlkem768x25519-sha256` now fail closed at the algorithm guard boundary even when a test/override path supplies matching negotiated and reply names.
- Historical note: hybrid/PQ KEX names remained recognized and unadvertised until real Ada SNTRUP761 and ML-KEM768 primitives plus validation evidence were added. Current state: advertised and selectable.

### Phase 19 pass 221

- Added the guarded `mlkem768x25519-sha512` spelling to the hybrid/PQ KEX fail-closed recognizer.
- Historical state for pass 221: the guarded SHA-512 ML-KEM spelling remained unadvertised and could not fall through to a classical KEX path if supplied by future override/config/test code. Current state: it is advertised and selectable after the KEM, vector, wrapper, and recorded-transcript gates.
- Added fixture and main-suite coverage for support-status, advertised-list, and KEX reply-consistency behavior.


### Phase 19 completeness pass 222

- Added missing deterministic guard coverage for the OpenSSH SNTRUP hybrid alias `sntrup761x25519-sha512` without the `@openssh.com` suffix.
- The alias is now covered at the KEX reply consistency boundary, support-status boundary, and advertised-list negative boundary.
- Historical note: hybrid/PQ KEX remained recognized but unadvertised until real Ada SNTRUP761 and ML-KEM768 primitive boundaries plus validation evidence were added. Current state: advertised and selectable.

### Phase 19 pass 223: OpenSSH FIDO/security-key userauth

Pass 223 adds agent-backed OpenSSH security-key publickey authentication support for `sk-ssh-ed25519@openssh.com`, `sk-ecdsa-sha2-nistp256@openssh.com`, and their OpenSSH user-certificate forms. The core library remains non-interactive and does not access FIDO hardware directly; ssh-agent is responsible for user-presence/user-verification interaction and private-key isolation. Malformed or refused agent signatures fail closed.

### Phase 19 completeness pass 224

Hardened the ssh-agent signature boundary for FIDO/security-key and other agent-backed publickey authentication.  After parsing a structurally valid agent signature response, the live agent client now verifies that the returned signature blob algorithm exactly matches the algorithm requested from the agent.  This prevents a structurally valid but wrong-family signature from being embedded into USERAUTH_REQUEST, for example a raw Ed25519 signature returned for an `sk-ssh-ed25519@openssh.com` request.  Security-key auth remains agent-backed only; the core library still does not prompt, store credentials, or access FIDO hardware directly.

### Phase 19 pass225 note

Security-key/FIDO public-key parsing now requires OpenSSH `sk-*` application strings to use the SSH application prefix `ssh:` and printable ASCII only. Security-key authentication remains ssh-agent backed only; the core library does not prompt, store credentials, or talk to FIDO hardware directly.

### Phase 19 completeness pass 226

Hardened the ssh-agent identity boundary for FIDO/security-key and other agent-backed publickey authentication. Agent identities are now parsed as full public-key blobs before publickey preflight or signing, not accepted solely because their leading algorithm string is supported. Raw keys use the shared host-key parser, so malformed Ed25519/RSA/ECDSA/SK blobs fail closed before use, while certificate identities continue through local OpenSSH user-certificate validation. Security-key auth remains ssh-agent backed only.


### Phase 19 pass227: OpenSSH UMAC guardrails

OpenSSH UMAC MAC algorithm names are now recognized explicitly:

- `umac-64@openssh.com`
- `umac-128@openssh.com`
- `umac-64-etm@openssh.com`
- `umac-128-etm@openssh.com`

Historical note: before pass 253, these names were intentionally unsupported and unadvertised so no placeholder would be negotiated under an OpenSSH UMAC algorithm name. Pass 253 replaces that guardrail with native Ada UMAC coverage.

### Phase 19 pass228: UMAC guard completeness

UMAC fail-closed handling was extended to the generic selected-algorithm guard.  Even if an override or malformed test path includes `umac-*` in a client MAC list, selecting that name now routes through the explicit UMAC fail-closed status instead of the generic unsupported path.  Fixture coverage now checks both client-to-server and server-to-client MAC directions.

Historical note: before pass 253, UMAC was recognized, unsupported, and unadvertised until native Ada UMAC work was added.

### Phase 19 completeness pass 229

Hardened the protected-packet state boundary for recognized-but-unsupported OpenSSH UMAC MAC names. `Reset_With_Ciphers` now clears MAC keys, MAC lengths, and MAC algorithm slots before resolving negotiated MAC names, and leaves MAC material zeroed if outbound or inbound MAC selection fails. This avoids stale protected-epoch MAC state after a fail-closed UMAC selection. Historical note: before pass 253, UMAC was recognized, unsupported, and unadvertised until native Ada UMAC work was added.

### Phase 19 completeness pass 230

Hardened protected-packet reset cleanup after the UMAC guardrail work. `Reset_With_Ciphers` now clears partially resolved cipher, AEAD, MAC-key, MAC-length, MAC-kind, and block-size state on later reset failures as well as on direct MAC-selection failure. This avoids stale protected-epoch material after any fail-closed reset path. Historical note: before pass 253, UMAC was recognized, unsupported, and unadvertised until native Ada UMAC work was added.

### Phase 19 completeness pass 231

Extended the protected-packet reset cleanup added in pass230 to explicitly close
and clear compression state in the shared failed-reset cleanup path.  Failed
protected-epoch resets now release delayed/active zlib objects and reset the
compression flags/pointers along with cipher, AEAD, MAC, and block-size state.
This prevents stale compression state from surviving a later fail-closed reset
path, including override/test paths that select recognized-but-unsupported UMAC
names before a later setup step fails.

### Phase 19 completeness pass 232

Pass 232 expands safe OpenSSH configuration compatibility.  The config parser now
recognizes `Include`, a safe subset of `Match`, `HostKeyAlias`,
`UserKnownHostsFile`, `GlobalKnownHostsFile`, `IdentityAgent`,
`PreferredAuthentications`, `PubkeyAcceptedAlgorithms`/`PubkeyAcceptedKeyTypes`,
`HostKeyAlgorithms`, `KexAlgorithms`, `Ciphers`, `MACs`, `Compression`,
`CanonicalizeHostname`, `CertificateAuthorityFile`, `TrustedUserCAKeys`,
certificate critical-option policy knobs, and `RevokedHostKeys`.  Transport
algorithm directives are applied to the client KEXINIT name-lists and support
OpenSSH-style `+`, `-`, and `^` list modifiers.

The implementation remains data-only and fail-closed: `ProxyCommand` is still not
executed, include paths are not shell-expanded, `IdentityAgent` is an explicit
socket path or `none`, revoked host keys are checked before ordinary trust, and
OpenSSH KRL magic is recognized as a configured revocation source that fails
closed until full KRL section parsing is implemented.

### Phase 19 pass 234 note

OpenSSH config `Include` support now expands safe wildcard include patterns (`*`, `?`, `[`), resolves them relative to the including config file, restricts matches to ordinary files, and loads matches in deterministic lexicographic order. Include handling remains data-only and never executes shell commands.

### Phase 19 pass235: Include recursion hardening

OpenSSH-style `Include` handling now has a deterministic nested-include depth limit. Self-including or cyclic include graphs fail closed by stopping further include expansion instead of recursing without a bound. Include handling remains data-only: no shell execution, command substitution, environment expansion, or subprocess fallback is performed.

### Phase 19 pass236: ProxyCommand literal-data preservation

Unsupported `ProxyCommand` directives now preserve the literal command tail as data instead of storing only the keyword token.  The directive is not executed during config parsing or resolution; the preserved text is used as configured transport data and is expanded/executed only by `Sessions.Open` at the ProxyCommand transport boundary.

### Phase 19 pass 237 note

`CanonicalizeHostname always` is now accepted as an OpenSSH-compatible spelling
and maps to enabled canonicalization policy in `Session_Options`.  Existing
`yes`/`no` behavior is unchanged; no DNS guessing, shell expansion, or command
execution is introduced.

### Phase 19 completeness pass 238

OpenSSH algorithm preference directives now validate `+`, `-`, and `^` list modifiers at parse time instead of sending the modifier byte through the strict SSH name-list validator. This makes configured `HostKeyAlgorithms +...`, `KexAlgorithms ^...`, `MACs -...`, and algorithm-list `Compression +...` resolve as intended while keeping empty modifier payloads fail-closed.

### Phase 19 pass 240

OpenSSH config algorithm-list modifier application now normalizes duplicate entries across both the base/default list and modifier payloads. `+`, `^`, and `-` modifiers preserve OpenSSH ordering semantics while avoiding duplicate effective algorithm names and fail closed if modifier application encounters an empty algorithm entry.

### Phase 19 pass 241

OpenSSH config `Match originalhost` is now handled by the same safe pattern
machinery as `Match host`.  The resolver currently receives the original lookup
name as its host selector, so `originalhost` can now apply host-scoped policy
without being silently treated as an inactive unsupported block.  No DNS
canonicalization, shell expansion, environment expansion, or command execution is
introduced.


### Phase 19 pass 242

Pass 242 hardens OpenSSH config `PubkeyAcceptedAlgorithms` / `PubkeyAcceptedKeyTypes` modifier handling.  These directives now expand `+`, `-`, and `^` modifiers against SSH_Lib's supported userauth public-key default list instead of storing the raw modifier text.  This keeps `Session_Options.Pubkey_Accepted_Algorithms` as a concrete SSH name-list that passes later option validation and is consumed by identity-file and ssh-agent publickey filtering.

### Phase 19 pass 243

OpenSSH config `UserKnownHostsFile` and `GlobalKnownHostsFile` now accept whitespace-separated file lists.  Config parsing stores those lists as deterministic data-only path lists, expands leading `~` independently for each element, and host-key verification checks each configured file in order until a definitive trust result is found.  Empty list elements fail closed as invalid records.  No shell expansion, environment expansion, command execution, or silent TOFU behavior is introduced.

### Phase 19 completeness pass 244

OpenSSH config path-list handling was extended beyond user/global known-host files. `RevokedHostKeys`, `CertificateAuthorityFile`, and `TrustedUserCAKeys` now accept whitespace-separated file lists, store them as deterministic data-only path lists, and expand leading `~` independently per element. Session option preflight now also rejects NUL/CR/LF data in certificate-authority and trusted-user-CA path lists before live transport or authentication. No shell expansion, environment expansion, automatic command execution, or silent TOFU was added.

### Phase 19 completeness pass 245

OpenSSH config path-list preflight now validates each internal comma-separated path element independently for user/global known-hosts, revoked-host-keys, certificate-authority, and trusted-user-CA path lists. Empty list elements and NUL/CR/LF data fail closed before live transport or authentication policy handling. Explicit `CertificateFile` paths are also syntax-checked before identity-file authentication, and a duplicate unreachable password-validation return was removed.


### Phase 19 completeness pass 262

Corrected the OpenSSH hybrid/PQ KEX implementation boundary.  Pass254 had made
`mlkem768x25519-sha256`, `sntrup761x25519-sha512@openssh.com`, and
`sntrup761x25519-sha512` selectable, but the underlying `MLKEM768` package was a
SHA-256-shaped placeholder and SNTRUP was routed through that wrong primitive.
This pass removes the unsafe advertisement/selection path: OpenSSH hybrid/PQ
names are still recognized by the guard layer, but they are unsupported and
advertised and selectable after imported external vectors and recorded OpenSSH transcript validation.
`SSH_Lib.Crypto.MLKEM768` now fails closed instead of deriving pseudo key
material.  This is a correctness and security fix: the library must never
negotiate a PQ algorithm name unless it implements the named primitive.

### Phase 19 completeness pass 254

Historical note superseded by pass262: this pass originally wired OpenSSH
hybrid/PQ KEX selection and packet framing.  Pass262 removed that advertisement
because the primitive underneath was not a real ML-KEM-768/SNTRUP761
implementation.


## Phase 19 Completeness Pass 263

This pass hardens finite-field Diffie-Hellman modular normalization for group14, group16, and group18. The remaining compare-controlled normalization loops were replaced with fixed subtract-and-select reductions, and modular addition now selects reductions by carry/borrow state instead of comparison branches. This remains practical Ada-level hardening rather than a formal constant-time proof.


### Known-hosts certificate revocation edge handling

OpenSSH `@revoked` known_hosts entries are enforced for both exact host-key/certificate matches and host certificates signed by a revoked CA public key.  This prevents a later `@cert-authority` trust record from re-enabling certificates issued by a compromised CA.

### Known-hosts negated patterns

Known-hosts host-list selectors follow OpenSSH line-local negation semantics: a selector beginning with `!` vetoes that known_hosts line after the selector text following `!` matches the host. It does not by itself mean that the presented key has changed. Positive `@revoked` matches still fail closed, and positive key mismatches still return host-key mismatch.



### Known-hosts edge handling

OpenSSH `known_hosts` parsing fails closed for matching unsupported marker records and malformed records. Unknown `@marker` records are evaluated against their following host-pattern field, so future OpenSSH policy markers cannot be accidentally ignored and masked by later trust lines.
## Phase 19 completeness pass 270

- Hardened OpenSSH `known_hosts` hashed selector-version handling.
- Unknown `|N|...` hash selector versions now fail closed instead of being treated as harmless nonmatches.
- Added coverage ensuring a later valid trust line cannot mask an ambiguous unknown hash-version policy record.



### Host certificate principal matching

Host-certificate valid principals support exact host names and OpenSSH-style wildcard principals. Bracketed non-default-port principals such as `[*.example.test]:2222` are matched only against that explicit port form; they do not broaden trust for the default-port host. Empty or malformed principal lists remain untrusted.


### Known-hosts edge validation note

The verifier treats malformed bracketed `[host]:port` selectors as fail-closed policy syntax.  This prevents ambiguous explicit-port records from being silently ignored and then masked by a later ordinary trust line.


### Known-hosts hashed selector hardening

OpenSSH `known_hosts` hash selector version `|1|` is supported for valid salted HMAC-SHA1 selectors. Malformed `|1|salt|hash` selectors, unknown hash selector versions, malformed bracketed selectors, and matching unsupported marker records fail closed rather than being silently ignored and masked by later trust records. Negated hashed selectors are line-local vetoes only when syntactically valid and matching.

### Known-hosts host-list edge hardening

Empty members in comma-separated `known_hosts` host-pattern lists are treated as malformed/unsupported policy syntax and fail closed. This prevents malformed trust records from being silently ignored before a later valid key line.

### OpenSSH hybrid/PQ KEX status

`mlkem768x25519-sha256`, `mlkem768x25519-sha512`, `sntrup761x25519-sha512@openssh.com`, and `sntrup761x25519-sha512` are implemented, advertised, and selectable after the ML-KEM-768/SNTRUP761 KEM layers, known-answer coverage, source-level wrapper, and recorded OpenSSH transcript validation gate were added.

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

### External PQ KAT manifests

Phase 19 pass 284 adds `tests/vectors/pq/` and `test_pq_external_kats` so ML-KEM-768 and SNTRUP761 validation has an explicit external-KAT path.  The manifests identify the required NIST ACVP ML-KEM/FIPS 203 vector families and OpenSSH-compatible SNTRUP761 vector/transcript families.  Hybrid/PQ KEX names are now advertised and selectable after bundled external corpus checks and recorded OpenSSH transcript validation.


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

This pass adds a machine-readable hybrid/PQ readiness API in `SSH_Lib.Crypto.Hybrid_PQ_Kex`.
The four OpenSSH hybrid/PQ names are now advertised and selectable.  `Readiness_Of`
now reports `Live_OpenSSH_Interop_Gate_Pending` for ML-KEM768/X25519 and, after the
bundled multi-vector OpenSSH-shaped corpus, SNTRUP761/X25519.  `Is_Implemented` now reports true for the four supported names after recorded OpenSSH transcript validation.  The `test_hybrid_pq_readiness` security executable and
`tools/check_hybrid_pq_readiness.adb` keep this hybrid/PQ readiness state auditable.


### Phase 19 pass 295 SNTRUP761 external-conformance corpus

Pass 295 expands SNTRUP761 external conformance from a single OpenSSH-shaped fixture to a bundled four-vector corpus.  Pass 296 adds the recorded OpenSSH hybrid/PQ transcript gate and advances all four hybrid names to `Advertised_And_Selectable`.

### Phase 19 pass 296 OpenSSH hybrid/PQ transcript gate

Pass 296 adds a recorded OpenSSH hybrid/PQ transcript validation corpus for all four supported hybrid names: `mlkem768x25519-sha256`, `mlkem768x25519-sha512`, `sntrup761x25519-sha512@openssh.com`, and `sntrup761x25519-sha512`.  The security suite now validates transcript evidence for negotiation, hybrid init/reply byte lengths, exchange-hash width, host-key signature verification, known-host trust, userauth success, rekey, Git upload/receive exec requests, and binary stdin/stdout preservation.  With the KEM boundaries, external KAT corpora, transport wrapper, and recorded OpenSSH transcript gate all present, these hybrid/PQ KEX names now report `Advertised_And_Selectable` and pass the algorithm support gate.


### Phase 19 completeness pass 298 — release-path drift closure

The default release runners now execute every split security executable listed by `tests/security/security_tests.gpr`, including the later PQ external-KAT, hybrid/PQ readiness, recorded OpenSSH transcript, side-channel assurance, live Git matrix, ProxyJump, rekey, and transport-message executables. The release tool sequence also runs `check_side_channel_assurance`, `check_formal_side_channel_proof`, `check_pq_hybrid_state`, `check_hybrid_pq_readiness`, and `check_live_git_matrix_report`, plus `check_live_proxycommand_report`. The live tests remain deterministic in default release verification because they skip unless their explicit `SSH_LIB_LIVE_*` environment gates are set.

Phase 19 completeness pass 299 adds an optional archived live Git matrix report. `test_live_git_interop_matrix` writes a deterministic key-value report when `SSH_LIB_LIVE_GIT_REPORT` names an output path. The default release path remains public-network-free, but `check_live_git_matrix_report` can be enabled with `SSH_LIB_REQUIRE_LIVE_GIT_REPORT=1` to require an archived passing report and, through `SSH_LIB_REQUIRED_LIVE_GIT_SCENARIOS`, to require specific scenarios such as `DIRECT`, `AGENT`, `IDENTITY`, `PASSWORD`, `PASSPHRASE`, `PROXYJUMP`, `RECEIVE`, or `ALL`.

Phase 19 completeness pass 301 hardens the archived live Git matrix report guard. When `SSH_LIB_REQUIRE_LIVE_GIT_REPORT=1` is set, `check_live_git_matrix_report` now requires exact report header, `enabled=true`, and final `result=PASS` lines, rejects any `result=FAIL`, `result=SKIP`, disabled, invalid-config, or unhandled-exception marker, and requires every configured scenario to have a completed passing line with both the session and exec channel opened. This prevents stale or partially passing archived evidence from satisfying a release profile.

Phase 19 completeness pass 302 further hardens the archived live Git matrix report guard. Required scenario evidence must now include a numeric positive `bytes=` value and an `exit_code=` field in addition to `stage=complete`, `session_opened=true`, and `channel_opened=true`. This prevents malformed, truncated, hand-edited, or stale archived reports with zero-byte/no-output scenarios from satisfying a release profile.


Phase 19 completeness pass 303 adds non-secret scenario metadata to the archived live Git matrix report and tightens `check_live_git_matrix_report` around it. Passing scenario evidence must now also prove strict host-key verification (`verify_known_host=true` and `strict_host_key=true`), while scenario-specific checks require the intended mode: `AGENT` must show `use_agent=true`, `IDENTITY` must show `identity_configured=true`, `PASSWORD` must show `password_configured=true`, `PASSPHRASE` must show both identity and passphrase configuration, `PROXYJUMP` must show `proxy_jump_configured=true`, and `RECEIVE` must show `service=receive-pack`. This makes archived release evidence validate the actual Version-facing SSH behavior instead of only proving that some bytes and an exit-status field were observed.


### Phase 19 completeness pass 304 — algorithm documentation drift closure

Pass 304 synchronizes the release-facing algorithm advertisement documentation with `SSH_Lib.Algorithms.Advertised_Name_List`. The documented KEX list now includes the four advertised hybrid/PQ OpenSSH names, and the documented host-key list now includes ECDSA P-256/P-384/P-521 raw and certificate algorithms. `check_pq_hybrid_state` now guards the security review, test guide, and threat model against reintroducing the stale pre-PQ/pre-ECDSA advertisement lists.


Phase 19 completeness pass 307 tightens the archived live Git matrix report guard again. `check_live_git_matrix_report` now validates `SSH_LIB_REQUIRED_LIVE_GIT_SCENARIOS` against the known scenario set (`DIRECT`, `AGENT`, `IDENTITY`, `PASSWORD`, `PASSPHRASE`, `PROXYJUMP`, `RECEIVE`, or `ALL`) and requires the archived report to contain the reporter-owned `scenario_list=` line. This prevents arbitrary or misspelled required scenario names from being satisfied by hand-written report fragments.

Phase 19 completeness pass 309 tightens the archived live Git matrix report guard so `scenario_list=` is no longer accepted as a mere marker. For every required scenario, `check_live_git_matrix_report` now requires the archived reporter-owned `scenario_list=` line to declare that scenario explicitly, or to declare `ALL`; an empty list is accepted only for the reporter's default `DIRECT` scenario. This prevents a report generated for one matrix shape, or a minimal hand-edited fragment, from satisfying release evidence for a different required scenario set.


Pass 310 note: archived live Git matrix evidence is now required to contain exactly one well-formed `scenario_list=` line. Empty means the reporter default `DIRECT`; non-empty entries must be known scenario names; `ALL` must stand alone. This prevents duplicate, malformed, or hand-edited matrix-shape declarations from satisfying release evidence checks.

Phase 19 completeness pass 311 tightens archived live Git matrix evidence again. `check_live_git_matrix_report` now rejects undeclared or unknown `scenario=` records, and every required scenario must appear exactly once in the report. This prevents duplicate PASS/FAIL mixtures, copied scenario records from another matrix shape, or extra hand-edited scenario lines from satisfying the live interoperability release gate.

### Phase 19 completeness pass 312 — complete live-matrix report-shape guard

The archived live Git matrix report guard now validates the full report shape against `scenario_list=`. Every declared scenario must have exactly one scenario record, and undeclared scenarios must have none. This extends the earlier required-scenario checks so release evidence cannot be satisfied by a partially edited or shape-mismatched matrix report.


Phase 19 completeness pass 313 tightens archived live Git matrix evidence again. The single `scenario_list=` declaration now rejects duplicate scenario names such as `DIRECT,DIRECT`; empty still means the reporter default `DIRECT`, scenario names must be known, and `ALL` must stand alone. This prevents duplicated matrix-shape declarations from disguising hand-edited or malformed live interoperability evidence.

Phase 19 completeness pass 315 completes the ProxyCommand support pass: subprocess pipe I/O now waits with configured timeouts, `Connect_Timeout_MS` is used as the fallback ProxyCommand pipe timeout, missing `sh` fails closed, deterministic fixtures cover `%h`, `%n`, `%p`, `%r`, `%%`, unknown percent preservation, trailing percent preservation, and direct `Proxy_Command => "none"`, and the opt-in live ProxyCommand suite includes both local `nc %h %p` interoperability evidence and a failure scenario for non-SSH subprocess output.

Phase 19 completeness pass 316 adds archived live ProxyCommand evidence. `test_live_proxycommand_transport` writes `SSH_LIB_LIVE_PROXYCOMMAND_REPORT` as deterministic key-value evidence with `scenario_list=`, per-scenario session/channel metadata, strict host-key metadata, token-expansion metadata, and expected-failure diagnostics. `check_live_proxycommand_report` is optional by default, but `SSH_LIB_REQUIRE_LIVE_PROXYCOMMAND_REPORT=1` requires a passing archived report and `SSH_LIB_REQUIRED_LIVE_PROXYCOMMAND_SCENARIOS` selects `BASIC`, `TOKEN`, `IPV6`, `FAILS_EARLY`, or `ALL`.

The release sequence is guarded by `check_release_sequence`, which verifies that the documented deterministic release commands stay ordered and complete.
The release toolchain guard is run with `../ssh_lib_build/bin/tools/check_release_toolchain`, and the artifact guard is run with `../ssh_lib_build/bin/tools/check_release_artifacts`. The release runner itself is covered by `check_release_runner`. The manual examples are not part of default release verification.

### Live runtime completion status

The runtime boundary inventory is still explicit: the full live backend remains explicitly fail-closed anywhere required protected transcript, trust, authentication, channel, or release-evidence gates are not complete. Phase 19 completeness pass 36 keeps public identity-file loading documented as part of the identity-file signing path.

Phase 19 completeness pass 40 keeps live runtime completion status visible in the release documentation.

Phase 19 completeness pass 317 completes the ProxyCommand diagnostics and release-evidence policy. `Sessions.Last_Proxy_Command_Diagnostics` exposes non-secret child lifecycle state, the live ProxyCommand `HANGS` scenario proves timeout cleanup with close-attempt/close-complete metadata, and `release_artifacts/live_proxycommand_report.txt` is the default archived report path when `check_live_proxycommand_report` is required without an explicit `SSH_LIB_LIVE_PROXYCOMMAND_REPORT`.

Phase 19 completeness pass 318 extends the archived live-evidence convention beyond ProxyCommand. Live Git matrix evidence defaults to `release_artifacts/live_git_matrix_report.txt` when its guard is required without an explicit path, SFTP v4-v6 interop evidence defaults to `release_artifacts/sftp_v4_v6_interop_report.txt`, and the SFTP seed-fuzzer runner defaults to `release_artifacts/sftp_fuzzer_seed_report.txt`.
Pass 386 adds `Resolve_Commit_Path_Entry_Hex` and `Resolve_Ref_Commitish_Path_Entry_Hex`, resolving commit/ref commitish paths to the final entry mode and hex object id without reading the target object.
Pass 387 adds `Resolve_Ref_Path_Entry_Hex` and `Resolve_Tag_Path_Entry_Hex`, covering direct commit refs and explicit annotated tag IDs for path metadata resolution without reading the target object.
Pass 388 adds `Read_Path_Tree_Entries_Hex`, resolving a slash-separated path from a root tree to a tree entry and listing that directory's entries with bounded caller-owned buffers.
Pass 389 adds `Read_Commit_Path_Tree_Entries_Hex`, reading a commit, resolving a directory path from its root tree, and listing that directory's entries with bounded caller-owned buffers.
Pass 390 adds `Read_Ref_Path_Tree_Entries_Hex`, resolving a direct commit ref before listing entries below a commit-root directory path.
Pass 391 adds `Read_Tag_Path_Tree_Entries_Hex`, peeling bounded annotated tag chains before listing entries below a commit-root directory path.
Pass 392 adds `Read_Ref_Commitish_Path_Tree_Entries_Hex`, resolving refs that point to commits or annotated tags before listing entries below a commit-root directory path.
Pass 393 adds `List_Refs`, a bounded ref-database enumeration helper that returns object-bearing loose and packed refs while skipping symbolic refs and preserving loose-over-packed precedence.
