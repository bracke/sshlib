with Ada.Containers.Vectors;
with Ada.Streams;
with Ada.Strings.Unbounded;
with Interfaces;
with CryptoLib.Errors;
with SSH_Lib.Protocol.Buffers;
with SSH_Lib.SCP;
with SSH_Lib.SFTP;
with SSH_Lib.Sessions;

--  @summary High-level SCP/SFTP file-transfer facade over an SSH session.
--
--  A single entry point for remote file management: it opens the SCP or SFTP
--  subsystem per operation, delegates to SSH_Lib.SCP / SSH_Lib.SFTP, and closes
--  the channel afterwards.  Offers byte/file/stream uploads and downloads,
--  resumable transfers, directory listing and recursion, attribute and symlink
--  operations, server-side copy/rename, and higher-level backup workflows
--  (upload, verify, delete, restore, and checksummed inventory manifests).
package SSH_Lib.File_Transfer is
   type Upload_Method is (Upload_Auto, Upload_SCP, Upload_SFTP);

   type Workflow_Operation is
     (Upload_Workflow,
      Verify_Workflow,
      Delete_Workflow,
      Restore_Workflow,
      Inventory_Workflow);

   type Delete_Target is
     (Delete_Auto, Delete_File, Delete_Directory, Delete_Tree);

   type Restore_Conflict_Policy is
     (Overwrite_Existing, Skip_Existing, Fail_If_Exists);

   type Inventory_Entry_Kind is
     (Inventory_File, Inventory_Directory, Inventory_Symlink, Inventory_Other);

   type Workflow_Result is record
      Operation        : Workflow_Operation := Upload_Workflow;
      Status           : CryptoLib.Errors.Status := CryptoLib.Errors.Ok;
      Remote_Path      : Ada.Strings.Unbounded.Unbounded_String;
      Local_Path       : Ada.Strings.Unbounded.Unbounded_String;
      Items_Processed  : Natural := 0;
      Bytes_Processed  : Interfaces.Unsigned_64 := 0;
      Verified         : Boolean := False;
      Digest_Algorithm : Ada.Strings.Unbounded.Unbounded_String;
      Digest           : SSH_Lib.Protocol.Buffers.Packet_Buffer;
   end record;

   type Inventory_Entry is record
      Path             : Ada.Strings.Unbounded.Unbounded_String;
      Kind             : Inventory_Entry_Kind := Inventory_Other;
      Attributes       : SSH_Lib.SFTP.File_Attributes;
      Link_Target      : Ada.Strings.Unbounded.Unbounded_String;
      Digest_Algorithm : Ada.Strings.Unbounded.Unbounded_String;
      Digest           : SSH_Lib.Protocol.Buffers.Packet_Buffer;
   end record;

   package Inventory_Entry_Vectors is new
     Ada.Containers.Vectors
       (Index_Type   => Natural,
        Element_Type => Inventory_Entry);

   type Inventory_Result is record
      Result  : Workflow_Result :=
        (Operation => Inventory_Workflow, others => <>);
      Entries : Inventory_Entry_Vectors.Vector;
   end record;

   --  Longest explicit or derived protocol filename accepted by the facade.
   Maximum_File_Name_Length : constant Natural :=
     SSH_Lib.SCP.Maximum_File_Name_Length;
   --  Longest remote path accepted by facade SCP and Upload_Auto uploads.
   Maximum_SCP_Remote_Path_Length : constant Natural :=
     SSH_Lib.SCP.Maximum_Remote_Path_Length;
   --  Longest composed SFTP remote path accepted by facade SFTP uploads.
   Maximum_SFTP_Remote_Path_Length : constant Natural :=
     SSH_Lib.SFTP.Maximum_Remote_Path_Length;
   --  Maximum bytes per streamed local-file channel write for facade SCP and
   --  Upload_Auto uploads.
   SCP_Upload_Chunk_Size : constant Natural := SSH_Lib.SCP.Upload_Chunk_Size;
   --  Maximum data bytes per SSH_FXP_WRITE request for facade SFTP uploads.
   SFTP_Upload_Chunk_Size : constant Natural := SSH_Lib.SFTP.Upload_Chunk_Size;

   --  Construct an SFTP transfer-tuning options record from named settings.
   --  @param Pipeline_Depth              the number of in-flight requests
   --  @param Retry_Count                 retries per failed request
   --  @param Verify_After_Transfer       re-read and verify after transfer
   --  @param Atomic_Upload               upload to a temp name then rename
   --  @param Read_Chunk_Size             bytes per local read
   --  @param Write_Chunk_Size            data bytes per SSH_FXP_WRITE
   --  @param Adaptive_Chunking           adjust chunk size to conditions
   --  @param Minimum_Adaptive_Chunk_Size floor for adaptive chunk sizing
   --  @return the assembled transfer options
   function SFTP_Transfer_Options
     (Pipeline_Depth        : Positive := SSH_Lib.SFTP.Default_Pipeline_Depth;
      Retry_Count           : Natural := 0;
      Verify_After_Transfer : Boolean := False;
      Atomic_Upload               : Boolean := False;
      Read_Chunk_Size             : Positive := SSH_Lib.SFTP.Upload_Chunk_Size;
      Write_Chunk_Size            : Positive := SSH_Lib.SFTP.Upload_Chunk_Size;
      Adaptive_Chunking           : Boolean := False;
      Minimum_Adaptive_Chunk_Size : Positive := 4 * 1024)
      return SSH_Lib.SFTP.Transfer_Options;

   --  First-class SFTP-backed file-management workflows. These wrappers use
   --  exact remote paths, return typed workflow diagnostics, and delegate to
   --  the lower-level upload/download/remove/list/stat helpers.

   --  Upload a local file or (when Recursive) tree to a remote path.
   --  @param Session        the session to transfer over
   --  @param Local_Path     the local source file or directory
   --  @param Remote_Path    the exact remote destination path
   --  @param Recursive      when True, upload a directory tree
   --  @param Directory_Mode octal mode for created remote directories
   --  @param File_Mode      octal mode for uploaded files
   --  @param Options        recursion options (filter, progress, policy)
   --  @param Transfer       transfer-tuning options
   --  @return the workflow result (status and transfer counters)
   function Upload
     (Session        : in out SSH_Lib.Sessions.Session;
      Local_Path     : String;
      Remote_Path    : String;
      Recursive      : Boolean := False;
      Directory_Mode : String := "0755";
      File_Mode      : String := "0644";
      Options        : SSH_Lib.SFTP.Recursive_Options :=
        SSH_Lib.SFTP.Default_Recursive_Options;
      Transfer       : SSH_Lib.SFTP.Transfer_Options :=
        SSH_Lib.SFTP.Default_Transfer_Options)
      return Workflow_Result;

   --  Verify a remote file's integrity by size and/or server-side checksum.
   --  @param Session       the session to query over
   --  @param Remote_Path   the remote file to verify
   --  @param Expected_Size the expected byte size (used when Check_Size)
   --  @param Check_Size    when True, compare the file size to Expected_Size
   --  @param Algorithms    comma-separated checksum algorithms ("" to skip)
   --  @param Offset        starting byte offset for a ranged checksum
   --  @param Length        number of bytes to checksum (0 = to end of file)
   --  @param Block_Size    per-block checksum size (0 = whole-file digest)
   --  @return the workflow result (Verified flag, digest, and status)
   function Verify
     (Session       : in out SSH_Lib.Sessions.Session;
      Remote_Path   : String;
      Expected_Size : Interfaces.Unsigned_64 := 0;
      Check_Size    : Boolean := False;
      Algorithms    : String := "";
      Offset        : Interfaces.Unsigned_64 := 0;
      Length        : Interfaces.Unsigned_64 := 0;
      Block_Size    : Interfaces.Unsigned_32 := 0)
      return Workflow_Result;

   --  Delete a remote file, directory, or tree per the chosen target kind.
   --  @param Session     the session to operate over
   --  @param Remote_Path the remote path to delete
   --  @param Target      what to delete (auto-detect, file, dir, or tree)
   --  @param Options     recursion options used for tree deletion
   --  @return the workflow result (status and item counts)
   function Delete
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Target      : Delete_Target := Delete_Auto;
      Options     : SSH_Lib.SFTP.Recursive_Options :=
        SSH_Lib.SFTP.Default_Recursive_Options)
      return Workflow_Result;

   --  Restore (download) a remote file or tree to a local path under a policy.
   --  @param Session     the session to transfer over
   --  @param Remote_Path the remote source path
   --  @param Local_Path  the local destination path
   --  @param Recursive   when True, restore a directory tree
   --  @param Policy      how to handle existing local files
   --  @param Options     recursion options (filter, progress, policy)
   --  @param Transfer    transfer-tuning options
   --  @return the workflow result (status and transfer counters)
   function Restore
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Local_Path  : String;
      Recursive   : Boolean := False;
      Policy      : Restore_Conflict_Policy := Overwrite_Existing;
      Options     : SSH_Lib.SFTP.Recursive_Options :=
        SSH_Lib.SFTP.Default_Recursive_Options;
      Transfer    : SSH_Lib.SFTP.Transfer_Options :=
        SSH_Lib.SFTP.Default_Transfer_Options)
      return Workflow_Result;

   --  Enumerate a remote path into an inventory of entries (no checksums).
   --  @param Session     the session to query over
   --  @param Remote_Path the remote path to inventory
   --  @param Recursive   when True, descend into subdirectories
   --  @return the inventory result (entries plus workflow status)
   function Inventory
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Recursive   : Boolean := False)
      return Inventory_Result;

   --  Enumerate a remote path and compute a checksum per file entry.
   --  @param Session     the session to query over
   --  @param Remote_Path the remote path to inventory
   --  @param Recursive   when True, descend into subdirectories
   --  @param Algorithms  comma-separated checksum algorithms to record
   --  @param Block_Size  per-block checksum size (0 = whole-file digest)
   --  @return the inventory result with per-entry digests
   function Inventory_With_Checks
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Recursive   : Boolean := False;
      Algorithms  : String := "sha256";
      Block_Size  : Interfaces.Unsigned_32 := 0)
      return Inventory_Result;

   --  Serialize an inventory result into a textual manifest.
   --  @param Inventory the inventory result to render
   --  @return the manifest text
   function Inventory_Manifest
     (Inventory : Inventory_Result)
      return Ada.Strings.Unbounded.Unbounded_String;

   --  Parse a textual manifest back into an inventory result.
   --  @param Manifest  the manifest text to parse
   --  @param Inventory the reconstructed inventory result
   --  @return Ok on success, else a failure Status on malformed input
   function Parse_Inventory_Manifest
     (Manifest  : String;
      Inventory : out Inventory_Result) return CryptoLib.Errors.Status;

   --  Verify remote files under Remote_Path against a stored manifest.
   --  @param Session     the session to query over
   --  @param Manifest    the manifest text describing expected files/digests
   --  @param Remote_Path the remote root to check against the manifest
   --  @param Recursive   when True, verify the whole tree
   --  @return the workflow result (Verified flag and status)
   function Verify_Inventory
     (Session     : in out SSH_Lib.Sessions.Session;
      Manifest    : String;
      Remote_Path : String;
      Recursive   : Boolean := True)
      return Workflow_Result;

   --  Restore files described by an inventory from a remote root to a local
   --  root under a conflict policy.
   --  @param Session     the session to transfer over
   --  @param Inventory   the inventory listing the files to restore
   --  @param Source_Root the remote root the inventory paths are relative to
   --  @param Local_Root  the local root to restore into
   --  @param Policy      how to handle existing local files
   --  @param Transfer    transfer-tuning options
   --  @return the workflow result (status and transfer counters)
   function Restore_From_Inventory
     (Session     : in out SSH_Lib.Sessions.Session;
      Inventory   : Inventory_Result;
      Source_Root : String;
      Local_Root  : String;
      Policy      : Restore_Conflict_Policy := Overwrite_Existing;
      Transfer    : SSH_Lib.SFTP.Transfer_Options :=
        SSH_Lib.SFTP.Default_Transfer_Options)
      return Workflow_Result;

   --  Restore files described by a manifest string from a remote root to a
   --  local root under a conflict policy.
   --  @param Session     the session to transfer over
   --  @param Manifest    the manifest text describing files to restore
   --  @param Source_Root the remote root the manifest paths are relative to
   --  @param Local_Root  the local root to restore into
   --  @param Policy      how to handle existing local files
   --  @param Transfer    transfer-tuning options
   --  @return the workflow result (status and transfer counters)
   function Restore_From_Manifest
     (Session     : in out SSH_Lib.Sessions.Session;
      Manifest    : String;
      Source_Root : String;
      Local_Root  : String;
      Policy      : Restore_Conflict_Policy := Overwrite_Existing;
      Transfer    : SSH_Lib.SFTP.Transfer_Options :=
        SSH_Lib.SFTP.Default_Transfer_Options)
      return Workflow_Result;

   --  Construct an SFTP recursive-operation options record from named settings.
   --  @param Preserve_Attributes copy source permissions and timestamps
   --  @param Filter              optional per-entry include/exclude callback
   --  @param Progress            optional progress-reporting callback
   --  @param Continue_On_Error   keep going past per-entry failures
   --  @param Overwrite_Files     overwrite existing destination files
   --  @param Follow_Symlinks     descend through symlinked directories
   --  @param Skip_Unchanged      skip entries whose size/mtime are unchanged
   --  @return the assembled recursive options
   function SFTP_Recursive_Options
     (Preserve_Attributes : Boolean := False;
      Filter              : SSH_Lib.SFTP.Recursive_Filter_Access := null;
      Progress            : SSH_Lib.SFTP.Recursive_Progress_Access := null;
      Continue_On_Error   : Boolean := False;
      Overwrite_Files     : Boolean := True;
      Follow_Symlinks     : Boolean := False;
      Skip_Unchanged      : Boolean := False)
      return SSH_Lib.SFTP.Recursive_Options;

   --  Upload one regular-file byte array. Upload_Auto currently selects SCP.
   --  File_Name must be a single protocol filename: non-empty, not "." or
   --  "..", no '/', NUL, CR, or LF, and no longer than
   --  Maximum_File_Name_Length. SCP uses File_Name as the protocol
   --  filename; SFTP uploads to Remote_Path/File_Name and preflights the
   --  composed path against Maximum_SFTP_Remote_Path_Length. SCP and
   --  Upload_Auto remote paths are limited by Maximum_SCP_Remote_Path_Length.
   --  @param Session      the session to upload over
   --  @param Remote_Path  the remote directory path
   --  @param File_Name    the single protocol filename to create
   --  @param Data         the file contents to upload
   --  @param Mode         the octal file mode to set
   --  @param Method       the transport to use (auto, SCP, or SFTP)
   --  @param SFTP_Options transfer-tuning options for the SFTP path
   --  @return Ok on success, else a failure Status
   function Upload_Data
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      File_Name   : String;
      Data        : Ada.Streams.Stream_Element_Array;
      Mode        : String := "0644";
      Method      : Upload_Method := Upload_Auto;
      SFTP_Options : SSH_Lib.SFTP.Transfer_Options :=
        SSH_Lib.SFTP.Default_Transfer_Options)
      return CryptoLib.Errors.Status;

   --  Stream one local regular file to Remote_Path. Upload_Auto currently
   --  selects SCP. SCP derives the protocol filename from Local_Path; SFTP
   --  uploads to Remote_Path/simple-name(Local_Path) and preflights the
   --  composed path against Maximum_SFTP_Remote_Path_Length. SCP and
   --  Upload_Auto remote paths are limited by Maximum_SCP_Remote_Path_Length.
   --  The derived simple name follows the same filename validation rules as
   --  explicit File_Name overloads. Streamed SCP writes use at most
   --  SCP_Upload_Chunk_Size bytes; streamed SFTP writes use at most
   --  SFTP_Upload_Chunk_Size data bytes per request.
   --  @param Session      the session to upload over
   --  @param Remote_Path  the remote directory path
   --  @param Local_Path   the local file to stream
   --  @param Mode         the octal file mode to set
   --  @param Method       the transport to use (auto, SCP, or SFTP)
   --  @param SFTP_Options transfer-tuning options for the SFTP path
   --  @return Ok on success, else a failure Status
   function Upload_File
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Local_Path  : String;
      Mode        : String := "0644";
      Method      : Upload_Method := Upload_Auto;
      SFTP_Options : SSH_Lib.SFTP.Transfer_Options :=
        SSH_Lib.SFTP.Default_Transfer_Options)
      return CryptoLib.Errors.Status;

   --  Stream one local regular file with an explicit remote filename. File_Name
   --  must be a single protocol filename: non-empty, not "." or "..", no
   --  '/', NUL, CR, or LF, and no longer than
   --  Maximum_File_Name_Length. SCP uses File_Name as the protocol
   --  filename; SFTP uploads to Remote_Path/File_Name and preflights the
   --  composed path against Maximum_SFTP_Remote_Path_Length. SCP and
   --  Upload_Auto remote paths are limited by Maximum_SCP_Remote_Path_Length.
   --  Streamed SCP writes use at most SCP_Upload_Chunk_Size bytes; streamed
   --  SFTP writes use at most SFTP_Upload_Chunk_Size data bytes per request.
   --  @param Session      the session to upload over
   --  @param Remote_Path  the remote directory path
   --  @param Local_Path   the local file to stream
   --  @param File_Name    the explicit single protocol filename to create
   --  @param Mode         the octal file mode to set
   --  @param Method       the transport to use (auto, SCP, or SFTP)
   --  @param SFTP_Options transfer-tuning options for the SFTP path
   --  @return Ok on success, else a failure Status
   function Upload_File
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Local_Path  : String;
      File_Name   : String;
      Mode        : String := "0644";
      Method      : Upload_Method := Upload_Auto;
      SFTP_Options : SSH_Lib.SFTP.Transfer_Options :=
        SSH_Lib.SFTP.Default_Transfer_Options)
      return CryptoLib.Errors.Status;

   --  SFTP-backed facade operations. These open the SFTP subsystem for the
   --  operation, delegate to SSH_Lib.SFTP, and close the channel afterwards.

   --  Download a whole remote file into an in-memory buffer.
   --  @param Session     the session to transfer over
   --  @param Remote_Path the remote file to download
   --  @param Data        receives the downloaded file contents
   --  @param Options     transfer-tuning options
   --  @return Ok on success, else a failure Status
   function Download_Data
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Data        : out SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Options     : SSH_Lib.SFTP.Transfer_Options :=
        SSH_Lib.SFTP.Default_Transfer_Options)
      return CryptoLib.Errors.Status;

   --  Upload a remote file whose bytes are produced by a stream reader.
   --  @param Session     the session to transfer over
   --  @param Remote_Path the remote destination path
   --  @param Size        the total number of bytes to upload
   --  @param Reader      the callback that supplies successive data chunks
   --  @param Mode        the octal file mode to set
   --  @param Options     transfer-tuning options
   --  @return Ok on success, else a failure Status
   function Upload_Stream
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Size        : Interfaces.Unsigned_64;
      Reader      : SSH_Lib.SFTP.Stream_Reader_Access;
      Mode        : String := "0644";
      Options     : SSH_Lib.SFTP.Transfer_Options :=
        SSH_Lib.SFTP.Default_Transfer_Options)
      return CryptoLib.Errors.Status;

   --  Download a remote file, delivering its bytes to a stream writer.
   --  @param Session     the session to transfer over
   --  @param Remote_Path the remote file to download
   --  @param Writer      the callback that consumes successive data chunks
   --  @param Options     transfer-tuning options
   --  @return Ok on success, else a failure Status
   function Download_Stream
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Writer      : SSH_Lib.SFTP.Stream_Writer_Access;
      Options     : SSH_Lib.SFTP.Transfer_Options :=
        SSH_Lib.SFTP.Default_Transfer_Options)
      return CryptoLib.Errors.Status;

   --  Download a remote file to a local file path.
   --  @param Session     the session to transfer over
   --  @param Remote_Path the remote file to download
   --  @param Local_Path  the local destination file path
   --  @param Options     transfer-tuning options
   --  @return Ok on success, else a failure Status
   function Download_File
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Local_Path  : String;
      Options     : SSH_Lib.SFTP.Transfer_Options :=
        SSH_Lib.SFTP.Default_Transfer_Options)
      return CryptoLib.Errors.Status;

   --  Resume a partial download, appending only the missing tail bytes.
   --  @param Session     the session to transfer over
   --  @param Remote_Path the remote file to download
   --  @param Local_Path  the partially downloaded local file to extend
   --  @param Options     transfer-tuning options
   --  @return Ok on success, else a failure Status
   function Resume_Download_File
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Local_Path  : String;
      Options     : SSH_Lib.SFTP.Transfer_Options :=
        SSH_Lib.SFTP.Default_Transfer_Options)
      return CryptoLib.Errors.Status;

   --  Resume a partial upload, sending only the missing tail bytes.
   --  @param Session     the session to transfer over
   --  @param Remote_Path the remote file to extend
   --  @param Local_Path  the local source file
   --  @param Mode        the octal file mode to set on completion
   --  @param Options     transfer-tuning options
   --  @return Ok on success, else a failure Status
   function Resume_Upload_File
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Local_Path  : String;
      Mode        : String := "0644";
      Options     : SSH_Lib.SFTP.Transfer_Options :=
        SSH_Lib.SFTP.Default_Transfer_Options)
      return CryptoLib.Errors.Status;

   --  List a remote directory as a newline-separated set of entry names.
   --  @param Session     the session to query over
   --  @param Remote_Path the remote directory to list
   --  @param Names       receives the entry names
   --  @return Ok on success, else a failure Status
   function List_Directory
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Names       : out Ada.Strings.Unbounded.Unbounded_String)
      return CryptoLib.Errors.Status;

   --  List a remote directory as a vector of entries with attributes.
   --  @param Session     the session to query over
   --  @param Remote_Path the remote directory to list
   --  @param Entries     receives the directory entries (name plus attributes)
   --  @return Ok on success, else a failure Status
   function List_Directory
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Entries     : out SSH_Lib.SFTP.Directory_Entry_Vectors.Vector)
      return CryptoLib.Errors.Status;

   --  List a remote directory, delivering entries page by page to a callback.
   --  @param Session     the session to query over
   --  @param Remote_Path the remote directory to list
   --  @param Callback    the callback invoked with each page of entries
   --  @return Ok on success, else a failure Status
   function List_Directory_Paged
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Callback    : SSH_Lib.SFTP.Directory_Page_Callback_Access)
      return CryptoLib.Errors.Status;

   --  Stat a remote path, following symlinks.
   --  @param Session     the session to query over
   --  @param Remote_Path the remote path to stat
   --  @param Attributes  receives the file attributes
   --  @return Ok on success, else a failure Status
   function Stat
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Attributes  : out SSH_Lib.SFTP.File_Attributes)
      return CryptoLib.Errors.Status;

   --  Stat a remote path without following a final symlink (lstat).
   --  @param Session     the session to query over
   --  @param Remote_Path the remote path to stat
   --  @param Attributes  receives the file attributes of the link itself
   --  @return Ok on success, else a failure Status
   function LStat
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Attributes  : out SSH_Lib.SFTP.File_Attributes)
      return CryptoLib.Errors.Status;

   --  Resolve a remote path to its canonical absolute form (realpath).
   --  @param Session        the session to query over
   --  @param Remote_Path    the remote path to canonicalize
   --  @param Canonical_Path receives the canonical absolute path
   --  @return Ok on success, else a failure Status
   function Realpath
     (Session        : in out SSH_Lib.Sessions.Session;
      Remote_Path    : String;
      Canonical_Path : out Ada.Strings.Unbounded.Unbounded_String)
      return CryptoLib.Errors.Status;

   --  Set a remote path's permission bits from an octal mode string.
   --  @param Session     the session to operate over
   --  @param Remote_Path the remote path to modify
   --  @param Mode        the octal permission mode to set
   --  @return Ok on success, else a failure Status
   function Set_Permissions
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Mode        : String)
      return CryptoLib.Errors.Status;

   --  Set a remote path's full attribute set (setstat), following symlinks.
   --  @param Session     the session to operate over
   --  @param Remote_Path the remote path to modify
   --  @param Attributes  the attributes to apply
   --  @return Ok on success, else a failure Status
   function Set_Attributes
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Attributes  : SSH_Lib.SFTP.File_Attributes)
      return CryptoLib.Errors.Status;

   --  Create a remote directory with the given octal mode.
   --  @param Session     the session to operate over
   --  @param Remote_Path the remote directory path to create
   --  @param Mode        the octal directory mode to set
   --  @return Ok on success, else a failure Status
   function Make_Directory
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Mode        : String := "0755")
      return CryptoLib.Errors.Status;

   --  Remove an empty remote directory.
   --  @param Session     the session to operate over
   --  @param Remote_Path the remote directory to remove
   --  @return Ok on success, else a failure Status
   function Remove_Directory
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String)
      return CryptoLib.Errors.Status;

   --  Remove a remote regular file.
   --  @param Session     the session to operate over
   --  @param Remote_Path the remote file to remove
   --  @return Ok on success, else a failure Status
   function Remove_File
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String)
      return CryptoLib.Errors.Status;

   --  Recursively upload a local directory tree to a remote directory.
   --  @param Session        the session to transfer over
   --  @param Remote_Path    the remote destination directory
   --  @param Local_Path     the local source directory
   --  @param Directory_Mode octal mode for created remote directories
   --  @param File_Mode      octal mode for uploaded files
   --  @param Options        recursion options (filter, progress, policy)
   --  @return Ok on success, else a failure Status
   function Upload_Directory
     (Session        : in out SSH_Lib.Sessions.Session;
      Remote_Path    : String;
      Local_Path     : String;
      Directory_Mode : String := "0755";
      File_Mode      : String := "0644";
      Options        : SSH_Lib.SFTP.Recursive_Options :=
        SSH_Lib.SFTP.Default_Recursive_Options)
      return CryptoLib.Errors.Status;

   --  Recursively download a remote directory tree to a local directory.
   --  @param Session     the session to transfer over
   --  @param Remote_Path the remote source directory
   --  @param Local_Path  the local destination directory
   --  @param Options     recursion options (filter, progress, policy)
   --  @return Ok on success, else a failure Status
   function Download_Directory
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Local_Path  : String;
      Options     : SSH_Lib.SFTP.Recursive_Options :=
        SSH_Lib.SFTP.Default_Recursive_Options)
      return CryptoLib.Errors.Status;

   --  Recursively remove a remote directory tree.
   --  @param Session     the session to operate over
   --  @param Remote_Path the remote tree root to remove
   --  @param Options     recursion options (filter, progress, policy)
   --  @return Ok on success, else a failure Status
   function Remove_Tree
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Options     : SSH_Lib.SFTP.Recursive_Options :=
        SSH_Lib.SFTP.Default_Recursive_Options)
      return CryptoLib.Errors.Status;

   --  Recursively copy one remote tree to another remote location.
   --  @param Session            the session to operate over
   --  @param Source_Remote_Path the remote source tree root
   --  @param Target_Remote_Path the remote destination tree root
   --  @param Directory_Mode     octal mode for created directories
   --  @param File_Mode          octal mode for copied files
   --  @param Options            recursion options (filter, progress, policy)
   --  @return Ok on success, else a failure Status
   function Copy_Tree
     (Session             : in out SSH_Lib.Sessions.Session;
      Source_Remote_Path  : String;
      Target_Remote_Path  : String;
      Directory_Mode      : String := "0755";
      File_Mode           : String := "0644";
      Options             : SSH_Lib.SFTP.Recursive_Options :=
        SSH_Lib.SFTP.Default_Recursive_Options)
      return CryptoLib.Errors.Status;

   --  Rename or move a remote path (SSH_FXP_RENAME).
   --  @param Session  the session to operate over
   --  @param Old_Path the existing remote path
   --  @param New_Path the new remote path
   --  @return Ok on success, else a failure Status
   function Rename
     (Session  : in out SSH_Lib.Sessions.Session;
      Old_Path : String;
      New_Path : String)
      return CryptoLib.Errors.Status;

   --  Atomically rename a remote path, replacing any existing target
   --  (posix-rename@openssh.com).
   --  @param Session  the session to operate over
   --  @param Old_Path the existing remote path
   --  @param New_Path the new remote path (overwritten if it exists)
   --  @return Ok on success, else a failure Status
   function Posix_Rename
     (Session  : in out SSH_Lib.Sessions.Session;
      Old_Path : String;
      New_Path : String)
      return CryptoLib.Errors.Status;

   --  Create a hard link to a remote file (hardlink@openssh.com).
   --  @param Session  the session to operate over
   --  @param Old_Path the existing remote file to link to
   --  @param New_Path the new hard-link path
   --  @return Ok on success, else a failure Status
   function Hardlink
     (Session  : in out SSH_Lib.Sessions.Session;
      Old_Path : String;
      New_Path : String)
      return CryptoLib.Errors.Status;

   --  Set attributes on a remote path without following a final symlink
   --  (lsetstat).
   --  @param Session     the session to operate over
   --  @param Remote_Path the remote path (or link) to modify
   --  @param Attributes  the attributes to apply
   --  @return Ok on success, else a failure Status
   function LSet_Attributes
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Attributes  : SSH_Lib.SFTP.File_Attributes)
      return CryptoLib.Errors.Status;

   --  Query filesystem statistics for the volume holding a remote path
   --  (statvfs@openssh.com).
   --  @param Session     the session to query over
   --  @param Remote_Path a remote path on the target filesystem
   --  @param Stats       receives the filesystem statistics
   --  @return Ok on success, else a failure Status
   function StatVFS
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Stats       : out SSH_Lib.SFTP.File_System_Stats)
      return CryptoLib.Errors.Status;

   --  Query the server's advertised protocol limits (limits@openssh.com).
   --  @param Session the session to query over
   --  @param Values  receives the server limits
   --  @return Ok on success, else a failure Status
   function Limits
     (Session : in out SSH_Lib.Sessions.Session;
      Values  : out SSH_Lib.SFTP.Server_Limits)
      return CryptoLib.Errors.Status;

   --  Send a raw SSH_FXP_EXTENDED request and return the extended reply.
   --  @param Session        the session to operate over
   --  @param Extension_Name the extension name to invoke
   --  @param Payload        the extension-specific request payload
   --  @param Reply_Data     receives the extension reply payload
   --  @return Ok on success, else a failure Status
   function Extended_Request
     (Session        : in out SSH_Lib.Sessions.Session;
      Extension_Name : String;
      Payload        : Ada.Streams.Stream_Element_Array;
      Reply_Data     : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;

   --  Read the target of a remote symbolic link (readlink).
   --  @param Session     the session to query over
   --  @param Remote_Path the remote symlink to read
   --  @param Target_Path receives the link's target path
   --  @return Ok on success, else a failure Status
   function Read_Link
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Target_Path : out Ada.Strings.Unbounded.Unbounded_String)
      return CryptoLib.Errors.Status;

   --  Create a remote symbolic link.
   --  @param Session     the session to operate over
   --  @param Target_Path the path the new link points to
   --  @param Link_Path   the remote symlink path to create
   --  @return Ok on success, else a failure Status
   function Create_Symlink
     (Session     : in out SSH_Lib.Sessions.Session;
      Target_Path : String;
      Link_Path   : String)
      return CryptoLib.Errors.Status;

   --  Read Length bytes from a remote file starting at Offset.
   --  @param Session     the session to transfer over
   --  @param Remote_Path the remote file to read
   --  @param Offset      the starting byte offset
   --  @param Length      the number of bytes to read
   --  @param Data        receives the bytes read
   --  @return Ok on success, else a failure Status
   function Read_At
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Offset      : Interfaces.Unsigned_64;
      Length      : Natural;
      Data        : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;

   --  Write bytes to a remote file at a given offset, creating it if needed.
   --  @param Session     the session to transfer over
   --  @param Remote_Path the remote file to write
   --  @param Offset      the starting byte offset
   --  @param Data        the bytes to write
   --  @param Mode        the octal file mode used if the file is created
   --  @return Ok on success, else a failure Status
   function Write_At
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Offset      : Interfaces.Unsigned_64;
      Data        : Ada.Streams.Stream_Element_Array;
      Mode        : String := "0644")
      return CryptoLib.Errors.Status;

   --  Stat a remote file through an open handle (SSH_FXP_FSTAT).
   --  @param Session     the session to query over
   --  @param Remote_Path the remote file to open and stat
   --  @param Attributes  receives the file attributes
   --  @return Ok on success, else a failure Status
   function FStat
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Attributes  : out SSH_Lib.SFTP.File_Attributes)
      return CryptoLib.Errors.Status;

   --  Set a remote file's permissions through an open handle (SSH_FXP_FSETSTAT).
   --  @param Session     the session to operate over
   --  @param Remote_Path the remote file to open and modify
   --  @param Mode        the octal permission mode to set
   --  @return Ok on success, else a failure Status
   function Set_Handle_Permissions
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Mode        : String)
      return CryptoLib.Errors.Status;

   --  Set a remote file's attributes through an open handle (SSH_FXP_FSETSTAT).
   --  @param Session     the session to operate over
   --  @param Remote_Path the remote file to open and modify
   --  @param Attributes  the attributes to apply
   --  @return Ok on success, else a failure Status
   function Set_Handle_Attributes
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Attributes  : SSH_Lib.SFTP.File_Attributes)
      return CryptoLib.Errors.Status;

   --  Flush a remote file's buffers to stable storage (fsync@openssh.com).
   --  @param Session     the session to operate over
   --  @param Remote_Path the remote file to fsync
   --  @return Ok on success, else a failure Status
   function Fsync
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String)
      return CryptoLib.Errors.Status;

   --  Expand a remote path server-side (expand-path@openssh.com), e.g. "~".
   --  @param Session       the session to query over
   --  @param Remote_Path   the remote path to expand
   --  @param Expanded_Path receives the expanded path
   --  @return Ok on success, else a failure Status
   function Expand_Path
     (Session       : in out SSH_Lib.Sessions.Session;
      Remote_Path   : String;
      Expanded_Path : out Ada.Strings.Unbounded.Unbounded_String)
      return CryptoLib.Errors.Status;

   --  Compute a server-side checksum of a remote file or byte range
   --  (check-file@openssh.com).
   --  @param Session     the session to query over
   --  @param Remote_Path the remote file to checksum
   --  @param Algorithms  comma-separated candidate checksum algorithm names
   --  @param Offset      the starting byte offset
   --  @param Length      the number of bytes to checksum (0 = to end)
   --  @param Block_Size  per-block checksum size (0 = whole-file digest)
   --  @param Algorithm   receives the algorithm the server actually used
   --  @param Digest      receives the computed digest(s)
   --  @return Ok on success, else a failure Status
   function Check_File
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Algorithms  : String;
      Offset      : Interfaces.Unsigned_64;
      Length      : Interfaces.Unsigned_64;
      Block_Size  : Interfaces.Unsigned_32;
      Algorithm   : out Ada.Strings.Unbounded.Unbounded_String;
      Digest      : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;

   --  Synchronize a directory in the given direction (upload or download),
   --  transferring only differing entries.
   --  @param Session        the session to transfer over
   --  @param Direction      the sync direction (local->remote or remote->local)
   --  @param Remote_Path    the remote directory
   --  @param Local_Path     the local directory
   --  @param Directory_Mode octal mode for created directories
   --  @param File_Mode      octal mode for created files
   --  @param Options        sync options (deletion, comparison, filters)
   --  @return Ok on success, else a failure Status
   function Sync_Directory
     (Session        : in out SSH_Lib.Sessions.Session;
      Direction      : SSH_Lib.SFTP.Sync_Direction;
      Remote_Path    : String;
      Local_Path     : String;
      Directory_Mode : String := "0755";
      File_Mode      : String := "0644";
      Options        : SSH_Lib.SFTP.Sync_Options :=
        SSH_Lib.SFTP.Default_Sync_Options)
      return CryptoLib.Errors.Status;

   --  Server-side copy a byte range from one remote file into another
   --  (copy-data@openssh.com), without round-tripping data through the client.
   --  @param Session            the session to operate over
   --  @param Source_Remote_Path the remote source file
   --  @param Target_Remote_Path the remote destination file
   --  @param Source_Offset      the starting offset in the source
   --  @param Length             the number of bytes to copy
   --  @param Target_Offset      the starting offset in the destination
   --  @param Mode               the octal mode used if the target is created
   --  @return Ok on success, else a failure Status
   function Copy_File_Range
     (Session            : in out SSH_Lib.Sessions.Session;
      Source_Remote_Path : String;
      Target_Remote_Path : String;
      Source_Offset      : Interfaces.Unsigned_64;
      Length             : Interfaces.Unsigned_64;
      Target_Offset      : Interfaces.Unsigned_64 := 0;
      Mode               : String := "0644")
      return CryptoLib.Errors.Status;
end SSH_Lib.File_Transfer;
