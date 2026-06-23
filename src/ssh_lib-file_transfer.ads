with Ada.Containers.Vectors;
with Ada.Streams;
with Ada.Strings.Unbounded;
with Interfaces;
with CryptoLib.Errors;
with SSH_Lib.Protocol.Buffers;
with SSH_Lib.SCP;
with SSH_Lib.SFTP;
with SSH_Lib.Sessions;

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

   function Delete
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Target      : Delete_Target := Delete_Auto;
      Options     : SSH_Lib.SFTP.Recursive_Options :=
        SSH_Lib.SFTP.Default_Recursive_Options)
      return Workflow_Result;

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

   function Inventory
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Recursive   : Boolean := False)
      return Inventory_Result;

   function Inventory_With_Checks
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Recursive   : Boolean := False;
      Algorithms  : String := "sha256";
      Block_Size  : Interfaces.Unsigned_32 := 0)
      return Inventory_Result;

   function Inventory_Manifest
     (Inventory : Inventory_Result)
      return Ada.Strings.Unbounded.Unbounded_String;

   function Parse_Inventory_Manifest
     (Manifest  : String;
      Inventory : out Inventory_Result) return CryptoLib.Errors.Status;

   function Verify_Inventory
     (Session     : in out SSH_Lib.Sessions.Session;
      Manifest    : String;
      Remote_Path : String;
      Recursive   : Boolean := True)
      return Workflow_Result;

   function Restore_From_Inventory
     (Session     : in out SSH_Lib.Sessions.Session;
      Inventory   : Inventory_Result;
      Source_Root : String;
      Local_Root  : String;
      Policy      : Restore_Conflict_Policy := Overwrite_Existing;
      Transfer    : SSH_Lib.SFTP.Transfer_Options :=
        SSH_Lib.SFTP.Default_Transfer_Options)
      return Workflow_Result;

   function Restore_From_Manifest
     (Session     : in out SSH_Lib.Sessions.Session;
      Manifest    : String;
      Source_Root : String;
      Local_Root  : String;
      Policy      : Restore_Conflict_Policy := Overwrite_Existing;
      Transfer    : SSH_Lib.SFTP.Transfer_Options :=
        SSH_Lib.SFTP.Default_Transfer_Options)
      return Workflow_Result;

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
   function Download_Data
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Data        : out SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Options     : SSH_Lib.SFTP.Transfer_Options :=
        SSH_Lib.SFTP.Default_Transfer_Options)
      return CryptoLib.Errors.Status;

   function Upload_Stream
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Size        : Interfaces.Unsigned_64;
      Reader      : SSH_Lib.SFTP.Stream_Reader_Access;
      Mode        : String := "0644";
      Options     : SSH_Lib.SFTP.Transfer_Options :=
        SSH_Lib.SFTP.Default_Transfer_Options)
      return CryptoLib.Errors.Status;

   function Download_Stream
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Writer      : SSH_Lib.SFTP.Stream_Writer_Access;
      Options     : SSH_Lib.SFTP.Transfer_Options :=
        SSH_Lib.SFTP.Default_Transfer_Options)
      return CryptoLib.Errors.Status;

   function Download_File
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Local_Path  : String;
      Options     : SSH_Lib.SFTP.Transfer_Options :=
        SSH_Lib.SFTP.Default_Transfer_Options)
      return CryptoLib.Errors.Status;

   function Resume_Download_File
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Local_Path  : String;
      Options     : SSH_Lib.SFTP.Transfer_Options :=
        SSH_Lib.SFTP.Default_Transfer_Options)
      return CryptoLib.Errors.Status;

   function Resume_Upload_File
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Local_Path  : String;
      Mode        : String := "0644";
      Options     : SSH_Lib.SFTP.Transfer_Options :=
        SSH_Lib.SFTP.Default_Transfer_Options)
      return CryptoLib.Errors.Status;

   function List_Directory
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Names       : out Ada.Strings.Unbounded.Unbounded_String)
      return CryptoLib.Errors.Status;

   function List_Directory
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Entries     : out SSH_Lib.SFTP.Directory_Entry_Vectors.Vector)
      return CryptoLib.Errors.Status;

   function List_Directory_Paged
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Callback    : SSH_Lib.SFTP.Directory_Page_Callback_Access)
      return CryptoLib.Errors.Status;

   function Stat
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Attributes  : out SSH_Lib.SFTP.File_Attributes)
      return CryptoLib.Errors.Status;

   function LStat
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Attributes  : out SSH_Lib.SFTP.File_Attributes)
      return CryptoLib.Errors.Status;

   function Realpath
     (Session        : in out SSH_Lib.Sessions.Session;
      Remote_Path    : String;
      Canonical_Path : out Ada.Strings.Unbounded.Unbounded_String)
      return CryptoLib.Errors.Status;

   function Set_Permissions
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Mode        : String)
      return CryptoLib.Errors.Status;

   function Set_Attributes
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Attributes  : SSH_Lib.SFTP.File_Attributes)
      return CryptoLib.Errors.Status;

   function Make_Directory
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Mode        : String := "0755")
      return CryptoLib.Errors.Status;

   function Remove_Directory
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String)
      return CryptoLib.Errors.Status;

   function Remove_File
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String)
      return CryptoLib.Errors.Status;

   function Upload_Directory
     (Session        : in out SSH_Lib.Sessions.Session;
      Remote_Path    : String;
      Local_Path     : String;
      Directory_Mode : String := "0755";
      File_Mode      : String := "0644";
      Options        : SSH_Lib.SFTP.Recursive_Options :=
        SSH_Lib.SFTP.Default_Recursive_Options)
      return CryptoLib.Errors.Status;

   function Download_Directory
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Local_Path  : String;
      Options     : SSH_Lib.SFTP.Recursive_Options :=
        SSH_Lib.SFTP.Default_Recursive_Options)
      return CryptoLib.Errors.Status;

   function Remove_Tree
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Options     : SSH_Lib.SFTP.Recursive_Options :=
        SSH_Lib.SFTP.Default_Recursive_Options)
      return CryptoLib.Errors.Status;

   function Copy_Tree
     (Session             : in out SSH_Lib.Sessions.Session;
      Source_Remote_Path  : String;
      Target_Remote_Path  : String;
      Directory_Mode      : String := "0755";
      File_Mode           : String := "0644";
      Options             : SSH_Lib.SFTP.Recursive_Options :=
        SSH_Lib.SFTP.Default_Recursive_Options)
      return CryptoLib.Errors.Status;

   function Rename
     (Session  : in out SSH_Lib.Sessions.Session;
      Old_Path : String;
      New_Path : String)
      return CryptoLib.Errors.Status;

   function Posix_Rename
     (Session  : in out SSH_Lib.Sessions.Session;
      Old_Path : String;
      New_Path : String)
      return CryptoLib.Errors.Status;

   function Hardlink
     (Session  : in out SSH_Lib.Sessions.Session;
      Old_Path : String;
      New_Path : String)
      return CryptoLib.Errors.Status;

   function LSet_Attributes
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Attributes  : SSH_Lib.SFTP.File_Attributes)
      return CryptoLib.Errors.Status;

   function StatVFS
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Stats       : out SSH_Lib.SFTP.File_System_Stats)
      return CryptoLib.Errors.Status;

   function Limits
     (Session : in out SSH_Lib.Sessions.Session;
      Values  : out SSH_Lib.SFTP.Server_Limits)
      return CryptoLib.Errors.Status;

   function Extended_Request
     (Session        : in out SSH_Lib.Sessions.Session;
      Extension_Name : String;
      Payload        : Ada.Streams.Stream_Element_Array;
      Reply_Data     : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;

   function Read_Link
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Target_Path : out Ada.Strings.Unbounded.Unbounded_String)
      return CryptoLib.Errors.Status;

   function Create_Symlink
     (Session     : in out SSH_Lib.Sessions.Session;
      Target_Path : String;
      Link_Path   : String)
      return CryptoLib.Errors.Status;

   function Read_At
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Offset      : Interfaces.Unsigned_64;
      Length      : Natural;
      Data        : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;

   function Write_At
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Offset      : Interfaces.Unsigned_64;
      Data        : Ada.Streams.Stream_Element_Array;
      Mode        : String := "0644")
      return CryptoLib.Errors.Status;

   function FStat
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Attributes  : out SSH_Lib.SFTP.File_Attributes)
      return CryptoLib.Errors.Status;

   function Set_Handle_Permissions
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Mode        : String)
      return CryptoLib.Errors.Status;

   function Set_Handle_Attributes
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Attributes  : SSH_Lib.SFTP.File_Attributes)
      return CryptoLib.Errors.Status;

   function Fsync
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String)
      return CryptoLib.Errors.Status;

   function Expand_Path
     (Session       : in out SSH_Lib.Sessions.Session;
      Remote_Path   : String;
      Expanded_Path : out Ada.Strings.Unbounded.Unbounded_String)
      return CryptoLib.Errors.Status;

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
