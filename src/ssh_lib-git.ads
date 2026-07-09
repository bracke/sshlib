with Ada.Streams;
with Ada.Strings.Unbounded;
with CryptoLib.Errors;
with SSH_Lib.Protocol.Buffers;

--  @summary Git wire-protocol, object-database, and packfile engine for the SSH transport.
--
--  Implements the Git side of the SSH remote helper: building git-upload-pack and git-receive-pack remote-exec
--  commands, reading and writing the on-disk object database (loose objects, packfiles, and pack indexes), refs, the
--  index, the worktree, and config, encoding and parsing the pkt-line wire protocol (v0 and v2), and driving fetch and
--  push workflows. Every operation reports a CryptoLib.Errors.Status and is written to reject malformed input rather
--  than raise.
package SSH_Lib.Git is
   Maximum_Repository_Path_Length : constant Natural := 65_536;
   Maximum_Pkt_Line_Length        : constant Natural := 65_535;
   Maximum_Pkt_Line_Payload_Length : constant Natural :=
     Maximum_Pkt_Line_Length - 4;
   Object_ID_SHA1_Hex_Length      : constant Natural := 40;
   Maximum_Ref_Name_Length        : constant Natural := 1024;
   Maximum_Capability_Token_Length : constant Natural := 1024;
   Object_ID_SHA1_Raw_Length      : constant Natural := 20;
   Maximum_Pack_Delta_Chain_Length : constant Natural := 1024;
   Maximum_Ref_Resolution_Depth   : constant Natural := 32;

   --  Report whether a path is a valid, safe worktree-relative path.
   --  @param Path the repository-relative path
   --  @return True when the path is a valid worktree path.
   function Valid_Worktree_Path (Path : String) return Boolean;

   --  Test a repository-relative path against a Git pathspec pattern.
   --  @param Path the repository-relative path
   --  @param Pathspec the pathspec pattern to match
   --  @param Matches set True when the path matches the pathspec
   --  @return Ok on success, or an error status on failure.
   function Pathspec_Matches
     (Path     : String;
      Pathspec : String;
      Matches  : out Boolean)
      return CryptoLib.Errors.Status;

   type Pkt_Line_Kind is
     (Pkt_Data,
      Pkt_Flush,
      Pkt_Delimiter,
      Pkt_Response_End);

   type Pkt_Line_Cursor is record
      Position           : Ada.Streams.Stream_Element_Offset := 0;
      Packet_Count       : Natural := 0;
      Data_Count         : Natural := 0;
      Flush_Count        : Natural := 0;
      Delimiter_Count    : Natural := 0;
      Response_End_Count : Natural := 0;
      At_End             : Boolean := True;
   end record;

   type Pack_Object_Kind is
     (Pack_Commit,
      Pack_Tree,
      Pack_Blob,
      Pack_Tag,
      Pack_OFS_Delta,
      Pack_REF_Delta);

   type Three_Way_Merge_Result is
     (Merge_Unchanged,
      Merge_Use_Ours,
      Merge_Use_Theirs,
      Merge_Conflict);

   type Worktree_Path_Status is
     (Worktree_Path_Missing,
      Worktree_Path_Unchanged,
      Worktree_Path_Modified);

   type Porcelain_Path_Status is
     (Porcelain_Path_Absent,
      Porcelain_Path_Untracked,
      Porcelain_Path_Tracked_Missing,
      Porcelain_Path_Tracked_Unchanged,
      Porcelain_Path_Tracked_Modified);

   type Ref_Name_Kind is
     (Ref_HEAD,
      Ref_Branch,
      Ref_Tag,
      Ref_Remote,
      Ref_Other);

   type Side_Band_Kind is
     (Side_Band_Data,
      Side_Band_Progress,
      Side_Band_Error);

   type Side_Band_Stream_Summary is record
      Data_Count       : Natural := 0;
      Progress_Count   : Natural := 0;
      Error_Count      : Natural := 0;
      Has_Pack_Data    : Boolean := False;
      Pack_Object_Count : Natural := 0;
      Has_Flush        : Boolean := False;
   end record;

   type Status_Report_Kind is
     (Status_Unpack_Ok,
      Status_Unpack_Error,
      Status_Ref_Ok,
      Status_Ref_Error);

   type Upload_Pack_ACK_Kind is
     (Upload_Pack_NAK,
      Upload_Pack_ACK,
      Upload_Pack_ACK_Continue,
      Upload_Pack_ACK_Common,
      Upload_Pack_ACK_Ready);

   type Upload_Pack_ACK_Stream_Summary is record
      NAK_Count      : Natural := 0;
      ACK_Count      : Natural := 0;
      Continue_Count : Natural := 0;
      Common_Count   : Natural := 0;
      Ready_Count    : Natural := 0;
      Has_Flush      : Boolean := False;
   end record;

   type Upload_Pack_Negotiation_Summary is record
      Want_Count              : Natural := 0;
      Have_Count              : Natural := 0;
      Shallow_Count           : Natural := 0;
      Deepen_Count            : Natural := 0;
      Filter_Count            : Natural := 0;
      Has_Done                : Boolean := False;
      Has_Flush               : Boolean := False;
      Uses_Capabilities       : Boolean := False;
      Uses_Multi_ACK          : Boolean := False;
      Uses_Multi_ACK_Detailed : Boolean := False;
      Uses_Side_Band          : Boolean := False;
      Uses_Side_Band_64K      : Boolean := False;
      Uses_No_Done            : Boolean := False;
   end record;

   type Object_ID_Hex_Text is
     array (Positive range 1 .. Object_ID_SHA1_Hex_Length)
       of Ada.Streams.Stream_Element;

   type Object_ID_Hex_Array is
     array (Positive range <>) of Object_ID_Hex_Text;

   type Tree_Entry_Mode_Array is array (Positive range <>) of Natural;

   type Tree_Entry_Name_Last_Array is
     array (Positive range <>) of Ada.Streams.Stream_Element_Offset;

   type Ref_Name_Last_Array is
     array (Positive range <>) of Ada.Streams.Stream_Element_Offset;

   type Config_Value_Last_Array is
     array (Positive range <>) of Ada.Streams.Stream_Element_Offset;

   type Index_Path_Last_Array is
     array (Positive range <>) of Ada.Streams.Stream_Element_Offset;

   type Receive_Pack_Request_Summary is record
      Update_Count    : Natural := 0;
      Has_Delete      : Boolean := False;
      Has_Create      : Boolean := False;
      Has_Update      : Boolean := False;
      Has_Capabilities : Boolean := False;
      Has_Flush       : Boolean := False;
      Has_Pack_Data   : Boolean := False;
      Pack_Object_Count : Natural := 0;
   end record;

   type Upload_Pack_Response_Summary is record
      ACK_Count         : Natural := 0;
      Has_NAK           : Boolean := False;
      Has_Ready_ACK     : Boolean := False;
      Side_Data_Count   : Natural := 0;
      Side_Progress_Count : Natural := 0;
      Side_Error_Count  : Natural := 0;
      Has_Pack_Data     : Boolean := False;
      Pack_Object_Count : Natural := 0;
      Has_Flush         : Boolean := False;
   end record;

   type Receive_Pack_Report_Summary is record
      Has_Unpack_OK    : Boolean := False;
      Has_Unpack_Error : Boolean := False;
      Ref_OK_Count     : Natural := 0;
      Ref_Error_Count  : Natural := 0;
      Has_Flush        : Boolean := False;
   end record;

   type Protocol_V2_Request_Summary is record
      Command_Count    : Natural := 0;
      Capability_Count : Natural := 0;
      Argument_Count   : Natural := 0;
      Has_Ls_Refs      : Boolean := False;
      Has_Fetch        : Boolean := False;
      Has_Server_Option : Boolean := False;
      Has_Object_Info  : Boolean := False;
      Has_Object_Format : Boolean := False;
      Has_Agent        : Boolean := False;
      Has_Session_ID   : Boolean := False;
      Has_Symrefs      : Boolean := False;
      Has_Peel         : Boolean := False;
      Has_Ref_Prefix   : Boolean := False;
      Has_Want         : Boolean := False;
      Has_Have         : Boolean := False;
      Has_Done         : Boolean := False;
      Has_Filter       : Boolean := False;
      Has_Delimiter    : Boolean := False;
      Has_Flush        : Boolean := False;
   end record;

   type Protocol_V2_Response_Summary is record
      Data_Count        : Natural := 0;
      Delimiter_Count   : Natural := 0;
      Has_Delimiter     : Boolean := False;
      Has_Error_Line    : Boolean := False;
      Has_Response_End  : Boolean := False;
      Has_Flush         : Boolean := False;
   end record;

   type Protocol_V2_Capability_Summary is record
      Capability_Count : Natural := 0;
      Has_Ls_Refs      : Boolean := False;
      Has_Fetch        : Boolean := False;
      Has_Server_Option : Boolean := False;
      Has_Object_Format : Boolean := False;
      Has_Agent        : Boolean := False;
      Has_Session_ID   : Boolean := False;
      Has_Flush        : Boolean := False;
   end record;

   type Fetch_Workflow_State is
     (Fetch_Not_Started,
      Fetch_Request_Built,
      Fetch_Response_Accepted,
      Fetch_Refs_Applied,
      Fetch_Finished,
      Fetch_Failed);

   type Fetch_Workflow is record
      State            : Fetch_Workflow_State := Fetch_Not_Started;
      Request_Summary  : Upload_Pack_Negotiation_Summary;
      Response_Summary : Upload_Pack_Response_Summary;
      Applied_Count    : Natural := 0;
   end record;

   type Push_Workflow_State is
     (Push_Not_Started,
      Push_Request_Built,
      Push_Report_Accepted,
      Push_Refs_Applied,
      Push_Finished,
      Push_Failed);

   type Push_Workflow is record
      State           : Push_Workflow_State := Push_Not_Started;
      Request_Summary : Receive_Pack_Request_Summary;
      Report_Summary  : Receive_Pack_Report_Summary;
      Applied_Count   : Natural := 0;
   end record;

   type Porcelain_Status_Summary is record
      Untracked_Count       : Natural := 0;
      Ignored_Count         : Natural := 0;
      Missing_Count         : Natural := 0;
      Unchanged_Count       : Natural := 0;
      Modified_Count        : Natural := 0;
      Has_Untracked         : Boolean := False;
      Has_Ignored           : Boolean := False;
      Has_Tracked_Changes   : Boolean := False;
      Is_Clean              : Boolean := True;
      Pathspec_Applied      : Boolean := False;
      Include_Ignored       : Boolean := False;
   end record;

   type Porcelain_Index_Worktree_Model is record
      Index_Path_Count       : Natural := 0;
      Worktree_File_Count    : Natural := 0;
      Current_Branch_Found   : Boolean := False;
      HEAD_Attached          : Boolean := False;
      HEAD_Resolved          : Boolean := False;
      Status                 : Porcelain_Status_Summary;
   end record;

   type Repository_Database_Summary is record
      Ref_Count                : Natural := 0;
      Branch_Count             : Natural := 0;
      Tag_Count                : Natural := 0;
      Remote_Tracking_Count    : Natural := 0;
      Loose_Object_Count       : Natural := 0;
      Stored_Object_Count      : Natural := 0;
      Pack_Index_Count         : Natural := 0;
      HEAD_Attached            : Boolean := False;
      HEAD_Resolved            : Boolean := False;
      Missing_Ref_Target_Count : Natural := 0;
      Has_Missing_Ref_Targets  : Boolean := False;
   end record;

   type Fetch_Policy_Decision is
     (Fetch_Policy_Stop,
      Fetch_Policy_Retry,
      Fetch_Policy_Request_More_Haves,
      Fetch_Policy_Accept_Pack);

   type Push_Policy_Decision is
     (Push_Policy_Stop,
      Push_Policy_Retry,
      Push_Policy_Rebuild_With_Pack);

   type Ref_Advertisement_Summary is record
      Ref_Count         : Natural := 0;
      Peeled_Count      : Natural := 0;
      Symref_Count      : Natural := 0;
      Capability_Count  : Natural := 0;
      Has_HEAD          : Boolean := False;
      Has_Capabilities  : Boolean := False;
      Has_Flush         : Boolean := False;
      Has_Response_End  : Boolean := False;
   end record;

   type Pack_Index_Layout is record
      Header_Offset         : Natural := 0;
      Fanout_Offset         : Natural := 0;
      Object_IDs_Offset     : Natural := 0;
      CRCs_Offset           : Natural := 0;
      Offsets_Offset        : Natural := 0;
      Large_Offsets_Offset  : Natural := 0;
      Pack_Checksum_Offset  : Natural := 0;
      Index_Checksum_Offset : Natural := 0;
      Total_Length          : Natural := 0;
   end record;

   type Pack_Delta_Span is record
      First : Ada.Streams.Stream_Element_Offset;
      Last  : Ada.Streams.Stream_Element_Offset;
   end record;

   type Pack_Delta_Span_Array is array (Positive range <>) of Pack_Delta_Span;

   type Pack_Object_Counts is record
      Commits    : Natural := 0;
      Trees      : Natural := 0;
      Blobs      : Natural := 0;
      Tags       : Natural := 0;
      OFS_Deltas : Natural := 0;
      REF_Deltas : Natural := 0;
   end record;

   --  Build OpenSSH-compatible remote exec command strings for Git.
   --  Repository_Path is emitted as one POSIX-style single-quoted
   --  remote command argument.  Empty paths, NUL, CR, LF, paths
   --  longer than Maximum_Repository_Path_Length, and paths whose quoted
   --  command would exceed SSH_Lib.Protocol.Channels.Maximum_Command_Length
   --  are rejected.
   --  @param Repository_Path the remote repository path
   --  @param Command the resulting remote-exec command string
   --  @return Ok on success, or an error status on failure.
   function Build_Upload_Pack_Command
     (Repository_Path : String;
      Command         : out Ada.Strings.Unbounded.Unbounded_String)
      return CryptoLib.Errors.Status;

   --  Build the OpenSSH remote-exec command string that runs git-receive-pack on a repository.
   --  @param Repository_Path the remote repository path
   --  @param Command the resulting remote-exec command string
   --  @return Ok on success, or an error status on failure.
   function Build_Receive_Pack_Command
     (Repository_Path : String;
      Command         : out Ada.Strings.Unbounded.Unbounded_String)
      return CryptoLib.Errors.Status;

   --  Convenience wrappers around the status-returning builders.
   --  They raise Constraint_Error for invalid repository paths.
   --  @param Repository_Path the remote repository path
   --  @return the git-upload-pack remote-exec command string.
   function Upload_Pack_Command (Repository_Path : String) return String;

   --  Return the git-receive-pack remote-exec command string, raising Constraint_Error for an invalid path.
   --  @param Repository_Path the remote repository path
   --  @return the git-receive-pack remote-exec command string.
   function Receive_Pack_Command (Repository_Path : String) return String;

   --  Create the initial on-disk .git directory layout and default state under a root.
   --  @param Repository_Root filesystem path to the repository root
   --  @return Ok on success, or an error status on failure.
   function Initialize_Repository_State
     (Repository_Root : String)
      return CryptoLib.Errors.Status;

   --  Write an empty Git index file to the repository.
   --  @param Repository_Root filesystem path to the repository root
   --  @return Ok on success, or an error status on failure.
   function Write_Empty_Index
     (Repository_Root : String)
      return CryptoLib.Errors.Status;

   --  Read the index file header, returning its format version and entry count.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Version the object/index format version
   --  @param Entry_Count the number of entries
   --  @return Ok on success, or an error status on failure.
   function Read_Index_Header
     (Repository_Root : String;
      Version         : out Natural;
      Entry_Count     : out Natural)
      return CryptoLib.Errors.Status;

   --  Encode a single Git index entry from its file metadata and object id.
   --  @param File_Mode the Git file-mode bits
   --  @param Path the repository-relative path
   --  @param Object_ID the raw binary object identifier
   --  @param File_Size the file size in bytes
   --  @param Entry_Data the encoded entry bytes
   --  @param Last index of the last valid element written
   --  @return Ok on success, or an error status on failure.
   function Build_Index_Entry
     (File_Mode  : Natural;
      Path       : String;
      Object_ID  : Ada.Streams.Stream_Element_Array;
      File_Size  : Natural;
      Entry_Data : out Ada.Streams.Stream_Element_Array;
      Last       : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   --  Write the index file from a block of already-encoded entries.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Entry_Data the encoded entry bytes
   --  @param Entry_Count the number of entries
   --  @return Ok on success, or an error status on failure.
   function Write_Index
     (Repository_Root : String;
      Entry_Data      : Ada.Streams.Stream_Element_Array;
      Entry_Count     : Natural)
      return CryptoLib.Errors.Status;

   --  Parse one index entry at a byte offset, also returning the offset of the next entry.
   --  @param Entry_Data the encoded entry bytes
   --  @param Entry_Offset byte offset of the entry within the data
   --  @param File_Mode the Git file-mode bits
   --  @param Path the repository-relative path
   --  @param Path_Last index of the last valid element of the path
   --  @param Object_ID the raw binary object identifier
   --  @param Object_Last index of the last valid element of the object id
   --  @param File_Size the file size in bytes
   --  @param Next_Offset byte offset of the following entry
   --  @return Ok on success, or an error status on failure.
   function Parse_Index_Entry
     (Entry_Data  : Ada.Streams.Stream_Element_Array;
      Entry_Offset : Natural;
      File_Mode   : out Natural;
      Path        : out Ada.Streams.Stream_Element_Array;
      Path_Last   : out Ada.Streams.Stream_Element_Offset;
      Object_ID   : out Ada.Streams.Stream_Element_Array;
      Object_Last : out Ada.Streams.Stream_Element_Offset;
      File_Size   : out Natural;
      Next_Offset : out Natural)
      return CryptoLib.Errors.Status;

   --  Read the index entry at a given position, returning its file metadata and object id.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Entry_Index zero-based index of the entry to read
   --  @param File_Mode the Git file-mode bits
   --  @param Path the repository-relative path
   --  @param Path_Last index of the last valid element of the path
   --  @param Object_ID the raw binary object identifier
   --  @param Object_Last index of the last valid element of the object id
   --  @param File_Size the file size in bytes
   --  @return Ok on success, or an error status on failure.
   function Read_Index_Entry
     (Repository_Root : String;
      Entry_Index     : Natural;
      File_Mode       : out Natural;
      Path            : out Ada.Streams.Stream_Element_Array;
      Path_Last       : out Ada.Streams.Stream_Element_Offset;
      Object_ID       : out Ada.Streams.Stream_Element_Array;
      Object_Last     : out Ada.Streams.Stream_Element_Offset;
      File_Size       : out Natural)
      return CryptoLib.Errors.Status;

   --  Look up an index entry by path, returning its metadata if present.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Path the repository-relative path
   --  @param File_Mode the Git file-mode bits
   --  @param Object_ID the raw binary object identifier
   --  @param Object_Last index of the last valid element of the object id
   --  @param File_Size the file size in bytes
   --  @param Found set True when the item was found
   --  @return Ok on success, or an error status on failure.
   function Find_Index_Entry
     (Repository_Root : String;
      Path            : Ada.Streams.Stream_Element_Array;
      File_Mode       : out Natural;
      Object_ID       : out Ada.Streams.Stream_Element_Array;
      Object_Last     : out Ada.Streams.Stream_Element_Offset;
      File_Size       : out Natural;
      Found           : out Boolean)
      return CryptoLib.Errors.Status;

   --  Read the object contents referenced by an indexed path.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Path the repository-relative path
   --  @param Kind the object type
   --  @param Data the resulting object contents
   --  @param Last index of the last valid element written
   --  @param Found set True when the item was found
   --  @return Ok on success, or an error status on failure.
   function Read_Index_Path_Object
     (Repository_Root : String;
      Path            : Ada.Streams.Stream_Element_Array;
      Kind            : out Pack_Object_Kind;
      Data            : out Ada.Streams.Stream_Element_Array;
      Last            : out Ada.Streams.Stream_Element_Offset;
      Found           : out Boolean)
      return CryptoLib.Errors.Status;

   --  List every path recorded in the index.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Paths packed buffer of the path names
   --  @param Path_Lasts end offset of each packed path name
   --  @param Path_Count the number of paths
   --  @return Ok on success, or an error status on failure.
   function List_Index_Paths
     (Repository_Root : String;
      Paths           : out Ada.Streams.Stream_Element_Array;
      Path_Lasts      : out Index_Path_Last_Array;
      Path_Count      : out Natural)
      return CryptoLib.Errors.Status;

   --  Write data to a file in the worktree.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Path the repository-relative path
   --  @param Data the file contents to write
   --  @return Ok on success, or an error status on failure.
   function Write_Worktree_File
     (Repository_Root : String;
      Path            : String;
      Data            : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Read the contents of a worktree file.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Path the repository-relative path
   --  @param Data the file contents read
   --  @param Last index of the last valid element written
   --  @return Ok on success, or an error status on failure.
   function Read_Worktree_File
     (Repository_Root : String;
      Path            : String;
      Data            : out Ada.Streams.Stream_Element_Array;
      Last            : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   --  Report whether a worktree file exists.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Path the repository-relative path
   --  @param Found set True when the item was found
   --  @return Ok on success, or an error status on failure.
   function Worktree_File_Exists
     (Repository_Root : String;
      Path            : String;
      Found           : out Boolean)
      return CryptoLib.Errors.Status;

   --  Delete a file from the worktree.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Path the repository-relative path
   --  @param Removed set True when the item was removed
   --  @return Ok on success, or an error status on failure.
   function Delete_Worktree_File
     (Repository_Root : String;
      Path            : String;
      Removed         : out Boolean)
      return CryptoLib.Errors.Status;

   --  Materialize a single indexed path into the worktree.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Path the repository-relative path
   --  @param Written set True when a file was written
   --  @return Ok on success, or an error status on failure.
   function Checkout_Index_Path
     (Repository_Root : String;
      Path            : Ada.Streams.Stream_Element_Array;
      Written         : out Boolean)
      return CryptoLib.Errors.Status;

   --  Materialize every indexed path into the worktree.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Written_Count the number of files written
   --  @return Ok on success, or an error status on failure.
   function Checkout_Index_All
     (Repository_Root : String;
      Written_Count   : out Natural)
      return CryptoLib.Errors.Status;

   --  Compare an indexed path's recorded content against the current worktree file.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Path the repository-relative path
   --  @param Path_Status the classified status of the path
   --  @return Ok on success, or an error status on failure.
   function Compare_Index_Path_To_Worktree
     (Repository_Root : String;
      Path            : Ada.Streams.Stream_Element_Array;
      Path_Status     : out Worktree_Path_Status)
      return CryptoLib.Errors.Status;

   --  Count indexed paths that are missing, unchanged, or modified in the worktree.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Missing_Count count of tracked paths missing from the worktree
   --  @param Unchanged_Count count of unchanged paths
   --  @param Modified_Count count of modified paths
   --  @return Ok on success, or an error status on failure.
   function Summarize_Index_Worktree
     (Repository_Root  : String;
      Missing_Count    : out Natural;
      Unchanged_Count  : out Natural;
      Modified_Count   : out Natural)
      return CryptoLib.Errors.Status;

   --  Classify a worktree path's status relative to the index.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Path the repository-relative path
   --  @param Path_Status the classified status of the path
   --  @return Ok on success, or an error status on failure.
   function Classify_Worktree_Path
     (Repository_Root : String;
      Path            : String;
      Path_Status     : out Porcelain_Path_Status)
      return CryptoLib.Errors.Status;

   --  Classify a list of worktree paths and tally each status category.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Paths packed buffer of the path names
   --  @param Path_Lasts end offset of each packed path name
   --  @param Path_Count the number of paths
   --  @param Absent_Count count of absent paths
   --  @param Untracked_Count count of untracked paths
   --  @param Missing_Count count of tracked paths missing from the worktree
   --  @param Unchanged_Count count of unchanged paths
   --  @param Modified_Count count of modified paths
   --  @return Ok on success, or an error status on failure.
   function Summarize_Worktree_Paths
     (Repository_Root  : String;
      Paths            : Ada.Streams.Stream_Element_Array;
      Path_Lasts       : Index_Path_Last_Array;
      Path_Count       : Natural;
      Absent_Count     : out Natural;
      Untracked_Count  : out Natural;
      Missing_Count    : out Natural;
      Unchanged_Count  : out Natural;
      Modified_Count   : out Natural)
      return CryptoLib.Errors.Status;

   --  List every file present in the worktree.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Paths packed buffer of the path names
   --  @param Path_Lasts end offset of each packed path name
   --  @param Path_Count the number of paths
   --  @return Ok on success, or an error status on failure.
   function List_Worktree_Files
     (Repository_Root : String;
      Paths           : out Ada.Streams.Stream_Element_Array;
      Path_Lasts      : out Index_Path_Last_Array;
      Path_Count      : out Natural)
      return CryptoLib.Errors.Status;

   --  Report whether a worktree path is ignored by .gitignore rules.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Path the repository-relative path
   --  @param Ignored set True when the path is ignored
   --  @return Ok on success, or an error status on failure.
   function Worktree_Path_Ignored
     (Repository_Root : String;
      Path            : String;
      Ignored         : out Boolean)
      return CryptoLib.Errors.Status;

   --  Tally untracked, missing, unchanged, and modified paths across the whole worktree.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Untracked_Count count of untracked paths
   --  @param Missing_Count count of tracked paths missing from the worktree
   --  @param Unchanged_Count count of unchanged paths
   --  @param Modified_Count count of modified paths
   --  @return Ok on success, or an error status on failure.
   function Summarize_Worktree_Status
     (Repository_Root  : String;
      Untracked_Count  : out Natural;
      Missing_Count    : out Natural;
      Unchanged_Count  : out Natural;
      Modified_Count   : out Natural)
      return CryptoLib.Errors.Status;

   --  Tally worktree status counts restricted to paths matching a pathspec.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Pathspec the pathspec pattern to match
   --  @param Untracked_Count count of untracked paths
   --  @param Missing_Count count of tracked paths missing from the worktree
   --  @param Unchanged_Count count of unchanged paths
   --  @param Modified_Count count of modified paths
   --  @return Ok on success, or an error status on failure.
   function Summarize_Worktree_Status_Matching
     (Repository_Root  : String;
      Pathspec         : String;
      Untracked_Count  : out Natural;
      Missing_Count    : out Natural;
      Unchanged_Count  : out Natural;
      Modified_Count   : out Natural)
      return CryptoLib.Errors.Status;

   --  Tally worktree status counts including a separate count of ignored files.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Untracked_Count count of untracked paths
   --  @param Ignored_Count count of ignored paths
   --  @param Missing_Count count of tracked paths missing from the worktree
   --  @param Unchanged_Count count of unchanged paths
   --  @param Modified_Count count of modified paths
   --  @return Ok on success, or an error status on failure.
   function Summarize_Worktree_Status_With_Ignored
     (Repository_Root  : String;
      Untracked_Count  : out Natural;
      Ignored_Count    : out Natural;
      Missing_Count    : out Natural;
      Unchanged_Count  : out Natural;
      Modified_Count   : out Natural)
      return CryptoLib.Errors.Status;

   --  Compute a full porcelain status summary for the worktree, optionally including ignored files.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Pathspec the pathspec pattern to match
   --  @param Include_Ignored whether ignored files are included
   --  @param Summary the computed summary record
   --  @return Ok on success, or an error status on failure.
   function Evaluate_Porcelain_Status
     (Repository_Root  : String;
      Pathspec         : String;
      Include_Ignored  : Boolean;
      Summary          : out Porcelain_Status_Summary)
      return CryptoLib.Errors.Status;

   --  Build a combined index/worktree/HEAD model used to render porcelain status.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Pathspec the pathspec pattern to match
   --  @param Include_Ignored whether ignored files are included
   --  @param Model the computed index/worktree/HEAD model
   --  @return Ok on success, or an error status on failure.
   function Read_Porcelain_Index_Worktree_Model
     (Repository_Root  : String;
      Pathspec         : String;
      Include_Ignored  : Boolean;
      Model            : out Porcelain_Index_Worktree_Model)
      return CryptoLib.Errors.Status;

   --  Detect a single rename between a deleted indexed path and a new worktree file.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Old_Path the former path name
   --  @param Old_Last index of the last valid element of the former path
   --  @param New_Path the new path name
   --  @param New_Last index of the last valid element of the new path
   --  @param Found set True when the item was found
   --  @return Ok on success, or an error status on failure.
   function Detect_Worktree_Rename
     (Repository_Root : String;
      Old_Path        : out Ada.Streams.Stream_Element_Array;
      Old_Last        : out Ada.Streams.Stream_Element_Offset;
      New_Path        : out Ada.Streams.Stream_Element_Array;
      New_Last        : out Ada.Streams.Stream_Element_Offset;
      Found           : out Boolean)
      return CryptoLib.Errors.Status;

   --  Detect a single copy of an indexed path into a new worktree file.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Source_Path the copy source path name
   --  @param Source_Last index of the last valid element of the source path
   --  @param Copy_Path the copy destination path name
   --  @param Copy_Last index of the last valid element of the copy path
   --  @param Found set True when the item was found
   --  @return Ok on success, or an error status on failure.
   function Detect_Worktree_Copy
     (Repository_Root : String;
      Source_Path     : out Ada.Streams.Stream_Element_Array;
      Source_Last     : out Ada.Streams.Stream_Element_Offset;
      Copy_Path       : out Ada.Streams.Stream_Element_Array;
      Copy_Last       : out Ada.Streams.Stream_Element_Offset;
      Found           : out Boolean)
      return CryptoLib.Errors.Status;

   --  Remove worktree files that are not tracked in the index.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Removed_Count the number of items removed
   --  @return Ok on success, or an error status on failure.
   function Clean_Worktree_Not_In_Index
     (Repository_Root : String;
      Removed_Count   : out Natural)
      return CryptoLib.Errors.Status;

   --  Hash a worktree file, store it as a blob, and add it to the index.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Path the repository-relative path
   --  @param Object_ID_Hex the object's hex-encoded id
   --  @param Last index of the last valid element written
   --  @return Ok on success, or an error status on failure.
   function Stage_Worktree_File
     (Repository_Root : String;
      Path            : String;
      Object_ID_Hex   : out Ada.Streams.Stream_Element_Array;
      Last            : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   --  Remove a path from the index.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Path the repository-relative path
   --  @param Removed set True when the item was removed
   --  @return Ok on success, or an error status on failure.
   function Remove_Index_Path
     (Repository_Root : String;
      Path            : String;
      Removed         : out Boolean)
      return CryptoLib.Errors.Status;

   --  Reset the index to match the root tree of a commit.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Commit_ID_Hex the commit's hex-encoded id
   --  @param Entry_Count the number of entries
   --  @return Ok on success, or an error status on failure.
   function Reset_Index_To_Commit_Root
     (Repository_Root : String;
      Commit_ID_Hex   : Ada.Streams.Stream_Element_Array;
      Entry_Count     : out Natural)
      return CryptoLib.Errors.Status;

   --  Check out a branch, updating HEAD, the index, and the worktree.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Branch_Name the branch name
   --  @param Written_Count the number of files written
   --  @return Ok on success, or an error status on failure.
   function Checkout_Branch
     (Repository_Root : String;
      Branch_Name     : String;
      Written_Count   : out Natural)
      return CryptoLib.Errors.Status;

   --  Test whether one commit is a first-parent ancestor of another.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Ancestor_Commit_Hex the candidate ancestor commit's hex id
   --  @param Descendant_Commit_Hex the candidate descendant commit's hex id
   --  @param Is_Ancestor set True when the ancestor relation holds
   --  @return Ok on success, or an error status on failure.
   function Is_Ancestor_First_Parent
     (Repository_Root      : String;
      Ancestor_Commit_Hex  : Ada.Streams.Stream_Element_Array;
      Descendant_Commit_Hex : Ada.Streams.Stream_Element_Array;
      Is_Ancestor          : out Boolean)
      return CryptoLib.Errors.Status;

   --  Fast-forward a branch to a new commit when it is a descendant.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Branch_Name the branch name
   --  @param New_Commit_Hex the new commit's hex id
   --  @param Updated set True when the ref was updated
   --  @return Ok on success, or an error status on failure.
   function Fast_Forward_Branch
     (Repository_Root : String;
      Branch_Name     : String;
      New_Commit_Hex  : Ada.Streams.Stream_Element_Array;
      Updated         : out Boolean)
      return CryptoLib.Errors.Status;

   --  Apply a push-style branch update with an old-value check and optional force.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Branch_Name the branch name
   --  @param Expected_Old_Hex the expected current hex id, for the compare-and-swap check
   --  @param New_Commit_Hex the new commit's hex id
   --  @param Allow_Non_Fast_Forward whether non-fast-forward updates are allowed
   --  @param Updated set True when the ref was updated
   --  @return Ok on success, or an error status on failure.
   function Apply_Push_Branch_Update
     (Repository_Root        : String;
      Branch_Name            : String;
      Expected_Old_Hex       : Ada.Streams.Stream_Element_Array;
      New_Commit_Hex         : Ada.Streams.Stream_Element_Array;
      Allow_Non_Fast_Forward : Boolean;
      Updated                : out Boolean)
      return CryptoLib.Errors.Status;

   --  Create a commit from the current index and advance a branch to it.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Branch_Name the branch name
   --  @param Author_Line the commit author identity line
   --  @param Committer_Line the commit committer identity line
   --  @param Message the message text
   --  @param Commit_ID_Hex the commit's hex-encoded id
   --  @param Last index of the last valid element written
   --  @return Ok on success, or an error status on failure.
   function Commit_Index_To_Branch
     (Repository_Root : String;
      Branch_Name     : String;
      Author_Line     : String;
      Committer_Line  : String;
      Message         : String;
      Commit_ID_Hex   : out Ada.Streams.Stream_Element_Array;
      Last            : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   --  Stage a single worktree file and commit it to a branch in one step.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Branch_Name the branch name
   --  @param Path the repository-relative path
   --  @param Author_Line the commit author identity line
   --  @param Committer_Line the commit committer identity line
   --  @param Message the message text
   --  @param Commit_ID_Hex the commit's hex-encoded id
   --  @param Last index of the last valid element written
   --  @return Ok on success, or an error status on failure.
   function Stage_And_Commit_Worktree_File
     (Repository_Root : String;
      Branch_Name     : String;
      Path            : String;
      Author_Line     : String;
      Committer_Line  : String;
      Message         : String;
      Commit_ID_Hex   : out Ada.Streams.Stream_Element_Array;
      Last            : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   --  Compress and store an object as a loose object, returning its id.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Kind the object type
   --  @param Data the object contents to store
   --  @param Object_ID_Hex the object's hex-encoded id
   --  @param Last index of the last valid element written
   --  @return Ok on success, or an error status on failure.
   function Store_Loose_Object
     (Repository_Root : String;
      Kind            : Pack_Object_Kind;
      Data            : Ada.Streams.Stream_Element_Array;
      Object_ID_Hex   : out Ada.Streams.Stream_Element_Array;
      Last            : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   --  Validate an object's contents, then store it as a loose object.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Kind the object type
   --  @param Data the object contents to store
   --  @param Object_ID_Hex the object's hex-encoded id
   --  @param Last index of the last valid element written
   --  @return Ok on success, or an error status on failure.
   function Store_Loose_Object_Validated
     (Repository_Root : String;
      Kind            : Pack_Object_Kind;
      Data            : Ada.Streams.Stream_Element_Array;
      Object_ID_Hex   : out Ada.Streams.Stream_Element_Array;
      Last            : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   --  Delete a loose object by id.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Object_ID_Hex the object's hex-encoded id
   --  @return Ok on success, or an error status on failure.
   function Delete_Loose_Object
     (Repository_Root : String;
      Object_ID_Hex   : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Store a packfile under .git, returning its checksum.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Pack_Data the packfile bytes
   --  @param Pack_Checksum_Hex the pack's hex-encoded checksum
   --  @param Last index of the last valid element written
   --  @return Ok on success, or an error status on failure.
   function Store_Pack_File
     (Repository_Root    : String;
      Pack_Data          : Ada.Streams.Stream_Element_Array;
      Pack_Checksum_Hex  : out Ada.Streams.Stream_Element_Array;
      Last               : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   --  Read a stored packfile by its checksum.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Pack_Checksum_Hex the pack's hex-encoded checksum
   --  @param Pack_Data the packfile bytes
   --  @param Last index of the last valid element written
   --  @return Ok on success, or an error status on failure.
   function Read_Pack_File
     (Repository_Root    : String;
      Pack_Checksum_Hex  : Ada.Streams.Stream_Element_Array;
      Pack_Data          : out Ada.Streams.Stream_Element_Array;
      Last               : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   --  Delete a stored packfile by its checksum.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Pack_Checksum_Hex the pack's hex-encoded checksum
   --  @return Ok on success, or an error status on failure.
   function Delete_Pack_File
     (Repository_Root    : String;
      Pack_Checksum_Hex  : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Store a pack index (.idx) for a given pack checksum.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Pack_Checksum_Hex the pack's hex-encoded checksum
   --  @param Index_Data the pack index bytes
   --  @return Ok on success, or an error status on failure.
   function Store_Pack_Index
     (Repository_Root    : String;
      Pack_Checksum_Hex  : Ada.Streams.Stream_Element_Array;
      Index_Data         : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Read a stored pack index by its pack checksum.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Pack_Checksum_Hex the pack's hex-encoded checksum
   --  @param Index_Data the pack index bytes
   --  @param Last index of the last valid element written
   --  @return Ok on success, or an error status on failure.
   function Read_Pack_Index
     (Repository_Root    : String;
      Pack_Checksum_Hex  : Ada.Streams.Stream_Element_Array;
      Index_Data         : out Ada.Streams.Stream_Element_Array;
      Last               : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   --  Delete a stored pack index by its pack checksum.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Pack_Checksum_Hex the pack's hex-encoded checksum
   --  @return Ok on success, or an error status on failure.
   function Delete_Pack_Index
     (Repository_Root    : String;
      Pack_Checksum_Hex  : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Delete both the packfile and its index for a pack checksum.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Pack_Checksum_Hex the pack's hex-encoded checksum
   --  @param Deleted_Pack_File set True when the packfile was deleted
   --  @param Deleted_Pack_Index set True when the pack index was deleted
   --  @return Ok on success, or an error status on failure.
   function Delete_Stored_Pack
     (Repository_Root    : String;
      Pack_Checksum_Hex  : Ada.Streams.Stream_Element_Array;
      Deleted_Pack_File  : out Boolean;
      Deleted_Pack_Index : out Boolean)
      return CryptoLib.Errors.Status;

   --  Read a single object from a specific pack without resolving deltas.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Pack_Checksum_Hex the pack's hex-encoded checksum
   --  @param Object_ID_Hex the object's hex-encoded id
   --  @param Pack_Data the packfile bytes
   --  @param Index_Data the pack index bytes
   --  @param Kind the object type
   --  @param Data the resulting object contents
   --  @param Last index of the last valid element written
   --  @return Ok on success, or an error status on failure.
   function Read_Packed_Object
     (Repository_Root    : String;
      Pack_Checksum_Hex  : Ada.Streams.Stream_Element_Array;
      Object_ID_Hex      : Ada.Streams.Stream_Element_Array;
      Pack_Data          : out Ada.Streams.Stream_Element_Array;
      Index_Data         : out Ada.Streams.Stream_Element_Array;
      Kind               : out Pack_Object_Kind;
      Data               : out Ada.Streams.Stream_Element_Array;
      Last               : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   --  Read a packed object and verify its computed id.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Pack_Checksum_Hex the pack's hex-encoded checksum
   --  @param Object_ID_Hex the object's hex-encoded id
   --  @param Pack_Data the packfile bytes
   --  @param Index_Data the pack index bytes
   --  @param Kind the object type
   --  @param Data the resulting object contents
   --  @param Last index of the last valid element written
   --  @return Ok on success, or an error status on failure.
   function Read_Packed_Object_Validated
     (Repository_Root    : String;
      Pack_Checksum_Hex  : Ada.Streams.Stream_Element_Array;
      Object_ID_Hex      : Ada.Streams.Stream_Element_Array;
      Pack_Data          : out Ada.Streams.Stream_Element_Array;
      Index_Data         : out Ada.Streams.Stream_Element_Array;
      Kind               : out Pack_Object_Kind;
      Data               : out Ada.Streams.Stream_Element_Array;
      Last               : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   --  Read a packed object, resolving any delta chain against its bases.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Pack_Checksum_Hex the pack's hex-encoded checksum
   --  @param Object_ID_Hex the object's hex-encoded id
   --  @param Pack_Data the packfile bytes
   --  @param Index_Data the pack index bytes
   --  @param Base_Data scratch buffer for delta base objects
   --  @param Delta_Data scratch buffer for delta objects
   --  @param Workspace scratch buffer for delta-chain reconstruction
   --  @param Kind the object type
   --  @param Data the resulting object contents
   --  @param Last index of the last valid element written
   --  @return Ok on success, or an error status on failure.
   function Read_Packed_Object_Resolved
     (Repository_Root    : String;
      Pack_Checksum_Hex  : Ada.Streams.Stream_Element_Array;
      Object_ID_Hex      : Ada.Streams.Stream_Element_Array;
      Pack_Data          : out Ada.Streams.Stream_Element_Array;
      Index_Data         : out Ada.Streams.Stream_Element_Array;
      Base_Data          : out Ada.Streams.Stream_Element_Array;
      Delta_Data         : out Ada.Streams.Stream_Element_Array;
      Workspace          : out Ada.Streams.Stream_Element_Array;
      Kind               : out Pack_Object_Kind;
      Data               : out Ada.Streams.Stream_Element_Array;
      Last               : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   --  Read and delta-resolve a packed object, verifying its computed id.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Pack_Checksum_Hex the pack's hex-encoded checksum
   --  @param Object_ID_Hex the object's hex-encoded id
   --  @param Pack_Data the packfile bytes
   --  @param Index_Data the pack index bytes
   --  @param Base_Data scratch buffer for delta base objects
   --  @param Delta_Data scratch buffer for delta objects
   --  @param Workspace scratch buffer for delta-chain reconstruction
   --  @param Kind the object type
   --  @param Data the resulting object contents
   --  @param Last index of the last valid element written
   --  @return Ok on success, or an error status on failure.
   function Read_Packed_Object_Resolved_Validated
     (Repository_Root    : String;
      Pack_Checksum_Hex  : Ada.Streams.Stream_Element_Array;
      Object_ID_Hex      : Ada.Streams.Stream_Element_Array;
      Pack_Data          : out Ada.Streams.Stream_Element_Array;
      Index_Data         : out Ada.Streams.Stream_Element_Array;
      Base_Data          : out Ada.Streams.Stream_Element_Array;
      Delta_Data         : out Ada.Streams.Stream_Element_Array;
      Workspace          : out Ada.Streams.Stream_Element_Array;
      Kind               : out Pack_Object_Kind;
      Data               : out Ada.Streams.Stream_Element_Array;
      Last               : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   --  Read an object from loose storage or any pack, without resolving deltas.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Object_ID_Hex the object's hex-encoded id
   --  @param Pack_Checksum_Hex the pack's hex-encoded checksum
   --  @param Pack_Data the packfile bytes
   --  @param Index_Data the pack index bytes
   --  @param Kind the object type
   --  @param Data the resulting object contents
   --  @param Last index of the last valid element written
   --  @return Ok on success, or an error status on failure.
   function Read_Stored_Object
     (Repository_Root    : String;
      Object_ID_Hex      : Ada.Streams.Stream_Element_Array;
      Pack_Checksum_Hex  : Ada.Streams.Stream_Element_Array;
      Pack_Data          : out Ada.Streams.Stream_Element_Array;
      Index_Data         : out Ada.Streams.Stream_Element_Array;
      Kind               : out Pack_Object_Kind;
      Data               : out Ada.Streams.Stream_Element_Array;
      Last               : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   --  Read a stored object, resolving delta chains as needed.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Object_ID_Hex the object's hex-encoded id
   --  @param Pack_Checksum_Hex the pack's hex-encoded checksum
   --  @param Pack_Data the packfile bytes
   --  @param Index_Data the pack index bytes
   --  @param Base_Data scratch buffer for delta base objects
   --  @param Delta_Data scratch buffer for delta objects
   --  @param Workspace scratch buffer for delta-chain reconstruction
   --  @param Kind the object type
   --  @param Data the resulting object contents
   --  @param Last index of the last valid element written
   --  @return Ok on success, or an error status on failure.
   function Read_Stored_Object_Resolved
     (Repository_Root    : String;
      Object_ID_Hex      : Ada.Streams.Stream_Element_Array;
      Pack_Checksum_Hex  : Ada.Streams.Stream_Element_Array;
      Pack_Data          : out Ada.Streams.Stream_Element_Array;
      Index_Data         : out Ada.Streams.Stream_Element_Array;
      Base_Data          : out Ada.Streams.Stream_Element_Array;
      Delta_Data         : out Ada.Streams.Stream_Element_Array;
      Workspace          : out Ada.Streams.Stream_Element_Array;
      Kind               : out Pack_Object_Kind;
      Data               : out Ada.Streams.Stream_Element_Array;
      Last               : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   --  Read and delta-resolve a stored object, verifying its id.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Object_ID_Hex the object's hex-encoded id
   --  @param Pack_Checksum_Hex the pack's hex-encoded checksum
   --  @param Pack_Data the packfile bytes
   --  @param Index_Data the pack index bytes
   --  @param Base_Data scratch buffer for delta base objects
   --  @param Delta_Data scratch buffer for delta objects
   --  @param Workspace scratch buffer for delta-chain reconstruction
   --  @param Kind the object type
   --  @param Data the resulting object contents
   --  @param Last index of the last valid element written
   --  @return Ok on success, or an error status on failure.
   function Read_Stored_Object_Resolved_Validated
     (Repository_Root    : String;
      Object_ID_Hex      : Ada.Streams.Stream_Element_Array;
      Pack_Checksum_Hex  : Ada.Streams.Stream_Element_Array;
      Pack_Data          : out Ada.Streams.Stream_Element_Array;
      Index_Data         : out Ada.Streams.Stream_Element_Array;
      Base_Data          : out Ada.Streams.Stream_Element_Array;
      Delta_Data         : out Ada.Streams.Stream_Element_Array;
      Workspace          : out Ada.Streams.Stream_Element_Array;
      Kind               : out Pack_Object_Kind;
      Data               : out Ada.Streams.Stream_Element_Array;
      Last               : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   --  Read a stored object and verify its computed id.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Object_ID_Hex the object's hex-encoded id
   --  @param Pack_Checksum_Hex the pack's hex-encoded checksum
   --  @param Pack_Data the packfile bytes
   --  @param Index_Data the pack index bytes
   --  @param Kind the object type
   --  @param Data the resulting object contents
   --  @param Last index of the last valid element written
   --  @return Ok on success, or an error status on failure.
   function Read_Stored_Object_Validated
     (Repository_Root    : String;
      Object_ID_Hex      : Ada.Streams.Stream_Element_Array;
      Pack_Checksum_Hex  : Ada.Streams.Stream_Element_Array;
      Pack_Data          : out Ada.Streams.Stream_Element_Array;
      Index_Data         : out Ada.Streams.Stream_Element_Array;
      Kind               : out Pack_Object_Kind;
      Data               : out Ada.Streams.Stream_Element_Array;
      Last               : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   --  Determine whether an object exists in loose or packed storage and where.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Object_ID_Hex the object's hex-encoded id
   --  @param Pack_Checksums_Hex packed buffer of candidate pack checksums
   --  @param Pack_Checksums_Last index of the last valid element of the pack-checksums buffer
   --  @param Pack_Checksum_Hex the pack's hex-encoded checksum
   --  @param Pack_Checksum_Last index of the last valid element of the pack checksum
   --  @param Index_Data the pack index bytes
   --  @param Found set True when the item was found
   --  @return Ok on success, or an error status on failure.
   function Stored_Object_Exists
     (Repository_Root       : String;
      Object_ID_Hex         : Ada.Streams.Stream_Element_Array;
      Pack_Checksums_Hex    : out Ada.Streams.Stream_Element_Array;
      Pack_Checksums_Last   : out Ada.Streams.Stream_Element_Offset;
      Pack_Checksum_Hex     : out Ada.Streams.Stream_Element_Array;
      Pack_Checksum_Last    : out Ada.Streams.Stream_Element_Offset;
      Index_Data            : out Ada.Streams.Stream_Element_Array;
      Found                 : out Boolean)
      return CryptoLib.Errors.Status;

   --  List the checksums of all stored pack indexes.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Pack_Checksums_Hex packed buffer of candidate pack checksums
   --  @param Last index of the last valid element written
   --  @param Count the number of items produced
   --  @return Ok on success, or an error status on failure.
   function List_Pack_Index_Checksums
     (Repository_Root    : String;
      Pack_Checksums_Hex : out Ada.Streams.Stream_Element_Array;
      Last               : out Ada.Streams.Stream_Element_Offset;
      Count              : out Natural)
      return CryptoLib.Errors.Status;

   --  List the ids of all loose objects.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Object_IDs_Hex the resulting hex-encoded object ids
   --  @param Count the number of items produced
   --  @return Ok on success, or an error status on failure.
   function List_Loose_Object_IDs
     (Repository_Root : String;
      Object_IDs_Hex  : out Object_ID_Hex_Array;
      Count           : out Natural)
      return CryptoLib.Errors.Status;

   --  List the ids of all objects contained in one pack.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Pack_Checksum_Hex the pack's hex-encoded checksum
   --  @param Index_Data the pack index bytes
   --  @param Index_Last index of the last valid element of the index data
   --  @param Object_IDs_Hex the resulting hex-encoded object ids
   --  @param Count the number of items produced
   --  @return Ok on success, or an error status on failure.
   function List_Packed_Object_IDs
     (Repository_Root    : String;
      Pack_Checksum_Hex  : Ada.Streams.Stream_Element_Array;
      Index_Data         : out Ada.Streams.Stream_Element_Array;
      Index_Last         : out Ada.Streams.Stream_Element_Offset;
      Object_IDs_Hex     : out Object_ID_Hex_Array;
      Count              : out Natural)
      return CryptoLib.Errors.Status;

   --  List the ids of all objects across loose and packed storage.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Pack_Checksums_Hex packed buffer of candidate pack checksums
   --  @param Pack_Checksums_Last index of the last valid element of the pack-checksums buffer
   --  @param Index_Data the pack index bytes
   --  @param Index_Last index of the last valid element of the index data
   --  @param Object_IDs_Hex the resulting hex-encoded object ids
   --  @param Count the number of items produced
   --  @return Ok on success, or an error status on failure.
   function List_Stored_Object_IDs
     (Repository_Root       : String;
      Pack_Checksums_Hex    : out Ada.Streams.Stream_Element_Array;
      Pack_Checksums_Last   : out Ada.Streams.Stream_Element_Offset;
      Index_Data            : out Ada.Streams.Stream_Element_Array;
      Index_Last            : out Ada.Streams.Stream_Element_Offset;
      Object_IDs_Hex        : out Object_ID_Hex_Array;
      Count                 : out Natural)
      return CryptoLib.Errors.Status;

   --  Summarize ref, object, and pack counts for the whole repository.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Summary the computed summary record
   --  @return Ok on success, or an error status on failure.
   function Summarize_Repository_Database
     (Repository_Root : String;
      Summary         : out Repository_Database_Summary)
      return CryptoLib.Errors.Status;

   --  Read an object from anywhere in storage, reporting which pack held it.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Object_ID_Hex the object's hex-encoded id
   --  @param Pack_Checksums_Hex packed buffer of candidate pack checksums
   --  @param Pack_Data the packfile bytes
   --  @param Index_Data the pack index bytes
   --  @param Pack_Checksum_Hex the pack's hex-encoded checksum
   --  @param Pack_Checksum_Last index of the last valid element of the pack checksum
   --  @param Kind the object type
   --  @param Data the resulting object contents
   --  @param Last index of the last valid element written
   --  @return Ok on success, or an error status on failure.
   function Read_Any_Stored_Object
     (Repository_Root     : String;
      Object_ID_Hex       : Ada.Streams.Stream_Element_Array;
      Pack_Checksums_Hex  : out Ada.Streams.Stream_Element_Array;
      Pack_Data           : out Ada.Streams.Stream_Element_Array;
      Index_Data          : out Ada.Streams.Stream_Element_Array;
      Pack_Checksum_Hex   : out Ada.Streams.Stream_Element_Array;
      Pack_Checksum_Last  : out Ada.Streams.Stream_Element_Offset;
      Kind                : out Pack_Object_Kind;
      Data                : out Ada.Streams.Stream_Element_Array;
      Last                : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   --  Read and delta-resolve an object from anywhere in storage.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Object_ID_Hex the object's hex-encoded id
   --  @param Pack_Checksums_Hex packed buffer of candidate pack checksums
   --  @param Pack_Data the packfile bytes
   --  @param Index_Data the pack index bytes
   --  @param Base_Data scratch buffer for delta base objects
   --  @param Delta_Data scratch buffer for delta objects
   --  @param Workspace scratch buffer for delta-chain reconstruction
   --  @param Pack_Checksum_Hex the pack's hex-encoded checksum
   --  @param Pack_Checksum_Last index of the last valid element of the pack checksum
   --  @param Kind the object type
   --  @param Data the resulting object contents
   --  @param Last index of the last valid element written
   --  @return Ok on success, or an error status on failure.
   function Read_Any_Stored_Object_Resolved
     (Repository_Root     : String;
      Object_ID_Hex       : Ada.Streams.Stream_Element_Array;
      Pack_Checksums_Hex  : out Ada.Streams.Stream_Element_Array;
      Pack_Data           : out Ada.Streams.Stream_Element_Array;
      Index_Data          : out Ada.Streams.Stream_Element_Array;
      Base_Data           : out Ada.Streams.Stream_Element_Array;
      Delta_Data          : out Ada.Streams.Stream_Element_Array;
      Workspace           : out Ada.Streams.Stream_Element_Array;
      Pack_Checksum_Hex   : out Ada.Streams.Stream_Element_Array;
      Pack_Checksum_Last  : out Ada.Streams.Stream_Element_Offset;
      Kind                : out Pack_Object_Kind;
      Data                : out Ada.Streams.Stream_Element_Array;
      Last                : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   --  Read, delta-resolve, and verify an object from anywhere in storage.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Object_ID_Hex the object's hex-encoded id
   --  @param Pack_Checksums_Hex packed buffer of candidate pack checksums
   --  @param Pack_Data the packfile bytes
   --  @param Index_Data the pack index bytes
   --  @param Base_Data scratch buffer for delta base objects
   --  @param Delta_Data scratch buffer for delta objects
   --  @param Workspace scratch buffer for delta-chain reconstruction
   --  @param Pack_Checksum_Hex the pack's hex-encoded checksum
   --  @param Pack_Checksum_Last index of the last valid element of the pack checksum
   --  @param Kind the object type
   --  @param Data the resulting object contents
   --  @param Last index of the last valid element written
   --  @return Ok on success, or an error status on failure.
   function Read_Any_Stored_Object_Resolved_Validated
     (Repository_Root     : String;
      Object_ID_Hex       : Ada.Streams.Stream_Element_Array;
      Pack_Checksums_Hex  : out Ada.Streams.Stream_Element_Array;
      Pack_Data           : out Ada.Streams.Stream_Element_Array;
      Index_Data          : out Ada.Streams.Stream_Element_Array;
      Base_Data           : out Ada.Streams.Stream_Element_Array;
      Delta_Data          : out Ada.Streams.Stream_Element_Array;
      Workspace           : out Ada.Streams.Stream_Element_Array;
      Pack_Checksum_Hex   : out Ada.Streams.Stream_Element_Array;
      Pack_Checksum_Last  : out Ada.Streams.Stream_Element_Offset;
      Kind                : out Pack_Object_Kind;
      Data                : out Ada.Streams.Stream_Element_Array;
      Last                : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   --  Read and verify an object from anywhere in storage.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Object_ID_Hex the object's hex-encoded id
   --  @param Pack_Checksums_Hex packed buffer of candidate pack checksums
   --  @param Pack_Data the packfile bytes
   --  @param Index_Data the pack index bytes
   --  @param Pack_Checksum_Hex the pack's hex-encoded checksum
   --  @param Pack_Checksum_Last index of the last valid element of the pack checksum
   --  @param Kind the object type
   --  @param Data the resulting object contents
   --  @param Last index of the last valid element written
   --  @return Ok on success, or an error status on failure.
   function Read_Any_Stored_Object_Validated
     (Repository_Root     : String;
      Object_ID_Hex       : Ada.Streams.Stream_Element_Array;
      Pack_Checksums_Hex  : out Ada.Streams.Stream_Element_Array;
      Pack_Data           : out Ada.Streams.Stream_Element_Array;
      Index_Data          : out Ada.Streams.Stream_Element_Array;
      Pack_Checksum_Hex   : out Ada.Streams.Stream_Element_Array;
      Pack_Checksum_Last  : out Ada.Streams.Stream_Element_Offset;
      Kind                : out Pack_Object_Kind;
      Data                : out Ada.Streams.Stream_Element_Array;
      Last                : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   --  Read the object named by an entry within a given tree.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Tree_ID_Hex the tree's hex-encoded id
   --  @param Entry_Name the tree entry name
   --  @param Pack_Checksums_Hex packed buffer of candidate pack checksums
   --  @param Pack_Data the packfile bytes
   --  @param Index_Data the pack index bytes
   --  @param Pack_Checksum_Hex the pack's hex-encoded checksum
   --  @param Pack_Checksum_Last index of the last valid element of the pack checksum
   --  @param Tree_Data the tree object bytes
   --  @param Tree_Last index of the last valid element of the tree data
   --  @param Entry_Mode the resolved entry's file mode
   --  @param Kind the object type
   --  @param Data the resulting object contents
   --  @param Last index of the last valid element written
   --  @return Ok on success, or an error status on failure.
   function Read_Tree_Entry_Object
     (Repository_Root     : String;
      Tree_ID_Hex         : Ada.Streams.Stream_Element_Array;
      Entry_Name          : Ada.Streams.Stream_Element_Array;
      Pack_Checksums_Hex  : out Ada.Streams.Stream_Element_Array;
      Pack_Data           : out Ada.Streams.Stream_Element_Array;
      Index_Data          : out Ada.Streams.Stream_Element_Array;
      Pack_Checksum_Hex   : out Ada.Streams.Stream_Element_Array;
      Pack_Checksum_Last  : out Ada.Streams.Stream_Element_Offset;
      Tree_Data           : out Ada.Streams.Stream_Element_Array;
      Tree_Last           : out Ada.Streams.Stream_Element_Offset;
      Entry_Mode          : out Natural;
      Kind                : out Pack_Object_Kind;
      Data                : out Ada.Streams.Stream_Element_Array;
      Last                : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   --  List the entries of an in-memory tree object with hex-encoded ids.
   --  @param Tree_Data the tree object bytes
   --  @param Names packed buffer of entry names
   --  @param Name_Lasts end offset of each packed name
   --  @param Modes the file mode of each entry
   --  @param Object_IDs_Hex the resulting hex-encoded object ids
   --  @param Count the number of items produced
   --  @return Ok on success, or an error status on failure.
   function List_Tree_Entries_Hex
     (Tree_Data      : Ada.Streams.Stream_Element_Array;
      Names          : out Ada.Streams.Stream_Element_Array;
      Name_Lasts     : out Tree_Entry_Name_Last_Array;
      Modes          : out Tree_Entry_Mode_Array;
      Object_IDs_Hex : out Object_ID_Hex_Array;
      Count          : out Natural)
      return CryptoLib.Errors.Status;

   --  Read a tree object by id and list its entries with hex ids.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Tree_ID_Hex the tree's hex-encoded id
   --  @param Pack_Checksums_Hex packed buffer of candidate pack checksums
   --  @param Pack_Data the packfile bytes
   --  @param Index_Data the pack index bytes
   --  @param Pack_Checksum_Hex the pack's hex-encoded checksum
   --  @param Pack_Checksum_Last index of the last valid element of the pack checksum
   --  @param Tree_Data the tree object bytes
   --  @param Tree_Last index of the last valid element of the tree data
   --  @param Names packed buffer of entry names
   --  @param Name_Lasts end offset of each packed name
   --  @param Modes the file mode of each entry
   --  @param Object_IDs_Hex the resulting hex-encoded object ids
   --  @param Count the number of items produced
   --  @return Ok on success, or an error status on failure.
   function Read_Tree_Entries_Hex
     (Repository_Root     : String;
      Tree_ID_Hex         : Ada.Streams.Stream_Element_Array;
      Pack_Checksums_Hex  : out Ada.Streams.Stream_Element_Array;
      Pack_Data           : out Ada.Streams.Stream_Element_Array;
      Index_Data          : out Ada.Streams.Stream_Element_Array;
      Pack_Checksum_Hex   : out Ada.Streams.Stream_Element_Array;
      Pack_Checksum_Last  : out Ada.Streams.Stream_Element_Offset;
      Tree_Data           : out Ada.Streams.Stream_Element_Array;
      Tree_Last           : out Ada.Streams.Stream_Element_Offset;
      Names               : out Ada.Streams.Stream_Element_Array;
      Name_Lasts          : out Tree_Entry_Name_Last_Array;
      Modes               : out Tree_Entry_Mode_Array;
      Object_IDs_Hex      : out Object_ID_Hex_Array;
      Count               : out Natural)
      return CryptoLib.Errors.Status;

   --  Recursively list every path reachable from a root tree.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Root_Tree_ID_Hex the root tree's hex-encoded id
   --  @param Paths packed buffer of the path names
   --  @param Path_Lasts end offset of each packed path name
   --  @param Modes the file mode of each entry
   --  @param Object_IDs_Hex the resulting hex-encoded object ids
   --  @param Count the number of items produced
   --  @return Ok on success, or an error status on failure.
   function List_Tree_Paths_Hex
     (Repository_Root : String;
      Root_Tree_ID_Hex : Ada.Streams.Stream_Element_Array;
      Paths           : out Ada.Streams.Stream_Element_Array;
      Path_Lasts      : out Index_Path_Last_Array;
      Modes           : out Tree_Entry_Mode_Array;
      Object_IDs_Hex  : out Object_ID_Hex_Array;
      Count           : out Natural)
      return CryptoLib.Errors.Status;

   --  Recursively list root-tree paths matching a pathspec.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Root_Tree_ID_Hex the root tree's hex-encoded id
   --  @param Pathspec the pathspec pattern to match
   --  @param Paths packed buffer of the path names
   --  @param Path_Lasts end offset of each packed path name
   --  @param Modes the file mode of each entry
   --  @param Object_IDs_Hex the resulting hex-encoded object ids
   --  @param Count the number of items produced
   --  @return Ok on success, or an error status on failure.
   function List_Tree_Paths_Matching_Hex
     (Repository_Root  : String;
      Root_Tree_ID_Hex : Ada.Streams.Stream_Element_Array;
      Pathspec         : String;
      Paths            : out Ada.Streams.Stream_Element_Array;
      Path_Lasts       : out Index_Path_Last_Array;
      Modes            : out Tree_Entry_Mode_Array;
      Object_IDs_Hex   : out Object_ID_Hex_Array;
      Count            : out Natural)
      return CryptoLib.Errors.Status;

   --  Read the object at a path resolved from a root tree.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Root_Tree_ID_Hex the root tree's hex-encoded id
   --  @param Path the repository-relative path
   --  @param Pack_Checksums_Hex packed buffer of candidate pack checksums
   --  @param Pack_Data the packfile bytes
   --  @param Index_Data the pack index bytes
   --  @param Pack_Checksum_Hex the pack's hex-encoded checksum
   --  @param Pack_Checksum_Last index of the last valid element of the pack checksum
   --  @param Tree_Data the tree object bytes
   --  @param Tree_Last index of the last valid element of the tree data
   --  @param Entry_Mode the resolved entry's file mode
   --  @param Kind the object type
   --  @param Data the resulting object contents
   --  @param Last index of the last valid element written
   --  @return Ok on success, or an error status on failure.
   function Read_Path_Object
     (Repository_Root     : String;
      Root_Tree_ID_Hex    : Ada.Streams.Stream_Element_Array;
      Path                : Ada.Streams.Stream_Element_Array;
      Pack_Checksums_Hex  : out Ada.Streams.Stream_Element_Array;
      Pack_Data           : out Ada.Streams.Stream_Element_Array;
      Index_Data          : out Ada.Streams.Stream_Element_Array;
      Pack_Checksum_Hex   : out Ada.Streams.Stream_Element_Array;
      Pack_Checksum_Last  : out Ada.Streams.Stream_Element_Offset;
      Tree_Data           : out Ada.Streams.Stream_Element_Array;
      Tree_Last           : out Ada.Streams.Stream_Element_Offset;
      Entry_Mode          : out Natural;
      Kind                : out Pack_Object_Kind;
      Data                : out Ada.Streams.Stream_Element_Array;
      Last                : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   --  Resolve a path within a root tree to its entry mode and object id.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Root_Tree_ID_Hex the root tree's hex-encoded id
   --  @param Path the repository-relative path
   --  @param Pack_Checksums_Hex packed buffer of candidate pack checksums
   --  @param Pack_Data the packfile bytes
   --  @param Index_Data the pack index bytes
   --  @param Pack_Checksum_Hex the pack's hex-encoded checksum
   --  @param Pack_Checksum_Last index of the last valid element of the pack checksum
   --  @param Tree_Data the tree object bytes
   --  @param Tree_Last index of the last valid element of the tree data
   --  @param Entry_Mode the resolved entry's file mode
   --  @param Entry_ID_Hex the resolved entry's hex id
   --  @param Entry_ID_Last index of the last valid element of the entry id
   --  @return Ok on success, or an error status on failure.
   function Resolve_Path_Entry_Hex
     (Repository_Root     : String;
      Root_Tree_ID_Hex    : Ada.Streams.Stream_Element_Array;
      Path                : Ada.Streams.Stream_Element_Array;
      Pack_Checksums_Hex  : out Ada.Streams.Stream_Element_Array;
      Pack_Data           : out Ada.Streams.Stream_Element_Array;
      Index_Data          : out Ada.Streams.Stream_Element_Array;
      Pack_Checksum_Hex   : out Ada.Streams.Stream_Element_Array;
      Pack_Checksum_Last  : out Ada.Streams.Stream_Element_Offset;
      Tree_Data           : out Ada.Streams.Stream_Element_Array;
      Tree_Last           : out Ada.Streams.Stream_Element_Offset;
      Entry_Mode          : out Natural;
      Entry_ID_Hex        : out Ada.Streams.Stream_Element_Array;
      Entry_ID_Last       : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   --  Resolve a path to a subtree within a root tree and list its entries.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Root_Tree_ID_Hex the root tree's hex-encoded id
   --  @param Path the repository-relative path
   --  @param Pack_Checksums_Hex packed buffer of candidate pack checksums
   --  @param Pack_Data the packfile bytes
   --  @param Index_Data the pack index bytes
   --  @param Pack_Checksum_Hex the pack's hex-encoded checksum
   --  @param Pack_Checksum_Last index of the last valid element of the pack checksum
   --  @param Path_Tree_Data the subtree object bytes for the path
   --  @param Path_Tree_Last index of the last valid element of the subtree data
   --  @param Path_Mode the file mode of the resolved path
   --  @param Tree_Data the tree object bytes
   --  @param Tree_Last index of the last valid element of the tree data
   --  @param Names packed buffer of entry names
   --  @param Name_Lasts end offset of each packed name
   --  @param Modes the file mode of each entry
   --  @param Object_IDs_Hex the resulting hex-encoded object ids
   --  @param Count the number of items produced
   --  @return Ok on success, or an error status on failure.
   function Read_Path_Tree_Entries_Hex
     (Repository_Root     : String;
      Root_Tree_ID_Hex    : Ada.Streams.Stream_Element_Array;
      Path                : Ada.Streams.Stream_Element_Array;
      Pack_Checksums_Hex  : out Ada.Streams.Stream_Element_Array;
      Pack_Data           : out Ada.Streams.Stream_Element_Array;
      Index_Data          : out Ada.Streams.Stream_Element_Array;
      Pack_Checksum_Hex   : out Ada.Streams.Stream_Element_Array;
      Pack_Checksum_Last  : out Ada.Streams.Stream_Element_Offset;
      Path_Tree_Data      : out Ada.Streams.Stream_Element_Array;
      Path_Tree_Last      : out Ada.Streams.Stream_Element_Offset;
      Path_Mode           : out Natural;
      Tree_Data           : out Ada.Streams.Stream_Element_Array;
      Tree_Last           : out Ada.Streams.Stream_Element_Offset;
      Names               : out Ada.Streams.Stream_Element_Array;
      Name_Lasts          : out Tree_Entry_Name_Last_Array;
      Modes               : out Tree_Entry_Mode_Array;
      Object_IDs_Hex      : out Object_ID_Hex_Array;
      Count               : out Natural)
      return CryptoLib.Errors.Status;

   --  Read the object at a path within a commit's tree.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Commit_ID_Hex the commit's hex-encoded id
   --  @param Path the repository-relative path
   --  @param Pack_Checksums_Hex packed buffer of candidate pack checksums
   --  @param Pack_Data the packfile bytes
   --  @param Index_Data the pack index bytes
   --  @param Pack_Checksum_Hex the pack's hex-encoded checksum
   --  @param Pack_Checksum_Last index of the last valid element of the pack checksum
   --  @param Commit_Data the commit object bytes
   --  @param Commit_Last index of the last valid element of the commit data
   --  @param Root_Tree_ID_Hex the root tree's hex-encoded id
   --  @param Root_Tree_ID_Last index of the last valid element of the root tree id
   --  @param Tree_Data the tree object bytes
   --  @param Tree_Last index of the last valid element of the tree data
   --  @param Entry_Mode the resolved entry's file mode
   --  @param Kind the object type
   --  @param Data the resulting object contents
   --  @param Last index of the last valid element written
   --  @return Ok on success, or an error status on failure.
   function Read_Commit_Path_Object
     (Repository_Root     : String;
      Commit_ID_Hex       : Ada.Streams.Stream_Element_Array;
      Path                : Ada.Streams.Stream_Element_Array;
      Pack_Checksums_Hex  : out Ada.Streams.Stream_Element_Array;
      Pack_Data           : out Ada.Streams.Stream_Element_Array;
      Index_Data          : out Ada.Streams.Stream_Element_Array;
      Pack_Checksum_Hex   : out Ada.Streams.Stream_Element_Array;
      Pack_Checksum_Last  : out Ada.Streams.Stream_Element_Offset;
      Commit_Data         : out Ada.Streams.Stream_Element_Array;
      Commit_Last         : out Ada.Streams.Stream_Element_Offset;
      Root_Tree_ID_Hex    : out Ada.Streams.Stream_Element_Array;
      Root_Tree_ID_Last   : out Ada.Streams.Stream_Element_Offset;
      Tree_Data           : out Ada.Streams.Stream_Element_Array;
      Tree_Last           : out Ada.Streams.Stream_Element_Offset;
      Entry_Mode          : out Natural;
      Kind                : out Pack_Object_Kind;
      Data                : out Ada.Streams.Stream_Element_Array;
      Last                : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   --  Resolve a path within a commit's tree to its entry mode and id.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Commit_ID_Hex the commit's hex-encoded id
   --  @param Path the repository-relative path
   --  @param Pack_Checksums_Hex packed buffer of candidate pack checksums
   --  @param Pack_Data the packfile bytes
   --  @param Index_Data the pack index bytes
   --  @param Pack_Checksum_Hex the pack's hex-encoded checksum
   --  @param Pack_Checksum_Last index of the last valid element of the pack checksum
   --  @param Commit_Data the commit object bytes
   --  @param Commit_Last index of the last valid element of the commit data
   --  @param Root_Tree_ID_Hex the root tree's hex-encoded id
   --  @param Root_Tree_ID_Last index of the last valid element of the root tree id
   --  @param Tree_Data the tree object bytes
   --  @param Tree_Last index of the last valid element of the tree data
   --  @param Entry_Mode the resolved entry's file mode
   --  @param Entry_ID_Hex the resolved entry's hex id
   --  @param Entry_ID_Last index of the last valid element of the entry id
   --  @return Ok on success, or an error status on failure.
   function Resolve_Commit_Path_Entry_Hex
     (Repository_Root     : String;
      Commit_ID_Hex       : Ada.Streams.Stream_Element_Array;
      Path                : Ada.Streams.Stream_Element_Array;
      Pack_Checksums_Hex  : out Ada.Streams.Stream_Element_Array;
      Pack_Data           : out Ada.Streams.Stream_Element_Array;
      Index_Data          : out Ada.Streams.Stream_Element_Array;
      Pack_Checksum_Hex   : out Ada.Streams.Stream_Element_Array;
      Pack_Checksum_Last  : out Ada.Streams.Stream_Element_Offset;
      Commit_Data         : out Ada.Streams.Stream_Element_Array;
      Commit_Last         : out Ada.Streams.Stream_Element_Offset;
      Root_Tree_ID_Hex    : out Ada.Streams.Stream_Element_Array;
      Root_Tree_ID_Last   : out Ada.Streams.Stream_Element_Offset;
      Tree_Data           : out Ada.Streams.Stream_Element_Array;
      Tree_Last           : out Ada.Streams.Stream_Element_Offset;
      Entry_Mode          : out Natural;
      Entry_ID_Hex        : out Ada.Streams.Stream_Element_Array;
      Entry_ID_Last       : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   --  Read a commit and its root tree object.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Commit_ID_Hex the commit's hex-encoded id
   --  @param Pack_Checksums_Hex packed buffer of candidate pack checksums
   --  @param Pack_Data the packfile bytes
   --  @param Index_Data the pack index bytes
   --  @param Pack_Checksum_Hex the pack's hex-encoded checksum
   --  @param Pack_Checksum_Last index of the last valid element of the pack checksum
   --  @param Commit_Data the commit object bytes
   --  @param Commit_Last index of the last valid element of the commit data
   --  @param Root_Tree_ID_Hex the root tree's hex-encoded id
   --  @param Root_Tree_ID_Last index of the last valid element of the root tree id
   --  @param Tree_Data the tree object bytes
   --  @param Tree_Last index of the last valid element of the tree data
   --  @param Entry_Count the number of entries
   --  @return Ok on success, or an error status on failure.
   function Read_Commit_Tree_Object
     (Repository_Root     : String;
      Commit_ID_Hex       : Ada.Streams.Stream_Element_Array;
      Pack_Checksums_Hex  : out Ada.Streams.Stream_Element_Array;
      Pack_Data           : out Ada.Streams.Stream_Element_Array;
      Index_Data          : out Ada.Streams.Stream_Element_Array;
      Pack_Checksum_Hex   : out Ada.Streams.Stream_Element_Array;
      Pack_Checksum_Last  : out Ada.Streams.Stream_Element_Offset;
      Commit_Data         : out Ada.Streams.Stream_Element_Array;
      Commit_Last         : out Ada.Streams.Stream_Element_Offset;
      Root_Tree_ID_Hex    : out Ada.Streams.Stream_Element_Array;
      Root_Tree_ID_Last   : out Ada.Streams.Stream_Element_Offset;
      Tree_Data           : out Ada.Streams.Stream_Element_Array;
      Tree_Last           : out Ada.Streams.Stream_Element_Offset;
      Entry_Count         : out Natural)
      return CryptoLib.Errors.Status;

   --  Read a commit's root tree and list its entries.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Commit_ID_Hex the commit's hex-encoded id
   --  @param Pack_Checksums_Hex packed buffer of candidate pack checksums
   --  @param Pack_Data the packfile bytes
   --  @param Index_Data the pack index bytes
   --  @param Pack_Checksum_Hex the pack's hex-encoded checksum
   --  @param Pack_Checksum_Last index of the last valid element of the pack checksum
   --  @param Commit_Data the commit object bytes
   --  @param Commit_Last index of the last valid element of the commit data
   --  @param Root_Tree_ID_Hex the root tree's hex-encoded id
   --  @param Root_Tree_ID_Last index of the last valid element of the root tree id
   --  @param Tree_Data the tree object bytes
   --  @param Tree_Last index of the last valid element of the tree data
   --  @param Names packed buffer of entry names
   --  @param Name_Lasts end offset of each packed name
   --  @param Modes the file mode of each entry
   --  @param Object_IDs_Hex the resulting hex-encoded object ids
   --  @param Count the number of items produced
   --  @return Ok on success, or an error status on failure.
   function Read_Commit_Tree_Entries_Hex
     (Repository_Root     : String;
      Commit_ID_Hex       : Ada.Streams.Stream_Element_Array;
      Pack_Checksums_Hex  : out Ada.Streams.Stream_Element_Array;
      Pack_Data           : out Ada.Streams.Stream_Element_Array;
      Index_Data          : out Ada.Streams.Stream_Element_Array;
      Pack_Checksum_Hex   : out Ada.Streams.Stream_Element_Array;
      Pack_Checksum_Last  : out Ada.Streams.Stream_Element_Offset;
      Commit_Data         : out Ada.Streams.Stream_Element_Array;
      Commit_Last         : out Ada.Streams.Stream_Element_Offset;
      Root_Tree_ID_Hex    : out Ada.Streams.Stream_Element_Array;
      Root_Tree_ID_Last   : out Ada.Streams.Stream_Element_Offset;
      Tree_Data           : out Ada.Streams.Stream_Element_Array;
      Tree_Last           : out Ada.Streams.Stream_Element_Offset;
      Names               : out Ada.Streams.Stream_Element_Array;
      Name_Lasts          : out Tree_Entry_Name_Last_Array;
      Modes               : out Tree_Entry_Mode_Array;
      Object_IDs_Hex      : out Object_ID_Hex_Array;
      Count               : out Natural)
      return CryptoLib.Errors.Status;

   --  Recursively list every path in a commit's tree.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Commit_ID_Hex the commit's hex-encoded id
   --  @param Paths packed buffer of the path names
   --  @param Path_Lasts end offset of each packed path name
   --  @param Modes the file mode of each entry
   --  @param Object_IDs_Hex the resulting hex-encoded object ids
   --  @param Count the number of items produced
   --  @return Ok on success, or an error status on failure.
   function List_Commit_Tree_Paths_Hex
     (Repository_Root : String;
      Commit_ID_Hex   : Ada.Streams.Stream_Element_Array;
      Paths           : out Ada.Streams.Stream_Element_Array;
      Path_Lasts      : out Index_Path_Last_Array;
      Modes           : out Tree_Entry_Mode_Array;
      Object_IDs_Hex  : out Object_ID_Hex_Array;
      Count           : out Natural)
      return CryptoLib.Errors.Status;

   --  Recursively list commit-tree paths matching a pathspec.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Commit_ID_Hex the commit's hex-encoded id
   --  @param Pathspec the pathspec pattern to match
   --  @param Paths packed buffer of the path names
   --  @param Path_Lasts end offset of each packed path name
   --  @param Modes the file mode of each entry
   --  @param Object_IDs_Hex the resulting hex-encoded object ids
   --  @param Count the number of items produced
   --  @return Ok on success, or an error status on failure.
   function List_Commit_Tree_Paths_Matching_Hex
     (Repository_Root : String;
      Commit_ID_Hex   : Ada.Streams.Stream_Element_Array;
      Pathspec        : String;
      Paths           : out Ada.Streams.Stream_Element_Array;
      Path_Lasts      : out Index_Path_Last_Array;
      Modes           : out Tree_Entry_Mode_Array;
      Object_IDs_Hex  : out Object_ID_Hex_Array;
      Count           : out Natural)
      return CryptoLib.Errors.Status;

   --  Resolve a path to a subtree within a commit and list its entries.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Commit_ID_Hex the commit's hex-encoded id
   --  @param Path the repository-relative path
   --  @param Pack_Checksums_Hex packed buffer of candidate pack checksums
   --  @param Pack_Data the packfile bytes
   --  @param Index_Data the pack index bytes
   --  @param Pack_Checksum_Hex the pack's hex-encoded checksum
   --  @param Pack_Checksum_Last index of the last valid element of the pack checksum
   --  @param Commit_Data the commit object bytes
   --  @param Commit_Last index of the last valid element of the commit data
   --  @param Root_Tree_ID_Hex the root tree's hex-encoded id
   --  @param Root_Tree_ID_Last index of the last valid element of the root tree id
   --  @param Path_Tree_Data the subtree object bytes for the path
   --  @param Path_Tree_Last index of the last valid element of the subtree data
   --  @param Path_Mode the file mode of the resolved path
   --  @param Tree_Data the tree object bytes
   --  @param Tree_Last index of the last valid element of the tree data
   --  @param Names packed buffer of entry names
   --  @param Name_Lasts end offset of each packed name
   --  @param Modes the file mode of each entry
   --  @param Object_IDs_Hex the resulting hex-encoded object ids
   --  @param Count the number of items produced
   --  @return Ok on success, or an error status on failure.
   function Read_Commit_Path_Tree_Entries_Hex
     (Repository_Root     : String;
      Commit_ID_Hex       : Ada.Streams.Stream_Element_Array;
      Path                : Ada.Streams.Stream_Element_Array;
      Pack_Checksums_Hex  : out Ada.Streams.Stream_Element_Array;
      Pack_Data           : out Ada.Streams.Stream_Element_Array;
      Index_Data          : out Ada.Streams.Stream_Element_Array;
      Pack_Checksum_Hex   : out Ada.Streams.Stream_Element_Array;
      Pack_Checksum_Last  : out Ada.Streams.Stream_Element_Offset;
      Commit_Data         : out Ada.Streams.Stream_Element_Array;
      Commit_Last         : out Ada.Streams.Stream_Element_Offset;
      Root_Tree_ID_Hex    : out Ada.Streams.Stream_Element_Array;
      Root_Tree_ID_Last   : out Ada.Streams.Stream_Element_Offset;
      Path_Tree_Data      : out Ada.Streams.Stream_Element_Array;
      Path_Tree_Last      : out Ada.Streams.Stream_Element_Offset;
      Path_Mode           : out Natural;
      Tree_Data           : out Ada.Streams.Stream_Element_Array;
      Tree_Last           : out Ada.Streams.Stream_Element_Offset;
      Names               : out Ada.Streams.Stream_Element_Array;
      Name_Lasts          : out Tree_Entry_Name_Last_Array;
      Modes               : out Tree_Entry_Mode_Array;
      Object_IDs_Hex      : out Object_ID_Hex_Array;
      Count               : out Natural)
      return CryptoLib.Errors.Status;

   --  Resolve a ref, then read the object at a path within its tree.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Ref_Name the ref name
   --  @param Path the repository-relative path
   --  @param Resolved_ID_Hex the resolved object's hex id
   --  @param Resolved_ID_Last index of the last valid element of the resolved id
   --  @param Pack_Checksums_Hex packed buffer of candidate pack checksums
   --  @param Pack_Data the packfile bytes
   --  @param Index_Data the pack index bytes
   --  @param Pack_Checksum_Hex the pack's hex-encoded checksum
   --  @param Pack_Checksum_Last index of the last valid element of the pack checksum
   --  @param Commit_Data the commit object bytes
   --  @param Commit_Last index of the last valid element of the commit data
   --  @param Root_Tree_ID_Hex the root tree's hex-encoded id
   --  @param Root_Tree_ID_Last index of the last valid element of the root tree id
   --  @param Tree_Data the tree object bytes
   --  @param Tree_Last index of the last valid element of the tree data
   --  @param Entry_Mode the resolved entry's file mode
   --  @param Kind the object type
   --  @param Data the resulting object contents
   --  @param Last index of the last valid element written
   --  @return Ok on success, or an error status on failure.
   function Read_Ref_Path_Object
     (Repository_Root     : String;
      Ref_Name            : String;
      Path                : Ada.Streams.Stream_Element_Array;
      Resolved_ID_Hex     : out Ada.Streams.Stream_Element_Array;
      Resolved_ID_Last    : out Ada.Streams.Stream_Element_Offset;
      Pack_Checksums_Hex  : out Ada.Streams.Stream_Element_Array;
      Pack_Data           : out Ada.Streams.Stream_Element_Array;
      Index_Data          : out Ada.Streams.Stream_Element_Array;
      Pack_Checksum_Hex   : out Ada.Streams.Stream_Element_Array;
      Pack_Checksum_Last  : out Ada.Streams.Stream_Element_Offset;
      Commit_Data         : out Ada.Streams.Stream_Element_Array;
      Commit_Last         : out Ada.Streams.Stream_Element_Offset;
      Root_Tree_ID_Hex    : out Ada.Streams.Stream_Element_Array;
      Root_Tree_ID_Last   : out Ada.Streams.Stream_Element_Offset;
      Tree_Data           : out Ada.Streams.Stream_Element_Array;
      Tree_Last           : out Ada.Streams.Stream_Element_Offset;
      Entry_Mode          : out Natural;
      Kind                : out Pack_Object_Kind;
      Data                : out Ada.Streams.Stream_Element_Array;
      Last                : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   --  Resolve a ref and list the entries of a subtree at a path.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Ref_Name the ref name
   --  @param Path the repository-relative path
   --  @param Resolved_ID_Hex the resolved object's hex id
   --  @param Resolved_ID_Last index of the last valid element of the resolved id
   --  @param Pack_Checksums_Hex packed buffer of candidate pack checksums
   --  @param Pack_Data the packfile bytes
   --  @param Index_Data the pack index bytes
   --  @param Pack_Checksum_Hex the pack's hex-encoded checksum
   --  @param Pack_Checksum_Last index of the last valid element of the pack checksum
   --  @param Commit_Data the commit object bytes
   --  @param Commit_Last index of the last valid element of the commit data
   --  @param Root_Tree_ID_Hex the root tree's hex-encoded id
   --  @param Root_Tree_ID_Last index of the last valid element of the root tree id
   --  @param Path_Tree_Data the subtree object bytes for the path
   --  @param Path_Tree_Last index of the last valid element of the subtree data
   --  @param Path_Mode the file mode of the resolved path
   --  @param Tree_Data the tree object bytes
   --  @param Tree_Last index of the last valid element of the tree data
   --  @param Names packed buffer of entry names
   --  @param Name_Lasts end offset of each packed name
   --  @param Modes the file mode of each entry
   --  @param Object_IDs_Hex the resulting hex-encoded object ids
   --  @param Count the number of items produced
   --  @return Ok on success, or an error status on failure.
   function Read_Ref_Path_Tree_Entries_Hex
     (Repository_Root     : String;
      Ref_Name            : String;
      Path                : Ada.Streams.Stream_Element_Array;
      Resolved_ID_Hex     : out Ada.Streams.Stream_Element_Array;
      Resolved_ID_Last    : out Ada.Streams.Stream_Element_Offset;
      Pack_Checksums_Hex  : out Ada.Streams.Stream_Element_Array;
      Pack_Data           : out Ada.Streams.Stream_Element_Array;
      Index_Data          : out Ada.Streams.Stream_Element_Array;
      Pack_Checksum_Hex   : out Ada.Streams.Stream_Element_Array;
      Pack_Checksum_Last  : out Ada.Streams.Stream_Element_Offset;
      Commit_Data         : out Ada.Streams.Stream_Element_Array;
      Commit_Last         : out Ada.Streams.Stream_Element_Offset;
      Root_Tree_ID_Hex    : out Ada.Streams.Stream_Element_Array;
      Root_Tree_ID_Last   : out Ada.Streams.Stream_Element_Offset;
      Path_Tree_Data      : out Ada.Streams.Stream_Element_Array;
      Path_Tree_Last      : out Ada.Streams.Stream_Element_Offset;
      Path_Mode           : out Natural;
      Tree_Data           : out Ada.Streams.Stream_Element_Array;
      Tree_Last           : out Ada.Streams.Stream_Element_Offset;
      Names               : out Ada.Streams.Stream_Element_Array;
      Name_Lasts          : out Tree_Entry_Name_Last_Array;
      Modes               : out Tree_Entry_Mode_Array;
      Object_IDs_Hex      : out Object_ID_Hex_Array;
      Count               : out Natural)
      return CryptoLib.Errors.Status;

   --  Resolve a ref, then resolve a path to its entry mode and id.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Ref_Name the ref name
   --  @param Path the repository-relative path
   --  @param Resolved_ID_Hex the resolved object's hex id
   --  @param Resolved_ID_Last index of the last valid element of the resolved id
   --  @param Pack_Checksums_Hex packed buffer of candidate pack checksums
   --  @param Pack_Data the packfile bytes
   --  @param Index_Data the pack index bytes
   --  @param Pack_Checksum_Hex the pack's hex-encoded checksum
   --  @param Pack_Checksum_Last index of the last valid element of the pack checksum
   --  @param Commit_Data the commit object bytes
   --  @param Commit_Last index of the last valid element of the commit data
   --  @param Root_Tree_ID_Hex the root tree's hex-encoded id
   --  @param Root_Tree_ID_Last index of the last valid element of the root tree id
   --  @param Tree_Data the tree object bytes
   --  @param Tree_Last index of the last valid element of the tree data
   --  @param Entry_Mode the resolved entry's file mode
   --  @param Entry_ID_Hex the resolved entry's hex id
   --  @param Entry_ID_Last index of the last valid element of the entry id
   --  @return Ok on success, or an error status on failure.
   function Resolve_Ref_Path_Entry_Hex
     (Repository_Root     : String;
      Ref_Name            : String;
      Path                : Ada.Streams.Stream_Element_Array;
      Resolved_ID_Hex     : out Ada.Streams.Stream_Element_Array;
      Resolved_ID_Last    : out Ada.Streams.Stream_Element_Offset;
      Pack_Checksums_Hex  : out Ada.Streams.Stream_Element_Array;
      Pack_Data           : out Ada.Streams.Stream_Element_Array;
      Index_Data          : out Ada.Streams.Stream_Element_Array;
      Pack_Checksum_Hex   : out Ada.Streams.Stream_Element_Array;
      Pack_Checksum_Last  : out Ada.Streams.Stream_Element_Offset;
      Commit_Data         : out Ada.Streams.Stream_Element_Array;
      Commit_Last         : out Ada.Streams.Stream_Element_Offset;
      Root_Tree_ID_Hex    : out Ada.Streams.Stream_Element_Array;
      Root_Tree_ID_Last   : out Ada.Streams.Stream_Element_Offset;
      Tree_Data           : out Ada.Streams.Stream_Element_Array;
      Tree_Last           : out Ada.Streams.Stream_Element_Offset;
      Entry_Mode          : out Natural;
      Entry_ID_Hex        : out Ada.Streams.Stream_Element_Array;
      Entry_ID_Last       : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   --  Peel a tag to a commit, then read the object at a path in its tree.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Tag_ID_Hex the tag object's hex id
   --  @param Path the repository-relative path
   --  @param Peeled_Commit_Hex the peeled commit's hex id
   --  @param Peeled_Commit_Last index of the last valid element of the peeled commit id
   --  @param Pack_Checksums_Hex packed buffer of candidate pack checksums
   --  @param Pack_Data the packfile bytes
   --  @param Index_Data the pack index bytes
   --  @param Pack_Checksum_Hex the pack's hex-encoded checksum
   --  @param Pack_Checksum_Last index of the last valid element of the pack checksum
   --  @param Tag_Data the tag object bytes
   --  @param Tag_Last index of the last valid element of the tag data
   --  @param Commit_Data the commit object bytes
   --  @param Commit_Last index of the last valid element of the commit data
   --  @param Root_Tree_ID_Hex the root tree's hex-encoded id
   --  @param Root_Tree_ID_Last index of the last valid element of the root tree id
   --  @param Tree_Data the tree object bytes
   --  @param Tree_Last index of the last valid element of the tree data
   --  @param Entry_Mode the resolved entry's file mode
   --  @param Kind the object type
   --  @param Data the resulting object contents
   --  @param Last index of the last valid element written
   --  @return Ok on success, or an error status on failure.
   function Read_Tag_Path_Object
     (Repository_Root     : String;
      Tag_ID_Hex          : Ada.Streams.Stream_Element_Array;
      Path                : Ada.Streams.Stream_Element_Array;
      Peeled_Commit_Hex   : out Ada.Streams.Stream_Element_Array;
      Peeled_Commit_Last  : out Ada.Streams.Stream_Element_Offset;
      Pack_Checksums_Hex  : out Ada.Streams.Stream_Element_Array;
      Pack_Data           : out Ada.Streams.Stream_Element_Array;
      Index_Data          : out Ada.Streams.Stream_Element_Array;
      Pack_Checksum_Hex   : out Ada.Streams.Stream_Element_Array;
      Pack_Checksum_Last  : out Ada.Streams.Stream_Element_Offset;
      Tag_Data            : out Ada.Streams.Stream_Element_Array;
      Tag_Last            : out Ada.Streams.Stream_Element_Offset;
      Commit_Data         : out Ada.Streams.Stream_Element_Array;
      Commit_Last         : out Ada.Streams.Stream_Element_Offset;
      Root_Tree_ID_Hex    : out Ada.Streams.Stream_Element_Array;
      Root_Tree_ID_Last   : out Ada.Streams.Stream_Element_Offset;
      Tree_Data           : out Ada.Streams.Stream_Element_Array;
      Tree_Last           : out Ada.Streams.Stream_Element_Offset;
      Entry_Mode          : out Natural;
      Kind                : out Pack_Object_Kind;
      Data                : out Ada.Streams.Stream_Element_Array;
      Last                : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   --  Peel a tag and list the entries of a subtree at a path.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Tag_ID_Hex the tag object's hex id
   --  @param Path the repository-relative path
   --  @param Peeled_Commit_Hex the peeled commit's hex id
   --  @param Peeled_Commit_Last index of the last valid element of the peeled commit id
   --  @param Pack_Checksums_Hex packed buffer of candidate pack checksums
   --  @param Pack_Data the packfile bytes
   --  @param Index_Data the pack index bytes
   --  @param Pack_Checksum_Hex the pack's hex-encoded checksum
   --  @param Pack_Checksum_Last index of the last valid element of the pack checksum
   --  @param Tag_Data the tag object bytes
   --  @param Tag_Last index of the last valid element of the tag data
   --  @param Commit_Data the commit object bytes
   --  @param Commit_Last index of the last valid element of the commit data
   --  @param Root_Tree_ID_Hex the root tree's hex-encoded id
   --  @param Root_Tree_ID_Last index of the last valid element of the root tree id
   --  @param Path_Tree_Data the subtree object bytes for the path
   --  @param Path_Tree_Last index of the last valid element of the subtree data
   --  @param Path_Mode the file mode of the resolved path
   --  @param Tree_Data the tree object bytes
   --  @param Tree_Last index of the last valid element of the tree data
   --  @param Names packed buffer of entry names
   --  @param Name_Lasts end offset of each packed name
   --  @param Modes the file mode of each entry
   --  @param Object_IDs_Hex the resulting hex-encoded object ids
   --  @param Count the number of items produced
   --  @return Ok on success, or an error status on failure.
   function Read_Tag_Path_Tree_Entries_Hex
     (Repository_Root     : String;
      Tag_ID_Hex          : Ada.Streams.Stream_Element_Array;
      Path                : Ada.Streams.Stream_Element_Array;
      Peeled_Commit_Hex   : out Ada.Streams.Stream_Element_Array;
      Peeled_Commit_Last  : out Ada.Streams.Stream_Element_Offset;
      Pack_Checksums_Hex  : out Ada.Streams.Stream_Element_Array;
      Pack_Data           : out Ada.Streams.Stream_Element_Array;
      Index_Data          : out Ada.Streams.Stream_Element_Array;
      Pack_Checksum_Hex   : out Ada.Streams.Stream_Element_Array;
      Pack_Checksum_Last  : out Ada.Streams.Stream_Element_Offset;
      Tag_Data            : out Ada.Streams.Stream_Element_Array;
      Tag_Last            : out Ada.Streams.Stream_Element_Offset;
      Commit_Data         : out Ada.Streams.Stream_Element_Array;
      Commit_Last         : out Ada.Streams.Stream_Element_Offset;
      Root_Tree_ID_Hex    : out Ada.Streams.Stream_Element_Array;
      Root_Tree_ID_Last   : out Ada.Streams.Stream_Element_Offset;
      Path_Tree_Data      : out Ada.Streams.Stream_Element_Array;
      Path_Tree_Last      : out Ada.Streams.Stream_Element_Offset;
      Path_Mode           : out Natural;
      Tree_Data           : out Ada.Streams.Stream_Element_Array;
      Tree_Last           : out Ada.Streams.Stream_Element_Offset;
      Names               : out Ada.Streams.Stream_Element_Array;
      Name_Lasts          : out Tree_Entry_Name_Last_Array;
      Modes               : out Tree_Entry_Mode_Array;
      Object_IDs_Hex      : out Object_ID_Hex_Array;
      Count               : out Natural)
      return CryptoLib.Errors.Status;

   --  Peel a tag, then resolve a path to its entry mode and id.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Tag_ID_Hex the tag object's hex id
   --  @param Path the repository-relative path
   --  @param Peeled_Commit_Hex the peeled commit's hex id
   --  @param Peeled_Commit_Last index of the last valid element of the peeled commit id
   --  @param Pack_Checksums_Hex packed buffer of candidate pack checksums
   --  @param Pack_Data the packfile bytes
   --  @param Index_Data the pack index bytes
   --  @param Pack_Checksum_Hex the pack's hex-encoded checksum
   --  @param Pack_Checksum_Last index of the last valid element of the pack checksum
   --  @param Tag_Data the tag object bytes
   --  @param Tag_Last index of the last valid element of the tag data
   --  @param Commit_Data the commit object bytes
   --  @param Commit_Last index of the last valid element of the commit data
   --  @param Root_Tree_ID_Hex the root tree's hex-encoded id
   --  @param Root_Tree_ID_Last index of the last valid element of the root tree id
   --  @param Tree_Data the tree object bytes
   --  @param Tree_Last index of the last valid element of the tree data
   --  @param Entry_Mode the resolved entry's file mode
   --  @param Entry_ID_Hex the resolved entry's hex id
   --  @param Entry_ID_Last index of the last valid element of the entry id
   --  @return Ok on success, or an error status on failure.
   function Resolve_Tag_Path_Entry_Hex
     (Repository_Root     : String;
      Tag_ID_Hex          : Ada.Streams.Stream_Element_Array;
      Path                : Ada.Streams.Stream_Element_Array;
      Peeled_Commit_Hex   : out Ada.Streams.Stream_Element_Array;
      Peeled_Commit_Last  : out Ada.Streams.Stream_Element_Offset;
      Pack_Checksums_Hex  : out Ada.Streams.Stream_Element_Array;
      Pack_Data           : out Ada.Streams.Stream_Element_Array;
      Index_Data          : out Ada.Streams.Stream_Element_Array;
      Pack_Checksum_Hex   : out Ada.Streams.Stream_Element_Array;
      Pack_Checksum_Last  : out Ada.Streams.Stream_Element_Offset;
      Tag_Data            : out Ada.Streams.Stream_Element_Array;
      Tag_Last            : out Ada.Streams.Stream_Element_Offset;
      Commit_Data         : out Ada.Streams.Stream_Element_Array;
      Commit_Last         : out Ada.Streams.Stream_Element_Offset;
      Root_Tree_ID_Hex    : out Ada.Streams.Stream_Element_Array;
      Root_Tree_ID_Last   : out Ada.Streams.Stream_Element_Offset;
      Tree_Data           : out Ada.Streams.Stream_Element_Array;
      Tree_Last           : out Ada.Streams.Stream_Element_Offset;
      Entry_Mode          : out Natural;
      Entry_ID_Hex        : out Ada.Streams.Stream_Element_Array;
      Entry_ID_Last       : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   --  Resolve a ref to a commit (peeling tags) and read the object at a path.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Ref_Name the ref name
   --  @param Path the repository-relative path
   --  @param Resolved_ID_Hex the resolved object's hex id
   --  @param Resolved_ID_Last index of the last valid element of the resolved id
   --  @param Peeled_Commit_Hex the peeled commit's hex id
   --  @param Peeled_Commit_Last index of the last valid element of the peeled commit id
   --  @param Pack_Checksums_Hex packed buffer of candidate pack checksums
   --  @param Pack_Data the packfile bytes
   --  @param Index_Data the pack index bytes
   --  @param Pack_Checksum_Hex the pack's hex-encoded checksum
   --  @param Pack_Checksum_Last index of the last valid element of the pack checksum
   --  @param Tag_Data the tag object bytes
   --  @param Tag_Last index of the last valid element of the tag data
   --  @param Commit_Data the commit object bytes
   --  @param Commit_Last index of the last valid element of the commit data
   --  @param Root_Tree_ID_Hex the root tree's hex-encoded id
   --  @param Root_Tree_ID_Last index of the last valid element of the root tree id
   --  @param Tree_Data the tree object bytes
   --  @param Tree_Last index of the last valid element of the tree data
   --  @param Entry_Mode the resolved entry's file mode
   --  @param Kind the object type
   --  @param Data the resulting object contents
   --  @param Last index of the last valid element written
   --  @return Ok on success, or an error status on failure.
   function Read_Ref_Commitish_Path_Object
     (Repository_Root     : String;
      Ref_Name            : String;
      Path                : Ada.Streams.Stream_Element_Array;
      Resolved_ID_Hex     : out Ada.Streams.Stream_Element_Array;
      Resolved_ID_Last    : out Ada.Streams.Stream_Element_Offset;
      Peeled_Commit_Hex   : out Ada.Streams.Stream_Element_Array;
      Peeled_Commit_Last  : out Ada.Streams.Stream_Element_Offset;
      Pack_Checksums_Hex  : out Ada.Streams.Stream_Element_Array;
      Pack_Data           : out Ada.Streams.Stream_Element_Array;
      Index_Data          : out Ada.Streams.Stream_Element_Array;
      Pack_Checksum_Hex   : out Ada.Streams.Stream_Element_Array;
      Pack_Checksum_Last  : out Ada.Streams.Stream_Element_Offset;
      Tag_Data            : out Ada.Streams.Stream_Element_Array;
      Tag_Last            : out Ada.Streams.Stream_Element_Offset;
      Commit_Data         : out Ada.Streams.Stream_Element_Array;
      Commit_Last         : out Ada.Streams.Stream_Element_Offset;
      Root_Tree_ID_Hex    : out Ada.Streams.Stream_Element_Array;
      Root_Tree_ID_Last   : out Ada.Streams.Stream_Element_Offset;
      Tree_Data           : out Ada.Streams.Stream_Element_Array;
      Tree_Last           : out Ada.Streams.Stream_Element_Offset;
      Entry_Mode          : out Natural;
      Kind                : out Pack_Object_Kind;
      Data                : out Ada.Streams.Stream_Element_Array;
      Last                : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   --  Resolve a ref to a commit and list a subtree's entries at a path.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Ref_Name the ref name
   --  @param Path the repository-relative path
   --  @param Resolved_ID_Hex the resolved object's hex id
   --  @param Resolved_ID_Last index of the last valid element of the resolved id
   --  @param Peeled_Commit_Hex the peeled commit's hex id
   --  @param Peeled_Commit_Last index of the last valid element of the peeled commit id
   --  @param Pack_Checksums_Hex packed buffer of candidate pack checksums
   --  @param Pack_Data the packfile bytes
   --  @param Index_Data the pack index bytes
   --  @param Pack_Checksum_Hex the pack's hex-encoded checksum
   --  @param Pack_Checksum_Last index of the last valid element of the pack checksum
   --  @param Tag_Data the tag object bytes
   --  @param Tag_Last index of the last valid element of the tag data
   --  @param Commit_Data the commit object bytes
   --  @param Commit_Last index of the last valid element of the commit data
   --  @param Root_Tree_ID_Hex the root tree's hex-encoded id
   --  @param Root_Tree_ID_Last index of the last valid element of the root tree id
   --  @param Path_Tree_Data the subtree object bytes for the path
   --  @param Path_Tree_Last index of the last valid element of the subtree data
   --  @param Path_Mode the file mode of the resolved path
   --  @param Tree_Data the tree object bytes
   --  @param Tree_Last index of the last valid element of the tree data
   --  @param Names packed buffer of entry names
   --  @param Name_Lasts end offset of each packed name
   --  @param Modes the file mode of each entry
   --  @param Object_IDs_Hex the resulting hex-encoded object ids
   --  @param Count the number of items produced
   --  @return Ok on success, or an error status on failure.
   function Read_Ref_Commitish_Path_Tree_Entries_Hex
     (Repository_Root     : String;
      Ref_Name            : String;
      Path                : Ada.Streams.Stream_Element_Array;
      Resolved_ID_Hex     : out Ada.Streams.Stream_Element_Array;
      Resolved_ID_Last    : out Ada.Streams.Stream_Element_Offset;
      Peeled_Commit_Hex   : out Ada.Streams.Stream_Element_Array;
      Peeled_Commit_Last  : out Ada.Streams.Stream_Element_Offset;
      Pack_Checksums_Hex  : out Ada.Streams.Stream_Element_Array;
      Pack_Data           : out Ada.Streams.Stream_Element_Array;
      Index_Data          : out Ada.Streams.Stream_Element_Array;
      Pack_Checksum_Hex   : out Ada.Streams.Stream_Element_Array;
      Pack_Checksum_Last  : out Ada.Streams.Stream_Element_Offset;
      Tag_Data            : out Ada.Streams.Stream_Element_Array;
      Tag_Last            : out Ada.Streams.Stream_Element_Offset;
      Commit_Data         : out Ada.Streams.Stream_Element_Array;
      Commit_Last         : out Ada.Streams.Stream_Element_Offset;
      Root_Tree_ID_Hex    : out Ada.Streams.Stream_Element_Array;
      Root_Tree_ID_Last   : out Ada.Streams.Stream_Element_Offset;
      Path_Tree_Data      : out Ada.Streams.Stream_Element_Array;
      Path_Tree_Last      : out Ada.Streams.Stream_Element_Offset;
      Path_Mode           : out Natural;
      Tree_Data           : out Ada.Streams.Stream_Element_Array;
      Tree_Last           : out Ada.Streams.Stream_Element_Offset;
      Names               : out Ada.Streams.Stream_Element_Array;
      Name_Lasts          : out Tree_Entry_Name_Last_Array;
      Modes               : out Tree_Entry_Mode_Array;
      Object_IDs_Hex      : out Object_ID_Hex_Array;
      Count               : out Natural)
      return CryptoLib.Errors.Status;

   --  Resolve a ref to a commit and resolve a path to its entry id.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Ref_Name the ref name
   --  @param Path the repository-relative path
   --  @param Resolved_ID_Hex the resolved object's hex id
   --  @param Resolved_ID_Last index of the last valid element of the resolved id
   --  @param Peeled_Commit_Hex the peeled commit's hex id
   --  @param Peeled_Commit_Last index of the last valid element of the peeled commit id
   --  @param Pack_Checksums_Hex packed buffer of candidate pack checksums
   --  @param Pack_Data the packfile bytes
   --  @param Index_Data the pack index bytes
   --  @param Pack_Checksum_Hex the pack's hex-encoded checksum
   --  @param Pack_Checksum_Last index of the last valid element of the pack checksum
   --  @param Tag_Data the tag object bytes
   --  @param Tag_Last index of the last valid element of the tag data
   --  @param Commit_Data the commit object bytes
   --  @param Commit_Last index of the last valid element of the commit data
   --  @param Root_Tree_ID_Hex the root tree's hex-encoded id
   --  @param Root_Tree_ID_Last index of the last valid element of the root tree id
   --  @param Tree_Data the tree object bytes
   --  @param Tree_Last index of the last valid element of the tree data
   --  @param Entry_Mode the resolved entry's file mode
   --  @param Entry_ID_Hex the resolved entry's hex id
   --  @param Entry_ID_Last index of the last valid element of the entry id
   --  @return Ok on success, or an error status on failure.
   function Resolve_Ref_Commitish_Path_Entry_Hex
     (Repository_Root     : String;
      Ref_Name            : String;
      Path                : Ada.Streams.Stream_Element_Array;
      Resolved_ID_Hex     : out Ada.Streams.Stream_Element_Array;
      Resolved_ID_Last    : out Ada.Streams.Stream_Element_Offset;
      Peeled_Commit_Hex   : out Ada.Streams.Stream_Element_Array;
      Peeled_Commit_Last  : out Ada.Streams.Stream_Element_Offset;
      Pack_Checksums_Hex  : out Ada.Streams.Stream_Element_Array;
      Pack_Data           : out Ada.Streams.Stream_Element_Array;
      Index_Data          : out Ada.Streams.Stream_Element_Array;
      Pack_Checksum_Hex   : out Ada.Streams.Stream_Element_Array;
      Pack_Checksum_Last  : out Ada.Streams.Stream_Element_Offset;
      Tag_Data            : out Ada.Streams.Stream_Element_Array;
      Tag_Last            : out Ada.Streams.Stream_Element_Offset;
      Commit_Data         : out Ada.Streams.Stream_Element_Array;
      Commit_Last         : out Ada.Streams.Stream_Element_Offset;
      Root_Tree_ID_Hex    : out Ada.Streams.Stream_Element_Array;
      Root_Tree_ID_Last   : out Ada.Streams.Stream_Element_Offset;
      Tree_Data           : out Ada.Streams.Stream_Element_Array;
      Tree_Last           : out Ada.Streams.Stream_Element_Offset;
      Entry_Mode          : out Natural;
      Entry_ID_Hex        : out Ada.Streams.Stream_Element_Array;
      Entry_ID_Last       : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   --  Resolve a ref to a commit and read its root tree object.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Ref_Name the ref name
   --  @param Resolved_ID_Hex the resolved object's hex id
   --  @param Resolved_ID_Last index of the last valid element of the resolved id
   --  @param Peeled_Commit_Hex the peeled commit's hex id
   --  @param Peeled_Commit_Last index of the last valid element of the peeled commit id
   --  @param Pack_Checksums_Hex packed buffer of candidate pack checksums
   --  @param Pack_Data the packfile bytes
   --  @param Index_Data the pack index bytes
   --  @param Pack_Checksum_Hex the pack's hex-encoded checksum
   --  @param Pack_Checksum_Last index of the last valid element of the pack checksum
   --  @param Tag_Data the tag object bytes
   --  @param Tag_Last index of the last valid element of the tag data
   --  @param Commit_Data the commit object bytes
   --  @param Commit_Last index of the last valid element of the commit data
   --  @param Root_Tree_ID_Hex the root tree's hex-encoded id
   --  @param Root_Tree_ID_Last index of the last valid element of the root tree id
   --  @param Tree_Data the tree object bytes
   --  @param Tree_Last index of the last valid element of the tree data
   --  @param Entry_Count the number of entries
   --  @return Ok on success, or an error status on failure.
   function Read_Ref_Commitish_Tree_Object
     (Repository_Root     : String;
      Ref_Name            : String;
      Resolved_ID_Hex     : out Ada.Streams.Stream_Element_Array;
      Resolved_ID_Last    : out Ada.Streams.Stream_Element_Offset;
      Peeled_Commit_Hex   : out Ada.Streams.Stream_Element_Array;
      Peeled_Commit_Last  : out Ada.Streams.Stream_Element_Offset;
      Pack_Checksums_Hex  : out Ada.Streams.Stream_Element_Array;
      Pack_Data           : out Ada.Streams.Stream_Element_Array;
      Index_Data          : out Ada.Streams.Stream_Element_Array;
      Pack_Checksum_Hex   : out Ada.Streams.Stream_Element_Array;
      Pack_Checksum_Last  : out Ada.Streams.Stream_Element_Offset;
      Tag_Data            : out Ada.Streams.Stream_Element_Array;
      Tag_Last            : out Ada.Streams.Stream_Element_Offset;
      Commit_Data         : out Ada.Streams.Stream_Element_Array;
      Commit_Last         : out Ada.Streams.Stream_Element_Offset;
      Root_Tree_ID_Hex    : out Ada.Streams.Stream_Element_Array;
      Root_Tree_ID_Last   : out Ada.Streams.Stream_Element_Offset;
      Tree_Data           : out Ada.Streams.Stream_Element_Array;
      Tree_Last           : out Ada.Streams.Stream_Element_Offset;
      Entry_Count         : out Natural)
      return CryptoLib.Errors.Status;

   --  Resolve a ref to a commit and list its root tree entries.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Ref_Name the ref name
   --  @param Resolved_ID_Hex the resolved object's hex id
   --  @param Resolved_ID_Last index of the last valid element of the resolved id
   --  @param Peeled_Commit_Hex the peeled commit's hex id
   --  @param Peeled_Commit_Last index of the last valid element of the peeled commit id
   --  @param Pack_Checksums_Hex packed buffer of candidate pack checksums
   --  @param Pack_Data the packfile bytes
   --  @param Index_Data the pack index bytes
   --  @param Pack_Checksum_Hex the pack's hex-encoded checksum
   --  @param Pack_Checksum_Last index of the last valid element of the pack checksum
   --  @param Tag_Data the tag object bytes
   --  @param Tag_Last index of the last valid element of the tag data
   --  @param Commit_Data the commit object bytes
   --  @param Commit_Last index of the last valid element of the commit data
   --  @param Root_Tree_ID_Hex the root tree's hex-encoded id
   --  @param Root_Tree_ID_Last index of the last valid element of the root tree id
   --  @param Tree_Data the tree object bytes
   --  @param Tree_Last index of the last valid element of the tree data
   --  @param Names packed buffer of entry names
   --  @param Name_Lasts end offset of each packed name
   --  @param Modes the file mode of each entry
   --  @param Object_IDs_Hex the resulting hex-encoded object ids
   --  @param Count the number of items produced
   --  @return Ok on success, or an error status on failure.
   function Read_Ref_Commitish_Tree_Entries_Hex
     (Repository_Root     : String;
      Ref_Name            : String;
      Resolved_ID_Hex     : out Ada.Streams.Stream_Element_Array;
      Resolved_ID_Last    : out Ada.Streams.Stream_Element_Offset;
      Peeled_Commit_Hex   : out Ada.Streams.Stream_Element_Array;
      Peeled_Commit_Last  : out Ada.Streams.Stream_Element_Offset;
      Pack_Checksums_Hex  : out Ada.Streams.Stream_Element_Array;
      Pack_Data           : out Ada.Streams.Stream_Element_Array;
      Index_Data          : out Ada.Streams.Stream_Element_Array;
      Pack_Checksum_Hex   : out Ada.Streams.Stream_Element_Array;
      Pack_Checksum_Last  : out Ada.Streams.Stream_Element_Offset;
      Tag_Data            : out Ada.Streams.Stream_Element_Array;
      Tag_Last            : out Ada.Streams.Stream_Element_Offset;
      Commit_Data         : out Ada.Streams.Stream_Element_Array;
      Commit_Last         : out Ada.Streams.Stream_Element_Offset;
      Root_Tree_ID_Hex    : out Ada.Streams.Stream_Element_Array;
      Root_Tree_ID_Last   : out Ada.Streams.Stream_Element_Offset;
      Tree_Data           : out Ada.Streams.Stream_Element_Array;
      Tree_Last           : out Ada.Streams.Stream_Element_Offset;
      Names               : out Ada.Streams.Stream_Element_Array;
      Name_Lasts          : out Tree_Entry_Name_Last_Array;
      Modes               : out Tree_Entry_Mode_Array;
      Object_IDs_Hex      : out Object_ID_Hex_Array;
      Count               : out Natural)
      return CryptoLib.Errors.Status;

   --  Resolve a ref to a commit and recursively list every tree path.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Ref_Name the ref name
   --  @param Paths packed buffer of the path names
   --  @param Path_Lasts end offset of each packed path name
   --  @param Modes the file mode of each entry
   --  @param Object_IDs_Hex the resulting hex-encoded object ids
   --  @param Count the number of items produced
   --  @return Ok on success, or an error status on failure.
   function List_Ref_Commitish_Tree_Paths_Hex
     (Repository_Root : String;
      Ref_Name        : String;
      Paths           : out Ada.Streams.Stream_Element_Array;
      Path_Lasts      : out Index_Path_Last_Array;
      Modes           : out Tree_Entry_Mode_Array;
      Object_IDs_Hex  : out Object_ID_Hex_Array;
      Count           : out Natural)
      return CryptoLib.Errors.Status;

   --  Resolve a ref to a commit and list tree paths matching a pathspec.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Ref_Name the ref name
   --  @param Pathspec the pathspec pattern to match
   --  @param Paths packed buffer of the path names
   --  @param Path_Lasts end offset of each packed path name
   --  @param Modes the file mode of each entry
   --  @param Object_IDs_Hex the resulting hex-encoded object ids
   --  @param Count the number of items produced
   --  @return Ok on success, or an error status on failure.
   function List_Ref_Commitish_Tree_Paths_Matching_Hex
     (Repository_Root : String;
      Ref_Name        : String;
      Pathspec        : String;
      Paths           : out Ada.Streams.Stream_Element_Array;
      Path_Lasts      : out Index_Path_Last_Array;
      Modes           : out Tree_Entry_Mode_Array;
      Object_IDs_Hex  : out Object_ID_Hex_Array;
      Count           : out Natural)
      return CryptoLib.Errors.Status;

   --  Recursively list every path in HEAD's tree.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Paths packed buffer of the path names
   --  @param Path_Lasts end offset of each packed path name
   --  @param Modes the file mode of each entry
   --  @param Object_IDs_Hex the resulting hex-encoded object ids
   --  @param Count the number of items produced
   --  @return Ok on success, or an error status on failure.
   function List_HEAD_Tree_Paths_Hex
     (Repository_Root : String;
      Paths           : out Ada.Streams.Stream_Element_Array;
      Path_Lasts      : out Index_Path_Last_Array;
      Modes           : out Tree_Entry_Mode_Array;
      Object_IDs_Hex  : out Object_ID_Hex_Array;
      Count           : out Natural)
      return CryptoLib.Errors.Status;

   --  List HEAD tree paths matching a pathspec.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Pathspec the pathspec pattern to match
   --  @param Paths packed buffer of the path names
   --  @param Path_Lasts end offset of each packed path name
   --  @param Modes the file mode of each entry
   --  @param Object_IDs_Hex the resulting hex-encoded object ids
   --  @param Count the number of items produced
   --  @return Ok on success, or an error status on failure.
   function List_HEAD_Tree_Paths_Matching_Hex
     (Repository_Root : String;
      Pathspec        : String;
      Paths           : out Ada.Streams.Stream_Element_Array;
      Path_Lasts      : out Index_Path_Last_Array;
      Modes           : out Tree_Entry_Mode_Array;
      Object_IDs_Hex  : out Object_ID_Hex_Array;
      Count           : out Natural)
      return CryptoLib.Errors.Status;

   --  Recursively list every path in a branch's tree.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Branch_Name the branch name
   --  @param Paths packed buffer of the path names
   --  @param Path_Lasts end offset of each packed path name
   --  @param Modes the file mode of each entry
   --  @param Object_IDs_Hex the resulting hex-encoded object ids
   --  @param Count the number of items produced
   --  @return Ok on success, or an error status on failure.
   function List_Branch_Tree_Paths_Hex
     (Repository_Root : String;
      Branch_Name     : String;
      Paths           : out Ada.Streams.Stream_Element_Array;
      Path_Lasts      : out Index_Path_Last_Array;
      Modes           : out Tree_Entry_Mode_Array;
      Object_IDs_Hex  : out Object_ID_Hex_Array;
      Count           : out Natural)
      return CryptoLib.Errors.Status;

   --  List a branch's tree paths matching a pathspec.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Branch_Name the branch name
   --  @param Pathspec the pathspec pattern to match
   --  @param Paths packed buffer of the path names
   --  @param Path_Lasts end offset of each packed path name
   --  @param Modes the file mode of each entry
   --  @param Object_IDs_Hex the resulting hex-encoded object ids
   --  @param Count the number of items produced
   --  @return Ok on success, or an error status on failure.
   function List_Branch_Tree_Paths_Matching_Hex
     (Repository_Root : String;
      Branch_Name     : String;
      Pathspec        : String;
      Paths           : out Ada.Streams.Stream_Element_Array;
      Path_Lasts      : out Index_Path_Last_Array;
      Modes           : out Tree_Entry_Mode_Array;
      Object_IDs_Hex  : out Object_ID_Hex_Array;
      Count           : out Natural)
      return CryptoLib.Errors.Status;

   --  Recursively list every path in a tag's tree.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Tag_Name the tag name
   --  @param Paths packed buffer of the path names
   --  @param Path_Lasts end offset of each packed path name
   --  @param Modes the file mode of each entry
   --  @param Object_IDs_Hex the resulting hex-encoded object ids
   --  @param Count the number of items produced
   --  @return Ok on success, or an error status on failure.
   function List_Tag_Tree_Paths_Hex
     (Repository_Root : String;
      Tag_Name        : String;
      Paths           : out Ada.Streams.Stream_Element_Array;
      Path_Lasts      : out Index_Path_Last_Array;
      Modes           : out Tree_Entry_Mode_Array;
      Object_IDs_Hex  : out Object_ID_Hex_Array;
      Count           : out Natural)
      return CryptoLib.Errors.Status;

   --  List a tag's tree paths matching a pathspec.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Tag_Name the tag name
   --  @param Pathspec the pathspec pattern to match
   --  @param Paths packed buffer of the path names
   --  @param Path_Lasts end offset of each packed path name
   --  @param Modes the file mode of each entry
   --  @param Object_IDs_Hex the resulting hex-encoded object ids
   --  @param Count the number of items produced
   --  @return Ok on success, or an error status on failure.
   function List_Tag_Tree_Paths_Matching_Hex
     (Repository_Root : String;
      Tag_Name        : String;
      Pathspec        : String;
      Paths           : out Ada.Streams.Stream_Element_Array;
      Path_Lasts      : out Index_Path_Last_Array;
      Modes           : out Tree_Entry_Mode_Array;
      Object_IDs_Hex  : out Object_ID_Hex_Array;
      Count           : out Natural)
      return CryptoLib.Errors.Status;

   --  Read a loose object by id.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Object_ID_Hex the object's hex-encoded id
   --  @param Kind the object type
   --  @param Data the resulting object contents
   --  @param Last index of the last valid element written
   --  @return Ok on success, or an error status on failure.
   function Read_Loose_Object
     (Repository_Root : String;
      Object_ID_Hex   : Ada.Streams.Stream_Element_Array;
      Kind            : out Pack_Object_Kind;
      Data            : out Ada.Streams.Stream_Element_Array;
      Last            : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   --  Read a loose object and verify its computed id.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Object_ID_Hex the object's hex-encoded id
   --  @param Kind the object type
   --  @param Data the resulting object contents
   --  @param Last index of the last valid element written
   --  @return Ok on success, or an error status on failure.
   function Read_Loose_Object_Validated
     (Repository_Root : String;
      Object_ID_Hex   : Ada.Streams.Stream_Element_Array;
      Kind            : out Pack_Object_Kind;
      Data            : out Ada.Streams.Stream_Element_Array;
      Last            : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   --  Write a direct (non-symbolic) ref to a loose ref file.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Ref_Name the ref name
   --  @param Object_ID_Hex the object's hex-encoded id
   --  @return Ok on success, or an error status on failure.
   function Write_Direct_Ref
     (Repository_Root : String;
      Ref_Name        : String;
      Object_ID_Hex   : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Read the object id from a loose direct ref file.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Ref_Name the ref name
   --  @param Object_ID_Hex the object's hex-encoded id
   --  @param Last index of the last valid element written
   --  @return Ok on success, or an error status on failure.
   function Read_Direct_Ref
     (Repository_Root : String;
      Ref_Name        : String;
      Object_ID_Hex   : out Ada.Streams.Stream_Element_Array;
      Last            : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   --  Delete a loose direct ref file.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Ref_Name the ref name
   --  @return Ok on success, or an error status on failure.
   function Delete_Direct_Ref
     (Repository_Root : String;
      Ref_Name        : String)
      return CryptoLib.Errors.Status;

   --  Write a symbolic ref pointing at another ref.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Ref_Name the ref name
   --  @param Target_Ref_Name the target ref name
   --  @return Ok on success, or an error status on failure.
   function Write_Symbolic_Ref
     (Repository_Root  : String;
      Ref_Name         : String;
      Target_Ref_Name  : String)
      return CryptoLib.Errors.Status;

   --  Read the target of a symbolic ref.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Ref_Name the ref name
   --  @param Target_Ref_Name the target ref name
   --  @param Last index of the last valid element written
   --  @return Ok on success, or an error status on failure.
   function Read_Symbolic_Ref
     (Repository_Root  : String;
      Ref_Name         : String;
      Target_Ref_Name  : out Ada.Streams.Stream_Element_Array;
      Last             : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   --  Delete a symbolic ref, returning its former target.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Ref_Name the ref name
   --  @param Target_Ref_Name the target ref name
   --  @param Last index of the last valid element written
   --  @return Ok on success, or an error status on failure.
   function Delete_Symbolic_Ref
     (Repository_Root  : String;
      Ref_Name         : String;
      Target_Ref_Name  : out Ada.Streams.Stream_Element_Array;
      Last             : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   --  Add or update a ref in the packed-refs file.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Ref_Name the ref name
   --  @param Object_ID_Hex the object's hex-encoded id
   --  @return Ok on success, or an error status on failure.
   function Write_Packed_Ref
     (Repository_Root : String;
      Ref_Name        : String;
      Object_ID_Hex   : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Read a ref's object id from the packed-refs file.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Ref_Name the ref name
   --  @param Object_ID_Hex the object's hex-encoded id
   --  @param Last index of the last valid element written
   --  @return Ok on success, or an error status on failure.
   function Read_Packed_Ref
     (Repository_Root : String;
      Ref_Name        : String;
      Object_ID_Hex   : out Ada.Streams.Stream_Element_Array;
      Last            : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   --  Remove a ref from the packed-refs file.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Ref_Name the ref name
   --  @return Ok on success, or an error status on failure.
   function Delete_Packed_Ref
     (Repository_Root : String;
      Ref_Name        : String)
      return CryptoLib.Errors.Status;

   --  List every ref in the repository with its object id.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Names packed buffer of entry names
   --  @param Name_Lasts end offset of each packed name
   --  @param Object_IDs_Hex the resulting hex-encoded object ids
   --  @param Count the number of items produced
   --  @return Ok on success, or an error status on failure.
   function List_Refs
     (Repository_Root : String;
      Names           : out Ada.Streams.Stream_Element_Array;
      Name_Lasts      : out Ref_Name_Last_Array;
      Object_IDs_Hex  : out Object_ID_Hex_Array;
      Count           : out Natural)
      return CryptoLib.Errors.Status;

   --  List local branch refs with their object ids.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Names packed buffer of entry names
   --  @param Name_Lasts end offset of each packed name
   --  @param Object_IDs_Hex the resulting hex-encoded object ids
   --  @param Count the number of items produced
   --  @return Ok on success, or an error status on failure.
   function List_Branches
     (Repository_Root : String;
      Names           : out Ada.Streams.Stream_Element_Array;
      Name_Lasts      : out Ref_Name_Last_Array;
      Object_IDs_Hex  : out Object_ID_Hex_Array;
      Count           : out Natural)
      return CryptoLib.Errors.Status;

   --  List tag refs with their object ids.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Names packed buffer of entry names
   --  @param Name_Lasts end offset of each packed name
   --  @param Object_IDs_Hex the resulting hex-encoded object ids
   --  @param Count the number of items produced
   --  @return Ok on success, or an error status on failure.
   function List_Tag_Refs
     (Repository_Root : String;
      Names           : out Ada.Streams.Stream_Element_Array;
      Name_Lasts      : out Ref_Name_Last_Array;
      Object_IDs_Hex  : out Object_ID_Hex_Array;
      Count           : out Natural)
      return CryptoLib.Errors.Status;

   --  List remote-tracking branch refs with their object ids.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Names packed buffer of entry names
   --  @param Name_Lasts end offset of each packed name
   --  @param Object_IDs_Hex the resulting hex-encoded object ids
   --  @param Count the number of items produced
   --  @return Ok on success, or an error status on failure.
   function List_Remote_Tracking_Branches
     (Repository_Root : String;
      Names           : out Ada.Streams.Stream_Element_Array;
      Name_Lasts      : out Ref_Name_Last_Array;
      Object_IDs_Hex  : out Object_ID_Hex_Array;
      Count           : out Natural)
      return CryptoLib.Errors.Status;

   --  Resolve a ref by name to a concrete object id, following symrefs.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Ref_Name the ref name
   --  @param Object_ID_Hex the object's hex-encoded id
   --  @param Last index of the last valid element written
   --  @return Ok on success, or an error status on failure.
   function Resolve_Ref
     (Repository_Root : String;
      Ref_Name        : String;
      Object_ID_Hex   : out Ada.Streams.Stream_Element_Array;
      Last            : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   --  Point HEAD symbolically at a given ref.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Target_Ref_Name the target ref name
   --  @return Ok on success, or an error status on failure.
   function Attach_HEAD
     (Repository_Root : String;
      Target_Ref_Name : String)
      return CryptoLib.Errors.Status;

   --  Point HEAD symbolically at a local branch.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Branch_Name the branch name
   --  @return Ok on success, or an error status on failure.
   function Attach_HEAD_To_Branch
     (Repository_Root : String;
      Branch_Name     : String)
      return CryptoLib.Errors.Status;

   --  Detach HEAD to point directly at an object id.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Object_ID_Hex the object's hex-encoded id
   --  @return Ok on success, or an error status on failure.
   function Detach_HEAD
     (Repository_Root : String;
      Object_ID_Hex   : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Resolve HEAD to a concrete object id.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Object_ID_Hex the object's hex-encoded id
   --  @param Last index of the last valid element written
   --  @return Ok on success, or an error status on failure.
   function Resolve_HEAD
     (Repository_Root : String;
      Object_ID_Hex   : out Ada.Streams.Stream_Element_Array;
      Last            : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   --  Read HEAD, reporting its target ref and whether it is attached.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Target_Ref_Name the target ref name
   --  @param Last index of the last valid element written
   --  @param Attached set True when HEAD is attached to a branch
   --  @return Ok on success, or an error status on failure.
   function Read_HEAD_Target
     (Repository_Root : String;
      Target_Ref_Name : out Ada.Streams.Stream_Element_Array;
      Last            : out Ada.Streams.Stream_Element_Offset;
      Attached        : out Boolean)
      return CryptoLib.Errors.Status;

   --  Read the name of the branch HEAD is attached to, if any.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Branch_Name the branch name
   --  @param Last index of the last valid element written
   --  @param Found set True when the item was found
   --  @return Ok on success, or an error status on failure.
   function Read_Current_Branch
     (Repository_Root : String;
      Branch_Name     : out Ada.Streams.Stream_Element_Array;
      Last            : out Ada.Streams.Stream_Element_Offset;
      Found           : out Boolean)
      return CryptoLib.Errors.Status;

   --  Write a branch ref to a given object id.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Branch_Name the branch name
   --  @param Object_ID_Hex the object's hex-encoded id
   --  @return Ok on success, or an error status on failure.
   function Write_Branch
     (Repository_Root : String;
      Branch_Name     : String;
      Object_ID_Hex   : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Create a branch pointing at HEAD's current commit.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Branch_Name the branch name
   --  @return Ok on success, or an error status on failure.
   function Create_Branch_From_HEAD
     (Repository_Root : String;
      Branch_Name     : String)
      return CryptoLib.Errors.Status;

   --  Read a branch ref's object id.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Branch_Name the branch name
   --  @param Object_ID_Hex the object's hex-encoded id
   --  @param Last index of the last valid element written
   --  @return Ok on success, or an error status on failure.
   function Read_Branch
     (Repository_Root : String;
      Branch_Name     : String;
      Object_ID_Hex   : out Ada.Streams.Stream_Element_Array;
      Last            : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   --  Resolve a branch ref to a concrete object id.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Branch_Name the branch name
   --  @param Object_ID_Hex the object's hex-encoded id
   --  @param Last index of the last valid element written
   --  @return Ok on success, or an error status on failure.
   function Resolve_Branch
     (Repository_Root : String;
      Branch_Name     : String;
      Object_ID_Hex   : out Ada.Streams.Stream_Element_Array;
      Last            : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   --  Delete a branch ref.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Branch_Name the branch name
   --  @return Ok on success, or an error status on failure.
   function Delete_Branch
     (Repository_Root : String;
      Branch_Name     : String)
      return CryptoLib.Errors.Status;

   --  Report whether a branch exists, returning its object id if so.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Branch_Name the branch name
   --  @param Object_ID_Hex the object's hex-encoded id
   --  @param Last index of the last valid element written
   --  @param Found set True when the item was found
   --  @return Ok on success, or an error status on failure.
   function Branch_Exists
     (Repository_Root : String;
      Branch_Name     : String;
      Object_ID_Hex   : out Ada.Streams.Stream_Element_Array;
      Last            : out Ada.Streams.Stream_Element_Offset;
      Found           : out Boolean)
      return CryptoLib.Errors.Status;

   --  Write a remote-tracking branch ref to an object id.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Branch_Name the branch name
   --  @param Object_ID_Hex the object's hex-encoded id
   --  @return Ok on success, or an error status on failure.
   function Write_Remote_Tracking_Branch
     (Repository_Root : String;
      Branch_Name     : String;
      Object_ID_Hex   : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Create a remote-tracking branch pointing at HEAD.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Branch_Name the branch name
   --  @return Ok on success, or an error status on failure.
   function Create_Remote_Tracking_Branch_From_HEAD
     (Repository_Root : String;
      Branch_Name     : String)
      return CryptoLib.Errors.Status;

   --  Read a remote-tracking branch's object id.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Branch_Name the branch name
   --  @param Object_ID_Hex the object's hex-encoded id
   --  @param Last index of the last valid element written
   --  @return Ok on success, or an error status on failure.
   function Read_Remote_Tracking_Branch
     (Repository_Root : String;
      Branch_Name     : String;
      Object_ID_Hex   : out Ada.Streams.Stream_Element_Array;
      Last            : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   --  Resolve a remote-tracking branch to a concrete object id.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Branch_Name the branch name
   --  @param Object_ID_Hex the object's hex-encoded id
   --  @param Last index of the last valid element written
   --  @return Ok on success, or an error status on failure.
   function Resolve_Remote_Tracking_Branch
     (Repository_Root : String;
      Branch_Name     : String;
      Object_ID_Hex   : out Ada.Streams.Stream_Element_Array;
      Last            : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   --  Delete a remote-tracking branch ref.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Branch_Name the branch name
   --  @return Ok on success, or an error status on failure.
   function Delete_Remote_Tracking_Branch
     (Repository_Root : String;
      Branch_Name     : String)
      return CryptoLib.Errors.Status;

   --  Report whether a remote-tracking branch exists, with its id.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Branch_Name the branch name
   --  @param Object_ID_Hex the object's hex-encoded id
   --  @param Last index of the last valid element written
   --  @param Found set True when the item was found
   --  @return Ok on success, or an error status on failure.
   function Remote_Tracking_Branch_Exists
     (Repository_Root : String;
      Branch_Name     : String;
      Object_ID_Hex   : out Ada.Streams.Stream_Element_Array;
      Last            : out Ada.Streams.Stream_Element_Offset;
      Found           : out Boolean)
      return CryptoLib.Errors.Status;

   --  Apply a fetched update to a remote-tracking branch with fast-forward checks.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Remote_Name the remote name
   --  @param Branch_Name the branch name
   --  @param New_Commit_Hex the new commit's hex id
   --  @param Allow_Non_Fast_Forward whether non-fast-forward updates are allowed
   --  @param Updated set True when the ref was updated
   --  @return Ok on success, or an error status on failure.
   function Apply_Fetch_Ref_Update
     (Repository_Root        : String;
      Remote_Name            : String;
      Branch_Name            : String;
      New_Commit_Hex         : Ada.Streams.Stream_Element_Array;
      Allow_Non_Fast_Forward : Boolean;
      Updated                : out Boolean)
      return CryptoLib.Errors.Status;

   --  Write a tag ref to an object id.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Tag_Name the tag name
   --  @param Object_ID_Hex the object's hex-encoded id
   --  @return Ok on success, or an error status on failure.
   function Write_Tag_Ref
     (Repository_Root : String;
      Tag_Name        : String;
      Object_ID_Hex   : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Create a lightweight tag ref pointing at HEAD.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Tag_Name the tag name
   --  @return Ok on success, or an error status on failure.
   function Create_Tag_Ref_From_HEAD
     (Repository_Root : String;
      Tag_Name        : String)
      return CryptoLib.Errors.Status;

   --  Read a tag ref's object id.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Tag_Name the tag name
   --  @param Object_ID_Hex the object's hex-encoded id
   --  @param Last index of the last valid element written
   --  @return Ok on success, or an error status on failure.
   function Read_Tag_Ref
     (Repository_Root : String;
      Tag_Name        : String;
      Object_ID_Hex   : out Ada.Streams.Stream_Element_Array;
      Last            : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   --  Resolve a tag ref to a concrete object id.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Tag_Name the tag name
   --  @param Object_ID_Hex the object's hex-encoded id
   --  @param Last index of the last valid element written
   --  @return Ok on success, or an error status on failure.
   function Resolve_Tag_Ref
     (Repository_Root : String;
      Tag_Name        : String;
      Object_ID_Hex   : out Ada.Streams.Stream_Element_Array;
      Last            : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   --  Delete a tag ref.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Tag_Name the tag name
   --  @return Ok on success, or an error status on failure.
   function Delete_Tag_Ref
     (Repository_Root : String;
      Tag_Name        : String)
      return CryptoLib.Errors.Status;

   --  Report whether a tag ref exists, returning its id.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Tag_Name the tag name
   --  @param Object_ID_Hex the object's hex-encoded id
   --  @param Last index of the last valid element written
   --  @param Found set True when the item was found
   --  @return Ok on success, or an error status on failure.
   function Tag_Ref_Exists
     (Repository_Root : String;
      Tag_Name        : String;
      Object_ID_Hex   : out Ada.Streams.Stream_Element_Array;
      Last            : out Ada.Streams.Stream_Element_Offset;
      Found           : out Boolean)
      return CryptoLib.Errors.Status;

   --  Append an entry to a ref's reflog.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Ref_Name the ref name
   --  @param Old_ID_Hex the previous object hex id
   --  @param New_ID_Hex the new object hex id
   --  @param Actor the reflog actor identity
   --  @param Message the message text
   --  @return Ok on success, or an error status on failure.
   function Append_Reflog_Entry
     (Repository_Root : String;
      Ref_Name        : String;
      Old_ID_Hex      : Ada.Streams.Stream_Element_Array;
      New_ID_Hex      : Ada.Streams.Stream_Element_Array;
      Actor           : String;
      Message         : String)
      return CryptoLib.Errors.Status;

   --  Read the most recent reflog entry for a ref.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Ref_Name the ref name
   --  @param Line the resulting line bytes
   --  @param Last index of the last valid element written
   --  @return Ok on success, or an error status on failure.
   function Read_Reflog_Last_Entry
     (Repository_Root : String;
      Ref_Name        : String;
      Line            : out Ada.Streams.Stream_Element_Array;
      Last            : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   --  Read a single value for a config section and key.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Section the config section name
   --  @param Key the config key name
   --  @param Value the value bytes
   --  @param Last index of the last valid element written
   --  @param Found set True when the item was found
   --  @return Ok on success, or an error status on failure.
   function Read_Config_Value
     (Repository_Root : String;
      Section         : String;
      Key             : String;
      Value           : out Ada.Streams.Stream_Element_Array;
      Last            : out Ada.Streams.Stream_Element_Offset;
      Found           : out Boolean)
      return CryptoLib.Errors.Status;

   --  Read all values for a multi-valued config section and key.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Section the config section name
   --  @param Key the config key name
   --  @param Values packed buffer of the values
   --  @param Value_Lasts end offset of each packed value
   --  @param Count the number of items produced
   --  @return Ok on success, or an error status on failure.
   function Read_Config_Values
     (Repository_Root : String;
      Section         : String;
      Key             : String;
      Values          : out Ada.Streams.Stream_Element_Array;
      Value_Lasts     : out Config_Value_Last_Array;
      Count           : out Natural)
      return CryptoLib.Errors.Status;

   --  Set a config value, replacing any existing one.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Section the config section name
   --  @param Key the config key name
   --  @param Value the value to set
   --  @return Ok on success, or an error status on failure.
   function Write_Config_Value
     (Repository_Root : String;
      Section         : String;
      Key             : String;
      Value           : String)
      return CryptoLib.Errors.Status;

   --  Append an additional value to a multi-valued config key.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Section the config section name
   --  @param Key the config key name
   --  @param Value the value to set
   --  @return Ok on success, or an error status on failure.
   function Append_Config_Value
     (Repository_Root : String;
      Section         : String;
      Key             : String;
      Value           : String)
      return CryptoLib.Errors.Status;

   --  Delete a config key's value.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Section the config section name
   --  @param Key the config key name
   --  @param Removed set True when the item was removed
   --  @return Ok on success, or an error status on failure.
   function Delete_Config_Value
     (Repository_Root : String;
      Section         : String;
      Key             : String;
      Removed         : out Boolean)
      return CryptoLib.Errors.Status;

   --  Set a remote's URL in config.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Remote_Name the remote name
   --  @param URL the URL to set
   --  @return Ok on success, or an error status on failure.
   function Write_Remote_URL
     (Repository_Root : String;
      Remote_Name     : String;
      URL             : String)
      return CryptoLib.Errors.Status;

   --  Read a remote's URL from config.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Remote_Name the remote name
   --  @param URL the URL bytes
   --  @param Last index of the last valid element written
   --  @param Found set True when the item was found
   --  @return Ok on success, or an error status on failure.
   function Read_Remote_URL
     (Repository_Root : String;
      Remote_Name     : String;
      URL             : out Ada.Streams.Stream_Element_Array;
      Last            : out Ada.Streams.Stream_Element_Offset;
      Found           : out Boolean)
      return CryptoLib.Errors.Status;

   --  Delete a remote's URL from config.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Remote_Name the remote name
   --  @param Removed set True when the item was removed
   --  @return Ok on success, or an error status on failure.
   function Delete_Remote_URL
     (Repository_Root : String;
      Remote_Name     : String;
      Removed         : out Boolean)
      return CryptoLib.Errors.Status;

   --  Set a remote's fetch refspec, replacing existing ones.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Remote_Name the remote name
   --  @param RefSpec the refspec to set
   --  @return Ok on success, or an error status on failure.
   function Write_Remote_Fetch_Refspec
     (Repository_Root : String;
      Remote_Name     : String;
      RefSpec         : String)
      return CryptoLib.Errors.Status;

   --  Read a remote's first fetch refspec.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Remote_Name the remote name
   --  @param RefSpec the refspec bytes
   --  @param Last index of the last valid element written
   --  @param Found set True when the item was found
   --  @return Ok on success, or an error status on failure.
   function Read_Remote_Fetch_Refspec
     (Repository_Root : String;
      Remote_Name     : String;
      RefSpec         : out Ada.Streams.Stream_Element_Array;
      Last            : out Ada.Streams.Stream_Element_Offset;
      Found           : out Boolean)
      return CryptoLib.Errors.Status;

   --  Append an additional fetch refspec to a remote.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Remote_Name the remote name
   --  @param RefSpec the refspec to set
   --  @return Ok on success, or an error status on failure.
   function Append_Remote_Fetch_Refspec
     (Repository_Root : String;
      Remote_Name     : String;
      RefSpec         : String)
      return CryptoLib.Errors.Status;

   --  Read all fetch refspecs for a remote.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Remote_Name the remote name
   --  @param RefSpecs packed buffer of the refspecs
   --  @param RefSpec_Lasts end offset of each packed refspec
   --  @param Count the number of items produced
   --  @return Ok on success, or an error status on failure.
   function Read_Remote_Fetch_Refspecs
     (Repository_Root : String;
      Remote_Name     : String;
      RefSpecs        : out Ada.Streams.Stream_Element_Array;
      RefSpec_Lasts   : out Config_Value_Last_Array;
      Count           : out Natural)
      return CryptoLib.Errors.Status;

   --  Delete all fetch refspecs for a remote.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Remote_Name the remote name
   --  @param Removed set True when the item was removed
   --  @return Ok on success, or an error status on failure.
   function Delete_Remote_Fetch_Refspecs
     (Repository_Root : String;
      Remote_Name     : String;
      Removed         : out Boolean)
      return CryptoLib.Errors.Status;

   --  Set a remote's push refspec, replacing existing ones.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Remote_Name the remote name
   --  @param RefSpec the refspec to set
   --  @return Ok on success, or an error status on failure.
   function Write_Remote_Push_Refspec
     (Repository_Root : String;
      Remote_Name     : String;
      RefSpec         : String)
      return CryptoLib.Errors.Status;

   --  Read a remote's first push refspec.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Remote_Name the remote name
   --  @param RefSpec the refspec bytes
   --  @param Last index of the last valid element written
   --  @param Found set True when the item was found
   --  @return Ok on success, or an error status on failure.
   function Read_Remote_Push_Refspec
     (Repository_Root : String;
      Remote_Name     : String;
      RefSpec         : out Ada.Streams.Stream_Element_Array;
      Last            : out Ada.Streams.Stream_Element_Offset;
      Found           : out Boolean)
      return CryptoLib.Errors.Status;

   --  Append an additional push refspec to a remote.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Remote_Name the remote name
   --  @param RefSpec the refspec to set
   --  @return Ok on success, or an error status on failure.
   function Append_Remote_Push_Refspec
     (Repository_Root : String;
      Remote_Name     : String;
      RefSpec         : String)
      return CryptoLib.Errors.Status;

   --  Read all push refspecs for a remote.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Remote_Name the remote name
   --  @param RefSpecs packed buffer of the refspecs
   --  @param RefSpec_Lasts end offset of each packed refspec
   --  @param Count the number of items produced
   --  @return Ok on success, or an error status on failure.
   function Read_Remote_Push_Refspecs
     (Repository_Root : String;
      Remote_Name     : String;
      RefSpecs        : out Ada.Streams.Stream_Element_Array;
      RefSpec_Lasts   : out Config_Value_Last_Array;
      Count           : out Natural)
      return CryptoLib.Errors.Status;

   --  Delete all push refspecs for a remote.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Remote_Name the remote name
   --  @param Removed set True when the item was removed
   --  @return Ok on success, or an error status on failure.
   function Delete_Remote_Push_Refspecs
     (Repository_Root : String;
      Remote_Name     : String;
      Removed         : out Boolean)
      return CryptoLib.Errors.Status;

   --  Set the credential.helper config value.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Helper the credential helper command
   --  @return Ok on success, or an error status on failure.
   function Write_Credential_Helper
     (Repository_Root : String;
      Helper          : String)
      return CryptoLib.Errors.Status;

   --  Read the first credential.helper config value.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Helper the credential helper bytes
   --  @param Last index of the last valid element written
   --  @param Found set True when the item was found
   --  @return Ok on success, or an error status on failure.
   function Read_Credential_Helper
     (Repository_Root : String;
      Helper          : out Ada.Streams.Stream_Element_Array;
      Last            : out Ada.Streams.Stream_Element_Offset;
      Found           : out Boolean)
      return CryptoLib.Errors.Status;

   --  Append an additional credential.helper value.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Helper the credential helper command
   --  @return Ok on success, or an error status on failure.
   function Append_Credential_Helper
     (Repository_Root : String;
      Helper          : String)
      return CryptoLib.Errors.Status;

   --  Read all credential.helper config values.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Helpers packed buffer of the credential helpers
   --  @param Lasts end offset of each packed value
   --  @param Count the number of items produced
   --  @return Ok on success, or an error status on failure.
   function Read_Credential_Helpers
     (Repository_Root : String;
      Helpers         : out Ada.Streams.Stream_Element_Array;
      Lasts           : out Config_Value_Last_Array;
      Count           : out Natural)
      return CryptoLib.Errors.Status;

   --  Delete the credential.helper config values.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Removed set True when the item was removed
   --  @return Ok on success, or an error status on failure.
   function Delete_Credential_Helper
     (Repository_Root : String;
      Removed         : out Boolean)
      return CryptoLib.Errors.Status;

   --  Set the credential.username config value.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Username the username
   --  @return Ok on success, or an error status on failure.
   function Write_Credential_Username
     (Repository_Root : String;
      Username        : String)
      return CryptoLib.Errors.Status;

   --  Read the credential.username config value.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Username the username bytes
   --  @param Last index of the last valid element written
   --  @param Found set True when the item was found
   --  @return Ok on success, or an error status on failure.
   function Read_Credential_Username
     (Repository_Root : String;
      Username        : out Ada.Streams.Stream_Element_Array;
      Last            : out Ada.Streams.Stream_Element_Offset;
      Found           : out Boolean)
      return CryptoLib.Errors.Status;

   --  Delete the credential.username config value.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Removed set True when the item was removed
   --  @return Ok on success, or an error status on failure.
   function Delete_Credential_Username
     (Repository_Root : String;
      Removed         : out Boolean)
      return CryptoLib.Errors.Status;

   --  Format a git-credential helper request payload.
   --  @param Protocol the credential protocol (e.g. https)
   --  @param Host the credential host
   --  @param Path the repository-relative path
   --  @param Username the username
   --  @param Password the password
   --  @param Data the resulting object contents
   --  @param Last index of the last valid element written
   --  @return Ok on success, or an error status on failure.
   function Build_Credential_Helper_Request
     (Protocol : String;
      Host     : String;
      Path     : String;
      Username : String;
      Password : String;
      Data     : out Ada.Streams.Stream_Element_Array;
      Last     : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   --  Parse a git-credential helper response for username and password.
   --  @param Data the raw bytes to parse
   --  @param Username the username bytes
   --  @param Username_Last index of the last valid element of the username
   --  @param Has_Username set True when a username was returned
   --  @param Password the password bytes
   --  @param Password_Last index of the last valid element of the password
   --  @param Has_Password set True when a password was returned
   --  @return Ok on success, or an error status on failure.
   function Parse_Credential_Helper_Response
     (Data         : Ada.Streams.Stream_Element_Array;
      Username     : out Ada.Streams.Stream_Element_Array;
      Username_Last : out Ada.Streams.Stream_Element_Offset;
      Has_Username : out Boolean;
      Password     : out Ada.Streams.Stream_Element_Array;
      Password_Last : out Ada.Streams.Stream_Element_Offset;
      Has_Password : out Boolean)
      return CryptoLib.Errors.Status;

   --  Run an external credential helper and capture the credentials it returns.
   --  @param Helper_Command the external credential helper command to run
   --  @param Protocol the credential protocol (e.g. https)
   --  @param Host the credential host
   --  @param Path the repository-relative path
   --  @param Username the username
   --  @param Password the password
   --  @param Timeout_MS the helper timeout in milliseconds
   --  @param Out_Username the username returned by the helper
   --  @param Username_Last index of the last valid element of the username
   --  @param Has_Username set True when a username was returned
   --  @param Out_Password the password returned by the helper
   --  @param Password_Last index of the last valid element of the password
   --  @param Has_Password set True when a password was returned
   --  @return Ok on success, or an error status on failure.
   function Execute_Credential_Helper
     (Helper_Command : String;
      Protocol       : String;
      Host           : String;
      Path           : String;
      Username       : String;
      Password       : String;
      Timeout_MS     : Natural;
      Out_Username   : out Ada.Streams.Stream_Element_Array;
      Username_Last  : out Ada.Streams.Stream_Element_Offset;
      Has_Username   : out Boolean;
      Out_Password   : out Ada.Streams.Stream_Element_Array;
      Password_Last  : out Ada.Streams.Stream_Element_Offset;
      Has_Password   : out Boolean)
      return CryptoLib.Errors.Status;

   --  Format the interactive password-prompt string for a credential.
   --  @param Protocol the credential protocol (e.g. https)
   --  @param Host the credential host
   --  @param Path the repository-relative path
   --  @param Username the username
   --  @param Prompt the formatted prompt text
   --  @param Last index of the last valid element written
   --  @return Ok on success, or an error status on failure.
   function Build_Credential_Password_Prompt
     (Protocol : String;
      Host     : String;
      Path     : String;
      Username : String;
      Prompt   : out Ada.Streams.Stream_Element_Array;
      Last     : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   --  Prompt the user on the terminal for a credential password.
   --  @param Protocol the credential protocol (e.g. https)
   --  @param Host the credential host
   --  @param Path the repository-relative path
   --  @param Username the username
   --  @param Password the password bytes
   --  @param Last index of the last valid element written
   --  @return Ok on success, or an error status on failure.
   function Prompt_Credential_Password
     (Protocol : String;
      Host     : String;
      Path     : String;
      Username : String;
      Password : out Ada.Streams.Stream_Element_Array;
      Last     : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   --  Store a credential in the plaintext credential store.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Protocol the credential protocol (e.g. https)
   --  @param Host the credential host
   --  @param Path the repository-relative path
   --  @param Username the username
   --  @param Password the password
   --  @return Ok on success, or an error status on failure.
   function Write_Credential_Store
     (Repository_Root : String;
      Protocol        : String;
      Host            : String;
      Path            : String;
      Username        : String;
      Password        : String)
      return CryptoLib.Errors.Status;

   --  Look up a stored credential's password by protocol, host, path, and username.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Protocol the credential protocol (e.g. https)
   --  @param Host the credential host
   --  @param Path the repository-relative path
   --  @param Username the username
   --  @param Password the password bytes
   --  @param Last index of the last valid element written
   --  @param Found set True when the item was found
   --  @return Ok on success, or an error status on failure.
   function Read_Credential_Store
     (Repository_Root : String;
      Protocol        : String;
      Host            : String;
      Path            : String;
      Username        : String;
      Password        : out Ada.Streams.Stream_Element_Array;
      Last            : out Ada.Streams.Stream_Element_Offset;
      Found           : out Boolean)
      return CryptoLib.Errors.Status;

   --  Remove a credential from the credential store.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Protocol the credential protocol (e.g. https)
   --  @param Host the credential host
   --  @param Path the repository-relative path
   --  @param Username the username
   --  @param Removed set True when the item was removed
   --  @return Ok on success, or an error status on failure.
   function Delete_Credential_Store
     (Repository_Root : String;
      Protocol        : String;
      Host            : String;
      Path            : String;
      Username        : String;
      Removed         : out Boolean)
      return CryptoLib.Errors.Status;

   --  Zeroize a buffer holding credential material.
   --  @param Data the credential buffer to zeroize in place
   procedure Clear_Credential_Data
     (Data : in out Ada.Streams.Stream_Element_Array);

   --  Set core.bare in config.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Is_Bare the core.bare flag
   --  @return Ok on success, or an error status on failure.
   function Write_Core_Bare
     (Repository_Root : String;
      Is_Bare         : Boolean)
      return CryptoLib.Errors.Status;

   --  Read core.bare from config.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Is_Bare the core.bare flag
   --  @param Found set True when the item was found
   --  @return Ok on success, or an error status on failure.
   function Read_Core_Bare
     (Repository_Root : String;
      Is_Bare         : out Boolean;
      Found           : out Boolean)
      return CryptoLib.Errors.Status;

   --  Delete core.bare from config.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Removed set True when the item was removed
   --  @return Ok on success, or an error status on failure.
   function Delete_Core_Bare
     (Repository_Root : String;
      Removed         : out Boolean)
      return CryptoLib.Errors.Status;

   --  Set core.filemode in config.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Filemode the core.filemode flag
   --  @return Ok on success, or an error status on failure.
   function Write_Core_Filemode
     (Repository_Root : String;
      Filemode        : Boolean)
      return CryptoLib.Errors.Status;

   --  Read core.filemode from config.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Filemode the core.filemode flag
   --  @param Found set True when the item was found
   --  @return Ok on success, or an error status on failure.
   function Read_Core_Filemode
     (Repository_Root : String;
      Filemode        : out Boolean;
      Found           : out Boolean)
      return CryptoLib.Errors.Status;

   --  Delete core.filemode from config.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Removed set True when the item was removed
   --  @return Ok on success, or an error status on failure.
   function Delete_Core_Filemode
     (Repository_Root : String;
      Removed         : out Boolean)
      return CryptoLib.Errors.Status;

   --  Set core.logallrefupdates in config.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Log_All_Ref_Updates the core.logallrefupdates flag
   --  @return Ok on success, or an error status on failure.
   function Write_Core_Log_All_Ref_Updates
     (Repository_Root      : String;
      Log_All_Ref_Updates : Boolean)
      return CryptoLib.Errors.Status;

   --  Read core.logallrefupdates from config.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Log_All_Ref_Updates the core.logallrefupdates flag
   --  @param Found set True when the item was found
   --  @return Ok on success, or an error status on failure.
   function Read_Core_Log_All_Ref_Updates
     (Repository_Root      : String;
      Log_All_Ref_Updates : out Boolean;
      Found                : out Boolean)
      return CryptoLib.Errors.Status;

   --  Delete core.logallrefupdates from config.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Removed set True when the item was removed
   --  @return Ok on success, or an error status on failure.
   function Delete_Core_Log_All_Ref_Updates
     (Repository_Root : String;
      Removed         : out Boolean)
      return CryptoLib.Errors.Status;

   --  Set user.name in config.
   --  @param Repository_Root filesystem path to the repository root
   --  @param User_Name the user name to set
   --  @return Ok on success, or an error status on failure.
   function Write_User_Name
     (Repository_Root : String;
      User_Name       : String)
      return CryptoLib.Errors.Status;

   --  Read user.name from config.
   --  @param Repository_Root filesystem path to the repository root
   --  @param User_Name the user name bytes
   --  @param Last index of the last valid element written
   --  @param Found set True when the item was found
   --  @return Ok on success, or an error status on failure.
   function Read_User_Name
     (Repository_Root : String;
      User_Name       : out Ada.Streams.Stream_Element_Array;
      Last            : out Ada.Streams.Stream_Element_Offset;
      Found           : out Boolean)
      return CryptoLib.Errors.Status;

   --  Delete user.name from config.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Removed set True when the item was removed
   --  @return Ok on success, or an error status on failure.
   function Delete_User_Name
     (Repository_Root : String;
      Removed         : out Boolean)
      return CryptoLib.Errors.Status;

   --  Set user.email in config.
   --  @param Repository_Root filesystem path to the repository root
   --  @param User_Email the user email to set
   --  @return Ok on success, or an error status on failure.
   function Write_User_Email
     (Repository_Root : String;
      User_Email      : String)
      return CryptoLib.Errors.Status;

   --  Read user.email from config.
   --  @param Repository_Root filesystem path to the repository root
   --  @param User_Email the user email bytes
   --  @param Last index of the last valid element written
   --  @param Found set True when the item was found
   --  @return Ok on success, or an error status on failure.
   function Read_User_Email
     (Repository_Root : String;
      User_Email      : out Ada.Streams.Stream_Element_Array;
      Last            : out Ada.Streams.Stream_Element_Offset;
      Found           : out Boolean)
      return CryptoLib.Errors.Status;

   --  Delete user.email from config.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Removed set True when the item was removed
   --  @return Ok on success, or an error status on failure.
   function Delete_User_Email
     (Repository_Root : String;
      Removed         : out Boolean)
      return CryptoLib.Errors.Status;

   --  Set init.defaultBranch in config.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Branch_Name the branch name
   --  @return Ok on success, or an error status on failure.
   function Write_Init_Default_Branch
     (Repository_Root : String;
      Branch_Name     : String)
      return CryptoLib.Errors.Status;

   --  Read init.defaultBranch from config.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Branch_Name the branch name
   --  @param Last index of the last valid element written
   --  @param Found set True when the item was found
   --  @return Ok on success, or an error status on failure.
   function Read_Init_Default_Branch
     (Repository_Root : String;
      Branch_Name     : out Ada.Streams.Stream_Element_Array;
      Last            : out Ada.Streams.Stream_Element_Offset;
      Found           : out Boolean)
      return CryptoLib.Errors.Status;

   --  Delete init.defaultBranch from config.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Removed set True when the item was removed
   --  @return Ok on success, or an error status on failure.
   function Delete_Init_Default_Branch
     (Repository_Root : String;
      Removed         : out Boolean)
      return CryptoLib.Errors.Status;

   --  Set push.default in config.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Mode the mode string to set
   --  @return Ok on success, or an error status on failure.
   function Write_Push_Default
     (Repository_Root : String;
      Mode            : String)
      return CryptoLib.Errors.Status;

   --  Read push.default from config.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Mode the mode bytes
   --  @param Last index of the last valid element written
   --  @param Found set True when the item was found
   --  @return Ok on success, or an error status on failure.
   function Read_Push_Default
     (Repository_Root : String;
      Mode            : out Ada.Streams.Stream_Element_Array;
      Last            : out Ada.Streams.Stream_Element_Offset;
      Found           : out Boolean)
      return CryptoLib.Errors.Status;

   --  Delete push.default from config.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Removed set True when the item was removed
   --  @return Ok on success, or an error status on failure.
   function Delete_Push_Default
     (Repository_Root : String;
      Removed         : out Boolean)
      return CryptoLib.Errors.Status;

   --  Set pull.rebase in config.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Mode the mode string to set
   --  @return Ok on success, or an error status on failure.
   function Write_Pull_Rebase
     (Repository_Root : String;
      Mode            : String)
      return CryptoLib.Errors.Status;

   --  Read pull.rebase from config.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Mode the mode bytes
   --  @param Last index of the last valid element written
   --  @param Found set True when the item was found
   --  @return Ok on success, or an error status on failure.
   function Read_Pull_Rebase
     (Repository_Root : String;
      Mode            : out Ada.Streams.Stream_Element_Array;
      Last            : out Ada.Streams.Stream_Element_Offset;
      Found           : out Boolean)
      return CryptoLib.Errors.Status;

   --  Delete pull.rebase from config.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Removed set True when the item was removed
   --  @return Ok on success, or an error status on failure.
   function Delete_Pull_Rebase
     (Repository_Root : String;
      Removed         : out Boolean)
      return CryptoLib.Errors.Status;

   --  Set a branch's upstream remote and merge ref in config.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Branch_Name the branch name
   --  @param Remote_Name the remote name
   --  @param Merge_Ref_Name the upstream merge ref name
   --  @return Ok on success, or an error status on failure.
   function Write_Branch_Upstream
     (Repository_Root : String;
      Branch_Name     : String;
      Remote_Name     : String;
      Merge_Ref_Name  : String)
      return CryptoLib.Errors.Status;

   --  Read a branch's configured upstream remote and merge ref.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Branch_Name the branch name
   --  @param Remote_Name the remote name
   --  @param Remote_Last index of the last valid element of the remote name
   --  @param Merge_Ref_Name the upstream merge ref name
   --  @param Merge_Last index of the last valid element of the merge ref name
   --  @param Found set True when the item was found
   --  @return Ok on success, or an error status on failure.
   function Read_Branch_Upstream
     (Repository_Root : String;
      Branch_Name     : String;
      Remote_Name     : out Ada.Streams.Stream_Element_Array;
      Remote_Last     : out Ada.Streams.Stream_Element_Offset;
      Merge_Ref_Name  : out Ada.Streams.Stream_Element_Array;
      Merge_Last      : out Ada.Streams.Stream_Element_Offset;
      Found           : out Boolean)
      return CryptoLib.Errors.Status;

   --  Delete a branch's upstream configuration.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Branch_Name the branch name
   --  @param Removed set True when the item was removed
   --  @return Ok on success, or an error status on failure.
   function Delete_Branch_Upstream
     (Repository_Root : String;
      Branch_Name     : String;
      Removed         : out Boolean)
      return CryptoLib.Errors.Status;

   --  Report whether any ref of the given name exists, with its id.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Ref_Name the ref name
   --  @param Object_ID_Hex the object's hex-encoded id
   --  @param Last index of the last valid element written
   --  @param Found set True when the item was found
   --  @return Ok on success, or an error status on failure.
   function Ref_Exists
     (Repository_Root : String;
      Ref_Name        : String;
      Object_ID_Hex   : out Ada.Streams.Stream_Element_Array;
      Last            : out Ada.Streams.Stream_Element_Offset;
      Found           : out Boolean)
      return CryptoLib.Errors.Status;

   --  Atomically write a direct ref via a temporary file and rename.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Ref_Name the ref name
   --  @param Object_ID_Hex the object's hex-encoded id
   --  @return Ok on success, or an error status on failure.
   function Write_Direct_Ref_Atomic
     (Repository_Root : String;
      Ref_Name        : String;
      Object_ID_Hex   : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Atomically update a direct ref only when it matches an expected id.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Ref_Name the ref name
   --  @param Expected_Object_ID_Hex the expected current hex id, for the compare-and-swap check
   --  @param New_Object_ID_Hex the new object hex id
   --  @return Ok on success, or an error status on failure.
   function Compare_And_Swap_Direct_Ref
     (Repository_Root        : String;
      Ref_Name               : String;
      Expected_Object_ID_Hex : Ada.Streams.Stream_Element_Array;
      New_Object_ID_Hex      : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Atomically delete a direct ref.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Ref_Name the ref name
   --  @return Ok on success, or an error status on failure.
   function Delete_Direct_Ref_Atomic
     (Repository_Root : String;
      Ref_Name        : String)
      return CryptoLib.Errors.Status;

   --  Atomically delete a direct ref only when it matches an expected id.
   --  @param Repository_Root filesystem path to the repository root
   --  @param Ref_Name the ref name
   --  @param Expected_Object_ID_Hex the expected current hex id, for the compare-and-swap check
   --  @return Ok on success, or an error status on failure.
   function Compare_And_Delete_Direct_Ref
     (Repository_Root        : String;
      Ref_Name               : String;
      Expected_Object_ID_Hex : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Parse a pkt-line's four-byte length header and classify its kind.
   --  @param Data the raw bytes to parse
   --  @param Kind the object type
   --  @param Packet_Length the total packet length in bytes
   --  @return Ok on success, or an error status on failure.
   function Parse_Pkt_Line_Header
     (Data          : Ada.Streams.Stream_Element_Array;
      Kind          : out Pkt_Line_Kind;
      Packet_Length : out Natural)
      return CryptoLib.Errors.Status;

   --  Copy the payload bytes of a single pkt-line.
   --  @param Data the raw bytes to parse
   --  @param Payload the copied payload bytes
   --  @param Last index of the last valid element written
   --  @return Ok on success, or an error status on failure.
   function Copy_Pkt_Line_Payload
     (Data    : Ada.Streams.Stream_Element_Array;
      Payload : out Ada.Streams.Stream_Element_Array;
      Last    : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   --  Initialize a cursor for iterating the pkt-lines in a buffer.
   --  @param Data the raw bytes to parse
   --  @param Cursor the pkt-line iteration cursor
   procedure Reset_Pkt_Line_Cursor
     (Data   : Ada.Streams.Stream_Element_Array;
      Cursor : out Pkt_Line_Cursor);

   --  Advance the cursor to the next pkt-line, reporting its kind and byte ranges.
   --  @param Data the raw bytes to parse
   --  @param Cursor the pkt-line iteration cursor
   --  @param Kind the object type
   --  @param Packet_First byte offset of the first byte of the packet
   --  @param Packet_Last byte offset of the last byte of the packet
   --  @param Payload_First byte offset of the first payload byte
   --  @param Payload_Last byte offset of the last payload byte
   --  @return Ok on success, or an error status on failure.
   function Next_Pkt_Line
     (Data          : Ada.Streams.Stream_Element_Array;
      Cursor        : in out Pkt_Line_Cursor;
      Kind          : out Pkt_Line_Kind;
      Packet_First  : out Ada.Streams.Stream_Element_Offset;
      Packet_Last   : out Ada.Streams.Stream_Element_Offset;
      Payload_First : out Ada.Streams.Stream_Element_Offset;
      Payload_Last  : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   --  Report whether a pkt-line cursor has reached the end of its buffer.
   --  @param Cursor the pkt-line iteration cursor
   --  @return True when the cursor is at the end of the buffer.
   function Pkt_Line_Cursor_Done
     (Cursor : Pkt_Line_Cursor)
      return Boolean;

   --  Encode a payload as a pkt-line packet.
   --  @param Payload the payload to encode
   --  @return the encoded pkt-line packet buffer.
   function Encode_Pkt_Line
     (Payload : Ada.Streams.Stream_Element_Array)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;

   --  Encode a flush packet (0000).
   --  @return the encoded pkt-line packet buffer.
   function Encode_Pkt_Flush
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;

   --  Encode a delimiter packet (0001).
   --  @return the encoded pkt-line packet buffer.
   function Encode_Pkt_Delimiter
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;

   --  Encode a response-end packet (0002).
   --  @return the encoded pkt-line packet buffer.
   function Encode_Pkt_Response_End
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;

   --  Encode an upload-pack 'want' line with optional capabilities.
   --  @param Object_ID_Hex the object's hex-encoded id
   --  @param Capabilities the capability list bytes
   --  @return the encoded pkt-line packet buffer.
   function Encode_Upload_Pack_Want_Line
     (Object_ID_Hex : Ada.Streams.Stream_Element_Array;
      Capabilities  : Ada.Streams.Stream_Element_Array)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;

   --  Encode an upload-pack 'have' line.
   --  @param Object_ID_Hex the object's hex-encoded id
   --  @return the encoded pkt-line packet buffer.
   function Encode_Upload_Pack_Have_Line
     (Object_ID_Hex : Ada.Streams.Stream_Element_Array)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;

   --  Encode an upload-pack 'done' line.
   --  @return the encoded pkt-line packet buffer.
   function Encode_Upload_Pack_Done_Line
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;

   --  Encode an upload-pack 'deepen' line for a shallow depth.
   --  @param Depth the shallow-clone depth
   --  @return the encoded pkt-line packet buffer.
   function Encode_Upload_Pack_Deepen_Line
     (Depth : Natural)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;

   --  Encode an upload-pack 'shallow' line for an object id.
   --  @param Object_ID_Hex the object's hex-encoded id
   --  @return the encoded pkt-line packet buffer.
   function Encode_Upload_Pack_Shallow_Line
     (Object_ID_Hex : Ada.Streams.Stream_Element_Array)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;

   --  Encode an upload-pack 'filter' line for a partial-clone filter.
   --  @param Filter_Spec the partial-clone filter specification
   --  @return the encoded pkt-line packet buffer.
   function Encode_Upload_Pack_Filter_Line
     (Filter_Spec : Ada.Streams.Stream_Element_Array)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;

   --  Parse an upload-pack ACK/NAK packet.
   --  @param Data the raw bytes to parse
   --  @param Kind the object type
   --  @param Object_ID_Hex the object's hex-encoded id
   --  @param Last index of the last valid element written
   --  @return Ok on success, or an error status on failure.
   function Parse_Upload_Pack_ACK_Packet
     (Data          : Ada.Streams.Stream_Element_Array;
      Kind          : out Upload_Pack_ACK_Kind;
      Object_ID_Hex : out Ada.Streams.Stream_Element_Array;
      Last          : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   --  Validate a stream of upload-pack ACK/NAK packets and summarize it.
   --  @param Data the raw bytes to parse
   --  @param Summary the computed summary record
   --  @return Ok on success, or an error status on failure.
   function Validate_Upload_Pack_ACK_Stream
     (Data    : Ada.Streams.Stream_Element_Array;
      Summary : out Upload_Pack_ACK_Stream_Summary)
      return CryptoLib.Errors.Status;

   --  Validate an upload-pack negotiation request and summarize it.
   --  @param Data the raw bytes to parse
   --  @param Summary the computed summary record
   --  @return Ok on success, or an error status on failure.
   function Validate_Upload_Pack_Negotiation_Request
     (Data    : Ada.Streams.Stream_Element_Array;
      Summary : out Upload_Pack_Negotiation_Summary)
      return CryptoLib.Errors.Status;

   --  Encode a complete upload-pack fetch request from wants, haves, and shallows.
   --  @param Wants the wanted object ids
   --  @param Haves the already-present object ids
   --  @param Shallows the shallow boundary object ids
   --  @param Capabilities the capability list bytes
   --  @param Depth the shallow-clone depth
   --  @param Filter_Spec the partial-clone filter specification
   --  @param Include_Done whether to append a 'done' line
   --  @return the encoded pkt-line packet buffer.
   function Encode_Upload_Pack_Fetch_Request
     (Wants        : Object_ID_Hex_Array;
      Haves        : Object_ID_Hex_Array;
      Shallows     : Object_ID_Hex_Array;
      Capabilities : Ada.Streams.Stream_Element_Array;
      Depth        : Natural;
      Filter_Spec  : Ada.Streams.Stream_Element_Array;
      Include_Done : Boolean)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;

   --  Encode a receive-pack ref-update command line.
   --  @param Old_ID_Hex the previous object hex id
   --  @param New_ID_Hex the new object hex id
   --  @param Ref_Name the ref name
   --  @param Capabilities the capability list bytes
   --  @return the encoded pkt-line packet buffer.
   function Encode_Receive_Pack_Update_Line
     (Old_ID_Hex   : Object_ID_Hex_Text;
      New_ID_Hex   : Object_ID_Hex_Text;
      Ref_Name     : Ada.Streams.Stream_Element_Array;
      Capabilities : Ada.Streams.Stream_Element_Array)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;

   --  Validate a receive-pack request and summarize it.
   --  @param Data the raw bytes to parse
   --  @param Summary the computed summary record
   --  @return Ok on success, or an error status on failure.
   function Validate_Receive_Pack_Request
     (Data    : Ada.Streams.Stream_Element_Array;
      Summary : out Receive_Pack_Request_Summary)
      return CryptoLib.Errors.Status;

   --  Validate an upload-pack response stream and summarize it.
   --  @param Data the raw bytes to parse
   --  @param Summary the computed summary record
   --  @return Ok on success, or an error status on failure.
   function Validate_Upload_Pack_Response
     (Data    : Ada.Streams.Stream_Element_Array;
      Summary : out Upload_Pack_Response_Summary)
      return CryptoLib.Errors.Status;

   --  Validate a receive-pack status report and summarize it.
   --  @param Data the raw bytes to parse
   --  @param Summary the computed summary record
   --  @return Ok on success, or an error status on failure.
   function Validate_Receive_Pack_Report
     (Data    : Ada.Streams.Stream_Element_Array;
      Summary : out Receive_Pack_Report_Summary)
      return CryptoLib.Errors.Status;

   --  Reset a fetch workflow to its initial state.
   --  @param Workflow the workflow state record
   procedure Reset_Fetch_Workflow (Workflow : out Fetch_Workflow);

   --  Build the fetch request for a fetch workflow, advancing its state.
   --  @param Workflow the workflow state record
   --  @param Wants the wanted object ids
   --  @param Haves the already-present object ids
   --  @param Shallows the shallow boundary object ids
   --  @param Capabilities the capability list bytes
   --  @param Depth the shallow-clone depth
   --  @param Filter_Spec the partial-clone filter specification
   --  @param Include_Done whether to append a 'done' line
   --  @param Request the encoded request packet buffer
   --  @return Ok on success, or an error status on failure.
   function Fetch_Build_Request
     (Workflow     : in out Fetch_Workflow;
      Wants        : Object_ID_Hex_Array;
      Haves        : Object_ID_Hex_Array;
      Shallows     : Object_ID_Hex_Array;
      Capabilities : Ada.Streams.Stream_Element_Array;
      Depth        : Natural;
      Filter_Spec  : Ada.Streams.Stream_Element_Array;
      Include_Done : Boolean;
      Request      : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;

   --  Feed the server response into a fetch workflow and validate it.
   --  @param Workflow the workflow state record
   --  @param Response the server response bytes
   --  @return Ok on success, or an error status on failure.
   function Fetch_Accept_Response
     (Workflow : in out Fetch_Workflow;
      Response : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Apply a fetched remote-tracking update within a fetch workflow.
   --  @param Workflow the workflow state record
   --  @param Repository_Root filesystem path to the repository root
   --  @param Remote_Name the remote name
   --  @param Branch_Name the branch name
   --  @param New_Commit_Hex the new commit's hex id
   --  @param Allow_Non_Fast_Forward whether non-fast-forward updates are allowed
   --  @param Updated set True when the ref was updated
   --  @return Ok on success, or an error status on failure.
   function Fetch_Apply_Remote_Tracking_Update
     (Workflow               : in out Fetch_Workflow;
      Repository_Root        : String;
      Remote_Name            : String;
      Branch_Name            : String;
      New_Commit_Hex         : Ada.Streams.Stream_Element_Array;
      Allow_Non_Fast_Forward : Boolean;
      Updated                : out Boolean)
      return CryptoLib.Errors.Status;

   --  Finalize a fetch workflow.
   --  @param Workflow the workflow state record
   --  @return Ok on success, or an error status on failure.
   function Fetch_Finish
     (Workflow : in out Fetch_Workflow)
      return CryptoLib.Errors.Status;

   --  Reset a push workflow to its initial state.
   --  @param Workflow the workflow state record
   procedure Reset_Push_Workflow (Workflow : out Push_Workflow);

   --  Build the push request (ref updates plus packfile) for a push workflow.
   --  @param Workflow the workflow state record
   --  @param Updates the encoded ref-update command lines
   --  @param Pack_Data the packfile bytes
   --  @param Request the encoded request packet buffer
   --  @return Ok on success, or an error status on failure.
   function Push_Build_Request
     (Workflow     : in out Push_Workflow;
      Updates      : Ada.Streams.Stream_Element_Array;
      Pack_Data    : Ada.Streams.Stream_Element_Array;
      Request      : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;

   --  Feed the server report into a push workflow and validate it.
   --  @param Workflow the workflow state record
   --  @param Report the server status report bytes
   --  @return Ok on success, or an error status on failure.
   function Push_Accept_Report
     (Workflow : in out Push_Workflow;
      Report   : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Apply a pushed branch update within a push workflow.
   --  @param Workflow the workflow state record
   --  @param Repository_Root filesystem path to the repository root
   --  @param Branch_Name the branch name
   --  @param Expected_Old_Hex the expected current hex id, for the compare-and-swap check
   --  @param New_Commit_Hex the new commit's hex id
   --  @param Allow_Non_Fast_Forward whether non-fast-forward updates are allowed
   --  @param Updated set True when the ref was updated
   --  @return Ok on success, or an error status on failure.
   function Push_Apply_Branch_Update
     (Workflow               : in out Push_Workflow;
      Repository_Root        : String;
      Branch_Name            : String;
      Expected_Old_Hex       : Ada.Streams.Stream_Element_Array;
      New_Commit_Hex         : Ada.Streams.Stream_Element_Array;
      Allow_Non_Fast_Forward : Boolean;
      Updated                : out Boolean)
      return CryptoLib.Errors.Status;

   --  Finalize a push workflow.
   --  @param Workflow the workflow state record
   --  @return Ok on success, or an error status on failure.
   function Push_Finish
     (Workflow : in out Push_Workflow)
      return CryptoLib.Errors.Status;

   --  Decide the next fetch action from the workflow state and attempt counts.
   --  @param Workflow the workflow state record
   --  @param Attempt the current attempt number
   --  @param Max_Attempts the maximum number of attempts
   --  @param Local_Have_Count the number of local have ids available
   --  @param Decision the chosen policy decision
   --  @return Ok on success, or an error status on failure.
   function Decide_Fetch_Policy
     (Workflow         : Fetch_Workflow;
      Attempt          : Natural;
      Max_Attempts     : Natural;
      Local_Have_Count : Natural;
      Decision         : out Fetch_Policy_Decision)
      return CryptoLib.Errors.Status;

   --  Decide the next push action from the workflow state and attempt counts.
   --  @param Workflow the workflow state record
   --  @param Attempt the current attempt number
   --  @param Max_Attempts the maximum number of attempts
   --  @param Decision the chosen policy decision
   --  @return Ok on success, or an error status on failure.
   function Decide_Push_Policy
     (Workflow     : Push_Workflow;
      Attempt      : Natural;
      Max_Attempts : Natural;
      Decision     : out Push_Policy_Decision)
      return CryptoLib.Errors.Status;

   --  Encode a protocol v2 command request with capabilities and arguments.
   --  @param Command_Name the protocol v2 command name
   --  @param Capabilities the capability list bytes
   --  @param Arguments the protocol v2 argument lines
   --  @return the encoded pkt-line packet buffer.
   function Encode_Protocol_V2_Command_Request
     (Command_Name : Ada.Streams.Stream_Element_Array;
      Capabilities : Ada.Streams.Stream_Element_Array;
      Arguments    : Ada.Streams.Stream_Element_Array)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;

   --  Validate a protocol v2 command request and summarize it.
   --  @param Data the raw bytes to parse
   --  @param Summary the computed summary record
   --  @return Ok on success, or an error status on failure.
   function Validate_Protocol_V2_Command_Request
     (Data    : Ada.Streams.Stream_Element_Array;
      Summary : out Protocol_V2_Request_Summary)
      return CryptoLib.Errors.Status;

   --  Validate a protocol v2 capability advertisement and summarize it.
   --  @param Data the raw bytes to parse
   --  @param Summary the computed summary record
   --  @return Ok on success, or an error status on failure.
   function Validate_Protocol_V2_Capability_Advertisement
     (Data    : Ada.Streams.Stream_Element_Array;
      Summary : out Protocol_V2_Capability_Summary)
      return CryptoLib.Errors.Status;

   --  Validate a protocol v2 response stream and summarize it.
   --  @param Data the raw bytes to parse
   --  @param Summary the computed summary record
   --  @return Ok on success, or an error status on failure.
   function Validate_Protocol_V2_Response
     (Data    : Ada.Streams.Stream_Element_Array;
      Summary : out Protocol_V2_Response_Summary)
      return CryptoLib.Errors.Status;

   --  Parse a single ref-advertisement packet into id, ref name, and capabilities.
   --  @param Data the raw bytes to parse
   --  @param Object_ID_Hex the object's hex-encoded id
   --  @param Object_Last index of the last valid element of the object id
   --  @param Ref_Name the ref name
   --  @param Ref_Last index of the last valid element of the ref name
   --  @param Capabilities the capability list bytes
   --  @param Cap_Last index of the last valid element of the capabilities
   --  @param Has_Caps set True when the packet carries capabilities
   --  @param Is_Peeled set True for a peeled tag advertisement line
   --  @param Is_Symref set True for a symbolic-ref advertisement line
   --  @return Ok on success, or an error status on failure.
   function Parse_Ref_Advertisement_Packet
     (Data          : Ada.Streams.Stream_Element_Array;
      Object_ID_Hex : out Ada.Streams.Stream_Element_Array;
      Object_Last   : out Ada.Streams.Stream_Element_Offset;
      Ref_Name      : out Ada.Streams.Stream_Element_Array;
      Ref_Last      : out Ada.Streams.Stream_Element_Offset;
      Capabilities  : out Ada.Streams.Stream_Element_Array;
      Cap_Last      : out Ada.Streams.Stream_Element_Offset;
      Has_Caps      : out Boolean;
      Is_Peeled     : out Boolean;
      Is_Symref     : out Boolean)
      return CryptoLib.Errors.Status;

   --  Validate a full ref-advertisement stream and summarize it.
   --  @param Data the raw bytes to parse
   --  @param Summary the computed summary record
   --  @return Ok on success, or an error status on failure.
   function Validate_Ref_Advertisement_Stream
     (Data    : Ada.Streams.Stream_Element_Array;
      Summary : out Ref_Advertisement_Summary)
      return CryptoLib.Errors.Status;

   --  Parse a packfile header, returning its version and object count.
   --  @param Data the raw bytes to parse
   --  @param Version the object/index format version
   --  @param Object_Count the number of objects
   --  @return Ok on success, or an error status on failure.
   function Parse_Pack_Header
     (Data         : Ada.Streams.Stream_Element_Array;
      Version      : out Natural;
      Object_Count : out Natural)
      return CryptoLib.Errors.Status;

   --  Parse a pack index header, returning its version.
   --  @param Data the raw bytes to parse
   --  @param Version the object/index format version
   --  @return Ok on success, or an error status on failure.
   function Parse_Pack_Index_Header
     (Data    : Ada.Streams.Stream_Element_Array;
      Version : out Natural)
      return CryptoLib.Errors.Status;

   --  Read the object count from a pack index fanout table.
   --  @param Data the raw bytes to parse
   --  @param Object_Count the number of objects
   --  @return Ok on success, or an error status on failure.
   function Parse_Pack_Index_Fanout
     (Data         : Ada.Streams.Stream_Element_Array;
      Object_Count : out Natural)
      return CryptoLib.Errors.Status;

   --  Copy the object id at a given position from a pack index.
   --  @param Data the raw bytes to parse
   --  @param Object_Index zero-based index of the object in the pack index
   --  @param Object_ID the raw binary object identifier
   --  @param Last index of the last valid element written
   --  @return Ok on success, or an error status on failure.
   function Copy_Pack_Index_Object_ID
     (Data         : Ada.Streams.Stream_Element_Array;
      Object_Index : Natural;
      Object_ID    : out Ada.Streams.Stream_Element_Array;
      Last         : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   --  Read the CRC32 for an object entry in a pack index.
   --  @param Data the raw bytes to parse
   --  @param Object_Index zero-based index of the object in the pack index
   --  @param CRC_Value the CRC32 value
   --  @return Ok on success, or an error status on failure.
   function Parse_Pack_Index_CRC
     (Data         : Ada.Streams.Stream_Element_Array;
      Object_Index : Natural;
      CRC_Value    : out Natural)
      return CryptoLib.Errors.Status;

   --  Read an object's pack offset from the index, noting large-offset use.
   --  @param Data the raw bytes to parse
   --  @param Object_Index zero-based index of the object in the pack index
   --  @param Pack_Offset byte offset of the object within the packfile
   --  @param Large_Offset_Index index into the large-offset table
   --  @param Uses_Large_Offset set True when the offset lives in the large-offset table
   --  @return Ok on success, or an error status on failure.
   function Parse_Pack_Index_Offset
     (Data               : Ada.Streams.Stream_Element_Array;
      Object_Index       : Natural;
      Pack_Offset        : out Natural;
      Large_Offset_Index : out Natural;
      Uses_Large_Offset  : out Boolean)
      return CryptoLib.Errors.Status;

   --  Read a 64-bit large offset from a pack index's large-offset table.
   --  @param Data the raw bytes to parse
   --  @param Large_Offset_Index index into the large-offset table
   --  @param Pack_Offset byte offset of the object within the packfile
   --  @return Ok on success, or an error status on failure.
   function Parse_Pack_Index_Large_Offset
     (Data               : Ada.Streams.Stream_Element_Array;
      Large_Offset_Index : Natural;
      Pack_Offset        : out Natural)
      return CryptoLib.Errors.Status;

   --  Copy the trailing pack checksum from a pack index.
   --  @param Data the raw bytes to parse
   --  @param Checksum the copied checksum bytes
   --  @param Last index of the last valid element written
   --  @return Ok on success, or an error status on failure.
   function Copy_Pack_Index_Checksum
     (Data     : Ada.Streams.Stream_Element_Array;
      Checksum : out Ada.Streams.Stream_Element_Array;
      Last     : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   --  Compute the byte offset of each section of a pack index.
   --  @param Object_Count the number of objects
   --  @param Large_Offset_Count the number of large offsets
   --  @param Layout the computed pack-index section layout
   --  @return Ok on success, or an error status on failure.
   function Compute_Pack_Index_Layout
     (Object_Count       : Natural;
      Large_Offset_Count : Natural;
      Layout             : out Pack_Index_Layout)
      return CryptoLib.Errors.Status;

   --  Build a pack index (.idx) from a packfile.
   --  @param Pack_Data the packfile bytes
   --  @param Object_Scratch scratch buffer for object reconstruction
   --  @param Index_Data the pack index bytes
   --  @param Last index of the last valid element written
   --  @return Ok on success, or an error status on failure.
   function Build_Pack_Index
     (Pack_Data      : Ada.Streams.Stream_Element_Array;
      Object_Scratch : out Ada.Streams.Stream_Element_Array;
      Index_Data     : out Ada.Streams.Stream_Element_Array;
      Last           : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   --  Check that a pack index's object ids are sorted ascending.
   --  @param Data the raw bytes to parse
   --  @param Object_Count the number of objects
   --  @return Ok on success, or an error status on failure.
   function Validate_Pack_Index_Object_ID_Order
     (Data         : Ada.Streams.Stream_Element_Array;
      Object_Count : Natural)
      return CryptoLib.Errors.Status;

   --  Check that a pack index fanout table agrees with its object ids.
   --  @param Fanout the pack-index fanout table bytes
   --  @param Object_IDs the pack-index object id table bytes
   --  @param Object_Count the number of objects
   --  @return Ok on success, or an error status on failure.
   function Validate_Pack_Index_Fanout_Matches_Object_IDs
     (Fanout       : Ada.Streams.Stream_Element_Array;
      Object_IDs   : Ada.Streams.Stream_Element_Array;
      Object_Count : Natural)
      return CryptoLib.Errors.Status;

   --  Check the large-offset count implied by a pack index's offset table.
   --  @param Offsets_Table the pack-index offset table bytes
   --  @param Object_Count the number of objects
   --  @param Large_Offset_Count the number of large offsets
   --  @return Ok on success, or an error status on failure.
   function Validate_Pack_Index_Large_Offset_Count
     (Offsets_Table      : Ada.Streams.Stream_Element_Array;
      Object_Count       : Natural;
      Large_Offset_Count : Natural)
      return CryptoLib.Errors.Status;

   --  Validate a pack index's structure and report its layout.
   --  @param Data the raw bytes to parse
   --  @param Object_Count the number of objects
   --  @param Large_Offset_Count the number of large offsets
   --  @param Layout the computed pack-index section layout
   --  @return Ok on success, or an error status on failure.
   function Validate_Pack_Index
     (Data               : Ada.Streams.Stream_Element_Array;
      Object_Count       : out Natural;
      Large_Offset_Count : out Natural;
      Layout             : out Pack_Index_Layout)
      return CryptoLib.Errors.Status;

   --  Verify a packfile's trailing SHA checksum.
   --  @param Pack_Data the packfile bytes
   --  @return Ok on success, or an error status on failure.
   function Verify_Pack_Trailer_Checksum
     (Pack_Data : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Verify a pack index's trailing self-checksum.
   --  @param Index_Data the pack index bytes
   --  @return Ok on success, or an error status on failure.
   function Verify_Pack_Index_Checksum
     (Index_Data : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Verify that a pack index's recorded pack checksum matches an expected one.
   --  @param Index_Data the pack index bytes
   --  @param Expected_Pack_Checksum the expected pack checksum
   --  @return Ok on success, or an error status on failure.
   function Verify_Pack_Index_Pack_Checksum
     (Index_Data              : Ada.Streams.Stream_Element_Array;
      Expected_Pack_Checksum  : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Find an object by raw id in a pack index, returning its pack offset.
   --  @param Index_Data the pack index bytes
   --  @param Object_ID the raw binary object identifier
   --  @param Object_Index zero-based index of the object in the pack index
   --  @param Pack_Offset byte offset of the object within the packfile
   --  @return Ok on success, or an error status on failure.
   function Find_Pack_Index_Object
     (Index_Data        : Ada.Streams.Stream_Element_Array;
      Object_ID         : Ada.Streams.Stream_Element_Array;
      Object_Index      : out Natural;
      Pack_Offset       : out Natural)
      return CryptoLib.Errors.Status;

   --  Find an object by hex id in a pack index, returning its pack offset.
   --  @param Index_Data the pack index bytes
   --  @param Object_ID_Hex the object's hex-encoded id
   --  @param Object_Index zero-based index of the object in the pack index
   --  @param Pack_Offset byte offset of the object within the packfile
   --  @return Ok on success, or an error status on failure.
   function Find_Pack_Index_Object_Hex
     (Index_Data        : Ada.Streams.Stream_Element_Array;
      Object_ID_Hex     : Ada.Streams.Stream_Element_Array;
      Object_Index      : out Natural;
      Pack_Offset       : out Natural)
      return CryptoLib.Errors.Status;

   --  List every object id recorded in a pack index.
   --  @param Index_Data the pack index bytes
   --  @param Object_IDs_Hex the resulting hex-encoded object ids
   --  @param Count the number of items produced
   --  @return Ok on success, or an error status on failure.
   function List_Pack_Index_Object_IDs
     (Index_Data     : Ada.Streams.Stream_Element_Array;
      Object_IDs_Hex : out Object_ID_Hex_Array;
      Count          : out Natural)
      return CryptoLib.Errors.Status;

   --  Verify that every pack-index offset points at a valid pack object.
   --  @param Index_Data the pack index bytes
   --  @param Pack_Data the packfile bytes
   --  @param Scratch scratch buffer for object reconstruction
   --  @param Object_Count the number of objects
   --  @param Trailer_Offset byte offset of the packfile trailer
   --  @return Ok on success, or an error status on failure.
   function Validate_Pack_Index_Offsets
     (Index_Data     : Ada.Streams.Stream_Element_Array;
      Pack_Data      : Ada.Streams.Stream_Element_Array;
      Scratch        : out Ada.Streams.Stream_Element_Array;
      Object_Count   : out Natural;
      Trailer_Offset : out Natural)
      return CryptoLib.Errors.Status;

   --  Verify every pack-index CRC against the packfile.
   --  @param Index_Data the pack index bytes
   --  @param Pack_Data the packfile bytes
   --  @param Scratch scratch buffer for object reconstruction
   --  @param Object_Count the number of objects
   --  @param Trailer_Offset byte offset of the packfile trailer
   --  @return Ok on success, or an error status on failure.
   function Validate_Pack_Index_CRCs
     (Index_Data     : Ada.Streams.Stream_Element_Array;
      Pack_Data      : Ada.Streams.Stream_Element_Array;
      Scratch        : out Ada.Streams.Stream_Element_Array;
      Object_Count   : out Natural;
      Trailer_Offset : out Natural)
      return CryptoLib.Errors.Status;

   --  Verify that every delta object's base is present.
   --  @param Index_Data the pack index bytes
   --  @param Pack_Data the packfile bytes
   --  @param Scratch scratch buffer for object reconstruction
   --  @param Object_Count the number of objects
   --  @param Trailer_Offset byte offset of the packfile trailer
   --  @return Ok on success, or an error status on failure.
   function Validate_Pack_Delta_Bases
     (Index_Data     : Ada.Streams.Stream_Element_Array;
      Pack_Data      : Ada.Streams.Stream_Element_Array;
      Scratch        : out Ada.Streams.Stream_Element_Array;
      Object_Count   : out Natural;
      Trailer_Offset : out Natural)
      return CryptoLib.Errors.Status;

   --  Verify that the delta dependency graph is acyclic and bounded.
   --  @param Index_Data the pack index bytes
   --  @param Pack_Data the packfile bytes
   --  @param Scratch scratch buffer for object reconstruction
   --  @param Object_Count the number of objects
   --  @param Trailer_Offset byte offset of the packfile trailer
   --  @return Ok on success, or an error status on failure.
   function Validate_Pack_Delta_Graph
     (Index_Data     : Ada.Streams.Stream_Element_Array;
      Pack_Data      : Ada.Streams.Stream_Element_Array;
      Scratch        : out Ada.Streams.Stream_Element_Array;
      Object_Count   : out Natural;
      Trailer_Offset : out Natural)
      return CryptoLib.Errors.Status;

   --  Verify the computed ids of all non-delta pack objects.
   --  @param Index_Data the pack index bytes
   --  @param Pack_Data the packfile bytes
   --  @param Scratch scratch buffer for object reconstruction
   --  @param Object_Count the number of objects
   --  @param Verified_Count the number of objects verified
   --  @param Trailer_Offset byte offset of the packfile trailer
   --  @return Ok on success, or an error status on failure.
   function Validate_Pack_Non_Delta_Object_IDs
     (Index_Data      : Ada.Streams.Stream_Element_Array;
      Pack_Data       : Ada.Streams.Stream_Element_Array;
      Scratch         : out Ada.Streams.Stream_Element_Array;
      Object_Count    : out Natural;
      Verified_Count  : out Natural;
      Trailer_Offset  : out Natural)
      return CryptoLib.Errors.Status;

   --  Verify ids of pack objects that delta directly against a stored base.
   --  @param Index_Data the pack index bytes
   --  @param Pack_Data the packfile bytes
   --  @param Base_Scratch scratch buffer for delta base objects
   --  @param Delta_Scratch scratch buffer for delta objects
   --  @param Result_Scratch scratch buffer for reconstructed objects
   --  @param Object_Count the number of objects
   --  @param Resolved_Count the number of delta objects resolved
   --  @param Trailer_Offset byte offset of the packfile trailer
   --  @return Ok on success, or an error status on failure.
   function Validate_Pack_Immediate_Delta_Object_IDs
     (Index_Data      : Ada.Streams.Stream_Element_Array;
      Pack_Data       : Ada.Streams.Stream_Element_Array;
      Base_Scratch    : out Ada.Streams.Stream_Element_Array;
      Delta_Scratch   : out Ada.Streams.Stream_Element_Array;
      Result_Scratch  : out Ada.Streams.Stream_Element_Array;
      Object_Count    : out Natural;
      Resolved_Count  : out Natural;
      Trailer_Offset  : out Natural)
      return CryptoLib.Errors.Status;

   --  Verify ids of pack objects reached through multi-step delta chains.
   --  @param Index_Data the pack index bytes
   --  @param Pack_Data the packfile bytes
   --  @param Base_Scratch scratch buffer for delta base objects
   --  @param Delta_Scratch scratch buffer for delta objects
   --  @param Workspace scratch buffer for delta-chain reconstruction
   --  @param Result_Scratch scratch buffer for reconstructed objects
   --  @param Object_Count the number of objects
   --  @param Resolved_Count the number of delta objects resolved
   --  @param Trailer_Offset byte offset of the packfile trailer
   --  @return Ok on success, or an error status on failure.
   function Validate_Pack_Delta_Chain_Object_IDs
     (Index_Data      : Ada.Streams.Stream_Element_Array;
      Pack_Data       : Ada.Streams.Stream_Element_Array;
      Base_Scratch    : out Ada.Streams.Stream_Element_Array;
      Delta_Scratch   : out Ada.Streams.Stream_Element_Array;
      Workspace       : out Ada.Streams.Stream_Element_Array;
      Result_Scratch  : out Ada.Streams.Stream_Element_Array;
      Object_Count    : out Natural;
      Resolved_Count  : out Natural;
      Trailer_Offset  : out Natural)
      return CryptoLib.Errors.Status;

   --  Verify the computed id of every object in a packfile.
   --  @param Index_Data the pack index bytes
   --  @param Pack_Data the packfile bytes
   --  @param Base_Scratch scratch buffer for delta base objects
   --  @param Delta_Scratch scratch buffer for delta objects
   --  @param Workspace scratch buffer for delta-chain reconstruction
   --  @param Result_Scratch scratch buffer for reconstructed objects
   --  @param Object_Count the number of objects
   --  @param Verified_Count the number of objects verified
   --  @param Resolved_Count the number of delta objects resolved
   --  @param Trailer_Offset byte offset of the packfile trailer
   --  @return Ok on success, or an error status on failure.
   function Validate_Pack_Object_IDs
     (Index_Data      : Ada.Streams.Stream_Element_Array;
      Pack_Data       : Ada.Streams.Stream_Element_Array;
      Base_Scratch    : out Ada.Streams.Stream_Element_Array;
      Delta_Scratch   : out Ada.Streams.Stream_Element_Array;
      Workspace       : out Ada.Streams.Stream_Element_Array;
      Result_Scratch  : out Ada.Streams.Stream_Element_Array;
      Object_Count    : out Natural;
      Verified_Count  : out Natural;
      Resolved_Count  : out Natural;
      Trailer_Offset  : out Natural)
      return CryptoLib.Errors.Status;

   --  Run full structural and id validation over a packfile and its index.
   --  @param Index_Data the pack index bytes
   --  @param Pack_Data the packfile bytes
   --  @param Base_Scratch scratch buffer for delta base objects
   --  @param Delta_Scratch scratch buffer for delta objects
   --  @param Workspace scratch buffer for delta-chain reconstruction
   --  @param Result_Scratch scratch buffer for reconstructed objects
   --  @param Object_Count the number of objects
   --  @param Verified_Count the number of objects verified
   --  @param Resolved_Count the number of delta objects resolved
   --  @param Trailer_Offset byte offset of the packfile trailer
   --  @return Ok on success, or an error status on failure.
   function Validate_Pack_Integrity
     (Index_Data      : Ada.Streams.Stream_Element_Array;
      Pack_Data       : Ada.Streams.Stream_Element_Array;
      Base_Scratch    : out Ada.Streams.Stream_Element_Array;
      Delta_Scratch   : out Ada.Streams.Stream_Element_Array;
      Workspace       : out Ada.Streams.Stream_Element_Array;
      Result_Scratch  : out Ada.Streams.Stream_Element_Array;
      Object_Count    : out Natural;
      Verified_Count  : out Natural;
      Resolved_Count  : out Natural;
      Trailer_Offset  : out Natural)
      return CryptoLib.Errors.Status;

   --  Count a packfile's objects by type.
   --  @param Pack_Data the packfile bytes
   --  @param Scratch scratch buffer for object reconstruction
   --  @param Counts the per-type object counts
   --  @param Object_Count the number of objects
   --  @param Trailer_Offset byte offset of the packfile trailer
   --  @return Ok on success, or an error status on failure.
   function Inventory_Pack_Objects
     (Pack_Data      : Ada.Streams.Stream_Element_Array;
      Scratch        : out Ada.Streams.Stream_Element_Array;
      Counts         : out Pack_Object_Counts;
      Object_Count   : out Natural;
      Trailer_Offset : out Natural)
      return CryptoLib.Errors.Status;

   --  Compute the object id for object contents of a given type.
   --  @param Kind the object type
   --  @param Data the input object bytes
   --  @param Object_ID the raw binary object identifier
   --  @param Last index of the last valid element written
   --  @return Ok on success, or an error status on failure.
   function Compute_Object_ID
     (Kind      : Pack_Object_Kind;
      Data      : Ada.Streams.Stream_Element_Array;
      Object_ID : out Ada.Streams.Stream_Element_Array;
      Last      : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   --  Encode a single tree entry from mode, name, and object id.
   --  @param File_Mode the Git file-mode bits
   --  @param Name the entry name
   --  @param Object_ID the raw binary object identifier
   --  @param Entry_Data the encoded entry bytes
   --  @param Last index of the last valid element written
   --  @return Ok on success, or an error status on failure.
   function Build_Tree_Entry
     (File_Mode : Natural;
      Name      : String;
      Object_ID : Ada.Streams.Stream_Element_Array;
      Entry_Data : out Ada.Streams.Stream_Element_Array;
      Last      : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   --  Build a commit object from tree, parent, author, committer, and message.
   --  @param Tree_ID_Hex the tree's hex-encoded id
   --  @param Has_Parent whether the commit has a parent
   --  @param Parent_ID_Hex the parent commit's hex id
   --  @param Author_Line the commit author identity line
   --  @param Committer_Line the commit committer identity line
   --  @param Message the message text
   --  @param Commit_Data the commit object bytes
   --  @param Last index of the last valid element written
   --  @return Ok on success, or an error status on failure.
   function Build_Commit_Object
     (Tree_ID_Hex    : Ada.Streams.Stream_Element_Array;
      Has_Parent     : Boolean;
      Parent_ID_Hex  : Ada.Streams.Stream_Element_Array;
      Author_Line    : String;
      Committer_Line : String;
      Message        : String;
      Commit_Data    : out Ada.Streams.Stream_Element_Array;
      Last           : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   --  Build a conflict-marked file from ours and theirs contents.
   --  @param Ours_Label label for the ours side
   --  @param Ours_Data content of the ours side
   --  @param Theirs_Label label for the theirs side
   --  @param Theirs_Data content of the theirs side
   --  @param Conflict_Data the conflict-marked output bytes
   --  @param Last index of the last valid element written
   --  @return Ok on success, or an error status on failure.
   function Build_Merge_Conflict_File
     (Ours_Label    : String;
      Ours_Data     : Ada.Streams.Stream_Element_Array;
      Theirs_Label  : String;
      Theirs_Data   : Ada.Streams.Stream_Element_Array;
      Conflict_Data : out Ada.Streams.Stream_Element_Array;
      Last          : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   --  Classify a three-way blob merge as unchanged, ours, theirs, or conflict.
   --  @param Base_ID_Hex the merge base blob's hex id
   --  @param Ours_ID_Hex the ours blob's hex id
   --  @param Theirs_ID_Hex the theirs blob's hex id
   --  @param Result the classified merge result
   --  @return Ok on success, or an error status on failure.
   function Classify_Three_Way_Blob_Merge
     (Base_ID_Hex   : Ada.Streams.Stream_Element_Array;
      Ours_ID_Hex   : Ada.Streams.Stream_Element_Array;
      Theirs_ID_Hex : Ada.Streams.Stream_Element_Array;
      Result        : out Three_Way_Merge_Result)
      return CryptoLib.Errors.Status;

   --  Format one 'pick' line for a sequencer todo list.
   --  @param Commit_ID_Hex the commit's hex-encoded id
   --  @param Subject the commit subject line
   --  @param Line the resulting line bytes
   --  @param Last index of the last valid element written
   --  @return Ok on success, or an error status on failure.
   function Build_Sequencer_Pick_Line
     (Commit_ID_Hex : Ada.Streams.Stream_Element_Array;
      Subject       : String;
      Line          : out Ada.Streams.Stream_Element_Array;
      Last          : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   --  Build a full sequencer pick todo list from commits and subjects.
   --  @param Commit_IDs_Hex the commit hex ids to pick
   --  @param Subjects packed buffer of commit subjects
   --  @param Subject_Lasts end offset of each packed subject
   --  @param Count the number of items produced
   --  @param Todo the resulting sequencer todo bytes
   --  @param Last index of the last valid element written
   --  @return Ok on success, or an error status on failure.
   function Build_Sequencer_Pick_Todo
     (Commit_IDs_Hex : Object_ID_Hex_Array;
      Subjects       : Ada.Streams.Stream_Element_Array;
      Subject_Lasts  : Index_Path_Last_Array;
      Count          : Natural;
      Todo           : out Ada.Streams.Stream_Element_Array;
      Last           : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   --  Build an annotated tag object.
   --  @param Target_ID_Hex the tag target's hex id
   --  @param Target_Kind the tag target's object type
   --  @param Tag_Name the tag name
   --  @param Tagger_Line the tagger identity line
   --  @param Message the message text
   --  @param Tag_Data the tag object bytes
   --  @param Last index of the last valid element written
   --  @return Ok on success, or an error status on failure.
   function Build_Tag_Object
     (Target_ID_Hex : Ada.Streams.Stream_Element_Array;
      Target_Kind   : Pack_Object_Kind;
      Tag_Name      : String;
      Tagger_Line   : String;
      Message       : String;
      Tag_Data      : out Ada.Streams.Stream_Element_Array;
      Last          : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   --  Parse one tree entry at a byte offset, returning the next offset.
   --  @param Data the raw bytes to parse
   --  @param Entry_Offset byte offset of the entry within the data
   --  @param File_Mode the Git file-mode bits
   --  @param Name the parsed name bytes
   --  @param Name_Last index of the last valid element of the name
   --  @param Object_ID the raw binary object identifier
   --  @param Object_Last index of the last valid element of the object id
   --  @param Next_Offset byte offset of the following entry
   --  @return Ok on success, or an error status on failure.
   function Parse_Tree_Entry
     (Data         : Ada.Streams.Stream_Element_Array;
      Entry_Offset : Natural;
      File_Mode    : out Natural;
      Name         : out Ada.Streams.Stream_Element_Array;
      Name_Last    : out Ada.Streams.Stream_Element_Offset;
      Object_ID    : out Ada.Streams.Stream_Element_Array;
      Object_Last  : out Ada.Streams.Stream_Element_Offset;
      Next_Offset  : out Natural)
      return CryptoLib.Errors.Status;

   --  Validate a tree object's structure and count its entries.
   --  @param Data the raw bytes to parse
   --  @param Entry_Count the number of entries
   --  @return Ok on success, or an error status on failure.
   function Validate_Tree_Object
     (Data        : Ada.Streams.Stream_Element_Array;
      Entry_Count : out Natural)
      return CryptoLib.Errors.Status;

   --  Find a tree entry by name, returning its raw object id.
   --  @param Data the raw bytes to parse
   --  @param Name the entry name
   --  @param File_Mode the Git file-mode bits
   --  @param Object_ID the raw binary object identifier
   --  @param Object_Last index of the last valid element of the object id
   --  @return Ok on success, or an error status on failure.
   function Find_Tree_Entry
     (Data        : Ada.Streams.Stream_Element_Array;
      Name        : Ada.Streams.Stream_Element_Array;
      File_Mode   : out Natural;
      Object_ID   : out Ada.Streams.Stream_Element_Array;
      Object_Last : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   --  Find a tree entry by name, returning its hex object id.
   --  @param Data the raw bytes to parse
   --  @param Name the entry name
   --  @param File_Mode the Git file-mode bits
   --  @param Object_ID the raw binary object identifier
   --  @param Object_Last index of the last valid element of the object id
   --  @return Ok on success, or an error status on failure.
   function Find_Tree_Entry_Hex
     (Data        : Ada.Streams.Stream_Element_Array;
      Name        : Ada.Streams.Stream_Element_Array;
      File_Mode   : out Natural;
      Object_ID   : out Ada.Streams.Stream_Element_Array;
      Object_Last : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   --  Parse the tree id from a commit object.
   --  @param Data the raw bytes to parse
   --  @param Tree_ID_Hex the tree's hex-encoded id
   --  @param Last index of the last valid element written
   --  @return Ok on success, or an error status on failure.
   function Parse_Commit_Tree_ID
     (Data        : Ada.Streams.Stream_Element_Array;
      Tree_ID_Hex : out Ada.Streams.Stream_Element_Array;
      Last        : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   --  Parse the Nth parent id from a commit object.
   --  @param Data the raw bytes to parse
   --  @param Parent_Index the one-based parent position to read
   --  @param Parent_ID_Hex the parent commit's hex id
   --  @param Last index of the last valid element written
   --  @return Ok on success, or an error status on failure.
   function Parse_Commit_Parent_ID
     (Data          : Ada.Streams.Stream_Element_Array;
      Parent_Index  : Positive;
      Parent_ID_Hex : out Ada.Streams.Stream_Element_Array;
      Last          : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   --  Extract the author line from a commit object.
   --  @param Data the raw bytes to parse
   --  @param Text the extracted text bytes
   --  @param Last index of the last valid element written
   --  @return Ok on success, or an error status on failure.
   function Parse_Commit_Author_Line
     (Data : Ada.Streams.Stream_Element_Array;
      Text : out Ada.Streams.Stream_Element_Array;
      Last : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   --  Extract the committer line from a commit object.
   --  @param Data the raw bytes to parse
   --  @param Text the extracted text bytes
   --  @param Last index of the last valid element written
   --  @return Ok on success, or an error status on failure.
   function Parse_Commit_Committer_Line
     (Data : Ada.Streams.Stream_Element_Array;
      Text : out Ada.Streams.Stream_Element_Array;
      Last : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   --  Find the byte offset where a commit's message begins.
   --  @param Data the raw bytes to parse
   --  @param Message_Offset byte offset where the message begins
   --  @return Ok on success, or an error status on failure.
   function Parse_Commit_Message_Offset
     (Data           : Ada.Streams.Stream_Element_Array;
      Message_Offset : out Natural)
      return CryptoLib.Errors.Status;

   --  Validate a commit object and count its parents.
   --  @param Data the raw bytes to parse
   --  @param Parent_Count the number of parents
   --  @return Ok on success, or an error status on failure.
   function Validate_Commit_Object
     (Data         : Ada.Streams.Stream_Element_Array;
      Parent_Count : out Natural)
      return CryptoLib.Errors.Status;

   --  Parse an annotated tag's target id and object type.
   --  @param Data the raw bytes to parse
   --  @param Target_ID_Hex the tag target's hex id
   --  @param Last index of the last valid element written
   --  @param Target_Kind the tag target's object type
   --  @return Ok on success, or an error status on failure.
   function Parse_Tag_Target
     (Data          : Ada.Streams.Stream_Element_Array;
      Target_ID_Hex : out Ada.Streams.Stream_Element_Array;
      Last          : out Ada.Streams.Stream_Element_Offset;
      Target_Kind   : out Pack_Object_Kind)
      return CryptoLib.Errors.Status;

   --  Parse the tag name from an annotated tag object.
   --  @param Data the raw bytes to parse
   --  @param Name the parsed name bytes
   --  @param Last index of the last valid element written
   --  @return Ok on success, or an error status on failure.
   function Parse_Tag_Name
     (Data : Ada.Streams.Stream_Element_Array;
      Name : out Ada.Streams.Stream_Element_Array;
      Last : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   --  Find the byte offset where a tag's message begins.
   --  @param Data the raw bytes to parse
   --  @param Message_Offset byte offset where the message begins
   --  @return Ok on success, or an error status on failure.
   function Parse_Tag_Message_Offset
     (Data           : Ada.Streams.Stream_Element_Array;
      Message_Offset : out Natural)
      return CryptoLib.Errors.Status;

   --  Validate object contents for a given object type.
   --  @param Kind the object type
   --  @param Data the object contents to validate
   --  @return Ok on success, or an error status on failure.
   function Validate_Object_Data
     (Kind : Pack_Object_Kind;
      Data : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Validate an annotated tag object and report its target type.
   --  @param Data the raw bytes to parse
   --  @param Target_Kind the tag target's object type
   --  @return Ok on success, or an error status on failure.
   function Validate_Tag_Object
     (Data        : Ada.Streams.Stream_Element_Array;
      Target_Kind : out Pack_Object_Kind)
      return CryptoLib.Errors.Status;

   --  Hex-encode a raw object id.
   --  @param Object_ID the raw binary object identifier
   --  @param Hex_Text the hex-encoded id text
   --  @param Last index of the last valid element written
   --  @return Ok on success, or an error status on failure.
   function Encode_Object_ID_Hex
     (Object_ID : Ada.Streams.Stream_Element_Array;
      Hex_Text  : out Ada.Streams.Stream_Element_Array;
      Last      : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   --  Decode a hex object id to its raw bytes.
   --  @param Hex_Text the hex-encoded id text
   --  @param Object_ID the raw binary object identifier
   --  @param Last index of the last valid element written
   --  @return Ok on success, or an error status on failure.
   function Parse_Object_ID_Hex
     (Hex_Text  : Ada.Streams.Stream_Element_Array;
      Object_ID : out Ada.Streams.Stream_Element_Array;
      Last      : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   --  Parse a pack object header, returning its type and uncompressed size.
   --  @param Data the raw bytes to parse
   --  @param Kind the object type
   --  @param Uncompressed_Size the object's uncompressed size in bytes
   --  @param Header_Length the length of the object header in bytes
   --  @return Ok on success, or an error status on failure.
   function Parse_Pack_Object_Header
     (Data              : Ada.Streams.Stream_Element_Array;
      Kind              : out Pack_Object_Kind;
      Uncompressed_Size : out Natural;
      Header_Length     : out Natural)
      return CryptoLib.Errors.Status;

   --  Inflate a pack object's zlib-compressed data to its expected size.
   --  @param Compressed_Data the zlib-compressed object bytes
   --  @param Expected_Uncompressed_Size the expected uncompressed size in bytes
   --  @param Inflated_Data the inflated object bytes
   --  @param Last index of the last valid element written
   --  @return Ok on success, or an error status on failure.
   function Inflate_Pack_Object_Data
     (Compressed_Data            : Ada.Streams.Stream_Element_Array;
      Expected_Uncompressed_Size : Natural;
      Inflated_Data              : out Ada.Streams.Stream_Element_Array;
      Last                       : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   --  Inflate a pack object's zlib-compressed data to its expected size. Also report the number of compressed bytes
   --  consumed.
   --  @param Compressed_Data the zlib-compressed object bytes
   --  @param Expected_Uncompressed_Size the expected uncompressed size in bytes
   --  @param Inflated_Data the inflated object bytes
   --  @param Last index of the last valid element written
   --  @param Consumed_Length the number of compressed bytes consumed
   --  @return Ok on success, or an error status on failure.
   function Inflate_Pack_Object_Data
     (Compressed_Data            : Ada.Streams.Stream_Element_Array;
      Expected_Uncompressed_Size : Natural;
      Inflated_Data              : out Ada.Streams.Stream_Element_Array;
      Last                       : out Ada.Streams.Stream_Element_Offset;
      Consumed_Length            : out Natural)
      return CryptoLib.Errors.Status;

   --  Parse and inflate the pack object at a byte offset in a packfile.
   --  @param Pack_Data the packfile bytes
   --  @param Pack_Offset byte offset of the object within the packfile
   --  @param Kind the object type
   --  @param Uncompressed_Size the object's uncompressed size in bytes
   --  @param Header_Length the length of the object header in bytes
   --  @param Payload_Offset byte offset of the object payload within the packfile
   --  @param Inflated_Data the inflated object bytes
   --  @param Last index of the last valid element written
   --  @return Ok on success, or an error status on failure.
   function Inflate_Pack_Object_At_Offset
     (Pack_Data         : Ada.Streams.Stream_Element_Array;
      Pack_Offset       : Natural;
      Kind              : out Pack_Object_Kind;
      Uncompressed_Size : out Natural;
      Header_Length     : out Natural;
      Payload_Offset    : out Natural;
      Inflated_Data     : out Ada.Streams.Stream_Element_Array;
      Last              : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   --  Parse and inflate the pack object at a byte offset in a packfile. Also report the offset of the next object.
   --  @param Pack_Data the packfile bytes
   --  @param Pack_Offset byte offset of the object within the packfile
   --  @param Kind the object type
   --  @param Uncompressed_Size the object's uncompressed size in bytes
   --  @param Header_Length the length of the object header in bytes
   --  @param Payload_Offset byte offset of the object payload within the packfile
   --  @param Inflated_Data the inflated object bytes
   --  @param Last index of the last valid element written
   --  @param Next_Offset byte offset of the following entry
   --  @return Ok on success, or an error status on failure.
   function Inflate_Pack_Object_At_Offset
     (Pack_Data         : Ada.Streams.Stream_Element_Array;
      Pack_Offset       : Natural;
      Kind              : out Pack_Object_Kind;
      Uncompressed_Size : out Natural;
      Header_Length     : out Natural;
      Payload_Offset    : out Natural;
      Inflated_Data     : out Ada.Streams.Stream_Element_Array;
      Last              : out Ada.Streams.Stream_Element_Offset;
      Next_Offset       : out Natural)
      return CryptoLib.Errors.Status;

   --  Walk and validate the sequence of objects in a packfile.
   --  @param Pack_Data the packfile bytes
   --  @param Scratch scratch buffer for object reconstruction
   --  @param Object_Count the number of objects
   --  @param Trailer_Offset byte offset of the packfile trailer
   --  @return Ok on success, or an error status on failure.
   function Validate_Pack_Object_Sequence
     (Pack_Data      : Ada.Streams.Stream_Element_Array;
      Scratch        : out Ada.Streams.Stream_Element_Array;
      Object_Count   : out Natural;
      Trailer_Offset : out Natural)
      return CryptoLib.Errors.Status;

   --  Apply a single pack delta to a base to reconstruct an object.
   --  @param Base_Data scratch buffer for delta base objects
   --  @param Delta_Data scratch buffer for delta objects
   --  @param Result the classified merge result
   --  @param Last index of the last valid element written
   --  @return Ok on success, or an error status on failure.
   function Apply_Pack_Delta
     (Base_Data  : Ada.Streams.Stream_Element_Array;
      Delta_Data : Ada.Streams.Stream_Element_Array;
      Result     : out Ada.Streams.Stream_Element_Array;
      Last       : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   --  Apply a chain of pack deltas to a base to reconstruct an object.
   --  @param Base_Data scratch buffer for delta base objects
   --  @param Delta_Data scratch buffer for delta objects
   --  @param Deltas the spans of the delta chain to apply
   --  @param Workspace scratch buffer for delta-chain reconstruction
   --  @param Result the classified merge result
   --  @param Last index of the last valid element written
   --  @return Ok on success, or an error status on failure.
   function Apply_Pack_Delta_Chain
     (Base_Data  : Ada.Streams.Stream_Element_Array;
      Delta_Data : Ada.Streams.Stream_Element_Array;
      Deltas     : Pack_Delta_Span_Array;
      Workspace  : out Ada.Streams.Stream_Element_Array;
      Result     : out Ada.Streams.Stream_Element_Array;
      Last       : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   --  Parse the base object id of a REF_DELTA pack object.
   --  @param Data the raw bytes to parse
   --  @param Base_Object_ID the parsed base object id
   --  @param Base_Last index of the last valid element of the base id
   --  @param Consumed_Length the number of compressed bytes consumed
   --  @return Ok on success, or an error status on failure.
   function Parse_Pack_REF_Delta_Base
     (Data            : Ada.Streams.Stream_Element_Array;
      Base_Object_ID  : out Ada.Streams.Stream_Element_Array;
      Base_Last       : out Ada.Streams.Stream_Element_Offset;
      Consumed_Length : out Natural)
      return CryptoLib.Errors.Status;

   --  Parse the negative base offset of an OFS_DELTA pack object.
   --  @param Data the raw bytes to parse
   --  @param Negative_Offset the negative offset back to the base object
   --  @param Consumed_Length the number of compressed bytes consumed
   --  @return Ok on success, or an error status on failure.
   function Parse_Pack_OFS_Delta_Base
     (Data            : Ada.Streams.Stream_Element_Array;
      Negative_Offset : out Natural;
      Consumed_Length : out Natural)
      return CryptoLib.Errors.Status;

   --  Report whether a string is a valid hex object id.
   --  @param Text the text to validate
   --  @return True when the text is a valid object id.
   function Valid_Object_ID (Text : String) return Boolean;

   --  Report whether a string is a valid ref name.
   --  @param Name the entry name
   --  @return True when the name is a valid ref name.
   function Valid_Ref_Name (Name : String) return Boolean;

   --  Report whether a string is a valid fetch refspec.
   --  @param RefSpec the refspec to set
   --  @return True when the refspec is a valid fetch refspec.
   function Valid_Fetch_Refspec (RefSpec : String) return Boolean;

   --  Report whether a string is a valid push refspec.
   --  @param RefSpec the refspec to set
   --  @return True when the refspec is a valid push refspec.
   function Valid_Push_Refspec (RefSpec : String) return Boolean;

   --  Report whether a string is a valid push.default mode.
   --  @param Mode the mode string to set
   --  @return True when the mode is a valid push.default value.
   function Valid_Push_Default_Mode (Mode : String) return Boolean;

   --  Report whether a string is a valid pull.rebase mode.
   --  @param Mode the mode string to set
   --  @return True when the mode is a valid pull.rebase value.
   function Valid_Pull_Rebase_Mode (Mode : String) return Boolean;

   --  Classify a ref name as HEAD, branch, tag, remote, or other.
   --  @param Name the entry name
   --  @param Kind the object type
   --  @return Ok on success, or an error status on failure.
   function Classify_Ref_Name
     (Name : String;
      Kind : out Ref_Name_Kind)
      return CryptoLib.Errors.Status;

   --  Parse a side-band packet, classifying it as data, progress, or error.
   --  @param Data the raw bytes to parse
   --  @param Kind the object type
   --  @param Payload the copied payload bytes
   --  @param Last index of the last valid element written
   --  @return Ok on success, or an error status on failure.
   function Parse_Side_Band_Packet
     (Data    : Ada.Streams.Stream_Element_Array;
      Kind    : out Side_Band_Kind;
      Payload : out Ada.Streams.Stream_Element_Array;
      Last    : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   --  Validate a side-band stream and summarize it.
   --  @param Data the raw bytes to parse
   --  @param Summary the computed summary record
   --  @return Ok on success, or an error status on failure.
   function Validate_Side_Band_Stream
     (Data    : Ada.Streams.Stream_Element_Array;
      Summary : out Side_Band_Stream_Summary)
      return CryptoLib.Errors.Status;

   --  Parse a receive-pack status report packet.
   --  @param Data the raw bytes to parse
   --  @param Kind the object type
   --  @param Ref_Name the ref name
   --  @param Ref_Last index of the last valid element of the ref name
   --  @param Message the message text
   --  @param Message_Last index of the last valid element of the message
   --  @return Ok on success, or an error status on failure.
   function Parse_Status_Report_Packet
     (Data         : Ada.Streams.Stream_Element_Array;
      Kind         : out Status_Report_Kind;
      Ref_Name     : out Ada.Streams.Stream_Element_Array;
      Ref_Last     : out Ada.Streams.Stream_Element_Offset;
      Message      : out Ada.Streams.Stream_Element_Array;
      Message_Last : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   --  Parse a capability token into its name and optional value.
   --  @param Token the capability token bytes
   --  @param Name the parsed name bytes
   --  @param Name_Last index of the last valid element of the name
   --  @param Value the value bytes
   --  @param Value_Last index of the last valid element of the value
   --  @param Has_Value set True when the token carries a value
   --  @return Ok on success, or an error status on failure.
   function Parse_Capability_Token
     (Token      : Ada.Streams.Stream_Element_Array;
      Name       : out Ada.Streams.Stream_Element_Array;
      Name_Last  : out Ada.Streams.Stream_Element_Offset;
      Value      : out Ada.Streams.Stream_Element_Array;
      Value_Last : out Ada.Streams.Stream_Element_Offset;
      Has_Value  : out Boolean)
      return CryptoLib.Errors.Status;

   --  Copy the next capability token from a space-separated list.
   --  @param List the capability list bytes
   --  @param Cursor the pkt-line iteration cursor
   --  @param Token the copied capability token bytes
   --  @param Last index of the last valid element written
   --  @param Has_Token set True when a token was produced
   --  @return Ok on success, or an error status on failure.
   function Copy_Next_Capability_Token
     (List      : Ada.Streams.Stream_Element_Array;
      Cursor    : in out Ada.Streams.Stream_Element_Offset;
      Token     : out Ada.Streams.Stream_Element_Array;
      Last      : out Ada.Streams.Stream_Element_Offset;
      Has_Token : out Boolean)
      return CryptoLib.Errors.Status;
end SSH_Lib.Git;
