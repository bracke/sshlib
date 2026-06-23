with Ada.Streams;
with Ada.Strings.Unbounded;
with CryptoLib.Errors;
with SSH_Lib.Protocol.Buffers;

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

   function Valid_Worktree_Path (Path : String) return Boolean;

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
   function Build_Upload_Pack_Command
     (Repository_Path : String;
      Command         : out Ada.Strings.Unbounded.Unbounded_String)
      return CryptoLib.Errors.Status;

   function Build_Receive_Pack_Command
     (Repository_Path : String;
      Command         : out Ada.Strings.Unbounded.Unbounded_String)
      return CryptoLib.Errors.Status;

   --  Convenience wrappers around the status-returning builders.
   --  They raise Constraint_Error for invalid repository paths.
   function Upload_Pack_Command (Repository_Path : String) return String;

   function Receive_Pack_Command (Repository_Path : String) return String;

   function Initialize_Repository_State
     (Repository_Root : String)
      return CryptoLib.Errors.Status;

   function Write_Empty_Index
     (Repository_Root : String)
      return CryptoLib.Errors.Status;

   function Read_Index_Header
     (Repository_Root : String;
      Version         : out Natural;
      Entry_Count     : out Natural)
      return CryptoLib.Errors.Status;

   function Build_Index_Entry
     (File_Mode  : Natural;
      Path       : String;
      Object_ID  : Ada.Streams.Stream_Element_Array;
      File_Size  : Natural;
      Entry_Data : out Ada.Streams.Stream_Element_Array;
      Last       : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   function Write_Index
     (Repository_Root : String;
      Entry_Data      : Ada.Streams.Stream_Element_Array;
      Entry_Count     : Natural)
      return CryptoLib.Errors.Status;

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

   function Find_Index_Entry
     (Repository_Root : String;
      Path            : Ada.Streams.Stream_Element_Array;
      File_Mode       : out Natural;
      Object_ID       : out Ada.Streams.Stream_Element_Array;
      Object_Last     : out Ada.Streams.Stream_Element_Offset;
      File_Size       : out Natural;
      Found           : out Boolean)
      return CryptoLib.Errors.Status;

   function Read_Index_Path_Object
     (Repository_Root : String;
      Path            : Ada.Streams.Stream_Element_Array;
      Kind            : out Pack_Object_Kind;
      Data            : out Ada.Streams.Stream_Element_Array;
      Last            : out Ada.Streams.Stream_Element_Offset;
      Found           : out Boolean)
      return CryptoLib.Errors.Status;

   function List_Index_Paths
     (Repository_Root : String;
      Paths           : out Ada.Streams.Stream_Element_Array;
      Path_Lasts      : out Index_Path_Last_Array;
      Path_Count      : out Natural)
      return CryptoLib.Errors.Status;

   function Write_Worktree_File
     (Repository_Root : String;
      Path            : String;
      Data            : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   function Read_Worktree_File
     (Repository_Root : String;
      Path            : String;
      Data            : out Ada.Streams.Stream_Element_Array;
      Last            : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   function Worktree_File_Exists
     (Repository_Root : String;
      Path            : String;
      Found           : out Boolean)
      return CryptoLib.Errors.Status;

   function Delete_Worktree_File
     (Repository_Root : String;
      Path            : String;
      Removed         : out Boolean)
      return CryptoLib.Errors.Status;

   function Checkout_Index_Path
     (Repository_Root : String;
      Path            : Ada.Streams.Stream_Element_Array;
      Written         : out Boolean)
      return CryptoLib.Errors.Status;

   function Checkout_Index_All
     (Repository_Root : String;
      Written_Count   : out Natural)
      return CryptoLib.Errors.Status;

   function Compare_Index_Path_To_Worktree
     (Repository_Root : String;
      Path            : Ada.Streams.Stream_Element_Array;
      Path_Status     : out Worktree_Path_Status)
      return CryptoLib.Errors.Status;

   function Summarize_Index_Worktree
     (Repository_Root  : String;
      Missing_Count    : out Natural;
      Unchanged_Count  : out Natural;
      Modified_Count   : out Natural)
      return CryptoLib.Errors.Status;

   function Classify_Worktree_Path
     (Repository_Root : String;
      Path            : String;
      Path_Status     : out Porcelain_Path_Status)
      return CryptoLib.Errors.Status;

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

   function List_Worktree_Files
     (Repository_Root : String;
      Paths           : out Ada.Streams.Stream_Element_Array;
      Path_Lasts      : out Index_Path_Last_Array;
      Path_Count      : out Natural)
      return CryptoLib.Errors.Status;

   function Worktree_Path_Ignored
     (Repository_Root : String;
      Path            : String;
      Ignored         : out Boolean)
      return CryptoLib.Errors.Status;

   function Summarize_Worktree_Status
     (Repository_Root  : String;
      Untracked_Count  : out Natural;
      Missing_Count    : out Natural;
      Unchanged_Count  : out Natural;
      Modified_Count   : out Natural)
      return CryptoLib.Errors.Status;

   function Summarize_Worktree_Status_Matching
     (Repository_Root  : String;
      Pathspec         : String;
      Untracked_Count  : out Natural;
      Missing_Count    : out Natural;
      Unchanged_Count  : out Natural;
      Modified_Count   : out Natural)
      return CryptoLib.Errors.Status;

   function Summarize_Worktree_Status_With_Ignored
     (Repository_Root  : String;
      Untracked_Count  : out Natural;
      Ignored_Count    : out Natural;
      Missing_Count    : out Natural;
      Unchanged_Count  : out Natural;
      Modified_Count   : out Natural)
      return CryptoLib.Errors.Status;

   function Evaluate_Porcelain_Status
     (Repository_Root  : String;
      Pathspec         : String;
      Include_Ignored  : Boolean;
      Summary          : out Porcelain_Status_Summary)
      return CryptoLib.Errors.Status;

   function Read_Porcelain_Index_Worktree_Model
     (Repository_Root  : String;
      Pathspec         : String;
      Include_Ignored  : Boolean;
      Model            : out Porcelain_Index_Worktree_Model)
      return CryptoLib.Errors.Status;

   function Detect_Worktree_Rename
     (Repository_Root : String;
      Old_Path        : out Ada.Streams.Stream_Element_Array;
      Old_Last        : out Ada.Streams.Stream_Element_Offset;
      New_Path        : out Ada.Streams.Stream_Element_Array;
      New_Last        : out Ada.Streams.Stream_Element_Offset;
      Found           : out Boolean)
      return CryptoLib.Errors.Status;

   function Detect_Worktree_Copy
     (Repository_Root : String;
      Source_Path     : out Ada.Streams.Stream_Element_Array;
      Source_Last     : out Ada.Streams.Stream_Element_Offset;
      Copy_Path       : out Ada.Streams.Stream_Element_Array;
      Copy_Last       : out Ada.Streams.Stream_Element_Offset;
      Found           : out Boolean)
      return CryptoLib.Errors.Status;

   function Clean_Worktree_Not_In_Index
     (Repository_Root : String;
      Removed_Count   : out Natural)
      return CryptoLib.Errors.Status;

   function Stage_Worktree_File
     (Repository_Root : String;
      Path            : String;
      Object_ID_Hex   : out Ada.Streams.Stream_Element_Array;
      Last            : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   function Remove_Index_Path
     (Repository_Root : String;
      Path            : String;
      Removed         : out Boolean)
      return CryptoLib.Errors.Status;

   function Reset_Index_To_Commit_Root
     (Repository_Root : String;
      Commit_ID_Hex   : Ada.Streams.Stream_Element_Array;
      Entry_Count     : out Natural)
      return CryptoLib.Errors.Status;

   function Checkout_Branch
     (Repository_Root : String;
      Branch_Name     : String;
      Written_Count   : out Natural)
      return CryptoLib.Errors.Status;

   function Is_Ancestor_First_Parent
     (Repository_Root      : String;
      Ancestor_Commit_Hex  : Ada.Streams.Stream_Element_Array;
      Descendant_Commit_Hex : Ada.Streams.Stream_Element_Array;
      Is_Ancestor          : out Boolean)
      return CryptoLib.Errors.Status;

   function Fast_Forward_Branch
     (Repository_Root : String;
      Branch_Name     : String;
      New_Commit_Hex  : Ada.Streams.Stream_Element_Array;
      Updated         : out Boolean)
      return CryptoLib.Errors.Status;

   function Apply_Push_Branch_Update
     (Repository_Root        : String;
      Branch_Name            : String;
      Expected_Old_Hex       : Ada.Streams.Stream_Element_Array;
      New_Commit_Hex         : Ada.Streams.Stream_Element_Array;
      Allow_Non_Fast_Forward : Boolean;
      Updated                : out Boolean)
      return CryptoLib.Errors.Status;

   function Commit_Index_To_Branch
     (Repository_Root : String;
      Branch_Name     : String;
      Author_Line     : String;
      Committer_Line  : String;
      Message         : String;
      Commit_ID_Hex   : out Ada.Streams.Stream_Element_Array;
      Last            : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   function Store_Loose_Object
     (Repository_Root : String;
      Kind            : Pack_Object_Kind;
      Data            : Ada.Streams.Stream_Element_Array;
      Object_ID_Hex   : out Ada.Streams.Stream_Element_Array;
      Last            : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   function Store_Loose_Object_Validated
     (Repository_Root : String;
      Kind            : Pack_Object_Kind;
      Data            : Ada.Streams.Stream_Element_Array;
      Object_ID_Hex   : out Ada.Streams.Stream_Element_Array;
      Last            : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   function Delete_Loose_Object
     (Repository_Root : String;
      Object_ID_Hex   : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   function Store_Pack_File
     (Repository_Root    : String;
      Pack_Data          : Ada.Streams.Stream_Element_Array;
      Pack_Checksum_Hex  : out Ada.Streams.Stream_Element_Array;
      Last               : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   function Read_Pack_File
     (Repository_Root    : String;
      Pack_Checksum_Hex  : Ada.Streams.Stream_Element_Array;
      Pack_Data          : out Ada.Streams.Stream_Element_Array;
      Last               : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   function Delete_Pack_File
     (Repository_Root    : String;
      Pack_Checksum_Hex  : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   function Store_Pack_Index
     (Repository_Root    : String;
      Pack_Checksum_Hex  : Ada.Streams.Stream_Element_Array;
      Index_Data         : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   function Read_Pack_Index
     (Repository_Root    : String;
      Pack_Checksum_Hex  : Ada.Streams.Stream_Element_Array;
      Index_Data         : out Ada.Streams.Stream_Element_Array;
      Last               : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   function Delete_Pack_Index
     (Repository_Root    : String;
      Pack_Checksum_Hex  : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   function Delete_Stored_Pack
     (Repository_Root    : String;
      Pack_Checksum_Hex  : Ada.Streams.Stream_Element_Array;
      Deleted_Pack_File  : out Boolean;
      Deleted_Pack_Index : out Boolean)
      return CryptoLib.Errors.Status;

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

   function List_Pack_Index_Checksums
     (Repository_Root    : String;
      Pack_Checksums_Hex : out Ada.Streams.Stream_Element_Array;
      Last               : out Ada.Streams.Stream_Element_Offset;
      Count              : out Natural)
      return CryptoLib.Errors.Status;

   function List_Loose_Object_IDs
     (Repository_Root : String;
      Object_IDs_Hex  : out Object_ID_Hex_Array;
      Count           : out Natural)
      return CryptoLib.Errors.Status;

   function List_Packed_Object_IDs
     (Repository_Root    : String;
      Pack_Checksum_Hex  : Ada.Streams.Stream_Element_Array;
      Index_Data         : out Ada.Streams.Stream_Element_Array;
      Index_Last         : out Ada.Streams.Stream_Element_Offset;
      Object_IDs_Hex     : out Object_ID_Hex_Array;
      Count              : out Natural)
      return CryptoLib.Errors.Status;

   function List_Stored_Object_IDs
     (Repository_Root       : String;
      Pack_Checksums_Hex    : out Ada.Streams.Stream_Element_Array;
      Pack_Checksums_Last   : out Ada.Streams.Stream_Element_Offset;
      Index_Data            : out Ada.Streams.Stream_Element_Array;
      Index_Last            : out Ada.Streams.Stream_Element_Offset;
      Object_IDs_Hex        : out Object_ID_Hex_Array;
      Count                 : out Natural)
      return CryptoLib.Errors.Status;

   function Summarize_Repository_Database
     (Repository_Root : String;
      Summary         : out Repository_Database_Summary)
      return CryptoLib.Errors.Status;

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

   function List_Tree_Entries_Hex
     (Tree_Data      : Ada.Streams.Stream_Element_Array;
      Names          : out Ada.Streams.Stream_Element_Array;
      Name_Lasts     : out Tree_Entry_Name_Last_Array;
      Modes          : out Tree_Entry_Mode_Array;
      Object_IDs_Hex : out Object_ID_Hex_Array;
      Count          : out Natural)
      return CryptoLib.Errors.Status;

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

   function List_Tree_Paths_Hex
     (Repository_Root : String;
      Root_Tree_ID_Hex : Ada.Streams.Stream_Element_Array;
      Paths           : out Ada.Streams.Stream_Element_Array;
      Path_Lasts      : out Index_Path_Last_Array;
      Modes           : out Tree_Entry_Mode_Array;
      Object_IDs_Hex  : out Object_ID_Hex_Array;
      Count           : out Natural)
      return CryptoLib.Errors.Status;

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

   function List_Commit_Tree_Paths_Hex
     (Repository_Root : String;
      Commit_ID_Hex   : Ada.Streams.Stream_Element_Array;
      Paths           : out Ada.Streams.Stream_Element_Array;
      Path_Lasts      : out Index_Path_Last_Array;
      Modes           : out Tree_Entry_Mode_Array;
      Object_IDs_Hex  : out Object_ID_Hex_Array;
      Count           : out Natural)
      return CryptoLib.Errors.Status;

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

   function List_Ref_Commitish_Tree_Paths_Hex
     (Repository_Root : String;
      Ref_Name        : String;
      Paths           : out Ada.Streams.Stream_Element_Array;
      Path_Lasts      : out Index_Path_Last_Array;
      Modes           : out Tree_Entry_Mode_Array;
      Object_IDs_Hex  : out Object_ID_Hex_Array;
      Count           : out Natural)
      return CryptoLib.Errors.Status;

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

   function List_HEAD_Tree_Paths_Hex
     (Repository_Root : String;
      Paths           : out Ada.Streams.Stream_Element_Array;
      Path_Lasts      : out Index_Path_Last_Array;
      Modes           : out Tree_Entry_Mode_Array;
      Object_IDs_Hex  : out Object_ID_Hex_Array;
      Count           : out Natural)
      return CryptoLib.Errors.Status;

   function List_HEAD_Tree_Paths_Matching_Hex
     (Repository_Root : String;
      Pathspec        : String;
      Paths           : out Ada.Streams.Stream_Element_Array;
      Path_Lasts      : out Index_Path_Last_Array;
      Modes           : out Tree_Entry_Mode_Array;
      Object_IDs_Hex  : out Object_ID_Hex_Array;
      Count           : out Natural)
      return CryptoLib.Errors.Status;

   function List_Branch_Tree_Paths_Hex
     (Repository_Root : String;
      Branch_Name     : String;
      Paths           : out Ada.Streams.Stream_Element_Array;
      Path_Lasts      : out Index_Path_Last_Array;
      Modes           : out Tree_Entry_Mode_Array;
      Object_IDs_Hex  : out Object_ID_Hex_Array;
      Count           : out Natural)
      return CryptoLib.Errors.Status;

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

   function List_Tag_Tree_Paths_Hex
     (Repository_Root : String;
      Tag_Name        : String;
      Paths           : out Ada.Streams.Stream_Element_Array;
      Path_Lasts      : out Index_Path_Last_Array;
      Modes           : out Tree_Entry_Mode_Array;
      Object_IDs_Hex  : out Object_ID_Hex_Array;
      Count           : out Natural)
      return CryptoLib.Errors.Status;

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

   function Read_Loose_Object
     (Repository_Root : String;
      Object_ID_Hex   : Ada.Streams.Stream_Element_Array;
      Kind            : out Pack_Object_Kind;
      Data            : out Ada.Streams.Stream_Element_Array;
      Last            : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   function Read_Loose_Object_Validated
     (Repository_Root : String;
      Object_ID_Hex   : Ada.Streams.Stream_Element_Array;
      Kind            : out Pack_Object_Kind;
      Data            : out Ada.Streams.Stream_Element_Array;
      Last            : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   function Write_Direct_Ref
     (Repository_Root : String;
      Ref_Name        : String;
      Object_ID_Hex   : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   function Read_Direct_Ref
     (Repository_Root : String;
      Ref_Name        : String;
      Object_ID_Hex   : out Ada.Streams.Stream_Element_Array;
      Last            : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   function Delete_Direct_Ref
     (Repository_Root : String;
      Ref_Name        : String)
      return CryptoLib.Errors.Status;

   function Write_Symbolic_Ref
     (Repository_Root  : String;
      Ref_Name         : String;
      Target_Ref_Name  : String)
      return CryptoLib.Errors.Status;

   function Read_Symbolic_Ref
     (Repository_Root  : String;
      Ref_Name         : String;
      Target_Ref_Name  : out Ada.Streams.Stream_Element_Array;
      Last             : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   function Delete_Symbolic_Ref
     (Repository_Root  : String;
      Ref_Name         : String;
      Target_Ref_Name  : out Ada.Streams.Stream_Element_Array;
      Last             : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   function Write_Packed_Ref
     (Repository_Root : String;
      Ref_Name        : String;
      Object_ID_Hex   : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   function Read_Packed_Ref
     (Repository_Root : String;
      Ref_Name        : String;
      Object_ID_Hex   : out Ada.Streams.Stream_Element_Array;
      Last            : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   function Delete_Packed_Ref
     (Repository_Root : String;
      Ref_Name        : String)
      return CryptoLib.Errors.Status;

   function List_Refs
     (Repository_Root : String;
      Names           : out Ada.Streams.Stream_Element_Array;
      Name_Lasts      : out Ref_Name_Last_Array;
      Object_IDs_Hex  : out Object_ID_Hex_Array;
      Count           : out Natural)
      return CryptoLib.Errors.Status;

   function List_Branches
     (Repository_Root : String;
      Names           : out Ada.Streams.Stream_Element_Array;
      Name_Lasts      : out Ref_Name_Last_Array;
      Object_IDs_Hex  : out Object_ID_Hex_Array;
      Count           : out Natural)
      return CryptoLib.Errors.Status;

   function List_Tag_Refs
     (Repository_Root : String;
      Names           : out Ada.Streams.Stream_Element_Array;
      Name_Lasts      : out Ref_Name_Last_Array;
      Object_IDs_Hex  : out Object_ID_Hex_Array;
      Count           : out Natural)
      return CryptoLib.Errors.Status;

   function List_Remote_Tracking_Branches
     (Repository_Root : String;
      Names           : out Ada.Streams.Stream_Element_Array;
      Name_Lasts      : out Ref_Name_Last_Array;
      Object_IDs_Hex  : out Object_ID_Hex_Array;
      Count           : out Natural)
      return CryptoLib.Errors.Status;

   function Resolve_Ref
     (Repository_Root : String;
      Ref_Name        : String;
      Object_ID_Hex   : out Ada.Streams.Stream_Element_Array;
      Last            : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   function Attach_HEAD
     (Repository_Root : String;
      Target_Ref_Name : String)
      return CryptoLib.Errors.Status;

   function Attach_HEAD_To_Branch
     (Repository_Root : String;
      Branch_Name     : String)
      return CryptoLib.Errors.Status;

   function Detach_HEAD
     (Repository_Root : String;
      Object_ID_Hex   : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   function Resolve_HEAD
     (Repository_Root : String;
      Object_ID_Hex   : out Ada.Streams.Stream_Element_Array;
      Last            : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   function Read_HEAD_Target
     (Repository_Root : String;
      Target_Ref_Name : out Ada.Streams.Stream_Element_Array;
      Last            : out Ada.Streams.Stream_Element_Offset;
      Attached        : out Boolean)
      return CryptoLib.Errors.Status;

   function Read_Current_Branch
     (Repository_Root : String;
      Branch_Name     : out Ada.Streams.Stream_Element_Array;
      Last            : out Ada.Streams.Stream_Element_Offset;
      Found           : out Boolean)
      return CryptoLib.Errors.Status;

   function Write_Branch
     (Repository_Root : String;
      Branch_Name     : String;
      Object_ID_Hex   : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   function Create_Branch_From_HEAD
     (Repository_Root : String;
      Branch_Name     : String)
      return CryptoLib.Errors.Status;

   function Read_Branch
     (Repository_Root : String;
      Branch_Name     : String;
      Object_ID_Hex   : out Ada.Streams.Stream_Element_Array;
      Last            : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   function Resolve_Branch
     (Repository_Root : String;
      Branch_Name     : String;
      Object_ID_Hex   : out Ada.Streams.Stream_Element_Array;
      Last            : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   function Delete_Branch
     (Repository_Root : String;
      Branch_Name     : String)
      return CryptoLib.Errors.Status;

   function Branch_Exists
     (Repository_Root : String;
      Branch_Name     : String;
      Object_ID_Hex   : out Ada.Streams.Stream_Element_Array;
      Last            : out Ada.Streams.Stream_Element_Offset;
      Found           : out Boolean)
      return CryptoLib.Errors.Status;

   function Write_Remote_Tracking_Branch
     (Repository_Root : String;
      Branch_Name     : String;
      Object_ID_Hex   : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   function Create_Remote_Tracking_Branch_From_HEAD
     (Repository_Root : String;
      Branch_Name     : String)
      return CryptoLib.Errors.Status;

   function Read_Remote_Tracking_Branch
     (Repository_Root : String;
      Branch_Name     : String;
      Object_ID_Hex   : out Ada.Streams.Stream_Element_Array;
      Last            : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   function Resolve_Remote_Tracking_Branch
     (Repository_Root : String;
      Branch_Name     : String;
      Object_ID_Hex   : out Ada.Streams.Stream_Element_Array;
      Last            : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   function Delete_Remote_Tracking_Branch
     (Repository_Root : String;
      Branch_Name     : String)
      return CryptoLib.Errors.Status;

   function Remote_Tracking_Branch_Exists
     (Repository_Root : String;
      Branch_Name     : String;
      Object_ID_Hex   : out Ada.Streams.Stream_Element_Array;
      Last            : out Ada.Streams.Stream_Element_Offset;
      Found           : out Boolean)
      return CryptoLib.Errors.Status;

   function Apply_Fetch_Ref_Update
     (Repository_Root        : String;
      Remote_Name            : String;
      Branch_Name            : String;
      New_Commit_Hex         : Ada.Streams.Stream_Element_Array;
      Allow_Non_Fast_Forward : Boolean;
      Updated                : out Boolean)
      return CryptoLib.Errors.Status;

   function Write_Tag_Ref
     (Repository_Root : String;
      Tag_Name        : String;
      Object_ID_Hex   : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   function Create_Tag_Ref_From_HEAD
     (Repository_Root : String;
      Tag_Name        : String)
      return CryptoLib.Errors.Status;

   function Read_Tag_Ref
     (Repository_Root : String;
      Tag_Name        : String;
      Object_ID_Hex   : out Ada.Streams.Stream_Element_Array;
      Last            : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   function Resolve_Tag_Ref
     (Repository_Root : String;
      Tag_Name        : String;
      Object_ID_Hex   : out Ada.Streams.Stream_Element_Array;
      Last            : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   function Delete_Tag_Ref
     (Repository_Root : String;
      Tag_Name        : String)
      return CryptoLib.Errors.Status;

   function Tag_Ref_Exists
     (Repository_Root : String;
      Tag_Name        : String;
      Object_ID_Hex   : out Ada.Streams.Stream_Element_Array;
      Last            : out Ada.Streams.Stream_Element_Offset;
      Found           : out Boolean)
      return CryptoLib.Errors.Status;

   function Append_Reflog_Entry
     (Repository_Root : String;
      Ref_Name        : String;
      Old_ID_Hex      : Ada.Streams.Stream_Element_Array;
      New_ID_Hex      : Ada.Streams.Stream_Element_Array;
      Actor           : String;
      Message         : String)
      return CryptoLib.Errors.Status;

   function Read_Reflog_Last_Entry
     (Repository_Root : String;
      Ref_Name        : String;
      Line            : out Ada.Streams.Stream_Element_Array;
      Last            : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   function Read_Config_Value
     (Repository_Root : String;
      Section         : String;
      Key             : String;
      Value           : out Ada.Streams.Stream_Element_Array;
      Last            : out Ada.Streams.Stream_Element_Offset;
      Found           : out Boolean)
      return CryptoLib.Errors.Status;

   function Read_Config_Values
     (Repository_Root : String;
      Section         : String;
      Key             : String;
      Values          : out Ada.Streams.Stream_Element_Array;
      Value_Lasts     : out Config_Value_Last_Array;
      Count           : out Natural)
      return CryptoLib.Errors.Status;

   function Write_Config_Value
     (Repository_Root : String;
      Section         : String;
      Key             : String;
      Value           : String)
      return CryptoLib.Errors.Status;

   function Append_Config_Value
     (Repository_Root : String;
      Section         : String;
      Key             : String;
      Value           : String)
      return CryptoLib.Errors.Status;

   function Delete_Config_Value
     (Repository_Root : String;
      Section         : String;
      Key             : String;
      Removed         : out Boolean)
      return CryptoLib.Errors.Status;

   function Write_Remote_URL
     (Repository_Root : String;
      Remote_Name     : String;
      URL             : String)
      return CryptoLib.Errors.Status;

   function Read_Remote_URL
     (Repository_Root : String;
      Remote_Name     : String;
      URL             : out Ada.Streams.Stream_Element_Array;
      Last            : out Ada.Streams.Stream_Element_Offset;
      Found           : out Boolean)
      return CryptoLib.Errors.Status;

   function Delete_Remote_URL
     (Repository_Root : String;
      Remote_Name     : String;
      Removed         : out Boolean)
      return CryptoLib.Errors.Status;

   function Write_Remote_Fetch_Refspec
     (Repository_Root : String;
      Remote_Name     : String;
      RefSpec         : String)
      return CryptoLib.Errors.Status;

   function Read_Remote_Fetch_Refspec
     (Repository_Root : String;
      Remote_Name     : String;
      RefSpec         : out Ada.Streams.Stream_Element_Array;
      Last            : out Ada.Streams.Stream_Element_Offset;
      Found           : out Boolean)
      return CryptoLib.Errors.Status;

   function Append_Remote_Fetch_Refspec
     (Repository_Root : String;
      Remote_Name     : String;
      RefSpec         : String)
      return CryptoLib.Errors.Status;

   function Read_Remote_Fetch_Refspecs
     (Repository_Root : String;
      Remote_Name     : String;
      RefSpecs        : out Ada.Streams.Stream_Element_Array;
      RefSpec_Lasts   : out Config_Value_Last_Array;
      Count           : out Natural)
      return CryptoLib.Errors.Status;

   function Delete_Remote_Fetch_Refspecs
     (Repository_Root : String;
      Remote_Name     : String;
      Removed         : out Boolean)
      return CryptoLib.Errors.Status;

   function Write_Remote_Push_Refspec
     (Repository_Root : String;
      Remote_Name     : String;
      RefSpec         : String)
      return CryptoLib.Errors.Status;

   function Read_Remote_Push_Refspec
     (Repository_Root : String;
      Remote_Name     : String;
      RefSpec         : out Ada.Streams.Stream_Element_Array;
      Last            : out Ada.Streams.Stream_Element_Offset;
      Found           : out Boolean)
      return CryptoLib.Errors.Status;

   function Append_Remote_Push_Refspec
     (Repository_Root : String;
      Remote_Name     : String;
      RefSpec         : String)
      return CryptoLib.Errors.Status;

   function Read_Remote_Push_Refspecs
     (Repository_Root : String;
      Remote_Name     : String;
      RefSpecs        : out Ada.Streams.Stream_Element_Array;
      RefSpec_Lasts   : out Config_Value_Last_Array;
      Count           : out Natural)
      return CryptoLib.Errors.Status;

   function Delete_Remote_Push_Refspecs
     (Repository_Root : String;
      Remote_Name     : String;
      Removed         : out Boolean)
      return CryptoLib.Errors.Status;

   function Write_Credential_Helper
     (Repository_Root : String;
      Helper          : String)
      return CryptoLib.Errors.Status;

   function Read_Credential_Helper
     (Repository_Root : String;
      Helper          : out Ada.Streams.Stream_Element_Array;
      Last            : out Ada.Streams.Stream_Element_Offset;
      Found           : out Boolean)
      return CryptoLib.Errors.Status;

   function Append_Credential_Helper
     (Repository_Root : String;
      Helper          : String)
      return CryptoLib.Errors.Status;

   function Read_Credential_Helpers
     (Repository_Root : String;
      Helpers         : out Ada.Streams.Stream_Element_Array;
      Lasts           : out Config_Value_Last_Array;
      Count           : out Natural)
      return CryptoLib.Errors.Status;

   function Delete_Credential_Helper
     (Repository_Root : String;
      Removed         : out Boolean)
      return CryptoLib.Errors.Status;

   function Write_Credential_Username
     (Repository_Root : String;
      Username        : String)
      return CryptoLib.Errors.Status;

   function Read_Credential_Username
     (Repository_Root : String;
      Username        : out Ada.Streams.Stream_Element_Array;
      Last            : out Ada.Streams.Stream_Element_Offset;
      Found           : out Boolean)
      return CryptoLib.Errors.Status;

   function Delete_Credential_Username
     (Repository_Root : String;
      Removed         : out Boolean)
      return CryptoLib.Errors.Status;

   function Build_Credential_Helper_Request
     (Protocol : String;
      Host     : String;
      Path     : String;
      Username : String;
      Password : String;
      Data     : out Ada.Streams.Stream_Element_Array;
      Last     : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   function Parse_Credential_Helper_Response
     (Data         : Ada.Streams.Stream_Element_Array;
      Username     : out Ada.Streams.Stream_Element_Array;
      Username_Last : out Ada.Streams.Stream_Element_Offset;
      Has_Username : out Boolean;
      Password     : out Ada.Streams.Stream_Element_Array;
      Password_Last : out Ada.Streams.Stream_Element_Offset;
      Has_Password : out Boolean)
      return CryptoLib.Errors.Status;

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

   function Build_Credential_Password_Prompt
     (Protocol : String;
      Host     : String;
      Path     : String;
      Username : String;
      Prompt   : out Ada.Streams.Stream_Element_Array;
      Last     : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   function Prompt_Credential_Password
     (Protocol : String;
      Host     : String;
      Path     : String;
      Username : String;
      Password : out Ada.Streams.Stream_Element_Array;
      Last     : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   function Write_Credential_Store
     (Repository_Root : String;
      Protocol        : String;
      Host            : String;
      Path            : String;
      Username        : String;
      Password        : String)
      return CryptoLib.Errors.Status;

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

   function Delete_Credential_Store
     (Repository_Root : String;
      Protocol        : String;
      Host            : String;
      Path            : String;
      Username        : String;
      Removed         : out Boolean)
      return CryptoLib.Errors.Status;

   procedure Clear_Credential_Data
     (Data : in out Ada.Streams.Stream_Element_Array);

   function Write_Core_Bare
     (Repository_Root : String;
      Is_Bare         : Boolean)
      return CryptoLib.Errors.Status;

   function Read_Core_Bare
     (Repository_Root : String;
      Is_Bare         : out Boolean;
      Found           : out Boolean)
      return CryptoLib.Errors.Status;

   function Delete_Core_Bare
     (Repository_Root : String;
      Removed         : out Boolean)
      return CryptoLib.Errors.Status;

   function Write_Core_Filemode
     (Repository_Root : String;
      Filemode        : Boolean)
      return CryptoLib.Errors.Status;

   function Read_Core_Filemode
     (Repository_Root : String;
      Filemode        : out Boolean;
      Found           : out Boolean)
      return CryptoLib.Errors.Status;

   function Delete_Core_Filemode
     (Repository_Root : String;
      Removed         : out Boolean)
      return CryptoLib.Errors.Status;

   function Write_Core_Log_All_Ref_Updates
     (Repository_Root      : String;
      Log_All_Ref_Updates : Boolean)
      return CryptoLib.Errors.Status;

   function Read_Core_Log_All_Ref_Updates
     (Repository_Root      : String;
      Log_All_Ref_Updates : out Boolean;
      Found                : out Boolean)
      return CryptoLib.Errors.Status;

   function Delete_Core_Log_All_Ref_Updates
     (Repository_Root : String;
      Removed         : out Boolean)
      return CryptoLib.Errors.Status;

   function Write_User_Name
     (Repository_Root : String;
      User_Name       : String)
      return CryptoLib.Errors.Status;

   function Read_User_Name
     (Repository_Root : String;
      User_Name       : out Ada.Streams.Stream_Element_Array;
      Last            : out Ada.Streams.Stream_Element_Offset;
      Found           : out Boolean)
      return CryptoLib.Errors.Status;

   function Delete_User_Name
     (Repository_Root : String;
      Removed         : out Boolean)
      return CryptoLib.Errors.Status;

   function Write_User_Email
     (Repository_Root : String;
      User_Email      : String)
      return CryptoLib.Errors.Status;

   function Read_User_Email
     (Repository_Root : String;
      User_Email      : out Ada.Streams.Stream_Element_Array;
      Last            : out Ada.Streams.Stream_Element_Offset;
      Found           : out Boolean)
      return CryptoLib.Errors.Status;

   function Delete_User_Email
     (Repository_Root : String;
      Removed         : out Boolean)
      return CryptoLib.Errors.Status;

   function Write_Init_Default_Branch
     (Repository_Root : String;
      Branch_Name     : String)
      return CryptoLib.Errors.Status;

   function Read_Init_Default_Branch
     (Repository_Root : String;
      Branch_Name     : out Ada.Streams.Stream_Element_Array;
      Last            : out Ada.Streams.Stream_Element_Offset;
      Found           : out Boolean)
      return CryptoLib.Errors.Status;

   function Delete_Init_Default_Branch
     (Repository_Root : String;
      Removed         : out Boolean)
      return CryptoLib.Errors.Status;

   function Write_Push_Default
     (Repository_Root : String;
      Mode            : String)
      return CryptoLib.Errors.Status;

   function Read_Push_Default
     (Repository_Root : String;
      Mode            : out Ada.Streams.Stream_Element_Array;
      Last            : out Ada.Streams.Stream_Element_Offset;
      Found           : out Boolean)
      return CryptoLib.Errors.Status;

   function Delete_Push_Default
     (Repository_Root : String;
      Removed         : out Boolean)
      return CryptoLib.Errors.Status;

   function Write_Pull_Rebase
     (Repository_Root : String;
      Mode            : String)
      return CryptoLib.Errors.Status;

   function Read_Pull_Rebase
     (Repository_Root : String;
      Mode            : out Ada.Streams.Stream_Element_Array;
      Last            : out Ada.Streams.Stream_Element_Offset;
      Found           : out Boolean)
      return CryptoLib.Errors.Status;

   function Delete_Pull_Rebase
     (Repository_Root : String;
      Removed         : out Boolean)
      return CryptoLib.Errors.Status;

   function Write_Branch_Upstream
     (Repository_Root : String;
      Branch_Name     : String;
      Remote_Name     : String;
      Merge_Ref_Name  : String)
      return CryptoLib.Errors.Status;

   function Read_Branch_Upstream
     (Repository_Root : String;
      Branch_Name     : String;
      Remote_Name     : out Ada.Streams.Stream_Element_Array;
      Remote_Last     : out Ada.Streams.Stream_Element_Offset;
      Merge_Ref_Name  : out Ada.Streams.Stream_Element_Array;
      Merge_Last      : out Ada.Streams.Stream_Element_Offset;
      Found           : out Boolean)
      return CryptoLib.Errors.Status;

   function Delete_Branch_Upstream
     (Repository_Root : String;
      Branch_Name     : String;
      Removed         : out Boolean)
      return CryptoLib.Errors.Status;

   function Ref_Exists
     (Repository_Root : String;
      Ref_Name        : String;
      Object_ID_Hex   : out Ada.Streams.Stream_Element_Array;
      Last            : out Ada.Streams.Stream_Element_Offset;
      Found           : out Boolean)
      return CryptoLib.Errors.Status;

   function Write_Direct_Ref_Atomic
     (Repository_Root : String;
      Ref_Name        : String;
      Object_ID_Hex   : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   function Compare_And_Swap_Direct_Ref
     (Repository_Root        : String;
      Ref_Name               : String;
      Expected_Object_ID_Hex : Ada.Streams.Stream_Element_Array;
      New_Object_ID_Hex      : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   function Delete_Direct_Ref_Atomic
     (Repository_Root : String;
      Ref_Name        : String)
      return CryptoLib.Errors.Status;

   function Compare_And_Delete_Direct_Ref
     (Repository_Root        : String;
      Ref_Name               : String;
      Expected_Object_ID_Hex : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   function Parse_Pkt_Line_Header
     (Data          : Ada.Streams.Stream_Element_Array;
      Kind          : out Pkt_Line_Kind;
      Packet_Length : out Natural)
      return CryptoLib.Errors.Status;

   function Copy_Pkt_Line_Payload
     (Data    : Ada.Streams.Stream_Element_Array;
      Payload : out Ada.Streams.Stream_Element_Array;
      Last    : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   procedure Reset_Pkt_Line_Cursor
     (Data   : Ada.Streams.Stream_Element_Array;
      Cursor : out Pkt_Line_Cursor);

   function Next_Pkt_Line
     (Data          : Ada.Streams.Stream_Element_Array;
      Cursor        : in out Pkt_Line_Cursor;
      Kind          : out Pkt_Line_Kind;
      Packet_First  : out Ada.Streams.Stream_Element_Offset;
      Packet_Last   : out Ada.Streams.Stream_Element_Offset;
      Payload_First : out Ada.Streams.Stream_Element_Offset;
      Payload_Last  : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   function Pkt_Line_Cursor_Done
     (Cursor : Pkt_Line_Cursor)
      return Boolean;

   function Encode_Pkt_Line
     (Payload : Ada.Streams.Stream_Element_Array)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;

   function Encode_Pkt_Flush
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;

   function Encode_Pkt_Delimiter
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;

   function Encode_Pkt_Response_End
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;

   function Encode_Upload_Pack_Want_Line
     (Object_ID_Hex : Ada.Streams.Stream_Element_Array;
      Capabilities  : Ada.Streams.Stream_Element_Array)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;

   function Encode_Upload_Pack_Have_Line
     (Object_ID_Hex : Ada.Streams.Stream_Element_Array)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;

   function Encode_Upload_Pack_Done_Line
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;

   function Encode_Upload_Pack_Deepen_Line
     (Depth : Natural)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;

   function Encode_Upload_Pack_Shallow_Line
     (Object_ID_Hex : Ada.Streams.Stream_Element_Array)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;

   function Encode_Upload_Pack_Filter_Line
     (Filter_Spec : Ada.Streams.Stream_Element_Array)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;

   function Parse_Upload_Pack_ACK_Packet
     (Data          : Ada.Streams.Stream_Element_Array;
      Kind          : out Upload_Pack_ACK_Kind;
      Object_ID_Hex : out Ada.Streams.Stream_Element_Array;
      Last          : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   function Validate_Upload_Pack_ACK_Stream
     (Data    : Ada.Streams.Stream_Element_Array;
      Summary : out Upload_Pack_ACK_Stream_Summary)
      return CryptoLib.Errors.Status;

   function Validate_Upload_Pack_Negotiation_Request
     (Data    : Ada.Streams.Stream_Element_Array;
      Summary : out Upload_Pack_Negotiation_Summary)
      return CryptoLib.Errors.Status;

   function Encode_Upload_Pack_Fetch_Request
     (Wants        : Object_ID_Hex_Array;
      Haves        : Object_ID_Hex_Array;
      Shallows     : Object_ID_Hex_Array;
      Capabilities : Ada.Streams.Stream_Element_Array;
      Depth        : Natural;
      Filter_Spec  : Ada.Streams.Stream_Element_Array;
      Include_Done : Boolean)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;

   function Encode_Receive_Pack_Update_Line
     (Old_ID_Hex   : Object_ID_Hex_Text;
      New_ID_Hex   : Object_ID_Hex_Text;
      Ref_Name     : Ada.Streams.Stream_Element_Array;
      Capabilities : Ada.Streams.Stream_Element_Array)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;

   function Validate_Receive_Pack_Request
     (Data    : Ada.Streams.Stream_Element_Array;
      Summary : out Receive_Pack_Request_Summary)
      return CryptoLib.Errors.Status;

   function Validate_Upload_Pack_Response
     (Data    : Ada.Streams.Stream_Element_Array;
      Summary : out Upload_Pack_Response_Summary)
      return CryptoLib.Errors.Status;

   function Validate_Receive_Pack_Report
     (Data    : Ada.Streams.Stream_Element_Array;
      Summary : out Receive_Pack_Report_Summary)
      return CryptoLib.Errors.Status;

   procedure Reset_Fetch_Workflow (Workflow : out Fetch_Workflow);

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

   function Fetch_Accept_Response
     (Workflow : in out Fetch_Workflow;
      Response : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   function Fetch_Apply_Remote_Tracking_Update
     (Workflow               : in out Fetch_Workflow;
      Repository_Root        : String;
      Remote_Name            : String;
      Branch_Name            : String;
      New_Commit_Hex         : Ada.Streams.Stream_Element_Array;
      Allow_Non_Fast_Forward : Boolean;
      Updated                : out Boolean)
      return CryptoLib.Errors.Status;

   function Fetch_Finish
     (Workflow : in out Fetch_Workflow)
      return CryptoLib.Errors.Status;

   procedure Reset_Push_Workflow (Workflow : out Push_Workflow);

   function Push_Build_Request
     (Workflow     : in out Push_Workflow;
      Updates      : Ada.Streams.Stream_Element_Array;
      Pack_Data    : Ada.Streams.Stream_Element_Array;
      Request      : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;

   function Push_Accept_Report
     (Workflow : in out Push_Workflow;
      Report   : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   function Push_Apply_Branch_Update
     (Workflow               : in out Push_Workflow;
      Repository_Root        : String;
      Branch_Name            : String;
      Expected_Old_Hex       : Ada.Streams.Stream_Element_Array;
      New_Commit_Hex         : Ada.Streams.Stream_Element_Array;
      Allow_Non_Fast_Forward : Boolean;
      Updated                : out Boolean)
      return CryptoLib.Errors.Status;

   function Push_Finish
     (Workflow : in out Push_Workflow)
      return CryptoLib.Errors.Status;

   function Decide_Fetch_Policy
     (Workflow         : Fetch_Workflow;
      Attempt          : Natural;
      Max_Attempts     : Natural;
      Local_Have_Count : Natural;
      Decision         : out Fetch_Policy_Decision)
      return CryptoLib.Errors.Status;

   function Decide_Push_Policy
     (Workflow     : Push_Workflow;
      Attempt      : Natural;
      Max_Attempts : Natural;
      Decision     : out Push_Policy_Decision)
      return CryptoLib.Errors.Status;

   function Encode_Protocol_V2_Command_Request
     (Command_Name : Ada.Streams.Stream_Element_Array;
      Capabilities : Ada.Streams.Stream_Element_Array;
      Arguments    : Ada.Streams.Stream_Element_Array)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;

   function Validate_Protocol_V2_Command_Request
     (Data    : Ada.Streams.Stream_Element_Array;
      Summary : out Protocol_V2_Request_Summary)
      return CryptoLib.Errors.Status;

   function Validate_Protocol_V2_Capability_Advertisement
     (Data    : Ada.Streams.Stream_Element_Array;
      Summary : out Protocol_V2_Capability_Summary)
      return CryptoLib.Errors.Status;

   function Validate_Protocol_V2_Response
     (Data    : Ada.Streams.Stream_Element_Array;
      Summary : out Protocol_V2_Response_Summary)
      return CryptoLib.Errors.Status;

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

   function Validate_Ref_Advertisement_Stream
     (Data    : Ada.Streams.Stream_Element_Array;
      Summary : out Ref_Advertisement_Summary)
      return CryptoLib.Errors.Status;

   function Parse_Pack_Header
     (Data         : Ada.Streams.Stream_Element_Array;
      Version      : out Natural;
      Object_Count : out Natural)
      return CryptoLib.Errors.Status;

   function Parse_Pack_Index_Header
     (Data    : Ada.Streams.Stream_Element_Array;
      Version : out Natural)
      return CryptoLib.Errors.Status;

   function Parse_Pack_Index_Fanout
     (Data         : Ada.Streams.Stream_Element_Array;
      Object_Count : out Natural)
      return CryptoLib.Errors.Status;

   function Copy_Pack_Index_Object_ID
     (Data         : Ada.Streams.Stream_Element_Array;
      Object_Index : Natural;
      Object_ID    : out Ada.Streams.Stream_Element_Array;
      Last         : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   function Parse_Pack_Index_CRC
     (Data         : Ada.Streams.Stream_Element_Array;
      Object_Index : Natural;
      CRC_Value    : out Natural)
      return CryptoLib.Errors.Status;

   function Parse_Pack_Index_Offset
     (Data               : Ada.Streams.Stream_Element_Array;
      Object_Index       : Natural;
      Pack_Offset        : out Natural;
      Large_Offset_Index : out Natural;
      Uses_Large_Offset  : out Boolean)
      return CryptoLib.Errors.Status;

   function Parse_Pack_Index_Large_Offset
     (Data               : Ada.Streams.Stream_Element_Array;
      Large_Offset_Index : Natural;
      Pack_Offset        : out Natural)
      return CryptoLib.Errors.Status;

   function Copy_Pack_Index_Checksum
     (Data     : Ada.Streams.Stream_Element_Array;
      Checksum : out Ada.Streams.Stream_Element_Array;
      Last     : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   function Compute_Pack_Index_Layout
     (Object_Count       : Natural;
      Large_Offset_Count : Natural;
      Layout             : out Pack_Index_Layout)
      return CryptoLib.Errors.Status;

   function Build_Pack_Index
     (Pack_Data      : Ada.Streams.Stream_Element_Array;
      Object_Scratch : out Ada.Streams.Stream_Element_Array;
      Index_Data     : out Ada.Streams.Stream_Element_Array;
      Last           : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   function Validate_Pack_Index_Object_ID_Order
     (Data         : Ada.Streams.Stream_Element_Array;
      Object_Count : Natural)
      return CryptoLib.Errors.Status;

   function Validate_Pack_Index_Fanout_Matches_Object_IDs
     (Fanout       : Ada.Streams.Stream_Element_Array;
      Object_IDs   : Ada.Streams.Stream_Element_Array;
      Object_Count : Natural)
      return CryptoLib.Errors.Status;

   function Validate_Pack_Index_Large_Offset_Count
     (Offsets_Table      : Ada.Streams.Stream_Element_Array;
      Object_Count       : Natural;
      Large_Offset_Count : Natural)
      return CryptoLib.Errors.Status;

   function Validate_Pack_Index
     (Data               : Ada.Streams.Stream_Element_Array;
      Object_Count       : out Natural;
      Large_Offset_Count : out Natural;
      Layout             : out Pack_Index_Layout)
      return CryptoLib.Errors.Status;

   function Verify_Pack_Trailer_Checksum
     (Pack_Data : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   function Verify_Pack_Index_Checksum
     (Index_Data : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   function Verify_Pack_Index_Pack_Checksum
     (Index_Data              : Ada.Streams.Stream_Element_Array;
      Expected_Pack_Checksum  : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   function Find_Pack_Index_Object
     (Index_Data        : Ada.Streams.Stream_Element_Array;
      Object_ID         : Ada.Streams.Stream_Element_Array;
      Object_Index      : out Natural;
      Pack_Offset       : out Natural)
      return CryptoLib.Errors.Status;

   function Find_Pack_Index_Object_Hex
     (Index_Data        : Ada.Streams.Stream_Element_Array;
      Object_ID_Hex     : Ada.Streams.Stream_Element_Array;
      Object_Index      : out Natural;
      Pack_Offset       : out Natural)
      return CryptoLib.Errors.Status;

   function List_Pack_Index_Object_IDs
     (Index_Data     : Ada.Streams.Stream_Element_Array;
      Object_IDs_Hex : out Object_ID_Hex_Array;
      Count          : out Natural)
      return CryptoLib.Errors.Status;

   function Validate_Pack_Index_Offsets
     (Index_Data     : Ada.Streams.Stream_Element_Array;
      Pack_Data      : Ada.Streams.Stream_Element_Array;
      Scratch        : out Ada.Streams.Stream_Element_Array;
      Object_Count   : out Natural;
      Trailer_Offset : out Natural)
      return CryptoLib.Errors.Status;

   function Validate_Pack_Index_CRCs
     (Index_Data     : Ada.Streams.Stream_Element_Array;
      Pack_Data      : Ada.Streams.Stream_Element_Array;
      Scratch        : out Ada.Streams.Stream_Element_Array;
      Object_Count   : out Natural;
      Trailer_Offset : out Natural)
      return CryptoLib.Errors.Status;

   function Validate_Pack_Delta_Bases
     (Index_Data     : Ada.Streams.Stream_Element_Array;
      Pack_Data      : Ada.Streams.Stream_Element_Array;
      Scratch        : out Ada.Streams.Stream_Element_Array;
      Object_Count   : out Natural;
      Trailer_Offset : out Natural)
      return CryptoLib.Errors.Status;

   function Validate_Pack_Delta_Graph
     (Index_Data     : Ada.Streams.Stream_Element_Array;
      Pack_Data      : Ada.Streams.Stream_Element_Array;
      Scratch        : out Ada.Streams.Stream_Element_Array;
      Object_Count   : out Natural;
      Trailer_Offset : out Natural)
      return CryptoLib.Errors.Status;

   function Validate_Pack_Non_Delta_Object_IDs
     (Index_Data      : Ada.Streams.Stream_Element_Array;
      Pack_Data       : Ada.Streams.Stream_Element_Array;
      Scratch         : out Ada.Streams.Stream_Element_Array;
      Object_Count    : out Natural;
      Verified_Count  : out Natural;
      Trailer_Offset  : out Natural)
      return CryptoLib.Errors.Status;

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

   function Inventory_Pack_Objects
     (Pack_Data      : Ada.Streams.Stream_Element_Array;
      Scratch        : out Ada.Streams.Stream_Element_Array;
      Counts         : out Pack_Object_Counts;
      Object_Count   : out Natural;
      Trailer_Offset : out Natural)
      return CryptoLib.Errors.Status;

   function Compute_Object_ID
     (Kind      : Pack_Object_Kind;
      Data      : Ada.Streams.Stream_Element_Array;
      Object_ID : out Ada.Streams.Stream_Element_Array;
      Last      : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   function Build_Tree_Entry
     (File_Mode : Natural;
      Name      : String;
      Object_ID : Ada.Streams.Stream_Element_Array;
      Entry_Data : out Ada.Streams.Stream_Element_Array;
      Last      : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

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

   function Build_Merge_Conflict_File
     (Ours_Label    : String;
      Ours_Data     : Ada.Streams.Stream_Element_Array;
      Theirs_Label  : String;
      Theirs_Data   : Ada.Streams.Stream_Element_Array;
      Conflict_Data : out Ada.Streams.Stream_Element_Array;
      Last          : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   function Classify_Three_Way_Blob_Merge
     (Base_ID_Hex   : Ada.Streams.Stream_Element_Array;
      Ours_ID_Hex   : Ada.Streams.Stream_Element_Array;
      Theirs_ID_Hex : Ada.Streams.Stream_Element_Array;
      Result        : out Three_Way_Merge_Result)
      return CryptoLib.Errors.Status;

   function Build_Sequencer_Pick_Line
     (Commit_ID_Hex : Ada.Streams.Stream_Element_Array;
      Subject       : String;
      Line          : out Ada.Streams.Stream_Element_Array;
      Last          : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   function Build_Tag_Object
     (Target_ID_Hex : Ada.Streams.Stream_Element_Array;
      Target_Kind   : Pack_Object_Kind;
      Tag_Name      : String;
      Tagger_Line   : String;
      Message       : String;
      Tag_Data      : out Ada.Streams.Stream_Element_Array;
      Last          : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

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

   function Validate_Tree_Object
     (Data        : Ada.Streams.Stream_Element_Array;
      Entry_Count : out Natural)
      return CryptoLib.Errors.Status;

   function Find_Tree_Entry
     (Data        : Ada.Streams.Stream_Element_Array;
      Name        : Ada.Streams.Stream_Element_Array;
      File_Mode   : out Natural;
      Object_ID   : out Ada.Streams.Stream_Element_Array;
      Object_Last : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   function Find_Tree_Entry_Hex
     (Data        : Ada.Streams.Stream_Element_Array;
      Name        : Ada.Streams.Stream_Element_Array;
      File_Mode   : out Natural;
      Object_ID   : out Ada.Streams.Stream_Element_Array;
      Object_Last : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   function Parse_Commit_Tree_ID
     (Data        : Ada.Streams.Stream_Element_Array;
      Tree_ID_Hex : out Ada.Streams.Stream_Element_Array;
      Last        : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   function Parse_Commit_Parent_ID
     (Data          : Ada.Streams.Stream_Element_Array;
      Parent_Index  : Positive;
      Parent_ID_Hex : out Ada.Streams.Stream_Element_Array;
      Last          : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   function Parse_Commit_Author_Line
     (Data : Ada.Streams.Stream_Element_Array;
      Text : out Ada.Streams.Stream_Element_Array;
      Last : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   function Parse_Commit_Committer_Line
     (Data : Ada.Streams.Stream_Element_Array;
      Text : out Ada.Streams.Stream_Element_Array;
      Last : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   function Parse_Commit_Message_Offset
     (Data           : Ada.Streams.Stream_Element_Array;
      Message_Offset : out Natural)
      return CryptoLib.Errors.Status;

   function Validate_Commit_Object
     (Data         : Ada.Streams.Stream_Element_Array;
      Parent_Count : out Natural)
      return CryptoLib.Errors.Status;

   function Parse_Tag_Target
     (Data          : Ada.Streams.Stream_Element_Array;
      Target_ID_Hex : out Ada.Streams.Stream_Element_Array;
      Last          : out Ada.Streams.Stream_Element_Offset;
      Target_Kind   : out Pack_Object_Kind)
      return CryptoLib.Errors.Status;

   function Parse_Tag_Name
     (Data : Ada.Streams.Stream_Element_Array;
      Name : out Ada.Streams.Stream_Element_Array;
      Last : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   function Parse_Tag_Message_Offset
     (Data           : Ada.Streams.Stream_Element_Array;
      Message_Offset : out Natural)
      return CryptoLib.Errors.Status;

   function Validate_Object_Data
     (Kind : Pack_Object_Kind;
      Data : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   function Validate_Tag_Object
     (Data        : Ada.Streams.Stream_Element_Array;
      Target_Kind : out Pack_Object_Kind)
      return CryptoLib.Errors.Status;

   function Encode_Object_ID_Hex
     (Object_ID : Ada.Streams.Stream_Element_Array;
      Hex_Text  : out Ada.Streams.Stream_Element_Array;
      Last      : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   function Parse_Object_ID_Hex
     (Hex_Text  : Ada.Streams.Stream_Element_Array;
      Object_ID : out Ada.Streams.Stream_Element_Array;
      Last      : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   function Parse_Pack_Object_Header
     (Data              : Ada.Streams.Stream_Element_Array;
      Kind              : out Pack_Object_Kind;
      Uncompressed_Size : out Natural;
      Header_Length     : out Natural)
      return CryptoLib.Errors.Status;

   function Inflate_Pack_Object_Data
     (Compressed_Data            : Ada.Streams.Stream_Element_Array;
      Expected_Uncompressed_Size : Natural;
      Inflated_Data              : out Ada.Streams.Stream_Element_Array;
      Last                       : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   function Inflate_Pack_Object_Data
     (Compressed_Data            : Ada.Streams.Stream_Element_Array;
      Expected_Uncompressed_Size : Natural;
      Inflated_Data              : out Ada.Streams.Stream_Element_Array;
      Last                       : out Ada.Streams.Stream_Element_Offset;
      Consumed_Length            : out Natural)
      return CryptoLib.Errors.Status;

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

   function Validate_Pack_Object_Sequence
     (Pack_Data      : Ada.Streams.Stream_Element_Array;
      Scratch        : out Ada.Streams.Stream_Element_Array;
      Object_Count   : out Natural;
      Trailer_Offset : out Natural)
      return CryptoLib.Errors.Status;

   function Apply_Pack_Delta
     (Base_Data  : Ada.Streams.Stream_Element_Array;
      Delta_Data : Ada.Streams.Stream_Element_Array;
      Result     : out Ada.Streams.Stream_Element_Array;
      Last       : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   function Apply_Pack_Delta_Chain
     (Base_Data  : Ada.Streams.Stream_Element_Array;
      Delta_Data : Ada.Streams.Stream_Element_Array;
      Deltas     : Pack_Delta_Span_Array;
      Workspace  : out Ada.Streams.Stream_Element_Array;
      Result     : out Ada.Streams.Stream_Element_Array;
      Last       : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   function Parse_Pack_REF_Delta_Base
     (Data            : Ada.Streams.Stream_Element_Array;
      Base_Object_ID  : out Ada.Streams.Stream_Element_Array;
      Base_Last       : out Ada.Streams.Stream_Element_Offset;
      Consumed_Length : out Natural)
      return CryptoLib.Errors.Status;

   function Parse_Pack_OFS_Delta_Base
     (Data            : Ada.Streams.Stream_Element_Array;
      Negative_Offset : out Natural;
      Consumed_Length : out Natural)
      return CryptoLib.Errors.Status;

   function Valid_Object_ID (Text : String) return Boolean;

   function Valid_Ref_Name (Name : String) return Boolean;

   function Valid_Fetch_Refspec (RefSpec : String) return Boolean;

   function Valid_Push_Refspec (RefSpec : String) return Boolean;

   function Valid_Push_Default_Mode (Mode : String) return Boolean;

   function Valid_Pull_Rebase_Mode (Mode : String) return Boolean;

   function Classify_Ref_Name
     (Name : String;
      Kind : out Ref_Name_Kind)
      return CryptoLib.Errors.Status;

   function Parse_Side_Band_Packet
     (Data    : Ada.Streams.Stream_Element_Array;
      Kind    : out Side_Band_Kind;
      Payload : out Ada.Streams.Stream_Element_Array;
      Last    : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   function Validate_Side_Band_Stream
     (Data    : Ada.Streams.Stream_Element_Array;
      Summary : out Side_Band_Stream_Summary)
      return CryptoLib.Errors.Status;

   function Parse_Status_Report_Packet
     (Data         : Ada.Streams.Stream_Element_Array;
      Kind         : out Status_Report_Kind;
      Ref_Name     : out Ada.Streams.Stream_Element_Array;
      Ref_Last     : out Ada.Streams.Stream_Element_Offset;
      Message      : out Ada.Streams.Stream_Element_Array;
      Message_Last : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   function Parse_Capability_Token
     (Token      : Ada.Streams.Stream_Element_Array;
      Name       : out Ada.Streams.Stream_Element_Array;
      Name_Last  : out Ada.Streams.Stream_Element_Offset;
      Value      : out Ada.Streams.Stream_Element_Array;
      Value_Last : out Ada.Streams.Stream_Element_Offset;
      Has_Value  : out Boolean)
      return CryptoLib.Errors.Status;

   function Copy_Next_Capability_Token
     (List      : Ada.Streams.Stream_Element_Array;
      Cursor    : in out Ada.Streams.Stream_Element_Offset;
      Token     : out Ada.Streams.Stream_Element_Array;
      Last      : out Ada.Streams.Stream_Element_Offset;
      Has_Token : out Boolean)
      return CryptoLib.Errors.Status;
end SSH_Lib.Git;
