with Ada.Calendar;
with Ada.Containers.Vectors;
with Ada.Streams;
with Ada.Strings.Unbounded;
with Interfaces;
with SSH_Lib.Channels;
with CryptoLib.Errors;
with SSH_Lib.Protocol.Buffers;
with SSH_Lib.Sessions;

package SSH_Lib.SFTP is
   Protocol_Version           : constant Natural := 3;
   Minimum_Protocol_Version   : constant Natural := 3;
   Maximum_Protocol_Version   : constant Natural := 6;
   --  Maximum SFTP packet payload accepted or emitted by this implementation.
   Maximum_Packet_Length      : constant Natural := 256 * 1024;
   --  Maximum data bytes sent in one SSH_FXP_WRITE request.
   Upload_Chunk_Size          : constant Natural := 32_768;
   --  Default number of outstanding read/write requests for high-level transfers.
   Default_Pipeline_Depth     : constant Positive := 4;
   --  Upper bound accepted for configurable transfer pipelining.
   Maximum_Pipeline_Depth     : constant Positive := 64;
   --  Longest remote path that can fit in an SSH_FXP_OPEN upload request.
   Maximum_Remote_Path_Length : constant Natural := Maximum_Packet_Length - 21;

   SSH_FXP_INIT           : constant := 1;
   SSH_FXP_VERSION        : constant := 2;
   SSH_FXP_OPEN           : constant := 3;
   SSH_FXP_CLOSE          : constant := 4;
   SSH_FXP_READ           : constant := 5;
   SSH_FXP_WRITE          : constant := 6;
   SSH_FXP_LSTAT          : constant := 7;
   SSH_FXP_FSTAT          : constant := 8;
   SSH_FXP_SETSTAT        : constant := 9;
   SSH_FXP_FSETSTAT       : constant := 10;
   SSH_FXP_OPENDIR        : constant := 11;
   SSH_FXP_READDIR        : constant := 12;
   SSH_FXP_REMOVE         : constant := 13;
   SSH_FXP_MKDIR          : constant := 14;
   SSH_FXP_RMDIR          : constant := 15;
   SSH_FXP_REALPATH       : constant := 16;
   SSH_FXP_STAT           : constant := 17;
   SSH_FXP_RENAME         : constant := 18;
   SSH_FXP_READLINK       : constant := 19;
   SSH_FXP_SYMLINK        : constant :=
     20; --  v3 name retained for compatibility
   SSH_FXP_LINK           : constant := 21;
   SSH_FXP_BLOCK          : constant := 22;
   SSH_FXP_UNBLOCK        : constant := 23;
   SSH_FXP_STATUS         : constant := 101;
   SSH_FXP_HANDLE         : constant := 102;
   SSH_FXP_DATA           : constant := 103;
   SSH_FXP_NAME           : constant := 104;
   SSH_FXP_ATTRS          : constant := 105;
   SSH_FXP_EXTENDED       : constant := 200;
   SSH_FXP_EXTENDED_REPLY : constant := 201;

   SSH_FX_OK                          : constant := 0;
   SSH_FX_EOF                         : constant := 1;
   SSH_FX_NO_SUCH_FILE                : constant := 2;
   SSH_FX_PERMISSION_DENIED           : constant := 3;
   SSH_FX_FAILURE                     : constant := 4;
   SSH_FX_BAD_MESSAGE                 : constant := 5;
   SSH_FX_NO_CONNECTION               : constant := 6;
   SSH_FX_CONNECTION_LOST             : constant := 7;
   SSH_FX_OP_UNSUPPORTED              : constant := 8;
   SSH_FX_INVALID_HANDLE              : constant := 9;
   SSH_FX_NO_SUCH_PATH                : constant := 10;
   SSH_FX_FILE_ALREADY_EXISTS         : constant := 11;
   SSH_FX_WRITE_PROTECT               : constant := 12;
   SSH_FX_NO_MEDIA                    : constant := 13;
   SSH_FX_NO_SPACE_ON_FILESYSTEM      : constant := 14;
   SSH_FX_QUOTA_EXCEEDED              : constant := 15;
   SSH_FX_UNKNOWN_PRINCIPAL           : constant := 16;
   SSH_FX_LOCK_CONFLICT               : constant := 17;
   SSH_FX_DIR_NOT_EMPTY               : constant := 18;
   SSH_FX_NOT_A_DIRECTORY             : constant := 19;
   SSH_FX_INVALID_FILENAME            : constant := 20;
   SSH_FX_LINK_LOOP                   : constant := 21;
   SSH_FX_CANNOT_DELETE               : constant := 22;
   SSH_FX_INVALID_PARAMETER           : constant := 23;
   SSH_FX_FILE_IS_A_DIRECTORY         : constant := 24;
   SSH_FX_BYTE_RANGE_LOCK_CONFLICT    : constant := 25;
   SSH_FX_BYTE_RANGE_LOCK_REFUSED     : constant := 26;
   SSH_FX_DELETE_PENDING              : constant := 27;
   SSH_FX_FILE_CORRUPT                : constant := 28;
   SSH_FX_OWNER_INVALID               : constant := 29;
   SSH_FX_GROUP_INVALID               : constant := 30;
   SSH_FX_NO_MATCHING_BYTE_RANGE_LOCK : constant := 31;

   Posix_Rename_Extension   : constant String := "posix-rename@openssh.com";
   Fsync_Extension          : constant String := "fsync@openssh.com";
   StatVFS_Extension        : constant String := "statvfs@openssh.com";
   Hardlink_Extension       : constant String := "hardlink@openssh.com";
   LSetStat_Extension       : constant String := "lsetstat@openssh.com";
   Limits_Extension         : constant String := "limits@openssh.com";
   Copy_Data_Extension      : constant String := "copy-data";
   Expand_Path_Extension    : constant String := "expand-path@openssh.com";
   Check_File_Extension     : constant String := "check-file";
   Supported2_Extension     : constant String := "supported2";
   Versions_Extension       : constant String := "versions";
   Version_Select_Extension : constant String := "version-select";
   Text_Seek_Extension      : constant String := "text-seek";

   type Known_Extension is
     (Posix_Rename_Known_Extension,
      Fsync_Known_Extension,
      StatVFS_Known_Extension,
      Hardlink_Known_Extension,
      LSetStat_Known_Extension,
      Limits_Known_Extension,
      Copy_Data_Known_Extension,
      Expand_Path_Known_Extension,
      Check_File_Known_Extension,
      Supported2_Known_Extension,
      Versions_Known_Extension,
      Version_Select_Known_Extension,
      Text_Seek_Known_Extension);

   function Extension_Name (Extension : Known_Extension) return String;

   type Supported_Capabilities is record
      Present                     : Boolean := False;
      Supported_Attribute_Mask    : Interfaces.Unsigned_32 := 0;
      Supported_Attribute_Bits    : Interfaces.Unsigned_32 := 0;
      Supported_Open_Flags        : Interfaces.Unsigned_32 := 0;
      Supported_Access_Mask       : Interfaces.Unsigned_32 := 0;
      Max_Read_Size               : Interfaces.Unsigned_32 := 0;
      Supported_Open_Block_Vector : Interfaces.Unsigned_16 := 0;
      Supported_Block_Vector      : Interfaces.Unsigned_16 := 0;
   end record;

   type Extension_Info is record
      Posix_Rename : Boolean := False;
      Fsync        : Boolean := False;
      StatVFS      : Boolean := False;
      Hardlink     : Boolean := False;
      LSetStat     : Boolean := False;
      Limits       : Boolean := False;
      Copy_Data    : Boolean := False;
      Expand_Path  : Boolean := False;
      Check_File   : Boolean := False;
      Supported2   : Boolean := False;
      Versions     : Boolean := False;
      Version_2    : Boolean := False;
      Version_3    : Boolean := False;
      Version_4    : Boolean := False;
      Version_5    : Boolean := False;
      Version_6    : Boolean := False;
      Text_Seek    : Boolean := False;
      Capabilities : Supported_Capabilities := (others => <>);
   end record;

   function Supports_Extension
     (Extensions : Extension_Info; Name : String) return Boolean;

   function Supports_Extension
     (Extensions : Extension_Info; Extension : Known_Extension) return Boolean;

   function Supports_Protocol_Version (Version : Natural) return Boolean;

   function Last_Remote_Status_Code return Interfaces.Unsigned_32;

   function Last_Remote_Status_Message
      return Ada.Strings.Unbounded.Unbounded_String;

   function Status_Code_Name (Code : Interfaces.Unsigned_32) return String;

   function Last_Remote_Status_Name return String;

   type SFTP_Operation is
     (Unknown_Operation,
      Open_Operation,
      Close_Operation,
      Upload_Operation,
      Download_Operation,
      Stat_Operation,
      Set_Attributes_Operation,
      Remove_Operation,
      Rename_Operation,
      Directory_Operation,
      Link_Operation,
      Lock_Operation,
      Check_File_Operation,
      StatVFS_Operation,
      Limits_Operation,
      Extended_Operation);

   type SFTP_Result is record
      Operation             : SFTP_Operation := Unknown_Operation;
      Status                : CryptoLib.Errors.Status := CryptoLib.Errors.Ok;
      Remote_Status_Code    : Interfaces.Unsigned_32 := SSH_FX_OK;
      Remote_Status_Name    : Ada.Strings.Unbounded.Unbounded_String;
      Remote_Status_Message : Ada.Strings.Unbounded.Unbounded_String;
   end record;

   function Last_Result return SFTP_Result;

   function Result_For_Status
     (Status    : CryptoLib.Errors.Status;
      Operation : SFTP_Operation := Unknown_Operation) return SFTP_Result;

   procedure Capture_Result
     (Status    : CryptoLib.Errors.Status;
      Result    : out SFTP_Result;
      Operation : SFTP_Operation := Unknown_Operation);

   type Server_Limits is record
      Max_Packet_Length : Interfaces.Unsigned_64 := 0;
      Max_Read_Length   : Interfaces.Unsigned_64 := 0;
      Max_Write_Length  : Interfaces.Unsigned_64 := 0;
      Max_Open_Handles  : Interfaces.Unsigned_64 := 0;
   end record;

   type File_System_Stats is record
      Block_Size             : Interfaces.Unsigned_64 := 0;
      Fundamental_Block_Size : Interfaces.Unsigned_64 := 0;
      Blocks                 : Interfaces.Unsigned_64 := 0;
      Free_Blocks            : Interfaces.Unsigned_64 := 0;
      Available_Blocks       : Interfaces.Unsigned_64 := 0;
      File_Nodes             : Interfaces.Unsigned_64 := 0;
      Free_File_Nodes        : Interfaces.Unsigned_64 := 0;
      Available_File_Nodes   : Interfaces.Unsigned_64 := 0;
      File_System_Id         : Interfaces.Unsigned_64 := 0;
      Flags                  : Interfaces.Unsigned_64 := 0;
      Maximum_Name_Length    : Interfaces.Unsigned_64 := 0;
   end record;

   type Check_File_Result is record
      Result    : SFTP_Result;
      Algorithm : Ada.Strings.Unbounded.Unbounded_String;
      Digest    : SSH_Lib.Protocol.Buffers.Packet_Buffer;
   end record;

   type StatVFS_Result is record
      Result : SFTP_Result;
      Stats  : File_System_Stats := (others => 0);
   end record;

   type Limits_Result is record
      Result : SFTP_Result;
      Values : Server_Limits := (others => 0);
   end record;

   type Extended_Request_Result is record
      Result     : SFTP_Result;
      Reply_Data : SSH_Lib.Protocol.Buffers.Packet_Buffer;
   end record;

   type Negotiated_Snapshot is record
      Result       : SFTP_Result;
      Version      : Natural := 0;
      Extensions   : Extension_Info := (others => <>);
      Limits_Known : Boolean := False;
      Limits       : Server_Limits := (others => 0);
   end record;

   type Extended_Attribute is record
      Name  : Ada.Strings.Unbounded.Unbounded_String;
      Value : Ada.Strings.Unbounded.Unbounded_String;
   end record;

   package Extended_Attribute_Vectors is new
     Ada.Containers.Vectors
       (Index_Type   => Natural,
        Element_Type => Extended_Attribute);

   type File_Attributes is record
      Size_Known              : Boolean := False;
      Size                    : Interfaces.Unsigned_64 := 0;
      Allocation_Size_Known   : Boolean := False;
      Allocation_Size         : Interfaces.Unsigned_64 := 0;
      UID_GID_Known           : Boolean := False;
      UID                     : Interfaces.Unsigned_32 := 0;
      GID                     : Interfaces.Unsigned_32 := 0;
      Owner_Group_Known       : Boolean := False;
      Owner                   : Ada.Strings.Unbounded.Unbounded_String;
      Group                   : Ada.Strings.Unbounded.Unbounded_String;
      Permissions_Known       : Boolean := False;
      Permissions             : Interfaces.Unsigned_32 := 0;
      Times_Known             : Boolean := False;
      Access_Time             : Interfaces.Unsigned_32 := 0;
      Access_Time_Nanoseconds : Interfaces.Unsigned_32 := 0;
      Modify_Time             : Interfaces.Unsigned_32 := 0;
      Modify_Time_Nanoseconds : Interfaces.Unsigned_32 := 0;
      Create_Time_Known       : Boolean := False;
      Create_Time             : Interfaces.Unsigned_32 := 0;
      Create_Time_Nanoseconds : Interfaces.Unsigned_32 := 0;
      ACL_Known               : Boolean := False;
      ACL                     : Ada.Strings.Unbounded.Unbounded_String;
      Attribute_Bits_Known    : Boolean := False;
      Attribute_Bits          : Interfaces.Unsigned_32 := 0;
      Attribute_Bits_Valid    : Interfaces.Unsigned_32 := 0;
      Text_Hint_Known         : Boolean := False;
      Text_Hint               : Interfaces.Unsigned_8 := 0;
      Mime_Type_Known         : Boolean := False;
      Mime_Type               : Ada.Strings.Unbounded.Unbounded_String;
      Link_Count_Known        : Boolean := False;
      Link_Count              : Interfaces.Unsigned_32 := 0;
      Untranslated_Name_Known : Boolean := False;
      Untranslated_Name       : Ada.Strings.Unbounded.Unbounded_String;
      Extended_Attributes     : Extended_Attribute_Vectors.Vector;
   end record;

   Owner_Read_Permission    : constant Interfaces.Unsigned_32 := 8#400#;
   Owner_Write_Permission   : constant Interfaces.Unsigned_32 := 8#200#;
   Owner_Execute_Permission : constant Interfaces.Unsigned_32 := 8#100#;
   Group_Read_Permission    : constant Interfaces.Unsigned_32 := 8#040#;
   Group_Write_Permission   : constant Interfaces.Unsigned_32 := 8#020#;
   Group_Execute_Permission : constant Interfaces.Unsigned_32 := 8#010#;
   Other_Read_Permission    : constant Interfaces.Unsigned_32 := 8#004#;
   Other_Write_Permission   : constant Interfaces.Unsigned_32 := 8#002#;
   Other_Execute_Permission : constant Interfaces.Unsigned_32 := 8#001#;

   function Has_Extended_Attribute
     (Attributes : File_Attributes; Name : String) return Boolean;

   function Extended_Attribute_Value
     (Attributes : File_Attributes;
      Name       : String;
      Value      : out Ada.Strings.Unbounded.Unbounded_String) return Boolean;

   procedure Set_Extended_Attribute
     (Attributes : in out File_Attributes; Name : String; Value : String);

   function Extended_Attribute_Count
     (Attributes : File_Attributes) return Natural;

   procedure Clear_Extended_Attributes (Attributes : in out File_Attributes);

   function Is_Directory (Attributes : File_Attributes) return Boolean;
   function Is_Regular_File (Attributes : File_Attributes) return Boolean;
   function Is_Symlink (Attributes : File_Attributes) return Boolean;
   function Is_Other_File_Type (Attributes : File_Attributes) return Boolean;

   function Mode_To_Permissions
     (Mode : String; Permissions : out Interfaces.Unsigned_32) return Boolean;

   function Permissions_To_Mode
     (Permissions : Interfaces.Unsigned_32) return String;

   function Permission_Bits
     (Attributes : File_Attributes) return Interfaces.Unsigned_32;

   function Has_Permission
     (Attributes : File_Attributes; Permission : Interfaces.Unsigned_32)
      return Boolean;

   function Owner_Can_Read (Attributes : File_Attributes) return Boolean;
   function Owner_Can_Write (Attributes : File_Attributes) return Boolean;
   function Owner_Can_Execute (Attributes : File_Attributes) return Boolean;
   function Group_Can_Read (Attributes : File_Attributes) return Boolean;
   function Group_Can_Write (Attributes : File_Attributes) return Boolean;
   function Group_Can_Execute (Attributes : File_Attributes) return Boolean;
   function Other_Can_Read (Attributes : File_Attributes) return Boolean;
   function Other_Can_Write (Attributes : File_Attributes) return Boolean;
   function Other_Can_Execute (Attributes : File_Attributes) return Boolean;

   function Set_Permissions_Mode
     (Attributes : in out File_Attributes; Mode : String) return Boolean;

   procedure Set_UID_GID
     (Attributes : in out File_Attributes;
      UID        : Interfaces.Unsigned_32;
      GID        : Interfaces.Unsigned_32);

   procedure Set_Allocation_Size
     (Attributes : in out File_Attributes; Size : Interfaces.Unsigned_64);

   procedure Set_Owner_Group
     (Attributes : in out File_Attributes; Owner : String; Group : String);

   procedure Set_Create_Time
     (Attributes  : in out File_Attributes;
      Create_Time : Ada.Calendar.Time;
      Nanoseconds : Interfaces.Unsigned_32 := 0);

   procedure Set_ACL (Attributes : in out File_Attributes; ACL : String);

   procedure Set_Attribute_Bits
     (Attributes : in out File_Attributes;
      Bits       : Interfaces.Unsigned_32;
      Valid      : Interfaces.Unsigned_32);

   procedure Set_Text_Hint
     (Attributes : in out File_Attributes; Hint : Interfaces.Unsigned_8);

   procedure Set_Mime_Type
     (Attributes : in out File_Attributes; Mime_Type : String);

   procedure Set_Link_Count
     (Attributes : in out File_Attributes; Count : Interfaces.Unsigned_32);

   procedure Set_Untranslated_Name
     (Attributes : in out File_Attributes; Name : String);

   function Access_Time_Value
     (Attributes : File_Attributes; Value : out Ada.Calendar.Time)
      return Boolean;

   function Modify_Time_Value
     (Attributes : File_Attributes; Value : out Ada.Calendar.Time)
      return Boolean;

   procedure Set_Times
     (Attributes  : in out File_Attributes;
      Access_Time : Ada.Calendar.Time;
      Modify_Time : Ada.Calendar.Time);

   function Copy_Metadata
     (Source           : File_Attributes;
      Include_Size     : Boolean := False;
      Include_UID_GID  : Boolean := False;
      Include_Extended : Boolean := True) return File_Attributes;

   type Directory_Entry is record
      Name       : Ada.Strings.Unbounded.Unbounded_String;
      Long_Name  : Ada.Strings.Unbounded.Unbounded_String;
      Attributes : File_Attributes;
   end record;

   package Directory_Entry_Vectors is new
     Ada.Containers.Vectors
       (Index_Type   => Natural,
        Element_Type => Directory_Entry);

   type Directory_Page_Callback_Access is
     access function
       (Entries : Directory_Entry_Vectors.Vector) return CryptoLib.Errors.Status;

   type Open_Mode is
     (Read_Only,
      Write_Truncate,
      Write_No_Truncate,
      Append,
      Create_New,
      Read_Write);

   function Supports_Open_Mode
     (Extensions : Extension_Info; Mode : Open_Mode) return Boolean;

   function Supports_Attributes
     (Extensions : Extension_Info;
      Attributes : File_Attributes;
      Version    : Natural := Protocol_Version) return Boolean;

   function Supports_Block_Mask
     (Extensions : Extension_Info; Lock_Mask : Interfaces.Unsigned_32)
      return Boolean;

   type Transfer_Options is record
      Pipeline_Depth        : Positive := Default_Pipeline_Depth;
      Retry_Count           : Natural := 0;
      Verify_After_Transfer : Boolean := False;
      Atomic_Upload               : Boolean := False;
      Read_Chunk_Size             : Positive := Upload_Chunk_Size;
      Write_Chunk_Size            : Positive := Upload_Chunk_Size;
      Adaptive_Chunking           : Boolean := False;
      Minimum_Adaptive_Chunk_Size : Positive := 4 * 1024;
   end record;

   Default_Transfer_Options : constant Transfer_Options := (others => <>);

   type Stream_Reader_Access is
     access function
       (Offset         : Interfaces.Unsigned_64;
        Maximum_Length : Natural;
        Data           : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
        return CryptoLib.Errors.Status;

   type Stream_Writer_Access is
     access function
       (Offset : Interfaces.Unsigned_64;
        Data   : Ada.Streams.Stream_Element_Array)
        return CryptoLib.Errors.Status;

   type File_Handle is private;
   type Client is limited private;

   function Is_Open (Handle : File_Handle) return Boolean;
   function Is_Open (Item : Client) return Boolean;
   function Version (Item : Client) return Natural;
   function Extensions (Item : Client) return Extension_Info;
   function Negotiated_Info (Item : Client) return Negotiated_Snapshot;

   function Limits
     (Item   : Client;
      Values : out Server_Limits) return Boolean;

   function Encode_Init_Packet return SSH_Lib.Protocol.Buffers.Packet_Buffer;

   function Encode_Init_Packet
     (Requested_Version : Natural)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;

   function Parse_Version_Packet
     (Packet : SSH_Lib.Protocol.Buffers.Packet_Buffer; Version : out Natural)
      return CryptoLib.Errors.Status;

   function Parse_Version_Packet
     (Packet     : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Version    : out Natural;
      Extensions : out Extension_Info) return CryptoLib.Errors.Status;

   --  Low-level SFTP reply parser helpers used by diagnostics and fuzzing.
   --  They validate full packet framing and accept ordinary parser failures as
   --  status returns; callers should treat runtime exceptions as defects.
   function Parse_Status_Packet
     (Packet        : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Expected_Id   : Interfaces.Unsigned_32;
      Expected_Code : Interfaces.Unsigned_32 := SSH_FX_OK)
      return CryptoLib.Errors.Status;

   function Parse_Handle_Packet
     (Packet      : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Expected_Id : Interfaces.Unsigned_32;
      Handle      : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;

   function Parse_Extended_Reply_Packet
     (Packet      : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Expected_Id : Interfaces.Unsigned_32;
      Reply_Data  : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;

   function Parse_Check_File_Packet
     (Packet      : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Expected_Id : Interfaces.Unsigned_32;
      Algorithm   : out Ada.Strings.Unbounded.Unbounded_String;
      Digest      : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;

   function Parse_Limits_Packet
     (Packet      : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Expected_Id : Interfaces.Unsigned_32;
      Values      : out Server_Limits) return CryptoLib.Errors.Status;

   function Parse_StatVFS_Packet
     (Packet      : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Expected_Id : Interfaces.Unsigned_32;
      Stats       : out File_System_Stats) return CryptoLib.Errors.Status;

   function Parse_Attrs_Packet
     (Packet      : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Expected_Id : Interfaces.Unsigned_32;
      Attributes  : out File_Attributes) return CryptoLib.Errors.Status;

   function Parse_Attrs_Packet
     (Packet      : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Expected_Id : Interfaces.Unsigned_32;
      Attributes  : out File_Attributes;
      Version     : Natural) return CryptoLib.Errors.Status;

   function Parse_Data_Packet
     (Packet      : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Expected_Id : Interfaces.Unsigned_32;
      Data_Out    : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;

   function Parse_Name_Packet
     (Packet      : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Expected_Id : Interfaces.Unsigned_32;
      Names       : in out Ada.Strings.Unbounded.Unbounded_String)
      return CryptoLib.Errors.Status;

   function Parse_Name_Packet
     (Packet      : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Expected_Id : Interfaces.Unsigned_32;
      Names       : in out Ada.Strings.Unbounded.Unbounded_String;
      Version     : Natural) return CryptoLib.Errors.Status;

   --  Send SSH_FXP_INIT and read SSH_FXP_VERSION over an already-open
   --  ``sftp`` subsystem channel.
   function Initialize
     (Channel : in out SSH_Lib.Channels.Channel; Version : out Natural)
      return CryptoLib.Errors.Status;

   function Initialize
     (Channel           : in out SSH_Lib.Channels.Channel;
      Requested_Version : Natural;
      Version           : out Natural) return CryptoLib.Errors.Status;

   function Initialize
     (Channel    : in out SSH_Lib.Channels.Channel;
      Version    : out Natural;
      Extensions : out Extension_Info) return CryptoLib.Errors.Status;

   function Initialize
     (Channel           : in out SSH_Lib.Channels.Channel;
      Requested_Version : Natural;
      Version           : out Natural;
      Extensions        : out Extension_Info) return CryptoLib.Errors.Status;

   --  Open the ``sftp`` subsystem on Session and initialize the SFTP protocol.
   --  Channel is left open on success and closed on initialization failure.
   function Open
     (Session : in out SSH_Lib.Sessions.Session;
      Channel : in out SSH_Lib.Channels.Channel;
      Version : out Natural) return CryptoLib.Errors.Status;

   function Open
     (Session           : in out SSH_Lib.Sessions.Session;
      Channel           : in out SSH_Lib.Channels.Channel;
      Requested_Version : Natural;
      Version           : out Natural) return CryptoLib.Errors.Status;

   function Open
     (Session    : in out SSH_Lib.Sessions.Session;
      Channel    : in out SSH_Lib.Channels.Channel;
      Version    : out Natural;
      Extensions : out Extension_Info) return CryptoLib.Errors.Status;

   function Open
     (Session           : in out SSH_Lib.Sessions.Session;
      Channel           : in out SSH_Lib.Channels.Channel;
      Requested_Version : Natural;
      Version           : out Natural;
      Extensions        : out Extension_Info) return CryptoLib.Errors.Status;

   function Open
     (Session : in out SSH_Lib.Sessions.Session; Item : in out Client)
      return CryptoLib.Errors.Status;

   function Open
     (Session           : in out SSH_Lib.Sessions.Session;
      Item              : in out Client;
      Requested_Version : Natural) return CryptoLib.Errors.Status;

   function Close (Item : in out Client) return CryptoLib.Errors.Status;

   --  Upload one regular file over an initialized SFTP channel.
   --  Remote_Path must be non-empty, contain no NUL byte, and fit within
   --  Maximum_Remote_Path_Length. Mode must be four octal digits.
   function Upload_Data
     (Channel     : in out SSH_Lib.Channels.Channel;
      Remote_Path : String;
      Data        : Ada.Streams.Stream_Element_Array;
      Mode        : String := "0644";
      Options     : Transfer_Options := Default_Transfer_Options)
      return CryptoLib.Errors.Status;

   --  Open SFTP, upload one regular file, and close the channel.
   --  Remote_Path and Mode follow the same validation rules as channel-level
   --  Upload_Data and are checked before opening the subsystem.
   function Upload_Data
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Data        : Ada.Streams.Stream_Element_Array;
      Mode        : String := "0644";
      Options     : Transfer_Options := Default_Transfer_Options)
      return CryptoLib.Errors.Status;

   function Upload_Data
     (Item        : in out Client;
      Remote_Path : String;
      Data        : Ada.Streams.Stream_Element_Array;
      Mode        : String := "0644";
      Options     : Transfer_Options := Default_Transfer_Options)
      return CryptoLib.Errors.Status;

   --  Upload Size bytes from Reader without requiring the caller to stage the
   --  whole payload in memory or in a local file. Reader is called with the
   --  next remote offset and maximum chunk size and must return a non-empty
   --  chunk no larger than Maximum_Length until Size bytes have been supplied.
   function Upload_Stream
     (Channel     : in out SSH_Lib.Channels.Channel;
      Remote_Path : String;
      Size        : Interfaces.Unsigned_64;
      Reader      : Stream_Reader_Access;
      Mode        : String := "0644";
      Options     : Transfer_Options := Default_Transfer_Options)
      return CryptoLib.Errors.Status;

   function Upload_Stream
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Size        : Interfaces.Unsigned_64;
      Reader      : Stream_Reader_Access;
      Mode        : String := "0644";
      Options     : Transfer_Options := Default_Transfer_Options)
      return CryptoLib.Errors.Status;

   --  Download one remote regular file into memory over an initialized SFTP
   --  channel. Data is replaced on success.
   function Download_Data
     (Channel     : in out SSH_Lib.Channels.Channel;
      Remote_Path : String;
      Data        : out SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Options     : Transfer_Options := Default_Transfer_Options)
      return CryptoLib.Errors.Status;

   --  Open SFTP, download one remote regular file into memory, and close the
   --  channel.
   function Download_Data
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Data        : out SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Options     : Transfer_Options := Default_Transfer_Options)
      return CryptoLib.Errors.Status;

   --  Download one remote regular file by passing each received chunk to
   --  Writer. Chunks are delivered in offset order and no whole-file buffer or
   --  local file is allocated by the library.
   function Download_Stream
     (Channel     : in out SSH_Lib.Channels.Channel;
      Remote_Path : String;
      Writer      : Stream_Writer_Access;
      Options     : Transfer_Options := Default_Transfer_Options)
      return CryptoLib.Errors.Status;

   function Download_Stream
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Writer      : Stream_Writer_Access;
      Options     : Transfer_Options := Default_Transfer_Options)
      return CryptoLib.Errors.Status;

   --  Download one remote regular file to Local_Path. Existing local files are
   --  replaced only after remote data has been read successfully.
   function Download_File
     (Channel     : in out SSH_Lib.Channels.Channel;
      Remote_Path : String;
      Local_Path  : String;
      Options     : Transfer_Options := Default_Transfer_Options)
      return CryptoLib.Errors.Status;

   function Download_File
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Local_Path  : String;
      Options     : Transfer_Options := Default_Transfer_Options)
      return CryptoLib.Errors.Status;

   --  Resume a partial local file by appending the missing remote bytes. If
   --  Local_Path does not exist, this behaves like Download_File without the
   --  temporary replacement file. If the local file is already complete, no
   --  remote file handle is opened. A local file larger than the remote file is
   --  rejected.
   function Resume_Download_File
     (Channel     : in out SSH_Lib.Channels.Channel;
      Remote_Path : String;
      Local_Path  : String;
      Options     : Transfer_Options := Default_Transfer_Options)
      return CryptoLib.Errors.Status;

   function Resume_Download_File
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Local_Path  : String;
      Options     : Transfer_Options := Default_Transfer_Options)
      return CryptoLib.Errors.Status;

   --  Resume a partial remote file by writing the missing suffix from the
   --  local file. A missing remote file starts at offset zero. A remote file
   --  larger than the local file is rejected. Atomic_Upload is not compatible
   --  with resume and is rejected.
   function Resume_Upload_File
     (Channel     : in out SSH_Lib.Channels.Channel;
      Remote_Path : String;
      Local_Path  : String;
      Mode        : String := "0644";
      Options     : Transfer_Options := Default_Transfer_Options)
      return CryptoLib.Errors.Status;

   function Resume_Upload_File
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Local_Path  : String;
      Mode        : String := "0644";
      Options     : Transfer_Options := Default_Transfer_Options)
      return CryptoLib.Errors.Status;

   --  List a remote directory. Names is newline-separated UTF-8/byte-preserving
   --  Ada String data as delivered by the server, excluding no entries.
   function List_Directory
     (Channel     : in out SSH_Lib.Channels.Channel;
      Remote_Path : String;
      Names       : out Ada.Strings.Unbounded.Unbounded_String)
      return CryptoLib.Errors.Status;

   function List_Directory
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Names       : out Ada.Strings.Unbounded.Unbounded_String)
      return CryptoLib.Errors.Status;

   --  List a remote directory preserving name, longname, and attributes for
   --  each SSH_FXP_NAME entry returned by the server.
   function List_Directory
     (Channel     : in out SSH_Lib.Channels.Channel;
      Remote_Path : String;
      Entries     : out Directory_Entry_Vectors.Vector)
      return CryptoLib.Errors.Status;

   function List_Directory
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Entries     : out Directory_Entry_Vectors.Vector)
      return CryptoLib.Errors.Status;

   --  Stream directory entries one server page at a time. Callback is invoked
   --  once for each non-empty SSH_FXP_NAME page and may return any non-Ok
   --  status to stop enumeration after the current page.
   function List_Directory_Paged
     (Channel     : in out SSH_Lib.Channels.Channel;
      Remote_Path : String;
      Callback    : Directory_Page_Callback_Access)
      return CryptoLib.Errors.Status;

   function List_Directory_Paged
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Callback    : Directory_Page_Callback_Access)
      return CryptoLib.Errors.Status;

   function Stat
     (Channel     : in out SSH_Lib.Channels.Channel;
      Remote_Path : String;
      Attributes  : out File_Attributes) return CryptoLib.Errors.Status;

   function Stat
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Attributes  : out File_Attributes) return CryptoLib.Errors.Status;

   function LStat
     (Channel     : in out SSH_Lib.Channels.Channel;
      Remote_Path : String;
      Attributes  : out File_Attributes) return CryptoLib.Errors.Status;

   function LStat
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Attributes  : out File_Attributes) return CryptoLib.Errors.Status;

   --  Canonicalize a remote path using SSH_FXP_REALPATH.
   function Realpath
     (Channel        : in out SSH_Lib.Channels.Channel;
      Remote_Path    : String;
      Canonical_Path : out Ada.Strings.Unbounded.Unbounded_String)
      return CryptoLib.Errors.Status;

   function Realpath
     (Session        : in out SSH_Lib.Sessions.Session;
      Remote_Path    : String;
      Canonical_Path : out Ada.Strings.Unbounded.Unbounded_String)
      return CryptoLib.Errors.Status;

   --  Open a remote file and return its protocol handle. Handles are scoped to
   --  the initialized SFTP channel that opened them and must be closed.
   function Open_Read
     (Channel     : in out SSH_Lib.Channels.Channel;
      Remote_Path : String;
      Handle      : out File_Handle) return CryptoLib.Errors.Status;

   function Open_Read
     (Channel     : in out SSH_Lib.Channels.Channel;
      Remote_Path : String;
      Handle      : out File_Handle;
      Version     : Natural) return CryptoLib.Errors.Status;

   function Open_Write
     (Channel     : in out SSH_Lib.Channels.Channel;
      Remote_Path : String;
      Handle      : out File_Handle;
      Mode        : String := "0644") return CryptoLib.Errors.Status;

   function Open_File
     (Channel          : in out SSH_Lib.Channels.Channel;
      Remote_Path      : String;
      Handle           : out File_Handle;
      Mode             : Open_Mode;
      Permissions_Mode : String := "0644") return CryptoLib.Errors.Status;

   function Open_File
     (Channel          : in out SSH_Lib.Channels.Channel;
      Remote_Path      : String;
      Handle           : out File_Handle;
      Mode             : Open_Mode;
      Permissions_Mode : String;
      Version          : Natural) return CryptoLib.Errors.Status;

   function Read_At
     (Channel : in out SSH_Lib.Channels.Channel;
      Handle  : File_Handle;
      Offset  : Interfaces.Unsigned_64;
      Length  : Natural;
      Data    : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;

   function Write_At
     (Channel : in out SSH_Lib.Channels.Channel;
      Handle  : File_Handle;
      Offset  : Interfaces.Unsigned_64;
      Data    : Ada.Streams.Stream_Element_Array) return CryptoLib.Errors.Status;

   function Download_Data
     (Channel     : in out SSH_Lib.Channels.Channel;
      Remote_Path : String;
      Offset      : Interfaces.Unsigned_64;
      Length      : Natural;
      Data        : out SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Options     : Transfer_Options := Default_Transfer_Options)
      return CryptoLib.Errors.Status;

   function Upload_Data
     (Channel     : in out SSH_Lib.Channels.Channel;
      Remote_Path : String;
      Offset      : Interfaces.Unsigned_64;
      Data        : Ada.Streams.Stream_Element_Array;
      Mode        : String := "0644";
      Options     : Transfer_Options := Default_Transfer_Options)
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
      Mode        : String := "0644") return CryptoLib.Errors.Status;

   function FStat
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Attributes  : out File_Attributes) return CryptoLib.Errors.Status;

   function Set_Handle_Permissions
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Mode        : String) return CryptoLib.Errors.Status;

   function Set_Handle_Attributes
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Attributes  : File_Attributes) return CryptoLib.Errors.Status;

   function Close
     (Channel : in out SSH_Lib.Channels.Channel; Handle : in out File_Handle)
      return CryptoLib.Errors.Status;

   function Close
     (Channel : in out SSH_Lib.Channels.Channel;
      Handle  : in out File_Handle;
      Result  : out SFTP_Result) return CryptoLib.Errors.Status;

   function FStat
     (Channel    : in out SSH_Lib.Channels.Channel;
      Handle     : File_Handle;
      Attributes : out File_Attributes) return CryptoLib.Errors.Status;

   function FStat
     (Channel    : in out SSH_Lib.Channels.Channel;
      Handle     : File_Handle;
      Attributes : out File_Attributes;
      Result     : out SFTP_Result) return CryptoLib.Errors.Status;

   function Set_Handle_Permissions
     (Channel : in out SSH_Lib.Channels.Channel;
      Handle  : File_Handle;
      Mode    : String) return CryptoLib.Errors.Status;

   function Set_Handle_Permissions
     (Channel : in out SSH_Lib.Channels.Channel;
      Handle  : File_Handle;
      Mode    : String;
      Result  : out SFTP_Result) return CryptoLib.Errors.Status;

   function Set_Handle_Attributes
     (Channel    : in out SSH_Lib.Channels.Channel;
      Handle     : File_Handle;
      Attributes : File_Attributes) return CryptoLib.Errors.Status;

   function Set_Handle_Attributes
     (Channel    : in out SSH_Lib.Channels.Channel;
      Handle     : File_Handle;
      Attributes : File_Attributes;
      Result     : out SFTP_Result) return CryptoLib.Errors.Status;

   function Set_Permissions
     (Channel     : in out SSH_Lib.Channels.Channel;
      Remote_Path : String;
      Mode        : String) return CryptoLib.Errors.Status;

   function Set_Permissions
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Mode        : String) return CryptoLib.Errors.Status;

   function Set_Attributes
     (Channel     : in out SSH_Lib.Channels.Channel;
      Remote_Path : String;
      Attributes  : File_Attributes) return CryptoLib.Errors.Status;

   function Set_Attributes
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Attributes  : File_Attributes) return CryptoLib.Errors.Status;

   function Set_Path_Owner_Group
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Owner       : String;
      Group       : String) return CryptoLib.Errors.Status;

   function Set_Path_Mime_Type
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Mime_Type   : String) return CryptoLib.Errors.Status;

   function Set_Path_ACL
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      ACL         : String) return CryptoLib.Errors.Status;

   function Set_Path_Attribute_Bits
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Bits        : Interfaces.Unsigned_32;
      Valid       : Interfaces.Unsigned_32) return CryptoLib.Errors.Status;

   function Set_Path_Text_Hint
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Hint        : Interfaces.Unsigned_8) return CryptoLib.Errors.Status;

   function Make_Directory
     (Channel     : in out SSH_Lib.Channels.Channel;
      Remote_Path : String;
      Mode        : String := "0755") return CryptoLib.Errors.Status;

   function Make_Directory
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Mode        : String := "0755") return CryptoLib.Errors.Status;

   function Remove_Directory
     (Channel : in out SSH_Lib.Channels.Channel; Remote_Path : String)
      return CryptoLib.Errors.Status;

   function Remove_Directory
     (Session : in out SSH_Lib.Sessions.Session; Remote_Path : String)
      return CryptoLib.Errors.Status;

   function Remove_File
     (Channel : in out SSH_Lib.Channels.Channel; Remote_Path : String)
      return CryptoLib.Errors.Status;

   function Remove_File
     (Channel     : in out SSH_Lib.Channels.Channel;
      Remote_Path : String;
      Result      : out SFTP_Result) return CryptoLib.Errors.Status;

   function Remove_File
     (Session : in out SSH_Lib.Sessions.Session; Remote_Path : String)
      return CryptoLib.Errors.Status;

   function Remove_File
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Result      : out SFTP_Result) return CryptoLib.Errors.Status;

   type Recursive_Entry_Kind is
     (Tree_File, Tree_Directory, Tree_Symlink, Tree_Other);

   type Recursive_Operation is
     (Tree_Upload, Tree_Download, Tree_Remove, Tree_Copy, Tree_Sync);

   type Recursive_Filter_Access is
     access function
       (Source_Path : String;
        Target_Path : String;
        Kind        : Recursive_Entry_Kind) return Boolean;

   type Recursive_Progress_Access is
     access procedure
       (Operation   : Recursive_Operation;
        Source_Path : String;
        Target_Path : String;
        Bytes_Done  : Interfaces.Unsigned_64;
        Bytes_Total : Interfaces.Unsigned_64);

   type Recursive_Options is record
      Preserve_Attributes : Boolean := False;
      Filter              : Recursive_Filter_Access := null;
      Progress            : Recursive_Progress_Access := null;
      Continue_On_Error   : Boolean := False;
      Overwrite_Files     : Boolean := True;
      Follow_Symlinks     : Boolean := False;
      Skip_Unchanged      : Boolean := False;
   end record;

   Default_Recursive_Options : constant Recursive_Options := (others => <>);

   type Sync_Direction is (Sync_Upload, Sync_Download);

   type Sync_Options is record
      Recursive      : Recursive_Options := Default_Recursive_Options;
      Delete_Extra   : Boolean := False;
      Skip_Unchanged : Boolean := True;
   end record;

   Default_Sync_Options : constant Sync_Options := (others => <>);

   --  Recursively upload a local directory tree into Remote_Path. The remote
   --  root directory is created if possible; an existing remote directory is
   --  accepted. Directory_Mode is used for created directories and File_Mode
   --  for uploaded regular files.
   function Upload_Directory
     (Channel        : in out SSH_Lib.Channels.Channel;
      Remote_Path    : String;
      Local_Path     : String;
      Directory_Mode : String := "0755";
      File_Mode      : String := "0644";
      Options        : Recursive_Options := Default_Recursive_Options)
      return CryptoLib.Errors.Status;

   function Upload_Directory
     (Session        : in out SSH_Lib.Sessions.Session;
      Remote_Path    : String;
      Local_Path     : String;
      Directory_Mode : String := "0755";
      File_Mode      : String := "0644";
      Options        : Recursive_Options := Default_Recursive_Options)
      return CryptoLib.Errors.Status;

   --  Recursively download Remote_Path into Local_Path. Local directories are
   --  created as needed; existing regular files are replaced using the same
   --  temporary-file behavior as Download_File.
   function Download_Directory
     (Channel     : in out SSH_Lib.Channels.Channel;
      Remote_Path : String;
      Local_Path  : String;
      Options     : Recursive_Options := Default_Recursive_Options)
      return CryptoLib.Errors.Status;

   function Download_Directory
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Local_Path  : String;
      Options     : Recursive_Options := Default_Recursive_Options)
      return CryptoLib.Errors.Status;

   --  Recursively remove a remote file or directory tree. Symbolic links are
   --  removed as links when the server reports symlink permissions.
   function Remove_Tree
     (Channel     : in out SSH_Lib.Channels.Channel;
      Remote_Path : String;
      Options     : Recursive_Options := Default_Recursive_Options)
      return CryptoLib.Errors.Status;

   function Remove_Tree
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Options     : Recursive_Options := Default_Recursive_Options)
      return CryptoLib.Errors.Status;

   --  Recursively copy a remote file or directory tree to another remote path
   --  over the same initialized SFTP channel. File contents are copied through
   --  the client using the existing download/upload primitives.
   function Copy_Tree
     (Channel            : in out SSH_Lib.Channels.Channel;
      Source_Remote_Path : String;
      Target_Remote_Path : String;
      Directory_Mode     : String := "0755";
      File_Mode          : String := "0644";
      Options            : Recursive_Options := Default_Recursive_Options)
      return CryptoLib.Errors.Status;

   function Copy_Tree
     (Session            : in out SSH_Lib.Sessions.Session;
      Source_Remote_Path : String;
      Target_Remote_Path : String;
      Directory_Mode     : String := "0755";
      File_Mode          : String := "0644";
      Options            : Recursive_Options := Default_Recursive_Options)
      return CryptoLib.Errors.Status;

   function Sync_Directory
     (Channel        : in out SSH_Lib.Channels.Channel;
      Direction      : Sync_Direction;
      Remote_Path    : String;
      Local_Path     : String;
      Directory_Mode : String := "0755";
      File_Mode      : String := "0644";
      Options        : Sync_Options := Default_Sync_Options)
      return CryptoLib.Errors.Status;

   function Sync_Directory
     (Session        : in out SSH_Lib.Sessions.Session;
      Direction      : Sync_Direction;
      Remote_Path    : String;
      Local_Path     : String;
      Directory_Mode : String := "0755";
      File_Mode      : String := "0644";
      Options        : Sync_Options := Default_Sync_Options)
      return CryptoLib.Errors.Status;

   function Rename
     (Channel  : in out SSH_Lib.Channels.Channel;
      Old_Path : String;
      New_Path : String) return CryptoLib.Errors.Status;

   function Rename
     (Channel  : in out SSH_Lib.Channels.Channel;
      Old_Path : String;
      New_Path : String;
      Result   : out SFTP_Result) return CryptoLib.Errors.Status;

   function Rename
     (Session  : in out SSH_Lib.Sessions.Session;
      Old_Path : String;
      New_Path : String) return CryptoLib.Errors.Status;

   function Rename
     (Session  : in out SSH_Lib.Sessions.Session;
      Old_Path : String;
      New_Path : String;
      Result   : out SFTP_Result) return CryptoLib.Errors.Status;

   function Posix_Rename
     (Channel  : in out SSH_Lib.Channels.Channel;
      Old_Path : String;
      New_Path : String) return CryptoLib.Errors.Status;

   function Posix_Rename
     (Channel  : in out SSH_Lib.Channels.Channel;
      Old_Path : String;
      New_Path : String;
      Result   : out SFTP_Result) return CryptoLib.Errors.Status;

   function Posix_Rename
     (Session  : in out SSH_Lib.Sessions.Session;
      Old_Path : String;
      New_Path : String) return CryptoLib.Errors.Status;

   function Posix_Rename
     (Session  : in out SSH_Lib.Sessions.Session;
      Old_Path : String;
      New_Path : String;
      Result   : out SFTP_Result) return CryptoLib.Errors.Status;

   function Hardlink
     (Channel  : in out SSH_Lib.Channels.Channel;
      Old_Path : String;
      New_Path : String) return CryptoLib.Errors.Status;

   function Hardlink
     (Channel  : in out SSH_Lib.Channels.Channel;
      Old_Path : String;
      New_Path : String;
      Result   : out SFTP_Result) return CryptoLib.Errors.Status;

   function Hardlink
     (Session  : in out SSH_Lib.Sessions.Session;
      Old_Path : String;
      New_Path : String) return CryptoLib.Errors.Status;

   function Hardlink
     (Session  : in out SSH_Lib.Sessions.Session;
      Old_Path : String;
      New_Path : String;
      Result   : out SFTP_Result) return CryptoLib.Errors.Status;

   function Fsync
     (Channel : in out SSH_Lib.Channels.Channel; Handle : File_Handle)
      return CryptoLib.Errors.Status;

   function Fsync
     (Channel : in out SSH_Lib.Channels.Channel;
      Handle  : File_Handle;
      Result  : out SFTP_Result) return CryptoLib.Errors.Status;

   function Fsync
     (Session : in out SSH_Lib.Sessions.Session; Remote_Path : String)
      return CryptoLib.Errors.Status;

   function Fsync
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Result      : out SFTP_Result) return CryptoLib.Errors.Status;

   function Expand_Path
     (Channel       : in out SSH_Lib.Channels.Channel;
      Remote_Path   : String;
      Expanded_Path : out Ada.Strings.Unbounded.Unbounded_String)
      return CryptoLib.Errors.Status;

   function Expand_Path
     (Channel       : in out SSH_Lib.Channels.Channel;
      Remote_Path   : String;
      Expanded_Path : out Ada.Strings.Unbounded.Unbounded_String;
      Result        : out SFTP_Result) return CryptoLib.Errors.Status;

   function Expand_Path
     (Session       : in out SSH_Lib.Sessions.Session;
      Remote_Path   : String;
      Expanded_Path : out Ada.Strings.Unbounded.Unbounded_String)
      return CryptoLib.Errors.Status;

   function Expand_Path
     (Session       : in out SSH_Lib.Sessions.Session;
      Remote_Path   : String;
      Expanded_Path : out Ada.Strings.Unbounded.Unbounded_String;
      Result        : out SFTP_Result) return CryptoLib.Errors.Status;

   function Expand_Path
     (Item          : in out Client;
      Remote_Path   : String;
      Expanded_Path : out Ada.Strings.Unbounded.Unbounded_String)
      return CryptoLib.Errors.Status;

   function Expand_Path
     (Item          : in out Client;
      Remote_Path   : String;
      Expanded_Path : out Ada.Strings.Unbounded.Unbounded_String;
      Result        : out SFTP_Result) return CryptoLib.Errors.Status;

   function Check_File
     (Channel    : in out SSH_Lib.Channels.Channel;
      Handle     : File_Handle;
      Algorithms : String;
      Offset     : Interfaces.Unsigned_64;
      Length     : Interfaces.Unsigned_64;
      Block_Size : Interfaces.Unsigned_32;
      Algorithm  : out Ada.Strings.Unbounded.Unbounded_String;
      Digest     : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;

   function Check_File_Info
     (Channel    : in out SSH_Lib.Channels.Channel;
      Handle     : File_Handle;
      Algorithms : String;
      Offset     : Interfaces.Unsigned_64 := 0;
      Length     : Interfaces.Unsigned_64 := 0;
      Block_Size : Interfaces.Unsigned_32 := 0) return Check_File_Result;

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

   function Check_File
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Algorithms  : String;
      Offset      : Interfaces.Unsigned_64;
      Length      : Interfaces.Unsigned_64;
      Block_Size  : Interfaces.Unsigned_32;
      Algorithm   : out Ada.Strings.Unbounded.Unbounded_String;
      Digest      : out SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Result      : out SFTP_Result) return CryptoLib.Errors.Status;

   function Check_File
     (Item        : in out Client;
      Remote_Path : String;
      Algorithms  : String;
      Offset      : Interfaces.Unsigned_64;
      Length      : Interfaces.Unsigned_64;
      Block_Size  : Interfaces.Unsigned_32;
      Algorithm   : out Ada.Strings.Unbounded.Unbounded_String;
      Digest      : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;

   function Check_File
     (Item        : in out Client;
      Remote_Path : String;
      Algorithms  : String;
      Offset      : Interfaces.Unsigned_64;
      Length      : Interfaces.Unsigned_64;
      Block_Size  : Interfaces.Unsigned_32;
      Algorithm   : out Ada.Strings.Unbounded.Unbounded_String;
      Digest      : out SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Result      : out SFTP_Result) return CryptoLib.Errors.Status;

   function Check_File_Info
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Algorithms  : String;
      Offset      : Interfaces.Unsigned_64 := 0;
      Length      : Interfaces.Unsigned_64 := 0;
      Block_Size  : Interfaces.Unsigned_32 := 0) return Check_File_Result;

   function Check_File_Info
     (Item        : in out Client;
      Remote_Path : String;
      Algorithms  : String;
      Offset      : Interfaces.Unsigned_64 := 0;
      Length      : Interfaces.Unsigned_64 := 0;
      Block_Size  : Interfaces.Unsigned_32 := 0) return Check_File_Result;

   function Copy_Data
     (Channel       : in out SSH_Lib.Channels.Channel;
      Source_Handle : File_Handle;
      Source_Offset : Interfaces.Unsigned_64;
      Length        : Interfaces.Unsigned_64;
      Target_Handle : File_Handle;
      Target_Offset : Interfaces.Unsigned_64) return CryptoLib.Errors.Status;

   function Copy_Data
     (Channel       : in out SSH_Lib.Channels.Channel;
      Source_Handle : File_Handle;
      Source_Offset : Interfaces.Unsigned_64;
      Length        : Interfaces.Unsigned_64;
      Target_Handle : File_Handle;
      Target_Offset : Interfaces.Unsigned_64;
      Result        : out SFTP_Result) return CryptoLib.Errors.Status;

   function Copy_File_Range
     (Session            : in out SSH_Lib.Sessions.Session;
      Source_Remote_Path : String;
      Target_Remote_Path : String;
      Source_Offset      : Interfaces.Unsigned_64;
      Length             : Interfaces.Unsigned_64;
      Target_Offset      : Interfaces.Unsigned_64 := 0;
      Mode               : String := "0644") return CryptoLib.Errors.Status;

   function Copy_File_Range
     (Session            : in out SSH_Lib.Sessions.Session;
      Source_Remote_Path : String;
      Target_Remote_Path : String;
      Source_Offset      : Interfaces.Unsigned_64;
      Length             : Interfaces.Unsigned_64;
      Target_Offset      : Interfaces.Unsigned_64;
      Mode               : String;
      Result             : out SFTP_Result) return CryptoLib.Errors.Status;

   function LSet_Attributes
     (Channel     : in out SSH_Lib.Channels.Channel;
      Remote_Path : String;
      Attributes  : File_Attributes) return CryptoLib.Errors.Status;

   function LSet_Attributes
     (Channel     : in out SSH_Lib.Channels.Channel;
      Remote_Path : String;
      Attributes  : File_Attributes;
      Result      : out SFTP_Result) return CryptoLib.Errors.Status;

   function LSet_Attributes
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Attributes  : File_Attributes) return CryptoLib.Errors.Status;

   function LSet_Attributes
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Attributes  : File_Attributes;
      Result      : out SFTP_Result) return CryptoLib.Errors.Status;

   function StatVFS
     (Channel     : in out SSH_Lib.Channels.Channel;
      Remote_Path : String;
      Stats       : out File_System_Stats) return CryptoLib.Errors.Status;

   function StatVFS
     (Channel     : in out SSH_Lib.Channels.Channel;
      Remote_Path : String;
      Stats       : out File_System_Stats;
      Result      : out SFTP_Result) return CryptoLib.Errors.Status;

   function StatVFS
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Stats       : out File_System_Stats) return CryptoLib.Errors.Status;

   function StatVFS
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Stats       : out File_System_Stats;
      Result      : out SFTP_Result) return CryptoLib.Errors.Status;

   function StatVFS_Info
     (Channel     : in out SSH_Lib.Channels.Channel;
      Remote_Path : String) return StatVFS_Result;

   function StatVFS_Info
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String) return StatVFS_Result;

   function Limits
     (Channel : in out SSH_Lib.Channels.Channel; Values : out Server_Limits)
      return CryptoLib.Errors.Status;

   function Limits
     (Channel : in out SSH_Lib.Channels.Channel;
      Values  : out Server_Limits;
      Result  : out SFTP_Result) return CryptoLib.Errors.Status;

   function Limits
     (Session : in out SSH_Lib.Sessions.Session; Values : out Server_Limits)
      return CryptoLib.Errors.Status;

   function Limits
     (Session : in out SSH_Lib.Sessions.Session;
      Values  : out Server_Limits;
      Result  : out SFTP_Result) return CryptoLib.Errors.Status;

   function Limits_Info
     (Channel : in out SSH_Lib.Channels.Channel) return Limits_Result;

   function Limits_Info
     (Session : in out SSH_Lib.Sessions.Session) return Limits_Result;

   --  Send an arbitrary SSH_FXP_EXTENDED request. Payload is appended after
   --  the extension name exactly as supplied. Reply_Data is replaced with the
   --  raw SSH_FXP_EXTENDED_REPLY payload after the request id. If the server
   --  returns SSH_FXP_STATUS, the status is mapped and Reply_Data is cleared.
   function Extended_Request
     (Channel        : in out SSH_Lib.Channels.Channel;
      Extension_Name : String;
      Payload        : Ada.Streams.Stream_Element_Array;
      Reply_Data     : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;

   function Extended_Request
     (Session        : in out SSH_Lib.Sessions.Session;
      Extension_Name : String;
      Payload        : Ada.Streams.Stream_Element_Array;
      Reply_Data     : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;

   function Extended_Request
     (Item           : in out Client;
      Extension_Name : String;
      Payload        : Ada.Streams.Stream_Element_Array;
      Reply_Data     : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;

   function Extended_Request_Info
     (Channel        : in out SSH_Lib.Channels.Channel;
      Extension_Name : String;
      Payload        : Ada.Streams.Stream_Element_Array)
      return Extended_Request_Result;

   function Extended_Request_Info
     (Session        : in out SSH_Lib.Sessions.Session;
      Extension_Name : String;
      Payload        : Ada.Streams.Stream_Element_Array)
      return Extended_Request_Result;

   function Extended_Request_Info
     (Item           : in out Client;
      Extension_Name : String;
      Payload        : Ada.Streams.Stream_Element_Array)
      return Extended_Request_Result;

   function Read_Link
     (Channel     : in out SSH_Lib.Channels.Channel;
      Remote_Path : String;
      Target_Path : out Ada.Strings.Unbounded.Unbounded_String)
      return CryptoLib.Errors.Status;

   function Read_Link
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Target_Path : out Ada.Strings.Unbounded.Unbounded_String)
      return CryptoLib.Errors.Status;

   function Create_Symlink
     (Channel     : in out SSH_Lib.Channels.Channel;
      Target_Path : String;
      Link_Path   : String) return CryptoLib.Errors.Status;

   function Create_Symlink
     (Session     : in out SSH_Lib.Sessions.Session;
      Target_Path : String;
      Link_Path   : String) return CryptoLib.Errors.Status;

   function Create_Link
     (Channel  : in out SSH_Lib.Channels.Channel;
      New_Link : String;
      Existing : String;
      Symbolic : Boolean := True) return CryptoLib.Errors.Status;

   function Create_Link
     (Channel  : in out SSH_Lib.Channels.Channel;
      New_Link : String;
      Existing : String;
      Symbolic : Boolean;
      Result   : out SFTP_Result) return CryptoLib.Errors.Status;

   function Create_Link
     (Item     : in out Client;
      New_Link : String;
      Existing : String;
      Symbolic : Boolean := True) return CryptoLib.Errors.Status;

   function Create_Link
     (Item     : in out Client;
      New_Link : String;
      Existing : String;
      Symbolic : Boolean;
      Result   : out SFTP_Result) return CryptoLib.Errors.Status;

   function Create_Link
     (Session  : in out SSH_Lib.Sessions.Session;
      New_Link : String;
      Existing : String;
      Symbolic : Boolean := True) return CryptoLib.Errors.Status;

   function Create_Link
     (Session  : in out SSH_Lib.Sessions.Session;
      New_Link : String;
      Existing : String;
      Symbolic : Boolean;
      Result   : out SFTP_Result) return CryptoLib.Errors.Status;

   function Text_Seek
     (Channel     : in out SSH_Lib.Channels.Channel;
      Handle      : File_Handle;
      Line_Number : Interfaces.Unsigned_64) return CryptoLib.Errors.Status;

   function Text_Seek
     (Item        : in out Client;
      Remote_Path : String;
      Line_Number : Interfaces.Unsigned_64) return CryptoLib.Errors.Status;

   function Text_Seek
     (Item        : in out Client;
      Remote_Path : String;
      Line_Number : Interfaces.Unsigned_64;
      Result      : out SFTP_Result) return CryptoLib.Errors.Status;

   function Text_Seek
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Line_Number : Interfaces.Unsigned_64) return CryptoLib.Errors.Status;

   function Lock_Range
     (Channel   : in out SSH_Lib.Channels.Channel;
      Handle    : File_Handle;
      Offset    : Interfaces.Unsigned_64;
      Length    : Interfaces.Unsigned_64;
      Lock_Mask : Interfaces.Unsigned_32) return CryptoLib.Errors.Status;

   function Lock_Range
     (Item        : in out Client;
      Remote_Path : String;
      Offset      : Interfaces.Unsigned_64;
      Length      : Interfaces.Unsigned_64;
      Lock_Mask   : Interfaces.Unsigned_32) return CryptoLib.Errors.Status;

   function Lock_Range
     (Item        : in out Client;
      Remote_Path : String;
      Offset      : Interfaces.Unsigned_64;
      Length      : Interfaces.Unsigned_64;
      Lock_Mask   : Interfaces.Unsigned_32;
      Result      : out SFTP_Result) return CryptoLib.Errors.Status;

   function Lock_Range
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Offset      : Interfaces.Unsigned_64;
      Length      : Interfaces.Unsigned_64;
      Lock_Mask   : Interfaces.Unsigned_32) return CryptoLib.Errors.Status;

   function Unlock_Range
     (Channel : in out SSH_Lib.Channels.Channel;
      Handle  : File_Handle;
      Offset  : Interfaces.Unsigned_64;
      Length  : Interfaces.Unsigned_64) return CryptoLib.Errors.Status;

   function Unlock_Range
     (Item        : in out Client;
      Remote_Path : String;
      Offset      : Interfaces.Unsigned_64;
      Length      : Interfaces.Unsigned_64) return CryptoLib.Errors.Status;

   function Unlock_Range
     (Item        : in out Client;
      Remote_Path : String;
      Offset      : Interfaces.Unsigned_64;
      Length      : Interfaces.Unsigned_64;
      Result      : out SFTP_Result) return CryptoLib.Errors.Status;

   function Unlock_Range
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Offset      : Interfaces.Unsigned_64;
      Length      : Interfaces.Unsigned_64) return CryptoLib.Errors.Status;

   function Version_Select
     (Item : in out Client; Requested_Version : Natural)
      return CryptoLib.Errors.Status;

   function Version_Select
     (Item              : in out Client;
      Requested_Version : Natural;
      Result            : out SFTP_Result) return CryptoLib.Errors.Status;

   --  Stream a local regular file over an initialized SFTP channel.
   --  Remote_Path must be non-empty, contain no NUL byte, and fit within
   --  Maximum_Remote_Path_Length. Mode must be four octal digits.
   function Upload_File
     (Channel     : in out SSH_Lib.Channels.Channel;
      Remote_Path : String;
      Local_Path  : String;
      Mode        : String := "0644";
      Options     : Transfer_Options := Default_Transfer_Options)
      return CryptoLib.Errors.Status;

   --  Open SFTP, stream a local regular file, and close the channel.
   --  Remote_Path and Mode are validated before local file checks or subsystem
   --  open.
   function Upload_File
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Local_Path  : String;
      Mode        : String := "0644";
      Options     : Transfer_Options := Default_Transfer_Options)
      return CryptoLib.Errors.Status;

   function Upload_File
     (Item        : in out Client;
      Remote_Path : String;
      Local_Path  : String;
      Mode        : String := "0644";
      Options     : Transfer_Options := Default_Transfer_Options)
      return CryptoLib.Errors.Status;

   function Upload_File
     (Item        : in out Client;
      Remote_Path : String;
      Local_Path  : String;
      Mode        : String;
      Options     : Transfer_Options;
      Result      : out SFTP_Result) return CryptoLib.Errors.Status;

   function Upload_Stream
     (Item        : in out Client;
      Remote_Path : String;
      Size        : Interfaces.Unsigned_64;
      Reader      : Stream_Reader_Access;
      Mode        : String := "0644";
      Options     : Transfer_Options := Default_Transfer_Options)
      return CryptoLib.Errors.Status;

   function Upload_Stream
     (Item        : in out Client;
      Remote_Path : String;
      Size        : Interfaces.Unsigned_64;
      Reader      : Stream_Reader_Access;
      Mode        : String;
      Options     : Transfer_Options;
      Result      : out SFTP_Result) return CryptoLib.Errors.Status;

   function Download_File
     (Item        : in out Client;
      Remote_Path : String;
      Local_Path  : String;
      Options     : Transfer_Options := Default_Transfer_Options)
      return CryptoLib.Errors.Status;

   function Download_File
     (Item        : in out Client;
      Remote_Path : String;
      Local_Path  : String;
      Options     : Transfer_Options;
      Result      : out SFTP_Result) return CryptoLib.Errors.Status;

   function Download_Stream
     (Item        : in out Client;
      Remote_Path : String;
      Writer      : Stream_Writer_Access;
      Options     : Transfer_Options := Default_Transfer_Options)
      return CryptoLib.Errors.Status;

   function Download_Stream
     (Item        : in out Client;
      Remote_Path : String;
      Writer      : Stream_Writer_Access;
      Options     : Transfer_Options;
      Result      : out SFTP_Result) return CryptoLib.Errors.Status;

   function Resume_Download_File
     (Item        : in out Client;
      Remote_Path : String;
      Local_Path  : String;
      Options     : Transfer_Options := Default_Transfer_Options)
      return CryptoLib.Errors.Status;

   function Resume_Download_File
     (Item        : in out Client;
      Remote_Path : String;
      Local_Path  : String;
      Options     : Transfer_Options;
      Result      : out SFTP_Result) return CryptoLib.Errors.Status;

   function Resume_Upload_File
     (Item        : in out Client;
      Remote_Path : String;
      Local_Path  : String;
      Mode        : String := "0644";
      Options     : Transfer_Options := Default_Transfer_Options)
      return CryptoLib.Errors.Status;

   function Resume_Upload_File
     (Item        : in out Client;
      Remote_Path : String;
      Local_Path  : String;
      Mode        : String;
      Options     : Transfer_Options;
      Result      : out SFTP_Result) return CryptoLib.Errors.Status;

   function Download_Data
     (Item        : in out Client;
      Remote_Path : String;
      Data        : out SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Options     : Transfer_Options := Default_Transfer_Options)
      return CryptoLib.Errors.Status;

   function Download_Data
     (Item        : in out Client;
      Remote_Path : String;
      Data        : out SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Options     : Transfer_Options;
      Result      : out SFTP_Result) return CryptoLib.Errors.Status;

   function Read_At
     (Item        : in out Client;
      Remote_Path : String;
      Offset      : Interfaces.Unsigned_64;
      Length      : Natural;
      Data        : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;

   function Read_At
     (Item        : in out Client;
      Remote_Path : String;
      Offset      : Interfaces.Unsigned_64;
      Length      : Natural;
      Data        : out SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Result      : out SFTP_Result) return CryptoLib.Errors.Status;

   function Write_At
     (Item        : in out Client;
      Remote_Path : String;
      Offset      : Interfaces.Unsigned_64;
      Data        : Ada.Streams.Stream_Element_Array;
      Mode        : String := "0644") return CryptoLib.Errors.Status;

   function Write_At
     (Item        : in out Client;
      Remote_Path : String;
      Offset      : Interfaces.Unsigned_64;
      Data        : Ada.Streams.Stream_Element_Array;
      Mode        : String;
      Result      : out SFTP_Result) return CryptoLib.Errors.Status;

   function Fsync
     (Item : in out Client; Remote_Path : String) return CryptoLib.Errors.Status;

   function Fsync
     (Item        : in out Client;
      Remote_Path : String;
      Result      : out SFTP_Result) return CryptoLib.Errors.Status;

   function List_Directory
     (Item        : in out Client;
      Remote_Path : String;
      Entries     : out Directory_Entry_Vectors.Vector)
      return CryptoLib.Errors.Status;

   function List_Directory
     (Item        : in out Client;
      Remote_Path : String;
      Entries     : out Directory_Entry_Vectors.Vector;
      Result      : out SFTP_Result) return CryptoLib.Errors.Status;

   function List_Directory
     (Item        : in out Client;
      Remote_Path : String;
      Names       : out Ada.Strings.Unbounded.Unbounded_String)
      return CryptoLib.Errors.Status;

   function List_Directory_Paged
     (Item        : in out Client;
      Remote_Path : String;
      Callback    : Directory_Page_Callback_Access)
      return CryptoLib.Errors.Status;

   function LStat
     (Item        : in out Client;
      Remote_Path : String;
      Attributes  : out File_Attributes) return CryptoLib.Errors.Status;

   function LStat
     (Item        : in out Client;
      Remote_Path : String;
      Attributes  : out File_Attributes;
      Result      : out SFTP_Result) return CryptoLib.Errors.Status;

   function Realpath
     (Item           : in out Client;
      Remote_Path    : String;
      Canonical_Path : out Ada.Strings.Unbounded.Unbounded_String)
      return CryptoLib.Errors.Status;

   function Realpath
     (Item           : in out Client;
      Remote_Path    : String;
      Canonical_Path : out Ada.Strings.Unbounded.Unbounded_String;
      Result         : out SFTP_Result) return CryptoLib.Errors.Status;

   function Set_Attributes
     (Item : in out Client; Remote_Path : String; Attributes : File_Attributes)
      return CryptoLib.Errors.Status;

   function Set_Attributes
     (Item        : in out Client;
      Remote_Path : String;
      Attributes  : File_Attributes;
      Result      : out SFTP_Result) return CryptoLib.Errors.Status;

   function Set_Path_Owner_Group
     (Item        : in out Client;
      Remote_Path : String;
      Owner       : String;
      Group       : String) return CryptoLib.Errors.Status;

   function Set_Path_Owner_Group
     (Item        : in out Client;
      Remote_Path : String;
      Owner       : String;
      Group       : String;
      Result      : out SFTP_Result) return CryptoLib.Errors.Status;

   function Set_Path_Mime_Type
     (Item : in out Client; Remote_Path : String; Mime_Type : String)
      return CryptoLib.Errors.Status;

   function Set_Path_Mime_Type
     (Item        : in out Client;
      Remote_Path : String;
      Mime_Type   : String;
      Result      : out SFTP_Result) return CryptoLib.Errors.Status;

   function Set_Path_ACL
     (Item : in out Client; Remote_Path : String; ACL : String)
      return CryptoLib.Errors.Status;

   function Set_Path_ACL
     (Item        : in out Client;
      Remote_Path : String;
      ACL         : String;
      Result      : out SFTP_Result) return CryptoLib.Errors.Status;

   function Set_Path_Attribute_Bits
     (Item        : in out Client;
      Remote_Path : String;
      Bits        : Interfaces.Unsigned_32;
      Valid       : Interfaces.Unsigned_32) return CryptoLib.Errors.Status;

   function Set_Path_Attribute_Bits
     (Item        : in out Client;
      Remote_Path : String;
      Bits        : Interfaces.Unsigned_32;
      Valid       : Interfaces.Unsigned_32;
      Result      : out SFTP_Result) return CryptoLib.Errors.Status;

   function Set_Path_Text_Hint
     (Item : in out Client; Remote_Path : String; Hint : Interfaces.Unsigned_8)
      return CryptoLib.Errors.Status;

   function Set_Path_Text_Hint
     (Item        : in out Client;
      Remote_Path : String;
      Hint        : Interfaces.Unsigned_8;
      Result      : out SFTP_Result) return CryptoLib.Errors.Status;

   function Remove_File
     (Item : in out Client; Remote_Path : String) return CryptoLib.Errors.Status;

   function Remove_File
     (Item        : in out Client;
      Remote_Path : String;
      Result      : out SFTP_Result) return CryptoLib.Errors.Status;

   function Make_Directory
     (Item : in out Client; Remote_Path : String; Mode : String := "0755")
      return CryptoLib.Errors.Status;

   function Make_Directory
     (Item        : in out Client;
      Remote_Path : String;
      Mode        : String;
      Result      : out SFTP_Result) return CryptoLib.Errors.Status;

   function Remove_Directory
     (Item : in out Client; Remote_Path : String)
      return CryptoLib.Errors.Status;

   function Remove_Directory
     (Item        : in out Client;
      Remote_Path : String;
      Result      : out SFTP_Result) return CryptoLib.Errors.Status;

   function Stat
     (Item        : in out Client;
      Remote_Path : String;
      Attributes  : out File_Attributes) return CryptoLib.Errors.Status;

   function Upload_Directory
     (Item           : in out Client;
      Remote_Path    : String;
      Local_Path     : String;
      Directory_Mode : String := "0755";
      File_Mode      : String := "0644";
      Options        : Recursive_Options := Default_Recursive_Options)
      return CryptoLib.Errors.Status;

   function Upload_Directory
     (Item           : in out Client;
      Remote_Path    : String;
      Local_Path     : String;
      Directory_Mode : String;
      File_Mode      : String;
      Options        : Recursive_Options;
      Result         : out SFTP_Result) return CryptoLib.Errors.Status;

   function Download_Directory
     (Item        : in out Client;
      Remote_Path : String;
      Local_Path  : String;
      Options     : Recursive_Options := Default_Recursive_Options)
      return CryptoLib.Errors.Status;

   function Download_Directory
     (Item        : in out Client;
      Remote_Path : String;
      Local_Path  : String;
      Options     : Recursive_Options;
      Result      : out SFTP_Result) return CryptoLib.Errors.Status;

   function Remove_Tree
     (Item        : in out Client;
      Remote_Path : String;
      Options     : Recursive_Options := Default_Recursive_Options)
      return CryptoLib.Errors.Status;

   function Remove_Tree
     (Item        : in out Client;
      Remote_Path : String;
      Options     : Recursive_Options;
      Result      : out SFTP_Result) return CryptoLib.Errors.Status;

   function Copy_Tree
     (Item               : in out Client;
      Source_Remote_Path : String;
      Target_Remote_Path : String;
      Directory_Mode     : String := "0755";
      File_Mode          : String := "0644";
      Options            : Recursive_Options := Default_Recursive_Options)
      return CryptoLib.Errors.Status;

   function Copy_Tree
     (Item               : in out Client;
      Source_Remote_Path : String;
      Target_Remote_Path : String;
      Directory_Mode     : String;
      File_Mode          : String;
      Options            : Recursive_Options;
      Result             : out SFTP_Result) return CryptoLib.Errors.Status;

   function Sync_Directory
     (Item           : in out Client;
      Direction      : Sync_Direction;
      Remote_Path    : String;
      Local_Path     : String;
      Directory_Mode : String := "0755";
      File_Mode      : String := "0644";
      Options        : Sync_Options := Default_Sync_Options)
      return CryptoLib.Errors.Status;

   function Sync_Directory
     (Item           : in out Client;
      Direction      : Sync_Direction;
      Remote_Path    : String;
      Local_Path     : String;
      Directory_Mode : String;
      File_Mode      : String;
      Options        : Sync_Options;
      Result         : out SFTP_Result) return CryptoLib.Errors.Status;

   function Read_Link
     (Item        : in out Client;
      Remote_Path : String;
      Target_Path : out Ada.Strings.Unbounded.Unbounded_String)
      return CryptoLib.Errors.Status;

   function Read_Link
     (Item        : in out Client;
      Remote_Path : String;
      Target_Path : out Ada.Strings.Unbounded.Unbounded_String;
      Result      : out SFTP_Result) return CryptoLib.Errors.Status;

   function Create_Symlink
     (Item        : in out Client;
      Target_Path : String;
      Link_Path   : String) return CryptoLib.Errors.Status;

   function Create_Symlink
     (Item        : in out Client;
      Target_Path : String;
      Link_Path   : String;
      Result      : out SFTP_Result) return CryptoLib.Errors.Status;

private
   type File_Handle is record
      Data          : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Opened        : Boolean := False;
      Version       : Natural := Protocol_Version;
      Context_Known : Boolean := False;
      Extensions    : Extension_Info := (others => <>);
   end record;

   type Client is limited record
      Channel      : SSH_Lib.Channels.Channel;
      Opened       : Boolean := False;
      Version      : Natural := 0;
      Extensions   : Extension_Info := (others => <>);
      Limits_Known : Boolean := False;
      Limits       : Server_Limits := (others => 0);
   end record;
end SSH_Lib.SFTP;
