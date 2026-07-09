with Ada.Calendar;
with Ada.Containers.Vectors;
with Ada.Streams;
with Ada.Strings.Unbounded;
with Interfaces;
with SSH_Lib.Channels;
with CryptoLib.Errors;
with SSH_Lib.Protocol.Buffers;
with SSH_Lib.Sessions;

--  @summary Client and codec for the SSH File Transfer Protocol (SFTP).
--
--  Implements the SFTP protocol (draft-ietf-secsh-filexfer), speaking versions
--  3 through 6 with a negotiated default of 3, over an already-established SSH
--  session or channel.  Provides packet codecs (SSH_FXP_* encode/parse), a
--  File_Attributes model, and high-level file, directory, and tree transfer
--  operations, plus the common OpenSSH extensions (posix-rename, fsync,
--  statvfs, hardlink, lsetstat, limits, copy-data, expand-path, check-file).
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

   --  Return the wire name string for a known SFTP extension.
   --  @param Extension the known SFTP extension
   --  @return the extension's wire name string
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

   --  Report whether the negotiated extension set includes a given extension.
   --  @param Extensions the negotiated server extension set
   --  @param Name       the extension wire name to look up
   --  @return True if the extension is supported, False otherwise
   function Supports_Extension
     (Extensions : Extension_Info; Name : String) return Boolean;

   --  Report whether the negotiated extension set includes a given extension.
   --  @param Extensions the negotiated server extension set
   --  @param Extension  the known SFTP extension
   --  @return True if the extension is supported, False otherwise
   function Supports_Extension
     (Extensions : Extension_Info; Extension : Known_Extension) return Boolean;

   --  Report whether an SFTP protocol version is supported by this implementation.
   --  @param Version the SFTP protocol version to assume
   --  @return True if the version is supported, False otherwise
   function Supports_Protocol_Version (Version : Natural) return Boolean;

   --  Return the SSH_FX_* status code from the most recent remote status reply.
   --  @return the last remote SSH_FX_* status code
   function Last_Remote_Status_Code return Interfaces.Unsigned_32;

   --  Return the human-readable message from the most recent remote status reply.
   --  @return the last remote status message
   function Last_Remote_Status_Message
      return Ada.Strings.Unbounded.Unbounded_String;

   --  Return the symbolic SSH_FX_* name for a status code.
   --  @param Code the SSH_FX_* status code
   --  @return the symbolic SSH_FX_* status name
   function Status_Code_Name (Code : Interfaces.Unsigned_32) return String;

   --  Return the symbolic name of the most recent remote status code.
   --  @return the symbolic SSH_FX_* status name of the last reply
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

   --  Return the SFTP_Result captured from the most recent operation.
   --  @return the most recent SFTP result
   function Last_Result return SFTP_Result;

   --  Build an SFTP_Result wrapping a status and operation kind.
   --  @param Status    the status value to wrap
   --  @param Operation the operation kind to record
   --  @return the constructed SFTP_Result
   function Result_For_Status
     (Status    : CryptoLib.Errors.Status;
      Operation : SFTP_Operation := Unknown_Operation) return SFTP_Result;

   --  Capture a status and operation kind into an SFTP_Result and record it as the last result.
   --  @param Status    the status value to wrap
   --  @param Result    detailed operation result: remote status code, symbolic name, and message
   --  @param Operation the operation kind to record
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

   --  Report whether the attributes carry a named extended attribute.
   --  @param Attributes the attributes to apply
   --  @param Name       the extended-attribute name
   --  @return True if the named extended attribute is present, False otherwise
   function Has_Extended_Attribute
     (Attributes : File_Attributes; Name : String) return Boolean;

   --  Retrieve the value of a named extended attribute.
   --  @param Attributes the attributes to apply
   --  @param Name       the extended-attribute name
   --  @param Value      the retrieved attribute value
   --  @return True if the attribute exists and Value was set, False otherwise
   function Extended_Attribute_Value
     (Attributes : File_Attributes;
      Name       : String;
      Value      : out Ada.Strings.Unbounded.Unbounded_String) return Boolean;

   --  Set or replace a named extended attribute.
   --  @param Attributes the attribute record to modify
   --  @param Name       the extended-attribute name
   --  @param Value      the extended-attribute value to store
   procedure Set_Extended_Attribute
     (Attributes : in out File_Attributes; Name : String; Value : String);

   --  Return the number of extended attributes present.
   --  @param Attributes the attributes to apply
   --  @return the number of extended attributes
   function Extended_Attribute_Count
     (Attributes : File_Attributes) return Natural;

   --  Remove all extended attributes from the record.
   --  @param Attributes the attribute record to modify
   procedure Clear_Extended_Attributes (Attributes : in out File_Attributes);

   --  Report whether the attributes describe a directory.
   --  @param Attributes the attributes to apply
   --  @return True if the attributes describe a directory, False otherwise
   function Is_Directory (Attributes : File_Attributes) return Boolean;
   --  Report whether the attributes describe a regular file.
   --  @param Attributes the attributes to apply
   --  @return True if the attributes describe a regular file, False otherwise
   function Is_Regular_File (Attributes : File_Attributes) return Boolean;
   --  Report whether the attributes describe a symbolic link.
   --  @param Attributes the attributes to apply
   --  @return True if the attributes describe a symbolic link, False otherwise
   function Is_Symlink (Attributes : File_Attributes) return Boolean;
   --  Report whether the attributes describe some other object type.
   --  @param Attributes the attributes to apply
   --  @return True if the attributes describe some other object type, False otherwise
   function Is_Other_File_Type (Attributes : File_Attributes) return Boolean;

   --  Convert an octal mode string into a POSIX permission bit mask.
   --  @param Mode        the octal permission mode string (e.g. "0644")
   --  @param Permissions the resulting POSIX permission bit mask
   --  @return True if Mode parsed and Permissions was set, False otherwise
   function Mode_To_Permissions
     (Mode : String; Permissions : out Interfaces.Unsigned_32) return Boolean;

   --  Convert a POSIX permission bit mask into an octal mode string.
   --  @param Permissions the POSIX permission bit mask
   --  @return the equivalent octal mode string
   function Permissions_To_Mode
     (Permissions : Interfaces.Unsigned_32) return String;

   --  Return the POSIX permission bits from the attributes.
   --  @param Attributes the attributes to apply
   --  @return the POSIX permission bits
   function Permission_Bits
     (Attributes : File_Attributes) return Interfaces.Unsigned_32;

   --  Report whether the attributes have a given permission bit set.
   --  @param Attributes the attributes to apply
   --  @param Permission the permission bit to test
   --  @return True if the permission bit is set, False otherwise
   function Has_Permission
     (Attributes : File_Attributes; Permission : Interfaces.Unsigned_32)
      return Boolean;

   --  Report whether the owner has read permission.
   --  @param Attributes the attributes to apply
   --  @return True if the permission is granted, False otherwise
   function Owner_Can_Read (Attributes : File_Attributes) return Boolean;
   --  Report whether the owner has write permission.
   --  @param Attributes the attributes to apply
   --  @return True if the permission is granted, False otherwise
   function Owner_Can_Write (Attributes : File_Attributes) return Boolean;
   --  Report whether the owner has execute permission.
   --  @param Attributes the attributes to apply
   --  @return True if the permission is granted, False otherwise
   function Owner_Can_Execute (Attributes : File_Attributes) return Boolean;
   --  Report whether the group has read permission.
   --  @param Attributes the attributes to apply
   --  @return True if the permission is granted, False otherwise
   function Group_Can_Read (Attributes : File_Attributes) return Boolean;
   --  Report whether the group has write permission.
   --  @param Attributes the attributes to apply
   --  @return True if the permission is granted, False otherwise
   function Group_Can_Write (Attributes : File_Attributes) return Boolean;
   --  Report whether the group has execute permission.
   --  @param Attributes the attributes to apply
   --  @return True if the permission is granted, False otherwise
   function Group_Can_Execute (Attributes : File_Attributes) return Boolean;
   --  Report whether others have read permission.
   --  @param Attributes the attributes to apply
   --  @return True if the permission is granted, False otherwise
   function Other_Can_Read (Attributes : File_Attributes) return Boolean;
   --  Report whether others have write permission.
   --  @param Attributes the attributes to apply
   --  @return True if the permission is granted, False otherwise
   function Other_Can_Write (Attributes : File_Attributes) return Boolean;
   --  Report whether others have execute permission.
   --  @param Attributes the attributes to apply
   --  @return True if the permission is granted, False otherwise
   function Other_Can_Execute (Attributes : File_Attributes) return Boolean;

   --  Set the permission bits from an octal mode string.
   --  @param Attributes the attribute record to modify
   --  @param Mode       the octal permission mode string (e.g. "0644")
   --  @return True if Mode parsed and was applied, False otherwise
   function Set_Permissions_Mode
     (Attributes : in out File_Attributes; Mode : String) return Boolean;

   --  Set the numeric owner and group ids.
   --  @param Attributes the attribute record to modify
   --  @param UID        the numeric user id
   --  @param GID        the numeric group id
   procedure Set_UID_GID
     (Attributes : in out File_Attributes;
      UID        : Interfaces.Unsigned_32;
      GID        : Interfaces.Unsigned_32);

   --  Set the allocation-size attribute.
   --  @param Attributes the attribute record to modify
   --  @param Size       the allocation size in bytes
   procedure Set_Allocation_Size
     (Attributes : in out File_Attributes; Size : Interfaces.Unsigned_64);

   --  Set the textual owner and group names.
   --  @param Attributes the attribute record to modify
   --  @param Owner      the owner name
   --  @param Group      the group name
   procedure Set_Owner_Group
     (Attributes : in out File_Attributes; Owner : String; Group : String);

   --  Set the creation-time attribute.
   --  @param Attributes  the attribute record to modify
   --  @param Create_Time the creation timestamp
   --  @param Nanoseconds the sub-second nanosecond component
   procedure Set_Create_Time
     (Attributes  : in out File_Attributes;
      Create_Time : Ada.Calendar.Time;
      Nanoseconds : Interfaces.Unsigned_32 := 0);

   --  Set the ACL attribute.
   --  @param Attributes the attribute record to modify
   --  @param ACL        the access-control-list string
   procedure Set_ACL (Attributes : in out File_Attributes; ACL : String);

   --  Set the attribute bits and their valid mask.
   --  @param Attributes the attribute record to modify
   --  @param Bits       the attribute bits to set
   --  @param Valid      the mask of attribute bits that are valid
   procedure Set_Attribute_Bits
     (Attributes : in out File_Attributes;
      Bits       : Interfaces.Unsigned_32;
      Valid      : Interfaces.Unsigned_32);

   --  Set the text/binary hint attribute.
   --  @param Attributes the attribute record to modify
   --  @param Hint       the text/binary hint value
   procedure Set_Text_Hint
     (Attributes : in out File_Attributes; Hint : Interfaces.Unsigned_8);

   --  Set the MIME type attribute.
   --  @param Attributes the attribute record to modify
   --  @param Mime_Type  the MIME type string
   procedure Set_Mime_Type
     (Attributes : in out File_Attributes; Mime_Type : String);

   --  Set the link-count attribute.
   --  @param Attributes the attribute record to modify
   --  @param Count      the link count
   procedure Set_Link_Count
     (Attributes : in out File_Attributes; Count : Interfaces.Unsigned_32);

   --  Set the untranslated-name attribute.
   --  @param Attributes the attribute record to modify
   --  @param Name       the untranslated filename to store
   procedure Set_Untranslated_Name
     (Attributes : in out File_Attributes; Name : String);

   --  Retrieve the access time as an Ada.Calendar.Time.
   --  @param Attributes the attributes to apply
   --  @param Value      the retrieved timestamp
   --  @return True if the access time is known and Value was set, False otherwise
   function Access_Time_Value
     (Attributes : File_Attributes; Value : out Ada.Calendar.Time)
      return Boolean;

   --  Retrieve the modification time as an Ada.Calendar.Time.
   --  @param Attributes the attributes to apply
   --  @param Value      the retrieved timestamp
   --  @return True if the modification time is known and Value was set, False otherwise
   function Modify_Time_Value
     (Attributes : File_Attributes; Value : out Ada.Calendar.Time)
      return Boolean;

   --  Set the access and modification times.
   --  @param Attributes  the attribute record to modify
   --  @param Access_Time the access timestamp
   --  @param Modify_Time the modification timestamp
   procedure Set_Times
     (Attributes  : in out File_Attributes;
      Access_Time : Ada.Calendar.Time;
      Modify_Time : Ada.Calendar.Time);

   --  Copy selected metadata fields into a new File_Attributes value.
   --  @param Source           the attributes to copy from
   --  @param Include_Size     whether to copy the size field
   --  @param Include_UID_GID  whether to copy the numeric uid and gid
   --  @param Include_Extended whether to copy extended attributes
   --  @return a new File_Attributes value holding the selected fields
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

   --  Report whether the negotiated protocol supports a given open mode.
   --  @param Extensions the negotiated server extension set
   --  @param Mode       the file open mode
   --  @return True if the open mode is supported, False otherwise
   function Supports_Open_Mode
     (Extensions : Extension_Info; Mode : Open_Mode) return Boolean;

   --  Report whether the negotiated protocol version supports the given attributes.
   --  @param Extensions the negotiated server extension set
   --  @param Attributes the attributes to apply
   --  @param Version    the SFTP protocol version to assume
   --  @return True if the attributes are supported, False otherwise
   function Supports_Attributes
     (Extensions : Extension_Info;
      Attributes : File_Attributes;
      Version    : Natural := Protocol_Version) return Boolean;

   --  Report whether the server supports a given byte-range lock mask.
   --  @param Extensions the negotiated server extension set
   --  @param Lock_Mask  the byte-range lock type mask
   --  @return True if the lock mask is supported, False otherwise
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

   --  Report whether the object is open.
   --  @param Handle the open remote file handle
   --  @return True if open, False otherwise
   function Is_Open (Handle : File_Handle) return Boolean;
   --  Report whether the object is open.
   --  @param Item the SFTP client object
   --  @return True if open, False otherwise
   function Is_Open (Item : Client) return Boolean;
   --  Return the negotiated SFTP protocol version of the client.
   --  @param Item the SFTP client object
   --  @return the negotiated SFTP protocol version
   function Version (Item : Client) return Natural;
   --  Return the server extension advertisement negotiated by the client.
   --  @param Item the SFTP client object
   --  @return the client's negotiated extension set
   function Extensions (Item : Client) return Extension_Info;
   --  Return a snapshot of the client's negotiated version, extensions, and limits.
   --  @param Item the SFTP client object
   --  @return a snapshot of the negotiated version, extensions, and limits
   function Negotiated_Info (Item : Client) return Negotiated_Snapshot;

   --  Retrieve the server's SFTP protocol limits.
   --  @param Item   the SFTP client object
   --  @param Values the retrieved server limits
   --  @return True if limits are known and Values was set, False otherwise
   function Limits
     (Item   : Client;
      Values : out Server_Limits) return Boolean;

   --  Encode an SSH_FXP_INIT packet advertising the client protocol version.
   --  @return the encoded SSH_FXP_INIT packet
   function Encode_Init_Packet return SSH_Lib.Protocol.Buffers.Packet_Buffer;

   --  Encode an SSH_FXP_INIT packet advertising the client protocol version.
   --  @param Requested_Version the SFTP protocol version to request
   --  @return the encoded SSH_FXP_INIT packet
   function Encode_Init_Packet
     (Requested_Version : Natural)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;

   --  Parse an SSH_FXP_VERSION reply, extracting the negotiated version and any extensions.
   --  @param Packet  the raw reply packet to parse
   --  @param Version the negotiated SFTP protocol version
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Parse_Version_Packet
     (Packet : SSH_Lib.Protocol.Buffers.Packet_Buffer; Version : out Natural)
      return CryptoLib.Errors.Status;

   --  Parse an SSH_FXP_VERSION reply, extracting the negotiated version and any extensions.
   --  @param Packet     the raw reply packet to parse
   --  @param Version    the negotiated SFTP protocol version
   --  @param Extensions the parsed server extension advertisement
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Parse_Version_Packet
     (Packet     : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Version    : out Natural;
      Extensions : out Extension_Info) return CryptoLib.Errors.Status;

   --  Low-level SFTP reply parser helpers used by diagnostics and fuzzing.
   --  They validate full packet framing and accept ordinary parser failures as
   --  status returns; callers should treat runtime exceptions as defects.
   --  @param Packet        the raw reply packet to parse
   --  @param Expected_Id   the request id the reply must match
   --  @param Expected_Code the SSH_FX_* status code expected for success
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Parse_Status_Packet
     (Packet        : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Expected_Id   : Interfaces.Unsigned_32;
      Expected_Code : Interfaces.Unsigned_32 := SSH_FX_OK)
      return CryptoLib.Errors.Status;

   --  Parse an SSH_FXP_HANDLE reply and extract the returned file handle.
   --  @param Packet      the raw reply packet to parse
   --  @param Expected_Id the request id the reply must match
   --  @param Handle      the open remote file handle
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Parse_Handle_Packet
     (Packet      : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Expected_Id : Interfaces.Unsigned_32;
      Handle      : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;

   --  Parse an SSH_FXP_EXTENDED_REPLY and extract its raw reply payload.
   --  @param Packet      the raw reply packet to parse
   --  @param Expected_Id the request id the reply must match
   --  @param Reply_Data  the raw extended-reply payload
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Parse_Extended_Reply_Packet
     (Packet      : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Expected_Id : Interfaces.Unsigned_32;
      Reply_Data  : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;

   --  Parse a check-file extended reply, extracting the hash algorithm and digest.
   --  @param Packet      the raw reply packet to parse
   --  @param Expected_Id the request id the reply must match
   --  @param Algorithm   the hash algorithm actually used by the server
   --  @param Digest      the returned hash digest bytes
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Parse_Check_File_Packet
     (Packet      : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Expected_Id : Interfaces.Unsigned_32;
      Algorithm   : out Ada.Strings.Unbounded.Unbounded_String;
      Digest      : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;

   --  Parse a limits@openssh.com reply into a Server_Limits record.
   --  @param Packet      the raw reply packet to parse
   --  @param Expected_Id the request id the reply must match
   --  @param Values      the retrieved server limits
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Parse_Limits_Packet
     (Packet      : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Expected_Id : Interfaces.Unsigned_32;
      Values      : out Server_Limits) return CryptoLib.Errors.Status;

   --  Parse a statvfs@openssh.com reply into a File_System_Stats record.
   --  @param Packet      the raw reply packet to parse
   --  @param Expected_Id the request id the reply must match
   --  @param Stats       the retrieved filesystem statistics
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Parse_StatVFS_Packet
     (Packet      : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Expected_Id : Interfaces.Unsigned_32;
      Stats       : out File_System_Stats) return CryptoLib.Errors.Status;

   --  Parse an SSH_FXP_ATTRS reply into a File_Attributes record.
   --  @param Packet      the raw reply packet to parse
   --  @param Expected_Id the request id the reply must match
   --  @param Attributes  the retrieved file attributes
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Parse_Attrs_Packet
     (Packet      : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Expected_Id : Interfaces.Unsigned_32;
      Attributes  : out File_Attributes) return CryptoLib.Errors.Status;

   --  Parse an SSH_FXP_ATTRS reply into a File_Attributes record.
   --  @param Packet      the raw reply packet to parse
   --  @param Expected_Id the request id the reply must match
   --  @param Attributes  the retrieved file attributes
   --  @param Version     the SFTP protocol version to assume
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Parse_Attrs_Packet
     (Packet      : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Expected_Id : Interfaces.Unsigned_32;
      Attributes  : out File_Attributes;
      Version     : Natural) return CryptoLib.Errors.Status;

   --  Parse an SSH_FXP_DATA reply and extract the returned data bytes.
   --  @param Packet      the raw reply packet to parse
   --  @param Expected_Id the request id the reply must match
   --  @param Data_Out    the received data bytes
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Parse_Data_Packet
     (Packet      : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Expected_Id : Interfaces.Unsigned_32;
      Data_Out    : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;

   --  Parse an SSH_FXP_NAME reply, appending the returned names.
   --  @param Packet      the raw reply packet to parse
   --  @param Expected_Id the request id the reply must match
   --  @param Names       the accumulated newline-separated entry names
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Parse_Name_Packet
     (Packet      : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Expected_Id : Interfaces.Unsigned_32;
      Names       : in out Ada.Strings.Unbounded.Unbounded_String)
      return CryptoLib.Errors.Status;

   --  Parse an SSH_FXP_NAME reply, appending the returned names.
   --  @param Packet      the raw reply packet to parse
   --  @param Expected_Id the request id the reply must match
   --  @param Names       the accumulated newline-separated entry names
   --  @param Version     the SFTP protocol version to assume
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Parse_Name_Packet
     (Packet      : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Expected_Id : Interfaces.Unsigned_32;
      Names       : in out Ada.Strings.Unbounded.Unbounded_String;
      Version     : Natural) return CryptoLib.Errors.Status;

   --  Send SSH_FXP_INIT and read SSH_FXP_VERSION over an already-open
   --  ``sftp`` subsystem channel.
   --  @param Channel the initialized SFTP subsystem channel
   --  @param Version the negotiated SFTP protocol version
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Initialize
     (Channel : in out SSH_Lib.Channels.Channel; Version : out Natural)
      return CryptoLib.Errors.Status;

   --  Send SSH_FXP_INIT and read SSH_FXP_VERSION over an already-open sftp subsystem channel.
   --  @param Channel           the initialized SFTP subsystem channel
   --  @param Requested_Version the SFTP protocol version to request
   --  @param Version           the negotiated SFTP protocol version
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Initialize
     (Channel           : in out SSH_Lib.Channels.Channel;
      Requested_Version : Natural;
      Version           : out Natural) return CryptoLib.Errors.Status;

   --  Send SSH_FXP_INIT and read SSH_FXP_VERSION over an already-open sftp subsystem channel.
   --  @param Channel    the initialized SFTP subsystem channel
   --  @param Version    the negotiated SFTP protocol version
   --  @param Extensions the parsed server extension advertisement
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Initialize
     (Channel    : in out SSH_Lib.Channels.Channel;
      Version    : out Natural;
      Extensions : out Extension_Info) return CryptoLib.Errors.Status;

   --  Send SSH_FXP_INIT and read SSH_FXP_VERSION over an already-open sftp subsystem channel.
   --  @param Channel           the initialized SFTP subsystem channel
   --  @param Requested_Version the SFTP protocol version to request
   --  @param Version           the negotiated SFTP protocol version
   --  @param Extensions        the parsed server extension advertisement
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Initialize
     (Channel           : in out SSH_Lib.Channels.Channel;
      Requested_Version : Natural;
      Version           : out Natural;
      Extensions        : out Extension_Info) return CryptoLib.Errors.Status;

   --  Open the ``sftp`` subsystem on Session and initialize the SFTP protocol.
   --  Channel is left open on success and closed on initialization failure.
   --  @param Session the SSH session on which to open the SFTP subsystem
   --  @param Channel the initialized SFTP subsystem channel
   --  @param Version the negotiated SFTP protocol version
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Open
     (Session : in out SSH_Lib.Sessions.Session;
      Channel : in out SSH_Lib.Channels.Channel;
      Version : out Natural) return CryptoLib.Errors.Status;

   --  Open the sftp subsystem and initialize the SFTP protocol.
   --  @param Session           the SSH session on which to open the SFTP subsystem
   --  @param Channel           the initialized SFTP subsystem channel
   --  @param Requested_Version the SFTP protocol version to request
   --  @param Version           the negotiated SFTP protocol version
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Open
     (Session           : in out SSH_Lib.Sessions.Session;
      Channel           : in out SSH_Lib.Channels.Channel;
      Requested_Version : Natural;
      Version           : out Natural) return CryptoLib.Errors.Status;

   --  Open the sftp subsystem and initialize the SFTP protocol.
   --  @param Session    the SSH session on which to open the SFTP subsystem
   --  @param Channel    the initialized SFTP subsystem channel
   --  @param Version    the negotiated SFTP protocol version
   --  @param Extensions the parsed server extension advertisement
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Open
     (Session    : in out SSH_Lib.Sessions.Session;
      Channel    : in out SSH_Lib.Channels.Channel;
      Version    : out Natural;
      Extensions : out Extension_Info) return CryptoLib.Errors.Status;

   --  Open the sftp subsystem and initialize the SFTP protocol.
   --  @param Session           the SSH session on which to open the SFTP subsystem
   --  @param Channel           the initialized SFTP subsystem channel
   --  @param Requested_Version the SFTP protocol version to request
   --  @param Version           the negotiated SFTP protocol version
   --  @param Extensions        the parsed server extension advertisement
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Open
     (Session           : in out SSH_Lib.Sessions.Session;
      Channel           : in out SSH_Lib.Channels.Channel;
      Requested_Version : Natural;
      Version           : out Natural;
      Extensions        : out Extension_Info) return CryptoLib.Errors.Status;

   --  Open the sftp subsystem and initialize the SFTP protocol.
   --  @param Session the SSH session on which to open the SFTP subsystem
   --  @param Item    the SFTP client object
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Open
     (Session : in out SSH_Lib.Sessions.Session; Item : in out Client)
      return CryptoLib.Errors.Status;

   --  Open the sftp subsystem and initialize the SFTP protocol.
   --  @param Session           the SSH session on which to open the SFTP subsystem
   --  @param Item              the SFTP client object
   --  @param Requested_Version the SFTP protocol version to request
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Open
     (Session           : in out SSH_Lib.Sessions.Session;
      Item              : in out Client;
      Requested_Version : Natural) return CryptoLib.Errors.Status;

   --  Close an SFTP resource, releasing its server-side state.
   --  @param Item the SFTP client object
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Close (Item : in out Client) return CryptoLib.Errors.Status;

   --  Upload one regular file over an initialized SFTP channel.
   --  Remote_Path must be non-empty, contain no NUL byte, and fit within
   --  Maximum_Remote_Path_Length. Mode must be four octal digits.
   --  @param Channel     the initialized SFTP subsystem channel
   --  @param Remote_Path the target path on the remote server
   --  @param Data        the data bytes to write
   --  @param Mode        the octal permission mode string (e.g. "0644")
   --  @param Options     transfer tuning options (pipeline depth, chunk sizes, retries, verification)
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
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
   --  @param Session     the SSH session on which to open the SFTP subsystem
   --  @param Remote_Path the target path on the remote server
   --  @param Data        the data bytes to write
   --  @param Mode        the octal permission mode string (e.g. "0644")
   --  @param Options     transfer tuning options (pipeline depth, chunk sizes, retries, verification)
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Upload_Data
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Data        : Ada.Streams.Stream_Element_Array;
      Mode        : String := "0644";
      Options     : Transfer_Options := Default_Transfer_Options)
      return CryptoLib.Errors.Status;

   --  Upload in-memory data to a remote regular file.
   --  @param Item        the SFTP client object
   --  @param Remote_Path the target path on the remote server
   --  @param Data        the data bytes to write
   --  @param Mode        the octal permission mode string (e.g. "0644")
   --  @param Options     transfer tuning options (pipeline depth, chunk sizes, retries, verification)
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
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
   --  @param Channel     the initialized SFTP subsystem channel
   --  @param Remote_Path the target path on the remote server
   --  @param Size        the total number of bytes to upload
   --  @param Reader      the callback supplying the next chunk of upload data
   --  @param Mode        the octal permission mode string (e.g. "0644")
   --  @param Options     transfer tuning options (pipeline depth, chunk sizes, retries, verification)
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Upload_Stream
     (Channel     : in out SSH_Lib.Channels.Channel;
      Remote_Path : String;
      Size        : Interfaces.Unsigned_64;
      Reader      : Stream_Reader_Access;
      Mode        : String := "0644";
      Options     : Transfer_Options := Default_Transfer_Options)
      return CryptoLib.Errors.Status;

   --  Upload bytes supplied on demand by a reader callback, without staging the whole payload.
   --  @param Session     the SSH session on which to open the SFTP subsystem
   --  @param Remote_Path the target path on the remote server
   --  @param Size        the total number of bytes to upload
   --  @param Reader      the callback supplying the next chunk of upload data
   --  @param Mode        the octal permission mode string (e.g. "0644")
   --  @param Options     transfer tuning options (pipeline depth, chunk sizes, retries, verification)
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
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
   --  @param Channel     the initialized SFTP subsystem channel
   --  @param Remote_Path the target path on the remote server
   --  @param Data        the received data bytes
   --  @param Options     transfer tuning options (pipeline depth, chunk sizes, retries, verification)
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Download_Data
     (Channel     : in out SSH_Lib.Channels.Channel;
      Remote_Path : String;
      Data        : out SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Options     : Transfer_Options := Default_Transfer_Options)
      return CryptoLib.Errors.Status;

   --  Open SFTP, download one remote regular file into memory, and close the
   --  channel.
   --  @param Session     the SSH session on which to open the SFTP subsystem
   --  @param Remote_Path the target path on the remote server
   --  @param Data        the received data bytes
   --  @param Options     transfer tuning options (pipeline depth, chunk sizes, retries, verification)
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Download_Data
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Data        : out SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Options     : Transfer_Options := Default_Transfer_Options)
      return CryptoLib.Errors.Status;

   --  Download one remote regular file by passing each received chunk to
   --  Writer. Chunks are delivered in offset order and no whole-file buffer or
   --  local file is allocated by the library.
   --  @param Channel     the initialized SFTP subsystem channel
   --  @param Remote_Path the target path on the remote server
   --  @param Writer      the callback receiving each downloaded chunk
   --  @param Options     transfer tuning options (pipeline depth, chunk sizes, retries, verification)
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Download_Stream
     (Channel     : in out SSH_Lib.Channels.Channel;
      Remote_Path : String;
      Writer      : Stream_Writer_Access;
      Options     : Transfer_Options := Default_Transfer_Options)
      return CryptoLib.Errors.Status;

   --  Download a remote regular file, delivering each chunk to a writer callback.
   --  @param Session     the SSH session on which to open the SFTP subsystem
   --  @param Remote_Path the target path on the remote server
   --  @param Writer      the callback receiving each downloaded chunk
   --  @param Options     transfer tuning options (pipeline depth, chunk sizes, retries, verification)
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Download_Stream
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Writer      : Stream_Writer_Access;
      Options     : Transfer_Options := Default_Transfer_Options)
      return CryptoLib.Errors.Status;

   --  Download one remote regular file to Local_Path. Existing local files are
   --  replaced only after remote data has been read successfully.
   --  @param Channel     the initialized SFTP subsystem channel
   --  @param Remote_Path the target path on the remote server
   --  @param Local_Path  the path on the local filesystem
   --  @param Options     transfer tuning options (pipeline depth, chunk sizes, retries, verification)
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Download_File
     (Channel     : in out SSH_Lib.Channels.Channel;
      Remote_Path : String;
      Local_Path  : String;
      Options     : Transfer_Options := Default_Transfer_Options)
      return CryptoLib.Errors.Status;

   --  Download a remote regular file to a local path.
   --  @param Session     the SSH session on which to open the SFTP subsystem
   --  @param Remote_Path the target path on the remote server
   --  @param Local_Path  the path on the local filesystem
   --  @param Options     transfer tuning options (pipeline depth, chunk sizes, retries, verification)
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
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
   --  @param Channel     the initialized SFTP subsystem channel
   --  @param Remote_Path the target path on the remote server
   --  @param Local_Path  the path on the local filesystem
   --  @param Options     transfer tuning options (pipeline depth, chunk sizes, retries, verification)
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Resume_Download_File
     (Channel     : in out SSH_Lib.Channels.Channel;
      Remote_Path : String;
      Local_Path  : String;
      Options     : Transfer_Options := Default_Transfer_Options)
      return CryptoLib.Errors.Status;

   --  Resume a partial local download by appending the missing remote bytes.
   --  @param Session     the SSH session on which to open the SFTP subsystem
   --  @param Remote_Path the target path on the remote server
   --  @param Local_Path  the path on the local filesystem
   --  @param Options     transfer tuning options (pipeline depth, chunk sizes, retries, verification)
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
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
   --  @param Channel     the initialized SFTP subsystem channel
   --  @param Remote_Path the target path on the remote server
   --  @param Local_Path  the path on the local filesystem
   --  @param Mode        the octal permission mode string (e.g. "0644")
   --  @param Options     transfer tuning options (pipeline depth, chunk sizes, retries, verification)
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Resume_Upload_File
     (Channel     : in out SSH_Lib.Channels.Channel;
      Remote_Path : String;
      Local_Path  : String;
      Mode        : String := "0644";
      Options     : Transfer_Options := Default_Transfer_Options)
      return CryptoLib.Errors.Status;

   --  Resume a partial remote upload by writing the missing local suffix.
   --  @param Session     the SSH session on which to open the SFTP subsystem
   --  @param Remote_Path the target path on the remote server
   --  @param Local_Path  the path on the local filesystem
   --  @param Mode        the octal permission mode string (e.g. "0644")
   --  @param Options     transfer tuning options (pipeline depth, chunk sizes, retries, verification)
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Resume_Upload_File
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Local_Path  : String;
      Mode        : String := "0644";
      Options     : Transfer_Options := Default_Transfer_Options)
      return CryptoLib.Errors.Status;

   --  List a remote directory. Names is newline-separated UTF-8/byte-preserving
   --  Ada String data as delivered by the server, excluding no entries.
   --  @param Channel     the initialized SFTP subsystem channel
   --  @param Remote_Path the target path on the remote server
   --  @param Names       the accumulated newline-separated entry names
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function List_Directory
     (Channel     : in out SSH_Lib.Channels.Channel;
      Remote_Path : String;
      Names       : out Ada.Strings.Unbounded.Unbounded_String)
      return CryptoLib.Errors.Status;

   --  List a remote directory.
   --  @param Session     the SSH session on which to open the SFTP subsystem
   --  @param Remote_Path the target path on the remote server
   --  @param Names       the accumulated newline-separated entry names
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function List_Directory
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Names       : out Ada.Strings.Unbounded.Unbounded_String)
      return CryptoLib.Errors.Status;

   --  List a remote directory preserving name, longname, and attributes for
   --  each SSH_FXP_NAME entry returned by the server.
   --  @param Channel     the initialized SFTP subsystem channel
   --  @param Remote_Path the target path on the remote server
   --  @param Entries     the collected directory entries
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function List_Directory
     (Channel     : in out SSH_Lib.Channels.Channel;
      Remote_Path : String;
      Entries     : out Directory_Entry_Vectors.Vector)
      return CryptoLib.Errors.Status;

   --  List a remote directory.
   --  @param Session     the SSH session on which to open the SFTP subsystem
   --  @param Remote_Path the target path on the remote server
   --  @param Entries     the collected directory entries
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function List_Directory
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Entries     : out Directory_Entry_Vectors.Vector)
      return CryptoLib.Errors.Status;

   --  Stream directory entries one server page at a time. Callback is invoked
   --  once for each non-empty SSH_FXP_NAME page and may return any non-Ok
   --  status to stop enumeration after the current page.
   --  @param Channel     the initialized SFTP subsystem channel
   --  @param Remote_Path the target path on the remote server
   --  @param Callback    the callback invoked for each directory page
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function List_Directory_Paged
     (Channel     : in out SSH_Lib.Channels.Channel;
      Remote_Path : String;
      Callback    : Directory_Page_Callback_Access)
      return CryptoLib.Errors.Status;

   --  Stream a remote directory one server page at a time through a callback.
   --  @param Session     the SSH session on which to open the SFTP subsystem
   --  @param Remote_Path the target path on the remote server
   --  @param Callback    the callback invoked for each directory page
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function List_Directory_Paged
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Callback    : Directory_Page_Callback_Access)
      return CryptoLib.Errors.Status;

   --  Retrieve attributes of a remote path, following symbolic links (SSH_FXP_STAT).
   --  @param Channel     the initialized SFTP subsystem channel
   --  @param Remote_Path the target path on the remote server
   --  @param Attributes  the retrieved file attributes
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Stat
     (Channel     : in out SSH_Lib.Channels.Channel;
      Remote_Path : String;
      Attributes  : out File_Attributes) return CryptoLib.Errors.Status;

   --  Retrieve attributes of a remote path, following symbolic links (SSH_FXP_STAT).
   --  @param Session     the SSH session on which to open the SFTP subsystem
   --  @param Remote_Path the target path on the remote server
   --  @param Attributes  the retrieved file attributes
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Stat
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Attributes  : out File_Attributes) return CryptoLib.Errors.Status;

   --  Retrieve attributes of a remote path without following symbolic links (SSH_FXP_LSTAT).
   --  @param Channel     the initialized SFTP subsystem channel
   --  @param Remote_Path the target path on the remote server
   --  @param Attributes  the retrieved file attributes
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function LStat
     (Channel     : in out SSH_Lib.Channels.Channel;
      Remote_Path : String;
      Attributes  : out File_Attributes) return CryptoLib.Errors.Status;

   --  Retrieve attributes of a remote path without following symbolic links (SSH_FXP_LSTAT).
   --  @param Session     the SSH session on which to open the SFTP subsystem
   --  @param Remote_Path the target path on the remote server
   --  @param Attributes  the retrieved file attributes
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function LStat
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Attributes  : out File_Attributes) return CryptoLib.Errors.Status;

   --  Canonicalize a remote path using SSH_FXP_REALPATH.
   --  @param Channel        the initialized SFTP subsystem channel
   --  @param Remote_Path    the target path on the remote server
   --  @param Canonical_Path the canonicalized absolute path
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Realpath
     (Channel        : in out SSH_Lib.Channels.Channel;
      Remote_Path    : String;
      Canonical_Path : out Ada.Strings.Unbounded.Unbounded_String)
      return CryptoLib.Errors.Status;

   --  Canonicalize a remote path using SSH_FXP_REALPATH.
   --  @param Session        the SSH session on which to open the SFTP subsystem
   --  @param Remote_Path    the target path on the remote server
   --  @param Canonical_Path the canonicalized absolute path
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Realpath
     (Session        : in out SSH_Lib.Sessions.Session;
      Remote_Path    : String;
      Canonical_Path : out Ada.Strings.Unbounded.Unbounded_String)
      return CryptoLib.Errors.Status;

   --  Open a remote file and return its protocol handle. Handles are scoped to
   --  the initialized SFTP channel that opened them and must be closed.
   --  @param Channel     the initialized SFTP subsystem channel
   --  @param Remote_Path the target path on the remote server
   --  @param Handle      the open remote file handle
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Open_Read
     (Channel     : in out SSH_Lib.Channels.Channel;
      Remote_Path : String;
      Handle      : out File_Handle) return CryptoLib.Errors.Status;

   --  Open a remote file for reading and return its protocol handle.
   --  @param Channel     the initialized SFTP subsystem channel
   --  @param Remote_Path the target path on the remote server
   --  @param Handle      the open remote file handle
   --  @param Version     the SFTP protocol version to assume
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Open_Read
     (Channel     : in out SSH_Lib.Channels.Channel;
      Remote_Path : String;
      Handle      : out File_Handle;
      Version     : Natural) return CryptoLib.Errors.Status;

   --  Open (creating and truncating) a remote file for writing and return its handle.
   --  @param Channel     the initialized SFTP subsystem channel
   --  @param Remote_Path the target path on the remote server
   --  @param Handle      the open remote file handle
   --  @param Mode        the octal permission mode string (e.g. "0644")
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Open_Write
     (Channel     : in out SSH_Lib.Channels.Channel;
      Remote_Path : String;
      Handle      : out File_Handle;
      Mode        : String := "0644") return CryptoLib.Errors.Status;

   --  Open a remote file in a given mode and return its protocol handle.
   --  @param Channel          the initialized SFTP subsystem channel
   --  @param Remote_Path      the target path on the remote server
   --  @param Handle           the open remote file handle
   --  @param Mode             the file open mode
   --  @param Permissions_Mode the octal permission mode for a newly created file
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Open_File
     (Channel          : in out SSH_Lib.Channels.Channel;
      Remote_Path      : String;
      Handle           : out File_Handle;
      Mode             : Open_Mode;
      Permissions_Mode : String := "0644") return CryptoLib.Errors.Status;

   --  Open a remote file in a given mode and return its protocol handle.
   --  @param Channel          the initialized SFTP subsystem channel
   --  @param Remote_Path      the target path on the remote server
   --  @param Handle           the open remote file handle
   --  @param Mode             the file open mode
   --  @param Permissions_Mode the octal permission mode for a newly created file
   --  @param Version          the SFTP protocol version to assume
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Open_File
     (Channel          : in out SSH_Lib.Channels.Channel;
      Remote_Path      : String;
      Handle           : out File_Handle;
      Mode             : Open_Mode;
      Permissions_Mode : String;
      Version          : Natural) return CryptoLib.Errors.Status;

   --  Read bytes from a file at a given offset (SSH_FXP_READ).
   --  @param Channel the initialized SFTP subsystem channel
   --  @param Handle  the open remote file handle
   --  @param Offset  the byte offset within the file
   --  @param Length  the number of bytes
   --  @param Data    the received data bytes
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Read_At
     (Channel : in out SSH_Lib.Channels.Channel;
      Handle  : File_Handle;
      Offset  : Interfaces.Unsigned_64;
      Length  : Natural;
      Data    : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;

   --  Write bytes to a file at a given offset (SSH_FXP_WRITE).
   --  @param Channel the initialized SFTP subsystem channel
   --  @param Handle  the open remote file handle
   --  @param Offset  the byte offset within the file
   --  @param Data    the data bytes to write
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Write_At
     (Channel : in out SSH_Lib.Channels.Channel;
      Handle  : File_Handle;
      Offset  : Interfaces.Unsigned_64;
      Data    : Ada.Streams.Stream_Element_Array) return CryptoLib.Errors.Status;

   --  Download a byte range of a remote file into memory.
   --  @param Channel     the initialized SFTP subsystem channel
   --  @param Remote_Path the target path on the remote server
   --  @param Offset      the byte offset within the file
   --  @param Length      the number of bytes
   --  @param Data        the received data bytes
   --  @param Options     transfer tuning options (pipeline depth, chunk sizes, retries, verification)
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Download_Data
     (Channel     : in out SSH_Lib.Channels.Channel;
      Remote_Path : String;
      Offset      : Interfaces.Unsigned_64;
      Length      : Natural;
      Data        : out SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Options     : Transfer_Options := Default_Transfer_Options)
      return CryptoLib.Errors.Status;

   --  Write in-memory data to a remote file starting at a given byte offset.
   --  @param Channel     the initialized SFTP subsystem channel
   --  @param Remote_Path the target path on the remote server
   --  @param Offset      the byte offset within the file
   --  @param Data        the data bytes to write
   --  @param Mode        the octal permission mode string (e.g. "0644")
   --  @param Options     transfer tuning options (pipeline depth, chunk sizes, retries, verification)
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Upload_Data
     (Channel     : in out SSH_Lib.Channels.Channel;
      Remote_Path : String;
      Offset      : Interfaces.Unsigned_64;
      Data        : Ada.Streams.Stream_Element_Array;
      Mode        : String := "0644";
      Options     : Transfer_Options := Default_Transfer_Options)
      return CryptoLib.Errors.Status;

   --  Read bytes from a file at a given offset (SSH_FXP_READ).
   --  @param Session     the SSH session on which to open the SFTP subsystem
   --  @param Remote_Path the target path on the remote server
   --  @param Offset      the byte offset within the file
   --  @param Length      the number of bytes
   --  @param Data        the received data bytes
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Read_At
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Offset      : Interfaces.Unsigned_64;
      Length      : Natural;
      Data        : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;

   --  Write bytes to a file at a given offset (SSH_FXP_WRITE).
   --  @param Session     the SSH session on which to open the SFTP subsystem
   --  @param Remote_Path the target path on the remote server
   --  @param Offset      the byte offset within the file
   --  @param Data        the data bytes to write
   --  @param Mode        the octal permission mode string (e.g. "0644")
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Write_At
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Offset      : Interfaces.Unsigned_64;
      Data        : Ada.Streams.Stream_Element_Array;
      Mode        : String := "0644") return CryptoLib.Errors.Status;

   --  Retrieve attributes of an open remote file (SSH_FXP_FSTAT).
   --  @param Session     the SSH session on which to open the SFTP subsystem
   --  @param Remote_Path the target path on the remote server
   --  @param Attributes  the retrieved file attributes
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function FStat
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Attributes  : out File_Attributes) return CryptoLib.Errors.Status;

   --  Set the permission bits of an open file handle (SSH_FXP_FSETSTAT).
   --  @param Session     the SSH session on which to open the SFTP subsystem
   --  @param Remote_Path the target path on the remote server
   --  @param Mode        the octal permission mode string (e.g. "0644")
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Set_Handle_Permissions
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Mode        : String) return CryptoLib.Errors.Status;

   --  Set attributes on an open file handle (SSH_FXP_FSETSTAT).
   --  @param Session     the SSH session on which to open the SFTP subsystem
   --  @param Remote_Path the target path on the remote server
   --  @param Attributes  the attributes to apply
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Set_Handle_Attributes
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Attributes  : File_Attributes) return CryptoLib.Errors.Status;

   --  Close an SFTP resource, releasing its server-side state.
   --  @param Channel the initialized SFTP subsystem channel
   --  @param Handle  the open remote file handle
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Close
     (Channel : in out SSH_Lib.Channels.Channel; Handle : in out File_Handle)
      return CryptoLib.Errors.Status;

   --  Close an SFTP resource, releasing its server-side state.
   --  @param Channel the initialized SFTP subsystem channel
   --  @param Handle  the open remote file handle
   --  @param Result  detailed operation result: remote status code, symbolic name, and message
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Close
     (Channel : in out SSH_Lib.Channels.Channel;
      Handle  : in out File_Handle;
      Result  : out SFTP_Result) return CryptoLib.Errors.Status;

   --  Retrieve attributes of an open remote file (SSH_FXP_FSTAT).
   --  @param Channel    the initialized SFTP subsystem channel
   --  @param Handle     the open remote file handle
   --  @param Attributes the retrieved file attributes
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function FStat
     (Channel    : in out SSH_Lib.Channels.Channel;
      Handle     : File_Handle;
      Attributes : out File_Attributes) return CryptoLib.Errors.Status;

   --  Retrieve attributes of an open remote file (SSH_FXP_FSTAT).
   --  @param Channel    the initialized SFTP subsystem channel
   --  @param Handle     the open remote file handle
   --  @param Attributes the retrieved file attributes
   --  @param Result     detailed operation result: remote status code, symbolic name, and message
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function FStat
     (Channel    : in out SSH_Lib.Channels.Channel;
      Handle     : File_Handle;
      Attributes : out File_Attributes;
      Result     : out SFTP_Result) return CryptoLib.Errors.Status;

   --  Set the permission bits of an open file handle (SSH_FXP_FSETSTAT).
   --  @param Channel the initialized SFTP subsystem channel
   --  @param Handle  the open remote file handle
   --  @param Mode    the octal permission mode string (e.g. "0644")
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Set_Handle_Permissions
     (Channel : in out SSH_Lib.Channels.Channel;
      Handle  : File_Handle;
      Mode    : String) return CryptoLib.Errors.Status;

   --  Set the permission bits of an open file handle (SSH_FXP_FSETSTAT).
   --  @param Channel the initialized SFTP subsystem channel
   --  @param Handle  the open remote file handle
   --  @param Mode    the octal permission mode string (e.g. "0644")
   --  @param Result  detailed operation result: remote status code, symbolic name, and message
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Set_Handle_Permissions
     (Channel : in out SSH_Lib.Channels.Channel;
      Handle  : File_Handle;
      Mode    : String;
      Result  : out SFTP_Result) return CryptoLib.Errors.Status;

   --  Set attributes on an open file handle (SSH_FXP_FSETSTAT).
   --  @param Channel    the initialized SFTP subsystem channel
   --  @param Handle     the open remote file handle
   --  @param Attributes the attributes to apply
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Set_Handle_Attributes
     (Channel    : in out SSH_Lib.Channels.Channel;
      Handle     : File_Handle;
      Attributes : File_Attributes) return CryptoLib.Errors.Status;

   --  Set attributes on an open file handle (SSH_FXP_FSETSTAT).
   --  @param Channel    the initialized SFTP subsystem channel
   --  @param Handle     the open remote file handle
   --  @param Attributes the attributes to apply
   --  @param Result     detailed operation result: remote status code, symbolic name, and message
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Set_Handle_Attributes
     (Channel    : in out SSH_Lib.Channels.Channel;
      Handle     : File_Handle;
      Attributes : File_Attributes;
      Result     : out SFTP_Result) return CryptoLib.Errors.Status;

   --  Set the permission bits of a remote path (SSH_FXP_SETSTAT).
   --  @param Channel     the initialized SFTP subsystem channel
   --  @param Remote_Path the target path on the remote server
   --  @param Mode        the octal permission mode string (e.g. "0644")
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Set_Permissions
     (Channel     : in out SSH_Lib.Channels.Channel;
      Remote_Path : String;
      Mode        : String) return CryptoLib.Errors.Status;

   --  Set the permission bits of a remote path (SSH_FXP_SETSTAT).
   --  @param Session     the SSH session on which to open the SFTP subsystem
   --  @param Remote_Path the target path on the remote server
   --  @param Mode        the octal permission mode string (e.g. "0644")
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Set_Permissions
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Mode        : String) return CryptoLib.Errors.Status;

   --  Set attributes on a remote path (SSH_FXP_SETSTAT).
   --  @param Channel     the initialized SFTP subsystem channel
   --  @param Remote_Path the target path on the remote server
   --  @param Attributes  the attributes to apply
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Set_Attributes
     (Channel     : in out SSH_Lib.Channels.Channel;
      Remote_Path : String;
      Attributes  : File_Attributes) return CryptoLib.Errors.Status;

   --  Set attributes on a remote path (SSH_FXP_SETSTAT).
   --  @param Session     the SSH session on which to open the SFTP subsystem
   --  @param Remote_Path the target path on the remote server
   --  @param Attributes  the attributes to apply
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Set_Attributes
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Attributes  : File_Attributes) return CryptoLib.Errors.Status;

   --  Set the owner and group of a remote path.
   --  @param Session     the SSH session on which to open the SFTP subsystem
   --  @param Remote_Path the target path on the remote server
   --  @param Owner       the owner name
   --  @param Group       the group name
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Set_Path_Owner_Group
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Owner       : String;
      Group       : String) return CryptoLib.Errors.Status;

   --  Set the MIME type attribute of a remote path.
   --  @param Session     the SSH session on which to open the SFTP subsystem
   --  @param Remote_Path the target path on the remote server
   --  @param Mime_Type   the MIME type string
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Set_Path_Mime_Type
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Mime_Type   : String) return CryptoLib.Errors.Status;

   --  Set the ACL attribute of a remote path.
   --  @param Session     the SSH session on which to open the SFTP subsystem
   --  @param Remote_Path the target path on the remote server
   --  @param ACL         the access-control-list string
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Set_Path_ACL
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      ACL         : String) return CryptoLib.Errors.Status;

   --  Set the attribute bits and their valid mask on a remote path.
   --  @param Session     the SSH session on which to open the SFTP subsystem
   --  @param Remote_Path the target path on the remote server
   --  @param Bits        the attribute bits to set
   --  @param Valid       the mask of attribute bits that are valid
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Set_Path_Attribute_Bits
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Bits        : Interfaces.Unsigned_32;
      Valid       : Interfaces.Unsigned_32) return CryptoLib.Errors.Status;

   --  Set the text/binary hint attribute of a remote path.
   --  @param Session     the SSH session on which to open the SFTP subsystem
   --  @param Remote_Path the target path on the remote server
   --  @param Hint        the text/binary hint value
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Set_Path_Text_Hint
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Hint        : Interfaces.Unsigned_8) return CryptoLib.Errors.Status;

   --  Create a remote directory (SSH_FXP_MKDIR).
   --  @param Channel     the initialized SFTP subsystem channel
   --  @param Remote_Path the target path on the remote server
   --  @param Mode        the octal permission mode string (e.g. "0644")
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Make_Directory
     (Channel     : in out SSH_Lib.Channels.Channel;
      Remote_Path : String;
      Mode        : String := "0755") return CryptoLib.Errors.Status;

   --  Create a remote directory (SSH_FXP_MKDIR).
   --  @param Session     the SSH session on which to open the SFTP subsystem
   --  @param Remote_Path the target path on the remote server
   --  @param Mode        the octal permission mode string (e.g. "0644")
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Make_Directory
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Mode        : String := "0755") return CryptoLib.Errors.Status;

   --  Remove a remote directory (SSH_FXP_RMDIR).
   --  @param Channel     the initialized SFTP subsystem channel
   --  @param Remote_Path the target path on the remote server
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Remove_Directory
     (Channel : in out SSH_Lib.Channels.Channel; Remote_Path : String)
      return CryptoLib.Errors.Status;

   --  Remove a remote directory (SSH_FXP_RMDIR).
   --  @param Session     the SSH session on which to open the SFTP subsystem
   --  @param Remote_Path the target path on the remote server
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Remove_Directory
     (Session : in out SSH_Lib.Sessions.Session; Remote_Path : String)
      return CryptoLib.Errors.Status;

   --  Remove a remote file (SSH_FXP_REMOVE).
   --  @param Channel     the initialized SFTP subsystem channel
   --  @param Remote_Path the target path on the remote server
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Remove_File
     (Channel : in out SSH_Lib.Channels.Channel; Remote_Path : String)
      return CryptoLib.Errors.Status;

   --  Remove a remote file (SSH_FXP_REMOVE).
   --  @param Channel     the initialized SFTP subsystem channel
   --  @param Remote_Path the target path on the remote server
   --  @param Result      detailed operation result: remote status code, symbolic name, and message
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Remove_File
     (Channel     : in out SSH_Lib.Channels.Channel;
      Remote_Path : String;
      Result      : out SFTP_Result) return CryptoLib.Errors.Status;

   --  Remove a remote file (SSH_FXP_REMOVE).
   --  @param Session     the SSH session on which to open the SFTP subsystem
   --  @param Remote_Path the target path on the remote server
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Remove_File
     (Session : in out SSH_Lib.Sessions.Session; Remote_Path : String)
      return CryptoLib.Errors.Status;

   --  Remove a remote file (SSH_FXP_REMOVE).
   --  @param Session     the SSH session on which to open the SFTP subsystem
   --  @param Remote_Path the target path on the remote server
   --  @param Result      detailed operation result: remote status code, symbolic name, and message
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
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
   --  @param Channel        the initialized SFTP subsystem channel
   --  @param Remote_Path    the target path on the remote server
   --  @param Local_Path     the path on the local filesystem
   --  @param Directory_Mode the octal mode for created directories
   --  @param File_Mode      the octal mode for created files
   --  @param Options        recursive-traversal options (filter, progress, overwrite, symlink handling)
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Upload_Directory
     (Channel        : in out SSH_Lib.Channels.Channel;
      Remote_Path    : String;
      Local_Path     : String;
      Directory_Mode : String := "0755";
      File_Mode      : String := "0644";
      Options        : Recursive_Options := Default_Recursive_Options)
      return CryptoLib.Errors.Status;

   --  Recursively upload a local directory tree to a remote path.
   --  @param Session        the SSH session on which to open the SFTP subsystem
   --  @param Remote_Path    the target path on the remote server
   --  @param Local_Path     the path on the local filesystem
   --  @param Directory_Mode the octal mode for created directories
   --  @param File_Mode      the octal mode for created files
   --  @param Options        recursive-traversal options (filter, progress, overwrite, symlink handling)
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
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
   --  @param Channel     the initialized SFTP subsystem channel
   --  @param Remote_Path the target path on the remote server
   --  @param Local_Path  the path on the local filesystem
   --  @param Options     recursive-traversal options (filter, progress, overwrite, symlink handling)
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Download_Directory
     (Channel     : in out SSH_Lib.Channels.Channel;
      Remote_Path : String;
      Local_Path  : String;
      Options     : Recursive_Options := Default_Recursive_Options)
      return CryptoLib.Errors.Status;

   --  Recursively download a remote directory tree to a local path.
   --  @param Session     the SSH session on which to open the SFTP subsystem
   --  @param Remote_Path the target path on the remote server
   --  @param Local_Path  the path on the local filesystem
   --  @param Options     recursive-traversal options (filter, progress, overwrite, symlink handling)
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Download_Directory
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Local_Path  : String;
      Options     : Recursive_Options := Default_Recursive_Options)
      return CryptoLib.Errors.Status;

   --  Recursively remove a remote file or directory tree. Symbolic links are
   --  removed as links when the server reports symlink permissions.
   --  @param Channel     the initialized SFTP subsystem channel
   --  @param Remote_Path the target path on the remote server
   --  @param Options     recursive-traversal options (filter, progress, overwrite, symlink handling)
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Remove_Tree
     (Channel     : in out SSH_Lib.Channels.Channel;
      Remote_Path : String;
      Options     : Recursive_Options := Default_Recursive_Options)
      return CryptoLib.Errors.Status;

   --  Recursively remove a remote file or directory tree.
   --  @param Session     the SSH session on which to open the SFTP subsystem
   --  @param Remote_Path the target path on the remote server
   --  @param Options     recursive-traversal options (filter, progress, overwrite, symlink handling)
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Remove_Tree
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Options     : Recursive_Options := Default_Recursive_Options)
      return CryptoLib.Errors.Status;

   --  Recursively copy a remote file or directory tree to another remote path
   --  over the same initialized SFTP channel. File contents are copied through
   --  the client using the existing download/upload primitives.
   --  @param Channel            the initialized SFTP subsystem channel
   --  @param Source_Remote_Path the source remote path
   --  @param Target_Remote_Path the destination remote path
   --  @param Directory_Mode     the octal mode for created directories
   --  @param File_Mode          the octal mode for created files
   --  @param Options            recursive-traversal options (filter, progress, overwrite, symlink handling)
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Copy_Tree
     (Channel            : in out SSH_Lib.Channels.Channel;
      Source_Remote_Path : String;
      Target_Remote_Path : String;
      Directory_Mode     : String := "0755";
      File_Mode          : String := "0644";
      Options            : Recursive_Options := Default_Recursive_Options)
      return CryptoLib.Errors.Status;

   --  Recursively copy a remote file or directory tree to another remote path.
   --  @param Session            the SSH session on which to open the SFTP subsystem
   --  @param Source_Remote_Path the source remote path
   --  @param Target_Remote_Path the destination remote path
   --  @param Directory_Mode     the octal mode for created directories
   --  @param File_Mode          the octal mode for created files
   --  @param Options            recursive-traversal options (filter, progress, overwrite, symlink handling)
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Copy_Tree
     (Session            : in out SSH_Lib.Sessions.Session;
      Source_Remote_Path : String;
      Target_Remote_Path : String;
      Directory_Mode     : String := "0755";
      File_Mode          : String := "0644";
      Options            : Recursive_Options := Default_Recursive_Options)
      return CryptoLib.Errors.Status;

   --  Synchronize a directory tree between local and remote in a given direction.
   --  @param Channel        the initialized SFTP subsystem channel
   --  @param Direction      the synchronization direction (upload or download)
   --  @param Remote_Path    the target path on the remote server
   --  @param Local_Path     the path on the local filesystem
   --  @param Directory_Mode the octal mode for created directories
   --  @param File_Mode      the octal mode for created files
   --  @param Options        synchronization options (deletion of extras, skip-unchanged)
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Sync_Directory
     (Channel        : in out SSH_Lib.Channels.Channel;
      Direction      : Sync_Direction;
      Remote_Path    : String;
      Local_Path     : String;
      Directory_Mode : String := "0755";
      File_Mode      : String := "0644";
      Options        : Sync_Options := Default_Sync_Options)
      return CryptoLib.Errors.Status;

   --  Synchronize a directory tree between local and remote in a given direction.
   --  @param Session        the SSH session on which to open the SFTP subsystem
   --  @param Direction      the synchronization direction (upload or download)
   --  @param Remote_Path    the target path on the remote server
   --  @param Local_Path     the path on the local filesystem
   --  @param Directory_Mode the octal mode for created directories
   --  @param File_Mode      the octal mode for created files
   --  @param Options        synchronization options (deletion of extras, skip-unchanged)
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Sync_Directory
     (Session        : in out SSH_Lib.Sessions.Session;
      Direction      : Sync_Direction;
      Remote_Path    : String;
      Local_Path     : String;
      Directory_Mode : String := "0755";
      File_Mode      : String := "0644";
      Options        : Sync_Options := Default_Sync_Options)
      return CryptoLib.Errors.Status;

   --  Rename a remote path (SSH_FXP_RENAME).
   --  @param Channel  the initialized SFTP subsystem channel
   --  @param Old_Path the current remote path
   --  @param New_Path the new remote path
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Rename
     (Channel  : in out SSH_Lib.Channels.Channel;
      Old_Path : String;
      New_Path : String) return CryptoLib.Errors.Status;

   --  Rename a remote path (SSH_FXP_RENAME).
   --  @param Channel  the initialized SFTP subsystem channel
   --  @param Old_Path the current remote path
   --  @param New_Path the new remote path
   --  @param Result   detailed operation result: remote status code, symbolic name, and message
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Rename
     (Channel  : in out SSH_Lib.Channels.Channel;
      Old_Path : String;
      New_Path : String;
      Result   : out SFTP_Result) return CryptoLib.Errors.Status;

   --  Rename a remote path (SSH_FXP_RENAME).
   --  @param Session  the SSH session on which to open the SFTP subsystem
   --  @param Old_Path the current remote path
   --  @param New_Path the new remote path
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Rename
     (Session  : in out SSH_Lib.Sessions.Session;
      Old_Path : String;
      New_Path : String) return CryptoLib.Errors.Status;

   --  Rename a remote path (SSH_FXP_RENAME).
   --  @param Session  the SSH session on which to open the SFTP subsystem
   --  @param Old_Path the current remote path
   --  @param New_Path the new remote path
   --  @param Result   detailed operation result: remote status code, symbolic name, and message
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Rename
     (Session  : in out SSH_Lib.Sessions.Session;
      Old_Path : String;
      New_Path : String;
      Result   : out SFTP_Result) return CryptoLib.Errors.Status;

   --  Atomically rename a remote path using the posix-rename@openssh.com extension.
   --  @param Channel  the initialized SFTP subsystem channel
   --  @param Old_Path the current remote path
   --  @param New_Path the new remote path
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Posix_Rename
     (Channel  : in out SSH_Lib.Channels.Channel;
      Old_Path : String;
      New_Path : String) return CryptoLib.Errors.Status;

   --  Atomically rename a remote path using the posix-rename@openssh.com extension.
   --  @param Channel  the initialized SFTP subsystem channel
   --  @param Old_Path the current remote path
   --  @param New_Path the new remote path
   --  @param Result   detailed operation result: remote status code, symbolic name, and message
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Posix_Rename
     (Channel  : in out SSH_Lib.Channels.Channel;
      Old_Path : String;
      New_Path : String;
      Result   : out SFTP_Result) return CryptoLib.Errors.Status;

   --  Atomically rename a remote path using the posix-rename@openssh.com extension.
   --  @param Session  the SSH session on which to open the SFTP subsystem
   --  @param Old_Path the current remote path
   --  @param New_Path the new remote path
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Posix_Rename
     (Session  : in out SSH_Lib.Sessions.Session;
      Old_Path : String;
      New_Path : String) return CryptoLib.Errors.Status;

   --  Atomically rename a remote path using the posix-rename@openssh.com extension.
   --  @param Session  the SSH session on which to open the SFTP subsystem
   --  @param Old_Path the current remote path
   --  @param New_Path the new remote path
   --  @param Result   detailed operation result: remote status code, symbolic name, and message
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Posix_Rename
     (Session  : in out SSH_Lib.Sessions.Session;
      Old_Path : String;
      New_Path : String;
      Result   : out SFTP_Result) return CryptoLib.Errors.Status;

   --  Create a hard link using the hardlink@openssh.com extension.
   --  @param Channel  the initialized SFTP subsystem channel
   --  @param Old_Path the current remote path
   --  @param New_Path the new remote path
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Hardlink
     (Channel  : in out SSH_Lib.Channels.Channel;
      Old_Path : String;
      New_Path : String) return CryptoLib.Errors.Status;

   --  Create a hard link using the hardlink@openssh.com extension.
   --  @param Channel  the initialized SFTP subsystem channel
   --  @param Old_Path the current remote path
   --  @param New_Path the new remote path
   --  @param Result   detailed operation result: remote status code, symbolic name, and message
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Hardlink
     (Channel  : in out SSH_Lib.Channels.Channel;
      Old_Path : String;
      New_Path : String;
      Result   : out SFTP_Result) return CryptoLib.Errors.Status;

   --  Create a hard link using the hardlink@openssh.com extension.
   --  @param Session  the SSH session on which to open the SFTP subsystem
   --  @param Old_Path the current remote path
   --  @param New_Path the new remote path
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Hardlink
     (Session  : in out SSH_Lib.Sessions.Session;
      Old_Path : String;
      New_Path : String) return CryptoLib.Errors.Status;

   --  Create a hard link using the hardlink@openssh.com extension.
   --  @param Session  the SSH session on which to open the SFTP subsystem
   --  @param Old_Path the current remote path
   --  @param New_Path the new remote path
   --  @param Result   detailed operation result: remote status code, symbolic name, and message
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Hardlink
     (Session  : in out SSH_Lib.Sessions.Session;
      Old_Path : String;
      New_Path : String;
      Result   : out SFTP_Result) return CryptoLib.Errors.Status;

   --  Flush a remote file to stable storage using the fsync@openssh.com extension.
   --  @param Channel the initialized SFTP subsystem channel
   --  @param Handle  the open remote file handle
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Fsync
     (Channel : in out SSH_Lib.Channels.Channel; Handle : File_Handle)
      return CryptoLib.Errors.Status;

   --  Flush a remote file to stable storage using the fsync@openssh.com extension.
   --  @param Channel the initialized SFTP subsystem channel
   --  @param Handle  the open remote file handle
   --  @param Result  detailed operation result: remote status code, symbolic name, and message
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Fsync
     (Channel : in out SSH_Lib.Channels.Channel;
      Handle  : File_Handle;
      Result  : out SFTP_Result) return CryptoLib.Errors.Status;

   --  Flush a remote file to stable storage using the fsync@openssh.com extension.
   --  @param Session     the SSH session on which to open the SFTP subsystem
   --  @param Remote_Path the target path on the remote server
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Fsync
     (Session : in out SSH_Lib.Sessions.Session; Remote_Path : String)
      return CryptoLib.Errors.Status;

   --  Flush a remote file to stable storage using the fsync@openssh.com extension.
   --  @param Session     the SSH session on which to open the SFTP subsystem
   --  @param Remote_Path the target path on the remote server
   --  @param Result      detailed operation result: remote status code, symbolic name, and message
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Fsync
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Result      : out SFTP_Result) return CryptoLib.Errors.Status;

   --  Expand a remote path using the expand-path@openssh.com extension.
   --  @param Channel       the initialized SFTP subsystem channel
   --  @param Remote_Path   the target path on the remote server
   --  @param Expanded_Path the expanded absolute path
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Expand_Path
     (Channel       : in out SSH_Lib.Channels.Channel;
      Remote_Path   : String;
      Expanded_Path : out Ada.Strings.Unbounded.Unbounded_String)
      return CryptoLib.Errors.Status;

   --  Expand a remote path using the expand-path@openssh.com extension.
   --  @param Channel       the initialized SFTP subsystem channel
   --  @param Remote_Path   the target path on the remote server
   --  @param Expanded_Path the expanded absolute path
   --  @param Result        detailed operation result: remote status code, symbolic name, and message
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Expand_Path
     (Channel       : in out SSH_Lib.Channels.Channel;
      Remote_Path   : String;
      Expanded_Path : out Ada.Strings.Unbounded.Unbounded_String;
      Result        : out SFTP_Result) return CryptoLib.Errors.Status;

   --  Expand a remote path using the expand-path@openssh.com extension.
   --  @param Session       the SSH session on which to open the SFTP subsystem
   --  @param Remote_Path   the target path on the remote server
   --  @param Expanded_Path the expanded absolute path
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Expand_Path
     (Session       : in out SSH_Lib.Sessions.Session;
      Remote_Path   : String;
      Expanded_Path : out Ada.Strings.Unbounded.Unbounded_String)
      return CryptoLib.Errors.Status;

   --  Expand a remote path using the expand-path@openssh.com extension.
   --  @param Session       the SSH session on which to open the SFTP subsystem
   --  @param Remote_Path   the target path on the remote server
   --  @param Expanded_Path the expanded absolute path
   --  @param Result        detailed operation result: remote status code, symbolic name, and message
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Expand_Path
     (Session       : in out SSH_Lib.Sessions.Session;
      Remote_Path   : String;
      Expanded_Path : out Ada.Strings.Unbounded.Unbounded_String;
      Result        : out SFTP_Result) return CryptoLib.Errors.Status;

   --  Expand a remote path using the expand-path@openssh.com extension.
   --  @param Item          the SFTP client object
   --  @param Remote_Path   the target path on the remote server
   --  @param Expanded_Path the expanded absolute path
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Expand_Path
     (Item          : in out Client;
      Remote_Path   : String;
      Expanded_Path : out Ada.Strings.Unbounded.Unbounded_String)
      return CryptoLib.Errors.Status;

   --  Expand a remote path using the expand-path@openssh.com extension.
   --  @param Item          the SFTP client object
   --  @param Remote_Path   the target path on the remote server
   --  @param Expanded_Path the expanded absolute path
   --  @param Result        detailed operation result: remote status code, symbolic name, and message
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Expand_Path
     (Item          : in out Client;
      Remote_Path   : String;
      Expanded_Path : out Ada.Strings.Unbounded.Unbounded_String;
      Result        : out SFTP_Result) return CryptoLib.Errors.Status;

   --  Compute one or more content hashes of a remote file using the check-file extension.
   --  @param Channel    the initialized SFTP subsystem channel
   --  @param Handle     the open remote file handle
   --  @param Algorithms the ordered list of acceptable hash algorithm names
   --  @param Offset     the byte offset within the file
   --  @param Length     the number of bytes
   --  @param Block_Size the hash block size in bytes (0 for a single digest over the whole range)
   --  @param Algorithm  the hash algorithm actually used by the server
   --  @param Digest     the returned hash digest bytes
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
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

   --  Compute remote file content hashes via the check-file extension, returning a Check_File_Result.
   --  @param Channel    the initialized SFTP subsystem channel
   --  @param Handle     the open remote file handle
   --  @param Algorithms the ordered list of acceptable hash algorithm names
   --  @param Offset     the byte offset within the file
   --  @param Length     the number of bytes
   --  @param Block_Size the hash block size in bytes (0 for a single digest over the whole range)
   --  @return a Check_File_Result with the algorithm, digest, and status
   function Check_File_Info
     (Channel    : in out SSH_Lib.Channels.Channel;
      Handle     : File_Handle;
      Algorithms : String;
      Offset     : Interfaces.Unsigned_64 := 0;
      Length     : Interfaces.Unsigned_64 := 0;
      Block_Size : Interfaces.Unsigned_32 := 0) return Check_File_Result;

   --  Compute one or more content hashes of a remote file using the check-file extension.
   --  @param Session     the SSH session on which to open the SFTP subsystem
   --  @param Remote_Path the target path on the remote server
   --  @param Algorithms  the ordered list of acceptable hash algorithm names
   --  @param Offset      the byte offset within the file
   --  @param Length      the number of bytes
   --  @param Block_Size  the hash block size in bytes (0 for a single digest over the whole range)
   --  @param Algorithm   the hash algorithm actually used by the server
   --  @param Digest      the returned hash digest bytes
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
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

   --  Compute one or more content hashes of a remote file using the check-file extension.
   --  @param Session     the SSH session on which to open the SFTP subsystem
   --  @param Remote_Path the target path on the remote server
   --  @param Algorithms  the ordered list of acceptable hash algorithm names
   --  @param Offset      the byte offset within the file
   --  @param Length      the number of bytes
   --  @param Block_Size  the hash block size in bytes (0 for a single digest over the whole range)
   --  @param Algorithm   the hash algorithm actually used by the server
   --  @param Digest      the returned hash digest bytes
   --  @param Result      detailed operation result: remote status code, symbolic name, and message
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
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

   --  Compute one or more content hashes of a remote file using the check-file extension.
   --  @param Item        the SFTP client object
   --  @param Remote_Path the target path on the remote server
   --  @param Algorithms  the ordered list of acceptable hash algorithm names
   --  @param Offset      the byte offset within the file
   --  @param Length      the number of bytes
   --  @param Block_Size  the hash block size in bytes (0 for a single digest over the whole range)
   --  @param Algorithm   the hash algorithm actually used by the server
   --  @param Digest      the returned hash digest bytes
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
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

   --  Compute one or more content hashes of a remote file using the check-file extension.
   --  @param Item        the SFTP client object
   --  @param Remote_Path the target path on the remote server
   --  @param Algorithms  the ordered list of acceptable hash algorithm names
   --  @param Offset      the byte offset within the file
   --  @param Length      the number of bytes
   --  @param Block_Size  the hash block size in bytes (0 for a single digest over the whole range)
   --  @param Algorithm   the hash algorithm actually used by the server
   --  @param Digest      the returned hash digest bytes
   --  @param Result      detailed operation result: remote status code, symbolic name, and message
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
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

   --  Compute remote file content hashes via the check-file extension, returning a Check_File_Result.
   --  @param Session     the SSH session on which to open the SFTP subsystem
   --  @param Remote_Path the target path on the remote server
   --  @param Algorithms  the ordered list of acceptable hash algorithm names
   --  @param Offset      the byte offset within the file
   --  @param Length      the number of bytes
   --  @param Block_Size  the hash block size in bytes (0 for a single digest over the whole range)
   --  @return a Check_File_Result with the algorithm, digest, and status
   function Check_File_Info
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Algorithms  : String;
      Offset      : Interfaces.Unsigned_64 := 0;
      Length      : Interfaces.Unsigned_64 := 0;
      Block_Size  : Interfaces.Unsigned_32 := 0) return Check_File_Result;

   --  Compute remote file content hashes via the check-file extension, returning a Check_File_Result.
   --  @param Item        the SFTP client object
   --  @param Remote_Path the target path on the remote server
   --  @param Algorithms  the ordered list of acceptable hash algorithm names
   --  @param Offset      the byte offset within the file
   --  @param Length      the number of bytes
   --  @param Block_Size  the hash block size in bytes (0 for a single digest over the whole range)
   --  @return a Check_File_Result with the algorithm, digest, and status
   function Check_File_Info
     (Item        : in out Client;
      Remote_Path : String;
      Algorithms  : String;
      Offset      : Interfaces.Unsigned_64 := 0;
      Length      : Interfaces.Unsigned_64 := 0;
      Block_Size  : Interfaces.Unsigned_32 := 0) return Check_File_Result;

   --  Copy a byte range between two open handles using the copy-data extension.
   --  @param Channel       the initialized SFTP subsystem channel
   --  @param Source_Handle the open source file handle
   --  @param Source_Offset the starting byte offset in the source
   --  @param Length        the number of bytes
   --  @param Target_Handle the open destination file handle
   --  @param Target_Offset the starting byte offset in the target
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Copy_Data
     (Channel       : in out SSH_Lib.Channels.Channel;
      Source_Handle : File_Handle;
      Source_Offset : Interfaces.Unsigned_64;
      Length        : Interfaces.Unsigned_64;
      Target_Handle : File_Handle;
      Target_Offset : Interfaces.Unsigned_64) return CryptoLib.Errors.Status;

   --  Copy a byte range between two open handles using the copy-data extension.
   --  @param Channel       the initialized SFTP subsystem channel
   --  @param Source_Handle the open source file handle
   --  @param Source_Offset the starting byte offset in the source
   --  @param Length        the number of bytes
   --  @param Target_Handle the open destination file handle
   --  @param Target_Offset the starting byte offset in the target
   --  @param Result        detailed operation result: remote status code, symbolic name, and message
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Copy_Data
     (Channel       : in out SSH_Lib.Channels.Channel;
      Source_Handle : File_Handle;
      Source_Offset : Interfaces.Unsigned_64;
      Length        : Interfaces.Unsigned_64;
      Target_Handle : File_Handle;
      Target_Offset : Interfaces.Unsigned_64;
      Result        : out SFTP_Result) return CryptoLib.Errors.Status;

   --  Copy a byte range from one remote path to another using the copy-data extension.
   --  @param Session            the SSH session on which to open the SFTP subsystem
   --  @param Source_Remote_Path the source remote path
   --  @param Target_Remote_Path the destination remote path
   --  @param Source_Offset      the starting byte offset in the source
   --  @param Length             the number of bytes
   --  @param Target_Offset      the starting byte offset in the target
   --  @param Mode               the octal permission mode string (e.g. "0644")
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Copy_File_Range
     (Session            : in out SSH_Lib.Sessions.Session;
      Source_Remote_Path : String;
      Target_Remote_Path : String;
      Source_Offset      : Interfaces.Unsigned_64;
      Length             : Interfaces.Unsigned_64;
      Target_Offset      : Interfaces.Unsigned_64 := 0;
      Mode               : String := "0644") return CryptoLib.Errors.Status;

   --  Copy a byte range from one remote path to another using the copy-data extension.
   --  @param Session            the SSH session on which to open the SFTP subsystem
   --  @param Source_Remote_Path the source remote path
   --  @param Target_Remote_Path the destination remote path
   --  @param Source_Offset      the starting byte offset in the source
   --  @param Length             the number of bytes
   --  @param Target_Offset      the starting byte offset in the target
   --  @param Mode               the octal permission mode string (e.g. "0644")
   --  @param Result             detailed operation result: remote status code, symbolic name, and message
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Copy_File_Range
     (Session            : in out SSH_Lib.Sessions.Session;
      Source_Remote_Path : String;
      Target_Remote_Path : String;
      Source_Offset      : Interfaces.Unsigned_64;
      Length             : Interfaces.Unsigned_64;
      Target_Offset      : Interfaces.Unsigned_64;
      Mode               : String;
      Result             : out SFTP_Result) return CryptoLib.Errors.Status;

   --  Set attributes on a symbolic link without following it (lsetstat@openssh.com).
   --  @param Channel     the initialized SFTP subsystem channel
   --  @param Remote_Path the target path on the remote server
   --  @param Attributes  the attributes to apply
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function LSet_Attributes
     (Channel     : in out SSH_Lib.Channels.Channel;
      Remote_Path : String;
      Attributes  : File_Attributes) return CryptoLib.Errors.Status;

   --  Set attributes on a symbolic link without following it (lsetstat@openssh.com).
   --  @param Channel     the initialized SFTP subsystem channel
   --  @param Remote_Path the target path on the remote server
   --  @param Attributes  the attributes to apply
   --  @param Result      detailed operation result: remote status code, symbolic name, and message
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function LSet_Attributes
     (Channel     : in out SSH_Lib.Channels.Channel;
      Remote_Path : String;
      Attributes  : File_Attributes;
      Result      : out SFTP_Result) return CryptoLib.Errors.Status;

   --  Set attributes on a symbolic link without following it (lsetstat@openssh.com).
   --  @param Session     the SSH session on which to open the SFTP subsystem
   --  @param Remote_Path the target path on the remote server
   --  @param Attributes  the attributes to apply
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function LSet_Attributes
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Attributes  : File_Attributes) return CryptoLib.Errors.Status;

   --  Set attributes on a symbolic link without following it (lsetstat@openssh.com).
   --  @param Session     the SSH session on which to open the SFTP subsystem
   --  @param Remote_Path the target path on the remote server
   --  @param Attributes  the attributes to apply
   --  @param Result      detailed operation result: remote status code, symbolic name, and message
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function LSet_Attributes
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Attributes  : File_Attributes;
      Result      : out SFTP_Result) return CryptoLib.Errors.Status;

   --  Query remote filesystem statistics using the statvfs@openssh.com extension.
   --  @param Channel     the initialized SFTP subsystem channel
   --  @param Remote_Path the target path on the remote server
   --  @param Stats       the retrieved filesystem statistics
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function StatVFS
     (Channel     : in out SSH_Lib.Channels.Channel;
      Remote_Path : String;
      Stats       : out File_System_Stats) return CryptoLib.Errors.Status;

   --  Query remote filesystem statistics using the statvfs@openssh.com extension.
   --  @param Channel     the initialized SFTP subsystem channel
   --  @param Remote_Path the target path on the remote server
   --  @param Stats       the retrieved filesystem statistics
   --  @param Result      detailed operation result: remote status code, symbolic name, and message
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function StatVFS
     (Channel     : in out SSH_Lib.Channels.Channel;
      Remote_Path : String;
      Stats       : out File_System_Stats;
      Result      : out SFTP_Result) return CryptoLib.Errors.Status;

   --  Query remote filesystem statistics using the statvfs@openssh.com extension.
   --  @param Session     the SSH session on which to open the SFTP subsystem
   --  @param Remote_Path the target path on the remote server
   --  @param Stats       the retrieved filesystem statistics
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function StatVFS
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Stats       : out File_System_Stats) return CryptoLib.Errors.Status;

   --  Query remote filesystem statistics using the statvfs@openssh.com extension.
   --  @param Session     the SSH session on which to open the SFTP subsystem
   --  @param Remote_Path the target path on the remote server
   --  @param Stats       the retrieved filesystem statistics
   --  @param Result      detailed operation result: remote status code, symbolic name, and message
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function StatVFS
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Stats       : out File_System_Stats;
      Result      : out SFTP_Result) return CryptoLib.Errors.Status;

   --  Query filesystem statistics via statvfs@openssh.com, returning a StatVFS_Result.
   --  @param Channel     the initialized SFTP subsystem channel
   --  @param Remote_Path the target path on the remote server
   --  @return a StatVFS_Result with the filesystem statistics and status
   function StatVFS_Info
     (Channel     : in out SSH_Lib.Channels.Channel;
      Remote_Path : String) return StatVFS_Result;

   --  Query filesystem statistics via statvfs@openssh.com, returning a StatVFS_Result.
   --  @param Session     the SSH session on which to open the SFTP subsystem
   --  @param Remote_Path the target path on the remote server
   --  @return a StatVFS_Result with the filesystem statistics and status
   function StatVFS_Info
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String) return StatVFS_Result;

   --  Retrieve the server's SFTP protocol limits.
   --  @param Channel the initialized SFTP subsystem channel
   --  @param Values  the retrieved server limits
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Limits
     (Channel : in out SSH_Lib.Channels.Channel; Values : out Server_Limits)
      return CryptoLib.Errors.Status;

   --  Retrieve the server's SFTP protocol limits.
   --  @param Channel the initialized SFTP subsystem channel
   --  @param Values  the retrieved server limits
   --  @param Result  detailed operation result: remote status code, symbolic name, and message
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Limits
     (Channel : in out SSH_Lib.Channels.Channel;
      Values  : out Server_Limits;
      Result  : out SFTP_Result) return CryptoLib.Errors.Status;

   --  Retrieve the server's SFTP protocol limits.
   --  @param Session the SSH session on which to open the SFTP subsystem
   --  @param Values  the retrieved server limits
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Limits
     (Session : in out SSH_Lib.Sessions.Session; Values : out Server_Limits)
      return CryptoLib.Errors.Status;

   --  Retrieve the server's SFTP protocol limits.
   --  @param Session the SSH session on which to open the SFTP subsystem
   --  @param Values  the retrieved server limits
   --  @param Result  detailed operation result: remote status code, symbolic name, and message
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Limits
     (Session : in out SSH_Lib.Sessions.Session;
      Values  : out Server_Limits;
      Result  : out SFTP_Result) return CryptoLib.Errors.Status;

   --  Query server protocol limits via limits@openssh.com, returning a Limits_Result.
   --  @param Channel the initialized SFTP subsystem channel
   --  @return a Limits_Result with the server limits and status
   function Limits_Info
     (Channel : in out SSH_Lib.Channels.Channel) return Limits_Result;

   --  Query server protocol limits via limits@openssh.com, returning a Limits_Result.
   --  @param Session the SSH session on which to open the SFTP subsystem
   --  @return a Limits_Result with the server limits and status
   function Limits_Info
     (Session : in out SSH_Lib.Sessions.Session) return Limits_Result;

   --  Send an arbitrary SSH_FXP_EXTENDED request. Payload is appended after
   --  the extension name exactly as supplied. Reply_Data is replaced with the
   --  raw SSH_FXP_EXTENDED_REPLY payload after the request id. If the server
   --  returns SSH_FXP_STATUS, the status is mapped and Reply_Data is cleared.
   --  @param Channel        the initialized SFTP subsystem channel
   --  @param Extension_Name the SSH_FXP_EXTENDED extension name
   --  @param Payload        the request payload appended after the extension name
   --  @param Reply_Data     the raw extended-reply payload
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Extended_Request
     (Channel        : in out SSH_Lib.Channels.Channel;
      Extension_Name : String;
      Payload        : Ada.Streams.Stream_Element_Array;
      Reply_Data     : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;

   --  Send an arbitrary SSH_FXP_EXTENDED request and return its raw reply payload.
   --  @param Session        the SSH session on which to open the SFTP subsystem
   --  @param Extension_Name the SSH_FXP_EXTENDED extension name
   --  @param Payload        the request payload appended after the extension name
   --  @param Reply_Data     the raw extended-reply payload
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Extended_Request
     (Session        : in out SSH_Lib.Sessions.Session;
      Extension_Name : String;
      Payload        : Ada.Streams.Stream_Element_Array;
      Reply_Data     : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;

   --  Send an arbitrary SSH_FXP_EXTENDED request and return its raw reply payload.
   --  @param Item           the SFTP client object
   --  @param Extension_Name the SSH_FXP_EXTENDED extension name
   --  @param Payload        the request payload appended after the extension name
   --  @param Reply_Data     the raw extended-reply payload
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Extended_Request
     (Item           : in out Client;
      Extension_Name : String;
      Payload        : Ada.Streams.Stream_Element_Array;
      Reply_Data     : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;

   --  Send an SSH_FXP_EXTENDED request, returning an Extended_Request_Result.
   --  @param Channel        the initialized SFTP subsystem channel
   --  @param Extension_Name the SSH_FXP_EXTENDED extension name
   --  @param Payload        the request payload appended after the extension name
   --  @return an Extended_Request_Result with the reply payload and status
   function Extended_Request_Info
     (Channel        : in out SSH_Lib.Channels.Channel;
      Extension_Name : String;
      Payload        : Ada.Streams.Stream_Element_Array)
      return Extended_Request_Result;

   --  Send an SSH_FXP_EXTENDED request, returning an Extended_Request_Result.
   --  @param Session        the SSH session on which to open the SFTP subsystem
   --  @param Extension_Name the SSH_FXP_EXTENDED extension name
   --  @param Payload        the request payload appended after the extension name
   --  @return an Extended_Request_Result with the reply payload and status
   function Extended_Request_Info
     (Session        : in out SSH_Lib.Sessions.Session;
      Extension_Name : String;
      Payload        : Ada.Streams.Stream_Element_Array)
      return Extended_Request_Result;

   --  Send an SSH_FXP_EXTENDED request, returning an Extended_Request_Result.
   --  @param Item           the SFTP client object
   --  @param Extension_Name the SSH_FXP_EXTENDED extension name
   --  @param Payload        the request payload appended after the extension name
   --  @return an Extended_Request_Result with the reply payload and status
   function Extended_Request_Info
     (Item           : in out Client;
      Extension_Name : String;
      Payload        : Ada.Streams.Stream_Element_Array)
      return Extended_Request_Result;

   --  Read the target of a remote symbolic link (SSH_FXP_READLINK).
   --  @param Channel     the initialized SFTP subsystem channel
   --  @param Remote_Path the target path on the remote server
   --  @param Target_Path the recovered link target path
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Read_Link
     (Channel     : in out SSH_Lib.Channels.Channel;
      Remote_Path : String;
      Target_Path : out Ada.Strings.Unbounded.Unbounded_String)
      return CryptoLib.Errors.Status;

   --  Read the target of a remote symbolic link (SSH_FXP_READLINK).
   --  @param Session     the SSH session on which to open the SFTP subsystem
   --  @param Remote_Path the target path on the remote server
   --  @param Target_Path the recovered link target path
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Read_Link
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Target_Path : out Ada.Strings.Unbounded.Unbounded_String)
      return CryptoLib.Errors.Status;

   --  Create a remote symbolic link.
   --  @param Channel     the initialized SFTP subsystem channel
   --  @param Target_Path the path the symbolic link points to
   --  @param Link_Path   the symbolic link path to create
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Create_Symlink
     (Channel     : in out SSH_Lib.Channels.Channel;
      Target_Path : String;
      Link_Path   : String) return CryptoLib.Errors.Status;

   --  Create a remote symbolic link.
   --  @param Session     the SSH session on which to open the SFTP subsystem
   --  @param Target_Path the path the symbolic link points to
   --  @param Link_Path   the symbolic link path to create
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Create_Symlink
     (Session     : in out SSH_Lib.Sessions.Session;
      Target_Path : String;
      Link_Path   : String) return CryptoLib.Errors.Status;

   --  Create a remote symbolic or hard link (SSH_FXP_LINK).
   --  @param Channel  the initialized SFTP subsystem channel
   --  @param New_Link the link path to create
   --  @param Existing the existing path the new link refers to
   --  @param Symbolic True to create a symbolic link, False for a hard link
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Create_Link
     (Channel  : in out SSH_Lib.Channels.Channel;
      New_Link : String;
      Existing : String;
      Symbolic : Boolean := True) return CryptoLib.Errors.Status;

   --  Create a remote symbolic or hard link (SSH_FXP_LINK).
   --  @param Channel  the initialized SFTP subsystem channel
   --  @param New_Link the link path to create
   --  @param Existing the existing path the new link refers to
   --  @param Symbolic True to create a symbolic link, False for a hard link
   --  @param Result   detailed operation result: remote status code, symbolic name, and message
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Create_Link
     (Channel  : in out SSH_Lib.Channels.Channel;
      New_Link : String;
      Existing : String;
      Symbolic : Boolean;
      Result   : out SFTP_Result) return CryptoLib.Errors.Status;

   --  Create a remote symbolic or hard link (SSH_FXP_LINK).
   --  @param Item     the SFTP client object
   --  @param New_Link the link path to create
   --  @param Existing the existing path the new link refers to
   --  @param Symbolic True to create a symbolic link, False for a hard link
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Create_Link
     (Item     : in out Client;
      New_Link : String;
      Existing : String;
      Symbolic : Boolean := True) return CryptoLib.Errors.Status;

   --  Create a remote symbolic or hard link (SSH_FXP_LINK).
   --  @param Item     the SFTP client object
   --  @param New_Link the link path to create
   --  @param Existing the existing path the new link refers to
   --  @param Symbolic True to create a symbolic link, False for a hard link
   --  @param Result   detailed operation result: remote status code, symbolic name, and message
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Create_Link
     (Item     : in out Client;
      New_Link : String;
      Existing : String;
      Symbolic : Boolean;
      Result   : out SFTP_Result) return CryptoLib.Errors.Status;

   --  Create a remote symbolic or hard link (SSH_FXP_LINK).
   --  @param Session  the SSH session on which to open the SFTP subsystem
   --  @param New_Link the link path to create
   --  @param Existing the existing path the new link refers to
   --  @param Symbolic True to create a symbolic link, False for a hard link
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Create_Link
     (Session  : in out SSH_Lib.Sessions.Session;
      New_Link : String;
      Existing : String;
      Symbolic : Boolean := True) return CryptoLib.Errors.Status;

   --  Create a remote symbolic or hard link (SSH_FXP_LINK).
   --  @param Session  the SSH session on which to open the SFTP subsystem
   --  @param New_Link the link path to create
   --  @param Existing the existing path the new link refers to
   --  @param Symbolic True to create a symbolic link, False for a hard link
   --  @param Result   detailed operation result: remote status code, symbolic name, and message
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Create_Link
     (Session  : in out SSH_Lib.Sessions.Session;
      New_Link : String;
      Existing : String;
      Symbolic : Boolean;
      Result   : out SFTP_Result) return CryptoLib.Errors.Status;

   --  Seek to a line boundary in a text-mode file using the text-seek extension.
   --  @param Channel     the initialized SFTP subsystem channel
   --  @param Handle      the open remote file handle
   --  @param Line_Number the zero-based line number to seek to
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Text_Seek
     (Channel     : in out SSH_Lib.Channels.Channel;
      Handle      : File_Handle;
      Line_Number : Interfaces.Unsigned_64) return CryptoLib.Errors.Status;

   --  Seek to a line boundary in a text-mode file using the text-seek extension.
   --  @param Item        the SFTP client object
   --  @param Remote_Path the target path on the remote server
   --  @param Line_Number the zero-based line number to seek to
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Text_Seek
     (Item        : in out Client;
      Remote_Path : String;
      Line_Number : Interfaces.Unsigned_64) return CryptoLib.Errors.Status;

   --  Seek to a line boundary in a text-mode file using the text-seek extension.
   --  @param Item        the SFTP client object
   --  @param Remote_Path the target path on the remote server
   --  @param Line_Number the zero-based line number to seek to
   --  @param Result      detailed operation result: remote status code, symbolic name, and message
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Text_Seek
     (Item        : in out Client;
      Remote_Path : String;
      Line_Number : Interfaces.Unsigned_64;
      Result      : out SFTP_Result) return CryptoLib.Errors.Status;

   --  Seek to a line boundary in a text-mode file using the text-seek extension.
   --  @param Session     the SSH session on which to open the SFTP subsystem
   --  @param Remote_Path the target path on the remote server
   --  @param Line_Number the zero-based line number to seek to
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Text_Seek
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Line_Number : Interfaces.Unsigned_64) return CryptoLib.Errors.Status;

   --  Acquire a byte-range lock on a file (SSH_FXP_BLOCK).
   --  @param Channel   the initialized SFTP subsystem channel
   --  @param Handle    the open remote file handle
   --  @param Offset    the byte offset within the file
   --  @param Length    the number of bytes
   --  @param Lock_Mask the byte-range lock type mask
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Lock_Range
     (Channel   : in out SSH_Lib.Channels.Channel;
      Handle    : File_Handle;
      Offset    : Interfaces.Unsigned_64;
      Length    : Interfaces.Unsigned_64;
      Lock_Mask : Interfaces.Unsigned_32) return CryptoLib.Errors.Status;

   --  Acquire a byte-range lock on a file (SSH_FXP_BLOCK).
   --  @param Item        the SFTP client object
   --  @param Remote_Path the target path on the remote server
   --  @param Offset      the byte offset within the file
   --  @param Length      the number of bytes
   --  @param Lock_Mask   the byte-range lock type mask
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Lock_Range
     (Item        : in out Client;
      Remote_Path : String;
      Offset      : Interfaces.Unsigned_64;
      Length      : Interfaces.Unsigned_64;
      Lock_Mask   : Interfaces.Unsigned_32) return CryptoLib.Errors.Status;

   --  Acquire a byte-range lock on a file (SSH_FXP_BLOCK).
   --  @param Item        the SFTP client object
   --  @param Remote_Path the target path on the remote server
   --  @param Offset      the byte offset within the file
   --  @param Length      the number of bytes
   --  @param Lock_Mask   the byte-range lock type mask
   --  @param Result      detailed operation result: remote status code, symbolic name, and message
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Lock_Range
     (Item        : in out Client;
      Remote_Path : String;
      Offset      : Interfaces.Unsigned_64;
      Length      : Interfaces.Unsigned_64;
      Lock_Mask   : Interfaces.Unsigned_32;
      Result      : out SFTP_Result) return CryptoLib.Errors.Status;

   --  Acquire a byte-range lock on a file (SSH_FXP_BLOCK).
   --  @param Session     the SSH session on which to open the SFTP subsystem
   --  @param Remote_Path the target path on the remote server
   --  @param Offset      the byte offset within the file
   --  @param Length      the number of bytes
   --  @param Lock_Mask   the byte-range lock type mask
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Lock_Range
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Offset      : Interfaces.Unsigned_64;
      Length      : Interfaces.Unsigned_64;
      Lock_Mask   : Interfaces.Unsigned_32) return CryptoLib.Errors.Status;

   --  Release a byte-range lock on a file (SSH_FXP_UNBLOCK).
   --  @param Channel the initialized SFTP subsystem channel
   --  @param Handle  the open remote file handle
   --  @param Offset  the byte offset within the file
   --  @param Length  the number of bytes
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Unlock_Range
     (Channel : in out SSH_Lib.Channels.Channel;
      Handle  : File_Handle;
      Offset  : Interfaces.Unsigned_64;
      Length  : Interfaces.Unsigned_64) return CryptoLib.Errors.Status;

   --  Release a byte-range lock on a file (SSH_FXP_UNBLOCK).
   --  @param Item        the SFTP client object
   --  @param Remote_Path the target path on the remote server
   --  @param Offset      the byte offset within the file
   --  @param Length      the number of bytes
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Unlock_Range
     (Item        : in out Client;
      Remote_Path : String;
      Offset      : Interfaces.Unsigned_64;
      Length      : Interfaces.Unsigned_64) return CryptoLib.Errors.Status;

   --  Release a byte-range lock on a file (SSH_FXP_UNBLOCK).
   --  @param Item        the SFTP client object
   --  @param Remote_Path the target path on the remote server
   --  @param Offset      the byte offset within the file
   --  @param Length      the number of bytes
   --  @param Result      detailed operation result: remote status code, symbolic name, and message
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Unlock_Range
     (Item        : in out Client;
      Remote_Path : String;
      Offset      : Interfaces.Unsigned_64;
      Length      : Interfaces.Unsigned_64;
      Result      : out SFTP_Result) return CryptoLib.Errors.Status;

   --  Release a byte-range lock on a file (SSH_FXP_UNBLOCK).
   --  @param Session     the SSH session on which to open the SFTP subsystem
   --  @param Remote_Path the target path on the remote server
   --  @param Offset      the byte offset within the file
   --  @param Length      the number of bytes
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Unlock_Range
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Offset      : Interfaces.Unsigned_64;
      Length      : Interfaces.Unsigned_64) return CryptoLib.Errors.Status;

   --  Select an SFTP protocol version using the version-select extension.
   --  @param Item              the SFTP client object
   --  @param Requested_Version the SFTP protocol version to request
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Version_Select
     (Item : in out Client; Requested_Version : Natural)
      return CryptoLib.Errors.Status;

   --  Select an SFTP protocol version using the version-select extension.
   --  @param Item              the SFTP client object
   --  @param Requested_Version the SFTP protocol version to request
   --  @param Result            detailed operation result: remote status code, symbolic name, and message
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Version_Select
     (Item              : in out Client;
      Requested_Version : Natural;
      Result            : out SFTP_Result) return CryptoLib.Errors.Status;

   --  Stream a local regular file over an initialized SFTP channel.
   --  Remote_Path must be non-empty, contain no NUL byte, and fit within
   --  Maximum_Remote_Path_Length. Mode must be four octal digits.
   --  @param Channel     the initialized SFTP subsystem channel
   --  @param Remote_Path the target path on the remote server
   --  @param Local_Path  the path on the local filesystem
   --  @param Mode        the octal permission mode string (e.g. "0644")
   --  @param Options     transfer tuning options (pipeline depth, chunk sizes, retries, verification)
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
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
   --  @param Session     the SSH session on which to open the SFTP subsystem
   --  @param Remote_Path the target path on the remote server
   --  @param Local_Path  the path on the local filesystem
   --  @param Mode        the octal permission mode string (e.g. "0644")
   --  @param Options     transfer tuning options (pipeline depth, chunk sizes, retries, verification)
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Upload_File
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Local_Path  : String;
      Mode        : String := "0644";
      Options     : Transfer_Options := Default_Transfer_Options)
      return CryptoLib.Errors.Status;

   --  Stream a local regular file to a remote path.
   --  @param Item        the SFTP client object
   --  @param Remote_Path the target path on the remote server
   --  @param Local_Path  the path on the local filesystem
   --  @param Mode        the octal permission mode string (e.g. "0644")
   --  @param Options     transfer tuning options (pipeline depth, chunk sizes, retries, verification)
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Upload_File
     (Item        : in out Client;
      Remote_Path : String;
      Local_Path  : String;
      Mode        : String := "0644";
      Options     : Transfer_Options := Default_Transfer_Options)
      return CryptoLib.Errors.Status;

   --  Stream a local regular file to a remote path.
   --  @param Item        the SFTP client object
   --  @param Remote_Path the target path on the remote server
   --  @param Local_Path  the path on the local filesystem
   --  @param Mode        the octal permission mode string (e.g. "0644")
   --  @param Options     transfer tuning options (pipeline depth, chunk sizes, retries, verification)
   --  @param Result      detailed operation result: remote status code, symbolic name, and message
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Upload_File
     (Item        : in out Client;
      Remote_Path : String;
      Local_Path  : String;
      Mode        : String;
      Options     : Transfer_Options;
      Result      : out SFTP_Result) return CryptoLib.Errors.Status;

   --  Upload bytes supplied on demand by a reader callback, without staging the whole payload.
   --  @param Item        the SFTP client object
   --  @param Remote_Path the target path on the remote server
   --  @param Size        the total number of bytes to upload
   --  @param Reader      the callback supplying the next chunk of upload data
   --  @param Mode        the octal permission mode string (e.g. "0644")
   --  @param Options     transfer tuning options (pipeline depth, chunk sizes, retries, verification)
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Upload_Stream
     (Item        : in out Client;
      Remote_Path : String;
      Size        : Interfaces.Unsigned_64;
      Reader      : Stream_Reader_Access;
      Mode        : String := "0644";
      Options     : Transfer_Options := Default_Transfer_Options)
      return CryptoLib.Errors.Status;

   --  Upload bytes supplied on demand by a reader callback, without staging the whole payload.
   --  @param Item        the SFTP client object
   --  @param Remote_Path the target path on the remote server
   --  @param Size        the total number of bytes to upload
   --  @param Reader      the callback supplying the next chunk of upload data
   --  @param Mode        the octal permission mode string (e.g. "0644")
   --  @param Options     transfer tuning options (pipeline depth, chunk sizes, retries, verification)
   --  @param Result      detailed operation result: remote status code, symbolic name, and message
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Upload_Stream
     (Item        : in out Client;
      Remote_Path : String;
      Size        : Interfaces.Unsigned_64;
      Reader      : Stream_Reader_Access;
      Mode        : String;
      Options     : Transfer_Options;
      Result      : out SFTP_Result) return CryptoLib.Errors.Status;

   --  Download a remote regular file to a local path.
   --  @param Item        the SFTP client object
   --  @param Remote_Path the target path on the remote server
   --  @param Local_Path  the path on the local filesystem
   --  @param Options     transfer tuning options (pipeline depth, chunk sizes, retries, verification)
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Download_File
     (Item        : in out Client;
      Remote_Path : String;
      Local_Path  : String;
      Options     : Transfer_Options := Default_Transfer_Options)
      return CryptoLib.Errors.Status;

   --  Download a remote regular file to a local path.
   --  @param Item        the SFTP client object
   --  @param Remote_Path the target path on the remote server
   --  @param Local_Path  the path on the local filesystem
   --  @param Options     transfer tuning options (pipeline depth, chunk sizes, retries, verification)
   --  @param Result      detailed operation result: remote status code, symbolic name, and message
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Download_File
     (Item        : in out Client;
      Remote_Path : String;
      Local_Path  : String;
      Options     : Transfer_Options;
      Result      : out SFTP_Result) return CryptoLib.Errors.Status;

   --  Download a remote regular file, delivering each chunk to a writer callback.
   --  @param Item        the SFTP client object
   --  @param Remote_Path the target path on the remote server
   --  @param Writer      the callback receiving each downloaded chunk
   --  @param Options     transfer tuning options (pipeline depth, chunk sizes, retries, verification)
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Download_Stream
     (Item        : in out Client;
      Remote_Path : String;
      Writer      : Stream_Writer_Access;
      Options     : Transfer_Options := Default_Transfer_Options)
      return CryptoLib.Errors.Status;

   --  Download a remote regular file, delivering each chunk to a writer callback.
   --  @param Item        the SFTP client object
   --  @param Remote_Path the target path on the remote server
   --  @param Writer      the callback receiving each downloaded chunk
   --  @param Options     transfer tuning options (pipeline depth, chunk sizes, retries, verification)
   --  @param Result      detailed operation result: remote status code, symbolic name, and message
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Download_Stream
     (Item        : in out Client;
      Remote_Path : String;
      Writer      : Stream_Writer_Access;
      Options     : Transfer_Options;
      Result      : out SFTP_Result) return CryptoLib.Errors.Status;

   --  Resume a partial local download by appending the missing remote bytes.
   --  @param Item        the SFTP client object
   --  @param Remote_Path the target path on the remote server
   --  @param Local_Path  the path on the local filesystem
   --  @param Options     transfer tuning options (pipeline depth, chunk sizes, retries, verification)
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Resume_Download_File
     (Item        : in out Client;
      Remote_Path : String;
      Local_Path  : String;
      Options     : Transfer_Options := Default_Transfer_Options)
      return CryptoLib.Errors.Status;

   --  Resume a partial local download by appending the missing remote bytes.
   --  @param Item        the SFTP client object
   --  @param Remote_Path the target path on the remote server
   --  @param Local_Path  the path on the local filesystem
   --  @param Options     transfer tuning options (pipeline depth, chunk sizes, retries, verification)
   --  @param Result      detailed operation result: remote status code, symbolic name, and message
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Resume_Download_File
     (Item        : in out Client;
      Remote_Path : String;
      Local_Path  : String;
      Options     : Transfer_Options;
      Result      : out SFTP_Result) return CryptoLib.Errors.Status;

   --  Resume a partial remote upload by writing the missing local suffix.
   --  @param Item        the SFTP client object
   --  @param Remote_Path the target path on the remote server
   --  @param Local_Path  the path on the local filesystem
   --  @param Mode        the octal permission mode string (e.g. "0644")
   --  @param Options     transfer tuning options (pipeline depth, chunk sizes, retries, verification)
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Resume_Upload_File
     (Item        : in out Client;
      Remote_Path : String;
      Local_Path  : String;
      Mode        : String := "0644";
      Options     : Transfer_Options := Default_Transfer_Options)
      return CryptoLib.Errors.Status;

   --  Resume a partial remote upload by writing the missing local suffix.
   --  @param Item        the SFTP client object
   --  @param Remote_Path the target path on the remote server
   --  @param Local_Path  the path on the local filesystem
   --  @param Mode        the octal permission mode string (e.g. "0644")
   --  @param Options     transfer tuning options (pipeline depth, chunk sizes, retries, verification)
   --  @param Result      detailed operation result: remote status code, symbolic name, and message
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Resume_Upload_File
     (Item        : in out Client;
      Remote_Path : String;
      Local_Path  : String;
      Mode        : String;
      Options     : Transfer_Options;
      Result      : out SFTP_Result) return CryptoLib.Errors.Status;

   --  Download a remote regular file into memory.
   --  @param Item        the SFTP client object
   --  @param Remote_Path the target path on the remote server
   --  @param Data        the received data bytes
   --  @param Options     transfer tuning options (pipeline depth, chunk sizes, retries, verification)
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Download_Data
     (Item        : in out Client;
      Remote_Path : String;
      Data        : out SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Options     : Transfer_Options := Default_Transfer_Options)
      return CryptoLib.Errors.Status;

   --  Download a remote regular file into memory.
   --  @param Item        the SFTP client object
   --  @param Remote_Path the target path on the remote server
   --  @param Data        the received data bytes
   --  @param Options     transfer tuning options (pipeline depth, chunk sizes, retries, verification)
   --  @param Result      detailed operation result: remote status code, symbolic name, and message
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Download_Data
     (Item        : in out Client;
      Remote_Path : String;
      Data        : out SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Options     : Transfer_Options;
      Result      : out SFTP_Result) return CryptoLib.Errors.Status;

   --  Read bytes from a file at a given offset (SSH_FXP_READ).
   --  @param Item        the SFTP client object
   --  @param Remote_Path the target path on the remote server
   --  @param Offset      the byte offset within the file
   --  @param Length      the number of bytes
   --  @param Data        the received data bytes
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Read_At
     (Item        : in out Client;
      Remote_Path : String;
      Offset      : Interfaces.Unsigned_64;
      Length      : Natural;
      Data        : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;

   --  Read bytes from a file at a given offset (SSH_FXP_READ).
   --  @param Item        the SFTP client object
   --  @param Remote_Path the target path on the remote server
   --  @param Offset      the byte offset within the file
   --  @param Length      the number of bytes
   --  @param Data        the received data bytes
   --  @param Result      detailed operation result: remote status code, symbolic name, and message
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Read_At
     (Item        : in out Client;
      Remote_Path : String;
      Offset      : Interfaces.Unsigned_64;
      Length      : Natural;
      Data        : out SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Result      : out SFTP_Result) return CryptoLib.Errors.Status;

   --  Write bytes to a file at a given offset (SSH_FXP_WRITE).
   --  @param Item        the SFTP client object
   --  @param Remote_Path the target path on the remote server
   --  @param Offset      the byte offset within the file
   --  @param Data        the data bytes to write
   --  @param Mode        the octal permission mode string (e.g. "0644")
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Write_At
     (Item        : in out Client;
      Remote_Path : String;
      Offset      : Interfaces.Unsigned_64;
      Data        : Ada.Streams.Stream_Element_Array;
      Mode        : String := "0644") return CryptoLib.Errors.Status;

   --  Write bytes to a file at a given offset (SSH_FXP_WRITE).
   --  @param Item        the SFTP client object
   --  @param Remote_Path the target path on the remote server
   --  @param Offset      the byte offset within the file
   --  @param Data        the data bytes to write
   --  @param Mode        the octal permission mode string (e.g. "0644")
   --  @param Result      detailed operation result: remote status code, symbolic name, and message
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Write_At
     (Item        : in out Client;
      Remote_Path : String;
      Offset      : Interfaces.Unsigned_64;
      Data        : Ada.Streams.Stream_Element_Array;
      Mode        : String;
      Result      : out SFTP_Result) return CryptoLib.Errors.Status;

   --  Flush a remote file to stable storage using the fsync@openssh.com extension.
   --  @param Item        the SFTP client object
   --  @param Remote_Path the target path on the remote server
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Fsync
     (Item : in out Client; Remote_Path : String) return CryptoLib.Errors.Status;

   --  Flush a remote file to stable storage using the fsync@openssh.com extension.
   --  @param Item        the SFTP client object
   --  @param Remote_Path the target path on the remote server
   --  @param Result      detailed operation result: remote status code, symbolic name, and message
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Fsync
     (Item        : in out Client;
      Remote_Path : String;
      Result      : out SFTP_Result) return CryptoLib.Errors.Status;

   --  List a remote directory.
   --  @param Item        the SFTP client object
   --  @param Remote_Path the target path on the remote server
   --  @param Entries     the collected directory entries
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function List_Directory
     (Item        : in out Client;
      Remote_Path : String;
      Entries     : out Directory_Entry_Vectors.Vector)
      return CryptoLib.Errors.Status;

   --  List a remote directory.
   --  @param Item        the SFTP client object
   --  @param Remote_Path the target path on the remote server
   --  @param Entries     the collected directory entries
   --  @param Result      detailed operation result: remote status code, symbolic name, and message
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function List_Directory
     (Item        : in out Client;
      Remote_Path : String;
      Entries     : out Directory_Entry_Vectors.Vector;
      Result      : out SFTP_Result) return CryptoLib.Errors.Status;

   --  List a remote directory.
   --  @param Item        the SFTP client object
   --  @param Remote_Path the target path on the remote server
   --  @param Names       the accumulated newline-separated entry names
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function List_Directory
     (Item        : in out Client;
      Remote_Path : String;
      Names       : out Ada.Strings.Unbounded.Unbounded_String)
      return CryptoLib.Errors.Status;

   --  Stream a remote directory one server page at a time through a callback.
   --  @param Item        the SFTP client object
   --  @param Remote_Path the target path on the remote server
   --  @param Callback    the callback invoked for each directory page
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function List_Directory_Paged
     (Item        : in out Client;
      Remote_Path : String;
      Callback    : Directory_Page_Callback_Access)
      return CryptoLib.Errors.Status;

   --  Retrieve attributes of a remote path without following symbolic links (SSH_FXP_LSTAT).
   --  @param Item        the SFTP client object
   --  @param Remote_Path the target path on the remote server
   --  @param Attributes  the retrieved file attributes
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function LStat
     (Item        : in out Client;
      Remote_Path : String;
      Attributes  : out File_Attributes) return CryptoLib.Errors.Status;

   --  Retrieve attributes of a remote path without following symbolic links (SSH_FXP_LSTAT).
   --  @param Item        the SFTP client object
   --  @param Remote_Path the target path on the remote server
   --  @param Attributes  the retrieved file attributes
   --  @param Result      detailed operation result: remote status code, symbolic name, and message
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function LStat
     (Item        : in out Client;
      Remote_Path : String;
      Attributes  : out File_Attributes;
      Result      : out SFTP_Result) return CryptoLib.Errors.Status;

   --  Canonicalize a remote path using SSH_FXP_REALPATH.
   --  @param Item           the SFTP client object
   --  @param Remote_Path    the target path on the remote server
   --  @param Canonical_Path the canonicalized absolute path
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Realpath
     (Item           : in out Client;
      Remote_Path    : String;
      Canonical_Path : out Ada.Strings.Unbounded.Unbounded_String)
      return CryptoLib.Errors.Status;

   --  Canonicalize a remote path using SSH_FXP_REALPATH.
   --  @param Item           the SFTP client object
   --  @param Remote_Path    the target path on the remote server
   --  @param Canonical_Path the canonicalized absolute path
   --  @param Result         detailed operation result: remote status code, symbolic name, and message
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Realpath
     (Item           : in out Client;
      Remote_Path    : String;
      Canonical_Path : out Ada.Strings.Unbounded.Unbounded_String;
      Result         : out SFTP_Result) return CryptoLib.Errors.Status;

   --  Set attributes on a remote path (SSH_FXP_SETSTAT).
   --  @param Item        the SFTP client object
   --  @param Remote_Path the target path on the remote server
   --  @param Attributes  the attributes to apply
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Set_Attributes
     (Item : in out Client; Remote_Path : String; Attributes : File_Attributes)
      return CryptoLib.Errors.Status;

   --  Set attributes on a remote path (SSH_FXP_SETSTAT).
   --  @param Item        the SFTP client object
   --  @param Remote_Path the target path on the remote server
   --  @param Attributes  the attributes to apply
   --  @param Result      detailed operation result: remote status code, symbolic name, and message
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Set_Attributes
     (Item        : in out Client;
      Remote_Path : String;
      Attributes  : File_Attributes;
      Result      : out SFTP_Result) return CryptoLib.Errors.Status;

   --  Set the owner and group of a remote path.
   --  @param Item        the SFTP client object
   --  @param Remote_Path the target path on the remote server
   --  @param Owner       the owner name
   --  @param Group       the group name
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Set_Path_Owner_Group
     (Item        : in out Client;
      Remote_Path : String;
      Owner       : String;
      Group       : String) return CryptoLib.Errors.Status;

   --  Set the owner and group of a remote path.
   --  @param Item        the SFTP client object
   --  @param Remote_Path the target path on the remote server
   --  @param Owner       the owner name
   --  @param Group       the group name
   --  @param Result      detailed operation result: remote status code, symbolic name, and message
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Set_Path_Owner_Group
     (Item        : in out Client;
      Remote_Path : String;
      Owner       : String;
      Group       : String;
      Result      : out SFTP_Result) return CryptoLib.Errors.Status;

   --  Set the MIME type attribute of a remote path.
   --  @param Item        the SFTP client object
   --  @param Remote_Path the target path on the remote server
   --  @param Mime_Type   the MIME type string
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Set_Path_Mime_Type
     (Item : in out Client; Remote_Path : String; Mime_Type : String)
      return CryptoLib.Errors.Status;

   --  Set the MIME type attribute of a remote path.
   --  @param Item        the SFTP client object
   --  @param Remote_Path the target path on the remote server
   --  @param Mime_Type   the MIME type string
   --  @param Result      detailed operation result: remote status code, symbolic name, and message
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Set_Path_Mime_Type
     (Item        : in out Client;
      Remote_Path : String;
      Mime_Type   : String;
      Result      : out SFTP_Result) return CryptoLib.Errors.Status;

   --  Set the ACL attribute of a remote path.
   --  @param Item        the SFTP client object
   --  @param Remote_Path the target path on the remote server
   --  @param ACL         the access-control-list string
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Set_Path_ACL
     (Item : in out Client; Remote_Path : String; ACL : String)
      return CryptoLib.Errors.Status;

   --  Set the ACL attribute of a remote path.
   --  @param Item        the SFTP client object
   --  @param Remote_Path the target path on the remote server
   --  @param ACL         the access-control-list string
   --  @param Result      detailed operation result: remote status code, symbolic name, and message
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Set_Path_ACL
     (Item        : in out Client;
      Remote_Path : String;
      ACL         : String;
      Result      : out SFTP_Result) return CryptoLib.Errors.Status;

   --  Set the attribute bits and their valid mask on a remote path.
   --  @param Item        the SFTP client object
   --  @param Remote_Path the target path on the remote server
   --  @param Bits        the attribute bits to set
   --  @param Valid       the mask of attribute bits that are valid
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Set_Path_Attribute_Bits
     (Item        : in out Client;
      Remote_Path : String;
      Bits        : Interfaces.Unsigned_32;
      Valid       : Interfaces.Unsigned_32) return CryptoLib.Errors.Status;

   --  Set the attribute bits and their valid mask on a remote path.
   --  @param Item        the SFTP client object
   --  @param Remote_Path the target path on the remote server
   --  @param Bits        the attribute bits to set
   --  @param Valid       the mask of attribute bits that are valid
   --  @param Result      detailed operation result: remote status code, symbolic name, and message
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Set_Path_Attribute_Bits
     (Item        : in out Client;
      Remote_Path : String;
      Bits        : Interfaces.Unsigned_32;
      Valid       : Interfaces.Unsigned_32;
      Result      : out SFTP_Result) return CryptoLib.Errors.Status;

   --  Set the text/binary hint attribute of a remote path.
   --  @param Item        the SFTP client object
   --  @param Remote_Path the target path on the remote server
   --  @param Hint        the text/binary hint value
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Set_Path_Text_Hint
     (Item : in out Client; Remote_Path : String; Hint : Interfaces.Unsigned_8)
      return CryptoLib.Errors.Status;

   --  Set the text/binary hint attribute of a remote path.
   --  @param Item        the SFTP client object
   --  @param Remote_Path the target path on the remote server
   --  @param Hint        the text/binary hint value
   --  @param Result      detailed operation result: remote status code, symbolic name, and message
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Set_Path_Text_Hint
     (Item        : in out Client;
      Remote_Path : String;
      Hint        : Interfaces.Unsigned_8;
      Result      : out SFTP_Result) return CryptoLib.Errors.Status;

   --  Remove a remote file (SSH_FXP_REMOVE).
   --  @param Item        the SFTP client object
   --  @param Remote_Path the target path on the remote server
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Remove_File
     (Item : in out Client; Remote_Path : String) return CryptoLib.Errors.Status;

   --  Remove a remote file (SSH_FXP_REMOVE).
   --  @param Item        the SFTP client object
   --  @param Remote_Path the target path on the remote server
   --  @param Result      detailed operation result: remote status code, symbolic name, and message
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Remove_File
     (Item        : in out Client;
      Remote_Path : String;
      Result      : out SFTP_Result) return CryptoLib.Errors.Status;

   --  Create a remote directory (SSH_FXP_MKDIR).
   --  @param Item        the SFTP client object
   --  @param Remote_Path the target path on the remote server
   --  @param Mode        the octal permission mode string (e.g. "0644")
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Make_Directory
     (Item : in out Client; Remote_Path : String; Mode : String := "0755")
      return CryptoLib.Errors.Status;

   --  Create a remote directory (SSH_FXP_MKDIR).
   --  @param Item        the SFTP client object
   --  @param Remote_Path the target path on the remote server
   --  @param Mode        the octal permission mode string (e.g. "0644")
   --  @param Result      detailed operation result: remote status code, symbolic name, and message
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Make_Directory
     (Item        : in out Client;
      Remote_Path : String;
      Mode        : String;
      Result      : out SFTP_Result) return CryptoLib.Errors.Status;

   --  Remove a remote directory (SSH_FXP_RMDIR).
   --  @param Item        the SFTP client object
   --  @param Remote_Path the target path on the remote server
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Remove_Directory
     (Item : in out Client; Remote_Path : String)
      return CryptoLib.Errors.Status;

   --  Remove a remote directory (SSH_FXP_RMDIR).
   --  @param Item        the SFTP client object
   --  @param Remote_Path the target path on the remote server
   --  @param Result      detailed operation result: remote status code, symbolic name, and message
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Remove_Directory
     (Item        : in out Client;
      Remote_Path : String;
      Result      : out SFTP_Result) return CryptoLib.Errors.Status;

   --  Retrieve attributes of a remote path, following symbolic links (SSH_FXP_STAT).
   --  @param Item        the SFTP client object
   --  @param Remote_Path the target path on the remote server
   --  @param Attributes  the retrieved file attributes
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Stat
     (Item        : in out Client;
      Remote_Path : String;
      Attributes  : out File_Attributes) return CryptoLib.Errors.Status;

   --  Recursively upload a local directory tree to a remote path.
   --  @param Item           the SFTP client object
   --  @param Remote_Path    the target path on the remote server
   --  @param Local_Path     the path on the local filesystem
   --  @param Directory_Mode the octal mode for created directories
   --  @param File_Mode      the octal mode for created files
   --  @param Options        recursive-traversal options (filter, progress, overwrite, symlink handling)
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Upload_Directory
     (Item           : in out Client;
      Remote_Path    : String;
      Local_Path     : String;
      Directory_Mode : String := "0755";
      File_Mode      : String := "0644";
      Options        : Recursive_Options := Default_Recursive_Options)
      return CryptoLib.Errors.Status;

   --  Recursively upload a local directory tree to a remote path.
   --  @param Item           the SFTP client object
   --  @param Remote_Path    the target path on the remote server
   --  @param Local_Path     the path on the local filesystem
   --  @param Directory_Mode the octal mode for created directories
   --  @param File_Mode      the octal mode for created files
   --  @param Options        recursive-traversal options (filter, progress, overwrite, symlink handling)
   --  @param Result         detailed operation result: remote status code, symbolic name, and message
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Upload_Directory
     (Item           : in out Client;
      Remote_Path    : String;
      Local_Path     : String;
      Directory_Mode : String;
      File_Mode      : String;
      Options        : Recursive_Options;
      Result         : out SFTP_Result) return CryptoLib.Errors.Status;

   --  Recursively download a remote directory tree to a local path.
   --  @param Item        the SFTP client object
   --  @param Remote_Path the target path on the remote server
   --  @param Local_Path  the path on the local filesystem
   --  @param Options     recursive-traversal options (filter, progress, overwrite, symlink handling)
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Download_Directory
     (Item        : in out Client;
      Remote_Path : String;
      Local_Path  : String;
      Options     : Recursive_Options := Default_Recursive_Options)
      return CryptoLib.Errors.Status;

   --  Recursively download a remote directory tree to a local path.
   --  @param Item        the SFTP client object
   --  @param Remote_Path the target path on the remote server
   --  @param Local_Path  the path on the local filesystem
   --  @param Options     recursive-traversal options (filter, progress, overwrite, symlink handling)
   --  @param Result      detailed operation result: remote status code, symbolic name, and message
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Download_Directory
     (Item        : in out Client;
      Remote_Path : String;
      Local_Path  : String;
      Options     : Recursive_Options;
      Result      : out SFTP_Result) return CryptoLib.Errors.Status;

   --  Recursively remove a remote file or directory tree.
   --  @param Item        the SFTP client object
   --  @param Remote_Path the target path on the remote server
   --  @param Options     recursive-traversal options (filter, progress, overwrite, symlink handling)
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Remove_Tree
     (Item        : in out Client;
      Remote_Path : String;
      Options     : Recursive_Options := Default_Recursive_Options)
      return CryptoLib.Errors.Status;

   --  Recursively remove a remote file or directory tree.
   --  @param Item        the SFTP client object
   --  @param Remote_Path the target path on the remote server
   --  @param Options     recursive-traversal options (filter, progress, overwrite, symlink handling)
   --  @param Result      detailed operation result: remote status code, symbolic name, and message
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Remove_Tree
     (Item        : in out Client;
      Remote_Path : String;
      Options     : Recursive_Options;
      Result      : out SFTP_Result) return CryptoLib.Errors.Status;

   --  Recursively copy a remote file or directory tree to another remote path.
   --  @param Item               the SFTP client object
   --  @param Source_Remote_Path the source remote path
   --  @param Target_Remote_Path the destination remote path
   --  @param Directory_Mode     the octal mode for created directories
   --  @param File_Mode          the octal mode for created files
   --  @param Options            recursive-traversal options (filter, progress, overwrite, symlink handling)
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Copy_Tree
     (Item               : in out Client;
      Source_Remote_Path : String;
      Target_Remote_Path : String;
      Directory_Mode     : String := "0755";
      File_Mode          : String := "0644";
      Options            : Recursive_Options := Default_Recursive_Options)
      return CryptoLib.Errors.Status;

   --  Recursively copy a remote file or directory tree to another remote path.
   --  @param Item               the SFTP client object
   --  @param Source_Remote_Path the source remote path
   --  @param Target_Remote_Path the destination remote path
   --  @param Directory_Mode     the octal mode for created directories
   --  @param File_Mode          the octal mode for created files
   --  @param Options            recursive-traversal options (filter, progress, overwrite, symlink handling)
   --  @param Result             detailed operation result: remote status code, symbolic name, and message
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Copy_Tree
     (Item               : in out Client;
      Source_Remote_Path : String;
      Target_Remote_Path : String;
      Directory_Mode     : String;
      File_Mode          : String;
      Options            : Recursive_Options;
      Result             : out SFTP_Result) return CryptoLib.Errors.Status;

   --  Synchronize a directory tree between local and remote in a given direction.
   --  @param Item           the SFTP client object
   --  @param Direction      the synchronization direction (upload or download)
   --  @param Remote_Path    the target path on the remote server
   --  @param Local_Path     the path on the local filesystem
   --  @param Directory_Mode the octal mode for created directories
   --  @param File_Mode      the octal mode for created files
   --  @param Options        synchronization options (deletion of extras, skip-unchanged)
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Sync_Directory
     (Item           : in out Client;
      Direction      : Sync_Direction;
      Remote_Path    : String;
      Local_Path     : String;
      Directory_Mode : String := "0755";
      File_Mode      : String := "0644";
      Options        : Sync_Options := Default_Sync_Options)
      return CryptoLib.Errors.Status;

   --  Synchronize a directory tree between local and remote in a given direction.
   --  @param Item           the SFTP client object
   --  @param Direction      the synchronization direction (upload or download)
   --  @param Remote_Path    the target path on the remote server
   --  @param Local_Path     the path on the local filesystem
   --  @param Directory_Mode the octal mode for created directories
   --  @param File_Mode      the octal mode for created files
   --  @param Options        synchronization options (deletion of extras, skip-unchanged)
   --  @param Result         detailed operation result: remote status code, symbolic name, and message
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Sync_Directory
     (Item           : in out Client;
      Direction      : Sync_Direction;
      Remote_Path    : String;
      Local_Path     : String;
      Directory_Mode : String;
      File_Mode      : String;
      Options        : Sync_Options;
      Result         : out SFTP_Result) return CryptoLib.Errors.Status;

   --  Read the target of a remote symbolic link (SSH_FXP_READLINK).
   --  @param Item        the SFTP client object
   --  @param Remote_Path the target path on the remote server
   --  @param Target_Path the recovered link target path
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Read_Link
     (Item        : in out Client;
      Remote_Path : String;
      Target_Path : out Ada.Strings.Unbounded.Unbounded_String)
      return CryptoLib.Errors.Status;

   --  Read the target of a remote symbolic link (SSH_FXP_READLINK).
   --  @param Item        the SFTP client object
   --  @param Remote_Path the target path on the remote server
   --  @param Target_Path the recovered link target path
   --  @param Result      detailed operation result: remote status code, symbolic name, and message
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Read_Link
     (Item        : in out Client;
      Remote_Path : String;
      Target_Path : out Ada.Strings.Unbounded.Unbounded_String;
      Result      : out SFTP_Result) return CryptoLib.Errors.Status;

   --  Create a remote symbolic link.
   --  @param Item        the SFTP client object
   --  @param Target_Path the path the symbolic link points to
   --  @param Link_Path   the symbolic link path to create
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
   function Create_Symlink
     (Item        : in out Client;
      Target_Path : String;
      Link_Path   : String) return CryptoLib.Errors.Status;

   --  Create a remote symbolic link.
   --  @param Item        the SFTP client object
   --  @param Target_Path the path the symbolic link points to
   --  @param Link_Path   the symbolic link path to create
   --  @param Result      detailed operation result: remote status code, symbolic name, and message
   --  @return Ok on success, or a CryptoLib.Errors.Status code describing the failure
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
