with Ada.Directories;
with Ada.Streams.Stream_IO;
with Interfaces.C;
with Interfaces.C.Strings;
with System;
with SSH_Lib.Protocol.Numbers;

package body SSH_Lib.SFTP is
   use Ada.Streams;
   use Ada.Strings.Unbounded;
   use type CryptoLib.Errors.Status;
   use type Interfaces.Unsigned_16;
   use type Interfaces.Unsigned_32;
   use type Interfaces.Unsigned_64;
   use type Interfaces.C.int;
   use type Interfaces.C.long;
   use type Interfaces.C.size_t;
   use type Interfaces.C.char;
   use type Interfaces.C.Strings.chars_ptr;
   use type Ada.Directories.File_Kind;
   use type Ada.Streams.Stream_IO.Count;
   use type Ada.Calendar.Time;

   Pflag_Read              : constant Interfaces.Unsigned_32 := 16#0000_0001#;
   Pflag_Write             : constant Interfaces.Unsigned_32 := 16#0000_0002#;
   Pflag_Append            : constant Interfaces.Unsigned_32 := 16#0000_0004#;
   Pflag_Create            : constant Interfaces.Unsigned_32 := 16#0000_0008#;
   Pflag_Truncate          : constant Interfaces.Unsigned_32 := 16#0000_0010#;
   Pflag_Exclusive         : constant Interfaces.Unsigned_32 := 16#0000_0020#;
   Ace4_Read_Data          : constant Interfaces.Unsigned_32 := 16#0000_0001#;
   Ace4_Write_Data         : constant Interfaces.Unsigned_32 := 16#0000_0002#;
   Ace4_Append_Data        : constant Interfaces.Unsigned_32 := 16#0000_0004#;
   Ace4_Write_Attributes   : constant Interfaces.Unsigned_32 := 16#0000_0100#;
   Open4_Create_New        : constant Interfaces.Unsigned_32 := 16#0000_0000#;
   Open4_Create_Truncate   : constant Interfaces.Unsigned_32 := 16#0000_0001#;
   Open4_Open_Existing     : constant Interfaces.Unsigned_32 := 16#0000_0002#;
   Open4_Open_Or_Create    : constant Interfaces.Unsigned_32 := 16#0000_0003#;
   Open4_Append_Data       : constant Interfaces.Unsigned_32 := 16#0000_0008#;
   Attr_Size               : constant Interfaces.Unsigned_32 := 16#0000_0001#;
   Attr_UID_GID            : constant Interfaces.Unsigned_32 := 16#0000_0002#;
   Attr_Permissions        : constant Interfaces.Unsigned_32 := 16#0000_0004#;
   Attr_ACMODTime          : constant Interfaces.Unsigned_32 := 16#0000_0008#;
   Attr_Extended           : constant Interfaces.Unsigned_32 := 16#8000_0000#;
   Attr4_Size              : constant Interfaces.Unsigned_32 := 16#0000_0001#;
   Attr4_Allocation_Size   : constant Interfaces.Unsigned_32 := 16#0000_0002#;
   Attr4_Owner_Group       : constant Interfaces.Unsigned_32 := 16#0000_0004#;
   Attr4_Permissions       : constant Interfaces.Unsigned_32 := 16#0000_0008#;
   Attr4_Access_Time       : constant Interfaces.Unsigned_32 := 16#0000_0010#;
   Attr4_Create_Time       : constant Interfaces.Unsigned_32 := 16#0000_0020#;
   Attr4_Modify_Time       : constant Interfaces.Unsigned_32 := 16#0000_0040#;
   Attr4_ACL               : constant Interfaces.Unsigned_32 := 16#0000_0080#;
   Attr4_Bits              : constant Interfaces.Unsigned_32 := 16#0000_0100#;
   Attr4_Text_Hint         : constant Interfaces.Unsigned_32 := 16#0000_0200#;
   Attr4_Mime_Type         : constant Interfaces.Unsigned_32 := 16#0000_0400#;
   Attr4_Link_Count        : constant Interfaces.Unsigned_32 := 16#0000_0800#;
   Attr4_Untranslated_Name : constant Interfaces.Unsigned_32 := 16#0000_1000#;
   Attr4_Extended          : constant Interfaces.Unsigned_32 := 16#8000_0000#;
   File_Type_Regular       : constant Stream_Element := 1;
   File_Type_Directory     : constant Stream_Element := 2;
   File_Type_Symlink       : constant Stream_Element := 3;
   File_Type_Special       : constant Stream_Element := 4;
   File_Type_Unknown       : constant Stream_Element := 5;
   Write_Request_Overhead  : constant Natural := 21;
   Maximum_Handle_Length   : constant Natural :=
     Maximum_Packet_Length - Write_Request_Overhead - Upload_Chunk_Size;
   File_Type_Mask          : constant Interfaces.Unsigned_32 := 16#0000_F000#;
   Directory_Type          : constant Interfaces.Unsigned_32 := 16#0000_4000#;
   Regular_Type            : constant Interfaces.Unsigned_32 := 16#0000_8000#;
   Symlink_Type            : constant Interfaces.Unsigned_32 := 16#0000_A000#;

   Local_XAttr_Prefix : constant String := "xattr:";

   Last_Status_Code_Value    : Interfaces.Unsigned_32 := SSH_FX_OK;
   Last_Status_Message_Value : Unbounded_String;

   type C_Utime_Buffer is record
      Access_Time : Interfaces.C.long;
      Modify_Time : Interfaces.C.long;
   end record;
   pragma Convention (C, C_Utime_Buffer);

   function C_Utime
     (Path : Interfaces.C.Strings.chars_ptr; Times : access C_Utime_Buffer)
      return Interfaces.C.int;
   pragma Import (C, C_Utime, "utime");

   function C_ListXAttr
     (Path : Interfaces.C.Strings.chars_ptr;
      List : System.Address;
      Size : Interfaces.C.size_t) return Interfaces.C.long;
   pragma Import (C, C_ListXAttr, "listxattr");

   function C_GetXAttr
     (Path  : Interfaces.C.Strings.chars_ptr;
      Name  : Interfaces.C.Strings.chars_ptr;
      Value : System.Address;
      Size  : Interfaces.C.size_t) return Interfaces.C.long;
   pragma Import (C, C_GetXAttr, "getxattr");

   function C_SetXAttr
     (Path  : Interfaces.C.Strings.chars_ptr;
      Name  : Interfaces.C.Strings.chars_ptr;
      Value : System.Address;
      Size  : Interfaces.C.size_t;
      Flags : Interfaces.C.int) return Interfaces.C.int;
   pragma Import (C, C_SetXAttr, "setxattr");

   function Parse_Mode
     (Mode : String; Permissions : out Interfaces.Unsigned_32)
      return CryptoLib.Errors.Status;

   function To_Stream (Value : String) return Stream_Element_Array is
      Result :
        Stream_Element_Array
          (Stream_Element_Offset'(1) .. Stream_Element_Offset (Value'Length));
      Cursor : Stream_Element_Offset := Result'First;
   begin
      for Character_Value of Value loop
         Result (Cursor) := Stream_Element (Character'Pos (Character_Value));
         Cursor := Cursor + 1;
      end loop;
      return Result;
   end To_Stream;

   function Stream_To_Text (Data : Stream_Element_Array) return String is
      Result : String (1 .. Data'Length);
      Cursor : Natural := Result'First;
   begin
      for Byte_Value of Data loop
         Result (Cursor) := Character'Val (Byte_Value);
         Cursor := Cursor + 1;
      end loop;
      return Result;
   end Stream_To_Text;

   function Has_Extended_Attribute
     (Attributes : File_Attributes; Name : String) return Boolean is
   begin
      for Attribute of Attributes.Extended_Attributes loop
         if To_String (Attribute.Name) = Name then
            return True;
         end if;
      end loop;
      return False;
   exception
      when others =>
         return False;
   end Has_Extended_Attribute;

   function Extended_Attribute_Value
     (Attributes : File_Attributes;
      Name       : String;
      Value      : out Unbounded_String) return Boolean is
   begin
      Value := Null_Unbounded_String;
      for Attribute of Attributes.Extended_Attributes loop
         if To_String (Attribute.Name) = Name then
            Value := Attribute.Value;
            return True;
         end if;
      end loop;
      return False;
   exception
      when others =>
         Value := Null_Unbounded_String;
         return False;
   end Extended_Attribute_Value;

   procedure Set_Extended_Attribute
     (Attributes : in out File_Attributes; Name : String; Value : String) is
   begin
      for Attribute of Attributes.Extended_Attributes loop
         if To_String (Attribute.Name) = Name then
            Attribute.Value := To_Unbounded_String (Value);
            return;
         end if;
      end loop;

      Attributes.Extended_Attributes.Append
        (Extended_Attribute'
           (Name  => To_Unbounded_String (Name),
            Value => To_Unbounded_String (Value)));
   exception
      when others =>
         null;
   end Set_Extended_Attribute;

   function File_Type_From_Permissions
     (Attributes : File_Attributes) return Stream_Element
   is
      Type_Bits : Interfaces.Unsigned_32 := 0;
   begin
      if not Attributes.Permissions_Known then
         return File_Type_Unknown;
      end if;

      Type_Bits := Attributes.Permissions and File_Type_Mask;
      if Type_Bits = Regular_Type then
         return File_Type_Regular;
      elsif Type_Bits = Directory_Type then
         return File_Type_Directory;
      elsif Type_Bits = Symlink_Type then
         return File_Type_Symlink;
      else
         return File_Type_Special;
      end if;
   exception
      when others =>
         return File_Type_Unknown;
   end File_Type_From_Permissions;

   procedure Apply_File_Type
     (Attributes : in out File_Attributes; File_Type : Stream_Element)
   is
      Type_Bits : Interfaces.Unsigned_32 := 0;
   begin
      case File_Type is
         when File_Type_Regular   =>
            Type_Bits := Regular_Type;

         when File_Type_Directory =>
            Type_Bits := Directory_Type;

         when File_Type_Symlink   =>
            Type_Bits := Symlink_Type;

         when others              =>
            return;
      end case;

      Attributes.Permissions_Known := True;
      Attributes.Permissions :=
        (Attributes.Permissions and not File_Type_Mask) or Type_Bits;
   exception
      when others =>
         null;
   end Apply_File_Type;

   function Extended_Attribute_Count
     (Attributes : File_Attributes) return Natural is
   begin
      return Natural (Attributes.Extended_Attributes.Length);
   exception
      when others =>
         return 0;
   end Extended_Attribute_Count;

   procedure Clear_Extended_Attributes (Attributes : in out File_Attributes) is
   begin
      Attributes.Extended_Attributes.Clear;
   exception
      when others =>
         null;
   end Clear_Extended_Attributes;

   function Extension_Name (Extension : Known_Extension) return String is
   begin
      case Extension is
         when Posix_Rename_Known_Extension =>
            return Posix_Rename_Extension;
         when Fsync_Known_Extension =>
            return Fsync_Extension;
         when StatVFS_Known_Extension =>
            return StatVFS_Extension;
         when Hardlink_Known_Extension =>
            return Hardlink_Extension;
         when LSetStat_Known_Extension =>
            return LSetStat_Extension;
         when Limits_Known_Extension =>
            return Limits_Extension;
         when Copy_Data_Known_Extension =>
            return Copy_Data_Extension;
         when Expand_Path_Known_Extension =>
            return Expand_Path_Extension;
         when Check_File_Known_Extension =>
            return Check_File_Extension;
         when Supported2_Known_Extension =>
            return Supported2_Extension;
         when Versions_Known_Extension =>
            return Versions_Extension;
         when Version_Select_Known_Extension =>
            return Version_Select_Extension;
         when Text_Seek_Known_Extension =>
            return Text_Seek_Extension;
      end case;
   end Extension_Name;

   function Supports_Extension
     (Extensions : Extension_Info; Name : String) return Boolean is
   begin
      return
        (Name = Posix_Rename_Extension and then Extensions.Posix_Rename)
        or else (Name = Fsync_Extension and then Extensions.Fsync)
        or else (Name = StatVFS_Extension and then Extensions.StatVFS)
        or else (Name = Hardlink_Extension and then Extensions.Hardlink)
        or else (Name = LSetStat_Extension and then Extensions.LSetStat)
        or else (Name = Limits_Extension and then Extensions.Limits)
        or else (Name = Copy_Data_Extension and then Extensions.Copy_Data)
        or else (Name = Expand_Path_Extension and then Extensions.Expand_Path)
        or else (Name = Check_File_Extension and then Extensions.Check_File)
        or else (Name = Supported2_Extension and then Extensions.Supported2)
        or else (Name = Versions_Extension and then Extensions.Versions)
        or else (Name = Text_Seek_Extension and then Extensions.Text_Seek);
   end Supports_Extension;

   function Supports_Extension
     (Extensions : Extension_Info; Extension : Known_Extension) return Boolean is
   begin
      if Extension = Version_Select_Known_Extension then
         return Extensions.Versions;
      end if;
      return Supports_Extension (Extensions, Extension_Name (Extension));
   end Supports_Extension;

   function Supports_Protocol_Version (Version : Natural) return Boolean is
   begin
      return
        Version >= Minimum_Protocol_Version
        and then Version <= Maximum_Protocol_Version;
   end Supports_Protocol_Version;

   function Last_Remote_Status_Code return Interfaces.Unsigned_32 is
   begin
      return Last_Status_Code_Value;
   end Last_Remote_Status_Code;

   function Last_Remote_Status_Message return Unbounded_String is
   begin
      return Last_Status_Message_Value;
   end Last_Remote_Status_Message;

   function Status_Code_Name (Code : Interfaces.Unsigned_32) return String is
   begin
      case Code is
         when SSH_FX_OK                          =>
            return "SSH_FX_OK";

         when SSH_FX_EOF                         =>
            return "SSH_FX_EOF";

         when SSH_FX_NO_SUCH_FILE                =>
            return "SSH_FX_NO_SUCH_FILE";

         when SSH_FX_PERMISSION_DENIED           =>
            return "SSH_FX_PERMISSION_DENIED";

         when SSH_FX_FAILURE                     =>
            return "SSH_FX_FAILURE";

         when SSH_FX_BAD_MESSAGE                 =>
            return "SSH_FX_BAD_MESSAGE";

         when SSH_FX_NO_CONNECTION               =>
            return "SSH_FX_NO_CONNECTION";

         when SSH_FX_CONNECTION_LOST             =>
            return "SSH_FX_CONNECTION_LOST";

         when SSH_FX_OP_UNSUPPORTED              =>
            return "SSH_FX_OP_UNSUPPORTED";

         when SSH_FX_INVALID_HANDLE              =>
            return "SSH_FX_INVALID_HANDLE";

         when SSH_FX_NO_SUCH_PATH                =>
            return "SSH_FX_NO_SUCH_PATH";

         when SSH_FX_FILE_ALREADY_EXISTS         =>
            return "SSH_FX_FILE_ALREADY_EXISTS";

         when SSH_FX_WRITE_PROTECT               =>
            return "SSH_FX_WRITE_PROTECT";

         when SSH_FX_NO_MEDIA                    =>
            return "SSH_FX_NO_MEDIA";

         when SSH_FX_NO_SPACE_ON_FILESYSTEM      =>
            return "SSH_FX_NO_SPACE_ON_FILESYSTEM";

         when SSH_FX_QUOTA_EXCEEDED              =>
            return "SSH_FX_QUOTA_EXCEEDED";

         when SSH_FX_UNKNOWN_PRINCIPAL           =>
            return "SSH_FX_UNKNOWN_PRINCIPAL";

         when SSH_FX_LOCK_CONFLICT               =>
            return "SSH_FX_LOCK_CONFLICT";

         when SSH_FX_DIR_NOT_EMPTY               =>
            return "SSH_FX_DIR_NOT_EMPTY";

         when SSH_FX_NOT_A_DIRECTORY             =>
            return "SSH_FX_NOT_A_DIRECTORY";

         when SSH_FX_INVALID_FILENAME            =>
            return "SSH_FX_INVALID_FILENAME";

         when SSH_FX_LINK_LOOP                   =>
            return "SSH_FX_LINK_LOOP";

         when SSH_FX_CANNOT_DELETE               =>
            return "SSH_FX_CANNOT_DELETE";

         when SSH_FX_INVALID_PARAMETER           =>
            return "SSH_FX_INVALID_PARAMETER";

         when SSH_FX_FILE_IS_A_DIRECTORY         =>
            return "SSH_FX_FILE_IS_A_DIRECTORY";

         when SSH_FX_BYTE_RANGE_LOCK_CONFLICT    =>
            return "SSH_FX_BYTE_RANGE_LOCK_CONFLICT";

         when SSH_FX_BYTE_RANGE_LOCK_REFUSED     =>
            return "SSH_FX_BYTE_RANGE_LOCK_REFUSED";

         when SSH_FX_DELETE_PENDING              =>
            return "SSH_FX_DELETE_PENDING";

         when SSH_FX_FILE_CORRUPT                =>
            return "SSH_FX_FILE_CORRUPT";

         when SSH_FX_OWNER_INVALID               =>
            return "SSH_FX_OWNER_INVALID";

         when SSH_FX_GROUP_INVALID               =>
            return "SSH_FX_GROUP_INVALID";

         when SSH_FX_NO_MATCHING_BYTE_RANGE_LOCK =>
            return "SSH_FX_NO_MATCHING_BYTE_RANGE_LOCK";

         when others                             =>
            return "SSH_FX_UNKNOWN";
      end case;
   end Status_Code_Name;

   function Last_Remote_Status_Name return String is
   begin
      return Status_Code_Name (Last_Status_Code_Value);
   end Last_Remote_Status_Name;

   function Result_For_Status
     (Status    : CryptoLib.Errors.Status;
      Operation : SFTP_Operation := Unknown_Operation) return SFTP_Result is
   begin
      return
        (Operation             => Operation,
         Status                => Status,
         Remote_Status_Code    => Last_Status_Code_Value,
         Remote_Status_Name    =>
           To_Unbounded_String (Status_Code_Name (Last_Status_Code_Value)),
         Remote_Status_Message => Last_Status_Message_Value);
   end Result_For_Status;

   procedure Capture_Result
     (Status    : CryptoLib.Errors.Status;
      Result    : out SFTP_Result;
      Operation : SFTP_Operation := Unknown_Operation) is
   begin
      Result := Result_For_Status (Status, Operation);
   end Capture_Result;

   function Last_Result return SFTP_Result is
      Status : CryptoLib.Errors.Status := CryptoLib.Errors.Remote_Failure;
   begin
      case Last_Status_Code_Value is
         when SSH_FX_OK                                 =>
            Status := CryptoLib.Errors.Ok;

         when SSH_FX_EOF                                =>
            Status := CryptoLib.Errors.End_Of_Stream;

         when SSH_FX_NO_SUCH_FILE | SSH_FX_NO_SUCH_PATH =>
            Status := CryptoLib.Errors.No_Such_File;

         when SSH_FX_PERMISSION_DENIED
            | SSH_FX_WRITE_PROTECT
            | SSH_FX_OWNER_INVALID
            | SSH_FX_GROUP_INVALID                      =>
            Status := CryptoLib.Errors.Permission_Denied;

         when SSH_FX_OP_UNSUPPORTED                     =>
            Status := CryptoLib.Errors.Unsupported_Feature;

         when SSH_FX_BAD_MESSAGE                        =>
            Status := CryptoLib.Errors.Read_Failed;

         when SSH_FX_INVALID_HANDLE
            | SSH_FX_FILE_ALREADY_EXISTS
            | SSH_FX_INVALID_FILENAME
            | SSH_FX_INVALID_PARAMETER
            | SSH_FX_FILE_IS_A_DIRECTORY                =>
            Status := CryptoLib.Errors.Invalid_Command;

         when others                                    =>
            Status := CryptoLib.Errors.Remote_Failure;
      end case;
      return Result_For_Status (Status);
   end Last_Result;

   function Remote_Child_Path
     (Parent_Path : String; Name : String) return String is
   begin
      if Parent_Path'Length = 0 or else Name'Length = 0 then
         return "";
      elsif Parent_Path (Parent_Path'Last) = '/' then
         return Parent_Path & Name;
      else
         return Parent_Path & "/" & Name;
      end if;
   end Remote_Child_Path;

   function Is_Dot_Entry (Name : String) return Boolean is
   begin
      return Name = "." or else Name = "..";
   end Is_Dot_Entry;

   function Attribute_Is_Directory
     (Attributes : File_Attributes) return Boolean is
   begin
      return
        Attributes.Permissions_Known
        and then (Attributes.Permissions and File_Type_Mask) = Directory_Type;
   end Attribute_Is_Directory;

   function Attribute_Is_Regular (Attributes : File_Attributes) return Boolean
   is
   begin
      return
        Attributes.Permissions_Known
        and then (Attributes.Permissions and File_Type_Mask) = Regular_Type;
   end Attribute_Is_Regular;

   function Attribute_Is_Symlink (Attributes : File_Attributes) return Boolean
   is
   begin
      return
        Attributes.Permissions_Known
        and then (Attributes.Permissions and File_Type_Mask) = Symlink_Type;
   end Attribute_Is_Symlink;

   function Unix_Epoch return Ada.Calendar.Time is
   begin
      return Ada.Calendar.Time_Of (1970, 1, 1, 0.0);
   end Unix_Epoch;

   function Time_To_Posix_Seconds
     (Value : Ada.Calendar.Time) return Interfaces.C.long
   is
      Seconds : constant Duration := Value - Unix_Epoch;
   begin
      if Seconds < 0.0 then
         return 0;
      elsif Seconds > 2_147_483_647.0 then
         return Interfaces.C.long (2_147_483_647);
      else
         return Interfaces.C.long (Seconds);
      end if;
   exception
      when others =>
         return 0;
   end Time_To_Posix_Seconds;

   function Set_Local_Modification_Time
     (Local_Path : String; Modify_Time : Ada.Calendar.Time) return Boolean
   is
      Path  : Interfaces.C.Strings.chars_ptr := Interfaces.C.Strings.Null_Ptr;
      Times : aliased C_Utime_Buffer;
      Stamp : constant Interfaces.C.long :=
        Time_To_Posix_Seconds (Modify_Time);
   begin
      if Local_Path'Length = 0 then
         return False;
      end if;
      Path := Interfaces.C.Strings.New_String (Local_Path);
      Times.Access_Time := Stamp;
      Times.Modify_Time := Stamp;
      declare
         Result : constant Boolean := C_Utime (Path, Times'Access) = 0;
      begin
         Interfaces.C.Strings.Free (Path);
         return Result;
      end;
   exception
      when others =>
         return False;
   end Set_Local_Modification_Time;

   function Char_Array_To_String
     (Data : Interfaces.C.char_array; Length : Natural) return String
   is
      Result : String (1 .. Length);
   begin
      for Index in Result'Range loop
         Result (Index) :=
           Character'Val
             (Interfaces.C.char'Pos
                (Data (Data'First + Interfaces.C.size_t (Index - 1))));
      end loop;
      return Result;
   exception
      when others =>
         return "";
   end Char_Array_To_String;

   procedure Capture_Local_Metadata
     (Local_Path : String; Attributes : in out File_Attributes)
   is
      Path      : Interfaces.C.Strings.chars_ptr :=
        Interfaces.C.Strings.Null_Ptr;
      Needed    : Interfaces.C.long := 0;
      Retrieved : Interfaces.C.long := 0;
   begin
      if Local_Path'Length = 0 then
         return;
      end if;

      if Ada.Directories.Exists (Local_Path) then
         Set_Times
           (Attributes,
            Ada.Directories.Modification_Time (Local_Path),
            Ada.Directories.Modification_Time (Local_Path));
      end if;

      Path := Interfaces.C.Strings.New_String (Local_Path);
      Needed := C_ListXAttr (Path, System.Null_Address, 0);
      if Needed <= 0 or else Needed > 65_536 then
         Interfaces.C.Strings.Free (Path);
         return;
      end if;

      declare
         Names :
           aliased Interfaces.C.char_array
                     (0 .. Interfaces.C.size_t (Needed - 1));
      begin
         Retrieved :=
           C_ListXAttr (Path, Names'Address, Interfaces.C.size_t (Needed));
         if Retrieved <= 0 then
            Interfaces.C.Strings.Free (Path);
            return;
         end if;

         declare
            Cursor : Interfaces.C.size_t := 0;
            Last   : constant Interfaces.C.size_t :=
              Interfaces.C.size_t (Retrieved - 1);
         begin
            while Cursor <= Last loop
               declare
                  Start : constant Interfaces.C.size_t := Cursor;
               begin
                  while Cursor <= Last
                    and then Names (Cursor) /= Interfaces.C.nul
                  loop
                     Cursor := Cursor + 1;
                  end loop;
                  if Cursor > Start then
                     declare
                        Name_Length  : constant Natural :=
                          Natural (Cursor - Start);
                        Name_Value   : constant String :=
                          Char_Array_To_String
                            (Names (Start .. Cursor - 1), Name_Length);
                        Name_Ptr     : Interfaces.C.Strings.chars_ptr :=
                          Interfaces.C.Strings.New_String (Name_Value);
                        Value_Needed : constant Interfaces.C.long :=
                          C_GetXAttr (Path, Name_Ptr, System.Null_Address, 0);
                     begin
                        if Value_Needed > 0 and then Value_Needed <= 65_536
                        then
                           declare
                              Value_Buffer :
                                aliased Interfaces.C.char_array
                                          (0
                                           ..
                                             Interfaces.C.size_t
                                               (Value_Needed - 1));
                              Value_Size   : constant Interfaces.C.long :=
                                C_GetXAttr
                                  (Path,
                                   Name_Ptr,
                                   Value_Buffer'Address,
                                   Interfaces.C.size_t (Value_Needed));
                           begin
                              if Value_Size >= 0 then
                                 Set_Extended_Attribute
                                   (Attributes,
                                    Local_XAttr_Prefix & Name_Value,
                                    Char_Array_To_String
                                      (Value_Buffer, Natural (Value_Size)));
                              end if;
                           end;
                        end if;
                        Interfaces.C.Strings.Free (Name_Ptr);
                     exception
                        when others =>
                           null;
                     end;
                  end if;
                  Cursor := Cursor + 1;
               end;
            end loop;
         end;
      end;
      Interfaces.C.Strings.Free (Path);
   exception
      when others =>
         if Path /= Interfaces.C.Strings.Null_Ptr then
            Interfaces.C.Strings.Free (Path);
         end if;
   end Capture_Local_Metadata;

   procedure Restore_Local_Metadata
     (Local_Path : String; Attributes : File_Attributes)
   is
      Path : Interfaces.C.Strings.chars_ptr := Interfaces.C.Strings.Null_Ptr;
   begin
      if Local_Path'Length = 0 then
         return;
      end if;

      Path := Interfaces.C.Strings.New_String (Local_Path);
      for Attribute of Attributes.Extended_Attributes loop
         declare
            Attribute_Name : constant String := To_String (Attribute.Name);
         begin
            if Attribute_Name'Length > Local_XAttr_Prefix'Length
              and then
                Attribute_Name
                  (Attribute_Name'First
                   .. Attribute_Name'First + Local_XAttr_Prefix'Length - 1)
                = Local_XAttr_Prefix
            then
               declare
                  XName     : constant String :=
                    Attribute_Name
                      (Attribute_Name'First
                       + Local_XAttr_Prefix'Length
                       .. Attribute_Name'Last);
                  XName_Ptr : Interfaces.C.Strings.chars_ptr :=
                    Interfaces.C.Strings.New_String (XName);
                  XValue    : constant String := To_String (Attribute.Value);
                  CValue    : aliased Interfaces.C.char_array :=
                    Interfaces.C.To_C (XValue, Append_Nul => False);
                  Result    : Interfaces.C.int;
               begin
                  Result :=
                    C_SetXAttr
                      (Path,
                       XName_Ptr,
                       CValue'Address,
                       Interfaces.C.size_t (XValue'Length),
                       0);
                  pragma Unreferenced (Result);
                  Interfaces.C.Strings.Free (XName_Ptr);
               exception
                  when others =>
                     null;
               end;
            end if;
         end;
      end loop;
      Interfaces.C.Strings.Free (Path);

      if Attributes.Times_Known then
         declare
            Modify_Time : Ada.Calendar.Time;
            Applied     : Boolean;
         begin
            if Modify_Time_Value (Attributes, Modify_Time) then
               Applied :=
                 Set_Local_Modification_Time (Local_Path, Modify_Time);
               pragma Unreferenced (Applied);
            end if;
         end;
      end if;
   exception
      when others =>
         if Path /= Interfaces.C.Strings.Null_Ptr then
            Interfaces.C.Strings.Free (Path);
         end if;
   end Restore_Local_Metadata;

   function Is_Directory (Attributes : File_Attributes) return Boolean is
   begin
      return Attribute_Is_Directory (Attributes);
   end Is_Directory;

   function Is_Regular_File (Attributes : File_Attributes) return Boolean is
   begin
      return Attribute_Is_Regular (Attributes);
   end Is_Regular_File;

   function Is_Symlink (Attributes : File_Attributes) return Boolean is
   begin
      return Attribute_Is_Symlink (Attributes);
   end Is_Symlink;

   function Is_Other_File_Type (Attributes : File_Attributes) return Boolean is
   begin
      return
        Attributes.Permissions_Known
        and then (Attributes.Permissions and File_Type_Mask) /= 0
        and then not Is_Directory (Attributes)
        and then not Is_Regular_File (Attributes)
        and then not Is_Symlink (Attributes);
   end Is_Other_File_Type;

   function Mode_To_Permissions
     (Mode : String; Permissions : out Interfaces.Unsigned_32) return Boolean
   is
   begin
      return Parse_Mode (Mode, Permissions) = CryptoLib.Errors.Ok;
   exception
      when others =>
         Permissions := 0;
         return False;
   end Mode_To_Permissions;

   function Permissions_To_Mode
     (Permissions : Interfaces.Unsigned_32) return String
   is
      Bits   : Interfaces.Unsigned_32 := Permissions and 16#0000_0FFF#;
      Result : String (1 .. 4);
   begin
      for Index in reverse Result'Range loop
         Result (Index) :=
           Character'Val (Character'Pos ('0') + Integer (Bits mod 8));
         Bits := Bits / 8;
      end loop;
      return Result;
   exception
      when others =>
         return "0000";
   end Permissions_To_Mode;

   function Permission_Bits
     (Attributes : File_Attributes) return Interfaces.Unsigned_32 is
   begin
      if not Attributes.Permissions_Known then
         return 0;
      end if;
      return Attributes.Permissions and 16#0000_0FFF#;
   end Permission_Bits;

   function Has_Permission
     (Attributes : File_Attributes; Permission : Interfaces.Unsigned_32)
      return Boolean is
   begin
      return
        Attributes.Permissions_Known
        and then (Permission_Bits (Attributes) and Permission) /= 0;
   exception
      when others =>
         return False;
   end Has_Permission;

   function Owner_Can_Read (Attributes : File_Attributes) return Boolean is
   begin
      return Has_Permission (Attributes, Owner_Read_Permission);
   end Owner_Can_Read;

   function Owner_Can_Write (Attributes : File_Attributes) return Boolean is
   begin
      return Has_Permission (Attributes, Owner_Write_Permission);
   end Owner_Can_Write;

   function Owner_Can_Execute (Attributes : File_Attributes) return Boolean is
   begin
      return Has_Permission (Attributes, Owner_Execute_Permission);
   end Owner_Can_Execute;

   function Group_Can_Read (Attributes : File_Attributes) return Boolean is
   begin
      return Has_Permission (Attributes, Group_Read_Permission);
   end Group_Can_Read;

   function Group_Can_Write (Attributes : File_Attributes) return Boolean is
   begin
      return Has_Permission (Attributes, Group_Write_Permission);
   end Group_Can_Write;

   function Group_Can_Execute (Attributes : File_Attributes) return Boolean is
   begin
      return Has_Permission (Attributes, Group_Execute_Permission);
   end Group_Can_Execute;

   function Other_Can_Read (Attributes : File_Attributes) return Boolean is
   begin
      return Has_Permission (Attributes, Other_Read_Permission);
   end Other_Can_Read;

   function Other_Can_Write (Attributes : File_Attributes) return Boolean is
   begin
      return Has_Permission (Attributes, Other_Write_Permission);
   end Other_Can_Write;

   function Other_Can_Execute (Attributes : File_Attributes) return Boolean is
   begin
      return Has_Permission (Attributes, Other_Execute_Permission);
   end Other_Can_Execute;

   function Set_Permissions_Mode
     (Attributes : in out File_Attributes; Mode : String) return Boolean
   is
      Parsed    : Interfaces.Unsigned_32 := 0;
      Type_Bits : Interfaces.Unsigned_32 := 0;
   begin
      if not Mode_To_Permissions (Mode, Parsed) then
         return False;
      end if;
      if Attributes.Permissions_Known then
         Type_Bits := Attributes.Permissions and File_Type_Mask;
      end if;
      Attributes.Permissions_Known := True;
      Attributes.Permissions := Type_Bits or Parsed;
      return True;
   exception
      when others =>
         return False;
   end Set_Permissions_Mode;

   procedure Set_UID_GID
     (Attributes : in out File_Attributes;
      UID        : Interfaces.Unsigned_32;
      GID        : Interfaces.Unsigned_32) is
   begin
      Attributes.UID_GID_Known := True;
      Attributes.UID := UID;
      Attributes.GID := GID;
   end Set_UID_GID;

   procedure Set_Allocation_Size
     (Attributes : in out File_Attributes; Size : Interfaces.Unsigned_64) is
   begin
      Attributes.Allocation_Size_Known := True;
      Attributes.Allocation_Size := Size;
   end Set_Allocation_Size;

   procedure Set_Owner_Group
     (Attributes : in out File_Attributes; Owner : String; Group : String) is
   begin
      Attributes.Owner_Group_Known := True;
      Attributes.Owner := To_Unbounded_String (Owner);
      Attributes.Group := To_Unbounded_String (Group);
   end Set_Owner_Group;

   procedure Set_Create_Time
     (Attributes  : in out File_Attributes;
      Create_Time : Ada.Calendar.Time;
      Nanoseconds : Interfaces.Unsigned_32 := 0)
   is
      Seconds : constant Duration := Create_Time - Unix_Epoch;
   begin
      if Seconds < 0.0 or else Seconds > Duration (Interfaces.Unsigned_32'Last)
      then
         Attributes.Create_Time_Known := False;
         Attributes.Create_Time := 0;
         Attributes.Create_Time_Nanoseconds := 0;
         return;
      end if;
      Attributes.Create_Time_Known := True;
      Attributes.Create_Time := Interfaces.Unsigned_32 (Seconds);
      Attributes.Create_Time_Nanoseconds := Nanoseconds;
   exception
      when others =>
         Attributes.Create_Time_Known := False;
         Attributes.Create_Time := 0;
         Attributes.Create_Time_Nanoseconds := 0;
   end Set_Create_Time;

   procedure Set_ACL (Attributes : in out File_Attributes; ACL : String) is
   begin
      Attributes.ACL_Known := True;
      Attributes.ACL := To_Unbounded_String (ACL);
   end Set_ACL;

   procedure Set_Attribute_Bits
     (Attributes : in out File_Attributes;
      Bits       : Interfaces.Unsigned_32;
      Valid      : Interfaces.Unsigned_32) is
   begin
      Attributes.Attribute_Bits_Known := True;
      Attributes.Attribute_Bits := Bits;
      Attributes.Attribute_Bits_Valid := Valid;
   end Set_Attribute_Bits;

   procedure Set_Text_Hint
     (Attributes : in out File_Attributes; Hint : Interfaces.Unsigned_8) is
   begin
      Attributes.Text_Hint_Known := True;
      Attributes.Text_Hint := Hint;
   end Set_Text_Hint;

   procedure Set_Mime_Type
     (Attributes : in out File_Attributes; Mime_Type : String) is
   begin
      Attributes.Mime_Type_Known := True;
      Attributes.Mime_Type := To_Unbounded_String (Mime_Type);
   end Set_Mime_Type;

   procedure Set_Link_Count
     (Attributes : in out File_Attributes; Count : Interfaces.Unsigned_32) is
   begin
      Attributes.Link_Count_Known := True;
      Attributes.Link_Count := Count;
   end Set_Link_Count;

   procedure Set_Untranslated_Name
     (Attributes : in out File_Attributes; Name : String) is
   begin
      Attributes.Untranslated_Name_Known := True;
      Attributes.Untranslated_Name := To_Unbounded_String (Name);
   end Set_Untranslated_Name;

   function Access_Time_Value
     (Attributes : File_Attributes; Value : out Ada.Calendar.Time)
      return Boolean is
   begin
      Value := Unix_Epoch;
      if not Attributes.Times_Known then
         return False;
      end if;
      Value := Unix_Epoch + Duration (Attributes.Access_Time);
      return True;
   exception
      when others =>
         Value := Unix_Epoch;
         return False;
   end Access_Time_Value;

   function Modify_Time_Value
     (Attributes : File_Attributes; Value : out Ada.Calendar.Time)
      return Boolean is
   begin
      Value := Unix_Epoch;
      if not Attributes.Times_Known then
         return False;
      end if;
      Value := Unix_Epoch + Duration (Attributes.Modify_Time);
      return True;
   exception
      when others =>
         Value := Unix_Epoch;
         return False;
   end Modify_Time_Value;

   procedure Set_Times
     (Attributes  : in out File_Attributes;
      Access_Time : Ada.Calendar.Time;
      Modify_Time : Ada.Calendar.Time)
   is
      Access_Seconds : constant Duration := Access_Time - Unix_Epoch;
      Modify_Seconds : constant Duration := Modify_Time - Unix_Epoch;
   begin
      if Access_Seconds < 0.0
        or else Modify_Seconds < 0.0
        or else Access_Seconds > Duration (Interfaces.Unsigned_32'Last)
        or else Modify_Seconds > Duration (Interfaces.Unsigned_32'Last)
      then
         Attributes.Times_Known := False;
         Attributes.Access_Time := 0;
         Attributes.Modify_Time := 0;
         return;
      end if;

      Attributes.Times_Known := True;
      Attributes.Access_Time := Interfaces.Unsigned_32 (Access_Seconds);
      Attributes.Modify_Time := Interfaces.Unsigned_32 (Modify_Seconds);
   exception
      when others =>
         Attributes.Times_Known := False;
         Attributes.Access_Time := 0;
         Attributes.Modify_Time := 0;
   end Set_Times;

   function Copy_Metadata
     (Source           : File_Attributes;
      Include_Size     : Boolean := False;
      Include_UID_GID  : Boolean := False;
      Include_Extended : Boolean := True) return File_Attributes
   is
      Result : File_Attributes;
   begin
      if Include_Size and then Source.Size_Known then
         Result.Size_Known := True;
         Result.Size := Source.Size;
      end if;
      if Include_UID_GID and then Source.UID_GID_Known then
         Result.UID_GID_Known := True;
         Result.UID := Source.UID;
         Result.GID := Source.GID;
      end if;
      if Source.Permissions_Known then
         Result.Permissions_Known := True;
         Result.Permissions := Source.Permissions;
      end if;
      if Source.Allocation_Size_Known then
         Result.Allocation_Size_Known := True;
         Result.Allocation_Size := Source.Allocation_Size;
      end if;
      if Source.Owner_Group_Known then
         Result.Owner_Group_Known := True;
         Result.Owner := Source.Owner;
         Result.Group := Source.Group;
      end if;
      if Source.Times_Known then
         Result.Times_Known := True;
         Result.Access_Time := Source.Access_Time;
         Result.Access_Time_Nanoseconds := Source.Access_Time_Nanoseconds;
         Result.Modify_Time := Source.Modify_Time;
         Result.Modify_Time_Nanoseconds := Source.Modify_Time_Nanoseconds;
      end if;
      if Source.Create_Time_Known then
         Result.Create_Time_Known := True;
         Result.Create_Time := Source.Create_Time;
         Result.Create_Time_Nanoseconds := Source.Create_Time_Nanoseconds;
      end if;
      if Source.ACL_Known then
         Result.ACL_Known := True;
         Result.ACL := Source.ACL;
      end if;
      if Source.Attribute_Bits_Known then
         Result.Attribute_Bits_Known := True;
         Result.Attribute_Bits := Source.Attribute_Bits;
         Result.Attribute_Bits_Valid := Source.Attribute_Bits_Valid;
      end if;
      if Source.Text_Hint_Known then
         Result.Text_Hint_Known := True;
         Result.Text_Hint := Source.Text_Hint;
      end if;
      if Source.Mime_Type_Known then
         Result.Mime_Type_Known := True;
         Result.Mime_Type := Source.Mime_Type;
      end if;
      if Source.Link_Count_Known then
         Result.Link_Count_Known := True;
         Result.Link_Count := Source.Link_Count;
      end if;
      if Source.Untranslated_Name_Known then
         Result.Untranslated_Name_Known := True;
         Result.Untranslated_Name := Source.Untranslated_Name;
      end if;
      if Include_Extended then
         Result.Extended_Attributes := Source.Extended_Attributes;
      end if;
      return Result;
   exception
      when others =>
         return (others => <>);
   end Copy_Metadata;

   function Safe_Remote_Path (Remote_Path : String) return Boolean is
   begin
      if Remote_Path'Length = 0
        or else Remote_Path'Length > Maximum_Remote_Path_Length
      then
         return False;
      end if;

      for Path_Character of Remote_Path loop
         if Path_Character = Character'Val (0) then
            return False;
         end if;
      end loop;
      return True;
   end Safe_Remote_Path;

   function Retryable_Transfer_Status
     (Status_Value : CryptoLib.Errors.Status) return Boolean is
   begin
      return
        Status_Value
        in CryptoLib.Errors.Timeout
         | CryptoLib.Errors.Connection_Failed
         | CryptoLib.Errors.Channel_Open_Failed
         | CryptoLib.Errors.Channel_Request_Failed
         | CryptoLib.Errors.Read_Failed
         | CryptoLib.Errors.Write_Failed;
   end Retryable_Transfer_Status;

   function Remote_Temporary_Path (Remote_Path : String) return String is
      Suffix : constant String := ".ada-ssh-upload.tmp";
   begin
      if Remote_Path'Length + Suffix'Length > Maximum_Remote_Path_Length then
         return "";
      end if;
      return Remote_Path & Suffix;
   end Remote_Temporary_Path;

   function Verify_Remote_Size
     (Channel       : in out SSH_Lib.Channels.Channel;
      Remote_Path   : String;
      Expected_Size : Interfaces.Unsigned_64) return CryptoLib.Errors.Status
   is
      Attributes   : File_Attributes;
      Status_Value : CryptoLib.Errors.Status;
   begin
      Status_Value := Stat (Channel, Remote_Path, Attributes);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      if not Attributes.Size_Known or else Attributes.Size /= Expected_Size
      then
         return CryptoLib.Errors.Remote_Failure;
      end if;
      return CryptoLib.Errors.Ok;
   end Verify_Remote_Size;

   function Verify_Local_Size
     (Local_Path : String; Expected_Size : Interfaces.Unsigned_64)
      return CryptoLib.Errors.Status
   is
      Size_Value : Ada.Directories.File_Size;
   begin
      if not Ada.Directories.Exists (Local_Path) then
         return CryptoLib.Errors.No_Such_File;
      end if;
      Size_Value := Ada.Directories.Size (Local_Path);
      if Interfaces.Unsigned_64 (Size_Value) /= Expected_Size then
         return CryptoLib.Errors.Read_Failed;
      end if;
      return CryptoLib.Errors.Ok;
   exception
      when others =>
         return CryptoLib.Errors.Internal_Error;
   end Verify_Local_Size;

   function Local_File_Ready
     (Local_Path : String; Size : out Natural) return CryptoLib.Errors.Status
   is
      Size_Value : Ada.Streams.Stream_IO.Count := 0;
   begin
      Size := 0;
      if Local_Path'Length = 0
        or else not Ada.Directories.Exists (Local_Path)
        or else
          Ada.Directories.Kind (Local_Path) /= Ada.Directories.Ordinary_File
      then
         return CryptoLib.Errors.Read_Failed;
      end if;

      declare
         File_Item : Ada.Streams.Stream_IO.File_Type;
      begin
         Ada.Streams.Stream_IO.Open
           (File_Item, Ada.Streams.Stream_IO.In_File, Local_Path);
         Size_Value := Ada.Streams.Stream_IO.Size (File_Item);
         Ada.Streams.Stream_IO.Close (File_Item);
      exception
         when others =>
            if Ada.Streams.Stream_IO.Is_Open (File_Item) then
               Ada.Streams.Stream_IO.Close (File_Item);
            end if;
            return CryptoLib.Errors.Read_Failed;
      end;

      if Size_Value > Ada.Streams.Stream_IO.Count (Natural'Last) then
         return CryptoLib.Errors.Read_Failed;
      end if;

      Size := Natural (Size_Value);
      return CryptoLib.Errors.Ok;
   exception
      when others =>
         Size := 0;
         return CryptoLib.Errors.Read_Failed;
   end Local_File_Ready;

   function Parse_Mode
     (Mode : String; Permissions : out Interfaces.Unsigned_32)
      return CryptoLib.Errors.Status
   is
      Value : Interfaces.Unsigned_32 := 0;
   begin
      Permissions := 0;
      if Mode'Length /= 4 then
         return CryptoLib.Errors.Invalid_Command;
      end if;

      for Mode_Character of Mode loop
         if Mode_Character not in '0' .. '7' then
            return CryptoLib.Errors.Invalid_Command;
         end if;
         Value :=
           Value
           * 8
           + Interfaces.Unsigned_32
               (Character'Pos (Mode_Character) - Character'Pos ('0'));
      end loop;

      Permissions := Value;
      return CryptoLib.Errors.Ok;
   exception
      when others =>
         Permissions := 0;
         return CryptoLib.Errors.Invalid_Command;
   end Parse_Mode;

   function Valid_Mode (Mode : String) return Boolean is
      Permissions : Interfaces.Unsigned_32 := 0;
   begin
      return Parse_Mode (Mode, Permissions) = CryptoLib.Errors.Ok;
   exception
      when others =>
         return False;
   end Valid_Mode;

   function Effective_Pipeline_Depth
     (Options : Transfer_Options) return Positive is
   begin
      if Options.Pipeline_Depth > Maximum_Pipeline_Depth then
         return Maximum_Pipeline_Depth;
      else
         return Options.Pipeline_Depth;
      end if;
   end Effective_Pipeline_Depth;

   function Adapted_Transfer_Options
     (Options : Transfer_Options;
      Attempt : Natural) return Transfer_Options
   is
      Result : Transfer_Options := Options;
   begin
      if Options.Adaptive_Chunking and then Attempt > 0 then
         for Step in 1 .. Attempt loop
            if Result.Read_Chunk_Size > Options.Minimum_Adaptive_Chunk_Size then
               Result.Read_Chunk_Size :=
                 Positive'Max
                   (Options.Minimum_Adaptive_Chunk_Size,
                    Result.Read_Chunk_Size / 2);
            end if;
            if Result.Write_Chunk_Size > Options.Minimum_Adaptive_Chunk_Size then
               Result.Write_Chunk_Size :=
                 Positive'Max
                   (Options.Minimum_Adaptive_Chunk_Size,
                    Result.Write_Chunk_Size / 2);
            end if;
            if Result.Pipeline_Depth > 1 then
               Result.Pipeline_Depth := Positive'Max (1, Result.Pipeline_Depth / 2);
            end if;
         end loop;
      end if;
      return Result;
   exception
      when others =>
         return Options;
   end Adapted_Transfer_Options;

   function Effective_Write_Chunk_Size
     (Options : Transfer_Options) return Natural is
   begin
      return Natural'Min (Upload_Chunk_Size, Options.Write_Chunk_Size);
   exception
      when others =>
         return Upload_Chunk_Size;
   end Effective_Write_Chunk_Size;

   function Effective_Write_Chunk_Size
     (Options      : Transfer_Options;
      Limits_Known : Boolean;
      Limits       : Server_Limits) return Natural
   is
      Result : Natural := Effective_Write_Chunk_Size (Options);
   begin
      if Limits_Known
        and then Limits.Max_Write_Length > 0
        and then Limits.Max_Write_Length < Interfaces.Unsigned_64 (Result)
      then
         Result := Natural (Limits.Max_Write_Length);
      end if;
      return Result;
   exception
      when others =>
         return Effective_Write_Chunk_Size (Options);
   end Effective_Write_Chunk_Size;

   function Effective_Read_Chunk_Size
     (Extensions : Extension_Info) return Natural is
   begin
      if Extensions.Capabilities.Present
        and then Extensions.Capabilities.Max_Read_Size > 0
        and then
          Extensions.Capabilities.Max_Read_Size
          < Interfaces.Unsigned_32 (Upload_Chunk_Size)
      then
         return Natural (Extensions.Capabilities.Max_Read_Size);
      end if;
      return Upload_Chunk_Size;
   exception
      when others =>
         return Upload_Chunk_Size;
   end Effective_Read_Chunk_Size;

   function Effective_Read_Chunk_Size
     (Extensions : Extension_Info; Options : Transfer_Options) return Natural
   is
   begin
      return
        Natural'Min
          (Effective_Read_Chunk_Size (Extensions), Options.Read_Chunk_Size);
   exception
      when others =>
         return Upload_Chunk_Size;
   end Effective_Read_Chunk_Size;

   function Validate_Upload_Target
     (Remote_Path : String; Mode : String) return CryptoLib.Errors.Status
   is
      Permissions : Interfaces.Unsigned_32 := 0;
   begin
      if not Safe_Remote_Path (Remote_Path) then
         return CryptoLib.Errors.Invalid_Command;
      end if;

      return Parse_Mode (Mode, Permissions);
   exception
      when others =>
         return CryptoLib.Errors.Invalid_Command;
   end Validate_Upload_Target;

   function Encode_Uint64
     (Value : Interfaces.Unsigned_64) return Stream_Element_Array
   is
      Result : Stream_Element_Array (1 .. 8);
      Work   : Interfaces.Unsigned_64 := Value;
   begin
      for Index in reverse Result'Range loop
         Result (Index) :=
           Stream_Element (Work mod Interfaces.Unsigned_64'(256));
         Work := Work / Interfaces.Unsigned_64'(256);
      end loop;
      return Result;
   end Encode_Uint64;

   function Decode_Uint16
     (Data  : Stream_Element_Array;
      First : Stream_Element_Offset;
      Value : out Interfaces.Unsigned_16;
      Next  : out Stream_Element_Offset) return CryptoLib.Errors.Status is
   begin
      Value := 0;
      if First + 1 > Data'Last then
         Next := First;
         return CryptoLib.Errors.Read_Failed;
      end if;
      Value :=
        Interfaces.Unsigned_16
          (Integer (Data (First)) * 256 + Integer (Data (First + 1)));
      Next := First + 2;
      return CryptoLib.Errors.Ok;
   exception
      when others =>
         Value := 0;
         Next := First;
         return CryptoLib.Errors.Read_Failed;
   end Decode_Uint16;

   function Natural_Text (Value : Natural) return String is
      Image : constant String := Natural'Image (Value);
   begin
      return Image (Image'First + 1 .. Image'Last);
   end Natural_Text;

   function Append_SFTP_String
     (Packet : in out SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Data   : Stream_Element_Array) return CryptoLib.Errors.Status
   is
      Status_Value : CryptoLib.Errors.Status;
   begin
      Status_Value :=
        SSH_Lib.Protocol.Buffers.Append
          (Packet,
           SSH_Lib.Protocol.Numbers.Encode_Uint32
             (Interfaces.Unsigned_32 (Data'Length)));
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      return SSH_Lib.Protocol.Buffers.Append (Packet, Data);
   exception
      when others =>
         return CryptoLib.Errors.Internal_Error;
   end Append_SFTP_String;

   function Start_Request
     (Message_Type : Stream_Element; Request_Id : Interfaces.Unsigned_32)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer
   is
      Result       : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Status_Value : CryptoLib.Errors.Status;
   begin
      SSH_Lib.Protocol.Buffers.Clear (Result);
      Status_Value :=
        SSH_Lib.Protocol.Buffers.Append_Byte (Result, Message_Type);
      if Status_Value = CryptoLib.Errors.Ok then
         Status_Value :=
           SSH_Lib.Protocol.Buffers.Append
             (Result, SSH_Lib.Protocol.Numbers.Encode_Uint32 (Request_Id));
      end if;
      if Status_Value /= CryptoLib.Errors.Ok then
         SSH_Lib.Protocol.Buffers.Clear (Result);
      end if;
      return Result;
   exception
      when others =>
         SSH_Lib.Protocol.Buffers.Clear (Result);
         return Result;
   end Start_Request;

   function With_Length
     (Payload : SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer
   is
      Result       : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Payload_Data : constant Stream_Element_Array :=
        SSH_Lib.Protocol.Buffers.To_Array (Payload);
      Status_Value : CryptoLib.Errors.Status;
   begin
      SSH_Lib.Protocol.Buffers.Clear (Result);
      Status_Value :=
        SSH_Lib.Protocol.Buffers.Append
          (Result,
           SSH_Lib.Protocol.Numbers.Encode_Uint32
             (Interfaces.Unsigned_32 (Payload_Data'Length)));
      if Status_Value = CryptoLib.Errors.Ok then
         Status_Value :=
           SSH_Lib.Protocol.Buffers.Append (Result, Payload_Data);
      end if;
      if Status_Value /= CryptoLib.Errors.Ok then
         SSH_Lib.Protocol.Buffers.Clear (Result);
      end if;
      return Result;
   exception
      when others =>
         SSH_Lib.Protocol.Buffers.Clear (Result);
         return Result;
   end With_Length;

   function Open_Mode_Flags (Mode : Open_Mode) return Interfaces.Unsigned_32 is
   begin
      case Mode is
         when Read_Only         =>
            return Pflag_Read;

         when Write_Truncate    =>
            return Pflag_Write or Pflag_Create or Pflag_Truncate;

         when Write_No_Truncate =>
            return Pflag_Write or Pflag_Create;

         when Append            =>
            return Pflag_Write or Pflag_Append or Pflag_Create;

         when Create_New        =>
            return Pflag_Write or Pflag_Create or Pflag_Exclusive;

         when Read_Write        =>
            return Pflag_Read or Pflag_Write;
      end case;
   end Open_Mode_Flags;

   function Open_Mode_Desired_Access
     (Mode : Open_Mode) return Interfaces.Unsigned_32 is
   begin
      case Mode is
         when Read_Only                                       =>
            return Ace4_Read_Data;

         when Write_Truncate | Write_No_Truncate | Create_New =>
            return Ace4_Write_Data or Ace4_Write_Attributes;

         when Append                                          =>
            return Ace4_Append_Data or Ace4_Write_Attributes;

         when Read_Write                                      =>
            return Ace4_Read_Data or Ace4_Write_Data;
      end case;
   end Open_Mode_Desired_Access;

   function Open_Mode_V4_Flags (Mode : Open_Mode) return Interfaces.Unsigned_32
   is
   begin
      case Mode is
         when Read_Only | Read_Write =>
            return Open4_Open_Existing;

         when Write_Truncate         =>
            return Open4_Create_Truncate;

         when Write_No_Truncate      =>
            return Open4_Open_Or_Create;

         when Append                 =>
            return Open4_Open_Or_Create or Open4_Append_Data;

         when Create_New             =>
            return Open4_Create_New;
      end case;
   end Open_Mode_V4_Flags;

   function Attribute_Flags_For_Version
     (Attributes : File_Attributes; Version : Natural)
      return Interfaces.Unsigned_32
   is
      Flags : Interfaces.Unsigned_32 := 0;
   begin
      if Version <= 3 then
         if Attributes.Size_Known then
            Flags := Flags or Attr_Size;
         end if;
         if Attributes.UID_GID_Known then
            Flags := Flags or Attr_UID_GID;
         end if;
         if Attributes.Permissions_Known then
            Flags := Flags or Attr_Permissions;
         end if;
         if Attributes.Times_Known then
            Flags := Flags or Attr_ACMODTime;
         end if;
         if not Attributes.Extended_Attributes.Is_Empty then
            Flags := Flags or Attr_Extended;
         end if;
      else
         if Attributes.Size_Known then
            Flags := Flags or Attr4_Size;
         end if;
         if Attributes.Allocation_Size_Known then
            Flags := Flags or Attr4_Allocation_Size;
         end if;
         if Attributes.Owner_Group_Known then
            Flags := Flags or Attr4_Owner_Group;
         end if;
         if Attributes.Permissions_Known then
            Flags := Flags or Attr4_Permissions;
         end if;
         if Attributes.Times_Known then
            Flags := Flags or Attr4_Access_Time or Attr4_Modify_Time;
         end if;
         if Attributes.Create_Time_Known then
            Flags := Flags or Attr4_Create_Time;
         end if;
         if Attributes.ACL_Known then
            Flags := Flags or Attr4_ACL;
         end if;
         if Attributes.Attribute_Bits_Known then
            Flags := Flags or Attr4_Bits;
         end if;
         if Attributes.Text_Hint_Known then
            Flags := Flags or Attr4_Text_Hint;
         end if;
         if Attributes.Mime_Type_Known then
            Flags := Flags or Attr4_Mime_Type;
         end if;
         if Attributes.Link_Count_Known then
            Flags := Flags or Attr4_Link_Count;
         end if;
         if Attributes.Untranslated_Name_Known then
            Flags := Flags or Attr4_Untranslated_Name;
         end if;
         if not Attributes.Extended_Attributes.Is_Empty then
            Flags := Flags or Attr4_Extended;
         end if;
      end if;
      return Flags;
   exception
      when others =>
         return 0;
   end Attribute_Flags_For_Version;

   function Supports_Open_Mode
     (Extensions : Extension_Info; Mode : Open_Mode) return Boolean
   is
      Desired : constant Interfaces.Unsigned_32 :=
        Open_Mode_Desired_Access (Mode);
      Flags   : constant Interfaces.Unsigned_32 := Open_Mode_V4_Flags (Mode);
   begin
      if not Extensions.Capabilities.Present then
         return True;
      end if;
      return
        (Desired and not Extensions.Capabilities.Supported_Access_Mask) = 0
        and then
          (Flags and not Extensions.Capabilities.Supported_Open_Flags) = 0;
   exception
      when others =>
         return False;
   end Supports_Open_Mode;

   function Supports_Attributes
     (Extensions : Extension_Info;
      Attributes : File_Attributes;
      Version    : Natural := Protocol_Version) return Boolean
   is
      Flags : constant Interfaces.Unsigned_32 :=
        Attribute_Flags_For_Version (Attributes, Version);
   begin
      if not Extensions.Capabilities.Present or else Version <= 3 then
         return True;
      end if;
      return
        (Flags and not Extensions.Capabilities.Supported_Attribute_Mask) = 0
        and then
          (not Attributes.Attribute_Bits_Known
           or else
             (Attributes.Attribute_Bits
              and not Extensions.Capabilities.Supported_Attribute_Bits)
             = 0);
   exception
      when others =>
         return False;
   end Supports_Attributes;

   function Supports_Block_Mask
     (Extensions : Extension_Info; Lock_Mask : Interfaces.Unsigned_32)
      return Boolean is
   begin
      if not Extensions.Capabilities.Present then
         return True;
      end if;
      return
        Lock_Mask <= Interfaces.Unsigned_32 (Interfaces.Unsigned_16'Last)
        and then
          (Interfaces.Unsigned_16 (Lock_Mask)
           and not Extensions.Capabilities.Supported_Block_Vector)
          = 0;
   exception
      when others =>
         return False;
   end Supports_Block_Mask;

   function Advertises_Protocol_Version
     (Extensions : Extension_Info; Requested_Version : Natural) return Boolean
   is
   begin
      case Requested_Version is
         when 2      =>
            return Extensions.Version_2;

         when 3      =>
            return Extensions.Version_3;

         when 4      =>
            return Extensions.Version_4;

         when 5      =>
            return Extensions.Version_5;

         when 6      =>
            return Extensions.Version_6;

         when others =>
            return False;
      end case;
   end Advertises_Protocol_Version;

   function Open_Mode_Uses_Permissions (Mode : Open_Mode) return Boolean is
   begin
      return Mode in Write_Truncate | Write_No_Truncate | Append | Create_New;
   end Open_Mode_Uses_Permissions;

   function Append_Open_Attributes
     (Packet     : in out SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Attributes : File_Attributes;
      Has_Attrs  : Boolean;
      Version    : Natural) return CryptoLib.Errors.Status;

   function Encode_Open_Mode_Request
     (Request_Id       : Interfaces.Unsigned_32;
      Remote_Path      : String;
      Mode             : Open_Mode;
      Permissions_Mode : String;
      Version          : Natural := Protocol_Version)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer
   is
      Payload      : SSH_Lib.Protocol.Buffers.Packet_Buffer :=
        Start_Request (SSH_FXP_OPEN, Request_Id);
      Permissions  : Interfaces.Unsigned_32 := 0;
      Attributes   : File_Attributes;
      Status_Value : CryptoLib.Errors.Status;
   begin
      if SSH_Lib.Protocol.Buffers.Is_Empty (Payload)
        or else not Safe_Remote_Path (Remote_Path)
      then
         SSH_Lib.Protocol.Buffers.Clear (Payload);
         return Payload;
      end if;

      if Open_Mode_Uses_Permissions (Mode)
        and then
          Parse_Mode (Permissions_Mode, Permissions) /= CryptoLib.Errors.Ok
      then
         SSH_Lib.Protocol.Buffers.Clear (Payload);
         return Payload;
      end if;

      if Open_Mode_Uses_Permissions (Mode) then
         Attributes.Permissions_Known := True;
         Attributes.Permissions := Regular_Type or Permissions;
      end if;

      Status_Value := Append_SFTP_String (Payload, To_Stream (Remote_Path));
      if Version <= 3 then
         if Status_Value = CryptoLib.Errors.Ok then
            Status_Value :=
              SSH_Lib.Protocol.Buffers.Append
                (Payload,
                 SSH_Lib.Protocol.Numbers.Encode_Uint32
                   (Open_Mode_Flags (Mode)));
         end if;
         if Status_Value = CryptoLib.Errors.Ok then
            Status_Value :=
              Append_Open_Attributes
                (Payload,
                 Attributes,
                 Open_Mode_Uses_Permissions (Mode),
                 Version);
         end if;
      else
         if Status_Value = CryptoLib.Errors.Ok then
            Status_Value :=
              SSH_Lib.Protocol.Buffers.Append
                (Payload,
                 SSH_Lib.Protocol.Numbers.Encode_Uint32
                   (Open_Mode_Desired_Access (Mode)));
         end if;
         if Status_Value = CryptoLib.Errors.Ok then
            Status_Value :=
              SSH_Lib.Protocol.Buffers.Append
                (Payload,
                 SSH_Lib.Protocol.Numbers.Encode_Uint32
                   (Open_Mode_V4_Flags (Mode)));
         end if;
         if Status_Value = CryptoLib.Errors.Ok then
            Status_Value :=
              Append_Open_Attributes
                (Payload,
                 Attributes,
                 Open_Mode_Uses_Permissions (Mode),
                 Version);
         end if;
      end if;
      if Status_Value /= CryptoLib.Errors.Ok then
         SSH_Lib.Protocol.Buffers.Clear (Payload);
         return Payload;
      end if;
      return With_Length (Payload);
   exception
      when others =>
         SSH_Lib.Protocol.Buffers.Clear (Payload);
         return Payload;
   end Encode_Open_Mode_Request;

   function Encode_Open_Request
     (Request_Id  : Interfaces.Unsigned_32;
      Remote_Path : String;
      Mode        : String;
      Version     : Natural := Protocol_Version)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer is
   begin
      return
        Encode_Open_Mode_Request
          (Request_Id, Remote_Path, Write_Truncate, Mode, Version);
   end Encode_Open_Request;

   function Encode_Write_Request
     (Request_Id : Interfaces.Unsigned_32;
      Handle     : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Offset     : Interfaces.Unsigned_64;
      Data       : Stream_Element_Array)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer
   is
      Payload      : SSH_Lib.Protocol.Buffers.Packet_Buffer :=
        Start_Request (SSH_FXP_WRITE, Request_Id);
      Status_Value : CryptoLib.Errors.Status;
   begin
      if SSH_Lib.Protocol.Buffers.Is_Empty (Payload) then
         return Payload;
      end if;

      Status_Value :=
        Append_SFTP_String
          (Payload, SSH_Lib.Protocol.Buffers.To_Array (Handle));
      if Status_Value = CryptoLib.Errors.Ok then
         Status_Value :=
           SSH_Lib.Protocol.Buffers.Append (Payload, Encode_Uint64 (Offset));
      end if;
      if Status_Value = CryptoLib.Errors.Ok then
         Status_Value := Append_SFTP_String (Payload, Data);
      end if;
      if Status_Value /= CryptoLib.Errors.Ok then
         SSH_Lib.Protocol.Buffers.Clear (Payload);
         return Payload;
      end if;
      return With_Length (Payload);
   exception
      when others =>
         SSH_Lib.Protocol.Buffers.Clear (Payload);
         return Payload;
   end Encode_Write_Request;

   function Encode_Close_Request
     (Request_Id : Interfaces.Unsigned_32;
      Handle     : SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer
   is
      Payload      : SSH_Lib.Protocol.Buffers.Packet_Buffer :=
        Start_Request (SSH_FXP_CLOSE, Request_Id);
      Status_Value : CryptoLib.Errors.Status;
   begin
      if SSH_Lib.Protocol.Buffers.Is_Empty (Payload) then
         return Payload;
      end if;

      Status_Value :=
        Append_SFTP_String
          (Payload, SSH_Lib.Protocol.Buffers.To_Array (Handle));
      if Status_Value /= CryptoLib.Errors.Ok then
         SSH_Lib.Protocol.Buffers.Clear (Payload);
         return Payload;
      end if;
      return With_Length (Payload);
   exception
      when others =>
         SSH_Lib.Protocol.Buffers.Clear (Payload);
         return Payload;
   end Encode_Close_Request;

   function Decode_Uint64
     (Data        : Stream_Element_Array;
      First_Index : Stream_Element_Offset;
      Value       : out Interfaces.Unsigned_64;
      Next_Index  : out Stream_Element_Offset) return CryptoLib.Errors.Status is
   begin
      Value := 0;
      Next_Index := First_Index;
      if First_Index > Data'Last or else First_Index + 7 > Data'Last then
         return CryptoLib.Errors.Read_Failed;
      end if;

      for Index in First_Index .. First_Index + 7 loop
         Value := Value * 256 + Interfaces.Unsigned_64 (Data (Index));
      end loop;
      Next_Index := First_Index + 8;
      return CryptoLib.Errors.Ok;
   exception
      when others =>
         Value := 0;
         Next_Index := First_Index;
         return CryptoLib.Errors.Read_Failed;
   end Decode_Uint64;

   function Packet_String_To_Text
     (Item : SSH_Lib.Protocol.Buffers.Packet_Buffer) return String is
   begin
      return Stream_To_Text (SSH_Lib.Protocol.Buffers.To_Array (Item));
   end Packet_String_To_Text;

   function Encode_Path_Request
     (Message_Type : Stream_Element;
      Request_Id   : Interfaces.Unsigned_32;
      Remote_Path  : String) return SSH_Lib.Protocol.Buffers.Packet_Buffer
   is
      Payload      : SSH_Lib.Protocol.Buffers.Packet_Buffer :=
        Start_Request (Message_Type, Request_Id);
      Status_Value : CryptoLib.Errors.Status;
   begin
      if SSH_Lib.Protocol.Buffers.Is_Empty (Payload)
        or else not Safe_Remote_Path (Remote_Path)
      then
         SSH_Lib.Protocol.Buffers.Clear (Payload);
         return Payload;
      end if;

      Status_Value := Append_SFTP_String (Payload, To_Stream (Remote_Path));
      if Status_Value /= CryptoLib.Errors.Ok then
         SSH_Lib.Protocol.Buffers.Clear (Payload);
         return Payload;
      end if;
      return With_Length (Payload);
   exception
      when others =>
         SSH_Lib.Protocol.Buffers.Clear (Payload);
         return Payload;
   end Encode_Path_Request;

   function Encode_Two_Path_Request
     (Message_Type : Stream_Element;
      Request_Id   : Interfaces.Unsigned_32;
      First_Path   : String;
      Second_Path  : String) return SSH_Lib.Protocol.Buffers.Packet_Buffer
   is
      Payload      : SSH_Lib.Protocol.Buffers.Packet_Buffer :=
        Start_Request (Message_Type, Request_Id);
      Status_Value : CryptoLib.Errors.Status;
   begin
      if SSH_Lib.Protocol.Buffers.Is_Empty (Payload)
        or else not Safe_Remote_Path (First_Path)
        or else not Safe_Remote_Path (Second_Path)
      then
         SSH_Lib.Protocol.Buffers.Clear (Payload);
         return Payload;
      end if;

      Status_Value := Append_SFTP_String (Payload, To_Stream (First_Path));
      if Status_Value = CryptoLib.Errors.Ok then
         Status_Value := Append_SFTP_String (Payload, To_Stream (Second_Path));
      end if;
      if Status_Value /= CryptoLib.Errors.Ok then
         SSH_Lib.Protocol.Buffers.Clear (Payload);
         return Payload;
      end if;
      return With_Length (Payload);
   exception
      when others =>
         SSH_Lib.Protocol.Buffers.Clear (Payload);
         return Payload;
   end Encode_Two_Path_Request;

   function Encode_Extended_Request
     (Request_Id : Interfaces.Unsigned_32; Extension_Name : String)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;

   function Encode_Link_Request
     (Request_Id : Interfaces.Unsigned_32;
      New_Link   : String;
      Existing   : String;
      Symbolic   : Boolean) return SSH_Lib.Protocol.Buffers.Packet_Buffer
   is
      Payload      : SSH_Lib.Protocol.Buffers.Packet_Buffer :=
        Start_Request (SSH_FXP_LINK, Request_Id);
      Status_Value : CryptoLib.Errors.Status;
   begin
      if SSH_Lib.Protocol.Buffers.Is_Empty (Payload)
        or else not Safe_Remote_Path (New_Link)
        or else not Safe_Remote_Path (Existing)
      then
         SSH_Lib.Protocol.Buffers.Clear (Payload);
         return Payload;
      end if;

      Status_Value := Append_SFTP_String (Payload, To_Stream (New_Link));
      if Status_Value = CryptoLib.Errors.Ok then
         Status_Value := Append_SFTP_String (Payload, To_Stream (Existing));
      end if;
      if Status_Value = CryptoLib.Errors.Ok then
         Status_Value :=
           SSH_Lib.Protocol.Buffers.Append_Byte
             (Payload, (if Symbolic then 1 else 0));
      end if;
      if Status_Value /= CryptoLib.Errors.Ok then
         SSH_Lib.Protocol.Buffers.Clear (Payload);
         return Payload;
      end if;
      return With_Length (Payload);
   exception
      when others =>
         SSH_Lib.Protocol.Buffers.Clear (Payload);
         return Payload;
   end Encode_Link_Request;

   function Encode_Block_Request
     (Request_Id : Interfaces.Unsigned_32;
      Message    : Stream_Element;
      Handle     : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Offset     : Interfaces.Unsigned_64;
      Length     : Interfaces.Unsigned_64;
      Lock_Mask  : Interfaces.Unsigned_32 := 0)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer
   is
      Payload      : SSH_Lib.Protocol.Buffers.Packet_Buffer :=
        Start_Request (Message, Request_Id);
      Status_Value : CryptoLib.Errors.Status;
   begin
      if SSH_Lib.Protocol.Buffers.Is_Empty (Payload)
        or else SSH_Lib.Protocol.Buffers.Is_Empty (Handle)
      then
         SSH_Lib.Protocol.Buffers.Clear (Payload);
         return Payload;
      end if;

      Status_Value :=
        Append_SFTP_String
          (Payload, SSH_Lib.Protocol.Buffers.To_Array (Handle));
      if Status_Value = CryptoLib.Errors.Ok then
         Status_Value :=
           SSH_Lib.Protocol.Buffers.Append (Payload, Encode_Uint64 (Offset));
      end if;
      if Status_Value = CryptoLib.Errors.Ok then
         Status_Value :=
           SSH_Lib.Protocol.Buffers.Append (Payload, Encode_Uint64 (Length));
      end if;
      if Status_Value = CryptoLib.Errors.Ok and then Message = SSH_FXP_BLOCK then
         Status_Value :=
           SSH_Lib.Protocol.Buffers.Append
             (Payload, SSH_Lib.Protocol.Numbers.Encode_Uint32 (Lock_Mask));
      end if;
      if Status_Value /= CryptoLib.Errors.Ok then
         SSH_Lib.Protocol.Buffers.Clear (Payload);
         return Payload;
      end if;
      return With_Length (Payload);
   exception
      when others =>
         SSH_Lib.Protocol.Buffers.Clear (Payload);
         return Payload;
   end Encode_Block_Request;

   function Encode_Text_Seek_Request
     (Request_Id  : Interfaces.Unsigned_32;
      Handle      : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Line_Number : Interfaces.Unsigned_64)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer
   is
      Payload      : SSH_Lib.Protocol.Buffers.Packet_Buffer :=
        Encode_Extended_Request (Request_Id, Text_Seek_Extension);
      Status_Value : CryptoLib.Errors.Status;
   begin
      if SSH_Lib.Protocol.Buffers.Is_Empty (Payload)
        or else SSH_Lib.Protocol.Buffers.Is_Empty (Handle)
      then
         SSH_Lib.Protocol.Buffers.Clear (Payload);
         return Payload;
      end if;

      Status_Value :=
        Append_SFTP_String
          (Payload, SSH_Lib.Protocol.Buffers.To_Array (Handle));
      if Status_Value = CryptoLib.Errors.Ok then
         Status_Value :=
           SSH_Lib.Protocol.Buffers.Append
             (Payload, Encode_Uint64 (Line_Number));
      end if;
      if Status_Value /= CryptoLib.Errors.Ok then
         SSH_Lib.Protocol.Buffers.Clear (Payload);
         return Payload;
      end if;
      return With_Length (Payload);
   exception
      when others =>
         SSH_Lib.Protocol.Buffers.Clear (Payload);
         return Payload;
   end Encode_Text_Seek_Request;

   function Encode_Version_Select_Request
     (Request_Id : Interfaces.Unsigned_32; Requested_Version : Natural)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer
   is
      Payload      : SSH_Lib.Protocol.Buffers.Packet_Buffer :=
        Encode_Extended_Request (Request_Id, Version_Select_Extension);
      Status_Value : CryptoLib.Errors.Status;
   begin
      if SSH_Lib.Protocol.Buffers.Is_Empty (Payload) then
         return Payload;
      end if;

      Status_Value :=
        Append_SFTP_String
          (Payload, To_Stream (Natural_Text (Requested_Version)));
      if Status_Value /= CryptoLib.Errors.Ok then
         SSH_Lib.Protocol.Buffers.Clear (Payload);
         return Payload;
      end if;
      return With_Length (Payload);
   exception
      when others =>
         SSH_Lib.Protocol.Buffers.Clear (Payload);
         return Payload;
   end Encode_Version_Select_Request;

   function Has_Attributes (Attributes : File_Attributes) return Boolean;

   function Append_Attributes
     (Packet     : in out SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Attributes : File_Attributes) return CryptoLib.Errors.Status;

   function Encode_Extended_Request
     (Request_Id : Interfaces.Unsigned_32; Extension_Name : String)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer
   is
      Payload      : SSH_Lib.Protocol.Buffers.Packet_Buffer :=
        Start_Request (SSH_FXP_EXTENDED, Request_Id);
      Status_Value : CryptoLib.Errors.Status;
   begin
      if SSH_Lib.Protocol.Buffers.Is_Empty (Payload)
        or else Extension_Name'Length = 0
      then
         SSH_Lib.Protocol.Buffers.Clear (Payload);
         return Payload;
      end if;

      Status_Value := Append_SFTP_String (Payload, To_Stream (Extension_Name));
      if Status_Value /= CryptoLib.Errors.Ok then
         SSH_Lib.Protocol.Buffers.Clear (Payload);
      end if;
      return Payload;
   exception
      when others =>
         SSH_Lib.Protocol.Buffers.Clear (Payload);
         return Payload;
   end Encode_Extended_Request;

   function Encode_Extended_Name_Request
     (Request_Id : Interfaces.Unsigned_32; Extension_Name : String)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer
   is
      Payload : SSH_Lib.Protocol.Buffers.Packet_Buffer :=
        Encode_Extended_Request (Request_Id, Extension_Name);
   begin
      if SSH_Lib.Protocol.Buffers.Is_Empty (Payload) then
         return Payload;
      end if;
      return With_Length (Payload);
   exception
      when others =>
         SSH_Lib.Protocol.Buffers.Clear (Payload);
         return Payload;
   end Encode_Extended_Name_Request;

   function Encode_Extended_Raw_Request
     (Request_Id     : Interfaces.Unsigned_32;
      Extension_Name : String;
      Payload_Data   : Stream_Element_Array)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer
   is
      Payload      : SSH_Lib.Protocol.Buffers.Packet_Buffer :=
        Encode_Extended_Request (Request_Id, Extension_Name);
      Status_Value : CryptoLib.Errors.Status;
   begin
      if SSH_Lib.Protocol.Buffers.Is_Empty (Payload) then
         return Payload;
      end if;

      if Payload_Data'Length > 0 then
         Status_Value :=
           SSH_Lib.Protocol.Buffers.Append (Payload, Payload_Data);
         if Status_Value /= CryptoLib.Errors.Ok then
            SSH_Lib.Protocol.Buffers.Clear (Payload);
            return Payload;
         end if;
      end if;
      return With_Length (Payload);
   exception
      when others =>
         SSH_Lib.Protocol.Buffers.Clear (Payload);
         return Payload;
   end Encode_Extended_Raw_Request;

   function Encode_Extended_Path_Request
     (Request_Id     : Interfaces.Unsigned_32;
      Extension_Name : String;
      Remote_Path    : String) return SSH_Lib.Protocol.Buffers.Packet_Buffer
   is
      Payload      : SSH_Lib.Protocol.Buffers.Packet_Buffer :=
        Encode_Extended_Request (Request_Id, Extension_Name);
      Status_Value : CryptoLib.Errors.Status;
   begin
      if SSH_Lib.Protocol.Buffers.Is_Empty (Payload)
        or else not Safe_Remote_Path (Remote_Path)
      then
         SSH_Lib.Protocol.Buffers.Clear (Payload);
         return Payload;
      end if;

      Status_Value := Append_SFTP_String (Payload, To_Stream (Remote_Path));
      if Status_Value /= CryptoLib.Errors.Ok then
         SSH_Lib.Protocol.Buffers.Clear (Payload);
         return Payload;
      end if;
      return With_Length (Payload);
   exception
      when others =>
         SSH_Lib.Protocol.Buffers.Clear (Payload);
         return Payload;
   end Encode_Extended_Path_Request;

   function Encode_Extended_Two_Path_Request
     (Request_Id     : Interfaces.Unsigned_32;
      Extension_Name : String;
      First_Path     : String;
      Second_Path    : String) return SSH_Lib.Protocol.Buffers.Packet_Buffer
   is
      Payload      : SSH_Lib.Protocol.Buffers.Packet_Buffer :=
        Encode_Extended_Request (Request_Id, Extension_Name);
      Status_Value : CryptoLib.Errors.Status;
   begin
      if SSH_Lib.Protocol.Buffers.Is_Empty (Payload)
        or else not Safe_Remote_Path (First_Path)
        or else not Safe_Remote_Path (Second_Path)
      then
         SSH_Lib.Protocol.Buffers.Clear (Payload);
         return Payload;
      end if;

      Status_Value := Append_SFTP_String (Payload, To_Stream (First_Path));
      if Status_Value = CryptoLib.Errors.Ok then
         Status_Value := Append_SFTP_String (Payload, To_Stream (Second_Path));
      end if;
      if Status_Value /= CryptoLib.Errors.Ok then
         SSH_Lib.Protocol.Buffers.Clear (Payload);
         return Payload;
      end if;
      return With_Length (Payload);
   exception
      when others =>
         SSH_Lib.Protocol.Buffers.Clear (Payload);
         return Payload;
   end Encode_Extended_Two_Path_Request;

   function Encode_Extended_Handle_Request
     (Request_Id     : Interfaces.Unsigned_32;
      Extension_Name : String;
      Handle         : SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer
   is
      Payload      : SSH_Lib.Protocol.Buffers.Packet_Buffer :=
        Encode_Extended_Request (Request_Id, Extension_Name);
      Status_Value : CryptoLib.Errors.Status;
   begin
      if SSH_Lib.Protocol.Buffers.Is_Empty (Payload)
        or else SSH_Lib.Protocol.Buffers.Is_Empty (Handle)
      then
         SSH_Lib.Protocol.Buffers.Clear (Payload);
         return Payload;
      end if;

      Status_Value :=
        Append_SFTP_String
          (Payload, SSH_Lib.Protocol.Buffers.To_Array (Handle));
      if Status_Value /= CryptoLib.Errors.Ok then
         SSH_Lib.Protocol.Buffers.Clear (Payload);
         return Payload;
      end if;
      return With_Length (Payload);
   exception
      when others =>
         SSH_Lib.Protocol.Buffers.Clear (Payload);
         return Payload;
   end Encode_Extended_Handle_Request;

   function Encode_Copy_Data_Request
     (Request_Id    : Interfaces.Unsigned_32;
      Source_Handle : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Source_Offset : Interfaces.Unsigned_64;
      Length        : Interfaces.Unsigned_64;
      Target_Handle : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Target_Offset : Interfaces.Unsigned_64)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer
   is
      Payload      : SSH_Lib.Protocol.Buffers.Packet_Buffer :=
        Encode_Extended_Request (Request_Id, Copy_Data_Extension);
      Status_Value : CryptoLib.Errors.Status;
   begin
      if SSH_Lib.Protocol.Buffers.Is_Empty (Payload)
        or else SSH_Lib.Protocol.Buffers.Is_Empty (Source_Handle)
        or else SSH_Lib.Protocol.Buffers.Is_Empty (Target_Handle)
      then
         SSH_Lib.Protocol.Buffers.Clear (Payload);
         return Payload;
      end if;

      Status_Value :=
        Append_SFTP_String
          (Payload, SSH_Lib.Protocol.Buffers.To_Array (Source_Handle));
      if Status_Value = CryptoLib.Errors.Ok then
         Status_Value :=
           SSH_Lib.Protocol.Buffers.Append
             (Payload, Encode_Uint64 (Source_Offset));
      end if;
      if Status_Value = CryptoLib.Errors.Ok then
         Status_Value :=
           SSH_Lib.Protocol.Buffers.Append (Payload, Encode_Uint64 (Length));
      end if;
      if Status_Value = CryptoLib.Errors.Ok then
         Status_Value :=
           Append_SFTP_String
             (Payload, SSH_Lib.Protocol.Buffers.To_Array (Target_Handle));
      end if;
      if Status_Value = CryptoLib.Errors.Ok then
         Status_Value :=
           SSH_Lib.Protocol.Buffers.Append
             (Payload, Encode_Uint64 (Target_Offset));
      end if;
      if Status_Value /= CryptoLib.Errors.Ok then
         SSH_Lib.Protocol.Buffers.Clear (Payload);
         return Payload;
      end if;
      return With_Length (Payload);
   exception
      when others =>
         SSH_Lib.Protocol.Buffers.Clear (Payload);
         return Payload;
   end Encode_Copy_Data_Request;

   function Encode_Check_File_Request
     (Request_Id : Interfaces.Unsigned_32;
      Handle     : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Algorithms : String;
      Offset     : Interfaces.Unsigned_64;
      Length     : Interfaces.Unsigned_64;
      Block_Size : Interfaces.Unsigned_32)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer
   is
      Payload      : SSH_Lib.Protocol.Buffers.Packet_Buffer :=
        Encode_Extended_Request (Request_Id, Check_File_Extension);
      Status_Value : CryptoLib.Errors.Status;
   begin
      if SSH_Lib.Protocol.Buffers.Is_Empty (Payload)
        or else SSH_Lib.Protocol.Buffers.Is_Empty (Handle)
        or else Algorithms'Length = 0
      then
         SSH_Lib.Protocol.Buffers.Clear (Payload);
         return Payload;
      end if;

      Status_Value :=
        Append_SFTP_String
          (Payload, SSH_Lib.Protocol.Buffers.To_Array (Handle));
      if Status_Value = CryptoLib.Errors.Ok then
         Status_Value := Append_SFTP_String (Payload, To_Stream (Algorithms));
      end if;
      if Status_Value = CryptoLib.Errors.Ok then
         Status_Value :=
           SSH_Lib.Protocol.Buffers.Append (Payload, Encode_Uint64 (Offset));
      end if;
      if Status_Value = CryptoLib.Errors.Ok then
         Status_Value :=
           SSH_Lib.Protocol.Buffers.Append (Payload, Encode_Uint64 (Length));
      end if;
      if Status_Value = CryptoLib.Errors.Ok then
         Status_Value :=
           SSH_Lib.Protocol.Buffers.Append
             (Payload, SSH_Lib.Protocol.Numbers.Encode_Uint32 (Block_Size));
      end if;
      if Status_Value /= CryptoLib.Errors.Ok then
         SSH_Lib.Protocol.Buffers.Clear (Payload);
         return Payload;
      end if;
      return With_Length (Payload);
   exception
      when others =>
         SSH_Lib.Protocol.Buffers.Clear (Payload);
         return Payload;
   end Encode_Check_File_Request;

   function Encode_Extended_Set_Attributes_Request
     (Request_Id     : Interfaces.Unsigned_32;
      Extension_Name : String;
      Remote_Path    : String;
      Attributes     : File_Attributes)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer
   is
      Payload      : SSH_Lib.Protocol.Buffers.Packet_Buffer :=
        Encode_Extended_Request (Request_Id, Extension_Name);
      Status_Value : CryptoLib.Errors.Status;
   begin
      if SSH_Lib.Protocol.Buffers.Is_Empty (Payload)
        or else not Safe_Remote_Path (Remote_Path)
        or else not Has_Attributes (Attributes)
      then
         SSH_Lib.Protocol.Buffers.Clear (Payload);
         return Payload;
      end if;

      Status_Value := Append_SFTP_String (Payload, To_Stream (Remote_Path));
      if Status_Value = CryptoLib.Errors.Ok then
         Status_Value := Append_Attributes (Payload, Attributes);
      end if;
      if Status_Value /= CryptoLib.Errors.Ok then
         SSH_Lib.Protocol.Buffers.Clear (Payload);
         return Payload;
      end if;
      return With_Length (Payload);
   exception
      when others =>
         SSH_Lib.Protocol.Buffers.Clear (Payload);
         return Payload;
   end Encode_Extended_Set_Attributes_Request;

   function Encode_Open_Read_Request
     (Request_Id  : Interfaces.Unsigned_32;
      Remote_Path : String;
      Version     : Natural := Protocol_Version)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer is
   begin
      return
        Encode_Open_Mode_Request
          (Request_Id, Remote_Path, Read_Only, "0000", Version);
   end Encode_Open_Read_Request;

   function Encode_Handle_Request
     (Message_Type : Stream_Element;
      Request_Id   : Interfaces.Unsigned_32;
      Handle       : SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer
   is
      Payload      : SSH_Lib.Protocol.Buffers.Packet_Buffer :=
        Start_Request (Message_Type, Request_Id);
      Status_Value : CryptoLib.Errors.Status;
   begin
      if SSH_Lib.Protocol.Buffers.Is_Empty (Payload) then
         return Payload;
      end if;

      Status_Value :=
        Append_SFTP_String
          (Payload, SSH_Lib.Protocol.Buffers.To_Array (Handle));
      if Status_Value /= CryptoLib.Errors.Ok then
         SSH_Lib.Protocol.Buffers.Clear (Payload);
         return Payload;
      end if;
      return With_Length (Payload);
   exception
      when others =>
         SSH_Lib.Protocol.Buffers.Clear (Payload);
         return Payload;
   end Encode_Handle_Request;

   function Encode_Read_Request
     (Request_Id : Interfaces.Unsigned_32;
      Handle     : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Offset     : Interfaces.Unsigned_64;
      Length     : Natural) return SSH_Lib.Protocol.Buffers.Packet_Buffer
   is
      Payload      : SSH_Lib.Protocol.Buffers.Packet_Buffer :=
        Start_Request (SSH_FXP_READ, Request_Id);
      Status_Value : CryptoLib.Errors.Status;
   begin
      if SSH_Lib.Protocol.Buffers.Is_Empty (Payload) or else Length = 0 then
         SSH_Lib.Protocol.Buffers.Clear (Payload);
         return Payload;
      end if;

      Status_Value :=
        Append_SFTP_String
          (Payload, SSH_Lib.Protocol.Buffers.To_Array (Handle));
      if Status_Value = CryptoLib.Errors.Ok then
         Status_Value :=
           SSH_Lib.Protocol.Buffers.Append (Payload, Encode_Uint64 (Offset));
      end if;
      if Status_Value = CryptoLib.Errors.Ok then
         Status_Value :=
           SSH_Lib.Protocol.Buffers.Append
             (Payload,
              SSH_Lib.Protocol.Numbers.Encode_Uint32
                (Interfaces.Unsigned_32 (Length)));
      end if;
      if Status_Value /= CryptoLib.Errors.Ok then
         SSH_Lib.Protocol.Buffers.Clear (Payload);
         return Payload;
      end if;
      return With_Length (Payload);
   exception
      when others =>
         SSH_Lib.Protocol.Buffers.Clear (Payload);
         return Payload;
   end Encode_Read_Request;

   function Append_Attributes
     (Packet     : in out SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Attributes : File_Attributes;
      Version    : Natural) return CryptoLib.Errors.Status;

   function Append_Open_Attributes
     (Packet     : in out SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Attributes : File_Attributes;
      Has_Attrs  : Boolean;
      Version    : Natural) return CryptoLib.Errors.Status
   is
      Status_Value : CryptoLib.Errors.Status;
   begin
      if Has_Attrs then
         return Append_Attributes (Packet, Attributes, Version);
      elsif Version <= 3 then
         return
           SSH_Lib.Protocol.Buffers.Append
             (Packet, SSH_Lib.Protocol.Numbers.Encode_Uint32 (0));
      else
         Status_Value :=
           SSH_Lib.Protocol.Buffers.Append
             (Packet, SSH_Lib.Protocol.Numbers.Encode_Uint32 (0));
         if Status_Value = CryptoLib.Errors.Ok then
            Status_Value :=
              SSH_Lib.Protocol.Buffers.Append_Byte (Packet, File_Type_Unknown);
         end if;
         return Status_Value;
      end if;
   exception
      when others =>
         return CryptoLib.Errors.Internal_Error;
   end Append_Open_Attributes;

   function Encode_Mkdir_Request
     (Request_Id  : Interfaces.Unsigned_32;
      Remote_Path : String;
      Mode        : String;
      Version     : Natural := Protocol_Version)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer
   is
      Payload      : SSH_Lib.Protocol.Buffers.Packet_Buffer :=
        Start_Request (SSH_FXP_MKDIR, Request_Id);
      Permissions  : Interfaces.Unsigned_32 := 0;
      Attributes   : File_Attributes;
      Status_Value : CryptoLib.Errors.Status;
   begin
      if SSH_Lib.Protocol.Buffers.Is_Empty (Payload)
        or else not Safe_Remote_Path (Remote_Path)
        or else Parse_Mode (Mode, Permissions) /= CryptoLib.Errors.Ok
      then
         SSH_Lib.Protocol.Buffers.Clear (Payload);
         return Payload;
      end if;

      Attributes.Permissions_Known := True;
      Attributes.Permissions := Directory_Type or Permissions;
      Status_Value := Append_SFTP_String (Payload, To_Stream (Remote_Path));
      if Status_Value = CryptoLib.Errors.Ok then
         Status_Value := Append_Attributes (Payload, Attributes, Version);
      end if;
      if Status_Value /= CryptoLib.Errors.Ok then
         SSH_Lib.Protocol.Buffers.Clear (Payload);
         return Payload;
      end if;
      return With_Length (Payload);
   exception
      when others =>
         SSH_Lib.Protocol.Buffers.Clear (Payload);
         return Payload;
   end Encode_Mkdir_Request;

   function Append_Attributes
     (Packet     : in out SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Attributes : File_Attributes) return CryptoLib.Errors.Status
   is
      Flags        : Interfaces.Unsigned_32 := 0;
      Status_Value : CryptoLib.Errors.Status;
   begin
      if Attributes.Size_Known then
         Flags := Flags or Attr_Size;
      end if;
      if Attributes.UID_GID_Known then
         Flags := Flags or Attr_UID_GID;
      end if;
      if Attributes.Permissions_Known then
         Flags := Flags or Attr_Permissions;
      end if;
      if Attributes.Times_Known then
         Flags := Flags or Attr_ACMODTime;
      end if;
      if not Attributes.Extended_Attributes.Is_Empty then
         Flags := Flags or Attr_Extended;
      end if;
      if Flags = 0 then
         return CryptoLib.Errors.Invalid_Command;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Buffers.Append
          (Packet, SSH_Lib.Protocol.Numbers.Encode_Uint32 (Flags));
      if Status_Value = CryptoLib.Errors.Ok and then Attributes.Size_Known then
         Status_Value :=
           SSH_Lib.Protocol.Buffers.Append
             (Packet, Encode_Uint64 (Attributes.Size));
      end if;
      if Status_Value = CryptoLib.Errors.Ok and then Attributes.UID_GID_Known
      then
         Status_Value :=
           SSH_Lib.Protocol.Buffers.Append
             (Packet, SSH_Lib.Protocol.Numbers.Encode_Uint32 (Attributes.UID));
      end if;
      if Status_Value = CryptoLib.Errors.Ok and then Attributes.UID_GID_Known
      then
         Status_Value :=
           SSH_Lib.Protocol.Buffers.Append
             (Packet, SSH_Lib.Protocol.Numbers.Encode_Uint32 (Attributes.GID));
      end if;
      if Status_Value = CryptoLib.Errors.Ok and then Attributes.Permissions_Known
      then
         Status_Value :=
           SSH_Lib.Protocol.Buffers.Append
             (Packet,
              SSH_Lib.Protocol.Numbers.Encode_Uint32 (Attributes.Permissions));
      end if;
      if Status_Value = CryptoLib.Errors.Ok and then Attributes.Times_Known then
         Status_Value :=
           SSH_Lib.Protocol.Buffers.Append
             (Packet,
              SSH_Lib.Protocol.Numbers.Encode_Uint32 (Attributes.Access_Time));
      end if;
      if Status_Value = CryptoLib.Errors.Ok and then Attributes.Times_Known then
         Status_Value :=
           SSH_Lib.Protocol.Buffers.Append
             (Packet,
              SSH_Lib.Protocol.Numbers.Encode_Uint32 (Attributes.Modify_Time));
      end if;
      if Status_Value = CryptoLib.Errors.Ok
        and then not Attributes.Extended_Attributes.Is_Empty
      then
         Status_Value :=
           SSH_Lib.Protocol.Buffers.Append
             (Packet,
              SSH_Lib.Protocol.Numbers.Encode_Uint32
                (Interfaces.Unsigned_32
                   (Attributes.Extended_Attributes.Length)));
      end if;
      if Status_Value = CryptoLib.Errors.Ok then
         for Attribute of Attributes.Extended_Attributes loop
            Status_Value :=
              Append_SFTP_String
                (Packet, To_Stream (To_String (Attribute.Name)));
            if Status_Value /= CryptoLib.Errors.Ok then
               return Status_Value;
            end if;
            Status_Value :=
              Append_SFTP_String
                (Packet, To_Stream (To_String (Attribute.Value)));
            if Status_Value /= CryptoLib.Errors.Ok then
               return Status_Value;
            end if;
         end loop;
      end if;
      return Status_Value;
   exception
      when others =>
         return CryptoLib.Errors.Internal_Error;
   end Append_Attributes;

   function Append_Attributes
     (Packet     : in out SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Attributes : File_Attributes;
      Version    : Natural) return CryptoLib.Errors.Status
   is
      Flags        : Interfaces.Unsigned_32 := 0;
      Status_Value : CryptoLib.Errors.Status;
   begin
      if Version <= 3 then
         return Append_Attributes (Packet, Attributes);
      end if;

      if Attributes.Size_Known then
         Flags := Flags or Attr4_Size;
      end if;
      if Attributes.Allocation_Size_Known then
         Flags := Flags or Attr4_Allocation_Size;
      end if;
      if Attributes.Owner_Group_Known then
         Flags := Flags or Attr4_Owner_Group;
      end if;
      if Attributes.Permissions_Known then
         Flags := Flags or Attr4_Permissions;
      end if;
      if Attributes.Times_Known then
         Flags := Flags or Attr4_Access_Time or Attr4_Modify_Time;
      end if;
      if Attributes.Create_Time_Known then
         Flags := Flags or Attr4_Create_Time;
      end if;
      if Attributes.ACL_Known then
         Flags := Flags or Attr4_ACL;
      end if;
      if Attributes.Attribute_Bits_Known then
         Flags := Flags or Attr4_Bits;
      end if;
      if Attributes.Text_Hint_Known then
         Flags := Flags or Attr4_Text_Hint;
      end if;
      if Attributes.Mime_Type_Known then
         Flags := Flags or Attr4_Mime_Type;
      end if;
      if Attributes.Link_Count_Known then
         Flags := Flags or Attr4_Link_Count;
      end if;
      if Attributes.Untranslated_Name_Known then
         Flags := Flags or Attr4_Untranslated_Name;
      end if;
      if not Attributes.Extended_Attributes.Is_Empty then
         Flags := Flags or Attr4_Extended;
      end if;
      if Flags = 0 then
         return CryptoLib.Errors.Invalid_Command;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Buffers.Append
          (Packet, SSH_Lib.Protocol.Numbers.Encode_Uint32 (Flags));
      if Status_Value = CryptoLib.Errors.Ok then
         Status_Value :=
           SSH_Lib.Protocol.Buffers.Append_Byte
             (Packet, File_Type_From_Permissions (Attributes));
      end if;
      if Status_Value = CryptoLib.Errors.Ok and then Attributes.Size_Known then
         Status_Value :=
           SSH_Lib.Protocol.Buffers.Append
             (Packet, Encode_Uint64 (Attributes.Size));
      end if;
      if Status_Value = CryptoLib.Errors.Ok
        and then Attributes.Allocation_Size_Known
      then
         Status_Value :=
           SSH_Lib.Protocol.Buffers.Append
             (Packet, Encode_Uint64 (Attributes.Allocation_Size));
      end if;
      if Status_Value = CryptoLib.Errors.Ok and then Attributes.Owner_Group_Known
      then
         Status_Value :=
           Append_SFTP_String
             (Packet, To_Stream (To_String (Attributes.Owner)));
      end if;
      if Status_Value = CryptoLib.Errors.Ok and then Attributes.Owner_Group_Known
      then
         Status_Value :=
           Append_SFTP_String
             (Packet, To_Stream (To_String (Attributes.Group)));
      end if;
      if Status_Value = CryptoLib.Errors.Ok and then Attributes.Permissions_Known
      then
         Status_Value :=
           SSH_Lib.Protocol.Buffers.Append
             (Packet,
              SSH_Lib.Protocol.Numbers.Encode_Uint32 (Attributes.Permissions));
      end if;
      if Status_Value = CryptoLib.Errors.Ok and then Attributes.Times_Known then
         Status_Value :=
           SSH_Lib.Protocol.Buffers.Append
             (Packet,
              Encode_Uint64 (Interfaces.Unsigned_64 (Attributes.Access_Time)));
      end if;
      if Status_Value = CryptoLib.Errors.Ok and then Attributes.Times_Known then
         Status_Value :=
           SSH_Lib.Protocol.Buffers.Append
             (Packet,
              SSH_Lib.Protocol.Numbers.Encode_Uint32
                (Attributes.Access_Time_Nanoseconds));
      end if;
      if Status_Value = CryptoLib.Errors.Ok and then Attributes.Create_Time_Known
      then
         Status_Value :=
           SSH_Lib.Protocol.Buffers.Append
             (Packet,
              Encode_Uint64 (Interfaces.Unsigned_64 (Attributes.Create_Time)));
      end if;
      if Status_Value = CryptoLib.Errors.Ok and then Attributes.Create_Time_Known
      then
         Status_Value :=
           SSH_Lib.Protocol.Buffers.Append
             (Packet,
              SSH_Lib.Protocol.Numbers.Encode_Uint32
                (Attributes.Create_Time_Nanoseconds));
      end if;
      if Status_Value = CryptoLib.Errors.Ok and then Attributes.Times_Known then
         Status_Value :=
           SSH_Lib.Protocol.Buffers.Append
             (Packet,
              Encode_Uint64 (Interfaces.Unsigned_64 (Attributes.Modify_Time)));
      end if;
      if Status_Value = CryptoLib.Errors.Ok and then Attributes.Times_Known then
         Status_Value :=
           SSH_Lib.Protocol.Buffers.Append
             (Packet,
              SSH_Lib.Protocol.Numbers.Encode_Uint32
                (Attributes.Modify_Time_Nanoseconds));
      end if;
      if Status_Value = CryptoLib.Errors.Ok and then Attributes.ACL_Known then
         Status_Value :=
           Append_SFTP_String (Packet, To_Stream (To_String (Attributes.ACL)));
      end if;
      if Status_Value = CryptoLib.Errors.Ok
        and then Attributes.Attribute_Bits_Known
      then
         Status_Value :=
           SSH_Lib.Protocol.Buffers.Append
             (Packet,
              SSH_Lib.Protocol.Numbers.Encode_Uint32
                (Attributes.Attribute_Bits));
      end if;
      if Status_Value = CryptoLib.Errors.Ok
        and then Attributes.Attribute_Bits_Known
      then
         Status_Value :=
           SSH_Lib.Protocol.Buffers.Append
             (Packet,
              SSH_Lib.Protocol.Numbers.Encode_Uint32
                (Attributes.Attribute_Bits_Valid));
      end if;
      if Status_Value = CryptoLib.Errors.Ok and then Attributes.Text_Hint_Known
      then
         Status_Value :=
           SSH_Lib.Protocol.Buffers.Append_Byte
             (Packet, Stream_Element (Attributes.Text_Hint));
      end if;
      if Status_Value = CryptoLib.Errors.Ok and then Attributes.Mime_Type_Known
      then
         Status_Value :=
           Append_SFTP_String
             (Packet, To_Stream (To_String (Attributes.Mime_Type)));
      end if;
      if Status_Value = CryptoLib.Errors.Ok and then Attributes.Link_Count_Known
      then
         Status_Value :=
           SSH_Lib.Protocol.Buffers.Append
             (Packet,
              SSH_Lib.Protocol.Numbers.Encode_Uint32 (Attributes.Link_Count));
      end if;
      if Status_Value = CryptoLib.Errors.Ok
        and then Attributes.Untranslated_Name_Known
      then
         Status_Value :=
           Append_SFTP_String
             (Packet, To_Stream (To_String (Attributes.Untranslated_Name)));
      end if;
      if Status_Value = CryptoLib.Errors.Ok
        and then not Attributes.Extended_Attributes.Is_Empty
      then
         Status_Value :=
           SSH_Lib.Protocol.Buffers.Append
             (Packet,
              SSH_Lib.Protocol.Numbers.Encode_Uint32
                (Interfaces.Unsigned_32
                   (Attributes.Extended_Attributes.Length)));
      end if;
      if Status_Value = CryptoLib.Errors.Ok then
         for Attribute of Attributes.Extended_Attributes loop
            Status_Value :=
              Append_SFTP_String
                (Packet, To_Stream (To_String (Attribute.Name)));
            if Status_Value /= CryptoLib.Errors.Ok then
               return Status_Value;
            end if;
            Status_Value :=
              Append_SFTP_String
                (Packet, To_Stream (To_String (Attribute.Value)));
            if Status_Value /= CryptoLib.Errors.Ok then
               return Status_Value;
            end if;
         end loop;
      end if;
      return Status_Value;
   exception
      when others =>
         return CryptoLib.Errors.Internal_Error;
   end Append_Attributes;

   function Permissions_Attributes (Mode : String) return File_Attributes is
      Permissions  : Interfaces.Unsigned_32 := 0;
      Status_Value : CryptoLib.Errors.Status;
      Result       : File_Attributes;
   begin
      Status_Value := Parse_Mode (Mode, Permissions);
      if Status_Value = CryptoLib.Errors.Ok then
         Result.Permissions_Known := True;
         Result.Permissions := Permissions;
      end if;
      return Result;
   exception
      when others =>
         return (others => <>);
   end Permissions_Attributes;

   function Has_Attributes (Attributes : File_Attributes) return Boolean is
   begin
      return
        Attributes.Size_Known
        or else Attributes.Allocation_Size_Known
        or else Attributes.UID_GID_Known
        or else Attributes.Owner_Group_Known
        or else Attributes.Permissions_Known
        or else Attributes.Times_Known
        or else Attributes.Create_Time_Known
        or else Attributes.ACL_Known
        or else Attributes.Attribute_Bits_Known
        or else Attributes.Text_Hint_Known
        or else Attributes.Mime_Type_Known
        or else Attributes.Link_Count_Known
        or else Attributes.Untranslated_Name_Known
        or else not Attributes.Extended_Attributes.Is_Empty;
   end Has_Attributes;

   function Encode_Set_Attributes_Request
     (Request_Id  : Interfaces.Unsigned_32;
      Remote_Path : String;
      Attributes  : File_Attributes;
      Version     : Natural := Protocol_Version)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer
   is
      Payload      : SSH_Lib.Protocol.Buffers.Packet_Buffer :=
        Start_Request (SSH_FXP_SETSTAT, Request_Id);
      Status_Value : CryptoLib.Errors.Status;
   begin
      if SSH_Lib.Protocol.Buffers.Is_Empty (Payload)
        or else not Safe_Remote_Path (Remote_Path)
      then
         SSH_Lib.Protocol.Buffers.Clear (Payload);
         return Payload;
      end if;

      Status_Value := Append_SFTP_String (Payload, To_Stream (Remote_Path));
      if Status_Value = CryptoLib.Errors.Ok then
         Status_Value := Append_Attributes (Payload, Attributes, Version);
      end if;
      if Status_Value /= CryptoLib.Errors.Ok then
         SSH_Lib.Protocol.Buffers.Clear (Payload);
         return Payload;
      end if;
      return With_Length (Payload);
   exception
      when others =>
         SSH_Lib.Protocol.Buffers.Clear (Payload);
         return Payload;
   end Encode_Set_Attributes_Request;

   function Encode_FSet_Attributes_Request
     (Request_Id : Interfaces.Unsigned_32;
      Handle     : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Attributes : File_Attributes;
      Version    : Natural := Protocol_Version)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer
   is
      Payload      : SSH_Lib.Protocol.Buffers.Packet_Buffer :=
        Start_Request (SSH_FXP_FSETSTAT, Request_Id);
      Status_Value : CryptoLib.Errors.Status;
   begin
      if SSH_Lib.Protocol.Buffers.Is_Empty (Payload)
        or else SSH_Lib.Protocol.Buffers.Is_Empty (Handle)
      then
         SSH_Lib.Protocol.Buffers.Clear (Payload);
         return Payload;
      end if;

      Status_Value :=
        Append_SFTP_String
          (Payload, SSH_Lib.Protocol.Buffers.To_Array (Handle));
      if Status_Value = CryptoLib.Errors.Ok then
         Status_Value := Append_Attributes (Payload, Attributes, Version);
      end if;
      if Status_Value /= CryptoLib.Errors.Ok then
         SSH_Lib.Protocol.Buffers.Clear (Payload);
         return Payload;
      end if;
      return With_Length (Payload);
   exception
      when others =>
         SSH_Lib.Protocol.Buffers.Clear (Payload);
         return Payload;
   end Encode_FSet_Attributes_Request;

   function Encode_Init_Packet
     (Requested_Version : Natural)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer
   is
      Result       : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Status_Value : CryptoLib.Errors.Status;
   begin
      SSH_Lib.Protocol.Buffers.Clear (Result);
      if not Supports_Protocol_Version (Requested_Version) then
         return Result;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Buffers.Append
          (Result,
           SSH_Lib.Protocol.Numbers.Encode_Uint32
             (Interfaces.Unsigned_32 (5)));
      if Status_Value /= CryptoLib.Errors.Ok then
         SSH_Lib.Protocol.Buffers.Clear (Result);
         return Result;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Buffers.Append_Byte (Result, SSH_FXP_INIT);
      if Status_Value /= CryptoLib.Errors.Ok then
         SSH_Lib.Protocol.Buffers.Clear (Result);
         return Result;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Buffers.Append
          (Result,
           SSH_Lib.Protocol.Numbers.Encode_Uint32
             (Interfaces.Unsigned_32 (Requested_Version)));
      if Status_Value /= CryptoLib.Errors.Ok then
         SSH_Lib.Protocol.Buffers.Clear (Result);
      end if;
      return Result;
   exception
      when others =>
         SSH_Lib.Protocol.Buffers.Clear (Result);
         return Result;
   end Encode_Init_Packet;

   function Encode_Init_Packet return SSH_Lib.Protocol.Buffers.Packet_Buffer is
   begin
      return Encode_Init_Packet (Protocol_Version);
   end Encode_Init_Packet;

   procedure Mark_Extension
     (Extensions : in out Extension_Info; Name : String);

   procedure Parse_Versions_Extension
     (Extensions : in out Extension_Info; Data : Stream_Element_Array)
   is
      Text  : constant String := Stream_To_Text (Data);
      First : Positive := Text'First;
      Last  : Natural;
   begin
      Extensions.Versions := True;
      while First <= Text'Last loop
         Last := First;
         while Last <= Text'Last and then Text (Last) /= ',' loop
            Last := Last + 1;
         end loop;

         declare
            Token : constant String := Text (First .. Last - 1);
         begin
            if Token = "2" then
               Extensions.Version_2 := True;
            elsif Token = "3" then
               Extensions.Version_3 := True;
            elsif Token = "4" then
               Extensions.Version_4 := True;
            elsif Token = "5" then
               Extensions.Version_5 := True;
            elsif Token = "6" then
               Extensions.Version_6 := True;
            end if;
         end;

         First := Last + 1;
      end loop;
   exception
      when others =>
         Extensions.Versions := True;
   end Parse_Versions_Extension;

   procedure Parse_Supported2_Extension
     (Extensions : in out Extension_Info; Data : Stream_Element_Array)
   is
      Cursor       : Stream_Element_Offset := Data'First;
      Count        : Interfaces.Unsigned_32 := 0;
      Ignored_Text : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Status_Value : CryptoLib.Errors.Status;
   begin
      Extensions.Supported2 := True;
      Extensions.Capabilities.Present := True;
      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_Uint32
          (Data,
           Cursor,
           Extensions.Capabilities.Supported_Attribute_Mask,
           Cursor);
      if Status_Value = CryptoLib.Errors.Ok then
         Status_Value :=
           SSH_Lib.Protocol.Numbers.Decode_Uint32
             (Data,
              Cursor,
              Extensions.Capabilities.Supported_Attribute_Bits,
              Cursor);
      end if;
      if Status_Value = CryptoLib.Errors.Ok then
         Status_Value :=
           SSH_Lib.Protocol.Numbers.Decode_Uint32
             (Data,
              Cursor,
              Extensions.Capabilities.Supported_Open_Flags,
              Cursor);
      end if;
      if Status_Value = CryptoLib.Errors.Ok then
         Status_Value :=
           SSH_Lib.Protocol.Numbers.Decode_Uint32
             (Data,
              Cursor,
              Extensions.Capabilities.Supported_Access_Mask,
              Cursor);
      end if;
      if Status_Value = CryptoLib.Errors.Ok then
         Status_Value :=
           SSH_Lib.Protocol.Numbers.Decode_Uint32
             (Data, Cursor, Extensions.Capabilities.Max_Read_Size, Cursor);
      end if;
      if Status_Value = CryptoLib.Errors.Ok then
         Status_Value :=
           Decode_Uint16
             (Data,
              Cursor,
              Extensions.Capabilities.Supported_Open_Block_Vector,
              Cursor);
      end if;
      if Status_Value = CryptoLib.Errors.Ok then
         Status_Value :=
           Decode_Uint16
             (Data,
              Cursor,
              Extensions.Capabilities.Supported_Block_Vector,
              Cursor);
      end if;
      if Status_Value /= CryptoLib.Errors.Ok then
         Extensions.Capabilities := (others => <>);
         return;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_Uint32 (Data, Cursor, Count, Cursor);
      if Status_Value /= CryptoLib.Errors.Ok then
         return;
      end if;
      for Index in 1 .. Count loop
         Status_Value :=
           SSH_Lib.Protocol.Numbers.Decode_SSH_String
             (Data, Cursor, Ignored_Text, Cursor);
         exit when Status_Value /= CryptoLib.Errors.Ok;
      end loop;

      if Status_Value = CryptoLib.Errors.Ok then
         Status_Value :=
           SSH_Lib.Protocol.Numbers.Decode_Uint32
             (Data, Cursor, Count, Cursor);
      end if;
      if Status_Value /= CryptoLib.Errors.Ok then
         return;
      end if;
      for Index in 1 .. Count loop
         Status_Value :=
           SSH_Lib.Protocol.Numbers.Decode_SSH_String
             (Data, Cursor, Ignored_Text, Cursor);
         exit when Status_Value /= CryptoLib.Errors.Ok;
         Mark_Extension (Extensions, Packet_String_To_Text (Ignored_Text));
      end loop;
   exception
      when others =>
         Extensions.Supported2 := True;
   end Parse_Supported2_Extension;

   procedure Mark_Extension (Extensions : in out Extension_Info; Name : String)
   is
   begin
      if Name = Posix_Rename_Extension then
         Extensions.Posix_Rename := True;
      elsif Name = Fsync_Extension then
         Extensions.Fsync := True;
      elsif Name = StatVFS_Extension then
         Extensions.StatVFS := True;
      elsif Name = Hardlink_Extension then
         Extensions.Hardlink := True;
      elsif Name = LSetStat_Extension then
         Extensions.LSetStat := True;
      elsif Name = Limits_Extension then
         Extensions.Limits := True;
      elsif Name = Copy_Data_Extension then
         Extensions.Copy_Data := True;
      elsif Name = Expand_Path_Extension then
         Extensions.Expand_Path := True;
      elsif Name = Check_File_Extension then
         Extensions.Check_File := True;
      elsif Name = Supported2_Extension then
         Extensions.Supported2 := True;
      elsif Name = Versions_Extension then
         Extensions.Versions := True;
      elsif Name = Text_Seek_Extension then
         Extensions.Text_Seek := True;
      end if;
   end Mark_Extension;

   procedure Mark_Extension
     (Extensions : in out Extension_Info;
      Name       : String;
      Value      : Stream_Element_Array) is
   begin
      Mark_Extension (Extensions, Name);
      if Name = Versions_Extension then
         Parse_Versions_Extension (Extensions, Value);
      elsif Name = Supported2_Extension then
         Parse_Supported2_Extension (Extensions, Value);
      end if;
   exception
      when others =>
         Mark_Extension (Extensions, Name);
   end Mark_Extension;

   function Parse_Version_Packet
     (Packet     : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Version    : out Natural;
      Extensions : out Extension_Info) return CryptoLib.Errors.Status
   is
      Data          : constant Stream_Element_Array :=
        SSH_Lib.Protocol.Buffers.To_Array (Packet);
      Cursor        : Stream_Element_Offset;
      Packet_Length : Interfaces.Unsigned_32 := 0;
      Version_Value : Interfaces.Unsigned_32 := 0;
      Field_Length  : Interfaces.Unsigned_32 := 0;
      Status_Value  : CryptoLib.Errors.Status;
   begin
      Version := 0;
      Extensions := (others => <>);
      if Data'Length < 9 then
         return CryptoLib.Errors.Read_Failed;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_Uint32
          (Data, Data'First, Packet_Length, Cursor);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;

      if Packet_Length < 5
        or else Packet_Length > Interfaces.Unsigned_32 (Maximum_Packet_Length)
        or else Natural (Packet_Length) /= Data'Length - 4
        or else Data (Cursor) /= SSH_FXP_VERSION
      then
         return CryptoLib.Errors.Read_Failed;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_Uint32
          (Data, Cursor + 1, Version_Value, Cursor);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;

      Version := Natural (Version_Value);
      if not Supports_Protocol_Version (Version) then
         return CryptoLib.Errors.Unsupported_Feature;
      end if;

      while Cursor <= Data'Last loop
         declare
            Name_First : Stream_Element_Offset;
            Name_Last  : Stream_Element_Offset;
         begin
            Status_Value :=
              SSH_Lib.Protocol.Numbers.Decode_Uint32
                (Data, Cursor, Field_Length, Cursor);
            if Status_Value /= CryptoLib.Errors.Ok
              or else Field_Length = 0
              or else
                Cursor + Stream_Element_Offset (Field_Length) - 1 > Data'Last
            then
               return CryptoLib.Errors.Read_Failed;
            end if;

            Name_First := Cursor;
            Name_Last := Cursor + Stream_Element_Offset (Field_Length) - 1;
            Cursor := Name_Last + 1;

            Status_Value :=
              SSH_Lib.Protocol.Numbers.Decode_Uint32
                (Data, Cursor, Field_Length, Cursor);
            if Status_Value /= CryptoLib.Errors.Ok
              or else
                Cursor + Stream_Element_Offset (Field_Length) - 1 > Data'Last
            then
               return CryptoLib.Errors.Read_Failed;
            end if;

            declare
               Value_First : constant Stream_Element_Offset := Cursor;
               Value_Last  : constant Stream_Element_Offset :=
                 Cursor + Stream_Element_Offset (Field_Length) - 1;
            begin
               if Field_Length = 0 then
                  Mark_Extension
                    (Extensions,
                     Stream_To_Text (Data (Name_First .. Name_Last)));
               else
                  Mark_Extension
                    (Extensions,
                     Stream_To_Text (Data (Name_First .. Name_Last)),
                     Data (Value_First .. Value_Last));
               end if;
            end;
            Cursor := Cursor + Stream_Element_Offset (Field_Length);
         end;
      end loop;

      return CryptoLib.Errors.Ok;
   exception
      when others =>
         Version := 0;
         Extensions := (others => <>);
         return CryptoLib.Errors.Read_Failed;
   end Parse_Version_Packet;

   function Parse_Version_Packet
     (Packet : SSH_Lib.Protocol.Buffers.Packet_Buffer; Version : out Natural)
      return CryptoLib.Errors.Status
   is
      Extensions : Extension_Info;
   begin
      return Parse_Version_Packet (Packet, Version, Extensions);
   end Parse_Version_Packet;

   function Read_Exact
     (Channel : in out SSH_Lib.Channels.Channel;
      Data    : out Stream_Element_Array) return CryptoLib.Errors.Status
   is
      Cursor       : Stream_Element_Offset := Data'First;
      Last         : Stream_Element_Offset;
      Status_Value : CryptoLib.Errors.Status;
   begin
      if Data'Length = 0 then
         return CryptoLib.Errors.Ok;
      end if;

      while Cursor <= Data'Last loop
         Status_Value :=
           SSH_Lib.Channels.Read_Some
             (Channel, Data (Cursor .. Data'Last), Last);
         if Status_Value /= CryptoLib.Errors.Ok then
            return Status_Value;
         elsif Last < Cursor then
            return CryptoLib.Errors.Read_Failed;
         end if;
         Cursor := Last + 1;
      end loop;

      return CryptoLib.Errors.Ok;
   exception
      when others =>
         return CryptoLib.Errors.Read_Failed;
   end Read_Exact;

   function Read_Packet
     (Channel : in out SSH_Lib.Channels.Channel;
      Packet  : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status
   is
      Header        : Stream_Element_Array (1 .. 4);
      Cursor        : Stream_Element_Offset;
      Packet_Length : Interfaces.Unsigned_32 := 0;
      Status_Value  : CryptoLib.Errors.Status;
   begin
      SSH_Lib.Protocol.Buffers.Clear (Packet);
      Status_Value := Read_Exact (Channel, Header);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_Uint32
          (Header, Header'First, Packet_Length, Cursor);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      elsif Packet_Length = 0
        or else Packet_Length > Interfaces.Unsigned_32 (Maximum_Packet_Length)
      then
         return CryptoLib.Errors.Read_Failed;
      end if;

      declare
         Payload :
           Stream_Element_Array (1 .. Stream_Element_Offset (Packet_Length));
      begin
         Status_Value := Read_Exact (Channel, Payload);
         if Status_Value /= CryptoLib.Errors.Ok then
            return Status_Value;
         end if;

         Status_Value := SSH_Lib.Protocol.Buffers.Append (Packet, Header);
         if Status_Value = CryptoLib.Errors.Ok then
            Status_Value := SSH_Lib.Protocol.Buffers.Append (Packet, Payload);
         end if;
         return Status_Value;
      end;
   exception
      when others =>
         SSH_Lib.Protocol.Buffers.Clear (Packet);
         return CryptoLib.Errors.Read_Failed;
   end Read_Packet;

   function Parse_Handle_Packet
     (Packet      : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Expected_Id : Interfaces.Unsigned_32;
      Handle      : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status
   is
      Data          : constant Stream_Element_Array :=
        SSH_Lib.Protocol.Buffers.To_Array (Packet);
      Cursor        : Stream_Element_Offset;
      Packet_Length : Interfaces.Unsigned_32 := 0;
      Request_Id    : Interfaces.Unsigned_32 := 0;
      Handle_Length : Interfaces.Unsigned_32 := 0;
      Status_Value  : CryptoLib.Errors.Status;
   begin
      SSH_Lib.Protocol.Buffers.Clear (Handle);
      if Data'Length < 13 then
         return CryptoLib.Errors.Read_Failed;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_Uint32
          (Data, Data'First, Packet_Length, Cursor);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      if Natural (Packet_Length) /= Data'Length - 4 then
         return CryptoLib.Errors.Read_Failed;
      elsif Data (Cursor) = SSH_FXP_STATUS then
         Status_Value := Parse_Status_Packet (Packet, Expected_Id);
         if Status_Value = CryptoLib.Errors.Ok then
            return CryptoLib.Errors.Read_Failed;
         else
            return Status_Value;
         end if;
      elsif Data (Cursor) /= SSH_FXP_HANDLE then
         return CryptoLib.Errors.Read_Failed;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_Uint32
          (Data, Cursor + 1, Request_Id, Cursor);
      if Status_Value /= CryptoLib.Errors.Ok or else Request_Id /= Expected_Id
      then
         return CryptoLib.Errors.Read_Failed;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_Uint32
          (Data, Cursor, Handle_Length, Cursor);
      if Status_Value /= CryptoLib.Errors.Ok
        or else Handle_Length = 0
        or else Handle_Length > Interfaces.Unsigned_32 (Maximum_Handle_Length)
        or else Cursor + Stream_Element_Offset (Handle_Length) - 1 > Data'Last
        or else Cursor + Stream_Element_Offset (Handle_Length) /= Data'Last + 1
      then
         return CryptoLib.Errors.Read_Failed;
      end if;

      return
        SSH_Lib.Protocol.Buffers.Set
          (Handle,
           Data
             (Cursor .. Cursor + Stream_Element_Offset (Handle_Length) - 1));
   exception
      when others =>
         SSH_Lib.Protocol.Buffers.Clear (Handle);
         return CryptoLib.Errors.Read_Failed;
   end Parse_Handle_Packet;

   function Parse_Attributes
     (Data       : Stream_Element_Array;
      First      : Stream_Element_Offset;
      Attributes : out File_Attributes;
      Next       : out Stream_Element_Offset) return CryptoLib.Errors.Status
   is
      Flags        : Interfaces.Unsigned_32 := 0;
      Status_Value : CryptoLib.Errors.Status;
   begin
      Attributes := (others => <>);
      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_Uint32 (Data, First, Flags, Next);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;

      if (Flags and Attr_Size) /= 0 then
         Attributes.Size_Known := True;
         Status_Value := Decode_Uint64 (Data, Next, Attributes.Size, Next);
         if Status_Value /= CryptoLib.Errors.Ok then
            return Status_Value;
         end if;
      end if;

      if (Flags and Attr_UID_GID) /= 0 then
         Attributes.UID_GID_Known := True;
         Status_Value :=
           SSH_Lib.Protocol.Numbers.Decode_Uint32
             (Data, Next, Attributes.UID, Next);
         if Status_Value /= CryptoLib.Errors.Ok then
            return Status_Value;
         end if;
         Status_Value :=
           SSH_Lib.Protocol.Numbers.Decode_Uint32
             (Data, Next, Attributes.GID, Next);
         if Status_Value /= CryptoLib.Errors.Ok then
            return Status_Value;
         end if;
      end if;

      if (Flags and Attr_Permissions) /= 0 then
         Attributes.Permissions_Known := True;
         Status_Value :=
           SSH_Lib.Protocol.Numbers.Decode_Uint32
             (Data, Next, Attributes.Permissions, Next);
         if Status_Value /= CryptoLib.Errors.Ok then
            return Status_Value;
         end if;
      end if;

      if (Flags and Attr_ACMODTime) /= 0 then
         Attributes.Times_Known := True;
         Status_Value :=
           SSH_Lib.Protocol.Numbers.Decode_Uint32
             (Data, Next, Attributes.Access_Time, Next);
         if Status_Value /= CryptoLib.Errors.Ok then
            return Status_Value;
         end if;
         Status_Value :=
           SSH_Lib.Protocol.Numbers.Decode_Uint32
             (Data, Next, Attributes.Modify_Time, Next);
         if Status_Value /= CryptoLib.Errors.Ok then
            return Status_Value;
         end if;
      end if;

      if (Flags and Attr_Extended) /= 0 then
         declare
            Count        : Interfaces.Unsigned_32 := 0;
            Name_Buffer  : SSH_Lib.Protocol.Buffers.Packet_Buffer;
            Value_Buffer : SSH_Lib.Protocol.Buffers.Packet_Buffer;
         begin
            Status_Value :=
              SSH_Lib.Protocol.Numbers.Decode_Uint32 (Data, Next, Count, Next);
            if Status_Value /= CryptoLib.Errors.Ok then
               return Status_Value;
            end if;

            for Index in 1 .. Count loop
               Status_Value :=
                 SSH_Lib.Protocol.Numbers.Decode_SSH_String
                   (Data, Next, Name_Buffer, Next);
               if Status_Value /= CryptoLib.Errors.Ok then
                  return CryptoLib.Errors.Read_Failed;
               end if;
               Status_Value :=
                 SSH_Lib.Protocol.Numbers.Decode_SSH_String
                   (Data, Next, Value_Buffer, Next);
               if Status_Value /= CryptoLib.Errors.Ok then
                  return CryptoLib.Errors.Read_Failed;
               end if;
               Attributes.Extended_Attributes.Append
                 (Extended_Attribute'
                    (Name  =>
                       To_Unbounded_String
                         (Packet_String_To_Text (Name_Buffer)),
                     Value =>
                       To_Unbounded_String
                         (Packet_String_To_Text (Value_Buffer))));
            end loop;
         end;
      end if;

      return CryptoLib.Errors.Ok;
   exception
      when others =>
         Attributes := (others => <>);
         Next := First;
         return CryptoLib.Errors.Read_Failed;
   end Parse_Attributes;

   function Parse_Attributes
     (Data       : Stream_Element_Array;
      First      : Stream_Element_Offset;
      Attributes : out File_Attributes;
      Next       : out Stream_Element_Offset;
      Version    : Natural) return CryptoLib.Errors.Status
   is
      Flags          : Interfaces.Unsigned_32 := 0;
      File_Type      : Stream_Element := File_Type_Unknown;
      Time64         : Interfaces.Unsigned_64 := 0;
      Nanoseconds    : Interfaces.Unsigned_32 := 0;
      Ignored_Uint64 : Interfaces.Unsigned_64 := 0;
      Owner_Buffer   : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Group_Buffer   : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      ACL_Buffer     : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Status_Value   : CryptoLib.Errors.Status;
   begin
      if Version <= 3 then
         return Parse_Attributes (Data, First, Attributes, Next);
      end if;

      Attributes := (others => <>);
      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_Uint32 (Data, First, Flags, Next);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      elsif Next > Data'Last then
         return CryptoLib.Errors.Read_Failed;
      end if;

      File_Type := Data (Next);
      Next := Next + 1;
      Apply_File_Type (Attributes, File_Type);

      if (Flags and Attr4_Size) /= 0 then
         Attributes.Size_Known := True;
         Status_Value := Decode_Uint64 (Data, Next, Attributes.Size, Next);
         if Status_Value /= CryptoLib.Errors.Ok then
            return Status_Value;
         end if;
      end if;

      if (Flags and Attr4_Allocation_Size) /= 0 then
         Attributes.Allocation_Size_Known := True;
         Status_Value :=
           Decode_Uint64 (Data, Next, Attributes.Allocation_Size, Next);
         if Status_Value /= CryptoLib.Errors.Ok then
            return Status_Value;
         end if;
      end if;

      if (Flags and Attr4_Owner_Group) /= 0 then
         Status_Value :=
           SSH_Lib.Protocol.Numbers.Decode_SSH_String
             (Data, Next, Owner_Buffer, Next);
         if Status_Value /= CryptoLib.Errors.Ok then
            return CryptoLib.Errors.Read_Failed;
         end if;
         Status_Value :=
           SSH_Lib.Protocol.Numbers.Decode_SSH_String
             (Data, Next, Group_Buffer, Next);
         if Status_Value /= CryptoLib.Errors.Ok then
            return CryptoLib.Errors.Read_Failed;
         end if;
         Attributes.Owner_Group_Known := True;
         Attributes.Owner :=
           To_Unbounded_String (Packet_String_To_Text (Owner_Buffer));
         Attributes.Group :=
           To_Unbounded_String (Packet_String_To_Text (Group_Buffer));
         Set_Extended_Attribute
           (Attributes,
            "owner@ietf.org",
            Packet_String_To_Text (Owner_Buffer));
         Set_Extended_Attribute
           (Attributes,
            "group@ietf.org",
            Packet_String_To_Text (Group_Buffer));
      end if;

      if (Flags and Attr4_Permissions) /= 0 then
         Attributes.Permissions_Known := True;
         Status_Value :=
           SSH_Lib.Protocol.Numbers.Decode_Uint32
             (Data, Next, Attributes.Permissions, Next);
         if Status_Value /= CryptoLib.Errors.Ok then
            return Status_Value;
         end if;
      end if;

      if (Flags and Attr4_Access_Time) /= 0 then
         Attributes.Times_Known := True;
         Status_Value := Decode_Uint64 (Data, Next, Time64, Next);
         if Status_Value /= CryptoLib.Errors.Ok then
            return Status_Value;
         end if;
         Status_Value :=
           SSH_Lib.Protocol.Numbers.Decode_Uint32
             (Data, Next, Nanoseconds, Next);
         if Status_Value /= CryptoLib.Errors.Ok then
            return Status_Value;
         end if;
         Attributes.Access_Time :=
           Interfaces.Unsigned_32 (Time64 and 16#FFFF_FFFF#);
         Attributes.Access_Time_Nanoseconds := Nanoseconds;
      end if;

      if (Flags and Attr4_Create_Time) /= 0 then
         Attributes.Create_Time_Known := True;
         Status_Value := Decode_Uint64 (Data, Next, Time64, Next);
         if Status_Value /= CryptoLib.Errors.Ok then
            return Status_Value;
         end if;
         Status_Value :=
           SSH_Lib.Protocol.Numbers.Decode_Uint32
             (Data, Next, Nanoseconds, Next);
         if Status_Value /= CryptoLib.Errors.Ok then
            return Status_Value;
         end if;
         Attributes.Create_Time :=
           Interfaces.Unsigned_32 (Time64 and 16#FFFF_FFFF#);
         Attributes.Create_Time_Nanoseconds := Nanoseconds;
      end if;

      if (Flags and Attr4_Modify_Time) /= 0 then
         Attributes.Times_Known := True;
         Status_Value := Decode_Uint64 (Data, Next, Time64, Next);
         if Status_Value /= CryptoLib.Errors.Ok then
            return Status_Value;
         end if;
         Status_Value :=
           SSH_Lib.Protocol.Numbers.Decode_Uint32
             (Data, Next, Nanoseconds, Next);
         if Status_Value /= CryptoLib.Errors.Ok then
            return Status_Value;
         end if;
         Attributes.Modify_Time :=
           Interfaces.Unsigned_32 (Time64 and 16#FFFF_FFFF#);
         Attributes.Modify_Time_Nanoseconds := Nanoseconds;
      end if;

      if (Flags and Attr4_ACL) /= 0 then
         Status_Value :=
           SSH_Lib.Protocol.Numbers.Decode_SSH_String
             (Data, Next, ACL_Buffer, Next);
         if Status_Value /= CryptoLib.Errors.Ok then
            return CryptoLib.Errors.Read_Failed;
         end if;
         Attributes.ACL_Known := True;
         Attributes.ACL :=
           To_Unbounded_String (Packet_String_To_Text (ACL_Buffer));
         Set_Extended_Attribute
           (Attributes, "acl@ietf.org", Packet_String_To_Text (ACL_Buffer));
      end if;

      if (Flags and Attr4_Bits) /= 0 then
         Attributes.Attribute_Bits_Known := True;
         Status_Value :=
           SSH_Lib.Protocol.Numbers.Decode_Uint32
             (Data, Next, Attributes.Attribute_Bits, Next);
         if Status_Value /= CryptoLib.Errors.Ok then
            return Status_Value;
         end if;
         Status_Value :=
           SSH_Lib.Protocol.Numbers.Decode_Uint32
             (Data, Next, Attributes.Attribute_Bits_Valid, Next);
         if Status_Value /= CryptoLib.Errors.Ok then
            return Status_Value;
         end if;
      end if;

      if (Flags and Attr4_Text_Hint) /= 0 then
         if Next > Data'Last then
            return CryptoLib.Errors.Read_Failed;
         end if;
         Attributes.Text_Hint_Known := True;
         Attributes.Text_Hint := Interfaces.Unsigned_8 (Data (Next));
         Next := Next + 1;
      end if;

      if (Flags and Attr4_Mime_Type) /= 0 then
         declare
            Mime_Buffer : SSH_Lib.Protocol.Buffers.Packet_Buffer;
         begin
            Attributes.Mime_Type_Known := True;
            Status_Value :=
              SSH_Lib.Protocol.Numbers.Decode_SSH_String
                (Data, Next, Mime_Buffer, Next);
            if Status_Value /= CryptoLib.Errors.Ok then
               return CryptoLib.Errors.Read_Failed;
            end if;
            Attributes.Mime_Type :=
              To_Unbounded_String (Packet_String_To_Text (Mime_Buffer));
         end;
      end if;

      if (Flags and Attr4_Link_Count) /= 0 then
         Attributes.Link_Count_Known := True;
         Status_Value :=
           SSH_Lib.Protocol.Numbers.Decode_Uint32
             (Data, Next, Attributes.Link_Count, Next);
         if Status_Value /= CryptoLib.Errors.Ok then
            return Status_Value;
         end if;
      end if;

      if (Flags and Attr4_Untranslated_Name) /= 0 then
         declare
            Name_Buffer : SSH_Lib.Protocol.Buffers.Packet_Buffer;
         begin
            Attributes.Untranslated_Name_Known := True;
            Status_Value :=
              SSH_Lib.Protocol.Numbers.Decode_SSH_String
                (Data, Next, Name_Buffer, Next);
            if Status_Value /= CryptoLib.Errors.Ok then
               return CryptoLib.Errors.Read_Failed;
            end if;
            Attributes.Untranslated_Name :=
              To_Unbounded_String (Packet_String_To_Text (Name_Buffer));
         end;
      end if;

      if (Flags and Attr4_Extended) /= 0 then
         declare
            Count        : Interfaces.Unsigned_32 := 0;
            Name_Buffer  : SSH_Lib.Protocol.Buffers.Packet_Buffer;
            Value_Buffer : SSH_Lib.Protocol.Buffers.Packet_Buffer;
         begin
            Status_Value :=
              SSH_Lib.Protocol.Numbers.Decode_Uint32 (Data, Next, Count, Next);
            if Status_Value /= CryptoLib.Errors.Ok then
               return Status_Value;
            end if;

            for Index in 1 .. Count loop
               Status_Value :=
                 SSH_Lib.Protocol.Numbers.Decode_SSH_String
                   (Data, Next, Name_Buffer, Next);
               if Status_Value /= CryptoLib.Errors.Ok then
                  return CryptoLib.Errors.Read_Failed;
               end if;
               Status_Value :=
                 SSH_Lib.Protocol.Numbers.Decode_SSH_String
                   (Data, Next, Value_Buffer, Next);
               if Status_Value /= CryptoLib.Errors.Ok then
                  return CryptoLib.Errors.Read_Failed;
               end if;
               Attributes.Extended_Attributes.Append
                 (Extended_Attribute'
                    (Name  =>
                       To_Unbounded_String
                         (Packet_String_To_Text (Name_Buffer)),
                     Value =>
                       To_Unbounded_String
                         (Packet_String_To_Text (Value_Buffer))));
            end loop;
         end;
      end if;

      return CryptoLib.Errors.Ok;
   exception
      when others =>
         Attributes := (others => <>);
         Next := First;
         return CryptoLib.Errors.Read_Failed;
   end Parse_Attributes;

   function Parse_Extended_Reply_Packet
     (Packet      : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Expected_Id : Interfaces.Unsigned_32;
      Reply_Data  : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status
   is
      Data          : constant Stream_Element_Array :=
        SSH_Lib.Protocol.Buffers.To_Array (Packet);
      Cursor        : Stream_Element_Offset;
      Packet_Length : Interfaces.Unsigned_32 := 0;
      Request_Id    : Interfaces.Unsigned_32 := 0;
      Status_Value  : CryptoLib.Errors.Status;
   begin
      SSH_Lib.Protocol.Buffers.Clear (Reply_Data);
      if Data'Length < 9 then
         return CryptoLib.Errors.Read_Failed;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_Uint32
          (Data, Data'First, Packet_Length, Cursor);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      elsif Natural (Packet_Length) /= Data'Length - 4 then
         return CryptoLib.Errors.Read_Failed;
      elsif Data (Cursor) = SSH_FXP_STATUS then
         return Parse_Status_Packet (Packet, Expected_Id);
      elsif Data (Cursor) /= SSH_FXP_EXTENDED_REPLY then
         return CryptoLib.Errors.Read_Failed;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_Uint32
          (Data, Cursor + 1, Request_Id, Cursor);
      if Status_Value /= CryptoLib.Errors.Ok or else Request_Id /= Expected_Id
      then
         return CryptoLib.Errors.Read_Failed;
      end if;

      if Cursor <= Data'Last then
         return
           SSH_Lib.Protocol.Buffers.Set
             (Reply_Data, Data (Cursor .. Data'Last));
      else
         return CryptoLib.Errors.Ok;
      end if;
   exception
      when others =>
         SSH_Lib.Protocol.Buffers.Clear (Reply_Data);
         return CryptoLib.Errors.Read_Failed;
   end Parse_Extended_Reply_Packet;

   function Parse_Check_File_Packet
     (Packet      : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Expected_Id : Interfaces.Unsigned_32;
      Algorithm   : out Unbounded_String;
      Digest      : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status
   is
      Reply        : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Cursor       : Stream_Element_Offset;
      Name_Buffer  : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Alg_Buffer   : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Hash_Buffer  : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Status_Value : CryptoLib.Errors.Status;
   begin
      Algorithm := Null_Unbounded_String;
      SSH_Lib.Protocol.Buffers.Clear (Digest);
      Status_Value := Parse_Extended_Reply_Packet (Packet, Expected_Id, Reply);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;

      declare
         Raw : constant Stream_Element_Array :=
           SSH_Lib.Protocol.Buffers.To_Array (Reply);
      begin
         if Raw'Length = 0 then
            return CryptoLib.Errors.Read_Failed;
         end if;
         Status_Value :=
           SSH_Lib.Protocol.Numbers.Decode_SSH_String
             (Raw, Raw'First, Name_Buffer, Cursor);
         if Status_Value /= CryptoLib.Errors.Ok
           or else Packet_String_To_Text (Name_Buffer) /= Check_File_Extension
         then
            return CryptoLib.Errors.Read_Failed;
         end if;
         Status_Value :=
           SSH_Lib.Protocol.Numbers.Decode_SSH_String
             (Raw, Cursor, Alg_Buffer, Cursor);
         if Status_Value /= CryptoLib.Errors.Ok then
            return CryptoLib.Errors.Read_Failed;
         end if;
         Status_Value :=
           SSH_Lib.Protocol.Numbers.Decode_SSH_String
             (Raw, Cursor, Hash_Buffer, Cursor);
         if Status_Value /= CryptoLib.Errors.Ok or else Cursor /= Raw'Last + 1
         then
            return CryptoLib.Errors.Read_Failed;
         end if;
         Algorithm := To_Unbounded_String (Packet_String_To_Text (Alg_Buffer));
         return
           SSH_Lib.Protocol.Buffers.Set
             (Digest, SSH_Lib.Protocol.Buffers.To_Array (Hash_Buffer));
      end;
   exception
      when others =>
         Algorithm := Null_Unbounded_String;
         SSH_Lib.Protocol.Buffers.Clear (Digest);
         return CryptoLib.Errors.Read_Failed;
   end Parse_Check_File_Packet;

   function Parse_Limits_Packet
     (Packet      : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Expected_Id : Interfaces.Unsigned_32;
      Values      : out Server_Limits) return CryptoLib.Errors.Status
   is
      Data          : constant Stream_Element_Array :=
        SSH_Lib.Protocol.Buffers.To_Array (Packet);
      Cursor        : Stream_Element_Offset;
      Packet_Length : Interfaces.Unsigned_32 := 0;
      Request_Id    : Interfaces.Unsigned_32 := 0;
      Status_Value  : CryptoLib.Errors.Status;
   begin
      Values := (others => 0);
      if Data'Length < 13 then
         return CryptoLib.Errors.Read_Failed;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_Uint32
          (Data, Data'First, Packet_Length, Cursor);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      elsif Natural (Packet_Length) /= Data'Length - 4 then
         return CryptoLib.Errors.Read_Failed;
      elsif Data (Cursor) = SSH_FXP_STATUS then
         return Parse_Status_Packet (Packet, Expected_Id);
      elsif Data (Cursor) /= SSH_FXP_EXTENDED_REPLY then
         return CryptoLib.Errors.Read_Failed;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_Uint32
          (Data, Cursor + 1, Request_Id, Cursor);
      if Status_Value /= CryptoLib.Errors.Ok or else Request_Id /= Expected_Id
      then
         return CryptoLib.Errors.Read_Failed;
      end if;

      Status_Value :=
        Decode_Uint64 (Data, Cursor, Values.Max_Packet_Length, Cursor);
      if Status_Value = CryptoLib.Errors.Ok then
         Status_Value :=
           Decode_Uint64 (Data, Cursor, Values.Max_Read_Length, Cursor);
      end if;
      if Status_Value = CryptoLib.Errors.Ok then
         Status_Value :=
           Decode_Uint64 (Data, Cursor, Values.Max_Write_Length, Cursor);
      end if;
      if Status_Value = CryptoLib.Errors.Ok then
         Status_Value :=
           Decode_Uint64 (Data, Cursor, Values.Max_Open_Handles, Cursor);
      end if;

      if Status_Value /= CryptoLib.Errors.Ok or else Cursor /= Data'Last + 1 then
         Values := (others => 0);
         return CryptoLib.Errors.Read_Failed;
      end if;
      return CryptoLib.Errors.Ok;
   exception
      when others =>
         Values := (others => 0);
         return CryptoLib.Errors.Read_Failed;
   end Parse_Limits_Packet;

   function Parse_StatVFS_Packet
     (Packet      : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Expected_Id : Interfaces.Unsigned_32;
      Stats       : out File_System_Stats) return CryptoLib.Errors.Status
   is
      Data          : constant Stream_Element_Array :=
        SSH_Lib.Protocol.Buffers.To_Array (Packet);
      Cursor        : Stream_Element_Offset;
      Packet_Length : Interfaces.Unsigned_32 := 0;
      Request_Id    : Interfaces.Unsigned_32 := 0;
      Status_Value  : CryptoLib.Errors.Status;
   begin
      Stats := (others => 0);
      if Data'Length < 13 then
         return CryptoLib.Errors.Read_Failed;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_Uint32
          (Data, Data'First, Packet_Length, Cursor);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      elsif Natural (Packet_Length) /= Data'Length - 4 then
         return CryptoLib.Errors.Read_Failed;
      elsif Data (Cursor) = SSH_FXP_STATUS then
         return Parse_Status_Packet (Packet, Expected_Id);
      elsif Data (Cursor) /= SSH_FXP_EXTENDED_REPLY then
         return CryptoLib.Errors.Read_Failed;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_Uint32
          (Data, Cursor + 1, Request_Id, Cursor);
      if Status_Value /= CryptoLib.Errors.Ok or else Request_Id /= Expected_Id
      then
         return CryptoLib.Errors.Read_Failed;
      end if;

      Status_Value := Decode_Uint64 (Data, Cursor, Stats.Block_Size, Cursor);
      if Status_Value = CryptoLib.Errors.Ok then
         Status_Value :=
           Decode_Uint64 (Data, Cursor, Stats.Fundamental_Block_Size, Cursor);
      end if;
      if Status_Value = CryptoLib.Errors.Ok then
         Status_Value := Decode_Uint64 (Data, Cursor, Stats.Blocks, Cursor);
      end if;
      if Status_Value = CryptoLib.Errors.Ok then
         Status_Value :=
           Decode_Uint64 (Data, Cursor, Stats.Free_Blocks, Cursor);
      end if;
      if Status_Value = CryptoLib.Errors.Ok then
         Status_Value :=
           Decode_Uint64 (Data, Cursor, Stats.Available_Blocks, Cursor);
      end if;
      if Status_Value = CryptoLib.Errors.Ok then
         Status_Value :=
           Decode_Uint64 (Data, Cursor, Stats.File_Nodes, Cursor);
      end if;
      if Status_Value = CryptoLib.Errors.Ok then
         Status_Value :=
           Decode_Uint64 (Data, Cursor, Stats.Free_File_Nodes, Cursor);
      end if;
      if Status_Value = CryptoLib.Errors.Ok then
         Status_Value :=
           Decode_Uint64 (Data, Cursor, Stats.Available_File_Nodes, Cursor);
      end if;
      if Status_Value = CryptoLib.Errors.Ok then
         Status_Value :=
           Decode_Uint64 (Data, Cursor, Stats.File_System_Id, Cursor);
      end if;
      if Status_Value = CryptoLib.Errors.Ok then
         Status_Value := Decode_Uint64 (Data, Cursor, Stats.Flags, Cursor);
      end if;
      if Status_Value = CryptoLib.Errors.Ok then
         Status_Value :=
           Decode_Uint64 (Data, Cursor, Stats.Maximum_Name_Length, Cursor);
      end if;

      if Status_Value /= CryptoLib.Errors.Ok or else Cursor /= Data'Last + 1 then
         Stats := (others => 0);
         return CryptoLib.Errors.Read_Failed;
      end if;
      return CryptoLib.Errors.Ok;
   exception
      when others =>
         Stats := (others => 0);
         return CryptoLib.Errors.Read_Failed;
   end Parse_StatVFS_Packet;

   function Parse_Attrs_Packet
     (Packet      : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Expected_Id : Interfaces.Unsigned_32;
      Attributes  : out File_Attributes) return CryptoLib.Errors.Status
   is
      Data          : constant Stream_Element_Array :=
        SSH_Lib.Protocol.Buffers.To_Array (Packet);
      Cursor        : Stream_Element_Offset;
      Packet_Length : Interfaces.Unsigned_32 := 0;
      Request_Id    : Interfaces.Unsigned_32 := 0;
      Status_Value  : CryptoLib.Errors.Status;
   begin
      Attributes := (others => <>);
      if Data'Length < 9 then
         return CryptoLib.Errors.Read_Failed;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_Uint32
          (Data, Data'First, Packet_Length, Cursor);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      elsif Natural (Packet_Length) /= Data'Length - 4 then
         return CryptoLib.Errors.Read_Failed;
      elsif Data (Cursor) = SSH_FXP_STATUS then
         return Parse_Status_Packet (Packet, Expected_Id);
      elsif Data (Cursor) /= SSH_FXP_ATTRS then
         return CryptoLib.Errors.Read_Failed;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_Uint32
          (Data, Cursor + 1, Request_Id, Cursor);
      if Status_Value /= CryptoLib.Errors.Ok or else Request_Id /= Expected_Id
      then
         return CryptoLib.Errors.Read_Failed;
      end if;

      Status_Value := Parse_Attributes (Data, Cursor, Attributes, Cursor);
      if Status_Value /= CryptoLib.Errors.Ok or else Cursor /= Data'Last + 1 then
         return CryptoLib.Errors.Read_Failed;
      end if;
      return CryptoLib.Errors.Ok;
   exception
      when others =>
         Attributes := (others => <>);
         return CryptoLib.Errors.Read_Failed;
   end Parse_Attrs_Packet;

   function Parse_Attrs_Packet
     (Packet      : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Expected_Id : Interfaces.Unsigned_32;
      Attributes  : out File_Attributes;
      Version     : Natural) return CryptoLib.Errors.Status
   is
      Data          : constant Stream_Element_Array :=
        SSH_Lib.Protocol.Buffers.To_Array (Packet);
      Cursor        : Stream_Element_Offset;
      Packet_Length : Interfaces.Unsigned_32 := 0;
      Request_Id    : Interfaces.Unsigned_32 := 0;
      Status_Value  : CryptoLib.Errors.Status;
   begin
      Attributes := (others => <>);
      if Version <= 3 then
         return Parse_Attrs_Packet (Packet, Expected_Id, Attributes);
      elsif Data'Length < 9 then
         return CryptoLib.Errors.Read_Failed;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_Uint32
          (Data, Data'First, Packet_Length, Cursor);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      elsif Natural (Packet_Length) /= Data'Length - 4 then
         return CryptoLib.Errors.Read_Failed;
      elsif Data (Cursor) = SSH_FXP_STATUS then
         return Parse_Status_Packet (Packet, Expected_Id);
      elsif Data (Cursor) /= SSH_FXP_ATTRS then
         return CryptoLib.Errors.Read_Failed;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_Uint32
          (Data, Cursor + 1, Request_Id, Cursor);
      if Status_Value /= CryptoLib.Errors.Ok or else Request_Id /= Expected_Id
      then
         return CryptoLib.Errors.Read_Failed;
      end if;

      Status_Value :=
        Parse_Attributes (Data, Cursor, Attributes, Cursor, Version);
      if Status_Value /= CryptoLib.Errors.Ok or else Cursor /= Data'Last + 1 then
         return CryptoLib.Errors.Read_Failed;
      end if;
      return CryptoLib.Errors.Ok;
   exception
      when others =>
         Attributes := (others => <>);
         return CryptoLib.Errors.Read_Failed;
   end Parse_Attrs_Packet;

   function Parse_Data_Packet
     (Packet      : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Expected_Id : Interfaces.Unsigned_32;
      Data_Out    : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status
   is
      Data          : constant Stream_Element_Array :=
        SSH_Lib.Protocol.Buffers.To_Array (Packet);
      Cursor        : Stream_Element_Offset;
      Packet_Length : Interfaces.Unsigned_32 := 0;
      Request_Id    : Interfaces.Unsigned_32 := 0;
      Data_Length   : Interfaces.Unsigned_32 := 0;
      Status_Value  : CryptoLib.Errors.Status;
   begin
      SSH_Lib.Protocol.Buffers.Clear (Data_Out);
      if Data'Length < 13 then
         return CryptoLib.Errors.Read_Failed;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_Uint32
          (Data, Data'First, Packet_Length, Cursor);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      elsif Natural (Packet_Length) /= Data'Length - 4 then
         return CryptoLib.Errors.Read_Failed;
      elsif Data (Cursor) = SSH_FXP_STATUS then
         if Parse_Status_Packet (Packet, Expected_Id, SSH_FX_EOF)
           = CryptoLib.Errors.Ok
         then
            return CryptoLib.Errors.End_Of_Stream;
         else
            return Parse_Status_Packet (Packet, Expected_Id);
         end if;
      elsif Data (Cursor) /= SSH_FXP_DATA then
         return CryptoLib.Errors.Read_Failed;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_Uint32
          (Data, Cursor + 1, Request_Id, Cursor);
      if Status_Value /= CryptoLib.Errors.Ok or else Request_Id /= Expected_Id
      then
         return CryptoLib.Errors.Read_Failed;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_Uint32
          (Data, Cursor, Data_Length, Cursor);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      elsif Data_Length = 0 then
         return CryptoLib.Errors.End_Of_Stream;
      elsif Cursor + Stream_Element_Offset (Data_Length) - 1 > Data'Last
        or else Cursor + Stream_Element_Offset (Data_Length) /= Data'Last + 1
      then
         return CryptoLib.Errors.Read_Failed;
      end if;

      return
        SSH_Lib.Protocol.Buffers.Set
          (Data_Out,
           Data (Cursor .. Cursor + Stream_Element_Offset (Data_Length) - 1));
   exception
      when others =>
         SSH_Lib.Protocol.Buffers.Clear (Data_Out);
         return CryptoLib.Errors.Read_Failed;
   end Parse_Data_Packet;

   function Parse_Name_Packet
     (Packet      : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Expected_Id : Interfaces.Unsigned_32;
      Names       : in out Unbounded_String) return CryptoLib.Errors.Status
   is
      Data          : constant Stream_Element_Array :=
        SSH_Lib.Protocol.Buffers.To_Array (Packet);
      Cursor        : Stream_Element_Offset;
      Packet_Length : Interfaces.Unsigned_32 := 0;
      Request_Id    : Interfaces.Unsigned_32 := 0;
      Count         : Interfaces.Unsigned_32 := 0;
      Name_Buffer   : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Long_Buffer   : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Ignored_Attrs : File_Attributes;
      Status_Value  : CryptoLib.Errors.Status;
   begin
      if Data'Length < 13 then
         return CryptoLib.Errors.Read_Failed;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_Uint32
          (Data, Data'First, Packet_Length, Cursor);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      elsif Natural (Packet_Length) /= Data'Length - 4 then
         return CryptoLib.Errors.Read_Failed;
      elsif Data (Cursor) = SSH_FXP_STATUS then
         if Parse_Status_Packet (Packet, Expected_Id, SSH_FX_EOF)
           = CryptoLib.Errors.Ok
         then
            return CryptoLib.Errors.End_Of_Stream;
         else
            return Parse_Status_Packet (Packet, Expected_Id);
         end if;
      elsif Data (Cursor) /= SSH_FXP_NAME then
         return CryptoLib.Errors.Read_Failed;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_Uint32
          (Data, Cursor + 1, Request_Id, Cursor);
      if Status_Value /= CryptoLib.Errors.Ok or else Request_Id /= Expected_Id
      then
         return CryptoLib.Errors.Read_Failed;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_Uint32 (Data, Cursor, Count, Cursor);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;

      for Index in 1 .. Count loop
         Status_Value :=
           SSH_Lib.Protocol.Numbers.Decode_SSH_String
             (Data, Cursor, Name_Buffer, Cursor);
         if Status_Value /= CryptoLib.Errors.Ok then
            return CryptoLib.Errors.Read_Failed;
         end if;
         Status_Value :=
           SSH_Lib.Protocol.Numbers.Decode_SSH_String
             (Data, Cursor, Long_Buffer, Cursor);
         if Status_Value /= CryptoLib.Errors.Ok then
            return CryptoLib.Errors.Read_Failed;
         end if;
         Status_Value :=
           Parse_Attributes (Data, Cursor, Ignored_Attrs, Cursor);
         if Status_Value /= CryptoLib.Errors.Ok then
            return Status_Value;
         end if;

         if Length (Names) > 0 then
            Append (Names, Character'Val (10));
         end if;
         Append (Names, Packet_String_To_Text (Name_Buffer));
      end loop;

      if Cursor /= Data'Last + 1 then
         return CryptoLib.Errors.Read_Failed;
      end if;
      return CryptoLib.Errors.Ok;
   exception
      when others =>
         return CryptoLib.Errors.Read_Failed;
   end Parse_Name_Packet;

   function Parse_Name_Packet
     (Packet      : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Expected_Id : Interfaces.Unsigned_32;
      Names       : in out Unbounded_String;
      Version     : Natural) return CryptoLib.Errors.Status
   is
      Data          : constant Stream_Element_Array :=
        SSH_Lib.Protocol.Buffers.To_Array (Packet);
      Cursor        : Stream_Element_Offset;
      Packet_Length : Interfaces.Unsigned_32 := 0;
      Request_Id    : Interfaces.Unsigned_32 := 0;
      Count         : Interfaces.Unsigned_32 := 0;
      Name_Buffer   : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Long_Buffer   : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Ignored_Attrs : File_Attributes;
      Status_Value  : CryptoLib.Errors.Status;
   begin
      if Version <= 3 then
         return Parse_Name_Packet (Packet, Expected_Id, Names);
      elsif Data'Length < 13 then
         return CryptoLib.Errors.Read_Failed;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_Uint32
          (Data, Data'First, Packet_Length, Cursor);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      elsif Natural (Packet_Length) /= Data'Length - 4 then
         return CryptoLib.Errors.Read_Failed;
      elsif Data (Cursor) = SSH_FXP_STATUS then
         if Parse_Status_Packet (Packet, Expected_Id, SSH_FX_EOF)
           = CryptoLib.Errors.Ok
         then
            return CryptoLib.Errors.End_Of_Stream;
         else
            return Parse_Status_Packet (Packet, Expected_Id);
         end if;
      elsif Data (Cursor) /= SSH_FXP_NAME then
         return CryptoLib.Errors.Read_Failed;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_Uint32
          (Data, Cursor + 1, Request_Id, Cursor);
      if Status_Value /= CryptoLib.Errors.Ok or else Request_Id /= Expected_Id
      then
         return CryptoLib.Errors.Read_Failed;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_Uint32 (Data, Cursor, Count, Cursor);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;

      for Index in 1 .. Count loop
         Status_Value :=
           SSH_Lib.Protocol.Numbers.Decode_SSH_String
             (Data, Cursor, Name_Buffer, Cursor);
         if Status_Value /= CryptoLib.Errors.Ok then
            return CryptoLib.Errors.Read_Failed;
         end if;
         if Version <= 3 then
            Status_Value :=
              SSH_Lib.Protocol.Numbers.Decode_SSH_String
                (Data, Cursor, Long_Buffer, Cursor);
            if Status_Value /= CryptoLib.Errors.Ok then
               return CryptoLib.Errors.Read_Failed;
            end if;
         end if;
         Status_Value :=
           Parse_Attributes (Data, Cursor, Ignored_Attrs, Cursor, Version);
         if Status_Value /= CryptoLib.Errors.Ok then
            return Status_Value;
         end if;

         if Length (Names) > 0 then
            Append (Names, Character'Val (10));
         end if;
         Append (Names, Packet_String_To_Text (Name_Buffer));
      end loop;

      if Cursor /= Data'Last + 1 then
         return CryptoLib.Errors.Read_Failed;
      end if;
      return CryptoLib.Errors.Ok;
   exception
      when others =>
         return CryptoLib.Errors.Read_Failed;
   end Parse_Name_Packet;

   function Parse_Directory_Entries_Packet
     (Packet      : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Expected_Id : Interfaces.Unsigned_32;
      Entries     : in out Directory_Entry_Vectors.Vector)
      return CryptoLib.Errors.Status
   is
      Data          : constant Stream_Element_Array :=
        SSH_Lib.Protocol.Buffers.To_Array (Packet);
      Cursor        : Stream_Element_Offset;
      Packet_Length : Interfaces.Unsigned_32 := 0;
      Request_Id    : Interfaces.Unsigned_32 := 0;
      Count         : Interfaces.Unsigned_32 := 0;
      Name_Buffer   : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Long_Buffer   : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Attributes    : File_Attributes;
      Status_Value  : CryptoLib.Errors.Status;
   begin
      if Data'Length < 13 then
         return CryptoLib.Errors.Read_Failed;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_Uint32
          (Data, Data'First, Packet_Length, Cursor);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      elsif Natural (Packet_Length) /= Data'Length - 4 then
         return CryptoLib.Errors.Read_Failed;
      elsif Data (Cursor) = SSH_FXP_STATUS then
         if Parse_Status_Packet (Packet, Expected_Id, SSH_FX_EOF)
           = CryptoLib.Errors.Ok
         then
            return CryptoLib.Errors.End_Of_Stream;
         else
            return Parse_Status_Packet (Packet, Expected_Id);
         end if;
      elsif Data (Cursor) /= SSH_FXP_NAME then
         return CryptoLib.Errors.Read_Failed;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_Uint32
          (Data, Cursor + 1, Request_Id, Cursor);
      if Status_Value /= CryptoLib.Errors.Ok or else Request_Id /= Expected_Id
      then
         return CryptoLib.Errors.Read_Failed;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_Uint32 (Data, Cursor, Count, Cursor);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;

      for Index in 1 .. Count loop
         Status_Value :=
           SSH_Lib.Protocol.Numbers.Decode_SSH_String
             (Data, Cursor, Name_Buffer, Cursor);
         if Status_Value /= CryptoLib.Errors.Ok then
            return CryptoLib.Errors.Read_Failed;
         end if;
         Status_Value :=
           SSH_Lib.Protocol.Numbers.Decode_SSH_String
             (Data, Cursor, Long_Buffer, Cursor);
         if Status_Value /= CryptoLib.Errors.Ok then
            return CryptoLib.Errors.Read_Failed;
         end if;
         Status_Value := Parse_Attributes (Data, Cursor, Attributes, Cursor);
         if Status_Value /= CryptoLib.Errors.Ok then
            return Status_Value;
         end if;

         Entries.Append
           (Directory_Entry'
              (Name       =>
                 To_Unbounded_String (Packet_String_To_Text (Name_Buffer)),
               Long_Name  =>
                 To_Unbounded_String (Packet_String_To_Text (Long_Buffer)),
               Attributes => Attributes));
      end loop;

      if Cursor /= Data'Last + 1 then
         return CryptoLib.Errors.Read_Failed;
      end if;
      return CryptoLib.Errors.Ok;
   exception
      when others =>
         return CryptoLib.Errors.Read_Failed;
   end Parse_Directory_Entries_Packet;

   function Parse_Directory_Entries_Packet
     (Packet      : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Expected_Id : Interfaces.Unsigned_32;
      Entries     : in out Directory_Entry_Vectors.Vector;
      Version     : Natural) return CryptoLib.Errors.Status
   is
      Data          : constant Stream_Element_Array :=
        SSH_Lib.Protocol.Buffers.To_Array (Packet);
      Cursor        : Stream_Element_Offset;
      Packet_Length : Interfaces.Unsigned_32 := 0;
      Request_Id    : Interfaces.Unsigned_32 := 0;
      Count         : Interfaces.Unsigned_32 := 0;
      Name_Buffer   : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Long_Buffer   : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Attributes    : File_Attributes;
      Status_Value  : CryptoLib.Errors.Status;
   begin
      if Version <= 3 then
         return Parse_Directory_Entries_Packet (Packet, Expected_Id, Entries);
      elsif Data'Length < 13 then
         return CryptoLib.Errors.Read_Failed;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_Uint32
          (Data, Data'First, Packet_Length, Cursor);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      elsif Natural (Packet_Length) /= Data'Length - 4 then
         return CryptoLib.Errors.Read_Failed;
      elsif Data (Cursor) = SSH_FXP_STATUS then
         if Parse_Status_Packet (Packet, Expected_Id, SSH_FX_EOF)
           = CryptoLib.Errors.Ok
         then
            return CryptoLib.Errors.End_Of_Stream;
         else
            return Parse_Status_Packet (Packet, Expected_Id);
         end if;
      elsif Data (Cursor) /= SSH_FXP_NAME then
         return CryptoLib.Errors.Read_Failed;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_Uint32
          (Data, Cursor + 1, Request_Id, Cursor);
      if Status_Value /= CryptoLib.Errors.Ok or else Request_Id /= Expected_Id
      then
         return CryptoLib.Errors.Read_Failed;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_Uint32 (Data, Cursor, Count, Cursor);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;

      for Index in 1 .. Count loop
         Status_Value :=
           SSH_Lib.Protocol.Numbers.Decode_SSH_String
             (Data, Cursor, Name_Buffer, Cursor);
         if Status_Value /= CryptoLib.Errors.Ok then
            return CryptoLib.Errors.Read_Failed;
         end if;
         if Version <= 3 then
            Status_Value :=
              SSH_Lib.Protocol.Numbers.Decode_SSH_String
                (Data, Cursor, Long_Buffer, Cursor);
            if Status_Value /= CryptoLib.Errors.Ok then
               return CryptoLib.Errors.Read_Failed;
            end if;
         else
            SSH_Lib.Protocol.Buffers.Clear (Long_Buffer);
         end if;
         Status_Value :=
           Parse_Attributes (Data, Cursor, Attributes, Cursor, Version);
         if Status_Value /= CryptoLib.Errors.Ok then
            return Status_Value;
         end if;

         Entries.Append
           (Directory_Entry'
              (Name       =>
                 To_Unbounded_String (Packet_String_To_Text (Name_Buffer)),
               Long_Name  =>
                 To_Unbounded_String (Packet_String_To_Text (Long_Buffer)),
               Attributes => Attributes));
      end loop;

      if Cursor /= Data'Last + 1 then
         return CryptoLib.Errors.Read_Failed;
      end if;
      return CryptoLib.Errors.Ok;
   exception
      when others =>
         return CryptoLib.Errors.Read_Failed;
   end Parse_Directory_Entries_Packet;
   function Status_Code_To_Status
     (Status_Code : Interfaces.Unsigned_32) return CryptoLib.Errors.Status is
   begin
      if Status_Code = SSH_FX_OK then
         return CryptoLib.Errors.Ok;
      elsif Status_Code = SSH_FX_EOF then
         return CryptoLib.Errors.End_Of_Stream;
      elsif Status_Code = SSH_FX_NO_SUCH_FILE
        or else Status_Code = SSH_FX_NO_SUCH_PATH
      then
         return CryptoLib.Errors.No_Such_File;
      elsif Status_Code = SSH_FX_PERMISSION_DENIED
        or else Status_Code = SSH_FX_WRITE_PROTECT
        or else Status_Code = SSH_FX_OWNER_INVALID
        or else Status_Code = SSH_FX_GROUP_INVALID
      then
         return CryptoLib.Errors.Permission_Denied;
      elsif Status_Code = SSH_FX_OP_UNSUPPORTED then
         return CryptoLib.Errors.Unsupported_Feature;
      elsif Status_Code = SSH_FX_BAD_MESSAGE then
         return CryptoLib.Errors.Read_Failed;
      elsif Status_Code = SSH_FX_INVALID_HANDLE
        or else Status_Code = SSH_FX_FILE_ALREADY_EXISTS
        or else Status_Code = SSH_FX_INVALID_FILENAME
        or else Status_Code = SSH_FX_INVALID_PARAMETER
        or else Status_Code = SSH_FX_FILE_IS_A_DIRECTORY
      then
         return CryptoLib.Errors.Invalid_Command;
      elsif Status_Code = SSH_FX_FAILURE
        or else Status_Code = SSH_FX_NO_CONNECTION
        or else Status_Code = SSH_FX_CONNECTION_LOST
        or else Status_Code = SSH_FX_NO_MEDIA
        or else Status_Code = SSH_FX_NO_SPACE_ON_FILESYSTEM
        or else Status_Code = SSH_FX_QUOTA_EXCEEDED
        or else Status_Code = SSH_FX_UNKNOWN_PRINCIPAL
        or else Status_Code = SSH_FX_LOCK_CONFLICT
        or else Status_Code = SSH_FX_DIR_NOT_EMPTY
        or else Status_Code = SSH_FX_NOT_A_DIRECTORY
        or else Status_Code = SSH_FX_LINK_LOOP
        or else Status_Code = SSH_FX_CANNOT_DELETE
        or else Status_Code = SSH_FX_BYTE_RANGE_LOCK_CONFLICT
        or else Status_Code = SSH_FX_BYTE_RANGE_LOCK_REFUSED
        or else Status_Code = SSH_FX_DELETE_PENDING
        or else Status_Code = SSH_FX_FILE_CORRUPT
        or else Status_Code = SSH_FX_NO_MATCHING_BYTE_RANGE_LOCK
      then
         return CryptoLib.Errors.Remote_Failure;
      else
         return CryptoLib.Errors.Write_Failed;
      end if;
   end Status_Code_To_Status;

   function Parse_Status_Packet
     (Packet        : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Expected_Id   : Interfaces.Unsigned_32;
      Expected_Code : Interfaces.Unsigned_32 := SSH_FX_OK)
      return CryptoLib.Errors.Status
   is
      Data          : constant Stream_Element_Array :=
        SSH_Lib.Protocol.Buffers.To_Array (Packet);
      Cursor        : Stream_Element_Offset;
      Packet_Length : Interfaces.Unsigned_32 := 0;
      Request_Id    : Interfaces.Unsigned_32 := 0;
      Status_Code   : Interfaces.Unsigned_32 := 0;
      Message_Text  : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Language_Text : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Status_Value  : CryptoLib.Errors.Status;
   begin
      if Data'Length < 13 then
         return CryptoLib.Errors.Read_Failed;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_Uint32
          (Data, Data'First, Packet_Length, Cursor);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      if Natural (Packet_Length) /= Data'Length - 4
        or else Data (Cursor) /= SSH_FXP_STATUS
      then
         return CryptoLib.Errors.Read_Failed;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_Uint32
          (Data, Cursor + 1, Request_Id, Cursor);
      if Status_Value /= CryptoLib.Errors.Ok or else Request_Id /= Expected_Id
      then
         return CryptoLib.Errors.Read_Failed;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_Uint32
          (Data, Cursor, Status_Code, Cursor);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      Last_Status_Code_Value := Status_Code;

      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_SSH_String
          (Data, Cursor, Message_Text, Cursor);
      if Status_Value /= CryptoLib.Errors.Ok then
         return CryptoLib.Errors.Read_Failed;
      end if;

      Last_Status_Message_Value :=
        To_Unbounded_String (Packet_String_To_Text (Message_Text));
      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_SSH_String
          (Data, Cursor, Language_Text, Cursor);
      if Status_Value /= CryptoLib.Errors.Ok or else Cursor /= Data'Last + 1 then
         return CryptoLib.Errors.Read_Failed;
      elsif Status_Code = Expected_Code then
         return CryptoLib.Errors.Ok;
      else
         return Status_Code_To_Status (Status_Code);
      end if;
   exception
      when others =>
         return CryptoLib.Errors.Read_Failed;
   end Parse_Status_Packet;

   function Parse_Status_Response
     (Packet     : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Request_Id : out Interfaces.Unsigned_32) return CryptoLib.Errors.Status
   is
      Data          : constant Stream_Element_Array :=
        SSH_Lib.Protocol.Buffers.To_Array (Packet);
      Cursor        : Stream_Element_Offset;
      Packet_Length : Interfaces.Unsigned_32 := 0;
      Status_Code   : Interfaces.Unsigned_32 := 0;
      Message_Text  : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Language_Text : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Status_Value  : CryptoLib.Errors.Status;
   begin
      Request_Id := 0;
      if Data'Length < 13 then
         return CryptoLib.Errors.Read_Failed;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_Uint32
          (Data, Data'First, Packet_Length, Cursor);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      if Natural (Packet_Length) /= Data'Length - 4
        or else Data (Cursor) /= SSH_FXP_STATUS
      then
         return CryptoLib.Errors.Read_Failed;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_Uint32
          (Data, Cursor + 1, Request_Id, Cursor);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_Uint32
          (Data, Cursor, Status_Code, Cursor);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      Last_Status_Code_Value := Status_Code;
      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_SSH_String
          (Data, Cursor, Message_Text, Cursor);
      if Status_Value /= CryptoLib.Errors.Ok then
         return CryptoLib.Errors.Read_Failed;
      end if;
      Last_Status_Message_Value :=
        To_Unbounded_String (Packet_String_To_Text (Message_Text));
      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_SSH_String
          (Data, Cursor, Language_Text, Cursor);
      if Status_Value /= CryptoLib.Errors.Ok or else Cursor /= Data'Last + 1 then
         return CryptoLib.Errors.Read_Failed;
      else
         return Status_Code_To_Status (Status_Code);
      end if;
   exception
      when others =>
         Request_Id := 0;
         return CryptoLib.Errors.Read_Failed;
   end Parse_Status_Response;

   function Parse_Data_Response
     (Packet     : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Request_Id : out Interfaces.Unsigned_32;
      Data_Out   : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status
   is
      Data          : constant Stream_Element_Array :=
        SSH_Lib.Protocol.Buffers.To_Array (Packet);
      Cursor        : Stream_Element_Offset;
      Packet_Length : Interfaces.Unsigned_32 := 0;
      Data_Length   : Interfaces.Unsigned_32 := 0;
      Status_Value  : CryptoLib.Errors.Status;
   begin
      Request_Id := 0;
      SSH_Lib.Protocol.Buffers.Clear (Data_Out);
      if Data'Length < 13 then
         return CryptoLib.Errors.Read_Failed;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_Uint32
          (Data, Data'First, Packet_Length, Cursor);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      elsif Natural (Packet_Length) /= Data'Length - 4 then
         return CryptoLib.Errors.Read_Failed;
      elsif Data (Cursor) = SSH_FXP_STATUS then
         return Parse_Status_Response (Packet, Request_Id);
      elsif Data (Cursor) /= SSH_FXP_DATA then
         return CryptoLib.Errors.Read_Failed;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_Uint32
          (Data, Cursor + 1, Request_Id, Cursor);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_Uint32
          (Data, Cursor, Data_Length, Cursor);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      elsif Data_Length = 0 then
         return CryptoLib.Errors.End_Of_Stream;
      elsif Cursor + Stream_Element_Offset (Data_Length) - 1 > Data'Last
        or else Cursor + Stream_Element_Offset (Data_Length) /= Data'Last + 1
      then
         return CryptoLib.Errors.Read_Failed;
      end if;

      return
        SSH_Lib.Protocol.Buffers.Set
          (Data_Out,
           Data (Cursor .. Cursor + Stream_Element_Offset (Data_Length) - 1));
   exception
      when others =>
         Request_Id := 0;
         SSH_Lib.Protocol.Buffers.Clear (Data_Out);
         return CryptoLib.Errors.Read_Failed;
   end Parse_Data_Response;

   function Send_Packet
     (Channel : in out SSH_Lib.Channels.Channel;
      Packet  : SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status is
   begin
      if SSH_Lib.Protocol.Buffers.Is_Empty (Packet) then
         return CryptoLib.Errors.Write_Failed;
      end if;
      return
        SSH_Lib.Channels.Write
          (Channel, SSH_Lib.Protocol.Buffers.To_Array (Packet));
   exception
      when others =>
         return CryptoLib.Errors.Write_Failed;
   end Send_Packet;

   function Is_Open (Handle : File_Handle) return Boolean is
   begin
      return
        Handle.Opened
        and then not SSH_Lib.Protocol.Buffers.Is_Empty (Handle.Data);
   end Is_Open;

   function Is_Open (Item : Client) return Boolean is
   begin
      return Item.Opened;
   exception
      when others =>
         return False;
   end Is_Open;

   function Version (Item : Client) return Natural is
   begin
      return Item.Version;
   exception
      when others =>
         return 0;
   end Version;

   function Extensions (Item : Client) return Extension_Info is
   begin
      return Item.Extensions;
   exception
      when others =>
         return (others => <>);
   end Extensions;

   function Negotiated_Info (Item : Client) return Negotiated_Snapshot is
      Snapshot : Negotiated_Snapshot;
   begin
      Snapshot.Version := Item.Version;
      Snapshot.Extensions := Item.Extensions;
      Snapshot.Limits_Known := Item.Opened and then Item.Limits_Known;
      Snapshot.Limits := Item.Limits;
      if Item.Opened then
         Snapshot.Result := Result_For_Status (CryptoLib.Errors.Ok, Open_Operation);
      else
         Snapshot.Result :=
           Result_For_Status (CryptoLib.Errors.Channel_Open_Failed, Open_Operation);
      end if;
      return Snapshot;
   exception
      when others =>
         Snapshot := (others => <>);
         Snapshot.Result :=
           Result_For_Status (CryptoLib.Errors.Internal_Error, Open_Operation);
         return Snapshot;
   end Negotiated_Info;

   function Limits
     (Item   : Client;
      Values : out Server_Limits) return Boolean is
   begin
      Values := Item.Limits;
      return Item.Opened and then Item.Limits_Known;
   exception
      when others =>
         Values := (others => 0);
         return False;
   end Limits;

   procedure Clear_Handle (Handle : in out File_Handle) is
   begin
      SSH_Lib.Protocol.Buffers.Clear (Handle.Data);
      Handle.Opened := False;
      Handle.Version := Protocol_Version;
      Handle.Context_Known := False;
      Handle.Extensions := (others => <>);
   end Clear_Handle;

   procedure Set_Handle_Context
     (Handle     : in out File_Handle;
      Version    : Natural;
      Extensions : Extension_Info) is
   begin
      if Handle.Opened then
         Handle.Version := Version;
         Handle.Extensions := Extensions;
         Handle.Context_Known := True;
      end if;
   end Set_Handle_Context;

   function Initialize
     (Channel           : in out SSH_Lib.Channels.Channel;
      Requested_Version : Natural;
      Version           : out Natural;
      Extensions        : out Extension_Info) return CryptoLib.Errors.Status
   is
      Init_Packet  : constant SSH_Lib.Protocol.Buffers.Packet_Buffer :=
        Encode_Init_Packet (Requested_Version);
      Reply_Packet : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Status_Value : CryptoLib.Errors.Status;
   begin
      Version := 0;
      Extensions := (others => <>);
      if SSH_Lib.Protocol.Buffers.Is_Empty (Init_Packet) then
         return CryptoLib.Errors.Write_Failed;
      end if;

      Status_Value :=
        SSH_Lib.Channels.Write
          (Channel, SSH_Lib.Protocol.Buffers.To_Array (Init_Packet));
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;

      Status_Value := Read_Packet (Channel, Reply_Packet);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;

      return Parse_Version_Packet (Reply_Packet, Version, Extensions);
   exception
      when others =>
         Version := 0;
         Extensions := (others => <>);
         return CryptoLib.Errors.Internal_Error;
   end Initialize;

   function Initialize
     (Channel    : in out SSH_Lib.Channels.Channel;
      Version    : out Natural;
      Extensions : out Extension_Info) return CryptoLib.Errors.Status is
   begin
      return Initialize (Channel, Protocol_Version, Version, Extensions);
   end Initialize;

   function Initialize
     (Channel           : in out SSH_Lib.Channels.Channel;
      Requested_Version : Natural;
      Version           : out Natural) return CryptoLib.Errors.Status
   is
      Extensions : Extension_Info;
   begin
      return Initialize (Channel, Requested_Version, Version, Extensions);
   end Initialize;

   function Initialize
     (Channel : in out SSH_Lib.Channels.Channel; Version : out Natural)
      return CryptoLib.Errors.Status
   is
      Extensions : Extension_Info;
   begin
      return Initialize (Channel, Version, Extensions);
   end Initialize;

   function Open_Remote_File
     (Channel     : in out SSH_Lib.Channels.Channel;
      Remote_Path : String;
      Mode        : String;
      Handle      : out SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Version     : Natural := Protocol_Version) return CryptoLib.Errors.Status
   is
      Open_Id      : constant Interfaces.Unsigned_32 := 1;
      Reply_Packet : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Status_Value : CryptoLib.Errors.Status;
   begin
      SSH_Lib.Protocol.Buffers.Clear (Handle);
      if Validate_Upload_Target (Remote_Path, Mode) /= CryptoLib.Errors.Ok then
         return CryptoLib.Errors.Invalid_Command;
      end if;

      Status_Value :=
        Send_Packet
          (Channel, Encode_Open_Request (Open_Id, Remote_Path, Mode, Version));
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;

      Status_Value := Read_Packet (Channel, Reply_Packet);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      return Parse_Handle_Packet (Reply_Packet, Open_Id, Handle);
   exception
      when others =>
         SSH_Lib.Protocol.Buffers.Clear (Handle);
         return CryptoLib.Errors.Internal_Error;
   end Open_Remote_File;

   function Open_Remote_File_Mode
     (Channel          : in out SSH_Lib.Channels.Channel;
      Remote_Path      : String;
      Mode             : Open_Mode;
      Permissions_Mode : String;
      Handle           : out SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Version          : Natural := Protocol_Version)
      return CryptoLib.Errors.Status
   is
      Open_Id      : constant Interfaces.Unsigned_32 := 1;
      Reply_Packet : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Status_Value : CryptoLib.Errors.Status;
   begin
      SSH_Lib.Protocol.Buffers.Clear (Handle);
      if not Safe_Remote_Path (Remote_Path)
        or else
          (Open_Mode_Uses_Permissions (Mode)
           and then
             Validate_Upload_Target (Remote_Path, Permissions_Mode)
             /= CryptoLib.Errors.Ok)
      then
         return CryptoLib.Errors.Invalid_Command;
      end if;

      Status_Value :=
        Send_Packet
          (Channel,
           Encode_Open_Mode_Request
             (Open_Id, Remote_Path, Mode, Permissions_Mode, Version));
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;

      Status_Value := Read_Packet (Channel, Reply_Packet);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      return Parse_Handle_Packet (Reply_Packet, Open_Id, Handle);
   exception
      when others =>
         SSH_Lib.Protocol.Buffers.Clear (Handle);
         return CryptoLib.Errors.Internal_Error;
   end Open_Remote_File_Mode;

   function Write_Remote_Data
     (Channel    : in out SSH_Lib.Channels.Channel;
      Handle     : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Request_Id : Interfaces.Unsigned_32;
      Offset     : Interfaces.Unsigned_64;
      Data       : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status
   is
      Reply_Packet : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Status_Value : CryptoLib.Errors.Status;
   begin
      Status_Value :=
        Send_Packet
          (Channel, Encode_Write_Request (Request_Id, Handle, Offset, Data));
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      Status_Value := Read_Packet (Channel, Reply_Packet);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      return Parse_Status_Packet (Reply_Packet, Request_Id);
   exception
      when others =>
         return CryptoLib.Errors.Internal_Error;
   end Write_Remote_Data;

   function Close_Remote_File
     (Channel    : in out SSH_Lib.Channels.Channel;
      Handle     : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Request_Id : Interfaces.Unsigned_32) return CryptoLib.Errors.Status
   is
      Reply_Packet : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Status_Value : CryptoLib.Errors.Status;
   begin
      Status_Value :=
        Send_Packet (Channel, Encode_Close_Request (Request_Id, Handle));
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      Status_Value := Read_Packet (Channel, Reply_Packet);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      return Parse_Status_Packet (Reply_Packet, Request_Id);
   exception
      when others =>
         return CryptoLib.Errors.Internal_Error;
   end Close_Remote_File;

   procedure Close_Remote_File_Best_Effort
     (Channel    : in out SSH_Lib.Channels.Channel;
      Handle     : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Request_Id : Interfaces.Unsigned_32)
   is
      Close_Status : CryptoLib.Errors.Status;
      pragma Unreferenced (Close_Status);
   begin
      Close_Status := Close_Remote_File (Channel, Handle, Request_Id);
   exception
      when others =>
         null;
   end Close_Remote_File_Best_Effort;

   function Open_Remote_Read_File
     (Channel     : in out SSH_Lib.Channels.Channel;
      Remote_Path : String;
      Handle      : out SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Version     : Natural := Protocol_Version) return CryptoLib.Errors.Status
   is
      Open_Id      : constant Interfaces.Unsigned_32 := 1;
      Reply_Packet : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Status_Value : CryptoLib.Errors.Status;
   begin
      SSH_Lib.Protocol.Buffers.Clear (Handle);
      if not Safe_Remote_Path (Remote_Path) then
         return CryptoLib.Errors.Invalid_Command;
      end if;

      Status_Value :=
        Send_Packet
          (Channel, Encode_Open_Read_Request (Open_Id, Remote_Path, Version));
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      Status_Value := Read_Packet (Channel, Reply_Packet);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      return Parse_Handle_Packet (Reply_Packet, Open_Id, Handle);
   exception
      when others =>
         SSH_Lib.Protocol.Buffers.Clear (Handle);
         return CryptoLib.Errors.Internal_Error;
   end Open_Remote_Read_File;

   function Pipelined_Write_Buffer
     (Channel          : in out SSH_Lib.Channels.Channel;
      Handle           : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Start_Offset     : Interfaces.Unsigned_64;
      Data             : Ada.Streams.Stream_Element_Array;
      First_Request_Id : Interfaces.Unsigned_32;
      Pipeline_Depth   : Positive;
      Next_Request_Id  : out Interfaces.Unsigned_32;
      Chunk_Size       : Natural := Upload_Chunk_Size)
      return CryptoLib.Errors.Status
   is
      subtype Window_Index is Natural range 1 .. Pipeline_Depth;
      Request_Ids  : array (Window_Index) of Interfaces.Unsigned_32 :=
        [others => 0];
      Active       : array (Window_Index) of Boolean := [others => False];
      Cursor       : Stream_Element_Offset := Data'First;
      Remaining    : Natural := Data'Length;
      Offset_Value : Interfaces.Unsigned_64 := Start_Offset;
      Request_Id   : Interfaces.Unsigned_32 := First_Request_Id;
      Outstanding  : Natural := 0;
      Reply_Packet : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Reply_Id     : Interfaces.Unsigned_32 := 0;
      Status_Value : CryptoLib.Errors.Status;

      function Free_Slot return Window_Index is
      begin
         for Index in Window_Index loop
            if not Active (Index) then
               return Index;
            end if;
         end loop;
         return Window_Index'First;
      end Free_Slot;

      function Slot_For (Id : Interfaces.Unsigned_32) return Window_Index is
      begin
         for Index in Window_Index loop
            if Active (Index) and then Request_Ids (Index) = Id then
               return Index;
            end if;
         end loop;
         return Window_Index'First;
      end Slot_For;
   begin
      Next_Request_Id := First_Request_Id;
      while Remaining > 0 or else Outstanding > 0 loop
         while Remaining > 0 and then Outstanding < Pipeline_Depth loop
            declare
               Write_Count : constant Natural :=
                 (if Remaining < Chunk_Size then Remaining else Chunk_Size);
               Last        : constant Stream_Element_Offset :=
                 Cursor + Stream_Element_Offset (Write_Count) - 1;
               Slot        : constant Window_Index := Free_Slot;
            begin
               Status_Value :=
                 Send_Packet
                   (Channel,
                    Encode_Write_Request
                      (Request_Id,
                       Handle,
                       Offset_Value,
                       Data (Cursor .. Last)));
               if Status_Value /= CryptoLib.Errors.Ok then
                  Next_Request_Id := Request_Id + 1;
                  return Status_Value;
               end if;

               Active (Slot) := True;
               Request_Ids (Slot) := Request_Id;
               Outstanding := Outstanding + 1;
               Cursor := Last + 1;
               Remaining := Remaining - Write_Count;
               Offset_Value :=
                 Offset_Value + Interfaces.Unsigned_64 (Write_Count);
               Request_Id := Request_Id + 1;
            end;
         end loop;

         if Outstanding > 0 then
            Status_Value := Read_Packet (Channel, Reply_Packet);
            if Status_Value /= CryptoLib.Errors.Ok then
               Next_Request_Id := Request_Id;
               return Status_Value;
            end if;
            Status_Value := Parse_Status_Response (Reply_Packet, Reply_Id);
            if Status_Value /= CryptoLib.Errors.Ok then
               Next_Request_Id := Request_Id;
               return Status_Value;
            end if;
            declare
               Slot : constant Window_Index := Slot_For (Reply_Id);
            begin
               if not Active (Slot) or else Request_Ids (Slot) /= Reply_Id then
                  Next_Request_Id := Request_Id;
                  return CryptoLib.Errors.Read_Failed;
               end if;
               Active (Slot) := False;
               Outstanding := Outstanding - 1;
            end;
         end if;
      end loop;

      Next_Request_Id := Request_Id;
      return CryptoLib.Errors.Ok;
   exception
      when others =>
         Next_Request_Id := First_Request_Id;
         return CryptoLib.Errors.Internal_Error;
   end Pipelined_Write_Buffer;

   function Pipelined_Write_File
     (Channel          : in out SSH_Lib.Channels.Channel;
      Handle           : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      File_Item        : in out Ada.Streams.Stream_IO.File_Type;
      Size_Value       : Natural;
      First_Request_Id : Interfaces.Unsigned_32;
      Pipeline_Depth   : Positive;
      Next_Request_Id  : out Interfaces.Unsigned_32;
      Chunk_Size       : Natural := Upload_Chunk_Size)
      return CryptoLib.Errors.Status
   is
      subtype Window_Index is Natural range 1 .. Pipeline_Depth;
      Request_Ids  : array (Window_Index) of Interfaces.Unsigned_32 :=
        [others => 0];
      Active       : array (Window_Index) of Boolean := [others => False];
      Remaining    : Natural := Size_Value;
      Offset_Value : Interfaces.Unsigned_64 := 0;
      Request_Id   : Interfaces.Unsigned_32 := First_Request_Id;
      Outstanding  : Natural := 0;
      Reply_Packet : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Reply_Id     : Interfaces.Unsigned_32 := 0;
      Status_Value : CryptoLib.Errors.Status;

      function Free_Slot return Window_Index is
      begin
         for Index in Window_Index loop
            if not Active (Index) then
               return Index;
            end if;
         end loop;
         return Window_Index'First;
      end Free_Slot;

      function Slot_For (Id : Interfaces.Unsigned_32) return Window_Index is
      begin
         for Index in Window_Index loop
            if Active (Index) and then Request_Ids (Index) = Id then
               return Index;
            end if;
         end loop;
         return Window_Index'First;
      end Slot_For;
   begin
      Next_Request_Id := First_Request_Id;
      while Remaining > 0 or else Outstanding > 0 loop
         while Remaining > 0 and then Outstanding < Pipeline_Depth loop
            declare
               Read_Count : constant Natural :=
                 (if Remaining < Chunk_Size then Remaining else Chunk_Size);
               Buffer     :
                 Stream_Element_Array
                   (1 .. Stream_Element_Offset (Read_Count));
               Last       : Stream_Element_Offset;
               Slot       : constant Window_Index := Free_Slot;
            begin
               Ada.Streams.Stream_IO.Read (File_Item, Buffer, Last);
               if Last /= Buffer'Last then
                  Next_Request_Id := Request_Id;
                  return CryptoLib.Errors.Read_Failed;
               end if;

               Status_Value :=
                 Send_Packet
                   (Channel,
                    Encode_Write_Request
                      (Request_Id, Handle, Offset_Value, Buffer));
               if Status_Value /= CryptoLib.Errors.Ok then
                  Next_Request_Id := Request_Id + 1;
                  return Status_Value;
               end if;

               Active (Slot) := True;
               Request_Ids (Slot) := Request_Id;
               Outstanding := Outstanding + 1;
               Remaining := Remaining - Read_Count;
               Offset_Value :=
                 Offset_Value + Interfaces.Unsigned_64 (Read_Count);
               Request_Id := Request_Id + 1;
            end;
         end loop;

         if Outstanding > 0 then
            Status_Value := Read_Packet (Channel, Reply_Packet);
            if Status_Value /= CryptoLib.Errors.Ok then
               Next_Request_Id := Request_Id;
               return Status_Value;
            end if;
            Status_Value := Parse_Status_Response (Reply_Packet, Reply_Id);
            if Status_Value /= CryptoLib.Errors.Ok then
               Next_Request_Id := Request_Id;
               return Status_Value;
            end if;
            declare
               Slot : constant Window_Index := Slot_For (Reply_Id);
            begin
               if not Active (Slot) or else Request_Ids (Slot) /= Reply_Id then
                  Next_Request_Id := Request_Id;
                  return CryptoLib.Errors.Read_Failed;
               end if;
               Active (Slot) := False;
               Outstanding := Outstanding - 1;
            end;
         end if;
      end loop;

      Next_Request_Id := Request_Id;
      return CryptoLib.Errors.Ok;
   exception
      when others =>
         Next_Request_Id := First_Request_Id;
         return CryptoLib.Errors.Internal_Error;
   end Pipelined_Write_File;

   function Pipelined_Write_File_From_Offset
     (Channel          : in out SSH_Lib.Channels.Channel;
      Handle           : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      File_Item        : in out Ada.Streams.Stream_IO.File_Type;
      Start_Offset     : Interfaces.Unsigned_64;
      Size_Value       : Natural;
      First_Request_Id : Interfaces.Unsigned_32;
      Pipeline_Depth   : Positive;
      Next_Request_Id  : out Interfaces.Unsigned_32;
      Chunk_Size       : Natural := Upload_Chunk_Size)
      return CryptoLib.Errors.Status
   is
      subtype Window_Index is Natural range 1 .. Pipeline_Depth;
      Request_Ids  : array (Window_Index) of Interfaces.Unsigned_32 :=
        [others => 0];
      Active       : array (Window_Index) of Boolean := [others => False];
      Remaining    : Natural := Size_Value;
      Offset_Value : Interfaces.Unsigned_64 := Start_Offset;
      Request_Id   : Interfaces.Unsigned_32 := First_Request_Id;
      Outstanding  : Natural := 0;
      Reply_Packet : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Reply_Id     : Interfaces.Unsigned_32 := 0;
      Status_Value : CryptoLib.Errors.Status;

      function Free_Slot return Window_Index is
      begin
         for Index in Window_Index loop
            if not Active (Index) then
               return Index;
            end if;
         end loop;
         return Window_Index'First;
      end Free_Slot;

      function Slot_For (Id : Interfaces.Unsigned_32) return Window_Index is
      begin
         for Index in Window_Index loop
            if Active (Index) and then Request_Ids (Index) = Id then
               return Index;
            end if;
         end loop;
         return Window_Index'First;
      end Slot_For;
   begin
      Next_Request_Id := First_Request_Id;
      if Size_Value = 0 then
         return CryptoLib.Errors.Ok;
      end if;
      if Start_Offset
        > Interfaces.Unsigned_64
            (Ada.Streams.Stream_IO.Count'Last
             - Ada.Streams.Stream_IO.Count'(1))
      then
         return CryptoLib.Errors.Read_Failed;
      end if;

      Ada.Streams.Stream_IO.Set_Index
        (File_Item,
         Ada.Streams.Stream_IO.Count (Start_Offset)
         + Ada.Streams.Stream_IO.Count'(1));

      while Remaining > 0 or else Outstanding > 0 loop
         while Remaining > 0 and then Outstanding < Pipeline_Depth loop
            declare
               Read_Count : constant Natural :=
                 (if Remaining < Chunk_Size then Remaining else Chunk_Size);
               Buffer     :
                 Stream_Element_Array
                   (1 .. Stream_Element_Offset (Read_Count));
               Last       : Stream_Element_Offset;
               Slot       : constant Window_Index := Free_Slot;
            begin
               Ada.Streams.Stream_IO.Read (File_Item, Buffer, Last);
               if Last /= Buffer'Last then
                  Next_Request_Id := Request_Id;
                  return CryptoLib.Errors.Read_Failed;
               end if;

               Status_Value :=
                 Send_Packet
                   (Channel,
                    Encode_Write_Request
                      (Request_Id, Handle, Offset_Value, Buffer));
               if Status_Value /= CryptoLib.Errors.Ok then
                  Next_Request_Id := Request_Id + 1;
                  return Status_Value;
               end if;

               Active (Slot) := True;
               Request_Ids (Slot) := Request_Id;
               Outstanding := Outstanding + 1;
               Remaining := Remaining - Read_Count;
               Offset_Value :=
                 Offset_Value + Interfaces.Unsigned_64 (Read_Count);
               Request_Id := Request_Id + 1;
            end;
         end loop;

         if Outstanding > 0 then
            Status_Value := Read_Packet (Channel, Reply_Packet);
            if Status_Value /= CryptoLib.Errors.Ok then
               Next_Request_Id := Request_Id;
               return Status_Value;
            end if;
            Status_Value := Parse_Status_Response (Reply_Packet, Reply_Id);
            if Status_Value /= CryptoLib.Errors.Ok then
               Next_Request_Id := Request_Id;
               return Status_Value;
            end if;
            declare
               Slot : constant Window_Index := Slot_For (Reply_Id);
            begin
               if not Active (Slot) or else Request_Ids (Slot) /= Reply_Id then
                  Next_Request_Id := Request_Id;
                  return CryptoLib.Errors.Read_Failed;
               end if;
               Active (Slot) := False;
               Outstanding := Outstanding - 1;
            end;
         end if;
      end loop;

      Next_Request_Id := Request_Id;
      return CryptoLib.Errors.Ok;
   exception
      when others =>
         Next_Request_Id := First_Request_Id;
         return CryptoLib.Errors.Internal_Error;
   end Pipelined_Write_File_From_Offset;

   function Pipelined_Read_To_Buffer
     (Channel          : in out SSH_Lib.Channels.Channel;
      Handle           : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Start_Offset     : Interfaces.Unsigned_64;
      Length           : Natural;
      First_Request_Id : Interfaces.Unsigned_32;
      Pipeline_Depth   : Positive;
      Data             : out SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Next_Request_Id  : out Interfaces.Unsigned_32;
      Chunk_Size       : Natural := Upload_Chunk_Size)
      return CryptoLib.Errors.Status
   is
      subtype Window_Index is Natural range 1 .. Pipeline_Depth;
      Request_Ids    : array (Window_Index) of Interfaces.Unsigned_32 :=
        [others => 0];
      Active         : array (Window_Index) of Boolean := [others => False];
      Received       : array (Window_Index) of Boolean := [others => False];
      Chunks         :
        array (Window_Index) of SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Offset_Value   : Interfaces.Unsigned_64 := Start_Offset;
      Remaining_Send : Natural := Length;
      Remaining_Emit : Natural := Length;
      Request_Id     : Interfaces.Unsigned_32 := First_Request_Id;
      Expected_Id    : Interfaces.Unsigned_32 := First_Request_Id;
      Outstanding    : Natural := 0;
      Reply_Packet   : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Reply_Chunk    : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Reply_Id       : Interfaces.Unsigned_32 := 0;
      Status_Value   : CryptoLib.Errors.Status;
      Eof_Seen       : Boolean := False;

      function Free_Slot return Window_Index is
      begin
         for Index in Window_Index loop
            if not Active (Index) then
               return Index;
            end if;
         end loop;
         return Window_Index'First;
      end Free_Slot;

      function Slot_For (Id : Interfaces.Unsigned_32) return Window_Index is
      begin
         for Index in Window_Index loop
            if Active (Index) and then Request_Ids (Index) = Id then
               return Index;
            end if;
         end loop;
         return Window_Index'First;
      end Slot_For;

      procedure Emit_Ready is
      begin
         loop
            declare
               Slot : constant Window_Index := Slot_For (Expected_Id);
            begin
               exit when
                 not Active (Slot)
                 or else Request_Ids (Slot) /= Expected_Id
                 or else not Received (Slot);
               declare
                  Chunk_Data : constant Stream_Element_Array :=
                    SSH_Lib.Protocol.Buffers.To_Array (Chunks (Slot));
               begin
                  if Chunk_Data'Length > 0 then
                     Status_Value :=
                       SSH_Lib.Protocol.Buffers.Append (Data, Chunk_Data);
                     if Status_Value /= CryptoLib.Errors.Ok then
                        return;
                     end if;
                     if Chunk_Data'Length >= Remaining_Emit then
                        Remaining_Emit := 0;
                     else
                        Remaining_Emit := Remaining_Emit - Chunk_Data'Length;
                     end if;
                  end if;
               end;
               Active (Slot) := False;
               Received (Slot) := False;
               SSH_Lib.Protocol.Buffers.Clear (Chunks (Slot));
               Outstanding := Outstanding - 1;
               Expected_Id := Expected_Id + 1;
            end;
         end loop;
      end Emit_Ready;
   begin
      SSH_Lib.Protocol.Buffers.Clear (Data);
      Next_Request_Id := First_Request_Id;
      if Length = 0 then
         return CryptoLib.Errors.Ok;
      end if;

      while Remaining_Emit > 0
        and then (Remaining_Send > 0 or else Outstanding > 0)
      loop
         while not Eof_Seen
           and then Remaining_Send > 0
           and then Outstanding < Pipeline_Depth
         loop
            declare
               Read_Count : constant Natural :=
                 (if Remaining_Send < Chunk_Size
                  then Remaining_Send
                  else Chunk_Size);
               Slot       : constant Window_Index := Free_Slot;
            begin
               Status_Value :=
                 Send_Packet
                   (Channel,
                    Encode_Read_Request
                      (Request_Id, Handle, Offset_Value, Read_Count));
               if Status_Value /= CryptoLib.Errors.Ok then
                  Next_Request_Id := Request_Id + 1;
                  return Status_Value;
               end if;
               Active (Slot) := True;
               Received (Slot) := False;
               Request_Ids (Slot) := Request_Id;
               SSH_Lib.Protocol.Buffers.Clear (Chunks (Slot));
               Outstanding := Outstanding + 1;
               Remaining_Send := Remaining_Send - Read_Count;
               Offset_Value :=
                 Offset_Value + Interfaces.Unsigned_64 (Read_Count);
               Request_Id := Request_Id + 1;
            end;
         end loop;

         exit when Outstanding = 0;
         Status_Value := Read_Packet (Channel, Reply_Packet);
         if Status_Value /= CryptoLib.Errors.Ok then
            Next_Request_Id := Request_Id;
            return Status_Value;
         end if;
         Status_Value :=
           Parse_Data_Response (Reply_Packet, Reply_Id, Reply_Chunk);
         if Status_Value = CryptoLib.Errors.End_Of_Stream then
            Eof_Seen := True;
            Remaining_Send := 0;
            declare
               Slot : constant Window_Index := Slot_For (Reply_Id);
            begin
               if not Active (Slot) or else Request_Ids (Slot) /= Reply_Id then
                  Next_Request_Id := Request_Id;
                  return CryptoLib.Errors.Read_Failed;
               end if;
               Received (Slot) := True;
               SSH_Lib.Protocol.Buffers.Clear (Chunks (Slot));
            end;
         elsif Status_Value /= CryptoLib.Errors.Ok then
            Next_Request_Id := Request_Id;
            return Status_Value;
         else
            declare
               Slot : constant Window_Index := Slot_For (Reply_Id);
            begin
               if not Active (Slot) or else Request_Ids (Slot) /= Reply_Id then
                  Next_Request_Id := Request_Id;
                  return CryptoLib.Errors.Read_Failed;
               end if;
               Status_Value :=
                 SSH_Lib.Protocol.Buffers.Set
                   (Chunks (Slot),
                    SSH_Lib.Protocol.Buffers.To_Array (Reply_Chunk));
               if Status_Value /= CryptoLib.Errors.Ok then
                  Next_Request_Id := Request_Id;
                  return Status_Value;
               end if;
               Received (Slot) := True;
            end;
         end if;

         Emit_Ready;
         if Status_Value /= CryptoLib.Errors.Ok then
            Next_Request_Id := Request_Id;
            return Status_Value;
         end if;
         exit when Eof_Seen and then Outstanding = 0;
      end loop;

      Next_Request_Id := Request_Id;
      return CryptoLib.Errors.Ok;
   exception
      when others =>
         SSH_Lib.Protocol.Buffers.Clear (Data);
         Next_Request_Id := First_Request_Id;
         return CryptoLib.Errors.Internal_Error;
   end Pipelined_Read_To_Buffer;

   function Download_Data
     (Channel     : in out SSH_Lib.Channels.Channel;
      Remote_Path : String;
      Data        : out SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Options     : Transfer_Options := Default_Transfer_Options)
      return CryptoLib.Errors.Status
   is
      Attributes    : File_Attributes;
      Handle        : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Request_Id    : Interfaces.Unsigned_32 := 2;
      Status_Value  : CryptoLib.Errors.Status;
      Remote_Opened : Boolean := False;
   begin
      SSH_Lib.Protocol.Buffers.Clear (Data);
      if not Safe_Remote_Path (Remote_Path) then
         return CryptoLib.Errors.Invalid_Command;
      end if;

      Status_Value := Stat (Channel, Remote_Path, Attributes);
      if Status_Value /= CryptoLib.Errors.Ok
        or else not Attributes.Size_Known
        or else Attributes.Size > Interfaces.Unsigned_64 (Natural'Last)
      then
         return CryptoLib.Errors.Read_Failed;
      end if;

      Status_Value := Open_Remote_Read_File (Channel, Remote_Path, Handle);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      Remote_Opened := True;

      Status_Value :=
        Pipelined_Read_To_Buffer
          (Channel,
           Handle,
           0,
           Natural (Attributes.Size),
           2,
           Effective_Pipeline_Depth (Options),
           Data,
           Request_Id,
           Options.Read_Chunk_Size);
      if Status_Value /= CryptoLib.Errors.Ok then
         Close_Remote_File_Best_Effort (Channel, Handle, Request_Id);
         return Status_Value;
      end if;

      Status_Value := Close_Remote_File (Channel, Handle, Request_Id);
      Remote_Opened := False;
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      if Options.Verify_After_Transfer
        and then
          SSH_Lib.Protocol.Buffers.To_Array (Data)'Length
          /= Natural (Attributes.Size)
      then
         SSH_Lib.Protocol.Buffers.Clear (Data);
         return CryptoLib.Errors.Read_Failed;
      end if;
      return CryptoLib.Errors.Ok;
   exception
      when others =>
         if Remote_Opened then
            Close_Remote_File_Best_Effort (Channel, Handle, Request_Id);
         end if;
         SSH_Lib.Protocol.Buffers.Clear (Data);
         return CryptoLib.Errors.Internal_Error;
   end Download_Data;

   function Download_Data
     (Channel     : in out SSH_Lib.Channels.Channel;
      Remote_Path : String;
      Offset      : Interfaces.Unsigned_64;
      Length      : Natural;
      Data        : out SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Options     : Transfer_Options := Default_Transfer_Options)
      return CryptoLib.Errors.Status
   is
      Handle        : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Request_Id    : Interfaces.Unsigned_32 := 2;
      Status_Value  : CryptoLib.Errors.Status;
      Remote_Opened : Boolean := False;
   begin
      SSH_Lib.Protocol.Buffers.Clear (Data);
      if Length = 0 then
         return CryptoLib.Errors.Ok;
      end if;

      Status_Value := Open_Remote_Read_File (Channel, Remote_Path, Handle);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      Remote_Opened := True;

      Status_Value :=
        Pipelined_Read_To_Buffer
          (Channel,
           Handle,
           Offset,
           Length,
           2,
           Effective_Pipeline_Depth (Options),
           Data,
           Request_Id,
           Options.Read_Chunk_Size);
      if Status_Value /= CryptoLib.Errors.Ok then
         Close_Remote_File_Best_Effort (Channel, Handle, Request_Id);
         return Status_Value;
      end if;

      Status_Value := Close_Remote_File (Channel, Handle, Request_Id);
      Remote_Opened := False;
      return Status_Value;
   exception
      when others =>
         if Remote_Opened then
            Close_Remote_File_Best_Effort (Channel, Handle, Request_Id);
         end if;
         SSH_Lib.Protocol.Buffers.Clear (Data);
         return CryptoLib.Errors.Internal_Error;
   end Download_Data;

   function Download_Stream
     (Channel     : in out SSH_Lib.Channels.Channel;
      Remote_Path : String;
      Writer      : Stream_Writer_Access;
      Options     : Transfer_Options := Default_Transfer_Options)
      return CryptoLib.Errors.Status
   is
      Attributes    : File_Attributes;
      Handle        : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Reply_Packet  : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Chunk         : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Offset_Value  : Interfaces.Unsigned_64 := 0;
      Request_Id    : Interfaces.Unsigned_32 := 2;
      Status_Value  : CryptoLib.Errors.Status;
      Remote_Opened : Boolean := False;
      pragma Unreferenced (Options);
   begin
      if not Safe_Remote_Path (Remote_Path) or else Writer = null then
         return CryptoLib.Errors.Invalid_Command;
      end if;

      Status_Value := Stat (Channel, Remote_Path, Attributes);
      if Status_Value /= CryptoLib.Errors.Ok or else not Attributes.Size_Known
      then
         return CryptoLib.Errors.Read_Failed;
      end if;

      Status_Value := Open_Remote_Read_File (Channel, Remote_Path, Handle);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      Remote_Opened := True;

      while Offset_Value < Attributes.Size loop
         declare
            Remaining  : constant Interfaces.Unsigned_64 :=
              Attributes.Size - Offset_Value;
            Read_Count : constant Natural :=
              (if Remaining < Interfaces.Unsigned_64 (Upload_Chunk_Size)
               then Natural (Remaining)
               else Upload_Chunk_Size);
         begin
            Status_Value :=
              Send_Packet
                (Channel,
                 Encode_Read_Request
                   (Request_Id, Handle, Offset_Value, Read_Count));
            if Status_Value /= CryptoLib.Errors.Ok then
               Close_Remote_File_Best_Effort (Channel, Handle, Request_Id + 1);
               return Status_Value;
            end if;

            Status_Value := Read_Packet (Channel, Reply_Packet);
            if Status_Value /= CryptoLib.Errors.Ok then
               Close_Remote_File_Best_Effort (Channel, Handle, Request_Id + 1);
               return Status_Value;
            end if;

            Status_Value :=
              Parse_Data_Packet (Reply_Packet, Request_Id, Chunk);
            if Status_Value /= CryptoLib.Errors.Ok then
               Close_Remote_File_Best_Effort (Channel, Handle, Request_Id + 1);
               return Status_Value;
            end if;

            declare
               Chunk_Data : constant Stream_Element_Array :=
                 SSH_Lib.Protocol.Buffers.To_Array (Chunk);
            begin
               if Chunk_Data'Length = 0 or else Chunk_Data'Length > Read_Count
               then
                  Close_Remote_File_Best_Effort
                    (Channel, Handle, Request_Id + 1);
                  return CryptoLib.Errors.Read_Failed;
               end if;
               Status_Value := Writer (Offset_Value, Chunk_Data);
               if Status_Value /= CryptoLib.Errors.Ok then
                  Close_Remote_File_Best_Effort
                    (Channel, Handle, Request_Id + 1);
                  return Status_Value;
               end if;
               Offset_Value :=
                 Offset_Value + Interfaces.Unsigned_64 (Chunk_Data'Length);
            end;
            Request_Id := Request_Id + 1;
         end;
      end loop;

      Status_Value := Close_Remote_File (Channel, Handle, Request_Id);
      Remote_Opened := False;
      return Status_Value;
   exception
      when others =>
         if Remote_Opened then
            Close_Remote_File_Best_Effort (Channel, Handle, Request_Id);
         end if;
         return CryptoLib.Errors.Internal_Error;
   end Download_Stream;

   function Download_File
     (Channel     : in out SSH_Lib.Channels.Channel;
      Remote_Path : String;
      Local_Path  : String;
      Options     : Transfer_Options := Default_Transfer_Options)
      return CryptoLib.Errors.Status
   is
      Attributes     : File_Attributes;
      Handle         : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Reply_Packet   : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Chunk          : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Pipelined_Data : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      File_Item      : Ada.Streams.Stream_IO.File_Type;
      Temp_Path      : constant String :=
        Local_Path & ".ada-ssh-sftp-download.tmp";
      Offset_Value   : Interfaces.Unsigned_64 := 0;
      Request_Id     : Interfaces.Unsigned_32 := 2;
      Status_Value   : CryptoLib.Errors.Status;
      Remote_Opened  : Boolean := False;
      Local_Opened   : Boolean := False;

      procedure Remove_Temp_File is
      begin
         if Ada.Directories.Exists (Temp_Path) then
            Ada.Directories.Delete_File (Temp_Path);
         end if;
      exception
         when others =>
            null;
      end Remove_Temp_File;
   begin
      if Local_Path'Length = 0 then
         return CryptoLib.Errors.Invalid_Command;
      end if;

      Remove_Temp_File;

      Status_Value := Stat (Channel, Remote_Path, Attributes);
      if Status_Value = CryptoLib.Errors.Ok
        and then Attributes.Size_Known
        and then Attributes.Size <= Interfaces.Unsigned_64 (Natural'Last)
      then
         Status_Value := Open_Remote_Read_File (Channel, Remote_Path, Handle);
         if Status_Value /= CryptoLib.Errors.Ok then
            return Status_Value;
         end if;
         Remote_Opened := True;
         Status_Value :=
           Pipelined_Read_To_Buffer
             (Channel,
              Handle,
              0,
              Natural (Attributes.Size),
              2,
              Effective_Pipeline_Depth (Options),
              Pipelined_Data,
              Request_Id);
         if Status_Value /= CryptoLib.Errors.Ok then
            Close_Remote_File_Best_Effort (Channel, Handle, Request_Id);
            Remove_Temp_File;
            return Status_Value;
         end if;
         Status_Value := Close_Remote_File (Channel, Handle, Request_Id);
         Remote_Opened := False;
         if Status_Value /= CryptoLib.Errors.Ok then
            Remove_Temp_File;
            return Status_Value;
         end if;

         Ada.Streams.Stream_IO.Create
           (File_Item, Ada.Streams.Stream_IO.Out_File, Temp_Path);
         Local_Opened := True;
         declare
            Bytes : constant Stream_Element_Array :=
              SSH_Lib.Protocol.Buffers.To_Array (Pipelined_Data);
         begin
            if Bytes'Length > 0 then
               Ada.Streams.Stream_IO.Write (File_Item, Bytes);
            end if;
         end;
         Ada.Streams.Stream_IO.Close (File_Item);
         Local_Opened := False;
         if Ada.Directories.Exists (Local_Path) then
            Ada.Directories.Delete_File (Local_Path);
         end if;
         Ada.Directories.Rename (Temp_Path, Local_Path);
         if Options.Verify_After_Transfer then
            if not Attributes.Size_Known then
               return CryptoLib.Errors.Remote_Failure;
            end if;
            return Verify_Local_Size (Local_Path, Attributes.Size);
         end if;
         return CryptoLib.Errors.Ok;
      end if;

      Status_Value := Open_Remote_Read_File (Channel, Remote_Path, Handle);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      Remote_Opened := True;

      Ada.Streams.Stream_IO.Create
        (File_Item, Ada.Streams.Stream_IO.Out_File, Temp_Path);
      Local_Opened := True;

      loop
         Status_Value :=
           Send_Packet
             (Channel,
              Encode_Read_Request
                (Request_Id, Handle, Offset_Value, Upload_Chunk_Size));
         if Status_Value /= CryptoLib.Errors.Ok then
            Ada.Streams.Stream_IO.Close (File_Item);
            Local_Opened := False;
            Close_Remote_File_Best_Effort (Channel, Handle, Request_Id + 1);
            Remove_Temp_File;
            return Status_Value;
         end if;
         Status_Value := Read_Packet (Channel, Reply_Packet);
         if Status_Value /= CryptoLib.Errors.Ok then
            Ada.Streams.Stream_IO.Close (File_Item);
            Local_Opened := False;
            Close_Remote_File_Best_Effort (Channel, Handle, Request_Id + 1);
            Remove_Temp_File;
            return Status_Value;
         end if;
         Status_Value := Parse_Data_Packet (Reply_Packet, Request_Id, Chunk);
         if Status_Value = CryptoLib.Errors.End_Of_Stream then
            exit;
         elsif Status_Value /= CryptoLib.Errors.Ok then
            Ada.Streams.Stream_IO.Close (File_Item);
            Local_Opened := False;
            Close_Remote_File_Best_Effort (Channel, Handle, Request_Id + 1);
            Remove_Temp_File;
            return Status_Value;
         end if;

         declare
            Chunk_Data : constant Stream_Element_Array :=
              SSH_Lib.Protocol.Buffers.To_Array (Chunk);
         begin
            if Chunk_Data'Length > 0 then
               Ada.Streams.Stream_IO.Write (File_Item, Chunk_Data);
            end if;
            Offset_Value :=
              Offset_Value + Interfaces.Unsigned_64 (Chunk_Data'Length);
         exception
            when others =>
               Ada.Streams.Stream_IO.Close (File_Item);
               Local_Opened := False;
               Close_Remote_File_Best_Effort (Channel, Handle, Request_Id + 1);
               Remove_Temp_File;
               return CryptoLib.Errors.Write_Failed;
         end;
         Request_Id := Request_Id + 1;
      end loop;

      Status_Value := Close_Remote_File (Channel, Handle, Request_Id + 1);
      Remote_Opened := False;
      if Status_Value /= CryptoLib.Errors.Ok then
         Ada.Streams.Stream_IO.Close (File_Item);
         Local_Opened := False;
         Remove_Temp_File;
         return Status_Value;
      end if;

      Ada.Streams.Stream_IO.Close (File_Item);
      Local_Opened := False;
      if Ada.Directories.Exists (Local_Path) then
         Ada.Directories.Delete_File (Local_Path);
      end if;
      Ada.Directories.Rename (Temp_Path, Local_Path);
      if Options.Verify_After_Transfer then
         if not Attributes.Size_Known then
            return CryptoLib.Errors.Remote_Failure;
         end if;
         return Verify_Local_Size (Local_Path, Attributes.Size);
      end if;
      return CryptoLib.Errors.Ok;
   exception
      when others =>
         if Local_Opened and then Ada.Streams.Stream_IO.Is_Open (File_Item)
         then
            Ada.Streams.Stream_IO.Close (File_Item);
         end if;
         if Remote_Opened then
            Close_Remote_File_Best_Effort (Channel, Handle, Request_Id + 1);
         end if;
         Remove_Temp_File;
         return CryptoLib.Errors.Write_Failed;
   end Download_File;

   function Resume_Download_File
     (Channel     : in out SSH_Lib.Channels.Channel;
      Remote_Path : String;
      Local_Path  : String;
      Options     : Transfer_Options := Default_Transfer_Options)
      return CryptoLib.Errors.Status
   is
      Attributes    : File_Attributes;
      Handle        : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Data          : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      File_Item     : Ada.Streams.Stream_IO.File_Type;
      Local_Size    : Interfaces.Unsigned_64 := 0;
      Remaining     : Natural := 0;
      Request_Id    : Interfaces.Unsigned_32 := 2;
      Status_Value  : CryptoLib.Errors.Status;
      Remote_Opened : Boolean := False;
      Local_Opened  : Boolean := False;
   begin
      if not Safe_Remote_Path (Remote_Path) or else Local_Path'Length = 0 then
         return CryptoLib.Errors.Invalid_Command;
      end if;

      if Ada.Directories.Exists (Local_Path) then
         if Ada.Directories.Kind (Local_Path) /= Ada.Directories.Ordinary_File
         then
            return CryptoLib.Errors.Invalid_Command;
         end if;
         Local_Size :=
           Interfaces.Unsigned_64 (Ada.Directories.Size (Local_Path));
      end if;

      Status_Value := Stat (Channel, Remote_Path, Attributes);
      if Status_Value /= CryptoLib.Errors.Ok
        or else not Attributes.Size_Known
        or else Attributes.Size > Interfaces.Unsigned_64 (Natural'Last)
      then
         return CryptoLib.Errors.Read_Failed;
      end if;
      if Local_Size > Attributes.Size then
         return CryptoLib.Errors.Invalid_Command;
      elsif Local_Size = Attributes.Size then
         if Options.Verify_After_Transfer then
            return Verify_Local_Size (Local_Path, Attributes.Size);
         end if;
         return CryptoLib.Errors.Ok;
      end if;

      Remaining := Natural (Attributes.Size - Local_Size);
      Status_Value := Open_Remote_Read_File (Channel, Remote_Path, Handle);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      Remote_Opened := True;

      Status_Value :=
        Pipelined_Read_To_Buffer
          (Channel,
           Handle,
           Local_Size,
           Remaining,
           2,
           Effective_Pipeline_Depth (Options),
           Data,
           Request_Id,
           Options.Read_Chunk_Size);
      if Status_Value /= CryptoLib.Errors.Ok then
         Close_Remote_File_Best_Effort (Channel, Handle, Request_Id);
         return Status_Value;
      end if;

      Status_Value := Close_Remote_File (Channel, Handle, Request_Id);
      Remote_Opened := False;
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;

      if Ada.Directories.Exists (Local_Path) then
         Ada.Streams.Stream_IO.Open
           (File_Item, Ada.Streams.Stream_IO.Append_File, Local_Path);
      else
         Ada.Streams.Stream_IO.Create
           (File_Item, Ada.Streams.Stream_IO.Out_File, Local_Path);
      end if;
      Local_Opened := True;
      declare
         Bytes : constant Stream_Element_Array :=
           SSH_Lib.Protocol.Buffers.To_Array (Data);
      begin
         if Bytes'Length /= Remaining then
            Ada.Streams.Stream_IO.Close (File_Item);
            Local_Opened := False;
            return CryptoLib.Errors.Read_Failed;
         elsif Bytes'Length > 0 then
            Ada.Streams.Stream_IO.Write (File_Item, Bytes);
         end if;
      end;
      Ada.Streams.Stream_IO.Close (File_Item);
      Local_Opened := False;

      if Options.Verify_After_Transfer then
         return Verify_Local_Size (Local_Path, Attributes.Size);
      end if;
      return CryptoLib.Errors.Ok;
   exception
      when others =>
         if Local_Opened and then Ada.Streams.Stream_IO.Is_Open (File_Item)
         then
            Ada.Streams.Stream_IO.Close (File_Item);
         end if;
         if Remote_Opened then
            Close_Remote_File_Best_Effort (Channel, Handle, Request_Id);
         end if;
         return CryptoLib.Errors.Write_Failed;
   end Resume_Download_File;

   function List_Directory
     (Channel     : in out SSH_Lib.Channels.Channel;
      Remote_Path : String;
      Names       : out Unbounded_String) return CryptoLib.Errors.Status
   is
      Handle        : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Reply_Packet  : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Request_Id    : Interfaces.Unsigned_32 := 2;
      Status_Value  : CryptoLib.Errors.Status;
      Remote_Opened : Boolean := False;
   begin
      Names := Null_Unbounded_String;
      if not Safe_Remote_Path (Remote_Path) then
         return CryptoLib.Errors.Invalid_Command;
      end if;

      Status_Value :=
        Send_Packet
          (Channel, Encode_Path_Request (SSH_FXP_OPENDIR, 1, Remote_Path));
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      Status_Value := Read_Packet (Channel, Reply_Packet);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      Status_Value := Parse_Handle_Packet (Reply_Packet, 1, Handle);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      Remote_Opened := True;

      loop
         Status_Value :=
           Send_Packet
             (Channel,
              Encode_Handle_Request (SSH_FXP_READDIR, Request_Id, Handle));
         if Status_Value /= CryptoLib.Errors.Ok then
            Close_Remote_File_Best_Effort (Channel, Handle, Request_Id + 1);
            return Status_Value;
         end if;
         Status_Value := Read_Packet (Channel, Reply_Packet);
         if Status_Value /= CryptoLib.Errors.Ok then
            Close_Remote_File_Best_Effort (Channel, Handle, Request_Id + 1);
            return Status_Value;
         end if;
         Status_Value := Parse_Name_Packet (Reply_Packet, Request_Id, Names);
         if Status_Value = CryptoLib.Errors.End_Of_Stream then
            exit;
         elsif Status_Value /= CryptoLib.Errors.Ok then
            Close_Remote_File_Best_Effort (Channel, Handle, Request_Id + 1);
            return Status_Value;
         end if;
         Request_Id := Request_Id + 1;
      end loop;

      Status_Value := Close_Remote_File (Channel, Handle, Request_Id + 1);
      Remote_Opened := False;
      return Status_Value;
   exception
      when others =>
         if Remote_Opened then
            Close_Remote_File_Best_Effort (Channel, Handle, Request_Id + 1);
         end if;
         Names := Null_Unbounded_String;
         return CryptoLib.Errors.Internal_Error;
   end List_Directory;

   function Simple_Status_Request
     (Channel : in out SSH_Lib.Channels.Channel;
      Packet  : SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;

   function List_Directory_Paged
     (Channel     : in out SSH_Lib.Channels.Channel;
      Remote_Path : String;
      Callback    : Directory_Page_Callback_Access)
      return CryptoLib.Errors.Status
   is
      Handle        : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Reply_Packet  : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Request_Id    : Interfaces.Unsigned_32 := 2;
      Page_Entries  : Directory_Entry_Vectors.Vector;
      Status_Value  : CryptoLib.Errors.Status;
      Remote_Opened : Boolean := False;
   begin
      if not Safe_Remote_Path (Remote_Path) or else Callback = null then
         return CryptoLib.Errors.Invalid_Command;
      end if;

      Status_Value :=
        Send_Packet
          (Channel, Encode_Path_Request (SSH_FXP_OPENDIR, 1, Remote_Path));
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      Status_Value := Read_Packet (Channel, Reply_Packet);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      Status_Value := Parse_Handle_Packet (Reply_Packet, 1, Handle);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      Remote_Opened := True;

      loop
         Status_Value :=
           Send_Packet
             (Channel,
              Encode_Handle_Request (SSH_FXP_READDIR, Request_Id, Handle));
         if Status_Value /= CryptoLib.Errors.Ok then
            Close_Remote_File_Best_Effort (Channel, Handle, Request_Id + 1);
            return Status_Value;
         end if;
         Status_Value := Read_Packet (Channel, Reply_Packet);
         if Status_Value /= CryptoLib.Errors.Ok then
            Close_Remote_File_Best_Effort (Channel, Handle, Request_Id + 1);
            return Status_Value;
         end if;

         Page_Entries.Clear;
         Status_Value :=
           Parse_Directory_Entries_Packet
             (Reply_Packet, Request_Id, Page_Entries);
         if Status_Value = CryptoLib.Errors.End_Of_Stream then
            exit;
         elsif Status_Value /= CryptoLib.Errors.Ok then
            Close_Remote_File_Best_Effort (Channel, Handle, Request_Id + 1);
            return Status_Value;
         elsif not Page_Entries.Is_Empty then
            Status_Value := Callback (Page_Entries);
            if Status_Value /= CryptoLib.Errors.Ok then
               Close_Remote_File_Best_Effort (Channel, Handle, Request_Id + 1);
               return Status_Value;
            end if;
         end if;
         Request_Id := Request_Id + 1;
      end loop;

      Status_Value := Close_Remote_File (Channel, Handle, Request_Id + 1);
      Remote_Opened := False;
      return Status_Value;
   exception
      when others =>
         if Remote_Opened then
            Close_Remote_File_Best_Effort (Channel, Handle, Request_Id + 1);
         end if;
         return CryptoLib.Errors.Internal_Error;
   end List_Directory_Paged;

   function List_Directory
     (Channel     : in out SSH_Lib.Channels.Channel;
      Remote_Path : String;
      Entries     : out Directory_Entry_Vectors.Vector)
      return CryptoLib.Errors.Status
   is
      Handle        : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Reply_Packet  : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Request_Id    : Interfaces.Unsigned_32 := 2;
      Status_Value  : CryptoLib.Errors.Status;
      Remote_Opened : Boolean := False;
   begin
      Entries.Clear;
      if not Safe_Remote_Path (Remote_Path) then
         return CryptoLib.Errors.Invalid_Command;
      end if;

      Status_Value :=
        Send_Packet
          (Channel, Encode_Path_Request (SSH_FXP_OPENDIR, 1, Remote_Path));
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      Status_Value := Read_Packet (Channel, Reply_Packet);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      Status_Value := Parse_Handle_Packet (Reply_Packet, 1, Handle);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      Remote_Opened := True;

      loop
         Status_Value :=
           Send_Packet
             (Channel,
              Encode_Handle_Request (SSH_FXP_READDIR, Request_Id, Handle));
         if Status_Value /= CryptoLib.Errors.Ok then
            Close_Remote_File_Best_Effort (Channel, Handle, Request_Id + 1);
            return Status_Value;
         end if;
         Status_Value := Read_Packet (Channel, Reply_Packet);
         if Status_Value /= CryptoLib.Errors.Ok then
            Close_Remote_File_Best_Effort (Channel, Handle, Request_Id + 1);
            return Status_Value;
         end if;
         Status_Value :=
           Parse_Directory_Entries_Packet (Reply_Packet, Request_Id, Entries);
         if Status_Value = CryptoLib.Errors.End_Of_Stream then
            exit;
         elsif Status_Value /= CryptoLib.Errors.Ok then
            Close_Remote_File_Best_Effort (Channel, Handle, Request_Id + 1);
            return Status_Value;
         end if;
         Request_Id := Request_Id + 1;
      end loop;

      Status_Value := Close_Remote_File (Channel, Handle, Request_Id + 1);
      Remote_Opened := False;
      return Status_Value;
   exception
      when others =>
         if Remote_Opened then
            Close_Remote_File_Best_Effort (Channel, Handle, Request_Id + 1);
         end if;
         Entries.Clear;
         return CryptoLib.Errors.Internal_Error;
   end List_Directory;

   function List_Directory
     (Channel     : in out SSH_Lib.Channels.Channel;
      Remote_Path : String;
      Entries     : out Directory_Entry_Vectors.Vector;
      Version     : Natural) return CryptoLib.Errors.Status
   is
      Handle        : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Reply_Packet  : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Request_Id    : Interfaces.Unsigned_32 := 2;
      Status_Value  : CryptoLib.Errors.Status;
      Remote_Opened : Boolean := False;
   begin
      Entries.Clear;
      if Version <= 3 then
         return List_Directory (Channel, Remote_Path, Entries);
      elsif not Safe_Remote_Path (Remote_Path) then
         return CryptoLib.Errors.Invalid_Command;
      end if;

      Status_Value :=
        Send_Packet
          (Channel, Encode_Path_Request (SSH_FXP_OPENDIR, 1, Remote_Path));
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      Status_Value := Read_Packet (Channel, Reply_Packet);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      Status_Value := Parse_Handle_Packet (Reply_Packet, 1, Handle);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      Remote_Opened := True;

      loop
         Status_Value :=
           Send_Packet
             (Channel,
              Encode_Handle_Request (SSH_FXP_READDIR, Request_Id, Handle));
         if Status_Value /= CryptoLib.Errors.Ok then
            Close_Remote_File_Best_Effort (Channel, Handle, Request_Id + 1);
            return Status_Value;
         end if;
         Status_Value := Read_Packet (Channel, Reply_Packet);
         if Status_Value /= CryptoLib.Errors.Ok then
            Close_Remote_File_Best_Effort (Channel, Handle, Request_Id + 1);
            return Status_Value;
         end if;
         Status_Value :=
           Parse_Directory_Entries_Packet
             (Reply_Packet, Request_Id, Entries, Version);
         if Status_Value = CryptoLib.Errors.End_Of_Stream then
            exit;
         elsif Status_Value /= CryptoLib.Errors.Ok then
            Close_Remote_File_Best_Effort (Channel, Handle, Request_Id + 1);
            return Status_Value;
         end if;
         Request_Id := Request_Id + 1;
      end loop;

      Status_Value := Close_Remote_File (Channel, Handle, Request_Id + 1);
      Remote_Opened := False;
      return Status_Value;
   exception
      when others =>
         if Remote_Opened then
            Close_Remote_File_Best_Effort (Channel, Handle, Request_Id + 1);
         end if;
         Entries.Clear;
         return CryptoLib.Errors.Internal_Error;
   end List_Directory;

   function Realpath
     (Channel        : in out SSH_Lib.Channels.Channel;
      Remote_Path    : String;
      Canonical_Path : out Unbounded_String;
      Version        : Natural) return CryptoLib.Errors.Status
   is
      Reply_Packet : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Status_Value : CryptoLib.Errors.Status;
   begin
      Canonical_Path := Null_Unbounded_String;
      if Version <= 3 then
         return Realpath (Channel, Remote_Path, Canonical_Path);
      elsif not Safe_Remote_Path (Remote_Path) then
         return CryptoLib.Errors.Invalid_Command;
      end if;
      Status_Value :=
        Send_Packet
          (Channel, Encode_Path_Request (SSH_FXP_REALPATH, 1, Remote_Path));
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      Status_Value := Read_Packet (Channel, Reply_Packet);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      return Parse_Name_Packet (Reply_Packet, 1, Canonical_Path, Version);
   exception
      when others =>
         Canonical_Path := Null_Unbounded_String;
         return CryptoLib.Errors.Internal_Error;
   end Realpath;

   function Stat_Request
     (Channel     : in out SSH_Lib.Channels.Channel;
      Message     : Stream_Element;
      Remote_Path : String;
      Attributes  : out File_Attributes) return CryptoLib.Errors.Status
   is
      Reply_Packet : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Status_Value : CryptoLib.Errors.Status;
   begin
      Attributes := (others => <>);
      Status_Value :=
        Send_Packet (Channel, Encode_Path_Request (Message, 1, Remote_Path));
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      Status_Value := Read_Packet (Channel, Reply_Packet);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      return Parse_Attrs_Packet (Reply_Packet, 1, Attributes);
   exception
      when others =>
         Attributes := (others => <>);
         return CryptoLib.Errors.Internal_Error;
   end Stat_Request;

   function Stat_Request
     (Channel     : in out SSH_Lib.Channels.Channel;
      Message     : Stream_Element;
      Remote_Path : String;
      Attributes  : out File_Attributes;
      Version     : Natural) return CryptoLib.Errors.Status
   is
      Reply_Packet : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Status_Value : CryptoLib.Errors.Status;
   begin
      Attributes := (others => <>);
      if Version <= 3 then
         return Stat_Request (Channel, Message, Remote_Path, Attributes);
      end if;

      Status_Value :=
        Send_Packet (Channel, Encode_Path_Request (Message, 1, Remote_Path));
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      Status_Value := Read_Packet (Channel, Reply_Packet);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      return Parse_Attrs_Packet (Reply_Packet, 1, Attributes, Version);
   exception
      when others =>
         Attributes := (others => <>);
         return CryptoLib.Errors.Internal_Error;
   end Stat_Request;

   function Stat
     (Channel     : in out SSH_Lib.Channels.Channel;
      Remote_Path : String;
      Attributes  : out File_Attributes) return CryptoLib.Errors.Status is
   begin
      if not Safe_Remote_Path (Remote_Path) then
         Attributes := (others => <>);
         return CryptoLib.Errors.Invalid_Command;
      end if;
      return Stat_Request (Channel, SSH_FXP_STAT, Remote_Path, Attributes);
   end Stat;

   function LStat
     (Channel     : in out SSH_Lib.Channels.Channel;
      Remote_Path : String;
      Attributes  : out File_Attributes) return CryptoLib.Errors.Status is
   begin
      if not Safe_Remote_Path (Remote_Path) then
         Attributes := (others => <>);
         return CryptoLib.Errors.Invalid_Command;
      end if;
      return Stat_Request (Channel, SSH_FXP_LSTAT, Remote_Path, Attributes);
   end LStat;

   function Realpath
     (Channel        : in out SSH_Lib.Channels.Channel;
      Remote_Path    : String;
      Canonical_Path : out Unbounded_String) return CryptoLib.Errors.Status
   is
      Reply_Packet : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Status_Value : CryptoLib.Errors.Status;
   begin
      Canonical_Path := Null_Unbounded_String;
      if not Safe_Remote_Path (Remote_Path) then
         return CryptoLib.Errors.Invalid_Command;
      end if;
      Status_Value :=
        Send_Packet
          (Channel, Encode_Path_Request (SSH_FXP_REALPATH, 1, Remote_Path));
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      Status_Value := Read_Packet (Channel, Reply_Packet);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      return Parse_Name_Packet (Reply_Packet, 1, Canonical_Path);
   exception
      when others =>
         Canonical_Path := Null_Unbounded_String;
         return CryptoLib.Errors.Internal_Error;
   end Realpath;

   function Open_Read
     (Channel     : in out SSH_Lib.Channels.Channel;
      Remote_Path : String;
      Handle      : out File_Handle) return CryptoLib.Errors.Status
   is
      Status_Value : CryptoLib.Errors.Status;
   begin
      Clear_Handle (Handle);
      Status_Value :=
        Open_Remote_Read_File (Channel, Remote_Path, Handle.Data);
      if Status_Value = CryptoLib.Errors.Ok then
         Handle.Opened := True;
         Handle.Version := Protocol_Version;
      else
         Clear_Handle (Handle);
      end if;
      return Status_Value;
   exception
      when others =>
         Clear_Handle (Handle);
         return CryptoLib.Errors.Internal_Error;
   end Open_Read;

   function Open_Read
     (Channel     : in out SSH_Lib.Channels.Channel;
      Remote_Path : String;
      Handle      : out File_Handle;
      Version     : Natural) return CryptoLib.Errors.Status
   is
      Status_Value : CryptoLib.Errors.Status;
   begin
      Clear_Handle (Handle);
      Status_Value :=
        Open_Remote_Read_File (Channel, Remote_Path, Handle.Data, Version);
      if Status_Value = CryptoLib.Errors.Ok then
         Handle.Opened := True;
         Handle.Version := Version;
      else
         Clear_Handle (Handle);
      end if;
      return Status_Value;
   exception
      when others =>
         Clear_Handle (Handle);
         return CryptoLib.Errors.Internal_Error;
   end Open_Read;

   function Open_Write
     (Channel     : in out SSH_Lib.Channels.Channel;
      Remote_Path : String;
      Handle      : out File_Handle;
      Mode        : String := "0644") return CryptoLib.Errors.Status is
   begin
      return Open_File (Channel, Remote_Path, Handle, Write_Truncate, Mode);
   end Open_Write;

   function Open_File
     (Channel          : in out SSH_Lib.Channels.Channel;
      Remote_Path      : String;
      Handle           : out File_Handle;
      Mode             : Open_Mode;
      Permissions_Mode : String := "0644") return CryptoLib.Errors.Status
   is
      Status_Value : CryptoLib.Errors.Status;
   begin
      Clear_Handle (Handle);
      Status_Value :=
        Open_Remote_File_Mode
          (Channel, Remote_Path, Mode, Permissions_Mode, Handle.Data);
      if Status_Value = CryptoLib.Errors.Ok then
         Handle.Opened := True;
         Handle.Version := Protocol_Version;
      else
         Clear_Handle (Handle);
      end if;
      return Status_Value;
   exception
      when others =>
         Clear_Handle (Handle);
         return CryptoLib.Errors.Internal_Error;
   end Open_File;

   function Open_File
     (Channel          : in out SSH_Lib.Channels.Channel;
      Remote_Path      : String;
      Handle           : out File_Handle;
      Mode             : Open_Mode;
      Permissions_Mode : String;
      Version          : Natural) return CryptoLib.Errors.Status
   is
      Status_Value : CryptoLib.Errors.Status;
   begin
      Clear_Handle (Handle);
      Status_Value :=
        Open_Remote_File_Mode
          (Channel, Remote_Path, Mode, Permissions_Mode, Handle.Data, Version);
      if Status_Value = CryptoLib.Errors.Ok then
         Handle.Opened := True;
         Handle.Version := Version;
      else
         Clear_Handle (Handle);
      end if;
      return Status_Value;
   exception
      when others =>
         Clear_Handle (Handle);
         return CryptoLib.Errors.Internal_Error;
   end Open_File;

   function Read_At
     (Channel : in out SSH_Lib.Channels.Channel;
      Handle  : File_Handle;
      Offset  : Interfaces.Unsigned_64;
      Length  : Natural;
      Data    : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status
   is
      Reply_Packet : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Status_Value : CryptoLib.Errors.Status;
   begin
      SSH_Lib.Protocol.Buffers.Clear (Data);
      if not Is_Open (Handle) or else Length = 0 then
         return CryptoLib.Errors.Invalid_Command;
      end if;
      Status_Value :=
        Send_Packet
          (Channel, Encode_Read_Request (1, Handle.Data, Offset, Length));
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      Status_Value := Read_Packet (Channel, Reply_Packet);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      return Parse_Data_Packet (Reply_Packet, 1, Data);
   exception
      when others =>
         SSH_Lib.Protocol.Buffers.Clear (Data);
         return CryptoLib.Errors.Internal_Error;
   end Read_At;

   function Write_At
     (Channel : in out SSH_Lib.Channels.Channel;
      Handle  : File_Handle;
      Offset  : Interfaces.Unsigned_64;
      Data    : Ada.Streams.Stream_Element_Array) return CryptoLib.Errors.Status
   is
   begin
      if not Is_Open (Handle) then
         return CryptoLib.Errors.Invalid_Command;
      end if;
      return Write_Remote_Data (Channel, Handle.Data, 1, Offset, Data);
   end Write_At;

   function Close
     (Channel : in out SSH_Lib.Channels.Channel; Handle : in out File_Handle)
      return CryptoLib.Errors.Status
   is
      Status_Value : CryptoLib.Errors.Status;
   begin
      if not Is_Open (Handle) then
         return CryptoLib.Errors.Invalid_Command;
      end if;
      Status_Value := Close_Remote_File (Channel, Handle.Data, 1);
      if Status_Value = CryptoLib.Errors.Ok then
         Clear_Handle (Handle);
      end if;
      return Status_Value;
   exception
      when others =>
         return CryptoLib.Errors.Internal_Error;
   end Close;

   function FStat
     (Channel    : in out SSH_Lib.Channels.Channel;
      Handle     : File_Handle;
      Attributes : out File_Attributes) return CryptoLib.Errors.Status
   is
      Reply_Packet : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Status_Value : CryptoLib.Errors.Status;
   begin
      Attributes := (others => <>);
      if not Is_Open (Handle) then
         return CryptoLib.Errors.Invalid_Command;
      end if;
      Status_Value :=
        Send_Packet
          (Channel, Encode_Handle_Request (SSH_FXP_FSTAT, 1, Handle.Data));
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      Status_Value := Read_Packet (Channel, Reply_Packet);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      return Parse_Attrs_Packet (Reply_Packet, 1, Attributes, Handle.Version);
   exception
      when others =>
         Attributes := (others => <>);
         return CryptoLib.Errors.Internal_Error;
   end FStat;

   function Set_Handle_Permissions
     (Channel : in out SSH_Lib.Channels.Channel;
      Handle  : File_Handle;
      Mode    : String) return CryptoLib.Errors.Status
   is
      Attributes : constant File_Attributes := Permissions_Attributes (Mode);
   begin
      if not Attributes.Permissions_Known then
         return CryptoLib.Errors.Invalid_Command;
      end if;
      return Set_Handle_Attributes (Channel, Handle, Attributes);
   end Set_Handle_Permissions;

   function Set_Handle_Attributes
     (Channel    : in out SSH_Lib.Channels.Channel;
      Handle     : File_Handle;
      Attributes : File_Attributes) return CryptoLib.Errors.Status is
   begin
      if not Is_Open (Handle) or else not Has_Attributes (Attributes) then
         return CryptoLib.Errors.Invalid_Command;
      end if;
      if Handle.Context_Known
        and then
          not Supports_Attributes
                (Handle.Extensions, Attributes, Handle.Version)
      then
         return CryptoLib.Errors.Unsupported_Feature;
      end if;
      return
        Simple_Status_Request
          (Channel,
           Encode_FSet_Attributes_Request
             (1, Handle.Data, Attributes, Handle.Version));
   end Set_Handle_Attributes;

   function Simple_Status_Request
     (Channel : in out SSH_Lib.Channels.Channel;
      Packet  : SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status
   is
      Reply_Packet : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Status_Value : CryptoLib.Errors.Status;
   begin
      Status_Value := Send_Packet (Channel, Packet);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      Status_Value := Read_Packet (Channel, Reply_Packet);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      return Parse_Status_Packet (Reply_Packet, 1);
   exception
      when others =>
         return CryptoLib.Errors.Internal_Error;
   end Simple_Status_Request;

   function Set_Permissions
     (Channel     : in out SSH_Lib.Channels.Channel;
      Remote_Path : String;
      Mode        : String) return CryptoLib.Errors.Status
   is
      Attributes : constant File_Attributes := Permissions_Attributes (Mode);
   begin
      if not Attributes.Permissions_Known then
         return CryptoLib.Errors.Invalid_Command;
      end if;
      return Set_Attributes (Channel, Remote_Path, Attributes);
   end Set_Permissions;

   function Set_Attributes
     (Channel     : in out SSH_Lib.Channels.Channel;
      Remote_Path : String;
      Attributes  : File_Attributes) return CryptoLib.Errors.Status is
   begin
      if not Safe_Remote_Path (Remote_Path)
        or else not Has_Attributes (Attributes)
      then
         return CryptoLib.Errors.Invalid_Command;
      end if;
      return
        Simple_Status_Request
          (Channel,
           Encode_Set_Attributes_Request (1, Remote_Path, Attributes));
   end Set_Attributes;

   function Make_Directory
     (Channel     : in out SSH_Lib.Channels.Channel;
      Remote_Path : String;
      Mode        : String := "0755") return CryptoLib.Errors.Status is
   begin
      if Validate_Upload_Target (Remote_Path, Mode) /= CryptoLib.Errors.Ok then
         return CryptoLib.Errors.Invalid_Command;
      end if;
      return
        Simple_Status_Request
          (Channel, Encode_Mkdir_Request (1, Remote_Path, Mode));
   end Make_Directory;

   function Remove_Directory
     (Channel : in out SSH_Lib.Channels.Channel; Remote_Path : String)
      return CryptoLib.Errors.Status is
   begin
      if not Safe_Remote_Path (Remote_Path) then
         return CryptoLib.Errors.Invalid_Command;
      end if;
      return
        Simple_Status_Request
          (Channel, Encode_Path_Request (SSH_FXP_RMDIR, 1, Remote_Path));
   end Remove_Directory;

   function Remove_File
     (Channel : in out SSH_Lib.Channels.Channel; Remote_Path : String)
      return CryptoLib.Errors.Status is
   begin
      if not Safe_Remote_Path (Remote_Path) then
         return CryptoLib.Errors.Invalid_Command;
      end if;
      return
        Simple_Status_Request
          (Channel, Encode_Path_Request (SSH_FXP_REMOVE, 1, Remote_Path));
   end Remove_File;

   function Remove_File
     (Channel     : in out SSH_Lib.Channels.Channel;
      Remote_Path : String;
      Result      : out SFTP_Result) return CryptoLib.Errors.Status
   is
      Status_Value : constant CryptoLib.Errors.Status :=
        Remove_File (Channel, Remote_Path);
   begin
      Capture_Result (Status_Value, Result, Remove_Operation);
      return Status_Value;
   end Remove_File;

   function Ensure_Remote_Directory
     (Channel     : in out SSH_Lib.Channels.Channel;
      Remote_Path : String;
      Mode        : String) return CryptoLib.Errors.Status
   is
      Attributes   : File_Attributes;
      Status_Value : CryptoLib.Errors.Status;
   begin
      Status_Value := Make_Directory (Channel, Remote_Path, Mode);
      if Status_Value = CryptoLib.Errors.Ok then
         return CryptoLib.Errors.Ok;
      end if;

      Status_Value := Stat (Channel, Remote_Path, Attributes);
      if Status_Value = CryptoLib.Errors.Ok
        and then Attribute_Is_Directory (Attributes)
      then
         return CryptoLib.Errors.Ok;
      elsif Status_Value = CryptoLib.Errors.Ok then
         return CryptoLib.Errors.Invalid_Command;
      else
         return Status_Value;
      end if;
   exception
      when others =>
         return CryptoLib.Errors.Internal_Error;
   end Ensure_Remote_Directory;

   function Remote_Path_Is_Directory
     (Channel     : in out SSH_Lib.Channels.Channel;
      Remote_Path : String;
      Attributes  : File_Attributes;
      Options     : Recursive_Options) return Boolean
   is
      Refreshed : File_Attributes;
   begin
      if Attribute_Is_Directory (Attributes) then
         return True;
      elsif Attribute_Is_Regular (Attributes) then
         return False;
      elsif Attribute_Is_Symlink (Attributes)
        and then not Options.Follow_Symlinks
      then
         return False;
      elsif (if Options.Follow_Symlinks
             then Stat (Channel, Remote_Path, Refreshed)
             else LStat (Channel, Remote_Path, Refreshed))
        = CryptoLib.Errors.Ok
      then
         return Attribute_Is_Directory (Refreshed);
      else
         return False;
      end if;
   exception
      when others =>
         return False;
   end Remote_Path_Is_Directory;

   function Entry_Kind_For
     (Attributes : File_Attributes) return Recursive_Entry_Kind is
   begin
      if Attribute_Is_Directory (Attributes) then
         return Tree_Directory;
      elsif Attribute_Is_Regular (Attributes) then
         return Tree_File;
      elsif Attribute_Is_Symlink (Attributes) then
         return Tree_Symlink;
      else
         return Tree_Other;
      end if;
   end Entry_Kind_For;

   function Handle_Recursive_Status
     (Options : Recursive_Options; Status_Value : CryptoLib.Errors.Status)
      return CryptoLib.Errors.Status is
   begin
      if Status_Value = CryptoLib.Errors.Ok or else Options.Continue_On_Error
      then
         return CryptoLib.Errors.Ok;
      else
         return Status_Value;
      end if;
   end Handle_Recursive_Status;

   function Remote_Target_File_Allowed
     (Channel     : in out SSH_Lib.Channels.Channel;
      Remote_Path : String;
      Options     : Recursive_Options) return CryptoLib.Errors.Status
   is
      Attributes   : File_Attributes;
      Status_Value : CryptoLib.Errors.Status;
   begin
      if Options.Overwrite_Files then
         return CryptoLib.Errors.Ok;
      end if;
      Status_Value := LStat (Channel, Remote_Path, Attributes);
      if Status_Value = CryptoLib.Errors.No_Such_File then
         return CryptoLib.Errors.Ok;
      elsif Status_Value = CryptoLib.Errors.Ok then
         return CryptoLib.Errors.Remote_Failure;
      else
         return Status_Value;
      end if;
   exception
      when others =>
         return CryptoLib.Errors.Internal_Error;
   end Remote_Target_File_Allowed;

   function Local_Target_File_Allowed
     (Local_Path : String; Options : Recursive_Options)
      return CryptoLib.Errors.Status is
   begin
      if Options.Overwrite_Files
        or else not Ada.Directories.Exists (Local_Path)
      then
         return CryptoLib.Errors.Ok;
      else
         return CryptoLib.Errors.Remote_Failure;
      end if;
   exception
      when others =>
         return CryptoLib.Errors.Internal_Error;
   end Local_Target_File_Allowed;

   function Should_Process
     (Options     : Recursive_Options;
      Source_Path : String;
      Target_Path : String;
      Kind        : Recursive_Entry_Kind) return Boolean is
   begin
      return
        Options.Filter = null
        or else Options.Filter (Source_Path, Target_Path, Kind);
   exception
      when others =>
         return False;
   end Should_Process;

   procedure Report_Progress
     (Options     : Recursive_Options;
      Operation   : Recursive_Operation;
      Source_Path : String;
      Target_Path : String;
      Bytes_Done  : Interfaces.Unsigned_64;
      Bytes_Total : Interfaces.Unsigned_64) is
   begin
      if Options.Progress /= null then
         Options.Progress
           (Operation, Source_Path, Target_Path, Bytes_Done, Bytes_Total);
      end if;
   exception
      when others =>
         null;
   end Report_Progress;

   function Preserve_Remote_Attributes
     (Channel     : in out SSH_Lib.Channels.Channel;
      Remote_Path : String;
      Attributes  : File_Attributes;
      Options     : Recursive_Options) return CryptoLib.Errors.Status
   is
      Status_Value : CryptoLib.Errors.Status;
      Portable     : File_Attributes := Attributes;
   begin
      if not Options.Preserve_Attributes
        or else not Has_Attributes (Attributes)
      then
         return CryptoLib.Errors.Ok;
      end if;

      Status_Value := Set_Attributes (Channel, Remote_Path, Attributes);
      if Status_Value = CryptoLib.Errors.Ok
        or else Extended_Attribute_Count (Attributes) = 0
      then
         return Status_Value;
      end if;

      Clear_Extended_Attributes (Portable);
      if Has_Attributes (Portable) then
         return Set_Attributes (Channel, Remote_Path, Portable);
      else
         return Status_Value;
      end if;
   end Preserve_Remote_Attributes;

   function Remote_File_Unchanged
     (Channel     : in out SSH_Lib.Channels.Channel;
      Local_Path  : String;
      Remote_Path : String) return Boolean
   is
      Attributes   : File_Attributes;
      Status_Value : CryptoLib.Errors.Status;
   begin
      if Local_Path'Length = 0
        or else not Ada.Directories.Exists (Local_Path)
        or else
          Ada.Directories.Kind (Local_Path) /= Ada.Directories.Ordinary_File
      then
         return False;
      end if;

      Status_Value := LStat (Channel, Remote_Path, Attributes);
      return
        Status_Value = CryptoLib.Errors.Ok
        and then Attribute_Is_Regular (Attributes)
        and then Attributes.Size_Known
        and then
          Attributes.Size
          = Interfaces.Unsigned_64 (Ada.Directories.Size (Local_Path));
   exception
      when others =>
         return False;
   end Remote_File_Unchanged;

   function Local_File_Unchanged
     (Local_Path : String; Attributes : File_Attributes) return Boolean is
   begin
      return
        Local_Path'Length > 0
        and then Ada.Directories.Exists (Local_Path)
        and then
          Ada.Directories.Kind (Local_Path) = Ada.Directories.Ordinary_File
        and then Attribute_Is_Regular (Attributes)
        and then Attributes.Size_Known
        and then
          Attributes.Size
          = Interfaces.Unsigned_64 (Ada.Directories.Size (Local_Path));
   exception
      when others =>
         return False;
   end Local_File_Unchanged;

   function Upload_Directory
     (Channel        : in out SSH_Lib.Channels.Channel;
      Remote_Path    : String;
      Local_Path     : String;
      Directory_Mode : String := "0755";
      File_Mode      : String := "0644";
      Options        : Recursive_Options := Default_Recursive_Options)
      return CryptoLib.Errors.Status
   is
      Search       : Ada.Directories.Search_Type;
      Local_Item   : Ada.Directories.Directory_Entry_Type;
      Status_Value : CryptoLib.Errors.Status;
      Searching    : Boolean := False;
   begin
      if Validate_Upload_Target (Remote_Path, Directory_Mode)
        /= CryptoLib.Errors.Ok
        or else not Valid_Mode (File_Mode)
        or else Local_Path'Length = 0
        or else not Ada.Directories.Exists (Local_Path)
        or else Ada.Directories.Kind (Local_Path) /= Ada.Directories.Directory
      then
         return CryptoLib.Errors.Invalid_Command;
      end if;

      if not Should_Process (Options, Local_Path, Remote_Path, Tree_Directory)
      then
         return CryptoLib.Errors.Ok;
      end if;

      Status_Value :=
        Ensure_Remote_Directory (Channel, Remote_Path, Directory_Mode);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      Report_Progress (Options, Tree_Upload, Local_Path, Remote_Path, 0, 0);

      Ada.Directories.Start_Search
        (Search,
         Directory => Local_Path,
         Pattern   => "*",
         Filter    =>
           Ada.Directories.Filter_Type'
             (Ada.Directories.Ordinary_File => True,
              Ada.Directories.Directory     => True,
              Ada.Directories.Special_File  => False));
      Searching := True;

      while Ada.Directories.More_Entries (Search) loop
         Ada.Directories.Get_Next_Entry (Search, Local_Item);
         declare
            Name             : constant String :=
              Ada.Directories.Simple_Name (Local_Item);
            Local_Child_Path : constant String :=
              Ada.Directories.Compose (Local_Path, Name);
            Remote_Child     : constant String :=
              Remote_Child_Path (Remote_Path, Name);
         begin
            if Is_Dot_Entry (Name) then
               Status_Value := CryptoLib.Errors.Ok;
            elsif Ada.Directories.Kind (Local_Item) = Ada.Directories.Directory
            then
               Status_Value :=
                 Upload_Directory
                   (Channel,
                    Remote_Child,
                    Local_Child_Path,
                    Directory_Mode,
                    File_Mode,
                    Options);
            elsif Should_Process
                    (Options, Local_Child_Path, Remote_Child, Tree_File)
            then
               if Options.Skip_Unchanged
                 and then
                   Remote_File_Unchanged
                     (Channel, Local_Child_Path, Remote_Child)
               then
                  Status_Value := CryptoLib.Errors.Ok;
               else
                  Status_Value :=
                    Remote_Target_File_Allowed
                      (Channel, Remote_Child, Options);
                  if Status_Value = CryptoLib.Errors.Ok then
                     Status_Value :=
                       Upload_File
                         (Channel, Remote_Child, Local_Child_Path, File_Mode);
                  end if;
               end if;
               if Status_Value = CryptoLib.Errors.Ok then
                  if Options.Preserve_Attributes then
                     declare
                        Local_Metadata : File_Attributes;
                     begin
                        Capture_Local_Metadata
                          (Local_Child_Path, Local_Metadata);
                        Status_Value :=
                          Preserve_Remote_Attributes
                            (Channel, Remote_Child, Local_Metadata, Options);
                     exception
                        when others =>
                           Status_Value := CryptoLib.Errors.Ok;
                     end;
                  end if;
               end if;
               if Status_Value = CryptoLib.Errors.Ok then
                  Report_Progress
                    (Options,
                     Tree_Upload,
                     Local_Child_Path,
                     Remote_Child,
                     Interfaces.Unsigned_64
                       (Ada.Directories.Size (Local_Child_Path)),
                     Interfaces.Unsigned_64
                       (Ada.Directories.Size (Local_Child_Path)));
               else
                  Status_Value :=
                    Handle_Recursive_Status (Options, Status_Value);
               end if;
            else
               Status_Value := CryptoLib.Errors.Ok;
            end if;
            Status_Value := Handle_Recursive_Status (Options, Status_Value);
            if Status_Value /= CryptoLib.Errors.Ok then
               Ada.Directories.End_Search (Search);
               return Status_Value;
            end if;
         end;
      end loop;

      Ada.Directories.End_Search (Search);
      if Options.Preserve_Attributes then
         declare
            Local_Metadata : File_Attributes;
         begin
            Capture_Local_Metadata (Local_Path, Local_Metadata);
            return
              Preserve_Remote_Attributes
                (Channel, Remote_Path, Local_Metadata, Options);
         exception
            when others =>
               return CryptoLib.Errors.Ok;
         end;
      end if;
      return CryptoLib.Errors.Ok;
   exception
      when others =>
         if Searching then
            Ada.Directories.End_Search (Search);
         end if;
         return CryptoLib.Errors.Internal_Error;
   end Upload_Directory;

   function Download_Directory
     (Channel     : in out SSH_Lib.Channels.Channel;
      Remote_Path : String;
      Local_Path  : String;
      Options     : Recursive_Options := Default_Recursive_Options)
      return CryptoLib.Errors.Status
   is
      Entries      : Directory_Entry_Vectors.Vector;
      Status_Value : CryptoLib.Errors.Status;
   begin
      if not Safe_Remote_Path (Remote_Path) or else Local_Path'Length = 0 then
         return CryptoLib.Errors.Invalid_Command;
      end if;

      if not Should_Process (Options, Remote_Path, Local_Path, Tree_Directory)
      then
         return CryptoLib.Errors.Ok;
      end if;

      Ada.Directories.Create_Path (Local_Path);
      Report_Progress (Options, Tree_Download, Remote_Path, Local_Path, 0, 0);
      Status_Value := List_Directory (Channel, Remote_Path, Entries);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;

      for Directory_Item of Entries loop
         declare
            Name         : constant String := To_String (Directory_Item.Name);
            Remote_Child : constant String :=
              Remote_Child_Path (Remote_Path, Name);
            Local_Child  : constant String :=
              Ada.Directories.Compose (Local_Path, Name);
         begin
            if not Is_Dot_Entry (Name) then
               if Remote_Path_Is_Directory
                    (Channel, Remote_Child, Directory_Item.Attributes, Options)
               then
                  Status_Value :=
                    Download_Directory
                      (Channel, Remote_Child, Local_Child, Options);
               elsif Should_Process
                       (Options,
                        Remote_Child,
                        Local_Child,
                        Entry_Kind_For (Directory_Item.Attributes))
               then
                  if Options.Skip_Unchanged
                    and then
                      Local_File_Unchanged
                        (Local_Child, Directory_Item.Attributes)
                  then
                     Status_Value := CryptoLib.Errors.Ok;
                  else
                     Status_Value :=
                       Local_Target_File_Allowed (Local_Child, Options);
                     if Status_Value = CryptoLib.Errors.Ok then
                        Status_Value :=
                          Download_File (Channel, Remote_Child, Local_Child);
                     end if;
                  end if;
                  if Status_Value = CryptoLib.Errors.Ok then
                     if Options.Preserve_Attributes then
                        Restore_Local_Metadata
                          (Local_Child, Directory_Item.Attributes);
                     end if;
                     Report_Progress
                       (Options,
                        Tree_Download,
                        Remote_Child,
                        Local_Child,
                        Directory_Item.Attributes.Size,
                        Directory_Item.Attributes.Size);
                  else
                     Status_Value :=
                       Handle_Recursive_Status (Options, Status_Value);
                  end if;
               else
                  Status_Value := CryptoLib.Errors.Ok;
               end if;
               Status_Value := Handle_Recursive_Status (Options, Status_Value);
               if Status_Value /= CryptoLib.Errors.Ok then
                  return Status_Value;
               end if;
            end if;
         end;
      end loop;
      if Options.Preserve_Attributes then
         declare
            Root_Attributes : File_Attributes;
         begin
            Status_Value := LStat (Channel, Remote_Path, Root_Attributes);
            if Status_Value = CryptoLib.Errors.Ok then
               Restore_Local_Metadata (Local_Path, Root_Attributes);
            end if;
         exception
            when others =>
               null;
         end;
      end if;
      return CryptoLib.Errors.Ok;
   exception
      when others =>
         return CryptoLib.Errors.Internal_Error;
   end Download_Directory;

   function Remove_Tree
     (Channel     : in out SSH_Lib.Channels.Channel;
      Remote_Path : String;
      Options     : Recursive_Options := Default_Recursive_Options)
      return CryptoLib.Errors.Status
   is
      Attributes   : File_Attributes;
      Entries      : Directory_Entry_Vectors.Vector;
      Status_Value : CryptoLib.Errors.Status;
   begin
      if not Safe_Remote_Path (Remote_Path) then
         return CryptoLib.Errors.Invalid_Command;
      end if;

      Status_Value := LStat (Channel, Remote_Path, Attributes);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;

      if not Should_Process
               (Options, Remote_Path, "", Entry_Kind_For (Attributes))
      then
         return CryptoLib.Errors.Ok;
      end if;

      if Attribute_Is_Directory (Attributes) then
         Status_Value := List_Directory (Channel, Remote_Path, Entries);
         if Status_Value /= CryptoLib.Errors.Ok then
            return Status_Value;
         end if;

         for Directory_Item of Entries loop
            declare
               Name : constant String := To_String (Directory_Item.Name);
            begin
               if not Is_Dot_Entry (Name) then
                  Status_Value :=
                    Remove_Tree
                      (Channel,
                       Remote_Child_Path (Remote_Path, Name),
                       Options);
                  Status_Value :=
                    Handle_Recursive_Status (Options, Status_Value);
                  Status_Value :=
                    Handle_Recursive_Status (Options, Status_Value);
                  if Status_Value /= CryptoLib.Errors.Ok then
                     return Status_Value;
                  end if;
               end if;
            end;
         end loop;
         Status_Value := Remove_Directory (Channel, Remote_Path);
         if Status_Value = CryptoLib.Errors.Ok then
            Report_Progress (Options, Tree_Remove, Remote_Path, "", 0, 0);
         end if;
         return Status_Value;
      else
         Status_Value := Remove_File (Channel, Remote_Path);
         if Status_Value = CryptoLib.Errors.Ok then
            Report_Progress
              (Options,
               Tree_Remove,
               Remote_Path,
               "",
               Attributes.Size,
               Attributes.Size);
         end if;
         return Status_Value;
      end if;
   exception
      when others =>
         return CryptoLib.Errors.Internal_Error;
   end Remove_Tree;

   function Copy_Tree
     (Channel            : in out SSH_Lib.Channels.Channel;
      Source_Remote_Path : String;
      Target_Remote_Path : String;
      Directory_Mode     : String := "0755";
      File_Mode          : String := "0644";
      Options            : Recursive_Options := Default_Recursive_Options)
      return CryptoLib.Errors.Status
   is
      Source_Attributes : File_Attributes;
      Entries           : Directory_Entry_Vectors.Vector;
      Data              : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Status_Value      : CryptoLib.Errors.Status;
   begin
      if not Safe_Remote_Path (Source_Remote_Path)
        or else
          Validate_Upload_Target (Target_Remote_Path, Directory_Mode)
          /= CryptoLib.Errors.Ok
        or else not Valid_Mode (File_Mode)
      then
         return CryptoLib.Errors.Invalid_Command;
      end if;

      Status_Value := LStat (Channel, Source_Remote_Path, Source_Attributes);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;

      if not Should_Process
               (Options,
                Source_Remote_Path,
                Target_Remote_Path,
                Entry_Kind_For (Source_Attributes))
      then
         return CryptoLib.Errors.Ok;
      end if;

      if Attribute_Is_Directory (Source_Attributes) then
         Status_Value :=
           Ensure_Remote_Directory
             (Channel, Target_Remote_Path, Directory_Mode);
         if Status_Value /= CryptoLib.Errors.Ok then
            return Status_Value;
         end if;

         Status_Value := List_Directory (Channel, Source_Remote_Path, Entries);
         if Status_Value /= CryptoLib.Errors.Ok then
            return Status_Value;
         end if;

         for Directory_Item of Entries loop
            declare
               Name : constant String := To_String (Directory_Item.Name);
            begin
               if not Is_Dot_Entry (Name) then
                  Status_Value :=
                    Copy_Tree
                      (Channel,
                       Remote_Child_Path (Source_Remote_Path, Name),
                       Remote_Child_Path (Target_Remote_Path, Name),
                       Directory_Mode,
                       File_Mode,
                       Options);
                  if Status_Value /= CryptoLib.Errors.Ok then
                     return Status_Value;
                  end if;
               end if;
            end;
         end loop;
         return
           Preserve_Remote_Attributes
             (Channel, Target_Remote_Path, Source_Attributes, Options);
      else
         Status_Value :=
           Remote_Target_File_Allowed (Channel, Target_Remote_Path, Options);
         if Status_Value /= CryptoLib.Errors.Ok then
            return Handle_Recursive_Status (Options, Status_Value);
         end if;
         Status_Value := Download_Data (Channel, Source_Remote_Path, Data);
         if Status_Value /= CryptoLib.Errors.Ok then
            return Handle_Recursive_Status (Options, Status_Value);
         end if;
         Status_Value :=
           Upload_Data
             (Channel,
              Target_Remote_Path,
              SSH_Lib.Protocol.Buffers.To_Array (Data),
              File_Mode);
         if Status_Value /= CryptoLib.Errors.Ok then
            return Handle_Recursive_Status (Options, Status_Value);
         end if;
         Status_Value :=
           Preserve_Remote_Attributes
             (Channel, Target_Remote_Path, Source_Attributes, Options);
         if Status_Value = CryptoLib.Errors.Ok then
            Report_Progress
              (Options,
               Tree_Copy,
               Source_Remote_Path,
               Target_Remote_Path,
               Source_Attributes.Size,
               Source_Attributes.Size);
         end if;
         return Status_Value;
      end if;
   exception
      when others =>
         return CryptoLib.Errors.Internal_Error;
   end Copy_Tree;

   function Sync_Directory
     (Channel        : in out SSH_Lib.Channels.Channel;
      Direction      : Sync_Direction;
      Remote_Path    : String;
      Local_Path     : String;
      Directory_Mode : String := "0755";
      File_Mode      : String := "0644";
      Options        : Sync_Options := Default_Sync_Options)
      return CryptoLib.Errors.Status
   is
      Status_Value        : CryptoLib.Errors.Status;
      Effective_Recursive : Recursive_Options := Options.Recursive;
   begin
      if not Safe_Remote_Path (Remote_Path)
        or else Local_Path'Length = 0
        or else not Valid_Mode (Directory_Mode)
        or else not Valid_Mode (File_Mode)
      then
         return CryptoLib.Errors.Invalid_Command;
      end if;

      if Options.Skip_Unchanged then
         Effective_Recursive.Skip_Unchanged := True;
      end if;

      if Direction = Sync_Upload then
         if Options.Delete_Extra then
            Status_Value :=
              Remove_Tree (Channel, Remote_Path, Effective_Recursive);
            if Status_Value /= CryptoLib.Errors.Ok
              and then Status_Value /= CryptoLib.Errors.No_Such_File
            then
               return Status_Value;
            end if;
         end if;
         Status_Value :=
           Upload_Directory
             (Channel,
              Remote_Path,
              Local_Path,
              Directory_Mode,
              File_Mode,
              Effective_Recursive);
      else
         if Options.Delete_Extra and then Ada.Directories.Exists (Local_Path)
         then
            Ada.Directories.Delete_Tree (Local_Path);
         end if;
         Status_Value :=
           Download_Directory
             (Channel, Remote_Path, Local_Path, Effective_Recursive);
      end if;

      if Status_Value = CryptoLib.Errors.Ok then
         Report_Progress
           (Effective_Recursive, Tree_Sync, Remote_Path, Local_Path, 0, 0);
      end if;
      return Status_Value;
   exception
      when others =>
         return CryptoLib.Errors.Internal_Error;
   end Sync_Directory;

   function Rename
     (Channel  : in out SSH_Lib.Channels.Channel;
      Old_Path : String;
      New_Path : String) return CryptoLib.Errors.Status is
   begin
      if not Safe_Remote_Path (Old_Path)
        or else not Safe_Remote_Path (New_Path)
      then
         return CryptoLib.Errors.Invalid_Command;
      end if;
      return
        Simple_Status_Request
          (Channel,
           Encode_Two_Path_Request (SSH_FXP_RENAME, 1, Old_Path, New_Path));
   end Rename;

   function Rename
     (Channel  : in out SSH_Lib.Channels.Channel;
      Old_Path : String;
      New_Path : String;
      Result   : out SFTP_Result) return CryptoLib.Errors.Status
   is
      Status_Value : constant CryptoLib.Errors.Status :=
        Rename (Channel, Old_Path, New_Path);
   begin
      Capture_Result (Status_Value, Result, Rename_Operation);
      return Status_Value;
   end Rename;

   function Posix_Rename
     (Channel  : in out SSH_Lib.Channels.Channel;
      Old_Path : String;
      New_Path : String) return CryptoLib.Errors.Status is
   begin
      if not Safe_Remote_Path (Old_Path)
        or else not Safe_Remote_Path (New_Path)
      then
         return CryptoLib.Errors.Invalid_Command;
      end if;
      return
        Simple_Status_Request
          (Channel,
           Encode_Extended_Two_Path_Request
             (1, Posix_Rename_Extension, Old_Path, New_Path));
   end Posix_Rename;

   function Posix_Rename
     (Channel  : in out SSH_Lib.Channels.Channel;
      Old_Path : String;
      New_Path : String;
      Result   : out SFTP_Result) return CryptoLib.Errors.Status
   is
      Status_Value : constant CryptoLib.Errors.Status :=
        Posix_Rename (Channel, Old_Path, New_Path);
   begin
      Capture_Result (Status_Value, Result, Rename_Operation);
      return Status_Value;
   end Posix_Rename;

   function Posix_Rename
     (Session  : in out SSH_Lib.Sessions.Session;
      Old_Path : String;
      New_Path : String;
      Result   : out SFTP_Result) return CryptoLib.Errors.Status
   is
      Status_Value : constant CryptoLib.Errors.Status :=
        Posix_Rename (Session, Old_Path, New_Path);
   begin
      Capture_Result (Status_Value, Result, Rename_Operation);
      return Status_Value;
   end Posix_Rename;

   function Hardlink
     (Channel  : in out SSH_Lib.Channels.Channel;
      Old_Path : String;
      New_Path : String) return CryptoLib.Errors.Status is
   begin
      if not Safe_Remote_Path (Old_Path)
        or else not Safe_Remote_Path (New_Path)
      then
         return CryptoLib.Errors.Invalid_Command;
      end if;
      return
        Simple_Status_Request
          (Channel,
           Encode_Extended_Two_Path_Request
             (1, Hardlink_Extension, Old_Path, New_Path));
   end Hardlink;

   function Fsync
     (Channel : in out SSH_Lib.Channels.Channel; Handle : File_Handle)
      return CryptoLib.Errors.Status is
   begin
      if not Is_Open (Handle) then
         return CryptoLib.Errors.Invalid_Command;
      elsif Handle.Context_Known and then not Handle.Extensions.Fsync then
         return CryptoLib.Errors.Unsupported_Feature;
      end if;
      return
        Simple_Status_Request
          (Channel,
           Encode_Extended_Handle_Request (1, Fsync_Extension, Handle.Data));
   end Fsync;

   function Check_File
     (Channel    : in out SSH_Lib.Channels.Channel;
      Handle     : File_Handle;
      Algorithms : String;
      Offset     : Interfaces.Unsigned_64;
      Length     : Interfaces.Unsigned_64;
      Block_Size : Interfaces.Unsigned_32;
      Algorithm  : out Unbounded_String;
      Digest     : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status
   is
      Reply_Packet : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Status_Value : CryptoLib.Errors.Status;
   begin
      Algorithm := Null_Unbounded_String;
      SSH_Lib.Protocol.Buffers.Clear (Digest);
      if not Is_Open (Handle) or else Algorithms'Length = 0 then
         return CryptoLib.Errors.Invalid_Command;
      end if;
      Status_Value :=
        Send_Packet
          (Channel,
           Encode_Check_File_Request
             (1, Handle.Data, Algorithms, Offset, Length, Block_Size));
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      Status_Value := Read_Packet (Channel, Reply_Packet);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      return Parse_Check_File_Packet (Reply_Packet, 1, Algorithm, Digest);
   exception
      when others =>
         Algorithm := Null_Unbounded_String;
         SSH_Lib.Protocol.Buffers.Clear (Digest);
         return CryptoLib.Errors.Internal_Error;
   end Check_File;

   function Check_File_Info
     (Channel    : in out SSH_Lib.Channels.Channel;
      Handle     : File_Handle;
      Algorithms : String;
      Offset     : Interfaces.Unsigned_64 := 0;
      Length     : Interfaces.Unsigned_64 := 0;
      Block_Size : Interfaces.Unsigned_32 := 0) return Check_File_Result
   is
      Info         : Check_File_Result;
      Status_Value : CryptoLib.Errors.Status;
   begin
      Status_Value :=
        Check_File
          (Channel,
           Handle,
           Algorithms,
           Offset,
           Length,
           Block_Size,
           Info.Algorithm,
           Info.Digest);
      Capture_Result (Status_Value, Info.Result, Check_File_Operation);
      return Info;
   exception
      when others =>
         SSH_Lib.Protocol.Buffers.Clear (Info.Digest);
         Info.Algorithm := Null_Unbounded_String;
         Capture_Result
           (CryptoLib.Errors.Internal_Error, Info.Result, Check_File_Operation);
         return Info;
   end Check_File_Info;

   function Copy_Data
     (Channel       : in out SSH_Lib.Channels.Channel;
      Source_Handle : File_Handle;
      Source_Offset : Interfaces.Unsigned_64;
      Length        : Interfaces.Unsigned_64;
      Target_Handle : File_Handle;
      Target_Offset : Interfaces.Unsigned_64) return CryptoLib.Errors.Status is
   begin
      if not Is_Open (Source_Handle)
        or else not Is_Open (Target_Handle)
        or else Length = 0
      then
         return CryptoLib.Errors.Invalid_Command;
      end if;
      return
        Simple_Status_Request
          (Channel,
           Encode_Copy_Data_Request
             (1,
              Source_Handle.Data,
              Source_Offset,
              Length,
              Target_Handle.Data,
              Target_Offset));
   end Copy_Data;

   function Expand_Path
     (Channel       : in out SSH_Lib.Channels.Channel;
      Remote_Path   : String;
      Expanded_Path : out Unbounded_String) return CryptoLib.Errors.Status
   is
      Reply_Packet : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Status_Value : CryptoLib.Errors.Status;
   begin
      Expanded_Path := Null_Unbounded_String;
      if not Safe_Remote_Path (Remote_Path) then
         return CryptoLib.Errors.Invalid_Command;
      end if;
      Status_Value :=
        Send_Packet
          (Channel,
           Encode_Extended_Path_Request
             (1, Expand_Path_Extension, Remote_Path));
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      Status_Value := Read_Packet (Channel, Reply_Packet);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      return Parse_Name_Packet (Reply_Packet, 1, Expanded_Path);
   exception
      when others =>
         Expanded_Path := Null_Unbounded_String;
         return CryptoLib.Errors.Internal_Error;
   end Expand_Path;

   function LSet_Attributes
     (Channel     : in out SSH_Lib.Channels.Channel;
      Remote_Path : String;
      Attributes  : File_Attributes) return CryptoLib.Errors.Status is
   begin
      if not Safe_Remote_Path (Remote_Path)
        or else not Has_Attributes (Attributes)
      then
         return CryptoLib.Errors.Invalid_Command;
      end if;
      return
        Simple_Status_Request
          (Channel,
           Encode_Extended_Set_Attributes_Request
             (1, LSetStat_Extension, Remote_Path, Attributes));
   end LSet_Attributes;

   function StatVFS
     (Channel     : in out SSH_Lib.Channels.Channel;
      Remote_Path : String;
      Stats       : out File_System_Stats) return CryptoLib.Errors.Status
   is
      Reply_Packet : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Status_Value : CryptoLib.Errors.Status;
   begin
      Stats := (others => 0);
      if not Safe_Remote_Path (Remote_Path) then
         return CryptoLib.Errors.Invalid_Command;
      end if;
      Status_Value :=
        Send_Packet
          (Channel,
           Encode_Extended_Path_Request (1, StatVFS_Extension, Remote_Path));
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      Status_Value := Read_Packet (Channel, Reply_Packet);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      return Parse_StatVFS_Packet (Reply_Packet, 1, Stats);
   exception
      when others =>
         Stats := (others => 0);
         return CryptoLib.Errors.Internal_Error;
   end StatVFS;

   function StatVFS
     (Channel     : in out SSH_Lib.Channels.Channel;
      Remote_Path : String;
      Stats       : out File_System_Stats;
      Result      : out SFTP_Result) return CryptoLib.Errors.Status
   is
      Status_Value : constant CryptoLib.Errors.Status :=
        StatVFS (Channel, Remote_Path, Stats);
   begin
      Capture_Result (Status_Value, Result, StatVFS_Operation);
      return Status_Value;
   end StatVFS;

   function Limits
     (Channel : in out SSH_Lib.Channels.Channel; Values : out Server_Limits)
      return CryptoLib.Errors.Status
   is
      Reply_Packet : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Status_Value : CryptoLib.Errors.Status;
   begin
      Values := (others => 0);
      Status_Value :=
        Send_Packet
          (Channel, Encode_Extended_Name_Request (1, Limits_Extension));
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      Status_Value := Read_Packet (Channel, Reply_Packet);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      return Parse_Limits_Packet (Reply_Packet, 1, Values);
   exception
      when others =>
         Values := (others => 0);
         return CryptoLib.Errors.Internal_Error;
   end Limits;

   function Limits
     (Channel : in out SSH_Lib.Channels.Channel;
      Values  : out Server_Limits;
      Result  : out SFTP_Result) return CryptoLib.Errors.Status
   is
      Status_Value : constant CryptoLib.Errors.Status :=
        Limits (Channel, Values);
   begin
      Capture_Result (Status_Value, Result, Limits_Operation);
      return Status_Value;
   end Limits;

   function Limits
     (Session : in out SSH_Lib.Sessions.Session;
      Values  : out Server_Limits;
      Result  : out SFTP_Result) return CryptoLib.Errors.Status
   is
      Status_Value : constant CryptoLib.Errors.Status :=
        Limits (Session, Values);
   begin
      Capture_Result (Status_Value, Result, Limits_Operation);
      return Status_Value;
   end Limits;

   function Limits_Info
     (Channel : in out SSH_Lib.Channels.Channel) return Limits_Result
   is
      Info         : Limits_Result;
      Status_Value : CryptoLib.Errors.Status;
   begin
      Status_Value := Limits (Channel, Info.Values, Info.Result);
      if Info.Result.Status /= Status_Value then
         Capture_Result (Status_Value, Info.Result, Limits_Operation);
      end if;
      return Info;
   exception
      when others =>
         Info.Values := (others => 0);
         Capture_Result
           (CryptoLib.Errors.Internal_Error, Info.Result, Limits_Operation);
         return Info;
   end Limits_Info;

   function Limits_Info
     (Session : in out SSH_Lib.Sessions.Session) return Limits_Result
   is
      Info         : Limits_Result;
      Status_Value : CryptoLib.Errors.Status;
   begin
      Status_Value := Limits (Session, Info.Values, Info.Result);
      if Info.Result.Status /= Status_Value then
         Capture_Result (Status_Value, Info.Result, Limits_Operation);
      end if;
      return Info;
   exception
      when others =>
         Info.Values := (others => 0);
         Capture_Result
           (CryptoLib.Errors.Internal_Error, Info.Result, Limits_Operation);
         return Info;
   end Limits_Info;

   function Extended_Request
     (Channel        : in out SSH_Lib.Channels.Channel;
      Extension_Name : String;
      Payload        : Stream_Element_Array;
      Reply_Data     : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status
   is
      Reply_Packet : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Status_Value : CryptoLib.Errors.Status;
   begin
      SSH_Lib.Protocol.Buffers.Clear (Reply_Data);
      if Extension_Name'Length = 0 then
         return CryptoLib.Errors.Invalid_Command;
      end if;

      Status_Value :=
        Send_Packet
          (Channel, Encode_Extended_Raw_Request (1, Extension_Name, Payload));
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      Status_Value := Read_Packet (Channel, Reply_Packet);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      return Parse_Extended_Reply_Packet (Reply_Packet, 1, Reply_Data);
   exception
      when others =>
         SSH_Lib.Protocol.Buffers.Clear (Reply_Data);
         return CryptoLib.Errors.Internal_Error;
   end Extended_Request;

   function Read_Link
     (Channel     : in out SSH_Lib.Channels.Channel;
      Remote_Path : String;
      Target_Path : out Unbounded_String) return CryptoLib.Errors.Status
   is
      Reply_Packet : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Status_Value : CryptoLib.Errors.Status;
   begin
      Target_Path := Null_Unbounded_String;
      if not Safe_Remote_Path (Remote_Path) then
         return CryptoLib.Errors.Invalid_Command;
      end if;
      Status_Value :=
        Send_Packet
          (Channel, Encode_Path_Request (SSH_FXP_READLINK, 1, Remote_Path));
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      Status_Value := Read_Packet (Channel, Reply_Packet);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      return Parse_Name_Packet (Reply_Packet, 1, Target_Path);
   exception
      when others =>
         Target_Path := Null_Unbounded_String;
         return CryptoLib.Errors.Internal_Error;
   end Read_Link;

   function Create_Symlink
     (Channel     : in out SSH_Lib.Channels.Channel;
      Target_Path : String;
      Link_Path   : String) return CryptoLib.Errors.Status is
   begin
      if not Safe_Remote_Path (Target_Path)
        or else not Safe_Remote_Path (Link_Path)
      then
         return CryptoLib.Errors.Invalid_Command;
      end if;
      return
        Simple_Status_Request
          (Channel,
           Encode_Two_Path_Request
             (SSH_FXP_SYMLINK, 1, Target_Path, Link_Path));
   end Create_Symlink;

   function Create_Link
     (Channel  : in out SSH_Lib.Channels.Channel;
      New_Link : String;
      Existing : String;
      Symbolic : Boolean := True) return CryptoLib.Errors.Status is
   begin
      if not Safe_Remote_Path (New_Link)
        or else not Safe_Remote_Path (Existing)
      then
         return CryptoLib.Errors.Invalid_Command;
      end if;
      return
        Simple_Status_Request
          (Channel, Encode_Link_Request (1, New_Link, Existing, Symbolic));
   end Create_Link;

   function Text_Seek
     (Channel     : in out SSH_Lib.Channels.Channel;
      Handle      : File_Handle;
      Line_Number : Interfaces.Unsigned_64) return CryptoLib.Errors.Status is
   begin
      if not Is_Open (Handle) then
         return CryptoLib.Errors.Invalid_Command;
      elsif Handle.Context_Known and then not Handle.Extensions.Text_Seek then
         return CryptoLib.Errors.Unsupported_Feature;
      end if;
      return
        Simple_Status_Request
          (Channel, Encode_Text_Seek_Request (1, Handle.Data, Line_Number));
   end Text_Seek;

   function Lock_Range
     (Channel   : in out SSH_Lib.Channels.Channel;
      Handle    : File_Handle;
      Offset    : Interfaces.Unsigned_64;
      Length    : Interfaces.Unsigned_64;
      Lock_Mask : Interfaces.Unsigned_32) return CryptoLib.Errors.Status is
   begin
      if not Is_Open (Handle) or else Length = 0 then
         return CryptoLib.Errors.Invalid_Command;
      elsif Handle.Context_Known
        and then not Supports_Block_Mask (Handle.Extensions, Lock_Mask)
      then
         return CryptoLib.Errors.Unsupported_Feature;
      end if;
      return
        Simple_Status_Request
          (Channel,
           Encode_Block_Request
             (1, SSH_FXP_BLOCK, Handle.Data, Offset, Length, Lock_Mask));
   end Lock_Range;

   function Unlock_Range
     (Channel : in out SSH_Lib.Channels.Channel;
      Handle  : File_Handle;
      Offset  : Interfaces.Unsigned_64;
      Length  : Interfaces.Unsigned_64) return CryptoLib.Errors.Status is
   begin
      if not Is_Open (Handle) or else Length = 0 then
         return CryptoLib.Errors.Invalid_Command;
      end if;
      return
        Simple_Status_Request
          (Channel,
           Encode_Block_Request
             (1, SSH_FXP_UNBLOCK, Handle.Data, Offset, Length));
   end Unlock_Range;

   function Version_Select
     (Item : in out Client; Requested_Version : Natural)
      return CryptoLib.Errors.Status
   is
      Status_Value : CryptoLib.Errors.Status;
   begin
      if not Item.Opened then
         return CryptoLib.Errors.Channel_Open_Failed;
      elsif not Supports_Protocol_Version (Requested_Version) then
         return CryptoLib.Errors.Unsupported_Feature;
      elsif not Item.Extensions.Versions
        or else
          not Advertises_Protocol_Version (Item.Extensions, Requested_Version)
      then
         return CryptoLib.Errors.Unsupported_Feature;
      end if;

      Status_Value :=
        Simple_Status_Request
          (Item.Channel, Encode_Version_Select_Request (1, Requested_Version));
      if Status_Value = CryptoLib.Errors.Ok then
         Item.Version := Requested_Version;
      end if;
      return Status_Value;
   exception
      when others =>
         return CryptoLib.Errors.Internal_Error;
   end Version_Select;

   function Create_Link
     (Item     : in out Client;
      New_Link : String;
      Existing : String;
      Symbolic : Boolean := True) return CryptoLib.Errors.Status is
   begin
      if not Item.Opened then
         return CryptoLib.Errors.Channel_Open_Failed;
      elsif Item.Version < 6 then
         return CryptoLib.Errors.Unsupported_Feature;
      end if;
      return Create_Link (Item.Channel, New_Link, Existing, Symbolic);
   exception
      when others =>
         return CryptoLib.Errors.Internal_Error;
   end Create_Link;

   function Text_Seek
     (Item        : in out Client;
      Remote_Path : String;
      Line_Number : Interfaces.Unsigned_64) return CryptoLib.Errors.Status
   is
      Handle       : File_Handle;
      Status_Value : CryptoLib.Errors.Status;
      Close_Status : CryptoLib.Errors.Status;
      pragma Unreferenced (Close_Status);
   begin
      if not Item.Opened then
         return CryptoLib.Errors.Channel_Open_Failed;
      elsif not Item.Extensions.Text_Seek
        or else not Supports_Open_Mode (Item.Extensions, Read_Only)
      then
         return CryptoLib.Errors.Unsupported_Feature;
      end if;
      Status_Value :=
        Open_Read (Item.Channel, Remote_Path, Handle, Item.Version);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      Status_Value := Text_Seek (Item.Channel, Handle, Line_Number);
      Close_Status := Close (Item.Channel, Handle);
      return Status_Value;
   exception
      when others =>
         return CryptoLib.Errors.Internal_Error;
   end Text_Seek;

   function Lock_Range
     (Item        : in out Client;
      Remote_Path : String;
      Offset      : Interfaces.Unsigned_64;
      Length      : Interfaces.Unsigned_64;
      Lock_Mask   : Interfaces.Unsigned_32) return CryptoLib.Errors.Status
   is
      Handle       : File_Handle;
      Status_Value : CryptoLib.Errors.Status;
      Close_Status : CryptoLib.Errors.Status;
      pragma Unreferenced (Close_Status);
   begin
      if not Item.Opened then
         return CryptoLib.Errors.Channel_Open_Failed;
      elsif Item.Version < 6
        or else not Supports_Block_Mask (Item.Extensions, Lock_Mask)
        or else not Supports_Open_Mode (Item.Extensions, Read_Write)
      then
         return CryptoLib.Errors.Unsupported_Feature;
      end if;
      Status_Value :=
        Open_File
          (Item.Channel,
           Remote_Path,
           Handle,
           Read_Write,
           "0644",
           Item.Version);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      Set_Handle_Context (Handle, Item.Version, Item.Extensions);
      Status_Value :=
        Lock_Range (Item.Channel, Handle, Offset, Length, Lock_Mask);
      Close_Status := Close (Item.Channel, Handle);
      return Status_Value;
   exception
      when others =>
         return CryptoLib.Errors.Internal_Error;
   end Lock_Range;

   function Unlock_Range
     (Item        : in out Client;
      Remote_Path : String;
      Offset      : Interfaces.Unsigned_64;
      Length      : Interfaces.Unsigned_64) return CryptoLib.Errors.Status
   is
      Handle       : File_Handle;
      Status_Value : CryptoLib.Errors.Status;
      Close_Status : CryptoLib.Errors.Status;
      pragma Unreferenced (Close_Status);
   begin
      if not Item.Opened then
         return CryptoLib.Errors.Channel_Open_Failed;
      elsif Item.Version < 6
        or else not Supports_Open_Mode (Item.Extensions, Read_Write)
      then
         return CryptoLib.Errors.Unsupported_Feature;
      end if;
      Status_Value :=
        Open_File
          (Item.Channel,
           Remote_Path,
           Handle,
           Read_Write,
           "0644",
           Item.Version);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      Set_Handle_Context (Handle, Item.Version, Item.Extensions);
      Status_Value := Unlock_Range (Item.Channel, Handle, Offset, Length);
      Close_Status := Close (Item.Channel, Handle);
      return Status_Value;
   exception
      when others =>
         return CryptoLib.Errors.Internal_Error;
   end Unlock_Range;

   function Upload_Data
     (Channel     : in out SSH_Lib.Channels.Channel;
      Remote_Path : String;
      Data        : Ada.Streams.Stream_Element_Array;
      Mode        : String := "0644";
      Options     : Transfer_Options := Default_Transfer_Options)
      return CryptoLib.Errors.Status
   is
      Handle        : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Target_Path   : Unbounded_String := To_Unbounded_String (Remote_Path);
      Request_Id    : Interfaces.Unsigned_32 := 2;
      Status_Value  : CryptoLib.Errors.Status;
      Remote_Opened : Boolean := False;
   begin
      if Options.Atomic_Upload then
         declare
            Temp_Path : constant String := Remote_Temporary_Path (Remote_Path);
         begin
            if Temp_Path'Length = 0 then
               return CryptoLib.Errors.Invalid_Command;
            end if;
            Target_Path := To_Unbounded_String (Temp_Path);
            Status_Value := Remove_File (Channel, Temp_Path);
         end;
      end if;

      Status_Value :=
        Open_Remote_File (Channel, To_String (Target_Path), Mode, Handle);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      Remote_Opened := True;

      Status_Value :=
        Pipelined_Write_Buffer
          (Channel,
           Handle,
           0,
           Data,
           2,
           Effective_Pipeline_Depth (Options),
           Request_Id,
           Effective_Write_Chunk_Size (Options));
      if Status_Value /= CryptoLib.Errors.Ok then
         Close_Remote_File_Best_Effort (Channel, Handle, Request_Id);
         return Status_Value;
      end if;

      Status_Value := Close_Remote_File (Channel, Handle, Request_Id);
      Remote_Opened := False;
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      if Options.Verify_After_Transfer then
         Status_Value :=
           Verify_Remote_Size
             (Channel,
              To_String (Target_Path),
              Interfaces.Unsigned_64 (Data'Length));
         if Status_Value /= CryptoLib.Errors.Ok then
            return Status_Value;
         end if;
      end if;
      if Options.Atomic_Upload then
         Status_Value :=
           Rename (Channel, To_String (Target_Path), Remote_Path);
         if Status_Value /= CryptoLib.Errors.Ok then
            return Status_Value;
         end if;
         if Options.Verify_After_Transfer then
            return
              Verify_Remote_Size
                (Channel, Remote_Path, Interfaces.Unsigned_64 (Data'Length));
         end if;
      end if;
      return CryptoLib.Errors.Ok;
   exception
      when others =>
         if Remote_Opened then
            Close_Remote_File_Best_Effort (Channel, Handle, Request_Id);
         end if;
         return CryptoLib.Errors.Internal_Error;
   end Upload_Data;

   function Upload_Data
     (Channel     : in out SSH_Lib.Channels.Channel;
      Remote_Path : String;
      Offset      : Interfaces.Unsigned_64;
      Data        : Ada.Streams.Stream_Element_Array;
      Mode        : String := "0644";
      Options     : Transfer_Options := Default_Transfer_Options)
      return CryptoLib.Errors.Status
   is
      Handle        : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Request_Id    : Interfaces.Unsigned_32 := 2;
      Status_Value  : CryptoLib.Errors.Status;
      Remote_Opened : Boolean := False;
   begin
      Status_Value :=
        Open_Remote_File_Mode
          (Channel, Remote_Path, Write_No_Truncate, Mode, Handle);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      Remote_Opened := True;

      Status_Value :=
        Pipelined_Write_Buffer
          (Channel,
           Handle,
           Offset,
           Data,
           2,
           Effective_Pipeline_Depth (Options),
           Request_Id,
           Effective_Write_Chunk_Size (Options));
      if Status_Value /= CryptoLib.Errors.Ok then
         Close_Remote_File_Best_Effort (Channel, Handle, Request_Id);
         return Status_Value;
      end if;

      Status_Value := Close_Remote_File (Channel, Handle, Request_Id);
      Remote_Opened := False;
      return Status_Value;
   exception
      when others =>
         if Remote_Opened then
            Close_Remote_File_Best_Effort (Channel, Handle, Request_Id);
         end if;
         return CryptoLib.Errors.Internal_Error;
   end Upload_Data;

   function Upload_File
     (Channel     : in out SSH_Lib.Channels.Channel;
      Remote_Path : String;
      Local_Path  : String;
      Mode        : String := "0644";
      Options     : Transfer_Options := Default_Transfer_Options)
      return CryptoLib.Errors.Status
   is
      Handle        : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      File_Item     : Ada.Streams.Stream_IO.File_Type;
      Target_Path   : Unbounded_String := To_Unbounded_String (Remote_Path);
      Size_Value    : Natural := 0;
      Request_Id    : Interfaces.Unsigned_32 := 2;
      Status_Value  : CryptoLib.Errors.Status;
      Remote_Opened : Boolean := False;
   begin
      Status_Value := Validate_Upload_Target (Remote_Path, Mode);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;

      Status_Value := Local_File_Ready (Local_Path, Size_Value);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;

      if Options.Atomic_Upload then
         declare
            Temp_Path : constant String := Remote_Temporary_Path (Remote_Path);
         begin
            if Temp_Path'Length = 0 then
               return CryptoLib.Errors.Invalid_Command;
            end if;
            Target_Path := To_Unbounded_String (Temp_Path);
            Status_Value := Remove_File (Channel, Temp_Path);
         end;
      end if;

      Status_Value :=
        Open_Remote_File (Channel, To_String (Target_Path), Mode, Handle);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      Remote_Opened := True;

      Ada.Streams.Stream_IO.Open
        (File_Item, Ada.Streams.Stream_IO.In_File, Local_Path);
      Status_Value :=
        Pipelined_Write_File
          (Channel,
           Handle,
           File_Item,
           Size_Value,
           2,
           Effective_Pipeline_Depth (Options),
           Request_Id,
           Effective_Write_Chunk_Size (Options));
      Ada.Streams.Stream_IO.Close (File_Item);
      if Status_Value /= CryptoLib.Errors.Ok then
         Close_Remote_File_Best_Effort (Channel, Handle, Request_Id);
         return Status_Value;
      end if;

      Status_Value := Close_Remote_File (Channel, Handle, Request_Id);
      Remote_Opened := False;
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      if Options.Verify_After_Transfer then
         Status_Value :=
           Verify_Remote_Size
             (Channel,
              To_String (Target_Path),
              Interfaces.Unsigned_64 (Size_Value));
         if Status_Value /= CryptoLib.Errors.Ok then
            return Status_Value;
         end if;
      end if;
      if Options.Atomic_Upload then
         Status_Value :=
           Rename (Channel, To_String (Target_Path), Remote_Path);
         if Status_Value /= CryptoLib.Errors.Ok then
            return Status_Value;
         end if;
         if Options.Verify_After_Transfer then
            return
              Verify_Remote_Size
                (Channel, Remote_Path, Interfaces.Unsigned_64 (Size_Value));
         end if;
      end if;
      return CryptoLib.Errors.Ok;
   exception
      when others =>
         if Ada.Streams.Stream_IO.Is_Open (File_Item) then
            Ada.Streams.Stream_IO.Close (File_Item);
         end if;
         if Remote_Opened then
            Close_Remote_File_Best_Effort (Channel, Handle, Request_Id);
         end if;
         return CryptoLib.Errors.Internal_Error;
   end Upload_File;

   function Open
     (Session           : in out SSH_Lib.Sessions.Session;
      Channel           : in out SSH_Lib.Channels.Channel;
      Requested_Version : Natural;
      Version           : out Natural;
      Extensions        : out Extension_Info) return CryptoLib.Errors.Status
   is
      Status_Value : CryptoLib.Errors.Status;
      Close_Status : CryptoLib.Errors.Status;
      Opened       : Boolean := False;
      pragma Unreferenced (Close_Status);
   begin
      Version := 0;
      Extensions := (others => <>);
      Status_Value :=
        SSH_Lib.Channels.Open_Subsystem (Session, "sftp", Channel);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      Opened := True;

      Status_Value :=
        Initialize (Channel, Requested_Version, Version, Extensions);
      if Status_Value /= CryptoLib.Errors.Ok then
         Close_Status := SSH_Lib.Channels.Close (Channel);
         Opened := False;
      end if;
      return Status_Value;
   exception
      when others =>
         if Opened then
            Close_Status := SSH_Lib.Channels.Close (Channel);
         end if;
         Version := 0;
         Extensions := (others => <>);
         return CryptoLib.Errors.Internal_Error;
   end Open;

   function Open
     (Session    : in out SSH_Lib.Sessions.Session;
      Channel    : in out SSH_Lib.Channels.Channel;
      Version    : out Natural;
      Extensions : out Extension_Info) return CryptoLib.Errors.Status is
   begin
      return Open (Session, Channel, Protocol_Version, Version, Extensions);
   end Open;

   function Open
     (Session           : in out SSH_Lib.Sessions.Session;
      Channel           : in out SSH_Lib.Channels.Channel;
      Requested_Version : Natural;
      Version           : out Natural) return CryptoLib.Errors.Status
   is
      Extensions : Extension_Info;
   begin
      return Open (Session, Channel, Requested_Version, Version, Extensions);
   end Open;

   function Open
     (Session : in out SSH_Lib.Sessions.Session;
      Channel : in out SSH_Lib.Channels.Channel;
      Version : out Natural) return CryptoLib.Errors.Status
   is
      Extensions : Extension_Info;
   begin
      return Open (Session, Channel, Version, Extensions);
   end Open;

   function Open
     (Session           : in out SSH_Lib.Sessions.Session;
      Item              : in out Client;
      Requested_Version : Natural) return CryptoLib.Errors.Status
   is
      Status_Value : CryptoLib.Errors.Status;
   begin
      if Item.Opened then
         return CryptoLib.Errors.Channel_Request_Failed;
      end if;

      Status_Value :=
        Open
          (Session,
           Item.Channel,
           Requested_Version,
           Item.Version,
           Item.Extensions);
      if Status_Value = CryptoLib.Errors.Ok then
         Item.Opened := True;
         Item.Limits_Known := False;
         Item.Limits := (others => 0);
         if Item.Extensions.Limits then
            declare
               Limits_Status : constant CryptoLib.Errors.Status :=
                 Limits (Item.Channel, Item.Limits);
            begin
               Item.Limits_Known := Limits_Status = CryptoLib.Errors.Ok;
               if not Item.Limits_Known then
                  Item.Limits := (others => 0);
               end if;
            end;
         end if;
      else
         Item.Opened := False;
         Item.Version := 0;
         Item.Extensions := (others => <>);
         Item.Limits_Known := False;
         Item.Limits := (others => 0);
      end if;
      return Status_Value;
   exception
      when others =>
         Item.Opened := False;
         Item.Version := 0;
         Item.Extensions := (others => <>);
         Item.Limits_Known := False;
         Item.Limits := (others => 0);
         return CryptoLib.Errors.Internal_Error;
   end Open;

   function Open
     (Session : in out SSH_Lib.Sessions.Session; Item : in out Client)
      return CryptoLib.Errors.Status is
   begin
      return Open (Session, Item, Protocol_Version);
   end Open;

   function Close (Item : in out Client) return CryptoLib.Errors.Status is
      Status_Value : CryptoLib.Errors.Status;
   begin
      if not Item.Opened then
         return CryptoLib.Errors.Ok;
      end if;
      Status_Value := SSH_Lib.Channels.Close (Item.Channel);
      Item.Opened := False;
      Item.Version := 0;
      Item.Extensions := (others => <>);
      Item.Limits_Known := False;
      Item.Limits := (others => 0);
      return Status_Value;
   exception
      when others =>
         Item.Opened := False;
         Item.Version := 0;
         Item.Extensions := (others => <>);
         Item.Limits_Known := False;
         Item.Limits := (others => 0);
         return CryptoLib.Errors.Internal_Error;
   end Close;

   function Upload_Data
     (Item        : in out Client;
      Remote_Path : String;
      Data        : Ada.Streams.Stream_Element_Array;
      Mode        : String := "0644";
      Options     : Transfer_Options := Default_Transfer_Options)
      return CryptoLib.Errors.Status
   is
      Handle        : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Target_Path   : Unbounded_String := To_Unbounded_String (Remote_Path);
      Request_Id    : Interfaces.Unsigned_32 := 2;
      Attributes    : File_Attributes;
      Status_Value  : CryptoLib.Errors.Status;
      Remote_Opened : Boolean := False;
   begin
      if not Item.Opened then
         return CryptoLib.Errors.Channel_Open_Failed;
      elsif not Supports_Open_Mode (Item.Extensions, Write_Truncate) then
         return CryptoLib.Errors.Unsupported_Feature;
      end if;

      if Options.Atomic_Upload then
         declare
            Temp_Path : constant String := Remote_Temporary_Path (Remote_Path);
         begin
            if Temp_Path'Length = 0 then
               return CryptoLib.Errors.Invalid_Command;
            end if;
            Target_Path := To_Unbounded_String (Temp_Path);
            Status_Value := Remove_File (Item.Channel, Temp_Path);
         end;
      end if;

      Status_Value :=
        Open_Remote_File
          (Item.Channel, To_String (Target_Path), Mode, Handle, Item.Version);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      Remote_Opened := True;

      Status_Value :=
        Pipelined_Write_Buffer
          (Item.Channel,
           Handle,
           0,
           Data,
           2,
           Effective_Pipeline_Depth (Options),
           Request_Id,
           Effective_Write_Chunk_Size
             (Options, Item.Limits_Known, Item.Limits));
      if Status_Value /= CryptoLib.Errors.Ok then
         Close_Remote_File_Best_Effort (Item.Channel, Handle, Request_Id);
         return Status_Value;
      end if;

      Status_Value := Close_Remote_File (Item.Channel, Handle, Request_Id);
      Remote_Opened := False;
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      if Options.Verify_After_Transfer then
         Status_Value :=
           Stat_Request
             (Item.Channel,
              SSH_FXP_STAT,
              To_String (Target_Path),
              Attributes,
              Item.Version);
         if Status_Value /= CryptoLib.Errors.Ok
           or else not Attributes.Size_Known
           or else Attributes.Size /= Interfaces.Unsigned_64 (Data'Length)
         then
            return CryptoLib.Errors.Remote_Failure;
         end if;
      end if;
      if Options.Atomic_Upload then
         Status_Value :=
           Rename (Item.Channel, To_String (Target_Path), Remote_Path);
         if Status_Value /= CryptoLib.Errors.Ok then
            return Status_Value;
         end if;
         if Options.Verify_After_Transfer then
            Status_Value :=
              Stat_Request
                (Item.Channel,
                 SSH_FXP_STAT,
                 Remote_Path,
                 Attributes,
                 Item.Version);
            if Status_Value /= CryptoLib.Errors.Ok
              or else not Attributes.Size_Known
              or else Attributes.Size /= Interfaces.Unsigned_64 (Data'Length)
            then
               return CryptoLib.Errors.Remote_Failure;
            end if;
         end if;
      end if;
      return CryptoLib.Errors.Ok;
   exception
      when others =>
         if Remote_Opened then
            Close_Remote_File_Best_Effort (Item.Channel, Handle, Request_Id);
         end if;
         return CryptoLib.Errors.Internal_Error;
   end Upload_Data;

   function Download_Data
     (Item        : in out Client;
      Remote_Path : String;
      Data        : out SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Options     : Transfer_Options := Default_Transfer_Options)
      return CryptoLib.Errors.Status
   is
      Attributes    : File_Attributes;
      Handle        : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Request_Id    : Interfaces.Unsigned_32 := 2;
      Status_Value  : CryptoLib.Errors.Status;
      Remote_Opened : Boolean := False;
   begin
      SSH_Lib.Protocol.Buffers.Clear (Data);
      if not Item.Opened then
         return CryptoLib.Errors.Channel_Open_Failed;
      elsif not Supports_Open_Mode (Item.Extensions, Read_Only) then
         return CryptoLib.Errors.Unsupported_Feature;
      elsif not Safe_Remote_Path (Remote_Path) then
         return CryptoLib.Errors.Invalid_Command;
      end if;

      Status_Value :=
        Stat_Request
          (Item.Channel, SSH_FXP_STAT, Remote_Path, Attributes, Item.Version);
      if Status_Value /= CryptoLib.Errors.Ok
        or else not Attributes.Size_Known
        or else Attributes.Size > Interfaces.Unsigned_64 (Natural'Last)
      then
         return CryptoLib.Errors.Read_Failed;
      end if;

      Status_Value :=
        Open_Remote_Read_File
          (Item.Channel, Remote_Path, Handle, Item.Version);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      Remote_Opened := True;

      Status_Value :=
        Pipelined_Read_To_Buffer
          (Item.Channel,
           Handle,
           0,
           Natural (Attributes.Size),
           2,
           Effective_Pipeline_Depth (Options),
           Data,
           Request_Id,
           Effective_Read_Chunk_Size (Item.Extensions, Options));
      if Status_Value /= CryptoLib.Errors.Ok then
         Close_Remote_File_Best_Effort (Item.Channel, Handle, Request_Id);
         return Status_Value;
      end if;

      Status_Value := Close_Remote_File (Item.Channel, Handle, Request_Id);
      Remote_Opened := False;
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      if Options.Verify_After_Transfer
        and then
          SSH_Lib.Protocol.Buffers.To_Array (Data)'Length
          /= Natural (Attributes.Size)
      then
         SSH_Lib.Protocol.Buffers.Clear (Data);
         return CryptoLib.Errors.Read_Failed;
      end if;
      return CryptoLib.Errors.Ok;
   exception
      when others =>
         if Remote_Opened then
            Close_Remote_File_Best_Effort (Item.Channel, Handle, Request_Id);
         end if;
         SSH_Lib.Protocol.Buffers.Clear (Data);
         return CryptoLib.Errors.Internal_Error;
   end Download_Data;

   function Stat
     (Item        : in out Client;
      Remote_Path : String;
      Attributes  : out File_Attributes) return CryptoLib.Errors.Status is
   begin
      Attributes := (others => <>);
      if not Item.Opened then
         return CryptoLib.Errors.Channel_Open_Failed;
      end if;
      return
        Stat_Request
          (Item.Channel, SSH_FXP_STAT, Remote_Path, Attributes, Item.Version);
   exception
      when others =>
         Attributes := (others => <>);
         return CryptoLib.Errors.Internal_Error;
   end Stat;

   function List_Directory
     (Item        : in out Client;
      Remote_Path : String;
      Entries     : out Directory_Entry_Vectors.Vector)
      return CryptoLib.Errors.Status is
   begin
      Entries.Clear;
      if not Item.Opened then
         return CryptoLib.Errors.Channel_Open_Failed;
      end if;
      return List_Directory (Item.Channel, Remote_Path, Entries, Item.Version);
   exception
      when others =>
         Entries.Clear;
         return CryptoLib.Errors.Internal_Error;
   end List_Directory;

   function LStat
     (Item        : in out Client;
      Remote_Path : String;
      Attributes  : out File_Attributes) return CryptoLib.Errors.Status is
   begin
      Attributes := (others => <>);
      if not Item.Opened then
         return CryptoLib.Errors.Channel_Open_Failed;
      end if;
      return
        Stat_Request
          (Item.Channel, SSH_FXP_LSTAT, Remote_Path, Attributes, Item.Version);
   exception
      when others =>
         Attributes := (others => <>);
         return CryptoLib.Errors.Internal_Error;
   end LStat;

   function Realpath
     (Item           : in out Client;
      Remote_Path    : String;
      Canonical_Path : out Unbounded_String) return CryptoLib.Errors.Status is
   begin
      Canonical_Path := Null_Unbounded_String;
      if not Item.Opened then
         return CryptoLib.Errors.Channel_Open_Failed;
      end if;
      return
        Realpath (Item.Channel, Remote_Path, Canonical_Path, Item.Version);
   exception
      when others =>
         Canonical_Path := Null_Unbounded_String;
         return CryptoLib.Errors.Internal_Error;
   end Realpath;

   function Set_Attributes
     (Item : in out Client; Remote_Path : String; Attributes : File_Attributes)
      return CryptoLib.Errors.Status is
   begin
      if not Item.Opened then
         return CryptoLib.Errors.Channel_Open_Failed;
      elsif not Supports_Attributes (Item.Extensions, Attributes, Item.Version)
      then
         return CryptoLib.Errors.Unsupported_Feature;
      end if;
      return
        Simple_Status_Request
          (Item.Channel,
           Encode_Set_Attributes_Request
             (1, Remote_Path, Attributes, Item.Version));
   exception
      when others =>
         return CryptoLib.Errors.Internal_Error;
   end Set_Attributes;

   function Set_Path_Owner_Group
     (Item        : in out Client;
      Remote_Path : String;
      Owner       : String;
      Group       : String) return CryptoLib.Errors.Status
   is
      Attributes : File_Attributes := (others => <>);
   begin
      Set_Owner_Group (Attributes, Owner, Group);
      return Set_Attributes (Item, Remote_Path, Attributes);
   end Set_Path_Owner_Group;

   function Set_Path_Mime_Type
     (Item : in out Client; Remote_Path : String; Mime_Type : String)
      return CryptoLib.Errors.Status
   is
      Attributes : File_Attributes := (others => <>);
   begin
      Set_Mime_Type (Attributes, Mime_Type);
      return Set_Attributes (Item, Remote_Path, Attributes);
   end Set_Path_Mime_Type;

   function Set_Path_ACL
     (Item : in out Client; Remote_Path : String; ACL : String)
      return CryptoLib.Errors.Status
   is
      Attributes : File_Attributes := (others => <>);
   begin
      Set_ACL (Attributes, ACL);
      return Set_Attributes (Item, Remote_Path, Attributes);
   end Set_Path_ACL;

   function Set_Path_Attribute_Bits
     (Item        : in out Client;
      Remote_Path : String;
      Bits        : Interfaces.Unsigned_32;
      Valid       : Interfaces.Unsigned_32) return CryptoLib.Errors.Status
   is
      Attributes : File_Attributes := (others => <>);
   begin
      Set_Attribute_Bits (Attributes, Bits, Valid);
      return Set_Attributes (Item, Remote_Path, Attributes);
   end Set_Path_Attribute_Bits;

   function Set_Path_Text_Hint
     (Item : in out Client; Remote_Path : String; Hint : Interfaces.Unsigned_8)
      return CryptoLib.Errors.Status
   is
      Attributes : File_Attributes := (others => <>);
   begin
      Set_Text_Hint (Attributes, Hint);
      return Set_Attributes (Item, Remote_Path, Attributes);
   end Set_Path_Text_Hint;

   function Remove_File
     (Item : in out Client; Remote_Path : String) return CryptoLib.Errors.Status
   is
   begin
      if not Item.Opened then
         return CryptoLib.Errors.Channel_Open_Failed;
      end if;
      return Remove_File (Item.Channel, Remote_Path);
   exception
      when others =>
         return CryptoLib.Errors.Internal_Error;
   end Remove_File;

   function Remove_File
     (Item        : in out Client;
      Remote_Path : String;
      Result      : out SFTP_Result) return CryptoLib.Errors.Status
   is
      Status_Value : constant CryptoLib.Errors.Status :=
        Remove_File (Item, Remote_Path);
   begin
      Capture_Result (Status_Value, Result, Remove_Operation);
      return Status_Value;
   end Remove_File;

   function Make_Directory
     (Item : in out Client; Remote_Path : String; Mode : String := "0755")
      return CryptoLib.Errors.Status
   is
      Attributes  : File_Attributes;
      Permissions : Interfaces.Unsigned_32 := 0;
   begin
      if not Item.Opened then
         return CryptoLib.Errors.Channel_Open_Failed;
      elsif not Mode_To_Permissions (Mode, Permissions) then
         return CryptoLib.Errors.Invalid_Command;
      end if;

      Attributes.Permissions_Known := True;
      Attributes.Permissions := Directory_Type or Permissions;
      if not Supports_Attributes (Item.Extensions, Attributes, Item.Version)
      then
         return CryptoLib.Errors.Unsupported_Feature;
      end if;

      return
        Simple_Status_Request
          (Item.Channel,
           Encode_Mkdir_Request (1, Remote_Path, Mode, Item.Version));
   exception
      when others =>
         return CryptoLib.Errors.Internal_Error;
   end Make_Directory;

   function Text_Seek
     (Item        : in out Client;
      Remote_Path : String;
      Line_Number : Interfaces.Unsigned_64;
      Result      : out SFTP_Result) return CryptoLib.Errors.Status
   is
      Status_Value : constant CryptoLib.Errors.Status :=
        Text_Seek (Item, Remote_Path, Line_Number);
   begin
      Capture_Result (Status_Value, Result, Extended_Operation);
      return Status_Value;
   end Text_Seek;

   function Lock_Range
     (Item        : in out Client;
      Remote_Path : String;
      Offset      : Interfaces.Unsigned_64;
      Length      : Interfaces.Unsigned_64;
      Lock_Mask   : Interfaces.Unsigned_32;
      Result      : out SFTP_Result) return CryptoLib.Errors.Status
   is
      Status_Value : constant CryptoLib.Errors.Status :=
        Lock_Range (Item, Remote_Path, Offset, Length, Lock_Mask);
   begin
      Capture_Result (Status_Value, Result, Lock_Operation);
      return Status_Value;
   end Lock_Range;

   function Unlock_Range
     (Item        : in out Client;
      Remote_Path : String;
      Offset      : Interfaces.Unsigned_64;
      Length      : Interfaces.Unsigned_64;
      Result      : out SFTP_Result) return CryptoLib.Errors.Status
   is
      Status_Value : constant CryptoLib.Errors.Status :=
        Unlock_Range (Item, Remote_Path, Offset, Length);
   begin
      Capture_Result (Status_Value, Result, Lock_Operation);
      return Status_Value;
   end Unlock_Range;

   function Version_Select
     (Item              : in out Client;
      Requested_Version : Natural;
      Result            : out SFTP_Result) return CryptoLib.Errors.Status
   is
      Status_Value : constant CryptoLib.Errors.Status :=
        Version_Select (Item, Requested_Version);
   begin
      Capture_Result (Status_Value, Result, Extended_Operation);
      return Status_Value;
   end Version_Select;

   function Download_Data
     (Item        : in out Client;
      Remote_Path : String;
      Data        : out SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Options     : Transfer_Options;
      Result      : out SFTP_Result) return CryptoLib.Errors.Status
   is
      Status_Value : constant CryptoLib.Errors.Status :=
        Download_Data (Item, Remote_Path, Data, Options);
   begin
      Capture_Result (Status_Value, Result, Download_Operation);
      return Status_Value;
   end Download_Data;

   function Read_At
     (Item        : in out Client;
      Remote_Path : String;
      Offset      : Interfaces.Unsigned_64;
      Length      : Natural;
      Data        : out SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Result      : out SFTP_Result) return CryptoLib.Errors.Status
   is
      Status_Value : constant CryptoLib.Errors.Status :=
        Read_At (Item, Remote_Path, Offset, Length, Data);
   begin
      Capture_Result (Status_Value, Result, Download_Operation);
      return Status_Value;
   end Read_At;

   function Write_At
     (Item        : in out Client;
      Remote_Path : String;
      Offset      : Interfaces.Unsigned_64;
      Data        : Ada.Streams.Stream_Element_Array;
      Mode        : String;
      Result      : out SFTP_Result) return CryptoLib.Errors.Status
   is
      Status_Value : constant CryptoLib.Errors.Status :=
        Write_At (Item, Remote_Path, Offset, Data, Mode);
   begin
      Capture_Result (Status_Value, Result, Upload_Operation);
      return Status_Value;
   end Write_At;

   function Fsync
     (Item        : in out Client;
      Remote_Path : String;
      Result      : out SFTP_Result) return CryptoLib.Errors.Status
   is
      Status_Value : constant CryptoLib.Errors.Status := Fsync (Item, Remote_Path);
   begin
      Capture_Result (Status_Value, Result, Extended_Operation);
      return Status_Value;
   end Fsync;

   function List_Directory
     (Item        : in out Client;
      Remote_Path : String;
      Entries     : out Directory_Entry_Vectors.Vector;
      Result      : out SFTP_Result) return CryptoLib.Errors.Status
   is
      Status_Value : constant CryptoLib.Errors.Status :=
        List_Directory (Item, Remote_Path, Entries);
   begin
      Capture_Result (Status_Value, Result, Directory_Operation);
      return Status_Value;
   end List_Directory;

   function LStat
     (Item        : in out Client;
      Remote_Path : String;
      Attributes  : out File_Attributes;
      Result      : out SFTP_Result) return CryptoLib.Errors.Status
   is
      Status_Value : constant CryptoLib.Errors.Status :=
        LStat (Item, Remote_Path, Attributes);
   begin
      Capture_Result (Status_Value, Result, Stat_Operation);
      return Status_Value;
   end LStat;

   function Realpath
     (Item           : in out Client;
      Remote_Path    : String;
      Canonical_Path : out Unbounded_String;
      Result         : out SFTP_Result) return CryptoLib.Errors.Status
   is
      Status_Value : constant CryptoLib.Errors.Status :=
        Realpath (Item, Remote_Path, Canonical_Path);
   begin
      Capture_Result (Status_Value, Result, Stat_Operation);
      return Status_Value;
   end Realpath;

   function Set_Attributes
     (Item        : in out Client;
      Remote_Path : String;
      Attributes  : File_Attributes;
      Result      : out SFTP_Result) return CryptoLib.Errors.Status
   is
      Status_Value : constant CryptoLib.Errors.Status :=
        Set_Attributes (Item, Remote_Path, Attributes);
   begin
      Capture_Result (Status_Value, Result, Set_Attributes_Operation);
      return Status_Value;
   end Set_Attributes;

   function Set_Path_Owner_Group
     (Item        : in out Client;
      Remote_Path : String;
      Owner       : String;
      Group       : String;
      Result      : out SFTP_Result) return CryptoLib.Errors.Status
   is
      Status_Value : constant CryptoLib.Errors.Status :=
        Set_Path_Owner_Group (Item, Remote_Path, Owner, Group);
   begin
      Capture_Result (Status_Value, Result, Set_Attributes_Operation);
      return Status_Value;
   end Set_Path_Owner_Group;

   function Set_Path_Mime_Type
     (Item        : in out Client;
      Remote_Path : String;
      Mime_Type   : String;
      Result      : out SFTP_Result) return CryptoLib.Errors.Status
   is
      Status_Value : constant CryptoLib.Errors.Status :=
        Set_Path_Mime_Type (Item, Remote_Path, Mime_Type);
   begin
      Capture_Result (Status_Value, Result, Set_Attributes_Operation);
      return Status_Value;
   end Set_Path_Mime_Type;

   function Set_Path_ACL
     (Item        : in out Client;
      Remote_Path : String;
      ACL         : String;
      Result      : out SFTP_Result) return CryptoLib.Errors.Status
   is
      Status_Value : constant CryptoLib.Errors.Status :=
        Set_Path_ACL (Item, Remote_Path, ACL);
   begin
      Capture_Result (Status_Value, Result, Set_Attributes_Operation);
      return Status_Value;
   end Set_Path_ACL;

   function Set_Path_Attribute_Bits
     (Item        : in out Client;
      Remote_Path : String;
      Bits        : Interfaces.Unsigned_32;
      Valid       : Interfaces.Unsigned_32;
      Result      : out SFTP_Result) return CryptoLib.Errors.Status
   is
      Status_Value : constant CryptoLib.Errors.Status :=
        Set_Path_Attribute_Bits (Item, Remote_Path, Bits, Valid);
   begin
      Capture_Result (Status_Value, Result, Set_Attributes_Operation);
      return Status_Value;
   end Set_Path_Attribute_Bits;

   function Set_Path_Text_Hint
     (Item        : in out Client;
      Remote_Path : String;
      Hint        : Interfaces.Unsigned_8;
      Result      : out SFTP_Result) return CryptoLib.Errors.Status
   is
      Status_Value : constant CryptoLib.Errors.Status :=
        Set_Path_Text_Hint (Item, Remote_Path, Hint);
   begin
      Capture_Result (Status_Value, Result, Set_Attributes_Operation);
      return Status_Value;
   end Set_Path_Text_Hint;

   function Make_Directory
     (Item        : in out Client;
      Remote_Path : String;
      Mode        : String;
      Result      : out SFTP_Result) return CryptoLib.Errors.Status
   is
      Status_Value : constant CryptoLib.Errors.Status :=
        Make_Directory (Item, Remote_Path, Mode);
   begin
      Capture_Result (Status_Value, Result, Directory_Operation);
      return Status_Value;
   end Make_Directory;

   function Read_At
     (Item        : in out Client;
      Remote_Path : String;
      Offset      : Interfaces.Unsigned_64;
      Length      : Natural;
      Data        : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status
   is
      Handle       : File_Handle;
      Status_Value : CryptoLib.Errors.Status;
      Close_Status : CryptoLib.Errors.Status;
      pragma Unreferenced (Close_Status);
   begin
      SSH_Lib.Protocol.Buffers.Clear (Data);
      if not Item.Opened then
         return CryptoLib.Errors.Channel_Open_Failed;
      elsif not Supports_Open_Mode (Item.Extensions, Read_Only) then
         return CryptoLib.Errors.Unsupported_Feature;
      end if;
      Status_Value :=
        Open_Read (Item.Channel, Remote_Path, Handle, Item.Version);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      Set_Handle_Context (Handle, Item.Version, Item.Extensions);
      if Length > Effective_Read_Chunk_Size (Item.Extensions) then
         declare
            Next_Request_Id : Interfaces.Unsigned_32 := 2;
         begin
            Status_Value :=
              Pipelined_Read_To_Buffer
                (Item.Channel,
                 Handle.Data,
                 Offset,
                 Length,
                 2,
                 Default_Pipeline_Depth,
                 Data,
                 Next_Request_Id,
                 Effective_Read_Chunk_Size (Item.Extensions));
         end;
      else
         Status_Value := Read_At (Item.Channel, Handle, Offset, Length, Data);
      end if;
      Close_Status := Close (Item.Channel, Handle);
      return Status_Value;
   exception
      when others =>
         SSH_Lib.Protocol.Buffers.Clear (Data);
         return CryptoLib.Errors.Internal_Error;
   end Read_At;

   function Write_At
     (Item        : in out Client;
      Remote_Path : String;
      Offset      : Interfaces.Unsigned_64;
      Data        : Ada.Streams.Stream_Element_Array;
      Mode        : String := "0644") return CryptoLib.Errors.Status
   is
      Handle       : File_Handle;
      Status_Value : CryptoLib.Errors.Status;
      Close_Status : CryptoLib.Errors.Status;
      pragma Unreferenced (Close_Status);
   begin
      if not Item.Opened then
         return CryptoLib.Errors.Channel_Open_Failed;
      elsif not Supports_Open_Mode (Item.Extensions, Write_No_Truncate) then
         return CryptoLib.Errors.Unsupported_Feature;
      end if;
      Status_Value :=
        Open_File
          (Item.Channel,
           Remote_Path,
           Handle,
           Write_No_Truncate,
           Mode,
           Item.Version);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      Set_Handle_Context (Handle, Item.Version, Item.Extensions);
      Status_Value := Write_At (Item.Channel, Handle, Offset, Data);
      Close_Status := Close (Item.Channel, Handle);
      return Status_Value;
   exception
      when others =>
         return CryptoLib.Errors.Internal_Error;
   end Write_At;

   function Fsync
     (Item : in out Client; Remote_Path : String) return CryptoLib.Errors.Status
   is
      Handle       : File_Handle;
      Status_Value : CryptoLib.Errors.Status;
      Close_Status : CryptoLib.Errors.Status;
      pragma Unreferenced (Close_Status);
   begin
      if not Item.Opened then
         return CryptoLib.Errors.Channel_Open_Failed;
      elsif not Item.Extensions.Fsync
        or else not Supports_Open_Mode (Item.Extensions, Read_Write)
      then
         return CryptoLib.Errors.Unsupported_Feature;
      end if;
      Status_Value :=
        Open_File
          (Item.Channel,
           Remote_Path,
           Handle,
           Read_Write,
           "0644",
           Item.Version);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      Set_Handle_Context (Handle, Item.Version, Item.Extensions);
      Status_Value := Fsync (Item.Channel, Handle);
      Close_Status := Close (Item.Channel, Handle);
      return Status_Value;
   exception
      when others =>
         return CryptoLib.Errors.Internal_Error;
   end Fsync;

   function Set_Path_Owner_Group
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Owner       : String;
      Group       : String) return CryptoLib.Errors.Status
   is
      Item         : Client;
      Status_Value : CryptoLib.Errors.Status;
      Close_Status : CryptoLib.Errors.Status;
      pragma Unreferenced (Close_Status);
   begin
      Status_Value := Open (Session, Item, Maximum_Protocol_Version);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      Status_Value := Set_Path_Owner_Group (Item, Remote_Path, Owner, Group);
      Close_Status := Close (Item);
      return Status_Value;
   exception
      when others =>
         return CryptoLib.Errors.Internal_Error;
   end Set_Path_Owner_Group;

   function Set_Path_Mime_Type
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Mime_Type   : String) return CryptoLib.Errors.Status
   is
      Item         : Client;
      Status_Value : CryptoLib.Errors.Status;
      Close_Status : CryptoLib.Errors.Status;
      pragma Unreferenced (Close_Status);
   begin
      Status_Value := Open (Session, Item, Maximum_Protocol_Version);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      Status_Value := Set_Path_Mime_Type (Item, Remote_Path, Mime_Type);
      Close_Status := Close (Item);
      return Status_Value;
   exception
      when others =>
         return CryptoLib.Errors.Internal_Error;
   end Set_Path_Mime_Type;

   function Set_Path_ACL
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      ACL         : String) return CryptoLib.Errors.Status
   is
      Item         : Client;
      Status_Value : CryptoLib.Errors.Status;
      Close_Status : CryptoLib.Errors.Status;
      pragma Unreferenced (Close_Status);
   begin
      Status_Value := Open (Session, Item, Maximum_Protocol_Version);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      Status_Value := Set_Path_ACL (Item, Remote_Path, ACL);
      Close_Status := Close (Item);
      return Status_Value;
   exception
      when others =>
         return CryptoLib.Errors.Internal_Error;
   end Set_Path_ACL;

   function Set_Path_Attribute_Bits
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Bits        : Interfaces.Unsigned_32;
      Valid       : Interfaces.Unsigned_32) return CryptoLib.Errors.Status
   is
      Item         : Client;
      Status_Value : CryptoLib.Errors.Status;
      Close_Status : CryptoLib.Errors.Status;
      pragma Unreferenced (Close_Status);
   begin
      Status_Value := Open (Session, Item, Maximum_Protocol_Version);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      Status_Value := Set_Path_Attribute_Bits (Item, Remote_Path, Bits, Valid);
      Close_Status := Close (Item);
      return Status_Value;
   exception
      when others =>
         return CryptoLib.Errors.Internal_Error;
   end Set_Path_Attribute_Bits;

   function Set_Path_Text_Hint
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Hint        : Interfaces.Unsigned_8) return CryptoLib.Errors.Status
   is
      Item         : Client;
      Status_Value : CryptoLib.Errors.Status;
      Close_Status : CryptoLib.Errors.Status;
      pragma Unreferenced (Close_Status);
   begin
      Status_Value := Open (Session, Item, Maximum_Protocol_Version);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      Status_Value := Set_Path_Text_Hint (Item, Remote_Path, Hint);
      Close_Status := Close (Item);
      return Status_Value;
   exception
      when others =>
         return CryptoLib.Errors.Internal_Error;
   end Set_Path_Text_Hint;

   function Download_Data
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Data        : out SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Options     : Transfer_Options := Default_Transfer_Options)
      return CryptoLib.Errors.Status
   is
      Status_Value : CryptoLib.Errors.Status := CryptoLib.Errors.Internal_Error;
   begin
      SSH_Lib.Protocol.Buffers.Clear (Data);
      if not Safe_Remote_Path (Remote_Path) then
         return CryptoLib.Errors.Invalid_Command;
      end if;

      for Attempt in 0 .. Options.Retry_Count loop
         declare
            Channel_Item : SSH_Lib.Channels.Channel;
            Version      : Natural := 0;
            Close_Status : CryptoLib.Errors.Status;
            Opened       : Boolean := False;
            pragma Unreferenced (Close_Status);
         begin
            Status_Value := Open (Session, Channel_Item, Version);
            if Status_Value /= CryptoLib.Errors.Ok then
               if Attempt = Options.Retry_Count
                 or else not Retryable_Transfer_Status (Status_Value)
               then
                  return Status_Value;
               end if;
            else
               Opened := True;
               Status_Value :=
                 Download_Data
                   (Channel_Item, Remote_Path, Data,
                    Adapted_Transfer_Options (Options, Attempt));
               Close_Status := SSH_Lib.Channels.Close (Channel_Item);
               Opened := False;
               if Status_Value = CryptoLib.Errors.Ok
                 or else Attempt = Options.Retry_Count
                 or else not Retryable_Transfer_Status (Status_Value)
               then
                  return Status_Value;
               end if;
               SSH_Lib.Protocol.Buffers.Clear (Data);
            end if;
         exception
            when others =>
               if Opened then
                  Close_Status := SSH_Lib.Channels.Close (Channel_Item);
               end if;
               SSH_Lib.Protocol.Buffers.Clear (Data);
               return CryptoLib.Errors.Internal_Error;
         end;
      end loop;
      return Status_Value;
   end Download_Data;

   function Download_Stream
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Writer      : Stream_Writer_Access;
      Options     : Transfer_Options := Default_Transfer_Options)
      return CryptoLib.Errors.Status
   is
      Status_Value : CryptoLib.Errors.Status := CryptoLib.Errors.Internal_Error;
   begin
      if not Safe_Remote_Path (Remote_Path) or else Writer = null then
         return CryptoLib.Errors.Invalid_Command;
      end if;

      for Attempt in 0 .. Options.Retry_Count loop
         declare
            Channel_Item : SSH_Lib.Channels.Channel;
            Version      : Natural := 0;
            Close_Status : CryptoLib.Errors.Status;
            Opened       : Boolean := False;
            pragma Unreferenced (Close_Status);
         begin
            Status_Value := Open (Session, Channel_Item, Version);
            if Status_Value /= CryptoLib.Errors.Ok then
               if Attempt = Options.Retry_Count
                 or else not Retryable_Transfer_Status (Status_Value)
               then
                  return Status_Value;
               end if;
            else
               Opened := True;
               Status_Value :=
                 Download_Stream (Channel_Item, Remote_Path, Writer, Options);
               Close_Status := SSH_Lib.Channels.Close (Channel_Item);
               Opened := False;
               if Status_Value = CryptoLib.Errors.Ok
                 or else Attempt = Options.Retry_Count
                 or else not Retryable_Transfer_Status (Status_Value)
               then
                  return Status_Value;
               end if;
            end if;
         exception
            when others =>
               if Opened then
                  Close_Status := SSH_Lib.Channels.Close (Channel_Item);
               end if;
               return CryptoLib.Errors.Internal_Error;
         end;
      end loop;
      return Status_Value;
   end Download_Stream;

   function Download_File
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Local_Path  : String;
      Options     : Transfer_Options := Default_Transfer_Options)
      return CryptoLib.Errors.Status
   is
      Status_Value : CryptoLib.Errors.Status := CryptoLib.Errors.Internal_Error;
   begin
      if not Safe_Remote_Path (Remote_Path) or else Local_Path'Length = 0 then
         return CryptoLib.Errors.Invalid_Command;
      end if;

      for Attempt in 0 .. Options.Retry_Count loop
         declare
            Channel_Item : SSH_Lib.Channels.Channel;
            Version      : Natural := 0;
            Close_Status : CryptoLib.Errors.Status;
            Opened       : Boolean := False;
            pragma Unreferenced (Close_Status);
         begin
            Status_Value := Open (Session, Channel_Item, Version);
            if Status_Value /= CryptoLib.Errors.Ok then
               if Attempt = Options.Retry_Count
                 or else not Retryable_Transfer_Status (Status_Value)
               then
                  return Status_Value;
               end if;
            else
               Opened := True;
               Status_Value :=
                 Download_File
                   (Channel_Item, Remote_Path, Local_Path, Options);
               Close_Status := SSH_Lib.Channels.Close (Channel_Item);
               Opened := False;
               if Status_Value = CryptoLib.Errors.Ok
                 or else Attempt = Options.Retry_Count
                 or else not Retryable_Transfer_Status (Status_Value)
               then
                  return Status_Value;
               end if;
            end if;
         exception
            when others =>
               if Opened then
                  Close_Status := SSH_Lib.Channels.Close (Channel_Item);
               end if;
               return CryptoLib.Errors.Internal_Error;
         end;
      end loop;
      return Status_Value;
   end Download_File;

   function Resume_Download_File
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Local_Path  : String;
      Options     : Transfer_Options := Default_Transfer_Options)
      return CryptoLib.Errors.Status
   is
      Status_Value : CryptoLib.Errors.Status := CryptoLib.Errors.Internal_Error;
   begin
      if not Safe_Remote_Path (Remote_Path) or else Local_Path'Length = 0 then
         return CryptoLib.Errors.Invalid_Command;
      end if;

      for Attempt in 0 .. Options.Retry_Count loop
         declare
            Channel_Item : SSH_Lib.Channels.Channel;
            Version      : Natural := 0;
            Close_Status : CryptoLib.Errors.Status;
            Opened       : Boolean := False;
            pragma Unreferenced (Close_Status);
         begin
            Status_Value := Open (Session, Channel_Item, Version);
            if Status_Value /= CryptoLib.Errors.Ok then
               if Attempt = Options.Retry_Count
                 or else not Retryable_Transfer_Status (Status_Value)
               then
                  return Status_Value;
               end if;
            else
               Opened := True;
               Status_Value :=
                 Resume_Download_File
                   (Channel_Item, Remote_Path, Local_Path, Options);
               Close_Status := SSH_Lib.Channels.Close (Channel_Item);
               Opened := False;
               if Status_Value = CryptoLib.Errors.Ok
                 or else Attempt = Options.Retry_Count
                 or else not Retryable_Transfer_Status (Status_Value)
               then
                  return Status_Value;
               end if;
            end if;
         exception
            when others =>
               if Opened then
                  Close_Status := SSH_Lib.Channels.Close (Channel_Item);
               end if;
               return CryptoLib.Errors.Internal_Error;
         end;
      end loop;
      return Status_Value;
   end Resume_Download_File;

   function List_Directory
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Names       : out Unbounded_String) return CryptoLib.Errors.Status
   is
      Channel_Item : SSH_Lib.Channels.Channel;
      Version      : Natural := 0;
      Status_Value : CryptoLib.Errors.Status;
      Close_Status : CryptoLib.Errors.Status;
      Opened       : Boolean := False;
      pragma Unreferenced (Close_Status);
   begin
      Names := Null_Unbounded_String;
      if not Safe_Remote_Path (Remote_Path) then
         return CryptoLib.Errors.Invalid_Command;
      end if;
      Status_Value := Open (Session, Channel_Item, Version);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      Opened := True;
      Status_Value := List_Directory (Channel_Item, Remote_Path, Names);
      Close_Status := SSH_Lib.Channels.Close (Channel_Item);
      Opened := False;
      return Status_Value;
   exception
      when others =>
         if Opened then
            Close_Status := SSH_Lib.Channels.Close (Channel_Item);
         end if;
         Names := Null_Unbounded_String;
         return CryptoLib.Errors.Internal_Error;
   end List_Directory;

   function List_Directory
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Entries     : out Directory_Entry_Vectors.Vector)
      return CryptoLib.Errors.Status
   is
      Channel_Item : SSH_Lib.Channels.Channel;
      Version      : Natural := 0;
      Status_Value : CryptoLib.Errors.Status;
      Close_Status : CryptoLib.Errors.Status;
      Opened       : Boolean := False;
      pragma Unreferenced (Close_Status);
   begin
      Entries.Clear;
      if not Safe_Remote_Path (Remote_Path) then
         return CryptoLib.Errors.Invalid_Command;
      end if;
      Status_Value := Open (Session, Channel_Item, Version);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      Opened := True;
      Status_Value := List_Directory (Channel_Item, Remote_Path, Entries);
      Close_Status := SSH_Lib.Channels.Close (Channel_Item);
      Opened := False;
      return Status_Value;
   exception
      when others =>
         if Opened then
            Close_Status := SSH_Lib.Channels.Close (Channel_Item);
         end if;
         Entries.Clear;
         return CryptoLib.Errors.Internal_Error;
   end List_Directory;

   function List_Directory_Paged
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Callback    : Directory_Page_Callback_Access)
      return CryptoLib.Errors.Status
   is
      Channel_Item : SSH_Lib.Channels.Channel;
      Version      : Natural := 0;
      Status_Value : CryptoLib.Errors.Status;
      Close_Status : CryptoLib.Errors.Status;
      Opened       : Boolean := False;
      pragma Unreferenced (Close_Status);
   begin
      if not Safe_Remote_Path (Remote_Path) or else Callback = null then
         return CryptoLib.Errors.Invalid_Command;
      end if;
      Status_Value := Open (Session, Channel_Item, Version);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      Opened := True;
      Status_Value :=
        List_Directory_Paged (Channel_Item, Remote_Path, Callback);
      Close_Status := SSH_Lib.Channels.Close (Channel_Item);
      Opened := False;
      return Status_Value;
   exception
      when others =>
         if Opened then
            Close_Status := SSH_Lib.Channels.Close (Channel_Item);
         end if;
         return CryptoLib.Errors.Internal_Error;
   end List_Directory_Paged;

   function Stat
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Attributes  : out File_Attributes) return CryptoLib.Errors.Status
   is
      Channel_Item : SSH_Lib.Channels.Channel;
      Version      : Natural := 0;
      Status_Value : CryptoLib.Errors.Status;
      Close_Status : CryptoLib.Errors.Status;
      Opened       : Boolean := False;
      pragma Unreferenced (Close_Status);
   begin
      Attributes := (others => <>);
      if not Safe_Remote_Path (Remote_Path) then
         return CryptoLib.Errors.Invalid_Command;
      end if;
      Status_Value := Open (Session, Channel_Item, Version);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      Opened := True;
      Status_Value := Stat (Channel_Item, Remote_Path, Attributes);
      Close_Status := SSH_Lib.Channels.Close (Channel_Item);
      Opened := False;
      return Status_Value;
   exception
      when others =>
         if Opened then
            Close_Status := SSH_Lib.Channels.Close (Channel_Item);
         end if;
         Attributes := (others => <>);
         return CryptoLib.Errors.Internal_Error;
   end Stat;

   function LStat
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Attributes  : out File_Attributes) return CryptoLib.Errors.Status
   is
      Channel_Item : SSH_Lib.Channels.Channel;
      Version      : Natural := 0;
      Status_Value : CryptoLib.Errors.Status;
      Close_Status : CryptoLib.Errors.Status;
      Opened       : Boolean := False;
      pragma Unreferenced (Close_Status);
   begin
      Attributes := (others => <>);
      if not Safe_Remote_Path (Remote_Path) then
         return CryptoLib.Errors.Invalid_Command;
      end if;
      Status_Value := Open (Session, Channel_Item, Version);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      Opened := True;
      Status_Value := LStat (Channel_Item, Remote_Path, Attributes);
      Close_Status := SSH_Lib.Channels.Close (Channel_Item);
      Opened := False;
      return Status_Value;
   exception
      when others =>
         if Opened then
            Close_Status := SSH_Lib.Channels.Close (Channel_Item);
         end if;
         Attributes := (others => <>);
         return CryptoLib.Errors.Internal_Error;
   end LStat;

   function Realpath
     (Session        : in out SSH_Lib.Sessions.Session;
      Remote_Path    : String;
      Canonical_Path : out Unbounded_String) return CryptoLib.Errors.Status
   is
      Channel_Item : SSH_Lib.Channels.Channel;
      Version      : Natural := 0;
      Status_Value : CryptoLib.Errors.Status;
      Close_Status : CryptoLib.Errors.Status;
      Opened       : Boolean := False;
      pragma Unreferenced (Close_Status);
   begin
      Canonical_Path := Null_Unbounded_String;
      if not Safe_Remote_Path (Remote_Path) then
         return CryptoLib.Errors.Invalid_Command;
      end if;
      Status_Value := Open (Session, Channel_Item, Version);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      Opened := True;
      Status_Value := Realpath (Channel_Item, Remote_Path, Canonical_Path);
      Close_Status := SSH_Lib.Channels.Close (Channel_Item);
      Opened := False;
      return Status_Value;
   exception
      when others =>
         if Opened then
            Close_Status := SSH_Lib.Channels.Close (Channel_Item);
         end if;
         Canonical_Path := Null_Unbounded_String;
         return CryptoLib.Errors.Internal_Error;
   end Realpath;

   function Set_Attributes
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Attributes  : File_Attributes) return CryptoLib.Errors.Status
   is
      Channel_Item : SSH_Lib.Channels.Channel;
      Version      : Natural := 0;
      Status_Value : CryptoLib.Errors.Status;
      Close_Status : CryptoLib.Errors.Status;
      Opened       : Boolean := False;
      pragma Unreferenced (Close_Status);
   begin
      if not Safe_Remote_Path (Remote_Path)
        or else not Has_Attributes (Attributes)
      then
         return CryptoLib.Errors.Invalid_Command;
      end if;
      Status_Value := Open (Session, Channel_Item, Version);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      Opened := True;
      Status_Value := Set_Attributes (Channel_Item, Remote_Path, Attributes);
      Close_Status := SSH_Lib.Channels.Close (Channel_Item);
      Opened := False;
      return Status_Value;
   exception
      when others =>
         if Opened then
            Close_Status := SSH_Lib.Channels.Close (Channel_Item);
         end if;
         return CryptoLib.Errors.Internal_Error;
   end Set_Attributes;

   function Set_Permissions
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Mode        : String) return CryptoLib.Errors.Status
   is
      Channel_Item : SSH_Lib.Channels.Channel;
      Version      : Natural := 0;
      Status_Value : CryptoLib.Errors.Status;
      Close_Status : CryptoLib.Errors.Status;
      Opened       : Boolean := False;
      pragma Unreferenced (Close_Status);
   begin
      if Validate_Upload_Target (Remote_Path, Mode) /= CryptoLib.Errors.Ok then
         return CryptoLib.Errors.Invalid_Command;
      end if;
      Status_Value := Open (Session, Channel_Item, Version);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      Opened := True;
      Status_Value := Set_Permissions (Channel_Item, Remote_Path, Mode);
      Close_Status := SSH_Lib.Channels.Close (Channel_Item);
      Opened := False;
      return Status_Value;
   exception
      when others =>
         if Opened then
            Close_Status := SSH_Lib.Channels.Close (Channel_Item);
         end if;
         return CryptoLib.Errors.Internal_Error;
   end Set_Permissions;

   function Make_Directory
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Mode        : String := "0755") return CryptoLib.Errors.Status
   is
      Channel_Item : SSH_Lib.Channels.Channel;
      Version      : Natural := 0;
      Status_Value : CryptoLib.Errors.Status;
      Close_Status : CryptoLib.Errors.Status;
      Opened       : Boolean := False;
      pragma Unreferenced (Close_Status);
   begin
      if Validate_Upload_Target (Remote_Path, Mode) /= CryptoLib.Errors.Ok then
         return CryptoLib.Errors.Invalid_Command;
      end if;
      Status_Value := Open (Session, Channel_Item, Version);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      Opened := True;
      Status_Value := Make_Directory (Channel_Item, Remote_Path, Mode);
      Close_Status := SSH_Lib.Channels.Close (Channel_Item);
      Opened := False;
      return Status_Value;
   exception
      when others =>
         if Opened then
            Close_Status := SSH_Lib.Channels.Close (Channel_Item);
         end if;
         return CryptoLib.Errors.Internal_Error;
   end Make_Directory;

   function Remove_Directory
     (Session : in out SSH_Lib.Sessions.Session; Remote_Path : String)
      return CryptoLib.Errors.Status
   is
      Channel_Item : SSH_Lib.Channels.Channel;
      Version      : Natural := 0;
      Status_Value : CryptoLib.Errors.Status;
      Close_Status : CryptoLib.Errors.Status;
      Opened       : Boolean := False;
      pragma Unreferenced (Close_Status);
   begin
      if not Safe_Remote_Path (Remote_Path) then
         return CryptoLib.Errors.Invalid_Command;
      end if;
      Status_Value := Open (Session, Channel_Item, Version);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      Opened := True;
      Status_Value := Remove_Directory (Channel_Item, Remote_Path);
      Close_Status := SSH_Lib.Channels.Close (Channel_Item);
      Opened := False;
      return Status_Value;
   exception
      when others =>
         if Opened then
            Close_Status := SSH_Lib.Channels.Close (Channel_Item);
         end if;
         return CryptoLib.Errors.Internal_Error;
   end Remove_Directory;

   function Remove_File
     (Session : in out SSH_Lib.Sessions.Session; Remote_Path : String)
      return CryptoLib.Errors.Status
   is
      Channel_Item : SSH_Lib.Channels.Channel;
      Version      : Natural := 0;
      Status_Value : CryptoLib.Errors.Status;
      Close_Status : CryptoLib.Errors.Status;
      Opened       : Boolean := False;
      pragma Unreferenced (Close_Status);
   begin
      if not Safe_Remote_Path (Remote_Path) then
         return CryptoLib.Errors.Invalid_Command;
      end if;
      Status_Value := Open (Session, Channel_Item, Version);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      Opened := True;
      Status_Value := Remove_File (Channel_Item, Remote_Path);
      Close_Status := SSH_Lib.Channels.Close (Channel_Item);
      Opened := False;
      return Status_Value;
   exception
      when others =>
         if Opened then
            Close_Status := SSH_Lib.Channels.Close (Channel_Item);
         end if;
         return CryptoLib.Errors.Internal_Error;
   end Remove_File;

   function Remove_File
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Result      : out SFTP_Result) return CryptoLib.Errors.Status
   is
      Status_Value : constant CryptoLib.Errors.Status :=
        Remove_File (Session, Remote_Path);
   begin
      Capture_Result (Status_Value, Result, Remove_Operation);
      return Status_Value;
   end Remove_File;

   function Upload_Directory
     (Session        : in out SSH_Lib.Sessions.Session;
      Remote_Path    : String;
      Local_Path     : String;
      Directory_Mode : String := "0755";
      File_Mode      : String := "0644";
      Options        : Recursive_Options := Default_Recursive_Options)
      return CryptoLib.Errors.Status
   is
      Channel_Item : SSH_Lib.Channels.Channel;
      Version      : Natural := 0;
      Status_Value : CryptoLib.Errors.Status;
      Close_Status : CryptoLib.Errors.Status;
      Opened       : Boolean := False;
      pragma Unreferenced (Close_Status);
   begin
      if Validate_Upload_Target (Remote_Path, Directory_Mode)
        /= CryptoLib.Errors.Ok
        or else not Valid_Mode (File_Mode)
        or else Local_Path'Length = 0
      then
         return CryptoLib.Errors.Invalid_Command;
      end if;
      Status_Value := Open (Session, Channel_Item, Version);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      Opened := True;
      Status_Value :=
        Upload_Directory
          (Channel_Item,
           Remote_Path,
           Local_Path,
           Directory_Mode,
           File_Mode,
           Options);
      Close_Status := SSH_Lib.Channels.Close (Channel_Item);
      Opened := False;
      return Status_Value;
   exception
      when others =>
         if Opened then
            Close_Status := SSH_Lib.Channels.Close (Channel_Item);
         end if;
         return CryptoLib.Errors.Internal_Error;
   end Upload_Directory;

   function Download_Directory
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Local_Path  : String;
      Options     : Recursive_Options := Default_Recursive_Options)
      return CryptoLib.Errors.Status
   is
      Channel_Item : SSH_Lib.Channels.Channel;
      Version      : Natural := 0;
      Status_Value : CryptoLib.Errors.Status;
      Close_Status : CryptoLib.Errors.Status;
      Opened       : Boolean := False;
      pragma Unreferenced (Close_Status);
   begin
      if not Safe_Remote_Path (Remote_Path) or else Local_Path'Length = 0 then
         return CryptoLib.Errors.Invalid_Command;
      end if;
      Status_Value := Open (Session, Channel_Item, Version);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      Opened := True;
      Status_Value :=
        Download_Directory (Channel_Item, Remote_Path, Local_Path, Options);
      Close_Status := SSH_Lib.Channels.Close (Channel_Item);
      Opened := False;
      return Status_Value;
   exception
      when others =>
         if Opened then
            Close_Status := SSH_Lib.Channels.Close (Channel_Item);
         end if;
         return CryptoLib.Errors.Internal_Error;
   end Download_Directory;

   function Remove_Tree
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Options     : Recursive_Options := Default_Recursive_Options)
      return CryptoLib.Errors.Status
   is
      Channel_Item : SSH_Lib.Channels.Channel;
      Version      : Natural := 0;
      Status_Value : CryptoLib.Errors.Status;
      Close_Status : CryptoLib.Errors.Status;
      Opened       : Boolean := False;
      pragma Unreferenced (Close_Status);
   begin
      if not Safe_Remote_Path (Remote_Path) then
         return CryptoLib.Errors.Invalid_Command;
      end if;
      Status_Value := Open (Session, Channel_Item, Version);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      Opened := True;
      Status_Value := Remove_Tree (Channel_Item, Remote_Path, Options);
      Close_Status := SSH_Lib.Channels.Close (Channel_Item);
      Opened := False;
      return Status_Value;
   exception
      when others =>
         if Opened then
            Close_Status := SSH_Lib.Channels.Close (Channel_Item);
         end if;
         return CryptoLib.Errors.Internal_Error;
   end Remove_Tree;

   function Copy_Tree
     (Session            : in out SSH_Lib.Sessions.Session;
      Source_Remote_Path : String;
      Target_Remote_Path : String;
      Directory_Mode     : String := "0755";
      File_Mode          : String := "0644";
      Options            : Recursive_Options := Default_Recursive_Options)
      return CryptoLib.Errors.Status
   is
      Channel_Item : SSH_Lib.Channels.Channel;
      Version      : Natural := 0;
      Status_Value : CryptoLib.Errors.Status;
      Close_Status : CryptoLib.Errors.Status;
      Opened       : Boolean := False;
      pragma Unreferenced (Close_Status);
   begin
      if not Safe_Remote_Path (Source_Remote_Path)
        or else
          Validate_Upload_Target (Target_Remote_Path, Directory_Mode)
          /= CryptoLib.Errors.Ok
        or else not Valid_Mode (File_Mode)
      then
         return CryptoLib.Errors.Invalid_Command;
      end if;
      Status_Value := Open (Session, Channel_Item, Version);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      Opened := True;
      Status_Value :=
        Copy_Tree
          (Channel_Item,
           Source_Remote_Path,
           Target_Remote_Path,
           Directory_Mode,
           File_Mode,
           Options);
      Close_Status := SSH_Lib.Channels.Close (Channel_Item);
      Opened := False;
      return Status_Value;
   exception
      when others =>
         if Opened then
            Close_Status := SSH_Lib.Channels.Close (Channel_Item);
         end if;
         return CryptoLib.Errors.Internal_Error;
   end Copy_Tree;

   function Sync_Directory
     (Session        : in out SSH_Lib.Sessions.Session;
      Direction      : Sync_Direction;
      Remote_Path    : String;
      Local_Path     : String;
      Directory_Mode : String := "0755";
      File_Mode      : String := "0644";
      Options        : Sync_Options := Default_Sync_Options)
      return CryptoLib.Errors.Status
   is
      Channel_Item : SSH_Lib.Channels.Channel;
      Version      : Natural := 0;
      Status_Value : CryptoLib.Errors.Status;
      Close_Status : CryptoLib.Errors.Status;
      Opened       : Boolean := False;
      pragma Unreferenced (Close_Status);
   begin
      Status_Value := Open (Session, Channel_Item, Version);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      Opened := True;
      Status_Value :=
        Sync_Directory
          (Channel_Item,
           Direction,
           Remote_Path,
           Local_Path,
           Directory_Mode,
           File_Mode,
           Options);
      Close_Status := SSH_Lib.Channels.Close (Channel_Item);
      Opened := False;
      return Status_Value;
   exception
      when others =>
         if Opened then
            Close_Status := SSH_Lib.Channels.Close (Channel_Item);
         end if;
         return CryptoLib.Errors.Internal_Error;
   end Sync_Directory;

   function Rename
     (Session  : in out SSH_Lib.Sessions.Session;
      Old_Path : String;
      New_Path : String) return CryptoLib.Errors.Status
   is
      Channel_Item : SSH_Lib.Channels.Channel;
      Version      : Natural := 0;
      Status_Value : CryptoLib.Errors.Status;
      Close_Status : CryptoLib.Errors.Status;
      Opened       : Boolean := False;
      pragma Unreferenced (Close_Status);
   begin
      if not Safe_Remote_Path (Old_Path)
        or else not Safe_Remote_Path (New_Path)
      then
         return CryptoLib.Errors.Invalid_Command;
      end if;
      Status_Value := Open (Session, Channel_Item, Version);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      Opened := True;
      Status_Value := Rename (Channel_Item, Old_Path, New_Path);
      Close_Status := SSH_Lib.Channels.Close (Channel_Item);
      Opened := False;
      return Status_Value;
   exception
      when others =>
         if Opened then
            Close_Status := SSH_Lib.Channels.Close (Channel_Item);
         end if;
         return CryptoLib.Errors.Internal_Error;
   end Rename;

   function Rename
     (Session  : in out SSH_Lib.Sessions.Session;
      Old_Path : String;
      New_Path : String;
      Result   : out SFTP_Result) return CryptoLib.Errors.Status
   is
      Status_Value : constant CryptoLib.Errors.Status :=
        Rename (Session, Old_Path, New_Path);
   begin
      Capture_Result (Status_Value, Result, Rename_Operation);
      return Status_Value;
   end Rename;

   function Read_At
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Offset      : Interfaces.Unsigned_64;
      Length      : Natural;
      Data        : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status
   is
      Item         : Client;
      Status_Value : CryptoLib.Errors.Status;
      Close_Status : CryptoLib.Errors.Status;
      pragma Unreferenced (Close_Status);
   begin
      Status_Value := Open (Session, Item);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      Status_Value := Read_At (Item, Remote_Path, Offset, Length, Data);
      Close_Status := Close (Item);
      return Status_Value;
   exception
      when others =>
         SSH_Lib.Protocol.Buffers.Clear (Data);
         return CryptoLib.Errors.Internal_Error;
   end Read_At;

   function Write_At
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Offset      : Interfaces.Unsigned_64;
      Data        : Ada.Streams.Stream_Element_Array;
      Mode        : String := "0644") return CryptoLib.Errors.Status
   is
      Item         : Client;
      Status_Value : CryptoLib.Errors.Status;
      Close_Status : CryptoLib.Errors.Status;
      pragma Unreferenced (Close_Status);
   begin
      Status_Value := Open (Session, Item);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      Status_Value := Write_At (Item, Remote_Path, Offset, Data, Mode);
      Close_Status := Close (Item);
      return Status_Value;
   exception
      when others =>
         return CryptoLib.Errors.Internal_Error;
   end Write_At;

   function FStat
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Attributes  : out File_Attributes) return CryptoLib.Errors.Status
   is
      Item         : Client;
      Handle       : File_Handle;
      Status_Value : CryptoLib.Errors.Status;
      Close_Status : CryptoLib.Errors.Status;
      pragma Unreferenced (Close_Status);
   begin
      Attributes := (others => <>);
      Status_Value := Open (Session, Item);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      Status_Value :=
        Open_Read (Item.Channel, Remote_Path, Handle, Item.Version);
      if Status_Value = CryptoLib.Errors.Ok then
         Set_Handle_Context (Handle, Item.Version, Item.Extensions);
         Status_Value := FStat (Item.Channel, Handle, Attributes);
         Close_Status := Close (Item.Channel, Handle);
      end if;
      Close_Status := Close (Item);
      return Status_Value;
   exception
      when others =>
         Attributes := (others => <>);
         return CryptoLib.Errors.Internal_Error;
   end FStat;

   function Set_Handle_Permissions
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Mode        : String) return CryptoLib.Errors.Status
   is
      Item         : Client;
      Handle       : File_Handle;
      Status_Value : CryptoLib.Errors.Status;
      Close_Status : CryptoLib.Errors.Status;
      pragma Unreferenced (Close_Status);
   begin
      Status_Value := Open (Session, Item);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      Status_Value :=
        Open_File
          (Item.Channel,
           Remote_Path,
           Handle,
           Read_Write,
           "0644",
           Item.Version);
      if Status_Value = CryptoLib.Errors.Ok then
         Set_Handle_Context (Handle, Item.Version, Item.Extensions);
         Status_Value := Set_Handle_Permissions (Item.Channel, Handle, Mode);
         Close_Status := Close (Item.Channel, Handle);
      end if;
      Close_Status := Close (Item);
      return Status_Value;
   exception
      when others =>
         return CryptoLib.Errors.Internal_Error;
   end Set_Handle_Permissions;

   function Set_Handle_Attributes
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Attributes  : File_Attributes) return CryptoLib.Errors.Status
   is
      Item         : Client;
      Handle       : File_Handle;
      Status_Value : CryptoLib.Errors.Status;
      Close_Status : CryptoLib.Errors.Status;
      pragma Unreferenced (Close_Status);
   begin
      Status_Value := Open (Session, Item);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      Status_Value :=
        Open_File
          (Item.Channel,
           Remote_Path,
           Handle,
           Read_Write,
           "0644",
           Item.Version);
      if Status_Value = CryptoLib.Errors.Ok then
         Set_Handle_Context (Handle, Item.Version, Item.Extensions);
         Status_Value :=
           Set_Handle_Attributes (Item.Channel, Handle, Attributes);
         Close_Status := Close (Item.Channel, Handle);
      end if;
      Close_Status := Close (Item);
      return Status_Value;
   exception
      when others =>
         return CryptoLib.Errors.Internal_Error;
   end Set_Handle_Attributes;

   function Fsync
     (Session : in out SSH_Lib.Sessions.Session; Remote_Path : String)
      return CryptoLib.Errors.Status
   is
      Item         : Client;
      Status_Value : CryptoLib.Errors.Status;
      Close_Status : CryptoLib.Errors.Status;
      pragma Unreferenced (Close_Status);
   begin
      Status_Value := Open (Session, Item);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      Status_Value := Fsync (Item, Remote_Path);
      Close_Status := Close (Item);
      return Status_Value;
   exception
      when others =>
         return CryptoLib.Errors.Internal_Error;
   end Fsync;

   function Expand_Path
     (Item          : in out Client;
      Remote_Path   : String;
      Expanded_Path : out Unbounded_String) return CryptoLib.Errors.Status is
   begin
      Expanded_Path := Null_Unbounded_String;
      if not Is_Open (Item) then
         return CryptoLib.Errors.Invalid_Command;
      elsif not Item.Extensions.Expand_Path then
         return CryptoLib.Errors.Unsupported_Feature;
      end if;
      return Expand_Path (Item.Channel, Remote_Path, Expanded_Path);
   exception
      when others =>
         Expanded_Path := Null_Unbounded_String;
         return CryptoLib.Errors.Internal_Error;
   end Expand_Path;

   function Check_File
     (Item        : in out Client;
      Remote_Path : String;
      Algorithms  : String;
      Offset      : Interfaces.Unsigned_64;
      Length      : Interfaces.Unsigned_64;
      Block_Size  : Interfaces.Unsigned_32;
      Algorithm   : out Unbounded_String;
      Digest      : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status
   is
      Handle       : File_Handle;
      Status_Value : CryptoLib.Errors.Status;
      Close_Status : CryptoLib.Errors.Status;
      pragma Unreferenced (Close_Status);
   begin
      Algorithm := Null_Unbounded_String;
      SSH_Lib.Protocol.Buffers.Clear (Digest);
      if not Item.Opened then
         return CryptoLib.Errors.Channel_Open_Failed;
      elsif not Item.Extensions.Check_File then
         return CryptoLib.Errors.Unsupported_Feature;
      end if;
      Status_Value :=
        Open_Read (Item.Channel, Remote_Path, Handle, Item.Version);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      Set_Handle_Context (Handle, Item.Version, Item.Extensions);
      Status_Value :=
        Check_File
          (Item.Channel,
           Handle,
           Algorithms,
           Offset,
           Length,
           Block_Size,
           Algorithm,
           Digest);
      Close_Status := Close (Item.Channel, Handle);
      return Status_Value;
   exception
      when others =>
         Algorithm := Null_Unbounded_String;
         SSH_Lib.Protocol.Buffers.Clear (Digest);
         return CryptoLib.Errors.Internal_Error;
   end Check_File;

   function Check_File
     (Item        : in out Client;
      Remote_Path : String;
      Algorithms  : String;
      Offset      : Interfaces.Unsigned_64;
      Length      : Interfaces.Unsigned_64;
      Block_Size  : Interfaces.Unsigned_32;
      Algorithm   : out Unbounded_String;
      Digest      : out SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Result      : out SFTP_Result) return CryptoLib.Errors.Status
   is
      Status_Value : constant CryptoLib.Errors.Status :=
        Check_File
          (Item, Remote_Path, Algorithms, Offset, Length, Block_Size,
           Algorithm, Digest);
   begin
      Capture_Result (Status_Value, Result, Check_File_Operation);
      return Status_Value;
   end Check_File;

   function Check_File
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Algorithms  : String;
      Offset      : Interfaces.Unsigned_64;
      Length      : Interfaces.Unsigned_64;
      Block_Size  : Interfaces.Unsigned_32;
      Algorithm   : out Unbounded_String;
      Digest      : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status
   is
      Item         : Client;
      Status_Value : CryptoLib.Errors.Status;
      Close_Status : CryptoLib.Errors.Status;
      pragma Unreferenced (Close_Status);
   begin
      Algorithm := Null_Unbounded_String;
      SSH_Lib.Protocol.Buffers.Clear (Digest);
      Status_Value := Open (Session, Item);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      Status_Value :=
        Check_File
          (Item,
           Remote_Path,
           Algorithms,
           Offset,
           Length,
           Block_Size,
           Algorithm,
           Digest);
      Close_Status := Close (Item);
      return Status_Value;
   exception
      when others =>
         Algorithm := Null_Unbounded_String;
         SSH_Lib.Protocol.Buffers.Clear (Digest);
         return CryptoLib.Errors.Internal_Error;
   end Check_File;

   function Check_File
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Algorithms  : String;
      Offset      : Interfaces.Unsigned_64;
      Length      : Interfaces.Unsigned_64;
      Block_Size  : Interfaces.Unsigned_32;
      Algorithm   : out Unbounded_String;
      Digest      : out SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Result      : out SFTP_Result) return CryptoLib.Errors.Status
   is
      Status_Value : constant CryptoLib.Errors.Status :=
        Check_File
          (Session, Remote_Path, Algorithms, Offset, Length, Block_Size,
           Algorithm, Digest);
   begin
      Capture_Result (Status_Value, Result, Check_File_Operation);
      return Status_Value;
   end Check_File;

   function Check_File_Info
     (Item        : in out Client;
      Remote_Path : String;
      Algorithms  : String;
      Offset      : Interfaces.Unsigned_64 := 0;
      Length      : Interfaces.Unsigned_64 := 0;
      Block_Size  : Interfaces.Unsigned_32 := 0) return Check_File_Result
   is
      Info         : Check_File_Result;
      Status_Value : CryptoLib.Errors.Status;
   begin
      Status_Value :=
        Check_File
          (Item,
           Remote_Path,
           Algorithms,
           Offset,
           Length,
           Block_Size,
           Info.Algorithm,
           Info.Digest,
           Info.Result);
      if Info.Result.Status /= Status_Value then
         Capture_Result (Status_Value, Info.Result, Check_File_Operation);
      end if;
      return Info;
   exception
      when others =>
         SSH_Lib.Protocol.Buffers.Clear (Info.Digest);
         Info.Algorithm := Null_Unbounded_String;
         Capture_Result
           (CryptoLib.Errors.Internal_Error, Info.Result, Check_File_Operation);
         return Info;
   end Check_File_Info;

   function Check_File_Info
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Algorithms  : String;
      Offset      : Interfaces.Unsigned_64 := 0;
      Length      : Interfaces.Unsigned_64 := 0;
      Block_Size  : Interfaces.Unsigned_32 := 0) return Check_File_Result
   is
      Info         : Check_File_Result;
      Status_Value : CryptoLib.Errors.Status;
   begin
      Status_Value :=
        Check_File
          (Session,
           Remote_Path,
           Algorithms,
           Offset,
           Length,
           Block_Size,
           Info.Algorithm,
           Info.Digest,
           Info.Result);
      if Info.Result.Status /= Status_Value then
         Capture_Result (Status_Value, Info.Result, Check_File_Operation);
      end if;
      return Info;
   exception
      when others =>
         SSH_Lib.Protocol.Buffers.Clear (Info.Digest);
         Info.Algorithm := Null_Unbounded_String;
         Capture_Result
           (CryptoLib.Errors.Internal_Error, Info.Result, Check_File_Operation);
         return Info;
   end Check_File_Info;

   function Copy_File_Range
     (Session            : in out SSH_Lib.Sessions.Session;
      Source_Remote_Path : String;
      Target_Remote_Path : String;
      Source_Offset      : Interfaces.Unsigned_64;
      Length             : Interfaces.Unsigned_64;
      Target_Offset      : Interfaces.Unsigned_64 := 0;
      Mode               : String := "0644") return CryptoLib.Errors.Status
   is
      Item          : Client;
      Source_Handle : File_Handle;
      Target_Handle : File_Handle;
      Status_Value  : CryptoLib.Errors.Status;
      Close_Status  : CryptoLib.Errors.Status;
      pragma Unreferenced (Close_Status);
   begin
      Status_Value := Open (Session, Item);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      elsif not Item.Extensions.Copy_Data then
         Close_Status := Close (Item);
         return CryptoLib.Errors.Unsupported_Feature;
      end if;

      Status_Value :=
        Open_Read
          (Item.Channel, Source_Remote_Path, Source_Handle, Item.Version);
      if Status_Value = CryptoLib.Errors.Ok then
         Set_Handle_Context (Source_Handle, Item.Version, Item.Extensions);
         Status_Value :=
           Open_File
             (Item.Channel,
              Target_Remote_Path,
              Target_Handle,
              Write_No_Truncate,
              Mode,
              Item.Version);
         if Status_Value = CryptoLib.Errors.Ok then
            Set_Handle_Context (Target_Handle, Item.Version, Item.Extensions);
         end if;
      end if;
      if Status_Value = CryptoLib.Errors.Ok then
         Status_Value :=
           Copy_Data
             (Item.Channel,
              Source_Handle,
              Source_Offset,
              Length,
              Target_Handle,
              Target_Offset);
      end if;
      if Is_Open (Target_Handle) then
         Close_Status := Close (Item.Channel, Target_Handle);
      end if;
      if Is_Open (Source_Handle) then
         Close_Status := Close (Item.Channel, Source_Handle);
      end if;
      Close_Status := Close (Item);
      return Status_Value;
   exception
      when others =>
         return CryptoLib.Errors.Internal_Error;
   end Copy_File_Range;

   function Posix_Rename
     (Session  : in out SSH_Lib.Sessions.Session;
      Old_Path : String;
      New_Path : String) return CryptoLib.Errors.Status
   is
      Channel_Item : SSH_Lib.Channels.Channel;
      Version      : Natural := 0;
      Extensions   : Extension_Info;
      Status_Value : CryptoLib.Errors.Status;
      Close_Status : CryptoLib.Errors.Status;
      Opened       : Boolean := False;
      pragma Unreferenced (Close_Status);
   begin
      if not Safe_Remote_Path (Old_Path)
        or else not Safe_Remote_Path (New_Path)
      then
         return CryptoLib.Errors.Invalid_Command;
      end if;
      Status_Value := Open (Session, Channel_Item, Version, Extensions);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      Opened := True;
      if not Extensions.Posix_Rename then
         Close_Status := SSH_Lib.Channels.Close (Channel_Item);
         Opened := False;
         return CryptoLib.Errors.Unsupported_Feature;
      end if;
      Status_Value := Posix_Rename (Channel_Item, Old_Path, New_Path);
      Close_Status := SSH_Lib.Channels.Close (Channel_Item);
      Opened := False;
      return Status_Value;
   exception
      when others =>
         if Opened then
            Close_Status := SSH_Lib.Channels.Close (Channel_Item);
         end if;
         return CryptoLib.Errors.Internal_Error;
   end Posix_Rename;

   function Hardlink
     (Session  : in out SSH_Lib.Sessions.Session;
      Old_Path : String;
      New_Path : String) return CryptoLib.Errors.Status
   is
      Channel_Item : SSH_Lib.Channels.Channel;
      Version      : Natural := 0;
      Extensions   : Extension_Info;
      Status_Value : CryptoLib.Errors.Status;
      Close_Status : CryptoLib.Errors.Status;
      Opened       : Boolean := False;
      pragma Unreferenced (Close_Status);
   begin
      if not Safe_Remote_Path (Old_Path)
        or else not Safe_Remote_Path (New_Path)
      then
         return CryptoLib.Errors.Invalid_Command;
      end if;
      Status_Value := Open (Session, Channel_Item, Version, Extensions);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      Opened := True;
      if not Extensions.Hardlink then
         Close_Status := SSH_Lib.Channels.Close (Channel_Item);
         Opened := False;
         return CryptoLib.Errors.Unsupported_Feature;
      end if;
      Status_Value := Hardlink (Channel_Item, Old_Path, New_Path);
      Close_Status := SSH_Lib.Channels.Close (Channel_Item);
      Opened := False;
      return Status_Value;
   exception
      when others =>
         if Opened then
            Close_Status := SSH_Lib.Channels.Close (Channel_Item);
         end if;
         return CryptoLib.Errors.Internal_Error;
   end Hardlink;

   function Expand_Path
     (Session       : in out SSH_Lib.Sessions.Session;
      Remote_Path   : String;
      Expanded_Path : out Unbounded_String) return CryptoLib.Errors.Status
   is
      Channel_Item : SSH_Lib.Channels.Channel;
      Version      : Natural := 0;
      Extensions   : Extension_Info;
      Status_Value : CryptoLib.Errors.Status;
      Close_Status : CryptoLib.Errors.Status;
      Opened       : Boolean := False;
      pragma Unreferenced (Close_Status);
   begin
      Expanded_Path := Null_Unbounded_String;
      if not Safe_Remote_Path (Remote_Path) then
         return CryptoLib.Errors.Invalid_Command;
      end if;
      Status_Value := Open (Session, Channel_Item, Version, Extensions);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      Opened := True;
      if not Extensions.Expand_Path then
         Close_Status := SSH_Lib.Channels.Close (Channel_Item);
         Opened := False;
         return CryptoLib.Errors.Unsupported_Feature;
      end if;
      Status_Value := Expand_Path (Channel_Item, Remote_Path, Expanded_Path);
      Close_Status := SSH_Lib.Channels.Close (Channel_Item);
      Opened := False;
      return Status_Value;
   exception
      when others =>
         if Opened then
            Close_Status := SSH_Lib.Channels.Close (Channel_Item);
         end if;
         Expanded_Path := Null_Unbounded_String;
         return CryptoLib.Errors.Internal_Error;
   end Expand_Path;

   function LSet_Attributes
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Attributes  : File_Attributes) return CryptoLib.Errors.Status
   is
      Channel_Item : SSH_Lib.Channels.Channel;
      Version      : Natural := 0;
      Extensions   : Extension_Info;
      Status_Value : CryptoLib.Errors.Status;
      Close_Status : CryptoLib.Errors.Status;
      Opened       : Boolean := False;
      pragma Unreferenced (Close_Status);
   begin
      if not Safe_Remote_Path (Remote_Path)
        or else not Has_Attributes (Attributes)
      then
         return CryptoLib.Errors.Invalid_Command;
      end if;
      Status_Value := Open (Session, Channel_Item, Version, Extensions);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      Opened := True;
      if not Extensions.LSetStat then
         Close_Status := SSH_Lib.Channels.Close (Channel_Item);
         Opened := False;
         return CryptoLib.Errors.Unsupported_Feature;
      end if;
      Status_Value := LSet_Attributes (Channel_Item, Remote_Path, Attributes);
      Close_Status := SSH_Lib.Channels.Close (Channel_Item);
      Opened := False;
      return Status_Value;
   exception
      when others =>
         if Opened then
            Close_Status := SSH_Lib.Channels.Close (Channel_Item);
         end if;
         return CryptoLib.Errors.Internal_Error;
   end LSet_Attributes;

   function StatVFS
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Stats       : out File_System_Stats) return CryptoLib.Errors.Status
   is
      Channel_Item : SSH_Lib.Channels.Channel;
      Version      : Natural := 0;
      Extensions   : Extension_Info;
      Status_Value : CryptoLib.Errors.Status;
      Close_Status : CryptoLib.Errors.Status;
      Opened       : Boolean := False;
      pragma Unreferenced (Close_Status);
   begin
      Stats := (others => 0);
      if not Safe_Remote_Path (Remote_Path) then
         return CryptoLib.Errors.Invalid_Command;
      end if;
      Status_Value := Open (Session, Channel_Item, Version, Extensions);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      Opened := True;
      if not Extensions.StatVFS then
         Close_Status := SSH_Lib.Channels.Close (Channel_Item);
         Opened := False;
         return CryptoLib.Errors.Unsupported_Feature;
      end if;
      Status_Value := StatVFS (Channel_Item, Remote_Path, Stats);
      Close_Status := SSH_Lib.Channels.Close (Channel_Item);
      Opened := False;
      return Status_Value;
   exception
      when others =>
         if Opened then
            Close_Status := SSH_Lib.Channels.Close (Channel_Item);
         end if;
         Stats := (others => 0);
         return CryptoLib.Errors.Internal_Error;
   end StatVFS;

   function StatVFS
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Stats       : out File_System_Stats;
      Result      : out SFTP_Result) return CryptoLib.Errors.Status
   is
      Status_Value : constant CryptoLib.Errors.Status :=
        StatVFS (Session, Remote_Path, Stats);
   begin
      Capture_Result (Status_Value, Result, StatVFS_Operation);
      return Status_Value;
   end StatVFS;

   function StatVFS_Info
     (Channel     : in out SSH_Lib.Channels.Channel;
      Remote_Path : String) return StatVFS_Result
   is
      Info         : StatVFS_Result;
      Status_Value : CryptoLib.Errors.Status;
   begin
      Status_Value := StatVFS (Channel, Remote_Path, Info.Stats, Info.Result);
      if Info.Result.Status /= Status_Value then
         Capture_Result (Status_Value, Info.Result, StatVFS_Operation);
      end if;
      return Info;
   exception
      when others =>
         Info.Stats := (others => 0);
         Capture_Result
           (CryptoLib.Errors.Internal_Error, Info.Result, StatVFS_Operation);
         return Info;
   end StatVFS_Info;

   function StatVFS_Info
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String) return StatVFS_Result
   is
      Info         : StatVFS_Result;
      Status_Value : CryptoLib.Errors.Status;
   begin
      Status_Value := StatVFS (Session, Remote_Path, Info.Stats, Info.Result);
      if Info.Result.Status /= Status_Value then
         Capture_Result (Status_Value, Info.Result, StatVFS_Operation);
      end if;
      return Info;
   exception
      when others =>
         Info.Stats := (others => 0);
         Capture_Result
           (CryptoLib.Errors.Internal_Error, Info.Result, StatVFS_Operation);
         return Info;
   end StatVFS_Info;

   function Limits
     (Session : in out SSH_Lib.Sessions.Session; Values : out Server_Limits)
      return CryptoLib.Errors.Status
   is
      Channel_Item : SSH_Lib.Channels.Channel;
      Version      : Natural := 0;
      Extensions   : Extension_Info;
      Status_Value : CryptoLib.Errors.Status;
      Close_Status : CryptoLib.Errors.Status;
      Opened       : Boolean := False;
      pragma Unreferenced (Close_Status);
   begin
      Values := (others => 0);
      Status_Value := Open (Session, Channel_Item, Version, Extensions);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      Opened := True;
      if not Extensions.Limits then
         Close_Status := SSH_Lib.Channels.Close (Channel_Item);
         Opened := False;
         return CryptoLib.Errors.Unsupported_Feature;
      end if;
      Status_Value := Limits (Channel_Item, Values);
      Close_Status := SSH_Lib.Channels.Close (Channel_Item);
      Opened := False;
      return Status_Value;
   exception
      when others =>
         if Opened then
            Close_Status := SSH_Lib.Channels.Close (Channel_Item);
         end if;
         Values := (others => 0);
         return CryptoLib.Errors.Internal_Error;
   end Limits;

   function Extended_Request
     (Session        : in out SSH_Lib.Sessions.Session;
      Extension_Name : String;
      Payload        : Stream_Element_Array;
      Reply_Data     : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status
   is
      Channel_Item : SSH_Lib.Channels.Channel;
      Version      : Natural := 0;
      Status_Value : CryptoLib.Errors.Status;
      Close_Status : CryptoLib.Errors.Status;
      Opened       : Boolean := False;
      pragma Unreferenced (Close_Status);
   begin
      SSH_Lib.Protocol.Buffers.Clear (Reply_Data);
      if Extension_Name'Length = 0 then
         return CryptoLib.Errors.Invalid_Command;
      end if;
      Status_Value := Open (Session, Channel_Item, Version);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      Opened := True;
      Status_Value :=
        Extended_Request (Channel_Item, Extension_Name, Payload, Reply_Data);
      Close_Status := SSH_Lib.Channels.Close (Channel_Item);
      Opened := False;
      return Status_Value;
   exception
      when others =>
         if Opened then
            Close_Status := SSH_Lib.Channels.Close (Channel_Item);
         end if;
         SSH_Lib.Protocol.Buffers.Clear (Reply_Data);
         return CryptoLib.Errors.Internal_Error;
   end Extended_Request;

   function Extended_Request
     (Item           : in out Client;
      Extension_Name : String;
      Payload        : Stream_Element_Array;
      Reply_Data     : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status is
   begin
      SSH_Lib.Protocol.Buffers.Clear (Reply_Data);
      if not Item.Opened then
         return CryptoLib.Errors.Channel_Open_Failed;
      end if;
      return Extended_Request
        (Item.Channel, Extension_Name, Payload, Reply_Data);
   exception
      when others =>
         SSH_Lib.Protocol.Buffers.Clear (Reply_Data);
         return CryptoLib.Errors.Internal_Error;
   end Extended_Request;

   function Extended_Request_Info
     (Channel        : in out SSH_Lib.Channels.Channel;
      Extension_Name : String;
      Payload        : Stream_Element_Array)
      return Extended_Request_Result
   is
      Info         : Extended_Request_Result;
      Status_Value : CryptoLib.Errors.Status;
   begin
      SSH_Lib.Protocol.Buffers.Clear (Info.Reply_Data);
      Status_Value :=
        Extended_Request (Channel, Extension_Name, Payload, Info.Reply_Data);
      Capture_Result (Status_Value, Info.Result, Extended_Operation);
      return Info;
   exception
      when others =>
         SSH_Lib.Protocol.Buffers.Clear (Info.Reply_Data);
         Capture_Result
           (CryptoLib.Errors.Internal_Error, Info.Result, Extended_Operation);
         return Info;
   end Extended_Request_Info;

   function Extended_Request_Info
     (Session        : in out SSH_Lib.Sessions.Session;
      Extension_Name : String;
      Payload        : Stream_Element_Array)
      return Extended_Request_Result
   is
      Info         : Extended_Request_Result;
      Status_Value : CryptoLib.Errors.Status;
   begin
      SSH_Lib.Protocol.Buffers.Clear (Info.Reply_Data);
      Status_Value :=
        Extended_Request (Session, Extension_Name, Payload, Info.Reply_Data);
      Capture_Result (Status_Value, Info.Result, Extended_Operation);
      return Info;
   exception
      when others =>
         SSH_Lib.Protocol.Buffers.Clear (Info.Reply_Data);
         Capture_Result
           (CryptoLib.Errors.Internal_Error, Info.Result, Extended_Operation);
         return Info;
   end Extended_Request_Info;

   function Extended_Request_Info
     (Item           : in out Client;
      Extension_Name : String;
      Payload        : Stream_Element_Array)
      return Extended_Request_Result
   is
      Info         : Extended_Request_Result;
      Status_Value : CryptoLib.Errors.Status;
   begin
      SSH_Lib.Protocol.Buffers.Clear (Info.Reply_Data);
      Status_Value :=
        Extended_Request (Item, Extension_Name, Payload, Info.Reply_Data);
      Capture_Result (Status_Value, Info.Result, Extended_Operation);
      return Info;
   exception
      when others =>
         SSH_Lib.Protocol.Buffers.Clear (Info.Reply_Data);
         Capture_Result
           (CryptoLib.Errors.Internal_Error, Info.Result, Extended_Operation);
         return Info;
   end Extended_Request_Info;

   function Read_Link
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Target_Path : out Unbounded_String) return CryptoLib.Errors.Status
   is
      Channel_Item : SSH_Lib.Channels.Channel;
      Version      : Natural := 0;
      Status_Value : CryptoLib.Errors.Status;
      Close_Status : CryptoLib.Errors.Status;
      Opened       : Boolean := False;
      pragma Unreferenced (Close_Status);
   begin
      Target_Path := Null_Unbounded_String;
      if not Safe_Remote_Path (Remote_Path) then
         return CryptoLib.Errors.Invalid_Command;
      end if;
      Status_Value := Open (Session, Channel_Item, Version);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      Opened := True;
      Status_Value := Read_Link (Channel_Item, Remote_Path, Target_Path);
      Close_Status := SSH_Lib.Channels.Close (Channel_Item);
      Opened := False;
      return Status_Value;
   exception
      when others =>
         if Opened then
            Close_Status := SSH_Lib.Channels.Close (Channel_Item);
         end if;
         Target_Path := Null_Unbounded_String;
         return CryptoLib.Errors.Internal_Error;
   end Read_Link;

   function Create_Symlink
     (Session     : in out SSH_Lib.Sessions.Session;
      Target_Path : String;
      Link_Path   : String) return CryptoLib.Errors.Status
   is
      Channel_Item : SSH_Lib.Channels.Channel;
      Version      : Natural := 0;
      Status_Value : CryptoLib.Errors.Status;
      Close_Status : CryptoLib.Errors.Status;
      Opened       : Boolean := False;
      pragma Unreferenced (Close_Status);
   begin
      if not Safe_Remote_Path (Target_Path)
        or else not Safe_Remote_Path (Link_Path)
      then
         return CryptoLib.Errors.Invalid_Command;
      end if;
      Status_Value := Open (Session, Channel_Item, Version);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      Opened := True;
      Status_Value := Create_Symlink (Channel_Item, Target_Path, Link_Path);
      Close_Status := SSH_Lib.Channels.Close (Channel_Item);
      Opened := False;
      return Status_Value;
   exception
      when others =>
         if Opened then
            Close_Status := SSH_Lib.Channels.Close (Channel_Item);
         end if;
         return CryptoLib.Errors.Internal_Error;
   end Create_Symlink;

   function Create_Link
     (Session  : in out SSH_Lib.Sessions.Session;
      New_Link : String;
      Existing : String;
      Symbolic : Boolean := True) return CryptoLib.Errors.Status
   is
      Item         : Client;
      Status_Value : CryptoLib.Errors.Status;
      Close_Status : CryptoLib.Errors.Status;
      pragma Unreferenced (Close_Status);
   begin
      Status_Value := Open (Session, Item, Maximum_Protocol_Version);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      Status_Value := Create_Link (Item, New_Link, Existing, Symbolic);
      Close_Status := Close (Item);
      return Status_Value;
   exception
      when others =>
         return CryptoLib.Errors.Internal_Error;
   end Create_Link;

   function Text_Seek
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Line_Number : Interfaces.Unsigned_64) return CryptoLib.Errors.Status
   is
      Item         : Client;
      Status_Value : CryptoLib.Errors.Status;
      Close_Status : CryptoLib.Errors.Status;
      pragma Unreferenced (Close_Status);
   begin
      Status_Value := Open (Session, Item, Maximum_Protocol_Version);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      Status_Value := Text_Seek (Item, Remote_Path, Line_Number);
      Close_Status := Close (Item);
      return Status_Value;
   exception
      when others =>
         return CryptoLib.Errors.Internal_Error;
   end Text_Seek;

   function Lock_Range
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Offset      : Interfaces.Unsigned_64;
      Length      : Interfaces.Unsigned_64;
      Lock_Mask   : Interfaces.Unsigned_32) return CryptoLib.Errors.Status
   is
      Item         : Client;
      Status_Value : CryptoLib.Errors.Status;
      Close_Status : CryptoLib.Errors.Status;
      pragma Unreferenced (Close_Status);
   begin
      Status_Value := Open (Session, Item, Maximum_Protocol_Version);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      Status_Value :=
        Lock_Range (Item, Remote_Path, Offset, Length, Lock_Mask);
      Close_Status := Close (Item);
      return Status_Value;
   exception
      when others =>
         return CryptoLib.Errors.Internal_Error;
   end Lock_Range;

   function Unlock_Range
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Offset      : Interfaces.Unsigned_64;
      Length      : Interfaces.Unsigned_64) return CryptoLib.Errors.Status
   is
      Item         : Client;
      Status_Value : CryptoLib.Errors.Status;
      Close_Status : CryptoLib.Errors.Status;
      pragma Unreferenced (Close_Status);
   begin
      Status_Value := Open (Session, Item, Maximum_Protocol_Version);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      Status_Value := Unlock_Range (Item, Remote_Path, Offset, Length);
      Close_Status := Close (Item);
      return Status_Value;
   exception
      when others =>
         return CryptoLib.Errors.Internal_Error;
   end Unlock_Range;

   function Upload_Stream
     (Channel     : in out SSH_Lib.Channels.Channel;
      Remote_Path : String;
      Size        : Interfaces.Unsigned_64;
      Reader      : Stream_Reader_Access;
      Mode        : String := "0644";
      Options     : Transfer_Options := Default_Transfer_Options)
      return CryptoLib.Errors.Status
   is
      Handle        : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Chunk         : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Reply_Packet  : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Target_Path   : Unbounded_String := To_Unbounded_String (Remote_Path);
      Offset_Value  : Interfaces.Unsigned_64 := 0;
      Request_Id    : Interfaces.Unsigned_32 := 2;
      Status_Value  : CryptoLib.Errors.Status;
      Remote_Opened : Boolean := False;
   begin
      Status_Value := Validate_Upload_Target (Remote_Path, Mode);
      if Status_Value /= CryptoLib.Errors.Ok or else Reader = null then
         return CryptoLib.Errors.Invalid_Command;
      end if;

      if Options.Atomic_Upload then
         declare
            Temp_Path : constant String := Remote_Temporary_Path (Remote_Path);
         begin
            if Temp_Path'Length = 0 then
               return CryptoLib.Errors.Invalid_Command;
            end if;
            Target_Path := To_Unbounded_String (Temp_Path);
            Status_Value := Remove_File (Channel, Temp_Path);
         end;
      end if;

      Status_Value :=
        Open_Remote_File (Channel, To_String (Target_Path), Mode, Handle);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      Remote_Opened := True;

      while Offset_Value < Size loop
         declare
            Remaining    : constant Interfaces.Unsigned_64 :=
              Size - Offset_Value;
            Maximum_Read : constant Natural :=
              (if Remaining < Interfaces.Unsigned_64 (Upload_Chunk_Size)
               then Natural (Remaining)
               else Upload_Chunk_Size);
         begin
            SSH_Lib.Protocol.Buffers.Clear (Chunk);
            Status_Value := Reader (Offset_Value, Maximum_Read, Chunk);
            if Status_Value /= CryptoLib.Errors.Ok then
               Close_Remote_File_Best_Effort (Channel, Handle, Request_Id);
               return Status_Value;
            end if;

            declare
               Chunk_Data : constant Stream_Element_Array :=
                 SSH_Lib.Protocol.Buffers.To_Array (Chunk);
            begin
               if Chunk_Data'Length = 0
                 or else Chunk_Data'Length > Maximum_Read
                 or else Interfaces.Unsigned_64 (Chunk_Data'Length) > Remaining
               then
                  Close_Remote_File_Best_Effort (Channel, Handle, Request_Id);
                  return CryptoLib.Errors.Read_Failed;
               end if;

               Status_Value :=
                 Send_Packet
                   (Channel,
                    Encode_Write_Request
                      (Request_Id, Handle, Offset_Value, Chunk_Data));
               if Status_Value /= CryptoLib.Errors.Ok then
                  Close_Remote_File_Best_Effort
                    (Channel, Handle, Request_Id + 1);
                  return Status_Value;
               end if;

               Status_Value := Read_Packet (Channel, Reply_Packet);
               if Status_Value /= CryptoLib.Errors.Ok then
                  Close_Remote_File_Best_Effort
                    (Channel, Handle, Request_Id + 1);
                  return Status_Value;
               end if;
               Status_Value := Parse_Status_Packet (Reply_Packet, Request_Id);
               if Status_Value /= CryptoLib.Errors.Ok then
                  Close_Remote_File_Best_Effort
                    (Channel, Handle, Request_Id + 1);
                  return Status_Value;
               end if;

               Offset_Value :=
                 Offset_Value + Interfaces.Unsigned_64 (Chunk_Data'Length);
               Request_Id := Request_Id + 1;
            end;
         end;
      end loop;

      Status_Value := Close_Remote_File (Channel, Handle, Request_Id);
      Remote_Opened := False;
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      if Options.Verify_After_Transfer then
         Status_Value :=
           Verify_Remote_Size (Channel, To_String (Target_Path), Size);
         if Status_Value /= CryptoLib.Errors.Ok then
            return Status_Value;
         end if;
      end if;
      if Options.Atomic_Upload then
         Status_Value :=
           Rename (Channel, To_String (Target_Path), Remote_Path);
         if Status_Value /= CryptoLib.Errors.Ok then
            return Status_Value;
         end if;
         if Options.Verify_After_Transfer then
            return Verify_Remote_Size (Channel, Remote_Path, Size);
         end if;
      end if;
      return CryptoLib.Errors.Ok;
   exception
      when others =>
         if Remote_Opened then
            Close_Remote_File_Best_Effort (Channel, Handle, Request_Id);
         end if;
         return CryptoLib.Errors.Internal_Error;
   end Upload_Stream;

   function Resume_Upload_File
     (Channel     : in out SSH_Lib.Channels.Channel;
      Remote_Path : String;
      Local_Path  : String;
      Mode        : String := "0644";
      Options     : Transfer_Options := Default_Transfer_Options)
      return CryptoLib.Errors.Status
   is
      Attributes    : File_Attributes;
      Handle        : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      File_Item     : Ada.Streams.Stream_IO.File_Type;
      Local_Size    : Natural := 0;
      Remote_Size   : Interfaces.Unsigned_64 := 0;
      Write_Size    : Natural := 0;
      Request_Id    : Interfaces.Unsigned_32 := 2;
      Status_Value  : CryptoLib.Errors.Status;
      Remote_Opened : Boolean := False;
   begin
      if Options.Atomic_Upload then
         return CryptoLib.Errors.Invalid_Command;
      end if;
      Status_Value := Validate_Upload_Target (Remote_Path, Mode);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      Status_Value := Local_File_Ready (Local_Path, Local_Size);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;

      Status_Value := Stat (Channel, Remote_Path, Attributes);
      if Status_Value = CryptoLib.Errors.Ok then
         if not Attributes.Size_Known then
            return CryptoLib.Errors.Read_Failed;
         end if;
         Remote_Size := Attributes.Size;
      elsif Status_Value = CryptoLib.Errors.No_Such_File then
         Remote_Size := 0;
      else
         return Status_Value;
      end if;

      if Remote_Size > Interfaces.Unsigned_64 (Local_Size) then
         return CryptoLib.Errors.Invalid_Command;
      elsif Remote_Size = Interfaces.Unsigned_64 (Local_Size) then
         if Options.Verify_After_Transfer then
            return Verify_Remote_Size (Channel, Remote_Path, Remote_Size);
         end if;
         return CryptoLib.Errors.Ok;
      end if;
      Write_Size := Local_Size - Natural (Remote_Size);

      Status_Value :=
        Open_Remote_File_Mode
          (Channel, Remote_Path, Write_No_Truncate, Mode, Handle);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      Remote_Opened := True;

      Ada.Streams.Stream_IO.Open
        (File_Item, Ada.Streams.Stream_IO.In_File, Local_Path);
      Status_Value :=
        Pipelined_Write_File_From_Offset
          (Channel,
           Handle,
           File_Item,
           Remote_Size,
           Write_Size,
           2,
           Effective_Pipeline_Depth (Options),
           Request_Id,
           Effective_Write_Chunk_Size (Options));
      Ada.Streams.Stream_IO.Close (File_Item);
      if Status_Value /= CryptoLib.Errors.Ok then
         Close_Remote_File_Best_Effort (Channel, Handle, Request_Id);
         return Status_Value;
      end if;

      Status_Value := Close_Remote_File (Channel, Handle, Request_Id);
      Remote_Opened := False;
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      if Options.Verify_After_Transfer then
         return
           Verify_Remote_Size
             (Channel, Remote_Path, Interfaces.Unsigned_64 (Local_Size));
      end if;
      return CryptoLib.Errors.Ok;
   exception
      when others =>
         if Ada.Streams.Stream_IO.Is_Open (File_Item) then
            Ada.Streams.Stream_IO.Close (File_Item);
         end if;
         if Remote_Opened then
            Close_Remote_File_Best_Effort (Channel, Handle, Request_Id);
         end if;
         return CryptoLib.Errors.Internal_Error;
   end Resume_Upload_File;

   function Resume_Upload_File
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Local_Path  : String;
      Mode        : String := "0644";
      Options     : Transfer_Options := Default_Transfer_Options)
      return CryptoLib.Errors.Status
   is
      Size_Value   : Natural := 0;
      Status_Value : CryptoLib.Errors.Status := CryptoLib.Errors.Internal_Error;
   begin
      if Options.Atomic_Upload then
         return CryptoLib.Errors.Invalid_Command;
      end if;
      Status_Value := Validate_Upload_Target (Remote_Path, Mode);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      Status_Value := Local_File_Ready (Local_Path, Size_Value);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;

      for Attempt in 0 .. Options.Retry_Count loop
         declare
            Channel_Item : SSH_Lib.Channels.Channel;
            Version      : Natural := 0;
            Close_Status : CryptoLib.Errors.Status;
            Opened       : Boolean := False;
            pragma Unreferenced (Close_Status);
         begin
            Status_Value := Open (Session, Channel_Item, Version);
            if Status_Value /= CryptoLib.Errors.Ok then
               if Attempt = Options.Retry_Count
                 or else not Retryable_Transfer_Status (Status_Value)
               then
                  return Status_Value;
               end if;
            else
               Opened := True;
               Status_Value :=
                 Resume_Upload_File
                   (Channel_Item, Remote_Path, Local_Path, Mode, Options);
               Close_Status := SSH_Lib.Channels.Close (Channel_Item);
               Opened := False;
               if Status_Value = CryptoLib.Errors.Ok
                 or else Attempt = Options.Retry_Count
                 or else not Retryable_Transfer_Status (Status_Value)
               then
                  return Status_Value;
               end if;
            end if;
         exception
            when others =>
               if Opened then
                  Close_Status := SSH_Lib.Channels.Close (Channel_Item);
               end if;
               return CryptoLib.Errors.Internal_Error;
         end;
      end loop;
      return Status_Value;
   end Resume_Upload_File;

   function Upload_Stream
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Size        : Interfaces.Unsigned_64;
      Reader      : Stream_Reader_Access;
      Mode        : String := "0644";
      Options     : Transfer_Options := Default_Transfer_Options)
      return CryptoLib.Errors.Status
   is
      Status_Value : CryptoLib.Errors.Status := CryptoLib.Errors.Internal_Error;
   begin
      Status_Value := Validate_Upload_Target (Remote_Path, Mode);
      if Status_Value /= CryptoLib.Errors.Ok or else Reader = null then
         return CryptoLib.Errors.Invalid_Command;
      end if;

      for Attempt in 0 .. Options.Retry_Count loop
         declare
            Channel_Item : SSH_Lib.Channels.Channel;
            Version      : Natural := 0;
            Close_Status : CryptoLib.Errors.Status;
            Opened       : Boolean := False;
            pragma Unreferenced (Close_Status);
         begin
            Status_Value := Open (Session, Channel_Item, Version);
            if Status_Value /= CryptoLib.Errors.Ok then
               if Attempt = Options.Retry_Count
                 or else not Retryable_Transfer_Status (Status_Value)
               then
                  return Status_Value;
               end if;
            else
               Opened := True;
               Status_Value :=
                 Upload_Stream
                   (Channel_Item, Remote_Path, Size, Reader, Mode, Options);
               Close_Status := SSH_Lib.Channels.Close (Channel_Item);
               Opened := False;
               if Status_Value = CryptoLib.Errors.Ok
                 or else Attempt = Options.Retry_Count
                 or else not Retryable_Transfer_Status (Status_Value)
               then
                  return Status_Value;
               end if;
            end if;
         exception
            when others =>
               if Opened then
                  Close_Status := SSH_Lib.Channels.Close (Channel_Item);
               end if;
               return CryptoLib.Errors.Internal_Error;
         end;
      end loop;
      return Status_Value;
   end Upload_Stream;

   function Upload_Data
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Data        : Ada.Streams.Stream_Element_Array;
      Mode        : String := "0644";
      Options     : Transfer_Options := Default_Transfer_Options)
      return CryptoLib.Errors.Status
   is
      Status_Value : CryptoLib.Errors.Status := CryptoLib.Errors.Internal_Error;
   begin
      Status_Value := Validate_Upload_Target (Remote_Path, Mode);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;

      for Attempt in 0 .. Options.Retry_Count loop
         declare
            Channel_Item : SSH_Lib.Channels.Channel;
            Version      : Natural := 0;
            Close_Status : CryptoLib.Errors.Status;
            Opened       : Boolean := False;
            pragma Unreferenced (Close_Status);
         begin
            Status_Value := Open (Session, Channel_Item, Version);
            if Status_Value /= CryptoLib.Errors.Ok then
               if Attempt = Options.Retry_Count
                 or else not Retryable_Transfer_Status (Status_Value)
               then
                  return Status_Value;
               end if;
            else
               Opened := True;
               Status_Value :=
                 Upload_Data
                   (Channel_Item, Remote_Path, Data, Mode,
                    Adapted_Transfer_Options (Options, Attempt));
               Close_Status := SSH_Lib.Channels.Close (Channel_Item);
               Opened := False;
               if Status_Value = CryptoLib.Errors.Ok
                 or else Attempt = Options.Retry_Count
                 or else not Retryable_Transfer_Status (Status_Value)
               then
                  return Status_Value;
               end if;
            end if;
         exception
            when others =>
               if Opened then
                  Close_Status := SSH_Lib.Channels.Close (Channel_Item);
               end if;
               return CryptoLib.Errors.Internal_Error;
         end;
      end loop;
      return Status_Value;
   end Upload_Data;

   function Upload_File
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Local_Path  : String;
      Mode        : String := "0644";
      Options     : Transfer_Options := Default_Transfer_Options)
      return CryptoLib.Errors.Status
   is
      Size_Value   : Natural := 0;
      Status_Value : CryptoLib.Errors.Status := CryptoLib.Errors.Internal_Error;
   begin
      Status_Value := Validate_Upload_Target (Remote_Path, Mode);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;

      Status_Value := Local_File_Ready (Local_Path, Size_Value);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;

      for Attempt in 0 .. Options.Retry_Count loop
         declare
            Channel_Item : SSH_Lib.Channels.Channel;
            Version      : Natural := 0;
            Close_Status : CryptoLib.Errors.Status;
            Opened       : Boolean := False;
            pragma Unreferenced (Close_Status);
         begin
            Status_Value := Open (Session, Channel_Item, Version);
            if Status_Value /= CryptoLib.Errors.Ok then
               if Attempt = Options.Retry_Count
                 or else not Retryable_Transfer_Status (Status_Value)
               then
                  return Status_Value;
               end if;
            else
               Opened := True;
               Status_Value :=
                 Upload_File
                   (Channel_Item, Remote_Path, Local_Path, Mode, Options);
               Close_Status := SSH_Lib.Channels.Close (Channel_Item);
               Opened := False;
               if Status_Value = CryptoLib.Errors.Ok
                 or else Attempt = Options.Retry_Count
                 or else not Retryable_Transfer_Status (Status_Value)
               then
                  return Status_Value;
               end if;
            end if;
         exception
            when others =>
               if Opened then
                  Close_Status := SSH_Lib.Channels.Close (Channel_Item);
               end if;
               return CryptoLib.Errors.Internal_Error;
         end;
      end loop;
      return Status_Value;
   end Upload_File;

   function Upload_File
     (Item        : in out Client;
      Remote_Path : String;
      Local_Path  : String;
      Mode        : String := "0644";
      Options     : Transfer_Options := Default_Transfer_Options)
      return CryptoLib.Errors.Status
   is
      Handle        : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      File_Item     : Ada.Streams.Stream_IO.File_Type;
      Target_Path   : Unbounded_String := To_Unbounded_String (Remote_Path);
      Size_Value    : Natural := 0;
      Request_Id    : Interfaces.Unsigned_32 := 2;
      Status_Value  : CryptoLib.Errors.Status;
      Remote_Opened : Boolean := False;
   begin
      if not Item.Opened then
         return CryptoLib.Errors.Channel_Open_Failed;
      elsif not Supports_Open_Mode (Item.Extensions, Write_Truncate) then
         return CryptoLib.Errors.Unsupported_Feature;
      end if;

      Status_Value := Validate_Upload_Target (Remote_Path, Mode);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      Status_Value := Local_File_Ready (Local_Path, Size_Value);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;

      if Options.Atomic_Upload then
         declare
            Temp_Path : constant String := Remote_Temporary_Path (Remote_Path);
         begin
            if Temp_Path'Length = 0 then
               return CryptoLib.Errors.Invalid_Command;
            end if;
            Target_Path := To_Unbounded_String (Temp_Path);
            Status_Value := Remove_File (Item.Channel, Temp_Path);
         end;
      end if;

      Status_Value :=
        Open_Remote_File
          (Item.Channel, To_String (Target_Path), Mode, Handle, Item.Version);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      Remote_Opened := True;

      Ada.Streams.Stream_IO.Open
        (File_Item, Ada.Streams.Stream_IO.In_File, Local_Path);
      Status_Value :=
        Pipelined_Write_File
          (Item.Channel,
           Handle,
           File_Item,
           Size_Value,
           2,
           Effective_Pipeline_Depth (Options),
           Request_Id,
           Effective_Write_Chunk_Size
             (Options, Item.Limits_Known, Item.Limits));
      Ada.Streams.Stream_IO.Close (File_Item);
      if Status_Value /= CryptoLib.Errors.Ok then
         Close_Remote_File_Best_Effort (Item.Channel, Handle, Request_Id);
         return Status_Value;
      end if;

      Status_Value := Close_Remote_File (Item.Channel, Handle, Request_Id);
      Remote_Opened := False;
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      if Options.Verify_After_Transfer then
         declare
            Attributes : File_Attributes;
         begin
            Status_Value := Stat (Item, To_String (Target_Path), Attributes);
            if Status_Value /= CryptoLib.Errors.Ok
              or else not Attributes.Size_Known
              or else Attributes.Size /= Interfaces.Unsigned_64 (Size_Value)
            then
               return CryptoLib.Errors.Remote_Failure;
            end if;
         end;
      end if;
      if Options.Atomic_Upload then
         Status_Value := Rename (Item.Channel, To_String (Target_Path), Remote_Path);
         if Status_Value /= CryptoLib.Errors.Ok then
            return Status_Value;
         end if;
         if Options.Verify_After_Transfer then
            declare
               Attributes : File_Attributes;
            begin
               Status_Value := Stat (Item, Remote_Path, Attributes);
               if Status_Value /= CryptoLib.Errors.Ok
                 or else not Attributes.Size_Known
                 or else Attributes.Size /= Interfaces.Unsigned_64 (Size_Value)
               then
                  return CryptoLib.Errors.Remote_Failure;
               end if;
            end;
         end if;
      end if;
      return CryptoLib.Errors.Ok;
   exception
      when others =>
         if Ada.Streams.Stream_IO.Is_Open (File_Item) then
            Ada.Streams.Stream_IO.Close (File_Item);
         end if;
         if Remote_Opened then
            Close_Remote_File_Best_Effort (Item.Channel, Handle, Request_Id);
         end if;
         return CryptoLib.Errors.Internal_Error;
   end Upload_File;

   function Upload_File
     (Item        : in out Client;
      Remote_Path : String;
      Local_Path  : String;
      Mode        : String;
      Options     : Transfer_Options;
      Result      : out SFTP_Result) return CryptoLib.Errors.Status
   is
      Status_Value : constant CryptoLib.Errors.Status :=
        Upload_File (Item, Remote_Path, Local_Path, Mode, Options);
   begin
      Capture_Result (Status_Value, Result, Upload_Operation);
      return Status_Value;
   end Upload_File;

   function Upload_Stream
     (Item        : in out Client;
      Remote_Path : String;
      Size        : Interfaces.Unsigned_64;
      Reader      : Stream_Reader_Access;
      Mode        : String := "0644";
      Options     : Transfer_Options := Default_Transfer_Options)
      return CryptoLib.Errors.Status
   is
      Handle        : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Chunk         : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Reply_Packet  : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Target_Path   : Unbounded_String := To_Unbounded_String (Remote_Path);
      Offset_Value  : Interfaces.Unsigned_64 := 0;
      Request_Id    : Interfaces.Unsigned_32 := 2;
      Status_Value  : CryptoLib.Errors.Status;
      Remote_Opened : Boolean := False;
      Write_Chunk   : constant Natural :=
        Effective_Write_Chunk_Size (Options, Item.Limits_Known, Item.Limits);
   begin
      if not Item.Opened then
         return CryptoLib.Errors.Channel_Open_Failed;
      elsif not Supports_Open_Mode (Item.Extensions, Write_Truncate) then
         return CryptoLib.Errors.Unsupported_Feature;
      end if;
      Status_Value := Validate_Upload_Target (Remote_Path, Mode);
      if Status_Value /= CryptoLib.Errors.Ok or else Reader = null then
         return CryptoLib.Errors.Invalid_Command;
      end if;

      if Options.Atomic_Upload then
         declare
            Temp_Path : constant String := Remote_Temporary_Path (Remote_Path);
         begin
            if Temp_Path'Length = 0 then
               return CryptoLib.Errors.Invalid_Command;
            end if;
            Target_Path := To_Unbounded_String (Temp_Path);
            Status_Value := Remove_File (Item.Channel, Temp_Path);
         end;
      end if;

      Status_Value :=
        Open_Remote_File
          (Item.Channel, To_String (Target_Path), Mode, Handle, Item.Version);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      Remote_Opened := True;

      while Offset_Value < Size loop
         declare
            Remaining    : constant Interfaces.Unsigned_64 :=
              Size - Offset_Value;
            Maximum_Read : constant Natural :=
              (if Remaining < Interfaces.Unsigned_64 (Write_Chunk)
               then Natural (Remaining)
               else Write_Chunk);
         begin
            SSH_Lib.Protocol.Buffers.Clear (Chunk);
            Status_Value := Reader (Offset_Value, Maximum_Read, Chunk);
            if Status_Value /= CryptoLib.Errors.Ok then
               Close_Remote_File_Best_Effort (Item.Channel, Handle, Request_Id);
               return Status_Value;
            end if;
            declare
               Chunk_Data : constant Stream_Element_Array :=
                 SSH_Lib.Protocol.Buffers.To_Array (Chunk);
            begin
               if Chunk_Data'Length = 0
                 or else Chunk_Data'Length > Maximum_Read
                 or else Interfaces.Unsigned_64 (Chunk_Data'Length) > Remaining
               then
                  Close_Remote_File_Best_Effort
                    (Item.Channel, Handle, Request_Id);
                  return CryptoLib.Errors.Read_Failed;
               end if;
               Status_Value :=
                 Send_Packet
                   (Item.Channel,
                    Encode_Write_Request
                      (Request_Id, Handle, Offset_Value, Chunk_Data));
               if Status_Value /= CryptoLib.Errors.Ok then
                  Close_Remote_File_Best_Effort
                    (Item.Channel, Handle, Request_Id + 1);
                  return Status_Value;
               end if;
               Status_Value := Read_Packet (Item.Channel, Reply_Packet);
               if Status_Value /= CryptoLib.Errors.Ok then
                  Close_Remote_File_Best_Effort
                    (Item.Channel, Handle, Request_Id + 1);
                  return Status_Value;
               end if;
               Status_Value := Parse_Status_Packet (Reply_Packet, Request_Id);
               if Status_Value /= CryptoLib.Errors.Ok then
                  Close_Remote_File_Best_Effort
                    (Item.Channel, Handle, Request_Id + 1);
                  return Status_Value;
               end if;
               Offset_Value :=
                 Offset_Value + Interfaces.Unsigned_64 (Chunk_Data'Length);
               Request_Id := Request_Id + 1;
            end;
         end;
      end loop;

      Status_Value := Close_Remote_File (Item.Channel, Handle, Request_Id);
      Remote_Opened := False;
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      if Options.Verify_After_Transfer then
         declare
            Attributes : File_Attributes;
         begin
            Status_Value := Stat (Item, To_String (Target_Path), Attributes);
            if Status_Value /= CryptoLib.Errors.Ok
              or else not Attributes.Size_Known
              or else Attributes.Size /= Size
            then
               return CryptoLib.Errors.Remote_Failure;
            end if;
         end;
      end if;
      if Options.Atomic_Upload then
         Status_Value := Rename (Item.Channel, To_String (Target_Path), Remote_Path);
         if Status_Value /= CryptoLib.Errors.Ok then
            return Status_Value;
         end if;
      end if;
      return CryptoLib.Errors.Ok;
   exception
      when others =>
         if Remote_Opened then
            Close_Remote_File_Best_Effort (Item.Channel, Handle, Request_Id);
         end if;
         return CryptoLib.Errors.Internal_Error;
   end Upload_Stream;

   function Upload_Stream
     (Item        : in out Client;
      Remote_Path : String;
      Size        : Interfaces.Unsigned_64;
      Reader      : Stream_Reader_Access;
      Mode        : String;
      Options     : Transfer_Options;
      Result      : out SFTP_Result) return CryptoLib.Errors.Status
   is
      Status_Value : constant CryptoLib.Errors.Status :=
        Upload_Stream (Item, Remote_Path, Size, Reader, Mode, Options);
   begin
      Capture_Result (Status_Value, Result, Upload_Operation);
      return Status_Value;
   end Upload_Stream;

   function Download_File
     (Item        : in out Client;
      Remote_Path : String;
      Local_Path  : String;
      Options     : Transfer_Options := Default_Transfer_Options)
      return CryptoLib.Errors.Status
   is
      Data         : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      File_Item    : Ada.Streams.Stream_IO.File_Type;
      Temp_Path    : constant String := Local_Path & ".ada-ssh-sftp-download.tmp";
      Status_Value : CryptoLib.Errors.Status;
      Local_Opened : Boolean := False;

      procedure Remove_Temp_File is
      begin
         if Ada.Directories.Exists (Temp_Path) then
            Ada.Directories.Delete_File (Temp_Path);
         end if;
      exception
         when others =>
            null;
      end Remove_Temp_File;
   begin
      if not Item.Opened then
         return CryptoLib.Errors.Channel_Open_Failed;
      elsif not Supports_Open_Mode (Item.Extensions, Read_Only)
        or else Local_Path'Length = 0
      then
         return CryptoLib.Errors.Invalid_Command;
      end if;

      Remove_Temp_File;
      Status_Value := Download_Data (Item, Remote_Path, Data, Options);
      if Status_Value /= CryptoLib.Errors.Ok then
         Remove_Temp_File;
         return Status_Value;
      end if;

      Ada.Streams.Stream_IO.Create
        (File_Item, Ada.Streams.Stream_IO.Out_File, Temp_Path);
      Local_Opened := True;
      declare
         Bytes : constant Stream_Element_Array :=
           SSH_Lib.Protocol.Buffers.To_Array (Data);
      begin
         if Bytes'Length > 0 then
            Ada.Streams.Stream_IO.Write (File_Item, Bytes);
         end if;
      end;
      Ada.Streams.Stream_IO.Close (File_Item);
      Local_Opened := False;
      if Ada.Directories.Exists (Local_Path) then
         Ada.Directories.Delete_File (Local_Path);
      end if;
      Ada.Directories.Rename (Temp_Path, Local_Path);
      return CryptoLib.Errors.Ok;
   exception
      when others =>
         if Local_Opened and then Ada.Streams.Stream_IO.Is_Open (File_Item) then
            Ada.Streams.Stream_IO.Close (File_Item);
         end if;
         Remove_Temp_File;
         return CryptoLib.Errors.Write_Failed;
   end Download_File;

   function Download_File
     (Item        : in out Client;
      Remote_Path : String;
      Local_Path  : String;
      Options     : Transfer_Options;
      Result      : out SFTP_Result) return CryptoLib.Errors.Status
   is
      Status_Value : constant CryptoLib.Errors.Status :=
        Download_File (Item, Remote_Path, Local_Path, Options);
   begin
      Capture_Result (Status_Value, Result, Download_Operation);
      return Status_Value;
   end Download_File;

   function Download_Stream
     (Item        : in out Client;
      Remote_Path : String;
      Writer      : Stream_Writer_Access;
      Options     : Transfer_Options := Default_Transfer_Options)
      return CryptoLib.Errors.Status
   is
      Attributes    : File_Attributes;
      Handle        : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Reply_Packet  : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Chunk         : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Offset_Value  : Interfaces.Unsigned_64 := 0;
      Request_Id    : Interfaces.Unsigned_32 := 2;
      Status_Value  : CryptoLib.Errors.Status;
      Remote_Opened : Boolean := False;
      Read_Chunk    : constant Natural := Effective_Read_Chunk_Size (Item.Extensions, Options);
   begin
      if not Item.Opened then
         return CryptoLib.Errors.Channel_Open_Failed;
      elsif not Supports_Open_Mode (Item.Extensions, Read_Only)
        or else not Safe_Remote_Path (Remote_Path)
        or else Writer = null
      then
         return CryptoLib.Errors.Invalid_Command;
      end if;

      Status_Value := Stat (Item, Remote_Path, Attributes);
      if Status_Value /= CryptoLib.Errors.Ok or else not Attributes.Size_Known
      then
         return CryptoLib.Errors.Read_Failed;
      end if;
      Status_Value :=
        Open_Remote_Read_File
          (Item.Channel, Remote_Path, Handle, Item.Version);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      Remote_Opened := True;

      while Offset_Value < Attributes.Size loop
         declare
            Remaining  : constant Interfaces.Unsigned_64 :=
              Attributes.Size - Offset_Value;
            Read_Count : constant Natural :=
              (if Remaining < Interfaces.Unsigned_64 (Read_Chunk)
               then Natural (Remaining)
               else Read_Chunk);
         begin
            Status_Value :=
              Send_Packet
                (Item.Channel,
                 Encode_Read_Request
                   (Request_Id, Handle, Offset_Value, Read_Count));
            if Status_Value /= CryptoLib.Errors.Ok then
               Close_Remote_File_Best_Effort
                 (Item.Channel, Handle, Request_Id + 1);
               return Status_Value;
            end if;
            Status_Value := Read_Packet (Item.Channel, Reply_Packet);
            if Status_Value /= CryptoLib.Errors.Ok then
               Close_Remote_File_Best_Effort
                 (Item.Channel, Handle, Request_Id + 1);
               return Status_Value;
            end if;
            Status_Value := Parse_Data_Packet (Reply_Packet, Request_Id, Chunk);
            if Status_Value /= CryptoLib.Errors.Ok then
               Close_Remote_File_Best_Effort
                 (Item.Channel, Handle, Request_Id + 1);
               return Status_Value;
            end if;
            declare
               Chunk_Data : constant Stream_Element_Array :=
                 SSH_Lib.Protocol.Buffers.To_Array (Chunk);
            begin
               if Chunk_Data'Length = 0 or else Chunk_Data'Length > Read_Count
               then
                  Close_Remote_File_Best_Effort
                    (Item.Channel, Handle, Request_Id + 1);
                  return CryptoLib.Errors.Read_Failed;
               end if;
               Status_Value := Writer (Offset_Value, Chunk_Data);
               if Status_Value /= CryptoLib.Errors.Ok then
                  Close_Remote_File_Best_Effort
                    (Item.Channel, Handle, Request_Id + 1);
                  return Status_Value;
               end if;
               Offset_Value :=
                 Offset_Value + Interfaces.Unsigned_64 (Chunk_Data'Length);
            end;
            Request_Id := Request_Id + 1;
         end;
      end loop;

      Status_Value := Close_Remote_File (Item.Channel, Handle, Request_Id);
      Remote_Opened := False;
      return Status_Value;
   exception
      when others =>
         if Remote_Opened then
            Close_Remote_File_Best_Effort (Item.Channel, Handle, Request_Id);
         end if;
         return CryptoLib.Errors.Internal_Error;
   end Download_Stream;

   function Download_Stream
     (Item        : in out Client;
      Remote_Path : String;
      Writer      : Stream_Writer_Access;
      Options     : Transfer_Options;
      Result      : out SFTP_Result) return CryptoLib.Errors.Status
   is
      Status_Value : constant CryptoLib.Errors.Status :=
        Download_Stream (Item, Remote_Path, Writer, Options);
   begin
      Capture_Result (Status_Value, Result, Download_Operation);
      return Status_Value;
   end Download_Stream;

   function Resume_Download_File
     (Item        : in out Client;
      Remote_Path : String;
      Local_Path  : String;
      Options     : Transfer_Options := Default_Transfer_Options)
      return CryptoLib.Errors.Status
   is
      Attributes    : File_Attributes;
      Handle        : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Data          : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      File_Item     : Ada.Streams.Stream_IO.File_Type;
      Local_Size    : Interfaces.Unsigned_64 := 0;
      Remaining     : Natural := 0;
      Request_Id    : Interfaces.Unsigned_32 := 2;
      Status_Value  : CryptoLib.Errors.Status;
      Remote_Opened : Boolean := False;
      Local_Opened  : Boolean := False;
   begin
      if not Item.Opened then
         return CryptoLib.Errors.Channel_Open_Failed;
      elsif not Supports_Open_Mode (Item.Extensions, Read_Only)
        or else not Safe_Remote_Path (Remote_Path)
        or else Local_Path'Length = 0
      then
         return CryptoLib.Errors.Invalid_Command;
      end if;

      if Ada.Directories.Exists (Local_Path) then
         if Ada.Directories.Kind (Local_Path) /= Ada.Directories.Ordinary_File
         then
            return CryptoLib.Errors.Invalid_Command;
         end if;
         Local_Size :=
           Interfaces.Unsigned_64 (Ada.Directories.Size (Local_Path));
      end if;

      Status_Value := Stat (Item, Remote_Path, Attributes);
      if Status_Value /= CryptoLib.Errors.Ok
        or else not Attributes.Size_Known
        or else Attributes.Size > Interfaces.Unsigned_64 (Natural'Last)
      then
         return CryptoLib.Errors.Read_Failed;
      end if;
      if Local_Size > Attributes.Size then
         return CryptoLib.Errors.Invalid_Command;
      elsif Local_Size = Attributes.Size then
         if Options.Verify_After_Transfer then
            return Verify_Local_Size (Local_Path, Attributes.Size);
         end if;
         return CryptoLib.Errors.Ok;
      end if;

      Remaining := Natural (Attributes.Size - Local_Size);
      Status_Value :=
        Open_Remote_Read_File
          (Item.Channel, Remote_Path, Handle, Item.Version);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      Remote_Opened := True;
      Status_Value :=
        Pipelined_Read_To_Buffer
          (Item.Channel,
           Handle,
           Local_Size,
           Remaining,
           2,
           Effective_Pipeline_Depth (Options),
           Data,
           Request_Id,
           Effective_Read_Chunk_Size (Item.Extensions, Options));
      if Status_Value /= CryptoLib.Errors.Ok then
         Close_Remote_File_Best_Effort (Item.Channel, Handle, Request_Id);
         return Status_Value;
      end if;
      Status_Value := Close_Remote_File (Item.Channel, Handle, Request_Id);
      Remote_Opened := False;
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;

      if Ada.Directories.Exists (Local_Path) then
         Ada.Streams.Stream_IO.Open
           (File_Item, Ada.Streams.Stream_IO.Append_File, Local_Path);
      else
         Ada.Streams.Stream_IO.Create
           (File_Item, Ada.Streams.Stream_IO.Out_File, Local_Path);
      end if;
      Local_Opened := True;
      declare
         Bytes : constant Stream_Element_Array :=
           SSH_Lib.Protocol.Buffers.To_Array (Data);
      begin
         if Bytes'Length > 0 then
            Ada.Streams.Stream_IO.Write (File_Item, Bytes);
         end if;
      end;
      Ada.Streams.Stream_IO.Close (File_Item);
      Local_Opened := False;
      if Options.Verify_After_Transfer then
         return Verify_Local_Size (Local_Path, Attributes.Size);
      end if;
      return CryptoLib.Errors.Ok;
   exception
      when others =>
         if Local_Opened and then Ada.Streams.Stream_IO.Is_Open (File_Item)
         then
            Ada.Streams.Stream_IO.Close (File_Item);
         end if;
         if Remote_Opened then
            Close_Remote_File_Best_Effort (Item.Channel, Handle, Request_Id);
         end if;
         return CryptoLib.Errors.Write_Failed;
   end Resume_Download_File;

   function Resume_Download_File
     (Item        : in out Client;
      Remote_Path : String;
      Local_Path  : String;
      Options     : Transfer_Options;
      Result      : out SFTP_Result) return CryptoLib.Errors.Status
   is
      Status_Value : constant CryptoLib.Errors.Status :=
        Resume_Download_File (Item, Remote_Path, Local_Path, Options);
   begin
      Capture_Result (Status_Value, Result, Download_Operation);
      return Status_Value;
   end Resume_Download_File;

   function Resume_Upload_File
     (Item        : in out Client;
      Remote_Path : String;
      Local_Path  : String;
      Mode        : String := "0644";
      Options     : Transfer_Options := Default_Transfer_Options)
      return CryptoLib.Errors.Status
   is
      Attributes    : File_Attributes;
      Handle        : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      File_Item     : Ada.Streams.Stream_IO.File_Type;
      Local_Size    : Natural := 0;
      Remote_Size   : Interfaces.Unsigned_64 := 0;
      Write_Size    : Natural := 0;
      Request_Id    : Interfaces.Unsigned_32 := 2;
      Status_Value  : CryptoLib.Errors.Status;
      Remote_Opened : Boolean := False;
   begin
      if not Item.Opened then
         return CryptoLib.Errors.Channel_Open_Failed;
      elsif not Supports_Open_Mode (Item.Extensions, Write_No_Truncate) then
         return CryptoLib.Errors.Unsupported_Feature;
      elsif Options.Atomic_Upload then
         return CryptoLib.Errors.Invalid_Command;
      end if;
      Status_Value := Validate_Upload_Target (Remote_Path, Mode);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      Status_Value := Local_File_Ready (Local_Path, Local_Size);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;

      Status_Value := Stat (Item, Remote_Path, Attributes);
      if Status_Value = CryptoLib.Errors.Ok then
         if not Attributes.Size_Known then
            return CryptoLib.Errors.Read_Failed;
         end if;
         Remote_Size := Attributes.Size;
      elsif Status_Value = CryptoLib.Errors.No_Such_File then
         Remote_Size := 0;
      else
         return Status_Value;
      end if;
      if Remote_Size > Interfaces.Unsigned_64 (Local_Size) then
         return CryptoLib.Errors.Invalid_Command;
      elsif Remote_Size = Interfaces.Unsigned_64 (Local_Size) then
         return CryptoLib.Errors.Ok;
      end if;
      Write_Size := Local_Size - Natural (Remote_Size);

      Status_Value :=
        Open_Remote_File_Mode
          (Item.Channel,
           Remote_Path,
           Write_No_Truncate,
           Mode,
           Handle,
           Item.Version);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      Remote_Opened := True;
      Ada.Streams.Stream_IO.Open
        (File_Item, Ada.Streams.Stream_IO.In_File, Local_Path);
      Status_Value :=
        Pipelined_Write_File_From_Offset
          (Item.Channel,
           Handle,
           File_Item,
           Remote_Size,
           Write_Size,
           2,
           Effective_Pipeline_Depth (Options),
           Request_Id,
           Effective_Write_Chunk_Size
             (Options, Item.Limits_Known, Item.Limits));
      Ada.Streams.Stream_IO.Close (File_Item);
      if Status_Value /= CryptoLib.Errors.Ok then
         Close_Remote_File_Best_Effort (Item.Channel, Handle, Request_Id);
         return Status_Value;
      end if;
      Status_Value := Close_Remote_File (Item.Channel, Handle, Request_Id);
      Remote_Opened := False;
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      if Options.Verify_After_Transfer then
         Status_Value := Stat (Item, Remote_Path, Attributes);
         if Status_Value /= CryptoLib.Errors.Ok
           or else not Attributes.Size_Known
           or else Attributes.Size /= Interfaces.Unsigned_64 (Local_Size)
         then
            return CryptoLib.Errors.Remote_Failure;
         end if;
      end if;
      return CryptoLib.Errors.Ok;
   exception
      when others =>
         if Ada.Streams.Stream_IO.Is_Open (File_Item) then
            Ada.Streams.Stream_IO.Close (File_Item);
         end if;
         if Remote_Opened then
            Close_Remote_File_Best_Effort (Item.Channel, Handle, Request_Id);
         end if;
         return CryptoLib.Errors.Internal_Error;
   end Resume_Upload_File;

   function Resume_Upload_File
     (Item        : in out Client;
      Remote_Path : String;
      Local_Path  : String;
      Mode        : String;
      Options     : Transfer_Options;
      Result      : out SFTP_Result) return CryptoLib.Errors.Status
   is
      Status_Value : constant CryptoLib.Errors.Status :=
        Resume_Upload_File (Item, Remote_Path, Local_Path, Mode, Options);
   begin
      Capture_Result (Status_Value, Result, Upload_Operation);
      return Status_Value;
   end Resume_Upload_File;

   function List_Directory
     (Item        : in out Client;
      Remote_Path : String;
      Names       : out Unbounded_String) return CryptoLib.Errors.Status is
   begin
      Names := Null_Unbounded_String;
      if not Item.Opened then
         return CryptoLib.Errors.Channel_Open_Failed;
      end if;
      return List_Directory (Item.Channel, Remote_Path, Names);
   exception
      when others =>
         Names := Null_Unbounded_String;
         return CryptoLib.Errors.Internal_Error;
   end List_Directory;

   function List_Directory_Paged
     (Item        : in out Client;
      Remote_Path : String;
      Callback    : Directory_Page_Callback_Access)
      return CryptoLib.Errors.Status is
   begin
      if not Item.Opened then
         return CryptoLib.Errors.Channel_Open_Failed;
      end if;
      return List_Directory_Paged (Item.Channel, Remote_Path, Callback);
   exception
      when others =>
         return CryptoLib.Errors.Internal_Error;
   end List_Directory_Paged;

   function Remove_Directory
     (Item : in out Client; Remote_Path : String)
      return CryptoLib.Errors.Status is
   begin
      if not Item.Opened then
         return CryptoLib.Errors.Channel_Open_Failed;
      end if;
      return Remove_Directory (Item.Channel, Remote_Path);
   exception
      when others =>
         return CryptoLib.Errors.Internal_Error;
   end Remove_Directory;

   function Remove_Directory
     (Item        : in out Client;
      Remote_Path : String;
      Result      : out SFTP_Result) return CryptoLib.Errors.Status
   is
      Status_Value : constant CryptoLib.Errors.Status :=
        Remove_Directory (Item, Remote_Path);
   begin
      Capture_Result (Status_Value, Result, Directory_Operation);
      return Status_Value;
   end Remove_Directory;

   function Upload_Directory
     (Item           : in out Client;
      Remote_Path    : String;
      Local_Path     : String;
      Directory_Mode : String := "0755";
      File_Mode      : String := "0644";
      Options        : Recursive_Options := Default_Recursive_Options)
      return CryptoLib.Errors.Status
   is
      Search       : Ada.Directories.Search_Type;
      Local_Item   : Ada.Directories.Directory_Entry_Type;
      Status_Value : CryptoLib.Errors.Status;
      Searching    : Boolean := False;
   begin
      if not Item.Opened then
         return CryptoLib.Errors.Channel_Open_Failed;
      elsif Validate_Upload_Target (Remote_Path, Directory_Mode)
        /= CryptoLib.Errors.Ok
        or else not Valid_Mode (File_Mode)
        or else Local_Path'Length = 0
        or else not Ada.Directories.Exists (Local_Path)
        or else Ada.Directories.Kind (Local_Path) /= Ada.Directories.Directory
      then
         return CryptoLib.Errors.Invalid_Command;
      end if;

      if not Should_Process (Options, Local_Path, Remote_Path, Tree_Directory)
      then
         return CryptoLib.Errors.Ok;
      end if;

      Status_Value :=
        Ensure_Remote_Directory (Item.Channel, Remote_Path, Directory_Mode);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      Report_Progress (Options, Tree_Upload, Local_Path, Remote_Path, 0, 0);

      Ada.Directories.Start_Search
        (Search,
         Directory => Local_Path,
         Pattern   => "*",
         Filter    =>
           Ada.Directories.Filter_Type'
             (Ada.Directories.Ordinary_File => True,
              Ada.Directories.Directory     => True,
              Ada.Directories.Special_File  => False));
      Searching := True;

      while Ada.Directories.More_Entries (Search) loop
         Ada.Directories.Get_Next_Entry (Search, Local_Item);
         declare
            Name             : constant String :=
              Ada.Directories.Simple_Name (Local_Item);
            Local_Child_Path : constant String :=
              Ada.Directories.Compose (Local_Path, Name);
            Remote_Child     : constant String :=
              Remote_Child_Path (Remote_Path, Name);
         begin
            if Is_Dot_Entry (Name) then
               Status_Value := CryptoLib.Errors.Ok;
            elsif Ada.Directories.Kind (Local_Item) = Ada.Directories.Directory
            then
               Status_Value :=
                 Upload_Directory
                   (Item,
                    Remote_Child,
                    Local_Child_Path,
                    Directory_Mode,
                    File_Mode,
                    Options);
            elsif Should_Process
                    (Options, Local_Child_Path, Remote_Child, Tree_File)
            then
               if Options.Skip_Unchanged
                 and then
                   Remote_File_Unchanged
                     (Item.Channel, Local_Child_Path, Remote_Child)
               then
                  Status_Value := CryptoLib.Errors.Ok;
               else
                  Status_Value :=
                    Remote_Target_File_Allowed
                      (Item.Channel, Remote_Child, Options);
                  if Status_Value = CryptoLib.Errors.Ok then
                     Status_Value :=
                       Upload_File
                         (Item, Remote_Child, Local_Child_Path, File_Mode);
                  end if;
               end if;
               if Status_Value = CryptoLib.Errors.Ok then
                  if Options.Preserve_Attributes then
                     declare
                        Local_Metadata : File_Attributes;
                     begin
                        Capture_Local_Metadata
                          (Local_Child_Path, Local_Metadata);
                        Status_Value :=
                          Preserve_Remote_Attributes
                            (Item.Channel,
                             Remote_Child,
                             Local_Metadata,
                             Options);
                     exception
                        when others =>
                           Status_Value := CryptoLib.Errors.Ok;
                     end;
                  end if;
               end if;
               if Status_Value = CryptoLib.Errors.Ok then
                  Report_Progress
                    (Options,
                     Tree_Upload,
                     Local_Child_Path,
                     Remote_Child,
                     Interfaces.Unsigned_64
                       (Ada.Directories.Size (Local_Child_Path)),
                     Interfaces.Unsigned_64
                       (Ada.Directories.Size (Local_Child_Path)));
               else
                  Status_Value :=
                    Handle_Recursive_Status (Options, Status_Value);
               end if;
            else
               Status_Value := CryptoLib.Errors.Ok;
            end if;
            Status_Value := Handle_Recursive_Status (Options, Status_Value);
            if Status_Value /= CryptoLib.Errors.Ok then
               Ada.Directories.End_Search (Search);
               return Status_Value;
            end if;
         end;
      end loop;

      Ada.Directories.End_Search (Search);
      if Options.Preserve_Attributes then
         declare
            Local_Metadata : File_Attributes;
         begin
            Capture_Local_Metadata (Local_Path, Local_Metadata);
            return
              Preserve_Remote_Attributes
                (Item.Channel, Remote_Path, Local_Metadata, Options);
         exception
            when others =>
               return CryptoLib.Errors.Ok;
         end;
      end if;
      return CryptoLib.Errors.Ok;
   exception
      when others =>
         if Searching then
            Ada.Directories.End_Search (Search);
         end if;
         return CryptoLib.Errors.Internal_Error;
   end Upload_Directory;

   function Upload_Directory
     (Item           : in out Client;
      Remote_Path    : String;
      Local_Path     : String;
      Directory_Mode : String;
      File_Mode      : String;
      Options        : Recursive_Options;
      Result         : out SFTP_Result) return CryptoLib.Errors.Status
   is
      Status_Value : constant CryptoLib.Errors.Status :=
        Upload_Directory
          (Item, Remote_Path, Local_Path, Directory_Mode, File_Mode, Options);
   begin
      Capture_Result (Status_Value, Result, Directory_Operation);
      return Status_Value;
   end Upload_Directory;

   function Download_Directory
     (Item        : in out Client;
      Remote_Path : String;
      Local_Path  : String;
      Options     : Recursive_Options := Default_Recursive_Options)
      return CryptoLib.Errors.Status
   is
      Entries      : Directory_Entry_Vectors.Vector;
      Status_Value : CryptoLib.Errors.Status;
   begin
      if not Item.Opened then
         return CryptoLib.Errors.Channel_Open_Failed;
      elsif not Safe_Remote_Path (Remote_Path) or else Local_Path'Length = 0
      then
         return CryptoLib.Errors.Invalid_Command;
      end if;

      if not Should_Process (Options, Remote_Path, Local_Path, Tree_Directory)
      then
         return CryptoLib.Errors.Ok;
      end if;

      Ada.Directories.Create_Path (Local_Path);
      Report_Progress (Options, Tree_Download, Remote_Path, Local_Path, 0, 0);
      Status_Value := List_Directory (Item, Remote_Path, Entries);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;

      for Directory_Item of Entries loop
         declare
            Name         : constant String := To_String (Directory_Item.Name);
            Remote_Child : constant String :=
              Remote_Child_Path (Remote_Path, Name);
            Local_Child  : constant String :=
              Ada.Directories.Compose (Local_Path, Name);
         begin
            if not Is_Dot_Entry (Name) then
               if Remote_Path_Is_Directory
                    (Item.Channel,
                     Remote_Child,
                     Directory_Item.Attributes,
                     Options)
               then
                  Status_Value :=
                    Download_Directory
                      (Item, Remote_Child, Local_Child, Options);
               elsif Should_Process
                       (Options,
                        Remote_Child,
                        Local_Child,
                        Entry_Kind_For (Directory_Item.Attributes))
               then
                  if Options.Skip_Unchanged
                    and then
                      Local_File_Unchanged
                        (Local_Child, Directory_Item.Attributes)
                  then
                     Status_Value := CryptoLib.Errors.Ok;
                  else
                     Status_Value :=
                       Local_Target_File_Allowed (Local_Child, Options);
                     if Status_Value = CryptoLib.Errors.Ok then
                        Status_Value :=
                          Download_File (Item, Remote_Child, Local_Child);
                     end if;
                  end if;
                  if Status_Value = CryptoLib.Errors.Ok then
                     if Options.Preserve_Attributes then
                        Restore_Local_Metadata
                          (Local_Child, Directory_Item.Attributes);
                     end if;
                     Report_Progress
                       (Options,
                        Tree_Download,
                        Remote_Child,
                        Local_Child,
                        Directory_Item.Attributes.Size,
                        Directory_Item.Attributes.Size);
                  else
                     Status_Value :=
                       Handle_Recursive_Status (Options, Status_Value);
                  end if;
               else
                  Status_Value := CryptoLib.Errors.Ok;
               end if;
               Status_Value := Handle_Recursive_Status (Options, Status_Value);
               if Status_Value /= CryptoLib.Errors.Ok then
                  return Status_Value;
               end if;
            end if;
         end;
      end loop;
      if Options.Preserve_Attributes then
         declare
            Root_Attributes : File_Attributes;
         begin
            Status_Value := LStat (Item, Remote_Path, Root_Attributes);
            if Status_Value = CryptoLib.Errors.Ok then
               Restore_Local_Metadata (Local_Path, Root_Attributes);
            end if;
         exception
            when others =>
               null;
         end;
      end if;
      return CryptoLib.Errors.Ok;
   exception
      when others =>
         return CryptoLib.Errors.Internal_Error;
   end Download_Directory;

   function Download_Directory
     (Item        : in out Client;
      Remote_Path : String;
      Local_Path  : String;
      Options     : Recursive_Options;
      Result      : out SFTP_Result) return CryptoLib.Errors.Status
   is
      Status_Value : constant CryptoLib.Errors.Status :=
        Download_Directory (Item, Remote_Path, Local_Path, Options);
   begin
      Capture_Result (Status_Value, Result, Directory_Operation);
      return Status_Value;
   end Download_Directory;

   function Remove_Tree
     (Item        : in out Client;
      Remote_Path : String;
      Options     : Recursive_Options := Default_Recursive_Options)
      return CryptoLib.Errors.Status
   is
      Attributes   : File_Attributes;
      Entries      : Directory_Entry_Vectors.Vector;
      Status_Value : CryptoLib.Errors.Status;
   begin
      if not Item.Opened then
         return CryptoLib.Errors.Channel_Open_Failed;
      elsif not Safe_Remote_Path (Remote_Path) then
         return CryptoLib.Errors.Invalid_Command;
      end if;

      Status_Value := LStat (Item, Remote_Path, Attributes);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      if not Should_Process
               (Options, Remote_Path, "", Entry_Kind_For (Attributes))
      then
         return CryptoLib.Errors.Ok;
      end if;

      if Attribute_Is_Directory (Attributes) then
         Status_Value := List_Directory (Item, Remote_Path, Entries);
         if Status_Value /= CryptoLib.Errors.Ok then
            return Status_Value;
         end if;
         for Directory_Item of Entries loop
            declare
               Name : constant String := To_String (Directory_Item.Name);
            begin
               if not Is_Dot_Entry (Name) then
                  Status_Value :=
                    Remove_Tree
                      (Item,
                       Remote_Child_Path (Remote_Path, Name),
                       Options);
                  Status_Value :=
                    Handle_Recursive_Status (Options, Status_Value);
                  if Status_Value /= CryptoLib.Errors.Ok then
                     return Status_Value;
                  end if;
               end if;
            end;
         end loop;
         Status_Value := Remove_Directory (Item, Remote_Path);
         if Status_Value = CryptoLib.Errors.Ok then
            Report_Progress (Options, Tree_Remove, Remote_Path, "", 0, 0);
         end if;
         return Status_Value;
      else
         Status_Value := Remove_File (Item, Remote_Path);
         if Status_Value = CryptoLib.Errors.Ok then
            Report_Progress
              (Options,
               Tree_Remove,
               Remote_Path,
               "",
               Attributes.Size,
               Attributes.Size);
         end if;
         return Status_Value;
      end if;
   exception
      when others =>
         return CryptoLib.Errors.Internal_Error;
   end Remove_Tree;

   function Remove_Tree
     (Item        : in out Client;
      Remote_Path : String;
      Options     : Recursive_Options;
      Result      : out SFTP_Result) return CryptoLib.Errors.Status
   is
      Status_Value : constant CryptoLib.Errors.Status :=
        Remove_Tree (Item, Remote_Path, Options);
   begin
      Capture_Result (Status_Value, Result, Remove_Operation);
      return Status_Value;
   end Remove_Tree;

   function Copy_Tree
     (Item               : in out Client;
      Source_Remote_Path : String;
      Target_Remote_Path : String;
      Directory_Mode     : String := "0755";
      File_Mode          : String := "0644";
      Options            : Recursive_Options := Default_Recursive_Options)
      return CryptoLib.Errors.Status
   is
      Source_Attributes : File_Attributes;
      Entries           : Directory_Entry_Vectors.Vector;
      Data              : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Status_Value      : CryptoLib.Errors.Status;
   begin
      if not Item.Opened then
         return CryptoLib.Errors.Channel_Open_Failed;
      elsif not Safe_Remote_Path (Source_Remote_Path)
        or else
          Validate_Upload_Target (Target_Remote_Path, Directory_Mode)
          /= CryptoLib.Errors.Ok
        or else not Valid_Mode (File_Mode)
      then
         return CryptoLib.Errors.Invalid_Command;
      end if;

      Status_Value := LStat (Item, Source_Remote_Path, Source_Attributes);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      if not Should_Process
               (Options,
                Source_Remote_Path,
                Target_Remote_Path,
                Entry_Kind_For (Source_Attributes))
      then
         return CryptoLib.Errors.Ok;
      end if;

      if Attribute_Is_Directory (Source_Attributes) then
         Status_Value :=
           Ensure_Remote_Directory
             (Item.Channel, Target_Remote_Path, Directory_Mode);
         if Status_Value /= CryptoLib.Errors.Ok then
            return Status_Value;
         end if;
         Status_Value := List_Directory (Item, Source_Remote_Path, Entries);
         if Status_Value /= CryptoLib.Errors.Ok then
            return Status_Value;
         end if;
         for Directory_Item of Entries loop
            declare
               Name : constant String := To_String (Directory_Item.Name);
            begin
               if not Is_Dot_Entry (Name) then
                  Status_Value :=
                    Copy_Tree
                      (Item,
                       Remote_Child_Path (Source_Remote_Path, Name),
                       Remote_Child_Path (Target_Remote_Path, Name),
                       Directory_Mode,
                       File_Mode,
                       Options);
                  if Status_Value /= CryptoLib.Errors.Ok then
                     return Status_Value;
                  end if;
               end if;
            end;
         end loop;
         return
           Preserve_Remote_Attributes
             (Item.Channel, Target_Remote_Path, Source_Attributes, Options);
      else
         Status_Value :=
           Remote_Target_File_Allowed
             (Item.Channel, Target_Remote_Path, Options);
         if Status_Value /= CryptoLib.Errors.Ok then
            return Handle_Recursive_Status (Options, Status_Value);
         end if;
         Status_Value := Download_Data (Item, Source_Remote_Path, Data);
         if Status_Value /= CryptoLib.Errors.Ok then
            return Handle_Recursive_Status (Options, Status_Value);
         end if;
         Status_Value :=
           Upload_Data
             (Item,
              Target_Remote_Path,
              SSH_Lib.Protocol.Buffers.To_Array (Data),
              File_Mode);
         if Status_Value /= CryptoLib.Errors.Ok then
            return Handle_Recursive_Status (Options, Status_Value);
         end if;
         Status_Value :=
           Preserve_Remote_Attributes
             (Item.Channel, Target_Remote_Path, Source_Attributes, Options);
         if Status_Value = CryptoLib.Errors.Ok then
            Report_Progress
              (Options,
               Tree_Copy,
               Source_Remote_Path,
               Target_Remote_Path,
               Source_Attributes.Size,
               Source_Attributes.Size);
         end if;
         return Status_Value;
      end if;
   exception
      when others =>
         return CryptoLib.Errors.Internal_Error;
   end Copy_Tree;

   function Copy_Tree
     (Item               : in out Client;
      Source_Remote_Path : String;
      Target_Remote_Path : String;
      Directory_Mode     : String;
      File_Mode          : String;
      Options            : Recursive_Options;
      Result             : out SFTP_Result) return CryptoLib.Errors.Status
   is
      Status_Value : constant CryptoLib.Errors.Status :=
        Copy_Tree
          (Item, Source_Remote_Path, Target_Remote_Path, Directory_Mode,
           File_Mode, Options);
   begin
      Capture_Result (Status_Value, Result, Directory_Operation);
      return Status_Value;
   end Copy_Tree;

   function Sync_Directory
     (Item           : in out Client;
      Direction      : Sync_Direction;
      Remote_Path    : String;
      Local_Path     : String;
      Directory_Mode : String := "0755";
      File_Mode      : String := "0644";
      Options        : Sync_Options := Default_Sync_Options)
      return CryptoLib.Errors.Status
   is
      Status_Value        : CryptoLib.Errors.Status;
      Effective_Recursive : Recursive_Options := Options.Recursive;
   begin
      if not Item.Opened then
         return CryptoLib.Errors.Channel_Open_Failed;
      elsif not Safe_Remote_Path (Remote_Path)
        or else Local_Path'Length = 0
        or else not Valid_Mode (Directory_Mode)
        or else not Valid_Mode (File_Mode)
      then
         return CryptoLib.Errors.Invalid_Command;
      end if;

      if Options.Skip_Unchanged then
         Effective_Recursive.Skip_Unchanged := True;
      end if;

      if Direction = Sync_Upload then
         if Options.Delete_Extra then
            Status_Value := Remove_Tree (Item, Remote_Path, Effective_Recursive);
            if Status_Value /= CryptoLib.Errors.Ok
              and then Status_Value /= CryptoLib.Errors.No_Such_File
            then
               return Status_Value;
            end if;
         end if;
         Status_Value :=
           Upload_Directory
             (Item,
              Remote_Path,
              Local_Path,
              Directory_Mode,
              File_Mode,
              Effective_Recursive);
      else
         if Options.Delete_Extra and then Ada.Directories.Exists (Local_Path)
         then
            Ada.Directories.Delete_Tree (Local_Path);
         end if;
         Status_Value :=
           Download_Directory
             (Item, Remote_Path, Local_Path, Effective_Recursive);
      end if;

      if Status_Value = CryptoLib.Errors.Ok then
         Report_Progress
           (Effective_Recursive, Tree_Sync, Remote_Path, Local_Path, 0, 0);
      end if;
      return Status_Value;
   exception
      when others =>
         return CryptoLib.Errors.Internal_Error;
   end Sync_Directory;

   function Sync_Directory
     (Item           : in out Client;
      Direction      : Sync_Direction;
      Remote_Path    : String;
      Local_Path     : String;
      Directory_Mode : String;
      File_Mode      : String;
      Options        : Sync_Options;
      Result         : out SFTP_Result) return CryptoLib.Errors.Status
   is
      Status_Value : constant CryptoLib.Errors.Status :=
        Sync_Directory
          (Item, Direction, Remote_Path, Local_Path, Directory_Mode,
           File_Mode, Options);
   begin
      Capture_Result (Status_Value, Result, Directory_Operation);
      return Status_Value;
   end Sync_Directory;

   function Read_Link
     (Item        : in out Client;
      Remote_Path : String;
      Target_Path : out Unbounded_String) return CryptoLib.Errors.Status is
   begin
      Target_Path := Null_Unbounded_String;
      if not Item.Opened then
         return CryptoLib.Errors.Channel_Open_Failed;
      end if;
      return Read_Link (Item.Channel, Remote_Path, Target_Path);
   exception
      when others =>
         Target_Path := Null_Unbounded_String;
         return CryptoLib.Errors.Internal_Error;
   end Read_Link;

   function Read_Link
     (Item        : in out Client;
      Remote_Path : String;
      Target_Path : out Unbounded_String;
      Result      : out SFTP_Result) return CryptoLib.Errors.Status
   is
      Status_Value : constant CryptoLib.Errors.Status :=
        Read_Link (Item, Remote_Path, Target_Path);
   begin
      Capture_Result (Status_Value, Result, Link_Operation);
      return Status_Value;
   end Read_Link;

   function Create_Symlink
     (Item        : in out Client;
      Target_Path : String;
      Link_Path   : String) return CryptoLib.Errors.Status is
   begin
      if not Item.Opened then
         return CryptoLib.Errors.Channel_Open_Failed;
      end if;
      return Create_Symlink (Item.Channel, Target_Path, Link_Path);
   exception
      when others =>
         return CryptoLib.Errors.Internal_Error;
   end Create_Symlink;

   function Create_Symlink
     (Item        : in out Client;
      Target_Path : String;
      Link_Path   : String;
      Result      : out SFTP_Result) return CryptoLib.Errors.Status
   is
      Status_Value : constant CryptoLib.Errors.Status :=
        Create_Symlink (Item, Target_Path, Link_Path);
   begin
      Capture_Result (Status_Value, Result, Link_Operation);
      return Status_Value;
   end Create_Symlink;

   function Close
     (Channel : in out SSH_Lib.Channels.Channel;
      Handle  : in out File_Handle;
      Result  : out SFTP_Result) return CryptoLib.Errors.Status
   is
      Status_Value : constant CryptoLib.Errors.Status := Close (Channel, Handle);
   begin
      Capture_Result (Status_Value, Result, Close_Operation);
      return Status_Value;
   end Close;

   function FStat
     (Channel    : in out SSH_Lib.Channels.Channel;
      Handle     : File_Handle;
      Attributes : out File_Attributes;
      Result     : out SFTP_Result) return CryptoLib.Errors.Status
   is
      Status_Value : constant CryptoLib.Errors.Status :=
        FStat (Channel, Handle, Attributes);
   begin
      Capture_Result (Status_Value, Result, Stat_Operation);
      return Status_Value;
   end FStat;

   function Set_Handle_Permissions
     (Channel : in out SSH_Lib.Channels.Channel;
      Handle  : File_Handle;
      Mode    : String;
      Result  : out SFTP_Result) return CryptoLib.Errors.Status
   is
      Status_Value : constant CryptoLib.Errors.Status :=
        Set_Handle_Permissions (Channel, Handle, Mode);
   begin
      Capture_Result (Status_Value, Result, Set_Attributes_Operation);
      return Status_Value;
   end Set_Handle_Permissions;

   function Set_Handle_Attributes
     (Channel    : in out SSH_Lib.Channels.Channel;
      Handle     : File_Handle;
      Attributes : File_Attributes;
      Result     : out SFTP_Result) return CryptoLib.Errors.Status
   is
      Status_Value : constant CryptoLib.Errors.Status :=
        Set_Handle_Attributes (Channel, Handle, Attributes);
   begin
      Capture_Result (Status_Value, Result, Set_Attributes_Operation);
      return Status_Value;
   end Set_Handle_Attributes;

   function Hardlink
     (Channel  : in out SSH_Lib.Channels.Channel;
      Old_Path : String;
      New_Path : String;
      Result   : out SFTP_Result) return CryptoLib.Errors.Status
   is
      Status_Value : constant CryptoLib.Errors.Status :=
        Hardlink (Channel, Old_Path, New_Path);
   begin
      Capture_Result (Status_Value, Result, Link_Operation);
      return Status_Value;
   end Hardlink;

   function Hardlink
     (Session  : in out SSH_Lib.Sessions.Session;
      Old_Path : String;
      New_Path : String;
      Result   : out SFTP_Result) return CryptoLib.Errors.Status
   is
      Status_Value : constant CryptoLib.Errors.Status :=
        Hardlink (Session, Old_Path, New_Path);
   begin
      Capture_Result (Status_Value, Result, Link_Operation);
      return Status_Value;
   end Hardlink;

   function Fsync
     (Channel : in out SSH_Lib.Channels.Channel;
      Handle  : File_Handle;
      Result  : out SFTP_Result) return CryptoLib.Errors.Status
   is
      Status_Value : constant CryptoLib.Errors.Status := Fsync (Channel, Handle);
   begin
      Capture_Result (Status_Value, Result, Extended_Operation);
      return Status_Value;
   end Fsync;

   function Fsync
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Result      : out SFTP_Result) return CryptoLib.Errors.Status
   is
      Status_Value : constant CryptoLib.Errors.Status :=
        Fsync (Session, Remote_Path);
   begin
      Capture_Result (Status_Value, Result, Extended_Operation);
      return Status_Value;
   end Fsync;

   function Expand_Path
     (Channel       : in out SSH_Lib.Channels.Channel;
      Remote_Path   : String;
      Expanded_Path : out Unbounded_String;
      Result        : out SFTP_Result) return CryptoLib.Errors.Status
   is
      Status_Value : constant CryptoLib.Errors.Status :=
        Expand_Path (Channel, Remote_Path, Expanded_Path);
   begin
      Capture_Result (Status_Value, Result, Extended_Operation);
      return Status_Value;
   end Expand_Path;

   function Expand_Path
     (Session       : in out SSH_Lib.Sessions.Session;
      Remote_Path   : String;
      Expanded_Path : out Unbounded_String;
      Result        : out SFTP_Result) return CryptoLib.Errors.Status
   is
      Status_Value : constant CryptoLib.Errors.Status :=
        Expand_Path (Session, Remote_Path, Expanded_Path);
   begin
      Capture_Result (Status_Value, Result, Extended_Operation);
      return Status_Value;
   end Expand_Path;

   function Expand_Path
     (Item          : in out Client;
      Remote_Path   : String;
      Expanded_Path : out Unbounded_String;
      Result        : out SFTP_Result) return CryptoLib.Errors.Status
   is
      Status_Value : constant CryptoLib.Errors.Status :=
        Expand_Path (Item, Remote_Path, Expanded_Path);
   begin
      Capture_Result (Status_Value, Result, Extended_Operation);
      return Status_Value;
   end Expand_Path;

   function Copy_Data
     (Channel       : in out SSH_Lib.Channels.Channel;
      Source_Handle : File_Handle;
      Source_Offset : Interfaces.Unsigned_64;
      Length        : Interfaces.Unsigned_64;
      Target_Handle : File_Handle;
      Target_Offset : Interfaces.Unsigned_64;
      Result        : out SFTP_Result) return CryptoLib.Errors.Status
   is
      Status_Value : constant CryptoLib.Errors.Status :=
        Copy_Data
          (Channel, Source_Handle, Source_Offset, Length, Target_Handle,
           Target_Offset);
   begin
      Capture_Result (Status_Value, Result, Extended_Operation);
      return Status_Value;
   end Copy_Data;

   function Copy_File_Range
     (Session            : in out SSH_Lib.Sessions.Session;
      Source_Remote_Path : String;
      Target_Remote_Path : String;
      Source_Offset      : Interfaces.Unsigned_64;
      Length             : Interfaces.Unsigned_64;
      Target_Offset      : Interfaces.Unsigned_64;
      Mode               : String;
      Result             : out SFTP_Result) return CryptoLib.Errors.Status
   is
      Status_Value : constant CryptoLib.Errors.Status :=
        Copy_File_Range
          (Session, Source_Remote_Path, Target_Remote_Path, Source_Offset,
           Length, Target_Offset, Mode);
   begin
      Capture_Result (Status_Value, Result, Extended_Operation);
      return Status_Value;
   end Copy_File_Range;

   function LSet_Attributes
     (Channel     : in out SSH_Lib.Channels.Channel;
      Remote_Path : String;
      Attributes  : File_Attributes;
      Result      : out SFTP_Result) return CryptoLib.Errors.Status
   is
      Status_Value : constant CryptoLib.Errors.Status :=
        LSet_Attributes (Channel, Remote_Path, Attributes);
   begin
      Capture_Result (Status_Value, Result, Set_Attributes_Operation);
      return Status_Value;
   end LSet_Attributes;

   function LSet_Attributes
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Attributes  : File_Attributes;
      Result      : out SFTP_Result) return CryptoLib.Errors.Status
   is
      Status_Value : constant CryptoLib.Errors.Status :=
        LSet_Attributes (Session, Remote_Path, Attributes);
   begin
      Capture_Result (Status_Value, Result, Set_Attributes_Operation);
      return Status_Value;
   end LSet_Attributes;

   function Create_Link
     (Channel  : in out SSH_Lib.Channels.Channel;
      New_Link : String;
      Existing : String;
      Symbolic : Boolean;
      Result   : out SFTP_Result) return CryptoLib.Errors.Status
   is
      Status_Value : constant CryptoLib.Errors.Status :=
        Create_Link (Channel, New_Link, Existing, Symbolic);
   begin
      Capture_Result (Status_Value, Result, Link_Operation);
      return Status_Value;
   end Create_Link;

   function Create_Link
     (Item     : in out Client;
      New_Link : String;
      Existing : String;
      Symbolic : Boolean;
      Result   : out SFTP_Result) return CryptoLib.Errors.Status
   is
      Status_Value : constant CryptoLib.Errors.Status :=
        Create_Link (Item, New_Link, Existing, Symbolic);
   begin
      Capture_Result (Status_Value, Result, Link_Operation);
      return Status_Value;
   end Create_Link;

   function Create_Link
     (Session  : in out SSH_Lib.Sessions.Session;
      New_Link : String;
      Existing : String;
      Symbolic : Boolean;
      Result   : out SFTP_Result) return CryptoLib.Errors.Status
   is
      Status_Value : constant CryptoLib.Errors.Status :=
        Create_Link (Session, New_Link, Existing, Symbolic);
   begin
      Capture_Result (Status_Value, Result, Link_Operation);
      return Status_Value;
   end Create_Link;

end SSH_Lib.SFTP;
