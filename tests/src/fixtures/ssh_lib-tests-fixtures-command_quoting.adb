with Ada.Calendar;
with Ada.Directories;
with Ada.Streams;
with Ada.Streams.Stream_IO;
with Ada.Strings.Unbounded;
with Ada.Text_IO;
with Interfaces;
with SSH_Lib.Channels;
with SSH_Lib.Channels.Test_Support;
with CryptoLib.Errors;
with SSH_Lib.File_Transfer;
with SSH_Lib.Git;
with SSH_Lib.Protocol.Buffers;
with SSH_Lib.Protocol.Channels;
with SSH_Lib.Protocol.Numbers;
with SSH_Lib.SCP;
with SSH_Lib.SFTP;
with SSH_Lib.Sessions;
with SSH_Lib.Sessions.Test_Support;
with SSH_Lib.Tests.Assertions;
with SSH_Lib.Tests.Fixtures.Temp_Paths;

package body SSH_Lib.Tests.Fixtures.Command_Quoting is

   use Ada.Strings.Unbounded;
   use type CryptoLib.Errors.Status;
   use type Ada.Streams.Stream_Element_Offset;
   use type Ada.Streams.Stream_Element_Array;
   use type Interfaces.Unsigned_32;
   use type Interfaces.Unsigned_64;
   use type SSH_Lib.SFTP.Recursive_Entry_Kind;
   use type Ada.Calendar.Time;

   procedure Check (Condition : Boolean; Label_Text : String) is
   begin
      if not Condition then
         Ada.Text_IO.Put_Line ("FAILED: " & Label_Text);
         raise Program_Error;
      end if;
   end Check;

   procedure Check_Natural_Equal
     (Left       : Natural;
      Right      : Natural;
      Label_Text : String)
   is
   begin
      Check (Left = Right, Label_Text);
   end Check_Natural_Equal;

   Recursive_Filter_Calls   : Natural := 0;
   Recursive_Progress_Calls : Natural := 0;

   function Include_Directories_Only
     (Source_Path : String;
      Target_Path : String;
      Kind        : SSH_Lib.SFTP.Recursive_Entry_Kind)
      return Boolean
   is
      pragma Unreferenced (Source_Path, Target_Path);
   begin
      Recursive_Filter_Calls := Recursive_Filter_Calls + 1;
      return Kind = SSH_Lib.SFTP.Tree_Directory;
   end Include_Directories_Only;

   procedure Count_Recursive_Progress
     (Operation   : SSH_Lib.SFTP.Recursive_Operation;
      Source_Path : String;
      Target_Path : String;
      Bytes_Done  : Interfaces.Unsigned_64;
      Bytes_Total : Interfaces.Unsigned_64)
   is
      pragma Unreferenced (Operation, Source_Path, Target_Path, Bytes_Done, Bytes_Total);
   begin
      Recursive_Progress_Calls := Recursive_Progress_Calls + 1;
   end Count_Recursive_Progress;

   function Include_All_Recursive
     (Source_Path : String;
      Target_Path : String;
      Kind        : SSH_Lib.SFTP.Recursive_Entry_Kind)
      return Boolean
   is
      pragma Unreferenced (Source_Path, Target_Path, Kind);
   begin
      Recursive_Filter_Calls := Recursive_Filter_Calls + 1;
      return True;
   end Include_All_Recursive;

   function Bytes_From_String (Value : String) return Ada.Streams.Stream_Element_Array is
      Result : Ada.Streams.Stream_Element_Array
        (Ada.Streams.Stream_Element_Offset'(1) .. Ada.Streams.Stream_Element_Offset (Value'Length));
      Cursor : Ada.Streams.Stream_Element_Offset := Result'First;
   begin
      for Character_Value of Value loop
         Result (Cursor) := Ada.Streams.Stream_Element (Character'Pos (Character_Value));
         Cursor := Cursor + 1;
      end loop;
      return Result;
   end Bytes_From_String;

   Stream_Download_Buffer : SSH_Lib.Protocol.Buffers.Packet_Buffer;
   Stream_Upload_Source   : SSH_Lib.Protocol.Buffers.Packet_Buffer;
   Stream_Upload_Limit    : Natural := 0;
   Directory_Page_Calls   : Natural := 0;
   Directory_Page_Entries : Natural := 0;
   Directory_Page_Names   : Unbounded_String;

   function Capture_Directory_Page
     (Entries : SSH_Lib.SFTP.Directory_Entry_Vectors.Vector)
      return CryptoLib.Errors.Status
   is
   begin
      Directory_Page_Calls := Directory_Page_Calls + 1;
      Directory_Page_Entries := Directory_Page_Entries + Natural (Entries.Length);
      for Item of Entries loop
         if Length (Directory_Page_Names) > 0 then
            Append (Directory_Page_Names, Character'Val (10));
         end if;
         Append (Directory_Page_Names, To_String (Item.Name));
      end loop;
      return CryptoLib.Errors.Ok;
   exception
      when others =>
         return CryptoLib.Errors.Internal_Error;
   end Capture_Directory_Page;

   function Capture_Stream_Chunk
     (Offset : Interfaces.Unsigned_64;
      Data   : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status
   is
      pragma Unreferenced (Offset);
   begin
      return SSH_Lib.Protocol.Buffers.Append (Stream_Download_Buffer, Data);
   exception
      when others =>
         return CryptoLib.Errors.Internal_Error;
   end Capture_Stream_Chunk;

   function Provide_Stream_Chunk
     (Offset         : Interfaces.Unsigned_64;
      Maximum_Length : Natural;
      Data           : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status
   is
      Source      : constant Ada.Streams.Stream_Element_Array :=
        SSH_Lib.Protocol.Buffers.To_Array (Stream_Upload_Source);
      Start_Index : Ada.Streams.Stream_Element_Offset;
      Count       : Natural;
   begin
      SSH_Lib.Protocol.Buffers.Clear (Data);
      if Offset > Interfaces.Unsigned_64 (Source'Length) then
         return CryptoLib.Errors.Read_Failed;
      end if;

      Count := Source'Length - Natural (Offset);
      if Stream_Upload_Limit > 0 and then Count > Stream_Upload_Limit then
         Count := Stream_Upload_Limit;
      end if;
      if Count > Maximum_Length then
         Count := Maximum_Length;
      end if;
      if Count = 0 then
         return CryptoLib.Errors.Read_Failed;
      end if;

      Start_Index := Source'First + Ada.Streams.Stream_Element_Offset (Offset);
      return SSH_Lib.Protocol.Buffers.Set
        (Data, Source (Start_Index .. Start_Index + Ada.Streams.Stream_Element_Offset (Count) - 1));
   exception
      when others =>
         SSH_Lib.Protocol.Buffers.Clear (Data);
         return CryptoLib.Errors.Internal_Error;
   end Provide_Stream_Chunk;

   function Build_Open_Confirmation
     (Recipient_Channel   : Interfaces.Unsigned_32;
      Sender_Channel      : Interfaces.Unsigned_32;
      Initial_Window_Size : Interfaces.Unsigned_32;
      Maximum_Packet_Size : Interfaces.Unsigned_32)
      return Ada.Streams.Stream_Element_Array
   is
      Work_Item : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Status_Value : CryptoLib.Errors.Status;
   begin
      SSH_Lib.Protocol.Buffers.Clear (Work_Item);
      Status_Value := SSH_Lib.Protocol.Buffers.Append_Byte
        (Work_Item, SSH_Lib.Protocol.Channels.SSH_MSG_CHANNEL_OPEN_CONFIRMATION);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok, "command quoting fixture", "open confirmation type");
      Status_Value := SSH_Lib.Protocol.Buffers.Append
        (Work_Item, SSH_Lib.Protocol.Numbers.Encode_Uint32 (Recipient_Channel));
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok, "command quoting fixture", "open confirmation recipient");
      Status_Value := SSH_Lib.Protocol.Buffers.Append
        (Work_Item, SSH_Lib.Protocol.Numbers.Encode_Uint32 (Sender_Channel));
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok, "command quoting fixture", "open confirmation sender");
      Status_Value := SSH_Lib.Protocol.Buffers.Append
        (Work_Item, SSH_Lib.Protocol.Numbers.Encode_Uint32 (Initial_Window_Size));
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok, "command quoting fixture", "open confirmation window");
      Status_Value := SSH_Lib.Protocol.Buffers.Append
        (Work_Item, SSH_Lib.Protocol.Numbers.Encode_Uint32 (Maximum_Packet_Size));
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok, "command quoting fixture", "open confirmation max packet");
      return SSH_Lib.Protocol.Buffers.To_Array (Work_Item);
   end Build_Open_Confirmation;

   function Build_Exec_Success
     (Recipient_Channel : Interfaces.Unsigned_32)
      return Ada.Streams.Stream_Element_Array
   is
      Work_Item : constant SSH_Lib.Protocol.Buffers.Packet_Buffer :=
        SSH_Lib.Protocol.Channels.Encode_Channel_Success (Recipient_Channel);
   begin
      return SSH_Lib.Protocol.Buffers.To_Array (Work_Item);
   end Build_Exec_Success;

   procedure Check_Build
     (Repository_Path  : String;
      Expected_Upload  : String;
      Expected_Receive : String := "")
   is
      Command_Text : Unbounded_String;
      Status_Value : CryptoLib.Errors.Status;
      Receive_Expected : constant String :=
        (if Expected_Receive'Length = 0
         then "git-receive-pack " & Expected_Upload (Expected_Upload'First + 16 .. Expected_Upload'Last)
         else Expected_Receive);
   begin
      Status_Value := SSH_Lib.Git.Build_Upload_Pack_Command (Repository_Path, Command_Text);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok, "Git command quoting", Repository_Path);
      Check (To_String (Command_Text) = Expected_Upload,
             "repository path quoted exactly for upload-pack: " & Repository_Path);
      Check (SSH_Lib.Protocol.Channels.Valid_Command (To_String (Command_Text)),
             "generated upload-pack command is accepted by Open_Exec validation");

      Status_Value := SSH_Lib.Git.Build_Receive_Pack_Command (Repository_Path, Command_Text);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok, "Git receive command quoting", Repository_Path);
      Check (To_String (Command_Text) = Receive_Expected,
             "repository path quoted exactly for receive-pack: " & Repository_Path);
      Check (SSH_Lib.Protocol.Channels.Valid_Command (To_String (Command_Text)),
             "generated receive-pack command is accepted by Open_Exec validation");
   end Check_Build;

   procedure Check_Rejected (Repository_Path : String; Label_Text : String) is
      Command_Text : Unbounded_String := To_Unbounded_String ("leftover");
      Status_Value : CryptoLib.Errors.Status;
      Raised : Boolean := False;
   begin
      Status_Value := SSH_Lib.Git.Build_Upload_Pack_Command (Repository_Path, Command_Text);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Invalid_Command, "Git command rejection", Label_Text);
      Check (Length (Command_Text) = 0, "rejected upload command leaves no command text: " & Label_Text);

      Status_Value := SSH_Lib.Git.Build_Receive_Pack_Command (Repository_Path, Command_Text);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Invalid_Command, "Git receive command rejection", Label_Text);
      Check (Length (Command_Text) = 0, "rejected receive command leaves no command text: " & Label_Text);

      begin
         declare
            Ignored : constant String := SSH_Lib.Git.Upload_Pack_Command (Repository_Path);
            pragma Unreferenced (Ignored);
         begin
            null;
         end;
      exception
         when Constraint_Error =>
            Raised := True;
      end;
      Check (Raised, "convenience wrapper raises Constraint_Error for " & Label_Text);
   end Check_Rejected;

   procedure Check_SCP_Command
     (Remote_Path      : String;
      Expected_Command : String)
   is
      Command_Text : Unbounded_String;
      Status_Value : CryptoLib.Errors.Status;
   begin
      Status_Value := SSH_Lib.SCP.Build_Upload_Command (Remote_Path, Command_Text);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok, "SCP command quoting", Remote_Path);
      Check (To_String (Command_Text) = Expected_Command,
             "SCP remote path quoted exactly: " & Remote_Path);
      Check (SSH_Lib.Protocol.Channels.Valid_Command (To_String (Command_Text)),
             "generated SCP command is accepted by Open_Exec validation");
   end Check_SCP_Command;

   procedure Check_SCP_Command_Rejected
     (Remote_Path : String;
      Label_Text  : String)
   is
      Command_Text : Unbounded_String := To_Unbounded_String ("leftover");
      Status_Value : CryptoLib.Errors.Status;
   begin
      Status_Value := SSH_Lib.SCP.Build_Upload_Command (Remote_Path, Command_Text);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Invalid_Command, "SCP command rejection", Label_Text);
      Check (Length (Command_Text) = 0, "rejected SCP command leaves no command text: " & Label_Text);
   end Check_SCP_Command_Rejected;

   procedure Check_SCP_Header
     (File_Name       : String;
      Size            : Natural;
      Mode            : String;
      Expected_Header : String)
   is
      Header_Text  : Unbounded_String;
      Status_Value : CryptoLib.Errors.Status;
   begin
      Status_Value := SSH_Lib.SCP.Build_File_Header (File_Name, Size, Mode, Header_Text);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok, "SCP file header", File_Name);
      Check (To_String (Header_Text) = Expected_Header,
             "SCP file header is exact for " & File_Name);
   end Check_SCP_Header;

   procedure Check_SCP_Header_Rejected
     (File_Name  : String;
      Size       : Natural;
      Mode       : String;
      Label_Text : String)
   is
      Header_Text  : Unbounded_String := To_Unbounded_String ("leftover");
      Status_Value : CryptoLib.Errors.Status;
   begin
      Status_Value := SSH_Lib.SCP.Build_File_Header (File_Name, Size, Mode, Header_Text);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Invalid_Command, "SCP header rejection", Label_Text);
      Check (Length (Header_Text) = 0, "rejected SCP header leaves no text: " & Label_Text);
   end Check_SCP_Header_Rejected;

   procedure Assert_SCP_Channel_Data
     (Payload       : Ada.Streams.Stream_Element_Array;
      Expected_Data : Ada.Streams.Stream_Element_Array;
      Label_Text    : String)
   is
      Event : SSH_Lib.Protocol.Channels.Channel_Data_Event;
      Status_Value : CryptoLib.Errors.Status;
   begin
      Status_Value := SSH_Lib.Protocol.Channels.Parse_Channel_Data
        (Payload, Expected_Recipient => 1, Item => Event);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok, "SCP upload", Label_Text & " parse channel data");
      SSH_Lib.Tests.Assertions.Check_Bytes
        (SSH_Lib.Protocol.Buffers.To_Array (Event.Data),
         Expected_Data,
         "SCP upload",
         Label_Text & " frame bytes exact");
   end Assert_SCP_Channel_Data;

   procedure Assert_SCP_Channel_Data
     (Channel_Item : SSH_Lib.Channels.Channel;
      Expected_Data : Ada.Streams.Stream_Element_Array;
      Label_Text : String)
   is
      Payload : constant Ada.Streams.Stream_Element_Array :=
        SSH_Lib.Channels.Test_Support.Last_Channel_Data_Payload_For_Test
          (Channel_Item);
      Event : SSH_Lib.Protocol.Channels.Channel_Data_Event;
      Status_Value : CryptoLib.Errors.Status;
   begin
      Status_Value := SSH_Lib.Protocol.Channels.Parse_Channel_Data
        (Payload, Expected_Recipient => 1, Item => Event);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok, "SCP upload", Label_Text & " parse channel data");
      SSH_Lib.Tests.Assertions.Check_Bytes
        (SSH_Lib.Protocol.Buffers.To_Array (Event.Data),
         Expected_Data,
         "SCP upload",
         Label_Text & " frame bytes exact");
   end Assert_SCP_Channel_Data;

   procedure Queue_SCP_Acks
     (Channel_Item : in out SSH_Lib.Channels.Channel;
      Ack_Bytes    : Ada.Streams.Stream_Element_Array;
      Label_Text   : String)
   is
      Status_Value : CryptoLib.Errors.Status;
   begin
      Status_Value := SSH_Lib.Channels.Test_Support.Queue_Stdout_For_Test
        (Channel_Item, Ack_Bytes);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok, "SCP upload", Label_Text & " queue ACK bytes");
   end Queue_SCP_Acks;

   function SFTP_Status_Packet
     (Request_Id : Interfaces.Unsigned_32;
      Code       : Interfaces.Unsigned_32 := SSH_Lib.SFTP.SSH_FX_OK)
      return Ada.Streams.Stream_Element_Array is
   begin
      return SSH_Lib.Protocol.Numbers.Encode_Uint32 (17)
        & Bytes_From_String ("" & Character'Val (SSH_Lib.SFTP.SSH_FXP_STATUS))
        & SSH_Lib.Protocol.Numbers.Encode_Uint32 (Request_Id)
        & SSH_Lib.Protocol.Numbers.Encode_Uint32 (Code)
        & SSH_Lib.Protocol.Numbers.Encode_Uint32 (0)
        & SSH_Lib.Protocol.Numbers.Encode_Uint32 (0);
   end SFTP_Status_Packet;

   function SFTP_Handle_Packet
     (Request_Id : Interfaces.Unsigned_32;
      Handle     : String)
      return Ada.Streams.Stream_Element_Array is
   begin
      return SSH_Lib.Protocol.Numbers.Encode_Uint32
          (Interfaces.Unsigned_32 (9 + Handle'Length))
        & Bytes_From_String ("" & Character'Val (SSH_Lib.SFTP.SSH_FXP_HANDLE))
        & SSH_Lib.Protocol.Numbers.Encode_Uint32 (Request_Id)
        & SSH_Lib.Protocol.Numbers.Encode_Uint32
            (Interfaces.Unsigned_32 (Handle'Length))
        & Bytes_From_String (Handle);
   end SFTP_Handle_Packet;

   function SFTP_Data_Packet
     (Request_Id : Interfaces.Unsigned_32;
      Value      : String)
      return Ada.Streams.Stream_Element_Array is
   begin
      return SSH_Lib.Protocol.Numbers.Encode_Uint32
          (Interfaces.Unsigned_32 (9 + Value'Length))
        & Bytes_From_String ("" & Character'Val (SSH_Lib.SFTP.SSH_FXP_DATA))
        & SSH_Lib.Protocol.Numbers.Encode_Uint32 (Request_Id)
        & SSH_Lib.Protocol.Numbers.Encode_Uint32
            (Interfaces.Unsigned_32 (Value'Length))
        & Bytes_From_String (Value);
   end SFTP_Data_Packet;

   function SFTP_Name_Entry (Name : String) return Ada.Streams.Stream_Element_Array is
   begin
      return SSH_Lib.Protocol.Numbers.Encode_Uint32
          (Interfaces.Unsigned_32 (Name'Length))
        & Bytes_From_String (Name)
        & SSH_Lib.Protocol.Numbers.Encode_Uint32
          (Interfaces.Unsigned_32 (Name'Length))
        & Bytes_From_String (Name)
        & SSH_Lib.Protocol.Numbers.Encode_Uint32 (0);
   end SFTP_Name_Entry;

   function SFTP_Name_Packet
     (Request_Id : Interfaces.Unsigned_32;
      First_Name : String;
      Second_Name : String := "")
      return Ada.Streams.Stream_Element_Array
   is
      Count : constant Interfaces.Unsigned_32 :=
        (if Second_Name'Length = 0 then 1 else 2);
      Entries : constant Ada.Streams.Stream_Element_Array :=
        (if Second_Name'Length = 0
         then SFTP_Name_Entry (First_Name)
         else SFTP_Name_Entry (First_Name) & SFTP_Name_Entry (Second_Name));
   begin
      return SSH_Lib.Protocol.Numbers.Encode_Uint32
          (Interfaces.Unsigned_32 (9 + Entries'Length))
        & Bytes_From_String ("" & Character'Val (SSH_Lib.SFTP.SSH_FXP_NAME))
        & SSH_Lib.Protocol.Numbers.Encode_Uint32 (Request_Id)
        & SSH_Lib.Protocol.Numbers.Encode_Uint32 (Count)
        & Entries;
   end SFTP_Name_Packet;

   function Encode_Test_Uint64
     (Value : Interfaces.Unsigned_64) return Ada.Streams.Stream_Element_Array
   is
   begin
      return Bytes_From_String
        (Character'Val (Integer (Value / 16#01_00_00_00_00_00_00# mod 256))
         & Character'Val (Integer (Value / 16#00_01_00_00_00_00_00# mod 256))
         & Character'Val (Integer (Value / 16#00_00_01_00_00_00_00# mod 256))
         & Character'Val (Integer (Value / 16#00_00_00_01_00_00_00# mod 256))
         & Character'Val (Integer (Value / 16#00_00_00_00_01_00_00# mod 256))
         & Character'Val (Integer (Value / 16#00_00_00_00_00_01_00# mod 256))
         & Character'Val (Integer (Value / 16#00_00_00_00_00_00_01# mod 256))
         & Character'Val (Integer (Value mod 256)));
   end Encode_Test_Uint64;

   function SFTP_Name_Entry_With_Attrs
     (Name        : String;
      Long_Name   : String;
      Size        : Interfaces.Unsigned_64;
      Permissions : Interfaces.Unsigned_32)
      return Ada.Streams.Stream_Element_Array is
   begin
      return SSH_Lib.Protocol.Numbers.Encode_Uint32
          (Interfaces.Unsigned_32 (Name'Length))
        & Bytes_From_String (Name)
        & SSH_Lib.Protocol.Numbers.Encode_Uint32
          (Interfaces.Unsigned_32 (Long_Name'Length))
        & Bytes_From_String (Long_Name)
        & SSH_Lib.Protocol.Numbers.Encode_Uint32 (16#0000_0005#)
        & Encode_Test_Uint64 (Size)
        & SSH_Lib.Protocol.Numbers.Encode_Uint32 (Permissions);
   end SFTP_Name_Entry_With_Attrs;

   function SFTP_Detailed_Name_Packet
     (Request_Id : Interfaces.Unsigned_32)
      return Ada.Streams.Stream_Element_Array
   is
      Entries : constant Ada.Streams.Stream_Element_Array :=
        SFTP_Name_Entry_With_Attrs ("alpha.txt", "-rw-r----- alpha.txt", 14, 8#640#)
        & SFTP_Name_Entry_With_Attrs ("logs", "drwxr-x--- logs", 0, 8#750#);
   begin
      return SSH_Lib.Protocol.Numbers.Encode_Uint32
          (Interfaces.Unsigned_32 (9 + Entries'Length))
        & Bytes_From_String ("" & Character'Val (SSH_Lib.SFTP.SSH_FXP_NAME))
        & SSH_Lib.Protocol.Numbers.Encode_Uint32 (Request_Id)
        & SSH_Lib.Protocol.Numbers.Encode_Uint32 (2)
        & Entries;
   end SFTP_Detailed_Name_Packet;

   function SFTP_Typed_Name_Entry
     (Name        : String;
      Permissions : Interfaces.Unsigned_32)
      return Ada.Streams.Stream_Element_Array is
   begin
      return SSH_Lib.Protocol.Numbers.Encode_Uint32
          (Interfaces.Unsigned_32 (Name'Length))
        & Bytes_From_String (Name)
        & SSH_Lib.Protocol.Numbers.Encode_Uint32
          (Interfaces.Unsigned_32 (Name'Length))
        & Bytes_From_String (Name)
        & SSH_Lib.Protocol.Numbers.Encode_Uint32 (16#0000_0004#)
        & SSH_Lib.Protocol.Numbers.Encode_Uint32 (Permissions);
   end SFTP_Typed_Name_Entry;

   function SFTP_Typed_Name_Packet
     (Request_Id        : Interfaces.Unsigned_32;
      First_Name        : String;
      First_Permissions : Interfaces.Unsigned_32;
      Second_Name       : String := "";
      Second_Permissions : Interfaces.Unsigned_32 := 0)
      return Ada.Streams.Stream_Element_Array
   is
      Count : constant Interfaces.Unsigned_32 :=
        (if Second_Name'Length = 0 then 1 else 2);
      Entries : constant Ada.Streams.Stream_Element_Array :=
        (if Second_Name'Length = 0
         then SFTP_Typed_Name_Entry (First_Name, First_Permissions)
         else SFTP_Typed_Name_Entry (First_Name, First_Permissions)
              & SFTP_Typed_Name_Entry (Second_Name, Second_Permissions));
   begin
      return SSH_Lib.Protocol.Numbers.Encode_Uint32
          (Interfaces.Unsigned_32 (9 + Entries'Length))
        & Bytes_From_String ("" & Character'Val (SSH_Lib.SFTP.SSH_FXP_NAME))
        & SSH_Lib.Protocol.Numbers.Encode_Uint32 (Request_Id)
        & SSH_Lib.Protocol.Numbers.Encode_Uint32 (Count)
        & Entries;
   end SFTP_Typed_Name_Packet;

   function SFTP_Open_Request_Packet
     (Request_Id  : Interfaces.Unsigned_32;
      Remote_Path : String;
      Flags       : Interfaces.Unsigned_32;
      Attributes  : Interfaces.Unsigned_32 := 0;
      Permissions : Interfaces.Unsigned_32 := 0)
      return Ada.Streams.Stream_Element_Array
   is
      Payload : constant Ada.Streams.Stream_Element_Array :=
        Bytes_From_String ("" & Character'Val (SSH_Lib.SFTP.SSH_FXP_OPEN))
        & SSH_Lib.Protocol.Numbers.Encode_Uint32 (Request_Id)
        & SSH_Lib.Protocol.Numbers.Encode_Uint32
            (Interfaces.Unsigned_32 (Remote_Path'Length))
        & Bytes_From_String (Remote_Path)
        & SSH_Lib.Protocol.Numbers.Encode_Uint32 (Flags)
        & SSH_Lib.Protocol.Numbers.Encode_Uint32 (Attributes)
        & (if Attributes = 0
           then Ada.Streams.Stream_Element_Array'(1 .. 0 => 0)
           else SSH_Lib.Protocol.Numbers.Encode_Uint32 (Permissions));
   begin
      return SSH_Lib.Protocol.Numbers.Encode_Uint32
          (Interfaces.Unsigned_32 (Payload'Length))
        & Payload;
   end SFTP_Open_Request_Packet;

   function SFTP_Open4_Request_Packet
     (Request_Id     : Interfaces.Unsigned_32;
      Remote_Path    : String;
      Desired_Access : Interfaces.Unsigned_32;
      Flags          : Interfaces.Unsigned_32;
      Attributes     : Interfaces.Unsigned_32 := 0;
      File_Type      : Ada.Streams.Stream_Element := 5;
      Permissions    : Interfaces.Unsigned_32 := 0)
      return Ada.Streams.Stream_Element_Array
   is
      Payload : constant Ada.Streams.Stream_Element_Array :=
        Bytes_From_String ("" & Character'Val (SSH_Lib.SFTP.SSH_FXP_OPEN))
        & SSH_Lib.Protocol.Numbers.Encode_Uint32 (Request_Id)
        & SSH_Lib.Protocol.Numbers.Encode_Uint32
            (Interfaces.Unsigned_32 (Remote_Path'Length))
        & Bytes_From_String (Remote_Path)
        & SSH_Lib.Protocol.Numbers.Encode_Uint32 (Desired_Access)
        & SSH_Lib.Protocol.Numbers.Encode_Uint32 (Flags)
        & SSH_Lib.Protocol.Numbers.Encode_Uint32 (Attributes)
        & Bytes_From_String ("" & Character'Val (File_Type))
        & (if Attributes = 0
           then Ada.Streams.Stream_Element_Array'(1 .. 0 => 0)
           else SSH_Lib.Protocol.Numbers.Encode_Uint32 (Permissions));
   begin
      return SSH_Lib.Protocol.Numbers.Encode_Uint32
          (Interfaces.Unsigned_32 (Payload'Length))
        & Payload;
   end SFTP_Open4_Request_Packet;

   function SFTP_Read_Request_Packet
     (Request_Id : Interfaces.Unsigned_32;
      Handle     : String;
      Offset     : Interfaces.Unsigned_64;
      Length     : Natural)
      return Ada.Streams.Stream_Element_Array
   is
      Payload : constant Ada.Streams.Stream_Element_Array :=
        Bytes_From_String ("" & Character'Val (SSH_Lib.SFTP.SSH_FXP_READ))
        & SSH_Lib.Protocol.Numbers.Encode_Uint32 (Request_Id)
        & SSH_Lib.Protocol.Numbers.Encode_Uint32
            (Interfaces.Unsigned_32 (Handle'Length))
        & Bytes_From_String (Handle)
        & Encode_Test_Uint64 (Offset)
        & SSH_Lib.Protocol.Numbers.Encode_Uint32 (Interfaces.Unsigned_32 (Length));
   begin
      return SSH_Lib.Protocol.Numbers.Encode_Uint32
          (Interfaces.Unsigned_32 (Payload'Length))
        & Payload;
   end SFTP_Read_Request_Packet;

   function SFTP_Write_Request_Packet
     (Request_Id : Interfaces.Unsigned_32;
      Handle     : String;
      Offset     : Interfaces.Unsigned_64;
      Value      : String)
      return Ada.Streams.Stream_Element_Array
   is
      Payload : constant Ada.Streams.Stream_Element_Array :=
        Bytes_From_String ("" & Character'Val (SSH_Lib.SFTP.SSH_FXP_WRITE))
        & SSH_Lib.Protocol.Numbers.Encode_Uint32 (Request_Id)
        & SSH_Lib.Protocol.Numbers.Encode_Uint32
            (Interfaces.Unsigned_32 (Handle'Length))
        & Bytes_From_String (Handle)
        & Encode_Test_Uint64 (Offset)
        & SSH_Lib.Protocol.Numbers.Encode_Uint32
            (Interfaces.Unsigned_32 (Value'Length))
        & Bytes_From_String (Value);
   begin
      return SSH_Lib.Protocol.Numbers.Encode_Uint32
          (Interfaces.Unsigned_32 (Payload'Length))
        & Payload;
   end SFTP_Write_Request_Packet;

   function SFTP_String (Value : String) return Ada.Streams.Stream_Element_Array is
   begin
      return SSH_Lib.Protocol.Numbers.Encode_Uint32
          (Interfaces.Unsigned_32 (Value'Length))
        & Bytes_From_String (Value);
   end SFTP_String;

   function SFTP_Version_Packet return Ada.Streams.Stream_Element_Array is
      Payload : constant Ada.Streams.Stream_Element_Array :=
        Bytes_From_String ("" & Character'Val (SSH_Lib.SFTP.SSH_FXP_VERSION))
        & SSH_Lib.Protocol.Numbers.Encode_Uint32 (3);
   begin
      return SSH_Lib.Protocol.Numbers.Encode_Uint32
          (Interfaces.Unsigned_32 (Payload'Length))
        & Payload;
   end SFTP_Version_Packet;

   function SFTP_Version_Packet
     (Version : Interfaces.Unsigned_32)
      return Ada.Streams.Stream_Element_Array
   is
      Payload : constant Ada.Streams.Stream_Element_Array :=
        Bytes_From_String ("" & Character'Val (SSH_Lib.SFTP.SSH_FXP_VERSION))
        & SSH_Lib.Protocol.Numbers.Encode_Uint32 (Version);
   begin
      return SSH_Lib.Protocol.Numbers.Encode_Uint32
          (Interfaces.Unsigned_32 (Payload'Length))
        & Payload;
   end SFTP_Version_Packet;

   function SFTP_Version_Extensions_Packet return Ada.Streams.Stream_Element_Array is
      Payload : constant Ada.Streams.Stream_Element_Array :=
        Bytes_From_String ("" & Character'Val (SSH_Lib.SFTP.SSH_FXP_VERSION))
        & SSH_Lib.Protocol.Numbers.Encode_Uint32 (3)
        & SFTP_String (SSH_Lib.SFTP.Posix_Rename_Extension) & SFTP_String ("1")
        & SFTP_String (SSH_Lib.SFTP.Fsync_Extension) & SFTP_String ("1")
        & SFTP_String (SSH_Lib.SFTP.StatVFS_Extension) & SFTP_String ("2")
        & SFTP_String (SSH_Lib.SFTP.Hardlink_Extension) & SFTP_String ("1")
        & SFTP_String (SSH_Lib.SFTP.LSetStat_Extension) & SFTP_String ("1")
        & SFTP_String (SSH_Lib.SFTP.Limits_Extension) & SFTP_String ("1")
        & SFTP_String (SSH_Lib.SFTP.Copy_Data_Extension) & SFTP_String ("1")
        & SFTP_String (SSH_Lib.SFTP.Expand_Path_Extension) & SFTP_String ("1")
        & SFTP_String (SSH_Lib.SFTP.Check_File_Extension) & SFTP_String ("md5,sha1")
        & SFTP_String ("unknown@example.test") & SFTP_String ("ignored");
   begin
      return SSH_Lib.Protocol.Numbers.Encode_Uint32
          (Interfaces.Unsigned_32 (Payload'Length))
        & Payload;
   end SFTP_Version_Extensions_Packet;

   function SFTP_Version_Capabilities_Packet return Ada.Streams.Stream_Element_Array is
      Supported2 : constant Ada.Streams.Stream_Element_Array :=
        SSH_Lib.Protocol.Numbers.Encode_Uint32 (16#0000_1FFF#)
        & SSH_Lib.Protocol.Numbers.Encode_Uint32 (16#0000_00FF#)
        & SSH_Lib.Protocol.Numbers.Encode_Uint32 (16#0000_000B#)
        & SSH_Lib.Protocol.Numbers.Encode_Uint32 (16#0000_0107#)
        & SSH_Lib.Protocol.Numbers.Encode_Uint32 (32768)
        & Bytes_From_String (Character'Val (16#12#) & Character'Val (16#34#))
        & Bytes_From_String (Character'Val (16#56#) & Character'Val (16#78#))
        & SSH_Lib.Protocol.Numbers.Encode_Uint32 (0)
        & SSH_Lib.Protocol.Numbers.Encode_Uint32 (1)
        & SFTP_String (SSH_Lib.SFTP.Text_Seek_Extension);
      Payload : constant Ada.Streams.Stream_Element_Array :=
        Bytes_From_String ("" & Character'Val (SSH_Lib.SFTP.SSH_FXP_VERSION))
        & SSH_Lib.Protocol.Numbers.Encode_Uint32 (6)
        & SFTP_String (SSH_Lib.SFTP.Versions_Extension) & SFTP_String ("3,4,5,6")
        & SFTP_String (SSH_Lib.SFTP.Supported2_Extension)
        & SSH_Lib.Protocol.Numbers.Encode_Uint32
            (Interfaces.Unsigned_32 (Supported2'Length))
        & Supported2;
   begin
      return SSH_Lib.Protocol.Numbers.Encode_Uint32
          (Interfaces.Unsigned_32 (Payload'Length))
        & Payload;
   end SFTP_Version_Capabilities_Packet;

   function SFTP_Version_Limited_Capabilities_Packet
      return Ada.Streams.Stream_Element_Array
   is
      Supported2 : constant Ada.Streams.Stream_Element_Array :=
        SSH_Lib.Protocol.Numbers.Encode_Uint32 (0)
        & SSH_Lib.Protocol.Numbers.Encode_Uint32 (0)
        & SSH_Lib.Protocol.Numbers.Encode_Uint32 (16#0000_0002#)
        & SSH_Lib.Protocol.Numbers.Encode_Uint32 (16#0000_0001#)
        & SSH_Lib.Protocol.Numbers.Encode_Uint32 (32768)
        & Bytes_From_String (Character'Val (0) & Character'Val (0))
        & Bytes_From_String (Character'Val (0) & Character'Val (1))
        & SSH_Lib.Protocol.Numbers.Encode_Uint32 (0)
        & SSH_Lib.Protocol.Numbers.Encode_Uint32 (0);
      Payload : constant Ada.Streams.Stream_Element_Array :=
        Bytes_From_String ("" & Character'Val (SSH_Lib.SFTP.SSH_FXP_VERSION))
        & SSH_Lib.Protocol.Numbers.Encode_Uint32 (6)
        & SFTP_String (SSH_Lib.SFTP.Versions_Extension) & SFTP_String ("3,6")
        & SFTP_String (SSH_Lib.SFTP.Supported2_Extension)
        & SSH_Lib.Protocol.Numbers.Encode_Uint32
            (Interfaces.Unsigned_32 (Supported2'Length))
        & Supported2;
   begin
      return SSH_Lib.Protocol.Numbers.Encode_Uint32
          (Interfaces.Unsigned_32 (Payload'Length))
        & Payload;
   end SFTP_Version_Limited_Capabilities_Packet;

   function SFTP_Extended_Two_Path_Request
     (Extension_Name : String;
      First_Path     : String;
      Second_Path    : String)
      return Ada.Streams.Stream_Element_Array
   is
      Payload : constant Ada.Streams.Stream_Element_Array :=
        Bytes_From_String ("" & Character'Val (SSH_Lib.SFTP.SSH_FXP_EXTENDED))
        & SSH_Lib.Protocol.Numbers.Encode_Uint32 (1)
        & SFTP_String (Extension_Name)
        & SFTP_String (First_Path)
        & SFTP_String (Second_Path);
   begin
      return SSH_Lib.Protocol.Numbers.Encode_Uint32
          (Interfaces.Unsigned_32 (Payload'Length))
        & Payload;
   end SFTP_Extended_Two_Path_Request;

   function SFTP_Extended_Handle_Request
     (Extension_Name : String;
      Handle         : String)
      return Ada.Streams.Stream_Element_Array
   is
      Payload : constant Ada.Streams.Stream_Element_Array :=
        Bytes_From_String ("" & Character'Val (SSH_Lib.SFTP.SSH_FXP_EXTENDED))
        & SSH_Lib.Protocol.Numbers.Encode_Uint32 (1)
        & SFTP_String (Extension_Name)
        & SFTP_String (Handle);
   begin
      return SSH_Lib.Protocol.Numbers.Encode_Uint32
          (Interfaces.Unsigned_32 (Payload'Length))
        & Payload;
   end SFTP_Extended_Handle_Request;

   function SFTP_Extended_Copy_Data_Request
     (Source_Handle : String;
      Source_Offset : Interfaces.Unsigned_64;
      Length        : Interfaces.Unsigned_64;
      Target_Handle : String;
      Target_Offset : Interfaces.Unsigned_64)
      return Ada.Streams.Stream_Element_Array
   is
      Payload : constant Ada.Streams.Stream_Element_Array :=
        Bytes_From_String ("" & Character'Val (SSH_Lib.SFTP.SSH_FXP_EXTENDED))
        & SSH_Lib.Protocol.Numbers.Encode_Uint32 (1)
        & SFTP_String (SSH_Lib.SFTP.Copy_Data_Extension)
        & SFTP_String (Source_Handle)
        & Encode_Test_Uint64 (Source_Offset)
        & Encode_Test_Uint64 (Length)
        & SFTP_String (Target_Handle)
        & Encode_Test_Uint64 (Target_Offset);
   begin
      return SSH_Lib.Protocol.Numbers.Encode_Uint32
          (Interfaces.Unsigned_32 (Payload'Length))
        & Payload;
   end SFTP_Extended_Copy_Data_Request;

   function SFTP_Extended_Check_File_Request
     (Handle       : String;
      Algorithms   : String;
      Offset       : Interfaces.Unsigned_64;
      Length       : Interfaces.Unsigned_64;
      Block_Size   : Interfaces.Unsigned_32)
      return Ada.Streams.Stream_Element_Array
   is
      Payload : constant Ada.Streams.Stream_Element_Array :=
        Bytes_From_String ("" & Character'Val (SSH_Lib.SFTP.SSH_FXP_EXTENDED))
        & SSH_Lib.Protocol.Numbers.Encode_Uint32 (1)
        & SFTP_String (SSH_Lib.SFTP.Check_File_Extension)
        & SFTP_String (Handle)
        & SFTP_String (Algorithms)
        & Encode_Test_Uint64 (Offset)
        & Encode_Test_Uint64 (Length)
        & SSH_Lib.Protocol.Numbers.Encode_Uint32 (Block_Size);
   begin
      return SSH_Lib.Protocol.Numbers.Encode_Uint32
          (Interfaces.Unsigned_32 (Payload'Length))
        & Payload;
   end SFTP_Extended_Check_File_Request;

   function SFTP_Extended_Name_Request
     (Extension_Name : String)
      return Ada.Streams.Stream_Element_Array
   is
      Payload : constant Ada.Streams.Stream_Element_Array :=
        Bytes_From_String ("" & Character'Val (SSH_Lib.SFTP.SSH_FXP_EXTENDED))
        & SSH_Lib.Protocol.Numbers.Encode_Uint32 (1)
        & SFTP_String (Extension_Name);
   begin
      return SSH_Lib.Protocol.Numbers.Encode_Uint32
          (Interfaces.Unsigned_32 (Payload'Length))
        & Payload;
   end SFTP_Extended_Name_Request;

   function SFTP_Extended_Path_Request
     (Extension_Name : String;
      Remote_Path    : String)
      return Ada.Streams.Stream_Element_Array
   is
      Payload : constant Ada.Streams.Stream_Element_Array :=
        Bytes_From_String ("" & Character'Val (SSH_Lib.SFTP.SSH_FXP_EXTENDED))
        & SSH_Lib.Protocol.Numbers.Encode_Uint32 (1)
        & SFTP_String (Extension_Name)
        & SFTP_String (Remote_Path);
   begin
      return SSH_Lib.Protocol.Numbers.Encode_Uint32
          (Interfaces.Unsigned_32 (Payload'Length))
        & Payload;
   end SFTP_Extended_Path_Request;

   function SFTP_Extended_Raw_Request
     (Extension_Name : String;
      Payload_Data   : Ada.Streams.Stream_Element_Array)
      return Ada.Streams.Stream_Element_Array
   is
      Payload : constant Ada.Streams.Stream_Element_Array :=
        Bytes_From_String ("" & Character'Val (SSH_Lib.SFTP.SSH_FXP_EXTENDED))
        & SSH_Lib.Protocol.Numbers.Encode_Uint32 (1)
        & SFTP_String (Extension_Name)
        & Payload_Data;
   begin
      return SSH_Lib.Protocol.Numbers.Encode_Uint32
          (Interfaces.Unsigned_32 (Payload'Length))
        & Payload;
   end SFTP_Extended_Raw_Request;

   function SFTP_Link_Request
     (New_Link : String;
      Existing : String;
      Symbolic : Boolean)
      return Ada.Streams.Stream_Element_Array
   is
      Payload : constant Ada.Streams.Stream_Element_Array :=
        Bytes_From_String ("" & Character'Val (SSH_Lib.SFTP.SSH_FXP_LINK))
        & SSH_Lib.Protocol.Numbers.Encode_Uint32 (1)
        & SFTP_String (New_Link)
        & SFTP_String (Existing)
        & Bytes_From_String ("" & Character'Val ((if Symbolic then 1 else 0)));
   begin
      return SSH_Lib.Protocol.Numbers.Encode_Uint32
          (Interfaces.Unsigned_32 (Payload'Length))
        & Payload;
   end SFTP_Link_Request;

   function SFTP_Block_Request
     (Message   : Ada.Streams.Stream_Element;
      Handle    : String;
      Offset    : Interfaces.Unsigned_64;
      Length    : Interfaces.Unsigned_64;
      Lock_Mask : Interfaces.Unsigned_32 := 0)
      return Ada.Streams.Stream_Element_Array
   is
      Payload : constant Ada.Streams.Stream_Element_Array :=
        Bytes_From_String ("" & Character'Val (Message))
        & SSH_Lib.Protocol.Numbers.Encode_Uint32 (1)
        & SFTP_String (Handle)
        & Encode_Test_Uint64 (Offset)
        & Encode_Test_Uint64 (Length)
        & (if Integer (Message) = SSH_Lib.SFTP.SSH_FXP_BLOCK
           then SSH_Lib.Protocol.Numbers.Encode_Uint32 (Lock_Mask)
           else Ada.Streams.Stream_Element_Array'(1 .. 0 => 0));
   begin
      return SSH_Lib.Protocol.Numbers.Encode_Uint32
          (Interfaces.Unsigned_32 (Payload'Length))
        & Payload;
   end SFTP_Block_Request;

   function SFTP_Text_Seek_Request
     (Handle      : String;
      Line_Number : Interfaces.Unsigned_64)
      return Ada.Streams.Stream_Element_Array is
   begin
      return SFTP_Extended_Raw_Request
        (SSH_Lib.SFTP.Text_Seek_Extension,
         SFTP_String (Handle) & Encode_Test_Uint64 (Line_Number));
   end SFTP_Text_Seek_Request;

   function SFTP_Extended_Reply_Packet
     (Request_Id   : Interfaces.Unsigned_32;
      Payload_Data : Ada.Streams.Stream_Element_Array)
      return Ada.Streams.Stream_Element_Array
   is
      Payload : constant Ada.Streams.Stream_Element_Array :=
        Bytes_From_String ("" & Character'Val (SSH_Lib.SFTP.SSH_FXP_EXTENDED_REPLY))
        & SSH_Lib.Protocol.Numbers.Encode_Uint32 (Request_Id)
        & Payload_Data;
   begin
      return SSH_Lib.Protocol.Numbers.Encode_Uint32
          (Interfaces.Unsigned_32 (Payload'Length))
        & Payload;
   end SFTP_Extended_Reply_Packet;

   function SFTP_Extended_Setattrs_Request
     (Extension_Name : String;
      Remote_Path    : String;
      Permissions    : Interfaces.Unsigned_32)
      return Ada.Streams.Stream_Element_Array
   is
      Payload : constant Ada.Streams.Stream_Element_Array :=
        Bytes_From_String ("" & Character'Val (SSH_Lib.SFTP.SSH_FXP_EXTENDED))
        & SSH_Lib.Protocol.Numbers.Encode_Uint32 (1)
        & SFTP_String (Extension_Name)
        & SFTP_String (Remote_Path)
        & SSH_Lib.Protocol.Numbers.Encode_Uint32 (16#0000_0004#)
        & SSH_Lib.Protocol.Numbers.Encode_Uint32 (Permissions);
   begin
      return SSH_Lib.Protocol.Numbers.Encode_Uint32
          (Interfaces.Unsigned_32 (Payload'Length))
        & Payload;
   end SFTP_Extended_Setattrs_Request;

   function SFTP_StatVFS_Packet
     (Request_Id : Interfaces.Unsigned_32)
      return Ada.Streams.Stream_Element_Array
   is
      Payload : constant Ada.Streams.Stream_Element_Array :=
        Bytes_From_String ("" & Character'Val (SSH_Lib.SFTP.SSH_FXP_EXTENDED_REPLY))
        & SSH_Lib.Protocol.Numbers.Encode_Uint32 (Request_Id)
        & Encode_Test_Uint64 (4096)
        & Encode_Test_Uint64 (4096)
        & Encode_Test_Uint64 (1000)
        & Encode_Test_Uint64 (800)
        & Encode_Test_Uint64 (700)
        & Encode_Test_Uint64 (600)
        & Encode_Test_Uint64 (500)
        & Encode_Test_Uint64 (400)
        & Encode_Test_Uint64 (12345)
        & Encode_Test_Uint64 (1)
        & Encode_Test_Uint64 (255);
   begin
      return SSH_Lib.Protocol.Numbers.Encode_Uint32
          (Interfaces.Unsigned_32 (Payload'Length))
        & Payload;
   end SFTP_StatVFS_Packet;

   function SFTP_Limits_Packet
     (Request_Id : Interfaces.Unsigned_32)
      return Ada.Streams.Stream_Element_Array
   is
      Payload : constant Ada.Streams.Stream_Element_Array :=
        Bytes_From_String ("" & Character'Val (SSH_Lib.SFTP.SSH_FXP_EXTENDED_REPLY))
        & SSH_Lib.Protocol.Numbers.Encode_Uint32 (Request_Id)
        & Encode_Test_Uint64 (262144)
        & Encode_Test_Uint64 (131072)
        & Encode_Test_Uint64 (65536)
        & Encode_Test_Uint64 (32);
   begin
      return SSH_Lib.Protocol.Numbers.Encode_Uint32
          (Interfaces.Unsigned_32 (Payload'Length))
        & Payload;
   end SFTP_Limits_Packet;

   function SFTP_Attrs_Packet
     (Request_Id  : Interfaces.Unsigned_32;
      Size        : Interfaces.Unsigned_64;
      Permissions : Interfaces.Unsigned_32)
      return Ada.Streams.Stream_Element_Array is
   begin
      return SSH_Lib.Protocol.Numbers.Encode_Uint32 (25)
        & Bytes_From_String ("" & Character'Val (SSH_Lib.SFTP.SSH_FXP_ATTRS))
        & SSH_Lib.Protocol.Numbers.Encode_Uint32 (Request_Id)
        & SSH_Lib.Protocol.Numbers.Encode_Uint32 (16#0000_0005#)
        & Encode_Test_Uint64 (Size)
        & SSH_Lib.Protocol.Numbers.Encode_Uint32 (Permissions);
   end SFTP_Attrs_Packet;

   function SFTP_V4_Attrs_Record
     (File_Type   : Ada.Streams.Stream_Element;
      Size        : Interfaces.Unsigned_64;
      Permissions : Interfaces.Unsigned_32;
      Access_Time : Interfaces.Unsigned_64 := 42;
      Modify_Time : Interfaces.Unsigned_64 := 99)
      return Ada.Streams.Stream_Element_Array is
   begin
      return SSH_Lib.Protocol.Numbers.Encode_Uint32 (16#0000_0059#)
        & Bytes_From_String ("" & Character'Val (File_Type))
        & Encode_Test_Uint64 (Size)
        & SSH_Lib.Protocol.Numbers.Encode_Uint32 (Permissions)
        & Encode_Test_Uint64 (Access_Time)
        & SSH_Lib.Protocol.Numbers.Encode_Uint32 (0)
        & Encode_Test_Uint64 (Modify_Time)
        & SSH_Lib.Protocol.Numbers.Encode_Uint32 (0);
   end SFTP_V4_Attrs_Record;

   function SFTP_V4_Rich_Attrs_Packet
     (Request_Id : Interfaces.Unsigned_32)
      return Ada.Streams.Stream_Element_Array
   is
      Payload : constant Ada.Streams.Stream_Element_Array :=
        Bytes_From_String ("" & Character'Val (SSH_Lib.SFTP.SSH_FXP_ATTRS))
        & SSH_Lib.Protocol.Numbers.Encode_Uint32 (Request_Id)
        & SSH_Lib.Protocol.Numbers.Encode_Uint32 (16#0000_1FFF#)
        & Bytes_From_String ("" & Character'Val (1))
        & Encode_Test_Uint64 (123)
        & Encode_Test_Uint64 (456)
        & SFTP_String ("alice")
        & SFTP_String ("staff")
        & SSH_Lib.Protocol.Numbers.Encode_Uint32 (8#100640#)
        & Encode_Test_Uint64 (11)
        & SSH_Lib.Protocol.Numbers.Encode_Uint32 (12)
        & Encode_Test_Uint64 (13)
        & SSH_Lib.Protocol.Numbers.Encode_Uint32 (14)
        & Encode_Test_Uint64 (15)
        & SSH_Lib.Protocol.Numbers.Encode_Uint32 (16)
        & SFTP_String ("acl")
        & SSH_Lib.Protocol.Numbers.Encode_Uint32 (16#AA55#)
        & SSH_Lib.Protocol.Numbers.Encode_Uint32 (16#FFFF#)
        & Bytes_From_String ("" & Character'Val (1))
        & SFTP_String ("text/plain")
        & SSH_Lib.Protocol.Numbers.Encode_Uint32 (2)
        & SFTP_String ("raw-name")
        & SSH_Lib.Protocol.Numbers.Encode_Uint32 (0);
   begin
      return SSH_Lib.Protocol.Numbers.Encode_Uint32
          (Interfaces.Unsigned_32 (Payload'Length))
        & Payload;
   end SFTP_V4_Rich_Attrs_Packet;

   function SFTP_V4_Attrs_Packet
     (Request_Id  : Interfaces.Unsigned_32;
      File_Type   : Ada.Streams.Stream_Element;
      Size        : Interfaces.Unsigned_64;
      Permissions : Interfaces.Unsigned_32)
      return Ada.Streams.Stream_Element_Array
   is
      Payload : constant Ada.Streams.Stream_Element_Array :=
        Bytes_From_String ("" & Character'Val (SSH_Lib.SFTP.SSH_FXP_ATTRS))
        & SSH_Lib.Protocol.Numbers.Encode_Uint32 (Request_Id)
        & SFTP_V4_Attrs_Record (File_Type, Size, Permissions);
   begin
      return SSH_Lib.Protocol.Numbers.Encode_Uint32
          (Interfaces.Unsigned_32 (Payload'Length))
        & Payload;
   end SFTP_V4_Attrs_Packet;

   function SFTP_V4_Name_Entry
     (Name        : String;
      File_Type   : Ada.Streams.Stream_Element;
      Size        : Interfaces.Unsigned_64;
      Permissions : Interfaces.Unsigned_32)
      return Ada.Streams.Stream_Element_Array is
   begin
      return SSH_Lib.Protocol.Numbers.Encode_Uint32
          (Interfaces.Unsigned_32 (Name'Length))
        & Bytes_From_String (Name)
        & SFTP_V4_Attrs_Record (File_Type, Size, Permissions);
   end SFTP_V4_Name_Entry;

   function SFTP_V4_Name_Packet
     (Request_Id   : Interfaces.Unsigned_32;
      First_Name   : String;
      First_Type   : Ada.Streams.Stream_Element;
      First_Size   : Interfaces.Unsigned_64;
      First_Perms  : Interfaces.Unsigned_32;
      Second_Name  : String := "";
      Second_Type  : Ada.Streams.Stream_Element := 1;
      Second_Size  : Interfaces.Unsigned_64 := 0;
      Second_Perms : Interfaces.Unsigned_32 := 0)
      return Ada.Streams.Stream_Element_Array
   is
      Count : constant Interfaces.Unsigned_32 :=
        (if Second_Name'Length = 0 then 1 else 2);
      Entries : constant Ada.Streams.Stream_Element_Array :=
        (if Second_Name'Length = 0
         then SFTP_V4_Name_Entry (First_Name, First_Type, First_Size, First_Perms)
         else SFTP_V4_Name_Entry (First_Name, First_Type, First_Size, First_Perms)
              & SFTP_V4_Name_Entry (Second_Name, Second_Type, Second_Size, Second_Perms));
      Payload : constant Ada.Streams.Stream_Element_Array :=
        Bytes_From_String ("" & Character'Val (SSH_Lib.SFTP.SSH_FXP_NAME))
        & SSH_Lib.Protocol.Numbers.Encode_Uint32 (Request_Id)
        & SSH_Lib.Protocol.Numbers.Encode_Uint32 (Count)
        & Entries;
   begin
      return SSH_Lib.Protocol.Numbers.Encode_Uint32
          (Interfaces.Unsigned_32 (Payload'Length))
        & Payload;
   end SFTP_V4_Name_Packet;

   function SFTP_Extended_Attrs_Packet
     (Request_Id : Interfaces.Unsigned_32;
      Name       : String;
      Value      : String)
      return Ada.Streams.Stream_Element_Array
   is
      Payload : constant Ada.Streams.Stream_Element_Array :=
        Bytes_From_String ("" & Character'Val (SSH_Lib.SFTP.SSH_FXP_ATTRS))
        & SSH_Lib.Protocol.Numbers.Encode_Uint32 (Request_Id)
        & SSH_Lib.Protocol.Numbers.Encode_Uint32 (16#8000_0005#)
        & Encode_Test_Uint64 (99)
        & SSH_Lib.Protocol.Numbers.Encode_Uint32 (8#100644#)
        & SSH_Lib.Protocol.Numbers.Encode_Uint32 (1)
        & SSH_Lib.Protocol.Numbers.Encode_Uint32
            (Interfaces.Unsigned_32 (Name'Length))
        & Bytes_From_String (Name)
        & SSH_Lib.Protocol.Numbers.Encode_Uint32
            (Interfaces.Unsigned_32 (Value'Length))
        & Bytes_From_String (Value);
   begin
      return SSH_Lib.Protocol.Numbers.Encode_Uint32
          (Interfaces.Unsigned_32 (Payload'Length))
        & Payload;
   end SFTP_Extended_Attrs_Packet;

   procedure Assert_Open_Exec_Accepts_Quoted_Command (Command_Text : String) is
      Session_Item : SSH_Lib.Sessions.Session;
      Channel_Item : SSH_Lib.Channels.Channel;
      Status_Value : CryptoLib.Errors.Status;
   begin
      declare
         Requested_Channel : SSH_Lib.Channels.Channel;
         Requested_Version : Natural := 0;
      begin
         SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
           (Requested_Channel, Local_Channel_Id => 0, Remote_Channel_Id => 1);
         Status_Value := SSH_Lib.Channels.Test_Support.Queue_Stdout_For_Test
           (Requested_Channel, SFTP_Version_Packet (Interfaces.Unsigned_32'(6)));
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP initialization", "queue version 6 packet");
         Status_Value := SSH_Lib.SFTP.Initialize
           (Requested_Channel, 6, Requested_Version);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP initialization", "request version 6 succeeds");
         Check (Requested_Version = 6, "SFTP initialization returns requested version 6");
         Assert_SCP_Channel_Data
           (Requested_Channel,
            SSH_Lib.Protocol.Buffers.To_Array (SSH_Lib.SFTP.Encode_Init_Packet (6)),
            "SFTP requested initialization");
      end;

      SSH_Lib.Sessions.Test_Support.Mark_Authenticated_Open_For_Test (Session_Item);
      Status_Value := SSH_Lib.Sessions.Test_Support.Queue_Channel_Open_Response_For_Test
        (Session_Item, Build_Open_Confirmation (0, 900, 4096, 8192));
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok, "Git command Open_Exec", "queue open response");
      Status_Value := SSH_Lib.Sessions.Test_Support.Queue_Exec_Response_For_Test
        (Session_Item, Build_Exec_Success (0));
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok, "Git command Open_Exec", "queue exec response");
      Status_Value := SSH_Lib.Channels.Open_Exec (Session_Item, Command_Text, Channel_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok, "Git command Open_Exec",
         "generated command accepted by production Open_Exec");

      declare
         Last_Exec : constant Ada.Streams.Stream_Element_Array :=
           SSH_Lib.Sessions.Test_Support.Last_Exec_Request_Payload_For_Test (Session_Item);
      begin
         SSH_Lib.Tests.Assertions.Check_Bytes
           (Last_Exec (Last_Exec'First + 18 .. Last_Exec'Last),
            Bytes_From_String (Command_Text),
            "Git command Open_Exec", "exec request command bytes are exact");
      end;
   end Assert_Open_Exec_Accepts_Quoted_Command;

   procedure Remove_If_Exists (Path : String) is
   begin
      if Ada.Directories.Exists (Path) then
         Ada.Directories.Delete_File (Path);
      end if;
   exception
      when others =>
         null;
   end Remove_If_Exists;

   procedure Remove_Local_Tree_If_Exists (Path : String) is
   begin
      if Ada.Directories.Exists (Path) then
         Ada.Directories.Delete_Tree (Path);
      end if;
   exception
      when others =>
         null;
   end Remove_Local_Tree_If_Exists;

   procedure Write_Test_File
     (Path  : String;
      Value : Ada.Streams.Stream_Element_Array)
   is
      File_Item : Ada.Streams.Stream_IO.File_Type;
   begin
      Remove_If_Exists (Path);
      Ada.Streams.Stream_IO.Create
        (File_Item, Ada.Streams.Stream_IO.Out_File, Path);
      Ada.Streams.Stream_IO.Write (File_Item, Value);
      Ada.Streams.Stream_IO.Close (File_Item);
   exception
      when others =>
         if Ada.Streams.Stream_IO.Is_Open (File_Item) then
            Ada.Streams.Stream_IO.Close (File_Item);
         end if;
         raise;
   end Write_Test_File;

   function Read_Test_File
     (Path : String) return Ada.Streams.Stream_Element_Array
   is
      File_Item : Ada.Streams.Stream_IO.File_Type;
   begin
      Ada.Streams.Stream_IO.Open (File_Item, Ada.Streams.Stream_IO.In_File, Path);
      declare
         Size_Value : constant Ada.Streams.Stream_IO.Count :=
           Ada.Streams.Stream_IO.Size (File_Item);
         Data       : Ada.Streams.Stream_Element_Array
           (1 .. Ada.Streams.Stream_Element_Offset (Size_Value));
         Last       : Ada.Streams.Stream_Element_Offset;
      begin
         if Data'Length > 0 then
            Ada.Streams.Stream_IO.Read (File_Item, Data, Last);
            Check (Last = Data'Last, "test file read returns complete data");
         end if;
         Ada.Streams.Stream_IO.Close (File_Item);
         return Data;
      end;
   exception
      when others =>
         if Ada.Streams.Stream_IO.Is_Open (File_Item) then
            Ada.Streams.Stream_IO.Close (File_Item);
         end if;
         raise;
   end Read_Test_File;

   procedure Assert_Git_Command_Quoting_And_Validation is
      Marker_Path : constant String :=
        SSH_Lib.Tests.Fixtures.Temp_Paths.Path ("phase19_git_command_shell_marker");
      Shell_Looking_Path : constant String := "$(touch " & Marker_Path & ").git";
      Command_Text : Unbounded_String;
      Status_Value : CryptoLib.Errors.Status;
      Command_Too_Long_Path : constant String
        (1 .. SSH_Lib.Git.Maximum_Repository_Path_Length) := [others => 'x'];
      Oversized_Path : constant String
        (1 .. SSH_Lib.Git.Maximum_Repository_Path_Length + 1) := [others => 'x'];
   begin
      Remove_If_Exists (Marker_Path);

      Check_Build ("repo.git", "git-upload-pack 'repo.git'");
      Check_Build ("group/repo.git", "git-upload-pack 'group/repo.git'");
      Check_Build ("repo with space.git", "git-upload-pack 'repo with space.git'");
      Check_Build ("a'b.git", "git-upload-pack 'a'\''b.git'", "git-receive-pack 'a'\''b.git'");
      Check_Build ("semi;colon.git", "git-upload-pack 'semi;colon.git'");
      Check_Build ("`touch bad`.git", "git-upload-pack '`touch bad`.git'");
      Check_Build ("back\slash.git", "git-upload-pack 'back\slash.git'");
      Check_Build ("double""quote.git", "git-upload-pack 'double""quote.git'");
      Check_Build ("paren&(repo).git", "git-upload-pack 'paren&(repo).git'");
      Check_Build (Shell_Looking_Path, "git-upload-pack '" & Shell_Looking_Path & "'");
      Check (not Ada.Directories.Exists (Marker_Path),
             "shell-looking repository path is quoted as data and not executed");

      Status_Value := SSH_Lib.Git.Build_Upload_Pack_Command ("a'b.git", Command_Text);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok, "Git command quoting", "single quote escaped");
      Assert_Open_Exec_Accepts_Quoted_Command (To_String (Command_Text));

      Check_Rejected ("", "empty repository path rejected");
      Check_Rejected ("bad" & Character'Val (0) & "repo.git", "NUL repository path rejected");
      Check_Rejected ("bad" & Character'Val (10) & "repo.git", "LF repository path rejected");
      Check_Rejected ("bad" & Character'Val (13) & "repo.git", "CR repository path rejected");
      Check_Rejected
        (Command_Too_Long_Path,
         "repository path rejected when quoted command would exceed "
           & "Open_Exec limit");
      Check_Rejected (Oversized_Path, "oversized repository path rejected");

      Check (not SSH_Lib.Protocol.Channels.Valid_Command ("git-upload-pack 'bad" & Character'Val (10) & "repo.git'"),
             "Open_Exec validation rejects generated-command LF if present");
      Check (not SSH_Lib.Protocol.Channels.Valid_Command (""),
             "Open_Exec validation rejects empty commands");
      Check (not SSH_Lib.Protocol.Channels.Valid_Command
               ([1 .. SSH_Lib.Protocol.Channels.Maximum_Command_Length + 1 => 'x']),
             "Open_Exec validation rejects oversized commands");
      Remove_If_Exists (Marker_Path);
   exception
      when others =>
         Remove_If_Exists (Marker_Path);
         raise;
   end Assert_Git_Command_Quoting_And_Validation;

   procedure Assert_SCP_Command_And_Header_Validation is
      Command_Text : Unbounded_String;
      Status_Value : CryptoLib.Errors.Status;
      Command_Too_Long_Path : constant String
        (1 .. SSH_Lib.SCP.Maximum_Remote_Path_Length) := [others => 'x'];
      Oversized_Path : constant String
        (1 .. SSH_Lib.SCP.Maximum_Remote_Path_Length + 1) := [others => 'x'];
   begin
      Check_Natural_Equal
        (SSH_Lib.File_Transfer.Maximum_File_Name_Length,
         SSH_Lib.SCP.Maximum_File_Name_Length,
         "file transfer facade filename limit aliases SCP limit");
      Check_Natural_Equal
        (SSH_Lib.File_Transfer.Maximum_SCP_Remote_Path_Length,
         SSH_Lib.SCP.Maximum_Remote_Path_Length,
         "file transfer facade SCP path limit aliases SCP limit");
      Check_Natural_Equal
        (SSH_Lib.File_Transfer.Maximum_SFTP_Remote_Path_Length,
         SSH_Lib.SFTP.Maximum_Remote_Path_Length,
         "file transfer facade SFTP path limit aliases SFTP limit");
      Check_Natural_Equal
        (SSH_Lib.File_Transfer.SCP_Upload_Chunk_Size,
         SSH_Lib.SCP.Upload_Chunk_Size,
         "file transfer facade SCP chunk size aliases SCP limit");
      Check_Natural_Equal
        (SSH_Lib.File_Transfer.SFTP_Upload_Chunk_Size,
         SSH_Lib.SFTP.Upload_Chunk_Size,
         "file transfer facade SFTP chunk size aliases SFTP limit");

      Check_SCP_Command ("/tmp/file.txt", "scp -t -- '/tmp/file.txt'");
      Check_SCP_Command ("dir/file with space.txt", "scp -t -- 'dir/file with space.txt'");
      Check_SCP_Command ("a'b.txt", "scp -t -- 'a'\''b.txt'");
      Check_SCP_Command ("semi;colon.txt", "scp -t -- 'semi;colon.txt'");
      Check_SCP_Command ("`touch bad`.txt", "scp -t -- '`touch bad`.txt'");
      Check_SCP_Command ("double""quote.txt", "scp -t -- 'double""quote.txt'");

      Status_Value := SSH_Lib.SCP.Build_Upload_Command ("a'b.txt", Command_Text);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok, "SCP command quoting", "single quote escaped");
      Assert_Open_Exec_Accepts_Quoted_Command (To_String (Command_Text));

      Check_SCP_Command_Rejected ("", "empty path rejected");
      Check_SCP_Command_Rejected ("bad" & Character'Val (0) & "file.txt", "NUL path rejected");
      Check_SCP_Command_Rejected ("bad" & Character'Val (10) & "file.txt", "LF path rejected");
      Check_SCP_Command_Rejected ("bad" & Character'Val (13) & "file.txt", "CR path rejected");
      Check_SCP_Command_Rejected
        (Command_Too_Long_Path,
         "path rejected when quoted command would exceed Open_Exec limit");
      Check_SCP_Command_Rejected (Oversized_Path, "oversized path rejected");

      Check_SCP_Header ("file.txt", 12, "0644", "C0644 12 file.txt" & Character'Val (10));
      Check_SCP_Header ("empty.txt", 0, "0600", "C0600 0 empty.txt" & Character'Val (10));
      Check_SCP_Header ("quote'name.txt", 1, "0640", "C0640 1 quote'name.txt" & Character'Val (10));

      Check_SCP_Header_Rejected ("", 1, "0644", "empty filename rejected");
      Check_SCP_Header_Rejected (".", 1, "0644", "dot filename rejected");
      Check_SCP_Header_Rejected ("..", 1, "0644", "dot-dot filename rejected");
      Check_SCP_Header_Rejected ("dir/file.txt", 1, "0644", "path filename rejected");
      Check_SCP_Header_Rejected ("bad" & Character'Val (0) & "file.txt", 1, "0644", "NUL filename rejected");
      Check_SCP_Header_Rejected ("bad" & Character'Val (10) & "file.txt", 1, "0644", "LF filename rejected");
      Check_SCP_Header_Rejected ("file.txt", 1, "644", "short mode rejected");
      Check_SCP_Header_Rejected ("file.txt", 1, "0888", "non-octal mode rejected");

      declare
         Channel_Item : SSH_Lib.Channels.Channel;
         Data_Item : constant Ada.Streams.Stream_Element_Array :=
           Bytes_From_String ("hello");
         Expected_Frame : constant Ada.Streams.Stream_Element_Array :=
           Bytes_From_String ("C0644 5 file.txt" & Character'Val (10) & "hello" & Character'Val (0));
      begin
         SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
           (Channel_Item, Local_Channel_Id => 0, Remote_Channel_Id => 1);
         Queue_SCP_Acks
           (Channel_Item, Bytes_From_String (Character'Val (0) & Character'Val (0)), "success");
         Status_Value := SSH_Lib.SCP.Upload_Data
           (Channel_Item, "file.txt", Data_Item, "0644");
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SCP upload", "channel upload succeeds");
         Assert_SCP_Channel_Data (Channel_Item, Expected_Frame, "channel upload");
         Check
           (SSH_Lib.Channels.Test_Support.Last_EOF_Payload_For_Test
              (Channel_Item)'Length > 0,
            "SCP upload sends SSH EOF after final ACK");
      end;

      declare
         Channel_Item : SSH_Lib.Channels.Channel;
      begin
         SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
           (Channel_Item, Local_Channel_Id => 0, Remote_Channel_Id => 1);
         Queue_SCP_Acks (Channel_Item, Bytes_From_String ("" & Character'Val (1)), "reject");
         Status_Value := SSH_Lib.SCP.Upload_Data
           (Channel_Item, "file.txt", Bytes_From_String ("hello"), "0644");
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Write_Failed, "SCP upload", "initial nonzero ACK rejected");
         Check
           (SSH_Lib.Channels.Test_Support.Last_Channel_Data_Payload_For_Test
              (Channel_Item)'Length = 0,
            "SCP upload does not write file data after initial nonzero ACK");
      end;

      declare
         Channel_Item : SSH_Lib.Channels.Channel;
         Local_Path : constant String :=
           SSH_Lib.Tests.Fixtures.Temp_Paths.Path ("scp_upload_file.txt");
         Expected_Terminator : constant Ada.Streams.Stream_Element_Array :=
           Bytes_From_String ("" & Character'Val (0));
         Expected_Byte_Count : constant Natural :=
           Bytes_From_String ("C0600 6 remote.txt" & Character'Val (10) & "local!" & Character'Val (0))'Length;
      begin
         Write_Test_File (Local_Path, Bytes_From_String ("local!"));
         SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
           (Channel_Item, Local_Channel_Id => 0, Remote_Channel_Id => 1);
         Queue_SCP_Acks
           (Channel_Item, Bytes_From_String (Character'Val (0) & Character'Val (0)), "file upload");
         Status_Value := SSH_Lib.SCP.Upload_File
           (Channel_Item, Local_Path, "remote.txt", "0600");
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SCP upload", "local file upload succeeds");
         Check
           (SSH_Lib.Channels.Test_Support.Outbound_Data_Byte_Count_For_Test
              (Channel_Item) = Expected_Byte_Count,
            "SCP local file upload writes expected total byte count");
         Check
           (SSH_Lib.Channels.Test_Support.Outbound_Data_Packet_Count_For_Test
              (Channel_Item) = 3,
            "SCP local file upload writes header, content, and terminator packets");
         Assert_SCP_Channel_Data (Channel_Item, Expected_Terminator, "local file upload terminator");
         Remove_If_Exists (Local_Path);
      exception
         when others =>
            Remove_If_Exists (Local_Path);
            raise;
      end;

      declare
         Channel_Item : SSH_Lib.Channels.Channel;
         Local_Path : constant String :=
           SSH_Lib.Tests.Fixtures.Temp_Paths.Path ("scp_empty_upload_file.txt");
         Expected_Terminator : constant Ada.Streams.Stream_Element_Array :=
           Bytes_From_String ("" & Character'Val (0));
         Expected_Byte_Count : constant Natural :=
           Bytes_From_String ("C0600 0 empty-remote.txt" & Character'Val (10) & Character'Val (0))'Length;
      begin
         Write_Test_File (Local_Path, Bytes_From_String (""));
         SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
           (Channel_Item, Local_Channel_Id => 0, Remote_Channel_Id => 1);
         Queue_SCP_Acks
           (Channel_Item, Bytes_From_String (Character'Val (0) & Character'Val (0)), "empty file upload");
         Status_Value := SSH_Lib.SCP.Upload_File
           (Channel_Item, Local_Path, "empty-remote.txt", "0600");
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SCP upload", "empty local file upload succeeds");
         Check
           (SSH_Lib.Channels.Test_Support.Outbound_Data_Byte_Count_For_Test
              (Channel_Item) = Expected_Byte_Count,
            "SCP empty local file upload writes header and terminator bytes");
         Check
           (SSH_Lib.Channels.Test_Support.Outbound_Data_Packet_Count_For_Test
              (Channel_Item) = 2,
            "SCP empty local file upload writes header and terminator packets");
         Assert_SCP_Channel_Data
           (Channel_Item, Expected_Terminator, "empty local file upload terminator");
         Remove_If_Exists (Local_Path);
      exception
         when others =>
            Remove_If_Exists (Local_Path);
            raise;
      end;

      declare
         Session_Item : SSH_Lib.Sessions.Session;
         Open_Status : CryptoLib.Errors.Status;
      begin
         SSH_Lib.Sessions.Test_Support.Mark_Authenticated_Open_For_Test (Session_Item);
         Open_Status := SSH_Lib.Sessions.Test_Support.Queue_Channel_Open_Response_For_Test
           (Session_Item, Build_Open_Confirmation (0, 900, 4096, 8192));
         SSH_Lib.Tests.Assertions.Check_Status
           (Open_Status, CryptoLib.Errors.Ok, "SCP upload", "queue open response");
         Open_Status := SSH_Lib.Sessions.Test_Support.Queue_Exec_Response_For_Test
           (Session_Item, Build_Exec_Success (0));
         SSH_Lib.Tests.Assertions.Check_Status
           (Open_Status, CryptoLib.Errors.Ok, "SCP upload", "queue exec response");

         Status_Value := SSH_Lib.SCP.Upload_Data
           (Session_Item, "/tmp/file.txt", "file.txt", Bytes_From_String ("hello"), "0644");
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Timeout, "SCP upload", "session upload reports missing remote ACK");
         declare
            Last_Exec : constant Ada.Streams.Stream_Element_Array :=
              SSH_Lib.Sessions.Test_Support.Last_Exec_Request_Payload_For_Test
                (Session_Item);
         begin
            SSH_Lib.Tests.Assertions.Check_Bytes
              (Last_Exec (Last_Exec'First + 18 .. Last_Exec'Last),
               Bytes_From_String ("scp -t -- '/tmp/file.txt'"),
               "SCP upload",
               "session upload exec request command bytes are exact");
         end;
         Check
           (SSH_Lib.Sessions.Test_Support.Active_Channel_Count_For_Test
              (Session_Item) = 0,
            "SCP upload closes the opened channel after transfer failure");
      end;

      declare
         Session_Item : SSH_Lib.Sessions.Session;
         Open_Status : CryptoLib.Errors.Status;
      begin
         SSH_Lib.Sessions.Test_Support.Mark_Authenticated_Open_For_Test (Session_Item);
         Open_Status := SSH_Lib.Sessions.Test_Support.Queue_Channel_Open_Response_For_Test
           (Session_Item, Build_Open_Confirmation (0, 900, 4096, 8192));
         SSH_Lib.Tests.Assertions.Check_Status
           (Open_Status, CryptoLib.Errors.Ok, "SCP upload preflight", "queue data open response");

         Status_Value := SSH_Lib.SCP.Upload_Data
           (Session_Item, "/tmp/file.txt", "bad/name.txt", Bytes_From_String ("hello"), "0644");
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value,
            CryptoLib.Errors.Invalid_Command,
            "SCP upload preflight",
            "bad data filename rejected before open");
         Check
           (SSH_Lib.Sessions.Test_Support.Active_Channel_Count_For_Test
              (Session_Item) = 0,
            "SCP data upload preflight does not open a channel for a bad filename");
      end;

      declare
         Session_Item : SSH_Lib.Sessions.Session;
         Open_Status : CryptoLib.Errors.Status;
      begin
         SSH_Lib.Sessions.Test_Support.Mark_Authenticated_Open_For_Test (Session_Item);
         Open_Status := SSH_Lib.Sessions.Test_Support.Queue_Channel_Open_Response_For_Test
           (Session_Item, Build_Open_Confirmation (0, 900, 4096, 8192));
         SSH_Lib.Tests.Assertions.Check_Status
           (Open_Status, CryptoLib.Errors.Ok, "SCP upload preflight", "queue file open response");

         Status_Value := SSH_Lib.SCP.Upload_File
           (Session_Item, "", "missing-scp-local-file.txt", "remote.txt", "0644");
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value,
            CryptoLib.Errors.Invalid_Command,
            "SCP upload preflight",
            "bad remote path rejected before local file check");
         Check
           (SSH_Lib.Sessions.Test_Support.Active_Channel_Count_For_Test
              (Session_Item) = 0,
            "SCP file upload preflight does not open a channel for a bad remote path");
      end;

      declare
         Session_Item : SSH_Lib.Sessions.Session;
         Open_Status : CryptoLib.Errors.Status;
         Local_Path : constant String :=
           SSH_Lib.Tests.Fixtures.Temp_Paths.Path ("scp_bad_name_preflight.txt");
      begin
         Write_Test_File (Local_Path, Bytes_From_String ("local!"));
         SSH_Lib.Sessions.Test_Support.Mark_Authenticated_Open_For_Test (Session_Item);
         Open_Status := SSH_Lib.Sessions.Test_Support.Queue_Channel_Open_Response_For_Test
           (Session_Item, Build_Open_Confirmation (0, 900, 4096, 8192));
         SSH_Lib.Tests.Assertions.Check_Status
           (Open_Status, CryptoLib.Errors.Ok, "SCP upload preflight", "queue open response");

         Status_Value := SSH_Lib.SCP.Upload_File
           (Session_Item, "/tmp/file.txt", Local_Path, "bad/name.txt", "0644");
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value,
            CryptoLib.Errors.Invalid_Command,
            "SCP upload preflight",
            "bad explicit filename rejected before open");
         Check
           (SSH_Lib.Sessions.Test_Support.Active_Channel_Count_For_Test
              (Session_Item) = 0,
            "SCP upload preflight does not open a channel for a bad filename");
         Remove_If_Exists (Local_Path);
      exception
         when others =>
            Remove_If_Exists (Local_Path);
            raise;
      end;

      declare
         Session_Item : SSH_Lib.Sessions.Session;
         Open_Status : CryptoLib.Errors.Status;
      begin
         SSH_Lib.Sessions.Test_Support.Mark_Authenticated_Open_For_Test (Session_Item);
         Open_Status := SSH_Lib.Sessions.Test_Support.Queue_Channel_Open_Response_For_Test
           (Session_Item, Build_Open_Confirmation (0, 900, 4096, 8192));
         SSH_Lib.Tests.Assertions.Check_Status
           (Open_Status, CryptoLib.Errors.Ok, "file transfer facade", "queue open response");
         Open_Status := SSH_Lib.Sessions.Test_Support.Queue_Exec_Response_For_Test
           (Session_Item, Build_Exec_Success (0));
         SSH_Lib.Tests.Assertions.Check_Status
           (Open_Status, CryptoLib.Errors.Ok, "file transfer facade", "queue exec response");

         Status_Value := SSH_Lib.File_Transfer.Upload_Data
           (Session_Item, "/tmp/facade.txt", "facade.txt", Bytes_From_String ("hello"));
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Timeout, "file transfer facade", "auto method reaches SCP ACK wait");
         declare
            Last_Exec : constant Ada.Streams.Stream_Element_Array :=
              SSH_Lib.Sessions.Test_Support.Last_Exec_Request_Payload_For_Test
                (Session_Item);
         begin
            SSH_Lib.Tests.Assertions.Check_Bytes
              (Last_Exec (Last_Exec'First + 18 .. Last_Exec'Last),
               Bytes_From_String ("scp -t -- '/tmp/facade.txt'"),
               "file transfer facade",
               "auto method selects SCP command bytes");
         end;
      end;

      declare
         Session_Item : SSH_Lib.Sessions.Session;
         Open_Status : CryptoLib.Errors.Status;
      begin
         SSH_Lib.Sessions.Test_Support.Mark_Authenticated_Open_For_Test (Session_Item);
         Open_Status := SSH_Lib.Sessions.Test_Support.Queue_Channel_Open_Response_For_Test
           (Session_Item, Build_Open_Confirmation (0, 900, 4096, 8192));
         SSH_Lib.Tests.Assertions.Check_Status
           (Open_Status, CryptoLib.Errors.Ok, "file transfer facade", "queue SFTP open response");
         Open_Status := SSH_Lib.Sessions.Test_Support.Queue_Exec_Response_For_Test
           (Session_Item, Build_Exec_Success (0));
         SSH_Lib.Tests.Assertions.Check_Status
           (Open_Status, CryptoLib.Errors.Ok, "file transfer facade", "queue SFTP subsystem response");
         Status_Value := SSH_Lib.File_Transfer.Upload_Data
           (Session_Item,
            "/tmp/facade.txt",
            "facade.txt",
            Bytes_From_String ("hello"),
            Method => SSH_Lib.File_Transfer.Upload_SFTP);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value,
            CryptoLib.Errors.Timeout,
            "file transfer facade",
            "explicit SFTP method waits for SFTP version packet");
         declare
            Last_Exec : constant Ada.Streams.Stream_Element_Array :=
              SSH_Lib.Sessions.Test_Support.Last_Exec_Request_Payload_For_Test
                (Session_Item);
            Expected : constant Ada.Streams.Stream_Element_Array :=
              SSH_Lib.Protocol.Buffers.To_Array
                (SSH_Lib.Protocol.Channels.Encode_Subsystem_Request (900, "sftp"));
         begin
            SSH_Lib.Tests.Assertions.Check_Bytes
              (Last_Exec, Expected, "file transfer facade", "SFTP method opens sftp subsystem");
         end;
      end;

      declare
         Session_Item  : SSH_Lib.Sessions.Session;
         Open_Status   : CryptoLib.Errors.Status;
         Remote_Target : constant String := "/tmp/facade_dir/facade.txt";
         Version_Packet : constant Ada.Streams.Stream_Element_Array :=
           Bytes_From_String
             (Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (5)
              & Character'Val (SSH_Lib.SFTP.SSH_FXP_VERSION)
              & Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (3));
         Expected_Open : constant Ada.Streams.Stream_Element_Array :=
           SSH_Lib.Protocol.Numbers.Encode_Uint32
             (Interfaces.Unsigned_32 (21 + Remote_Target'Length))
           & Bytes_From_String ("" & Character'Val (SSH_Lib.SFTP.SSH_FXP_OPEN))
           & SSH_Lib.Protocol.Numbers.Encode_Uint32 (1)
           & SSH_Lib.Protocol.Numbers.Encode_Uint32
               (Interfaces.Unsigned_32 (Remote_Target'Length))
           & Bytes_From_String (Remote_Target)
           & SSH_Lib.Protocol.Numbers.Encode_Uint32 (16#0000_001A#)
           & SSH_Lib.Protocol.Numbers.Encode_Uint32 (16#0000_0004#)
           & SSH_Lib.Protocol.Numbers.Encode_Uint32 (8#644#);
      begin
         SSH_Lib.Sessions.Test_Support.Mark_Authenticated_Open_For_Test (Session_Item);
         Open_Status := SSH_Lib.Sessions.Test_Support.Queue_Channel_Open_Response_For_Test
           (Session_Item, Build_Open_Confirmation (0, 900, 4096, 8192));
         SSH_Lib.Tests.Assertions.Check_Status
           (Open_Status, CryptoLib.Errors.Ok, "file transfer facade", "queue explicit SFTP open response");
         Open_Status := SSH_Lib.Sessions.Test_Support.Queue_Exec_Response_For_Test
           (Session_Item, Build_Exec_Success (0));
         SSH_Lib.Tests.Assertions.Check_Status
           (Open_Status, CryptoLib.Errors.Ok, "file transfer facade", "queue explicit SFTP subsystem response");
         Open_Status := SSH_Lib.Sessions.Test_Support.Queue_Next_Channel_Stdout_For_Test
           (Session_Item, Version_Packet);
         SSH_Lib.Tests.Assertions.Check_Status
           (Open_Status, CryptoLib.Errors.Ok, "file transfer facade", "queue explicit SFTP version packet");

         Status_Value := SSH_Lib.File_Transfer.Upload_Data
           (Session     => Session_Item,
            Remote_Path => "/tmp/facade_dir",
            File_Name   => "facade.txt",
            Data        => Bytes_From_String ("hello"),
            Method      => SSH_Lib.File_Transfer.Upload_SFTP);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value,
            CryptoLib.Errors.Timeout,
            "file transfer facade",
            "SFTP explicit data upload waits for handle reply");
         Assert_SCP_Channel_Data
           (SSH_Lib.Sessions.Test_Support.Last_Plain_Channel_Payload_For_Test
              (Session_Item),
            Expected_Open,
            "file transfer facade explicit SFTP open request");
      end;

      declare
         Session_Item  : SSH_Lib.Sessions.Session;
         Open_Status   : CryptoLib.Errors.Status;
         Local_Path    : constant String :=
           SSH_Lib.Tests.Fixtures.Temp_Paths.Path ("facade_sftp_explicit_file.txt");
         Remote_Target : constant String := "/tmp/facade_dir/explicit.txt";
         Version_Packet : constant Ada.Streams.Stream_Element_Array :=
           Bytes_From_String
             (Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (5)
              & Character'Val (SSH_Lib.SFTP.SSH_FXP_VERSION)
              & Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (3));
         Expected_Open : constant Ada.Streams.Stream_Element_Array :=
           SSH_Lib.Protocol.Numbers.Encode_Uint32
             (Interfaces.Unsigned_32 (21 + Remote_Target'Length))
           & Bytes_From_String ("" & Character'Val (SSH_Lib.SFTP.SSH_FXP_OPEN))
           & SSH_Lib.Protocol.Numbers.Encode_Uint32 (1)
           & SSH_Lib.Protocol.Numbers.Encode_Uint32
               (Interfaces.Unsigned_32 (Remote_Target'Length))
           & Bytes_From_String (Remote_Target)
           & SSH_Lib.Protocol.Numbers.Encode_Uint32 (16#0000_001A#)
           & SSH_Lib.Protocol.Numbers.Encode_Uint32 (16#0000_0004#)
           & SSH_Lib.Protocol.Numbers.Encode_Uint32 (8#640#);
      begin
         Write_Test_File (Local_Path, Bytes_From_String ("local!"));
         SSH_Lib.Sessions.Test_Support.Mark_Authenticated_Open_For_Test (Session_Item);
         Open_Status := SSH_Lib.Sessions.Test_Support.Queue_Channel_Open_Response_For_Test
           (Session_Item, Build_Open_Confirmation (0, 900, 4096, 8192));
         SSH_Lib.Tests.Assertions.Check_Status
           (Open_Status, CryptoLib.Errors.Ok, "file transfer facade", "queue explicit SFTP file open response");
         Open_Status := SSH_Lib.Sessions.Test_Support.Queue_Exec_Response_For_Test
           (Session_Item, Build_Exec_Success (0));
         SSH_Lib.Tests.Assertions.Check_Status
           (Open_Status, CryptoLib.Errors.Ok, "file transfer facade", "queue explicit SFTP file subsystem response");
         Open_Status := SSH_Lib.Sessions.Test_Support.Queue_Next_Channel_Stdout_For_Test
           (Session_Item, Version_Packet);
         SSH_Lib.Tests.Assertions.Check_Status
           (Open_Status, CryptoLib.Errors.Ok, "file transfer facade", "queue explicit SFTP file version packet");

         Status_Value := SSH_Lib.File_Transfer.Upload_File
           (Session     => Session_Item,
            Remote_Path => "/tmp/facade_dir",
            Local_Path  => Local_Path,
            File_Name   => "explicit.txt",
            Mode        => "0640",
            Method      => SSH_Lib.File_Transfer.Upload_SFTP);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value,
            CryptoLib.Errors.Timeout,
            "file transfer facade",
            "SFTP explicit file upload waits for handle reply");
         Assert_SCP_Channel_Data
           (SSH_Lib.Sessions.Test_Support.Last_Plain_Channel_Payload_For_Test
              (Session_Item),
            Expected_Open,
            "file transfer facade explicit SFTP file open request");
         Remove_If_Exists (Local_Path);
      exception
         when others =>
            Remove_If_Exists (Local_Path);
            raise;
      end;

      declare
         Session_Item  : SSH_Lib.Sessions.Session;
         Open_Status   : CryptoLib.Errors.Status;
         Remote_Target : constant String := "/tmp/facade_dir/trailing.txt";
         Version_Packet : constant Ada.Streams.Stream_Element_Array :=
           Bytes_From_String
             (Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (5)
              & Character'Val (SSH_Lib.SFTP.SSH_FXP_VERSION)
              & Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (3));
         Expected_Open : constant Ada.Streams.Stream_Element_Array :=
           SSH_Lib.Protocol.Numbers.Encode_Uint32
             (Interfaces.Unsigned_32 (21 + Remote_Target'Length))
           & Bytes_From_String ("" & Character'Val (SSH_Lib.SFTP.SSH_FXP_OPEN))
           & SSH_Lib.Protocol.Numbers.Encode_Uint32 (1)
           & SSH_Lib.Protocol.Numbers.Encode_Uint32
               (Interfaces.Unsigned_32 (Remote_Target'Length))
           & Bytes_From_String (Remote_Target)
           & SSH_Lib.Protocol.Numbers.Encode_Uint32 (16#0000_001A#)
           & SSH_Lib.Protocol.Numbers.Encode_Uint32 (16#0000_0004#)
           & SSH_Lib.Protocol.Numbers.Encode_Uint32 (8#644#);
      begin
         SSH_Lib.Sessions.Test_Support.Mark_Authenticated_Open_For_Test (Session_Item);
         Open_Status := SSH_Lib.Sessions.Test_Support.Queue_Channel_Open_Response_For_Test
           (Session_Item, Build_Open_Confirmation (0, 900, 4096, 8192));
         SSH_Lib.Tests.Assertions.Check_Status
           (Open_Status, CryptoLib.Errors.Ok, "file transfer facade", "queue trailing slash SFTP open response");
         Open_Status := SSH_Lib.Sessions.Test_Support.Queue_Exec_Response_For_Test
           (Session_Item, Build_Exec_Success (0));
         SSH_Lib.Tests.Assertions.Check_Status
           (Open_Status, CryptoLib.Errors.Ok, "file transfer facade", "queue trailing slash SFTP subsystem response");
         Open_Status := SSH_Lib.Sessions.Test_Support.Queue_Next_Channel_Stdout_For_Test
           (Session_Item, Version_Packet);
         SSH_Lib.Tests.Assertions.Check_Status
           (Open_Status, CryptoLib.Errors.Ok, "file transfer facade", "queue trailing slash SFTP version packet");

         Status_Value := SSH_Lib.File_Transfer.Upload_Data
           (Session     => Session_Item,
            Remote_Path => "/tmp/facade_dir/",
            File_Name   => "trailing.txt",
            Data        => Bytes_From_String ("hello"),
            Method      => SSH_Lib.File_Transfer.Upload_SFTP);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value,
            CryptoLib.Errors.Timeout,
            "file transfer facade",
            "SFTP trailing slash upload waits for handle reply");
         Assert_SCP_Channel_Data
           (SSH_Lib.Sessions.Test_Support.Last_Plain_Channel_Payload_For_Test
              (Session_Item),
            Expected_Open,
            "file transfer facade trailing slash SFTP open request");
      end;

      declare
         Session_Item : SSH_Lib.Sessions.Session;
         Open_Status  : CryptoLib.Errors.Status;
         Local_Path   : constant String :=
           SSH_Lib.Tests.Fixtures.Temp_Paths.Path ("facade_sftp_derived.txt");
         Remote_Target : constant String := "/tmp/facade_dir/facade_sftp_derived.txt";
         Version_Packet : constant Ada.Streams.Stream_Element_Array :=
           Bytes_From_String
             (Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (5)
              & Character'Val (SSH_Lib.SFTP.SSH_FXP_VERSION)
              & Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (3));
         Expected_Open : constant Ada.Streams.Stream_Element_Array :=
           SSH_Lib.Protocol.Numbers.Encode_Uint32
             (Interfaces.Unsigned_32 (21 + Remote_Target'Length))
           & Bytes_From_String ("" & Character'Val (SSH_Lib.SFTP.SSH_FXP_OPEN))
           & SSH_Lib.Protocol.Numbers.Encode_Uint32 (1)
           & SSH_Lib.Protocol.Numbers.Encode_Uint32
               (Interfaces.Unsigned_32 (Remote_Target'Length))
           & Bytes_From_String (Remote_Target)
           & SSH_Lib.Protocol.Numbers.Encode_Uint32 (16#0000_001A#)
           & SSH_Lib.Protocol.Numbers.Encode_Uint32 (16#0000_0004#)
           & SSH_Lib.Protocol.Numbers.Encode_Uint32 (8#600#);
      begin
         Write_Test_File (Local_Path, Bytes_From_String ("local!"));
         SSH_Lib.Sessions.Test_Support.Mark_Authenticated_Open_For_Test (Session_Item);
         Open_Status := SSH_Lib.Sessions.Test_Support.Queue_Channel_Open_Response_For_Test
           (Session_Item, Build_Open_Confirmation (0, 900, 4096, 8192));
         SSH_Lib.Tests.Assertions.Check_Status
           (Open_Status, CryptoLib.Errors.Ok, "file transfer facade", "queue derived SFTP open response");
         Open_Status := SSH_Lib.Sessions.Test_Support.Queue_Exec_Response_For_Test
           (Session_Item, Build_Exec_Success (0));
         SSH_Lib.Tests.Assertions.Check_Status
           (Open_Status, CryptoLib.Errors.Ok, "file transfer facade", "queue derived SFTP subsystem response");
         Open_Status := SSH_Lib.Sessions.Test_Support.Queue_Next_Channel_Stdout_For_Test
           (Session_Item, Version_Packet);
         SSH_Lib.Tests.Assertions.Check_Status
           (Open_Status, CryptoLib.Errors.Ok, "file transfer facade", "queue derived SFTP version packet");

         Status_Value := SSH_Lib.File_Transfer.Upload_File
           (Session     => Session_Item,
            Remote_Path => "/tmp/facade_dir",
            Local_Path  => Local_Path,
            Mode        => "0600",
            Method      => SSH_Lib.File_Transfer.Upload_SFTP);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value,
            CryptoLib.Errors.Timeout,
            "file transfer facade",
            "SFTP derived file upload waits for handle reply");
         Assert_SCP_Channel_Data
           (SSH_Lib.Sessions.Test_Support.Last_Plain_Channel_Payload_For_Test
              (Session_Item),
            Expected_Open,
            "file transfer facade derived SFTP open request");
         Remove_If_Exists (Local_Path);
      exception
         when others =>
            Remove_If_Exists (Local_Path);
            raise;
      end;

      declare
         Session_Item   : SSH_Lib.Sessions.Session;
         Open_Status    : CryptoLib.Errors.Status;
         Downloaded     : SSH_Lib.Protocol.Buffers.Packet_Buffer;
         Version_Packet : constant Ada.Streams.Stream_Element_Array :=
           Bytes_From_String
             (Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (5)
              & Character'Val (SSH_Lib.SFTP.SSH_FXP_VERSION)
              & Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (3));
      begin
         SSH_Lib.Sessions.Test_Support.Mark_Authenticated_Open_For_Test (Session_Item);
         Open_Status := SSH_Lib.Sessions.Test_Support.Queue_Channel_Open_Response_For_Test
           (Session_Item, Build_Open_Confirmation (0, 900, 4096, 8192));
         SSH_Lib.Tests.Assertions.Check_Status
           (Open_Status, CryptoLib.Errors.Ok, "file transfer facade", "queue SFTP download open response");
         Open_Status := SSH_Lib.Sessions.Test_Support.Queue_Exec_Response_For_Test
           (Session_Item, Build_Exec_Success (0));
         SSH_Lib.Tests.Assertions.Check_Status
           (Open_Status, CryptoLib.Errors.Ok, "file transfer facade", "queue SFTP download subsystem response");
         Open_Status := SSH_Lib.Sessions.Test_Support.Queue_Next_Channel_Stdout_For_Test
           (Session_Item,
            Version_Packet
            & SFTP_Handle_Packet (1, "h")
            & SFTP_Data_Packet (2, "abc")
            & SFTP_Status_Packet (3, SSH_Lib.SFTP.SSH_FX_EOF)
            & SFTP_Status_Packet (4));
         SSH_Lib.Tests.Assertions.Check_Status
           (Open_Status, CryptoLib.Errors.Ok, "file transfer facade", "queue SFTP download replies");

         Status_Value := SSH_Lib.File_Transfer.Download_Data
           (Session_Item, "/tmp/facade-download.txt", Downloaded);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "file transfer facade", "download facade succeeds");
         SSH_Lib.Tests.Assertions.Check_Bytes
           (SSH_Lib.Protocol.Buffers.To_Array (Downloaded),
            Bytes_From_String ("abc"),
            "file transfer facade",
            "download facade returns bytes");
      end;

      declare
         Session_Item   : SSH_Lib.Sessions.Session;
         Open_Status    : CryptoLib.Errors.Status;
         Attributes     : SSH_Lib.SFTP.File_Attributes;
         Version_Packet : constant Ada.Streams.Stream_Element_Array :=
           Bytes_From_String
             (Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (5)
              & Character'Val (SSH_Lib.SFTP.SSH_FXP_VERSION)
              & Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (3));
      begin
         SSH_Lib.Sessions.Test_Support.Mark_Authenticated_Open_For_Test (Session_Item);
         Open_Status := SSH_Lib.Sessions.Test_Support.Queue_Channel_Open_Response_For_Test
           (Session_Item, Build_Open_Confirmation (0, 900, 4096, 8192));
         SSH_Lib.Tests.Assertions.Check_Status
           (Open_Status, CryptoLib.Errors.Ok, "file transfer facade", "queue SFTP stat open response");
         Open_Status := SSH_Lib.Sessions.Test_Support.Queue_Exec_Response_For_Test
           (Session_Item, Build_Exec_Success (0));
         SSH_Lib.Tests.Assertions.Check_Status
           (Open_Status, CryptoLib.Errors.Ok, "file transfer facade", "queue SFTP stat subsystem response");
         Open_Status := SSH_Lib.Sessions.Test_Support.Queue_Next_Channel_Stdout_For_Test
           (Session_Item, Version_Packet & SFTP_Attrs_Packet (1, 44, 8#644#));
         SSH_Lib.Tests.Assertions.Check_Status
           (Open_Status, CryptoLib.Errors.Ok, "file transfer facade", "queue SFTP stat replies");

         Status_Value := SSH_Lib.File_Transfer.Stat
           (Session_Item, "/tmp/facade-stat.txt", Attributes);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "file transfer facade", "stat facade succeeds");
         Check (Attributes.Size_Known and then Attributes.Size = 44,
                "file transfer facade stat returns size");
         Check (Attributes.Permissions_Known and then Attributes.Permissions = 8#644#,
                "file transfer facade stat returns permissions");
      end;

      declare
         Session_Item   : SSH_Lib.Sessions.Session;
         Open_Status    : CryptoLib.Errors.Status;
         Version_Packet : constant Ada.Streams.Stream_Element_Array :=
           Bytes_From_String
             (Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (5)
              & Character'Val (SSH_Lib.SFTP.SSH_FXP_VERSION)
              & Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (3));
      begin
         SSH_Lib.Sessions.Test_Support.Mark_Authenticated_Open_For_Test (Session_Item);
         Open_Status := SSH_Lib.Sessions.Test_Support.Queue_Channel_Open_Response_For_Test
           (Session_Item, Build_Open_Confirmation (0, 900, 4096, 8192));
         SSH_Lib.Tests.Assertions.Check_Status
           (Open_Status, CryptoLib.Errors.Ok, "file transfer facade", "queue SFTP rename open response");
         Open_Status := SSH_Lib.Sessions.Test_Support.Queue_Exec_Response_For_Test
           (Session_Item, Build_Exec_Success (0));
         SSH_Lib.Tests.Assertions.Check_Status
           (Open_Status, CryptoLib.Errors.Ok, "file transfer facade", "queue SFTP rename subsystem response");
         Open_Status := SSH_Lib.Sessions.Test_Support.Queue_Next_Channel_Stdout_For_Test
           (Session_Item, Version_Packet & SFTP_Status_Packet (1));
         SSH_Lib.Tests.Assertions.Check_Status
           (Open_Status, CryptoLib.Errors.Ok, "file transfer facade", "queue SFTP rename replies");

         Status_Value := SSH_Lib.File_Transfer.Rename
           (Session_Item, "/tmp/old", "/tmp/new");
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "file transfer facade", "rename facade succeeds");
      end;

      declare
         Session_Item : SSH_Lib.Sessions.Session;
      begin
         declare
            Oversized_Remote_Path : constant String
              (1 .. SSH_Lib.SFTP.Maximum_Remote_Path_Length) := [others => 'x'];
         begin
            SSH_Lib.Sessions.Test_Support.Mark_Authenticated_Open_For_Test (Session_Item);
            Status_Value := SSH_Lib.File_Transfer.Upload_Data
              (Session     => Session_Item,
               Remote_Path => Oversized_Remote_Path,
               File_Name   => "a",
               Data        => Bytes_From_String ("hello"),
               Method      => SSH_Lib.File_Transfer.Upload_SFTP);
            SSH_Lib.Tests.Assertions.Check_Status
              (Status_Value,
               CryptoLib.Errors.Invalid_Command,
               "file transfer facade",
               "SFTP data upload rejects oversized composed path before open");
            Check
              (SSH_Lib.Sessions.Test_Support.Active_Channel_Count_For_Test
                 (Session_Item) = 0,
               "SFTP facade oversized composed path does not open a channel");
         end;

         Status_Value := SSH_Lib.File_Transfer.Upload_Data
           (Session     => Session_Item,
            Remote_Path => "/tmp",
            File_Name   => "bad/name.txt",
            Data        => Bytes_From_String ("hello"),
            Method      => SSH_Lib.File_Transfer.Upload_SFTP);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value,
            CryptoLib.Errors.Invalid_Command,
            "file transfer facade",
            "SFTP data upload rejects path-like explicit filename before open");

         declare
            Oversized_File_Name : constant String
              (1 .. SSH_Lib.File_Transfer.Maximum_File_Name_Length + 1) :=
                [others => 'x'];
         begin
            Status_Value := SSH_Lib.File_Transfer.Upload_Data
              (Session     => Session_Item,
               Remote_Path => "/tmp",
               File_Name   => Oversized_File_Name,
               Data        => Bytes_From_String ("hello"),
               Method      => SSH_Lib.File_Transfer.Upload_SFTP);
            SSH_Lib.Tests.Assertions.Check_Status
              (Status_Value,
               CryptoLib.Errors.Invalid_Command,
               "file transfer facade",
               "SFTP data upload rejects oversized explicit filename before open");

            Status_Value := SSH_Lib.File_Transfer.Upload_File
              (Session     => Session_Item,
               Remote_Path => "/tmp",
               Local_Path  => "missing-local-file.txt",
               File_Name   => Oversized_File_Name,
               Method      => SSH_Lib.File_Transfer.Upload_Auto);
            SSH_Lib.Tests.Assertions.Check_Status
              (Status_Value,
               CryptoLib.Errors.Invalid_Command,
               "file transfer facade",
               "auto file upload rejects oversized explicit filename before local file check");
            Check
              (SSH_Lib.Sessions.Test_Support.Active_Channel_Count_For_Test
                 (Session_Item) = 0,
               "facade oversized explicit filenames do not open a channel");
         end;

         Status_Value := SSH_Lib.File_Transfer.Upload_File
           (Session     => Session_Item,
            Remote_Path => "/tmp",
            Local_Path  => "missing-local-file.txt",
            File_Name   => "bad" & Character'Val (10) & "name.txt",
            Method      => SSH_Lib.File_Transfer.Upload_SFTP);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value,
            CryptoLib.Errors.Invalid_Command,
            "file transfer facade",
            "SFTP file upload rejects control-byte explicit filename before open");

         Status_Value := SSH_Lib.File_Transfer.Upload_Data
           (Session     => Session_Item,
            Remote_Path => "/tmp",
            File_Name   => "..",
            Data        => Bytes_From_String ("hello"),
            Method      => SSH_Lib.File_Transfer.Upload_SFTP);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value,
            CryptoLib.Errors.Invalid_Command,
            "file transfer facade",
            "SFTP data upload rejects dot-dot explicit filename before open");

         Status_Value := SSH_Lib.File_Transfer.Upload_File
           (Session     => Session_Item,
            Remote_Path => "/tmp",
            Local_Path  => "",
            Method      => SSH_Lib.File_Transfer.Upload_Auto);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value,
            CryptoLib.Errors.Invalid_Command,
            "file transfer facade",
            "auto file upload rejects empty derived filename before open");

         Status_Value := SSH_Lib.File_Transfer.Upload_File
           (Session     => Session_Item,
            Remote_Path => "/tmp",
            Local_Path  => "",
            Method      => SSH_Lib.File_Transfer.Upload_SFTP);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value,
            CryptoLib.Errors.Invalid_Command,
            "file transfer facade",
            "SFTP derived file upload rejects empty derived filename before local file check");
      end;
   end Assert_SCP_Command_And_Header_Validation;

   procedure Assert_Subsystem_Request_Validation is
      Session_Item : SSH_Lib.Sessions.Session;
      Channel_Item : SSH_Lib.Channels.Channel;
      Status_Value : CryptoLib.Errors.Status;
   begin
      SSH_Lib.Sessions.Test_Support.Mark_Authenticated_Open_For_Test (Session_Item);
      Status_Value := SSH_Lib.Sessions.Test_Support.Queue_Channel_Open_Response_For_Test
        (Session_Item, Build_Open_Confirmation (0, 900, 4096, 8192));
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok, "subsystem request", "queue open response");
      Status_Value := SSH_Lib.Sessions.Test_Support.Queue_Exec_Response_For_Test
        (Session_Item, Build_Exec_Success (0));
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok, "subsystem request", "queue subsystem response");

      Status_Value := SSH_Lib.Channels.Open_Subsystem
        (Session_Item, "sftp", Channel_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok, "subsystem request", "Open_Subsystem succeeds");
      declare
         Payload : constant Ada.Streams.Stream_Element_Array :=
           SSH_Lib.Sessions.Test_Support.Last_Exec_Request_Payload_For_Test
             (Session_Item);
         Expected : constant Ada.Streams.Stream_Element_Array :=
           SSH_Lib.Protocol.Buffers.To_Array
             (SSH_Lib.Protocol.Channels.Encode_Subsystem_Request (900, "sftp"));
      begin
         SSH_Lib.Tests.Assertions.Check_Bytes
           (Payload, Expected, "subsystem request", "request bytes are exact");
      end;

      Status_Value := SSH_Lib.Channels.Open_Subsystem
        (Session_Item, "bad" & Character'Val (10) & "name", Channel_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Invalid_Command,
         "subsystem request",
         "invalid subsystem name rejected");
   end Assert_Subsystem_Request_Validation;

   procedure Assert_SFTP_Initialization is
      Channel_Item : SSH_Lib.Channels.Channel;
      Session_Item : SSH_Lib.Sessions.Session;
      Version_Value : Natural := 0;
      Status_Value : CryptoLib.Errors.Status;
      Init_Packet : constant Ada.Streams.Stream_Element_Array :=
        SSH_Lib.Protocol.Buffers.To_Array (SSH_Lib.SFTP.Encode_Init_Packet);
      Version_Packet : constant Ada.Streams.Stream_Element_Array :=
        Bytes_From_String
          (Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (5)
           & Character'Val (SSH_Lib.SFTP.SSH_FXP_VERSION)
           & Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (3));
      Version_Buffer : SSH_Lib.Protocol.Buffers.Packet_Buffer;
   begin
      SSH_Lib.Tests.Assertions.Check_Bytes
        (Init_Packet,
         Bytes_From_String
           (Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (5)
            & Character'Val (SSH_Lib.SFTP.SSH_FXP_INIT)
            & Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (3)),
         "SFTP initialization",
         "init packet bytes are exact");

      Status_Value := SSH_Lib.Protocol.Buffers.Set (Version_Buffer, Version_Packet);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok, "SFTP initialization", "set version packet");
      Status_Value := SSH_Lib.SFTP.Parse_Version_Packet
        (Version_Buffer, Version_Value);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok, "SFTP initialization", "parse version packet");
      Check (Version_Value = 3, "SFTP initialization parses version 3");

      declare
         Extensions        : SSH_Lib.SFTP.Extension_Info;
         Extension_Packet  : constant Ada.Streams.Stream_Element_Array :=
           SFTP_Version_Extensions_Packet;
      begin
         Status_Value := SSH_Lib.Protocol.Buffers.Set
           (Version_Buffer, Extension_Packet);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP initialization", "set extension version packet");
         Status_Value := SSH_Lib.SFTP.Parse_Version_Packet
           (Version_Buffer, Version_Value, Extensions);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP initialization", "parse extensions");
         Check (Version_Value = 3, "SFTP initialization parses extension version 3");
         Check (Extensions.Posix_Rename and then Extensions.Fsync and then Extensions.StatVFS,
                "SFTP initialization detects core OpenSSH extensions");
         Check (Extensions.Hardlink and then Extensions.LSetStat and then Extensions.Limits,
                "SFTP initialization detects mutating OpenSSH extensions");
         Check (Extensions.Copy_Data and then Extensions.Expand_Path,
                "SFTP initialization detects transfer OpenSSH extensions");
         Check (Extensions.Check_File,
                "SFTP initialization detects checksum extension");
         Check
           (SSH_Lib.SFTP.Extension_Name
              (SSH_Lib.SFTP.Fsync_Known_Extension) =
              SSH_Lib.SFTP.Fsync_Extension
            and then SSH_Lib.SFTP.Supports_Extension
              (Extensions, SSH_Lib.SFTP.Fsync_Known_Extension)
            and then SSH_Lib.SFTP.Supports_Extension
              (Extensions, SSH_Lib.SFTP.Check_File_Known_Extension),
            "SFTP typed known extension catalogue covers advertised extensions");
         declare
            Capability_Packet : constant Ada.Streams.Stream_Element_Array :=
              SFTP_Version_Capabilities_Packet;
         begin
            Status_Value := SSH_Lib.Protocol.Buffers.Set
              (Version_Buffer, Capability_Packet);
            SSH_Lib.Tests.Assertions.Check_Status
              (Status_Value, CryptoLib.Errors.Ok, "SFTP initialization", "set capability version packet");
            Status_Value := SSH_Lib.SFTP.Parse_Version_Packet
              (Version_Buffer, Version_Value, Extensions);
            SSH_Lib.Tests.Assertions.Check_Status
              (Status_Value, CryptoLib.Errors.Ok, "SFTP initialization", "parse capability extensions");
            Check (Version_Value = 6 and then Extensions.Versions
                   and then Extensions.Version_3 and then Extensions.Version_6,
                   "SFTP initialization parses versions extension");
            Check
              (SSH_Lib.SFTP.Extension_Name
                 (SSH_Lib.SFTP.Version_Select_Known_Extension) =
                 SSH_Lib.SFTP.Version_Select_Extension
               and then SSH_Lib.SFTP.Supports_Extension
                 (Extensions, SSH_Lib.SFTP.Version_Select_Known_Extension),
               "SFTP typed known extension catalogue covers version-select");
            Check (Extensions.Supported2 and then Extensions.Text_Seek
                   and then Extensions.Capabilities.Present
                   and then Extensions.Capabilities.Max_Read_Size = 32768,
                   "SFTP initialization parses supported2 capabilities");
            Check
              (SSH_Lib.SFTP.Supports_Open_Mode
                 (Extensions, SSH_Lib.SFTP.Read_Only)
               and then SSH_Lib.SFTP.Supports_Block_Mask (Extensions, 16#5678#),
               "SFTP capability predicates accept advertised operations");
         end;

         declare
            Limited_Extensions : constant SSH_Lib.SFTP.Extension_Info :=
              (Capabilities =>
                 (Present                     => True,
                  Supported_Attribute_Mask    => 0,
                  Supported_Attribute_Bits    => 0,
                  Supported_Open_Flags        => 16#0000_0002#,
                  Supported_Access_Mask       => 16#0000_0001#,
                  Max_Read_Size               => 32768,
                  Supported_Open_Block_Vector => 0,
                  Supported_Block_Vector      => 1),
               others => <>);
            Metadata : SSH_Lib.SFTP.File_Attributes;
         begin
            Metadata.Permissions_Known := True;
            Metadata.Permissions := 8#600#;
            Check
              (SSH_Lib.SFTP.Supports_Open_Mode
                 (Limited_Extensions, SSH_Lib.SFTP.Read_Only)
               and then not SSH_Lib.SFTP.Supports_Open_Mode
                 (Limited_Extensions, SSH_Lib.SFTP.Write_Truncate),
               "SFTP supported2 open masks gate write modes");
            Check
              (not SSH_Lib.SFTP.Supports_Attributes
                 (Limited_Extensions, Metadata, 6),
               "SFTP supported2 attribute mask rejects unsupported attrs");
            Check
              (SSH_Lib.SFTP.Supports_Block_Mask (Limited_Extensions, 1)
               and then not SSH_Lib.SFTP.Supports_Block_Mask
                 (Limited_Extensions, 2),
               "SFTP supported2 block mask gates lock masks");
         end;

         declare
            Rich_Metadata : SSH_Lib.SFTP.File_Attributes;
            Copied        : SSH_Lib.SFTP.File_Attributes;
         begin
            SSH_Lib.SFTP.Set_Allocation_Size (Rich_Metadata, 4096);
            SSH_Lib.SFTP.Set_Owner_Group (Rich_Metadata, "owner", "group");
            SSH_Lib.SFTP.Set_Create_Time
              (Rich_Metadata, Ada.Calendar.Clock, 123);
            SSH_Lib.SFTP.Set_ACL (Rich_Metadata, "acl-data");
            SSH_Lib.SFTP.Set_Attribute_Bits
              (Rich_Metadata, 16#0000_0001#, 16#0000_00FF#);
            SSH_Lib.SFTP.Set_Text_Hint (Rich_Metadata, 1);
            SSH_Lib.SFTP.Set_Mime_Type (Rich_Metadata, "text/plain");
            SSH_Lib.SFTP.Set_Link_Count (Rich_Metadata, 2);
            SSH_Lib.SFTP.Set_Untranslated_Name
              (Rich_Metadata, "raw-name");
            Copied := SSH_Lib.SFTP.Copy_Metadata (Rich_Metadata);
            Check
              (Copied.Allocation_Size_Known
               and then Copied.Owner_Group_Known
               and then Copied.Create_Time_Known
               and then Copied.ACL_Known
               and then Copied.Attribute_Bits_Known
               and then Copied.Text_Hint_Known
               and then Copied.Mime_Type_Known
               and then Copied.Link_Count_Known
               and then Copied.Untranslated_Name_Known,
               "SFTP v4 attribute helpers populate copyable metadata");
         end;
         Check
           (SSH_Lib.SFTP.Supports_Extension
              (Extensions, SSH_Lib.SFTP.Posix_Rename_Extension),
            "SFTP initialization exposes extension lookup");
         Check
           (not SSH_Lib.SFTP.Supports_Extension
              (Extensions, "unknown@example.test"),
            "SFTP initialization ignores unknown extensions");
      end;

      declare
         Version_4_Packet : constant Ada.Streams.Stream_Element_Array :=
           Bytes_From_String
             (Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (5)
              & Character'Val (SSH_Lib.SFTP.SSH_FXP_VERSION)
              & Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (4));
         Version_6_Packet : constant Ada.Streams.Stream_Element_Array :=
           Bytes_From_String
             (Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (5)
              & Character'Val (SSH_Lib.SFTP.SSH_FXP_VERSION)
              & Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (6));
         Version_7_Packet : constant Ada.Streams.Stream_Element_Array :=
           Bytes_From_String
             (Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (5)
              & Character'Val (SSH_Lib.SFTP.SSH_FXP_VERSION)
              & Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (7));
      begin
         Check
           (SSH_Lib.SFTP.Supports_Protocol_Version (3)
            and then SSH_Lib.SFTP.Supports_Protocol_Version (6)
            and then not SSH_Lib.SFTP.Supports_Protocol_Version (7),
            "SFTP initialization exposes supported protocol version range");

         Status_Value := SSH_Lib.Protocol.Buffers.Set
           (Version_Buffer, Version_4_Packet);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP initialization", "set version 4 packet");
         Status_Value := SSH_Lib.SFTP.Parse_Version_Packet
           (Version_Buffer, Version_Value);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP initialization", "version 4 accepted");
         Check (Version_Value = 4, "SFTP initialization reports version 4 value");

         Status_Value := SSH_Lib.Protocol.Buffers.Set
           (Version_Buffer, Version_6_Packet);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP initialization", "set version 6 packet");
         Status_Value := SSH_Lib.SFTP.Parse_Version_Packet
           (Version_Buffer, Version_Value);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP initialization", "version 6 accepted");
         Check (Version_Value = 6, "SFTP initialization reports version 6 value");

         Status_Value := SSH_Lib.Protocol.Buffers.Set
           (Version_Buffer, Version_7_Packet);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP initialization", "set unsupported version packet");
         Status_Value := SSH_Lib.SFTP.Parse_Version_Packet
           (Version_Buffer, Version_Value);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value,
            CryptoLib.Errors.Unsupported_Feature,
            "SFTP initialization",
            "unsupported version rejected");
         Check (Version_Value = 7, "SFTP initialization reports unsupported version value");
      end;

      SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
        (Channel_Item, Local_Channel_Id => 0, Remote_Channel_Id => 1);
      Status_Value := SSH_Lib.Channels.Test_Support.Queue_Stdout_For_Test
        (Channel_Item, Version_Packet);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok, "SFTP initialization", "queue version packet");
      Status_Value := SSH_Lib.SFTP.Initialize (Channel_Item, Version_Value);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok, "SFTP initialization", "initialize succeeds");
      Check (Version_Value = 3, "SFTP initialization returns negotiated version");
      Assert_SCP_Channel_Data (Channel_Item, Init_Packet, "SFTP initialization");

      declare
         Extension_Channel : SSH_Lib.Channels.Channel;
         Extensions        : SSH_Lib.SFTP.Extension_Info;
      begin
         SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
           (Extension_Channel, Local_Channel_Id => 0, Remote_Channel_Id => 1);
         Status_Value := SSH_Lib.Channels.Test_Support.Queue_Stdout_For_Test
           (Extension_Channel, SFTP_Version_Extensions_Packet);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP initialization", "queue extension version packet");
         Status_Value := SSH_Lib.SFTP.Initialize
           (Extension_Channel, Version_Value, Extensions);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP initialization", "initialize returns extensions");
         Check (Version_Value = 3 and then Extensions.Posix_Rename and then Extensions.Fsync,
                "SFTP initialization overload returns negotiated extensions");
      end;

      SSH_Lib.Sessions.Test_Support.Mark_Authenticated_Open_For_Test (Session_Item);
      Status_Value := SSH_Lib.Sessions.Test_Support.Queue_Channel_Open_Response_For_Test
        (Session_Item, Build_Open_Confirmation (0, 900, 4096, 8192));
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok, "SFTP initialization", "queue subsystem open response");
      Status_Value := SSH_Lib.Sessions.Test_Support.Queue_Exec_Response_For_Test
        (Session_Item, Build_Exec_Success (0));
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok, "SFTP initialization", "queue subsystem success response");
      Status_Value := SSH_Lib.SFTP.Open (Session_Item, Channel_Item, Version_Value);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Timeout, "SFTP initialization",
         "open waits for version packet after subsystem");
      declare
         Payload : constant Ada.Streams.Stream_Element_Array :=
           SSH_Lib.Sessions.Test_Support.Last_Exec_Request_Payload_For_Test
             (Session_Item);
         Expected : constant Ada.Streams.Stream_Element_Array :=
           SSH_Lib.Protocol.Buffers.To_Array
             (SSH_Lib.Protocol.Channels.Encode_Subsystem_Request (900, "sftp"));
      begin
         SSH_Lib.Tests.Assertions.Check_Bytes
           (Payload, Expected, "SFTP initialization", "Open sends sftp subsystem request");
      end;

      declare
         Session_Item : SSH_Lib.Sessions.Session;
         Open_Status : CryptoLib.Errors.Status;
      begin
         SSH_Lib.Sessions.Test_Support.Mark_Authenticated_Open_For_Test (Session_Item);
         Open_Status := SSH_Lib.Sessions.Test_Support.Queue_Channel_Open_Response_For_Test
           (Session_Item, Build_Open_Confirmation (0, 900, 4096, 8192));
         SSH_Lib.Tests.Assertions.Check_Status
           (Open_Status, CryptoLib.Errors.Ok, "SFTP upload preflight", "queue open response");
         Status_Value := SSH_Lib.SFTP.Upload_Data
           (Session_Item, "", Bytes_From_String ("hello"), "0644");
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value,
            CryptoLib.Errors.Invalid_Command,
            "SFTP upload preflight",
            "empty remote path rejected before subsystem open");
         Check
           (SSH_Lib.Sessions.Test_Support.Active_Channel_Count_For_Test
              (Session_Item) = 0,
            "SFTP upload preflight does not open a channel for empty path");
      end;

      declare
         Upload_Channel : SSH_Lib.Channels.Channel;
         Oversized_Path : constant String
           (1 .. SSH_Lib.SFTP.Maximum_Remote_Path_Length + 1) := [others => 'x'];
      begin
         SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
           (Upload_Channel, Local_Channel_Id => 0, Remote_Channel_Id => 1);
         Status_Value := SSH_Lib.SFTP.Upload_Data
           (Upload_Channel, "", Bytes_From_String ("hello"), "0644");
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value,
            CryptoLib.Errors.Invalid_Command,
            "SFTP upload validation",
            "empty remote path rejected before write");
         Check
           (SSH_Lib.Channels.Test_Support.Outbound_Data_Packet_Count_For_Test
              (Upload_Channel) = 0,
            "SFTP upload validation does not write for empty path");

         Status_Value := SSH_Lib.SFTP.Upload_Data
           (Upload_Channel, Oversized_Path, Bytes_From_String ("hello"), "0644");
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value,
            CryptoLib.Errors.Invalid_Command,
            "SFTP upload validation",
            "oversized remote path rejected before write");
         Check
           (SSH_Lib.Channels.Test_Support.Outbound_Data_Packet_Count_For_Test
              (Upload_Channel) = 0,
            "SFTP upload validation does not write for oversized path");

         Status_Value := SSH_Lib.SFTP.Upload_File
           (Upload_Channel, "", "missing-sftp-local-file.txt", "0644");
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value,
            CryptoLib.Errors.Invalid_Command,
            "SFTP upload validation",
            "file upload rejects empty remote path before local file check");
         Check
           (SSH_Lib.Channels.Test_Support.Outbound_Data_Packet_Count_For_Test
              (Upload_Channel) = 0,
            "SFTP file upload validation does not write for empty path");

         Status_Value := SSH_Lib.SFTP.Upload_Data
           (Upload_Channel,
            "/tmp/bad-mode.txt",
            Bytes_From_String ("hello"),
            "bad!");
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value,
            CryptoLib.Errors.Invalid_Command,
            "SFTP upload validation",
            "invalid mode rejected before write");
         Check
           (SSH_Lib.Channels.Test_Support.Outbound_Data_Packet_Count_For_Test
              (Upload_Channel) = 0,
            "SFTP upload validation does not write for invalid mode");
      end;

      declare
         Upload_Channel : SSH_Lib.Channels.Channel;
         Open_Status : constant Ada.Streams.Stream_Element_Array :=
           Bytes_From_String
             (Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (17)
              & Character'Val (SSH_Lib.SFTP.SSH_FXP_STATUS)
              & Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (1)
              & Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (4)
              & Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (0)
              & Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (0));
      begin
         SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
           (Upload_Channel, Local_Channel_Id => 0, Remote_Channel_Id => 1);
         Status_Value := SSH_Lib.Channels.Test_Support.Queue_Stdout_For_Test
           (Upload_Channel, Open_Status);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP upload open denial", "queue server reply");
         Status_Value := SSH_Lib.SFTP.Upload_Data
           (Upload_Channel, "/tmp/upload.txt", Bytes_From_String ("hello"), "0644");
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value,
            CryptoLib.Errors.Remote_Failure,
            "SFTP upload open denial",
            "open status denial returns upload failure");
         Check
           (SSH_Lib.Channels.Test_Support.Outbound_Data_Packet_Count_For_Test
              (Upload_Channel) = 1,
            "SFTP upload open denial does not close an unopened handle");
      end;

      declare
         Upload_Channel : SSH_Lib.Channels.Channel;
         Large_Handle : constant Ada.Streams.Stream_Element_Array
           (Ada.Streams.Stream_Element_Offset'(1) .. Ada.Streams.Stream_Element_Offset'(230_000)) :=
           [others => Ada.Streams.Stream_Element (Character'Pos ('h'))];
         Handle_Response : constant Ada.Streams.Stream_Element_Array :=
           SSH_Lib.Protocol.Numbers.Encode_Uint32
             (Interfaces.Unsigned_32 (9 + Large_Handle'Length))
           & Bytes_From_String ("" & Character'Val (SSH_Lib.SFTP.SSH_FXP_HANDLE))
           & SSH_Lib.Protocol.Numbers.Encode_Uint32 (1)
           & SSH_Lib.Protocol.Numbers.Encode_Uint32
               (Interfaces.Unsigned_32 (Large_Handle'Length))
           & Large_Handle;
      begin
         SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
           (Upload_Channel, Local_Channel_Id => 0, Remote_Channel_Id => 1);
         Status_Value := SSH_Lib.Channels.Test_Support.Queue_Stdout_For_Test
           (Upload_Channel, Handle_Response);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP upload handle bounds", "queue oversized handle");
         Status_Value := SSH_Lib.SFTP.Upload_Data
           (Upload_Channel, "/tmp/upload.txt", Bytes_From_String ("hello"), "0644");
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value,
            CryptoLib.Errors.Read_Failed,
            "SFTP upload handle bounds",
            "oversized server handle rejected before data write");
         Check
           (SSH_Lib.Channels.Test_Support.Outbound_Data_Packet_Count_For_Test
              (Upload_Channel) = 1,
            "SFTP upload handle bounds sends only the open request");
      end;

      declare
         Upload_Channel : SSH_Lib.Channels.Channel;
         Handle_Response : constant Ada.Streams.Stream_Element_Array :=
           Bytes_From_String
             (Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (10)
              & Character'Val (SSH_Lib.SFTP.SSH_FXP_HANDLE)
              & Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (1)
              & Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (1)
              & "h");
         Write_Status : constant Ada.Streams.Stream_Element_Array :=
           Bytes_From_String
             (Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (17)
              & Character'Val (SSH_Lib.SFTP.SSH_FXP_STATUS)
              & Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (2)
              & Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (SSH_Lib.SFTP.SSH_FX_OK)
              & Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (0)
              & Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (0));
         Close_Status : constant Ada.Streams.Stream_Element_Array :=
           Bytes_From_String
             (Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (17)
              & Character'Val (SSH_Lib.SFTP.SSH_FXP_STATUS)
              & Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (3)
              & Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (SSH_Lib.SFTP.SSH_FX_OK)
              & Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (0)
              & Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (0));
         Expected_Close : constant Ada.Streams.Stream_Element_Array :=
           Bytes_From_String
             (Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (10)
              & Character'Val (SSH_Lib.SFTP.SSH_FXP_CLOSE)
              & Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (3)
              & Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (1)
              & "h");
      begin
         SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
           (Upload_Channel, Local_Channel_Id => 0, Remote_Channel_Id => 1);
         Status_Value := SSH_Lib.Channels.Test_Support.Queue_Stdout_For_Test
           (Upload_Channel, Handle_Response & Write_Status & Close_Status);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP upload", "queue server replies");
         Status_Value := SSH_Lib.SFTP.Upload_Data
           (Upload_Channel, "/tmp/upload.txt", Bytes_From_String ("hello"), "0644");
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP upload", "channel upload succeeds");
         Check
           (SSH_Lib.Channels.Test_Support.Outbound_Data_Packet_Count_For_Test
              (Upload_Channel) = 3,
            "SFTP upload emits open, write, and close packets");
         Assert_SCP_Channel_Data (Upload_Channel, Expected_Close, "SFTP upload close request");
      end;

      declare
         Upload_Channel : SSH_Lib.Channels.Channel;
         Large_Data : constant Ada.Streams.Stream_Element_Array
           (Ada.Streams.Stream_Element_Offset'(1) .. Ada.Streams.Stream_Element_Offset'(32_769)) :=
           [others => 65];
         Handle_Response : constant Ada.Streams.Stream_Element_Array :=
           Bytes_From_String
             (Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (10)
              & Character'Val (SSH_Lib.SFTP.SSH_FXP_HANDLE)
              & Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (1)
              & Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (1)
              & "h");
         First_Write_Status : constant Ada.Streams.Stream_Element_Array :=
           Bytes_From_String
             (Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (17)
              & Character'Val (SSH_Lib.SFTP.SSH_FXP_STATUS)
              & Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (2)
              & Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (SSH_Lib.SFTP.SSH_FX_OK)
              & Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (0)
              & Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (0));
         Second_Write_Status : constant Ada.Streams.Stream_Element_Array :=
           Bytes_From_String
             (Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (17)
              & Character'Val (SSH_Lib.SFTP.SSH_FXP_STATUS)
              & Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (3)
              & Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (SSH_Lib.SFTP.SSH_FX_OK)
              & Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (0)
              & Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (0));
         Close_Status : constant Ada.Streams.Stream_Element_Array :=
           Bytes_From_String
             (Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (17)
              & Character'Val (SSH_Lib.SFTP.SSH_FXP_STATUS)
              & Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (4)
              & Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (SSH_Lib.SFTP.SSH_FX_OK)
              & Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (0)
              & Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (0));
         Expected_Close : constant Ada.Streams.Stream_Element_Array :=
           Bytes_From_String
             (Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (10)
              & Character'Val (SSH_Lib.SFTP.SSH_FXP_CLOSE)
              & Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (4)
              & Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (1)
              & "h");
      begin
         SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
           (Upload_Channel, Local_Channel_Id => 0, Remote_Channel_Id => 1);
         Status_Value := SSH_Lib.Channels.Test_Support.Queue_Stdout_For_Test
           (Upload_Channel,
            Handle_Response & First_Write_Status & Second_Write_Status & Close_Status);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP chunked upload", "queue server replies");
         Status_Value := SSH_Lib.SFTP.Upload_Data
           (Upload_Channel, "/tmp/chunked.txt", Large_Data, "0644");
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP chunked upload", "channel upload succeeds");
         Check
           (SSH_Lib.Channels.Test_Support.Outbound_Data_Packet_Count_For_Test
              (Upload_Channel) = 4,
            "SFTP chunked upload emits open, two writes, and close");
         Assert_SCP_Channel_Data
           (Upload_Channel, Expected_Close, "SFTP chunked upload close request");
      end;

      declare
         Upload_Channel : SSH_Lib.Channels.Channel;
         Handle_Response : constant Ada.Streams.Stream_Element_Array :=
           Bytes_From_String
             (Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (10)
              & Character'Val (SSH_Lib.SFTP.SSH_FXP_HANDLE)
              & Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (1)
              & Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (1)
              & "h");
         Close_Status : constant Ada.Streams.Stream_Element_Array :=
           Bytes_From_String
             (Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (17)
              & Character'Val (SSH_Lib.SFTP.SSH_FXP_STATUS)
              & Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (2)
              & Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (SSH_Lib.SFTP.SSH_FX_OK)
              & Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (0)
              & Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (0));
         Expected_Close : constant Ada.Streams.Stream_Element_Array :=
           Bytes_From_String
             (Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (10)
              & Character'Val (SSH_Lib.SFTP.SSH_FXP_CLOSE)
              & Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (2)
              & Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (1)
              & "h");
      begin
         SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
           (Upload_Channel, Local_Channel_Id => 0, Remote_Channel_Id => 1);
         Status_Value := SSH_Lib.Channels.Test_Support.Queue_Stdout_For_Test
           (Upload_Channel, Handle_Response & Close_Status);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP empty upload", "queue server replies");
         Status_Value := SSH_Lib.SFTP.Upload_Data
           (Upload_Channel, "/tmp/empty.txt", Bytes_From_String (""), "0644");
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP empty upload", "channel upload succeeds");
         Check
           (SSH_Lib.Channels.Test_Support.Outbound_Data_Packet_Count_For_Test
              (Upload_Channel) = 2,
            "SFTP empty upload emits open and close only");
         Assert_SCP_Channel_Data
           (Upload_Channel, Expected_Close, "SFTP empty upload close request");
      end;

      declare
         Robust_Upload_Channel : SSH_Lib.Channels.Channel;
         Remote_Path           : constant String := "/tmp/robust.txt";
         Temp_Path             : constant String :=
           Remote_Path & ".ada-ssh-upload.tmp";
      begin
         SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
           (Robust_Upload_Channel, Local_Channel_Id => 0, Remote_Channel_Id => 1);
         Status_Value := SSH_Lib.Channels.Test_Support.Queue_Stdout_For_Test
           (Robust_Upload_Channel,
            SFTP_Status_Packet (1, SSH_Lib.SFTP.SSH_FX_NO_SUCH_FILE)
            & SFTP_Handle_Packet (1, "r")
            & SFTP_Status_Packet (2)
            & SFTP_Status_Packet (3)
            & SFTP_Attrs_Packet (1, 3, 8#600#)
            & SFTP_Status_Packet (1)
            & SFTP_Attrs_Packet (1, 3, 8#600#));
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP robust upload", "queue atomic replies");
         Status_Value := SSH_Lib.SFTP.Upload_Data
           (Robust_Upload_Channel,
            Remote_Path,
            Bytes_From_String ("abc"),
            "0600",
            (Pipeline_Depth        => 1,
             Retry_Count           => 0,
             Verify_After_Transfer => True,
             Atomic_Upload         => True,
             Read_Chunk_Size       => SSH_Lib.SFTP.Upload_Chunk_Size,
             Write_Chunk_Size      => SSH_Lib.SFTP.Upload_Chunk_Size,
             others                => <>));
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP robust upload", "atomic verified upload succeeds");
         Check
           (SSH_Lib.Channels.Test_Support.Outbound_Data_Packet_Count_For_Test
              (Robust_Upload_Channel) = 7,
            "SFTP robust upload emits remove, upload, verify, rename, and final verify");
         Assert_SCP_Channel_Data
           (Robust_Upload_Channel,
            SFTP_Open_Request_Packet (1, Temp_Path, 16#0000_001A#, 16#0000_0004#, 8#600#),
            "SFTP robust upload opens temporary path");
      end;

      declare
         Upload_Channel : SSH_Lib.Channels.Channel;
         Local_Path : constant String :=
           SSH_Lib.Tests.Fixtures.Temp_Paths.Path ("sftp_empty_upload_file.txt");
         Handle_Response : constant Ada.Streams.Stream_Element_Array :=
           Bytes_From_String
             (Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (10)
              & Character'Val (SSH_Lib.SFTP.SSH_FXP_HANDLE)
              & Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (1)
              & Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (1)
              & "h");
         Close_Status : constant Ada.Streams.Stream_Element_Array :=
           Bytes_From_String
             (Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (17)
              & Character'Val (SSH_Lib.SFTP.SSH_FXP_STATUS)
              & Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (2)
              & Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (SSH_Lib.SFTP.SSH_FX_OK)
              & Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (0)
              & Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (0));
         Expected_Close : constant Ada.Streams.Stream_Element_Array :=
           Bytes_From_String
             (Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (10)
              & Character'Val (SSH_Lib.SFTP.SSH_FXP_CLOSE)
              & Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (2)
              & Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (1)
              & "h");
      begin
         Write_Test_File (Local_Path, Bytes_From_String (""));
         SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
           (Upload_Channel, Local_Channel_Id => 0, Remote_Channel_Id => 1);
         Status_Value := SSH_Lib.Channels.Test_Support.Queue_Stdout_For_Test
           (Upload_Channel, Handle_Response & Close_Status);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP empty file upload", "queue server replies");
         Status_Value := SSH_Lib.SFTP.Upload_File
           (Upload_Channel, "/tmp/empty-file.txt", Local_Path, "0644");
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP empty file upload", "channel upload succeeds");
         Check
           (SSH_Lib.Channels.Test_Support.Outbound_Data_Packet_Count_For_Test
              (Upload_Channel) = 2,
            "SFTP empty file upload emits open and close only");
         Assert_SCP_Channel_Data
           (Upload_Channel, Expected_Close, "SFTP empty file upload close request");
         Remove_If_Exists (Local_Path);
      exception
         when others =>
            Remove_If_Exists (Local_Path);
            raise;
      end;

      declare
         Upload_Channel : SSH_Lib.Channels.Channel;
         Handle_Response : constant Ada.Streams.Stream_Element_Array :=
           Bytes_From_String
             (Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (10)
              & Character'Val (SSH_Lib.SFTP.SSH_FXP_HANDLE)
              & Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (1)
              & Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (1)
              & "h");
         Truncated_Write_Status : constant Ada.Streams.Stream_Element_Array :=
           Bytes_From_String
             (Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (9)
              & Character'Val (SSH_Lib.SFTP.SSH_FXP_STATUS)
              & Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (2)
              & Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (SSH_Lib.SFTP.SSH_FX_OK));
         Close_Status : constant Ada.Streams.Stream_Element_Array :=
           Bytes_From_String
             (Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (17)
              & Character'Val (SSH_Lib.SFTP.SSH_FXP_STATUS)
              & Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (3)
              & Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (SSH_Lib.SFTP.SSH_FX_OK)
              & Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (0)
              & Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (0));
      begin
         SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
           (Upload_Channel, Local_Channel_Id => 0, Remote_Channel_Id => 1);
         Status_Value := SSH_Lib.Channels.Test_Support.Queue_Stdout_For_Test
           (Upload_Channel, Handle_Response & Truncated_Write_Status & Close_Status);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP upload malformed status", "queue server replies");
         Status_Value := SSH_Lib.SFTP.Upload_Data
           (Upload_Channel, "/tmp/upload.txt", Bytes_From_String ("hello"), "0644");
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value,
            CryptoLib.Errors.Read_Failed,
            "SFTP upload malformed status",
            "truncated status is rejected");
         Check
           (SSH_Lib.Channels.Test_Support.Outbound_Data_Packet_Count_For_Test
              (Upload_Channel) = 3,
            "SFTP upload malformed status closes the remote handle");
      end;

      declare
         Upload_Channel : SSH_Lib.Channels.Channel;
         Handle_Response : constant Ada.Streams.Stream_Element_Array :=
           Bytes_From_String
             (Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (10)
              & Character'Val (SSH_Lib.SFTP.SSH_FXP_HANDLE)
              & Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (1)
              & Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (1)
              & "h");
         Write_Status : constant Ada.Streams.Stream_Element_Array :=
           Bytes_From_String
             (Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (17)
              & Character'Val (SSH_Lib.SFTP.SSH_FXP_STATUS)
              & Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (2)
              & Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (4)
              & Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (0)
              & Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (0));
         Close_Status : constant Ada.Streams.Stream_Element_Array :=
           Bytes_From_String
             (Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (17)
              & Character'Val (SSH_Lib.SFTP.SSH_FXP_STATUS)
              & Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (3)
              & Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (SSH_Lib.SFTP.SSH_FX_OK)
              & Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (0)
              & Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (0));
         Expected_Close : constant Ada.Streams.Stream_Element_Array :=
           Bytes_From_String
             (Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (10)
              & Character'Val (SSH_Lib.SFTP.SSH_FXP_CLOSE)
              & Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (3)
              & Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (1)
              & "h");
      begin
         SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
           (Upload_Channel, Local_Channel_Id => 0, Remote_Channel_Id => 1);
         Status_Value := SSH_Lib.Channels.Test_Support.Queue_Stdout_For_Test
           (Upload_Channel, Handle_Response & Write_Status & Close_Status);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP upload cleanup", "queue server replies");
         Status_Value := SSH_Lib.SFTP.Upload_Data
           (Upload_Channel, "/tmp/upload.txt", Bytes_From_String ("hello"), "0644");
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Remote_Failure, "SFTP upload cleanup", "write failure returned");
         Check
           (SSH_Lib.Channels.Test_Support.Outbound_Data_Packet_Count_For_Test
              (Upload_Channel) = 3,
            "SFTP upload cleanup closes the remote handle after write failure");
         Assert_SCP_Channel_Data
           (Upload_Channel, Expected_Close, "SFTP upload cleanup close request");
      end;

      declare
         Session_Item : SSH_Lib.Sessions.Session;
         Open_Status : CryptoLib.Errors.Status;
      begin
         SSH_Lib.Sessions.Test_Support.Mark_Authenticated_Open_For_Test (Session_Item);
         Open_Status := SSH_Lib.Sessions.Test_Support.Queue_Channel_Open_Response_For_Test
           (Session_Item, Build_Open_Confirmation (0, 900, 4096, 8192));
         SSH_Lib.Tests.Assertions.Check_Status
           (Open_Status, CryptoLib.Errors.Ok, "SFTP file upload preflight", "queue open response");
         Status_Value := SSH_Lib.SFTP.Upload_File
           (Session_Item, "/tmp/upload.txt", "missing-sftp-local-file.txt", "0644");
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value,
            CryptoLib.Errors.Read_Failed,
            "SFTP file upload preflight",
            "missing local file rejected before subsystem open");
         Check
           (SSH_Lib.Sessions.Test_Support.Active_Channel_Count_For_Test
              (Session_Item) = 0,
            "SFTP file upload preflight does not open a channel for missing local file");
      end;

      declare
         Upload_Channel : SSH_Lib.Channels.Channel;
         Local_Path : constant String :=
           SSH_Lib.Tests.Fixtures.Temp_Paths.Path ("sftp_upload_file.txt");
         Handle_Response : constant Ada.Streams.Stream_Element_Array :=
           Bytes_From_String
             (Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (10)
              & Character'Val (SSH_Lib.SFTP.SSH_FXP_HANDLE)
              & Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (1)
              & Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (1)
              & "h");
         Write_Status : constant Ada.Streams.Stream_Element_Array :=
           Bytes_From_String
             (Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (17)
              & Character'Val (SSH_Lib.SFTP.SSH_FXP_STATUS)
              & Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (2)
              & Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (SSH_Lib.SFTP.SSH_FX_OK)
              & Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (0)
              & Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (0));
         Close_Status : constant Ada.Streams.Stream_Element_Array :=
           Bytes_From_String
             (Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (17)
              & Character'Val (SSH_Lib.SFTP.SSH_FXP_STATUS)
              & Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (3)
              & Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (SSH_Lib.SFTP.SSH_FX_OK)
              & Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (0)
              & Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (0));
         Expected_Close : constant Ada.Streams.Stream_Element_Array :=
           Bytes_From_String
             (Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (10)
              & Character'Val (SSH_Lib.SFTP.SSH_FXP_CLOSE)
              & Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (3)
              & Character'Val (0) & Character'Val (0) & Character'Val (0) & Character'Val (1)
              & "h");
      begin
         Write_Test_File (Local_Path, Bytes_From_String ("local!"));
         SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
           (Upload_Channel, Local_Channel_Id => 0, Remote_Channel_Id => 1);
         Status_Value := SSH_Lib.Channels.Test_Support.Queue_Stdout_For_Test
           (Upload_Channel, Handle_Response & Write_Status & Close_Status);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP file upload", "queue server replies");
         Status_Value := SSH_Lib.SFTP.Upload_File
           (Upload_Channel, "/tmp/upload.txt", Local_Path, "0600");
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP file upload", "channel upload succeeds");
         Check
           (SSH_Lib.Channels.Test_Support.Outbound_Data_Packet_Count_For_Test
              (Upload_Channel) = 3,
            "SFTP file upload emits open, write, and close packets");
         Assert_SCP_Channel_Data
           (Upload_Channel, Expected_Close, "SFTP file upload close request");
         Remove_If_Exists (Local_Path);
      exception
         when others =>
            Remove_If_Exists (Local_Path);
            raise;
      end;

      declare
         Download_Channel : SSH_Lib.Channels.Channel;
         Downloaded       : SSH_Lib.Protocol.Buffers.Packet_Buffer;
         Handle_Response  : constant Ada.Streams.Stream_Element_Array :=
           SFTP_Handle_Packet (1, "h");
         Data_Response    : constant Ada.Streams.Stream_Element_Array :=
           SFTP_Data_Packet (2, "abc");
         EOF_Response     : constant Ada.Streams.Stream_Element_Array :=
           SFTP_Status_Packet (3, SSH_Lib.SFTP.SSH_FX_EOF);
         Close_Response   : constant Ada.Streams.Stream_Element_Array :=
           SFTP_Status_Packet (4);
      begin
         SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
           (Download_Channel, Local_Channel_Id => 0, Remote_Channel_Id => 1);
         Status_Value := SSH_Lib.Channels.Test_Support.Queue_Stdout_For_Test
           (Download_Channel, Handle_Response & Data_Response & EOF_Response & Close_Response);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP download", "queue server replies");
         Status_Value := SSH_Lib.SFTP.Download_Data
           (Download_Channel, "/tmp/download.txt", Downloaded);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP download", "channel download succeeds");
         SSH_Lib.Tests.Assertions.Check_Bytes
           (SSH_Lib.Protocol.Buffers.To_Array (Downloaded),
            Bytes_From_String ("abc"),
            "SFTP download",
            "downloaded bytes exact");
         Check
           (SSH_Lib.Channels.Test_Support.Outbound_Data_Packet_Count_For_Test
              (Download_Channel) = 3,
            "SFTP download emits open, read, and close packets");
      end;

      declare
         Stat_Channel : SSH_Lib.Channels.Channel;
         Attributes   : SSH_Lib.SFTP.File_Attributes;
      begin
         SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
           (Stat_Channel, Local_Channel_Id => 0, Remote_Channel_Id => 1);
         Status_Value := SSH_Lib.Channels.Test_Support.Queue_Stdout_For_Test
           (Stat_Channel, SFTP_Attrs_Packet (1, 42, 8#644#));
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP stat", "queue attrs reply");
         Status_Value := SSH_Lib.SFTP.Stat
           (Stat_Channel, "/tmp/file.txt", Attributes);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP stat", "stat succeeds");
         Check (Attributes.Size_Known and then Attributes.Size = 42,
                "SFTP stat parses size attribute");
         Check (Attributes.Permissions_Known and then Attributes.Permissions = 8#644#,
                "SFTP stat parses permissions attribute");
      end;

      declare
         Session_Item : SSH_Lib.Sessions.Session;
         Client_Item  : SSH_Lib.SFTP.Client;
         Attributes   : SSH_Lib.SFTP.File_Attributes;
         Open_Status  : CryptoLib.Errors.Status;
         Access_Out   : Ada.Calendar.Time;
         Modify_Out   : Ada.Calendar.Time;
      begin
         SSH_Lib.Sessions.Test_Support.Mark_Authenticated_Open_For_Test (Session_Item);
         Open_Status := SSH_Lib.Sessions.Test_Support.Queue_Channel_Open_Response_For_Test
           (Session_Item, Build_Open_Confirmation (0, 900, 4096, 8192));
         SSH_Lib.Tests.Assertions.Check_Status
           (Open_Status, CryptoLib.Errors.Ok, "SFTP v4 attrs", "queue open response");
         Open_Status := SSH_Lib.Sessions.Test_Support.Queue_Exec_Response_For_Test
           (Session_Item, Build_Exec_Success (0));
         SSH_Lib.Tests.Assertions.Check_Status
           (Open_Status, CryptoLib.Errors.Ok, "SFTP v4 attrs", "queue subsystem response");
         Open_Status := SSH_Lib.Sessions.Test_Support.Queue_Next_Channel_Stdout_For_Test
           (Session_Item,
            SFTP_Version_Packet (Interfaces.Unsigned_32'(4))
            & SFTP_V4_Attrs_Packet (1, 1, 77, 8#100600#));
         SSH_Lib.Tests.Assertions.Check_Status
           (Open_Status, CryptoLib.Errors.Ok, "SFTP v4 attrs", "queue version and stat reply");

         Status_Value := SSH_Lib.SFTP.Open (Session_Item, Client_Item);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP v4 attrs", "client opens at version 4");
         Status_Value := SSH_Lib.SFTP.Stat
           (Client_Item, "/tmp/v4-file", Attributes);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP v4 attrs", "stat parses version 4 attrs");
         Check (Attributes.Size_Known and then Attributes.Size = 77,
                "SFTP v4 attrs parses size");
         Check (Attributes.Permissions_Known and then Attributes.Permissions = 8#100600#,
                "SFTP v4 attrs parses shifted permissions flag");
         Check (SSH_Lib.SFTP.Access_Time_Value (Attributes, Access_Out)
                and then SSH_Lib.SFTP.Modify_Time_Value (Attributes, Modify_Out),
                "SFTP v4 attrs parses 64-bit timestamp fields");
      end;

      declare
         Session_Item : SSH_Lib.Sessions.Session;
         Client_Item  : SSH_Lib.SFTP.Client;
         Attributes   : SSH_Lib.SFTP.File_Attributes;
         Open_Status  : CryptoLib.Errors.Status;
      begin
         SSH_Lib.Sessions.Test_Support.Mark_Authenticated_Open_For_Test (Session_Item);
         Open_Status := SSH_Lib.Sessions.Test_Support.Queue_Channel_Open_Response_For_Test
           (Session_Item, Build_Open_Confirmation (0, 900, 4096, 8192));
         SSH_Lib.Tests.Assertions.Check_Status
           (Open_Status, CryptoLib.Errors.Ok, "SFTP rich attrs", "queue open response");
         Open_Status := SSH_Lib.Sessions.Test_Support.Queue_Exec_Response_For_Test
           (Session_Item, Build_Exec_Success (0));
         SSH_Lib.Tests.Assertions.Check_Status
           (Open_Status, CryptoLib.Errors.Ok, "SFTP rich attrs", "queue subsystem response");
         Open_Status := SSH_Lib.Sessions.Test_Support.Queue_Next_Channel_Stdout_For_Test
           (Session_Item, SFTP_Version_Packet (Interfaces.Unsigned_32'(6))
            & SFTP_V4_Rich_Attrs_Packet (1));
         SSH_Lib.Tests.Assertions.Check_Status
           (Open_Status, CryptoLib.Errors.Ok, "SFTP rich attrs", "queue attrs reply");
         Status_Value := SSH_Lib.SFTP.Open (Session_Item, Client_Item, 6);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP rich attrs", "client opens");
         Status_Value := SSH_Lib.SFTP.Stat (Client_Item, "/tmp/rich", Attributes);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP rich attrs", "stat parses rich attrs");
         Check (Attributes.Allocation_Size_Known and then Attributes.Allocation_Size = 456
                and then Attributes.Owner_Group_Known
                and then To_String (Attributes.Owner) = "alice"
                and then To_String (Attributes.Group) = "staff",
                "SFTP rich attrs parses allocation and owner/group");
         Check (Attributes.Create_Time_Known and then Attributes.Create_Time = 13
                and then Attributes.Create_Time_Nanoseconds = 14
                and then Attributes.ACL_Known and then To_String (Attributes.ACL) = "acl",
                "SFTP rich attrs parses create time and ACL");
         Check (Attributes.Attribute_Bits_Known and then Attributes.Attribute_Bits = 16#AA55#
                and then Attributes.Text_Hint_Known and then Natural (Attributes.Text_Hint) = 1
                and then Attributes.Mime_Type_Known
                and then To_String (Attributes.Mime_Type) = "text/plain"
                and then Attributes.Link_Count_Known and then Attributes.Link_Count = 2
                and then Attributes.Untranslated_Name_Known
                and then To_String (Attributes.Untranslated_Name) = "raw-name",
                "SFTP rich attrs parses v4-v6 extra fields");
      end;

      declare
         Session_Item : SSH_Lib.Sessions.Session;
         Client_Item  : SSH_Lib.SFTP.Client;
         Entries      : SSH_Lib.SFTP.Directory_Entry_Vectors.Vector;
         Open_Status  : CryptoLib.Errors.Status;
      begin
         SSH_Lib.Sessions.Test_Support.Mark_Authenticated_Open_For_Test (Session_Item);
         Open_Status := SSH_Lib.Sessions.Test_Support.Queue_Channel_Open_Response_For_Test
           (Session_Item, Build_Open_Confirmation (0, 900, 4096, 8192));
         SSH_Lib.Tests.Assertions.Check_Status
           (Open_Status, CryptoLib.Errors.Ok, "SFTP v6 name", "queue open response");
         Open_Status := SSH_Lib.Sessions.Test_Support.Queue_Exec_Response_For_Test
           (Session_Item, Build_Exec_Success (0));
         SSH_Lib.Tests.Assertions.Check_Status
           (Open_Status, CryptoLib.Errors.Ok, "SFTP v6 name", "queue subsystem response");
         Open_Status := SSH_Lib.Sessions.Test_Support.Queue_Next_Channel_Stdout_For_Test
           (Session_Item,
            SFTP_Version_Packet (Interfaces.Unsigned_32'(6))
            & SFTP_Handle_Packet (1, "d")
            & SFTP_V4_Name_Packet
                (2, "alpha.txt", 1, 14, 8#100640#, "logs", 2, 0, 8#040750#)
            & SFTP_Status_Packet (3, SSH_Lib.SFTP.SSH_FX_EOF)
            & SFTP_Status_Packet (4));
         SSH_Lib.Tests.Assertions.Check_Status
           (Open_Status, CryptoLib.Errors.Ok, "SFTP v6 name", "queue version and directory replies");

         Status_Value := SSH_Lib.SFTP.Open (Session_Item, Client_Item);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP v6 name", "client opens at version 6");
         Status_Value := SSH_Lib.SFTP.List_Directory
           (Client_Item, "/tmp", Entries);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP v6 name", "list parses version 6 names");
         Check (Natural (Entries.Length) = 2, "SFTP v6 name returns entries");
         Check (To_String (Entries (0).Name) = "alpha.txt"
                and then Length (Entries (0).Long_Name) = 0,
                "SFTP v6 name omits v3 longname field");
         Check (Entries (1).Attributes.Permissions_Known
                and then SSH_Lib.SFTP.Is_Directory (Entries (1).Attributes),
                "SFTP v6 name maps file type byte to directory metadata");
      end;

      declare
         Session_Item   : SSH_Lib.Sessions.Session;
         Client_Item    : SSH_Lib.SFTP.Client;
         Canonical_Path : Unbounded_String;
         Open_Status    : CryptoLib.Errors.Status;
      begin
         SSH_Lib.Sessions.Test_Support.Mark_Authenticated_Open_For_Test (Session_Item);
         Open_Status := SSH_Lib.Sessions.Test_Support.Queue_Channel_Open_Response_For_Test
           (Session_Item, Build_Open_Confirmation (0, 900, 4096, 8192));
         SSH_Lib.Tests.Assertions.Check_Status
           (Open_Status, CryptoLib.Errors.Ok, "SFTP v4 realpath", "queue open response");
         Open_Status := SSH_Lib.Sessions.Test_Support.Queue_Exec_Response_For_Test
           (Session_Item, Build_Exec_Success (0));
         SSH_Lib.Tests.Assertions.Check_Status
           (Open_Status, CryptoLib.Errors.Ok, "SFTP v4 realpath", "queue subsystem response");
         Open_Status := SSH_Lib.Sessions.Test_Support.Queue_Next_Channel_Stdout_For_Test
           (Session_Item,
            SFTP_Version_Packet (Interfaces.Unsigned_32'(4))
            & SFTP_V4_Name_Packet (1, "/srv/data/file", 1, 0, 8#100644#));
         SSH_Lib.Tests.Assertions.Check_Status
           (Open_Status, CryptoLib.Errors.Ok, "SFTP v4 realpath", "queue version and realpath reply");

         Status_Value := SSH_Lib.SFTP.Open (Session_Item, Client_Item);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP v4 realpath", "client opens at version 4");
         Status_Value := SSH_Lib.SFTP.Realpath
           (Client_Item, "data/../data/file", Canonical_Path);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP v4 realpath", "realpath parses version 4 name");
         Check (To_String (Canonical_Path) = "/srv/data/file",
                "SFTP v4 realpath returns canonical path");
      end;

      declare
         Permissions : Interfaces.Unsigned_32 := 0;
         Attributes  : SSH_Lib.SFTP.File_Attributes;
         Copy        : SSH_Lib.SFTP.File_Attributes;
         Access_In   : constant Ada.Calendar.Time :=
           Ada.Calendar.Time_Of (1970, 1, 1, 42.0);
         Modify_In   : constant Ada.Calendar.Time :=
           Ada.Calendar.Time_Of (1970, 1, 1, 99.0);
         Access_Out  : Ada.Calendar.Time;
         Modify_Out  : Ada.Calendar.Time;
         Value       : Unbounded_String;
      begin
         Check
           (SSH_Lib.SFTP.Mode_To_Permissions ("0644", Permissions)
            and then Permissions = 8#644#,
            "SFTP metadata converts mode string to permissions");
         Check
           (SSH_Lib.SFTP.Permissions_To_Mode (8#100755#) = "0755",
            "SFTP metadata converts permissions to mode string");

         Attributes.Permissions_Known := True;
         Attributes.Permissions := 8#100640#;
         Check (SSH_Lib.SFTP.Is_Regular_File (Attributes),
                "SFTP metadata detects regular file");
         Check (not SSH_Lib.SFTP.Is_Directory (Attributes),
                "SFTP metadata does not misclassify regular file");
         Check (SSH_Lib.SFTP.Permission_Bits (Attributes) = 8#640#,
                "SFTP metadata extracts permission bits");
         Check (SSH_Lib.SFTP.Owner_Can_Read (Attributes)
                and then SSH_Lib.SFTP.Owner_Can_Write (Attributes)
                and then SSH_Lib.SFTP.Group_Can_Read (Attributes)
                and then not SSH_Lib.SFTP.Group_Can_Write (Attributes)
                and then not SSH_Lib.SFTP.Other_Can_Read (Attributes)
                and then not SSH_Lib.SFTP.Other_Can_Execute (Attributes),
                "SFTP metadata maps individual permission bits");
         Check (SSH_Lib.SFTP.Set_Permissions_Mode (Attributes, "0755")
                and then SSH_Lib.SFTP.Is_Regular_File (Attributes)
                and then SSH_Lib.SFTP.Permission_Bits (Attributes) = 8#755#,
                "SFTP metadata sets mode while preserving file type");
         Attributes.Permissions := 8#040755#;
         Check (SSH_Lib.SFTP.Is_Directory (Attributes),
                "SFTP metadata detects directory");
         Attributes.Permissions := 8#120777#;
         Check (SSH_Lib.SFTP.Is_Symlink (Attributes),
                "SFTP metadata detects symlink");

         SSH_Lib.SFTP.Set_Times (Attributes, Access_In, Modify_In);
         Check
           (SSH_Lib.SFTP.Access_Time_Value (Attributes, Access_Out)
            and then SSH_Lib.SFTP.Modify_Time_Value (Attributes, Modify_Out)
            and then Access_Out = Access_In
            and then Modify_Out = Modify_In,
            "SFTP metadata round-trips Ada calendar times");

         Attributes.Size_Known := True;
         Attributes.Size := 123;
         SSH_Lib.SFTP.Set_UID_GID (Attributes, 1000, 1001);
         SSH_Lib.SFTP.Set_Extended_Attribute
           (Attributes, "copy@example", "yes");
         Check (SSH_Lib.SFTP.Extended_Attribute_Count (Attributes) = 1,
                "SFTP metadata counts extended attrs");
         Copy := SSH_Lib.SFTP.Copy_Metadata (Attributes);
         Check
           (not Copy.Size_Known
            and then not Copy.UID_GID_Known
            and then Copy.Permissions_Known
            and then Copy.Times_Known
            and then SSH_Lib.SFTP.Extended_Attribute_Value
              (Copy, "copy@example", Value)
            and then To_String (Value) = "yes",
            "SFTP metadata copy preserves safe metadata by default");
         Copy := SSH_Lib.SFTP.Copy_Metadata
           (Attributes, Include_Size => True, Include_UID_GID => True, Include_Extended => False);
         Check
           (Copy.Size_Known and then Copy.Size = 123
            and then Copy.UID_GID_Known
            and then Copy.UID = 1000
            and then Copy.GID = 1001
            and then not SSH_Lib.SFTP.Has_Extended_Attribute
              (Copy, "copy@example"),
            "SFTP metadata copy honors explicit include flags");
         SSH_Lib.SFTP.Clear_Extended_Attributes (Attributes);
         Check (SSH_Lib.SFTP.Extended_Attribute_Count (Attributes) = 0,
                "SFTP metadata clears extended attrs");
      end;

      declare
         List_Channel : SSH_Lib.Channels.Channel;
         Names        : Unbounded_String;
      begin
         SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
           (List_Channel, Local_Channel_Id => 0, Remote_Channel_Id => 1);
         Status_Value := SSH_Lib.Channels.Test_Support.Queue_Stdout_For_Test
           (List_Channel,
            SFTP_Handle_Packet (1, "d")
            & SFTP_Name_Packet (2, "one", "two")
            & SFTP_Status_Packet (3, SSH_Lib.SFTP.SSH_FX_EOF)
            & SFTP_Status_Packet (4));
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP list", "queue directory replies");
         Status_Value := SSH_Lib.SFTP.List_Directory
           (List_Channel, "/tmp", Names);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP list", "list succeeds");
         Check (To_String (Names) = "one" & Character'Val (10) & "two",
                "SFTP list returns newline-separated names");
      end;

      declare
         Detailed_List_Channel : SSH_Lib.Channels.Channel;
         Entries               : SSH_Lib.SFTP.Directory_Entry_Vectors.Vector;
      begin
         SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
           (Detailed_List_Channel, Local_Channel_Id => 0, Remote_Channel_Id => 1);
         Status_Value := SSH_Lib.Channels.Test_Support.Queue_Stdout_For_Test
           (Detailed_List_Channel,
            SFTP_Handle_Packet (1, "d")
            & SFTP_Detailed_Name_Packet (2)
            & SFTP_Status_Packet (3, SSH_Lib.SFTP.SSH_FX_EOF)
            & SFTP_Status_Packet (4));
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP detailed list", "queue directory replies");
         Status_Value := SSH_Lib.SFTP.List_Directory
           (Detailed_List_Channel, "/tmp", Entries);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP detailed list", "list succeeds");
         Check (Natural (Entries.Length) = 2,
                "SFTP detailed list returns two entries");
         Check (To_String (Entries (0).Name) = "alpha.txt",
                "SFTP detailed list preserves first name");
         Check (To_String (Entries (0).Long_Name) = "-rw-r----- alpha.txt",
                "SFTP detailed list preserves first longname");
         Check (Entries (0).Attributes.Size_Known
                and then Entries (0).Attributes.Size = 14,
                "SFTP detailed list preserves first size");
         Check (Entries (0).Attributes.Permissions_Known
                and then Entries (0).Attributes.Permissions = 8#640#,
                "SFTP detailed list preserves first permissions");
         Check (To_String (Entries (1).Name) = "logs",
                "SFTP detailed list preserves second name");
         Check (To_String (Entries (1).Long_Name) = "drwxr-x--- logs",
                "SFTP detailed list preserves second longname");
         Check (Entries (1).Attributes.Permissions_Known
                and then Entries (1).Attributes.Permissions = 8#750#,
                "SFTP detailed list preserves second permissions");
      end;

      declare
         Paged_List_Channel : SSH_Lib.Channels.Channel;
      begin
         Directory_Page_Calls := 0;
         Directory_Page_Entries := 0;
         Directory_Page_Names := Null_Unbounded_String;
         SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
           (Paged_List_Channel, Local_Channel_Id => 0, Remote_Channel_Id => 1);
         Status_Value := SSH_Lib.Channels.Test_Support.Queue_Stdout_For_Test
           (Paged_List_Channel,
            SFTP_Handle_Packet (1, "d")
            & SFTP_Name_Packet (2, "one")
            & SFTP_Name_Packet (3, "two")
            & SFTP_Status_Packet (4, SSH_Lib.SFTP.SSH_FX_EOF)
            & SFTP_Status_Packet (5));
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP paged list", "queue directory replies");
         Status_Value := SSH_Lib.SFTP.List_Directory_Paged
           (Paged_List_Channel, "/tmp", Capture_Directory_Page'Access);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP paged list", "paged list succeeds");
         Check (Directory_Page_Calls = 2,
                "SFTP paged list invokes callback once per page");
         Check (Directory_Page_Entries = 2,
                "SFTP paged list counts entries across pages");
         Check (To_String (Directory_Page_Names) = "one" & Character'Val (10) & "two",
                "SFTP paged list preserves page order");
         Check
           (SSH_Lib.Channels.Test_Support.Outbound_Data_Packet_Count_For_Test
              (Paged_List_Channel) = 5,
            "SFTP paged list emits open, reads, and close");
      end;

      declare
         Mutate_Channel : SSH_Lib.Channels.Channel;
      begin
         SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
           (Mutate_Channel, Local_Channel_Id => 0, Remote_Channel_Id => 1);
         Status_Value := SSH_Lib.Channels.Test_Support.Queue_Stdout_For_Test
           (Mutate_Channel, SFTP_Status_Packet (1));
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP mkdir", "queue status reply");
         Status_Value := SSH_Lib.SFTP.Make_Directory
           (Mutate_Channel, "/tmp/new-dir", "0755");
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP mkdir", "mkdir status succeeds");
      end;

      declare
         Link_Channel : SSH_Lib.Channels.Channel;
         Target_Path  : Unbounded_String;
      begin
         SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
           (Link_Channel, Local_Channel_Id => 0, Remote_Channel_Id => 1);
         Status_Value := SSH_Lib.Channels.Test_Support.Queue_Stdout_For_Test
           (Link_Channel, SFTP_Name_Packet (1, "../target"));
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP readlink", "queue name reply");
         Status_Value := SSH_Lib.SFTP.Read_Link
           (Link_Channel, "/tmp/link", Target_Path);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP readlink", "readlink succeeds");
         Check (To_String (Target_Path) = "../target",
                "SFTP readlink returns target path");
      end;

      declare
         Realpath_Channel : SSH_Lib.Channels.Channel;
         Canonical_Path   : Unbounded_String;
      begin
         SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
           (Realpath_Channel, Local_Channel_Id => 0, Remote_Channel_Id => 1);
         Status_Value := SSH_Lib.Channels.Test_Support.Queue_Stdout_For_Test
           (Realpath_Channel, SFTP_Name_Packet (1, "/srv/data/file"));
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP realpath", "queue name reply");
         Status_Value := SSH_Lib.SFTP.Realpath
           (Realpath_Channel, "data/../data/file", Canonical_Path);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP realpath", "realpath succeeds");
         Check (To_String (Canonical_Path) = "/srv/data/file",
                "SFTP realpath returns canonical path");
      end;

      declare
         Handle_Channel : SSH_Lib.Channels.Channel;
         Handle         : SSH_Lib.SFTP.File_Handle;
         Attributes     : SSH_Lib.SFTP.File_Attributes;
      begin
         SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
           (Handle_Channel, Local_Channel_Id => 0, Remote_Channel_Id => 1);
         Status_Value := SSH_Lib.Channels.Test_Support.Queue_Stdout_For_Test
           (Handle_Channel,
            SFTP_Handle_Packet (1, "h")
            & SFTP_Attrs_Packet (1, 11, 8#640#)
            & SFTP_Status_Packet (1));
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP handle fstat", "queue replies");
         Status_Value := SSH_Lib.SFTP.Open_Read
           (Handle_Channel, "/tmp/file", Handle);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP handle fstat", "open read succeeds");
         Check (SSH_Lib.SFTP.Is_Open (Handle), "SFTP handle is open after open-read");
         Status_Value := SSH_Lib.SFTP.FStat
           (Handle_Channel, Handle, Attributes);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP handle fstat", "fstat succeeds");
         Check (Attributes.Size_Known and then Attributes.Size = 11,
                "SFTP handle fstat parses size attribute");
         Check (Attributes.Permissions_Known and then Attributes.Permissions = 8#640#,
                "SFTP handle fstat parses permissions attribute");
         Status_Value := SSH_Lib.SFTP.Close (Handle_Channel, Handle);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP handle fstat", "close succeeds");
         Check (not SSH_Lib.SFTP.Is_Open (Handle), "SFTP handle is closed after close");
         Check
           (SSH_Lib.Channels.Test_Support.Outbound_Data_Packet_Count_For_Test
              (Handle_Channel) = 3,
            "SFTP handle fstat emits open, fstat, and close packets");
      end;

      declare
         Mode_Channel : SSH_Lib.Channels.Channel;
         Handle       : SSH_Lib.SFTP.File_Handle;
      begin
         SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
           (Mode_Channel, Local_Channel_Id => 0, Remote_Channel_Id => 1);
         Status_Value := SSH_Lib.Channels.Test_Support.Queue_Stdout_For_Test
           (Mode_Channel, SFTP_Handle_Packet (1, "a"));
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP open modes", "queue append handle");
         Status_Value := SSH_Lib.SFTP.Open_File
           (Mode_Channel, "/tmp/append", Handle, SSH_Lib.SFTP.Append, "0644");
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP open modes", "append open succeeds");
         Assert_SCP_Channel_Data
           (Mode_Channel,
            SFTP_Open_Request_Packet (1, "/tmp/append", 16#0000_000E#, 16#0000_0004#, 8#644#),
            "SFTP append open request");

         SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
           (Mode_Channel, Local_Channel_Id => 0, Remote_Channel_Id => 1);
         Status_Value := SSH_Lib.Channels.Test_Support.Queue_Stdout_For_Test
           (Mode_Channel, SFTP_Handle_Packet (1, "c"));
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP open modes", "queue create-new handle");
         Status_Value := SSH_Lib.SFTP.Open_File
           (Mode_Channel, "/tmp/new", Handle, SSH_Lib.SFTP.Create_New, "0600");
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP open modes", "create-new open succeeds");
         Assert_SCP_Channel_Data
           (Mode_Channel,
            SFTP_Open_Request_Packet (1, "/tmp/new", 16#0000_002A#, 16#0000_0004#, 8#600#),
            "SFTP create-new open request");

         SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
           (Mode_Channel, Local_Channel_Id => 0, Remote_Channel_Id => 1);
         Status_Value := SSH_Lib.Channels.Test_Support.Queue_Stdout_For_Test
           (Mode_Channel, SFTP_Handle_Packet (1, "r"));
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP open modes", "queue read-write handle");
         Status_Value := SSH_Lib.SFTP.Open_File
           (Mode_Channel, "/tmp/rw", Handle, SSH_Lib.SFTP.Read_Write);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP open modes", "read-write open succeeds");
         Assert_SCP_Channel_Data
           (Mode_Channel,
            SFTP_Open_Request_Packet (1, "/tmp/rw", 16#0000_0003#),
            "SFTP read-write open request");

         SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
           (Mode_Channel, Local_Channel_Id => 0, Remote_Channel_Id => 1);
         Status_Value := SSH_Lib.Channels.Test_Support.Queue_Stdout_For_Test
           (Mode_Channel, SFTP_Handle_Packet (1, "w"));
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP open modes", "queue no-truncate handle");
         Status_Value := SSH_Lib.SFTP.Open_File
           (Mode_Channel, "/tmp/write", Handle, SSH_Lib.SFTP.Write_No_Truncate, "0640");
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP open modes", "no-truncate open succeeds");
         Assert_SCP_Channel_Data
           (Mode_Channel,
            SFTP_Open_Request_Packet (1, "/tmp/write", 16#0000_000A#, 16#0000_0004#, 8#640#),
            "SFTP no-truncate open request");
      end;

      declare
         Mode_Channel : SSH_Lib.Channels.Channel;
         Handle       : SSH_Lib.SFTP.File_Handle;
      begin
         SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
           (Mode_Channel, Local_Channel_Id => 0, Remote_Channel_Id => 1);
         Status_Value := SSH_Lib.Channels.Test_Support.Queue_Stdout_For_Test
           (Mode_Channel, SFTP_Handle_Packet (1, "r"));
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP v4 open modes", "queue read handle");
         Status_Value := SSH_Lib.SFTP.Open_Read
           (Mode_Channel, "/tmp/read", Handle, 6);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP v4 open modes", "read open succeeds");
         Assert_SCP_Channel_Data
           (Mode_Channel,
            SFTP_Open4_Request_Packet
              (1, "/tmp/read", 16#0000_0001#, 16#0000_0002#),
            "SFTP v4 read open request");

         SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
           (Mode_Channel, Local_Channel_Id => 0, Remote_Channel_Id => 1);
         Status_Value := SSH_Lib.Channels.Test_Support.Queue_Stdout_For_Test
           (Mode_Channel, SFTP_Handle_Packet (1, "w"));
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP v4 open modes", "queue truncate handle");
         Status_Value := SSH_Lib.SFTP.Open_File
           (Mode_Channel, "/tmp/write", Handle, SSH_Lib.SFTP.Write_Truncate, "0600", 6);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP v4 open modes", "truncate open succeeds");
         Assert_SCP_Channel_Data
           (Mode_Channel,
            SFTP_Open4_Request_Packet
              (1, "/tmp/write", 16#0000_0102#, 16#0000_0001#,
               16#0000_0008#, 1, 8#100600#),
            "SFTP v4 truncate open request");
      end;

      declare
         Range_Channel : SSH_Lib.Channels.Channel;
         Handle        : SSH_Lib.SFTP.File_Handle;
         Chunk         : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      begin
         SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
           (Range_Channel, Local_Channel_Id => 0, Remote_Channel_Id => 1);
         Status_Value := SSH_Lib.Channels.Test_Support.Queue_Stdout_For_Test
           (Range_Channel,
            SFTP_Handle_Packet (1, "h")
            & SFTP_Data_Packet (1, "def")
            & SFTP_Status_Packet (1)
            & SFTP_Status_Packet (1));
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP ranged handle IO", "queue replies");
         Status_Value := SSH_Lib.SFTP.Open_File
           (Range_Channel, "/tmp/rw", Handle, SSH_Lib.SFTP.Read_Write);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP ranged handle IO", "open succeeds");
         Status_Value := SSH_Lib.SFTP.Read_At
           (Range_Channel, Handle, 3, 3, Chunk);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP ranged handle IO", "read-at succeeds");
         SSH_Lib.Tests.Assertions.Check_Bytes
           (SSH_Lib.Protocol.Buffers.To_Array (Chunk),
            Bytes_From_String ("def"),
            "SFTP ranged handle IO",
            "read-at bytes exact");
         Assert_SCP_Channel_Data
           (Range_Channel,
            SFTP_Read_Request_Packet (1, "h", 3, 3),
            "SFTP read-at request");
         Status_Value := SSH_Lib.SFTP.Write_At
           (Range_Channel, Handle, 6, Bytes_From_String ("ghi"));
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP ranged handle IO", "write-at succeeds");
         Assert_SCP_Channel_Data
           (Range_Channel,
            SFTP_Write_Request_Packet (1, "h", 6, "ghi"),
            "SFTP write-at request");
         Status_Value := SSH_Lib.SFTP.Close (Range_Channel, Handle);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP ranged handle IO", "close succeeds");
      end;

      declare
         Range_Download_Channel : SSH_Lib.Channels.Channel;
         Downloaded             : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      begin
         SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
           (Range_Download_Channel, Local_Channel_Id => 0, Remote_Channel_Id => 1);
         Status_Value := SSH_Lib.Channels.Test_Support.Queue_Stdout_For_Test
           (Range_Download_Channel,
            SFTP_Handle_Packet (1, "d")
            & SFTP_Data_Packet (2, "abc")
            & SFTP_Status_Packet (3));
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP ranged download", "queue replies");
         Status_Value := SSH_Lib.SFTP.Download_Data
           (Range_Download_Channel,
            "/tmp/file",
            10,
            3,
            Downloaded,
            (Pipeline_Depth => 1, others => <>));
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP ranged download", "download succeeds");
         SSH_Lib.Tests.Assertions.Check_Bytes
           (SSH_Lib.Protocol.Buffers.To_Array (Downloaded),
            Bytes_From_String ("abc"),
            "SFTP ranged download",
            "downloaded range exact");
         Check
           (SSH_Lib.Channels.Test_Support.Outbound_Data_Packet_Count_For_Test
              (Range_Download_Channel) = 3,
            "SFTP ranged download emits open, read, and close packets");
      end;

      declare
         Range_Upload_Channel : SSH_Lib.Channels.Channel;
      begin
         SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
           (Range_Upload_Channel, Local_Channel_Id => 0, Remote_Channel_Id => 1);
         Status_Value := SSH_Lib.Channels.Test_Support.Queue_Stdout_For_Test
           (Range_Upload_Channel,
            SFTP_Handle_Packet (1, "u")
            & SFTP_Status_Packet (2)
            & SFTP_Status_Packet (3));
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP ranged upload", "queue replies");
         Status_Value := SSH_Lib.SFTP.Upload_Data
           (Range_Upload_Channel,
            "/tmp/file",
            5,
            Bytes_From_String ("abc"),
            "0644",
            (Pipeline_Depth => 1, others => <>));
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP ranged upload", "upload succeeds");
         Check
           (SSH_Lib.Channels.Test_Support.Outbound_Data_Packet_Count_For_Test
              (Range_Upload_Channel) = 3,
            "SFTP ranged upload emits open, write, and close packets");
      end;

      declare
         FSet_Channel : SSH_Lib.Channels.Channel;
         Handle       : SSH_Lib.SFTP.File_Handle;
      begin
         SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
           (FSet_Channel, Local_Channel_Id => 0, Remote_Channel_Id => 1);
         Status_Value := SSH_Lib.Channels.Test_Support.Queue_Stdout_For_Test
           (FSet_Channel,
            SFTP_Handle_Packet (1, "w")
            & SFTP_Status_Packet (1)
            & SFTP_Status_Packet (1));
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP handle fsetstat", "queue replies");
         Status_Value := SSH_Lib.SFTP.Open_Write
           (FSet_Channel, "/tmp/file", Handle, "0600");
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP handle fsetstat", "open write succeeds");
         Status_Value := SSH_Lib.SFTP.Set_Handle_Permissions
           (FSet_Channel, Handle, "0644");
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP handle fsetstat", "fsetstat succeeds");
         Status_Value := SSH_Lib.SFTP.Close (FSet_Channel, Handle);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP handle fsetstat", "close succeeds");
         Check
           (SSH_Lib.Channels.Test_Support.Outbound_Data_Packet_Count_For_Test
              (FSet_Channel) = 3,
            "SFTP handle fsetstat emits open, fsetstat, and close packets");
      end;

      declare
         Download_Channel : SSH_Lib.Channels.Channel;
         Local_Path       : constant String :=
           SSH_Lib.Tests.Fixtures.Temp_Paths.Path ("sftp_download_file.txt");
         Temp_Path        : constant String :=
           Local_Path & ".ada-ssh-sftp-download.tmp";
      begin
         Remove_If_Exists (Local_Path);
         Remove_If_Exists (Temp_Path);
         Write_Test_File (Local_Path, Bytes_From_String ("old"));
         SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
           (Download_Channel, Local_Channel_Id => 0, Remote_Channel_Id => 1);
         Status_Value := SSH_Lib.Channels.Test_Support.Queue_Stdout_For_Test
           (Download_Channel,
            SFTP_Handle_Packet (1, "h")
            & SFTP_Data_Packet (2, "xy")
            & SFTP_Data_Packet (3, "z")
            & SFTP_Status_Packet (4, SSH_Lib.SFTP.SSH_FX_EOF)
            & SFTP_Status_Packet (5));
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP download file", "queue replies");
         Status_Value := SSH_Lib.SFTP.Download_File
           (Download_Channel, "/tmp/download.txt", Local_Path);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP download file", "download succeeds");
         SSH_Lib.Tests.Assertions.Check_Bytes
           (Read_Test_File (Local_Path),
            Bytes_From_String ("xyz"),
            "SFTP download file",
            "local file bytes exact");
         Check (not Ada.Directories.Exists (Temp_Path),
                "SFTP download file removes temporary file after success");
         Remove_If_Exists (Local_Path);
         Remove_If_Exists (Temp_Path);
      exception
         when others =>
            Remove_If_Exists (Local_Path);
            Remove_If_Exists (Temp_Path);
            raise;
      end;

      declare
         Download_Channel : SSH_Lib.Channels.Channel;
         Local_Path       : constant String :=
           SSH_Lib.Tests.Fixtures.Temp_Paths.Path ("sftp_download_file_failure.txt");
         Temp_Path        : constant String :=
           Local_Path & ".ada-ssh-sftp-download.tmp";
      begin
         Remove_If_Exists (Local_Path);
         Remove_If_Exists (Temp_Path);
         Write_Test_File (Local_Path, Bytes_From_String ("old"));
         SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
           (Download_Channel, Local_Channel_Id => 0, Remote_Channel_Id => 1);
         Status_Value := SSH_Lib.Channels.Test_Support.Queue_Stdout_For_Test
           (Download_Channel,
            SFTP_Handle_Packet (1, "h")
            & SFTP_Data_Packet (2, "partial")
            & SFTP_Status_Packet (3, SSH_Lib.SFTP.SSH_FX_FAILURE)
            & SFTP_Status_Packet (4));
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP download file failure", "queue replies");
         Status_Value := SSH_Lib.SFTP.Download_File
           (Download_Channel, "/tmp/download.txt", Local_Path);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Remote_Failure,
            "SFTP download file failure", "remote failure returned");
         SSH_Lib.Tests.Assertions.Check_Bytes
           (Read_Test_File (Local_Path),
            Bytes_From_String ("old"),
            "SFTP download file failure",
            "existing local file remains exact");
         Check (not Ada.Directories.Exists (Temp_Path),
                "SFTP download file failure removes temporary file");
         Remove_If_Exists (Local_Path);
         Remove_If_Exists (Temp_Path);
      exception
         when others =>
            Remove_If_Exists (Local_Path);
            Remove_If_Exists (Temp_Path);
            raise;
      end;

      declare
         Stream_Download_Channel : SSH_Lib.Channels.Channel;
      begin
         SSH_Lib.Protocol.Buffers.Clear (Stream_Download_Buffer);
         SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
           (Stream_Download_Channel, Local_Channel_Id => 0, Remote_Channel_Id => 1);
         Status_Value := SSH_Lib.Channels.Test_Support.Queue_Stdout_For_Test
           (Stream_Download_Channel,
            SFTP_Attrs_Packet (1, 3, 8#100644#)
            & SFTP_Handle_Packet (1, "h")
            & SFTP_Data_Packet (2, "ab")
            & SFTP_Data_Packet (3, "c")
            & SFTP_Status_Packet (4));
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP stream download", "queue replies");
         Status_Value := SSH_Lib.SFTP.Download_Stream
           (Stream_Download_Channel,
            "/tmp/stream.txt",
            Capture_Stream_Chunk'Access);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP stream download", "download succeeds");
         SSH_Lib.Tests.Assertions.Check_Bytes
           (SSH_Lib.Protocol.Buffers.To_Array (Stream_Download_Buffer),
            Bytes_From_String ("abc"),
            "SFTP stream download",
            "writer receives chunks in order");
         Check
           (SSH_Lib.Channels.Test_Support.Outbound_Data_Packet_Count_For_Test
              (Stream_Download_Channel) = 5,
            "SFTP stream download emits stat, open, reads, and close");
      end;

      declare
         Stream_Upload_Channel : SSH_Lib.Channels.Channel;
      begin
         SSH_Lib.Protocol.Buffers.Clear (Stream_Upload_Source);
         Status_Value := SSH_Lib.Protocol.Buffers.Set
           (Stream_Upload_Source, Bytes_From_String ("abcd"));
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP stream upload", "set source bytes");
         Stream_Upload_Limit := 2;
         SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
           (Stream_Upload_Channel, Local_Channel_Id => 0, Remote_Channel_Id => 1);
         Status_Value := SSH_Lib.Channels.Test_Support.Queue_Stdout_For_Test
           (Stream_Upload_Channel,
            SFTP_Handle_Packet (1, "h")
            & SFTP_Status_Packet (2)
            & SFTP_Status_Packet (3)
            & SFTP_Status_Packet (4));
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP stream upload", "queue replies");
         Status_Value := SSH_Lib.SFTP.Upload_Stream
           (Stream_Upload_Channel,
            "/tmp/stream.txt",
            4,
            Provide_Stream_Chunk'Access,
            "0644");
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP stream upload", "upload succeeds");
         Check
           (SSH_Lib.Channels.Test_Support.Outbound_Data_Packet_Count_For_Test
              (Stream_Upload_Channel) = 4,
            "SFTP stream upload emits open, two writes, and close");
         Stream_Upload_Limit := 0;
      end;

      declare
         Resume_Download_Channel : SSH_Lib.Channels.Channel;
         Local_Path              : constant String :=
           SSH_Lib.Tests.Fixtures.Temp_Paths.Path ("sftp_resume_download.txt");
      begin
         Remove_If_Exists (Local_Path);
         Write_Test_File (Local_Path, Bytes_From_String ("hel"));
         SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
           (Resume_Download_Channel, Local_Channel_Id => 0, Remote_Channel_Id => 1);
         Status_Value := SSH_Lib.Channels.Test_Support.Queue_Stdout_For_Test
           (Resume_Download_Channel,
            SFTP_Attrs_Packet (1, 5, 8#100644#)
            & SFTP_Handle_Packet (1, "h")
            & SFTP_Data_Packet (2, "lo")
            & SFTP_Status_Packet (3));
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP resume download", "queue replies");
         Status_Value := SSH_Lib.SFTP.Resume_Download_File
           (Resume_Download_Channel, "/tmp/resume.txt", Local_Path);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP resume download", "resume succeeds");
         SSH_Lib.Tests.Assertions.Check_Bytes
           (Read_Test_File (Local_Path),
            Bytes_From_String ("hello"),
            "SFTP resume download",
            "resume appends missing suffix");
         Check
           (SSH_Lib.Channels.Test_Support.Outbound_Data_Packet_Count_For_Test
              (Resume_Download_Channel) = 3,
            "SFTP resume download emits stat, read, and close");
         Remove_If_Exists (Local_Path);
      exception
         when others =>
            Remove_If_Exists (Local_Path);
            raise;
      end;

      declare
         Resume_Upload_Channel : SSH_Lib.Channels.Channel;
         Local_Path            : constant String :=
           SSH_Lib.Tests.Fixtures.Temp_Paths.Path ("sftp_resume_upload.txt");
      begin
         Remove_If_Exists (Local_Path);
         Write_Test_File (Local_Path, Bytes_From_String ("hello"));
         SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
           (Resume_Upload_Channel, Local_Channel_Id => 0, Remote_Channel_Id => 1);
         Status_Value := SSH_Lib.Channels.Test_Support.Queue_Stdout_For_Test
           (Resume_Upload_Channel,
            SFTP_Attrs_Packet (1, 2, 8#100644#)
            & SFTP_Handle_Packet (1, "h")
            & SFTP_Status_Packet (2)
            & SFTP_Status_Packet (3));
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP resume upload", "queue replies");
         Status_Value := SSH_Lib.SFTP.Resume_Upload_File
           (Resume_Upload_Channel, "/tmp/resume.txt", Local_Path, "0644");
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP resume upload", "resume succeeds");
         Check
           (SSH_Lib.Channels.Test_Support.Outbound_Data_Packet_Count_For_Test
              (Resume_Upload_Channel) = 4,
            "SFTP resume upload emits stat, open, write, and close");
         Remove_If_Exists (Local_Path);
      exception
         when others =>
            Remove_If_Exists (Local_Path);
            raise;
      end;

      declare
         LStat_Channel : SSH_Lib.Channels.Channel;
         Attributes    : SSH_Lib.SFTP.File_Attributes;
      begin
         SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
           (LStat_Channel, Local_Channel_Id => 0, Remote_Channel_Id => 1);
         Status_Value := SSH_Lib.Channels.Test_Support.Queue_Stdout_For_Test
           (LStat_Channel, SFTP_Attrs_Packet (1, 7, 8#600#));
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP lstat", "queue attrs reply");
         Status_Value := SSH_Lib.SFTP.LStat
           (LStat_Channel, "/tmp/link", Attributes);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP lstat", "lstat succeeds");
         Check (Attributes.Size_Known and then Attributes.Size = 7,
                "SFTP lstat parses size attribute");
         Check (Attributes.Permissions_Known and then Attributes.Permissions = 8#600#,
                "SFTP lstat parses permissions attribute");
      end;

      declare
         Chmod_Channel : SSH_Lib.Channels.Channel;
      begin
         SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
           (Chmod_Channel, Local_Channel_Id => 0, Remote_Channel_Id => 1);
         Status_Value := SSH_Lib.Channels.Test_Support.Queue_Stdout_For_Test
           (Chmod_Channel, SFTP_Status_Packet (1));
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP chmod", "queue status reply");
         Status_Value := SSH_Lib.SFTP.Set_Permissions
           (Chmod_Channel, "/tmp/file", "0600");
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP chmod", "chmod succeeds");
         Check
           (SSH_Lib.Channels.Test_Support.Outbound_Data_Packet_Count_For_Test
              (Chmod_Channel) = 1,
            "SFTP chmod emits one request");
      end;

      declare
         Attr_Channel : SSH_Lib.Channels.Channel;
         Attributes   : constant SSH_Lib.SFTP.File_Attributes :=
           (Size_Known        => True,
            Size              => 123,
            UID_GID_Known     => True,
            UID               => 1000,
            GID               => 1001,
            Permissions_Known => True,
            Permissions       => 8#640#,
            Times_Known       => True,
            Access_Time       => 11,
            Modify_Time       => 12,
            Extended_Attributes => <>,
            others => <>);
      begin
         SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
           (Attr_Channel, Local_Channel_Id => 0, Remote_Channel_Id => 1);
         Status_Value := SSH_Lib.Channels.Test_Support.Queue_Stdout_For_Test
           (Attr_Channel, SFTP_Status_Packet (1));
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP setattrs", "queue status reply");
         Status_Value := SSH_Lib.SFTP.Set_Attributes
           (Attr_Channel, "/tmp/file", Attributes);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP setattrs", "setattrs succeeds");
         Check
           (SSH_Lib.Channels.Test_Support.Outbound_Data_Packet_Count_For_Test
              (Attr_Channel) = 1,
            "SFTP setattrs emits one request");
      end;

      declare
         Handle_Attr_Channel : SSH_Lib.Channels.Channel;
         Handle              : SSH_Lib.SFTP.File_Handle;
         Attributes          : constant SSH_Lib.SFTP.File_Attributes :=
           (Size_Known        => True,
            Size              => 321,
            UID_GID_Known     => False,
            UID               => 0,
            GID               => 0,
            Permissions_Known => True,
            Permissions       => 8#600#,
            Times_Known       => True,
            Access_Time       => 21,
            Modify_Time       => 22,
            Extended_Attributes => <>,
            others => <>);
      begin
         SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
           (Handle_Attr_Channel, Local_Channel_Id => 0, Remote_Channel_Id => 1);
         Status_Value := SSH_Lib.Channels.Test_Support.Queue_Stdout_For_Test
           (Handle_Attr_Channel,
            SFTP_Handle_Packet (1, "a")
            & SFTP_Status_Packet (1)
            & SFTP_Status_Packet (1));
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP handle setattrs", "queue replies");
         Status_Value := SSH_Lib.SFTP.Open_Write
           (Handle_Attr_Channel, "/tmp/file", Handle, "0600");
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP handle setattrs", "open write succeeds");
         Status_Value := SSH_Lib.SFTP.Set_Handle_Attributes
           (Handle_Attr_Channel, Handle, Attributes);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP handle setattrs", "fsetattrs succeeds");
         Status_Value := SSH_Lib.SFTP.Close (Handle_Attr_Channel, Handle);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP handle setattrs", "close succeeds");
         Check
           (SSH_Lib.Channels.Test_Support.Outbound_Data_Packet_Count_For_Test
              (Handle_Attr_Channel) = 3,
            "SFTP handle setattrs emits open, fsetattrs, and close packets");
      end;

      declare
         No_Such_Channel     : SSH_Lib.Channels.Channel;
         Permission_Channel  : SSH_Lib.Channels.Channel;
         Unsupported_Channel : SSH_Lib.Channels.Channel;
      begin
         SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
           (No_Such_Channel, Local_Channel_Id => 0, Remote_Channel_Id => 1);
         Status_Value := SSH_Lib.Channels.Test_Support.Queue_Stdout_For_Test
           (No_Such_Channel,
            SFTP_Status_Packet (1, SSH_Lib.SFTP.SSH_FX_NO_SUCH_FILE));
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP status mapping", "queue no-such reply");
         Status_Value := SSH_Lib.SFTP.Remove_File
           (No_Such_Channel, "/tmp/missing");
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.No_Such_File,
            "SFTP status mapping", "no-such-file mapped");

         SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
           (Permission_Channel, Local_Channel_Id => 0, Remote_Channel_Id => 1);
         Status_Value := SSH_Lib.Channels.Test_Support.Queue_Stdout_For_Test
           (Permission_Channel,
            SFTP_Status_Packet (1, SSH_Lib.SFTP.SSH_FX_PERMISSION_DENIED));
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP status mapping", "queue permission reply");
         Status_Value := SSH_Lib.SFTP.Set_Permissions
           (Permission_Channel, "/tmp/file", "0600");
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Permission_Denied,
            "SFTP status mapping", "permission-denied mapped");

         SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
           (Unsupported_Channel, Local_Channel_Id => 0, Remote_Channel_Id => 1);
         Status_Value := SSH_Lib.Channels.Test_Support.Queue_Stdout_For_Test
           (Unsupported_Channel,
            SFTP_Status_Packet (1, SSH_Lib.SFTP.SSH_FX_OP_UNSUPPORTED));
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP status mapping", "queue unsupported reply");
         Status_Value := SSH_Lib.SFTP.Rename
           (Unsupported_Channel, "/tmp/a", "/tmp/b");
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Unsupported_Feature,
            "SFTP status mapping", "unsupported mapped");
      end;

      declare
         No_Path_Channel      : SSH_Lib.Channels.Channel;
         Invalid_Channel      : SSH_Lib.Channels.Channel;
         Lock_Conflict_Channel : SSH_Lib.Channels.Channel;
      begin
         SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
           (No_Path_Channel, Local_Channel_Id => 0, Remote_Channel_Id => 1);
         Status_Value := SSH_Lib.Channels.Test_Support.Queue_Stdout_For_Test
           (No_Path_Channel,
            SFTP_Status_Packet (1, SSH_Lib.SFTP.SSH_FX_NO_SUCH_PATH));
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP v4 status mapping",
            "queue no-such-path reply");
         Status_Value := SSH_Lib.SFTP.Remove_File
           (No_Path_Channel, "/tmp/missing");
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.No_Such_File,
            "SFTP v4 status mapping", "no-such-path mapped");

         SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
           (Invalid_Channel, Local_Channel_Id => 0, Remote_Channel_Id => 1);
         Status_Value := SSH_Lib.Channels.Test_Support.Queue_Stdout_For_Test
           (Invalid_Channel,
            SFTP_Status_Packet (1, SSH_Lib.SFTP.SSH_FX_INVALID_PARAMETER));
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP v4 status mapping",
            "queue invalid-parameter reply");
         Status_Value := SSH_Lib.SFTP.Remove_File
           (Invalid_Channel, "/tmp/file");
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Invalid_Command,
            "SFTP v4 status mapping", "invalid-parameter mapped");

         SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
           (Lock_Conflict_Channel, Local_Channel_Id => 0, Remote_Channel_Id => 1);
         Status_Value := SSH_Lib.Channels.Test_Support.Queue_Stdout_For_Test
           (Lock_Conflict_Channel,
            SFTP_Status_Packet
              (1, SSH_Lib.SFTP.SSH_FX_BYTE_RANGE_LOCK_REFUSED));
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP v4 status mapping",
            "queue lock-refused reply");
         declare
            Result : SSH_Lib.SFTP.SFTP_Result;
         begin
            Status_Value := SSH_Lib.SFTP.Remove_File
              (Lock_Conflict_Channel, "/tmp/file", Result);
            SSH_Lib.Tests.Assertions.Check_Status
              (Status_Value, CryptoLib.Errors.Remote_Failure,
               "SFTP v4 status mapping", "lock-refused mapped");
            Check
              (SSH_Lib.SFTP.SFTP_Operation'Pos (Result.Operation) =
                 SSH_Lib.SFTP.SFTP_Operation'Pos (SSH_Lib.SFTP.Remove_Operation)
               and then Result.Status = CryptoLib.Errors.Remote_Failure
               and then Result.Remote_Status_Code =
                 SSH_Lib.SFTP.SSH_FX_BYTE_RANGE_LOCK_REFUSED
               and then To_String (Result.Remote_Status_Name) =
                 "SSH_FX_BYTE_RANGE_LOCK_REFUSED",
               "SFTP typed remove result is operation-local");
         end;
         Check
           (SSH_Lib.SFTP.Last_Remote_Status_Code =
              SSH_Lib.SFTP.SSH_FX_BYTE_RANGE_LOCK_REFUSED
            and then SSH_Lib.SFTP.Last_Remote_Status_Name =
              "SSH_FX_BYTE_RANGE_LOCK_REFUSED",
            "SFTP v4 status mapping exposes exact remote status");
         declare
            Result : constant SSH_Lib.SFTP.SFTP_Result :=
              SSH_Lib.SFTP.Last_Result;
         begin
            Check
              (Result.Status = CryptoLib.Errors.Remote_Failure
               and then SSH_Lib.SFTP.SFTP_Operation'Pos (Result.Operation) =
                 SSH_Lib.SFTP.SFTP_Operation'Pos (SSH_Lib.SFTP.Unknown_Operation)
               and then Result.Remote_Status_Code =
                 SSH_Lib.SFTP.SSH_FX_BYTE_RANGE_LOCK_REFUSED
               and then To_String (Result.Remote_Status_Name) =
                 "SSH_FX_BYTE_RANGE_LOCK_REFUSED",
               "SFTP v4 status mapping exposes typed result details");
         end;

         declare
            Rename_Channel : SSH_Lib.Channels.Channel;
            Result         : SSH_Lib.SFTP.SFTP_Result;
         begin
            SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
              (Rename_Channel, Local_Channel_Id => 0, Remote_Channel_Id => 1);
            Status_Value := SSH_Lib.Channels.Test_Support.Queue_Stdout_For_Test
              (Rename_Channel,
               SFTP_Status_Packet
                 (1, SSH_Lib.SFTP.SSH_FX_FILE_ALREADY_EXISTS));
            SSH_Lib.Tests.Assertions.Check_Status
              (Status_Value, CryptoLib.Errors.Ok, "SFTP typed result",
               "queue rename conflict");
            Status_Value := SSH_Lib.SFTP.Rename
              (Rename_Channel, "/tmp/old", "/tmp/new", Result);
            SSH_Lib.Tests.Assertions.Check_Status
              (Status_Value, CryptoLib.Errors.Invalid_Command,
               "SFTP typed result", "rename result status");
            Check
              (SSH_Lib.SFTP.SFTP_Operation'Pos (Result.Operation) =
                 SSH_Lib.SFTP.SFTP_Operation'Pos
                   (SSH_Lib.SFTP.Rename_Operation)
               and then Result.Remote_Status_Code =
                 SSH_Lib.SFTP.SSH_FX_FILE_ALREADY_EXISTS,
               "SFTP typed rename result is operation-local");
         end;

         declare
            Limits_Channel : SSH_Lib.Channels.Channel;
            Values         : SSH_Lib.SFTP.Server_Limits;
            Result         : SSH_Lib.SFTP.SFTP_Result;
         begin
            SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
              (Limits_Channel, Local_Channel_Id => 0, Remote_Channel_Id => 1);
            Status_Value := SSH_Lib.Channels.Test_Support.Queue_Stdout_For_Test
              (Limits_Channel, SFTP_Limits_Packet (1));
            SSH_Lib.Tests.Assertions.Check_Status
              (Status_Value, CryptoLib.Errors.Ok, "SFTP typed result",
               "queue limits reply");
            Status_Value := SSH_Lib.SFTP.Limits
              (Limits_Channel, Values, Result);
            SSH_Lib.Tests.Assertions.Check_Status
              (Status_Value, CryptoLib.Errors.Ok,
               "SFTP typed result", "limits result status");
            Check
              (SSH_Lib.SFTP.SFTP_Operation'Pos (Result.Operation) =
                 SSH_Lib.SFTP.SFTP_Operation'Pos
                   (SSH_Lib.SFTP.Limits_Operation)
               and then Values.Max_Write_Length = 65536,
               "SFTP typed limits result is operation-local");
         end;
      end;

      declare
         Remove_File_Channel : SSH_Lib.Channels.Channel;
         Remove_Dir_Channel  : SSH_Lib.Channels.Channel;
         Rename_Channel      : SSH_Lib.Channels.Channel;
         Symlink_Channel     : SSH_Lib.Channels.Channel;
      begin
         SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
           (Remove_File_Channel, Local_Channel_Id => 0, Remote_Channel_Id => 1);
         Status_Value := SSH_Lib.Channels.Test_Support.Queue_Stdout_For_Test
           (Remove_File_Channel, SFTP_Status_Packet (1));
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP remove file", "queue status reply");
         Status_Value := SSH_Lib.SFTP.Remove_File
           (Remove_File_Channel, "/tmp/file");
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP remove file", "remove succeeds");

         SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
           (Remove_Dir_Channel, Local_Channel_Id => 0, Remote_Channel_Id => 1);
         Status_Value := SSH_Lib.Channels.Test_Support.Queue_Stdout_For_Test
           (Remove_Dir_Channel, SFTP_Status_Packet (1));
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP remove dir", "queue status reply");
         Status_Value := SSH_Lib.SFTP.Remove_Directory
           (Remove_Dir_Channel, "/tmp/dir");
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP remove dir", "remove succeeds");

         SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
           (Rename_Channel, Local_Channel_Id => 0, Remote_Channel_Id => 1);
         Status_Value := SSH_Lib.Channels.Test_Support.Queue_Stdout_For_Test
           (Rename_Channel, SFTP_Status_Packet (1));
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP rename", "queue status reply");
         Status_Value := SSH_Lib.SFTP.Rename
           (Rename_Channel, "/tmp/old", "/tmp/new");
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP rename", "rename succeeds");

         SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
           (Symlink_Channel, Local_Channel_Id => 0, Remote_Channel_Id => 1);
         Status_Value := SSH_Lib.Channels.Test_Support.Queue_Stdout_For_Test
           (Symlink_Channel, SFTP_Status_Packet (1));
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP symlink", "queue status reply");
         Status_Value := SSH_Lib.SFTP.Create_Symlink
           (Symlink_Channel, "../target", "/tmp/link");
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP symlink", "symlink succeeds");
      end;

      declare
         Upload_Dir_Channel : SSH_Lib.Channels.Channel;
         Local_Dir          : constant String :=
           SSH_Lib.Tests.Fixtures.Temp_Paths.Path ("sftp_upload_tree");
         Local_File         : constant String :=
           Ada.Directories.Compose (Local_Dir, "file.txt");
      begin
         Remove_Local_Tree_If_Exists (Local_Dir);
         Ada.Directories.Create_Path (Local_Dir);
         Write_Test_File (Local_File, Bytes_From_String ("tree"));
         SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
           (Upload_Dir_Channel, Local_Channel_Id => 0, Remote_Channel_Id => 1);
         Status_Value := SSH_Lib.Channels.Test_Support.Queue_Stdout_For_Test
           (Upload_Dir_Channel,
            SFTP_Status_Packet (1)
            & SFTP_Handle_Packet (1, "u")
            & SFTP_Status_Packet (2)
            & SFTP_Status_Packet (3));
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP recursive upload", "queue replies");
         Status_Value := SSH_Lib.SFTP.Upload_Directory
           (Upload_Dir_Channel, "/tmp/tree", Local_Dir, "0755", "0644");
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP recursive upload", "upload directory succeeds");
         Check
           (SSH_Lib.Channels.Test_Support.Outbound_Data_Packet_Count_For_Test
              (Upload_Dir_Channel) = 4,
            "SFTP recursive upload emits mkdir, open, write, and close");
         Remove_Local_Tree_If_Exists (Local_Dir);
      exception
         when others =>
            Remove_Local_Tree_If_Exists (Local_Dir);
            raise;
      end;

      declare
         Filter_Channel : SSH_Lib.Channels.Channel;
         Local_Dir      : constant String :=
           SSH_Lib.Tests.Fixtures.Temp_Paths.Path ("sftp_filter_tree");
         Local_File     : constant String :=
           Ada.Directories.Compose (Local_Dir, "skipped.txt");
         Options        : constant SSH_Lib.SFTP.Recursive_Options :=
           (Preserve_Attributes => False,
            Filter              => Include_Directories_Only'Access,
            Progress            => Count_Recursive_Progress'Access,
            others              => <>);
      begin
         Recursive_Filter_Calls := 0;
         Recursive_Progress_Calls := 0;
         Remove_Local_Tree_If_Exists (Local_Dir);
         Ada.Directories.Create_Path (Local_Dir);
         Write_Test_File (Local_File, Bytes_From_String ("skip"));
         SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
           (Filter_Channel, Local_Channel_Id => 0, Remote_Channel_Id => 1);
         Status_Value := SSH_Lib.Channels.Test_Support.Queue_Stdout_For_Test
           (Filter_Channel, SFTP_Status_Packet (1));
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP recursive options", "queue filtered mkdir");
         Status_Value := SSH_Lib.SFTP.Upload_Directory
           (Filter_Channel, "/tmp/filter", Local_Dir, "0755", "0644", Options);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP recursive options", "filtered upload succeeds");
         Check
           (SSH_Lib.Channels.Test_Support.Outbound_Data_Packet_Count_For_Test
              (Filter_Channel) = 1,
            "SFTP recursive options skips filtered file upload");
         Check (Recursive_Filter_Calls >= 2, "SFTP recursive options invokes filter");
         Check (Recursive_Progress_Calls >= 1, "SFTP recursive options invokes progress");
         Remove_Local_Tree_If_Exists (Local_Dir);
      exception
         when others =>
            Remove_Local_Tree_If_Exists (Local_Dir);
            raise;
      end;

      declare
         No_Overwrite_Channel : SSH_Lib.Channels.Channel;
         Local_Dir            : constant String :=
           SSH_Lib.Tests.Fixtures.Temp_Paths.Path ("sftp_no_overwrite_tree");
         Local_File           : constant String :=
           Ada.Directories.Compose (Local_Dir, "file.txt");
         Options              : constant SSH_Lib.SFTP.Recursive_Options :=
           (Overwrite_Files => False, others => <>);
      begin
         Remove_Local_Tree_If_Exists (Local_Dir);
         Ada.Directories.Create_Path (Local_Dir);
         Write_Test_File (Local_File, Bytes_From_String ("new"));
         SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
           (No_Overwrite_Channel, Local_Channel_Id => 0, Remote_Channel_Id => 1);
         Status_Value := SSH_Lib.Channels.Test_Support.Queue_Stdout_For_Test
           (No_Overwrite_Channel,
            SFTP_Status_Packet (1)
            & SFTP_Attrs_Packet (1, 3, 8#100644#));
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP recursive overwrite policy", "queue existing target");
         Status_Value := SSH_Lib.SFTP.Upload_Directory
           (No_Overwrite_Channel, "/tmp/tree", Local_Dir, "0755", "0644", Options);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Remote_Failure,
            "SFTP recursive overwrite policy", "existing target rejected");
         Check
           (SSH_Lib.Channels.Test_Support.Outbound_Data_Packet_Count_For_Test
              (No_Overwrite_Channel) = 2,
            "SFTP recursive overwrite policy does not upload existing file");
         Remove_Local_Tree_If_Exists (Local_Dir);
      exception
         when others =>
            Remove_Local_Tree_If_Exists (Local_Dir);
            raise;
      end;

      declare
         Continue_Channel : SSH_Lib.Channels.Channel;
         Local_Dir        : constant String :=
           SSH_Lib.Tests.Fixtures.Temp_Paths.Path ("sftp_continue_tree");
         Local_File       : constant String :=
           Ada.Directories.Compose (Local_Dir, "file.txt");
         Options          : constant SSH_Lib.SFTP.Recursive_Options :=
           (Continue_On_Error => True,
            Overwrite_Files   => False,
            others            => <>);
      begin
         Remove_Local_Tree_If_Exists (Local_Dir);
         Ada.Directories.Create_Path (Local_Dir);
         Write_Test_File (Local_File, Bytes_From_String ("new"));
         SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
           (Continue_Channel, Local_Channel_Id => 0, Remote_Channel_Id => 1);
         Status_Value := SSH_Lib.Channels.Test_Support.Queue_Stdout_For_Test
           (Continue_Channel,
            SFTP_Status_Packet (1)
            & SFTP_Attrs_Packet (1, 3, 8#100644#));
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP recursive continue policy", "queue existing target");
         Status_Value := SSH_Lib.SFTP.Upload_Directory
           (Continue_Channel, "/tmp/tree", Local_Dir, "0755", "0644", Options);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok,
            "SFTP recursive continue policy", "existing target skipped under continue");
         Check
           (SSH_Lib.Channels.Test_Support.Outbound_Data_Packet_Count_For_Test
              (Continue_Channel) = 2,
            "SFTP recursive continue policy does not upload existing file");
         Remove_Local_Tree_If_Exists (Local_Dir);
      exception
         when others =>
            Remove_Local_Tree_If_Exists (Local_Dir);
            raise;
      end;

      declare
         Skip_Channel : SSH_Lib.Channels.Channel;
         Local_Dir    : constant String :=
           SSH_Lib.Tests.Fixtures.Temp_Paths.Path ("sftp_skip_tree");
         Local_File   : constant String :=
           Ada.Directories.Compose (Local_Dir, "file.txt");
         Options      : constant SSH_Lib.SFTP.Recursive_Options :=
           (Skip_Unchanged => True, others => <>);
      begin
         Remove_Local_Tree_If_Exists (Local_Dir);
         Ada.Directories.Create_Path (Local_Dir);
         Write_Test_File (Local_File, Bytes_From_String ("new"));
         SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
           (Skip_Channel, Local_Channel_Id => 0, Remote_Channel_Id => 1);
         Status_Value := SSH_Lib.Channels.Test_Support.Queue_Stdout_For_Test
           (Skip_Channel,
            SFTP_Status_Packet (1)
            & SFTP_Attrs_Packet (1, 3, 8#100644#));
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP recursive skip", "queue unchanged target");
         Status_Value := SSH_Lib.SFTP.Upload_Directory
           (Skip_Channel, "/tmp/tree", Local_Dir, "0755", "0644", Options);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok,
            "SFTP recursive skip", "unchanged upload target skipped");
         Check
           (SSH_Lib.Channels.Test_Support.Outbound_Data_Packet_Count_For_Test
              (Skip_Channel) = 2,
            "SFTP recursive skip avoids uploading unchanged file");
         Remove_Local_Tree_If_Exists (Local_Dir);
      exception
         when others =>
            Remove_Local_Tree_If_Exists (Local_Dir);
            raise;
      end;

      declare
         Download_Dir_Channel : SSH_Lib.Channels.Channel;
         Local_Dir            : constant String :=
           SSH_Lib.Tests.Fixtures.Temp_Paths.Path ("sftp_download_tree");
         Local_File           : constant String :=
           Ada.Directories.Compose (Local_Dir, "file.txt");
      begin
         Remove_Local_Tree_If_Exists (Local_Dir);
         SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
           (Download_Dir_Channel, Local_Channel_Id => 0, Remote_Channel_Id => 1);
         Status_Value := SSH_Lib.Channels.Test_Support.Queue_Stdout_For_Test
           (Download_Dir_Channel,
            SFTP_Handle_Packet (1, "d")
            & SFTP_Typed_Name_Packet (2, "file.txt", 8#100644#)
            & SFTP_Status_Packet (3, SSH_Lib.SFTP.SSH_FX_EOF)
            & SFTP_Status_Packet (4)
            & SFTP_Handle_Packet (1, "f")
            & SFTP_Data_Packet (2, "tree")
            & SFTP_Status_Packet (3, SSH_Lib.SFTP.SSH_FX_EOF)
            & SFTP_Status_Packet (4));
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP recursive download", "queue replies");
         Status_Value := SSH_Lib.SFTP.Download_Directory
           (Download_Dir_Channel, "/tmp/tree", Local_Dir);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP recursive download", "download directory succeeds");
         SSH_Lib.Tests.Assertions.Check_Bytes
           (Read_Test_File (Local_File),
            Bytes_From_String ("tree"),
            "SFTP recursive download",
            "downloaded file bytes exact");
         Remove_Local_Tree_If_Exists (Local_Dir);
      exception
         when others =>
            Remove_Local_Tree_If_Exists (Local_Dir);
            raise;
      end;

      declare
         Download_Skip_Channel : SSH_Lib.Channels.Channel;
         Local_Dir             : constant String :=
           SSH_Lib.Tests.Fixtures.Temp_Paths.Path ("sftp_download_skip_tree");
         Local_File            : constant String :=
           Ada.Directories.Compose (Local_Dir, "alpha.txt");
         Options               : constant SSH_Lib.SFTP.Recursive_Options :=
           (Skip_Unchanged => True, others => <>);
      begin
         Remove_Local_Tree_If_Exists (Local_Dir);
         Ada.Directories.Create_Path (Local_Dir);
         Write_Test_File (Local_File, Bytes_From_String ("same-size-data"));
         SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
           (Download_Skip_Channel, Local_Channel_Id => 0, Remote_Channel_Id => 1);
         Status_Value := SSH_Lib.Channels.Test_Support.Queue_Stdout_For_Test
           (Download_Skip_Channel,
            SFTP_Handle_Packet (1, "d")
            & SFTP_Detailed_Name_Packet (2)
            & SFTP_Status_Packet (3, SSH_Lib.SFTP.SSH_FX_EOF)
            & SFTP_Status_Packet (4));
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP recursive download skip", "queue directory only");
         Status_Value := SSH_Lib.SFTP.Download_Directory
           (Download_Skip_Channel, "/tmp/tree", Local_Dir, Options);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok,
            "SFTP recursive download skip", "unchanged download target skipped");
         Check
           (SSH_Lib.Channels.Test_Support.Outbound_Data_Packet_Count_For_Test
              (Download_Skip_Channel) = 4,
            "SFTP recursive download skip avoids file download");
         Remove_Local_Tree_If_Exists (Local_Dir);
      exception
         when others =>
            Remove_Local_Tree_If_Exists (Local_Dir);
            raise;
      end;

      declare
         Remove_Tree_Channel : SSH_Lib.Channels.Channel;
      begin
         SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
           (Remove_Tree_Channel, Local_Channel_Id => 0, Remote_Channel_Id => 1);
         Status_Value := SSH_Lib.Channels.Test_Support.Queue_Stdout_For_Test
           (Remove_Tree_Channel,
            SFTP_Attrs_Packet (1, 0, 8#040755#)
            & SFTP_Handle_Packet (1, "r")
            & SFTP_Typed_Name_Packet (2, "file.txt", 8#100644#, "sub", 8#040755#)
            & SFTP_Status_Packet (3, SSH_Lib.SFTP.SSH_FX_EOF)
            & SFTP_Status_Packet (4)
            & SFTP_Attrs_Packet (1, 4, 8#100644#)
            & SFTP_Status_Packet (1)
            & SFTP_Attrs_Packet (1, 0, 8#040755#)
            & SFTP_Handle_Packet (1, "s")
            & SFTP_Status_Packet (2, SSH_Lib.SFTP.SSH_FX_EOF)
            & SFTP_Status_Packet (3)
            & SFTP_Status_Packet (1)
            & SFTP_Status_Packet (1));
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP recursive remove", "queue replies");
         Status_Value := SSH_Lib.SFTP.Remove_Tree
           (Remove_Tree_Channel, "/tmp/tree");
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP recursive remove", "remove tree succeeds");
      end;

      declare
         Copy_Tree_Channel : SSH_Lib.Channels.Channel;
      begin
         SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
           (Copy_Tree_Channel, Local_Channel_Id => 0, Remote_Channel_Id => 1);
         Status_Value := SSH_Lib.Channels.Test_Support.Queue_Stdout_For_Test
           (Copy_Tree_Channel,
            SFTP_Attrs_Packet (1, 4, 8#100644#)
            & SFTP_Handle_Packet (1, "c")
            & SFTP_Data_Packet (2, "copy")
            & SFTP_Status_Packet (3, SSH_Lib.SFTP.SSH_FX_EOF)
            & SFTP_Status_Packet (4)
            & SFTP_Handle_Packet (1, "o")
            & SFTP_Status_Packet (2)
            & SFTP_Status_Packet (3));
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP recursive copy", "queue replies");
         Status_Value := SSH_Lib.SFTP.Copy_Tree
           (Copy_Tree_Channel, "/tmp/source", "/tmp/target", "0755", "0644");
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP recursive copy", "copy tree file succeeds");
      end;

      declare
         Preserve_Copy_Channel : SSH_Lib.Channels.Channel;
         Options               : constant SSH_Lib.SFTP.Recursive_Options :=
           (Preserve_Attributes => True,
            Filter              => Include_All_Recursive'Access,
            Progress            => Count_Recursive_Progress'Access,
            others              => <>);
      begin
         Recursive_Filter_Calls := 0;
         Recursive_Progress_Calls := 0;
         SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
           (Preserve_Copy_Channel, Local_Channel_Id => 0, Remote_Channel_Id => 1);
         Status_Value := SSH_Lib.Channels.Test_Support.Queue_Stdout_For_Test
           (Preserve_Copy_Channel,
            SFTP_Attrs_Packet (1, 4, 8#100640#)
            & SFTP_Handle_Packet (1, "p")
            & SFTP_Data_Packet (2, "copy")
            & SFTP_Status_Packet (3, SSH_Lib.SFTP.SSH_FX_EOF)
            & SFTP_Status_Packet (4)
            & SFTP_Handle_Packet (1, "q")
            & SFTP_Status_Packet (2)
            & SFTP_Status_Packet (3)
            & SFTP_Status_Packet (1));
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP recursive preserve", "queue replies");
         Status_Value := SSH_Lib.SFTP.Copy_Tree
           (Preserve_Copy_Channel, "/tmp/source", "/tmp/target", "0755", "0644", Options);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP recursive preserve", "copy preserves attributes");
         Check (Recursive_Filter_Calls >= 1, "SFTP recursive preserve invokes filter");
         Check (Recursive_Progress_Calls >= 1, "SFTP recursive preserve invokes progress");
      end;

      declare
         Posix_Channel : SSH_Lib.Channels.Channel;
      begin
         SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
           (Posix_Channel, Local_Channel_Id => 0, Remote_Channel_Id => 1);
         Status_Value := SSH_Lib.Channels.Test_Support.Queue_Stdout_For_Test
           (Posix_Channel, SFTP_Status_Packet (1));
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP posix rename", "queue status reply");
         Status_Value := SSH_Lib.SFTP.Posix_Rename
           (Posix_Channel, "/tmp/old", "/tmp/new");
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP posix rename", "posix rename succeeds");
         Assert_SCP_Channel_Data
           (Posix_Channel,
            SFTP_Extended_Two_Path_Request
              (SSH_Lib.SFTP.Posix_Rename_Extension, "/tmp/old", "/tmp/new"),
            "SFTP posix rename request");
      end;

      declare
         Hardlink_Channel : SSH_Lib.Channels.Channel;
         Result           : SSH_Lib.SFTP.SFTP_Result;
      begin
         SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
           (Hardlink_Channel, Local_Channel_Id => 0, Remote_Channel_Id => 1);
         Status_Value := SSH_Lib.Channels.Test_Support.Queue_Stdout_For_Test
           (Hardlink_Channel, SFTP_Status_Packet (1));
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP hardlink", "queue status reply");
         Status_Value := SSH_Lib.SFTP.Hardlink
           (Hardlink_Channel, "/tmp/existing", "/tmp/link", Result);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP hardlink", "hardlink succeeds");
         Check
           (SSH_Lib.SFTP.SFTP_Operation'Pos (Result.Operation) =
              SSH_Lib.SFTP.SFTP_Operation'Pos
                (SSH_Lib.SFTP.Link_Operation),
            "SFTP hardlink result operation tag");
         Assert_SCP_Channel_Data
           (Hardlink_Channel,
            SFTP_Extended_Two_Path_Request
              (SSH_Lib.SFTP.Hardlink_Extension, "/tmp/existing", "/tmp/link"),
            "SFTP hardlink request");
      end;

      declare
         Link_Channel : SSH_Lib.Channels.Channel;
      begin
         SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
           (Link_Channel, Local_Channel_Id => 0, Remote_Channel_Id => 1);
         Status_Value := SSH_Lib.Channels.Test_Support.Queue_Stdout_For_Test
           (Link_Channel, SFTP_Status_Packet (1));
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP native link", "queue status reply");
         Status_Value := SSH_Lib.SFTP.Create_Link
           (Link_Channel, "/tmp/new", "/tmp/existing", Symbolic => False);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP native link", "link succeeds");
         Assert_SCP_Channel_Data
           (Link_Channel,
            SFTP_Link_Request ("/tmp/new", "/tmp/existing", False),
            "SFTP native link request");
      end;

      declare
         Block_Channel : SSH_Lib.Channels.Channel;
         Handle        : SSH_Lib.SFTP.File_Handle;
      begin
         SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
           (Block_Channel, Local_Channel_Id => 0, Remote_Channel_Id => 1);
         Status_Value := SSH_Lib.Channels.Test_Support.Queue_Stdout_For_Test
           (Block_Channel,
            SFTP_Handle_Packet (1, "h")
            & SFTP_Status_Packet (1)
            & SFTP_Status_Packet (1)
            & SFTP_Status_Packet (1));
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP range operations", "queue replies");
         Status_Value := SSH_Lib.SFTP.Open_File
           (Block_Channel, "/tmp/file", Handle, SSH_Lib.SFTP.Read_Write, "0644", 6);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP range operations", "open succeeds");
         Status_Value := SSH_Lib.SFTP.Lock_Range (Block_Channel, Handle, 2, 5, 16#0000_0001#);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP range operations", "lock succeeds");
         Assert_SCP_Channel_Data
           (Block_Channel,
            SFTP_Block_Request (SSH_Lib.SFTP.SSH_FXP_BLOCK, "h", 2, 5, 16#0000_0001#),
            "SFTP block request");
         Status_Value := SSH_Lib.SFTP.Unlock_Range (Block_Channel, Handle, 2, 5);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP range operations", "unlock succeeds");
         Assert_SCP_Channel_Data
           (Block_Channel,
            SFTP_Block_Request (SSH_Lib.SFTP.SSH_FXP_UNBLOCK, "h", 2, 5),
            "SFTP unblock request");
         Status_Value := SSH_Lib.SFTP.Text_Seek (Block_Channel, Handle, 7);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP range operations", "text-seek succeeds");
         Assert_SCP_Channel_Data
           (Block_Channel, SFTP_Text_Seek_Request ("h", 7), "SFTP text-seek request");
      end;

      declare
         Fsync_Channel : SSH_Lib.Channels.Channel;
         Handle        : SSH_Lib.SFTP.File_Handle;
         Result        : SSH_Lib.SFTP.SFTP_Result;
      begin
         SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
           (Fsync_Channel, Local_Channel_Id => 0, Remote_Channel_Id => 1);
         Status_Value := SSH_Lib.Channels.Test_Support.Queue_Stdout_For_Test
           (Fsync_Channel, SFTP_Handle_Packet (1, "h") & SFTP_Status_Packet (1));
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP fsync", "queue replies");
         Status_Value := SSH_Lib.SFTP.Open_Write
           (Fsync_Channel, "/tmp/file", Handle, "0644");
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP fsync", "open succeeds");
         Status_Value := SSH_Lib.SFTP.Fsync (Fsync_Channel, Handle, Result);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP fsync", "fsync succeeds");
         Check
           (SSH_Lib.SFTP.SFTP_Operation'Pos (Result.Operation) =
              SSH_Lib.SFTP.SFTP_Operation'Pos
                (SSH_Lib.SFTP.Extended_Operation),
            "SFTP fsync result operation tag");
         Assert_SCP_Channel_Data
           (Fsync_Channel,
            SFTP_Extended_Handle_Request (SSH_Lib.SFTP.Fsync_Extension, "h"),
            "SFTP fsync request");
      end;

      declare
         Copy_Data_Channel : SSH_Lib.Channels.Channel;
         Source_Handle     : SSH_Lib.SFTP.File_Handle;
         Target_Handle     : SSH_Lib.SFTP.File_Handle;
         Result            : SSH_Lib.SFTP.SFTP_Result;
      begin
         SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
           (Copy_Data_Channel, Local_Channel_Id => 0, Remote_Channel_Id => 1);
         Status_Value := SSH_Lib.Channels.Test_Support.Queue_Stdout_For_Test
           (Copy_Data_Channel,
            SFTP_Handle_Packet (1, "s")
            & SFTP_Handle_Packet (1, "t")
            & SFTP_Status_Packet (1));
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP copy-data", "queue replies");
         Status_Value := SSH_Lib.SFTP.Open_Read
           (Copy_Data_Channel, "/tmp/source", Source_Handle);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP copy-data", "open source");
         Status_Value := SSH_Lib.SFTP.Open_File
           (Copy_Data_Channel, "/tmp/target", Target_Handle,
            SSH_Lib.SFTP.Write_No_Truncate);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP copy-data", "open target");
         Status_Value := SSH_Lib.SFTP.Copy_Data
           (Copy_Data_Channel, Source_Handle, 2, 5, Target_Handle, 7, Result);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP copy-data", "copy succeeds");
         Check
           (SSH_Lib.SFTP.SFTP_Operation'Pos (Result.Operation) =
              SSH_Lib.SFTP.SFTP_Operation'Pos
                (SSH_Lib.SFTP.Extended_Operation),
            "SFTP copy-data result operation tag");
         Assert_SCP_Channel_Data
           (Copy_Data_Channel,
            SFTP_Extended_Copy_Data_Request ("s", 2, 5, "t", 7),
            "SFTP copy-data request");
      end;

      declare
         Check_Channel : SSH_Lib.Channels.Channel;
         Handle        : SSH_Lib.SFTP.File_Handle;
         Algorithm     : Unbounded_String;
         Digest        : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      begin
         SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
           (Check_Channel, Local_Channel_Id => 0, Remote_Channel_Id => 1);
         Status_Value := SSH_Lib.Channels.Test_Support.Queue_Stdout_For_Test
           (Check_Channel,
            SFTP_Handle_Packet (1, "h")
            & SFTP_Extended_Reply_Packet
                (1,
                 SFTP_String (SSH_Lib.SFTP.Check_File_Extension)
                 & SFTP_String ("sha1")
                 & SFTP_String ("digest")));
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP check-file", "queue replies");
         Status_Value := SSH_Lib.SFTP.Open_Read
           (Check_Channel, "/tmp/file", Handle);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP check-file", "open succeeds");
         Status_Value := SSH_Lib.SFTP.Check_File
           (Check_Channel, Handle, "sha1", 2, 5, 0, Algorithm, Digest);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP check-file", "check succeeds");
         Check (To_String (Algorithm) = "sha1",
                "SFTP check-file parses selected algorithm");
         SSH_Lib.Tests.Assertions.Check_Bytes
           (SSH_Lib.Protocol.Buffers.To_Array (Digest),
            Bytes_From_String ("digest"),
            "SFTP check-file",
            "digest bytes exact");
         declare
            Info_Channel : SSH_Lib.Channels.Channel;
            Info_Handle  : SSH_Lib.SFTP.File_Handle;
            Info         : SSH_Lib.SFTP.Check_File_Result;
         begin
            SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
              (Info_Channel, Local_Channel_Id => 0, Remote_Channel_Id => 1);
            Status_Value := SSH_Lib.Channels.Test_Support.Queue_Stdout_For_Test
              (Info_Channel,
               SFTP_Handle_Packet (1, "h")
               & SFTP_Extended_Reply_Packet
                   (1,
                    SFTP_String (SSH_Lib.SFTP.Check_File_Extension)
                    & SFTP_String ("sha1")
                    & SFTP_String ("digest")));
            SSH_Lib.Tests.Assertions.Check_Status
              (Status_Value, CryptoLib.Errors.Ok,
               "SFTP check-file info", "queue replies");
            Status_Value := SSH_Lib.SFTP.Open_Read
              (Info_Channel, "/tmp/file", Info_Handle);
            SSH_Lib.Tests.Assertions.Check_Status
              (Status_Value, CryptoLib.Errors.Ok,
               "SFTP check-file info", "open succeeds");
            Info := SSH_Lib.SFTP.Check_File_Info
              (Info_Channel, Info_Handle, "sha1", 2, 5, 0);
            SSH_Lib.Tests.Assertions.Check_Status
              (Info.Result.Status, CryptoLib.Errors.Ok,
               "SFTP check-file info", "result status");
            Check
              (SSH_Lib.SFTP.SFTP_Operation'Pos (Info.Result.Operation) =
                 SSH_Lib.SFTP.SFTP_Operation'Pos
                   (SSH_Lib.SFTP.Check_File_Operation)
               and then To_String (Info.Algorithm) = "sha1",
               "SFTP check-file info bundles operation and algorithm");
            SSH_Lib.Tests.Assertions.Check_Bytes
              (SSH_Lib.Protocol.Buffers.To_Array (Info.Digest),
               Bytes_From_String ("digest"),
               "SFTP check-file info",
               "digest bytes exact");
         end;
         Assert_SCP_Channel_Data
           (Check_Channel,
            SFTP_Extended_Check_File_Request ("h", "sha1", 2, 5, 0),
            "SFTP check-file request");
      end;

      declare
         LSet_Channel : SSH_Lib.Channels.Channel;
         Result       : SSH_Lib.SFTP.SFTP_Result;
         Attributes   : constant SSH_Lib.SFTP.File_Attributes :=
           (Size_Known        => False,
            Size              => 0,
            UID_GID_Known     => False,
            UID               => 0,
            GID               => 0,
            Permissions_Known => True,
            Permissions       => 8#640#,
            Times_Known       => False,
            Access_Time       => 0,
            Modify_Time       => 0,
            Extended_Attributes => <>,
            others => <>);
      begin
         SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
           (LSet_Channel, Local_Channel_Id => 0, Remote_Channel_Id => 1);
         Status_Value := SSH_Lib.Channels.Test_Support.Queue_Stdout_For_Test
           (LSet_Channel, SFTP_Status_Packet (1));
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP lsetstat", "queue status reply");
         Status_Value := SSH_Lib.SFTP.LSet_Attributes
           (LSet_Channel, "/tmp/link", Attributes, Result);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP lsetstat", "lsetstat succeeds");
         Check
           (SSH_Lib.SFTP.SFTP_Operation'Pos (Result.Operation) =
              SSH_Lib.SFTP.SFTP_Operation'Pos
                (SSH_Lib.SFTP.Set_Attributes_Operation),
            "SFTP lsetstat result operation tag");
         Assert_SCP_Channel_Data
           (LSet_Channel,
            SFTP_Extended_Setattrs_Request
              (SSH_Lib.SFTP.LSetStat_Extension, "/tmp/link", 8#640#),
            "SFTP lsetstat request");
      end;

      declare
         StatVFS_Channel : SSH_Lib.Channels.Channel;
         Stats           : SSH_Lib.SFTP.File_System_Stats;
      begin
         SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
           (StatVFS_Channel, Local_Channel_Id => 0, Remote_Channel_Id => 1);
         Status_Value := SSH_Lib.Channels.Test_Support.Queue_Stdout_For_Test
           (StatVFS_Channel, SFTP_StatVFS_Packet (1));
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP statvfs", "queue extended reply");
         Status_Value := SSH_Lib.SFTP.StatVFS
           (StatVFS_Channel, "/tmp", Stats);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP statvfs", "statvfs succeeds");
         Check (Stats.Block_Size = 4096 and then Stats.Blocks = 1000,
                "SFTP statvfs parses block fields");
         Check (Stats.File_System_Id = 12345 and then Stats.Maximum_Name_Length = 255,
                "SFTP statvfs parses tail fields");
         declare
            Info_Channel : SSH_Lib.Channels.Channel;
            Info         : SSH_Lib.SFTP.StatVFS_Result;
         begin
            SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
              (Info_Channel, Local_Channel_Id => 0, Remote_Channel_Id => 1);
            Status_Value := SSH_Lib.Channels.Test_Support.Queue_Stdout_For_Test
              (Info_Channel, SFTP_StatVFS_Packet (1));
            SSH_Lib.Tests.Assertions.Check_Status
              (Status_Value, CryptoLib.Errors.Ok,
               "SFTP statvfs info", "queue extended reply");
            Info := SSH_Lib.SFTP.StatVFS_Info (Info_Channel, "/tmp");
            SSH_Lib.Tests.Assertions.Check_Status
              (Info.Result.Status, CryptoLib.Errors.Ok,
               "SFTP statvfs info", "result status");
            Check
              (SSH_Lib.SFTP.SFTP_Operation'Pos (Info.Result.Operation) =
                 SSH_Lib.SFTP.SFTP_Operation'Pos
                   (SSH_Lib.SFTP.StatVFS_Operation)
               and then Info.Stats.Block_Size = 4096,
               "SFTP statvfs info bundles operation and stats");
         end;
         Assert_SCP_Channel_Data
           (StatVFS_Channel,
            SFTP_Extended_Path_Request (SSH_Lib.SFTP.StatVFS_Extension, "/tmp"),
            "SFTP statvfs request");
      end;

      declare
         Expand_Channel : SSH_Lib.Channels.Channel;
         Expanded_Path  : Unbounded_String;
         Result         : SSH_Lib.SFTP.SFTP_Result;
      begin
         SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
           (Expand_Channel, Local_Channel_Id => 0, Remote_Channel_Id => 1);
         Status_Value := SSH_Lib.Channels.Test_Support.Queue_Stdout_For_Test
           (Expand_Channel, SFTP_Name_Packet (1, "/home/test/file"));
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP expand-path", "queue name reply");
         Status_Value := SSH_Lib.SFTP.Expand_Path
           (Expand_Channel, "~/file", Expanded_Path, Result);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP expand-path", "expand succeeds");
         Check
           (SSH_Lib.SFTP.SFTP_Operation'Pos (Result.Operation) =
              SSH_Lib.SFTP.SFTP_Operation'Pos
                (SSH_Lib.SFTP.Extended_Operation),
            "SFTP expand-path result operation tag");
         Check (To_String (Expanded_Path) = "/home/test/file",
                "SFTP expand-path parses expanded path");
         Assert_SCP_Channel_Data
           (Expand_Channel,
            SFTP_Extended_Path_Request (SSH_Lib.SFTP.Expand_Path_Extension, "~/file"),
            "SFTP expand-path request");
      end;

      declare
         Generic_Ext_Channel : SSH_Lib.Channels.Channel;
         Reply_Data          : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      begin
         SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
           (Generic_Ext_Channel, Local_Channel_Id => 0, Remote_Channel_Id => 1);
         Status_Value := SSH_Lib.Channels.Test_Support.Queue_Stdout_For_Test
           (Generic_Ext_Channel,
            SFTP_Extended_Reply_Packet (1, Bytes_From_String ("reply")));
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP generic extension", "queue extended reply");
         Status_Value := SSH_Lib.SFTP.Extended_Request
           (Generic_Ext_Channel,
            "custom@example.test",
            Bytes_From_String ("payload"),
            Reply_Data);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP generic extension", "request succeeds");
         SSH_Lib.Tests.Assertions.Check_Bytes
           (SSH_Lib.Protocol.Buffers.To_Array (Reply_Data),
            Bytes_From_String ("reply"),
            "SFTP generic extension",
            "raw reply payload exact");
         Assert_SCP_Channel_Data
           (Generic_Ext_Channel,
            SFTP_Extended_Raw_Request
              ("custom@example.test", Bytes_From_String ("payload")),
            "SFTP generic extension request");
      end;

      declare
         Generic_Info_Channel : SSH_Lib.Channels.Channel;
         Info                 : SSH_Lib.SFTP.Extended_Request_Result;
      begin
         SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
           (Generic_Info_Channel, Local_Channel_Id => 0, Remote_Channel_Id => 1);
         Status_Value := SSH_Lib.Channels.Test_Support.Queue_Stdout_For_Test
           (Generic_Info_Channel,
            SFTP_Extended_Reply_Packet (1, Bytes_From_String ("typed-reply")));
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok,
            "SFTP generic extension info", "queue extended reply");
         Info := SSH_Lib.SFTP.Extended_Request_Info
           (Generic_Info_Channel,
            "typed@example.test",
            Bytes_From_String ("typed-payload"));
         SSH_Lib.Tests.Assertions.Check_Status
           (Info.Result.Status, CryptoLib.Errors.Ok,
            "SFTP generic extension info", "result status");
         Check
           (SSH_Lib.SFTP.SFTP_Operation'Pos (Info.Result.Operation) =
              SSH_Lib.SFTP.SFTP_Operation'Pos
                (SSH_Lib.SFTP.Extended_Operation),
            "SFTP generic extension info operation tag");
         SSH_Lib.Tests.Assertions.Check_Bytes
           (SSH_Lib.Protocol.Buffers.To_Array (Info.Reply_Data),
            Bytes_From_String ("typed-reply"),
            "SFTP generic extension info",
            "raw reply payload exact");
         Assert_SCP_Channel_Data
           (Generic_Info_Channel,
            SFTP_Extended_Raw_Request
              ("typed@example.test", Bytes_From_String ("typed-payload")),
            "SFTP generic extension info request");
      end;

      declare
         Session_Item : SSH_Lib.Sessions.Session;
         Client_Item  : SSH_Lib.SFTP.Client;
         Open_Status  : CryptoLib.Errors.Status;
         Result       : SSH_Lib.SFTP.SFTP_Result;
         Snapshot     : SSH_Lib.SFTP.Negotiated_Snapshot;
      begin
         SSH_Lib.Sessions.Test_Support.Mark_Authenticated_Open_For_Test (Session_Item);
         Open_Status := SSH_Lib.Sessions.Test_Support.Queue_Channel_Open_Response_For_Test
           (Session_Item, Build_Open_Confirmation (0, 900, 4096, 8192));
         SSH_Lib.Tests.Assertions.Check_Status
           (Open_Status, CryptoLib.Errors.Ok, "SFTP version-select", "queue open response");
         Open_Status := SSH_Lib.Sessions.Test_Support.Queue_Exec_Response_For_Test
           (Session_Item, Build_Exec_Success (0));
         SSH_Lib.Tests.Assertions.Check_Status
           (Open_Status, CryptoLib.Errors.Ok, "SFTP version-select", "queue subsystem response");
         Open_Status := SSH_Lib.Sessions.Test_Support.Queue_Next_Channel_Stdout_For_Test
           (Session_Item, SFTP_Version_Capabilities_Packet & SFTP_Status_Packet (1));
         SSH_Lib.Tests.Assertions.Check_Status
           (Open_Status, CryptoLib.Errors.Ok, "SFTP version-select", "queue replies");
         Status_Value := SSH_Lib.SFTP.Open (Session_Item, Client_Item, 6);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP version-select", "client opens");
         Snapshot := SSH_Lib.SFTP.Negotiated_Info (Client_Item);
         SSH_Lib.Tests.Assertions.Check_Status
           (Snapshot.Result.Status, CryptoLib.Errors.Ok,
            "SFTP negotiated snapshot", "snapshot status");
         Check
           (Snapshot.Version = 6
            and then Snapshot.Extensions.Supported2
            and then Snapshot.Extensions.Capabilities.Present
            and then Snapshot.Extensions.Capabilities.Max_Read_Size =
              Interfaces.Unsigned_32'(65536),
            "SFTP negotiated snapshot preserves version and supported2");
         Status_Value := SSH_Lib.SFTP.Version_Select (Client_Item, 4, Result);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP version-select", "version-select succeeds");
         SSH_Lib.Tests.Assertions.Check_Status
           (Result.Status, CryptoLib.Errors.Ok, "SFTP version-select", "result status");
         Check
           (SSH_Lib.SFTP.SFTP_Operation'Pos (Result.Operation) =
              SSH_Lib.SFTP.SFTP_Operation'Pos
                (SSH_Lib.SFTP.Extended_Operation),
            "SFTP version-select result operation tag");
         Check (SSH_Lib.SFTP.Version (Client_Item) = 4, "SFTP version-select updates client version");
         Status_Value := SSH_Lib.SFTP.Version_Select (Client_Item, 2);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Unsupported_Feature,
            "SFTP version-select", "unadvertised version rejected");
      end;

      declare
         Session_Item : SSH_Lib.Sessions.Session;
         Client_Item  : SSH_Lib.SFTP.Client;
         Open_Status  : CryptoLib.Errors.Status;
         Limits       : SSH_Lib.SFTP.Server_Limits;
         Has_Limits   : Boolean := False;
      begin
         SSH_Lib.Sessions.Test_Support.Mark_Authenticated_Open_For_Test (Session_Item);
         Open_Status := SSH_Lib.Sessions.Test_Support.Queue_Channel_Open_Response_For_Test
           (Session_Item, Build_Open_Confirmation (0, 900, 4096, 8192));
         SSH_Lib.Tests.Assertions.Check_Status
           (Open_Status, CryptoLib.Errors.Ok, "SFTP persistent limits",
            "queue open response");
         Open_Status := SSH_Lib.Sessions.Test_Support.Queue_Exec_Response_For_Test
           (Session_Item, Build_Exec_Success (0));
         SSH_Lib.Tests.Assertions.Check_Status
           (Open_Status, CryptoLib.Errors.Ok, "SFTP persistent limits",
            "queue subsystem response");
         Open_Status := SSH_Lib.Sessions.Test_Support.Queue_Next_Channel_Stdout_For_Test
           (Session_Item, SFTP_Version_Capabilities_Packet & SFTP_Limits_Packet (1));
         SSH_Lib.Tests.Assertions.Check_Status
           (Open_Status, CryptoLib.Errors.Ok, "SFTP persistent limits",
            "queue version and limits replies");
         Status_Value := SSH_Lib.SFTP.Open (Session_Item, Client_Item, 6);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP persistent limits",
            "client opens and probes limits");
         Has_Limits := SSH_Lib.SFTP.Limits (Client_Item, Limits);
         Check
           (Has_Limits and then Limits.Max_Write_Length = 65536,
            "SFTP persistent client caches server write limit");
      end;

      declare
         Session_Item : SSH_Lib.Sessions.Session;
         Client_Item  : SSH_Lib.SFTP.Client;
         Open_Status  : CryptoLib.Errors.Status;
         Result       : SSH_Lib.SFTP.SFTP_Result;
      begin
         SSH_Lib.Sessions.Test_Support.Mark_Authenticated_Open_For_Test (Session_Item);
         Open_Status := SSH_Lib.Sessions.Test_Support.Queue_Channel_Open_Response_For_Test
           (Session_Item, Build_Open_Confirmation (0, 900, 4096, 8192));
         SSH_Lib.Tests.Assertions.Check_Status
           (Open_Status, CryptoLib.Errors.Ok, "SFTP v6 path metadata helpers",
            "queue open response");
         Open_Status := SSH_Lib.Sessions.Test_Support.Queue_Exec_Response_For_Test
           (Session_Item, Build_Exec_Success (0));
         SSH_Lib.Tests.Assertions.Check_Status
           (Open_Status, CryptoLib.Errors.Ok, "SFTP v6 path metadata helpers",
            "queue subsystem response");
         Open_Status := SSH_Lib.Sessions.Test_Support.Queue_Next_Channel_Stdout_For_Test
           (Session_Item, SFTP_Version_Capabilities_Packet
            & SFTP_Status_Packet (1)
            & SFTP_Status_Packet (1));
         SSH_Lib.Tests.Assertions.Check_Status
           (Open_Status, CryptoLib.Errors.Ok, "SFTP v6 path metadata helpers",
            "queue metadata replies");
         Status_Value := SSH_Lib.SFTP.Open (Session_Item, Client_Item, 6);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP v6 path metadata helpers",
            "client opens");
         Status_Value := SSH_Lib.SFTP.Set_Path_Mime_Type
           (Client_Item, "/tmp/file", "text/plain", Result);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP v6 path metadata helpers",
            "mime type helper succeeds");
         Check
           (SSH_Lib.SFTP.SFTP_Operation'Pos (Result.Operation) =
              SSH_Lib.SFTP.SFTP_Operation'Pos
                (SSH_Lib.SFTP.Set_Attributes_Operation),
            "SFTP metadata result operation tag");
         Status_Value := SSH_Lib.SFTP.Set_Path_Owner_Group
           (Client_Item, "/tmp/file", "user", "group", Result);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP v6 path metadata helpers",
            "owner/group helper succeeds");
         SSH_Lib.Tests.Assertions.Check_Status
           (Result.Status, CryptoLib.Errors.Ok, "SFTP v6 path metadata helpers",
            "owner/group result status");
      end;

      declare
         Session_Item : SSH_Lib.Sessions.Session;
         Client_Item  : SSH_Lib.SFTP.Client;
         Open_Status  : CryptoLib.Errors.Status;
         Metadata     : SSH_Lib.SFTP.File_Attributes;
      begin
         SSH_Lib.Sessions.Test_Support.Mark_Authenticated_Open_For_Test (Session_Item);
         Open_Status := SSH_Lib.Sessions.Test_Support.Queue_Channel_Open_Response_For_Test
           (Session_Item, Build_Open_Confirmation (0, 900, 4096, 8192));
         SSH_Lib.Tests.Assertions.Check_Status
           (Open_Status, CryptoLib.Errors.Ok, "SFTP supported2 enforcement",
            "queue open response");
         Open_Status := SSH_Lib.Sessions.Test_Support.Queue_Exec_Response_For_Test
           (Session_Item, Build_Exec_Success (0));
         SSH_Lib.Tests.Assertions.Check_Status
           (Open_Status, CryptoLib.Errors.Ok, "SFTP supported2 enforcement",
            "queue subsystem response");
         Open_Status := SSH_Lib.Sessions.Test_Support.Queue_Next_Channel_Stdout_For_Test
           (Session_Item, SFTP_Version_Limited_Capabilities_Packet);
         SSH_Lib.Tests.Assertions.Check_Status
           (Open_Status, CryptoLib.Errors.Ok, "SFTP supported2 enforcement",
            "queue limited capabilities");
         Status_Value := SSH_Lib.SFTP.Open (Session_Item, Client_Item, 6);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP supported2 enforcement",
            "client opens with limited capabilities");
         Status_Value := SSH_Lib.SFTP.Write_At
           (Client_Item, "/tmp/blocked", 0, Bytes_From_String ("x"));
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Unsupported_Feature,
            "SFTP supported2 enforcement", "write-at rejected before request");
         Metadata.Permissions_Known := True;
         Metadata.Permissions := 8#600#;
         Status_Value := SSH_Lib.SFTP.Set_Attributes
           (Client_Item, "/tmp/blocked", Metadata);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Unsupported_Feature,
            "SFTP supported2 enforcement", "setattrs rejected before request");
         Status_Value := SSH_Lib.SFTP.Version_Select (Client_Item, 4);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Unsupported_Feature,
            "SFTP supported2 enforcement", "unadvertised version-select rejected");
      end;

      declare
         Session_Item : SSH_Lib.Sessions.Session;
         Client_Item  : SSH_Lib.SFTP.Client;
         Open_Status  : CryptoLib.Errors.Status;
         Result       : SSH_Lib.SFTP.SFTP_Result;
      begin
         SSH_Lib.Sessions.Test_Support.Mark_Authenticated_Open_For_Test (Session_Item);
         Open_Status := SSH_Lib.Sessions.Test_Support.Queue_Channel_Open_Response_For_Test
           (Session_Item, Build_Open_Confirmation (0, 900, 4096, 8192));
         SSH_Lib.Tests.Assertions.Check_Status
           (Open_Status, CryptoLib.Errors.Ok, "SFTP v4 native client ops",
            "queue open response");
         Open_Status := SSH_Lib.Sessions.Test_Support.Queue_Exec_Response_For_Test
           (Session_Item, Build_Exec_Success (0));
         SSH_Lib.Tests.Assertions.Check_Status
           (Open_Status, CryptoLib.Errors.Ok, "SFTP v4 native client ops",
            "queue subsystem response");
         Open_Status := SSH_Lib.Sessions.Test_Support.Queue_Next_Channel_Stdout_For_Test
           (Session_Item,
            SFTP_Version_Capabilities_Packet
            & SFTP_Status_Packet (1)
            & SFTP_Handle_Packet (1, "t")
            & SFTP_Status_Packet (1)
            & SFTP_Status_Packet (1)
            & SFTP_Handle_Packet (1, "l")
            & SFTP_Status_Packet (1)
            & SFTP_Status_Packet (1)
            & SFTP_Handle_Packet (1, "u")
            & SFTP_Status_Packet (1)
            & SFTP_Status_Packet (1));
         SSH_Lib.Tests.Assertions.Check_Status
           (Open_Status, CryptoLib.Errors.Ok, "SFTP v4 native client ops",
            "queue native replies");
         Status_Value := SSH_Lib.SFTP.Open (Session_Item, Client_Item, 6);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP v4 native client ops",
            "client opens");
         Status_Value := SSH_Lib.SFTP.Create_Link
           (Client_Item, "/tmp/link", "/tmp/existing", False, Result);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP v4 native client ops",
            "client create-link succeeds");
         Check
           (SSH_Lib.SFTP.SFTP_Operation'Pos (Result.Operation) =
              SSH_Lib.SFTP.SFTP_Operation'Pos (SSH_Lib.SFTP.Link_Operation),
            "SFTP create-link result operation tag");
         Status_Value := SSH_Lib.SFTP.Text_Seek
           (Client_Item, "/tmp/text", 12, Result);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP v4 native client ops",
            "client text-seek succeeds");
         Check
           (SSH_Lib.SFTP.SFTP_Operation'Pos (Result.Operation) =
              SSH_Lib.SFTP.SFTP_Operation'Pos
                (SSH_Lib.SFTP.Extended_Operation),
            "SFTP text-seek result operation tag");
         Status_Value := SSH_Lib.SFTP.Lock_Range
           (Client_Item, "/tmp/lock", 1, 8, 16#5678#, Result);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP v4 native client ops",
            "client lock-range succeeds");
         Check
           (SSH_Lib.SFTP.SFTP_Operation'Pos (Result.Operation) =
              SSH_Lib.SFTP.SFTP_Operation'Pos (SSH_Lib.SFTP.Lock_Operation),
            "SFTP lock-range result operation tag");
         Status_Value := SSH_Lib.SFTP.Unlock_Range
           (Client_Item, "/tmp/lock", 1, 8, Result);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP v4 native client ops",
            "client unlock-range succeeds");
      end;

      declare
         Session_Item : SSH_Lib.Sessions.Session;
         Open_Status  : CryptoLib.Errors.Status;
      begin
         SSH_Lib.Sessions.Test_Support.Mark_Authenticated_Open_For_Test (Session_Item);
         Open_Status := SSH_Lib.Sessions.Test_Support.Queue_Channel_Open_Response_For_Test
           (Session_Item, Build_Open_Confirmation (0, 900, 4096, 8192));
         SSH_Lib.Tests.Assertions.Check_Status
           (Open_Status, CryptoLib.Errors.Ok, "SFTP extension capability", "queue posix open");
         Open_Status := SSH_Lib.Sessions.Test_Support.Queue_Exec_Response_For_Test
           (Session_Item, Build_Exec_Success (0));
         SSH_Lib.Tests.Assertions.Check_Status
           (Open_Status, CryptoLib.Errors.Ok, "SFTP extension capability", "queue posix subsystem");
         Open_Status := SSH_Lib.Sessions.Test_Support.Queue_Next_Channel_Stdout_For_Test
           (Session_Item, SFTP_Version_Extensions_Packet & SFTP_Status_Packet (1));
         SSH_Lib.Tests.Assertions.Check_Status
           (Open_Status, CryptoLib.Errors.Ok, "SFTP extension capability", "queue posix extension replies");

         Status_Value := SSH_Lib.SFTP.Posix_Rename
           (Session_Item, "/tmp/old", "/tmp/new");
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok,
            "SFTP extension capability", "advertised posix rename succeeds");
      end;

      declare
         Session_Item : SSH_Lib.Sessions.Session;
         Open_Status  : CryptoLib.Errors.Status;
         Stats        : SSH_Lib.SFTP.File_System_Stats;
      begin
         SSH_Lib.Sessions.Test_Support.Mark_Authenticated_Open_For_Test (Session_Item);
         Open_Status := SSH_Lib.Sessions.Test_Support.Queue_Channel_Open_Response_For_Test
           (Session_Item, Build_Open_Confirmation (0, 900, 4096, 8192));
         SSH_Lib.Tests.Assertions.Check_Status
           (Open_Status, CryptoLib.Errors.Ok, "SFTP extension capability", "queue unsupported statvfs open");
         Open_Status := SSH_Lib.Sessions.Test_Support.Queue_Exec_Response_For_Test
           (Session_Item, Build_Exec_Success (0));
         SSH_Lib.Tests.Assertions.Check_Status
           (Open_Status, CryptoLib.Errors.Ok, "SFTP extension capability", "queue unsupported statvfs subsystem");
         Open_Status := SSH_Lib.Sessions.Test_Support.Queue_Next_Channel_Stdout_For_Test
           (Session_Item, SFTP_Version_Packet);
         SSH_Lib.Tests.Assertions.Check_Status
           (Open_Status, CryptoLib.Errors.Ok, "SFTP extension capability", "queue unsupported statvfs version");

         Status_Value := SSH_Lib.SFTP.StatVFS (Session_Item, "/tmp", Stats);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Unsupported_Feature,
            "SFTP extension capability", "unadvertised statvfs rejected before request");
      end;

      declare
         Session_Item : SSH_Lib.Sessions.Session;
         Open_Status  : CryptoLib.Errors.Status;
         Values       : SSH_Lib.SFTP.Server_Limits;
      begin
         SSH_Lib.Sessions.Test_Support.Mark_Authenticated_Open_For_Test (Session_Item);
         Open_Status := SSH_Lib.Sessions.Test_Support.Queue_Channel_Open_Response_For_Test
           (Session_Item, Build_Open_Confirmation (0, 900, 4096, 8192));
         SSH_Lib.Tests.Assertions.Check_Status
           (Open_Status, CryptoLib.Errors.Ok, "SFTP extension capability", "queue unsupported limits open");
         Open_Status := SSH_Lib.Sessions.Test_Support.Queue_Exec_Response_For_Test
           (Session_Item, Build_Exec_Success (0));
         SSH_Lib.Tests.Assertions.Check_Status
           (Open_Status, CryptoLib.Errors.Ok, "SFTP extension capability", "queue unsupported limits subsystem");
         Open_Status := SSH_Lib.Sessions.Test_Support.Queue_Next_Channel_Stdout_For_Test
           (Session_Item, SFTP_Version_Packet);
         SSH_Lib.Tests.Assertions.Check_Status
           (Open_Status, CryptoLib.Errors.Ok, "SFTP extension capability", "queue unsupported limits version");

         Status_Value := SSH_Lib.SFTP.Limits (Session_Item, Values);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Unsupported_Feature,
            "SFTP extension capability", "unadvertised limits rejected before request");
      end;

      declare
         Limits_Channel : SSH_Lib.Channels.Channel;
         Limits         : SSH_Lib.SFTP.Server_Limits;
      begin
         SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
           (Limits_Channel, Local_Channel_Id => 0, Remote_Channel_Id => 1);
         Status_Value := SSH_Lib.Channels.Test_Support.Queue_Stdout_For_Test
           (Limits_Channel, SFTP_Limits_Packet (1));
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP limits", "queue extended reply");
         Status_Value := SSH_Lib.SFTP.Limits (Limits_Channel, Limits);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP limits", "limits succeeds");
         Check (Limits.Max_Packet_Length = 262144
                and then Limits.Max_Read_Length = 131072,
                "SFTP limits parses packet and read limits");
         Check (Limits.Max_Write_Length = 65536
                and then Limits.Max_Open_Handles = 32,
                "SFTP limits parses write and handle limits");
         declare
            Info_Channel : SSH_Lib.Channels.Channel;
            Info         : SSH_Lib.SFTP.Limits_Result;
         begin
            SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
              (Info_Channel, Local_Channel_Id => 0, Remote_Channel_Id => 1);
            Status_Value := SSH_Lib.Channels.Test_Support.Queue_Stdout_For_Test
              (Info_Channel, SFTP_Limits_Packet (1));
            SSH_Lib.Tests.Assertions.Check_Status
              (Status_Value, CryptoLib.Errors.Ok,
               "SFTP limits info", "queue extended reply");
            Info := SSH_Lib.SFTP.Limits_Info (Info_Channel);
            SSH_Lib.Tests.Assertions.Check_Status
              (Info.Result.Status, CryptoLib.Errors.Ok,
               "SFTP limits info", "result status");
            Check
              (SSH_Lib.SFTP.SFTP_Operation'Pos (Info.Result.Operation) =
                 SSH_Lib.SFTP.SFTP_Operation'Pos
                   (SSH_Lib.SFTP.Limits_Operation)
               and then Info.Values.Max_Write_Length = 65536,
               "SFTP limits info bundles operation and values");
         end;
         Assert_SCP_Channel_Data
           (Limits_Channel,
            SFTP_Extended_Name_Request (SSH_Lib.SFTP.Limits_Extension),
            "SFTP limits request");
      end;

      declare
         Metadata_Channel : SSH_Lib.Channels.Channel;
         Attributes       : SSH_Lib.SFTP.File_Attributes;
         Value            : Unbounded_String;
      begin
         SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
           (Metadata_Channel, Local_Channel_Id => 0, Remote_Channel_Id => 1);
         Status_Value := SSH_Lib.Channels.Test_Support.Queue_Stdout_For_Test
           (Metadata_Channel,
            SFTP_Extended_Attrs_Packet (1, "metadata@example", "value-1"));
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP metadata", "queue attrs reply");
         Status_Value := SSH_Lib.SFTP.Stat
           (Metadata_Channel, "/tmp/file", Attributes);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "SFTP metadata", "stat succeeds");
         Check
           (Attributes.Size_Known and then Attributes.Size = 99,
            "SFTP metadata preserves ordinary attrs");
         Check
           (SSH_Lib.SFTP.Has_Extended_Attribute
              (Attributes, "metadata@example"),
            "SFTP metadata exposes extended attr presence");
         Check
           (SSH_Lib.SFTP.Extended_Attribute_Value
              (Attributes, "metadata@example", Value)
            and then To_String (Value) = "value-1",
            "SFTP metadata exposes extended attr value");
         SSH_Lib.SFTP.Set_Extended_Attribute
           (Attributes, "metadata@example", "value-2");
         Check
           (SSH_Lib.SFTP.Extended_Attribute_Value
              (Attributes, "metadata@example", Value)
            and then To_String (Value) = "value-2",
            "SFTP metadata updates extended attr value");
      end;

      declare
         Transfer_Options  : constant SSH_Lib.SFTP.Transfer_Options :=
           SSH_Lib.File_Transfer.SFTP_Transfer_Options
             (Pipeline_Depth        => 8,
              Retry_Count           => 2,
              Verify_After_Transfer => True,
              Atomic_Upload         => True,
              Read_Chunk_Size             => 4096,
              Write_Chunk_Size            => 8192,
              Adaptive_Chunking           => True,
              Minimum_Adaptive_Chunk_Size => 1024);
         Recursive_Options : constant SSH_Lib.SFTP.Recursive_Options :=
           SSH_Lib.File_Transfer.SFTP_Recursive_Options
             (Preserve_Attributes => True,
              Continue_On_Error   => True,
              Overwrite_Files     => False,
              Follow_Symlinks     => True,
              Skip_Unchanged      => True);
      begin
         Check
           (Transfer_Options.Pipeline_Depth = 8
            and then Transfer_Options.Retry_Count = 2
            and then Transfer_Options.Verify_After_Transfer
            and then Transfer_Options.Atomic_Upload
            and then Transfer_Options.Read_Chunk_Size = 4096
            and then Transfer_Options.Write_Chunk_Size = 8192
            and then Transfer_Options.Adaptive_Chunking
            and then Transfer_Options.Minimum_Adaptive_Chunk_Size = 1024,
            "file transfer facade builds SFTP transfer options");
         Check
           (Recursive_Options.Preserve_Attributes
            and then Recursive_Options.Continue_On_Error
            and then not Recursive_Options.Overwrite_Files
            and then Recursive_Options.Follow_Symlinks
            and then Recursive_Options.Skip_Unchanged,
            "file transfer facade builds SFTP recursive options");
      end;

      declare
         Invalid_Channel : SSH_Lib.Channels.Channel;
         Target_Path     : Unbounded_String;
      begin
         SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
           (Invalid_Channel, Local_Channel_Id => 0, Remote_Channel_Id => 1);
         Status_Value := SSH_Lib.SFTP.Set_Permissions
           (Invalid_Channel, "/tmp/file", "bad");
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Invalid_Command,
            "SFTP invalid preflight", "bad chmod mode rejected");
         Status_Value := SSH_Lib.SFTP.Remove_File (Invalid_Channel, "");
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Invalid_Command,
            "SFTP invalid preflight", "empty remove path rejected");
         Status_Value := SSH_Lib.SFTP.Rename
           (Invalid_Channel, "/tmp/old", "");
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Invalid_Command,
            "SFTP invalid preflight", "empty rename target rejected");
         Status_Value := SSH_Lib.SFTP.Read_Link
           (Invalid_Channel, "", Target_Path);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Invalid_Command,
            "SFTP invalid preflight", "empty readlink path rejected");
         Status_Value := SSH_Lib.SFTP.Create_Symlink
           (Invalid_Channel, "", "/tmp/link");
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Invalid_Command,
            "SFTP invalid preflight", "empty symlink target rejected");
         Status_Value := SSH_Lib.SFTP.Realpath
           (Invalid_Channel, "", Target_Path);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Invalid_Command,
            "SFTP invalid preflight", "empty realpath rejected");
         declare
            Closed_Handle : SSH_Lib.SFTP.File_Handle;
            Attributes    : SSH_Lib.SFTP.File_Attributes;
         begin
            Status_Value := SSH_Lib.SFTP.FStat
              (Invalid_Channel, Closed_Handle, Attributes);
            SSH_Lib.Tests.Assertions.Check_Status
              (Status_Value, CryptoLib.Errors.Invalid_Command,
               "SFTP invalid preflight", "closed fstat handle rejected");
            Status_Value := SSH_Lib.SFTP.Set_Handle_Permissions
              (Invalid_Channel, Closed_Handle, "0644");
            SSH_Lib.Tests.Assertions.Check_Status
              (Status_Value, CryptoLib.Errors.Invalid_Command,
               "SFTP invalid preflight", "closed fsetstat handle rejected");
            Status_Value := SSH_Lib.SFTP.Set_Attributes
              (Invalid_Channel, "/tmp/file", Attributes);
            SSH_Lib.Tests.Assertions.Check_Status
              (Status_Value, CryptoLib.Errors.Invalid_Command,
               "SFTP invalid preflight", "empty setattrs rejected");
            Status_Value := SSH_Lib.SFTP.Set_Handle_Attributes
              (Invalid_Channel, Closed_Handle, Attributes);
            SSH_Lib.Tests.Assertions.Check_Status
              (Status_Value, CryptoLib.Errors.Invalid_Command,
               "SFTP invalid preflight", "closed handle setattrs rejected");
         end;
         Check
           (SSH_Lib.Channels.Test_Support.Outbound_Data_Packet_Count_For_Test
              (Invalid_Channel) = 0,
            "SFTP invalid preflight emits no channel data");
      end;
   end Assert_SFTP_Initialization;
end SSH_Lib.Tests.Fixtures.Command_Quoting;
