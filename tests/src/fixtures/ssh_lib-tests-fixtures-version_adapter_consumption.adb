with Ada.Directories;
with Ada.Streams;
with Ada.Strings.Unbounded;
with Ada.Text_IO;
with Interfaces;
with SSH_Lib.Channels;
with SSH_Lib.Channels.Test_Support;
with SSH_Lib.Config;
with CryptoLib.Errors;
with SSH_Lib.Git_Transport;
with SSH_Lib.Protocol.Buffers;
with SSH_Lib.Protocol.Channels;
with SSH_Lib.Protocol.Numbers;
with SSH_Lib.Sessions;
with SSH_Lib.Sessions.Test_Support;
with SSH_Lib.Tests.Assertions;
with SSH_Lib.Tests.Fixtures.Temp_Paths;

package body SSH_Lib.Tests.Fixtures.Version_Adapter_Consumption is

   use Ada.Strings.Unbounded;
   use type CryptoLib.Errors.Status;
   use type Ada.Streams.Stream_Element_Offset;

   Request_Bytes : constant Ada.Streams.Stream_Element_Array (1 .. 6) :=
     [16#00#, 16#0A#, 16#0D#, 16#7F#, 16#80#, 16#FF#];

   Upload_Response_Bytes : constant Ada.Streams.Stream_Element_Array (1 .. 8) :=
     [16#FF#, 16#80#, 16#7F#, 16#0D#, 16#0A#, 16#00#, 16#50#, 16#4B#];

   Receive_Response_Bytes : constant Ada.Streams.Stream_Element_Array (1 .. 8) :=
     [16#50#, 16#41#, 16#43#, 16#4B#, 16#00#, 16#0A#, 16#80#, 16#FF#];

   procedure Check (Condition : Boolean; Label_Text : String) is
   begin
      if not Condition then
         Ada.Text_IO.Put_Line ("FAILED: " & Label_Text);
         raise Program_Error;
      end if;
   end Check;

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
        (Status_Value, CryptoLib.Errors.Ok, "version adapter fixture", "open confirmation type");
      Status_Value := SSH_Lib.Protocol.Buffers.Append
        (Work_Item, SSH_Lib.Protocol.Numbers.Encode_Uint32 (Recipient_Channel));
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok, "version adapter fixture", "open confirmation recipient");
      Status_Value := SSH_Lib.Protocol.Buffers.Append
        (Work_Item, SSH_Lib.Protocol.Numbers.Encode_Uint32 (Sender_Channel));
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok, "version adapter fixture", "open confirmation sender");
      Status_Value := SSH_Lib.Protocol.Buffers.Append
        (Work_Item, SSH_Lib.Protocol.Numbers.Encode_Uint32 (Initial_Window_Size));
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok, "version adapter fixture", "open confirmation window");
      Status_Value := SSH_Lib.Protocol.Buffers.Append
        (Work_Item, SSH_Lib.Protocol.Numbers.Encode_Uint32 (Maximum_Packet_Size));
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok, "version adapter fixture", "open confirmation max packet");
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

   procedure Write_Config (Path : String) is
      File_Item : Ada.Text_IO.File_Type;
   begin
      Ada.Text_IO.Create (File_Item, Ada.Text_IO.Out_File, Path);
      Ada.Text_IO.Put_Line (File_Item, "Host fixture");
      Ada.Text_IO.Put_Line (File_Item, "  HostName ssh-fixture.invalid");
      Ada.Text_IO.Put_Line (File_Item, "  User git");
      Ada.Text_IO.Put_Line (File_Item, "  Port 2222");
      Ada.Text_IO.Put_Line (File_Item, "  IdentityFile ~/.ssh/id_fixture_ed25519");
      Ada.Text_IO.Close (File_Item);
   end Write_Config;

   procedure Remove_If_Exists (Path : String) is
   begin
      if Ada.Directories.Exists (Path) then
         Ada.Directories.Delete_File (Path);
      end if;
   exception
      when others =>
         null;
   end Remove_If_Exists;

   procedure Assert_Command_Payload
     (Session_Item : SSH_Lib.Sessions.Session;
      Expected_Command : String;
      Scenario : String)
   is
      Payload : constant Ada.Streams.Stream_Element_Array :=
        SSH_Lib.Sessions.Test_Support.Last_Exec_Request_Payload_For_Test (Session_Item);
      Expected : constant Ada.Streams.Stream_Element_Array :=
        SSH_Lib.Protocol.Buffers.To_Array
          (SSH_Lib.Protocol.Channels.Encode_Exec_Request (900, Expected_Command));
   begin
      SSH_Lib.Tests.Assertions.Check_Bytes
        (Payload,
         Expected,
         "version adapter fixture",
         Scenario & " exec request command bytes are exact");
      Check (SSH_Lib.Protocol.Channels.Valid_Command (Expected_Command),
             Scenario & " generated command is valid for Open_Exec");
      Check (Bytes_From_String (Expected_Command)'Length > 0,
             Scenario & " expected command has byte representation");
   end Assert_Command_Payload;

   procedure Assert_Write_Payload
     (Channel_Item : SSH_Lib.Channels.Channel;
      Expected_Data : Ada.Streams.Stream_Element_Array;
      Scenario : String)
   is
      Payload : constant Ada.Streams.Stream_Element_Array :=
        SSH_Lib.Channels.Test_Support.Last_Channel_Data_Payload_For_Test (Channel_Item);
      Event : SSH_Lib.Protocol.Channels.Channel_Data_Event;
      Status_Value : CryptoLib.Errors.Status;
   begin
      Status_Value := SSH_Lib.Protocol.Channels.Parse_Channel_Data
        (Payload, Expected_Recipient => 900, Item => Event);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok, "version adapter fixture", Scenario & " parse channel data");
      SSH_Lib.Tests.Assertions.Check_Bytes
        (SSH_Lib.Protocol.Buffers.To_Array (Event.Data),
         Expected_Data,
         "version adapter fixture",
         Scenario & " request bytes exact");
   end Assert_Write_Payload;

   procedure Exercise_Service
     (Config_Item : SSH_Lib.Config.Host_Config;
      Requested : SSH_Lib.Git_Transport.Service;
      Expected_Command : String;
      Expected_Response : Ada.Streams.Stream_Element_Array;
      Scenario : String)
   is
      Options_Item : SSH_Lib.Sessions.Session_Options;
      Command_Item : Unbounded_String;
      Session_Item : SSH_Lib.Sessions.Session;
      Channel_Item : SSH_Lib.Channels.Channel;
      Status_Value : CryptoLib.Errors.Status;
      Buffer_Item : Ada.Streams.Stream_Element_Array (1 .. 32);
      Last_Index : Ada.Streams.Stream_Element_Offset;
      Exit_Code : Integer := -1;
   begin
      Status_Value := SSH_Lib.Git_Transport.Prepare
        (Remote_Text  => "ssh://git@fixture/repo.git",
         Config       => Config_Item,
         Default_User => "",
         Requested    => Requested,
         Options      => Options_Item,
         Command      => Command_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok, "version adapter fixture", Scenario & " prepare");
      Check (To_String (Options_Item.Host) = "ssh-fixture.invalid",
             Scenario & " config HostName resolved");
      Check (To_String (Options_Item.User) = "git",
             Scenario & " user resolved");
      Check (Options_Item.Port = 2222,
             Scenario & " port resolved");
      Check (Options_Item.Verify_Known_Host,
             Scenario & " keeps host-key verification enabled");
      Check (Options_Item.Strict_Host_Key,
             Scenario & " keeps strict host-key mode enabled");
      Check (To_String (Command_Item) = Expected_Command,
             Scenario & " command text exact");

      SSH_Lib.Sessions.Test_Support.Mark_Authenticated_Open_For_Test (Session_Item);
      Check (SSH_Lib.Sessions.Test_Support.Is_Open_For_Test (Session_Item),
             Scenario & " local fixture session open");
      Check (SSH_Lib.Sessions.Test_Support.Is_Encrypted_For_Test (Session_Item),
             Scenario & " local fixture session encrypted");
      Check (SSH_Lib.Sessions.Test_Support.Is_Host_Trusted_For_Test (Session_Item),
             Scenario & " local fixture host trusted");
      Check (SSH_Lib.Sessions.Test_Support.Is_Authenticated_For_Test (Session_Item),
             Scenario & " local fixture authenticated");

      Status_Value := SSH_Lib.Sessions.Test_Support.Queue_Channel_Open_Response_For_Test
        (Session_Item, Build_Open_Confirmation (0, 900, 4096, 8192));
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok, "version adapter fixture", Scenario & " queue channel open");
      Status_Value := SSH_Lib.Sessions.Test_Support.Queue_Exec_Response_For_Test
        (Session_Item, Build_Exec_Success (0));
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok, "version adapter fixture", Scenario & " queue exec success");

      Status_Value := SSH_Lib.Channels.Open_Exec
        (Session_Item, To_String (Command_Item), Channel_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok, "version adapter fixture", Scenario & " open exec");
      Assert_Command_Payload (Session_Item, Expected_Command, Scenario);

      Status_Value := SSH_Lib.Channels.Write (Channel_Item, Request_Bytes);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok, "version adapter fixture", Scenario & " write request bytes");
      Assert_Write_Payload (Channel_Item, Request_Bytes, Scenario);

      Status_Value := SSH_Lib.Channels.Test_Support.Queue_Stdout_For_Test
        (Channel_Item, Expected_Response);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok, "version adapter fixture", Scenario & " queue stdout response");
      Status_Value := SSH_Lib.Channels.Read_Some
        (Channel_Item, Buffer_Item, Last_Index);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok, "version adapter fixture", Scenario & " read response bytes");
      SSH_Lib.Tests.Assertions.Check_Bytes
        (Buffer_Item (Buffer_Item'First .. Last_Index),
         Expected_Response,
         "version adapter fixture",
         Scenario & " response bytes exact");

      Status_Value := SSH_Lib.Channels.Send_EOF (Channel_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok, "version adapter fixture", Scenario & " send EOF");
      Check (SSH_Lib.Channels.Test_Support.Last_EOF_Payload_For_Test (Channel_Item)'Length > 0,
             Scenario & " EOF packet emitted");

      SSH_Lib.Channels.Test_Support.Mark_Exit_Status_Known_For_Test (Channel_Item, 0);
      Status_Value := SSH_Lib.Channels.Exit_Status (Channel_Item, Exit_Code);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok, "version adapter fixture", Scenario & " exit status");
      Check (Exit_Code = 0, Scenario & " exit status zero");

      Status_Value := SSH_Lib.Channels.Close (Channel_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok, "version adapter fixture", Scenario & " channel close");
      Status_Value := SSH_Lib.Sessions.Close (Session_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok, "version adapter fixture", Scenario & " session close");
   end Exercise_Service;

   procedure Assert_Deterministic_Version_Adapter_Consumption is
      Config_Path : constant String :=
        SSH_Lib.Tests.Fixtures.Temp_Paths.Path ("phase19_version_adapter_config");
      Config_Item : SSH_Lib.Config.Host_Config;
      Status_Value : CryptoLib.Errors.Status;
   begin
      Remove_If_Exists (Config_Path);
      Write_Config (Config_Path);
      Status_Value := SSH_Lib.Config.Load (Config_Path, Config_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok, "version adapter fixture", "load config");

      Exercise_Service
        (Config_Item       => Config_Item,
         Requested         => SSH_Lib.Git_Transport.Upload_Pack,
         Expected_Command  => "git-upload-pack 'repo.git'",
         Expected_Response => Upload_Response_Bytes,
         Scenario          => "upload-pack");

      Exercise_Service
        (Config_Item       => Config_Item,
         Requested         => SSH_Lib.Git_Transport.Receive_Pack,
         Expected_Command  => "git-receive-pack 'repo.git'",
         Expected_Response => Receive_Response_Bytes,
         Scenario          => "receive-pack");

      Remove_If_Exists (Config_Path);
   end Assert_Deterministic_Version_Adapter_Consumption;
end SSH_Lib.Tests.Fixtures.Version_Adapter_Consumption;
