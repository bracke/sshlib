with Ada.Directories;
with Ada.Streams;
with Ada.Strings.Unbounded;
with Ada.Text_IO;
with SSH_Lib.Channels;
with SSH_Lib.Channels.Test_Support;
with SSH_Lib.Config;
with CryptoLib.Errors;
with SSH_Lib.Git;
with SSH_Lib.Identity_Files;
with SSH_Lib.Known_Hosts;
with SSH_Lib.Remote_Names;
with SSH_Lib.Sessions;
with SSH_Lib.Tests.Assertions;
with SSH_Lib.Tests.Fixtures.Known_Hosts;
with SSH_Lib.Tests.Fixtures.Temp_Paths;

package body SSH_Lib.Tests.Fixtures.Exception_Containment is

   use type SSH_Lib.Identity_Files.Key_Kind;
   use Ada.Streams;
   use Ada.Strings.Unbounded;
   use type CryptoLib.Errors.Status;
   use type SSH_Lib.Known_Hosts.Verification_Result;

   procedure Check (Condition : Boolean; Label_Text : String) is
   begin
      if not Condition then
         Ada.Text_IO.Put_Line ("FAILED: " & Label_Text);
         raise Program_Error;
      end if;
   end Check;

   procedure Remove_If_Exists (Path : String) is
   begin
      if Ada.Directories.Exists (Path) then
         Ada.Directories.Delete_File (Path);
      end if;
   exception
      when others =>
         null;
   end Remove_If_Exists;

   procedure Write_Text_File (Path : String; Text : String) is
      Output_File : Ada.Text_IO.File_Type;
   begin
      Remove_If_Exists (Path);
      Ada.Text_IO.Create (Output_File, Ada.Text_IO.Out_File, Path);
      Ada.Text_IO.Put (Output_File, Text);
      Ada.Text_IO.Close (Output_File);
   exception
      when others =>
         if Ada.Text_IO.Is_Open (Output_File) then
            Ada.Text_IO.Close (Output_File);
         end if;
         raise;
   end Write_Text_File;

   procedure Check_Status_Is_Failure
     (Actual_Status : CryptoLib.Errors.Status;
      Label_Text    : String)
   is
   begin
      Check
        (Actual_Status /= CryptoLib.Errors.Ok
         and then Actual_Status /= CryptoLib.Errors.End_Of_Stream,
         Label_Text & " returned deterministic failure status");
   end Check_Status_Is_Failure;

   procedure Assert_Session_Exception_Boundaries is
      Options      : SSH_Lib.Sessions.Session_Options;
      Session_Item : SSH_Lib.Sessions.Session;
      Result_Status : CryptoLib.Errors.Status;
   begin
      Options.Host := Null_Unbounded_String;
      Options.User := To_Unbounded_String ("git");
      Result_Status := SSH_Lib.Sessions.Open (Options, Session_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Result_Status, CryptoLib.Errors.Invalid_Host,
         "exception containment", "Sessions.Open maps invalid host to status");

      Options.Host := To_Unbounded_String ("example.com");
      Options.Port := 65_536;
      Result_Status := SSH_Lib.Sessions.Open (Options, Session_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Result_Status, CryptoLib.Errors.Invalid_Port,
         "exception containment", "Sessions.Open maps invalid port to status");

      Result_Status := SSH_Lib.Sessions.Close (Session_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Result_Status, CryptoLib.Errors.Ok,
         "exception containment", "Sessions.Close remains idempotent after failed open");
   exception
      when others =>
         Ada.Text_IO.Put_Line ("FAILED: Sessions public API leaked exception");
         raise Program_Error;
   end Assert_Session_Exception_Boundaries;

   procedure Assert_Channel_Exception_Boundaries is
      Session_Item : SSH_Lib.Sessions.Session;
      Channel_Item : SSH_Lib.Channels.Channel;
      Result_Status : CryptoLib.Errors.Status;
      Buffer_Data : Stream_Element_Array (1 .. 8);
      Last_Value  : Stream_Element_Offset := 0;
      Code_Value  : Integer := 0;
      Empty_Data  : Stream_Element_Array (1 .. 0);
   begin
      Result_Status := SSH_Lib.Channels.Open_Exec
        (Session_Item, "git-upload-pack 'repo.git'", Channel_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Result_Status, CryptoLib.Errors.Channel_Open_Failed,
         "exception containment", "Open_Exec on closed session returns status");

      Result_Status := SSH_Lib.Channels.Open_Exec
        (Session_Item, "bad" & Character'Val (10) & "command", Channel_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Result_Status, CryptoLib.Errors.Invalid_Command,
         "exception containment", "Open_Exec maps unsafe command to status");

      Result_Status := SSH_Lib.Channels.Read_Some
        (Channel_Item, Buffer_Data, Last_Value);
      Check_Status_Is_Failure
        (Result_Status, "Read_Some on closed/default channel");

      Result_Status := SSH_Lib.Channels.Write (Channel_Item, Empty_Data);
      Check_Status_Is_Failure
        (Result_Status, "Write on closed/default channel");

      Result_Status := SSH_Lib.Channels.Send_EOF (Channel_Item);
      Check_Status_Is_Failure
        (Result_Status, "Send_EOF on closed/default channel");

      Result_Status := SSH_Lib.Channels.Exit_Status (Channel_Item, Code_Value);
      Check_Status_Is_Failure
        (Result_Status, "Exit_Status on closed/default channel");
      Check
        (Code_Value = 0 or else Code_Value = -1,
         "Exit_Status initializes code on rejected/default channel");

      Result_Status := SSH_Lib.Channels.Close (Channel_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Result_Status, CryptoLib.Errors.Ok,
         "exception containment", "Channels.Close remains idempotent after rejected operations");
   exception
      when others =>
         Ada.Text_IO.Put_Line ("FAILED: Channels public API leaked exception");
         raise Program_Error;
   end Assert_Channel_Exception_Boundaries;

   procedure Assert_Channel_Dispatch_Exception_Boundaries is
      Channel_Item  : SSH_Lib.Channels.Channel;
      Result_Status : CryptoLib.Errors.Status;
      Malformed_Payload : constant Stream_Element_Array (1 .. 2) :=
        [1 => 16#5E#, 2 => 16#00#];
   begin
      SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
        (Channel_Item,
         Local_Channel_Id           => 7,
         Remote_Channel_Id          => 9,
         Remote_Remaining_Window    => 64,
         Remote_Maximum_Packet_Size => 8);

      Result_Status := SSH_Lib.Channels.Test_Support.Dispatch_Inbound_Payload_For_Test
        (Channel_Item, Malformed_Payload);
      Check_Status_Is_Failure
        (Result_Status, "malformed channel dispatch payload");
      Check
        (SSH_Lib.Channels.Test_Support.Is_Dirty_For_Test (Channel_Item),
         "malformed channel dispatch dirties channel instead of leaking exception");
   exception
      when others =>
         Ada.Text_IO.Put_Line ("FAILED: channel dispatch injection leaked exception");
         raise Program_Error;
   end Assert_Channel_Dispatch_Exception_Boundaries;

   procedure Assert_File_Exception_Boundaries is
      Missing_Path : constant String := SSH_Lib.Tests.Fixtures.Temp_Paths.Path
        ("phase19_exception_missing");
      Bad_Config_Path : constant String := SSH_Lib.Tests.Fixtures.Temp_Paths.Path
        ("phase19_exception_bad_config");
      Bad_Known_Path : constant String := SSH_Lib.Tests.Fixtures.Temp_Paths.Path
        ("phase19_exception_bad_known_hosts");
      Bad_Identity_Path : constant String := SSH_Lib.Tests.Fixtures.Temp_Paths.Path
        ("phase19_exception_bad_identity");
      Config_Item : SSH_Lib.Config.Host_Config;
      Known_Item  : SSH_Lib.Known_Hosts.Database;
      Identity_Item : SSH_Lib.Identity_Files.Identity_Key;
      Options : SSH_Lib.Sessions.Session_Options;
      Result_Status : CryptoLib.Errors.Status;
      Result_Value  : SSH_Lib.Known_Hosts.Verification_Result;
      Parsed_Remote : SSH_Lib.Remote_Names.Parsed_Remote;
      Presented_Key : constant SSH_Lib.Known_Hosts.Host_Key :=
        SSH_Lib.Tests.Fixtures.Known_Hosts.Fixture_Host_Key;
   begin
      Remove_If_Exists (Missing_Path);
      Result_Status := SSH_Lib.Known_Hosts.Load (Missing_Path, Known_Item);
      Check_Status_Is_Failure
        (Result_Status, "Known_Hosts.Load missing file");

      Result_Status := SSH_Lib.Config.Load (Missing_Path, Config_Item);
      Check_Status_Is_Failure
        (Result_Status, "Config.Load missing file");
      Check
        (not SSH_Lib.Config.Has_Unsupported_Feature (Config_Item, "example"),
         "Config.Load missing file leaves no unsupported feature marker");

      Result_Status := SSH_Lib.Identity_Files.Load (Missing_Path, Identity_Item);
      Check_Status_Is_Failure
        (Result_Status, "Identity_Files.Load missing file");
      Check
        (SSH_Lib.Identity_Files.Kind (Identity_Item) = SSH_Lib.Identity_Files.No_Key,
         "Identity_Files.Load clears key after missing file failure");

      Write_Text_File
        (Bad_Known_Path,
         "example.com ssh-ed25519 not-base64!!!" & Character'Val (10));
      Result_Value := SSH_Lib.Known_Hosts.Verify
        (Bad_Known_Path, "example.com", 22, Presented_Key);
      Check
        (Result_Value /= SSH_Lib.Known_Hosts.Trusted,
         "Known_Hosts.Verify malformed record is not trusted and does not raise");

      Write_Text_File
        (Bad_Config_Path,
         "Host example" & Character'Val (10)
         & "  Port not-a-number" & Character'Val (10));
      Result_Status := SSH_Lib.Config.Load (Bad_Config_Path, Config_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Result_Status, CryptoLib.Errors.Ok,
         "exception containment", "Config.Load malformed directive remains data-only");
      Result_Status := SSH_Lib.Config.Resolve
        (Config_Item, "example", "git", Options);
      Check_Status_Is_Failure
        (Result_Status, "Config.Resolve maps malformed port to status");
      Check
        (To_String (Options.User) = "" or else To_String (Options.User) = "git",
         "Config.Resolve initializes output record on malformed port path");

      Write_Text_File
        (Bad_Identity_Path,
         "-----BEGIN OPENSSH PRIVATE KEY-----" & Character'Val (10)
         & "not-valid-base64" & Character'Val (10)
         & "-----END OPENSSH PRIVATE KEY-----" & Character'Val (10));
      Result_Status := SSH_Lib.Identity_Files.Load (Bad_Identity_Path, Identity_Item);
      Check_Status_Is_Failure
        (Result_Status, "Identity_Files.Load malformed key");
      Check
        (SSH_Lib.Identity_Files.Kind (Identity_Item) = SSH_Lib.Identity_Files.No_Key,
         "Identity_Files.Load clears key after malformed key failure");

      Result_Status := SSH_Lib.Remote_Names.Parse
        ("ssh://git@/repo.git", Parsed_Remote);
      SSH_Lib.Tests.Assertions.Check_Status
        (Result_Status, CryptoLib.Errors.Invalid_Host,
         "exception containment", "Remote_Names.Parse maps invalid host to status");
      Check
        (not SSH_Lib.Remote_Names.Is_Valid (Parsed_Remote),
         "Remote_Names.Parse leaves invalid remote rejected");

      Remove_If_Exists (Bad_Config_Path);
      Remove_If_Exists (Bad_Known_Path);
      Remove_If_Exists (Bad_Identity_Path);
   exception
      when others =>
         Ada.Text_IO.Put_Line ("FAILED: file/config/remote exception containment leaked exception");
         raise Program_Error;
   end Assert_File_Exception_Boundaries;

   procedure Assert_Git_Command_Exception_Boundary is
      Command_Text : Unbounded_String;
      Rejected     : Boolean := False;
   begin
      Command_Text := To_Unbounded_String
        (SSH_Lib.Git.Upload_Pack_Command ("safe.git"));
      Check
        (To_String (Command_Text) = "git-upload-pack 'safe.git'",
         "Git helper still constructs safe command after containment checks");

      begin
         Command_Text := To_Unbounded_String
           (SSH_Lib.Git.Upload_Pack_Command
              ("bad" & Character'Val (0) & "repo.git"));
      exception
         when Constraint_Error =>
            Rejected := True;
      end;
      Check
        (Rejected,
         "Git helper rejects NUL path through documented Constraint_Error boundary");
   exception
      when others =>
         Ada.Text_IO.Put_Line ("FAILED: Git command exception boundary behaved unexpectedly");
         raise Program_Error;
   end Assert_Git_Command_Exception_Boundary;

   procedure Assert_Public_Api_Exception_Boundaries is
   begin
      Assert_Session_Exception_Boundaries;
      Assert_Channel_Exception_Boundaries;
      Assert_Channel_Dispatch_Exception_Boundaries;
      Assert_File_Exception_Boundaries;
      Assert_Git_Command_Exception_Boundary;
   end Assert_Public_Api_Exception_Boundaries;
end SSH_Lib.Tests.Fixtures.Exception_Containment;
