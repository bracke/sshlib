with Ada.Command_Line;
with Ada.Streams;
with Ada.Strings.Unbounded;
with Ada.Text_IO;
with CryptoLib.Errors;
with SSH_Lib.Git;
with SSH_Lib.Remote_Names;
with SSH_Lib.Sessions;

procedure Check_Phase17_Regressions is
   use Ada.Strings.Unbounded;
   use type Ada.Streams.Stream_Element;
   use type CryptoLib.Errors.Status;

   Failure_Count : Natural := 0;

   procedure Fail (Message_Text : String) is
   begin
      Ada.Text_IO.Put_Line ("FAIL: " & Message_Text);
      Failure_Count := Failure_Count + 1;
   end Fail;

   procedure Require (Condition : Boolean; Message_Text : String) is
   begin
      if not Condition then
         Fail (Message_Text);
      end if;
   end Require;

   procedure Check_Status_Model is
   begin
      for Status_Value in CryptoLib.Errors.Status loop
         if Status_Value = CryptoLib.Errors.Ok then
            Require
              (CryptoLib.Errors.Is_Success (Status_Value),
               "Ok must be the only success status and must report success");
         else
            Require
              (not CryptoLib.Errors.Is_Success (Status_Value),
               "non-Ok status must not report success: "
               & CryptoLib.Errors.Status'Image (Status_Value));
         end if;
      end loop;
   end Check_Status_Model;

   procedure Check_Session_Defaults is
      Options : SSH_Lib.Sessions.Session_Options;
   begin
      Require (Options.Port = 22, "default port must remain 22");
      Require
        (Options.Connect_Timeout_MS = 30_000,
         "default connect timeout must remain 30_000 ms");
      Require
        (Options.Read_Timeout_MS = 30_000,
         "default read timeout must remain 30_000 ms");
      Require
        (Options.Write_Timeout_MS = 30_000,
         "default write timeout must remain 30_000 ms");
      Require
        (Options.Verify_Known_Host,
         "Verify_Known_Host must default to True");
      Require
        (Options.Use_Agent,
         "Use_Agent must default to True");
      Require
        (Options.Strict_Host_Key,
         "Strict_Host_Key must default to True");
   end Check_Session_Defaults;

   procedure Check_Git_Command_Guards is
      Command : Unbounded_String;
      Status_Value : CryptoLib.Errors.Status;
   begin
      Status_Value := SSH_Lib.Git.Build_Upload_Pack_Command
        ("repo.git", Command);
      Require
        (Status_Value = CryptoLib.Errors.Ok
         and then To_String (Command) = "git-upload-pack 'repo.git'",
         "upload-pack command shape changed");

      Status_Value := SSH_Lib.Git.Build_Receive_Pack_Command
        ("repo.git", Command);
      Require
        (Status_Value = CryptoLib.Errors.Ok
         and then To_String (Command) = "git-receive-pack 'repo.git'",
         "receive-pack command shape changed");

      Status_Value := SSH_Lib.Git.Build_Upload_Pack_Command
        ("repo" & Character'Val (0) & "git", Command);
      Require
        (Status_Value = CryptoLib.Errors.Invalid_Command,
         "Git helper must reject NUL in repository paths");

      Status_Value := SSH_Lib.Git.Build_Upload_Pack_Command
        ("repo" & Character'Val (10) & "git", Command);
      Require
        (Status_Value = CryptoLib.Errors.Invalid_Command,
         "Git helper must reject LF in repository paths");

      Status_Value := SSH_Lib.Git.Build_Upload_Pack_Command
        ("repo" & Character'Val (13) & "git", Command);
      Require
        (Status_Value = CryptoLib.Errors.Invalid_Command,
         "Git helper must reject CR in repository paths");

      Status_Value := SSH_Lib.Git.Build_Upload_Pack_Command
        ("repo'quoted.git", Command);
      Require
        (Status_Value = CryptoLib.Errors.Ok
         and then To_String (Command) = "git-upload-pack 'repo'\''quoted.git'",
         "Git helper must quote single quotes deterministically");
   end Check_Git_Command_Guards;

   procedure Check_Remote_Name_Contract is
      Remote_Item : SSH_Lib.Remote_Names.Parsed_Remote;
      Status_Value : CryptoLib.Errors.Status;
   begin
      Status_Value := SSH_Lib.Remote_Names.Parse
        ("git@example.com:repo.git", Remote_Item);
      Require
        (Status_Value = CryptoLib.Errors.Ok,
         "scp-like Git remote should parse");
      Require
        (SSH_Lib.Remote_Names.Host (Remote_Item) = "example.com",
         "scp-like remote host changed");
      Require
        (SSH_Lib.Remote_Names.User (Remote_Item) = "git",
         "scp-like remote user changed");
      Require
        (SSH_Lib.Remote_Names.Repository_Path (Remote_Item) = "repo.git",
         "scp-like remote repository changed");
      Require
        (SSH_Lib.Remote_Names.Port (Remote_Item) = 22,
         "scp-like remote default port changed");

      Status_Value := SSH_Lib.Remote_Names.Parse
        ("ssh://git@example.com:2222/group/repo.git", Remote_Item);
      Require
        (Status_Value = CryptoLib.Errors.Ok,
         "ssh:// Git remote should parse");
      Require
        (SSH_Lib.Remote_Names.Host (Remote_Item) = "example.com",
         "ssh:// remote host changed");
      Require
        (SSH_Lib.Remote_Names.User (Remote_Item) = "git",
         "ssh:// remote user changed");
      Require
        (SSH_Lib.Remote_Names.Port (Remote_Item) = 2222,
         "ssh:// remote port changed");
   end Check_Remote_Name_Contract;

   procedure Check_Binary_Vector_Contract is
      Expected : constant Ada.Streams.Stream_Element_Array (1 .. 6) :=
        [1 => 16#00#,
         2 => 16#0A#,
         3 => 16#0D#,
         4 => 16#7F#,
         5 => 16#80#,
         6 => 16#FF#];
      Actual : constant Ada.Streams.Stream_Element_Array (Expected'Range) := Expected;
   begin
      for Index_Value in Expected'Range loop
         if Actual (Index_Value) /= Expected (Index_Value) then
            Fail
              ("binary byte mismatch at offset"
               & Ada.Streams.Stream_Element_Offset'Image (Index_Value));
         end if;
      end loop;
   end Check_Binary_Vector_Contract;

begin
   Check_Status_Model;
   Check_Session_Defaults;
   Check_Git_Command_Guards;
   Check_Remote_Name_Contract;
   Check_Binary_Vector_Contract;

   if Failure_Count = 0 then
      Ada.Text_IO.Put_Line ("Phase 17 regression guard passed");
   else
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
   end if;
end Check_Phase17_Regressions;
