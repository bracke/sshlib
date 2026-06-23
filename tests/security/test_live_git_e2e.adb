with Ada.Command_Line;
with Ada.Streams;
with Ada.Strings.Unbounded;
with Ada.Text_IO;
with SSH_Lib.Channels;
with CryptoLib.Errors;
with SSH_Lib.Git;
with SSH_Lib.Platform.Environment;
with SSH_Lib.Sessions;

procedure Test_Live_Git_E2E is
   use Ada.Strings.Unbounded;
   use Ada.Streams;
   use type CryptoLib.Errors.Status;

   Flush_Request : constant Stream_Element_Array (1 .. 4) :=
     [16#30#, 16#30#, 16#30#, 16#30#];

   function Env (Name : String) return String is
   begin
      return To_String (SSH_Lib.Platform.Environment.Getenv (Name));
   end Env;

   function Status_Image (Value : CryptoLib.Errors.Status) return String is
   begin
      return CryptoLib.Errors.Status'Image (Value);
   end Status_Image;

   procedure Fail (Message_Text : String) is
   begin
      Ada.Text_IO.Put_Line ("FAIL: " & Message_Text);
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
   end Fail;

   function Parse_Natural_Default
     (Text          : String;
      Default_Value : Natural)
      return Natural
   is
   begin
      if Text'Length = 0 then
         return Default_Value;
      end if;
      return Natural'Value (Text);
   exception
      when others =>
         return Default_Value;
   end Parse_Natural_Default;

   procedure Check_Status
     (Actual       : CryptoLib.Errors.Status;
      Expected     : CryptoLib.Errors.Status;
      Label_Text   : String;
      Failed_State : in out Boolean)
   is
   begin
      if Actual /= Expected then
         Fail
           (Label_Text & " expected " & Status_Image (Expected) &
            " got " & Status_Image (Actual));
         Failed_State := True;
      end if;
   end Check_Status;

   Enabled_Text     : constant String := Env ("SSH_LIB_LIVE_GIT_E2E");
   Host_Text        : constant String := Env ("SSH_LIB_LIVE_GIT_HOST");
   User_Text        : constant String := Env ("SSH_LIB_LIVE_GIT_USER");
   Repo_Text        : constant String := Env ("SSH_LIB_LIVE_GIT_REPO");
   Service_Text     : constant String := Env ("SSH_LIB_LIVE_GIT_SERVICE");
   Port_Text        : constant String := Env ("SSH_LIB_LIVE_GIT_PORT");
   Timeout_Text     : constant String := Env ("SSH_LIB_LIVE_GIT_TIMEOUT_MS");
   Known_Hosts_Text : constant String := Env ("SSH_LIB_LIVE_GIT_KNOWN_HOSTS");
   Identity_Text    : constant String := Env ("SSH_LIB_LIVE_GIT_IDENTITY");

   Options          : SSH_Lib.Sessions.Session_Options;
   Session_Item     : SSH_Lib.Sessions.Session;
   Channel_Item     : SSH_Lib.Channels.Channel;
   Command_Text     : Unbounded_String;
   Status_Value     : CryptoLib.Errors.Status;
   Read_Buffer      : Stream_Element_Array (1 .. 8192);
   Last_Index       : Stream_Element_Offset;
   Byte_Count       : Natural := 0;
   Exit_Code        : Integer := -1;
   Failed_State     : Boolean := False;
   Session_Opened   : Boolean := False;
   Channel_Opened   : Boolean := False;
begin
   if Enabled_Text /= "1" then
      Ada.Text_IO.Put_Line
        ("live Git-over-SSH end-to-end test skipped: set SSH_LIB_LIVE_GIT_E2E=1 to enable");
      return;
   end if;

   if Host_Text'Length = 0 or else User_Text'Length = 0 or else Repo_Text'Length = 0 then
      Fail
        ("SSH_LIB_LIVE_GIT_HOST, SSH_LIB_LIVE_GIT_USER, and " &
         "SSH_LIB_LIVE_GIT_REPO are required when SSH_LIB_LIVE_GIT_E2E=1");
      return;
   end if;

   Options.Host := To_Unbounded_String (Host_Text);
   Options.User := To_Unbounded_String (User_Text);
   Options.Port := Parse_Natural_Default (Port_Text, 22);
   Options.Connect_Timeout_MS := Parse_Natural_Default (Timeout_Text, 10_000);
   Options.Read_Timeout_MS := Parse_Natural_Default (Timeout_Text, 10_000);
   Options.Write_Timeout_MS := Parse_Natural_Default (Timeout_Text, 10_000);
   Options.Verify_Known_Host := True;
   Options.Strict_Host_Key := True;
   Options.Use_Agent := True;

   if Known_Hosts_Text'Length /= 0 then
      Options.Known_Hosts_File := To_Unbounded_String (Known_Hosts_Text);
   end if;

   if Identity_Text'Length /= 0 then
      Options.Identity_File := To_Unbounded_String (Identity_Text);
   end if;

   if Service_Text = "receive-pack" then
      Status_Value := SSH_Lib.Git.Build_Receive_Pack_Command
        (Repo_Text, Command_Text);
   else
      Status_Value := SSH_Lib.Git.Build_Upload_Pack_Command
        (Repo_Text, Command_Text);
   end if;
   Check_Status (Status_Value, CryptoLib.Errors.Ok, "build Git service command", Failed_State);
   if Failed_State then
      return;
   end if;

   Status_Value := SSH_Lib.Sessions.Open (Options, Session_Item);
   Check_Status (Status_Value, CryptoLib.Errors.Ok, "open authenticated live session", Failed_State);
   if Failed_State then
      return;
   end if;
   Session_Opened := True;

   Status_Value := SSH_Lib.Channels.Open_Exec
     (Session_Item, To_String (Command_Text), Channel_Item);
   Check_Status (Status_Value, CryptoLib.Errors.Ok, "open live Git exec channel", Failed_State);
   if not Failed_State then
      Channel_Opened := True;
   end if;

   if not Failed_State then
      Status_Value := SSH_Lib.Channels.Write (Channel_Item, Flush_Request);
      Check_Status (Status_Value, CryptoLib.Errors.Ok, "write opaque Git flush packet", Failed_State);
   end if;

   if not Failed_State then
      Status_Value := SSH_Lib.Channels.Send_EOF (Channel_Item);
      Check_Status (Status_Value, CryptoLib.Errors.Ok, "send live channel EOF", Failed_State);
   end if;

   if not Failed_State then
      for Attempt_Index in 1 .. 16 loop
         Status_Value := SSH_Lib.Channels.Read_Some
           (Channel_Item, Read_Buffer, Last_Index);

         if Status_Value = CryptoLib.Errors.Ok then
            if Last_Index >= Read_Buffer'First then
               Byte_Count := Byte_Count + Natural (Last_Index - Read_Buffer'First + 1);
            end if;
         elsif Status_Value = CryptoLib.Errors.End_Of_Stream then
            exit;
         elsif Status_Value = CryptoLib.Errors.Timeout and then Byte_Count > 0 then
            exit;
         else
            Fail ("read opaque Git response bytes got " & Status_Image (Status_Value));
            Failed_State := True;
            exit;
         end if;
      end loop;

      if not Failed_State and then Byte_Count = 0 then
         Fail ("live Git service returned no opaque stdout bytes");
         Failed_State := True;
      end if;
   end if;

   if Channel_Opened then
      Status_Value := SSH_Lib.Channels.Exit_Status (Channel_Item, Exit_Code);
      if Status_Value = CryptoLib.Errors.Ok
     or else Status_Value = CryptoLib.Errors.Remote_Exit_Nonzero
     or else Status_Value = CryptoLib.Errors.Channel_Request_Failed
   then
      Ada.Text_IO.Put_Line
        ("live Git exit-status observation: " & Status_Image (Status_Value) &
         ", code " & Integer'Image (Exit_Code));
      else
         Fail ("unexpected live Git exit-status result " & Status_Image (Status_Value));
         Failed_State := True;
      end if;

      Status_Value := SSH_Lib.Channels.Close (Channel_Item);
      if Status_Value /= CryptoLib.Errors.Ok
        and then Status_Value /= CryptoLib.Errors.End_Of_Stream
      then
         Fail ("close live Git channel got " & Status_Image (Status_Value));
         Failed_State := True;
      end if;
   end if;

   if Session_Opened then
      Status_Value := SSH_Lib.Sessions.Close (Session_Item);
      if Status_Value /= CryptoLib.Errors.Ok then
         Fail ("close live Git session got " & Status_Image (Status_Value));
         Failed_State := True;
      end if;
   end if;

   if not Failed_State then
      Ada.Text_IO.Put_Line
        ("live Git-over-SSH end-to-end test passed, opaque bytes read:" &
         Natural'Image (Byte_Count));
   end if;
end Test_Live_Git_E2E;
