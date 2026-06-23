with Ada.Characters.Handling;
with Ada.Command_Line;
with Ada.Streams;
with Ada.Strings;
with Ada.Strings.Fixed;
with Ada.Strings.Unbounded;
with Ada.Text_IO;
with SSH_Lib.Channels;
with CryptoLib.Errors;
with SSH_Lib.Platform.Environment;
with SSH_Lib.Sessions;

procedure Test_Live_Proxycommand_Transport is
   use Ada.Strings.Unbounded;
   use Ada.Streams;
   use type CryptoLib.Errors.Status;

   function Env (Name : String) return String is
   begin
      return To_String (SSH_Lib.Platform.Environment.Getenv (Name));
   end Env;

   function Status_Image (Value : CryptoLib.Errors.Status) return String is
   begin
      return CryptoLib.Errors.Status'Image (Value);
   end Status_Image;

   Report_File      : Ada.Text_IO.File_Type;
   Report_Open      : Boolean := False;
   Report_Has_Fail  : Boolean := False;
   Report_Path_Text : constant String := Env ("SSH_LIB_LIVE_PROXYCOMMAND_REPORT");

   procedure Write_Report_Line (Line_Text : String) is
   begin
      if Report_Open then
         Ada.Text_IO.Put_Line (Report_File, Line_Text);
      end if;
   end Write_Report_Line;

   procedure Fail (Message_Text : String; Failed_State : in out Boolean) is
   begin
      Ada.Text_IO.Put_Line ("FAIL: " & Message_Text);
      Failed_State := True;
      Report_Has_Fail := True;
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

   function Is_Enabled_Text (Text : String) return Boolean is
   begin
      return Text = "1"
        or else Text = "true"
        or else Text = "TRUE"
        or else Text = "yes"
        or else Text = "YES";
   end Is_Enabled_Text;

   function Canonical_Scenario_Name (Raw_Text : String) return String is
      Trimmed_Text : constant String :=
        Ada.Strings.Fixed.Trim (Raw_Text, Ada.Strings.Both);
      Result_Text  : String := Trimmed_Text;
   begin
      for Index_Value in Result_Text'Range loop
         Result_Text (Index_Value) :=
           Ada.Characters.Handling.To_Upper (Result_Text (Index_Value));
      end loop;
      return Result_Text;
   end Canonical_Scenario_Name;

   function Is_Known_Scenario (Scenario_Name : String) return Boolean is
   begin
      return Scenario_Name = "BASIC"
        or else Scenario_Name = "TOKEN"
        or else Scenario_Name = "IPV6"
        or else Scenario_Name = "FAILS_EARLY"
        or else Scenario_Name = "HANGS";
   end Is_Known_Scenario;

   function Scenario_Env
     (Scenario_Name : String;
      Field_Name    : String)
      return String
   is
      Specific_Name : constant String :=
        "SSH_LIB_LIVE_PROXYCOMMAND_" & Scenario_Name & "_" & Field_Name;
      Generic_Name  : constant String :=
        "SSH_LIB_LIVE_PROXYCOMMAND_" & Field_Name;
      Specific_Text : constant String := Env (Specific_Name);
   begin
      if Specific_Text'Length /= 0 then
         return Specific_Text;
      end if;
      return Env (Generic_Name);
   end Scenario_Env;

   function Contains_Text (Text : String; Needle : String) return Boolean is
   begin
      return Ada.Strings.Fixed.Index (Text, Needle) /= 0;
   end Contains_Text;

   function Bool_Image (Value : Boolean) return String is
   begin
      if Value then
         return "true";
      else
         return "false";
      end if;
   end Bool_Image;

   function Scenario_Uses_Token (Proxy_Command_Text : String) return Boolean is
   begin
      return Contains_Text (Proxy_Command_Text, "%h")
        or else Contains_Text (Proxy_Command_Text, "%n")
        or else Contains_Text (Proxy_Command_Text, "%p")
        or else Contains_Text (Proxy_Command_Text, "%r")
        or else Contains_Text (Proxy_Command_Text, "%%");
   end Scenario_Uses_Token;

   function Exit_Code_Image (Value : Integer) return String is
   begin
      return Ada.Strings.Fixed.Trim (Integer'Image (Value), Ada.Strings.Both);
   end Exit_Code_Image;

   function Safe_Field (Text : String) return String is
   begin
      if Text'Length = 0 then
         return "none";
      end if;

      for Index_Value in Text'Range loop
         if Text (Index_Value) = ' ' then
            return "redacted";
         end if;
      end loop;
      return Text;
   end Safe_Field;

   procedure Record_Scenario
     (Scenario_Name       : String;
      Result_Text         : String;
      Stage_Text          : String;
      Byte_Count          : Natural;
      Session_Opened      : Boolean;
      Channel_Opened      : Boolean;
      Exit_Code           : Integer;
      Open_Status         : CryptoLib.Errors.Status;
      Proxy_Command_Text  : String;
      Expected_Failure    : Boolean;
      Proxy_Diagnostic    : SSH_Lib.Sessions.Proxy_Command_Diagnostic;
      Diagnostic_Text     : String)
   is
      Bytes_Text : constant String :=
        Ada.Strings.Fixed.Trim (Natural'Image (Byte_Count), Ada.Strings.Both);
   begin
      Write_Report_Line
        ("scenario=" & Scenario_Name &
         " result=" & Result_Text &
         " stage=" & Stage_Text &
         " bytes=" & Bytes_Text &
         " session_opened=" & Bool_Image (Session_Opened) &
         " channel_opened=" & Bool_Image (Channel_Opened) &
         " exit_status=" & Status_Image (Open_Status) &
         " exit_code=" & Exit_Code_Image (Exit_Code) &
         " open_status=" & Status_Image (Open_Status) &
         " verify_known_host=true" &
         " strict_host_key=true" &
         " proxy_command_configured=true" &
         " token_expansion=" & Bool_Image (Scenario_Uses_Token (Proxy_Command_Text)) &
         " expected_failure=" & Bool_Image (Expected_Failure) &
         " proxy_child_started=" & Bool_Image (Proxy_Diagnostic.Child_Started) &
         " proxy_child_open=" & Bool_Image (Proxy_Diagnostic.Child_Open) &
         " proxy_close_attempted=" & Bool_Image (Proxy_Diagnostic.Close_Attempted) &
         " proxy_close_completed=" & Bool_Image (Proxy_Diagnostic.Close_Completed) &
         " proxy_exit_status_known=" & Bool_Image (Proxy_Diagnostic.Exit_Status_Known) &
         " proxy_exit_status=" & Exit_Code_Image (Proxy_Diagnostic.Exit_Status) &
         " proxy_shell=" & Safe_Field (To_String (Proxy_Diagnostic.Shell_Name)) &
         " proxy_lifecycle=" & Safe_Field (To_String (Proxy_Diagnostic.Lifecycle_Stage)) &
         " proxy_spawn_status=" & Status_Image (Proxy_Diagnostic.Spawn_Status) &
         " proxy_last_io_status=" & Status_Image (Proxy_Diagnostic.Last_IO_Status) &
         " proxy_close_status=" & Status_Image (Proxy_Diagnostic.Close_Status) &
         " diagnostic=" & Diagnostic_Text);
   end Record_Scenario;

   procedure Clear_Sensitive_Options
     (Options : in out SSH_Lib.Sessions.Session_Options)
   is
   begin
      Options.Use_Password := False;
      Options.Password := Null_Unbounded_String;
      Options.Use_Identity_Passphrase := False;
      Options.Identity_Passphrase := Null_Unbounded_String;
   end Clear_Sensitive_Options;

   procedure Run_Scenario
     (Scenario_Name        : String;
      Overall_Failed_State : in out Boolean)
   is
      Host_Text        : constant String := Scenario_Env (Scenario_Name, "HOST");
      User_Text        : constant String := Scenario_Env (Scenario_Name, "USER");
      Proxy_Command_Text  : constant String := Scenario_Env (Scenario_Name, "PROXY_COMMAND");
      Command_Text     : constant String := Scenario_Env (Scenario_Name, "COMMAND");
      Expected_Text    : constant String := Scenario_Env (Scenario_Name, "EXPECTED_STDOUT");
      Port_Text        : constant String := Scenario_Env (Scenario_Name, "PORT");
      Timeout_Text     : constant String := Scenario_Env (Scenario_Name, "TIMEOUT_MS");
      Known_Hosts_Text : constant String := Scenario_Env (Scenario_Name, "KNOWN_HOSTS");
      Identity_Text    : constant String := Scenario_Env (Scenario_Name, "IDENTITY");
      Password_Text    : constant String := Scenario_Env (Scenario_Name, "PASSWORD");
      Passphrase_Text  : constant String := Scenario_Env (Scenario_Name, "IDENTITY_PASSPHRASE");
      Use_Agent_Text   : constant String := Scenario_Env (Scenario_Name, "USE_AGENT");

      Options        : SSH_Lib.Sessions.Session_Options;
      Session_Item   : SSH_Lib.Sessions.Session;
      Channel_Item   : SSH_Lib.Channels.Channel;
      Status_Value   : CryptoLib.Errors.Status;
      Read_Buffer    : Stream_Element_Array (1 .. 4096);
      Last_Index     : Stream_Element_Offset;
      Byte_Count     : Natural := 0;
      Exit_Code      : Integer := -1;
      Failed_State   : Boolean := False;
      Session_Opened : Boolean := False;
      Channel_Opened : Boolean := False;
      Saw_Expected   : Boolean := Expected_Text'Length = 0;
      Proxy_Diagnostic : SSH_Lib.Sessions.Proxy_Command_Diagnostic;
   begin
      Ada.Text_IO.Put_Line ("live ProxyCommand scenario: " & Scenario_Name);

      if not Is_Known_Scenario (Scenario_Name) then
         Fail ("unknown live ProxyCommand scenario: " & Scenario_Name, Failed_State);
      end if;

      if Host_Text'Length = 0
        or else User_Text'Length = 0
        or else Proxy_Command_Text'Length = 0
        or else (Scenario_Name /= "FAILS_EARLY"
                 and then Scenario_Name /= "HANGS"
                 and then Command_Text'Length = 0)
      then
         Fail
           ("scenario " & Scenario_Name &
            " requires HOST, USER, PROXY_COMMAND, and COMMAND except FAILS_EARLY/HANGS",
            Failed_State);
      end if;

      if Scenario_Name = "TOKEN"
        and then
          (not Contains_Text (Proxy_Command_Text, "%h")
           or else not Contains_Text (Proxy_Command_Text, "%p"))
      then
         Fail
           ("scenario TOKEN requires PROXY_COMMAND to include %h and %p",
            Failed_State);
      end if;

      if Scenario_Name = "IPV6"
        and then not Contains_Text (Host_Text, ":")
      then
         Fail ("scenario IPV6 requires an IPv6 target HOST", Failed_State);
      end if;

      if Failed_State then
         Overall_Failed_State := True;
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
      Options.Proxy_Command := To_Unbounded_String (Proxy_Command_Text);

      if Use_Agent_Text'Length /= 0 then
         Options.Use_Agent := Is_Enabled_Text (Use_Agent_Text);
      else
         Options.Use_Agent := True;
      end if;

      if Known_Hosts_Text'Length /= 0 then
         Options.Known_Hosts_File := To_Unbounded_String (Known_Hosts_Text);
      end if;

      if Identity_Text'Length /= 0 then
         Options.Identity_File := To_Unbounded_String (Identity_Text);
      end if;

      if Password_Text'Length /= 0 then
         Options.Use_Password := True;
         Options.Password := To_Unbounded_String (Password_Text);
      end if;

      if Passphrase_Text'Length /= 0 then
         Options.Use_Identity_Passphrase := True;
         Options.Identity_Passphrase := To_Unbounded_String (Passphrase_Text);
      end if;

      Status_Value := SSH_Lib.Sessions.Open (Options, Session_Item);
      Proxy_Diagnostic :=
        SSH_Lib.Sessions.Last_Proxy_Command_Diagnostics (Session_Item);
      if Scenario_Name = "FAILS_EARLY" or else Scenario_Name = "HANGS" then
         if Status_Value = CryptoLib.Errors.Ok then
            Session_Opened := True;
            Fail
              ("FAILS_EARLY unexpectedly opened ProxyCommand-backed session",
               Failed_State);
         elsif Scenario_Name = "HANGS"
           and then Status_Value /= CryptoLib.Errors.Timeout
         then
            Fail
              ("HANGS expected Timeout but got " & Status_Image (Status_Value),
               Failed_State);
         else
            Ada.Text_IO.Put_Line
              ("PASS: " & Scenario_Name & " rejected ProxyCommand with " &
               Status_Image (Status_Value));
            Record_Scenario
              (Scenario_Name, "PASS",
               (if Scenario_Name = "HANGS" then "timeout_cleanup"
                else "expected_failure"),
               0, False, False, -1, Status_Value, Proxy_Command_Text, True,
               Proxy_Diagnostic,
               (if Scenario_Name = "HANGS" then "proxy_command_timeout"
                else "proxy_command_rejected"));
            Clear_Sensitive_Options (Options);
            return;
         end if;
      elsif Status_Value /= CryptoLib.Errors.Ok then
         Fail
           (Scenario_Name & " open ProxyCommand-backed session got " &
            Status_Image (Status_Value), Failed_State);
      else
         Session_Opened := True;
      end if;

      if not Failed_State then
         Status_Value := SSH_Lib.Channels.Open_Exec
           (Session_Item, Command_Text, Channel_Item);
         if Status_Value /= CryptoLib.Errors.Ok then
            Fail
              (Scenario_Name & " open exec over ProxyCommand got " &
               Status_Image (Status_Value), Failed_State);
         else
            Channel_Opened := True;
         end if;
      end if;

      if not Failed_State then
         for Attempt_Index in 1 .. 16 loop
            Status_Value := SSH_Lib.Channels.Read_Some
              (Channel_Item, Read_Buffer, Last_Index);

            if Status_Value = CryptoLib.Errors.Ok then
               if Last_Index >= Read_Buffer'First then
                  for Index_Value in Read_Buffer'First .. Last_Index loop
                     Byte_Count := Byte_Count + 1;
                     if Expected_Text'Length /= 0
                       and then Byte_Count <= Expected_Text'Length
                       and then Character'Val (Read_Buffer (Index_Value)) =
                         Expected_Text (Expected_Text'First + Byte_Count - 1)
                       and then Byte_Count = Expected_Text'Length
                     then
                        Saw_Expected := True;
                     end if;
                  end loop;
               end if;
            elsif Status_Value = CryptoLib.Errors.End_Of_Stream then
               exit;
            elsif Status_Value = CryptoLib.Errors.Timeout and then Byte_Count > 0 then
               exit;
            else
               Fail
                 (Scenario_Name & " read exec stdout over ProxyCommand got " &
                  Status_Image (Status_Value), Failed_State);
               exit;
            end if;
         end loop;

         if not Failed_State and then not Saw_Expected then
            Fail
              (Scenario_Name & " did not observe EXPECTED_STDOUT prefix",
               Failed_State);
         end if;
      end if;

      if Channel_Opened then
         Status_Value := SSH_Lib.Channels.Exit_Status (Channel_Item, Exit_Code);
         if Status_Value /= CryptoLib.Errors.Ok
           and then Status_Value /= CryptoLib.Errors.Channel_Request_Failed
           and then Status_Value /= CryptoLib.Errors.Remote_Exit_Nonzero
         then
            Fail
              (Scenario_Name & " unexpected exit-status result " &
               Status_Image (Status_Value), Failed_State);
         end if;

         Status_Value := SSH_Lib.Channels.Close (Channel_Item);
         if Status_Value /= CryptoLib.Errors.Ok
           and then Status_Value /= CryptoLib.Errors.End_Of_Stream
         then
            Fail
              (Scenario_Name & " close channel got " & Status_Image (Status_Value),
               Failed_State);
         end if;
      end if;

      if Session_Opened then
         Status_Value := SSH_Lib.Sessions.Close (Session_Item);
         Proxy_Diagnostic :=
           SSH_Lib.Sessions.Last_Proxy_Command_Diagnostics (Session_Item);
         if Status_Value /= CryptoLib.Errors.Ok then
            Fail
              (Scenario_Name & " close session got " & Status_Image (Status_Value),
               Failed_State);
         end if;
      end if;

      Clear_Sensitive_Options (Options);

      if Failed_State then
         Overall_Failed_State := True;
         Record_Scenario
           (Scenario_Name, "FAIL", "failed", Byte_Count, Session_Opened,
            Channel_Opened, Exit_Code, Status_Value, Proxy_Command_Text,
            Scenario_Name = "FAILS_EARLY" or else Scenario_Name = "HANGS",
            Proxy_Diagnostic, "scenario_failed");
      else
         Ada.Text_IO.Put_Line
           ("PASS: " & Scenario_Name & " ProxyCommand stdout bytes:" &
            Natural'Image (Byte_Count));
         Record_Scenario
           (Scenario_Name, "PASS", "complete", Byte_Count, Session_Opened,
            Channel_Opened, Exit_Code, Status_Value, Proxy_Command_Text,
            False, Proxy_Diagnostic, "none");
      end if;
   end Run_Scenario;

   procedure Run_List
     (Scenario_List        : String;
      Overall_Failed_State : in out Boolean)
   is
      Start_Index : Positive := Scenario_List'First;
      Stop_Index  : Natural;
   begin
      while Start_Index <= Scenario_List'Last loop
         Stop_Index := Start_Index;
         while Stop_Index <= Scenario_List'Last
           and then Scenario_List (Stop_Index) /= ','
         loop
            Stop_Index := Stop_Index + 1;
         end loop;

         if Stop_Index = Start_Index then
            Fail
              ("empty live ProxyCommand scenario in list",
               Overall_Failed_State);
         else
            declare
               Scenario_Name : constant String := Canonical_Scenario_Name
                 (Scenario_List (Start_Index .. Stop_Index - 1));
            begin
               if Scenario_Name'Length = 0 then
                  Fail
                    ("empty live ProxyCommand scenario in list",
                     Overall_Failed_State);
               elsif Scenario_Name = "ALL" then
                  Run_Scenario ("BASIC", Overall_Failed_State);
                  Run_Scenario ("TOKEN", Overall_Failed_State);
                  Run_Scenario ("IPV6", Overall_Failed_State);
                  Run_Scenario ("FAILS_EARLY", Overall_Failed_State);
                  Run_Scenario ("HANGS", Overall_Failed_State);
               elsif Is_Known_Scenario (Scenario_Name) then
                  Run_Scenario (Scenario_Name, Overall_Failed_State);
               else
                  Fail
                    ("unknown live ProxyCommand scenario in list: " & Scenario_Name,
                     Overall_Failed_State);
               end if;
            end;
         end if;

         Start_Index := Stop_Index + 1;
      end loop;
   end Run_List;

   Enabled_Text       : constant String := Env ("SSH_LIB_LIVE_PROXYCOMMAND");
   Scenario_List_Text : constant String := Env ("SSH_LIB_LIVE_PROXYCOMMAND_SCENARIOS");
   Failed_State       : Boolean := False;
begin
   if Report_Path_Text'Length /= 0 then
      Ada.Text_IO.Create (Report_File, Ada.Text_IO.Out_File, Report_Path_Text);
      Report_Open := True;
      Write_Report_Line ("ssh_lib_live_proxycommand_report_version=1");
      Write_Report_Line ("enabled=" & Bool_Image (Enabled_Text = "1"));
      Write_Report_Line
        ("scenario_list=" &
         (if Scenario_List_Text'Length = 0 then "BASIC" else Scenario_List_Text));
   end if;

   if Enabled_Text /= "1" then
      Ada.Text_IO.Put_Line
        ("live ProxyCommand transport test skipped: set SSH_LIB_LIVE_PROXYCOMMAND=1 to enable");
      Write_Report_Line ("result=SKIP reason=disabled");
      if Report_Open then
         Ada.Text_IO.Close (Report_File);
      end if;
      return;
   end if;

   if Scenario_List_Text'Length = 0 then
      Ada.Text_IO.Put_Line
        ("SSH_LIB_LIVE_PROXYCOMMAND_SCENARIOS is empty; defaulting to BASIC");
      Run_Scenario ("BASIC", Failed_State);
   else
      Run_List (Scenario_List_Text, Failed_State);
   end if;

   if Failed_State or else Report_Has_Fail then
      Write_Report_Line ("result=FAIL");
      if Report_Open then
         Ada.Text_IO.Close (Report_File);
      end if;
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
   else
      Write_Report_Line ("result=PASS");
      if Report_Open then
         Ada.Text_IO.Close (Report_File);
      end if;
      Ada.Text_IO.Put_Line ("live ProxyCommand transport tests passed");
   end if;
end Test_Live_Proxycommand_Transport;
