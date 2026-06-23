with Ada.Characters.Handling;
with Ada.Command_Line;
with Ada.Streams;
with Ada.Strings;
with Ada.Strings.Fixed;
with Ada.Strings.Unbounded;
with Ada.Text_IO;
with SSH_Lib.Channels;
with CryptoLib.Errors;
with SSH_Lib.Git;
with SSH_Lib.Platform.Environment;
with SSH_Lib.Sessions;

procedure Test_Live_Git_Interop_Matrix is
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

   Report_Path : constant String := Env ("SSH_LIB_LIVE_GIT_REPORT");
   Report_File : Ada.Text_IO.File_Type;
   Report_Open : Boolean := False;
   Report_Create_Failed : Boolean := False;

   procedure Open_Report is
   begin
      if Report_Path'Length /= 0 then
         Ada.Text_IO.Create (Report_File, Ada.Text_IO.Out_File, Report_Path);
         Report_Open := True;
         Ada.Text_IO.Put_Line
           (Report_File, "ssh_lib_live_git_interop_matrix_report_version=1");
      end if;
   exception
      when others =>
         Report_Create_Failed := True;
         Ada.Text_IO.Put_Line
           ("FAIL: cannot create SSH_LIB_LIVE_GIT_REPORT: " & Report_Path);
         Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
   end Open_Report;

   procedure Report_Line (Text : String) is
   begin
      if Report_Open then
         Ada.Text_IO.Put_Line (Report_File, Text);
      end if;
   exception
      when others =>
         null;
   end Report_Line;

   procedure Close_Report is
   begin
      if Report_Open then
         Ada.Text_IO.Close (Report_File);
         Report_Open := False;
      end if;
   exception
      when others =>
         Report_Open := False;
   end Close_Report;

   function Report_Bool (Value : Boolean) return String is
   begin
      if Value then
         return "true";
      end if;
      return "false";
   end Report_Bool;

   function Report_Natural (Value : Natural) return String is
   begin
      return Ada.Strings.Fixed.Trim (Natural'Image (Value), Ada.Strings.Both);
   end Report_Natural;

   function Report_Integer (Value : Integer) return String is
   begin
      return Ada.Strings.Fixed.Trim (Integer'Image (Value), Ada.Strings.Both);
   end Report_Integer;

   procedure Fail (Message_Text : String; Failed_State : in out Boolean) is
   begin
      Ada.Text_IO.Put_Line ("FAIL: " & Message_Text);
      Failed_State := True;
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

   function Scenario_Env
     (Scenario_Name : String;
      Field_Name    : String)
      return String
   is
      Specific_Name : constant String :=
        "SSH_LIB_LIVE_GIT_" & Scenario_Name & "_" & Field_Name;
      Generic_Name  : constant String :=
        "SSH_LIB_LIVE_GIT_" & Field_Name;
      Specific_Text : constant String := Env (Specific_Name);
   begin
      if Specific_Text'Length /= 0 then
         return Specific_Text;
      end if;
      return Env (Generic_Name);
   end Scenario_Env;

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
      return Scenario_Name = "DIRECT"
        or else Scenario_Name = "AGENT"
        or else Scenario_Name = "IDENTITY"
        or else Scenario_Name = "PASSWORD"
        or else Scenario_Name = "PASSPHRASE"
        or else Scenario_Name = "PROXYJUMP"
        or else Scenario_Name = "RECEIVE";
   end Is_Known_Scenario;

   procedure Clear_Sensitive_Options
     (Options : in out SSH_Lib.Sessions.Session_Options)
   is
   begin
      Options.Use_Password := False;
      Options.Password := Null_Unbounded_String;
      Options.Use_Identity_Passphrase := False;
      Options.Identity_Passphrase := Null_Unbounded_String;
   end Clear_Sensitive_Options;

   function Uses_Agent_Default (Scenario_Name : String) return Boolean is
   begin
      return Scenario_Name /= "IDENTITY"
        and then Scenario_Name /= "PASSWORD"
        and then Scenario_Name /= "PASSPHRASE";
   end Uses_Agent_Default;

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
            " got " & Status_Image (Actual), Failed_State);
      end if;
   end Check_Status;

   procedure Run_Scenario
     (Scenario_Name       : String;
      Matrix_Failed_State : in out Boolean)
   is
      Host_Text        : constant String := Scenario_Env (Scenario_Name, "HOST");
      User_Text        : constant String := Scenario_Env (Scenario_Name, "USER");
      Repo_Text        : constant String := Scenario_Env (Scenario_Name, "REPO");
      Service_Text     : constant String := Scenario_Env (Scenario_Name, "SERVICE");
      Port_Text        : constant String := Scenario_Env (Scenario_Name, "PORT");
      Timeout_Text     : constant String := Scenario_Env (Scenario_Name, "TIMEOUT_MS");
      Known_Hosts_Text : constant String := Scenario_Env (Scenario_Name, "KNOWN_HOSTS");
      Identity_Text    : constant String := Scenario_Env (Scenario_Name, "IDENTITY");
      Password_Text    : constant String := Scenario_Env (Scenario_Name, "PASSWORD");
      Passphrase_Text  : constant String := Scenario_Env (Scenario_Name, "IDENTITY_PASSPHRASE");
      Proxy_Jump_Text  : constant String := Scenario_Env (Scenario_Name, "PROXY_JUMP");
      Use_Agent_Text   : constant String := Scenario_Env (Scenario_Name, "USE_AGENT");

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
      Scenario_Service  : Unbounded_String := To_Unbounded_String (Service_Text);
      Scenario_Metadata : Unbounded_String;
   begin
      Ada.Text_IO.Put_Line ("live Git matrix scenario: " & Scenario_Name);

      if not Is_Known_Scenario (Scenario_Name) then
         Fail ("unknown live Git matrix scenario: " & Scenario_Name, Failed_State);
      end if;

      if Host_Text'Length = 0 or else User_Text'Length = 0 or else Repo_Text'Length = 0 then
         Fail
           ("scenario " & Scenario_Name &
            " requires HOST, USER, and REPO values", Failed_State);
      end if;

      if Scenario_Name = "RECEIVE" and then Service_Text'Length = 0 then
         Scenario_Service := To_Unbounded_String ("receive-pack");
      elsif Service_Text'Length = 0 then
         Scenario_Service := To_Unbounded_String ("upload-pack");
      end if;

      if Scenario_Name = "IDENTITY" and then Identity_Text'Length = 0 then
         Fail ("scenario IDENTITY requires IDENTITY", Failed_State);
      end if;

      if Scenario_Name = "PASSWORD" and then Password_Text'Length = 0 then
         Fail ("scenario PASSWORD requires PASSWORD", Failed_State);
      end if;

      if Scenario_Name = "PASSPHRASE" then
         if Identity_Text'Length = 0 then
            Fail ("scenario PASSPHRASE requires IDENTITY", Failed_State);
         end if;
         if Passphrase_Text'Length = 0 then
            Fail
              ("scenario PASSPHRASE requires IDENTITY_PASSPHRASE", Failed_State);
         end if;
      end if;

      if Scenario_Name = "PROXYJUMP" and then Proxy_Jump_Text'Length = 0 then
         Fail ("scenario PROXYJUMP requires PROXY_JUMP", Failed_State);
      end if;

      if Failed_State then
         Report_Line
           ("scenario=" & Scenario_Name &
            " result=FAIL stage=preflight bytes=0 status=INVALID_CONFIG");
         Matrix_Failed_State := True;
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

      if Use_Agent_Text'Length /= 0 then
         Options.Use_Agent := Is_Enabled_Text (Use_Agent_Text);
      else
         Options.Use_Agent := Uses_Agent_Default (Scenario_Name);
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

      if Proxy_Jump_Text'Length /= 0 then
         Options.Proxy_Jump := To_Unbounded_String (Proxy_Jump_Text);
      end if;

      Scenario_Metadata := To_Unbounded_String
        (" service=" & To_String (Scenario_Service) &
         " verify_known_host=" & Report_Bool (Options.Verify_Known_Host) &
         " strict_host_key=" & Report_Bool (Options.Strict_Host_Key) &
         " use_agent=" & Report_Bool (Options.Use_Agent) &
         " identity_configured=" & Report_Bool (Identity_Text'Length /= 0) &
         " password_configured=" & Report_Bool (Password_Text'Length /= 0) &
         " passphrase_configured=" & Report_Bool (Passphrase_Text'Length /= 0) &
         " proxy_jump_configured=" & Report_Bool (Proxy_Jump_Text'Length /= 0));

      if To_String (Scenario_Service) = "receive-pack" then
         Status_Value := SSH_Lib.Git.Build_Receive_Pack_Command
           (Repo_Text, Command_Text);
      else
         Status_Value := SSH_Lib.Git.Build_Upload_Pack_Command
           (Repo_Text, Command_Text);
      end if;
      Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         Scenario_Name & " build Git service command", Failed_State);

      if not Failed_State then
         Status_Value := SSH_Lib.Sessions.Open (Options, Session_Item);
         Check_Status
           (Status_Value, CryptoLib.Errors.Ok,
            Scenario_Name & " open authenticated live session", Failed_State);
      end if;

      if not Failed_State then
         Session_Opened := True;
         Status_Value := SSH_Lib.Channels.Open_Exec
           (Session_Item, To_String (Command_Text), Channel_Item);
         Check_Status
           (Status_Value, CryptoLib.Errors.Ok,
            Scenario_Name & " open live Git exec channel", Failed_State);
         Channel_Opened := not Failed_State;
      end if;

      if not Failed_State then
         Status_Value := SSH_Lib.Channels.Write (Channel_Item, Flush_Request);
         Check_Status
           (Status_Value, CryptoLib.Errors.Ok,
            Scenario_Name & " write opaque Git flush packet", Failed_State);
      end if;

      if not Failed_State then
         Status_Value := SSH_Lib.Channels.Send_EOF (Channel_Item);
         Check_Status
           (Status_Value, CryptoLib.Errors.Ok,
            Scenario_Name & " send live channel EOF", Failed_State);
      end if;

      if not Failed_State then
         for Attempt_Index in 1 .. 16 loop
            Status_Value := SSH_Lib.Channels.Read_Some
              (Channel_Item, Read_Buffer, Last_Index);

            if Status_Value = CryptoLib.Errors.Ok then
               if Last_Index >= Read_Buffer'First then
                  Byte_Count := Byte_Count +
                    Natural (Last_Index - Read_Buffer'First + 1);
               end if;
            elsif Status_Value = CryptoLib.Errors.End_Of_Stream then
               exit;
            elsif Status_Value = CryptoLib.Errors.Timeout and then Byte_Count > 0 then
               exit;
            else
               Fail
                 (Scenario_Name & " read opaque Git response bytes got " &
                  Status_Image (Status_Value), Failed_State);
               exit;
            end if;
         end loop;

         if not Failed_State and then Byte_Count = 0 then
            Fail
              (Scenario_Name & " live Git service returned no stdout bytes",
               Failed_State);
         end if;
      end if;

      if Channel_Opened then
         Status_Value := SSH_Lib.Channels.Exit_Status (Channel_Item, Exit_Code);
         if Status_Value = CryptoLib.Errors.Ok and then Exit_Code = 0 then
            Ada.Text_IO.Put_Line
              (Scenario_Name & " exit-status observation: " &
               Status_Image (Status_Value) & ", code " & Report_Integer (Exit_Code));
         elsif Status_Value = CryptoLib.Errors.Ok then
            Fail
              (Scenario_Name & " live Git service returned nonzero exit code " &
               Report_Integer (Exit_Code), Failed_State);
         elsif Status_Value = CryptoLib.Errors.Remote_Exit_Nonzero then
            Fail
              (Scenario_Name & " live Git service reported nonzero remote exit code " &
               Report_Integer (Exit_Code), Failed_State);
         elsif Status_Value = CryptoLib.Errors.Channel_Request_Failed then
            Fail
              (Scenario_Name & " live Git service did not provide a successful exit-status request",
               Failed_State);
         else
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
         if Status_Value /= CryptoLib.Errors.Ok then
            Fail
              (Scenario_Name & " close session got " & Status_Image (Status_Value),
               Failed_State);
         end if;
      end if;

      Clear_Sensitive_Options (Options);

      if Failed_State then
         Report_Line
           ("scenario=" & Scenario_Name &
            " result=FAIL stage=runtime bytes=" & Report_Natural (Byte_Count) &
            " session_opened=" & Report_Bool (Session_Opened) &
            " channel_opened=" & Report_Bool (Channel_Opened) &
            " exit_code=" & Report_Integer (Exit_Code) &
            To_String (Scenario_Metadata));
         Matrix_Failed_State := True;
      else
         Report_Line
           ("scenario=" & Scenario_Name &
            " result=PASS stage=complete bytes=" & Report_Natural (Byte_Count) &
            " session_opened=" & Report_Bool (Session_Opened) &
            " channel_opened=" & Report_Bool (Channel_Opened) &
            " exit_code=" & Report_Integer (Exit_Code) &
            To_String (Scenario_Metadata));
         Ada.Text_IO.Put_Line
           ("PASS: " & Scenario_Name & " read opaque bytes:" &
            Report_Natural (Byte_Count));
      end if;
   end Run_Scenario;

   procedure Run_List
     (Scenario_List       : String;
      Matrix_Failed_State : in out Boolean)
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

         if Stop_Index > Start_Index then
            declare
               Scenario_Name : constant String := Canonical_Scenario_Name
                 (Scenario_List (Start_Index .. Stop_Index - 1));
            begin
               if Scenario_Name = "ALL" then
                  Run_Scenario ("DIRECT", Matrix_Failed_State);
                  Run_Scenario ("AGENT", Matrix_Failed_State);
                  Run_Scenario ("IDENTITY", Matrix_Failed_State);
                  Run_Scenario ("PASSWORD", Matrix_Failed_State);
                  Run_Scenario ("PASSPHRASE", Matrix_Failed_State);
                  Run_Scenario ("PROXYJUMP", Matrix_Failed_State);
                  Run_Scenario ("RECEIVE", Matrix_Failed_State);
               elsif Is_Known_Scenario (Scenario_Name) then
                  Run_Scenario (Scenario_Name, Matrix_Failed_State);
               elsif Scenario_Name'Length /= 0 then
                  Fail
                    ("unknown live Git matrix scenario in list: " &
                     Scenario_Name, Matrix_Failed_State);
               end if;
            end;
         end if;

         Start_Index := Stop_Index + 1;
      end loop;
   end Run_List;

   Enabled_Text : constant String := Env ("SSH_LIB_LIVE_GIT_MATRIX");
   Scenario_List_Text : constant String := Env ("SSH_LIB_LIVE_GIT_SCENARIOS");
   Matrix_Failed_State : Boolean := False;
begin
   Open_Report;
   if Report_Create_Failed then
      return;
   end if;
   Report_Line ("enabled=" & Report_Bool (Is_Enabled_Text (Enabled_Text)));
   Report_Line ("scenario_list=" & Scenario_List_Text);

   if not Is_Enabled_Text (Enabled_Text) then
      Ada.Text_IO.Put_Line
        ("live Git interoperability matrix skipped: set SSH_LIB_LIVE_GIT_MATRIX=1 to enable");
      Report_Line ("result=SKIP reason=disabled");
      Close_Report;
      return;
   end if;

   if Scenario_List_Text'Length = 0 then
      Ada.Text_IO.Put_Line
        ("SSH_LIB_LIVE_GIT_SCENARIOS is empty; defaulting to DIRECT");
      Run_Scenario ("DIRECT", Matrix_Failed_State);
   else
      Run_List (Scenario_List_Text, Matrix_Failed_State);
   end if;

   if Matrix_Failed_State then
      Report_Line ("result=FAIL");
      Close_Report;
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
   else
      Report_Line ("result=PASS");
      Close_Report;
      Ada.Text_IO.Put_Line ("live Git interoperability matrix passed");
   end if;
exception
   when others =>
      Report_Line ("result=FAIL reason=unhandled_exception");
      Close_Report;
      raise;
end Test_Live_Git_Interop_Matrix;
