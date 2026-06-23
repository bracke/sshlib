with Ada.Command_Line;
with Ada.Directories;
with Ada.Strings.Fixed;
with Ada.Strings.Maps.Constants;
with Ada.Text_IO;

procedure Check_Sensitive_Logging is
   use Ada.Strings.Fixed;
   use type Ada.Directories.File_Kind;

   Failure_Count : Natural := 0;

   procedure Fail (Message_Text : String) is
   begin
      Ada.Text_IO.Put_Line ("FAIL: " & Message_Text);
      Failure_Count := Failure_Count + 1;
   end Fail;

   function Lower (Value : String) return String is
   begin
      return Translate (Value, Ada.Strings.Maps.Constants.Lower_Case_Map);
   end Lower;

   function Has_Suffix (Value : String; Suffix : String) return Boolean is
   begin
      return Value'Length >= Suffix'Length
        and then Value (Value'Last - Suffix'Length + 1 .. Value'Last) = Suffix;
   end Has_Suffix;

   function Is_Ada_Source (Name_Text : String) return Boolean is
      Lower_Name : constant String := Lower (Name_Text);
   begin
      return Has_Suffix (Lower_Name, ".adb")
        or else Has_Suffix (Lower_Name, ".ads");
   end Is_Ada_Source;

   function Is_Excluded_Audit_Tool (Path : String) return Boolean is
      Lower_Path : constant String := Lower (Path);
   begin
      return Index (Lower_Path, "tools/check_sensitive_logging.adb") /= 0
        or else Index (Lower_Path, "tools/check_security.adb") /= 0
        or else Index (Lower_Path, "tools/check_release.adb") /= 0
        or else Index (Lower_Path, "tools/check_no_subprocess.adb") /= 0
        or else Index (Lower_Path, "tools/check_binary_paths.adb") /= 0
        or else Index (Lower_Path, "tools/check_phase19_context.adb") /= 0;
   end Is_Excluded_Audit_Tool;

   function Strip_Comment_Outside_String (Line_Text : String) return String is
      Result : String := Line_Text;
      In_String : Boolean := False;
      Position : Natural := Line_Text'First;
   begin
      while Position <= Line_Text'Last loop
         if Line_Text (Position) = '"' then
            if In_String
              and then Position < Line_Text'Last
              and then Line_Text (Position + 1) = '"'
            then
               Position := Position + 2;
            else
               In_String := not In_String;
               Position := Position + 1;
            end if;
         elsif not In_String
           and then Position < Line_Text'Last
           and then Line_Text (Position .. Position + 1) = "--"
         then
            for Index_Value in Position .. Line_Text'Last loop
               Result (Index_Value) := ' ';
            end loop;
            return Result;
         else
            Position := Position + 1;
         end if;
      end loop;
      return Result;
   end Strip_Comment_Outside_String;

   function Has_Output_Or_Log_Sink (Lower_Line : String) return Boolean is
   begin
      return Index (Lower_Line, "put_line") /= 0
        or else Index (Lower_Line, "put (") /= 0
        or else Index (Lower_Line, "put_error") /= 0
        or else Index (Lower_Line, "trace (") /= 0
        or else Index (Lower_Line, ".trace") /= 0
        or else Index (Lower_Line, "debug (") /= 0
        or else Index (Lower_Line, ".debug") /= 0
        or else Index (Lower_Line, "logger") /= 0
        or else Index (Lower_Line, ".log") /= 0
        or else Index (Lower_Line, " log (") /= 0
        or else Index (Lower_Line, "log_line") /= 0
        or else Index (Lower_Line, "diagnostic (") /= 0;
   end Has_Output_Or_Log_Sink;

   function Has_Sensitive_Token (Lower_Line : String) return Boolean is
   begin
      return Index (Lower_Line, "private key") /= 0
        or else Index (Lower_Line, "private_key") /= 0
        or else Index (Lower_Line, "private-key") /= 0
        or else Index (Lower_Line, "session key") /= 0
        or else Index (Lower_Line, "session_key") /= 0
        or else Index (Lower_Line, "shared secret") /= 0
        or else Index (Lower_Line, "shared_secret") /= 0
        or else Index (Lower_Line, "signature payload") /= 0
        or else Index (Lower_Line, "signature_payload") /= 0
        or else Index (Lower_Line, "agent signature") /= 0
        or else Index (Lower_Line, "agent_signature") /= 0
        or else Index (Lower_Line, "identity seed") /= 0
        or else Index (Lower_Line, "identity_seed") /= 0
        or else Index (Lower_Line, "password") /= 0
        or else Index (Lower_Line, "passphrase") /= 0
        or else Index (Lower_Line, "secret") /= 0;
   end Has_Sensitive_Token;

   function Has_Explicit_Redaction (Lower_Line : String) return Boolean is
   begin
      return Index (Lower_Line, "redact") /= 0
        or else Index (Lower_Line, "redacted") /= 0
        or else Index (Lower_Line, "<redacted>") /= 0
        or else Index (Lower_Line, "safe_for_log") /= 0;
   end Has_Explicit_Redaction;

   function Has_Diagnostic_Exception (Lower_Line : String) return Boolean is
   begin
      return Index (Lower_Line, "diagnostic") /= 0
        and then (Index (Lower_Line, "status") /= 0
                  or else Index (Lower_Line, "category") /= 0
                  or else Index (Lower_Line, "summary") /= 0)
        and then not Has_Sensitive_Token (Lower_Line);
   end Has_Diagnostic_Exception;

   function Line_Has_Sensitive_Logging
     (Line_Text          : String;
      Previous_Line_Text : String := "")
      return Boolean
   is
      Code_Line : constant String := Strip_Comment_Outside_String (Line_Text);
      Lower_Line : constant String := Lower (Code_Line);
      Joined_Line : constant String :=
        (if Previous_Line_Text'Length = 0
         then Lower_Line
         else Lower (Strip_Comment_Outside_String (Previous_Line_Text)) & " " & Lower_Line);
   begin
      return
        ((Has_Output_Or_Log_Sink (Lower_Line)
          and then Has_Sensitive_Token (Lower_Line)
          and then not Has_Explicit_Redaction (Lower_Line)
          and then not Has_Diagnostic_Exception (Lower_Line))
         or else
         (Has_Output_Or_Log_Sink (Joined_Line)
          and then Has_Sensitive_Token (Joined_Line)
          and then not Has_Explicit_Redaction (Joined_Line)
          and then not Has_Diagnostic_Exception (Joined_Line)));
   end Line_Has_Sensitive_Logging;

   procedure Scan_File (Path : String) is
      File_Item : Ada.Text_IO.File_Type;
      Line_Number : Natural := 0;
      Previous_Code_Line : String (1 .. 512) := [others => ' '];
      Previous_Last : Natural := 0;
   begin
      if Is_Excluded_Audit_Tool (Path) then
         return;
      end if;

      Ada.Text_IO.Open (File_Item, Ada.Text_IO.In_File, Path);
      while not Ada.Text_IO.End_Of_File (File_Item) loop
         declare
            Line_Text : constant String := Ada.Text_IO.Get_Line (File_Item);
            Code_Line : constant String := Strip_Comment_Outside_String (Line_Text);
         begin
            Line_Number := Line_Number + 1;

            if Line_Has_Sensitive_Logging
                 (Line_Text          => Line_Text,
                  Previous_Line_Text =>
                    (if Previous_Last = 0 then "" else Previous_Code_Line (1 .. Previous_Last)))
            then
               Fail
                 ("possible sensitive logging sink: "
                  & Path & ":" & Natural'Image (Line_Number));
            end if;

            Previous_Last := Natural'Min (Code_Line'Length, Previous_Code_Line'Length);
            if Previous_Last > 0 then
               Previous_Code_Line (1 .. Previous_Last) := Code_Line (Code_Line'First .. Code_Line'First + Previous_Last - 1);
            end if;
         end;
      end loop;
      Ada.Text_IO.Close (File_Item);
   exception
      when others =>
         if Ada.Text_IO.Is_Open (File_Item) then
            Ada.Text_IO.Close (File_Item);
         end if;
         Fail ("unable to scan source: " & Path);
   end Scan_File;

   procedure Scan_Tree (Directory_Path : String) is
      Search_Item : Ada.Directories.Search_Type;
      Entry_Item : Ada.Directories.Directory_Entry_Type;
   begin
      if not Ada.Directories.Exists (Directory_Path) then
         return;
      end if;

      Ada.Directories.Start_Search
        (Search    => Search_Item,
         Directory => Directory_Path,
         Pattern   => "*",
         Filter    => [Ada.Directories.Ordinary_File => True,
                       Ada.Directories.Directory => True,
                       Ada.Directories.Special_File => False]);
      while Ada.Directories.More_Entries (Search_Item) loop
         Ada.Directories.Get_Next_Entry (Search_Item, Entry_Item);
         declare
            Path_Text : constant String := Ada.Directories.Full_Name (Entry_Item);
            Name_Text : constant String := Ada.Directories.Simple_Name (Entry_Item);
         begin
            if Ada.Directories.Kind (Entry_Item) = Ada.Directories.Directory then
               if Name_Text /= "." and then Name_Text /= ".." then
                  Scan_Tree (Path_Text);
               end if;
            elsif Is_Ada_Source (Name_Text) then
               Scan_File (Path_Text);
            end if;
         end;
      end loop;
      Ada.Directories.End_Search (Search_Item);
   exception
      when others =>
         Fail ("unable to scan directory: " & Directory_Path);
   end Scan_Tree;

   procedure Assert_Blocked
     (Line_Text          : String;
      Name_Text          : String;
      Previous_Line_Text : String := "")
   is
   begin
      if not Line_Has_Sensitive_Logging (Line_Text, Previous_Line_Text) then
         Fail ("self-test did not block sensitive logging fixture: " & Name_Text);
      end if;
   end Assert_Blocked;

   procedure Assert_Allowed
     (Line_Text          : String;
      Name_Text          : String;
      Previous_Line_Text : String := "")
   is
   begin
      if Line_Has_Sensitive_Logging (Line_Text, Previous_Line_Text) then
         Fail ("self-test rejected allowed logging fixture: " & Name_Text);
      end if;
   end Assert_Allowed;

   procedure Run_Self_Tests is
   begin
      Assert_Blocked ("Ada.Text_IO.Put_Line (""private key="" & Key_Text);", "private key Put_Line");
      Assert_Blocked ("Debug (""shared_secret="" & Secret_Text);", "shared_secret debug");
      Assert_Blocked ("Logger.Log (""signature-payload"" & Payload_Text);", "signature-payload log");
      Assert_Blocked ("Diagnostic (""agent signature"" & Signature_Text);", "agent signature diagnostic");
      Assert_Blocked
        (Line_Text          => "   & Password_Text);",
         Previous_Line_Text => "Ada.Text_IO.Put_Line (""password: """,
         Name_Text          => "multiline password sink");

      Assert_Allowed ("Ada.Text_IO.Put_Line (""private key <redacted>"");", "redacted private key");
      Assert_Allowed ("Safe_For_Log (""shared_secret"");", "safe_for_log marker");
      Assert_Allowed ("Diagnostic (""status category summary"");", "diagnostic status summary");
      Assert_Allowed ("-- Ada.Text_IO.Put_Line (""password"");", "commented policy text");
      Assert_Allowed ("Payload_Label := ""signature payload"";", "non-output label");

      if Failure_Count = 0 then
         Ada.Text_IO.Put_Line ("sensitive-logging self-tests passed");
      end if;
   end Run_Self_Tests;

begin
   if Ada.Command_Line.Argument_Count = 1
     and then Ada.Command_Line.Argument (1) = "--self-test"
   then
      Run_Self_Tests;
   else
      Scan_Tree ("src");
      Scan_Tree ("examples");
      Scan_Tree ("tests");
      Scan_Tree ("tools");

      if Failure_Count = 0 then
         Ada.Text_IO.Put_Line
           ("sensitive logging guard passed: src/examples/tests/non-audit-tools scanned");
      end if;
   end if;

   if Failure_Count /= 0 then
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
   end if;
end Check_Sensitive_Logging;
