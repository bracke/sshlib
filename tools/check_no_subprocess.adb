with Ada.Command_Line;
with Ada.Directories;
with Ada.Strings;
with Ada.Strings.Fixed;
with Ada.Strings.Maps.Constants;
with Ada.Strings.Unbounded;
with Ada.Text_IO;

procedure Check_No_Subprocess is
   use Ada.Strings.Fixed;
   use type Ada.Directories.File_Kind;
   use Ada.Strings.Unbounded;

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

   function Is_Name_Char (Value : Character) return Boolean is
   begin
      return Value in 'A' .. 'Z'
        or else Value in 'a' .. 'z'
        or else Value in '0' .. '9'
        or else Value = '_';
   end Is_Name_Char;

   function Contains_Call (Line_Text : String; Name_Text : String) return Boolean is
      Lower_Line : constant String := Lower (Line_Text);
      Position   : Natural := Index (Lower_Line, Name_Text);
      After_Name : Natural;
   begin
      while Position /= 0 loop
         if (Position = Lower_Line'First
             or else not Is_Name_Char (Lower_Line (Position - 1)))
           and then (Position + Name_Text'Length > Lower_Line'Last
                     or else not Is_Name_Char
                       (Lower_Line (Position + Name_Text'Length)))
         then
            After_Name := Position + Name_Text'Length;
            while After_Name <= Lower_Line'Last
              and then Lower_Line (After_Name) = ' '
            loop
               After_Name := After_Name + 1;
            end loop;

            if After_Name <= Lower_Line'Last
              and then Lower_Line (After_Name) = '('
            then
               return True;
            end if;
         end if;
         Position := Index (Lower_Line, Name_Text, Position + 1);
      end loop;
      return False;
   end Contains_Call;

   function Starts_With (Value : String; Prefix : String) return Boolean is
   begin
      return Value'Length >= Prefix'Length
        and then Value (Value'First .. Value'First + Prefix'Length - 1) = Prefix;
   end Starts_With;

   function Active_Text (Line_Text : String) return String is
      In_String : Boolean := False;
      Position  : Natural := Line_Text'First;
   begin
      if Line_Text'Length = 0 then
         return "";
      end if;

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
           and then Line_Text (Position) = '-'
           and then Position < Line_Text'Last
           and then Line_Text (Position + 1) = '-'
         then
            if Position = Line_Text'First then
               return "";
            else
               return Line_Text (Line_Text'First .. Position - 1);
            end if;
         else
            Position := Position + 1;
         end if;
      end loop;

      return Line_Text;
   end Active_Text;

   function Has_Subprocess_API (Line_Text : String) return Boolean is
      Lower_Line : constant String := Lower (Line_Text);
   begin
      return Index (Lower_Line, "gnat.os_lib.spawn") /= 0
        or else Index (Lower_Line, "non_blocking_spawn") /= 0
        or else Index (Lower_Line, "gnat.expect") /= 0
        or else Contains_Call (Line_Text, "spawn")
        or else Contains_Call (Line_Text, "popen")
        or else Contains_Call (Line_Text, "system")
        or else Contains_Call (Line_Text, "exec")
        or else Contains_Call (Line_Text, "execve")
        or else Contains_Call (Line_Text, "create_process")
        or else Index (Lower_Line, "local_exec") /= 0
        or else Index (Lower_Line, "process_execution") /= 0
        or else Index (Lower_Line, "/bin/sh") /= 0
        or else Index (Lower_Line, "cmd.exe") /= 0;
   end Has_Subprocess_API;

   function Is_Command_Literal (Value : String) return Boolean is
      Clean_Value : constant String := Lower (Trim (Value, Ada.Strings.Both));
   begin
      return Clean_Value = "ssh-agent"
        or else Clean_Value = "ssh-add"
        or else Starts_With (Clean_Value, "ssh-agent ")
        or else Starts_With (Clean_Value, "ssh-add ")
        or else Index (Clean_Value, "/bin/sh") /= 0
        or else Index (Clean_Value, "cmd.exe") /= 0
        or else Index (Clean_Value, "powershell") /= 0;
   end Is_Command_Literal;

   function Has_Command_Literal (Line_Text : String) return Boolean is
      Position : Natural := Line_Text'First;
   begin
      if Line_Text'Length = 0 then
         return False;
      end if;

      while Position <= Line_Text'Last loop
         if Line_Text (Position) = '"' then
            declare
               Literal_Text : Unbounded_String := Null_Unbounded_String;
            begin
               Position := Position + 1;
               while Position <= Line_Text'Last loop
                  if Line_Text (Position) = '"' then
                     if Position < Line_Text'Last
                       and then Line_Text (Position + 1) = '"'
                     then
                        Append (Literal_Text, '"');
                        Position := Position + 2;
                     else
                        exit;
                     end if;
                  else
                     Append (Literal_Text, Line_Text (Position));
                     Position := Position + 1;
                  end if;
               end loop;

               if Is_Command_Literal (To_String (Literal_Text)) then
                  return True;
               end if;
            end;
         end if;

         exit when Position > Line_Text'Last;
         Position := Position + 1;
      end loop;
      return False;
   end Has_Command_Literal;

   function Line_Has_Forbidden_Subprocess (Line_Text : String) return Boolean is
      Scan_Line : constant String := Active_Text (Line_Text);
   begin
      return Has_Subprocess_API (Scan_Line)
        or else Has_Command_Literal (Scan_Line);
   end Line_Has_Forbidden_Subprocess;

   procedure Scan_String_Literals
     (Path        : String;
      Line_Number : Natural;
      Line_Text   : String)
   is
   begin
      if Has_Command_Literal (Line_Text) then
         Fail
           ("local subprocess command literal in source: "
            & Path & ":" & Natural'Image (Line_Number));
      end if;
   end Scan_String_Literals;

   function Is_Ada_Or_Project_File (Name_Text : String) return Boolean is
      Lower_Name : constant String := Lower (Name_Text);
   begin
      return (Lower_Name'Length >= 4
              and then (Lower_Name (Lower_Name'Last - 3 .. Lower_Name'Last) = ".adb"
                        or else Lower_Name (Lower_Name'Last - 3 .. Lower_Name'Last) = ".ads"))
        or else (Lower_Name'Length >= 4
                 and then Lower_Name (Lower_Name'Last - 3 .. Lower_Name'Last) = ".gpr");
   end Is_Ada_Or_Project_File;

   function Is_Excluded_Audit_File (Name_Text : String) return Boolean is
      Lower_Name : constant String := Lower (Name_Text);
   begin
      return Lower_Name = "check_no_subprocess.adb"
        or else Lower_Name = "check_security.adb"
        or else Lower_Name = "check_release.adb"
        or else Lower_Name = "check_phase19_context.adb"
        or else Lower_Name = "check_release_runner.adb"
        or else Lower_Name = "run_release_validation.adb"
        or else Lower_Name = "run_sftp_v4_v6_interop.adb"
        or else Lower_Name = "run_sftp_fuzzer_seed_corpus.adb"
        or else Lower_Name = "local_sshd_fixture.adb";
   end Is_Excluded_Audit_File;

   function Is_Explicit_Subprocess_Boundary_File (Path : String) return Boolean is
      Lower_Path : constant String := Lower (Path);
   begin
      return Lower_Path = "src/ssh_lib-sessions-live_transcript.adb"
        or else Lower_Path = "src/ssh_lib-sessions-live_transcript.ads"
        or else Lower_Path = "src/ssh_lib-git.adb";
   end Is_Explicit_Subprocess_Boundary_File;

   procedure Scan_File (Path : String) is
      File_Item   : Ada.Text_IO.File_Type;
      Line_Number : Natural := 0;
   begin
      Ada.Text_IO.Open (File_Item, Ada.Text_IO.In_File, Path);
      while not Ada.Text_IO.End_Of_File (File_Item) loop
         declare
            Raw_Line  : constant String := Ada.Text_IO.Get_Line (File_Item);
            Scan_Line : constant String := Active_Text (Raw_Line);
         begin
            Line_Number := Line_Number + 1;
            if not Is_Explicit_Subprocess_Boundary_File (Path) then
               if Has_Subprocess_API (Scan_Line) then
                  Fail
                    ("subprocess API token in source: "
                     & Path & ":" & Natural'Image (Line_Number));
               end if;
               Scan_String_Literals (Path, Line_Number, Scan_Line);
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
      Entry_Item  : Ada.Directories.Directory_Entry_Type;
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
               if Name_Text /= "."
                 and then Name_Text /= ".."
                 and then Name_Text /= "obj"
                 and then Name_Text /= "bin"
                 and then Name_Text /= ".git"
               then
                  Scan_Tree (Path_Text);
               end if;
            elsif Is_Ada_Or_Project_File (Name_Text)
              and then not Is_Excluded_Audit_File (Name_Text)
            then
               Scan_File (Path_Text);
            end if;
         end;
      end loop;
      Ada.Directories.End_Search (Search_Item);
   exception
      when others =>
         Fail ("unable to scan directory: " & Directory_Path);
   end Scan_Tree;

   procedure Assert_Blocked (Line_Text : String; Name_Text : String) is
   begin
      if not Line_Has_Forbidden_Subprocess (Line_Text) then
         Fail ("self-test did not block subprocess fixture: " & Name_Text);
      end if;
   end Assert_Blocked;

   procedure Assert_Allowed (Line_Text : String; Name_Text : String) is
   begin
      if Line_Has_Forbidden_Subprocess (Line_Text) then
         Fail ("self-test rejected allowed fixture: " & Name_Text);
      end if;
   end Assert_Allowed;

   procedure Run_Self_Tests is
   begin
      Assert_Blocked ("Result := GNAT.OS_Lib.Spawn (Program_Name, Args);", "GNAT.OS_Lib.Spawn");
      Assert_Blocked ("Status := Spawn (Command, Args);", "bare Spawn call");
      Assert_Blocked ("Value := Popen (Command);", "popen call");
      Assert_Blocked ("Code := System (Command);", "system call");
      Assert_Blocked ("Run (""ssh-agent"" & Suffix);", "ssh-agent literal");
      Assert_Blocked ("Run (""ssh-add -l"");", "ssh-add literal");
      Assert_Blocked ("Shell := ""/bin/sh"";", "Unix shell literal");
      Assert_Blocked ("Shell := ""cmd.exe"";", "Windows shell literal");
      Assert_Blocked ("Shell := ""powershell -NoProfile"";", "PowerShell literal");

      Assert_Allowed ("Command := ""git-upload-pack '"" & Repo & ""'"";", "remote git command data");
      Assert_Allowed ("Directive := ""ProxyCommand none"";", "config directive text");
      Assert_Allowed ("Status := SSH_Lib.Channels.Open_Exec (Session, Command, Channel);", "remote Open_Exec API");
      Assert_Allowed ("-- GNAT.OS_Lib.Spawn must not be used", "policy comment");

      if Failure_Count = 0 then
         Ada.Text_IO.Put_Line ("no-subprocess self-tests passed");
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
           ("subprocess guard passed for src/examples/tests/tools with audit-tool exclusions");
      end if;
   end if;

   if Failure_Count /= 0 then
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
   end if;
end Check_No_Subprocess;
