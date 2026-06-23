with Ada.Command_Line;
with Ada.Directories;
with Ada.Environment_Variables;
with Ada.Strings.Fixed;
with Ada.Text_IO;
with GNAT.OS_Lib;
with GNAT.Strings;

procedure Run_SFTP_V4_V6_Interop is
   use type GNAT.Strings.String_Access;
   Failure_Count : Natural := 0;
   Passed_Count  : Natural := 0;
   Failed_Count  : Natural := 0;

   function Env (Name : String; Default_Value : String := "") return String is
   begin
      if Ada.Environment_Variables.Exists (Name) then
         return Ada.Environment_Variables.Value (Name);
      else
         return Default_Value;
      end if;
   end Env;

   Versions_Text : constant String :=
     (if Env ("SSH_LIB_TEST_SFTP_V4_REQUEST_VERSIONS")'Length > 0
      then Env ("SSH_LIB_TEST_SFTP_V4_REQUEST_VERSIONS")
      elsif Env ("SSH_LIB_TEST_SFTP_V4_REQUEST_VERSION")'Length > 0
      then Env ("SSH_LIB_TEST_SFTP_V4_REQUEST_VERSION")
      else "4,5,6");
   Report_Path : constant String :=
     (if Env ("SSH_LIB_TEST_SFTP_V4_REPORT")'Length > 0
      then Env ("SSH_LIB_TEST_SFTP_V4_REPORT")
      else "release_artifacts/sftp_v4_v6_interop_report.txt");
   Report_File : Ada.Text_IO.File_Type;

   function Image (Value : Natural) return String is
   begin
      return Ada.Strings.Fixed.Trim (Natural'Image (Value), Ada.Strings.Both);
   end Image;

   procedure Fail (Message_Text : String) is
   begin
      Ada.Text_IO.Put_Line (Ada.Text_IO.Standard_Error, "FAIL: " & Message_Text);
      Failure_Count := Failure_Count + 1;
   end Fail;

   procedure Require_Env (Name : String) is
   begin
      if Env (Name)'Length = 0 then
         Fail ("set " & Name);
      end if;
   end Require_Env;

   procedure Report_Line (Line_Text : String) is
   begin
      if Report_Path'Length > 0 then
         Ada.Text_IO.Put_Line (Report_File, Line_Text);
      end if;
   end Report_Line;

   procedure Put_Command
     (Program_Name : String;
      Args         : GNAT.OS_Lib.Argument_List) is
   begin
      Ada.Text_IO.Put ("+ " & Program_Name);
      for Index in Args'Range loop
         if Args (Index) /= null then
            Ada.Text_IO.Put (" " & Args (Index).all);
         end if;
      end loop;
      Ada.Text_IO.New_Line;
   end Put_Command;

   function Run_Command
     (Program_Name : String;
      Args         : GNAT.OS_Lib.Argument_List) return Boolean
   is
      Located     : GNAT.Strings.String_Access := null;
      Result_Code : Integer;
   begin
      Put_Command (Program_Name, Args);
      if Ada.Strings.Fixed.Index (Program_Name, "/") = 0
        and then Ada.Strings.Fixed.Index (Program_Name, "\") = 0
      then
         Located := GNAT.OS_Lib.Locate_Exec_On_Path (Program_Name);
      end if;

      if Located /= null then
         Result_Code := GNAT.OS_Lib.Spawn (Located.all, Args);
         GNAT.Strings.Free (Located);
      else
         Result_Code := GNAT.OS_Lib.Spawn (Program_Name, Args);
      end if;
      return Result_Code = 0;
   end Run_Command;

   procedure Build_Tests is
      Previous_Directory : constant String := Ada.Directories.Current_Directory;
   begin
      Ada.Directories.Set_Directory ("tests");
      if not Run_Command ("alr", [1 => new String'("build")]) then
         Fail ("tests build failed");
      end if;
      Ada.Directories.Set_Directory (Previous_Directory);
   exception
      when others =>
         Ada.Directories.Set_Directory (Previous_Directory);
         Fail ("exception while building tests");
   end Build_Tests;

   function Valid_Version (Version_Text : String) return Boolean is
   begin
      return Version_Text in "3" | "4" | "5" | "6";
   end Valid_Version;

   procedure Run_Version (Version_Text : String) is
      Previous_Directory : constant String := Ada.Directories.Current_Directory;
      Passed             : Boolean;
   begin
      if not Valid_Version (Version_Text) then
         Fail ("unsupported SFTP version in SSH_LIB_TEST_SFTP_V4_REQUEST_VERSIONS: " & Version_Text);
         return;
      end if;

      Ada.Text_IO.Put_Line ("==> SFTP live interop requested version " & Version_Text);
      Ada.Environment_Variables.Set ("SSH_LIB_TEST_SFTP_V4_REQUEST_VERSION", Version_Text);
      Ada.Directories.Set_Directory ("tests");
      Passed := Run_Command
        ("alr",
         [1 => new String'("exec"),
          2 => new String'("--"),
          3 => new String'("./bin/main")]);
      Ada.Directories.Set_Directory (Previous_Directory);

      if Passed then
         Passed_Count := Passed_Count + 1;
         Ada.Text_IO.Put_Line ("==> SFTP live interop requested version " & Version_Text & ": PASS");
         Report_Line ("version=" & Version_Text & " result=PASS");
      else
         Failed_Count := Failed_Count + 1;
         Ada.Text_IO.Put_Line (Ada.Text_IO.Standard_Error,
           "==> SFTP live interop requested version " & Version_Text & ": FAIL");
         Report_Line ("version=" & Version_Text & " result=FAIL");
      end if;
   exception
      when others =>
         Ada.Directories.Set_Directory (Previous_Directory);
         Failed_Count := Failed_Count + 1;
         Report_Line ("version=" & Version_Text & " result=FAIL");
   end Run_Version;

   procedure Run_Version_List is
      Start_Index : Positive := Versions_Text'First;
      Stop_Index  : Natural;
   begin
      while Start_Index <= Versions_Text'Last loop
         Stop_Index := Start_Index;
         while Stop_Index <= Versions_Text'Last
           and then Versions_Text (Stop_Index) /= ','
           and then Versions_Text (Stop_Index) /= ' '
         loop
            Stop_Index := Stop_Index + 1;
         end loop;

         if Stop_Index > Start_Index then
            Run_Version (Versions_Text (Start_Index .. Stop_Index - 1));
         end if;
         Start_Index := Stop_Index + 1;
      end loop;
   end Run_Version_List;

begin
   Require_Env ("SSH_LIB_TEST_SFTP_V4_HOST");
   Require_Env ("SSH_LIB_TEST_SFTP_V4_USER");
   Require_Env ("SSH_LIB_TEST_SFTP_V4_IDENTITY_FILE");
   Require_Env ("SSH_LIB_TEST_SFTP_V4_FILE");

   Ada.Environment_Variables.Set ("SSH_LIB_TEST_SFTP_V4_ENABLE", "1");
   if Env ("SSH_LIB_TEST_SFTP_V4_PORT")'Length = 0 then
      Ada.Environment_Variables.Set ("SSH_LIB_TEST_SFTP_V4_PORT", "22");
   end if;

   if Report_Path'Length > 0 then
      Ada.Text_IO.Create (Report_File, Ada.Text_IO.Out_File, Report_Path);
      Report_Line ("sftp_v4_v6_interop_report=1");
      Report_Line ("enabled=true");
      Report_Line ("requested_versions=" & Versions_Text);
      Report_Line ("host_configured=true");
      Report_Line ("identity_configured=true");
   end if;

   if Failure_Count = 0 then
      Build_Tests;
   end if;
   if Failure_Count = 0 then
      Run_Version_List;
   end if;

   Ada.Text_IO.Put_Line
     ("SFTP live interop matrix: " & Image (Passed_Count)
      & " passed," & Image (Failed_Count) & " failed");
   Report_Line ("passed=" & Image (Passed_Count));
   Report_Line ("failed=" & Image (Failed_Count));
   Report_Line ("result=" & (if Failure_Count = 0 and then Failed_Count = 0 then "PASS" else "FAIL"));

   if Report_Path'Length > 0 and then Ada.Text_IO.Is_Open (Report_File) then
      Ada.Text_IO.Close (Report_File);
   end if;

   if Failure_Count /= 0 or else Failed_Count /= 0 then
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
   end if;
exception
   when others =>
      if Report_Path'Length > 0 and then Ada.Text_IO.Is_Open (Report_File) then
         Ada.Text_IO.Close (Report_File);
      end if;
      Ada.Text_IO.Put_Line (Ada.Text_IO.Standard_Error, "FAIL: unhandled SFTP v4-v6 interop runner exception");
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
end Run_SFTP_V4_V6_Interop;
