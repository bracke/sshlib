with Ada.Command_Line;
with Ada.Directories;
with Ada.Environment_Variables;
with Ada.Strings.Fixed;
with Ada.Text_IO;
with GNAT.OS_Lib;
with GNAT.Strings;

procedure Run_SFTP_Fuzzer_Seed_Corpus is
   use type GNAT.Strings.String_Access;
   Failure_Count : Natural := 0;
   Passed_Count  : Natural := 0;
   Failed_Count  : Natural := 0;

   Harness_Path : constant String :=
     "ssh_lib_build/bin/tests_fuzz/sftp_packet_fuzzer";
   Seed_Root    : constant String :=
     "tests/vectors/sftp/packet_fuzzer_seeds";
   Report_Path  : constant String :=
     (if Ada.Environment_Variables.Exists ("SSH_LIB_SFTP_FUZZ_REPORT")
      then Ada.Environment_Variables.Value ("SSH_LIB_SFTP_FUZZ_REPORT")
      else "release_artifacts/sftp_fuzzer_seed_report.txt");

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

   function Exists_Executable (Path : String) return Boolean is
   begin
      return Ada.Directories.Exists (Path)
        or else Ada.Directories.Exists (Path & ".exe");
   end Exists_Executable;

   function Join_Path (Directory_Text : String; Name_Text : String) return String is
   begin
      if Directory_Text'Length = 0 then
         return Name_Text;
      elsif Directory_Text (Directory_Text'Last) = '/'
        or else Directory_Text (Directory_Text'Last) = '\'
      then
         return Directory_Text & Name_Text;
      else
         return Directory_Text & "/" & Name_Text;
      end if;
   end Join_Path;

   function Find_In_Path (Program_Name : String) return Boolean is
      Path_Text : constant String :=
        (if Ada.Environment_Variables.Exists ("PATH")
         then Ada.Environment_Variables.Value ("PATH")
         else "");
      Start_Index : Positive := Path_Text'First;
      Stop_Index  : Natural;
   begin
      if Exists_Executable (Program_Name) then
         return True;
      elsif Path_Text'Length = 0 then
         return False;
      end if;

      while Start_Index <= Path_Text'Last loop
         Stop_Index := Start_Index;
         while Stop_Index <= Path_Text'Last
           and then Path_Text (Stop_Index) /= ':'
           and then Path_Text (Stop_Index) /= ';'
         loop
            Stop_Index := Stop_Index + 1;
         end loop;

         declare
            Directory_Text : constant String :=
              Path_Text (Start_Index .. Stop_Index - 1);
         begin
            if Directory_Text'Length > 0
              and then Exists_Executable (Join_Path (Directory_Text, Program_Name))
            then
               return True;
            end if;
         end;

         Start_Index := Stop_Index + 1;
      end loop;
      return False;
   end Find_In_Path;

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

   procedure Build_Harness is
      Previous_Directory : constant String := Ada.Directories.Current_Directory;
   begin
      Ada.Directories.Set_Directory ("tests");
      if not Run_Command
        ("alr",
         [1 => new String'("exec"),
          2 => new String'("--"),
          3 => new String'("gprbuild"),
          4 => new String'("-P"),
          5 => new String'("fuzz/fuzz_tests.gpr")])
      then
         Fail ("failed to build SFTP packet fuzzer");
      end if;
      Ada.Directories.Set_Directory (Previous_Directory);
   exception
      when others =>
         Ada.Directories.Set_Directory (Previous_Directory);
         Fail ("exception while building SFTP packet fuzzer");
   end Build_Harness;

   procedure Run_Seed (Mode : String; Seed_Path : String; Label_Text : String) is
      Passed : constant Boolean :=
        Run_Command
          (Harness_Path,
           [1 => new String'(Mode),
            2 => new String'(Seed_Path)]);
   begin
      if Passed then
         Passed_Count := Passed_Count + 1;
         Report_Line ("seed=" & Label_Text & " mode=" & Mode & " result=PASS");
      else
         Failed_Count := Failed_Count + 1;
         Report_Line ("seed=" & Label_Text & " mode=" & Mode & " result=FAIL");
      end if;
   end Run_Seed;

   procedure Run_Root_Seeds is
      Search : Ada.Directories.Search_Type;
      Seed_Item : Ada.Directories.Directory_Entry_Type;
   begin
      Ada.Directories.Start_Search
        (Search, Seed_Root, "*.bin", [Ada.Directories.Ordinary_File => True, others => False]);
      while Ada.Directories.More_Entries (Search) loop
         Ada.Directories.Get_Next_Entry (Search, Seed_Item);
         declare
            Full_Path : constant String := Ada.Directories.Full_Name (Seed_Item);
            Name_Text : constant String := Ada.Directories.Simple_Name (Seed_Item);
         begin
            Run_Seed ("version", Full_Path, Name_Text);
         end;
      end loop;
      Ada.Directories.End_Search (Search);
   exception
      when others =>
         if Ada.Directories.More_Entries (Search) then
            Ada.Directories.End_Search (Search);
         end if;
         Fail ("failed while scanning root SFTP fuzzer seeds");
   end Run_Root_Seeds;

   procedure Run_Mode_Seeds is
      Directory_Search : Ada.Directories.Search_Type;
      Seed_Search      : Ada.Directories.Search_Type;
      Directory_Entry  : Ada.Directories.Directory_Entry_Type;
      Seed_Entry       : Ada.Directories.Directory_Entry_Type;
   begin
      Ada.Directories.Start_Search
        (Directory_Search, Seed_Root, "*", [Ada.Directories.Directory => True, others => False]);
      while Ada.Directories.More_Entries (Directory_Search) loop
         Ada.Directories.Get_Next_Entry (Directory_Search, Directory_Entry);
         declare
            Mode_Text : constant String := Ada.Directories.Simple_Name (Directory_Entry);
            Mode_Path : constant String := Ada.Directories.Full_Name (Directory_Entry);
         begin
            if Mode_Text /= "." and then Mode_Text /= ".." then
               Ada.Directories.Start_Search
                 (Seed_Search, Mode_Path, "*.bin", [Ada.Directories.Ordinary_File => True, others => False]);
               while Ada.Directories.More_Entries (Seed_Search) loop
                  Ada.Directories.Get_Next_Entry (Seed_Search, Seed_Entry);
                  declare
                     Seed_Path : constant String := Ada.Directories.Full_Name (Seed_Entry);
                     Label    : constant String :=
                       Mode_Text & "/" & Ada.Directories.Simple_Name (Seed_Entry);
                  begin
                     Run_Seed (Mode_Text, Seed_Path, Label);
                  end;
               end loop;
               Ada.Directories.End_Search (Seed_Search);
            end if;
         end;
      end loop;
      Ada.Directories.End_Search (Directory_Search);
   exception
      when others =>
         Fail ("failed while scanning mode SFTP fuzzer seeds");
   end Run_Mode_Seeds;

begin
   if Report_Path'Length > 0 then
      Ada.Text_IO.Create (Report_File, Ada.Text_IO.Out_File, Report_Path);
      Report_Line ("sftp_fuzzer_seed_report=1");
      Report_Line ("engine=seed-corpus");
      Report_Line ("afl_fuzz_available=" & (if Find_In_Path ("afl-fuzz") then "true" else "false"));
      Report_Line ("honggfuzz_available=" & (if Find_In_Path ("honggfuzz") then "true" else "false"));
      Report_Line ("cargo_afl_available=" & (if Find_In_Path ("cargo-afl") then "true" else "false"));
   end if;

   Build_Harness;
   if Failure_Count = 0 then
      Run_Root_Seeds;
      Run_Mode_Seeds;
   end if;

   Report_Line ("passed=" & Image (Passed_Count));
   Report_Line ("failed=" & Image (Failed_Count));
   Report_Line ("result=" & (if Failure_Count = 0 and then Failed_Count = 0 then "PASS" else "FAIL"));

   if Report_Path'Length > 0 and then Ada.Text_IO.Is_Open (Report_File) then
      Ada.Text_IO.Close (Report_File);
   end if;

   Ada.Text_IO.Put_Line
     ("SFTP fuzzer seed corpus: passed="
      & Image (Passed_Count) & " failed=" & Image (Failed_Count));

   if Failure_Count /= 0 or else Failed_Count /= 0 then
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
   end if;
exception
   when others =>
      if Report_Path'Length > 0 and then Ada.Text_IO.Is_Open (Report_File) then
         Ada.Text_IO.Close (Report_File);
      end if;
      Ada.Text_IO.Put_Line (Ada.Text_IO.Standard_Error, "FAIL: unhandled seed corpus runner exception");
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
end Run_SFTP_Fuzzer_Seed_Corpus;
