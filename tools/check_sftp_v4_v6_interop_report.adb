with Ada.Command_Line;
with Ada.Directories;
with Ada.Environment_Variables;
with Ada.Strings.Fixed;
with Ada.Text_IO;

procedure Check_SFTP_V4_V6_Interop_Report is
   use Ada.Strings.Fixed;

   Failure_Count : Natural := 0;

   function Env (Name : String; Default_Value : String := "") return String is
   begin
      if Ada.Environment_Variables.Exists (Name) then
         return Ada.Environment_Variables.Value (Name);
      else
         return Default_Value;
      end if;
   end Env;

   function Enabled (Value : String) return Boolean is
   begin
      return Value = "1" or else Value = "true" or else Value = "TRUE"
        or else Value = "yes" or else Value = "YES";
   end Enabled;

   procedure Fail (Message_Text : String) is
   begin
      Ada.Text_IO.Put_Line (Ada.Text_IO.Standard_Error, "FAIL: " & Message_Text);
      Failure_Count := Failure_Count + 1;
   end Fail;

   function File_Contains_Line (Path : String; Needle : String) return Boolean is
      File_Item : Ada.Text_IO.File_Type;
   begin
      Ada.Text_IO.Open (File_Item, Ada.Text_IO.In_File, Path);
      while not Ada.Text_IO.End_Of_File (File_Item) loop
         if Ada.Text_IO.Get_Line (File_Item) = Needle then
            Ada.Text_IO.Close (File_Item);
            return True;
         end if;
      end loop;
      Ada.Text_IO.Close (File_Item);
      return False;
   exception
      when others =>
         if Ada.Text_IO.Is_Open (File_Item) then
            Ada.Text_IO.Close (File_Item);
         end if;
         return False;
   end File_Contains_Line;

   function File_Contains_Text (Path : String; Needle : String) return Boolean is
      File_Item : Ada.Text_IO.File_Type;
   begin
      Ada.Text_IO.Open (File_Item, Ada.Text_IO.In_File, Path);
      while not Ada.Text_IO.End_Of_File (File_Item) loop
         if Index (Ada.Text_IO.Get_Line (File_Item), Needle) /= 0 then
            Ada.Text_IO.Close (File_Item);
            return True;
         end if;
      end loop;
      Ada.Text_IO.Close (File_Item);
      return False;
   exception
      when others =>
         if Ada.Text_IO.Is_Open (File_Item) then
            Ada.Text_IO.Close (File_Item);
         end if;
         return False;
   end File_Contains_Text;

   function Count_Lines (Path : String; Needle : String) return Natural is
      File_Item : Ada.Text_IO.File_Type;
      Count     : Natural := 0;
   begin
      Ada.Text_IO.Open (File_Item, Ada.Text_IO.In_File, Path);
      while not Ada.Text_IO.End_Of_File (File_Item) loop
         if Ada.Text_IO.Get_Line (File_Item) = Needle then
            Count := Count + 1;
         end if;
      end loop;
      Ada.Text_IO.Close (File_Item);
      return Count;
   exception
      when others =>
         if Ada.Text_IO.Is_Open (File_Item) then
            Ada.Text_IO.Close (File_Item);
         end if;
         return 0;
   end Count_Lines;

   procedure Require_Line (Path : String; Line_Text : String) is
   begin
      if not File_Contains_Line (Path, Line_Text) then
         Fail ("missing report line: " & Line_Text);
      end if;
   end Require_Line;

   procedure Reject_Text (Path : String; Needle : String) is
   begin
      if File_Contains_Text (Path, Needle) then
         Fail ("forbidden report text: " & Needle);
      end if;
   end Reject_Text;

   procedure Check_Version_List (Report_Path : String; Versions : String) is
      Start_Index : Positive := Versions'First;
      Stop_Index  : Natural;
   begin
      if Versions'Length = 0 then
         return;
      end if;

      while Start_Index <= Versions'Last loop
         Stop_Index := Start_Index;
         while Stop_Index <= Versions'Last
           and then Versions (Stop_Index) /= ','
           and then Versions (Stop_Index) /= ' '
         loop
            Stop_Index := Stop_Index + 1;
         end loop;

         if Stop_Index > Start_Index then
            declare
               Version_Text : constant String := Versions (Start_Index .. Stop_Index - 1);
            begin
               if Version_Text not in "3" | "4" | "5" | "6" then
                  Fail ("unsupported required SFTP version: " & Version_Text);
               elsif Count_Lines
                 (Report_Path, "version=" & Version_Text & " result=PASS") /= 1
               then
                  Fail ("expected exactly one passing report record for SFTP version " & Version_Text);
               end if;
            end;
         end if;

         Start_Index := Stop_Index + 1;
      end loop;
   end Check_Version_List;

   Require_Enabled : constant Boolean := Enabled (Env ("SSH_LIB_REQUIRE_SFTP_V4_REPORT", "0"));
   Default_Report_Path : constant String :=
     "release_artifacts/sftp_v4_v6_interop_report.txt";
   Report_Path : constant String :=
     (if Env ("SSH_LIB_TEST_SFTP_V4_REPORT")'Length > 0
      then Env ("SSH_LIB_TEST_SFTP_V4_REPORT")
      elsif Env ("SSH_LIB_SFTP_V4_REPORT")'Length > 0
      then Env ("SSH_LIB_SFTP_V4_REPORT")
      else Default_Report_Path);
   Required_Versions : constant String :=
     (if Env ("SSH_LIB_REQUIRED_SFTP_V4_VERSIONS")'Length > 0
      then Env ("SSH_LIB_REQUIRED_SFTP_V4_VERSIONS")
      elsif Env ("SSH_LIB_TEST_SFTP_V4_REQUEST_VERSIONS")'Length > 0
      then Env ("SSH_LIB_TEST_SFTP_V4_REQUEST_VERSIONS")
      else "4,5,6");
begin
   if not Require_Enabled then
      Ada.Text_IO.Put_Line ("SKIP: SSH_LIB_REQUIRE_SFTP_V4_REPORT is not enabled");
      return;
   elsif not Ada.Directories.Exists (Report_Path) then
      Fail ("missing SFTP v4-v6 interop report: " & Report_Path);
   else
      Require_Line (Report_Path, "sftp_v4_v6_interop_report=1");
      Require_Line (Report_Path, "enabled=true");
      Require_Line (Report_Path, "result=PASS");
      Reject_Text (Report_Path, "result=FAIL");
      Reject_Text (Report_Path, "result=SKIP");
      Check_Version_List (Report_Path, Required_Versions);
   end if;

   if Failure_Count = 0 then
      Ada.Text_IO.Put_Line ("PASS: SFTP v4-v6 interop report accepted: " & Report_Path);
   else
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
   end if;
end Check_SFTP_V4_V6_Interop_Report;
