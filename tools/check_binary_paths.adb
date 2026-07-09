with Ada.Command_Line;
with Ada.Directories;
with Ada.Strings.Fixed;
with Ada.Strings.Maps.Constants;
with Ada.Strings.Unbounded;
with Ada.Text_IO;

with Project_Tools.Files;

procedure Check_Binary_Paths is
   use Ada.Strings.Fixed;
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

   function Should_Scan (Name_Text : String) return Boolean is
      Lower_Name : constant String := Lower (Name_Text);
   begin
      return Index (Lower_Name, "channel") /= 0
        or else Index (Lower_Name, "packet") /= 0
        or else Index (Lower_Name, "agent") /= 0
        or else Index (Lower_Name, "identity") /= 0
        or else Index (Lower_Name, "known_hosts") /= 0;
   end Should_Scan;

   procedure Scan_File (Path : String) is
      File_Item : Ada.Text_IO.File_Type;
      Line_Number : Natural := 0;
   begin
      Ada.Text_IO.Open (File_Item, Ada.Text_IO.In_File, Path);
      while not Ada.Text_IO.End_Of_File (File_Item) loop
         declare
            Line_Text : constant String := Ada.Text_IO.Get_Line (File_Item);
            Lower_Line : constant String := Lower (Line_Text);
         begin
            Line_Number := Line_Number + 1;
            if Index (Lower_Line, "to_string") /= 0
              and then (Index (Lower_Line, "stream_element_array") /= 0
                        or else Index (Lower_Line, "payload") /= 0
                        or else Index (Lower_Line, "channel data") /= 0)
            then
               Fail ("possible text conversion in binary path: " & Path & ":" & Natural'Image (Line_Number));
            elsif Index (Lower_Line, "utf-8") /= 0
              or else Index (Lower_Line, "normalize line") /= 0
              or else Index (Lower_Line, "line ending conversion") /= 0
            then
               Fail ("possible text normalization in binary path: " & Path & ":" & Natural'Image (Line_Number));
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

begin
   --  Depth-first walk of src/ via the shared project_tools helper (replacing a
   --  hand-rolled recursive Ada.Directories scan), applying the same file
   --  filter so the set, order, and output are unchanged.
   for Path_Item of Project_Tools.Files.List_Tree ("src") loop
      declare
         Path : constant String := Ada.Strings.Unbounded.To_String (Path_Item);
         Name_Text : constant String := Ada.Directories.Simple_Name (Path);
         Lower_Name : constant String := Lower (Name_Text);
      begin
         if Should_Scan (Name_Text)
           and then Lower_Name'Length >= 4
           and then (Lower_Name (Lower_Name'Last - 3 .. Lower_Name'Last) = ".adb"
                     or else Lower_Name (Lower_Name'Last - 3 .. Lower_Name'Last) = ".ads")
         then
            Scan_File (Path);
         end if;
      end;
   end loop;

   if Failure_Count = 0 then
      Ada.Text_IO.Put_Line ("binary path guard passed");
   else
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
   end if;
end Check_Binary_Paths;
