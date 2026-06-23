with Ada.Command_Line;
with Ada.Directories;
with Ada.Environment_Variables;
with Ada.Text_IO;

procedure Check_Release_Toolchain is
   Failure_Count : Natural := 0;

   procedure Fail (Message_Text : String) is
   begin
      Ada.Text_IO.Put_Line ("FAIL: " & Message_Text);
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
      end if;

      if Path_Text'Length = 0 then
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
            Directory_Text : constant String := Path_Text (Start_Index .. Stop_Index - 1);
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

   procedure Require_Program (Program_Name : String; Purpose_Text : String) is
   begin
      if not Find_In_Path (Program_Name) then
         Fail ("required release tool not found on PATH: " & Program_Name
               & " (" & Purpose_Text & ")");
      end if;
   end Require_Program;

begin
   Ada.Text_IO.Put_Line ("Phase 19 release toolchain guard");
   Ada.Text_IO.Put_Line ("This guard is intentionally non-executing; it checks availability before the release command sequence is trusted.");

   Require_Program ("alr", "Alire crate build and execution wrapper");
   Require_Program ("gprbuild", "GPR project build execution");
   Require_Program ("gnatmake", "GNAT Ada compiler frontend availability");
   Require_Program ("gcc", "compiler driver used by GNAT installations");

   if Failure_Count = 0 then
      Ada.Text_IO.Put_Line ("release toolchain guard passed");
   else
      Ada.Text_IO.Put_Line
        ("Install Alire and a complete GNAT/GPR toolchain before running the release sequence. A gcc binary without gnat1 is not sufficient.");
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
   end if;
end Check_Release_Toolchain;
