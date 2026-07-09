with Ada.Command_Line;
with Ada.Text_IO;

with Project_Tools.Files;
with Project_Tools.Processes;

procedure Check_Release_Toolchain is
   Failure_Count : Natural := 0;

   procedure Fail (Message_Text : String) is
   begin
      Ada.Text_IO.Put_Line ("FAIL: " & Message_Text);
      Failure_Count := Failure_Count + 1;
   end Fail;

   procedure Require_Program (Program_Name : String; Purpose_Text : String) is
   begin
      if Project_Tools.Processes.Locate_Command (Program_Name) = "" then
         Fail ("required release tool not found on PATH: " & Program_Name
               & " (" & Purpose_Text & ")");
      end if;
   end Require_Program;

   procedure Require_Text (Path : String; Needle : String) is
   begin
      if not Project_Tools.Files.File_Exists (Path) then
         Fail ("required toolchain file not found: " & Path);
      elsif not Project_Tools.Files.File_Contains (Path, Needle) then
         Fail ("missing toolchain text in " & Path & ": " & Needle);
      end if;
   end Require_Text;

   procedure Require_Alire_GNAT_15 is
   begin
      Require_Text ("alire.toml", "gnat_native = ""^15""");
      Require_Text ("tests/alire.toml", "gnat_native = ""^15""");
      Require_Text ("tools/alire.toml", "gnat_native = ""^15""");
      Require_Text ("alire/alire.lock", "gnat=15.2.1");
      Require_Text ("alire/alire.lock", "version = ""15.2.1""");
      Require_Text ("tools/alire/alire.lock", "gnat=15.2.1");
      Require_Text ("tools/alire/alire.lock", "version = ""15.2.1""");
   end Require_Alire_GNAT_15;

begin
   Ada.Text_IO.Put_Line ("Phase 19 release toolchain guard");
   Ada.Text_IO.Put_Line
     ("This guard requires Alire GNAT 15 manifests and synced lock files.");

   Require_Program ("alr", "Alire crate build and execution wrapper");
   Require_Alire_GNAT_15;

   if Failure_Count = 0 then
      Ada.Text_IO.Put_Line ("release toolchain guard passed");
   else
      Ada.Text_IO.Put_Line
        ("Sync Alire GNAT 15 before running the release sequence; plain system GNAT is not accepted.");
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
   end if;
end Check_Release_Toolchain;
