with Ada.Text_IO;
with Ada.Strings;
with Ada.Strings.Fixed;
with SSH_Lib.Tests.Fixtures.Keys;

package body SSH_Lib.Tests.Fixtures.Known_Hosts is

   procedure Write_Record
     (Path     : String;
      Host     : String;
      Port     : Natural;
      Key_Blob : String)
   is
      Output_File : Ada.Text_IO.File_Type;
      Host_Field  : constant String :=
        (if Port = 22 then Host
         else "[" & Host & "]:"
              & Ada.Strings.Fixed.Trim
                  (Natural'Image (Port), Ada.Strings.Both));
   begin
      Ada.Text_IO.Create (Output_File, Ada.Text_IO.Out_File, Path);
      Ada.Text_IO.Put_Line
        (Output_File,
         Host_Field & " " & SSH_Lib.Tests.Fixtures.Keys.Test_Host_Key_Algorithm &
         " " & Key_Blob & " phase16-public-test-fixture");
      Ada.Text_IO.Close (Output_File);
   exception
      when others =>
         if Ada.Text_IO.Is_Open (Output_File) then
            Ada.Text_IO.Close (Output_File);
         end if;
         raise;
   end Write_Record;

   procedure Write_Matching_File
     (Path : String;
      Host : String;
      Port : Natural := 22) is
   begin
      Write_Record
        (Path,
         Host,
         Port,
         SSH_Lib.Tests.Fixtures.Keys.Test_Host_Key_Blob);
   end Write_Matching_File;

   procedure Write_Changed_File
     (Path : String;
      Host : String;
      Port : Natural := 22) is
   begin
      Write_Record
        (Path,
         Host,
         Port,
         SSH_Lib.Tests.Fixtures.Keys.Alternate_Host_Key_Blob);
   end Write_Changed_File;

   function Fixture_Host_Key return SSH_Lib.Known_Hosts.Host_Key is
   begin
      return SSH_Lib.Known_Hosts.Create_Host_Key
        (SSH_Lib.Tests.Fixtures.Keys.Test_Host_Key_Algorithm,
         SSH_Lib.Tests.Fixtures.Keys.Test_Host_Key_Blob);
   end Fixture_Host_Key;
end SSH_Lib.Tests.Fixtures.Known_Hosts;
