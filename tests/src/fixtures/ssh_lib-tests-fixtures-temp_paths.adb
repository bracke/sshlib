with Interfaces.C.Strings;
package body SSH_Lib.Tests.Fixtures.Temp_Paths is

   function Path (Name : String) return String is
   begin
      return "/tmp/ssh_lib_phase16_" & Name;
   end Path;

   procedure Make_Owner_Only (Name : String) is
      function C_Chmod (P : Interfaces.C.Strings.chars_ptr; Mode : Interfaces.C.int)
        return Interfaces.C.int
        with Import => True, Convention => C, External_Name => "chmod";
      C_Path  : Interfaces.C.Strings.chars_ptr := Interfaces.C.Strings.New_String (Name);
      Ignored : constant Interfaces.C.int := C_Chmod (C_Path, 8#600#);
   begin
      pragma Unreferenced (Ignored);
      Interfaces.C.Strings.Free (C_Path);
   exception
      when others =>
         null;
   end Make_Owner_Only;

   procedure Make_World_Readable (Name : String) is
      function C_Chmod (P : Interfaces.C.Strings.chars_ptr; Mode : Interfaces.C.int)
        return Interfaces.C.int
        with Import => True, Convention => C, External_Name => "chmod";
      C_Path  : Interfaces.C.Strings.chars_ptr := Interfaces.C.Strings.New_String (Name);
      Ignored : constant Interfaces.C.int := C_Chmod (C_Path, 8#644#);
   begin
      pragma Unreferenced (Ignored);
      Interfaces.C.Strings.Free (C_Path);
   exception
      when others =>
         null;
   end Make_World_Readable;

end SSH_Lib.Tests.Fixtures.Temp_Paths;
