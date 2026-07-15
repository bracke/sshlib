package body SSH_Lib.Platform.XAttr is

   use type Interfaces.C.long;

   --  Windows has no POSIX extended-attribute interface. Report that Path carries no
   --  attributes and accept writes as no-ops, so SFTP metadata round-trips without
   --  them instead of failing to link.

   function List_Names
     (Path : Interfaces.C.Strings.chars_ptr;
      List : System.Address;
      Size : Interfaces.C.size_t) return Interfaces.C.long
   is
      pragma Unreferenced (Path, List, Size);
   begin
      return 0;
   end List_Names;

   function Get_Value
     (Path  : Interfaces.C.Strings.chars_ptr;
      Name  : Interfaces.C.Strings.chars_ptr;
      Value : System.Address;
      Size  : Interfaces.C.size_t) return Interfaces.C.long
   is
      pragma Unreferenced (Path, Name, Value, Size);
   begin
      return -1;
   end Get_Value;

   function Set_Value
     (Path  : Interfaces.C.Strings.chars_ptr;
      Name  : Interfaces.C.Strings.chars_ptr;
      Value : System.Address;
      Size  : Interfaces.C.size_t;
      Flags : Interfaces.C.int) return Interfaces.C.int
   is
      pragma Unreferenced (Path, Name, Value, Size, Flags);
   begin
      return 0;
   end Set_Value;

end SSH_Lib.Platform.XAttr;
