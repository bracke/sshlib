package body SSH_Lib.Platform.XAttr is

   function C_ListXAttr
     (Path : Interfaces.C.Strings.chars_ptr;
      List : System.Address;
      Size : Interfaces.C.size_t) return Interfaces.C.long;
   pragma Import (C, C_ListXAttr, "listxattr");

   function C_GetXAttr
     (Path  : Interfaces.C.Strings.chars_ptr;
      Name  : Interfaces.C.Strings.chars_ptr;
      Value : System.Address;
      Size  : Interfaces.C.size_t) return Interfaces.C.long;
   pragma Import (C, C_GetXAttr, "getxattr");

   function C_SetXAttr
     (Path  : Interfaces.C.Strings.chars_ptr;
      Name  : Interfaces.C.Strings.chars_ptr;
      Value : System.Address;
      Size  : Interfaces.C.size_t;
      Flags : Interfaces.C.int) return Interfaces.C.int;
   pragma Import (C, C_SetXAttr, "setxattr");

   function List_Names
     (Path : Interfaces.C.Strings.chars_ptr;
      List : System.Address;
      Size : Interfaces.C.size_t) return Interfaces.C.long is
   begin
      return C_ListXAttr (Path, List, Size);
   end List_Names;

   function Get_Value
     (Path  : Interfaces.C.Strings.chars_ptr;
      Name  : Interfaces.C.Strings.chars_ptr;
      Value : System.Address;
      Size  : Interfaces.C.size_t) return Interfaces.C.long is
   begin
      return C_GetXAttr (Path, Name, Value, Size);
   end Get_Value;

   function Set_Value
     (Path  : Interfaces.C.Strings.chars_ptr;
      Name  : Interfaces.C.Strings.chars_ptr;
      Value : System.Address;
      Size  : Interfaces.C.size_t;
      Flags : Interfaces.C.int) return Interfaces.C.int is
   begin
      return C_SetXAttr (Path, Name, Value, Size, Flags);
   end Set_Value;

end SSH_Lib.Platform.XAttr;
