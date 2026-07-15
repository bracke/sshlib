with Interfaces.C;
with Interfaces.C.Strings;
with System;

--  @summary Host extended-attribute access for SFTP local-metadata round-trips.
--
--  Thin wrappers over the operating system's extended-attribute calls. POSIX maps
--  them to listxattr/getxattr/setxattr; Windows has no such interface, so its body
--  reports no attributes and drops writes -- SFTP metadata round-trips without
--  extended attributes there rather than failing to link against symbols that do
--  not exist.
package SSH_Lib.Platform.XAttr is

   --  List the names of Path's extended attributes into List (Size bytes). With a null
   --  List and Size 0, returns the buffer size needed. Negative on error.
   function List_Names
     (Path : Interfaces.C.Strings.chars_ptr;
      List : System.Address;
      Size : Interfaces.C.size_t) return Interfaces.C.long;

   --  Read attribute Name on Path into Value (Size bytes). With a null Value and Size 0,
   --  returns the value size needed. Negative on error.
   function Get_Value
     (Path  : Interfaces.C.Strings.chars_ptr;
      Name  : Interfaces.C.Strings.chars_ptr;
      Value : System.Address;
      Size  : Interfaces.C.size_t) return Interfaces.C.long;

   --  Set attribute Name on Path to the Size bytes at Value. Negative on error.
   function Set_Value
     (Path  : Interfaces.C.Strings.chars_ptr;
      Name  : Interfaces.C.Strings.chars_ptr;
      Value : System.Address;
      Size  : Interfaces.C.size_t;
      Flags : Interfaces.C.int) return Interfaces.C.int;

end SSH_Lib.Platform.XAttr;
