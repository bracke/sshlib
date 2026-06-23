with Ada.Strings.Unbounded;
with CryptoLib.Errors;

package SSH_Lib.Internal is
   pragma Elaborate_Body;

   function Has_Control_Break (Value : String) return Boolean;
   function Valid_Host (Value : String) return Boolean;
   function Valid_User (Value : String) return Boolean;
   function Valid_Command (Value : String) return Boolean;
   function Validate_Port (Value : Natural) return CryptoLib.Errors.Status;

   function Home_Directory return Ada.Strings.Unbounded.Unbounded_String;
   function Default_Known_Hosts_Path return Ada.Strings.Unbounded.Unbounded_String;
end SSH_Lib.Internal;
