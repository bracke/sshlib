with Ada.Strings.Unbounded;

package SSH_Lib.Platform.Paths is
   pragma Elaborate_Body;

   function Home_Directory return Ada.Strings.Unbounded.Unbounded_String;
   function Default_SSH_Config_Path return String;
   function Expand_Leading_Tilde (Value : String) return String;
end SSH_Lib.Platform.Paths;
