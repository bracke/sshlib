with SSH_Lib.Platform.Environment;

package body SSH_Lib.Platform.Paths is
   use Ada.Strings.Unbounded;

   function Home_Directory return Unbounded_String is
      Home : Unbounded_String := SSH_Lib.Platform.Environment.Getenv ("HOME");
   begin
      if Length (Home) = 0 then
         Home := SSH_Lib.Platform.Environment.Getenv ("USERPROFILE");
      end if;

      return Home;
   exception
      when others =>
         return Null_Unbounded_String;
   end Home_Directory;

   function Default_SSH_Config_Path return String is
      Home : constant String := To_String (Home_Directory);
   begin
      if Home'Length = 0 then
         return "";
      else
         return Home & "/.ssh/config";
      end if;
   end Default_SSH_Config_Path;

   function Expand_Leading_Tilde (Value : String) return String is
      Home : constant String := To_String (Home_Directory);
   begin
      if Value'Length >= 1
        and then Value (Value'First) = '~'
        and then Home'Length > 0
      then
         if Value'Length = 1 then
            return Home;
         elsif Value (Value'First + 1) = '/' then
            return Home & Value (Value'First + 1 .. Value'Last);
         end if;
      end if;

      return Value;
   exception
      when others =>
         return Value;
   end Expand_Leading_Tilde;
end SSH_Lib.Platform.Paths;
