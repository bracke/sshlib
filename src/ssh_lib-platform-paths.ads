with Ada.Strings.Unbounded;

--  @summary Home-directory and SSH path resolution across platforms.
--
--  Locates the user's home directory (via HOME, falling back to USERPROFILE),
--  derives the default ~/.ssh/config path from it, and expands a leading "~"
--  in a supplied path.
package SSH_Lib.Platform.Paths is
   pragma Elaborate_Body;

   --  Return the user's home directory from HOME, or USERPROFILE if HOME is unset.
   --  @return the home directory path, or an empty string if none is found
   function Home_Directory return Ada.Strings.Unbounded.Unbounded_String;

   --  Return the default SSH client config path (home & "/.ssh/config").
   --  @return the config path, or "" if the home directory cannot be determined
   function Default_SSH_Config_Path return String;

   --  Expand a leading "~" or "~/" in Value to the user's home directory.
   --  @param Value the path possibly beginning with a tilde
   --  @return Value with a leading tilde replaced by the home directory, or Value
   --          unchanged if it has no expandable tilde or home is unknown
   function Expand_Leading_Tilde (Value : String) return String;
end SSH_Lib.Platform.Paths;
