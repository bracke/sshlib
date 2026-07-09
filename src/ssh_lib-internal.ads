with Ada.Strings.Unbounded;
with CryptoLib.Errors;

--  @summary Internal validation helpers and default filesystem paths for the SSH client.
--
--  Shared predicates that reject hosts, users, and commands containing NUL/CR/LF
--  or whitespace, a port-range check, and helpers that resolve the user's home
--  directory and default known_hosts path from the environment.
package SSH_Lib.Internal is
   pragma Elaborate_Body;

   --  Test whether a string contains a NUL, LF, or CR control-break character.
   --  @param Value the string to scan
   --  @return True if any NUL, LF, or CR byte is present
   function Has_Control_Break (Value : String) return Boolean;

   --  Test whether a string is a valid hostname (non-empty, no control breaks or whitespace).
   --  @param Value the candidate host string
   --  @return True if the host is acceptable
   function Valid_Host (Value : String) return Boolean;

   --  Test whether a string is a valid username (non-empty, no control breaks or whitespace).
   --  @param Value the candidate user string
   --  @return True if the user is acceptable
   function Valid_User (Value : String) return Boolean;

   --  Test whether a string is a valid remote command (non-empty, no control breaks).
   --  @param Value the candidate command string
   --  @return True if the command is acceptable
   function Valid_Command (Value : String) return Boolean;

   --  Validate that a port number is in the range 1 .. 65535.
   --  @param Value the port number to check
   --  @return Ok if in range, Invalid_Port otherwise
   function Validate_Port (Value : Natural) return CryptoLib.Errors.Status;

   --  Resolve the user's home directory from HOME (then USERPROFILE).
   --  @return the home directory path, or the empty string if none is set
   function Home_Directory return Ada.Strings.Unbounded.Unbounded_String;

   --  Build the default known_hosts path (~/.ssh/known_hosts) under the home directory.
   --  @return the default known_hosts path, or the empty string if the home directory is unknown
   function Default_Known_Hosts_Path return Ada.Strings.Unbounded.Unbounded_String;
end SSH_Lib.Internal;
