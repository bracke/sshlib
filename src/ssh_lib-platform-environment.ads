with Ada.Strings.Unbounded;

--  @summary Environment-variable lookup with a pluggable, test-overridable provider.
--
--  Wraps process environment access behind a provider hook so tests can inject
--  fixed values instead of reading the real environment.  The active source is
--  either the process environment (the default), an installed provider callback,
--  or an in-memory override table populated by Set_Value_For_Test.
package SSH_Lib.Platform.Environment is
   Max_Listed_Environment : constant Positive := 64;

   type Environment_Provider is access function
     (Name : String)
      return Ada.Strings.Unbounded.Unbounded_String;

   --  Read a variable directly from the real process environment.
   --  @param Name the environment variable name to look up
   --  @return the variable's value, or the empty string if unset or on error
   function Default_Getenv
     (Name : String)
      return Ada.Strings.Unbounded.Unbounded_String;

   --  Install a provider callback that Getenv consults instead of the environment.
   --  @param Provider the lookup callback to use, or null to fall back to the default
   procedure Set_Provider (Provider : Environment_Provider);

   --  Record a fixed name/value pair in the in-memory override table used by tests,
   --  activating override mode and clearing any installed provider.
   --  @param Name  the variable name to override
   --  @param Value the value Getenv should return for that name
   procedure Set_Value_For_Test (Name : String; Value : String);

   --  Clear any installed provider and the override table, restoring default lookup.
   procedure Reset_Provider;

   --  Look up a variable via the active source (override table, provider, or environment).
   --  @param Name the environment variable name to look up
   --  @return the resolved value, or the empty string if unset or on error
   function Getenv
     (Name : String)
      return Ada.Strings.Unbounded.Unbounded_String;

   --  Report how many override entries are currently listed.
   --  @return the number of override entries, or 0 when override mode is inactive
   function Listed_Count return Natural;

   --  Fetch the name of an override entry by position.
   --  @param Index the 1-based override entry position
   --  @return the entry's variable name, or the empty string if out of range
   function Listed_Name
     (Index : Positive)
      return Ada.Strings.Unbounded.Unbounded_String;

   --  Fetch the value of an override entry by position.
   --  @param Index the 1-based override entry position
   --  @return the entry's value, or the empty string if out of range
   function Listed_Value
     (Index : Positive)
      return Ada.Strings.Unbounded.Unbounded_String;
end SSH_Lib.Platform.Environment;
