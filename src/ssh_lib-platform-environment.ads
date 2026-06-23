with Ada.Strings.Unbounded;

package SSH_Lib.Platform.Environment is

   type Environment_Provider is access function
     (Name : String)
      return Ada.Strings.Unbounded.Unbounded_String;

   function Default_Getenv
     (Name : String)
      return Ada.Strings.Unbounded.Unbounded_String;

   procedure Set_Provider (Provider : Environment_Provider);
   procedure Set_Value_For_Test (Name : String; Value : String);
   procedure Reset_Provider;

   function Getenv
     (Name : String)
      return Ada.Strings.Unbounded.Unbounded_String;
end SSH_Lib.Platform.Environment;
