with Ada.Environment_Variables;

package body SSH_Lib.Platform.Environment is
   use Ada.Strings.Unbounded;

   Current_Provider : Environment_Provider := null;
   Override_Active  : Boolean := False;
   Override_Name    : Unbounded_String := Null_Unbounded_String;
   Override_Value   : Unbounded_String := Null_Unbounded_String;

   function Default_Getenv
     (Name : String)
      return Unbounded_String
   is
   begin
      if Ada.Environment_Variables.Exists (Name) then
         return To_Unbounded_String (Ada.Environment_Variables.Value (Name));
      else
         return Null_Unbounded_String;
      end if;
   exception
      when others =>
         return Null_Unbounded_String;
   end Default_Getenv;

   procedure Set_Provider (Provider : Environment_Provider) is
   begin
      Current_Provider := Provider;
   end Set_Provider;

   procedure Set_Value_For_Test (Name : String; Value : String) is
   begin
      Override_Active := True;
      Override_Name := To_Unbounded_String (Name);
      Override_Value := To_Unbounded_String (Value);
      Current_Provider := null;
   end Set_Value_For_Test;

   procedure Reset_Provider is
   begin
      Current_Provider := null;
      Override_Active := False;
      Override_Name := Null_Unbounded_String;
      Override_Value := Null_Unbounded_String;
   end Reset_Provider;

   function Getenv
     (Name : String)
      return Unbounded_String
   is
   begin
      if Override_Active then
         if To_String (Override_Name) = Name then
            return Override_Value;
         else
            return Null_Unbounded_String;
         end if;
      elsif Current_Provider = null then
         return Default_Getenv (Name);
      else
         return Current_Provider.all (Name);
      end if;
   exception
      when others =>
         return Null_Unbounded_String;
   end Getenv;
end SSH_Lib.Platform.Environment;
