with Ada.Environment_Variables;

package body SSH_Lib.Platform.Environment is
   use Ada.Strings.Unbounded;

   type Environment_Entry is record
      Name  : Unbounded_String;
      Value : Unbounded_String;
   end record;

   type Environment_Entry_Array is
     array (Positive range 1 .. Max_Listed_Environment) of Environment_Entry;

   Current_Provider : Environment_Provider := null;
   Override_Active  : Boolean := False;
   Override_Count   : Natural := 0;
   Override_Items   : Environment_Entry_Array;

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
      Current_Provider := null;
      for Index in 1 .. Override_Count loop
         if To_String (Override_Items (Index).Name) = Name then
            Override_Items (Index).Value := To_Unbounded_String (Value);
            return;
         end if;
      end loop;
      if Override_Count < Max_Listed_Environment then
         Override_Count := Override_Count + 1;
         Override_Items (Override_Count).Name := To_Unbounded_String (Name);
         Override_Items (Override_Count).Value := To_Unbounded_String (Value);
      end if;
   end Set_Value_For_Test;

   procedure Reset_Provider is
   begin
      Current_Provider := null;
      Override_Active := False;
      for Index in 1 .. Override_Count loop
         Override_Items (Index).Name := Null_Unbounded_String;
         Override_Items (Index).Value := Null_Unbounded_String;
      end loop;
      Override_Count := 0;
   end Reset_Provider;

   function Getenv
     (Name : String)
      return Unbounded_String
   is
   begin
      if Override_Active then
         for Index in 1 .. Override_Count loop
            if To_String (Override_Items (Index).Name) = Name then
               return Override_Items (Index).Value;
            end if;
         end loop;
         return Null_Unbounded_String;
      elsif Current_Provider = null then
         return Default_Getenv (Name);
      else
         return Current_Provider.all (Name);
      end if;
   exception
      when others =>
         return Null_Unbounded_String;
   end Getenv;

   function Listed_Count return Natural is
   begin
      if Override_Active then
         return Override_Count;
      else
         return 0;
      end if;
   end Listed_Count;

   function Listed_Name
     (Index : Positive)
      return Unbounded_String
   is
   begin
      if Override_Active and then Index <= Override_Count then
         return Override_Items (Index).Name;
      else
         return Null_Unbounded_String;
      end if;
   end Listed_Name;

   function Listed_Value
     (Index : Positive)
      return Unbounded_String
   is
   begin
      if Override_Active and then Index <= Override_Count then
         return Override_Items (Index).Value;
      else
         return Null_Unbounded_String;
      end if;
   end Listed_Value;
end SSH_Lib.Platform.Environment;
