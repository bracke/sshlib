with Ada.Environment_Variables;

package body SSH_Lib.Internal is
   use Ada.Strings.Unbounded;

   function Has_Control_Break (Value : String) return Boolean is
   begin
      for Ch of Value loop
         if Ch = Character'Val (0)
           or else Ch = Character'Val (10)
           or else Ch = Character'Val (13)
         then
            return True;
         end if;
      end loop;
      return False;
   end Has_Control_Break;

   function Valid_Host (Value : String) return Boolean is
   begin
      if Value'Length = 0 or else Has_Control_Break (Value) then
         return False;
      end if;

      for Ch of Value loop
         if Ch = ' ' or else Ch = Character'Val (9) then
            return False;
         end if;
      end loop;

      return True;
   end Valid_Host;

   function Valid_User (Value : String) return Boolean is
   begin
      if Value'Length = 0 or else Has_Control_Break (Value) then
         return False;
      end if;

      for Ch of Value loop
         if Ch = ' ' or else Ch = Character'Val (9) then
            return False;
         end if;
      end loop;

      return True;
   end Valid_User;

   function Valid_Command (Value : String) return Boolean is
   begin
      return Value'Length > 0 and then not Has_Control_Break (Value);
   end Valid_Command;

   function Validate_Port (Value : Natural) return CryptoLib.Errors.Status is
   begin
      if Value = 0 or else Value > 65_535 then
         return CryptoLib.Errors.Invalid_Port;
      end if;
      return CryptoLib.Errors.Ok;
   end Validate_Port;

   function Home_Directory return Unbounded_String is
   begin
      if Ada.Environment_Variables.Exists ("HOME") then
         return To_Unbounded_String (Ada.Environment_Variables.Value ("HOME"));
      elsif Ada.Environment_Variables.Exists ("USERPROFILE") then
         return To_Unbounded_String (Ada.Environment_Variables.Value ("USERPROFILE"));
      else
         return Null_Unbounded_String;
      end if;
   exception
      when others =>
         return Null_Unbounded_String;
   end Home_Directory;

   function Default_Known_Hosts_Path return Unbounded_String is
      Home_Path : constant String := To_String (Home_Directory);
   begin
      if Home_Path'Length = 0 then
         return Null_Unbounded_String;
      else
         return To_Unbounded_String (Home_Path & "/.ssh/known_hosts");
      end if;
   end Default_Known_Hosts_Path;
end SSH_Lib.Internal;
