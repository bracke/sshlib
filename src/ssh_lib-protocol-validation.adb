package body SSH_Lib.Protocol.Validation is
   function Is_ASCII_Protocol_Name (Value : String) return Boolean is
   begin
      if Value'Length = 0 then
         return False;
      end if;

      for Character_Value of Value loop
         if Character_Value < '!' or else Character_Value > '~' then
            return False;
         end if;
      end loop;
      return True;
   end Is_ASCII_Protocol_Name;
end SSH_Lib.Protocol.Validation;
