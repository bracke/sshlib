with CryptoLib.Errors;

package body SSH_Lib.Diagnostics.Safe_Status is
   use CryptoLib.Errors;

   function Is_Decisive_Failure
     (Value : Status)
      return Boolean
   is
   begin
      return Value /= Ok;
   end Is_Decisive_Failure;

   function First_Decisive
     (Current_Status : Status;
      Next_Status    : Status)
      return Status
   is
   begin
      if Is_Decisive_Failure (Current_Status) then
         return Current_Status;
      else
         return Next_Status;
      end if;
   end First_Decisive;
end SSH_Lib.Diagnostics.Safe_Status;
