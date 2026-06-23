with CryptoLib.Errors;

use type CryptoLib.Errors.Status;

package body SSH_Lib.Identity_Files.Cleanup is
   procedure Release
     (Item : out Identity_Key) is
   begin
      Clear (Item);
   exception
      when others =>
         Clear (Item);
   end Release;

   function Finish_Parse
     (Item         : in out Identity_Key;
      Status_Value : CryptoLib.Errors.Status)
      return CryptoLib.Errors.Status
   is
   begin
      if Status_Value /= CryptoLib.Errors.Ok then
         Clear (Item);
      end if;
      return Status_Value;
   exception
      when others =>
         Clear (Item);
         return CryptoLib.Errors.Internal_Error;
   end Finish_Parse;
end SSH_Lib.Identity_Files.Cleanup;
