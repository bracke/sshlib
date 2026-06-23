with CryptoLib.Errors;

package SSH_Lib.Identity_Files.Cleanup is
   procedure Release
     (Item : out Identity_Key);

   function Finish_Parse
     (Item         : in out Identity_Key;
      Status_Value : CryptoLib.Errors.Status)
      return CryptoLib.Errors.Status;
end SSH_Lib.Identity_Files.Cleanup;
