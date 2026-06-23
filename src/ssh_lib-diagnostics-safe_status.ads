with CryptoLib.Errors;

package SSH_Lib.Diagnostics.Safe_Status is
   pragma Pure;

   function First_Decisive
     (Current_Status : CryptoLib.Errors.Status;
      Next_Status    : CryptoLib.Errors.Status)
      return CryptoLib.Errors.Status;

   function Is_Decisive_Failure
     (Value : CryptoLib.Errors.Status)
      return Boolean;
end SSH_Lib.Diagnostics.Safe_Status;
