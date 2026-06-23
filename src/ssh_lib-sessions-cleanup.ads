with CryptoLib.Errors;

package SSH_Lib.Sessions.Cleanup is
   function Close_After_Failure
     (Item         : in out Session;
      Status_Value : CryptoLib.Errors.Status)
      return CryptoLib.Errors.Status;
end SSH_Lib.Sessions.Cleanup;
