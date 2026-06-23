with CryptoLib.Errors;

package SSH_Lib.Channels.Cleanup is
   procedure Mark_Failed
     (Item   : in out Channel;
      Reason : CryptoLib.Errors.Status);

   function Close_Local
     (Item : in out Channel)
      return CryptoLib.Errors.Status;
end SSH_Lib.Channels.Cleanup;
