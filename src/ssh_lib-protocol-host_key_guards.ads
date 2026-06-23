with CryptoLib.Errors;
with SSH_Lib.Known_Hosts;

package SSH_Lib.Protocol.Host_Key_Guards is
   function Trust_After_Signature
     (Signature_Status     : CryptoLib.Errors.Status;
      Trust_Result         : SSH_Lib.Known_Hosts.Verification_Result;
      Verification_Enabled : Boolean := True)
      return CryptoLib.Errors.Status;

   function May_Authenticate
     (Signature_Status     : CryptoLib.Errors.Status;
      Trust_Result         : SSH_Lib.Known_Hosts.Verification_Result;
      Verification_Enabled : Boolean := True)
      return CryptoLib.Errors.Status;
end SSH_Lib.Protocol.Host_Key_Guards;
