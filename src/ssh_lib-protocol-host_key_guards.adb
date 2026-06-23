
package body SSH_Lib.Protocol.Host_Key_Guards is
   use type CryptoLib.Errors.Status;

   function Trust_After_Signature
     (Signature_Status     : CryptoLib.Errors.Status;
      Trust_Result         : SSH_Lib.Known_Hosts.Verification_Result;
      Verification_Enabled : Boolean := True)
      return CryptoLib.Errors.Status
   is
   begin
      if Signature_Status /= CryptoLib.Errors.Ok then
         --  A known_hosts match is local trust policy only. It must never mask
         --  a failed proof that the server owns the negotiated host key.
         return Signature_Status;
      end if;

      if not Verification_Enabled then
         return CryptoLib.Errors.Ok;
      end if;

      return SSH_Lib.Known_Hosts.To_Status (Trust_Result);
   exception
      when others =>
         return CryptoLib.Errors.Internal_Error;
   end Trust_After_Signature;

   function May_Authenticate
     (Signature_Status     : CryptoLib.Errors.Status;
      Trust_Result         : SSH_Lib.Known_Hosts.Verification_Result;
      Verification_Enabled : Boolean := True)
      return CryptoLib.Errors.Status
   is
   begin
      --  Authentication may begin only after key ownership has been verified
      --  and known_hosts trust has passed, unless verification was explicitly
      --  disabled by the caller.
      return Trust_After_Signature
        (Signature_Status, Trust_Result, Verification_Enabled);
   exception
      when others =>
         return CryptoLib.Errors.Internal_Error;
   end May_Authenticate;
end SSH_Lib.Protocol.Host_Key_Guards;
