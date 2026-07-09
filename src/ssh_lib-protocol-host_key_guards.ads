with CryptoLib.Errors;
with SSH_Lib.Known_Hosts;

--  @summary Guards that gate host-key trust behind a valid ownership proof.
--
--  Combine the host-key signature-verification outcome with the known_hosts
--  trust decision so a local known_hosts match can never mask a failed proof
--  that the server actually owns the negotiated host key.
package SSH_Lib.Protocol.Host_Key_Guards is
   --  Combine the signature check with the known_hosts result: a failed
   --  signature is returned unchanged; otherwise the known_hosts verdict is
   --  returned (or Ok when verification is disabled).
   --  @param Signature_Status     the host-key ownership-proof verification result
   --  @param Trust_Result         the known_hosts trust decision
   --  @param Verification_Enabled False to bypass the known_hosts trust check
   --  @return Ok if trusted, otherwise the governing error status
   function Trust_After_Signature
     (Signature_Status     : CryptoLib.Errors.Status;
      Trust_Result         : SSH_Lib.Known_Hosts.Verification_Result;
      Verification_Enabled : Boolean := True)
      return CryptoLib.Errors.Status;

   --  Decide whether userauth may begin: authentication is allowed only after
   --  key ownership is proven and known_hosts trust passes (same policy as
   --  Trust_After_Signature).
   --  @param Signature_Status     the host-key ownership-proof verification result
   --  @param Trust_Result         the known_hosts trust decision
   --  @param Verification_Enabled False to bypass the known_hosts trust check
   --  @return Ok if authentication may proceed, otherwise an error status
   function May_Authenticate
     (Signature_Status     : CryptoLib.Errors.Status;
      Trust_Result         : SSH_Lib.Known_Hosts.Verification_Result;
      Verification_Enabled : Boolean := True)
      return CryptoLib.Errors.Status;
end SSH_Lib.Protocol.Host_Key_Guards;
