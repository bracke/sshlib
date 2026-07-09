with Ada.Streams;
with CryptoLib.Errors;

--  @summary Verifies SSH public-key signatures across the supported algorithms.
--
--  A single dispatch point that checks an SSH-encoded signature over a message
--  against an SSH-encoded public key, selecting the verification primitive
--  (Ed25519, ECDSA, RSA-SHA2, sk-*, etc.) from the named algorithm.
package SSH_Lib.Signatures is

   --  Verify an SSH signature over a message with the given public key under the
   --  named algorithm.
   --  @param Algorithm_Name  the SSH signature algorithm name to verify under
   --  @param Public_Key_Blob the SSH-encoded public key to verify against
   --  @param Signature_Bytes the SSH-encoded signature blob to check
   --  @param Message_Bytes   the message the signature is expected to cover
   --  @return Ok if the signature is valid, an error status otherwise
   function Verify
     (Algorithm_Name : String;
      Public_Key_Blob : Ada.Streams.Stream_Element_Array;
      Signature_Bytes : Ada.Streams.Stream_Element_Array;
      Message_Bytes   : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;
end SSH_Lib.Signatures;
