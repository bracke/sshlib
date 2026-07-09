with Ada.Streams;
with CryptoLib.Errors;
with SSH_Lib.Identity_Files;
with CryptoLib.Buffers;

--  @summary Produces SSH userauth signatures from a loaded private key.
--
--  Given an in-memory identity key and a chosen public-key algorithm name, it
--  signs the userauth request payload and packages the result as the SSH
--  signature blob the "publickey" method expects.
package SSH_Lib.Private_Key_Signing is
   --  True when Key can sign for the requested userauth algorithm (key type and
   --  algorithm, e.g. an RSA key with rsa-sha2-256/512, are compatible).
   --  @param Key                  the loaded private identity key
   --  @param Public_Key_Algorithm the userauth public-key algorithm name
   --  @return True if a signature can be produced with this key and algorithm
   function Can_Sign_Userauth
     (Key                  : SSH_Lib.Identity_Files.Identity_Key;
      Public_Key_Algorithm : String)
      return Boolean;

   --  Sign the userauth Payload with Key under the named algorithm, emitting the
   --  SSH signature blob (algorithm name plus signature) for the request.
   --  @param Key                  the loaded private identity key
   --  @param Public_Key_Algorithm the userauth public-key algorithm name
   --  @param Payload              the bytes to be signed (the userauth request)
   --  @param Signature_Blob       the resulting SSH-encoded signature blob
   --  @return Ok on success, an error status on failure
   function Sign_Userauth
     (Key                 : SSH_Lib.Identity_Files.Identity_Key;
      Public_Key_Algorithm : String;
      Payload             : Ada.Streams.Stream_Element_Array;
      Signature_Blob      : out CryptoLib.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;
end SSH_Lib.Private_Key_Signing;
