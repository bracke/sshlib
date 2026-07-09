with Ada.Streams;
with CryptoLib.Errors;
with SSH_Lib.Protocol.Buffers;

--  @summary FIDO/U2F security-key (sk-*) userauth signing support.
--
--  Defines the callback through which a hardware security key produces a
--  signature and assembles the resulting sk-* "publickey" userauth request,
--  keeping the token-specific signing operation abstract behind the signer.
package SSH_Lib.Security_Keys is
   type Security_Key_Sign_Result is record
      Provided       : Boolean := False;
      Signature_Blob : SSH_Lib.Protocol.Buffers.Packet_Buffer;
   end record;

   type Security_Key_Signer is access function
     (Application          : String;
      Public_Key_Algorithm : String;
      Public_Key_Blob      : Ada.Streams.Stream_Element_Array;
      Data_To_Sign         : Ada.Streams.Stream_Element_Array)
      return Security_Key_Sign_Result;

   --  Invoke the security-key Signer over the to-be-signed userauth data and, if
   --  it provides a signature, assemble the complete sk-* "publickey" request.
   --  @param Signer               the callback that drives the hardware token
   --  @param Application           the FIDO application/relying-party identifier
   --  @param Session_Identifier   the SSH session identifier
   --  @param User_Name            the authenticating user name
   --  @param Public_Key_Algorithm the sk-* userauth public-key algorithm name
   --  @param Public_Key_Blob      the SSH-encoded public-key blob
   --  @param Request              the assembled userauth-request packet
   --  @return Ok on success, an error status if signing failed or was declined
   function Build_Signed_Request
     (Signer               : Security_Key_Signer;
      Application          : String;
      Session_Identifier   : Ada.Streams.Stream_Element_Array;
      User_Name            : String;
      Public_Key_Algorithm : String;
      Public_Key_Blob      : Ada.Streams.Stream_Element_Array;
      Request              : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;
end SSH_Lib.Security_Keys;
