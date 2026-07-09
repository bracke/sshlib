with Ada.Streams;
with CryptoLib.Errors;
with SSH_Lib.Identity_Files;
with SSH_Lib.Protocol.Buffers;

--  @summary Building signed publickey SSH_MSG_USERAUTH_REQUEST packets from an identity key.
--
--  Assembles the publickey userauth signature payload (session id, user name,
--  algorithm, and public-key blob), signs it with the identity's private key,
--  and encodes the resulting signed SSH_MSG_USERAUTH_REQUEST.  All buffers are
--  scrubbed on the way out and the request is cleared on any failure.
package SSH_Lib.Protocol.Userauth.Identity is
   --  Build a signed publickey userauth request, deriving the signature
   --  algorithm from the key (ssh-rsa is upgraded to rsa-sha2-512).
   --  @param Key                the identity key providing the public blob and signing material
   --  @param Session_Identifier the SSH session identifier bound into the signature
   --  @param User_Name          the authenticating user name
   --  @param Request            out parameter receiving the encoded signed request packet
   --  @return Ok on success, Authentication_Failed on empty payload/request, or
   --          a propagated signing or Internal_Error status
   function Build_Signed_Request_From_Identity
     (Key                  : SSH_Lib.Identity_Files.Identity_Key;
      Session_Identifier   : Ada.Streams.Stream_Element_Array;
      User_Name            : String;
      Request              : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;

   --  Build a signed publickey userauth request using an explicit public-key
   --  algorithm, deriving the public-key blob from the identity key.
   --  @param Key                  the identity key providing the public blob and signing material
   --  @param Session_Identifier   the SSH session identifier bound into the signature
   --  @param User_Name            the authenticating user name
   --  @param Public_Key_Algorithm the publickey algorithm name to advertise and sign with
   --  @param Request              out parameter receiving the encoded signed request packet
   --  @return Ok on success, Authentication_Failed on empty payload/request, or
   --          a propagated signing or Internal_Error status
   function Build_Signed_Request_From_Identity
     (Key                  : SSH_Lib.Identity_Files.Identity_Key;
      Session_Identifier   : Ada.Streams.Stream_Element_Array;
      User_Name            : String;
      Public_Key_Algorithm : String;
      Request              : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;

   --  Build a signed publickey userauth request with a caller-supplied public
   --  blob and independent advertised and signature algorithms.
   --  @param Key                  the identity key providing the signing material
   --  @param Session_Identifier   the SSH session identifier bound into the signature
   --  @param User_Name            the authenticating user name
   --  @param Public_Key_Algorithm the publickey algorithm name advertised in the request
   --  @param Public_Key_Blob      the encoded public-key blob to present
   --  @param Signature_Algorithm  the algorithm used to actually sign the payload
   --  @param Request              out parameter receiving the encoded signed request packet
   --  @return Ok on success, Authentication_Failed on empty payload/request, or
   --          a propagated signing or Internal_Error status
   function Build_Signed_Request_With_Public_Blob
     (Key                  : SSH_Lib.Identity_Files.Identity_Key;
      Session_Identifier   : Ada.Streams.Stream_Element_Array;
      User_Name            : String;
      Public_Key_Algorithm : String;
      Public_Key_Blob      : Ada.Streams.Stream_Element_Array;
      Signature_Algorithm  : String;
      Request              : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;
end SSH_Lib.Protocol.Userauth.Identity;
