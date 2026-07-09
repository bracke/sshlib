with Ada.Streams;
with CryptoLib.Errors;
with SSH_Lib.Protocol.Buffers;

--  @summary Assembles a publickey userauth request from an agent signature.
--
--  Takes a signature produced by an ssh-agent for an agent-held key and packs
--  it, together with the key blob and request fields, into the complete
--  SSH_MSG_USERAUTH_REQUEST "publickey" packet to send to the server.
package SSH_Lib.Protocol.Userauth.Agent_Identity is
   --  Build a signed "publickey" userauth request from an agent-produced
   --  signature over the corresponding to-be-signed data.
   --  @param Key_Blob             the SSH-encoded public-key blob of the identity
   --  @param Signature_Blob       the signature returned by the ssh-agent
   --  @param Session_Identifier   the SSH session identifier
   --  @param User_Name            the authenticating user name
   --  @param Public_Key_Algorithm the userauth public-key algorithm name
   --  @param Request              the assembled userauth-request packet
   --  @return Ok on success, an error status on failure
   function Build_Signed_Request_From_Agent_Signature
     (Key_Blob             : Ada.Streams.Stream_Element_Array;
      Signature_Blob       : Ada.Streams.Stream_Element_Array;
      Session_Identifier   : Ada.Streams.Stream_Element_Array;
      User_Name            : String;
      Public_Key_Algorithm : String;
      Request              : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;
end SSH_Lib.Protocol.Userauth.Agent_Identity;
