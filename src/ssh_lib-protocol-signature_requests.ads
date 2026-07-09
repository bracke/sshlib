with Ada.Streams;
with SSH_Lib.Protocol.Buffers;

--  @summary Builds the data blob that a "publickey" userauth signature covers.
--
--  Assembles the exact byte sequence an SSH client must sign for public-key
--  authentication: the session identifier followed by the userauth-request
--  fields (user name, service, method, algorithm, and public-key blob).
package SSH_Lib.Protocol.Signature_Requests is
   pragma Preelaborate;

   --  Build the to-be-signed data for a "publickey" userauth request: the
   --  session identifier prefixed to the userauth-request fields.
   --  @param Session_Identifier   the SSH session identifier (first exchange hash)
   --  @param User_Name            the authenticating user name
   --  @param Public_Key_Algorithm the userauth public-key algorithm name
   --  @param Public_Key_Blob      the SSH-encoded public-key blob
   --  @return the assembled buffer to be signed by the private key
   function Build_Userauth_Publickey_Data
     (Session_Identifier   : Ada.Streams.Stream_Element_Array;
      User_Name            : String;
      Public_Key_Algorithm : String;
      Public_Key_Blob      : Ada.Streams.Stream_Element_Array)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;
end SSH_Lib.Protocol.Signature_Requests;
