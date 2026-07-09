with Ada.Streams;
with Interfaces;
with CryptoLib.Errors;
with SSH_Lib.Protocol.Buffers;

--  @summary Wire encoding and decoding for the ssh-agent protocol.
--
--  Builds the request messages and parses the answers exchanged with a running
--  ssh-agent over its UNIX socket: the 4-byte length framing, request/answer
--  message type bytes, the identities listing, and RSA SHA-2 signing requests.
package SSH_Lib.Agent.Protocol is

   SSH_AGENT_FAILURE              : constant Ada.Streams.Stream_Element := 5;
   SSH_AGENTC_REQUEST_IDENTITIES  : constant Ada.Streams.Stream_Element := 11;
   SSH_AGENT_IDENTITIES_ANSWER    : constant Ada.Streams.Stream_Element := 12;
   SSH_AGENTC_SIGN_REQUEST        : constant Ada.Streams.Stream_Element := 13;
   SSH_AGENT_SIGN_RESPONSE        : constant Ada.Streams.Stream_Element := 14;

   SSH_AGENT_RSA_SHA2_256         : constant Interfaces.Unsigned_32 := 2;
   SSH_AGENT_RSA_SHA2_512         : constant Interfaces.Unsigned_32 := 4;

   --  Encode the 4-byte big-endian message-length prefix that frames an agent
   --  message on the wire.
   --  @param Payload_Length the number of payload bytes that follow the prefix
   --  @return the 4-byte length header
   function Encode_Message_Length
     (Payload_Length : Natural)
      return Ada.Streams.Stream_Element_Array;

   --  Decode the 4-byte big-endian message-length prefix of an agent message.
   --  @param Header         the 4-byte length header read from the socket
   --  @param Payload_Length the decoded count of payload bytes that follow
   --  @return Ok on success, else a failure Status (bad length or size)
   function Decode_Message_Length
     (Header         : Ada.Streams.Stream_Element_Array;
      Payload_Length : out Natural)
      return CryptoLib.Errors.Status;

   --  Encode a SSH_AGENTC_REQUEST_IDENTITIES message asking the agent to list
   --  its loaded identities.
   --  @return the full framed request message
   function Encode_Request_Identities
      return Ada.Streams.Stream_Element_Array;

   --  Parse a SSH_AGENT_IDENTITIES_ANSWER payload into the list of identities
   --  (key blob plus comment) held by the agent.
   --  @param Payload    the answer payload (without the length prefix)
   --  @param Identities the parsed list of agent identities
   --  @return Ok on success, else a failure Status on malformed input
   function Parse_Identities_Answer
     (Payload    : Ada.Streams.Stream_Element_Array;
      Identities : out SSH_Lib.Agent.Identity_List)
      return CryptoLib.Errors.Status;

   --  Map a public-key algorithm name to the ssh-agent signature request flags
   --  (RSA SHA2-256/512 for RSA keys; 0 when no flags apply).
   --  @param Public_Key_Algorithm the SSH public-key algorithm name
   --  @return the SSH_AGENT_RSA_SHA2_* flag bits, or 0 if none
   function Signature_Flags_For
     (Public_Key_Algorithm : String)
      return Interfaces.Unsigned_32;

   --  Build a SSH_AGENTC_SIGN_REQUEST message asking the agent to sign data
   --  with the identity named by Key_Blob using the given algorithm's flags.
   --  @param Key_Blob             the SSH-encoded public key selecting the
   --                              identity to sign with
   --  @param Data_To_Sign         the bytes to be signed
   --  @param Public_Key_Algorithm the algorithm name, which selects the flags
   --  @return the framed sign-request message buffer
   function Encode_Sign_Request
     (Key_Blob             : Ada.Streams.Stream_Element_Array;
      Data_To_Sign         : Ada.Streams.Stream_Element_Array;
      Public_Key_Algorithm : String)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;

   --  Check that a returned signature blob is well formed and its embedded
   --  algorithm name matches and is supported for Expected_Algorithm.
   --  @param Signature_Blob     the signature blob returned by the agent
   --  @param Expected_Algorithm the algorithm the signature must match
   --  @return Ok if valid and matching, else Authentication_Failed or a
   --          failure Status
   function Validate_Signature_Blob_For_Algorithm
     (Signature_Blob       : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Expected_Algorithm   : String)
      return CryptoLib.Errors.Status;

   --  Parse a SSH_AGENT_SIGN_RESPONSE payload, extracting the signature blob.
   --  @param Payload        the response payload (without the length prefix)
   --  @param Signature_Blob the extracted signature blob
   --  @return Ok on success, else a failure Status on malformed input
   function Parse_Sign_Response
     (Payload        : Ada.Streams.Stream_Element_Array;
      Signature_Blob : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;
end SSH_Lib.Agent.Protocol;
