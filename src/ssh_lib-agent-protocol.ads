with Ada.Streams;
with Interfaces;
with CryptoLib.Errors;
with SSH_Lib.Protocol.Buffers;

package SSH_Lib.Agent.Protocol is

   SSH_AGENT_FAILURE              : constant Ada.Streams.Stream_Element := 5;
   SSH_AGENTC_REQUEST_IDENTITIES  : constant Ada.Streams.Stream_Element := 11;
   SSH_AGENT_IDENTITIES_ANSWER    : constant Ada.Streams.Stream_Element := 12;
   SSH_AGENTC_SIGN_REQUEST        : constant Ada.Streams.Stream_Element := 13;
   SSH_AGENT_SIGN_RESPONSE        : constant Ada.Streams.Stream_Element := 14;

   SSH_AGENT_RSA_SHA2_256         : constant Interfaces.Unsigned_32 := 2;
   SSH_AGENT_RSA_SHA2_512         : constant Interfaces.Unsigned_32 := 4;

   function Encode_Message_Length
     (Payload_Length : Natural)
      return Ada.Streams.Stream_Element_Array;

   function Decode_Message_Length
     (Header         : Ada.Streams.Stream_Element_Array;
      Payload_Length : out Natural)
      return CryptoLib.Errors.Status;

   function Encode_Request_Identities
      return Ada.Streams.Stream_Element_Array;

   function Parse_Identities_Answer
     (Payload    : Ada.Streams.Stream_Element_Array;
      Identities : out SSH_Lib.Agent.Identity_List)
      return CryptoLib.Errors.Status;

   function Signature_Flags_For
     (Public_Key_Algorithm : String)
      return Interfaces.Unsigned_32;

   function Encode_Sign_Request
     (Key_Blob             : Ada.Streams.Stream_Element_Array;
      Data_To_Sign         : Ada.Streams.Stream_Element_Array;
      Public_Key_Algorithm : String)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;

   function Validate_Signature_Blob_For_Algorithm
     (Signature_Blob       : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Expected_Algorithm   : String)
      return CryptoLib.Errors.Status;

   function Parse_Sign_Response
     (Payload        : Ada.Streams.Stream_Element_Array;
      Signature_Blob : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;
end SSH_Lib.Agent.Protocol;
