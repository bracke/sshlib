with Ada.Streams;
with CryptoLib.Errors;
with SSH_Lib.Protocol.Buffers;

package SSH_Lib.Protocol.Service is

   SSH_MSG_SERVICE_REQUEST : constant Ada.Streams.Stream_Element := 5;
   SSH_MSG_SERVICE_ACCEPT  : constant Ada.Streams.Stream_Element := 6;

   function Encode_Service_Request
     (Service_Name : String)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;

   function Encode_Userauth_Service_Request
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;

   function Parse_Service_Accept
     (Payload       : Ada.Streams.Stream_Element_Array;
      Expected_Name : String)
      return CryptoLib.Errors.Status;
end SSH_Lib.Protocol.Service;
