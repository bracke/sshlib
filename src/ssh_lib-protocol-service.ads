with Ada.Streams;
with CryptoLib.Errors;
with SSH_Lib.Protocol.Buffers;

--  @summary Encoding and parsing of SSH_MSG_SERVICE_REQUEST/ACCEPT packets.
--
--  Builds SSH service-request packets (an ASCII service name wrapped as an SSH
--  string) and validates the server's SSH_MSG_SERVICE_ACCEPT reply, checking
--  that the echoed service name matches exactly and that no trailing bytes
--  follow the encoded name.
package SSH_Lib.Protocol.Service is

   SSH_MSG_SERVICE_REQUEST : constant Ada.Streams.Stream_Element := 5;
   SSH_MSG_SERVICE_ACCEPT  : constant Ada.Streams.Stream_Element := 6;

   --  Encode an SSH_MSG_SERVICE_REQUEST packet for the named service.
   --  @param Service_Name the ASCII service name to request (e.g. "ssh-userauth")
   --  @return the encoded packet buffer, or an empty buffer if the name is not
   --          a valid ASCII protocol name or encoding fails
   function Encode_Service_Request
     (Service_Name : String)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;

   --  Encode an SSH_MSG_SERVICE_REQUEST packet for the "ssh-userauth" service.
   --  @return the encoded ssh-userauth service-request packet buffer
   function Encode_Userauth_Service_Request
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;

   --  Validate a received SSH_MSG_SERVICE_ACCEPT packet against the expected name.
   --  @param Payload       the raw packet payload beginning with the message byte
   --  @param Expected_Name the ASCII service name the accept must echo back
   --  @return Ok when the message type, encoded name, and length all match;
   --          Handshake_Failed on any mismatch or malformed payload
   function Parse_Service_Accept
     (Payload       : Ada.Streams.Stream_Element_Array;
      Expected_Name : String)
      return CryptoLib.Errors.Status;
end SSH_Lib.Protocol.Service;
