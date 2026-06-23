with Ada.Streams;
with CryptoLib.Errors;
with SSH_Lib.Protocol.Buffers;

package SSH_Lib.Protocol.Global_Requests is

   SSH_MSG_GLOBAL_REQUEST  : constant Ada.Streams.Stream_Element := 80;
   SSH_MSG_REQUEST_SUCCESS : constant Ada.Streams.Stream_Element := 81;
   SSH_MSG_REQUEST_FAILURE : constant Ada.Streams.Stream_Element := 82;

   type Global_Request is record
      Want_Reply : Boolean := False;
   end record;

   function Encode_TCPIP_Forward_Request
     (Bind_Address : String;
      Bind_Port    : Natural)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;

   function Encode_Cancel_TCPIP_Forward_Request
     (Bind_Address : String;
      Bind_Port    : Natural)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;

   function Parse_TCPIP_Forward_Reply
     (Payload        : Ada.Streams.Stream_Element_Array;
      Requested_Port : Natural;
      Bound_Port     : out Natural)
      return CryptoLib.Errors.Status;

   function Parse_Global_Request
     (Payload : Ada.Streams.Stream_Element_Array;
      Item    : out Global_Request)
      return CryptoLib.Errors.Status;

   function Encode_Request_Failure
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;

   function Ignorable_While_Waiting_For_Channel_Response
     (Payload : Ada.Streams.Stream_Element_Array)
      return Boolean;
end SSH_Lib.Protocol.Global_Requests;
