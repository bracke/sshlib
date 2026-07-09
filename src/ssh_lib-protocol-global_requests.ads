with Ada.Streams;
with CryptoLib.Errors;
with SSH_Lib.Protocol.Buffers;

--  @summary Encode and parse RFC 4254 SSH_MSG_GLOBAL_REQUEST messages and replies.
--
--  Covers the global-request messages used for remote TCP/IP forwarding
--  (tcpip-forward / cancel-tcpip-forward), OpenSSH keepalives, and the
--  SUCCESS/FAILURE replies, plus the predicates the transport uses to skip
--  global-request traffic while waiting for a channel response.
package SSH_Lib.Protocol.Global_Requests is

   SSH_MSG_GLOBAL_REQUEST  : constant Ada.Streams.Stream_Element := 80;
   SSH_MSG_REQUEST_SUCCESS : constant Ada.Streams.Stream_Element := 81;
   SSH_MSG_REQUEST_FAILURE : constant Ada.Streams.Stream_Element := 82;

   type Global_Request is record
      Want_Reply : Boolean := False;
   end record;

   --  Encode a "tcpip-forward" global request asking the server to listen on a port.
   --  @param Bind_Address the address to bind on the server
   --  @param Bind_Port    the port to bind (0 requests a server-assigned port)
   --  @return the encoded packet, or an empty buffer on invalid input
   function Encode_TCPIP_Forward_Request
     (Bind_Address : String;
      Bind_Port    : Natural)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;

   --  Encode a "cancel-tcpip-forward" global request tearing down a forwarding.
   --  @param Bind_Address the previously bound address
   --  @param Bind_Port    the previously bound port
   --  @return the encoded packet, or an empty buffer on invalid input
   function Encode_Cancel_TCPIP_Forward_Request
     (Bind_Address : String;
      Bind_Port    : Natural)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;

   --  Encode a "keepalive@openssh.com" global request with want-reply set.
   --  @return the encoded keepalive packet, or an empty buffer on error
   function Encode_Keepalive_Request
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;

   --  Test whether a payload is the single-byte REQUEST_SUCCESS reply to a keepalive.
   --  @param Payload the received message payload
   --  @return True if the payload is exactly one SSH_MSG_REQUEST_SUCCESS byte
   function Is_Keepalive_Success
     (Payload : Ada.Streams.Stream_Element_Array)
      return Boolean;

   --  Parse the SUCCESS/FAILURE reply to a tcpip-forward request and recover the port.
   --  @param Payload        the received reply payload
   --  @param Requested_Port the port originally requested (0 means server-assigned)
   --  @param Bound_Port     the resulting bound port (echoed request, or decoded for 0)
   --  @return Ok on a valid success reply, Channel_Request_Failed otherwise
   function Parse_TCPIP_Forward_Reply
     (Payload        : Ada.Streams.Stream_Element_Array;
      Requested_Port : Natural;
      Bound_Port     : out Natural)
      return CryptoLib.Errors.Status;

   --  Parse an inbound SSH_MSG_GLOBAL_REQUEST, extracting its want-reply flag.
   --  @param Payload the received global-request payload
   --  @param Item    the parsed request (its Want_Reply flag)
   --  @return Ok on a well-formed request, Read_Failed otherwise
   function Parse_Global_Request
     (Payload : Ada.Streams.Stream_Element_Array;
      Item    : out Global_Request)
      return CryptoLib.Errors.Status;

   --  Encode a bare SSH_MSG_REQUEST_FAILURE reply to decline a global request.
   --  @return the encoded failure packet, or an empty buffer on error
   function Encode_Request_Failure
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;

   --  Test whether a message may be safely skipped while awaiting a channel response.
   --  @param Payload the received message payload
   --  @return True for REQUEST_SUCCESS/FAILURE and other transport messages ignorable during a wait
   function Ignorable_While_Waiting_For_Channel_Response
     (Payload : Ada.Streams.Stream_Element_Array)
      return Boolean;
end SSH_Lib.Protocol.Global_Requests;
