with Ada.Streams;
with CryptoLib.Errors;
with SSH_Lib.Protocol.Buffers;

--  @summary Classification and handling of SSH transport-layer control messages.
--
--  Recognizes the generic transport messages (DISCONNECT, IGNORE,
--  UNIMPLEMENTED, DEBUG, EXT_INFO) so callers waiting for a specific reply can
--  skip the harmless ones, map a peer disconnect to a failure status, and build
--  an outgoing DISCONNECT.
package SSH_Lib.Protocol.Transport_Messages is

   type Transport_Message_Kind is
     (Transport_Disconnect,
      Transport_Ignore,
      Transport_Unimplemented,
      Transport_Debug,
      Transport_Ext_Info,
      Transport_Other);

   --  Classify a message payload by its leading message-number byte.
   --  @param Payload the raw transport message payload
   --  @return the message kind, or Transport_Other if unrecognized or empty
   function Classify
     (Payload : Ada.Streams.Stream_Element_Array)
      return Transport_Message_Kind;

   --  Report whether a message may be silently skipped while awaiting another reply.
   --  @param Payload the raw transport message payload
   --  @return True for IGNORE, UNIMPLEMENTED, DEBUG, and EXT_INFO messages
   function Is_Ignorable_During_Wait
     (Payload : Ada.Streams.Stream_Element_Array)
      return Boolean;

   --  Map a message to a failure status, promoting a peer DISCONNECT to Connection_Failed.
   --  @param Payload         the raw transport message payload
   --  @param Default_Failure the status to return when Payload is not a DISCONNECT
   --  @return Connection_Failed for a DISCONNECT, otherwise Default_Failure
   function Failure_Status
     (Payload          : Ada.Streams.Stream_Element_Array;
      Default_Failure : CryptoLib.Errors.Status)
      return CryptoLib.Errors.Status;

   --  Encode an outgoing SSH_MSG_DISCONNECT with the given reason and description.
   --  @param Reason_Code the RFC 4253 disconnect reason code
   --  @param Description  the human-readable disconnect description text
   --  @return the encoded DISCONNECT wire payload (empty on encoding failure)
   function Encode_Disconnect
     (Reason_Code : Natural;
      Description : String)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;
end SSH_Lib.Protocol.Transport_Messages;
