with Ada.Streams;
with CryptoLib.Errors;
with SSH_Lib.Protocol.Buffers;

package SSH_Lib.Protocol.Transport_Messages is

   type Transport_Message_Kind is
     (Transport_Disconnect,
      Transport_Ignore,
      Transport_Unimplemented,
      Transport_Debug,
      Transport_Ext_Info,
      Transport_Other);

   function Classify
     (Payload : Ada.Streams.Stream_Element_Array)
      return Transport_Message_Kind;

   function Is_Ignorable_During_Wait
     (Payload : Ada.Streams.Stream_Element_Array)
      return Boolean;

   function Failure_Status
     (Payload          : Ada.Streams.Stream_Element_Array;
      Default_Failure : CryptoLib.Errors.Status)
      return CryptoLib.Errors.Status;

   function Encode_Disconnect
     (Reason_Code : Natural;
      Description : String)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;
end SSH_Lib.Protocol.Transport_Messages;
