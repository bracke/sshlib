with Ada.Streams;
with CryptoLib.Errors;
with SSH_Lib.Protocol.Buffers;

package SSH_Lib.Protocol.Protected_Packets.Test_Support is
   function Attach_Inbound_Mac
     (Item             : Protected_State;
      Cleartext_Packet : Ada.Streams.Stream_Element_Array;
      Packet           : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;
end SSH_Lib.Protocol.Protected_Packets.Test_Support;
