with Ada.Streams;
with CryptoLib.Errors;
with SSH_Lib.Protocol.Buffers;

--  @summary Internal test-harness helpers for the protected-packet codec.
--
--  Exposes internals of Protected_State that the AUnit suite needs to build
--  crafted wire packets; not part of the public transport API.
package SSH_Lib.Protocol.Protected_Packets.Test_Support is
   --  Build an inbound wire packet by appending the inbound MAC over a
   --  cleartext packet, using the state's inbound MAC key and sequence number.
   --  @param Item             the protected state supplying the inbound MAC key/algorithm
   --  @param Cleartext_Packet the cleartext packet (length, padding, payload) to authenticate
   --  @param Packet           the resulting packet with the inbound MAC appended
   --  @return Ok on success, or an error Status on failure
   function Attach_Inbound_Mac
     (Item             : Protected_State;
      Cleartext_Packet : Ada.Streams.Stream_Element_Array;
      Packet           : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;
end SSH_Lib.Protocol.Protected_Packets.Test_Support;
