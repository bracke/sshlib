with Ada.Streams;
with Interfaces;
with CryptoLib.Errors;
with SSH_Lib.Protocol.Buffers;

package SSH_Lib.Protocol.Packets is

   Cleartext_Block_Size : constant Natural := 8;
   Minimum_Padding_Size : constant Natural := 4;
   Maximum_Packet_Length : constant Natural := 256 * 1024;

   type Protocol_State is private;

   procedure Reset (Item : out Protocol_State);

   function Inbound_Sequence
     (Item : Protocol_State)
      return Interfaces.Unsigned_32;

   function Outbound_Sequence
     (Item : Protocol_State)
      return Interfaces.Unsigned_32;

   procedure Set_Sequences_For_Test
     (Item           : in out Protocol_State;
      Inbound_Value  : Interfaces.Unsigned_32;
      Outbound_Value : Interfaces.Unsigned_32);

   function Encode_Cleartext_Packet
     (Item              : in out Protocol_State;
      Payload           : Ada.Streams.Stream_Element_Array;
      Packet            : out SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Use_Test_Padding  : Boolean := False;
      Test_Padding_Byte : Ada.Streams.Stream_Element := 0;
      Block_Size        : Natural := Cleartext_Block_Size)
      return CryptoLib.Errors.Status;

   function Decode_Cleartext_Packet
     (Item       : in out Protocol_State;
      Packet     : Ada.Streams.Stream_Element_Array;
      Payload    : out SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Block_Size : Natural := Cleartext_Block_Size)
      return CryptoLib.Errors.Status;

private
   type Protocol_State is record
      Inbound_Value  : Interfaces.Unsigned_32 := 0;
      Outbound_Value : Interfaces.Unsigned_32 := 0;
   end record;
end SSH_Lib.Protocol.Packets;
