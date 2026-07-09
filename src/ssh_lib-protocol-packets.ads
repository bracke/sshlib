with Ada.Streams;
with Interfaces;
with CryptoLib.Errors;
with SSH_Lib.Protocol.Buffers;

--  @summary Frame and parse the SSH Binary Packet Protocol in cleartext, tracking sequence numbers.
--
--  Wraps a payload into an RFC 4253 binary packet (length, padding length,
--  payload, random padding) and reverses it, holding the inbound and outbound
--  packet sequence numbers that the MAC and AEAD ciphers consume as nonces.
package SSH_Lib.Protocol.Packets is

   Cleartext_Block_Size : constant Natural := 8;
   Minimum_Padding_Size : constant Natural := 4;
   Maximum_Packet_Length : constant Natural := 256 * 1024;

   type Protocol_State is private;

   --  Reset both packet sequence numbers to zero.
   --  @param Item the protocol state to reset
   procedure Reset (Item : out Protocol_State);

   --  Return the current inbound (received) packet sequence number.
   --  @param Item the protocol state
   --  @return the next inbound packet sequence number
   function Inbound_Sequence
     (Item : Protocol_State)
      return Interfaces.Unsigned_32;

   --  Return the current outbound (sent) packet sequence number.
   --  @param Item the protocol state
   --  @return the next outbound packet sequence number
   function Outbound_Sequence
     (Item : Protocol_State)
      return Interfaces.Unsigned_32;

   --  Force both packet sequence numbers to given values, for testing.
   --  @param Item           the protocol state to modify
   --  @param Inbound_Value  the inbound sequence number to set
   --  @param Outbound_Value the outbound sequence number to set
   procedure Set_Sequences_For_Test
     (Item           : in out Protocol_State;
      Inbound_Value  : Interfaces.Unsigned_32;
      Outbound_Value : Interfaces.Unsigned_32);

   --  Frame a payload into a padded cleartext binary packet, advancing the outbound sequence.
   --  @param Item               the protocol state (its outbound sequence is advanced)
   --  @param Payload            the payload bytes to wrap
   --  @param Packet             the framed binary packet
   --  @param Use_Test_Padding   whether to use a fixed padding byte instead of random padding
   --  @param Test_Padding_Byte  the fixed padding byte to use when Use_Test_Padding is set
   --  @param Block_Size         the alignment block size for padding
   --  @param Count_Length_Field whether the 4-byte length field is counted in the padding alignment
   --  @return Ok on success, an error status if the payload is too large or on error
   function Encode_Cleartext_Packet
     (Item              : in out Protocol_State;
      Payload           : Ada.Streams.Stream_Element_Array;
      Packet            : out SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Use_Test_Padding  : Boolean := False;
      Test_Padding_Byte : Ada.Streams.Stream_Element := 0;
      Block_Size        : Natural := Cleartext_Block_Size;
      Count_Length_Field : Boolean := True)
      return CryptoLib.Errors.Status;
   --  Count_Length_Field controls whether the 4-byte packet-length field is
   --  included in the block-size padding alignment. It is for block ciphers
   --  (the default), but must be False for AEAD ciphers (chacha20-poly1305,
   --  AES-GCM), where the length field is authenticated separately and is not
   --  part of the encrypted/aligned block stream.

   --  Parse a cleartext binary packet back into its payload, advancing the inbound sequence.
   --  @param Item               the protocol state (its inbound sequence is advanced)
   --  @param Packet             the framed binary packet to parse
   --  @param Payload            the recovered payload bytes
   --  @param Block_Size         the alignment block size used when framing
   --  @param Count_Length_Field whether the 4-byte length field was counted in the padding alignment
   --  @return Ok on success, an error status if the packet is malformed
   function Decode_Cleartext_Packet
     (Item       : in out Protocol_State;
      Packet     : Ada.Streams.Stream_Element_Array;
      Payload    : out SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Block_Size : Natural := Cleartext_Block_Size;
      Count_Length_Field : Boolean := True)
      return CryptoLib.Errors.Status;
   --  Count_Length_Field mirrors Encode_Cleartext_Packet: it must be False for
   --  AEAD ciphers (chacha20-poly1305, AES-GCM) so the 4-byte length field is
   --  excluded from the block-size alignment check on the decrypted plaintext.

private
   type Protocol_State is record
      Inbound_Value  : Interfaces.Unsigned_32 := 0;
      Outbound_Value : Interfaces.Unsigned_32 := 0;
   end record;
end SSH_Lib.Protocol.Packets;
