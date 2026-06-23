with SSH_Lib.Protocol.Numbers;
with SSH_Lib.Protocol.Random_Padding;

package body SSH_Lib.Protocol.Packets is

   use Ada.Streams;
   use Interfaces;
   use CryptoLib.Errors;
   use SSH_Lib.Protocol.Buffers;

   procedure Reset (Item : out Protocol_State) is
   begin
      Item.Inbound_Value := 0;
      Item.Outbound_Value := 0;
   end Reset;

   function Inbound_Sequence
     (Item : Protocol_State)
      return Unsigned_32
   is
   begin
      return Item.Inbound_Value;
   end Inbound_Sequence;

   function Outbound_Sequence
     (Item : Protocol_State)
      return Unsigned_32
   is
   begin
      return Item.Outbound_Value;
   end Outbound_Sequence;

   procedure Set_Sequences_For_Test
     (Item           : in out Protocol_State;
      Inbound_Value  : Unsigned_32;
      Outbound_Value : Unsigned_32)
   is
   begin
      Item.Inbound_Value := Inbound_Value;
      Item.Outbound_Value := Outbound_Value;
   end Set_Sequences_For_Test;

   procedure Increment_Outbound (Item : in out Protocol_State) is
   begin
      Item.Outbound_Value := Item.Outbound_Value + 1;
   end Increment_Outbound;

   procedure Increment_Inbound (Item : in out Protocol_State) is
   begin
      Item.Inbound_Value := Item.Inbound_Value + 1;
   end Increment_Inbound;

   function Effective_Block_Size (Block_Size : Natural) return Natural is
   begin
      if Block_Size < Cleartext_Block_Size then
         return Cleartext_Block_Size;
      elsif Block_Size > 255 then
         return 255;
      else
         return Block_Size;
      end if;
   end Effective_Block_Size;

   function Padding_Length_For
     (Payload_Length : Natural;
      Block_Size     : Natural)
      return Natural
   is
      Base_Length : constant Natural := 1 + Payload_Length;
      Padding_Length : Natural := Minimum_Padding_Size;
      Effective_Size  : constant Natural := Effective_Block_Size (Block_Size);
   begin
      while (4 + Base_Length + Padding_Length) mod Effective_Size /= 0 loop
         Padding_Length := Padding_Length + 1;
      end loop;
      return Padding_Length;
   end Padding_Length_For;

   function Encode_Cleartext_Packet
     (Item              : in out Protocol_State;
      Payload           : Stream_Element_Array;
      Packet            : out Packet_Buffer;
      Use_Test_Padding  : Boolean := False;
      Test_Padding_Byte : Stream_Element := 0;
      Block_Size        : Natural := Cleartext_Block_Size)
      return Status
   is
      Padding_Length : Natural;
      Packet_Length : Natural;
      Effective_Size : constant Natural := Effective_Block_Size (Block_Size);
      Status_Value : Status;
   begin
      Clear (Packet);

      if Payload'Length > Maximum_Packet_Length - 1 - Minimum_Padding_Size then
         return Handshake_Failed;
      end if;

      Padding_Length := Padding_Length_For (Payload'Length, Effective_Size);
      Packet_Length := 1 + Payload'Length + Padding_Length;

      if Packet_Length > Maximum_Packet_Length then
         return Handshake_Failed;
      end if;

      if (4 + Packet_Length) mod Effective_Size /= 0 then
         return Internal_Error;
      end if;

      Status_Value := Append
        (Packet,
         SSH_Lib.Protocol.Numbers.Encode_Uint32 (Unsigned_32 (Packet_Length)));
      if Status_Value /= Ok then
         Clear (Packet);
         return Status_Value;
      end if;

      Status_Value := Append_Byte (Packet, Stream_Element (Padding_Length));
      if Status_Value /= Ok then
         Clear (Packet);
         return Status_Value;
      end if;

      Status_Value := Append (Packet, Payload);
      if Status_Value /= Ok then
         Clear (Packet);
         return Status_Value;
      end if;

      declare
         Padding_Remaining : Natural := Padding_Length;
      begin
         while Padding_Remaining > 0 loop
            declare
               Byte_Value : Stream_Element;
            begin
               if Use_Test_Padding then
                  Byte_Value := Test_Padding_Byte;
               else
                  Status_Value := SSH_Lib.Protocol.Random_Padding.Next_Byte (Byte_Value);
                  if Status_Value /= Ok then
                     Clear (Packet);
                     return Status_Value;
                  end if;
               end if;

               Status_Value := Append_Byte (Packet, Byte_Value);
               if Status_Value /= Ok then
                  Clear (Packet);
                  return Status_Value;
               end if;

               Padding_Remaining := Padding_Remaining - 1;
            end;
         end loop;
      end;

      Increment_Outbound (Item);
      return Ok;
   exception
      when others =>
         Clear (Packet);
         return Internal_Error;
   end Encode_Cleartext_Packet;

   function Decode_Cleartext_Packet
     (Item    : in out Protocol_State;
      Packet  : Stream_Element_Array;
      Payload : out Packet_Buffer;
      Block_Size : Natural := Cleartext_Block_Size)
      return Status
   is
      Packet_Length_Value : Unsigned_32;
      Cursor : Stream_Element_Offset;
      Padding_Length : Natural;
      Payload_Length : Natural;
      Packet_End : Stream_Element_Offset;
      Payload_End : Stream_Element_Offset;
      Effective_Size : constant Natural := Effective_Block_Size (Block_Size);
      Status_Value : Status;
   begin
      Clear (Payload);
      if Packet'Length < 4 then
         return End_Of_Stream;
      end if;

      Status_Value := SSH_Lib.Protocol.Numbers.Decode_Uint32
        (Packet, Packet'First, Packet_Length_Value, Cursor);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      if Packet_Length_Value < Unsigned_32 (1 + Minimum_Padding_Size) then
         return Handshake_Failed;
      end if;

      if Packet_Length_Value > Unsigned_32 (Maximum_Packet_Length) then
         return Handshake_Failed;
      end if;

      if Natural (Packet'Length) < Natural (Packet_Length_Value) + 4 then
         return End_Of_Stream;
      end if;

      if Natural (Packet'Length) > Natural (Packet_Length_Value) + 4 then
         return Handshake_Failed;
      end if;

      if (Natural (Packet_Length_Value) + 4) mod Effective_Size /= 0 then
         return Handshake_Failed;
      end if;

      Packet_End := Packet'First + Stream_Element_Offset (Packet_Length_Value) + 3;
      Padding_Length := Natural (Packet (Cursor));
      if Padding_Length < Minimum_Padding_Size then
         return Handshake_Failed;
      end if;

      if Padding_Length > Natural (Packet_Length_Value) - 1 then
         return Handshake_Failed;
      end if;

      Payload_Length := Natural (Packet_Length_Value) - 1 - Padding_Length;
      if Payload_Length = 0 then
         Increment_Inbound (Item);
         return Ok;
      end if;

      Payload_End := Cursor + Stream_Element_Offset (Payload_Length);
      if Payload_End > Packet_End then
         return Handshake_Failed;
      end if;

      Status_Value := Set (Payload, Packet (Cursor + 1 .. Payload_End));
      if Status_Value /= Ok then
         Clear (Payload);
         return Status_Value;
      end if;

      Increment_Inbound (Item);
      return Ok;
   exception
      when others =>
         Clear (Payload);
         return Internal_Error;
   end Decode_Cleartext_Packet;
end SSH_Lib.Protocol.Packets;
