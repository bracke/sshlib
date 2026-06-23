with Interfaces;
with CryptoLib.Hashes;
with CryptoLib.Macs;
with SSH_Lib.Protocol.Numbers;

package body SSH_Lib.Protocol.Protected_Packets.Test_Support is
   use CryptoLib.Errors;
   use SSH_Lib.Protocol.Buffers;

   function Digest_To_Array
     (Digest_Item : CryptoLib.Hashes.SHA256_Digest)
      return Stream_Element_Array
   is
   begin
      return Result : Stream_Element_Array (1 .. Stream_Element_Offset (Mac_Length)) do
         for Index_Value in Digest_Item'Range loop
            Result (Stream_Element_Offset (Index_Value)) := Digest_Item (Index_Value);
         end loop;
      end return;
   end Digest_To_Array;

   function Mac_Input
     (Sequence_Value : Interfaces.Unsigned_32;
      Packet         : Stream_Element_Array)
      return Stream_Element_Array
   is
      Sequence_Bytes : constant Stream_Element_Array :=
        SSH_Lib.Protocol.Numbers.Encode_Uint32 (Sequence_Value);
   begin
      return Result : Stream_Element_Array
        (1 .. Stream_Element_Offset (Sequence_Bytes'Length + Packet'Length))
      do
         Result (1 .. Stream_Element_Offset (Sequence_Bytes'Length)) := Sequence_Bytes;
         if Packet'Length > 0 then
            Result
              (Stream_Element_Offset (Sequence_Bytes'Length) + 1 .. Result'Last) :=
              Packet;
         end if;
      end return;
   end Mac_Input;

   function Attach_Inbound_Mac
     (Item             : Protected_State;
      Cleartext_Packet : Stream_Element_Array;
      Packet           : out Packet_Buffer)
      return Status
   is
      Input_Data : constant Stream_Element_Array :=
        Mac_Input (Inbound_Sequence (Item), Cleartext_Packet);
      Mac_Array : constant Stream_Element_Array :=
        Digest_To_Array
          (CryptoLib.Macs.HMAC_SHA256
             (Item.Inbound_Mac_Key_Data
                (1 .. Stream_Element_Offset (Item.Inbound_Mac_Length)),
              Input_Data));
      Status_Value : Status;
   begin
      Clear (Packet);
      Status_Value := Append (Packet, Cleartext_Packet);
      if Status_Value /= Ok then
         Clear (Packet);
         return Status_Value;
      end if;
      Status_Value := Append (Packet, Mac_Array);
      if Status_Value /= Ok then
         Clear (Packet);
         return Status_Value;
      end if;
      return Ok;
   exception
      when others =>
         Clear (Packet);
         return Internal_Error;
   end Attach_Inbound_Mac;
end SSH_Lib.Protocol.Protected_Packets.Test_Support;
