with Interfaces;
with CryptoLib.Errors;
with SSH_Lib.Protocol.Numbers;

package body SSH_Lib.Derive is

   use Ada.Streams;
   use type CryptoLib.Errors.Status;
   use CryptoLib.Buffers;

   function Digest_To_Array
     (Digest_Value : CryptoLib.Hashes.SHA1_Digest) return Stream_Element_Array
   is
      Result : Stream_Element_Array (1 .. 20);
   begin
      for Index_Value in Digest_Value'Range loop
         Result (Stream_Element_Offset (Index_Value)) :=
           Digest_Value (Index_Value);
      end loop;
      return Result;
   end Digest_To_Array;

   function Digest_To_Array
     (Digest_Value : CryptoLib.Hashes.SHA256_Digest)
      return Stream_Element_Array
   is
      Result : Stream_Element_Array (1 .. 32);
   begin
      for Index_Value in Digest_Value'Range loop
         Result (Stream_Element_Offset (Index_Value)) :=
           Digest_Value (Index_Value);
      end loop;
      return Result;
   end Digest_To_Array;

   function Digest_To_Array
     (Digest_Value : CryptoLib.Hashes.SHA512_Digest)
      return Stream_Element_Array
   is
      Result : Stream_Element_Array (1 .. 64);
   begin
      for Index_Value in Digest_Value'Range loop
         Result (Stream_Element_Offset (Index_Value)) :=
           Digest_Value (Index_Value);
      end loop;
      return Result;
   end Digest_To_Array;

   function Append_Mpint
     (Work_Item : in out Packet_Buffer; Payload : Stream_Element_Array)
      return Boolean
   is
      First_Nonzero : Stream_Element_Offset := Payload'First;
      Magnitude     : Packet_Buffer;
   begin
      if Payload'Length = 0 then
         return
           Append (Work_Item, SSH_Lib.Protocol.Numbers.Encode_Uint32 (0))
           = CryptoLib.Errors.Ok;
      end if;

      while First_Nonzero <= Payload'Last and then Payload (First_Nonzero) = 0
      loop
         First_Nonzero := First_Nonzero + 1;
      end loop;

      if First_Nonzero > Payload'Last then
         return
           Append (Work_Item, SSH_Lib.Protocol.Numbers.Encode_Uint32 (0))
           = CryptoLib.Errors.Ok;
      end if;

      Clear (Magnitude);
      if Payload (First_Nonzero) >= 16#80# then
         if Append_Byte (Magnitude, 0) /= CryptoLib.Errors.Ok then
            return False;
         end if;
      end if;
      if Append (Magnitude, Payload (First_Nonzero .. Payload'Last))
        /= CryptoLib.Errors.Ok
      then
         return False;
      end if;
      return
        Append
          (Work_Item,
           SSH_Lib.Protocol.Numbers.Encode_Uint32
             (Interfaces.Unsigned_32 (Length (Magnitude))))
        = CryptoLib.Errors.Ok
        and then
          Append (Work_Item, To_Array (Magnitude)) = CryptoLib.Errors.Ok;
   end Append_Mpint;

   function One_Digest_SHA1
     (Shared_Secret      : Stream_Element_Array;
      Exchange_Hash      : CryptoLib.Hashes.SHA1_Digest;
      Session_Identifier : Stream_Element_Array;
      Label_Value        : Character;
      Prior_Key_Data     : Stream_Element_Array;
      Is_First_Block     : Boolean) return CryptoLib.Hashes.SHA1_Digest
   is
      Work_Item  : Packet_Buffer;
      Label_Byte : constant Stream_Element_Array (1 .. 1) :=
        [1 => Stream_Element (Character'Pos (Label_Value))];
   begin
      Clear (Work_Item);
      if not Append_Mpint (Work_Item, Shared_Secret) then
         return [others => 0];
      end if;
      if Append (Work_Item, Digest_To_Array (Exchange_Hash))
        /= CryptoLib.Errors.Ok
      then
         return [others => 0];
      end if;
      if Is_First_Block then
         if Append (Work_Item, Label_Byte) /= CryptoLib.Errors.Ok then
            return [others => 0];
         end if;
         if Append (Work_Item, Session_Identifier) /= CryptoLib.Errors.Ok then
            return [others => 0];
         end if;
      else
         if Append (Work_Item, Prior_Key_Data) /= CryptoLib.Errors.Ok then
            return [others => 0];
         end if;
      end if;
      return CryptoLib.Hashes.SHA1 (To_Array (Work_Item));
   end One_Digest_SHA1;

   function Derive_SHA1
     (Shared_Secret      : Stream_Element_Array;
      Exchange_Hash      : CryptoLib.Hashes.SHA1_Digest;
      Session_Identifier : Stream_Element_Array;
      Label_Value        : Character;
      Requested_Length   : Natural) return Packet_Buffer
   is
      Result_Item  : Packet_Buffer;
      Digest_Value : CryptoLib.Hashes.SHA1_Digest;
      Digest_Data  : Stream_Element_Array (1 .. 20);
      Need_Count   : Natural;
      Take_Count   : Natural;
   begin
      Clear (Result_Item);
      if Requested_Length = 0 or else Session_Identifier'Length = 0 then
         return Result_Item;
      end if;

      while Length (Result_Item) < Requested_Length loop
         Need_Count := Requested_Length - Length (Result_Item);
         Digest_Value :=
           One_Digest_SHA1
             (Shared_Secret,
              Exchange_Hash,
              Session_Identifier,
              Label_Value,
              To_Array (Result_Item),
              Length (Result_Item) = 0);
         Digest_Data := Digest_To_Array (Digest_Value);
         if Need_Count < Digest_Data'Length then
            Take_Count := Need_Count;
         else
            Take_Count := Digest_Data'Length;
         end if;
         if Append
              (Result_Item,
               Digest_Data (1 .. Stream_Element_Offset (Take_Count)))
           /= CryptoLib.Errors.Ok
         then
            Clear (Result_Item);
            return Result_Item;
         end if;
      end loop;

      return Result_Item;
   exception
      when others =>
         Clear (Result_Item);
         return Result_Item;
   end Derive_SHA1;

   function One_Digest
     (Shared_Secret      : Stream_Element_Array;
      Exchange_Hash      : CryptoLib.Hashes.SHA256_Digest;
      Session_Identifier : CryptoLib.Hashes.SHA256_Digest;
      Label_Value        : Character;
      Prior_Key_Data     : Stream_Element_Array;
      Is_First_Block     : Boolean) return CryptoLib.Hashes.SHA256_Digest
   is
      Work_Item  : Packet_Buffer;
      Label_Byte : constant Stream_Element_Array (1 .. 1) :=
        [1 => Stream_Element (Character'Pos (Label_Value))];
   begin
      Clear (Work_Item);
      if not Append_Mpint (Work_Item, Shared_Secret) then
         return [others => 0];
      end if;
      if Append (Work_Item, Digest_To_Array (Exchange_Hash))
        /= CryptoLib.Errors.Ok
      then
         return [others => 0];
      end if;
      if Is_First_Block then
         if Append (Work_Item, Label_Byte) /= CryptoLib.Errors.Ok then
            return [others => 0];
         end if;
         if Append (Work_Item, Digest_To_Array (Session_Identifier))
           /= CryptoLib.Errors.Ok
         then
            return [others => 0];
         end if;
      else
         if Append (Work_Item, Prior_Key_Data) /= CryptoLib.Errors.Ok then
            return [others => 0];
         end if;
      end if;
      return CryptoLib.Hashes.SHA256 (To_Array (Work_Item));
   end One_Digest;

   function Derive_SHA256
     (Shared_Secret      : Stream_Element_Array;
      Exchange_Hash      : CryptoLib.Hashes.SHA256_Digest;
      Session_Identifier : CryptoLib.Hashes.SHA256_Digest;
      Label_Value        : Character;
      Requested_Length   : Natural) return Packet_Buffer
   is
      Result_Item  : Packet_Buffer;
      Digest_Value : CryptoLib.Hashes.SHA256_Digest;
      Digest_Data  : Stream_Element_Array (1 .. 32);
      Need_Count   : Natural;
      Take_Count   : Natural;
   begin
      Clear (Result_Item);
      if Requested_Length = 0 then
         return Result_Item;
      end if;

      while Length (Result_Item) < Requested_Length loop
         Need_Count := Requested_Length - Length (Result_Item);
         Digest_Value :=
           One_Digest
             (Shared_Secret,
              Exchange_Hash,
              Session_Identifier,
              Label_Value,
              To_Array (Result_Item),
              Length (Result_Item) = 0);
         Digest_Data := Digest_To_Array (Digest_Value);
         if Need_Count < Digest_Data'Length then
            Take_Count := Need_Count;
         else
            Take_Count := Digest_Data'Length;
         end if;
         if Append
              (Result_Item,
               Digest_Data (1 .. Stream_Element_Offset (Take_Count)))
           /= CryptoLib.Errors.Ok
         then
            Clear (Result_Item);
            return Result_Item;
         end if;
      end loop;

      return Result_Item;
   exception
      when others =>
         Clear (Result_Item);
         return Result_Item;
   end Derive_SHA256;

   function One_Digest_SHA512
     (Shared_Secret      : Stream_Element_Array;
      Exchange_Hash      : CryptoLib.Hashes.SHA512_Digest;
      Session_Identifier : CryptoLib.Hashes.SHA512_Digest;
      Label_Value        : Character;
      Prior_Key_Data     : Stream_Element_Array;
      Is_First_Block     : Boolean) return CryptoLib.Hashes.SHA512_Digest
   is
      Work_Item  : Packet_Buffer;
      Label_Byte : constant Stream_Element_Array (1 .. 1) :=
        [1 => Stream_Element (Character'Pos (Label_Value))];
   begin
      Clear (Work_Item);
      if not Append_Mpint (Work_Item, Shared_Secret) then
         return [others => 0];
      end if;
      if Append (Work_Item, Digest_To_Array (Exchange_Hash))
        /= CryptoLib.Errors.Ok
      then
         return [others => 0];
      end if;
      if Is_First_Block then
         if Append (Work_Item, Label_Byte) /= CryptoLib.Errors.Ok then
            return [others => 0];
         end if;
         if Append (Work_Item, Digest_To_Array (Session_Identifier))
           /= CryptoLib.Errors.Ok
         then
            return [others => 0];
         end if;
      else
         if Append (Work_Item, Prior_Key_Data) /= CryptoLib.Errors.Ok then
            return [others => 0];
         end if;
      end if;
      return CryptoLib.Hashes.SHA512 (To_Array (Work_Item));
   end One_Digest_SHA512;

   function Derive_SHA512
     (Shared_Secret      : Stream_Element_Array;
      Exchange_Hash      : CryptoLib.Hashes.SHA512_Digest;
      Session_Identifier : CryptoLib.Hashes.SHA512_Digest;
      Label_Value        : Character;
      Requested_Length   : Natural) return Packet_Buffer
   is
      Result_Item  : Packet_Buffer;
      Digest_Value : CryptoLib.Hashes.SHA512_Digest;
      Digest_Data  : Stream_Element_Array (1 .. 64);
      Need_Count   : Natural;
      Take_Count   : Natural;
   begin
      Clear (Result_Item);
      if Requested_Length = 0 then
         return Result_Item;
      end if;

      while Length (Result_Item) < Requested_Length loop
         Need_Count := Requested_Length - Length (Result_Item);
         Digest_Value :=
           One_Digest_SHA512
             (Shared_Secret,
              Exchange_Hash,
              Session_Identifier,
              Label_Value,
              To_Array (Result_Item),
              Length (Result_Item) = 0);
         Digest_Data := Digest_To_Array (Digest_Value);
         if Need_Count < Digest_Data'Length then
            Take_Count := Need_Count;
         else
            Take_Count := Digest_Data'Length;
         end if;
         if Append
              (Result_Item,
               Digest_Data (1 .. Stream_Element_Offset (Take_Count)))
           /= CryptoLib.Errors.Ok
         then
            Clear (Result_Item);
            return Result_Item;
         end if;
      end loop;

      return Result_Item;
   exception
      when others =>
         Clear (Result_Item);
         return Result_Item;
   end Derive_SHA512;

end SSH_Lib.Derive;
