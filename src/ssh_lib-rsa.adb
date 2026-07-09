with CryptoLib.Hashes;
with CryptoLib.Constant_Time;
with CryptoLib.Secure_Wipe;
with SSH_Lib.Protocol.Numbers;
with System;

package body SSH_Lib.RSA is
   use Ada.Streams;
   use CryptoLib.Errors;

   Maximum_RSA_Modulus_Bytes : constant Natural := 1024;

   subtype Big_Index is Natural range 0 .. Maximum_RSA_Modulus_Bytes - 1;
   type Big_Value is array (Big_Index) of Natural range 0 .. 255;

   type RSA_Public_Key is record
      Exponent_Data  : Big_Value := [others => 0];
      Modulus_Data   : Big_Value := [others => 0];
      Exponent_Bytes : Natural := 0;
      Modulus_Bytes  : Natural := 0;
   end record;

   SHA1_Digest_Info_Prefix : constant Stream_Element_Array :=
     [1  => 16#30#,
      2  => 16#21#,
      3  => 16#30#,
      4  => 16#09#,
      5  => 16#06#,
      6  => 16#05#,
      7  => 16#2B#,
      8  => 16#0E#,
      9  => 16#03#,
      10 => 16#02#,
      11 => 16#1A#,
      12 => 16#05#,
      13 => 16#00#,
      14 => 16#04#,
      15 => 16#14#];

   SHA256_Digest_Info_Prefix : constant Stream_Element_Array :=
     [1  => 16#30#,
      2  => 16#31#,
      3  => 16#30#,
      4  => 16#0D#,
      5  => 16#06#,
      6  => 16#09#,
      7  => 16#60#,
      8  => 16#86#,
      9  => 16#48#,
      10 => 16#01#,
      11 => 16#65#,
      12 => 16#03#,
      13 => 16#04#,
      14 => 16#02#,
      15 => 16#01#,
      16 => 16#05#,
      17 => 16#00#,
      18 => 16#04#,
      19 => 16#20#];

   SHA512_Digest_Info_Prefix : constant Stream_Element_Array :=
     [1  => 16#30#,
      2  => 16#51#,
      3  => 16#30#,
      4  => 16#0D#,
      5  => 16#06#,
      6  => 16#09#,
      7  => 16#60#,
      8  => 16#86#,
      9  => 16#48#,
      10 => 16#01#,
      11 => 16#65#,
      12 => 16#03#,
      13 => 16#04#,
      14 => 16#02#,
      15 => 16#03#,
      16 => 16#05#,
      17 => 16#00#,
      18 => 16#04#,
      19 => 16#40#];

   function Bytes_Equal_String
     (Data : Stream_Element_Array; Text : String) return Boolean
   is
      Text_Index : Natural := Text'First;
   begin
      if Data'Length /= Text'Length then
         return False;
      end if;

      for Data_Index in Data'Range loop
         if Natural (Data (Data_Index)) /= Character'Pos (Text (Text_Index))
         then
            return False;
         end if;
         Text_Index := Text_Index + 1;
      end loop;

      return True;
   end Bytes_Equal_String;

   function Strip_Positive_Mpint
     (Data       : Stream_Element_Array;
      Is_Modulus : Boolean;
      Result     : out Big_Value;
      Byte_Count : out Natural) return Boolean
   is
      First_Index : Stream_Element_Offset := Data'First;
      Has_Nonzero : Boolean := False;
   begin
      Result := [others => 0];
      Byte_Count := 0;
      if Data'Length = 0 then
         return False;
      end if;

      if Data (First_Index) = 0 then
         if Data'Length = 1 then
            return False;
         end if;
         if Data (First_Index + 1) < 16#80# then
            return False;
         end if;
         First_Index := First_Index + 1;
      elsif Data (First_Index) >= 16#80# then
         return False;
      end if;

      Byte_Count := Natural (Data'Last - First_Index + 1);
      if Byte_Count = 0 or else Byte_Count > Maximum_RSA_Modulus_Bytes then
         return False;
      end if;
      if (not Is_Modulus) and then Byte_Count > 8 then
         --  SSH RSA exponents are small positive integers in practice.  Keep
         --  the implementation bounded and deterministic instead of accepting
         --  attacker-controlled huge exponent work factors.
         return False;
      end if;

      declare
         Target_Index : Natural := Maximum_RSA_Modulus_Bytes - Byte_Count;
      begin
         for Source_Index in First_Index .. Data'Last loop
            Result (Target_Index) := Natural (Data (Source_Index));
            if Data (Source_Index) /= 0 then
               Has_Nonzero := True;
            end if;
            Target_Index := Target_Index + 1;
         end loop;
      end;

      return Has_Nonzero;
   exception
      when others =>
         Result := [others => 0];
         Byte_Count := 0;
         return False;
   end Strip_Positive_Mpint;

   function Compare_From
     (Left_Item : Big_Value; Right_Item : Big_Value; First_Index : Big_Index)
      return Integer is
   begin
      for Index_Value in First_Index .. Big_Index'Last loop
         if Left_Item (Index_Value) < Right_Item (Index_Value) then
            return -1;
         elsif Left_Item (Index_Value) > Right_Item (Index_Value) then
            return 1;
         end if;
      end loop;
      return 0;
   end Compare_From;

   function Compare
     (Left_Item : Big_Value; Right_Item : Big_Value) return Integer is
   begin
      return Compare_From (Left_Item, Right_Item, Big_Index'First);
   end Compare;

   procedure Subtract_In_Place_From
     (Left_Item   : in out Big_Value;
      Right_Item  : Big_Value;
      First_Index : Big_Index)
   is
      Borrow_Value : Integer := 0;
      Diff_Value   : Integer;
   begin
      for Index_Value in reverse First_Index .. Big_Index'Last loop
         Diff_Value :=
           Left_Item (Index_Value) - Right_Item (Index_Value) - Borrow_Value;
         if Diff_Value < 0 then
            Diff_Value := Diff_Value + 256;
            Borrow_Value := 1;
         else
            Borrow_Value := 0;
         end if;
         Left_Item (Index_Value) := Diff_Value;
      end loop;
   end Subtract_In_Place_From;

   function Active_First_Byte (Modulus_Item : Big_Value) return Big_Index is
   begin
      for Index_Value in Big_Index loop
         if Modulus_Item (Index_Value) /= 0 then
            if Index_Value = Big_Index'First then
               return Big_Index'First;
            else
               return Index_Value - 1;
            end if;
         end if;
      end loop;
      return Big_Index'Last;
   end Active_First_Byte;

   procedure Normalize_Mod_From
     (Item         : in out Big_Value;
      Modulus_Item : Big_Value;
      First_Index  : Big_Index) is
   begin
      while Compare_From (Item, Modulus_Item, First_Index) >= 0 loop
         Subtract_In_Place_From (Item, Modulus_Item, First_Index);
      end loop;
   end Normalize_Mod_From;

   function Add_Mod
     (Left_Item : Big_Value; Right_Item : Big_Value; Modulus_Item : Big_Value)
      return Big_Value
   is
      Result_Value : Big_Value := [others => 0];
      Carry_Value  : Natural := 0;
      Sum_Value    : Natural;
      First_Index  : constant Big_Index := Active_First_Byte (Modulus_Item);
   begin
      for Index_Value in reverse First_Index .. Big_Index'Last loop
         Sum_Value :=
           Left_Item (Index_Value) + Right_Item (Index_Value) + Carry_Value;
         Result_Value (Index_Value) := Sum_Value mod 256;
         Carry_Value := Sum_Value / 256;
      end loop;
      if Carry_Value /= 0
        or else Compare_From (Result_Value, Modulus_Item, First_Index) >= 0
      then
         Subtract_In_Place_From (Result_Value, Modulus_Item, First_Index);
      end if;
      return Result_Value;
   end Add_Mod;

   function Double_Mod
     (Item : Big_Value; Modulus_Item : Big_Value) return Big_Value is
   begin
      return Add_Mod (Item, Item, Modulus_Item);
   end Double_Mod;

   function Add_No_Mod_From
     (Left_Item : Big_Value; Right_Item : Big_Value; First_Index : Big_Index)
      return Big_Value
   is
      Result_Value : Big_Value := [others => 0];
      Carry_Value  : Natural := 0;
      Sum_Value    : Natural;
   begin
      for Index_Value in reverse First_Index .. Big_Index'Last loop
         Sum_Value :=
           Left_Item (Index_Value) + Right_Item (Index_Value) + Carry_Value;
         Result_Value (Index_Value) := Sum_Value mod 256;
         Carry_Value := Sum_Value / 256;
      end loop;
      return Result_Value;
   end Add_No_Mod_From;

   function Subtract_Mod
     (Left_Item : Big_Value; Right_Item : Big_Value; Modulus_Item : Big_Value)
      return Big_Value
   is
      First_Index  : constant Big_Index := Active_First_Byte (Modulus_Item);
      Result_Value : Big_Value := Left_Item;
   begin
      if Compare_From (Result_Value, Right_Item, First_Index) < 0 then
         Result_Value :=
           Add_No_Mod_From (Result_Value, Modulus_Item, First_Index);
      end if;
      Subtract_In_Place_From (Result_Value, Right_Item, First_Index);
      return Result_Value;
   end Subtract_Mod;

   function Bytes_Mod
     (Data : Stream_Element_Array; Modulus_Item : Big_Value) return Big_Value
   is
      Result_Value : Big_Value := [others => 0];
      Byte_Value   : Big_Value := [others => 0];
   begin
      for Data_Index in Data'Range loop
         for Bit_Index in 1 .. 8 loop
            Result_Value := Double_Mod (Result_Value, Modulus_Item);
         end loop;
         Byte_Value := [others => 0];
         Byte_Value (Big_Index'Last) := Natural (Data (Data_Index));
         Result_Value := Add_Mod (Result_Value, Byte_Value, Modulus_Item);
      end loop;
      return Result_Value;
   end Bytes_Mod;

   function Get_Bit (Item : Big_Value; Bit_Index : Natural) return Boolean is
      Byte_Index : constant Natural := Bit_Index / 8;
      Bit_Offset : constant Natural := 7 - (Bit_Index mod 8);
   begin
      return (Item (Byte_Index) / (2 ** Bit_Offset)) mod 2 = 1;
   end Get_Bit;

   function Get_Bit_Value
     (Item : Big_Value; Bit_Index : Natural) return Natural
   is
      Byte_Index : constant Natural := Bit_Index / 8;
      Bit_Offset : constant Natural := 7 - (Bit_Index mod 8);
   begin
      return (Item (Byte_Index) / (2 ** Bit_Offset)) mod 2;
   end Get_Bit_Value;

   function Select_Big_From
     (False_Item  : Big_Value;
      True_Item   : Big_Value;
      Choice      : Natural;
      First_Index : Big_Index) return Big_Value
   is
      Choice_Value : constant Natural := Choice mod 2;
      Other_Value  : constant Natural := 1 - Choice_Value;
      Result_Value : Big_Value := [others => 0];
   begin
      for Index_Value in First_Index .. Big_Index'Last loop
         Result_Value (Index_Value) :=
           False_Item (Index_Value) * Other_Value
           + True_Item (Index_Value) * Choice_Value;
      end loop;
      return Result_Value;
   end Select_Big_From;

   function First_Public_Modulus_Bit (Modulus_Item : Big_Value) return Natural
   is
   begin
      --  The modulus is public key material.  Its effective bit length may be
      --  used to bound fixed-iteration arithmetic without leaking private
      --  exponents or scalar-dependent intermediates.
      for Bit_Index in 0 .. Maximum_RSA_Modulus_Bytes * 8 - 1 loop
         if Get_Bit (Modulus_Item, Bit_Index) then
            return Bit_Index;
         end if;
      end loop;
      return Maximum_RSA_Modulus_Bytes * 8 - 1;
   end First_Public_Modulus_Bit;

   function Multiply_Mod
     (Left_Item : Big_Value; Right_Item : Big_Value; Modulus_Item : Big_Value)
      return Big_Value
   is
      Result_Value    : Big_Value := [others => 0];
      Addend_Value    : Big_Value := Left_Item;
      Candidate_Value : Big_Value := [others => 0];
      Bit_Value       : Natural;
      First_Bit       : constant Natural :=
        First_Public_Modulus_Bit (Modulus_Item);
      First_Index     : constant Big_Index := Active_First_Byte (Modulus_Item);
   begin
      Normalize_Mod_From (Addend_Value, Modulus_Item, First_Index);
      --  Fixed-iteration double-and-add over the public modulus width: compute
      --  the add candidate for every relevant bit and select it arithmetically.
      --  This removes secret-exponent branch and loop-bound leakage from RSA
      --  private signing without paying the 8192-bit maximum on ordinary keys.
      for Bit_Index in reverse First_Bit .. Maximum_RSA_Modulus_Bytes * 8 - 1
      loop
         Bit_Value := Get_Bit_Value (Right_Item, Bit_Index);
         Candidate_Value := Add_Mod (Result_Value, Addend_Value, Modulus_Item);
         Result_Value :=
           Select_Big_From
             (Result_Value, Candidate_Value, Bit_Value, First_Index);
         Addend_Value := Double_Mod (Addend_Value, Modulus_Item);
      end loop;
      return Result_Value;
   end Multiply_Mod;

   function Pow_Mod
     (Base_Item     : Big_Value;
      Exponent_Item : Big_Value;
      Exponent_Bits : Natural;
      Modulus_Item  : Big_Value) return Big_Value
   is
      Result_Value : Big_Value := [others => 0];
      Base_Value   : Big_Value := Base_Item;
      First_Bit    : constant Natural :=
        Maximum_RSA_Modulus_Bytes * 8 - Exponent_Bits;
      First_Index  : constant Big_Index := Active_First_Byte (Modulus_Item);
   begin
      Result_Value (Maximum_RSA_Modulus_Bytes - 1) := 1;
      Normalize_Mod_From (Base_Value, Modulus_Item, First_Index);
      for Bit_Index in First_Bit .. Maximum_RSA_Modulus_Bytes * 8 - 1 loop
         declare
            Squared_Value   : constant Big_Value :=
              Multiply_Mod (Result_Value, Result_Value, Modulus_Item);
            Product_Value   : constant Big_Value :=
              Multiply_Mod (Squared_Value, Base_Value, Modulus_Item);
            Exponent_Choice : constant Natural :=
              Get_Bit_Value (Exponent_Item, Bit_Index);
         begin
            Result_Value :=
              Select_Big_From
                (Squared_Value, Product_Value, Exponent_Choice, First_Index);
         end;
      end loop;
      return Result_Value;
   end Pow_Mod;

   function Decode_Public_Key
     (Public_Key_Blob : Stream_Element_Array; Key_Item : out RSA_Public_Key)
      return Status
   is
      Algorithm_Buffer : CryptoLib.Buffers.Packet_Buffer;
      Exponent_Buffer  : CryptoLib.Buffers.Packet_Buffer;
      Modulus_Buffer   : CryptoLib.Buffers.Packet_Buffer;
      After_Algorithm  : Stream_Element_Offset;
      After_Exponent   : Stream_Element_Offset;
      After_Modulus    : Stream_Element_Offset;
      Status_Value     : Status;
   begin
      Key_Item :=
        (Exponent_Data  => [others => 0],
         Modulus_Data   => [others => 0],
         Exponent_Bytes => 0,
         Modulus_Bytes  => 0);
      if Public_Key_Blob'Length = 0 then
         return Handshake_Failed;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_SSH_String
          (Public_Key_Blob,
           Public_Key_Blob'First,
           Algorithm_Buffer,
           After_Algorithm);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      if not Bytes_Equal_String
               (CryptoLib.Buffers.To_Array (Algorithm_Buffer),
                "ssh-rsa")
      then
         return Handshake_Failed;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_SSH_String
          (Public_Key_Blob, After_Algorithm, Exponent_Buffer, After_Exponent);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_SSH_String
          (Public_Key_Blob, After_Exponent, Modulus_Buffer, After_Modulus);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      if After_Modulus /= Public_Key_Blob'Last + 1 then
         return Handshake_Failed;
      end if;

      declare
         Exponent_Array : constant Stream_Element_Array :=
           CryptoLib.Buffers.To_Array (Exponent_Buffer);
         Modulus_Array  : constant Stream_Element_Array :=
           CryptoLib.Buffers.To_Array (Modulus_Buffer);
      begin
         if not Strip_Positive_Mpint
                  (Exponent_Array,
                   False,
                   Key_Item.Exponent_Data,
                   Key_Item.Exponent_Bytes)
           or else
             not Strip_Positive_Mpint
                   (Modulus_Array,
                    True,
                    Key_Item.Modulus_Data,
                    Key_Item.Modulus_Bytes)
         then
            return Handshake_Failed;
         end if;
      end;

      if Key_Item.Modulus_Bytes < 128 then
         --  Reject toy-sized RSA host keys.  This is a verification primitive,
         --  not a compatibility path for obsolete key sizes.
         return Handshake_Failed;
      end if;

      return Ok;
   exception
      when others =>
         Key_Item :=
           (Exponent_Data  => [others => 0],
            Modulus_Data   => [others => 0],
            Exponent_Bytes => 0,
            Modulus_Bytes  => 0);
         return Internal_Error;
   end Decode_Public_Key;

   function Validate_Public_Key_Blob
     (Public_Key_Blob : Stream_Element_Array) return Status
   is
      Key_Item : RSA_Public_Key;
   begin
      return Decode_Public_Key (Public_Key_Blob, Key_Item);
   exception
      when others =>
         return Internal_Error;
   end Validate_Public_Key_Blob;

   function To_Modulus_Sized_Big
     (Data          : Stream_Element_Array;
      Modulus_Bytes : Natural;
      Result_Item   : out Big_Value) return Boolean
   is
      Target_Index : Natural;
   begin
      Result_Item := [others => 0];
      if Data'Length = 0 or else Data'Length > Modulus_Bytes then
         return False;
      end if;
      Target_Index := Maximum_RSA_Modulus_Bytes - Data'Length;
      for Source_Index in Data'Range loop
         Result_Item (Target_Index) := Natural (Data (Source_Index));
         Target_Index := Target_Index + 1;
      end loop;
      return True;
   exception
      when others =>
         Result_Item := [others => 0];
         return False;
   end To_Modulus_Sized_Big;

   function To_Modulus_Sized_Array
     (Item : Big_Value; Modulus_Bytes : Natural) return Stream_Element_Array
   is
      Result_Value :
        Stream_Element_Array (1 .. Stream_Element_Offset (Modulus_Bytes));
      Source_Index : Natural := Maximum_RSA_Modulus_Bytes - Modulus_Bytes;
   begin
      for Target_Index in Result_Value'Range loop
         Result_Value (Target_Index) := Stream_Element (Item (Source_Index));
         Source_Index := Source_Index + 1;
      end loop;
      return Result_Value;
   end To_Modulus_Sized_Array;

   function DigestInfo_SHA1
     (Message_Bytes : Stream_Element_Array) return Stream_Element_Array
   is
      Digest_Value : constant CryptoLib.Hashes.SHA1_Digest :=
        CryptoLib.Hashes.SHA1 (Message_Bytes);
      Result_Value :
        Stream_Element_Array
          (1 .. SHA1_Digest_Info_Prefix'Length + Digest_Value'Length);
      Out_Index    : Stream_Element_Offset := Result_Value'First;
   begin
      for Byte_Value of SHA1_Digest_Info_Prefix loop
         Result_Value (Out_Index) := Byte_Value;
         Out_Index := Out_Index + 1;
      end loop;
      for Byte_Value of Digest_Value loop
         Result_Value (Out_Index) := Byte_Value;
         Out_Index := Out_Index + 1;
      end loop;
      return Result_Value;
   end DigestInfo_SHA1;

   function DigestInfo_SHA256
     (Message_Bytes : Stream_Element_Array) return Stream_Element_Array
   is
      Digest_Value : constant CryptoLib.Hashes.SHA256_Digest :=
        CryptoLib.Hashes.SHA256 (Message_Bytes);
      Result_Value :
        Stream_Element_Array
          (1 .. SHA256_Digest_Info_Prefix'Length + Digest_Value'Length);
      Out_Index    : Stream_Element_Offset := Result_Value'First;
   begin
      for Byte_Value of SHA256_Digest_Info_Prefix loop
         Result_Value (Out_Index) := Byte_Value;
         Out_Index := Out_Index + 1;
      end loop;
      for Byte_Value of Digest_Value loop
         Result_Value (Out_Index) := Byte_Value;
         Out_Index := Out_Index + 1;
      end loop;
      return Result_Value;
   end DigestInfo_SHA256;

   function DigestInfo_SHA512
     (Message_Bytes : Stream_Element_Array) return Stream_Element_Array
   is
      Digest_Value : constant CryptoLib.Hashes.SHA512_Digest :=
        CryptoLib.Hashes.SHA512 (Message_Bytes);
      Result_Value :
        Stream_Element_Array
          (1 .. SHA512_Digest_Info_Prefix'Length + Digest_Value'Length);
      Out_Index    : Stream_Element_Offset := Result_Value'First;
   begin
      for Byte_Value of SHA512_Digest_Info_Prefix loop
         Result_Value (Out_Index) := Byte_Value;
         Out_Index := Out_Index + 1;
      end loop;
      for Byte_Value of Digest_Value loop
         Result_Value (Out_Index) := Byte_Value;
         Out_Index := Out_Index + 1;
      end loop;
      return Result_Value;
   end DigestInfo_SHA512;

   function Matches_PKCS1_V15
     (Encoded_Message : Stream_Element_Array;
      Expected_Tail   : Stream_Element_Array) return Boolean
   is
      Prefix_Ok    : Boolean := False;
      Padding_Ok   : Boolean := True;
      Tail_Ok      : Boolean := False;
      Padding_Last : Stream_Element_Offset;
      Tail_First   : Stream_Element_Offset;
   begin
      if Encoded_Message'Length < Expected_Tail'Length + 11 then
         return False;
      end if;

      Prefix_Ok :=
        Encoded_Message (Encoded_Message'First) = 0
        and then Encoded_Message (Encoded_Message'First + 1) = 1;
      Tail_First :=
        Encoded_Message'Last
        - Stream_Element_Offset (Expected_Tail'Length)
        + 1;
      Padding_Last := Tail_First - 2;

      if Padding_Last < Encoded_Message'First + 9 then
         return False;
      end if;

      for Index_Value in Encoded_Message'First + 2 .. Padding_Last loop
         Padding_Ok :=
           Padding_Ok and then Encoded_Message (Index_Value) = 16#FF#;
      end loop;

      if Encoded_Message (Tail_First - 1) /= 0 then
         Padding_Ok := False;
      end if;

      Tail_Ok :=
        CryptoLib.Constant_Time.Equal
          (Encoded_Message (Tail_First .. Encoded_Message'Last),
           Expected_Tail);
      return Prefix_Ok and then Padding_Ok and then Tail_Ok;
   exception
      when others =>
         return False;
   end Matches_PKCS1_V15;

   function Matches_PKCS1_V15_SHA1
     (Encoded_Message : Stream_Element_Array;
      Message_Bytes   : Stream_Element_Array) return Boolean
   is
      Expected_Tail : constant Stream_Element_Array :=
        DigestInfo_SHA1 (Message_Bytes);
   begin
      return Matches_PKCS1_V15 (Encoded_Message, Expected_Tail);
   exception
      when others =>
         return False;
   end Matches_PKCS1_V15_SHA1;

   function Matches_PKCS1_V15_SHA256
     (Encoded_Message : Stream_Element_Array;
      Message_Bytes   : Stream_Element_Array) return Boolean
   is
      Expected_Tail : constant Stream_Element_Array :=
        DigestInfo_SHA256 (Message_Bytes);
   begin
      return Matches_PKCS1_V15 (Encoded_Message, Expected_Tail);
   exception
      when others =>
         return False;
   end Matches_PKCS1_V15_SHA256;

   function Matches_PKCS1_V15_SHA512
     (Encoded_Message : Stream_Element_Array;
      Message_Bytes   : Stream_Element_Array) return Boolean
   is
      Expected_Tail : constant Stream_Element_Array :=
        DigestInfo_SHA512 (Message_Bytes);
   begin
      return Matches_PKCS1_V15 (Encoded_Message, Expected_Tail);
   exception
      when others =>
         return False;
   end Matches_PKCS1_V15_SHA512;

   function Verify_SHA1
     (Public_Key_Blob : Stream_Element_Array;
      Signature_Bytes : Stream_Element_Array;
      Message_Bytes   : Stream_Element_Array) return Status
   is
      Key_Item      : RSA_Public_Key;
      Signature_Big : Big_Value;
      Decoded_Big   : Big_Value;
      Exponent_Bits : Natural;
      Status_Value  : Status;
   begin
      if Signature_Bytes'Length = 0 then
         return Handshake_Failed;
      end if;

      Status_Value := Decode_Public_Key (Public_Key_Blob, Key_Item);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      if Signature_Bytes'Length /= Key_Item.Modulus_Bytes then
         return Handshake_Failed;
      end if;
      if not To_Modulus_Sized_Big
               (Signature_Bytes, Key_Item.Modulus_Bytes, Signature_Big)
      then
         return Handshake_Failed;
      end if;
      if Compare (Signature_Big, Key_Item.Modulus_Data) >= 0 then
         return Handshake_Failed;
      end if;

      Exponent_Bits := Key_Item.Exponent_Bytes * 8;
      Decoded_Big :=
        Pow_Mod
          (Signature_Big,
           Key_Item.Exponent_Data,
           Exponent_Bits,
           Key_Item.Modulus_Data);

      declare
         Encoded_Message : constant Stream_Element_Array :=
           To_Modulus_Sized_Array (Decoded_Big, Key_Item.Modulus_Bytes);
      begin
         if Matches_PKCS1_V15_SHA1 (Encoded_Message, Message_Bytes) then
            return Ok;
         else
            return Handshake_Failed;
         end if;
      end;
   exception
      when others =>
         return Internal_Error;
   end Verify_SHA1;

   function Verify_SHA2
     (Algorithm_Name  : String;
      Public_Key_Blob : Stream_Element_Array;
      Signature_Bytes : Stream_Element_Array;
      Message_Bytes   : Stream_Element_Array) return Status
   is
      Key_Item      : RSA_Public_Key;
      Signature_Big : Big_Value;
      Decoded_Big   : Big_Value;
      Exponent_Bits : Natural;
      Status_Value  : Status;
   begin
      if Algorithm_Name /= "rsa-sha2-256"
        and then Algorithm_Name /= "rsa-sha2-512"
      then
         return Unsupported_Feature;
      end if;

      if Signature_Bytes'Length = 0 then
         return Handshake_Failed;
      end if;

      Status_Value := Decode_Public_Key (Public_Key_Blob, Key_Item);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      if Signature_Bytes'Length /= Key_Item.Modulus_Bytes then
         return Handshake_Failed;
      end if;
      if not To_Modulus_Sized_Big
               (Signature_Bytes, Key_Item.Modulus_Bytes, Signature_Big)
      then
         return Handshake_Failed;
      end if;
      if Compare (Signature_Big, Key_Item.Modulus_Data) >= 0 then
         return Handshake_Failed;
      end if;

      Exponent_Bits := Key_Item.Exponent_Bytes * 8;
      Decoded_Big :=
        Pow_Mod
          (Signature_Big,
           Key_Item.Exponent_Data,
           Exponent_Bits,
           Key_Item.Modulus_Data);

      declare
         Encoded_Message : constant Stream_Element_Array :=
           To_Modulus_Sized_Array (Decoded_Big, Key_Item.Modulus_Bytes);
      begin
         if Algorithm_Name = "rsa-sha2-256" then
            if Matches_PKCS1_V15_SHA256 (Encoded_Message, Message_Bytes) then
               return Ok;
            else
               return Handshake_Failed;
            end if;
         else
            if Matches_PKCS1_V15_SHA512 (Encoded_Message, Message_Bytes) then
               return Ok;
            else
               return Handshake_Failed;
            end if;
         end if;
      end;
   exception
      when others =>
         return Internal_Error;
   end Verify_SHA2;
   function Build_PKCS1_V15_SHA1
     (Message_Bytes : Stream_Element_Array; Modulus_Bytes : Natural)
      return Stream_Element_Array
   is
      Digest_Info     : constant Stream_Element_Array :=
        DigestInfo_SHA1 (Message_Bytes);
      Result_Value    :
        Stream_Element_Array (1 .. Stream_Element_Offset (Modulus_Bytes));
      Separator_Index : constant Stream_Element_Offset :=
        Result_Value'Last - Stream_Element_Offset (Digest_Info'Length);
      Digest_Index    : Stream_Element_Offset := Digest_Info'First;
   begin
      Result_Value := [others => 16#FF#];
      Result_Value (Result_Value'First) := 0;
      Result_Value (Result_Value'First + 1) := 1;
      Result_Value (Separator_Index) := 0;
      for Out_Index in Separator_Index + 1 .. Result_Value'Last loop
         Result_Value (Out_Index) := Digest_Info (Digest_Index);
         Digest_Index := Digest_Index + 1;
      end loop;
      return Result_Value;
   end Build_PKCS1_V15_SHA1;

   function Build_PKCS1_V15_SHA512
     (Message_Bytes : Stream_Element_Array; Modulus_Bytes : Natural)
      return Stream_Element_Array
   is
      Digest_Info     : constant Stream_Element_Array :=
        DigestInfo_SHA512 (Message_Bytes);
      Result_Value    :
        Stream_Element_Array (1 .. Stream_Element_Offset (Modulus_Bytes));
      Separator_Index : constant Stream_Element_Offset :=
        Result_Value'Last - Stream_Element_Offset (Digest_Info'Length);
      Digest_Index    : Stream_Element_Offset := Digest_Info'First;
   begin
      Result_Value := [others => 16#FF#];
      Result_Value (Result_Value'First) := 0;
      Result_Value (Result_Value'First + 1) := 1;
      Result_Value (Separator_Index) := 0;
      for Out_Index in Separator_Index + 1 .. Result_Value'Last loop
         Result_Value (Out_Index) := Digest_Info (Digest_Index);
         Digest_Index := Digest_Index + 1;
      end loop;
      return Result_Value;
   end Build_PKCS1_V15_SHA512;

   function Build_PKCS1_V15_SHA256
     (Message_Bytes : Stream_Element_Array; Modulus_Bytes : Natural)
      return Stream_Element_Array
   is
      Digest_Info     : constant Stream_Element_Array :=
        DigestInfo_SHA256 (Message_Bytes);
      Result_Value    :
        Stream_Element_Array (1 .. Stream_Element_Offset (Modulus_Bytes));
      Separator_Index : constant Stream_Element_Offset :=
        Result_Value'Last - Stream_Element_Offset (Digest_Info'Length);
      Digest_Index    : Stream_Element_Offset := Digest_Info'First;
   begin
      Result_Value := [others => 16#FF#];
      Result_Value (Result_Value'First) := 0;
      Result_Value (Result_Value'First + 1) := 1;
      Result_Value (Separator_Index) := 0;
      for Out_Index in Separator_Index + 1 .. Result_Value'Last loop
         Result_Value (Out_Index) := Digest_Info (Digest_Index);
         Digest_Index := Digest_Index + 1;
      end loop;
      return Result_Value;
   end Build_PKCS1_V15_SHA256;

   function Sign_CRT
     (Public_Key_Blob        : Stream_Element_Array;
      Prime_P_Mpint          : Stream_Element_Array;
      Prime_Q_Mpint          : Stream_Element_Array;
      Exponent_DMP1_Mpint    : Stream_Element_Array;
      Exponent_DMQ1_Mpint    : Stream_Element_Array;
      Coefficient_IQMP_Mpint : Stream_Element_Array;
      Message_Bytes          : Stream_Element_Array;
      Signature_Bytes        : out CryptoLib.Buffers.Packet_Buffer;
      Digest_Kind            : Natural) return Status
   is
      Key_Item       : RSA_Public_Key;
      Prime_P_Big    : Big_Value;
      Prime_Q_Big    : Big_Value;
      DMP1_Big       : Big_Value;
      DMQ1_Big       : Big_Value;
      IQMP_Big       : Big_Value;
      Encoded_P_Big  : Big_Value;
      Encoded_Q_Big  : Big_Value;
      M1_Big         : Big_Value;
      M2_Big         : Big_Value;
      Difference_Big : Big_Value;
      H_Big          : Big_Value;
      QH_Big         : Big_Value;
      Signature_Big  : Big_Value;
      Prime_P_Bytes  : Natural := 0;
      Prime_Q_Bytes  : Natural := 0;
      DMP1_Bytes     : Natural := 0;
      DMQ1_Bytes     : Natural := 0;
      IQMP_Bytes     : Natural := 0;
      Status_Value   : Status;

      --  Scrub the RSA private primes, CRT exponents/coefficient, and the
      --  private intermediates.  Plain "X := [others => 0]" is elided at -O3.
      procedure Scrub_Secrets is
         use System;
      begin
         CryptoLib.Secure_Wipe.Wipe
           (Prime_P_Big'Address, Prime_P_Big'Size / Storage_Unit);
         CryptoLib.Secure_Wipe.Wipe
           (Prime_Q_Big'Address, Prime_Q_Big'Size / Storage_Unit);
         CryptoLib.Secure_Wipe.Wipe
           (DMP1_Big'Address, DMP1_Big'Size / Storage_Unit);
         CryptoLib.Secure_Wipe.Wipe
           (DMQ1_Big'Address, DMQ1_Big'Size / Storage_Unit);
         CryptoLib.Secure_Wipe.Wipe
           (IQMP_Big'Address, IQMP_Big'Size / Storage_Unit);
         CryptoLib.Secure_Wipe.Wipe
           (Encoded_P_Big'Address, Encoded_P_Big'Size / Storage_Unit);
         CryptoLib.Secure_Wipe.Wipe
           (Encoded_Q_Big'Address, Encoded_Q_Big'Size / Storage_Unit);
         CryptoLib.Secure_Wipe.Wipe (M1_Big'Address, M1_Big'Size / Storage_Unit);
         CryptoLib.Secure_Wipe.Wipe (M2_Big'Address, M2_Big'Size / Storage_Unit);
         CryptoLib.Secure_Wipe.Wipe
           (Difference_Big'Address, Difference_Big'Size / Storage_Unit);
         CryptoLib.Secure_Wipe.Wipe (H_Big'Address, H_Big'Size / Storage_Unit);
         CryptoLib.Secure_Wipe.Wipe (QH_Big'Address, QH_Big'Size / Storage_Unit);
      end Scrub_Secrets;
   begin
      CryptoLib.Buffers.Clear (Signature_Bytes);
      Status_Value := Decode_Public_Key (Public_Key_Blob, Key_Item);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      if not Strip_Positive_Mpint
               (Prime_P_Mpint, True, Prime_P_Big, Prime_P_Bytes)
        or else
          not Strip_Positive_Mpint
                (Prime_Q_Mpint, True, Prime_Q_Big, Prime_Q_Bytes)
        or else
          not Strip_Positive_Mpint
                (Exponent_DMP1_Mpint, True, DMP1_Big, DMP1_Bytes)
        or else
          not Strip_Positive_Mpint
                (Exponent_DMQ1_Mpint, True, DMQ1_Big, DMQ1_Bytes)
        or else
          not Strip_Positive_Mpint
                (Coefficient_IQMP_Mpint, True, IQMP_Big, IQMP_Bytes)
      then
         Scrub_Secrets;
         return Authentication_Failed;
      end if;

      if Prime_P_Bytes = 0
        or else Prime_Q_Bytes = 0
        or else DMP1_Bytes = 0
        or else DMQ1_Bytes = 0
        or else IQMP_Bytes = 0
        or else Prime_P_Bytes + Prime_Q_Bytes > Key_Item.Modulus_Bytes + 1
        or else DMP1_Bytes > Prime_P_Bytes
        or else DMQ1_Bytes > Prime_Q_Bytes
        or else IQMP_Bytes > Prime_P_Bytes
      then
         Scrub_Secrets;
         return Authentication_Failed;
      end if;

      declare
         Encoded_Message :
           Stream_Element_Array
             (1 .. Stream_Element_Offset (Key_Item.Modulus_Bytes));
         Result_Array    :
           Stream_Element_Array
             (1 .. Stream_Element_Offset (Key_Item.Modulus_Bytes));
      begin
         if Digest_Kind = 1 then
            if Key_Item.Modulus_Bytes
              < SHA1_Digest_Info_Prefix'Length + 20 + 11
            then
               Scrub_Secrets;
               return Authentication_Failed;
            end if;
            Encoded_Message :=
              Build_PKCS1_V15_SHA1 (Message_Bytes, Key_Item.Modulus_Bytes);
         elsif Digest_Kind = 256 then
            if Key_Item.Modulus_Bytes
              < SHA256_Digest_Info_Prefix'Length + 32 + 11
            then
               Scrub_Secrets;
               return Authentication_Failed;
            end if;
            Encoded_Message :=
              Build_PKCS1_V15_SHA256 (Message_Bytes, Key_Item.Modulus_Bytes);
         else
            if Key_Item.Modulus_Bytes
              < SHA512_Digest_Info_Prefix'Length + 64 + 11
            then
               Scrub_Secrets;
               return Authentication_Failed;
            end if;
            Encoded_Message :=
              Build_PKCS1_V15_SHA512 (Message_Bytes, Key_Item.Modulus_Bytes);
         end if;

         Encoded_P_Big := Bytes_Mod (Encoded_Message, Prime_P_Big);
         Encoded_Q_Big := Bytes_Mod (Encoded_Message, Prime_Q_Big);
         M1_Big :=
           Pow_Mod (Encoded_P_Big, DMP1_Big, Prime_P_Bytes * 8, Prime_P_Big);
         M2_Big :=
           Pow_Mod (Encoded_Q_Big, DMQ1_Big, Prime_Q_Bytes * 8, Prime_Q_Big);
         Difference_Big := Subtract_Mod (M1_Big, M2_Big, Prime_P_Big);
         H_Big := Multiply_Mod (IQMP_Big, Difference_Big, Prime_P_Big);
         QH_Big := Multiply_Mod (Prime_Q_Big, H_Big, Key_Item.Modulus_Data);
         Signature_Big := Add_Mod (M2_Big, QH_Big, Key_Item.Modulus_Data);
         Result_Array :=
           To_Modulus_Sized_Array (Signature_Big, Key_Item.Modulus_Bytes);
         Status_Value :=
           CryptoLib.Buffers.Set (Signature_Bytes, Result_Array);
      end;

      Scrub_Secrets;
      return Status_Value;
   exception
      when others =>
         CryptoLib.Buffers.Clear (Signature_Bytes);
         Scrub_Secrets;
         return Internal_Error;
   end Sign_CRT;

   function Sign_SHA1_CRT
     (Public_Key_Blob        : Stream_Element_Array;
      Prime_P_Mpint          : Stream_Element_Array;
      Prime_Q_Mpint          : Stream_Element_Array;
      Exponent_DMP1_Mpint    : Stream_Element_Array;
      Exponent_DMQ1_Mpint    : Stream_Element_Array;
      Coefficient_IQMP_Mpint : Stream_Element_Array;
      Message_Bytes          : Stream_Element_Array;
      Signature_Bytes        : out CryptoLib.Buffers.Packet_Buffer)
      return Status is
   begin
      return
        Sign_CRT
          (Public_Key_Blob,
           Prime_P_Mpint,
           Prime_Q_Mpint,
           Exponent_DMP1_Mpint,
           Exponent_DMQ1_Mpint,
           Coefficient_IQMP_Mpint,
           Message_Bytes,
           Signature_Bytes,
           1);
   end Sign_SHA1_CRT;

   function Sign_SHA2_256_CRT
     (Public_Key_Blob        : Stream_Element_Array;
      Prime_P_Mpint          : Stream_Element_Array;
      Prime_Q_Mpint          : Stream_Element_Array;
      Exponent_DMP1_Mpint    : Stream_Element_Array;
      Exponent_DMQ1_Mpint    : Stream_Element_Array;
      Coefficient_IQMP_Mpint : Stream_Element_Array;
      Message_Bytes          : Stream_Element_Array;
      Signature_Bytes        : out CryptoLib.Buffers.Packet_Buffer)
      return Status is
   begin
      return
        Sign_CRT
          (Public_Key_Blob,
           Prime_P_Mpint,
           Prime_Q_Mpint,
           Exponent_DMP1_Mpint,
           Exponent_DMQ1_Mpint,
           Coefficient_IQMP_Mpint,
           Message_Bytes,
           Signature_Bytes,
           256);
   end Sign_SHA2_256_CRT;

   function Sign_SHA2_512_CRT
     (Public_Key_Blob        : Stream_Element_Array;
      Prime_P_Mpint          : Stream_Element_Array;
      Prime_Q_Mpint          : Stream_Element_Array;
      Exponent_DMP1_Mpint    : Stream_Element_Array;
      Exponent_DMQ1_Mpint    : Stream_Element_Array;
      Coefficient_IQMP_Mpint : Stream_Element_Array;
      Message_Bytes          : Stream_Element_Array;
      Signature_Bytes        : out CryptoLib.Buffers.Packet_Buffer)
      return Status is
   begin
      return
        Sign_CRT
          (Public_Key_Blob,
           Prime_P_Mpint,
           Prime_Q_Mpint,
           Exponent_DMP1_Mpint,
           Exponent_DMQ1_Mpint,
           Coefficient_IQMP_Mpint,
           Message_Bytes,
           Signature_Bytes,
           512);
   end Sign_SHA2_512_CRT;

   function Sign_SHA1
     (Public_Key_Blob        : Stream_Element_Array;
      Private_Exponent_Mpint : Stream_Element_Array;
      Message_Bytes          : Stream_Element_Array;
      Signature_Bytes        : out CryptoLib.Buffers.Packet_Buffer)
      return Status
   is
      Key_Item               : RSA_Public_Key;
      Private_Exponent_Big   : Big_Value;
      Encoded_Big            : Big_Value;
      Signature_Big          : Big_Value;
      Private_Exponent_Bytes : Natural := 0;
      Status_Value           : Status;
   begin
      CryptoLib.Buffers.Clear (Signature_Bytes);
      Status_Value := Decode_Public_Key (Public_Key_Blob, Key_Item);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      if Private_Exponent_Mpint'Length = 0 then
         return Authentication_Failed;
      end if;
      if not Strip_Positive_Mpint
               (Private_Exponent_Mpint,
                True,
                Private_Exponent_Big,
                Private_Exponent_Bytes)
      then
         return Authentication_Failed;
      end if;
      if Private_Exponent_Bytes = 0
        or else Private_Exponent_Bytes > Key_Item.Modulus_Bytes
      then
         Private_Exponent_Big := [others => 0];
         return Authentication_Failed;
      end if;
      if Key_Item.Modulus_Bytes < SHA1_Digest_Info_Prefix'Length + 20 + 11 then
         Private_Exponent_Big := [others => 0];
         return Authentication_Failed;
      end if;

      declare
         Encoded_Message : constant Stream_Element_Array :=
           Build_PKCS1_V15_SHA1 (Message_Bytes, Key_Item.Modulus_Bytes);
         Result_Array    :
           Stream_Element_Array
             (1 .. Stream_Element_Offset (Key_Item.Modulus_Bytes));
      begin
         if not To_Modulus_Sized_Big
                  (Encoded_Message, Key_Item.Modulus_Bytes, Encoded_Big)
         then
            Private_Exponent_Big := [others => 0];
            return Authentication_Failed;
         end if;
         Signature_Big :=
           Pow_Mod
             (Encoded_Big,
              Private_Exponent_Big,
              Key_Item.Modulus_Bytes * 8,
              Key_Item.Modulus_Data);
         Result_Array :=
           To_Modulus_Sized_Array (Signature_Big, Key_Item.Modulus_Bytes);
         Private_Exponent_Big := [others => 0];
         Signature_Big := [others => 0];
         Status_Value :=
           CryptoLib.Buffers.Set (Signature_Bytes, Result_Array);
         Result_Array := [others => 0];
         return Status_Value;
      end;
   exception
      when others =>
         CryptoLib.Buffers.Clear (Signature_Bytes);
         return Internal_Error;
   end Sign_SHA1;

   function Sign_SHA2_256
     (Public_Key_Blob        : Stream_Element_Array;
      Private_Exponent_Mpint : Stream_Element_Array;
      Message_Bytes          : Stream_Element_Array;
      Signature_Bytes        : out CryptoLib.Buffers.Packet_Buffer)
      return Status
   is
      Key_Item               : RSA_Public_Key;
      Private_Exponent_Big   : Big_Value;
      Encoded_Big            : Big_Value;
      Signature_Big          : Big_Value;
      Private_Exponent_Bytes : Natural := 0;
      Status_Value           : Status;
   begin
      CryptoLib.Buffers.Clear (Signature_Bytes);
      Status_Value := Decode_Public_Key (Public_Key_Blob, Key_Item);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      if Private_Exponent_Mpint'Length = 0 then
         return Authentication_Failed;
      end if;
      if not Strip_Positive_Mpint
               (Private_Exponent_Mpint,
                True,
                Private_Exponent_Big,
                Private_Exponent_Bytes)
      then
         return Authentication_Failed;
      end if;
      if Private_Exponent_Bytes = 0
        or else Private_Exponent_Bytes > Key_Item.Modulus_Bytes
      then
         Private_Exponent_Big := [others => 0];
         return Authentication_Failed;
      end if;
      if Key_Item.Modulus_Bytes < SHA256_Digest_Info_Prefix'Length + 32 + 11
      then
         Private_Exponent_Big := [others => 0];
         return Authentication_Failed;
      end if;

      declare
         Encoded_Message : constant Stream_Element_Array :=
           Build_PKCS1_V15_SHA256 (Message_Bytes, Key_Item.Modulus_Bytes);
         Result_Array    :
           Stream_Element_Array
             (1 .. Stream_Element_Offset (Key_Item.Modulus_Bytes));
      begin
         if not To_Modulus_Sized_Big
                  (Encoded_Message, Key_Item.Modulus_Bytes, Encoded_Big)
         then
            Private_Exponent_Big := [others => 0];
            return Authentication_Failed;
         end if;
         Signature_Big :=
           Pow_Mod
             (Encoded_Big,
              Private_Exponent_Big,
              Key_Item.Modulus_Bytes * 8,
              Key_Item.Modulus_Data);
         Result_Array :=
           To_Modulus_Sized_Array (Signature_Big, Key_Item.Modulus_Bytes);
         Private_Exponent_Big := [others => 0];
         Signature_Big := [others => 0];
         Status_Value :=
           CryptoLib.Buffers.Set (Signature_Bytes, Result_Array);
         Result_Array := [others => 0];
         return Status_Value;
      end;
   exception
      when others =>
         CryptoLib.Buffers.Clear (Signature_Bytes);
         return Internal_Error;
   end Sign_SHA2_256;

   function Sign_SHA2_512
     (Public_Key_Blob        : Stream_Element_Array;
      Private_Exponent_Mpint : Stream_Element_Array;
      Message_Bytes          : Stream_Element_Array;
      Signature_Bytes        : out CryptoLib.Buffers.Packet_Buffer)
      return Status
   is
      Key_Item               : RSA_Public_Key;
      Private_Exponent_Big   : Big_Value;
      Encoded_Big            : Big_Value;
      Signature_Big          : Big_Value;
      Private_Exponent_Bytes : Natural := 0;
      Status_Value           : Status;
   begin
      CryptoLib.Buffers.Clear (Signature_Bytes);
      Status_Value := Decode_Public_Key (Public_Key_Blob, Key_Item);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      if Private_Exponent_Mpint'Length = 0 then
         return Authentication_Failed;
      end if;
      if not Strip_Positive_Mpint
               (Private_Exponent_Mpint,
                True,
                Private_Exponent_Big,
                Private_Exponent_Bytes)
      then
         return Authentication_Failed;
      end if;
      if Private_Exponent_Bytes = 0
        or else Private_Exponent_Bytes > Key_Item.Modulus_Bytes
      then
         Private_Exponent_Big := [others => 0];
         return Authentication_Failed;
      end if;
      if Key_Item.Modulus_Bytes < SHA512_Digest_Info_Prefix'Length + 64 + 11
      then
         Private_Exponent_Big := [others => 0];
         return Authentication_Failed;
      end if;

      declare
         Encoded_Message : constant Stream_Element_Array :=
           Build_PKCS1_V15_SHA512 (Message_Bytes, Key_Item.Modulus_Bytes);
         Result_Array    :
           Stream_Element_Array
             (1 .. Stream_Element_Offset (Key_Item.Modulus_Bytes));
      begin
         if not To_Modulus_Sized_Big
                  (Encoded_Message, Key_Item.Modulus_Bytes, Encoded_Big)
         then
            Private_Exponent_Big := [others => 0];
            return Authentication_Failed;
         end if;
         Signature_Big :=
           Pow_Mod
             (Encoded_Big,
              Private_Exponent_Big,
              Key_Item.Modulus_Bytes * 8,
              Key_Item.Modulus_Data);
         Result_Array :=
           To_Modulus_Sized_Array (Signature_Big, Key_Item.Modulus_Bytes);
         Private_Exponent_Big := [others => 0];
         Signature_Big := [others => 0];
         Status_Value :=
           CryptoLib.Buffers.Set (Signature_Bytes, Result_Array);
         Result_Array := [others => 0];
         return Status_Value;
      end;
   exception
      when others =>
         CryptoLib.Buffers.Clear (Signature_Bytes);
         return Internal_Error;
   end Sign_SHA2_512;

end SSH_Lib.RSA;
