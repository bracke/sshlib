with Ada.Unchecked_Deallocation;
with CryptoLib.Constant_Time;
with CryptoLib.Hashes;
with CryptoLib.Macs;
with CryptoLib.UMAC;
with SSH_Lib.Protocol.Numbers;

package body SSH_Lib.Protocol.Protected_Packets is
   use Interfaces;
   use CryptoLib.Errors;
   use SSH_Lib.Protocol.Buffers;

   --  AES block size: aes-gcm@openssh.com pads the encrypted portion to a
   --  multiple of 16 octets (RFC 5647), unlike the 8-octet default.
   AES_GCM_Block_Size : constant Natural := 16;

   function SHA1_Digest_To_Array
     (Digest_Item : CryptoLib.Hashes.SHA1_Digest)
      return Stream_Element_Array is
   begin
      return
         Result :
           Stream_Element_Array (1 .. Stream_Element_Offset (SHA1_Mac_Length))
      do
         for Index_Value in Digest_Item'Range loop
            Result (Stream_Element_Offset (Index_Value)) :=
              Digest_Item (Index_Value);
         end loop;
      end return;
   end SHA1_Digest_To_Array;

   function SHA1_96_Digest_To_Array
     (Digest_Item : CryptoLib.Hashes.SHA1_Digest)
      return Stream_Element_Array is
   begin
      return Result : Stream_Element_Array (1 .. 12) do
         for Index_Value in 1 .. 12 loop
            Result (Stream_Element_Offset (Index_Value)) :=
              Digest_Item (Index_Value);
         end loop;
      end return;
   end SHA1_96_Digest_To_Array;

   function MD5_Digest_To_Array
     (Digest_Item : CryptoLib.Hashes.MD5_Digest)
      return Stream_Element_Array is
   begin
      return Result : Stream_Element_Array (1 .. 16) do
         for Index_Value in Digest_Item'Range loop
            Result (Stream_Element_Offset (Index_Value)) :=
              Digest_Item (Index_Value);
         end loop;
      end return;
   end MD5_Digest_To_Array;

   function MD5_96_Digest_To_Array
     (Digest_Item : CryptoLib.Hashes.MD5_Digest)
      return Stream_Element_Array is
   begin
      return Result : Stream_Element_Array (1 .. 12) do
         for Index_Value in 1 .. 12 loop
            Result (Stream_Element_Offset (Index_Value)) :=
              Digest_Item (Index_Value);
         end loop;
      end return;
   end MD5_96_Digest_To_Array;

   function HMAC_MD5_Digest
     (Key_Data     : Stream_Element_Array;
      Message_Data : Stream_Element_Array)
      return CryptoLib.Hashes.MD5_Digest
   is
      Block_Length : constant Stream_Element_Offset := 64;
      Key_Block    : Stream_Element_Array (1 .. Block_Length) := [others => 0];
      Inner_Data   : Stream_Element_Array
        (1 .. Block_Length + Message_Data'Length);
      Outer_Data   : Stream_Element_Array (1 .. Block_Length + 16);
      Inner_Digest : CryptoLib.Hashes.MD5_Digest;
   begin
      if Key_Data'Length > Block_Length then
         declare
            Key_Digest : constant CryptoLib.Hashes.MD5_Digest :=
              CryptoLib.Hashes.MD5 (Key_Data);
         begin
            for Index_Value in Key_Digest'Range loop
               Key_Block (Stream_Element_Offset (Index_Value)) :=
                 Key_Digest (Index_Value);
            end loop;
         end;
      else
         if Key_Data'Length > 0 then
            for Index_Value in 0 .. Key_Data'Length - 1 loop
               Key_Block
                 (Key_Block'First + Stream_Element_Offset (Index_Value)) :=
                   Key_Data (Key_Data'First + Stream_Element_Offset (Index_Value));
            end loop;
         end if;
      end if;

      for Index_Value in Key_Block'Range loop
         Inner_Data (Index_Value) := Key_Block (Index_Value) xor 16#36#;
         Outer_Data (Index_Value) := Key_Block (Index_Value) xor 16#5C#;
      end loop;

      if Message_Data'Length > 0 then
         Inner_Data (Block_Length + 1 .. Inner_Data'Last) := Message_Data;
      end if;

      Inner_Digest := CryptoLib.Hashes.MD5 (Inner_Data);
      for Index_Value in Inner_Digest'Range loop
         Outer_Data
           (Block_Length + Stream_Element_Offset (Index_Value)) :=
             Inner_Digest (Index_Value);
      end loop;

      return CryptoLib.Hashes.MD5 (Outer_Data);
   end HMAC_MD5_Digest;

   function SHA256_Digest_To_Array
     (Digest_Item : CryptoLib.Hashes.SHA256_Digest)
      return Stream_Element_Array is
   begin
      return
         Result :
           Stream_Element_Array (1 .. Stream_Element_Offset (Mac_Length))
      do
         for Index_Value in Digest_Item'Range loop
            Result (Stream_Element_Offset (Index_Value)) :=
              Digest_Item (Index_Value);
         end loop;
      end return;
   end SHA256_Digest_To_Array;

   function SHA512_Digest_To_Array
     (Digest_Item : CryptoLib.Hashes.SHA512_Digest)
      return Stream_Element_Array is
   begin
      return
         Result :
           Stream_Element_Array
             (1 .. Stream_Element_Offset (Maximum_Mac_Length))
      do
         for Index_Value in Digest_Item'Range loop
            Result (Stream_Element_Offset (Index_Value)) :=
              Digest_Item (Index_Value);
         end loop;
      end return;
   end SHA512_Digest_To_Array;

   function Mac_Kind_For
     (Name_Text : String; Result : out Mac_Algorithm) return Status is
   begin
      if Name_Text = "umac-64@openssh.com" then
         Result := UMAC_64;
         return Ok;
      elsif Name_Text = "umac-64-etm@openssh.com" then
         Result := UMAC_64_ETM;
         return Ok;
      elsif Name_Text = "umac-128@openssh.com" then
         Result := UMAC_128;
         return Ok;
      elsif Name_Text = "umac-128-etm@openssh.com" then
         Result := UMAC_128_ETM;
         return Ok;
      elsif Name_Text = "hmac-sha1" then
         Result := HMAC_SHA1;
         return Ok;
      elsif Name_Text = "hmac-sha1-etm@openssh.com" then
         Result := HMAC_SHA1_ETM;
         return Ok;
      elsif Name_Text = "hmac-sha1-96" then
         Result := HMAC_SHA1_96;
         return Ok;
      elsif Name_Text = "hmac-sha1-96-etm@openssh.com" then
         Result := HMAC_SHA1_96_ETM;
         return Ok;
      elsif Name_Text = "hmac-md5" then
         Result := HMAC_MD5;
         return Ok;
      elsif Name_Text = "hmac-md5-etm@openssh.com" then
         Result := HMAC_MD5_ETM;
         return Ok;
      elsif Name_Text = "hmac-md5-96" then
         Result := HMAC_MD5_96;
         return Ok;
      elsif Name_Text = "hmac-md5-96-etm@openssh.com" then
         Result := HMAC_MD5_96_ETM;
         return Ok;
      elsif Name_Text = "hmac-sha2-256" then
         Result := HMAC_SHA2_256;
         return Ok;
      elsif Name_Text = "hmac-sha2-512" then
         Result := HMAC_SHA2_512;
         return Ok;
      elsif Name_Text = "hmac-sha2-256-etm@openssh.com" then
         Result := HMAC_SHA2_256_ETM;
         return Ok;
      elsif Name_Text = "hmac-sha2-512-etm@openssh.com" then
         Result := HMAC_SHA2_512_ETM;
         return Ok;
      end if;

      Result := HMAC_SHA2_256;
      return Unsupported_Feature;
   end Mac_Kind_For;

   function Length_For (Kind_Item : Mac_Algorithm) return Natural is
   begin
      case Kind_Item is
         when HMAC_SHA1 | HMAC_SHA1_ETM         =>
            return SHA1_Mac_Length;

         when HMAC_SHA1_96 | HMAC_SHA1_96_ETM   =>
            return 12;

         when HMAC_MD5 | HMAC_MD5_ETM           =>
            return 16;

         when HMAC_MD5_96 | HMAC_MD5_96_ETM     =>
            return 12;

         when HMAC_SHA2_256 | HMAC_SHA2_256_ETM =>
            return Mac_Length;

         when HMAC_SHA2_512 | HMAC_SHA2_512_ETM =>
            return Maximum_Mac_Length;

         when UMAC_64 | UMAC_64_ETM             =>
            return CryptoLib.UMAC.UMAC_64_Length;

         when UMAC_128 | UMAC_128_ETM           =>
            return CryptoLib.UMAC.UMAC_128_Length;
      end case;
   end Length_For;

   function Key_Length_For (Kind_Item : Mac_Algorithm) return Natural is
   begin
      case Kind_Item is
         when HMAC_SHA1 | HMAC_SHA1_ETM | HMAC_SHA1_96 | HMAC_SHA1_96_ETM =>
            return SHA1_Mac_Length;

         when HMAC_MD5 | HMAC_MD5_ETM | HMAC_MD5_96 | HMAC_MD5_96_ETM     =>
            return 16;

         when HMAC_SHA2_256 | HMAC_SHA2_256_ETM                           =>
            return Mac_Length;

         when HMAC_SHA2_512 | HMAC_SHA2_512_ETM                           =>
            return Maximum_Mac_Length;

         when UMAC_64 | UMAC_64_ETM | UMAC_128 | UMAC_128_ETM             =>
            return CryptoLib.UMAC.UMAC_Key_Length;
      end case;
   end Key_Length_For;

   function Is_EtM (Kind_Item : Mac_Algorithm) return Boolean is
   begin
      case Kind_Item is
         when HMAC_SHA1_ETM
            | HMAC_SHA1_96_ETM
            | HMAC_MD5_ETM
            | HMAC_MD5_96_ETM
            | HMAC_SHA2_256_ETM
            | HMAC_SHA2_512_ETM
            | UMAC_64_ETM
            | UMAC_128_ETM =>
            return True;

         when HMAC_SHA1
            | HMAC_SHA1_96
            | HMAC_MD5
            | HMAC_MD5_96
            | HMAC_SHA2_256
            | HMAC_SHA2_512
            | UMAC_64
            | UMAC_128     =>
            return False;
      end case;
   end Is_EtM;

   function Is_CBC_Cipher (Name_Text : String) return Boolean is
   begin
      return Name_Text = "aes128-cbc"
        or else Name_Text = "aes192-cbc"
        or else Name_Text = "aes256-cbc"
        or else Name_Text = "3des-cbc";
   end Is_CBC_Cipher;

   function Mac_Input
     (Sequence_Value : Unsigned_32; Packet : Stream_Element_Array)
      return Stream_Element_Array
   is
      Sequence_Bytes : constant Stream_Element_Array :=
        SSH_Lib.Protocol.Numbers.Encode_Uint32 (Sequence_Value);
   begin
      return
         Result :
           Stream_Element_Array
             (1
              .. Stream_Element_Offset (Sequence_Bytes'Length + Packet'Length))
      do
         Result (1 .. Stream_Element_Offset (Sequence_Bytes'Length)) :=
           Sequence_Bytes;
         if Packet'Length > 0 then
            Result
              (Stream_Element_Offset (Sequence_Bytes'Length)
               + 1
               .. Result'Last) :=
              Packet;
         end if;
      end return;
   end Mac_Input;

   function Expected_Mac
     (Kind_Item      : Mac_Algorithm;
      Key_Data       : Mac_Key_Buffer;
      Sequence_Value : Unsigned_32;
      Packet         : Stream_Element_Array) return Stream_Element_Array
   is
      Input_Data : constant Stream_Element_Array :=
        Mac_Input (Sequence_Value, Packet);
   begin
      case Kind_Item is
         when HMAC_SHA1 | HMAC_SHA1_ETM         =>
            return
              SHA1_Digest_To_Array
                (CryptoLib.Macs.HMAC_SHA1
                   (Key_Data (1 .. Stream_Element_Offset (SHA1_Mac_Length)),
                    Input_Data));

         when HMAC_SHA1_96 | HMAC_SHA1_96_ETM   =>
            return
              SHA1_96_Digest_To_Array
                (CryptoLib.Macs.HMAC_SHA1
                   (Key_Data (1 .. Stream_Element_Offset (SHA1_Mac_Length)),
                    Input_Data));

         when HMAC_MD5 | HMAC_MD5_ETM           =>
            return
              MD5_Digest_To_Array
                (HMAC_MD5_Digest
                   (Key_Data (1 .. 16),
                    Input_Data));

         when HMAC_MD5_96 | HMAC_MD5_96_ETM     =>
            return
              MD5_96_Digest_To_Array
                (HMAC_MD5_Digest
                   (Key_Data (1 .. 16),
                    Input_Data));

         when HMAC_SHA2_256 | HMAC_SHA2_256_ETM =>
            return
              SHA256_Digest_To_Array
                (CryptoLib.Macs.HMAC_SHA256
                   (Key_Data (1 .. Stream_Element_Offset (Mac_Length)),
                    Input_Data));

         when HMAC_SHA2_512 | HMAC_SHA2_512_ETM =>
            return
              SHA512_Digest_To_Array
                (CryptoLib.Macs.HMAC_SHA512 (Key_Data, Input_Data));

         when UMAC_64 | UMAC_64_ETM             =>
            declare
               UMAC_Key_Data : CryptoLib.UMAC.UMAC_Key;
            begin
               UMAC_Key_Data :=
                 Key_Data
                   (Key_Data'First
                    ..
                      Key_Data'First
                      + Stream_Element_Offset
                          (CryptoLib.UMAC.UMAC_Key_Length - 1));
               return
                 CryptoLib.UMAC.Generate
                   ("umac-64@openssh.com",
                    UMAC_Key_Data,
                    Sequence_Value,
                    Packet);
            end;

         when UMAC_128 | UMAC_128_ETM           =>
            declare
               UMAC_Key_Data : CryptoLib.UMAC.UMAC_Key;
            begin
               UMAC_Key_Data :=
                 Key_Data
                   (Key_Data'First
                    ..
                      Key_Data'First
                      + Stream_Element_Offset
                          (CryptoLib.UMAC.UMAC_Key_Length - 1));
               return
                 CryptoLib.UMAC.Generate
                   ("umac-128@openssh.com",
                    UMAC_Key_Data,
                    Sequence_Value,
                    Packet);
            end;
      end case;
   end Expected_Mac;

   procedure Mark_Dirty
     (Item : in out Protected_State; Reason : CryptoLib.Errors.Status) is
   begin
      Item.Dirty_Value := True;
      if Reason = Ok then
         Item.Failure := Internal_Error;
      else
         Item.Failure := Reason;
      end if;
   exception
      when others =>
         Item.Dirty_Value := True;
         Item.Failure := Internal_Error;
   end Mark_Dirty;

   procedure Free_Deflate is new
     Ada.Unchecked_Deallocation
       (Zlib.Compression_Filter_Type,
        Deflate_Filter_Access);

   procedure Free_Inflate is new
     Ada.Unchecked_Deallocation (Zlib.Filter_Type, Inflate_Filter_Access);

   procedure Close_Compression (Item : in out Protected_State) is
   begin
      if Item.Outbound_Compressor /= null then
         if Zlib.Is_Open (Item.Outbound_Compressor.all) then
            Zlib.Compress_Close
              (Item.Outbound_Compressor.all, Ignore_Error => True);
         end if;
         Free_Deflate (Item.Outbound_Compressor);
      end if;

      if Item.Inbound_Inflater /= null then
         if Zlib.Is_Open (Item.Inbound_Inflater.all) then
            Zlib.Close (Item.Inbound_Inflater.all, Ignore_Error => True);
         end if;
         Free_Inflate (Item.Inbound_Inflater);
      end if;

      Item.Outbound_Compression_Active := False;
      Item.Inbound_Compression_Active := False;
      Item.Outbound_Compression_Delayed := False;
      Item.Inbound_Compression_Delayed := False;
   exception
      when others =>
         Item.Outbound_Compressor := null;
         Item.Inbound_Inflater := null;
         Item.Outbound_Compression_Active := False;
         Item.Inbound_Compression_Active := False;
         Item.Outbound_Compression_Delayed := False;
         Item.Inbound_Compression_Delayed := False;
   end Close_Compression;

   function Produced
     (Out_Buffer : Stream_Element_Array; Out_Last : Stream_Element_Offset)
      return Boolean is
   begin
      return Out_Buffer'Length > 0 and then Out_Last >= Out_Buffer'First;
   end Produced;

   function Compress_Payload
     (Item    : in out Protected_State;
      Payload : Stream_Element_Array;
      Result  : out Packet_Buffer) return Status
   is
      Out_Data     :
        Stream_Element_Array
          (1
           ..
             Stream_Element_Offset
               (SSH_Lib.Protocol.Buffers.Max_Packet_Length));
      --  In_Last is an out-parameter of the zlib call below (set before it is
      --  read); seed it with Payload'First rather than Payload'First - 1 so an
      --  array whose 'First is the index type's minimum does not underflow.
      In_Last      : Stream_Element_Offset := Payload'First;
      Out_Last     : Stream_Element_Offset := Out_Data'First - 1;
      First_Input  : Stream_Element_Offset := Payload'First;
      Status_Value : Status := Ok;
   begin
      Clear (Result);

      if not Item.Outbound_Compression_Active then
         return Set (Result, Payload);
      end if;

      if Item.Outbound_Compressor = null then
         return Internal_Error;
      end if;

      --  OpenSSH-style per-packet compression: run the whole payload through a
      --  single Sync_Flush deflate that both consumes the input and flushes the
      --  packet's compressed block, looping only while the output buffer fills
      --  up completely (i.e. more compressed output is still pending). Because a
      --  Sync_Flush always emits at least a 4-byte flush marker, termination
      --  MUST key off "the output buffer was not completely filled", never off
      --  "no output was produced" (which never becomes true and would spin
      --  forever emitting markers).
      loop
         Zlib.Compress
           (Item.Outbound_Compressor.all,
            Payload (First_Input .. Payload'Last),
            In_Last,
            Out_Data,
            Out_Last,
            Zlib.Sync_Flush);

         if Produced (Out_Data, Out_Last) then
            Status_Value :=
              Append (Result, Out_Data (Out_Data'First .. Out_Last));
            if Status_Value /= Ok then
               return Status_Value;
            end if;
         end if;

         if In_Last >= First_Input then
            First_Input := In_Last + 1;
         end if;

         exit when Out_Last < Out_Data'Last;
      end loop;

      return Ok;
   exception
      when Zlib.Zlib_Error | Zlib.Status_Error =>
         return Write_Failed;
      when others =>
         return Internal_Error;
   end Compress_Payload;

   function Decompress_Payload
     (Item    : in out Protected_State;
      Payload : Stream_Element_Array;
      Result  : out Packet_Buffer) return Status
   is
      Out_Data     :
        Stream_Element_Array
          (1
           ..
             Stream_Element_Offset
               (SSH_Lib.Protocol.Buffers.Max_Packet_Length));
      --  In_Last is an out-parameter of the zlib call below (set before it is
      --  read); seed it with Payload'First rather than Payload'First - 1 so an
      --  array whose 'First is the index type's minimum does not underflow.
      In_Last      : Stream_Element_Offset := Payload'First;
      Out_Last     : Stream_Element_Offset := Out_Data'First - 1;
      First_Input  : Stream_Element_Offset := Payload'First;
      Status_Value : Status := Ok;
   begin
      Clear (Result);

      if not Item.Inbound_Compression_Active then
         return Set (Result, Payload);
      end if;

      if Item.Inbound_Inflater = null then
         return Internal_Error;
      end if;

      if Payload'Length > 0 then
         while First_Input <= Payload'Last loop
            Zlib.Translate
              (Item.Inbound_Inflater.all,
               Payload (First_Input .. Payload'Last),
               In_Last,
               Out_Data,
               Out_Last,
               Zlib.No_Flush);

            if Produced (Out_Data, Out_Last) then
               Status_Value :=
                 Append (Result, Out_Data (Out_Data'First .. Out_Last));
               if Status_Value /= Ok then
                  return Status_Value;
               end if;
            end if;

            if In_Last >= First_Input then
               First_Input := In_Last + 1;
            elsif not Produced (Out_Data, Out_Last) then
               return Read_Failed;
            end if;
         end loop;
      end if;

      loop
         Zlib.Flush
           (Item.Inbound_Inflater.all, Out_Data, Out_Last, Zlib.No_Flush);
         if Produced (Out_Data, Out_Last) then
            Status_Value :=
              Append (Result, Out_Data (Out_Data'First .. Out_Last));
            if Status_Value /= Ok then
               return Status_Value;
            end if;
         else
            exit;
         end if;
      end loop;

      return Ok;
   exception
      when Zlib.Zlib_Error | Zlib.Status_Error =>
         return Read_Failed;
      when others =>
         return Internal_Error;
   end Decompress_Payload;

   function Open_Outbound_Compressor
     (Item : in out Protected_State) return Status is
   begin
      if Item.Outbound_Compressor = null then
         Item.Outbound_Compressor := new Zlib.Compression_Filter_Type;
         Zlib.Deflate_Init
           (Item.Outbound_Compressor.all,
            Header => Zlib.Zlib_Header,
            Mode   => Zlib.Auto);
      end if;
      return Ok;
   exception
      when Zlib.Zlib_Error | Zlib.Status_Error =>
         return Unsupported_Feature;
      when others =>
         return Internal_Error;
   end Open_Outbound_Compressor;

   function Open_Inbound_Inflater (Item : in out Protected_State) return Status
   is
   begin
      if Item.Inbound_Inflater = null then
         Item.Inbound_Inflater := new Zlib.Filter_Type;
         Zlib.Inflate_Init
           (Item.Inbound_Inflater.all, Header => Zlib.Zlib_Header);
      end if;
      return Ok;
   exception
      when Zlib.Zlib_Error | Zlib.Status_Error =>
         return Unsupported_Feature;
      when others =>
         return Internal_Error;
   end Open_Inbound_Inflater;

   function Activate_Delayed_Compression
     (Item : in out Protected_State) return Status
   is
      Status_Value : Status;
   begin
      if Item.Outbound_Compression_Delayed then
         Status_Value := Open_Outbound_Compressor (Item);
         if Status_Value /= Ok then
            Mark_Dirty (Item, Status_Value);
            return Status_Value;
         end if;
         Item.Outbound_Compression_Active := True;
         Item.Outbound_Compression_Delayed := False;
      end if;

      if Item.Inbound_Compression_Delayed then
         Status_Value := Open_Inbound_Inflater (Item);
         if Status_Value /= Ok then
            Mark_Dirty (Item, Status_Value);
            return Status_Value;
         end if;
         Item.Inbound_Compression_Active := True;
         Item.Inbound_Compression_Delayed := False;
      end if;

      return Ok;
   exception
      when others =>
         Mark_Dirty (Item, Internal_Error);
         return Internal_Error;
   end Activate_Delayed_Compression;

   function Configure_Compression
     (Item                 : in out Protected_State;
      Outbound_Compression : String;
      Inbound_Compression  : String) return Status is
   begin
      Close_Compression (Item);

      if Outbound_Compression = "zlib" then
         declare
            Status_Value : constant Status := Open_Outbound_Compressor (Item);
         begin
            if Status_Value /= Ok then
               return Status_Value;
            end if;
         end;
         Item.Outbound_Compression_Active := True;
      elsif Outbound_Compression = "zlib@openssh.com" then
         Item.Outbound_Compression_Active := False;
         Item.Outbound_Compression_Delayed := True;
      elsif Outbound_Compression = "none" then
         Item.Outbound_Compression_Active := False;
      else
         return Unsupported_Feature;
      end if;

      if Inbound_Compression = "zlib" then
         declare
            Status_Value : constant Status := Open_Inbound_Inflater (Item);
         begin
            if Status_Value /= Ok then
               return Status_Value;
            end if;
         end;
         Item.Inbound_Compression_Active := True;
      elsif Inbound_Compression = "zlib@openssh.com" then
         Item.Inbound_Compression_Active := False;
         Item.Inbound_Compression_Delayed := True;
      elsif Inbound_Compression = "none" then
         Item.Inbound_Compression_Active := False;
      else
         return Unsupported_Feature;
      end if;

      return Ok;
   exception
      when Zlib.Zlib_Error | Zlib.Status_Error =>
         Close_Compression (Item);
         return Unsupported_Feature;
      when others =>
         Close_Compression (Item);
         return Internal_Error;
   end Configure_Compression;

   procedure Reset (Item : out Protected_State; Mac_Key : Stream_Element_Array)
   is
   begin
      SSH_Lib.Protocol.Packets.Reset (Item.Packet_State);
      Item.Outbound_Mac_Key_Data := [others => 0];
      Item.Inbound_Mac_Key_Data := [others => 0];
      Item.Outbound_Mac_Kind := HMAC_SHA2_256;
      Item.Inbound_Mac_Kind := HMAC_SHA2_256;
      Item.Outbound_Mac_Length := Mac_Length;
      Item.Inbound_Mac_Length := Mac_Length;
      CryptoLib.Ciphers.Reset (Item.Outbound_Cipher);
      CryptoLib.Ciphers.Reset (Item.Inbound_Cipher);
      Item.Outbound_Chacha20_Poly1305 := False;
      Item.Inbound_Chacha20_Poly1305 := False;
      Item.Outbound_Chacha_Key := [others => 0];
      Item.Inbound_Chacha_Key := [others => 0];
      Item.Outbound_AES_GCM := No_AES_GCM;
      Item.Inbound_AES_GCM := No_AES_GCM;
      Item.Outbound_AES_GCM_Key := [others => 0];
      Item.Inbound_AES_GCM_Key := [others => 0];
      Item.Outbound_AES_GCM_IV := [others => 0];
      Item.Inbound_AES_GCM_IV := [others => 0];
      Item.Outbound_CBC_Header_Encrypted := False;
      Item.Inbound_CBC_Header_Encrypted := False;
      Item.Outbound_Compression_Active := False;
      Item.Inbound_Compression_Active := False;
      Item.Outbound_Compression_Delayed := False;
      Item.Inbound_Compression_Delayed := False;
      Item.Outbound_Compressor := null;
      Item.Inbound_Inflater := null;
      Item.Cipher_Active := False;
      Item.Outbound_Block_Value :=
        SSH_Lib.Protocol.Packets.Cleartext_Block_Size;
      Item.Inbound_Block_Value :=
        SSH_Lib.Protocol.Packets.Cleartext_Block_Size;
      declare
         Copy_Size : constant Natural :=
           (if Mac_Key'Length < Mac_Length
            then Mac_Key'Length
            else Mac_Length);
      begin
         if Copy_Size > 0 then
            for Offset_Value in 0 .. Copy_Size - 1 loop
               Item.Outbound_Mac_Key_Data
                 (Stream_Element_Offset (Offset_Value + 1)) :=
                 Mac_Key
                   (Mac_Key'First + Stream_Element_Offset (Offset_Value));
               Item.Inbound_Mac_Key_Data
                 (Stream_Element_Offset (Offset_Value + 1)) :=
                 Mac_Key
                   (Mac_Key'First + Stream_Element_Offset (Offset_Value));
            end loop;
         end if;
      end;
      Item.Dirty_Value := False;
      Item.Failure := Ok;
   exception
      when others =>
         Item.Dirty_Value := True;
         Item.Failure := Internal_Error;
   end Reset;

   procedure Copy_Mac_Key
     (Source        : Stream_Element_Array;
      Required_Size : Natural;
      Target        : out Mac_Key_Buffer)
   is
      Copy_Size : constant Natural :=
        (if Source'Length < Required_Size
         then Source'Length
         else Required_Size);
   begin
      Target := [others => 0];
      if Copy_Size > 0 then
         for Offset_Value in 0 .. Copy_Size - 1 loop
            Target (Stream_Element_Offset (Offset_Value + 1)) :=
              Source (Source'First + Stream_Element_Offset (Offset_Value));
         end loop;
      end if;
   end Copy_Mac_Key;

   procedure Reset_With_Ciphers
     (Item              : out Protected_State;
      Algorithm_Name    : String;
      Outbound_Mac_Key  : Stream_Element_Array;
      Inbound_Mac_Key   : Stream_Element_Array;
      Outbound_Key_Data : Stream_Element_Array;
      Outbound_IV_Data  : Stream_Element_Array;
      Inbound_Key_Data  : Stream_Element_Array;
      Inbound_IV_Data   : Stream_Element_Array) is
   begin
      Reset_With_Ciphers
        (Item,
         Algorithm_Name,
         Algorithm_Name,
         "hmac-sha2-256",
         "hmac-sha2-256",
         Outbound_Mac_Key,
         Inbound_Mac_Key,
         Outbound_Key_Data,
         Outbound_IV_Data,
         Inbound_Key_Data,
         Inbound_IV_Data);
   end Reset_With_Ciphers;

   procedure Reset_With_Ciphers
     (Item                 : out Protected_State;
      Outbound_Cipher_Name : String;
      Inbound_Cipher_Name  : String;
      Outbound_Mac_Name    : String;
      Inbound_Mac_Name     : String;
      Outbound_Mac_Key     : Stream_Element_Array;
      Inbound_Mac_Key      : Stream_Element_Array;
      Outbound_Key_Data    : Stream_Element_Array;
      Outbound_IV_Data     : Stream_Element_Array;
      Inbound_Key_Data     : Stream_Element_Array;
      Inbound_IV_Data      : Stream_Element_Array) is
   begin
      Reset_With_Ciphers
        (Item,
         Outbound_Cipher_Name,
         Inbound_Cipher_Name,
         Outbound_Mac_Name,
         Inbound_Mac_Name,
         "none",
         "none",
         Outbound_Mac_Key,
         Inbound_Mac_Key,
         Outbound_Key_Data,
         Outbound_IV_Data,
         Inbound_Key_Data,
         Inbound_IV_Data);
   end Reset_With_Ciphers;

   procedure Copy_Chacha_Key
     (Source : Stream_Element_Array; Target : out ChaCha_Key_Buffer) is
   begin
      Target := [others => 0];
      if Source'Length < CryptoLib.ChaCha20_Poly1305.Key_Length then
         return;
      end if;
      for Index_Value in 0 .. CryptoLib.ChaCha20_Poly1305.Key_Length - 1
      loop
         Target (Target'First + Stream_Element_Offset (Index_Value)) :=
           Source (Source'First + Stream_Element_Offset (Index_Value));
      end loop;
   exception
      when others =>
         Target := [others => 0];
   end Copy_Chacha_Key;

   function AES_GCM_Name (Item : AES_GCM_Algorithm) return String is
   begin
      case Item is
         when AES128_GCM =>
            return "aes128-gcm@openssh.com";

         when AES256_GCM =>
            return "aes256-gcm@openssh.com";

         when No_AES_GCM =>
            return "";
      end case;
   end AES_GCM_Name;

   function AES_GCM_Kind (Name_Text : String) return AES_GCM_Algorithm is
   begin
      if Name_Text = "aes128-gcm@openssh.com" then
         return AES128_GCM;
      elsif Name_Text = "aes256-gcm@openssh.com" then
         return AES256_GCM;
      end if;
      return No_AES_GCM;
   end AES_GCM_Kind;

   procedure Copy_AES_GCM_Key
     (Source       : Stream_Element_Array;
      Length_Value : Natural;
      Target       : out AES_GCM_Key_Buffer) is
   begin
      Target := [others => 0];
      if Source'Length < Length_Value or else Length_Value > Target'Length then
         return;
      end if;
      for Index_Value in 0 .. Length_Value - 1 loop
         Target (Target'First + Stream_Element_Offset (Index_Value)) :=
           Source (Source'First + Stream_Element_Offset (Index_Value));
      end loop;
   exception
      when others =>
         Target := [others => 0];
   end Copy_AES_GCM_Key;

   procedure Increment_AES_GCM_IV (IV : in out AES_GCM_IV_Buffer) is
      --  RFC 5647: the 12-octet aes-gcm@openssh.com nonce is a 4-octet fixed
      --  field followed by an 8-octet invocation counter (IV bytes 5..12). The
      --  counter is incremented as a big-endian 64-bit integer after every
      --  packet so each packet gets a unique GCM nonce.
      Index : Stream_Element_Offset := IV'Last;
   begin
      while Index >= 5 loop
         IV (Index) := IV (Index) + 1;
         exit when IV (Index) /= 0;
         Index := Index - 1;
      end loop;
   end Increment_AES_GCM_IV;

   procedure Copy_AES_GCM_IV
     (Source : Stream_Element_Array; Target : out AES_GCM_IV_Buffer) is
   begin
      Target := [others => 0];
      if Source'Length < Target'Length then
         return;
      end if;
      for Index_Value in 0 .. Target'Length - 1 loop
         Target (Target'First + Stream_Element_Offset (Index_Value)) :=
           Source (Source'First + Stream_Element_Offset (Index_Value));
      end loop;
   exception
      when others =>
         Target := [others => 0];
   end Copy_AES_GCM_IV;

   procedure Reset_With_Ciphers
     (Item                 : out Protected_State;
      Outbound_Cipher_Name : String;
      Inbound_Cipher_Name  : String;
      Outbound_Mac_Name    : String;
      Inbound_Mac_Name     : String;
      Outbound_Compression : String;
      Inbound_Compression  : String;
      Outbound_Mac_Key     : Stream_Element_Array;
      Inbound_Mac_Key      : Stream_Element_Array;
      Outbound_Key_Data    : Stream_Element_Array;
      Outbound_IV_Data     : Stream_Element_Array;
      Inbound_Key_Data     : Stream_Element_Array;
      Inbound_IV_Data      : Stream_Element_Array)
   is
      Status_Value  : Status;
      Outbound_Kind : Mac_Algorithm;
      Inbound_Kind  : Mac_Algorithm;

      procedure Clear_Failed_Epoch_Material is
      begin
         --  A failed reset must not leave any partially resolved protected
         --  epoch material behind.  This is especially important for
         --  recognized-but-unsupported MAC names such as OpenSSH UMAC, and
         --  also protects later cipher/compression failures after MAC keys
         --  have already been copied into the transcript state.  Close and
         --  clear compression first because delayed/active zlib state may
         --  have been allocated before a later reset step fails.
         Close_Compression (Item);
         CryptoLib.Ciphers.Reset (Item.Outbound_Cipher);
         CryptoLib.Ciphers.Reset (Item.Inbound_Cipher);
         Item.Outbound_Chacha20_Poly1305 := False;
         Item.Inbound_Chacha20_Poly1305 := False;
         Item.Outbound_Chacha_Key := [others => 0];
         Item.Inbound_Chacha_Key := [others => 0];
         Item.Outbound_Mac_Key_Data := [others => 0];
         Item.Inbound_Mac_Key_Data := [others => 0];
         Item.Outbound_Mac_Length := 0;
         Item.Inbound_Mac_Length := 0;
         Item.Outbound_Mac_Kind := HMAC_SHA2_256;
         Item.Inbound_Mac_Kind := HMAC_SHA2_256;
         Item.Outbound_AES_GCM := No_AES_GCM;
         Item.Inbound_AES_GCM := No_AES_GCM;
         Item.Outbound_AES_GCM_Key := [others => 0];
         Item.Inbound_AES_GCM_Key := [others => 0];
         Item.Outbound_AES_GCM_IV := [others => 0];
         Item.Inbound_AES_GCM_IV := [others => 0];
         Item.Outbound_CBC_Header_Encrypted := False;
         Item.Inbound_CBC_Header_Encrypted := False;
         Item.Outbound_Compression_Active := False;
         Item.Inbound_Compression_Active := False;
         Item.Outbound_Compression_Delayed := False;
         Item.Inbound_Compression_Delayed := False;
         Item.Outbound_Compressor := null;
         Item.Inbound_Inflater := null;
         Item.Outbound_Block_Value :=
           SSH_Lib.Protocol.Packets.Cleartext_Block_Size;
         Item.Inbound_Block_Value :=
           SSH_Lib.Protocol.Packets.Cleartext_Block_Size;
      exception
         when others =>
            null;
      end Clear_Failed_Epoch_Material;
   begin
      SSH_Lib.Protocol.Packets.Reset (Item.Packet_State);
      CryptoLib.Ciphers.Reset (Item.Outbound_Cipher);
      CryptoLib.Ciphers.Reset (Item.Inbound_Cipher);
      Item.Outbound_Chacha20_Poly1305 := False;
      Item.Inbound_Chacha20_Poly1305 := False;
      Item.Outbound_Chacha_Key := [others => 0];
      Item.Inbound_Chacha_Key := [others => 0];
      --  Clear MAC state before resolving the negotiated names.  This keeps
      --  recognized-but-unsupported MACs such as OpenSSH UMAC fail-closed
      --  without leaving stale keys or lengths from a previously protected
      --  epoch in the transcript object.
      Item.Outbound_Mac_Key_Data := [others => 0];
      Item.Inbound_Mac_Key_Data := [others => 0];
      Item.Outbound_Mac_Length := 0;
      Item.Inbound_Mac_Length := 0;
      Item.Outbound_Mac_Kind := HMAC_SHA2_256;
      Item.Inbound_Mac_Kind := HMAC_SHA2_256;
      Item.Outbound_AES_GCM := No_AES_GCM;
      Item.Inbound_AES_GCM := No_AES_GCM;
      Item.Outbound_AES_GCM_Key := [others => 0];
      Item.Inbound_AES_GCM_Key := [others => 0];
      Item.Outbound_AES_GCM_IV := [others => 0];
      Item.Inbound_AES_GCM_IV := [others => 0];
      Item.Outbound_CBC_Header_Encrypted := False;
      Item.Inbound_CBC_Header_Encrypted := False;
      Item.Outbound_Compression_Active := False;
      Item.Inbound_Compression_Active := False;
      Item.Outbound_Compression_Delayed := False;
      Item.Inbound_Compression_Delayed := False;
      Item.Outbound_Compressor := null;
      Item.Inbound_Inflater := null;

      Status_Value := Mac_Kind_For (Outbound_Mac_Name, Outbound_Kind);
      if Status_Value /= Ok then
         Item.Cipher_Active := False;
         Clear_Failed_Epoch_Material;
         Item.Dirty_Value := True;
         Item.Failure := Status_Value;
         return;
      end if;

      Status_Value := Mac_Kind_For (Inbound_Mac_Name, Inbound_Kind);
      if Status_Value /= Ok then
         Item.Cipher_Active := False;
         Clear_Failed_Epoch_Material;
         Item.Dirty_Value := True;
         Item.Failure := Status_Value;
         return;
      end if;

      Item.Outbound_Mac_Kind := Outbound_Kind;
      Item.Inbound_Mac_Kind := Inbound_Kind;
      Item.Outbound_Mac_Length := Length_For (Outbound_Kind);
      Item.Inbound_Mac_Length := Length_For (Inbound_Kind);
      Copy_Mac_Key
        (Outbound_Mac_Key,
         Key_Length_For (Outbound_Kind),
         Item.Outbound_Mac_Key_Data);
      Copy_Mac_Key
        (Inbound_Mac_Key,
         Key_Length_For (Inbound_Kind),
         Item.Inbound_Mac_Key_Data);

      if Outbound_Cipher_Name = "chacha20-poly1305@openssh.com" then
         if Outbound_Key_Data'Length
           < CryptoLib.ChaCha20_Poly1305.Key_Length
         then
            Item.Cipher_Active := False;
            Clear_Failed_Epoch_Material;
            Item.Dirty_Value := True;
            Item.Failure := Handshake_Failed;
            return;
         end if;

         Copy_Chacha_Key (Outbound_Key_Data, Item.Outbound_Chacha_Key);
         Item.Outbound_Chacha20_Poly1305 := True;
         Item.Outbound_Block_Value :=
           SSH_Lib.Protocol.Packets.Cleartext_Block_Size;
         Item.Outbound_Mac_Length :=
           CryptoLib.ChaCha20_Poly1305.Tag_Length;
      elsif AES_GCM_Kind (Outbound_Cipher_Name) /= No_AES_GCM then
         declare
            GCM_Key_Length : constant Natural :=
              CryptoLib.Ciphers.AES_GCM_Key_Length (Outbound_Cipher_Name);
         begin
            if GCM_Key_Length = 0
              or else Outbound_Key_Data'Length < GCM_Key_Length
              or else Outbound_IV_Data'Length < Item.Outbound_AES_GCM_IV'Length
            then
               Item.Cipher_Active := False;
               Clear_Failed_Epoch_Material;
               Item.Dirty_Value := True;
               Item.Failure := Handshake_Failed;
               return;
            end if;
            Item.Outbound_AES_GCM := AES_GCM_Kind (Outbound_Cipher_Name);
            Copy_AES_GCM_Key
              (Outbound_Key_Data, GCM_Key_Length, Item.Outbound_AES_GCM_Key);
            Copy_AES_GCM_IV (Outbound_IV_Data, Item.Outbound_AES_GCM_IV);
            --  RFC 5647: the encrypted portion (padlen || payload || padding)
            --  must be a multiple of the 16-octet AES block, so pad to 16.
            Item.Outbound_Block_Value := AES_GCM_Block_Size;
            Item.Outbound_Mac_Length :=
              CryptoLib.Ciphers.AES_GCM_Tag_Length;
         end;
      else
         Status_Value :=
           CryptoLib.Ciphers.Initialize
             (Item.Outbound_Cipher,
              Outbound_Cipher_Name,
              CryptoLib.Ciphers.Client_To_Server,
              Outbound_Key_Data,
              Outbound_IV_Data);
         if Status_Value /= Ok then
            Item.Cipher_Active := False;
            Clear_Failed_Epoch_Material;
            Item.Dirty_Value := True;
            Item.Failure := Status_Value;
            return;
         end if;

         Item.Outbound_Block_Value :=
           CryptoLib.Ciphers.Block_Size (Item.Outbound_Cipher);
         Item.Outbound_CBC_Header_Encrypted :=
           Is_CBC_Cipher (Outbound_Cipher_Name);
      end if;

      if Inbound_Cipher_Name = "chacha20-poly1305@openssh.com" then
         if Inbound_Key_Data'Length
           < CryptoLib.ChaCha20_Poly1305.Key_Length
         then
            Item.Cipher_Active := False;
            Clear_Failed_Epoch_Material;
            Item.Dirty_Value := True;
            Item.Failure := Handshake_Failed;
            return;
         end if;

         Copy_Chacha_Key (Inbound_Key_Data, Item.Inbound_Chacha_Key);
         Item.Inbound_Chacha20_Poly1305 := True;
         Item.Inbound_Block_Value :=
           SSH_Lib.Protocol.Packets.Cleartext_Block_Size;
         Item.Inbound_Mac_Length :=
           CryptoLib.ChaCha20_Poly1305.Tag_Length;
      elsif AES_GCM_Kind (Inbound_Cipher_Name) /= No_AES_GCM then
         declare
            GCM_Key_Length : constant Natural :=
              CryptoLib.Ciphers.AES_GCM_Key_Length (Inbound_Cipher_Name);
         begin
            if GCM_Key_Length = 0
              or else Inbound_Key_Data'Length < GCM_Key_Length
              or else Inbound_IV_Data'Length < Item.Inbound_AES_GCM_IV'Length
            then
               Item.Cipher_Active := False;
               Clear_Failed_Epoch_Material;
               Item.Dirty_Value := True;
               Item.Failure := Handshake_Failed;
               return;
            end if;
            Item.Inbound_AES_GCM := AES_GCM_Kind (Inbound_Cipher_Name);
            Copy_AES_GCM_Key
              (Inbound_Key_Data, GCM_Key_Length, Item.Inbound_AES_GCM_Key);
            Copy_AES_GCM_IV (Inbound_IV_Data, Item.Inbound_AES_GCM_IV);
            --  RFC 5647: the encrypted portion (padlen || payload || padding)
            --  must be a multiple of the 16-octet AES block, so pad to 16.
            Item.Inbound_Block_Value := AES_GCM_Block_Size;
            Item.Inbound_Mac_Length :=
              CryptoLib.Ciphers.AES_GCM_Tag_Length;
         end;
      else
         Status_Value :=
           CryptoLib.Ciphers.Initialize
             (Item.Inbound_Cipher,
              Inbound_Cipher_Name,
              CryptoLib.Ciphers.Server_To_Client,
              Inbound_Key_Data,
              Inbound_IV_Data);
         if Status_Value /= Ok then
            Item.Cipher_Active := False;
            Clear_Failed_Epoch_Material;
            Item.Dirty_Value := True;
            Item.Failure := Status_Value;
            return;
         end if;

         Item.Inbound_Block_Value :=
           CryptoLib.Ciphers.Block_Size (Item.Inbound_Cipher);
         Item.Inbound_CBC_Header_Encrypted :=
           Is_CBC_Cipher (Inbound_Cipher_Name);
      end if;

      Status_Value :=
        Configure_Compression
          (Item, Outbound_Compression, Inbound_Compression);
      if Status_Value /= Ok then
         Item.Cipher_Active := False;
         Clear_Failed_Epoch_Material;
         Item.Dirty_Value := True;
         Item.Failure := Status_Value;
         return;
      end if;

      Item.Cipher_Active := True;
      Item.Dirty_Value := False;
      Item.Failure := Ok;
   exception
      when others =>
         Close_Compression (Item);
         Item.Cipher_Active := False;
         Clear_Failed_Epoch_Material;
         Item.Dirty_Value := True;
         Item.Failure := Internal_Error;
   end Reset_With_Ciphers;

   function Is_Dirty (Item : Protected_State) return Boolean is
   begin
      return Item.Dirty_Value;
   exception
      when others =>
         return True;
   end Is_Dirty;

   function Last_Failure (Item : Protected_State) return Status is
   begin
      return Item.Failure;
   exception
      when others =>
         return Internal_Error;
   end Last_Failure;

   function Outbound_Block_Size (Item : Protected_State) return Natural is
   begin
      if Item.Outbound_Block_Value
        < SSH_Lib.Protocol.Packets.Cleartext_Block_Size
      then
         return SSH_Lib.Protocol.Packets.Cleartext_Block_Size;
      end if;
      return Item.Outbound_Block_Value;
   exception
      when others =>
         return SSH_Lib.Protocol.Packets.Cleartext_Block_Size;
   end Outbound_Block_Size;

   function Inbound_Block_Size (Item : Protected_State) return Natural is
   begin
      if Item.Inbound_Block_Value
        < SSH_Lib.Protocol.Packets.Cleartext_Block_Size
      then
         return SSH_Lib.Protocol.Packets.Cleartext_Block_Size;
      end if;
      return Item.Inbound_Block_Value;
   exception
      when others =>
         return SSH_Lib.Protocol.Packets.Cleartext_Block_Size;
   end Inbound_Block_Size;

   function Inbound_Mac_Size (Item : Protected_State) return Natural is
   begin
      return Item.Inbound_Mac_Length;
   exception
      when others =>
         return Mac_Length;
   end Inbound_Mac_Size;

   function Inbound_Length_In_Alignment (Item : Protected_State) return Boolean
   is
   begin
      --  The 4-byte length is part of the block-padding alignment only for
      --  block ciphers with a plain (Mac-then-Encrypt) MAC. AEAD ciphers and
      --  Encrypt-then-MAC MACs send it in the clear, outside the aligned body.
      return not (Item.Inbound_Chacha20_Poly1305
                  or else Item.Inbound_AES_GCM /= No_AES_GCM
                  or else Is_EtM (Item.Inbound_Mac_Kind));
   exception
      when others =>
         return True;
   end Inbound_Length_In_Alignment;

   function Outbound_Mac_Size (Item : Protected_State) return Natural is
   begin
      return Item.Outbound_Mac_Length;
   exception
      when others =>
         return Mac_Length;
   end Outbound_Mac_Size;

   function Inbound_Header_Is_Clear (Item : Protected_State) return Boolean is
   begin
      return
        Item.Cipher_Active
        and then not Item.Inbound_Chacha20_Poly1305
        and then Item.Inbound_AES_GCM = No_AES_GCM
        and then Is_EtM (Item.Inbound_Mac_Kind);
   exception
      when others =>
         return False;
   end Inbound_Header_Is_Clear;

   function Outbound_Header_Is_Clear (Item : Protected_State) return Boolean is
   begin
      return
        Item.Cipher_Active
        and then not Item.Outbound_Chacha20_Poly1305
        and then Item.Outbound_AES_GCM = No_AES_GCM
        and then Is_EtM (Item.Outbound_Mac_Kind);
   exception
      when others =>
         return False;
   end Outbound_Header_Is_Clear;

   function Inbound_Sequence (Item : Protected_State) return Unsigned_32 is
   begin
      return SSH_Lib.Protocol.Packets.Inbound_Sequence (Item.Packet_State);
   exception
      when others =>
         return 0;
   end Inbound_Sequence;

   function Outbound_Sequence (Item : Protected_State) return Unsigned_32 is
   begin
      return SSH_Lib.Protocol.Packets.Outbound_Sequence (Item.Packet_State);
   exception
      when others =>
         return 0;
   end Outbound_Sequence;

   procedure Set_Sequences_For_Test
     (Item           : in out Protected_State;
      Inbound_Value  : Unsigned_32;
      Outbound_Value : Unsigned_32) is
   begin
      SSH_Lib.Protocol.Packets.Set_Sequences_For_Test
        (Item.Packet_State, Inbound_Value, Outbound_Value);
   exception
      when others =>
         Mark_Dirty (Item, Internal_Error);
   end Set_Sequences_For_Test;

   function Encode_Protected_Packet
     (Item              : in out Protected_State;
      Payload           : Stream_Element_Array;
      Packet            : out Packet_Buffer;
      Use_Test_Padding  : Boolean := False;
      Test_Padding_Byte : Stream_Element := 0) return Status
   is
      Plain_Packet    : Packet_Buffer;
      Encoded_Payload : Packet_Buffer;
      Status_Value    : Status;
      Sequence_Value  : constant Unsigned_32 :=
        SSH_Lib.Protocol.Packets.Outbound_Sequence (Item.Packet_State);
   begin
      Clear (Packet);
      if Item.Dirty_Value then
         return Write_Failed;
      end if;

      Status_Value := Compress_Payload (Item, Payload, Encoded_Payload);
      if Status_Value /= Ok then
         Mark_Dirty (Item, Status_Value);
         return Status_Value;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Packets.Encode_Cleartext_Packet
          (Item.Packet_State,
           To_Array (Encoded_Payload),
           Plain_Packet,
           Use_Test_Padding,
           Test_Padding_Byte,
           Outbound_Block_Size (Item),
           --  AEAD ciphers (chacha20-poly1305, AES-GCM) and Encrypt-then-MAC
           --  MACs send the 4-byte length field in the clear (it is
           --  authenticated separately), so it is excluded from the block-size
           --  padding alignment; only the encrypted body is aligned.
           Count_Length_Field =>
             not Item.Outbound_Chacha20_Poly1305
             and then Item.Outbound_AES_GCM = No_AES_GCM
             and then not Is_EtM (Item.Outbound_Mac_Kind));
      if Status_Value /= Ok then
         Mark_Dirty (Item, Status_Value);
         return Status_Value;
      end if;

      declare
         Plain_Array : constant Stream_Element_Array :=
           To_Array (Plain_Packet);
      begin
         if Item.Outbound_Chacha20_Poly1305 then
            declare
               Wire_Array :
                 Stream_Element_Array
                   (1
                    ..
                      Stream_Element_Offset
                        (Plain_Array'Length
                         + CryptoLib.ChaCha20_Poly1305.Tag_Length));
            begin
               Status_Value :=
                 CryptoLib.ChaCha20_Poly1305.Seal
                   (Item.Outbound_Chacha_Key,
                    Sequence_Value,
                    Plain_Array,
                    Wire_Array);
               if Status_Value = Ok then
                  Status_Value := Append (Packet, Wire_Array);
               end if;
               if Status_Value /= Ok then
                  Mark_Dirty (Item, Status_Value);
                  Clear (Packet);
                  return Status_Value;
               end if;
            end;
         elsif Item.Outbound_AES_GCM /= No_AES_GCM then
            declare
               Wire_Array :
                 Stream_Element_Array
                   (1
                    ..
                      Stream_Element_Offset
                        (Plain_Array'Length
                         + CryptoLib.Ciphers.AES_GCM_Tag_Length));
            begin
               Status_Value :=
                 CryptoLib.Ciphers.Seal_GCM
                   (AES_GCM_Name (Item.Outbound_AES_GCM),
                    Item.Outbound_AES_GCM_Key,
                    Item.Outbound_AES_GCM_IV,
                    Sequence_Value,
                    Plain_Array,
                    Wire_Array);
               if Status_Value = Ok then
                  Increment_AES_GCM_IV (Item.Outbound_AES_GCM_IV);
                  Status_Value := Append (Packet, Wire_Array);
               end if;
               if Status_Value /= Ok then
                  Mark_Dirty (Item, Status_Value);
                  Clear (Packet);
                  return Status_Value;
               end if;
            end;
         elsif Item.Cipher_Active and then Is_EtM (Item.Outbound_Mac_Kind) then
            declare
               Clear_Header : constant Stream_Element_Array :=
                 Plain_Array (Plain_Array'First .. Plain_Array'First + 3);
               Plain_Body   : constant Stream_Element_Array :=
                 Plain_Array (Plain_Array'First + 4 .. Plain_Array'Last);
               Cipher_Body  : Stream_Element_Array (Plain_Body'Range);
            begin
               Status_Value :=
                 CryptoLib.Ciphers.Encrypt
                   (Item.Outbound_Cipher, Plain_Body, Cipher_Body);
               if Status_Value /= Ok then
                  Mark_Dirty (Item, Status_Value);
                  Clear (Packet);
                  return Status_Value;
               end if;

               Status_Value := Append (Packet, Clear_Header);
               if Status_Value = Ok then
                  Status_Value := Append (Packet, Cipher_Body);
               end if;
               if Status_Value /= Ok then
                  Mark_Dirty (Item, Status_Value);
                  Clear (Packet);
                  return Status_Value;
               end if;

               declare
                  Wire_Array : constant Stream_Element_Array :=
                    To_Array (Packet);
                  Mac_Array  : constant Stream_Element_Array :=
                    Expected_Mac
                      (Item.Outbound_Mac_Kind,
                       Item.Outbound_Mac_Key_Data,
                       Sequence_Value,
                       Wire_Array);
               begin
                  Status_Value := Append (Packet, Mac_Array);
               end;
            end;
         else
            declare
               Mac_Array : constant Stream_Element_Array :=
                 Expected_Mac
                   (Item.Outbound_Mac_Kind,
                    Item.Outbound_Mac_Key_Data,
                    Sequence_Value,
                    Plain_Array);
            begin
               if Item.Cipher_Active then
                  declare
                     Cipher_Array : Stream_Element_Array (Plain_Array'Range);
                  begin
                     Status_Value :=
                       CryptoLib.Ciphers.Encrypt
                         (Item.Outbound_Cipher, Plain_Array, Cipher_Array);
                     if Status_Value /= Ok then
                        Mark_Dirty (Item, Status_Value);
                        Clear (Packet);
                        return Status_Value;
                     end if;

                     Status_Value := Append (Packet, Cipher_Array);
                  end;
               else
                  Status_Value := Append (Packet, Plain_Array);
               end if;
               if Status_Value = Ok then
                  Status_Value := Append (Packet, Mac_Array);
               end if;
            end;
         end if;

         if Status_Value /= Ok then
            Mark_Dirty (Item, Status_Value);
            Clear (Packet);
            return Status_Value;
         end if;
      end;

      return Ok;
   exception
      when others =>
         Clear (Packet);
         Mark_Dirty (Item, Internal_Error);
         return Internal_Error;
   end Encode_Protected_Packet;

   function Decode_Protected_Header
     (Item             : in out Protected_State;
      Encrypted_Header : Stream_Element_Array;
      Plain_Header     : out Stream_Element_Array) return Status is
   begin
      if Plain_Header'Length /= Encrypted_Header'Length
        or else Plain_Header'Length /= 4
      then
         Plain_Header := [others => 0];
         return Internal_Error;
      end if;

      if Item.Dirty_Value then
         Plain_Header := [others => 0];
         return Read_Failed;
      end if;

      if Item.Inbound_Chacha20_Poly1305 then
         return
           CryptoLib.ChaCha20_Poly1305.Encrypt_Length
             (Item.Inbound_Chacha_Key,
              SSH_Lib.Protocol.Packets.Inbound_Sequence (Item.Packet_State),
              Encrypted_Header,
              Plain_Header);
      elsif Item.Inbound_AES_GCM /= No_AES_GCM then
         return
           CryptoLib.Ciphers.Encrypt_GCM_Length
             (AES_GCM_Name (Item.Inbound_AES_GCM),
              Item.Inbound_AES_GCM_Key,
              Item.Inbound_AES_GCM_IV,
              SSH_Lib.Protocol.Packets.Inbound_Sequence (Item.Packet_State),
              Encrypted_Header,
              Plain_Header);
      elsif Item.Cipher_Active and then Is_EtM (Item.Inbound_Mac_Kind) then
         Plain_Header := Encrypted_Header;
         return Ok;
      elsif Item.Cipher_Active then
         return
           CryptoLib.Ciphers.Decrypt
             (Item.Inbound_Cipher, Encrypted_Header, Plain_Header);
      else
         Plain_Header := Encrypted_Header;
         return Ok;
      end if;
   exception
      when others =>
         Plain_Header := [others => 0];
         Mark_Dirty (Item, Internal_Error);
         return Internal_Error;
   end Decode_Protected_Header;

   function Inbound_Header_Requires_Block
     (Item : Protected_State) return Boolean is
   begin
      return Item.Cipher_Active
        and then Item.Inbound_CBC_Header_Encrypted
        and then not Is_EtM (Item.Inbound_Mac_Kind);
   end Inbound_Header_Requires_Block;

   function Decode_Protected_First_Block_Header
     (Item                  : in out Protected_State;
      Encrypted_First_Block : Stream_Element_Array;
      Plain_First_Block     : out Stream_Element_Array) return Status is
   begin
      if Plain_First_Block'Length /= Encrypted_First_Block'Length
        or else Encrypted_First_Block'Length /= Inbound_Block_Size (Item)
        or else not Inbound_Header_Requires_Block (Item)
      then
         Plain_First_Block := [others => 0];
         return Internal_Error;
      end if;

      if Item.Dirty_Value then
         Plain_First_Block := [others => 0];
         return Read_Failed;
      end if;

      return
        CryptoLib.Ciphers.Decrypt
          (Item.Inbound_Cipher, Encrypted_First_Block, Plain_First_Block);
   exception
      when others =>
         Plain_First_Block := [others => 0];
         Mark_Dirty (Item, Internal_Error);
         return Internal_Error;
   end Decode_Protected_First_Block_Header;

   function Decode_Protected_Packet_After_First_Block
     (Item                   : in out Protected_State;
      Plain_First_Block      : Stream_Element_Array;
      Encrypted_Rest_And_Mac : Stream_Element_Array;
      Payload                : out Packet_Buffer;
      Failure_When_Malformed : Status := Handshake_Failed) return Status
   is
      Sequence_Value : constant Unsigned_32 :=
        SSH_Lib.Protocol.Packets.Inbound_Sequence (Item.Packet_State);
      Status_Value   : Status;
   begin
      Clear (Payload);
      if Item.Dirty_Value then
         return Read_Failed;
      end if;

      if not Inbound_Header_Requires_Block (Item)
        or else Plain_First_Block'Length /= Inbound_Block_Size (Item)
        or else Encrypted_Rest_And_Mac'Length < Item.Inbound_Mac_Length
      then
         Mark_Dirty (Item, Failure_When_Malformed);
         return Failure_When_Malformed;
      end if;

      declare
         Rest_Length : constant Natural :=
           Encrypted_Rest_And_Mac'Length - Item.Inbound_Mac_Length;
         Actual_Mac : constant Stream_Element_Array :=
           Encrypted_Rest_And_Mac
             (Encrypted_Rest_And_Mac'Last
              - Stream_Element_Offset (Item.Inbound_Mac_Length)
              + 1
              .. Encrypted_Rest_And_Mac'Last);
      begin
         if Rest_Length = 0 then
            declare
               Plain_Packet : constant Stream_Element_Array := Plain_First_Block;
               Wanted_Mac   : constant Stream_Element_Array :=
                 Expected_Mac
                   (Item.Inbound_Mac_Kind,
                    Item.Inbound_Mac_Key_Data,
                    Sequence_Value,
                    Plain_Packet);
               Encoded_Payload : Packet_Buffer;
            begin
               if not CryptoLib.Constant_Time.Equal (Actual_Mac, Wanted_Mac) then
                  Mark_Dirty (Item, Failure_When_Malformed);
                  return Failure_When_Malformed;
               end if;
               Status_Value :=
                 SSH_Lib.Protocol.Packets.Decode_Cleartext_Packet
                   (Item.Packet_State,
                    Plain_Packet,
                    Encoded_Payload,
                    Inbound_Block_Size (Item));
               if Status_Value = Ok then
                  Status_Value :=
                    Decompress_Payload
                      (Item, To_Array (Encoded_Payload), Payload);
               end if;
            end;
         else
            if Rest_Length mod Inbound_Block_Size (Item) /= 0 then
               Mark_Dirty (Item, Failure_When_Malformed);
               return Failure_When_Malformed;
            end if;

            declare
               Encrypted_Rest : constant Stream_Element_Array :=
                 Encrypted_Rest_And_Mac
                   (Encrypted_Rest_And_Mac'First
                    ..
                      Encrypted_Rest_And_Mac'First
                      + Stream_Element_Offset (Rest_Length - 1));
               Plain_Rest : Stream_Element_Array (Encrypted_Rest'Range);
            begin
               Status_Value :=
                 CryptoLib.Ciphers.Decrypt
                   (Item.Inbound_Cipher, Encrypted_Rest, Plain_Rest);
               if Status_Value /= Ok then
                  Mark_Dirty (Item, Status_Value);
                  return Status_Value;
               end if;

               declare
                  Plain_Packet :
                    Stream_Element_Array
                      (1
                       ..
                         Stream_Element_Offset
                           (Plain_First_Block'Length + Plain_Rest'Length));
                  Wanted_Mac      : Stream_Element_Array
                    (1 .. Stream_Element_Offset (Item.Inbound_Mac_Length));
                  Encoded_Payload : Packet_Buffer;
               begin
                  Plain_Packet
                    (1 .. Stream_Element_Offset (Plain_First_Block'Length)) :=
                    Plain_First_Block;
                  Plain_Packet
                    (Stream_Element_Offset (Plain_First_Block'Length)
                     + 1
                     .. Plain_Packet'Last) :=
                    Plain_Rest;
                  Wanted_Mac :=
                    Expected_Mac
                      (Item.Inbound_Mac_Kind,
                       Item.Inbound_Mac_Key_Data,
                       Sequence_Value,
                       Plain_Packet);
                  if not CryptoLib.Constant_Time.Equal (Actual_Mac, Wanted_Mac)
                  then
                     Mark_Dirty (Item, Failure_When_Malformed);
                     return Failure_When_Malformed;
                  end if;
                  Status_Value :=
                    SSH_Lib.Protocol.Packets.Decode_Cleartext_Packet
                      (Item.Packet_State,
                       Plain_Packet,
                       Encoded_Payload,
                       Inbound_Block_Size (Item));
                  if Status_Value = Ok then
                     Status_Value :=
                       Decompress_Payload
                         (Item, To_Array (Encoded_Payload), Payload);
                  end if;
               end;
            end;
         end if;
      end;

      if Status_Value /= Ok then
         Mark_Dirty (Item, Failure_When_Malformed);
         Clear (Payload);
         return Failure_When_Malformed;
      end if;
      return Ok;
   exception
      when others =>
         Clear (Payload);
         Mark_Dirty (Item, Internal_Error);
         return Internal_Error;
   end Decode_Protected_Packet_After_First_Block;

   function Decode_Protected_Packet_After_Header
     (Item                   : in out Protected_State;
      Plain_Header           : Stream_Element_Array;
      Encrypted_Body_And_Mac : Stream_Element_Array;
      Payload                : out Packet_Buffer;
      Failure_When_Malformed : Status := Handshake_Failed) return Status
   is
      Sequence_Value : constant Unsigned_32 :=
        SSH_Lib.Protocol.Packets.Inbound_Sequence (Item.Packet_State);
      Status_Value   : Status;
   begin
      Clear (Payload);
      if Item.Dirty_Value then
         return Read_Failed;
      end if;

      if Plain_Header'Length /= 4
        or else Encrypted_Body_And_Mac'Length <= Item.Inbound_Mac_Length
      then
         Mark_Dirty (Item, Failure_When_Malformed);
         return Failure_When_Malformed;
      end if;

      if Item.Inbound_Chacha20_Poly1305 then
         declare
            Encrypted_Header : Stream_Element_Array (1 .. 4);
            Wire_Packet      :
              Stream_Element_Array
                (1
                 ..
                   Stream_Element_Offset
                     (Plain_Header'Length + Encrypted_Body_And_Mac'Length));
            Plain_Packet     :
              Stream_Element_Array
                (1
                 ..
                   Stream_Element_Offset
                     (Plain_Header'Length
                      + Encrypted_Body_And_Mac'Length
                      - CryptoLib.ChaCha20_Poly1305.Tag_Length));
         begin
            Status_Value :=
              CryptoLib.ChaCha20_Poly1305.Encrypt_Length
                (Item.Inbound_Chacha_Key,
                 Sequence_Value,
                 Plain_Header,
                 Encrypted_Header);
            if Status_Value /= Ok then
               Mark_Dirty (Item, Status_Value);
               return Status_Value;
            end if;
            Wire_Packet (1 .. 4) := Encrypted_Header;
            Wire_Packet (5 .. Wire_Packet'Last) := Encrypted_Body_And_Mac;
            Status_Value :=
              CryptoLib.ChaCha20_Poly1305.Open
                (Item.Inbound_Chacha_Key,
                 Sequence_Value,
                 Wire_Packet,
                 Plain_Packet);
            if Status_Value /= Ok then
               Mark_Dirty (Item, Failure_When_Malformed);
               return Failure_When_Malformed;
            end if;
            declare
               Encoded_Payload : Packet_Buffer;
            begin
               Status_Value :=
                 SSH_Lib.Protocol.Packets.Decode_Cleartext_Packet
                   (Item.Packet_State,
                    Plain_Packet,
                    Encoded_Payload,
                    Inbound_Block_Size (Item),
                    Count_Length_Field => False);
               if Status_Value = Ok then
                  Status_Value :=
                    Decompress_Payload
                      (Item, To_Array (Encoded_Payload), Payload);
               end if;
            end;
         end;

         if Status_Value /= Ok then
            Mark_Dirty (Item, Failure_When_Malformed);
            Clear (Payload);
            return Failure_When_Malformed;
         end if;
         return Ok;
      elsif Item.Inbound_AES_GCM /= No_AES_GCM then
         declare
            Encrypted_Header : Stream_Element_Array (1 .. 4);
            Wire_Packet      :
              Stream_Element_Array
                (1
                 ..
                   Stream_Element_Offset
                     (Plain_Header'Length + Encrypted_Body_And_Mac'Length));
            Plain_Packet     :
              Stream_Element_Array
                (1
                 ..
                   Stream_Element_Offset
                     (Plain_Header'Length
                      + Encrypted_Body_And_Mac'Length
                      - CryptoLib.Ciphers.AES_GCM_Tag_Length));
         begin
            Status_Value :=
              CryptoLib.Ciphers.Encrypt_GCM_Length
                (AES_GCM_Name (Item.Inbound_AES_GCM),
                 Item.Inbound_AES_GCM_Key,
                 Item.Inbound_AES_GCM_IV,
                 Sequence_Value,
                 Plain_Header,
                 Encrypted_Header);
            if Status_Value /= Ok then
               Mark_Dirty (Item, Status_Value);
               return Status_Value;
            end if;
            Wire_Packet (1 .. 4) := Encrypted_Header;
            Wire_Packet (5 .. Wire_Packet'Last) := Encrypted_Body_And_Mac;
            Status_Value :=
              CryptoLib.Ciphers.Open_GCM
                (AES_GCM_Name (Item.Inbound_AES_GCM),
                 Item.Inbound_AES_GCM_Key,
                 Item.Inbound_AES_GCM_IV,
                 Sequence_Value,
                 Wire_Packet,
                 Plain_Packet);
            if Status_Value /= Ok then
               Mark_Dirty (Item, Failure_When_Malformed);
               return Failure_When_Malformed;
            end if;
            --  Packet authenticated: advance the inbound invocation counter in
            --  lockstep with the peer's outbound counter.
            Increment_AES_GCM_IV (Item.Inbound_AES_GCM_IV);
            declare
               Encoded_Payload : Packet_Buffer;
            begin
               Status_Value :=
                 SSH_Lib.Protocol.Packets.Decode_Cleartext_Packet
                   (Item.Packet_State,
                    Plain_Packet,
                    Encoded_Payload,
                    Inbound_Block_Size (Item),
                    Count_Length_Field => False);
               if Status_Value = Ok then
                  Status_Value :=
                    Decompress_Payload
                      (Item, To_Array (Encoded_Payload), Payload);
               end if;
            end;
         end;

         if Status_Value /= Ok then
            Mark_Dirty (Item, Failure_When_Malformed);
            Clear (Payload);
            return Failure_When_Malformed;
         end if;
         return Ok;
      end if;

      declare
         Encrypted_Body_Last : constant Stream_Element_Offset :=
           Encrypted_Body_And_Mac'Last
           - Stream_Element_Offset (Item.Inbound_Mac_Length);
         Encrypted_Body      : constant Stream_Element_Array :=
           Encrypted_Body_And_Mac
             (Encrypted_Body_And_Mac'First .. Encrypted_Body_Last);
         Actual_Mac          : constant Stream_Element_Array :=
           Encrypted_Body_And_Mac
             (Encrypted_Body_Last + 1 .. Encrypted_Body_And_Mac'Last);
         Plain_Body          : Stream_Element_Array (Encrypted_Body'Range);
      begin
         if Item.Cipher_Active and then Is_EtM (Item.Inbound_Mac_Kind) then
            declare
               Wire_Packet :
                 Stream_Element_Array
                   (1
                    ..
                      Stream_Element_Offset
                        (Plain_Header'Length + Encrypted_Body'Length));
            begin
               Wire_Packet
                 (1 .. Stream_Element_Offset (Plain_Header'Length)) :=
                 Plain_Header;
               Wire_Packet
                 (Stream_Element_Offset (Plain_Header'Length)
                  + 1
                  .. Wire_Packet'Last) :=
                 Encrypted_Body;

               declare
                  Wanted_Mac : constant Stream_Element_Array :=
                    Expected_Mac
                      (Item.Inbound_Mac_Kind,
                       Item.Inbound_Mac_Key_Data,
                       Sequence_Value,
                       Wire_Packet);
               begin
                  if not CryptoLib.Constant_Time.Equal
                           (Actual_Mac, Wanted_Mac)
                  then
                     Mark_Dirty (Item, Failure_When_Malformed);
                     return Failure_When_Malformed;
                  end if;
               end;
            end;

            Status_Value :=
              CryptoLib.Ciphers.Decrypt
                (Item.Inbound_Cipher, Encrypted_Body, Plain_Body);
            if Status_Value /= Ok then
               Mark_Dirty (Item, Status_Value);
               return Status_Value;
            end if;
         else
            if Item.Cipher_Active then
               Status_Value :=
                 CryptoLib.Ciphers.Decrypt
                   (Item.Inbound_Cipher, Encrypted_Body, Plain_Body);
               if Status_Value /= Ok then
                  Mark_Dirty (Item, Status_Value);
                  return Status_Value;
               end if;
            else
               Plain_Body := Encrypted_Body;
            end if;
         end if;

         declare
            Plain_Packet :
              Stream_Element_Array
                (1
                 ..
                   Stream_Element_Offset
                     (Plain_Header'Length + Plain_Body'Length));
         begin
            Plain_Packet (1 .. Stream_Element_Offset (Plain_Header'Length)) :=
              Plain_Header;
            Plain_Packet
              (Stream_Element_Offset (Plain_Header'Length)
               + 1
               .. Plain_Packet'Last) :=
              Plain_Body;

            if not (Item.Cipher_Active and then Is_EtM (Item.Inbound_Mac_Kind))
            then
               declare
                  Wanted_Mac : constant Stream_Element_Array :=
                    Expected_Mac
                      (Item.Inbound_Mac_Kind,
                       Item.Inbound_Mac_Key_Data,
                       Sequence_Value,
                       Plain_Packet);
               begin
                  if not CryptoLib.Constant_Time.Equal
                           (Actual_Mac, Wanted_Mac)
                  then
                     Mark_Dirty (Item, Failure_When_Malformed);
                     return Failure_When_Malformed;
                  end if;
               end;
            end if;

            declare
               Encoded_Payload : Packet_Buffer;
            begin
               Status_Value :=
                 SSH_Lib.Protocol.Packets.Decode_Cleartext_Packet
                   (Item.Packet_State,
                    Plain_Packet,
                    Encoded_Payload,
                    Inbound_Block_Size (Item),
                    --  Encrypt-then-MAC keeps the length cleartext and out of
                    --  the block-padding alignment; a plain block-cipher MAC
                    --  includes it.
                    Count_Length_Field => Inbound_Length_In_Alignment (Item));
               if Status_Value = Ok then
                  Status_Value :=
                    Decompress_Payload
                      (Item, To_Array (Encoded_Payload), Payload);
               end if;
            end;
         end;
      end;

      if Status_Value /= Ok then
         Mark_Dirty (Item, Failure_When_Malformed);
         Clear (Payload);
         return Failure_When_Malformed;
      end if;

      return Ok;
   exception
      when others =>
         Clear (Payload);
         Mark_Dirty (Item, Internal_Error);
         return Internal_Error;
   end Decode_Protected_Packet_After_Header;

   function Decode_Protected_Packet
     (Item                   : in out Protected_State;
      Packet                 : Stream_Element_Array;
      Payload                : out Packet_Buffer;
      Failure_When_Malformed : Status := Handshake_Failed) return Status
   is
      Header_In    : Stream_Element_Array (1 .. 4);
      Header_Out   : Stream_Element_Array (1 .. 4);
      Status_Value : Status;
   begin
      Clear (Payload);
      if Packet'Length <= 4 + Item.Inbound_Mac_Length then
         Mark_Dirty (Item, Failure_When_Malformed);
         return Failure_When_Malformed;
      end if;

      if Item.Cipher_Active
        and then Item.Inbound_CBC_Header_Encrypted
        and then not Is_EtM (Item.Inbound_Mac_Kind)
      then
         declare
            Encrypted_Last : constant Stream_Element_Offset :=
              Packet'Last - Stream_Element_Offset (Item.Inbound_Mac_Length);
            Encrypted_Packet : constant Stream_Element_Array :=
              Packet (Packet'First .. Encrypted_Last);
            Actual_Mac : constant Stream_Element_Array :=
              Packet (Encrypted_Last + 1 .. Packet'Last);
            Plain_Packet : Stream_Element_Array (Encrypted_Packet'Range);
            Encoded_Payload : Packet_Buffer;
         begin
            if Encrypted_Packet'Length = 0
              or else Encrypted_Packet'Length mod Inbound_Block_Size (Item) /= 0
            then
               Mark_Dirty (Item, Failure_When_Malformed);
               return Failure_When_Malformed;
            end if;

            Status_Value :=
              CryptoLib.Ciphers.Decrypt
                (Item.Inbound_Cipher, Encrypted_Packet, Plain_Packet);
            if Status_Value /= Ok then
               Mark_Dirty (Item, Status_Value);
               return Status_Value;
            end if;

            declare
               Wanted_Mac : constant Stream_Element_Array :=
                 Expected_Mac
                   (Item.Inbound_Mac_Kind,
                    Item.Inbound_Mac_Key_Data,
                    SSH_Lib.Protocol.Packets.Inbound_Sequence
                      (Item.Packet_State),
                    Plain_Packet);
            begin
               if not CryptoLib.Constant_Time.Equal (Actual_Mac, Wanted_Mac) then
                  Mark_Dirty (Item, Failure_When_Malformed);
                  return Failure_When_Malformed;
               end if;
            end;

            Status_Value :=
              SSH_Lib.Protocol.Packets.Decode_Cleartext_Packet
                (Item.Packet_State,
                 Plain_Packet,
                 Encoded_Payload,
                 Inbound_Block_Size (Item));
            if Status_Value = Ok then
               Status_Value :=
                 Decompress_Payload (Item, To_Array (Encoded_Payload), Payload);
            end if;

            if Status_Value /= Ok then
               Mark_Dirty (Item, Failure_When_Malformed);
               Clear (Payload);
               return Failure_When_Malformed;
            end if;
            return Ok;
         end;
      end if;

      Header_In := Packet (Packet'First .. Packet'First + 3);
      Status_Value := Decode_Protected_Header (Item, Header_In, Header_Out);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      return
        Decode_Protected_Packet_After_Header
          (Item,
           Header_Out,
           Packet (Packet'First + 4 .. Packet'Last),
           Payload,
           Failure_When_Malformed);
   exception
      when others =>
         Clear (Payload);
         Mark_Dirty (Item, Internal_Error);
         return Internal_Error;
   end Decode_Protected_Packet;
end SSH_Lib.Protocol.Protected_Packets;
