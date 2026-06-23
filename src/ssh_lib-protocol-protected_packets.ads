with Ada.Streams; use Ada.Streams;
with Interfaces;
with CryptoLib.Errors;
with CryptoLib.Ciphers;
with CryptoLib.ChaCha20_Poly1305;
with SSH_Lib.Protocol.Buffers;
with SSH_Lib.Protocol.Packets;
with Zlib;

package SSH_Lib.Protocol.Protected_Packets is
   SHA1_Mac_Length : constant Natural := 20;
   Mac_Length : constant Natural := 32;
   Maximum_Mac_Length : constant Natural := 64;
   UMAC_Key_Length : constant Natural := 16;

   type Protected_State is private;

   procedure Reset
     (Item    : out Protected_State;
      Mac_Key : Ada.Streams.Stream_Element_Array);

   procedure Reset_With_Ciphers
     (Item                  : out Protected_State;
      Algorithm_Name        : String;
      Outbound_Mac_Key      : Ada.Streams.Stream_Element_Array;
      Inbound_Mac_Key       : Ada.Streams.Stream_Element_Array;
      Outbound_Key_Data     : Ada.Streams.Stream_Element_Array;
      Outbound_IV_Data      : Ada.Streams.Stream_Element_Array;
      Inbound_Key_Data      : Ada.Streams.Stream_Element_Array;
      Inbound_IV_Data       : Ada.Streams.Stream_Element_Array);

   procedure Reset_With_Ciphers
     (Item                  : out Protected_State;
      Outbound_Cipher_Name  : String;
      Inbound_Cipher_Name   : String;
      Outbound_Mac_Name     : String;
      Inbound_Mac_Name      : String;
      Outbound_Mac_Key      : Ada.Streams.Stream_Element_Array;
      Inbound_Mac_Key       : Ada.Streams.Stream_Element_Array;
      Outbound_Key_Data     : Ada.Streams.Stream_Element_Array;
      Outbound_IV_Data      : Ada.Streams.Stream_Element_Array;
      Inbound_Key_Data      : Ada.Streams.Stream_Element_Array;
      Inbound_IV_Data       : Ada.Streams.Stream_Element_Array);

   procedure Reset_With_Ciphers
     (Item                  : out Protected_State;
      Outbound_Cipher_Name  : String;
      Inbound_Cipher_Name   : String;
      Outbound_Mac_Name     : String;
      Inbound_Mac_Name      : String;
      Outbound_Compression  : String;
      Inbound_Compression   : String;
      Outbound_Mac_Key      : Ada.Streams.Stream_Element_Array;
      Inbound_Mac_Key       : Ada.Streams.Stream_Element_Array;
      Outbound_Key_Data     : Ada.Streams.Stream_Element_Array;
      Outbound_IV_Data      : Ada.Streams.Stream_Element_Array;
      Inbound_Key_Data      : Ada.Streams.Stream_Element_Array;
      Inbound_IV_Data       : Ada.Streams.Stream_Element_Array);

   function Is_Dirty (Item : Protected_State) return Boolean;

   function Last_Failure
     (Item : Protected_State)
      return CryptoLib.Errors.Status;

   function Outbound_Block_Size (Item : Protected_State) return Natural;

   function Inbound_Block_Size (Item : Protected_State) return Natural;

   function Inbound_Mac_Size (Item : Protected_State) return Natural;

   function Outbound_Mac_Size (Item : Protected_State) return Natural;

   function Inbound_Header_Is_Clear (Item : Protected_State) return Boolean;

   function Outbound_Header_Is_Clear (Item : Protected_State) return Boolean;

   function Inbound_Sequence
     (Item : Protected_State)
      return Interfaces.Unsigned_32;

   function Outbound_Sequence
     (Item : Protected_State)
      return Interfaces.Unsigned_32;

   procedure Set_Sequences_For_Test
     (Item           : in out Protected_State;
      Inbound_Value  : Interfaces.Unsigned_32;
      Outbound_Value : Interfaces.Unsigned_32);

   function Encode_Protected_Packet
     (Item              : in out Protected_State;
      Payload           : Ada.Streams.Stream_Element_Array;
      Packet            : out SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Use_Test_Padding  : Boolean := False;
      Test_Padding_Byte : Ada.Streams.Stream_Element := 0)
      return CryptoLib.Errors.Status;

   function Decode_Protected_Packet
     (Item    : in out Protected_State;
      Packet  : Ada.Streams.Stream_Element_Array;
      Payload : out SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Failure_When_Malformed : CryptoLib.Errors.Status := CryptoLib.Errors.Handshake_Failed)
      return CryptoLib.Errors.Status;

   function Decode_Protected_Header
     (Item             : in out Protected_State;
      Encrypted_Header : Ada.Streams.Stream_Element_Array;
      Plain_Header     : out Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   function Decode_Protected_Packet_After_Header
     (Item                   : in out Protected_State;
      Plain_Header           : Ada.Streams.Stream_Element_Array;
      Encrypted_Body_And_Mac : Ada.Streams.Stream_Element_Array;
      Payload                : out SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Failure_When_Malformed : CryptoLib.Errors.Status := CryptoLib.Errors.Handshake_Failed)
      return CryptoLib.Errors.Status;

   procedure Mark_Dirty
     (Item   : in out Protected_State;
      Reason : CryptoLib.Errors.Status);

   function Activate_Delayed_Compression
     (Item : in out Protected_State)
      return CryptoLib.Errors.Status;

private
   type Mac_Algorithm is
     (HMAC_SHA1,
      HMAC_SHA1_ETM,
      HMAC_SHA1_96,
      HMAC_SHA1_96_ETM,
      HMAC_SHA2_256,
      HMAC_SHA2_512,
      HMAC_SHA2_256_ETM,
      HMAC_SHA2_512_ETM,
      UMAC_64,
      UMAC_64_ETM,
      UMAC_128,
      UMAC_128_ETM);
   subtype Mac_Key_Index is
     Ada.Streams.Stream_Element_Offset range 1 ..
       Ada.Streams.Stream_Element_Offset (Maximum_Mac_Length);
   subtype Mac_Key_Buffer is Ada.Streams.Stream_Element_Array (Mac_Key_Index);
   subtype ChaCha_Key_Index is
     Ada.Streams.Stream_Element_Offset range 1 ..
       Ada.Streams.Stream_Element_Offset
         (CryptoLib.ChaCha20_Poly1305.Key_Length);
   subtype ChaCha_Key_Buffer is Ada.Streams.Stream_Element_Array (ChaCha_Key_Index);
   subtype AES_GCM_Key_Index is Ada.Streams.Stream_Element_Offset range 1 .. 32;
   subtype AES_GCM_IV_Index is Ada.Streams.Stream_Element_Offset range 1 .. 12;
   subtype AES_GCM_Key_Buffer is Ada.Streams.Stream_Element_Array (AES_GCM_Key_Index);
   subtype AES_GCM_IV_Buffer is Ada.Streams.Stream_Element_Array (AES_GCM_IV_Index);
   type AES_GCM_Algorithm is (No_AES_GCM, AES128_GCM, AES256_GCM);

   type Deflate_Filter_Access is access Zlib.Compression_Filter_Type;
   type Inflate_Filter_Access is access Zlib.Filter_Type;

   type Protected_State is record
      Packet_State : SSH_Lib.Protocol.Packets.Protocol_State;
      Outbound_Mac_Key_Data : Mac_Key_Buffer := [others => 0];
      Inbound_Mac_Key_Data  : Mac_Key_Buffer := [others => 0];
      Outbound_Mac_Kind     : Mac_Algorithm := HMAC_SHA2_256;
      Inbound_Mac_Kind      : Mac_Algorithm := HMAC_SHA2_256;
      Outbound_Mac_Length   : Natural range 0 .. Maximum_Mac_Length := Mac_Length;
      Inbound_Mac_Length    : Natural range 0 .. Maximum_Mac_Length := Mac_Length;
      Outbound_Cipher       : CryptoLib.Ciphers.Cipher_State;
      Inbound_Cipher        : CryptoLib.Ciphers.Cipher_State;
      Cipher_Active         : Boolean := False;
      Outbound_Chacha20_Poly1305 : Boolean := False;
      Inbound_Chacha20_Poly1305  : Boolean := False;
      Outbound_Chacha_Key        : ChaCha_Key_Buffer := [others => 0];
      Inbound_Chacha_Key         : ChaCha_Key_Buffer := [others => 0];
      Outbound_AES_GCM           : AES_GCM_Algorithm := No_AES_GCM;
      Inbound_AES_GCM            : AES_GCM_Algorithm := No_AES_GCM;
      Outbound_AES_GCM_Key       : AES_GCM_Key_Buffer := [others => 0];
      Inbound_AES_GCM_Key        : AES_GCM_Key_Buffer := [others => 0];
      Outbound_AES_GCM_IV        : AES_GCM_IV_Buffer := [others => 0];
      Inbound_AES_GCM_IV         : AES_GCM_IV_Buffer := [others => 0];
      Outbound_Compression_Active  : Boolean := False;
      Inbound_Compression_Active   : Boolean := False;
      Outbound_Compression_Delayed : Boolean := False;
      Inbound_Compression_Delayed  : Boolean := False;
      Outbound_Compressor          : Deflate_Filter_Access := null;
      Inbound_Inflater             : Inflate_Filter_Access := null;
      Outbound_Block_Value  : Natural := SSH_Lib.Protocol.Packets.Cleartext_Block_Size;
      Inbound_Block_Value   : Natural := SSH_Lib.Protocol.Packets.Cleartext_Block_Size;
      Dirty_Value  : Boolean := False;
      Failure      : CryptoLib.Errors.Status := CryptoLib.Errors.Ok;
   end record;
end SSH_Lib.Protocol.Protected_Packets;
