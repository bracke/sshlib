with Ada.Streams; use Ada.Streams;
with Interfaces;
with CryptoLib.Errors;
with CryptoLib.Ciphers;
with CryptoLib.ChaCha20_Poly1305;
with SSH_Lib.Protocol.Buffers;
with SSH_Lib.Protocol.Packets;
with Zlib;

--  @summary Seal and open post-NEWKEYS encrypted SSH binary packets.
--
--  Holds the negotiated inbound/outbound cipher, MAC, and compression state and
--  encodes/decodes the SSH Binary Packet Protocol after key exchange: block
--  ciphers with encrypt-and-MAC or encrypt-then-MAC, and AEAD ciphers
--  (chacha20-poly1305, AES-GCM).  Supports one-shot and incremental (header,
--  first-block, body) decode paths and per-direction sequence numbers.
package SSH_Lib.Protocol.Protected_Packets is
   SHA1_Mac_Length : constant Natural := 20;
   Mac_Length : constant Natural := 32;
   Maximum_Mac_Length : constant Natural := 64;
   UMAC_Key_Length : constant Natural := 16;

   type Protected_State is private;

   --  Reset the state to a MAC-only configuration (no cipher) with one shared
   --  MAC key for both directions; used for handshake-era protected framing.
   --  @param Item    the state to initialize
   --  @param Mac_Key the MAC key applied to both directions
   procedure Reset
     (Item    : out Protected_State;
      Mac_Key : Ada.Streams.Stream_Element_Array);

   --  Reset the state with a single cipher algorithm for both directions,
   --  installing per-direction MAC and cipher key/IV material.
   --  @param Item              the state to initialize
   --  @param Algorithm_Name    the cipher algorithm name for both directions
   --  @param Outbound_Mac_Key  the outbound MAC key
   --  @param Inbound_Mac_Key   the inbound MAC key
   --  @param Outbound_Key_Data the outbound cipher key
   --  @param Outbound_IV_Data  the outbound cipher IV
   --  @param Inbound_Key_Data  the inbound cipher key
   --  @param Inbound_IV_Data   the inbound cipher IV
   procedure Reset_With_Ciphers
     (Item                  : out Protected_State;
      Algorithm_Name        : String;
      Outbound_Mac_Key      : Ada.Streams.Stream_Element_Array;
      Inbound_Mac_Key       : Ada.Streams.Stream_Element_Array;
      Outbound_Key_Data     : Ada.Streams.Stream_Element_Array;
      Outbound_IV_Data      : Ada.Streams.Stream_Element_Array;
      Inbound_Key_Data      : Ada.Streams.Stream_Element_Array;
      Inbound_IV_Data       : Ada.Streams.Stream_Element_Array);

   --  Reset the state with independent inbound/outbound cipher and MAC
   --  algorithms and their key/IV material.
   --  @param Item                 the state to initialize
   --  @param Outbound_Cipher_Name the outbound cipher algorithm name
   --  @param Inbound_Cipher_Name  the inbound cipher algorithm name
   --  @param Outbound_Mac_Name    the outbound MAC algorithm name
   --  @param Inbound_Mac_Name     the inbound MAC algorithm name
   --  @param Outbound_Mac_Key     the outbound MAC key
   --  @param Inbound_Mac_Key      the inbound MAC key
   --  @param Outbound_Key_Data    the outbound cipher key
   --  @param Outbound_IV_Data     the outbound cipher IV
   --  @param Inbound_Key_Data     the inbound cipher key
   --  @param Inbound_IV_Data      the inbound cipher IV
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

   --  Reset the state with independent inbound/outbound ciphers, MACs, and
   --  compression algorithms plus their key/IV material.
   --  @param Item                 the state to initialize
   --  @param Outbound_Cipher_Name the outbound cipher algorithm name
   --  @param Inbound_Cipher_Name  the inbound cipher algorithm name
   --  @param Outbound_Mac_Name    the outbound MAC algorithm name
   --  @param Inbound_Mac_Name     the inbound MAC algorithm name
   --  @param Outbound_Compression the outbound compression algorithm name
   --  @param Inbound_Compression  the inbound compression algorithm name
   --  @param Outbound_Mac_Key     the outbound MAC key
   --  @param Inbound_Mac_Key      the inbound MAC key
   --  @param Outbound_Key_Data    the outbound cipher key
   --  @param Outbound_IV_Data     the outbound cipher IV
   --  @param Inbound_Key_Data     the inbound cipher key
   --  @param Inbound_IV_Data      the inbound cipher IV
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

   --  Whether the state has failed and can no longer process packets.
   --  @param Item the state to query
   --  @return True if the state is dirty (a prior operation failed)
   function Is_Dirty (Item : Protected_State) return Boolean;

   --  The Status recorded by the operation that marked the state dirty.
   --  @param Item the state to query
   --  @return the last failure Status (Ok if never failed)
   function Last_Failure
     (Item : Protected_State)
      return CryptoLib.Errors.Status;

   --  The outbound cipher block size used for padding alignment, in bytes.
   --  @param Item the state to query
   --  @return the outbound block size in bytes
   function Outbound_Block_Size (Item : Protected_State) return Natural;

   --  The inbound cipher block size used for padding alignment, in bytes.
   --  @param Item the state to query
   --  @return the inbound block size in bytes
   function Inbound_Block_Size (Item : Protected_State) return Natural;

   --  Whether the inbound 4-byte length field participates in block alignment.
   --  @param Item the state to query
   --  @return True when the length field is included in the block-size alignment
   function Inbound_Length_In_Alignment (Item : Protected_State) return Boolean;
   --  True when the 4-byte packet-length field is included in the block-size
   --  padding alignment (block ciphers). False for AEAD ciphers
   --  (chacha20-poly1305, AES-GCM), where the length is authenticated
   --  separately and excluded from the alignment.

   --  The inbound MAC length in bytes (0 for AEAD ciphers).
   --  @param Item the state to query
   --  @return the inbound MAC size in bytes
   function Inbound_Mac_Size (Item : Protected_State) return Natural;

   --  The outbound MAC length in bytes (0 for AEAD ciphers).
   --  @param Item the state to query
   --  @return the outbound MAC size in bytes
   function Outbound_Mac_Size (Item : Protected_State) return Natural;

   --  Whether the inbound 4-byte length field is transmitted in cleartext.
   --  @param Item the state to query
   --  @return True if the inbound length header is not encrypted (AEAD/EtM)
   function Inbound_Header_Is_Clear (Item : Protected_State) return Boolean;

   --  Whether the outbound 4-byte length field is transmitted in cleartext.
   --  @param Item the state to query
   --  @return True if the outbound length header is not encrypted (AEAD/EtM)
   function Outbound_Header_Is_Clear (Item : Protected_State) return Boolean;

   --  The current inbound packet sequence number.
   --  @param Item the state to query
   --  @return the inbound sequence number
   function Inbound_Sequence
     (Item : Protected_State)
      return Interfaces.Unsigned_32;

   --  The current outbound packet sequence number.
   --  @param Item the state to query
   --  @return the outbound sequence number
   function Outbound_Sequence
     (Item : Protected_State)
      return Interfaces.Unsigned_32;

   --  Force the inbound and outbound sequence numbers (test/strict-kex use).
   --  @param Item           the state to modify
   --  @param Inbound_Value  the new inbound sequence number
   --  @param Outbound_Value the new outbound sequence number
   procedure Set_Sequences_For_Test
     (Item           : in out Protected_State;
      Inbound_Value  : Interfaces.Unsigned_32;
      Outbound_Value : Interfaces.Unsigned_32);

   --  Seal one outbound SSH packet: compress, pad, encrypt, and MAC the payload,
   --  advancing the outbound sequence number.
   --  @param Item              the outbound state (mutated: sequence advances)
   --  @param Payload           the cleartext payload to send
   --  @param Packet            the resulting wire packet
   --  @param Use_Test_Padding  when True, use a deterministic padding byte
   --  @param Test_Padding_Byte the fixed padding byte when Use_Test_Padding is set
   --  @return Ok on success, or an error Status on failure
   function Encode_Protected_Packet
     (Item              : in out Protected_State;
      Payload           : Ada.Streams.Stream_Element_Array;
      Packet            : out SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Use_Test_Padding  : Boolean := False;
      Test_Padding_Byte : Ada.Streams.Stream_Element := 0)
      return CryptoLib.Errors.Status;

   --  Open one complete inbound wire packet: verify the MAC, decrypt, strip
   --  padding, and decompress, advancing the inbound sequence number.
   --  @param Item                   the inbound state (mutated: sequence advances)
   --  @param Packet                 the complete wire packet (ciphertext plus MAC)
   --  @param Payload                the recovered cleartext payload
   --  @param Failure_When_Malformed the Status to return on a malformed packet
   --  @return Ok on success, or an error Status on MAC/decrypt/format failure
   function Decode_Protected_Packet
     (Item    : in out Protected_State;
      Packet  : Ada.Streams.Stream_Element_Array;
      Payload : out SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Failure_When_Malformed : CryptoLib.Errors.Status := CryptoLib.Errors.Handshake_Failed)
      return CryptoLib.Errors.Status;

   --  Decode just the inbound 4-byte length header to learn the packet size,
   --  without advancing the sequence number (incremental read path).
   --  @param Item             the inbound state
   --  @param Encrypted_Header the 4 bytes as received on the wire
   --  @param Plain_Header     the 4-byte decoded length header
   --  @return Ok on success, or an error Status on failure
   function Decode_Protected_Header
     (Item             : in out Protected_State;
      Encrypted_Header : Ada.Streams.Stream_Element_Array;
      Plain_Header     : out Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Whether the inbound length can only be read by decrypting a full first
   --  block (CBC-style ciphers without encrypt-then-MAC).
   --  @param Item the state to query
   --  @return True if a full first block must be decrypted to read the length
   function Inbound_Header_Requires_Block
     (Item : Protected_State)
      return Boolean;

   --  Decrypt the inbound first cipher block to expose the length header when
   --  Inbound_Header_Requires_Block is True (does not advance the sequence).
   --  @param Item                  the inbound state
   --  @param Encrypted_First_Block the first cipher block as received
   --  @param Plain_First_Block     the decrypted first block (holds the length)
   --  @return Ok on success, or an error Status on failure
   function Decode_Protected_First_Block_Header
     (Item                  : in out Protected_State;
      Encrypted_First_Block : Ada.Streams.Stream_Element_Array;
      Plain_First_Block     : out Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Complete an inbound packet given the already-decrypted first block and the
   --  remaining ciphertext plus MAC, advancing the inbound sequence number.
   --  @param Item                   the inbound state (mutated: sequence advances)
   --  @param Plain_First_Block      the decrypted first block from the header step
   --  @param Encrypted_Rest_And_Mac the remaining ciphertext followed by the MAC
   --  @param Payload                the recovered cleartext payload
   --  @param Failure_When_Malformed the Status to return on a malformed packet
   --  @return Ok on success, or an error Status on MAC/decrypt/format failure
   function Decode_Protected_Packet_After_First_Block
     (Item                   : in out Protected_State;
      Plain_First_Block      : Ada.Streams.Stream_Element_Array;
      Encrypted_Rest_And_Mac : Ada.Streams.Stream_Element_Array;
      Payload                : out SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Failure_When_Malformed : CryptoLib.Errors.Status := CryptoLib.Errors.Handshake_Failed)
      return CryptoLib.Errors.Status;

   --  Complete an inbound packet given the already-decoded length header and the
   --  encrypted body plus MAC, advancing the inbound sequence number.
   --  @param Item                   the inbound state (mutated: sequence advances)
   --  @param Plain_Header           the decoded 4-byte length header
   --  @param Encrypted_Body_And_Mac the encrypted body followed by the MAC
   --  @param Payload                the recovered cleartext payload
   --  @param Failure_When_Malformed the Status to return on a malformed packet
   --  @return Ok on success, or an error Status on MAC/decrypt/format failure
   function Decode_Protected_Packet_After_Header
     (Item                   : in out Protected_State;
      Plain_Header           : Ada.Streams.Stream_Element_Array;
      Encrypted_Body_And_Mac : Ada.Streams.Stream_Element_Array;
      Payload                : out SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Failure_When_Malformed : CryptoLib.Errors.Status := CryptoLib.Errors.Handshake_Failed)
      return CryptoLib.Errors.Status;

   --  Mark the state dirty with a failure reason so no further packets are
   --  processed until it is reset.
   --  @param Item   the state to mark
   --  @param Reason the failure Status to record
   procedure Mark_Dirty
     (Item   : in out Protected_State;
      Reason : CryptoLib.Errors.Status);

   --  Activate zlib@openssh.com delayed compression on both directions after a
   --  successful authentication.
   --  @param Item the state to modify
   --  @return Ok on success, or an error Status on failure
   function Activate_Delayed_Compression
     (Item : in out Protected_State)
      return CryptoLib.Errors.Status;

private
   type Mac_Algorithm is
     (HMAC_SHA1,
      HMAC_SHA1_ETM,
      HMAC_SHA1_96,
      HMAC_SHA1_96_ETM,
      HMAC_MD5,
      HMAC_MD5_ETM,
      HMAC_MD5_96,
      HMAC_MD5_96_ETM,
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
      Outbound_CBC_Header_Encrypted : Boolean := False;
      Inbound_CBC_Header_Encrypted  : Boolean := False;
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
