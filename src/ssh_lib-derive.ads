with Ada.Streams;
with CryptoLib.Hashes;
with CryptoLib.Buffers;

package SSH_Lib.Derive is

   function Derive_SHA1
     (Shared_Secret      : Ada.Streams.Stream_Element_Array;
      Exchange_Hash      : CryptoLib.Hashes.SHA1_Digest;
      Session_Identifier : Ada.Streams.Stream_Element_Array;
      Label_Value        : Character;
      Requested_Length   : Natural)
      return CryptoLib.Buffers.Packet_Buffer;

   function Derive_SHA256
     (Shared_Secret      : Ada.Streams.Stream_Element_Array;
      Exchange_Hash      : CryptoLib.Hashes.SHA256_Digest;
      Session_Identifier : CryptoLib.Hashes.SHA256_Digest;
      Label_Value        : Character;
      Requested_Length   : Natural)
      return CryptoLib.Buffers.Packet_Buffer;

   function Derive_SHA512
     (Shared_Secret      : Ada.Streams.Stream_Element_Array;
      Exchange_Hash      : CryptoLib.Hashes.SHA512_Digest;
      Session_Identifier : CryptoLib.Hashes.SHA512_Digest;
      Label_Value        : Character;
      Requested_Length   : Natural)
      return CryptoLib.Buffers.Packet_Buffer;
end SSH_Lib.Derive;
