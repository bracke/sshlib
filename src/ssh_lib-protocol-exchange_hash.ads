with Ada.Streams;
with CryptoLib.Hashes;
with CryptoLib.Errors;
with SSH_Lib.Protocol.Buffers;

package SSH_Lib.Protocol.Exchange_Hash is

   subtype Exchange_Digest is CryptoLib.Hashes.SHA256_Digest;

   subtype Exchange_SHA1_Digest is CryptoLib.Hashes.SHA1_Digest;

   subtype Exchange_SHA512_Digest is CryptoLib.Hashes.SHA512_Digest;

   function Compute_Curve25519_SHA256
     (Client_Identification : String;
      Server_Identification : String;
      Client_Kexinit        : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Server_Kexinit        : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Server_Host_Key       : Ada.Streams.Stream_Element_Array;
      Client_Public_Key     : Ada.Streams.Stream_Element_Array;
      Server_Public_Key     : Ada.Streams.Stream_Element_Array;
      Shared_Secret         : Ada.Streams.Stream_Element_Array;
      Result_Digest         : out Exchange_Digest)
      return CryptoLib.Errors.Status;

   function Compute_ECDH_SHA256
     (Client_Identification : String;
      Server_Identification : String;
      Client_Kexinit        : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Server_Kexinit        : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Server_Host_Key       : Ada.Streams.Stream_Element_Array;
      Client_Public_Key     : Ada.Streams.Stream_Element_Array;
      Server_Public_Key     : Ada.Streams.Stream_Element_Array;
      Shared_Secret         : Ada.Streams.Stream_Element_Array;
      Result_Digest         : out Exchange_Digest)
      return CryptoLib.Errors.Status;

   function Compute_Hybrid_PQ_SHA256
     (Client_Identification : String;
      Server_Identification : String;
      Client_Kexinit        : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Server_Kexinit        : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Server_Host_Key       : Ada.Streams.Stream_Element_Array;
      Client_Init           : Ada.Streams.Stream_Element_Array;
      Server_Reply          : Ada.Streams.Stream_Element_Array;
      Shared_Secret         : Ada.Streams.Stream_Element_Array;
      Result_Digest         : out Exchange_Digest)
      return CryptoLib.Errors.Status;

   function Compute_Hybrid_PQ_SHA512
     (Client_Identification : String;
      Server_Identification : String;
      Client_Kexinit        : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Server_Kexinit        : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Server_Host_Key       : Ada.Streams.Stream_Element_Array;
      Client_Init           : Ada.Streams.Stream_Element_Array;
      Server_Reply          : Ada.Streams.Stream_Element_Array;
      Shared_Secret         : Ada.Streams.Stream_Element_Array;
      Result_Digest         : out Exchange_SHA512_Digest)
      return CryptoLib.Errors.Status;

   function Compute_Group14_SHA1
     (Client_Identification : String;
      Server_Identification : String;
      Client_Kexinit        : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Server_Kexinit        : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Server_Host_Key       : Ada.Streams.Stream_Element_Array;
      Client_Public_Value   : Ada.Streams.Stream_Element_Array;
      Server_Public_Value   : Ada.Streams.Stream_Element_Array;
      Shared_Secret         : Ada.Streams.Stream_Element_Array;
      Result_Digest         : out Exchange_SHA1_Digest)
      return CryptoLib.Errors.Status;

   function Compute_Group_Exchange_SHA1
     (Client_Identification : String;
      Server_Identification : String;
      Client_Kexinit        : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Server_Kexinit        : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Server_Host_Key       : Ada.Streams.Stream_Element_Array;
      Minimum_Bits          : Natural;
      Preferred_Bits        : Natural;
      Maximum_Bits          : Natural;
      Prime_Value           : Ada.Streams.Stream_Element_Array;
      Generator_Value       : Ada.Streams.Stream_Element_Array;
      Client_Public_Value   : Ada.Streams.Stream_Element_Array;
      Server_Public_Value   : Ada.Streams.Stream_Element_Array;
      Shared_Secret         : Ada.Streams.Stream_Element_Array;
      Result_Digest         : out Exchange_SHA1_Digest)
      return CryptoLib.Errors.Status;

   function Compute_Group_Exchange_SHA256
     (Client_Identification : String;
      Server_Identification : String;
      Client_Kexinit        : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Server_Kexinit        : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Server_Host_Key       : Ada.Streams.Stream_Element_Array;
      Minimum_Bits          : Natural;
      Preferred_Bits        : Natural;
      Maximum_Bits          : Natural;
      Prime_Value           : Ada.Streams.Stream_Element_Array;
      Generator_Value       : Ada.Streams.Stream_Element_Array;
      Client_Public_Value   : Ada.Streams.Stream_Element_Array;
      Server_Public_Value   : Ada.Streams.Stream_Element_Array;
      Shared_Secret         : Ada.Streams.Stream_Element_Array;
      Result_Digest         : out Exchange_Digest)
      return CryptoLib.Errors.Status;

   function Compute_Group14_SHA256
     (Client_Identification : String;
      Server_Identification : String;
      Client_Kexinit        : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Server_Kexinit        : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Server_Host_Key       : Ada.Streams.Stream_Element_Array;
      Client_Public_Value   : Ada.Streams.Stream_Element_Array;
      Server_Public_Value   : Ada.Streams.Stream_Element_Array;
      Shared_Secret         : Ada.Streams.Stream_Element_Array;
      Result_Digest         : out Exchange_Digest)
      return CryptoLib.Errors.Status;

   function Compute_Group16_SHA512
     (Client_Identification : String;
      Server_Identification : String;
      Client_Kexinit        : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Server_Kexinit        : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Server_Host_Key       : Ada.Streams.Stream_Element_Array;
      Client_Public_Value   : Ada.Streams.Stream_Element_Array;
      Server_Public_Value   : Ada.Streams.Stream_Element_Array;
      Shared_Secret         : Ada.Streams.Stream_Element_Array;
      Result_Digest         : out Exchange_SHA512_Digest)
      return CryptoLib.Errors.Status;

   function Compute_Group18_SHA512
     (Client_Identification : String;
      Server_Identification : String;
      Client_Kexinit        : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Server_Kexinit        : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Server_Host_Key       : Ada.Streams.Stream_Element_Array;
      Client_Public_Value   : Ada.Streams.Stream_Element_Array;
      Server_Public_Value   : Ada.Streams.Stream_Element_Array;
      Shared_Secret         : Ada.Streams.Stream_Element_Array;
      Result_Digest         : out Exchange_SHA512_Digest)
      return CryptoLib.Errors.Status;
end SSH_Lib.Protocol.Exchange_Hash;
