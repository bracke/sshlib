with Ada.Streams;
with CryptoLib.Hashes;
with CryptoLib.Errors;
with SSH_Lib.Protocol.Buffers;

--  @summary Computes the SSH key-exchange exchange hash H for each KEX method.
--
--  The exchange hash H binds the whole key-exchange transcript -- the two
--  identification strings, both KEXINIT payloads, the server host key, the
--  ephemeral public values and the shared secret -- into a single digest that
--  is signed by the host key and seeds all session keys (RFC 4253 sec. 8 and
--  the per-method KEX RFCs).  Each function encodes that transcript in the
--  exact order and wire format its method requires and hashes it with the
--  method's hash algorithm.
package SSH_Lib.Protocol.Exchange_Hash is

   subtype Exchange_Digest is CryptoLib.Hashes.SHA256_Digest;

   subtype Exchange_SHA1_Digest is CryptoLib.Hashes.SHA1_Digest;

   subtype Exchange_SHA384_Digest is CryptoLib.Hashes.SHA384_Digest;

   subtype Exchange_SHA512_Digest is CryptoLib.Hashes.SHA512_Digest;

   --  Compute the exchange hash for curve25519-sha256 key exchange.
   --  @param Client_Identification the client's SSH version banner (V_C)
   --  @param Server_Identification the server's SSH version banner (V_S)
   --  @param Client_Kexinit the client's SSH_MSG_KEXINIT payload (I_C)
   --  @param Server_Kexinit the server's SSH_MSG_KEXINIT payload (I_S)
   --  @param Server_Host_Key the server's public host key blob (K_S)
   --  @param Client_Public_Key the client's ephemeral X25519 public key (Q_C)
   --  @param Server_Public_Key the server's ephemeral X25519 public key (Q_S)
   --  @param Shared_Secret the raw X25519 shared secret K
   --  @param Result_Digest the computed SHA-256 exchange hash H
   --  @return Ok on success, or an error status on encoding failure
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

   --  Compute the exchange hash for ecdh-sha2-nistp256 key exchange.
   --  @param Client_Identification the client's SSH version banner (V_C)
   --  @param Server_Identification the server's SSH version banner (V_S)
   --  @param Client_Kexinit the client's SSH_MSG_KEXINIT payload (I_C)
   --  @param Server_Kexinit the server's SSH_MSG_KEXINIT payload (I_S)
   --  @param Server_Host_Key the server's public host key blob (K_S)
   --  @param Client_Public_Key the client's ephemeral P-256 public point (Q_C)
   --  @param Server_Public_Key the server's ephemeral P-256 public point (Q_S)
   --  @param Shared_Secret the ECDH shared secret K
   --  @param Result_Digest the computed SHA-256 exchange hash H
   --  @return Ok on success, or an error status on encoding failure
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

   --  Compute the exchange hash for ecdh-sha2-nistp384 key exchange.
   --  @param Client_Identification the client's SSH version banner (V_C)
   --  @param Server_Identification the server's SSH version banner (V_S)
   --  @param Client_Kexinit the client's SSH_MSG_KEXINIT payload (I_C)
   --  @param Server_Kexinit the server's SSH_MSG_KEXINIT payload (I_S)
   --  @param Server_Host_Key the server's public host key blob (K_S)
   --  @param Client_Public_Key the client's ephemeral P-384 public point (Q_C)
   --  @param Server_Public_Key the server's ephemeral P-384 public point (Q_S)
   --  @param Shared_Secret the ECDH shared secret K
   --  @param Result_Digest the computed SHA-384 exchange hash H
   --  @return Ok on success, or an error status on encoding failure
   function Compute_ECDH_Nistp384_SHA384
     (Client_Identification : String;
      Server_Identification : String;
      Client_Kexinit        : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Server_Kexinit        : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Server_Host_Key       : Ada.Streams.Stream_Element_Array;
      Client_Public_Key     : Ada.Streams.Stream_Element_Array;
      Server_Public_Key     : Ada.Streams.Stream_Element_Array;
      Shared_Secret         : Ada.Streams.Stream_Element_Array;
      Result_Digest         : out Exchange_SHA384_Digest)
      return CryptoLib.Errors.Status;

   --  Compute the exchange hash for ecdh-sha2-nistp521 key exchange.
   --  @param Client_Identification the client's SSH version banner (V_C)
   --  @param Server_Identification the server's SSH version banner (V_S)
   --  @param Client_Kexinit the client's SSH_MSG_KEXINIT payload (I_C)
   --  @param Server_Kexinit the server's SSH_MSG_KEXINIT payload (I_S)
   --  @param Server_Host_Key the server's public host key blob (K_S)
   --  @param Client_Public_Key the client's ephemeral P-521 public point (Q_C)
   --  @param Server_Public_Key the server's ephemeral P-521 public point (Q_S)
   --  @param Shared_Secret the ECDH shared secret K
   --  @param Result_Digest the computed SHA-512 exchange hash H
   --  @return Ok on success, or an error status on encoding failure
   function Compute_ECDH_Nistp521_SHA512
     (Client_Identification : String;
      Server_Identification : String;
      Client_Kexinit        : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Server_Kexinit        : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Server_Host_Key       : Ada.Streams.Stream_Element_Array;
      Client_Public_Key     : Ada.Streams.Stream_Element_Array;
      Server_Public_Key     : Ada.Streams.Stream_Element_Array;
      Shared_Secret         : Ada.Streams.Stream_Element_Array;
      Result_Digest         : out Exchange_SHA512_Digest)
      return CryptoLib.Errors.Status;

   --  Compute the exchange hash for a SHA-256 post-quantum hybrid KEX (e.g.
   --  sntrup761x25519-sha256), hashing the client init and server reply blobs.
   --  @param Client_Identification the client's SSH version banner (V_C)
   --  @param Server_Identification the server's SSH version banner (V_S)
   --  @param Client_Kexinit the client's SSH_MSG_KEXINIT payload (I_C)
   --  @param Server_Kexinit the server's SSH_MSG_KEXINIT payload (I_S)
   --  @param Server_Host_Key the server's public host key blob (K_S)
   --  @param Client_Init the client's hybrid KEX init blob (C_INIT)
   --  @param Server_Reply the server's hybrid KEX reply blob (S_REPLY)
   --  @param Shared_Secret the combined hybrid shared secret K
   --  @param Result_Digest the computed SHA-256 exchange hash H
   --  @return Ok on success, or an error status on encoding failure
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

   --  Compute the exchange hash for a SHA-512 post-quantum hybrid KEX (e.g.
   --  mlkem768x25519-sha512), hashing the client init and server reply blobs.
   --  @param Client_Identification the client's SSH version banner (V_C)
   --  @param Server_Identification the server's SSH version banner (V_S)
   --  @param Client_Kexinit the client's SSH_MSG_KEXINIT payload (I_C)
   --  @param Server_Kexinit the server's SSH_MSG_KEXINIT payload (I_S)
   --  @param Server_Host_Key the server's public host key blob (K_S)
   --  @param Client_Init the client's hybrid KEX init blob (C_INIT)
   --  @param Server_Reply the server's hybrid KEX reply blob (S_REPLY)
   --  @param Shared_Secret the combined hybrid shared secret K
   --  @param Result_Digest the computed SHA-512 exchange hash H
   --  @return Ok on success, or an error status on encoding failure
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

   --  Compute the exchange hash for diffie-hellman-group14-sha1 key exchange.
   --  @param Client_Identification the client's SSH version banner (V_C)
   --  @param Server_Identification the server's SSH version banner (V_S)
   --  @param Client_Kexinit the client's SSH_MSG_KEXINIT payload (I_C)
   --  @param Server_Kexinit the server's SSH_MSG_KEXINIT payload (I_S)
   --  @param Server_Host_Key the server's public host key blob (K_S)
   --  @param Client_Public_Value the client's DH public value e
   --  @param Server_Public_Value the server's DH public value f
   --  @param Shared_Secret the DH shared secret K
   --  @param Result_Digest the computed SHA-1 exchange hash H
   --  @return Ok on success, or an error status on encoding failure
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

   --  Compute the exchange hash for diffie-hellman-group-exchange-sha1, which
   --  also hashes the negotiated group bounds and the server-chosen group.
   --  @param Client_Identification the client's SSH version banner (V_C)
   --  @param Server_Identification the server's SSH version banner (V_S)
   --  @param Client_Kexinit the client's SSH_MSG_KEXINIT payload (I_C)
   --  @param Server_Kexinit the server's SSH_MSG_KEXINIT payload (I_S)
   --  @param Server_Host_Key the server's public host key blob (K_S)
   --  @param Minimum_Bits the minimum acceptable group size the client requested
   --  @param Preferred_Bits the preferred group size the client requested
   --  @param Maximum_Bits the maximum acceptable group size the client requested
   --  @param Prime_Value the server-supplied DH group prime p
   --  @param Generator_Value the server-supplied DH group generator g
   --  @param Client_Public_Value the client's DH public value e
   --  @param Server_Public_Value the server's DH public value f
   --  @param Shared_Secret the DH shared secret K
   --  @param Result_Digest the computed SHA-1 exchange hash H
   --  @return Ok on success, or an error status on encoding failure
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

   --  Compute the exchange hash for diffie-hellman-group-exchange-sha256, which
   --  also hashes the negotiated group bounds and the server-chosen group.
   --  @param Client_Identification the client's SSH version banner (V_C)
   --  @param Server_Identification the server's SSH version banner (V_S)
   --  @param Client_Kexinit the client's SSH_MSG_KEXINIT payload (I_C)
   --  @param Server_Kexinit the server's SSH_MSG_KEXINIT payload (I_S)
   --  @param Server_Host_Key the server's public host key blob (K_S)
   --  @param Minimum_Bits the minimum acceptable group size the client requested
   --  @param Preferred_Bits the preferred group size the client requested
   --  @param Maximum_Bits the maximum acceptable group size the client requested
   --  @param Prime_Value the server-supplied DH group prime p
   --  @param Generator_Value the server-supplied DH group generator g
   --  @param Client_Public_Value the client's DH public value e
   --  @param Server_Public_Value the server's DH public value f
   --  @param Shared_Secret the DH shared secret K
   --  @param Result_Digest the computed SHA-256 exchange hash H
   --  @return Ok on success, or an error status on encoding failure
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

   --  Compute the exchange hash for diffie-hellman-group14-sha256 key exchange.
   --  @param Client_Identification the client's SSH version banner (V_C)
   --  @param Server_Identification the server's SSH version banner (V_S)
   --  @param Client_Kexinit the client's SSH_MSG_KEXINIT payload (I_C)
   --  @param Server_Kexinit the server's SSH_MSG_KEXINIT payload (I_S)
   --  @param Server_Host_Key the server's public host key blob (K_S)
   --  @param Client_Public_Value the client's DH public value e
   --  @param Server_Public_Value the server's DH public value f
   --  @param Shared_Secret the DH shared secret K
   --  @param Result_Digest the computed SHA-256 exchange hash H
   --  @return Ok on success, or an error status on encoding failure
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

   --  Compute the exchange hash for diffie-hellman-group16-sha512 key exchange.
   --  @param Client_Identification the client's SSH version banner (V_C)
   --  @param Server_Identification the server's SSH version banner (V_S)
   --  @param Client_Kexinit the client's SSH_MSG_KEXINIT payload (I_C)
   --  @param Server_Kexinit the server's SSH_MSG_KEXINIT payload (I_S)
   --  @param Server_Host_Key the server's public host key blob (K_S)
   --  @param Client_Public_Value the client's DH public value e
   --  @param Server_Public_Value the server's DH public value f
   --  @param Shared_Secret the DH shared secret K
   --  @param Result_Digest the computed SHA-512 exchange hash H
   --  @return Ok on success, or an error status on encoding failure
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

   --  Compute the exchange hash for diffie-hellman-group18-sha512 key exchange.
   --  @param Client_Identification the client's SSH version banner (V_C)
   --  @param Server_Identification the server's SSH version banner (V_S)
   --  @param Client_Kexinit the client's SSH_MSG_KEXINIT payload (I_C)
   --  @param Server_Kexinit the server's SSH_MSG_KEXINIT payload (I_S)
   --  @param Server_Host_Key the server's public host key blob (K_S)
   --  @param Client_Public_Value the client's DH public value e
   --  @param Server_Public_Value the server's DH public value f
   --  @param Shared_Secret the DH shared secret K
   --  @param Result_Digest the computed SHA-512 exchange hash H
   --  @return Ok on success, or an error status on encoding failure
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
