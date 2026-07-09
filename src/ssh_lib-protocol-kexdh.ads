with Ada.Streams;
with CryptoLib.Errors;
with SSH_Lib.Protocol.Buffers;

--  @summary Encode and parse the KEXDH/ECDH key-exchange packets.
--
--  Builds the client INIT messages and parses the server GROUP/REPLY messages
--  for every supported key-exchange family: RFC 4419 group exchange, the fixed
--  group14 finite-field DH, Curve25519 and the NIST P-256/P-384/P-521 ECDH
--  curves, and the hybrid post-quantum method.  A parsed Reply carries the raw
--  host-key blob, the server public value Q_S, and the signature blob.
package SSH_Lib.Protocol.Kexdh is
   SSH_MSG_KEXDH_INIT  : constant Ada.Streams.Stream_Element := 30;
   SSH_MSG_KEXDH_REPLY : constant Ada.Streams.Stream_Element := 31;

   --  RFC 5656 ECDH uses the same message numbers as classic KEXDH, but
   --  the public values Q_C/Q_S are SSH strings containing SEC1 encoded
   --  elliptic-curve points rather than mpints.  Keep explicit aliases so
   --  packet code does not accidentally depend on the finite-field helper
   --  semantics.
   SSH_MSG_KEX_ECDH_INIT  : constant Ada.Streams.Stream_Element := 30;
   SSH_MSG_KEX_ECDH_REPLY : constant Ada.Streams.Stream_Element := 31;

   SSH_MSG_KEX_DH_GEX_GROUP   : constant Ada.Streams.Stream_Element := 31;
   SSH_MSG_KEX_DH_GEX_INIT    : constant Ada.Streams.Stream_Element := 32;
   SSH_MSG_KEX_DH_GEX_REPLY   : constant Ada.Streams.Stream_Element := 33;
   SSH_MSG_KEX_DH_GEX_REQUEST : constant Ada.Streams.Stream_Element := 34;

   type Group_Exchange_Group is record
      Prime_Value     : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Generator_Value : SSH_Lib.Protocol.Buffers.Packet_Buffer;
   end record;

   type Reply is record
      Host_Key_Blob       : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Server_Public_Value : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Signature_Blob      : SSH_Lib.Protocol.Buffers.Packet_Buffer;
   end record;

   --  Release any storage held by a group-exchange group record.
   --  @param Item the group record to clear
   procedure Clear (Item : out Group_Exchange_Group);

   --  Release any storage held by a parsed reply record.
   --  @param Item the reply record to clear
   procedure Clear (Item : out Reply);

   --  Encode an SSH_MSG_KEX_DH_GEX_REQUEST asking for a group in a size range.
   --  @param Minimum_Bits   the smallest acceptable prime modulus size in bits
   --  @param Preferred_Bits the preferred prime modulus size in bits
   --  @param Maximum_Bits   the largest acceptable prime modulus size in bits
   --  @param Payload        the encoded request message
   --  @return Ok on success or an encoding failure status
   function Encode_Group_Exchange_Request
     (Minimum_Bits   : Natural;
      Preferred_Bits : Natural;
      Maximum_Bits   : Natural;
      Payload        : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;

   --  Parse an SSH_MSG_KEX_DH_GEX_GROUP into its prime and generator.
   --  @param Payload the received group message
   --  @param Item    the parsed prime/generator pair
   --  @return Ok on success or a parse failure status
   function Parse_Group_Exchange_Group
     (Payload : Ada.Streams.Stream_Element_Array;
      Item    : out Group_Exchange_Group)
      return CryptoLib.Errors.Status;

   --  Encode an SSH_MSG_KEX_DH_GEX_INIT carrying the client public value e.
   --  @param Client_Public_Value the client DH public value e as an mpint
   --  @param Payload             the encoded init message
   --  @return Ok on success or an encoding failure status
   function Encode_Group_Exchange_Init
     (Client_Public_Value : Ada.Streams.Stream_Element_Array;
      Payload             : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;

   --  Parse an SSH_MSG_KEX_DH_GEX_REPLY into host key, server value and signature.
   --  @param Payload the received group-exchange reply message
   --  @param Item    the parsed reply (host key blob, Q_S, signature blob)
   --  @return Ok on success or a parse failure status
   function Parse_Group_Exchange_Reply
     (Payload : Ada.Streams.Stream_Element_Array;
      Item    : out Reply)
      return CryptoLib.Errors.Status;

   --  Encode a group14 SSH_MSG_KEXDH_INIT carrying the client public value e.
   --  @param Client_Public_Value the client DH public value e as an mpint
   --  @param Payload             the encoded init message
   --  @return Ok on success or an encoding failure status
   function Encode_Group14_Init
     (Client_Public_Value : Ada.Streams.Stream_Element_Array;
      Payload             : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;

   --  Parse a group14 SSH_MSG_KEXDH_REPLY into host key, server value and signature.
   --  @param Payload the received KEXDH reply message
   --  @param Item    the parsed reply (host key blob, Q_S, signature blob)
   --  @return Ok on success or a parse failure status
   function Parse_Group14_Reply
     (Payload : Ada.Streams.Stream_Element_Array;
      Item    : out Reply)
      return CryptoLib.Errors.Status;

   --  Encode a Curve25519 SSH_MSG_KEX_ECDH_INIT carrying the client public key.
   --  @param Client_Public_Key the 32-byte client Curve25519 public value Q_C
   --  @param Payload           the encoded init message
   --  @return Ok on success or an encoding failure status
   function Encode_Curve25519_Init
     (Client_Public_Key : Ada.Streams.Stream_Element_Array;
      Payload           : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;

   --  Parse a Curve25519 SSH_MSG_KEX_ECDH_REPLY into host key, Q_S and signature.
   --  @param Payload the received ECDH reply message
   --  @param Item    the parsed reply (host key blob, Q_S, signature blob)
   --  @return Ok on success or a parse failure status
   function Parse_Curve25519_Reply
     (Payload : Ada.Streams.Stream_Element_Array;
      Item    : out Reply)
      return CryptoLib.Errors.Status;

   --  Encode a NIST P-256 SSH_MSG_KEX_ECDH_INIT carrying the client public key.
   --  @param Client_Public_Key the SEC1-encoded client P-256 point Q_C
   --  @param Payload           the encoded init message
   --  @return Ok on success or an encoding failure status
   function Encode_ECDH_Nistp256_Init
     (Client_Public_Key : Ada.Streams.Stream_Element_Array;
      Payload           : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;

   --  Parse a NIST P-256 SSH_MSG_KEX_ECDH_REPLY into host key, Q_S and signature.
   --  @param Payload the received ECDH reply message
   --  @param Item    the parsed reply (host key blob, Q_S, signature blob)
   --  @return Ok on success or a parse failure status
   function Parse_ECDH_Nistp256_Reply
     (Payload : Ada.Streams.Stream_Element_Array;
      Item    : out Reply)
      return CryptoLib.Errors.Status;

   --  Encode a NIST P-384 SSH_MSG_KEX_ECDH_INIT carrying the client public key.
   --  @param Client_Public_Key the SEC1-encoded client P-384 point Q_C
   --  @param Payload           the encoded init message
   --  @return Ok on success or an encoding failure status
   function Encode_ECDH_Nistp384_Init
     (Client_Public_Key : Ada.Streams.Stream_Element_Array;
      Payload           : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;

   --  Parse a NIST P-384 SSH_MSG_KEX_ECDH_REPLY into host key, Q_S and signature.
   --  @param Payload the received ECDH reply message
   --  @param Item    the parsed reply (host key blob, Q_S, signature blob)
   --  @return Ok on success or a parse failure status
   function Parse_ECDH_Nistp384_Reply
     (Payload : Ada.Streams.Stream_Element_Array;
      Item    : out Reply)
      return CryptoLib.Errors.Status;

   --  Encode a NIST P-521 SSH_MSG_KEX_ECDH_INIT carrying the client public key.
   --  @param Client_Public_Key the SEC1-encoded client P-521 point Q_C
   --  @param Payload           the encoded init message
   --  @return Ok on success or an encoding failure status
   function Encode_ECDH_Nistp521_Init
     (Client_Public_Key : Ada.Streams.Stream_Element_Array;
      Payload           : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;

   --  Parse a NIST P-521 SSH_MSG_KEX_ECDH_REPLY into host key, Q_S and signature.
   --  @param Payload the received ECDH reply message
   --  @param Item    the parsed reply (host key blob, Q_S, signature blob)
   --  @return Ok on success or a parse failure status
   function Parse_ECDH_Nistp521_Reply
     (Payload : Ada.Streams.Stream_Element_Array;
      Item    : out Reply)
      return CryptoLib.Errors.Status;

   --  Encode a hybrid post-quantum SSH_MSG_KEX_ECDH_INIT carrying the client init.
   --  @param Client_Init the concatenated client PQ/classical public key blob
   --  @param Payload     the encoded init message
   --  @return Ok on success or an encoding failure status
   function Encode_Hybrid_PQ_Init
     (Client_Init : Ada.Streams.Stream_Element_Array;
      Payload     : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;

   --  Parse a hybrid post-quantum reply into host key, server value and signature.
   --  @param Payload the received hybrid ECDH reply message
   --  @param Item    the parsed reply (host key blob, Q_S, signature blob)
   --  @return Ok on success or a parse failure status
   function Parse_Hybrid_PQ_Reply
     (Payload : Ada.Streams.Stream_Element_Array;
      Item    : out Reply)
      return CryptoLib.Errors.Status;
end SSH_Lib.Protocol.Kexdh;
