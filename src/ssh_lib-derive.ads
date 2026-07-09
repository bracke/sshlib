with Ada.Streams;
with CryptoLib.Hashes;
with CryptoLib.Buffers;

--  @summary RFC 4253 key-derivation KDF that expands the shared secret into keys, IVs, and MACs.
--
--  Each function implements the "HASH(K || H || label || session_id) then
--  extend" construction for one hash algorithm, producing the requested number
--  of key bytes for a single derivation label (A..F: IVs, encryption keys, MAC keys).
package SSH_Lib.Derive is

   --  Derive keying material with SHA-1 per RFC 4253 for one label.
   --  @param Shared_Secret      the raw Diffie-Hellman shared secret K
   --  @param Exchange_Hash      the key-exchange hash H
   --  @param Session_Identifier the session id (H of the first exchange)
   --  @param Label_Value        the single-character derivation label ('A'..'F')
   --  @param Requested_Length   number of key bytes to produce
   --  @return a buffer holding Requested_Length derived bytes
   function Derive_SHA1
     (Shared_Secret      : Ada.Streams.Stream_Element_Array;
      Exchange_Hash      : CryptoLib.Hashes.SHA1_Digest;
      Session_Identifier : Ada.Streams.Stream_Element_Array;
      Label_Value        : Character;
      Requested_Length   : Natural)
      return CryptoLib.Buffers.Packet_Buffer;

   --  Derive keying material with SHA-256 per RFC 4253 for one label.
   --  As_String selects how the shared secret K is framed in the derivation
   --  hash: mpint (ECDH/DH, the default) or SSH string (post-quantum hybrid).
   --  @param Shared_Secret      the raw shared secret K
   --  @param Exchange_Hash      the key-exchange hash H
   --  @param Session_Identifier the session id (H of the first exchange)
   --  @param Label_Value        the single-character derivation label ('A'..'F')
   --  @param Requested_Length   number of key bytes to produce
   --  @param As_String          when True, frame K as an SSH string instead of an mpint
   --  @return a buffer holding Requested_Length derived bytes
   function Derive_SHA256
     (Shared_Secret      : Ada.Streams.Stream_Element_Array;
      Exchange_Hash      : CryptoLib.Hashes.SHA256_Digest;
      Session_Identifier : CryptoLib.Hashes.SHA256_Digest;
      Label_Value        : Character;
      Requested_Length   : Natural;
      As_String          : Boolean := False)
      return CryptoLib.Buffers.Packet_Buffer;

   --  Derive keying material with SHA-384 per RFC 4253 for one label.
   --  @param Shared_Secret      the raw shared secret K
   --  @param Exchange_Hash      the key-exchange hash H
   --  @param Session_Identifier the session id (H of the first exchange)
   --  @param Label_Value        the single-character derivation label ('A'..'F')
   --  @param Requested_Length   number of key bytes to produce
   --  @return a buffer holding Requested_Length derived bytes
   function Derive_SHA384
     (Shared_Secret      : Ada.Streams.Stream_Element_Array;
      Exchange_Hash      : CryptoLib.Hashes.SHA384_Digest;
      Session_Identifier : CryptoLib.Hashes.SHA384_Digest;
      Label_Value        : Character;
      Requested_Length   : Natural)
      return CryptoLib.Buffers.Packet_Buffer;

   --  Derive keying material with SHA-512 per RFC 4253 for one label.
   --  As_String selects how the shared secret K is framed in the derivation
   --  hash: mpint (ECDH/DH, the default) or SSH string (post-quantum hybrid).
   --  @param Shared_Secret      the raw shared secret K
   --  @param Exchange_Hash      the key-exchange hash H
   --  @param Session_Identifier the session id (H of the first exchange)
   --  @param Label_Value        the single-character derivation label ('A'..'F')
   --  @param Requested_Length   number of key bytes to produce
   --  @param As_String          when True, frame K as an SSH string instead of an mpint
   --  @return a buffer holding Requested_Length derived bytes
   function Derive_SHA512
     (Shared_Secret      : Ada.Streams.Stream_Element_Array;
      Exchange_Hash      : CryptoLib.Hashes.SHA512_Digest;
      Session_Identifier : CryptoLib.Hashes.SHA512_Digest;
      Label_Value        : Character;
      Requested_Length   : Natural;
      As_String          : Boolean := False)
      return CryptoLib.Buffers.Packet_Buffer;
end SSH_Lib.Derive;
