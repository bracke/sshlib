with Ada.Streams;
with CryptoLib.Hashes;
with CryptoLib.Errors;
with SSH_Lib.Protocol.Buffers;

--  @summary Derives the six directional SSH session keys from the KEX secret.
--
--  Implements the RFC 4253 section 7.2 key derivation: from the shared secret K,
--  the exchange hash H and the session identifier, it expands the two IVs, two
--  encryption keys and two integrity keys (client-to-server and server-to-client)
--  to the requested lengths, one variant per negotiated exchange-hash algorithm.
package SSH_Lib.Protocol.Session_Keys is

   type Derived_Keys is record
      Initial_IV_Client_To_Server     : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Initial_IV_Server_To_Client     : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Encryption_Key_Client_To_Server : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Encryption_Key_Server_To_Client : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Integrity_Key_Client_To_Server  : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Integrity_Key_Server_To_Client  : SSH_Lib.Protocol.Buffers.Packet_Buffer;
   end record;

   --  Wipe all derived key material, resetting the record to empty.
   --  @param Item the derived key set to clear
   procedure Clear (Item : out Derived_Keys);

   --  Derive the six directional session keys with SHA-1 as the KDF hash.
   --  @param Shared_Secret      the KEX shared secret K
   --  @param Exchange_Hash      the exchange hash H
   --  @param Session_Identifier the session identifier (H of the first KEX)
   --  @param IV_Length          the number of IV bytes to derive per direction
   --  @param Encryption_Length  the number of cipher-key bytes per direction
   --  @param Integrity_Length   the number of MAC-key bytes per direction
   --  @param Result_Item        the derived key set
   --  @return Ok on success, otherwise the failure status
   function Derive_SHA1_Keys
     (Shared_Secret      : Ada.Streams.Stream_Element_Array;
      Exchange_Hash      : CryptoLib.Hashes.SHA1_Digest;
      Session_Identifier : Ada.Streams.Stream_Element_Array;
      IV_Length          : Natural;
      Encryption_Length  : Natural;
      Integrity_Length   : Natural;
      Result_Item        : out Derived_Keys)
      return CryptoLib.Errors.Status;

   --  Derive the six directional session keys with SHA-256 as the KDF hash.
   --  @param Shared_Secret      the KEX shared secret K
   --  @param Exchange_Hash      the exchange hash H
   --  @param Session_Identifier the session identifier (H of the first KEX)
   --  @param IV_Length          the number of IV bytes to derive per direction
   --  @param Encryption_Length  the number of cipher-key bytes per direction
   --  @param Integrity_Length   the number of MAC-key bytes per direction
   --  @param Result_Item        the derived key set
   --  @param As_String          frame K as an SSH string rather than an mpint
   --                            (required by post-quantum hybrid key exchange)
   --  @return Ok on success, otherwise the failure status
   --  As_String frames the shared secret K as an SSH string rather than an
   --  mpint (required by post-quantum hybrid key exchange).
   function Derive_SHA256_Keys
     (Shared_Secret      : Ada.Streams.Stream_Element_Array;
      Exchange_Hash      : CryptoLib.Hashes.SHA256_Digest;
      Session_Identifier : CryptoLib.Hashes.SHA256_Digest;
      IV_Length          : Natural;
      Encryption_Length  : Natural;
      Integrity_Length   : Natural;
      Result_Item        : out Derived_Keys;
      As_String          : Boolean := False)
      return CryptoLib.Errors.Status;

   --  Derive the six directional session keys with SHA-384 as the KDF hash.
   --  @param Shared_Secret      the KEX shared secret K
   --  @param Exchange_Hash      the exchange hash H
   --  @param Session_Identifier the session identifier (H of the first KEX)
   --  @param IV_Length          the number of IV bytes to derive per direction
   --  @param Encryption_Length  the number of cipher-key bytes per direction
   --  @param Integrity_Length   the number of MAC-key bytes per direction
   --  @param Result_Item        the derived key set
   --  @return Ok on success, otherwise the failure status
   function Derive_SHA384_Keys
     (Shared_Secret      : Ada.Streams.Stream_Element_Array;
      Exchange_Hash      : CryptoLib.Hashes.SHA384_Digest;
      Session_Identifier : CryptoLib.Hashes.SHA384_Digest;
      IV_Length          : Natural;
      Encryption_Length  : Natural;
      Integrity_Length   : Natural;
      Result_Item        : out Derived_Keys)
      return CryptoLib.Errors.Status;

   --  Derive the six directional session keys with SHA-512 as the KDF hash.
   --  @param Shared_Secret      the KEX shared secret K
   --  @param Exchange_Hash      the exchange hash H
   --  @param Session_Identifier the session identifier (H of the first KEX)
   --  @param IV_Length          the number of IV bytes to derive per direction
   --  @param Encryption_Length  the number of cipher-key bytes per direction
   --  @param Integrity_Length   the number of MAC-key bytes per direction
   --  @param Result_Item        the derived key set
   --  @param As_String          frame K as an SSH string rather than an mpint
   --                            (required by post-quantum hybrid key exchange)
   --  @return Ok on success, otherwise the failure status
   function Derive_SHA512_Keys
     (Shared_Secret      : Ada.Streams.Stream_Element_Array;
      Exchange_Hash      : CryptoLib.Hashes.SHA512_Digest;
      Session_Identifier : CryptoLib.Hashes.SHA512_Digest;
      IV_Length          : Natural;
      Encryption_Length  : Natural;
      Integrity_Length   : Natural;
      Result_Item        : out Derived_Keys;
      As_String          : Boolean := False)
      return CryptoLib.Errors.Status;
end SSH_Lib.Protocol.Session_Keys;
