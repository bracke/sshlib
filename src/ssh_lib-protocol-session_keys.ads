with Ada.Streams;
with CryptoLib.Hashes;
with CryptoLib.Errors;
with SSH_Lib.Protocol.Buffers;

package SSH_Lib.Protocol.Session_Keys is

   type Derived_Keys is record
      Initial_IV_Client_To_Server     : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Initial_IV_Server_To_Client     : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Encryption_Key_Client_To_Server : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Encryption_Key_Server_To_Client : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Integrity_Key_Client_To_Server  : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Integrity_Key_Server_To_Client  : SSH_Lib.Protocol.Buffers.Packet_Buffer;
   end record;

   procedure Clear (Item : out Derived_Keys);

   function Derive_SHA1_Keys
     (Shared_Secret      : Ada.Streams.Stream_Element_Array;
      Exchange_Hash      : CryptoLib.Hashes.SHA1_Digest;
      Session_Identifier : Ada.Streams.Stream_Element_Array;
      IV_Length          : Natural;
      Encryption_Length  : Natural;
      Integrity_Length   : Natural;
      Result_Item        : out Derived_Keys)
      return CryptoLib.Errors.Status;

   function Derive_SHA256_Keys
     (Shared_Secret      : Ada.Streams.Stream_Element_Array;
      Exchange_Hash      : CryptoLib.Hashes.SHA256_Digest;
      Session_Identifier : CryptoLib.Hashes.SHA256_Digest;
      IV_Length          : Natural;
      Encryption_Length  : Natural;
      Integrity_Length   : Natural;
      Result_Item        : out Derived_Keys)
      return CryptoLib.Errors.Status;

   function Derive_SHA512_Keys
     (Shared_Secret      : Ada.Streams.Stream_Element_Array;
      Exchange_Hash      : CryptoLib.Hashes.SHA512_Digest;
      Session_Identifier : CryptoLib.Hashes.SHA512_Digest;
      IV_Length          : Natural;
      Encryption_Length  : Natural;
      Integrity_Length   : Natural;
      Result_Item        : out Derived_Keys)
      return CryptoLib.Errors.Status;
end SSH_Lib.Protocol.Session_Keys;
