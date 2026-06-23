with Ada.Streams;
with Interfaces;
with CryptoLib.Ciphers;
with CryptoLib.Hashes;
with CryptoLib.Errors;
with SSH_Lib.Keys;
with SSH_Lib.Protocol.Kex;
with SSH_Lib.Protocol.Session_Keys;

package SSH_Lib.Protocol.Encrypted_State is

   type Kex_State is private;

   procedure Reset (Item : out Kex_State);

   function Install_Derived_Keys
     (Item             : in out Kex_State;
      Algorithms_Item  : SSH_Lib.Protocol.Kex.Negotiated_Algorithms;
      Exchange_Hash    : CryptoLib.Hashes.SHA256_Digest;
      Session_Id       : CryptoLib.Hashes.SHA256_Digest;
      Keys_Item        : SSH_Lib.Protocol.Session_Keys.Derived_Keys)
      return CryptoLib.Errors.Status;

   function Store_Verified_Host_Key
     (Item     : in out Kex_State;
      Key_Item : SSH_Lib.Keys.Public_Key)
      return CryptoLib.Errors.Status;

   function Has_Verified_Host_Key (Item : Kex_State) return Boolean;

   function Verified_Host_Key
     (Item : Kex_State)
      return SSH_Lib.Keys.Public_Key;

   function Encode_Newkeys
      return Ada.Streams.Stream_Element_Array;

   function Send_Newkeys (Item : in out Kex_State) return CryptoLib.Errors.Status;

   function Receive_Newkeys
     (Item    : in out Kex_State;
      Payload : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   function Newkeys_Sent (Item : Kex_State) return Boolean;
   function Newkeys_Received (Item : Kex_State) return Boolean;
   function Kex_Complete (Item : Kex_State) return Boolean;
   function Outbound_Encrypted_Active (Item : Kex_State) return Boolean;
   function Inbound_Encrypted_Active (Item : Kex_State) return Boolean;

   function Outbound_Sequence (Item : Kex_State) return Interfaces.Unsigned_32;
   function Inbound_Sequence (Item : Kex_State) return Interfaces.Unsigned_32;

   procedure Set_Sequences_For_Test
     (Item           : in out Kex_State;
      Outbound_Value : Interfaces.Unsigned_32;
      Inbound_Value  : Interfaces.Unsigned_32);

   function Note_Outbound_Packet (Item : in out Kex_State) return CryptoLib.Errors.Status;
   function Note_Inbound_Packet (Item : in out Kex_State) return CryptoLib.Errors.Status;

private
   type Kex_State is record
      Algorithms_Value : SSH_Lib.Protocol.Kex.Negotiated_Algorithms;
      Exchange_Hash_Value : CryptoLib.Hashes.SHA256_Digest := [others => 0];
      Session_Id_Value : CryptoLib.Hashes.SHA256_Digest := [others => 0];
      Keys_Value : SSH_Lib.Protocol.Session_Keys.Derived_Keys;
      Verified_Host_Key_Value : SSH_Lib.Keys.Public_Key;
      Has_Verified_Host_Key_Value : Boolean := False;
      Client_To_Server_Cipher : CryptoLib.Ciphers.Cipher_State;
      Server_To_Client_Cipher : CryptoLib.Ciphers.Cipher_State;
      Outbound_Sequence_Value : Interfaces.Unsigned_32 := 0;
      Inbound_Sequence_Value : Interfaces.Unsigned_32 := 0;
      Newkeys_Sent_Value : Boolean := False;
      Newkeys_Received_Value : Boolean := False;
      Kex_Complete_Value : Boolean := False;
      Outbound_Active_Value : Boolean := False;
      Inbound_Active_Value : Boolean := False;
   end record;
end SSH_Lib.Protocol.Encrypted_State;
