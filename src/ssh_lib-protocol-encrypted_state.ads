with Ada.Streams;
with Interfaces;
with CryptoLib.Ciphers;
with CryptoLib.Hashes;
with CryptoLib.Errors;
with SSH_Lib.Keys;
with SSH_Lib.Protocol.Kex;
with SSH_Lib.Protocol.Session_Keys;

--  @summary Directional cipher and sequence state established at NEWKEYS.
--
--  A Kex_State captures the outcome of one key exchange: the negotiated
--  algorithms, the exchange hash and session id, the derived directional keys,
--  the verified host key, and the two directional cipher objects plus their
--  packet sequence numbers.  It tracks the NEWKEYS handshake (sent/received)
--  and, once complete, which direction is actively encrypted.
package SSH_Lib.Protocol.Encrypted_State is

   type Kex_State is private;

   --  Clear the state back to its initial, pre-key-exchange values.
   --  @param Item the state to reset
   procedure Reset (Item : out Kex_State);

   --  Record the negotiated algorithms, exchange hash, session id and derived
   --  keys, marking the key exchange complete (but not yet NEWKEYS-active).
   --  @param Item            the state to populate
   --  @param Algorithms_Item the negotiated per-direction algorithm names
   --  @param Exchange_Hash   the key-exchange hash H
   --  @param Session_Id      the session identifier (H of the first exchange)
   --  @param Keys_Item       the derived directional keys and IVs
   --  @return Ok on success, Internal_Error on an unexpected exception
   function Install_Derived_Keys
     (Item             : in out Kex_State;
      Algorithms_Item  : SSH_Lib.Protocol.Kex.Negotiated_Algorithms;
      Exchange_Hash    : CryptoLib.Hashes.SHA256_Digest;
      Session_Id       : CryptoLib.Hashes.SHA256_Digest;
      Keys_Item        : SSH_Lib.Protocol.Session_Keys.Derived_Keys)
      return CryptoLib.Errors.Status;

   --  Store the host key that was verified during this exchange for later query.
   --  @param Item     the state to update
   --  @param Key_Item the verified server host public key
   --  @return Ok on success, Handshake_Failed if the key is invalid,
   --          Internal_Error on an unexpected exception
   function Store_Verified_Host_Key
     (Item     : in out Kex_State;
      Key_Item : SSH_Lib.Keys.Public_Key)
      return CryptoLib.Errors.Status;

   --  Report whether a verified host key has been stored.
   --  @param Item the state to query
   --  @return True once Store_Verified_Host_Key has succeeded
   function Has_Verified_Host_Key (Item : Kex_State) return Boolean;

   --  Return the previously stored verified host key.
   --  @param Item the state to query
   --  @return the verified server host public key
   function Verified_Host_Key
     (Item : Kex_State)
      return SSH_Lib.Keys.Public_Key;

   --  Encode the single-byte SSH_MSG_NEWKEYS message payload.
   --  @return a one-element array holding the NEWKEYS message number
   function Encode_Newkeys
      return Ada.Streams.Stream_Element_Array;

   --  Activate the outbound cipher and mark NEWKEYS as sent for this direction.
   --  @param Item the state to advance
   --  @return Ok on success, Handshake_Failed if key exchange is incomplete or
   --          NEWKEYS was already sent, or a cipher-init failure status
   function Send_Newkeys (Item : in out Kex_State) return CryptoLib.Errors.Status;

   --  Validate a received SSH_MSG_NEWKEYS payload, then activate the inbound
   --  cipher and mark NEWKEYS as received.
   --  @param Item    the state to advance
   --  @param Payload the received NEWKEYS message payload (one byte)
   --  @return Ok on success, Handshake_Failed on a bad payload or out-of-order
   --          state, or a cipher-init failure status
   function Receive_Newkeys
     (Item    : in out Kex_State;
      Payload : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Report whether NEWKEYS has been sent to the peer.
   --  @param Item the state to query
   --  @return True once Send_Newkeys has succeeded
   function Newkeys_Sent (Item : Kex_State) return Boolean;
   --  Report whether NEWKEYS has been received from the peer.
   --  @param Item the state to query
   --  @return True once Receive_Newkeys has succeeded
   function Newkeys_Received (Item : Kex_State) return Boolean;
   --  Report whether the key exchange has completed (derived keys installed).
   --  @param Item the state to query
   --  @return True once Install_Derived_Keys has succeeded
   function Kex_Complete (Item : Kex_State) return Boolean;
   --  Report whether outbound packets are now encrypted.
   --  @param Item the state to query
   --  @return True once the outbound direction is NEWKEYS-active
   function Outbound_Encrypted_Active (Item : Kex_State) return Boolean;
   --  Report whether inbound packets are now encrypted.
   --  @param Item the state to query
   --  @return True once the inbound direction is NEWKEYS-active
   function Inbound_Encrypted_Active (Item : Kex_State) return Boolean;

   --  Return the current outbound packet sequence number.
   --  @param Item the state to query
   --  @return the next outbound SSH packet sequence number
   function Outbound_Sequence (Item : Kex_State) return Interfaces.Unsigned_32;
   --  Return the current inbound packet sequence number.
   --  @param Item the state to query
   --  @return the next inbound SSH packet sequence number
   function Inbound_Sequence (Item : Kex_State) return Interfaces.Unsigned_32;

   --  Force the directional sequence numbers to fixed values (testing only).
   --  @param Item           the state to modify
   --  @param Outbound_Value the outbound sequence number to install
   --  @param Inbound_Value  the inbound sequence number to install
   procedure Set_Sequences_For_Test
     (Item           : in out Kex_State;
      Outbound_Value : Interfaces.Unsigned_32;
      Inbound_Value  : Interfaces.Unsigned_32);

   --  Advance the outbound sequence number after sending one packet (wraps at
   --  2**32).
   --  @param Item the state to advance
   --  @return Ok on success, Internal_Error on an unexpected exception
   function Note_Outbound_Packet (Item : in out Kex_State) return CryptoLib.Errors.Status;
   --  Advance the inbound sequence number after receiving one packet (wraps at
   --  2**32).
   --  @param Item the state to advance
   --  @return Ok on success, Internal_Error on an unexpected exception
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
