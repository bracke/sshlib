with Ada.Strings.Unbounded;
with SSH_Lib.Protocol.Buffers;
with SSH_Lib.Keys.Internal;

package body SSH_Lib.Protocol.Encrypted_State is

   use Ada.Streams;
   use Ada.Strings.Unbounded;
   use Interfaces;
   use CryptoLib.Errors;

   Newkeys_Message : constant Stream_Element := 21;

   --  AEAD ciphers (chacha20-poly1305 and AES-GCM) are not modeled by the
   --  generic CryptoLib.Ciphers block-cipher interface; their SSH packet
   --  framing is performed by SSH_Lib.Protocol.Protected_Packets. This
   --  Kex_State's cipher objects are only ever Initialize-d here and never used
   --  to transform packet data, so an AEAD selection must not be pushed through
   --  CryptoLib.Ciphers.Initialize (which fails closed with Unsupported_Feature
   --  and would abort an otherwise valid handshake).
   function Is_AEAD_Cipher (Name : String) return Boolean is
     (Name = "chacha20-poly1305@openssh.com"
      or else Name = "aes128-gcm@openssh.com"
      or else Name = "aes256-gcm@openssh.com");

   procedure Reset (Item : out Kex_State) is
   begin
      SSH_Lib.Protocol.Kex.Clear (Item.Algorithms_Value);
      Item.Exchange_Hash_Value := [others => 0];
      Item.Session_Id_Value := [others => 0];
      SSH_Lib.Protocol.Session_Keys.Clear (Item.Keys_Value);
      CryptoLib.Ciphers.Reset (Item.Client_To_Server_Cipher);
      SSH_Lib.Keys.Internal.Clear (Item.Verified_Host_Key_Value);
      Item.Has_Verified_Host_Key_Value := False;
      CryptoLib.Ciphers.Reset (Item.Server_To_Client_Cipher);
      Item.Outbound_Sequence_Value := 0;
      Item.Inbound_Sequence_Value := 0;
      Item.Newkeys_Sent_Value := False;
      Item.Newkeys_Received_Value := False;
      Item.Kex_Complete_Value := False;
      Item.Outbound_Active_Value := False;
      Item.Inbound_Active_Value := False;
   end Reset;

   function Install_Derived_Keys
     (Item             : in out Kex_State;
      Algorithms_Item  : SSH_Lib.Protocol.Kex.Negotiated_Algorithms;
      Exchange_Hash    : CryptoLib.Hashes.SHA256_Digest;
      Session_Id       : CryptoLib.Hashes.SHA256_Digest;
      Keys_Item        : SSH_Lib.Protocol.Session_Keys.Derived_Keys)
      return Status
   is
   begin
      Item.Algorithms_Value := Algorithms_Item;
      Item.Exchange_Hash_Value := Exchange_Hash;
      Item.Session_Id_Value := Session_Id;
      Item.Keys_Value := Keys_Item;
      Item.Kex_Complete_Value := True;
      Item.Outbound_Active_Value := False;
      Item.Inbound_Active_Value := False;
      return Ok;
   exception
      when others =>
         Reset (Item);
         return Internal_Error;
   end Install_Derived_Keys;

   function Store_Verified_Host_Key
     (Item     : in out Kex_State;
      Key_Item : SSH_Lib.Keys.Public_Key)
      return Status
   is
      Status_Value : Status;
   begin
      if not SSH_Lib.Keys.Is_Valid (Key_Item) then
         SSH_Lib.Keys.Internal.Clear (Item.Verified_Host_Key_Value);
         Item.Has_Verified_Host_Key_Value := False;
         return Handshake_Failed;
      end if;

      declare
         Blob : constant Stream_Element_Array := SSH_Lib.Keys.Internal.Raw_Blob (Key_Item);
      begin
         Status_Value := SSH_Lib.Keys.Internal.Set_Public_Key
           (Item.Verified_Host_Key_Value, SSH_Lib.Keys.Algorithm (Key_Item), Blob);
      end;

      Item.Has_Verified_Host_Key_Value := Status_Value = Ok;
      return Status_Value;
   exception
      when others =>
         SSH_Lib.Keys.Internal.Clear (Item.Verified_Host_Key_Value);
         Item.Has_Verified_Host_Key_Value := False;
         return Internal_Error;
   end Store_Verified_Host_Key;

   function Has_Verified_Host_Key (Item : Kex_State) return Boolean is
   begin
      return Item.Has_Verified_Host_Key_Value;
   end Has_Verified_Host_Key;

   function Verified_Host_Key
     (Item : Kex_State)
      return SSH_Lib.Keys.Public_Key
   is
   begin
      return Item.Verified_Host_Key_Value;
   end Verified_Host_Key;

   function Encode_Newkeys return Stream_Element_Array is
   begin
      return Result : Stream_Element_Array (1 .. 1) do
         Result (1) := Newkeys_Message;
      end return;
   end Encode_Newkeys;

   function Send_Newkeys (Item : in out Kex_State) return Status is
   begin
      if not Item.Kex_Complete_Value or else Item.Newkeys_Sent_Value then
         return Handshake_Failed;
      end if;
      declare
         Cipher_Name : constant String :=
           To_String (Item.Algorithms_Value.Cipher_Client_To_Server);
      begin
         if not Is_AEAD_Cipher (Cipher_Name) then
            declare
               Status_Value : constant Status := CryptoLib.Ciphers.Initialize
                 (Item.Client_To_Server_Cipher,
                  Cipher_Name,
                  CryptoLib.Ciphers.Client_To_Server,
                  SSH_Lib.Protocol.Buffers.To_Array
                    (Item.Keys_Value.Encryption_Key_Client_To_Server),
                  SSH_Lib.Protocol.Buffers.To_Array
                    (Item.Keys_Value.Initial_IV_Client_To_Server));
            begin
               if Status_Value /= Ok then
                  Item.Outbound_Active_Value := False;
                  return Status_Value;
               end if;
            end;
         end if;
      end;
      Item.Newkeys_Sent_Value := True;
      Item.Outbound_Active_Value := True;
      return Ok;
   end Send_Newkeys;

   function Receive_Newkeys
     (Item    : in out Kex_State;
      Payload : Stream_Element_Array)
      return Status
   is
   begin
      if not Item.Kex_Complete_Value
        or else not Item.Newkeys_Sent_Value
        or else Item.Newkeys_Received_Value
      then
         return Handshake_Failed;
      end if;
      if Payload'Length /= 1 or else Payload (Payload'First) /= Newkeys_Message then
         return Handshake_Failed;
      end if;
      declare
         Cipher_Name : constant String :=
           To_String (Item.Algorithms_Value.Cipher_Server_To_Client);
      begin
         if not Is_AEAD_Cipher (Cipher_Name) then
            declare
               Status_Value : constant Status := CryptoLib.Ciphers.Initialize
                 (Item.Server_To_Client_Cipher,
                  Cipher_Name,
                  CryptoLib.Ciphers.Server_To_Client,
                  SSH_Lib.Protocol.Buffers.To_Array
                    (Item.Keys_Value.Encryption_Key_Server_To_Client),
                  SSH_Lib.Protocol.Buffers.To_Array
                    (Item.Keys_Value.Initial_IV_Server_To_Client));
            begin
               if Status_Value /= Ok then
                  Item.Inbound_Active_Value := False;
                  return Status_Value;
               end if;
            end;
         end if;
      end;
      Item.Newkeys_Received_Value := True;
      Item.Inbound_Active_Value := True;
      return Ok;
   end Receive_Newkeys;

   function Newkeys_Sent (Item : Kex_State) return Boolean is
   begin
      return Item.Newkeys_Sent_Value;
   end Newkeys_Sent;

   function Newkeys_Received (Item : Kex_State) return Boolean is
   begin
      return Item.Newkeys_Received_Value;
   end Newkeys_Received;

   function Kex_Complete (Item : Kex_State) return Boolean is
   begin
      return Item.Kex_Complete_Value;
   end Kex_Complete;

   function Outbound_Encrypted_Active (Item : Kex_State) return Boolean is
   begin
      return Item.Outbound_Active_Value;
   end Outbound_Encrypted_Active;

   function Inbound_Encrypted_Active (Item : Kex_State) return Boolean is
   begin
      return Item.Inbound_Active_Value;
   end Inbound_Encrypted_Active;

   function Outbound_Sequence (Item : Kex_State) return Unsigned_32 is
   begin
      return Item.Outbound_Sequence_Value;
   end Outbound_Sequence;

   function Inbound_Sequence (Item : Kex_State) return Unsigned_32 is
   begin
      return Item.Inbound_Sequence_Value;
   end Inbound_Sequence;

   procedure Set_Sequences_For_Test
     (Item           : in out Kex_State;
      Outbound_Value : Unsigned_32;
      Inbound_Value  : Unsigned_32)
   is
   begin
      Item.Outbound_Sequence_Value := Outbound_Value;
      Item.Inbound_Sequence_Value := Inbound_Value;
   end Set_Sequences_For_Test;

   function Note_Outbound_Packet (Item : in out Kex_State) return Status is
   begin
      Item.Outbound_Sequence_Value := Item.Outbound_Sequence_Value + 1;
      return Ok;
   exception
      when Constraint_Error =>
         Item.Outbound_Sequence_Value := 0;
         return Ok;
      when others =>
         return Internal_Error;
   end Note_Outbound_Packet;

   function Note_Inbound_Packet (Item : in out Kex_State) return Status is
   begin
      Item.Inbound_Sequence_Value := Item.Inbound_Sequence_Value + 1;
      return Ok;
   exception
      when Constraint_Error =>
         Item.Inbound_Sequence_Value := 0;
         return Ok;
      when others =>
         return Internal_Error;
   end Note_Inbound_Packet;
end SSH_Lib.Protocol.Encrypted_State;
