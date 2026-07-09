with SSH_Lib.Derive;

package body SSH_Lib.Protocol.Session_Keys is
   use SSH_Lib.Protocol.Buffers;

   procedure Clear (Item : out Derived_Keys) is
   begin
      SSH_Lib.Protocol.Buffers.Clear (Item.Initial_IV_Client_To_Server);
      SSH_Lib.Protocol.Buffers.Clear (Item.Initial_IV_Server_To_Client);
      SSH_Lib.Protocol.Buffers.Clear (Item.Encryption_Key_Client_To_Server);
      SSH_Lib.Protocol.Buffers.Clear (Item.Encryption_Key_Server_To_Client);
      SSH_Lib.Protocol.Buffers.Clear (Item.Integrity_Key_Client_To_Server);
      SSH_Lib.Protocol.Buffers.Clear (Item.Integrity_Key_Server_To_Client);
   end Clear;

   function Derive_SHA1_Keys
     (Shared_Secret      : Ada.Streams.Stream_Element_Array;
      Exchange_Hash      : CryptoLib.Hashes.SHA1_Digest;
      Session_Identifier : Ada.Streams.Stream_Element_Array;
      IV_Length          : Natural;
      Encryption_Length  : Natural;
      Integrity_Length   : Natural;
      Result_Item        : out Derived_Keys)
      return CryptoLib.Errors.Status
   is
   begin
      Clear (Result_Item);
      Result_Item.Initial_IV_Client_To_Server := SSH_Lib.Derive.Derive_SHA1
        (Shared_Secret, Exchange_Hash, Session_Identifier, 'A', IV_Length);
      Result_Item.Initial_IV_Server_To_Client := SSH_Lib.Derive.Derive_SHA1
        (Shared_Secret, Exchange_Hash, Session_Identifier, 'B', IV_Length);
      Result_Item.Encryption_Key_Client_To_Server := SSH_Lib.Derive.Derive_SHA1
        (Shared_Secret, Exchange_Hash, Session_Identifier, 'C', Encryption_Length);
      Result_Item.Encryption_Key_Server_To_Client := SSH_Lib.Derive.Derive_SHA1
        (Shared_Secret, Exchange_Hash, Session_Identifier, 'D', Encryption_Length);
      Result_Item.Integrity_Key_Client_To_Server := SSH_Lib.Derive.Derive_SHA1
        (Shared_Secret, Exchange_Hash, Session_Identifier, 'E', Integrity_Length);
      Result_Item.Integrity_Key_Server_To_Client := SSH_Lib.Derive.Derive_SHA1
        (Shared_Secret, Exchange_Hash, Session_Identifier, 'F', Integrity_Length);

      if Length (Result_Item.Initial_IV_Client_To_Server) /= IV_Length
        or else Length (Result_Item.Initial_IV_Server_To_Client) /= IV_Length
        or else Length (Result_Item.Encryption_Key_Client_To_Server) /= Encryption_Length
        or else Length (Result_Item.Encryption_Key_Server_To_Client) /= Encryption_Length
        or else Length (Result_Item.Integrity_Key_Client_To_Server) /= Integrity_Length
        or else Length (Result_Item.Integrity_Key_Server_To_Client) /= Integrity_Length
      then
         Clear (Result_Item);
         return CryptoLib.Errors.Internal_Error;
      end if;

      return CryptoLib.Errors.Ok;
   exception
      when others =>
         Clear (Result_Item);
         return CryptoLib.Errors.Internal_Error;
   end Derive_SHA1_Keys;

   function Derive_SHA256_Keys
     (Shared_Secret      : Ada.Streams.Stream_Element_Array;
      Exchange_Hash      : CryptoLib.Hashes.SHA256_Digest;
      Session_Identifier : CryptoLib.Hashes.SHA256_Digest;
      IV_Length          : Natural;
      Encryption_Length  : Natural;
      Integrity_Length   : Natural;
      Result_Item        : out Derived_Keys;
      As_String          : Boolean := False)
      return CryptoLib.Errors.Status
   is
   begin
      Clear (Result_Item);
      Result_Item.Initial_IV_Client_To_Server := SSH_Lib.Derive.Derive_SHA256
        (Shared_Secret, Exchange_Hash, Session_Identifier, 'A', IV_Length,
         As_String);
      Result_Item.Initial_IV_Server_To_Client := SSH_Lib.Derive.Derive_SHA256
        (Shared_Secret, Exchange_Hash, Session_Identifier, 'B', IV_Length,
         As_String);
      Result_Item.Encryption_Key_Client_To_Server := SSH_Lib.Derive.Derive_SHA256
        (Shared_Secret, Exchange_Hash, Session_Identifier, 'C', Encryption_Length,
         As_String);
      Result_Item.Encryption_Key_Server_To_Client := SSH_Lib.Derive.Derive_SHA256
        (Shared_Secret, Exchange_Hash, Session_Identifier, 'D', Encryption_Length,
         As_String);
      Result_Item.Integrity_Key_Client_To_Server := SSH_Lib.Derive.Derive_SHA256
        (Shared_Secret, Exchange_Hash, Session_Identifier, 'E', Integrity_Length,
         As_String);
      Result_Item.Integrity_Key_Server_To_Client := SSH_Lib.Derive.Derive_SHA256
        (Shared_Secret, Exchange_Hash, Session_Identifier, 'F', Integrity_Length,
         As_String);

      if Length (Result_Item.Initial_IV_Client_To_Server) /= IV_Length
        or else Length (Result_Item.Initial_IV_Server_To_Client) /= IV_Length
        or else Length (Result_Item.Encryption_Key_Client_To_Server) /= Encryption_Length
        or else Length (Result_Item.Encryption_Key_Server_To_Client) /= Encryption_Length
        or else Length (Result_Item.Integrity_Key_Client_To_Server) /= Integrity_Length
        or else Length (Result_Item.Integrity_Key_Server_To_Client) /= Integrity_Length
      then
         Clear (Result_Item);
         return CryptoLib.Errors.Internal_Error;
      end if;

      return CryptoLib.Errors.Ok;
   exception
      when others =>
         Clear (Result_Item);
         return CryptoLib.Errors.Internal_Error;
   end Derive_SHA256_Keys;

   function Derive_SHA384_Keys
     (Shared_Secret      : Ada.Streams.Stream_Element_Array;
      Exchange_Hash      : CryptoLib.Hashes.SHA384_Digest;
      Session_Identifier : CryptoLib.Hashes.SHA384_Digest;
      IV_Length          : Natural;
      Encryption_Length  : Natural;
      Integrity_Length   : Natural;
      Result_Item        : out Derived_Keys)
      return CryptoLib.Errors.Status
   is
   begin
      Clear (Result_Item);
      Result_Item.Initial_IV_Client_To_Server := SSH_Lib.Derive.Derive_SHA384
        (Shared_Secret, Exchange_Hash, Session_Identifier, 'A', IV_Length);
      Result_Item.Initial_IV_Server_To_Client := SSH_Lib.Derive.Derive_SHA384
        (Shared_Secret, Exchange_Hash, Session_Identifier, 'B', IV_Length);
      Result_Item.Encryption_Key_Client_To_Server := SSH_Lib.Derive.Derive_SHA384
        (Shared_Secret, Exchange_Hash, Session_Identifier, 'C', Encryption_Length);
      Result_Item.Encryption_Key_Server_To_Client := SSH_Lib.Derive.Derive_SHA384
        (Shared_Secret, Exchange_Hash, Session_Identifier, 'D', Encryption_Length);
      Result_Item.Integrity_Key_Client_To_Server := SSH_Lib.Derive.Derive_SHA384
        (Shared_Secret, Exchange_Hash, Session_Identifier, 'E', Integrity_Length);
      Result_Item.Integrity_Key_Server_To_Client := SSH_Lib.Derive.Derive_SHA384
        (Shared_Secret, Exchange_Hash, Session_Identifier, 'F', Integrity_Length);

      if Length (Result_Item.Initial_IV_Client_To_Server) /= IV_Length
        or else Length (Result_Item.Initial_IV_Server_To_Client) /= IV_Length
        or else Length (Result_Item.Encryption_Key_Client_To_Server) /= Encryption_Length
        or else Length (Result_Item.Encryption_Key_Server_To_Client) /= Encryption_Length
        or else Length (Result_Item.Integrity_Key_Client_To_Server) /= Integrity_Length
        or else Length (Result_Item.Integrity_Key_Server_To_Client) /= Integrity_Length
      then
         Clear (Result_Item);
         return CryptoLib.Errors.Internal_Error;
      end if;

      return CryptoLib.Errors.Ok;
   exception
      when others =>
         Clear (Result_Item);
         return CryptoLib.Errors.Internal_Error;
   end Derive_SHA384_Keys;

   function Derive_SHA512_Keys
     (Shared_Secret      : Ada.Streams.Stream_Element_Array;
      Exchange_Hash      : CryptoLib.Hashes.SHA512_Digest;
      Session_Identifier : CryptoLib.Hashes.SHA512_Digest;
      IV_Length          : Natural;
      Encryption_Length  : Natural;
      Integrity_Length   : Natural;
      Result_Item        : out Derived_Keys;
      As_String          : Boolean := False)
      return CryptoLib.Errors.Status
   is
   begin
      Clear (Result_Item);
      Result_Item.Initial_IV_Client_To_Server := SSH_Lib.Derive.Derive_SHA512
        (Shared_Secret, Exchange_Hash, Session_Identifier, 'A', IV_Length,
         As_String);
      Result_Item.Initial_IV_Server_To_Client := SSH_Lib.Derive.Derive_SHA512
        (Shared_Secret, Exchange_Hash, Session_Identifier, 'B', IV_Length,
         As_String);
      Result_Item.Encryption_Key_Client_To_Server := SSH_Lib.Derive.Derive_SHA512
        (Shared_Secret, Exchange_Hash, Session_Identifier, 'C', Encryption_Length,
         As_String);
      Result_Item.Encryption_Key_Server_To_Client := SSH_Lib.Derive.Derive_SHA512
        (Shared_Secret, Exchange_Hash, Session_Identifier, 'D', Encryption_Length,
         As_String);
      Result_Item.Integrity_Key_Client_To_Server := SSH_Lib.Derive.Derive_SHA512
        (Shared_Secret, Exchange_Hash, Session_Identifier, 'E', Integrity_Length,
         As_String);
      Result_Item.Integrity_Key_Server_To_Client := SSH_Lib.Derive.Derive_SHA512
        (Shared_Secret, Exchange_Hash, Session_Identifier, 'F', Integrity_Length,
         As_String);

      if Length (Result_Item.Initial_IV_Client_To_Server) /= IV_Length
        or else Length (Result_Item.Initial_IV_Server_To_Client) /= IV_Length
        or else Length (Result_Item.Encryption_Key_Client_To_Server) /= Encryption_Length
        or else Length (Result_Item.Encryption_Key_Server_To_Client) /= Encryption_Length
        or else Length (Result_Item.Integrity_Key_Client_To_Server) /= Integrity_Length
        or else Length (Result_Item.Integrity_Key_Server_To_Client) /= Integrity_Length
      then
         Clear (Result_Item);
         return CryptoLib.Errors.Internal_Error;
      end if;

      return CryptoLib.Errors.Ok;
   exception
      when others =>
         Clear (Result_Item);
         return CryptoLib.Errors.Internal_Error;
   end Derive_SHA512_Keys;

end SSH_Lib.Protocol.Session_Keys;
