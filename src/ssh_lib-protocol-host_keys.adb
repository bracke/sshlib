with Ada.Strings.Unbounded;
with SSH_Lib.ECDSA;
with SSH_Lib.Keys.Internal;
with SSH_Lib.Protocol.Buffers;
with SSH_Lib.Protocol.Certificates;
with SSH_Lib.Protocol.Numbers;
with SSH_Lib.Protocol.Signatures;
with SSH_Lib.Protocol.Validation;

package body SSH_Lib.Protocol.Host_Keys is
   use Ada.Streams;
   use Ada.Strings.Unbounded;
   use CryptoLib.Errors;
   use SSH_Lib.Protocol.Buffers;

   Maximum_RSA_Modulus_Bytes : constant Natural := 1025;

   function To_Algorithm_Name
     (Data : Stream_Element_Array; Text : out Unbounded_String) return Status
   is
   begin
      Text := Null_Unbounded_String;
      if Data'Length = 0 then
         return Handshake_Failed;
      end if;
      for Byte_Value of Data loop
         if Byte_Value > 127 then
            Text := Null_Unbounded_String;
            return Handshake_Failed;
         end if;
         Append (Text, Character'Val (Natural (Byte_Value)));
      end loop;
      if not SSH_Lib.Protocol.Validation.Is_ASCII_Protocol_Name
               (To_String (Text))
      then
         Text := Null_Unbounded_String;
         return Handshake_Failed;
      end if;
      return Ok;
   exception
      when others =>
         Text := Null_Unbounded_String;
         return Internal_Error;
   end To_Algorithm_Name;

   function Mpint_Is_Valid_Positive_Nonzero
     (Data : Stream_Element_Array; Is_Modulus : Boolean) return Boolean
   is
      Has_Nonzero : Boolean := False;
   begin
      if Data'Length = 0 then
         return False;
      end if;

      if Is_Modulus and then Data'Length > Maximum_RSA_Modulus_Bytes then
         return False;
      end if;

      if Data (Data'First) >= 16#80# then
         return False;
      end if;

      if Data'Length > 1
        and then Data (Data'First) = 0
        and then Data (Data'First + 1) < 16#80#
      then
         return False;
      end if;

      for Byte_Value of Data loop
         if Byte_Value /= 0 then
            Has_Nonzero := True;
         end if;
      end loop;

      return Has_Nonzero;
   end Mpint_Is_Valid_Positive_Nonzero;

   function Parse_Ed25519
     (Blob   : Stream_Element_Array;
      Cursor : Stream_Element_Offset;
      Item   : out SSH_Lib.Keys.Public_Key) return Status
   is
      Key_Buffer   : Packet_Buffer;
      Next_Index   : Stream_Element_Offset;
      Status_Value : Status;
   begin
      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_SSH_String
          (Blob, Cursor, Key_Buffer, Next_Index);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      if Next_Index /= Blob'Last + 1 then
         return Handshake_Failed;
      end if;
      if Length (Key_Buffer) /= 32 then
         return Handshake_Failed;
      end if;
      return SSH_Lib.Keys.Internal.Set_Public_Key (Item, "ssh-ed25519", Blob);
   end Parse_Ed25519;

   function Parse_ECDSA_Nistp256
     (Blob   : Stream_Element_Array;
      Cursor : Stream_Element_Offset;
      Item   : out SSH_Lib.Keys.Public_Key) return Status
   is
      Curve_Buffer : Packet_Buffer;
      Key_Buffer   : Packet_Buffer;
      After_Curve  : Stream_Element_Offset;
      After_Key    : Stream_Element_Offset;
      Status_Value : Status;
   begin
      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_SSH_String
          (Blob, Cursor, Curve_Buffer, After_Curve);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_SSH_String
          (Blob, After_Curve, Key_Buffer, After_Key);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      if After_Key /= Blob'Last + 1 then
         return Handshake_Failed;
      end if;
      declare
         Curve_Data : constant Stream_Element_Array := To_Array (Curve_Buffer);
         Key_Data   : constant Stream_Element_Array := To_Array (Key_Buffer);
      begin
         if Curve_Data'Length /= 8
           or else
             Curve_Data
             /= [1 => Character'Pos ('n'),
                 2 => Character'Pos ('i'),
                 3 => Character'Pos ('s'),
                 4 => Character'Pos ('t'),
                 5 => Character'Pos ('p'),
                 6 => Character'Pos ('2'),
                 7 => Character'Pos ('5'),
                 8 => Character'Pos ('6')]
         then
            return Handshake_Failed;
         end if;
         if Key_Data'Length /= 65 or else Key_Data (Key_Data'First) /= 16#04#
         then
            return Handshake_Failed;
         end if;
      end;
      Status_Value := SSH_Lib.ECDSA.Validate_Public_Nistp256 (Blob);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      return
        SSH_Lib.Keys.Internal.Set_Public_Key
          (Item, "ecdsa-sha2-nistp256", Blob);
   end Parse_ECDSA_Nistp256;

   function Parse_ECDSA_Nistp521
     (Blob   : Stream_Element_Array;
      Cursor : Stream_Element_Offset;
      Item   : out SSH_Lib.Keys.Public_Key) return Status
   is
      Curve_Buffer : Packet_Buffer;
      Key_Buffer   : Packet_Buffer;
      After_Curve  : Stream_Element_Offset;
      After_Key    : Stream_Element_Offset;
      Status_Value : Status;
   begin
      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_SSH_String
          (Blob, Cursor, Curve_Buffer, After_Curve);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_SSH_String
          (Blob, After_Curve, Key_Buffer, After_Key);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      if After_Key /= Blob'Last + 1 then
         return Handshake_Failed;
      end if;
      declare
         Curve_Data : constant Stream_Element_Array := To_Array (Curve_Buffer);
         Key_Data   : constant Stream_Element_Array := To_Array (Key_Buffer);
      begin
         if Curve_Data'Length /= 8
           or else
             Curve_Data
             /= [1 => Character'Pos ('n'),
                 2 => Character'Pos ('i'),
                 3 => Character'Pos ('s'),
                 4 => Character'Pos ('t'),
                 5 => Character'Pos ('p'),
                 6 => Character'Pos ('5'),
                 7 => Character'Pos ('2'),
                 8 => Character'Pos ('1')]
         then
            return Handshake_Failed;
         end if;
         if Key_Data'Length /= 133 or else Key_Data (Key_Data'First) /= 16#04#
         then
            return Handshake_Failed;
         end if;
      end;
      Status_Value := SSH_Lib.ECDSA.Validate_Public_Nistp521 (Blob);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      return
        SSH_Lib.Keys.Internal.Set_Public_Key
          (Item, "ecdsa-sha2-nistp521", Blob);
   end Parse_ECDSA_Nistp521;

   function Parse_ECDSA_Nistp384
     (Blob   : Stream_Element_Array;
      Cursor : Stream_Element_Offset;
      Item   : out SSH_Lib.Keys.Public_Key) return Status
   is
      Curve_Buffer : Packet_Buffer;
      Key_Buffer   : Packet_Buffer;
      After_Curve  : Stream_Element_Offset;
      After_Key    : Stream_Element_Offset;
      Status_Value : Status;
   begin
      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_SSH_String
          (Blob, Cursor, Curve_Buffer, After_Curve);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_SSH_String
          (Blob, After_Curve, Key_Buffer, After_Key);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      if After_Key /= Blob'Last + 1 then
         return Handshake_Failed;
      end if;
      declare
         Curve_Data : constant Stream_Element_Array := To_Array (Curve_Buffer);
         Key_Data   : constant Stream_Element_Array := To_Array (Key_Buffer);
      begin
         if Curve_Data'Length /= 8
           or else
             Curve_Data
             /= [1 => Character'Pos ('n'),
                 2 => Character'Pos ('i'),
                 3 => Character'Pos ('s'),
                 4 => Character'Pos ('t'),
                 5 => Character'Pos ('p'),
                 6 => Character'Pos ('3'),
                 7 => Character'Pos ('8'),
                 8 => Character'Pos ('4')]
         then
            return Handshake_Failed;
         end if;
         if Key_Data'Length /= 97 or else Key_Data (Key_Data'First) /= 16#04#
         then
            return Handshake_Failed;
         end if;
      end;
      Status_Value := SSH_Lib.ECDSA.Validate_Public_Nistp384 (Blob);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      return
        SSH_Lib.Keys.Internal.Set_Public_Key
          (Item, "ecdsa-sha2-nistp384", Blob);
   end Parse_ECDSA_Nistp384;

   function Application_String_Is_Safe
     (Data : Stream_Element_Array) return Boolean
   is
      Prefix : constant String := "ssh:";
      Cursor : Stream_Element_Offset := Data'First;
   begin
      if Data'Length < Prefix'Length or else Data'Length > 1024 then
         return False;
      end if;

      --  OpenSSH security-key public-key blobs carry an application string.
      --  For SSH keys this must be an SSH application/RP identifier such as
      --  "ssh:" or "ssh:example".  Keep the value text-safe at the protocol
      --  boundary while still treating it as data rather than executing or
      --  expanding it.
      for Character_Value of Prefix loop
         if Data (Cursor) /= Stream_Element (Character'Pos (Character_Value))
         then
            return False;
         end if;
         Cursor := Cursor + 1;
      end loop;

      for Byte_Value of Data loop
         if Byte_Value < 16#20# or else Byte_Value > 16#7E# then
            return False;
         end if;
      end loop;
      return True;
   exception
      when others =>
         return False;
   end Application_String_Is_Safe;

   function Parse_SK_Ed25519
     (Blob   : Stream_Element_Array;
      Cursor : Stream_Element_Offset;
      Item   : out SSH_Lib.Keys.Public_Key) return Status
   is
      Key_Buffer         : Packet_Buffer;
      Application_Buffer : Packet_Buffer;
      After_Key          : Stream_Element_Offset;
      After_App          : Stream_Element_Offset;
      Status_Value       : Status;
   begin
      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_SSH_String
          (Blob, Cursor, Key_Buffer, After_Key);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_SSH_String
          (Blob, After_Key, Application_Buffer, After_App);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      if After_App /= Blob'Last + 1 then
         return Handshake_Failed;
      end if;
      if Length (Key_Buffer) /= 32
        or else not Application_String_Is_Safe (To_Array (Application_Buffer))
      then
         return Handshake_Failed;
      end if;
      return
        SSH_Lib.Keys.Internal.Set_Public_Key
          (Item, "sk-ssh-ed25519@openssh.com", Blob);
   end Parse_SK_Ed25519;

   function Parse_SK_ECDSA_Nistp256
     (Blob   : Stream_Element_Array;
      Cursor : Stream_Element_Offset;
      Item   : out SSH_Lib.Keys.Public_Key) return Status
   is
      Curve_Buffer       : Packet_Buffer;
      Key_Buffer         : Packet_Buffer;
      Application_Buffer : Packet_Buffer;
      After_Curve        : Stream_Element_Offset;
      After_Key          : Stream_Element_Offset;
      After_App          : Stream_Element_Offset;
      Status_Value       : Status;
   begin
      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_SSH_String
          (Blob, Cursor, Curve_Buffer, After_Curve);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_SSH_String
          (Blob, After_Curve, Key_Buffer, After_Key);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_SSH_String
          (Blob, After_Key, Application_Buffer, After_App);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      if After_App /= Blob'Last + 1 then
         return Handshake_Failed;
      end if;
      declare
         Curve_Data : constant Stream_Element_Array := To_Array (Curve_Buffer);
      begin
         if Curve_Data'Length /= 8
           or else
             Curve_Data
             /= [1 => Character'Pos ('n'),
                 2 => Character'Pos ('i'),
                 3 => Character'Pos ('s'),
                 4 => Character'Pos ('t'),
                 5 => Character'Pos ('p'),
                 6 => Character'Pos ('2'),
                 7 => Character'Pos ('5'),
                 8 => Character'Pos ('6')]
           or else
             not Application_String_Is_Safe (To_Array (Application_Buffer))
         then
            return Handshake_Failed;
         end if;
      end;
      Status_Value :=
        SSH_Lib.ECDSA.Validate_Raw_Point_Nistp256
          (To_Array (Key_Buffer));
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      return
        SSH_Lib.Keys.Internal.Set_Public_Key
          (Item, "sk-ecdsa-sha2-nistp256@openssh.com", Blob);
   end Parse_SK_ECDSA_Nistp256;

   function Parse_RSA
     (Blob                 : Stream_Element_Array;
      Cursor               : Stream_Element_Offset;
      Negotiated_Algorithm : String;
      Item                 : out SSH_Lib.Keys.Public_Key) return Status
   is
      Exponent_Buffer : Packet_Buffer;
      Modulus_Buffer  : Packet_Buffer;
      After_Exponent  : Stream_Element_Offset;
      After_Modulus   : Stream_Element_Offset;
      Status_Value    : Status;
   begin
      if Negotiated_Algorithm /= "rsa-sha2-256"
        and then Negotiated_Algorithm /= "rsa-sha2-512"
        and then Negotiated_Algorithm /= "ssh-rsa"
      then
         return Handshake_Failed;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_SSH_String
          (Blob, Cursor, Exponent_Buffer, After_Exponent);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_SSH_String
          (Blob, After_Exponent, Modulus_Buffer, After_Modulus);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      if After_Modulus /= Blob'Last + 1 then
         return Handshake_Failed;
      end if;

      declare
         Exponent_Data : constant Stream_Element_Array :=
           To_Array (Exponent_Buffer);
         Modulus_Data  : constant Stream_Element_Array :=
           To_Array (Modulus_Buffer);
      begin
         if not Mpint_Is_Valid_Positive_Nonzero (Exponent_Data, False)
           or else not Mpint_Is_Valid_Positive_Nonzero (Modulus_Data, True)
         then
            return Handshake_Failed;
         end if;
      end;

      return SSH_Lib.Keys.Internal.Set_Public_Key (Item, "ssh-rsa", Blob);
   end Parse_RSA;

   function Parse
     (Blob                 : Stream_Element_Array;
      Negotiated_Algorithm : String;
      Item                 : out SSH_Lib.Keys.Public_Key) return Status
   is
      Algorithm_Buffer : Packet_Buffer;
      Algorithm_Text   : Unbounded_String;
      Cursor           : Stream_Element_Offset;
      Status_Value     : Status;
   begin
      SSH_Lib.Keys.Internal.Clear (Item);
      if Blob'Length = 0 then
         return Handshake_Failed;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_SSH_String
          (Blob, Blob'First, Algorithm_Buffer, Cursor);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      declare
         Algorithm_Data : constant Stream_Element_Array :=
           To_Array (Algorithm_Buffer);
      begin
         Status_Value := To_Algorithm_Name (Algorithm_Data, Algorithm_Text);
      end;
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      if SSH_Lib.Protocol.Certificates.Is_Certificate_Algorithm
           (To_String (Algorithm_Text))
      then
         if To_String (Algorithm_Text) /= Negotiated_Algorithm then
            return Handshake_Failed;
         end if;
         declare
            Host_Key      : SSH_Lib.Keys.Public_Key;
            Signature_Key : SSH_Lib.Keys.Public_Key;
         begin
            Status_Value :=
              SSH_Lib.Protocol.Certificates.Parse_Host_Certificate
                (Blob, To_String (Algorithm_Text), Host_Key, Signature_Key);
            if Status_Value /= Ok then
               return Status_Value;
            end if;
         end;
         return
           SSH_Lib.Keys.Internal.Set_Public_Key
             (Item, To_String (Algorithm_Text), Blob);
      elsif To_String (Algorithm_Text) = "ssh-ed25519" then
         if Negotiated_Algorithm /= "ssh-ed25519" then
            return Handshake_Failed;
         end if;
         return Parse_Ed25519 (Blob, Cursor, Item);
      elsif To_String (Algorithm_Text) = "ecdsa-sha2-nistp256" then
         if Negotiated_Algorithm /= "ecdsa-sha2-nistp256" then
            return Handshake_Failed;
         end if;
         return Parse_ECDSA_Nistp256 (Blob, Cursor, Item);
      elsif To_String (Algorithm_Text) = "ecdsa-sha2-nistp384" then
         if Negotiated_Algorithm /= "ecdsa-sha2-nistp384" then
            return Handshake_Failed;
         end if;
         return Parse_ECDSA_Nistp384 (Blob, Cursor, Item);
      elsif To_String (Algorithm_Text) = "ecdsa-sha2-nistp521" then
         if Negotiated_Algorithm /= "ecdsa-sha2-nistp521" then
            return Handshake_Failed;
         end if;
         return Parse_ECDSA_Nistp521 (Blob, Cursor, Item);
      elsif To_String (Algorithm_Text) = "sk-ssh-ed25519@openssh.com" then
         if Negotiated_Algorithm /= "sk-ssh-ed25519@openssh.com" then
            return Handshake_Failed;
         end if;
         return Parse_SK_Ed25519 (Blob, Cursor, Item);
      elsif To_String (Algorithm_Text) = "sk-ecdsa-sha2-nistp256@openssh.com"
      then
         if Negotiated_Algorithm /= "sk-ecdsa-sha2-nistp256@openssh.com" then
            return Handshake_Failed;
         end if;
         return Parse_SK_ECDSA_Nistp256 (Blob, Cursor, Item);
      elsif To_String (Algorithm_Text) = "ssh-rsa" then
         return Parse_RSA (Blob, Cursor, Negotiated_Algorithm, Item);
      else
         return Unsupported_Feature;
      end if;
   exception
      when others =>
         SSH_Lib.Keys.Internal.Clear (Item);
         return Internal_Error;
   end Parse;
   function Verify_And_Store
     (Host_Key_Blob        : Stream_Element_Array;
      Signature_Blob       : Stream_Element_Array;
      Negotiated_Algorithm : String;
      Exchange_Hash        : Stream_Element_Array;
      State_Item           : in out SSH_Lib.Protocol.Encrypted_State.Kex_State)
      return Status
   is
      Key_Item       : SSH_Lib.Keys.Public_Key;
      Signature_Item : SSH_Lib.Protocol.Signatures.Parsed_Signature;
      Status_Value   : Status;
   begin
      if SSH_Lib.Protocol.Certificates.Is_Certificate_Algorithm
           (Negotiated_Algorithm)
      then
         declare
            Raw_Key_Item         : SSH_Lib.Keys.Public_Key;
            Signature_Key_Item   : SSH_Lib.Keys.Public_Key;
            Certificate_Key_Item : SSH_Lib.Keys.Public_Key;
            Raw_Algorithm        : constant String :=
              SSH_Lib.Protocol.Certificates.Raw_Algorithm_For_Certificate
                (Negotiated_Algorithm);
         begin
            Status_Value :=
              SSH_Lib.Protocol.Certificates.Parse_Host_Certificate
                (Host_Key_Blob,
                 Negotiated_Algorithm,
                 Raw_Key_Item,
                 Signature_Key_Item);
            if Status_Value /= Ok then
               return Status_Value;
            end if;

            Status_Value :=
              SSH_Lib.Protocol.Signatures.Parse
                (Signature_Blob, Negotiated_Algorithm, Signature_Item);
            if Status_Value /= Ok then
               Status_Value :=
                 SSH_Lib.Protocol.Signatures.Parse
                   (Signature_Blob, Raw_Algorithm, Signature_Item);
            end if;
            if Status_Value /= Ok then
               return Status_Value;
            end if;

            Status_Value :=
              SSH_Lib.Protocol.Signatures.Verify
                (SSH_Lib.Protocol.Signatures.Algorithm (Signature_Item),
                 Raw_Key_Item,
                 Signature_Item,
                 Exchange_Hash);
            if Status_Value /= Ok then
               return Status_Value;
            end if;

            Status_Value :=
              SSH_Lib.Keys.Internal.Set_Public_Key
                (Certificate_Key_Item, Negotiated_Algorithm, Host_Key_Blob);
            if Status_Value /= Ok then
               return Status_Value;
            end if;
            return
              SSH_Lib.Protocol.Encrypted_State.Store_Verified_Host_Key
                (State_Item, Certificate_Key_Item);
         end;
      end if;

      Status_Value := Parse (Host_Key_Blob, Negotiated_Algorithm, Key_Item);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Signatures.Parse
          (Signature_Blob, Negotiated_Algorithm, Signature_Item);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Signatures.Verify
          (Negotiated_Algorithm, Key_Item, Signature_Item, Exchange_Hash);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      return
        SSH_Lib.Protocol.Encrypted_State.Store_Verified_Host_Key
          (State_Item, Key_Item);
   exception
      when others =>
         return Internal_Error;
   end Verify_And_Store;

end SSH_Lib.Protocol.Host_Keys;
