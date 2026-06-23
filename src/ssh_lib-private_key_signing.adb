with SSH_Lib.ECDSA;
with CryptoLib.Ed25519;
with SSH_Lib.RSA;
with SSH_Lib.Identity_Files.Signing_Access;
with SSH_Lib.Protocol.Numbers;

package body SSH_Lib.Private_Key_Signing is
   use Ada.Streams;
   use CryptoLib.Errors;
   use CryptoLib.Buffers;
   use type SSH_Lib.Identity_Files.Key_Kind;

   function String_Data (Value : String) return Stream_Element_Array is
      Result : Stream_Element_Array (1 .. Value'Length);
      Cursor : Stream_Element_Offset := Result'First;
   begin
      for Character_Value of Value loop
         Result (Cursor) := Stream_Element (Character'Pos (Character_Value));
         Cursor := Cursor + 1;
      end loop;
      return Result;
   end String_Data;

   function Has_RSA_CRT_Components
     (Key : SSH_Lib.Identity_Files.Identity_Key)
      return Boolean
   is
   begin
      return SSH_Lib.Identity_Files.Signing_Access.RSA_Prime_P (Key)'Length > 0
        and then SSH_Lib.Identity_Files.Signing_Access.RSA_Prime_Q (Key)'Length > 0
        and then SSH_Lib.Identity_Files.Signing_Access.RSA_Exponent_DMP1 (Key)'Length > 0
        and then SSH_Lib.Identity_Files.Signing_Access.RSA_Exponent_DMQ1 (Key)'Length > 0
        and then SSH_Lib.Identity_Files.Signing_Access.RSA_Coefficient_IQMP (Key)'Length > 0;
   exception
      when others =>
         return False;
   end Has_RSA_CRT_Components;

   function Supports_Algorithm
     (Key                  : SSH_Lib.Identity_Files.Identity_Key;
      Public_Key_Algorithm : String)
      return Boolean
   is
      Key_Algorithm : constant String := SSH_Lib.Identity_Files.Algorithm_Name (Key);
   begin
      if SSH_Lib.Identity_Files.Kind (Key) = SSH_Lib.Identity_Files.No_Key then
         return False;
      end if;
      if Key_Algorithm = "ssh-ed25519" then
         return Public_Key_Algorithm = "ssh-ed25519";
      elsif Key_Algorithm = "ecdsa-sha2-nistp256" then
         return Public_Key_Algorithm = "ecdsa-sha2-nistp256";
      elsif Key_Algorithm = "ssh-rsa" then
         return Public_Key_Algorithm = "rsa-sha2-256"
           or else Public_Key_Algorithm = "rsa-sha2-512"
           or else Public_Key_Algorithm = "ssh-rsa";
      else
         return False;
      end if;
   exception
      when others =>
         return False;
   end Supports_Algorithm;

   function Can_Sign_Userauth
     (Key                  : SSH_Lib.Identity_Files.Identity_Key;
      Public_Key_Algorithm : String)
      return Boolean
   is
   begin
      if not Supports_Algorithm (Key, Public_Key_Algorithm) then
         return False;
      end if;

      if SSH_Lib.Identity_Files.Kind (Key) = SSH_Lib.Identity_Files.Ed25519_Key then
         return SSH_Lib.Identity_Files.Signing_Access.Ed25519_Seed (Key)'Length = 32
           and then SSH_Lib.Identity_Files.Signing_Access.Ed25519_Public (Key)'Length = 32;
      elsif SSH_Lib.Identity_Files.Kind (Key) = SSH_Lib.Identity_Files.ECDSA_Nistp256_Key then
         return Public_Key_Algorithm = "ecdsa-sha2-nistp256"
           and then SSH_Lib.Identity_Files.Signing_Access.ECDSA_Private (Key)'Length > 0;
      elsif SSH_Lib.Identity_Files.Kind (Key) = SSH_Lib.Identity_Files.RSA_Key then
         return (Public_Key_Algorithm = "rsa-sha2-256"
                 or else Public_Key_Algorithm = "rsa-sha2-512"
                 or else Public_Key_Algorithm = "ssh-rsa")
           and then SSH_Lib.Identity_Files.Signing_Access.RSA_Exponent (Key)'Length > 0
           and then SSH_Lib.Identity_Files.Signing_Access.RSA_Modulus (Key)'Length > 0
           and then SSH_Lib.Identity_Files.Signing_Access.RSA_Private_Exponent (Key)'Length > 0;
      end if;

      return False;
   exception
      when others =>
         return False;
   end Can_Sign_Userauth;

   function Build_Ed25519_Signature
     (Key     : SSH_Lib.Identity_Files.Identity_Key;
      Payload : Stream_Element_Array;
      Output  : out Packet_Buffer)
      return Status
   is
      Seed_Data   : Stream_Element_Array :=
        SSH_Lib.Identity_Files.Signing_Access.Ed25519_Seed (Key);
      Public_Data : constant Stream_Element_Array :=
        SSH_Lib.Identity_Files.Signing_Access.Ed25519_Public (Key);
      Signature_Data : Stream_Element_Array (1 .. 64);
      Status_Value : Status;
      Alg_Buffer : constant Packet_Buffer :=
        SSH_Lib.Protocol.Numbers.Encode_SSH_String
          (String_Data ("ssh-ed25519"));
      Sig_Buffer : Packet_Buffer;
   begin
      Status_Value :=
        CryptoLib.Ed25519.Sign
          (Seed_Data, Public_Data, Payload, Signature_Data);
      Seed_Data := [others => 0];
      if Status_Value /= Ok then
         Signature_Data := [others => 0];
         Clear (Output);
         return Status_Value;
      end if;

      Status_Value := Set (Sig_Buffer, Signature_Data);
      Signature_Data := [others => 0];
      if Status_Value /= Ok then
         Clear (Output);
         return Status_Value;
      end if;

      Clear (Output);
      Status_Value := Append (Output, To_Array (Alg_Buffer));
      if Status_Value /= Ok then
         Clear (Output);
         Clear (Sig_Buffer);
         return Status_Value;
      end if;
      declare
         Encoded_Signature : constant Packet_Buffer :=
           SSH_Lib.Protocol.Numbers.Encode_SSH_String (To_Array (Sig_Buffer));
      begin
         Status_Value := Append (Output, To_Array (Encoded_Signature));
      end;
      Clear (Sig_Buffer);
      if Status_Value /= Ok then
         Clear (Output);
      end if;
      return Status_Value;
   exception
      when others =>
         if Seed_Data'Length > 0 then
            Seed_Data := [others => 0];
         end if;
         Clear (Output);
         return Internal_Error;
   end Build_Ed25519_Signature;

   function Build_RSA_SHA1_Signature
     (Key     : SSH_Lib.Identity_Files.Identity_Key;
      Payload : Stream_Element_Array;
      Output  : out Packet_Buffer)
      return Status
   is
      Raw_Signature : Packet_Buffer;
      Alg_Buffer : constant Packet_Buffer :=
        SSH_Lib.Protocol.Numbers.Encode_SSH_String
          (String_Data ("ssh-rsa"));
      Status_Value : Status;
   begin
      Clear (Output);
      if Has_RSA_CRT_Components (Key) then
         Status_Value := SSH_Lib.RSA.Sign_SHA1_CRT
           (SSH_Lib.Identity_Files.Public_Key_Blob (Key),
            SSH_Lib.Identity_Files.Signing_Access.RSA_Prime_P (Key),
            SSH_Lib.Identity_Files.Signing_Access.RSA_Prime_Q (Key),
            SSH_Lib.Identity_Files.Signing_Access.RSA_Exponent_DMP1 (Key),
            SSH_Lib.Identity_Files.Signing_Access.RSA_Exponent_DMQ1 (Key),
            SSH_Lib.Identity_Files.Signing_Access.RSA_Coefficient_IQMP (Key),
            Payload,
            Raw_Signature);
      else
         Status_Value := SSH_Lib.RSA.Sign_SHA1
           (SSH_Lib.Identity_Files.Public_Key_Blob (Key),
            SSH_Lib.Identity_Files.Signing_Access.RSA_Private_Exponent (Key),
            Payload,
            Raw_Signature);
      end if;
      if Status_Value /= Ok then
         Clear (Raw_Signature);
         return Status_Value;
      end if;

      Status_Value := Append (Output, To_Array (Alg_Buffer));
      if Status_Value /= Ok then
         Clear (Output);
         Clear (Raw_Signature);
         return Status_Value;
      end if;
      declare
         Encoded_Signature : constant Packet_Buffer :=
           SSH_Lib.Protocol.Numbers.Encode_SSH_String (To_Array (Raw_Signature));
      begin
         Status_Value := Append (Output, To_Array (Encoded_Signature));
      end;
      Clear (Raw_Signature);
      if Status_Value /= Ok then
         Clear (Output);
      end if;
      return Status_Value;
   exception
      when others =>
         Clear (Output);
         return Internal_Error;
   end Build_RSA_SHA1_Signature;

   function Build_RSA_SHA2_512_Signature
     (Key     : SSH_Lib.Identity_Files.Identity_Key;
      Payload : Stream_Element_Array;
      Output  : out Packet_Buffer)
      return Status
   is
      Raw_Signature : Packet_Buffer;
      Alg_Buffer : constant Packet_Buffer :=
        SSH_Lib.Protocol.Numbers.Encode_SSH_String
          (String_Data ("rsa-sha2-512"));
      Status_Value : Status;
   begin
      Clear (Output);
      if Has_RSA_CRT_Components (Key) then
         Status_Value := SSH_Lib.RSA.Sign_SHA2_512_CRT
           (SSH_Lib.Identity_Files.Public_Key_Blob (Key),
            SSH_Lib.Identity_Files.Signing_Access.RSA_Prime_P (Key),
            SSH_Lib.Identity_Files.Signing_Access.RSA_Prime_Q (Key),
            SSH_Lib.Identity_Files.Signing_Access.RSA_Exponent_DMP1 (Key),
            SSH_Lib.Identity_Files.Signing_Access.RSA_Exponent_DMQ1 (Key),
            SSH_Lib.Identity_Files.Signing_Access.RSA_Coefficient_IQMP (Key),
            Payload,
            Raw_Signature);
      else
         Status_Value := SSH_Lib.RSA.Sign_SHA2_512
           (SSH_Lib.Identity_Files.Public_Key_Blob (Key),
            SSH_Lib.Identity_Files.Signing_Access.RSA_Private_Exponent (Key),
            Payload,
            Raw_Signature);
      end if;
      if Status_Value /= Ok then
         Clear (Raw_Signature);
         return Status_Value;
      end if;

      Status_Value := Append (Output, To_Array (Alg_Buffer));
      if Status_Value /= Ok then
         Clear (Output);
         Clear (Raw_Signature);
         return Status_Value;
      end if;
      declare
         Encoded_Signature : constant Packet_Buffer :=
           SSH_Lib.Protocol.Numbers.Encode_SSH_String (To_Array (Raw_Signature));
      begin
         Status_Value := Append (Output, To_Array (Encoded_Signature));
      end;
      Clear (Raw_Signature);
      if Status_Value /= Ok then
         Clear (Output);
      end if;
      return Status_Value;
   exception
      when others =>
         Clear (Output);
         return Internal_Error;
   end Build_RSA_SHA2_512_Signature;

   function Build_RSA_SHA2_256_Signature
     (Key     : SSH_Lib.Identity_Files.Identity_Key;
      Payload : Stream_Element_Array;
      Output  : out Packet_Buffer)
      return Status
   is
      Raw_Signature : Packet_Buffer;
      Alg_Buffer : constant Packet_Buffer :=
        SSH_Lib.Protocol.Numbers.Encode_SSH_String
          (String_Data ("rsa-sha2-256"));
      Status_Value : Status;
   begin
      Clear (Output);
      if Has_RSA_CRT_Components (Key) then
         Status_Value := SSH_Lib.RSA.Sign_SHA2_256_CRT
           (SSH_Lib.Identity_Files.Public_Key_Blob (Key),
            SSH_Lib.Identity_Files.Signing_Access.RSA_Prime_P (Key),
            SSH_Lib.Identity_Files.Signing_Access.RSA_Prime_Q (Key),
            SSH_Lib.Identity_Files.Signing_Access.RSA_Exponent_DMP1 (Key),
            SSH_Lib.Identity_Files.Signing_Access.RSA_Exponent_DMQ1 (Key),
            SSH_Lib.Identity_Files.Signing_Access.RSA_Coefficient_IQMP (Key),
            Payload,
            Raw_Signature);
      else
         Status_Value := SSH_Lib.RSA.Sign_SHA2_256
           (SSH_Lib.Identity_Files.Public_Key_Blob (Key),
            SSH_Lib.Identity_Files.Signing_Access.RSA_Private_Exponent (Key),
            Payload,
            Raw_Signature);
      end if;
      if Status_Value /= Ok then
         Clear (Raw_Signature);
         return Status_Value;
      end if;

      Status_Value := Append (Output, To_Array (Alg_Buffer));
      if Status_Value /= Ok then
         Clear (Output);
         Clear (Raw_Signature);
         return Status_Value;
      end if;
      declare
         Encoded_Signature : constant Packet_Buffer :=
           SSH_Lib.Protocol.Numbers.Encode_SSH_String (To_Array (Raw_Signature));
      begin
         Status_Value := Append (Output, To_Array (Encoded_Signature));
      end;
      Clear (Raw_Signature);
      if Status_Value /= Ok then
         Clear (Output);
      end if;
      return Status_Value;
   exception
      when others =>
         Clear (Output);
         return Internal_Error;
   end Build_RSA_SHA2_256_Signature;

   function Build_ECDSA_Nistp256_Signature
     (Key     : SSH_Lib.Identity_Files.Identity_Key;
      Payload : Stream_Element_Array;
      Output  : out Packet_Buffer)
      return Status
   is
      Raw_Signature : Packet_Buffer;
      Alg_Buffer : constant Packet_Buffer :=
        SSH_Lib.Protocol.Numbers.Encode_SSH_String
          (String_Data ("ecdsa-sha2-nistp256"));
      Encoded_Signature : Packet_Buffer;
      Status_Value : Status;
   begin
      Clear (Output);
      Status_Value := Append (Output, To_Array (Alg_Buffer));
      if Status_Value /= Ok then
         Clear (Output);
         return Status_Value;
      end if;
      Status_Value := SSH_Lib.ECDSA.Sign_Nistp256
        (SSH_Lib.Identity_Files.Signing_Access.ECDSA_Private (Key),
         Payload,
         Raw_Signature);
      if Status_Value /= Ok then
         Clear (Raw_Signature);
         Clear (Output);
         return Status_Value;
      end if;
      Encoded_Signature := SSH_Lib.Protocol.Numbers.Encode_SSH_String
        (To_Array (Raw_Signature));
      Status_Value := Append (Output, To_Array (Encoded_Signature));
      Clear (Raw_Signature);
      if Status_Value /= Ok then
         Clear (Output);
      end if;
      return Status_Value;
   exception
      when others =>
         Clear (Output);
         return Internal_Error;
   end Build_ECDSA_Nistp256_Signature;

   function Sign_Userauth
     (Key                  : SSH_Lib.Identity_Files.Identity_Key;
      Public_Key_Algorithm : String;
      Payload              : Ada.Streams.Stream_Element_Array;
      Signature_Blob       : out CryptoLib.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status
   is
   begin
      CryptoLib.Buffers.Clear (Signature_Blob);
      if SSH_Lib.Identity_Files.Kind (Key) = SSH_Lib.Identity_Files.No_Key then
         return Authentication_Failed;
      end if;
      if not Supports_Algorithm (Key, Public_Key_Algorithm) then
         return Authentication_Failed;
      end if;
      if not Can_Sign_Userauth (Key, Public_Key_Algorithm) then
         return Unsupported_Feature;
      end if;
      if Public_Key_Algorithm = "ssh-ed25519" then
         return Build_Ed25519_Signature (Key, Payload, Signature_Blob);
      elsif Public_Key_Algorithm = "ecdsa-sha2-nistp256" then
         return Build_ECDSA_Nistp256_Signature (Key, Payload, Signature_Blob);
      elsif Public_Key_Algorithm = "rsa-sha2-256" then
         return Build_RSA_SHA2_256_Signature (Key, Payload, Signature_Blob);
      elsif Public_Key_Algorithm = "rsa-sha2-512" then
         return Build_RSA_SHA2_512_Signature (Key, Payload, Signature_Blob);
      elsif Public_Key_Algorithm = "ssh-rsa" then
         return Build_RSA_SHA1_Signature (Key, Payload, Signature_Blob);
      else
         return Unsupported_Feature;
      end if;
   exception
      when others =>
         CryptoLib.Buffers.Clear (Signature_Blob);
         return Internal_Error;
   end Sign_Userauth;
end SSH_Lib.Private_Key_Signing;
