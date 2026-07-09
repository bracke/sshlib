with CryptoLib.Buffers;
with CryptoLib.Ed25519;
with CryptoLib.Hashes;
with Interfaces;
with SSH_Lib.ECDSA;
with SSH_Lib.RSA;
with SSH_Lib.Protocol.Buffers;
with SSH_Lib.Protocol.Numbers;
with SSH_Lib.Protocol.Certificates;

package body SSH_Lib.Signatures is

   use Ada.Streams;
   use CryptoLib.Errors;

   function Extract_Ed25519_Public_Key
     (Public_Key_Blob  : Stream_Element_Array;
      Public_Key_Bytes : out Stream_Element_Array) return Status
   is
      Algorithm_Buffer : CryptoLib.Buffers.Packet_Buffer;
      Key_Buffer       : CryptoLib.Buffers.Packet_Buffer;
      After_Algorithm  : Stream_Element_Offset;
      After_Key        : Stream_Element_Offset;
      Status_Value     : Status;
   begin
      if Public_Key_Bytes'Length /= CryptoLib.Ed25519.Public_Key_Length
      then
         return Internal_Error;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_SSH_String
          (Public_Key_Blob,
           Public_Key_Blob'First,
           Algorithm_Buffer,
           After_Algorithm);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      if CryptoLib.Buffers.To_Array (Algorithm_Buffer)
        /= [1  => Character'Pos ('s'),
            2  => Character'Pos ('s'),
            3  => Character'Pos ('h'),
            4  => Character'Pos ('-'),
            5  => Character'Pos ('e'),
            6  => Character'Pos ('d'),
            7  => Character'Pos ('2'),
            8  => Character'Pos ('5'),
            9  => Character'Pos ('5'),
            10 => Character'Pos ('1'),
            11 => Character'Pos ('9')]
      then
         return Handshake_Failed;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_SSH_String
          (Public_Key_Blob, After_Algorithm, Key_Buffer, After_Key);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      if After_Key /= Public_Key_Blob'Last + 1 then
         return Handshake_Failed;
      end if;
      if CryptoLib.Buffers.Length (Key_Buffer)
        /= Public_Key_Bytes'Length
      then
         return Handshake_Failed;
      end if;

      Public_Key_Bytes := CryptoLib.Buffers.To_Array (Key_Buffer);
      return Ok;
   exception
      when others =>
         return Internal_Error;
   end Extract_Ed25519_Public_Key;

   function Bytes_From_String (Value : String) return Stream_Element_Array is
      Result : Stream_Element_Array (1 .. Stream_Element_Offset (Value'Length));
   begin
      for Index_Value in Value'Range loop
         Result
           (Stream_Element_Offset (Index_Value - Value'First + 1)) :=
             Stream_Element (Character'Pos (Value (Index_Value)));
      end loop;
      return Result;
   end Bytes_From_String;

   function Build_ECDSA_Nistp256_Blob
     (Point_Data : Stream_Element_Array) return Stream_Element_Array
   is
      Result       : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Status_Value : Status;
   begin
      SSH_Lib.Protocol.Buffers.Clear (Result);
      Status_Value := SSH_Lib.Protocol.Buffers.Append
        (Result,
         SSH_Lib.Protocol.Buffers.To_Array
           (SSH_Lib.Protocol.Numbers.Encode_SSH_String
              (Bytes_From_String ("ecdsa-sha2-nistp256"))));
      if Status_Value = Ok then
         Status_Value := SSH_Lib.Protocol.Buffers.Append
           (Result,
            SSH_Lib.Protocol.Buffers.To_Array
              (SSH_Lib.Protocol.Numbers.Encode_SSH_String
                 (Bytes_From_String ("nistp256"))));
      end if;
      if Status_Value = Ok then
         Status_Value := SSH_Lib.Protocol.Buffers.Append
           (Result,
            SSH_Lib.Protocol.Buffers.To_Array
              (SSH_Lib.Protocol.Numbers.Encode_SSH_String (Point_Data)));
      end if;
      if Status_Value /= Ok then
         return Empty : Stream_Element_Array (1 .. 0);
      end if;
      return SSH_Lib.Protocol.Buffers.To_Array (Result);
   exception
      when others =>
         return Empty : Stream_Element_Array (1 .. 0);
   end Build_ECDSA_Nistp256_Blob;

   function Parse_SK_Ed25519_Key
     (Public_Key_Blob  : Stream_Element_Array;
      Public_Key_Bytes : out Stream_Element_Array;
      Application_Data : out CryptoLib.Buffers.Packet_Buffer) return Status
   is
      Algorithm_Buffer : CryptoLib.Buffers.Packet_Buffer;
      Key_Buffer       : CryptoLib.Buffers.Packet_Buffer;
      After_Algorithm  : Stream_Element_Offset;
      After_Key        : Stream_Element_Offset;
      After_App        : Stream_Element_Offset;
      Status_Value     : Status;
   begin
      CryptoLib.Buffers.Clear (Application_Data);
      if Public_Key_Bytes'Length /= CryptoLib.Ed25519.Public_Key_Length then
         return Internal_Error;
      end if;

      Status_Value := SSH_Lib.Protocol.Numbers.Decode_SSH_String
        (Public_Key_Blob, Public_Key_Blob'First, Algorithm_Buffer, After_Algorithm);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      if CryptoLib.Buffers.To_Array (Algorithm_Buffer)
        /= Bytes_From_String ("sk-ssh-ed25519@openssh.com")
      then
         return Handshake_Failed;
      end if;

      Status_Value := SSH_Lib.Protocol.Numbers.Decode_SSH_String
        (Public_Key_Blob, After_Algorithm, Key_Buffer, After_Key);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      if CryptoLib.Buffers.Length (Key_Buffer) /= Public_Key_Bytes'Length then
         return Handshake_Failed;
      end if;
      Status_Value := SSH_Lib.Protocol.Numbers.Decode_SSH_String
        (Public_Key_Blob, After_Key, Application_Data, After_App);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      if After_App /= Public_Key_Blob'Last + 1 then
         return Handshake_Failed;
      end if;
      Public_Key_Bytes := CryptoLib.Buffers.To_Array (Key_Buffer);
      return Ok;
   exception
      when others =>
         CryptoLib.Buffers.Clear (Application_Data);
         return Internal_Error;
   end Parse_SK_Ed25519_Key;

   function Parse_SK_ECDSA_Key
     (Public_Key_Blob  : Stream_Element_Array;
      Point_Data       : out CryptoLib.Buffers.Packet_Buffer;
      Application_Data : out CryptoLib.Buffers.Packet_Buffer) return Status
   is
      Algorithm_Buffer : CryptoLib.Buffers.Packet_Buffer;
      Curve_Buffer     : CryptoLib.Buffers.Packet_Buffer;
      After_Algorithm  : Stream_Element_Offset;
      After_Curve      : Stream_Element_Offset;
      After_Point      : Stream_Element_Offset;
      After_App        : Stream_Element_Offset;
      Status_Value     : Status;
   begin
      CryptoLib.Buffers.Clear (Point_Data);
      CryptoLib.Buffers.Clear (Application_Data);
      Status_Value := SSH_Lib.Protocol.Numbers.Decode_SSH_String
        (Public_Key_Blob, Public_Key_Blob'First, Algorithm_Buffer, After_Algorithm);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      if CryptoLib.Buffers.To_Array (Algorithm_Buffer)
        /= Bytes_From_String ("sk-ecdsa-sha2-nistp256@openssh.com")
      then
         return Handshake_Failed;
      end if;
      Status_Value := SSH_Lib.Protocol.Numbers.Decode_SSH_String
        (Public_Key_Blob, After_Algorithm, Curve_Buffer, After_Curve);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      if CryptoLib.Buffers.To_Array (Curve_Buffer) /= Bytes_From_String ("nistp256") then
         return Handshake_Failed;
      end if;
      Status_Value := SSH_Lib.Protocol.Numbers.Decode_SSH_String
        (Public_Key_Blob, After_Curve, Point_Data, After_Point);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Status_Value := SSH_Lib.Protocol.Numbers.Decode_SSH_String
        (Public_Key_Blob, After_Point, Application_Data, After_App);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      if After_App /= Public_Key_Blob'Last + 1 then
         return Handshake_Failed;
      end if;
      return Ok;
   exception
      when others =>
         CryptoLib.Buffers.Clear (Point_Data);
         CryptoLib.Buffers.Clear (Application_Data);
         return Internal_Error;
   end Parse_SK_ECDSA_Key;

   function Parse_SK_Signature
     (Signature_Bytes : Stream_Element_Array;
      Inner_Signature : out CryptoLib.Buffers.Packet_Buffer;
      Flags_Value     : out Stream_Element;
      Counter_Bytes   : out Stream_Element_Array) return Status
   is
      Next_Index    : Stream_Element_Offset;
      Counter_Value : Interfaces.Unsigned_32;
      Cursor        : Stream_Element_Offset;
      Status_Value  : Status;
   begin
      CryptoLib.Buffers.Clear (Inner_Signature);
      Flags_Value := 0;
      Counter_Bytes := [others => 0];
      if Counter_Bytes'Length /= 4 then
         return Internal_Error;
      end if;
      Status_Value := SSH_Lib.Protocol.Numbers.Decode_SSH_String
        (Signature_Bytes, Signature_Bytes'First, Inner_Signature, Next_Index);
      if Status_Value /= Ok then
         return Handshake_Failed;
      end if;
      if Next_Index + 4 /= Signature_Bytes'Last then
         return Handshake_Failed;
      end if;
      Flags_Value := Signature_Bytes (Next_Index);
      Status_Value := SSH_Lib.Protocol.Numbers.Decode_Uint32
        (Signature_Bytes, Next_Index + 1, Counter_Value, Cursor);
      if Status_Value /= Ok or else Cursor /= Signature_Bytes'Last + 1 then
         return Handshake_Failed;
      end if;
      Counter_Bytes := SSH_Lib.Protocol.Numbers.Encode_Uint32 (Counter_Value);
      return Ok;
   exception
      when others =>
         CryptoLib.Buffers.Clear (Inner_Signature);
         return Internal_Error;
   end Parse_SK_Signature;

   function SK_Signed_Data
     (Application_Data : Stream_Element_Array;
      Flags_Value      : Stream_Element;
      Counter_Bytes    : Stream_Element_Array;
      Message_Bytes    : Stream_Element_Array) return Stream_Element_Array
   is
      App_Hash : constant CryptoLib.Hashes.SHA256_Digest :=
        CryptoLib.Hashes.SHA256 (Application_Data);
      Msg_Hash : constant CryptoLib.Hashes.SHA256_Digest :=
        CryptoLib.Hashes.SHA256 (Message_Bytes);
   begin
      return Result : Stream_Element_Array (1 .. 69) do
         for Index_Value in App_Hash'Range loop
            Result (Stream_Element_Offset (Index_Value)) :=
              App_Hash (Index_Value);
         end loop;
         Result (33) := Flags_Value;
         Result (34 .. 37) := Counter_Bytes;
         for Index_Value in Msg_Hash'Range loop
            Result (37 + Stream_Element_Offset (Index_Value)) :=
              Msg_Hash (Index_Value);
         end loop;
      end return;
   end SK_Signed_Data;

   function Verify
     (Algorithm_Name  : String;
      Public_Key_Blob : Stream_Element_Array;
      Signature_Bytes : Stream_Element_Array;
      Message_Bytes   : Stream_Element_Array) return Status
   is
      Ed_Public_Key :
        Stream_Element_Array
          (Stream_Element_Offset'(1) ..
           Stream_Element_Offset (CryptoLib.Ed25519.Public_Key_Length));
      Status_Value  : Status;
   begin
      declare
         Effective_Algorithm : constant String :=
           (if SSH_Lib.Protocol.Certificates.Is_Certificate_Algorithm
                 (Algorithm_Name)
            then
              SSH_Lib.Protocol.Certificates.Raw_Algorithm_For_Certificate
                (Algorithm_Name)
            else Algorithm_Name);
      begin
         if Effective_Algorithm = "ssh-ed25519" then
            Status_Value :=
              Extract_Ed25519_Public_Key (Public_Key_Blob, Ed_Public_Key);
            if Status_Value /= Ok then
               return Status_Value;
            end if;
            return
              CryptoLib.Ed25519.Verify
                (Ed_Public_Key, Signature_Bytes, Message_Bytes);
         elsif Effective_Algorithm = "ecdsa-sha2-nistp256" then
            return
              SSH_Lib.ECDSA.Verify_Nistp256
                (Public_Key_Blob, Signature_Bytes, Message_Bytes);
         elsif Effective_Algorithm = "ecdsa-sha2-nistp384" then
            return
              SSH_Lib.ECDSA.Verify_Nistp384
                (Public_Key_Blob, Signature_Bytes, Message_Bytes);
         elsif Effective_Algorithm = "ecdsa-sha2-nistp521" then
            return
              SSH_Lib.ECDSA.Verify_Nistp521
                (Public_Key_Blob, Signature_Bytes, Message_Bytes);
         elsif Effective_Algorithm = "sk-ssh-ed25519@openssh.com" then
            declare
               App_Buffer       : CryptoLib.Buffers.Packet_Buffer;
               Inner_Signature  : CryptoLib.Buffers.Packet_Buffer;
               Flags_Value      : Stream_Element;
               Counter_Bytes    : Stream_Element_Array (1 .. 4);
            begin
               Status_Value :=
                 Parse_SK_Ed25519_Key
                   (Public_Key_Blob, Ed_Public_Key, App_Buffer);
               if Status_Value /= Ok then
                  return Status_Value;
               end if;
               Status_Value :=
                 Parse_SK_Signature
                   (Signature_Bytes,
                    Inner_Signature,
                    Flags_Value,
                    Counter_Bytes);
               if Status_Value /= Ok then
                  return Status_Value;
               end if;
               return
                 CryptoLib.Ed25519.Verify
                   (Ed_Public_Key,
                    CryptoLib.Buffers.To_Array (Inner_Signature),
                    SK_Signed_Data
                      (CryptoLib.Buffers.To_Array (App_Buffer),
                       Flags_Value,
                       Counter_Bytes,
                       Message_Bytes));
            end;
         elsif Effective_Algorithm = "sk-ecdsa-sha2-nistp256@openssh.com" then
            declare
               Point_Buffer     : CryptoLib.Buffers.Packet_Buffer;
               App_Buffer       : CryptoLib.Buffers.Packet_Buffer;
               Inner_Signature  : CryptoLib.Buffers.Packet_Buffer;
               Flags_Value      : Stream_Element;
               Counter_Bytes    : Stream_Element_Array (1 .. 4);
            begin
               Status_Value :=
                 Parse_SK_ECDSA_Key
                   (Public_Key_Blob, Point_Buffer, App_Buffer);
               if Status_Value /= Ok then
                  return Status_Value;
               end if;
               Status_Value :=
                 Parse_SK_Signature
                   (Signature_Bytes,
                    Inner_Signature,
                    Flags_Value,
                    Counter_Bytes);
               if Status_Value /= Ok then
                  return Status_Value;
               end if;
               declare
                  ECDSA_Blob : constant Stream_Element_Array :=
                    Build_ECDSA_Nistp256_Blob
                      (CryptoLib.Buffers.To_Array (Point_Buffer));
               begin
                  if ECDSA_Blob'Length = 0 then
                     return Internal_Error;
                  end if;
                  return
                    SSH_Lib.ECDSA.Verify_Nistp256
                      (ECDSA_Blob,
                       CryptoLib.Buffers.To_Array (Inner_Signature),
                       SK_Signed_Data
                         (CryptoLib.Buffers.To_Array (App_Buffer),
                          Flags_Value,
                          Counter_Bytes,
                          Message_Bytes));
               end;
            end;
         elsif Effective_Algorithm = "rsa-sha2-256"
           or else Effective_Algorithm = "rsa-sha2-512"
         then
            return
              SSH_Lib.RSA.Verify_SHA2
                (Effective_Algorithm,
                 Public_Key_Blob,
                 Signature_Bytes,
                 Message_Bytes);
         elsif Effective_Algorithm = "ssh-rsa" then
            return
              SSH_Lib.RSA.Verify_SHA1
                (Public_Key_Blob, Signature_Bytes, Message_Bytes);
         else
            return Unsupported_Feature;
         end if;
      end;
   exception
      when others =>
         return Internal_Error;
   end Verify;
end SSH_Lib.Signatures;
