with CryptoLib.Buffers;
with CryptoLib.Ed25519;
with SSH_Lib.ECDSA;
with SSH_Lib.RSA;
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
