with SSH_Lib.Signatures;
with Interfaces;
with SSH_Lib.ECDSA;
with SSH_Lib.Keys.Internal;
with SSH_Lib.Protocol.Certificates;
with SSH_Lib.Protocol.Numbers;
with SSH_Lib.Protocol.Validation;

package body SSH_Lib.Protocol.Signatures is
   use Ada.Streams;
   use Ada.Strings.Unbounded;
   use CryptoLib.Errors;
   use SSH_Lib.Protocol.Buffers;

   procedure Clear (Item : out Parsed_Signature) is
   begin
      Item.Present := False;
      Item.Algorithm_Text := Null_Unbounded_String;
      SSH_Lib.Protocol.Buffers.Clear (Item.Signature_Data);
   end Clear;

   function Algorithm (Item : Parsed_Signature) return String is
   begin
      return To_String (Item.Algorithm_Text);
   end Algorithm;

   function Bytes
     (Item : Parsed_Signature)
      return Stream_Element_Array
   is
   begin
      return SSH_Lib.Protocol.Buffers.To_Array (Item.Signature_Data);
   end Bytes;

   function To_Algorithm_Name
     (Data : Stream_Element_Array;
      Text : out Unbounded_String)
      return Status
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
      if not SSH_Lib.Protocol.Validation.Is_ASCII_Protocol_Name (To_String (Text)) then
         Text := Null_Unbounded_String;
         return Handshake_Failed;
      end if;
      return Ok;
   exception
      when others =>
         Text := Null_Unbounded_String;
         return Internal_Error;
   end To_Algorithm_Name;

   function Validate_SK_Signature_Payload
     (Algorithm_Name  : String;
      Signature_Bytes : Stream_Element_Array) return Status
   is
      Inner_Signature : Packet_Buffer;
      Cursor          : Stream_Element_Offset;
      Next_Index      : Stream_Element_Offset;
      Counter_Value   : Interfaces.Unsigned_32;
      Status_Value    : Status;
   begin
      if Signature_Bytes'Length < 10 then
         return Handshake_Failed;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_SSH_String
          (Signature_Bytes, Signature_Bytes'First, Inner_Signature, Next_Index);
      if Status_Value /= Ok then
         return Handshake_Failed;
      end if;

      if Next_Index + 4 /= Signature_Bytes'Last then
         return Handshake_Failed;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_Uint32
          (Signature_Bytes, Next_Index + 1, Counter_Value, Cursor);
      if Status_Value /= Ok or else Cursor /= Signature_Bytes'Last + 1 then
         return Handshake_Failed;
      end if;

      declare
         Inner_Data : constant Stream_Element_Array := To_Array (Inner_Signature);
      begin
         if Algorithm_Name = "sk-ssh-ed25519@openssh.com" then
            if Inner_Data'Length /= 64 then
               return Handshake_Failed;
            end if;
         elsif Algorithm_Name = "sk-ecdsa-sha2-nistp256@openssh.com" then
            Status_Value := SSH_Lib.ECDSA.Validate_Signature_Nistp256
              (Inner_Data);
            if Status_Value /= Ok then
               return Status_Value;
            end if;
         else
            return Unsupported_Feature;
         end if;
      end;

      return Ok;
   exception
      when others =>
         return Internal_Error;
   end Validate_SK_Signature_Payload;

   function Parse
     (Blob                 : Stream_Element_Array;
      Negotiated_Algorithm : String;
      Item                 : out Parsed_Signature)
      return Status
   is
      Algorithm_Buffer : Packet_Buffer;
      Signature_Buffer : Packet_Buffer;
      Algorithm_Text : Unbounded_String;
      After_Algorithm : Stream_Element_Offset;
      After_Signature : Stream_Element_Offset;
      Status_Value : Status;
   begin
      Clear (Item);
      if Blob'Length = 0 then
         return Handshake_Failed;
      end if;

      Status_Value := SSH_Lib.Protocol.Numbers.Decode_SSH_String
        (Blob, Blob'First, Algorithm_Buffer, After_Algorithm);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      Status_Value := SSH_Lib.Protocol.Numbers.Decode_SSH_String
        (Blob, After_Algorithm, Signature_Buffer, After_Signature);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      if After_Signature /= Blob'Last + 1 then
         return Handshake_Failed;
      end if;

      declare
         Algorithm_Data : constant Stream_Element_Array := To_Array (Algorithm_Buffer);
      begin
         Status_Value := To_Algorithm_Name (Algorithm_Data, Algorithm_Text);
      end;
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      if To_String (Algorithm_Text) /= Negotiated_Algorithm then
         if SSH_Lib.Protocol.Certificates.Is_Certificate_Algorithm (Negotiated_Algorithm)
           and then To_String (Algorithm_Text) =
             SSH_Lib.Protocol.Certificates.Raw_Algorithm_For_Certificate (Negotiated_Algorithm)
         then
            null;
         else
            return Handshake_Failed;
         end if;
      end if;

      declare
         Effective_Algorithm : constant String :=
           (if SSH_Lib.Protocol.Certificates.Is_Certificate_Algorithm (To_String (Algorithm_Text)) then
               SSH_Lib.Protocol.Certificates.Raw_Algorithm_For_Certificate (To_String (Algorithm_Text))
            else
               To_String (Algorithm_Text));
      begin
         if Effective_Algorithm = "ssh-ed25519" then
            if Length (Signature_Buffer) /= 64 then
               return Handshake_Failed;
            end if;
         elsif Effective_Algorithm = "ecdsa-sha2-nistp256" then
            Status_Value := SSH_Lib.ECDSA.Validate_Signature_Nistp256
              (To_Array (Signature_Buffer));
            if Status_Value /= Ok then
               return Status_Value;
            end if;
         elsif Effective_Algorithm = "ecdsa-sha2-nistp384" then
            Status_Value := SSH_Lib.ECDSA.Validate_Signature_Nistp384
              (To_Array (Signature_Buffer));
            if Status_Value /= Ok then
               return Status_Value;
            end if;
         elsif Effective_Algorithm = "ecdsa-sha2-nistp521" then
            Status_Value := SSH_Lib.ECDSA.Validate_Signature_Nistp521
              (To_Array (Signature_Buffer));
            if Status_Value /= Ok then
               return Status_Value;
            end if;
         elsif Effective_Algorithm = "sk-ssh-ed25519@openssh.com"
           or else Effective_Algorithm = "sk-ecdsa-sha2-nistp256@openssh.com"
         then
            Status_Value :=
              Validate_SK_Signature_Payload
                (Effective_Algorithm, To_Array (Signature_Buffer));
            if Status_Value /= Ok then
               return Status_Value;
            end if;
         elsif Effective_Algorithm = "rsa-sha2-256"
           or else Effective_Algorithm = "rsa-sha2-512"
           or else Effective_Algorithm = "ssh-rsa"
         then
            if Length (Signature_Buffer) = 0 then
               return Handshake_Failed;
            end if;
         else
            return Unsupported_Feature;
         end if;
      end;

      Item.Present := True;
      Item.Algorithm_Text := Algorithm_Text;
      Status_Value := SSH_Lib.Protocol.Buffers.Set
        (Item.Signature_Data, To_Array (Signature_Buffer));
      if Status_Value /= Ok then
         Clear (Item);
         return Status_Value;
      end if;
      return Ok;
   exception
      when others =>
         Clear (Item);
         return Internal_Error;
   end Parse;

   function Verify
     (Negotiated_Algorithm : String;
      Key_Item             : SSH_Lib.Keys.Public_Key;
      Signature_Item       : Parsed_Signature;
      Exchange_Hash        : Stream_Element_Array)
      return Status
   is
   begin
      if not SSH_Lib.Keys.Is_Valid (Key_Item) or else not Signature_Item.Present then
         return Handshake_Failed;
      end if;

      if To_String (Signature_Item.Algorithm_Text) /= Negotiated_Algorithm then
         if SSH_Lib.Protocol.Certificates.Is_Certificate_Algorithm (Negotiated_Algorithm)
           and then To_String (Signature_Item.Algorithm_Text) =
             SSH_Lib.Protocol.Certificates.Raw_Algorithm_For_Certificate (Negotiated_Algorithm)
         then
            null;
         else
            return Handshake_Failed;
         end if;
      end if;

      declare
         Effective_Algorithm : constant String :=
           (if SSH_Lib.Protocol.Certificates.Is_Certificate_Algorithm (Negotiated_Algorithm) then
               SSH_Lib.Protocol.Certificates.Raw_Algorithm_For_Certificate (Negotiated_Algorithm)
            else
               Negotiated_Algorithm);
      begin
         if Effective_Algorithm = "ssh-ed25519"
           and then SSH_Lib.Keys.Algorithm (Key_Item) /= "ssh-ed25519"
         then
            return Handshake_Failed;
         elsif Effective_Algorithm = "ecdsa-sha2-nistp256"
           and then SSH_Lib.Keys.Algorithm (Key_Item) /= "ecdsa-sha2-nistp256"
         then
            return Handshake_Failed;
         elsif Effective_Algorithm = "sk-ssh-ed25519@openssh.com"
           and then SSH_Lib.Keys.Algorithm (Key_Item) /= "sk-ssh-ed25519@openssh.com"
         then
            return Handshake_Failed;
         elsif Effective_Algorithm = "sk-ecdsa-sha2-nistp256@openssh.com"
           and then SSH_Lib.Keys.Algorithm (Key_Item) /= "sk-ecdsa-sha2-nistp256@openssh.com"
         then
            return Handshake_Failed;
         elsif (Effective_Algorithm = "rsa-sha2-256"
                or else Effective_Algorithm = "rsa-sha2-512"
                or else Effective_Algorithm = "ssh-rsa")
           and then SSH_Lib.Keys.Algorithm (Key_Item) /= "ssh-rsa"
         then
            return Handshake_Failed;
         end if;
      end;

      declare
         Signature_Bytes : constant Stream_Element_Array := Bytes (Signature_Item);
      begin
         return SSH_Lib.Signatures.Verify
           (To_String (Signature_Item.Algorithm_Text),
            SSH_Lib.Keys.Internal.Raw_Blob (Key_Item),
            Signature_Bytes,
            Exchange_Hash);
      end;
   exception
      when others =>
         return Internal_Error;
   end Verify;
end SSH_Lib.Protocol.Signatures;
