with SSH_Lib.ECDSA;
with SSH_Lib.Protocol.Numbers;

package body SSH_Lib.Agent.Protocol is

   use Ada.Streams;
   use Interfaces;
   use CryptoLib.Errors;
   use SSH_Lib.Protocol.Buffers;

   function Encode_Message_Length
     (Payload_Length : Natural) return Stream_Element_Array is
   begin
      if Payload_Length = 0
        or else Payload_Length > SSH_Lib.Agent.Max_Agent_Message_Size
      then
         return SSH_Lib.Protocol.Numbers.Encode_Uint32 (0);
      end if;
      return
        SSH_Lib.Protocol.Numbers.Encode_Uint32 (Unsigned_32 (Payload_Length));
   end Encode_Message_Length;

   function Decode_Message_Length
     (Header : Stream_Element_Array; Payload_Length : out Natural)
      return Status
   is
      Cursor       : Stream_Element_Offset;
      Length_Value : Unsigned_32;
      Status_Value : Status;
   begin
      Payload_Length := 0;
      if Header'Length /= 4 then
         return Authentication_Failed;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_Uint32
          (Header, Header'First, Length_Value, Cursor);
      if Status_Value /= Ok then
         return Authentication_Failed;
      end if;

      if Cursor /= Header'Last + 1
        or else Length_Value = 0
        or else
          Length_Value > Unsigned_32 (SSH_Lib.Agent.Max_Agent_Message_Size)
      then
         return Authentication_Failed;
      end if;

      Payload_Length := Natural (Length_Value);
      return Ok;
   exception
      when others =>
         Payload_Length := 0;
         return Internal_Error;
   end Decode_Message_Length;

   function Encode_Request_Identities return Stream_Element_Array is
      Result : constant Stream_Element_Array (1 .. 1) :=
        [1 => SSH_AGENTC_REQUEST_IDENTITIES];
   begin
      return Result;
   end Encode_Request_Identities;

   function String_From_Comment_Octets
     (Payload : Stream_Element_Array; Status_Value : out Status) return String
   is
      Result : String (1 .. Payload'Length);
      Cursor : Positive := Result'First;
   begin
      Status_Value := Ok;
      for Byte_Value of Payload loop
         Result (Cursor) := Character'Val (Natural (Byte_Value));
         Cursor := Cursor + 1;
      end loop;
      return Result;
   exception
      when others =>
         Status_Value := Authentication_Failed;
         return "";
   end String_From_Comment_Octets;

   function Parse_Identities_Answer
     (Payload    : Stream_Element_Array;
      Identities : out SSH_Lib.Agent.Identity_List) return Status
   is
      Cursor       : Stream_Element_Offset;
      Count_Value  : Unsigned_32;
      Next_Index   : Stream_Element_Offset;
      Status_Value : Status;
      Key_Buffer   : Packet_Buffer;
      Comment_Data : Packet_Buffer;
   begin
      SSH_Lib.Agent.Clear (Identities);

      if Payload'Length < 1
        or else Payload'Length > SSH_Lib.Agent.Max_Agent_Message_Size
      then
         return Authentication_Failed;
      end if;

      if Payload (Payload'First) = SSH_AGENT_FAILURE then
         return Authentication_Failed;
      end if;

      if Payload (Payload'First) /= SSH_AGENT_IDENTITIES_ANSWER then
         return Authentication_Failed;
      end if;

      Cursor := Payload'First + 1;
      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_Uint32
          (Payload, Cursor, Count_Value, Next_Index);
      if Status_Value /= Ok then
         return Authentication_Failed;
      end if;

      if Count_Value > Unsigned_32 (SSH_Lib.Agent.Max_Identities) then
         return Authentication_Failed;
      end if;
      Cursor := Next_Index;

      for Identity_Index in 1 .. Natural (Count_Value) loop
         Status_Value :=
           SSH_Lib.Protocol.Numbers.Decode_SSH_String
             (Payload, Cursor, Key_Buffer, Next_Index);
         if Status_Value /= Ok
           or else Length (Key_Buffer) > SSH_Lib.Agent.Max_Public_Key_Blob
         then
            SSH_Lib.Agent.Clear (Identities);
            return Authentication_Failed;
         end if;
         Cursor := Next_Index;

         Status_Value :=
           SSH_Lib.Protocol.Numbers.Decode_SSH_String
             (Payload, Cursor, Comment_Data, Next_Index);
         if Status_Value /= Ok
           or else Length (Comment_Data) > SSH_Lib.Agent.Max_Comment_Length
         then
            SSH_Lib.Agent.Clear (Identities);
            return Authentication_Failed;
         end if;
         Cursor := Next_Index;

         declare
            Comment_Status : Status;
            Comment_Text   : constant String :=
              String_From_Comment_Octets
                (To_Array (Comment_Data), Comment_Status);
         begin
            if Comment_Status /= Ok then
               SSH_Lib.Agent.Clear (Identities);
               return Authentication_Failed;
            end if;

            Status_Value :=
              SSH_Lib.Agent.Add_Identity
                (Identities, To_Array (Key_Buffer), Comment_Text);
            if Status_Value /= Ok then
               SSH_Lib.Agent.Clear (Identities);
               return Authentication_Failed;
            end if;
         end;
      end loop;

      if Cursor /= Payload'Last + 1 then
         SSH_Lib.Agent.Clear (Identities);
         return Authentication_Failed;
      end if;

      return Ok;
   exception
      when others =>
         SSH_Lib.Agent.Clear (Identities);
         return Internal_Error;
   end Parse_Identities_Answer;

   function Signature_Flags_For
     (Public_Key_Algorithm : String) return Unsigned_32 is
   begin
      if Public_Key_Algorithm = "rsa-sha2-256" then
         return SSH_AGENT_RSA_SHA2_256;
      elsif Public_Key_Algorithm = "rsa-sha2-512" then
         return SSH_AGENT_RSA_SHA2_512;
      else
         return 0;
      end if;
   end Signature_Flags_For;

   function Supported_Signature_Algorithm
     (Public_Key_Algorithm : String) return Boolean is
   begin
      return
        Public_Key_Algorithm = "ssh-ed25519"
        or else Public_Key_Algorithm = "ecdsa-sha2-nistp256"
        or else Public_Key_Algorithm = "sk-ssh-ed25519@openssh.com"
        or else Public_Key_Algorithm = "sk-ecdsa-sha2-nistp256@openssh.com"
        or else Public_Key_Algorithm = "sk-ssh-ed25519-cert-v01@openssh.com"
        or else
          Public_Key_Algorithm = "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com"
        or else Public_Key_Algorithm = "rsa-sha2-256"
        or else Public_Key_Algorithm = "rsa-sha2-512"
        or else Public_Key_Algorithm = "ssh-rsa";
   end Supported_Signature_Algorithm;

   function Encode_Sign_Request
     (Key_Blob             : Stream_Element_Array;
      Data_To_Sign         : Stream_Element_Array;
      Public_Key_Algorithm : String) return Packet_Buffer
   is
      Result       : Packet_Buffer;
      Encoded_Key  : constant Packet_Buffer :=
        SSH_Lib.Protocol.Numbers.Encode_SSH_String (Key_Blob);
      Encoded_Data : constant Packet_Buffer :=
        SSH_Lib.Protocol.Numbers.Encode_SSH_String (Data_To_Sign);
      Status_Value : Status;
   begin
      Clear (Result);
      if Key_Blob'Length > SSH_Lib.Agent.Max_Public_Key_Blob
        or else Data_To_Sign'Length > Max_Packet_Length / 2
        or else not Supported_Signature_Algorithm (Public_Key_Algorithm)
      then
         return Result;
      end if;

      Status_Value := Append_Byte (Result, SSH_AGENTC_SIGN_REQUEST);
      if Status_Value = Ok then
         Status_Value := Append (Result, To_Array (Encoded_Key));
      end if;
      if Status_Value = Ok then
         Status_Value := Append (Result, To_Array (Encoded_Data));
      end if;
      if Status_Value = Ok then
         Status_Value :=
           Append
             (Result,
              SSH_Lib.Protocol.Numbers.Encode_Uint32
                (Signature_Flags_For (Public_Key_Algorithm)));
      end if;

      if Status_Value /= Ok then
         Clear (Result);
      end if;
      return Result;
   exception
      when others =>
         Clear (Result);
         return Result;
   end Encode_Sign_Request;

   function Bytes_Equal_Text
     (Data : Stream_Element_Array; Text : String) return Boolean
   is
      Cursor : Stream_Element_Offset := Data'First;
   begin
      if Data'Length /= Text'Length then
         return False;
      end if;

      for Character_Value of Text loop
         if Data (Cursor) /= Stream_Element (Character'Pos (Character_Value))
         then
            return False;
         end if;
         Cursor := Cursor + 1;
      end loop;

      return True;
   end Bytes_Equal_Text;

   function Validate_Security_Key_Signature_Payload
     (Algorithm_Data  : Stream_Element_Array;
      Signature_Bytes : Stream_Element_Array) return Status
   is
      Cursor          : Stream_Element_Offset;
      Next_Index      : Stream_Element_Offset;
      Inner_Signature : Packet_Buffer;
      Counter_Value   : Interfaces.Unsigned_32;
      Status_Value    : Status;
   begin
      if Signature_Bytes'Length < 10 then
         --  string signature || byte flags || uint32 counter
         return Authentication_Failed;
      end if;

      Cursor := Signature_Bytes'First;
      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_SSH_String
          (Signature_Bytes, Cursor, Inner_Signature, Next_Index);
      if Status_Value /= Ok then
         return Authentication_Failed;
      end if;

      --  Flags are a single octet.  The counter is a uint32.  The library does
      --  not interpret user-presence/user-verification policy locally; that is
      --  enforced by the authenticator/agent and the SSH server.  This boundary
      --  only rejects malformed agent signature payloads before building the
      --  USERAUTH_REQUEST.
      if Next_Index + 4 /= Signature_Bytes'Last then
         return Authentication_Failed;
      end if;
      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_Uint32
          (Signature_Bytes, Next_Index + 1, Counter_Value, Cursor);
      if Status_Value /= Ok or else Cursor /= Signature_Bytes'Last + 1 then
         return Authentication_Failed;
      end if;

      declare
         Inner_Data : constant Stream_Element_Array :=
           To_Array (Inner_Signature);
      begin
         if Bytes_Equal_Text (Algorithm_Data, "sk-ssh-ed25519@openssh.com")
           or else
             Bytes_Equal_Text
               (Algorithm_Data, "sk-ssh-ed25519-cert-v01@openssh.com")
         then
            if Inner_Data'Length /= 64 then
               return Authentication_Failed;
            end if;
         elsif Bytes_Equal_Text
                 (Algorithm_Data, "sk-ecdsa-sha2-nistp256@openssh.com")
           or else
             Bytes_Equal_Text
               (Algorithm_Data, "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com")
         then
            Status_Value :=
              SSH_Lib.ECDSA.Validate_Signature_Nistp256 (Inner_Data);
            if Status_Value /= Ok then
               return Authentication_Failed;
            end if;
         else
            return Authentication_Failed;
         end if;
      end;

      return Ok;
   exception
      when others =>
         return Internal_Error;
   end Validate_Security_Key_Signature_Payload;

   function Validate_Signature_Blob
     (Signature_Blob : Packet_Buffer) return Status
   is
      Signature_Data : constant Stream_Element_Array :=
        To_Array (Signature_Blob);
      Cursor         : Stream_Element_Offset;
      Next_Index     : Stream_Element_Offset;
      Name_Buffer    : Packet_Buffer;
      Bytes_Buffer   : Packet_Buffer;
      Status_Value   : Status;
   begin
      if Signature_Data'Length = 0 then
         return Authentication_Failed;
      end if;

      Cursor := Signature_Data'First;
      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_SSH_String
          (Signature_Data, Cursor, Name_Buffer, Next_Index);
      if Status_Value /= Ok or else Length (Name_Buffer) = 0 then
         return Authentication_Failed;
      end if;

      declare
         Algorithm_Data : constant Stream_Element_Array :=
           To_Array (Name_Buffer);
      begin
         for Byte_Value of Algorithm_Data loop
            if Byte_Value > 127 then
               return Authentication_Failed;
            end if;
         end loop;

         if not (Bytes_Equal_Text (Algorithm_Data, "ssh-ed25519")
                 or else
                   Bytes_Equal_Text (Algorithm_Data, "ecdsa-sha2-nistp256")
                 or else
                   Bytes_Equal_Text
                     (Algorithm_Data, "sk-ssh-ed25519@openssh.com")
                 or else
                   Bytes_Equal_Text
                     (Algorithm_Data, "sk-ecdsa-sha2-nistp256@openssh.com")
                 or else
                   Bytes_Equal_Text
                     (Algorithm_Data, "sk-ssh-ed25519-cert-v01@openssh.com")
                 or else
                   Bytes_Equal_Text
                     (Algorithm_Data,
                      "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com")
                 or else Bytes_Equal_Text (Algorithm_Data, "rsa-sha2-256")
                 or else Bytes_Equal_Text (Algorithm_Data, "rsa-sha2-512")
                 or else Bytes_Equal_Text (Algorithm_Data, "ssh-rsa"))
         then
            return Authentication_Failed;
         end if;
      end;

      Cursor := Next_Index;
      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_SSH_String
          (Signature_Data, Cursor, Bytes_Buffer, Next_Index);
      if Status_Value /= Ok or else Length (Bytes_Buffer) = 0 then
         return Authentication_Failed;
      end if;

      if Next_Index /= Signature_Data'Last + 1 then
         return Authentication_Failed;
      end if;

      declare
         Algorithm_Data  : constant Stream_Element_Array :=
           To_Array (Name_Buffer);
         Signature_Bytes : constant Stream_Element_Array :=
           To_Array (Bytes_Buffer);
      begin
         if Bytes_Equal_Text (Algorithm_Data, "ecdsa-sha2-nistp256") then
            Status_Value :=
              SSH_Lib.ECDSA.Validate_Signature_Nistp256 (Signature_Bytes);
            if Status_Value /= Ok then
               return Authentication_Failed;
            end if;
         elsif Bytes_Equal_Text (Algorithm_Data, "sk-ssh-ed25519@openssh.com")
           or else
             Bytes_Equal_Text
               (Algorithm_Data, "sk-ecdsa-sha2-nistp256@openssh.com")
           or else
             Bytes_Equal_Text
               (Algorithm_Data, "sk-ssh-ed25519-cert-v01@openssh.com")
           or else
             Bytes_Equal_Text
               (Algorithm_Data, "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com")
         then
            Status_Value :=
              Validate_Security_Key_Signature_Payload
                (Algorithm_Data, Signature_Bytes);
            if Status_Value /= Ok then
               return Authentication_Failed;
            end if;
         end if;
      end;

      return Ok;
   exception
      when others =>
         return Internal_Error;
   end Validate_Signature_Blob;

   function Validate_Signature_Blob_For_Algorithm
     (Signature_Blob : Packet_Buffer; Expected_Algorithm : String)
      return Status
   is
      Signature_Data : constant Stream_Element_Array :=
        To_Array (Signature_Blob);
      Cursor         : Stream_Element_Offset;
      Next_Index     : Stream_Element_Offset;
      Name_Buffer    : Packet_Buffer;
      Status_Value   : Status;
   begin
      if Expected_Algorithm'Length = 0
        or else not Supported_Signature_Algorithm (Expected_Algorithm)
      then
         return Authentication_Failed;
      end if;

      Status_Value := Validate_Signature_Blob (Signature_Blob);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      Cursor := Signature_Data'First;
      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_SSH_String
          (Signature_Data, Cursor, Name_Buffer, Next_Index);
      if Status_Value /= Ok or else Length (Name_Buffer) = 0 then
         return Authentication_Failed;
      end if;

      declare
         Algorithm_Data : constant Stream_Element_Array :=
           To_Array (Name_Buffer);
      begin
         if not Bytes_Equal_Text (Algorithm_Data, Expected_Algorithm) then
            return Authentication_Failed;
         end if;
      end;

      return Ok;
   exception
      when others =>
         return Internal_Error;
   end Validate_Signature_Blob_For_Algorithm;

   function Parse_Sign_Response
     (Payload : Stream_Element_Array; Signature_Blob : out Packet_Buffer)
      return Status
   is
      Cursor       : Stream_Element_Offset;
      Next_Index   : Stream_Element_Offset;
      Status_Value : Status;
   begin
      Clear (Signature_Blob);

      if Payload'Length < 1
        or else Payload'Length > SSH_Lib.Agent.Max_Agent_Message_Size
      then
         return Authentication_Failed;
      end if;

      if Payload (Payload'First) = SSH_AGENT_FAILURE then
         return Authentication_Failed;
      end if;

      if Payload (Payload'First) /= SSH_AGENT_SIGN_RESPONSE then
         return Authentication_Failed;
      end if;

      Cursor := Payload'First + 1;
      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_SSH_String
          (Payload, Cursor, Signature_Blob, Next_Index);
      if Status_Value /= Ok then
         Clear (Signature_Blob);
         return Authentication_Failed;
      end if;

      if Length (Signature_Blob) = 0 or else Next_Index /= Payload'Last + 1
      then
         Clear (Signature_Blob);
         return Authentication_Failed;
      end if;

      Status_Value := Validate_Signature_Blob (Signature_Blob);
      if Status_Value /= Ok then
         Clear (Signature_Blob);
         return Status_Value;
      end if;

      return Ok;
   exception
      when others =>
         Clear (Signature_Blob);
         return Internal_Error;
   end Parse_Sign_Response;
end SSH_Lib.Agent.Protocol;
