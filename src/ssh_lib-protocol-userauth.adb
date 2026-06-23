with SSH_Lib.Protocol.Numbers;
with SSH_Lib.Protocol.Validation;

package body SSH_Lib.Protocol.Userauth is
   use Ada.Streams;
   use type Interfaces.Unsigned_32;
   use CryptoLib.Errors;
   use SSH_Lib.Protocol.Buffers;

   function Valid_Protocol_Text (Value : String) return Boolean is
   begin
      if Value'Length = 0 then
         return False;
      end if;

      for Character_Value of Value loop
         if Character_Value = Character'Val (0)
           or else Character_Value = Character'Val (10)
           or else Character_Value = Character'Val (13)
         then
            return False;
         end if;
      end loop;

      return True;
   end Valid_Protocol_Text;

   function Valid_Keyboard_Interactive_Response_Text
     (Value : String) return Boolean is
   begin
      for Character_Value of Value loop
         if Character_Value = Character'Val (0)
           or else Character_Value = Character'Val (10)
           or else Character_Value = Character'Val (13)
         then
            return False;
         end if;
      end loop;

      return True;
   end Valid_Keyboard_Interactive_Response_Text;

   function Buffer_To_ASCII_String
     (Value : Packet_Buffer) return Ada.Strings.Unbounded.Unbounded_String
   is
      Result : Ada.Strings.Unbounded.Unbounded_String;
   begin
      for Byte_Value of To_Array (Value) loop
         if Byte_Value > 127 then
            return Ada.Strings.Unbounded.Null_Unbounded_String;
         end if;

         Ada.Strings.Unbounded.Append
           (Result, Character'Val (Natural (Byte_Value)));
      end loop;

      return Result;
   end Buffer_To_ASCII_String;

   procedure Clear_Keyboard_Interactive_Reply (Result : in out Reply) is
   begin
      Result.Keyboard_Interactive_Name :=
        Ada.Strings.Unbounded.Null_Unbounded_String;
      Result.Keyboard_Interactive_Instruction :=
        Ada.Strings.Unbounded.Null_Unbounded_String;
      Result.Keyboard_Interactive_Language_Tag :=
        Ada.Strings.Unbounded.Null_Unbounded_String;
      Result.Keyboard_Interactive_Prompts := 0;
      Result.Keyboard_Interactive_Echoes := 0;
      for Prompt_Index in Keyboard_Interactive_Prompt_Index loop
         Result.Keyboard_Interactive_Prompt_Items (Prompt_Index).Text :=
           Ada.Strings.Unbounded.Null_Unbounded_String;
         Result.Keyboard_Interactive_Prompt_Items (Prompt_Index).Echo := False;
      end loop;
   end Clear_Keyboard_Interactive_Reply;

   function Bytes_From_String (Value : String) return Stream_Element_Array is
      Result : Stream_Element_Array (1 .. Value'Length);
      Cursor : Stream_Element_Offset := Result'First;
   begin
      for Character_Value of Value loop
         Result (Cursor) := Stream_Element (Character'Pos (Character_Value));
         Cursor := Cursor + 1;
      end loop;
      return Result;
   end Bytes_From_String;

   function Append_String
     (Item : in out Packet_Buffer; Value : String) return Status
   is
      Encoded_Value : constant Packet_Buffer :=
        SSH_Lib.Protocol.Numbers.Encode_SSH_String (Bytes_From_String (Value));
   begin
      return Append (Item, To_Array (Encoded_Value));
   end Append_String;

   function Append_Binary_String
     (Item : in out Packet_Buffer; Value : Stream_Element_Array) return Status
   is
      Encoded_Value : constant Packet_Buffer :=
        SSH_Lib.Protocol.Numbers.Encode_SSH_String (Value);
   begin
      return Append (Item, To_Array (Encoded_Value));
   end Append_Binary_String;

   function Append_Uint32
     (Item : in out Packet_Buffer; Value : Interfaces.Unsigned_32)
      return Status is
   begin
      return Append (Item, SSH_Lib.Protocol.Numbers.Encode_Uint32 (Value));
   end Append_Uint32;

   function Encode_Publickey_Request
     (User_Name            : String;
      Public_Key_Algorithm : String;
      Public_Key_Blob      : Stream_Element_Array;
      Signature_Blob       : Stream_Element_Array;
      Signed_Request       : Boolean) return Packet_Buffer
   is
      Result       : Packet_Buffer;
      Status_Value : Status;
   begin
      Clear (Result);
      if not Valid_Protocol_Text (User_Name)
        or else
          not SSH_Lib.Protocol.Validation.Is_ASCII_Protocol_Name
                (Public_Key_Algorithm)
        or else Public_Key_Blob'Length = 0
        or else (Signed_Request and then Signature_Blob'Length = 0)
      then
         return Result;
      end if;

      Status_Value := Append_Byte (Result, SSH_MSG_USERAUTH_REQUEST);
      if Status_Value = Ok then
         Status_Value := Append_String (Result, User_Name);
      end if;
      if Status_Value = Ok then
         Status_Value := Append_String (Result, "ssh-connection");
      end if;
      if Status_Value = Ok then
         Status_Value := Append_String (Result, "publickey");
      end if;
      if Status_Value = Ok then
         Status_Value :=
           Append_Byte
             (Result,
              SSH_Lib.Protocol.Numbers.Encode_Boolean (Signed_Request));
      end if;
      if Status_Value = Ok then
         Status_Value := Append_String (Result, Public_Key_Algorithm);
      end if;
      if Status_Value = Ok then
         Status_Value := Append_Binary_String (Result, Public_Key_Blob);
      end if;
      if Status_Value = Ok and then Signed_Request then
         Status_Value := Append_Binary_String (Result, Signature_Blob);
      end if;

      if Status_Value /= Ok then
         Clear (Result);
      end if;
      return Result;
   exception
      when others =>
         Clear (Result);
         return Result;
   end Encode_Publickey_Request;

   function Encode_Publickey_Test_Request
     (User_Name            : String;
      Public_Key_Algorithm : String;
      Public_Key_Blob      : Stream_Element_Array) return Packet_Buffer
   is
      Empty_Signature : constant Stream_Element_Array (1 .. 0) :=
        [others => 0];
   begin
      return
        Encode_Publickey_Request
          (User_Name,
           Public_Key_Algorithm,
           Public_Key_Blob,
           Empty_Signature,
           False);
   end Encode_Publickey_Test_Request;

   function Build_Publickey_Signature_Payload
     (Session_Identifier   : Stream_Element_Array;
      User_Name            : String;
      Public_Key_Algorithm : String;
      Public_Key_Blob      : Stream_Element_Array) return Packet_Buffer
   is
      Result       : Packet_Buffer;
      Status_Value : Status;
   begin
      Clear (Result);
      if Session_Identifier'Length = 0
        or else not Valid_Protocol_Text (User_Name)
        or else
          not SSH_Lib.Protocol.Validation.Is_ASCII_Protocol_Name
                (Public_Key_Algorithm)
        or else Public_Key_Blob'Length = 0
      then
         return Result;
      end if;

      Status_Value := Append_Binary_String (Result, Session_Identifier);
      if Status_Value = Ok then
         Status_Value := Append_Byte (Result, SSH_MSG_USERAUTH_REQUEST);
      end if;
      if Status_Value = Ok then
         Status_Value := Append_String (Result, User_Name);
      end if;
      if Status_Value = Ok then
         Status_Value := Append_String (Result, "ssh-connection");
      end if;
      if Status_Value = Ok then
         Status_Value := Append_String (Result, "publickey");
      end if;
      if Status_Value = Ok then
         Status_Value :=
           Append_Byte
             (Result, SSH_Lib.Protocol.Numbers.Encode_Boolean (True));
      end if;
      if Status_Value = Ok then
         Status_Value := Append_String (Result, Public_Key_Algorithm);
      end if;
      if Status_Value = Ok then
         Status_Value := Append_Binary_String (Result, Public_Key_Blob);
      end if;

      if Status_Value /= Ok then
         Clear (Result);
      end if;
      return Result;
   exception
      when others =>
         Clear (Result);
         return Result;
   end Build_Publickey_Signature_Payload;

   function Encode_Publickey_Signed_Request
     (User_Name            : String;
      Public_Key_Algorithm : String;
      Public_Key_Blob      : Stream_Element_Array;
      Signature_Blob       : Stream_Element_Array) return Packet_Buffer is
   begin
      return
        Encode_Publickey_Request
          (User_Name,
           Public_Key_Algorithm,
           Public_Key_Blob,
           Signature_Blob,
           True);
   end Encode_Publickey_Signed_Request;

   function Skip_Banner (Payload : Stream_Element_Array) return Status is
      Cursor       : Stream_Element_Offset;
      Next_Index   : Stream_Element_Offset;
      Buffer_Value : Packet_Buffer;
      Status_Value : Status;
   begin
      Cursor := Payload'First + 1;
      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_SSH_String
          (Payload, Cursor, Buffer_Value, Next_Index);
      if Status_Value /= Ok then
         return Authentication_Failed;
      end if;
      Cursor := Next_Index;
      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_SSH_String
          (Payload, Cursor, Buffer_Value, Next_Index);
      if Status_Value /= Ok or else Next_Index /= Payload'Last + 1 then
         return Authentication_Failed;
      end if;
      return Ok;
   end Skip_Banner;

   function Parse_PK_OK
     (Payload : Stream_Element_Array; Result : in out Reply) return Status
   is
      Cursor          : Stream_Element_Offset;
      Next_Index      : Stream_Element_Offset;
      Algorithm_Value : Packet_Buffer;
      Status_Value    : Status;
   begin
      Cursor := Payload'First + 1;
      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_SSH_String
          (Payload, Cursor, Algorithm_Value, Next_Index);
      if Status_Value /= Ok or else Length (Algorithm_Value) = 0 then
         return Authentication_Failed;
      end if;

      declare
         Algorithm_Data : constant Stream_Element_Array :=
           To_Array (Algorithm_Value);
      begin
         Result.Public_Key_Algorithm :=
           Ada.Strings.Unbounded.Null_Unbounded_String;
         for Byte_Value of Algorithm_Data loop
            if Byte_Value > 127 then
               return Authentication_Failed;
            end if;
            Ada.Strings.Unbounded.Append
              (Result.Public_Key_Algorithm,
               Character'Val (Natural (Byte_Value)));
         end loop;
      end;

      if not SSH_Lib.Protocol.Validation.Is_ASCII_Protocol_Name
               (Ada.Strings.Unbounded.To_String (Result.Public_Key_Algorithm))
      then
         Result.Public_Key_Algorithm :=
           Ada.Strings.Unbounded.Null_Unbounded_String;
         return Authentication_Failed;
      end if;

      Cursor := Next_Index;
      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_SSH_String
          (Payload, Cursor, Result.Public_Key_Blob, Next_Index);
      if Status_Value /= Ok
        or else Length (Result.Public_Key_Blob) = 0
        or else Next_Index /= Payload'Last + 1
      then
         Result.Public_Key_Algorithm :=
           Ada.Strings.Unbounded.Null_Unbounded_String;
         Clear (Result.Public_Key_Blob);
         return Authentication_Failed;
      end if;

      return Ok;
   end Parse_PK_OK;

   function Skip_Password_Change_Request
     (Payload : Stream_Element_Array) return Status
   is
      Cursor       : Stream_Element_Offset;
      Next_Index   : Stream_Element_Offset;
      Buffer_Value : Packet_Buffer;
      Status_Value : Status;
   begin
      --  RFC 4252 reuses message number 60 for password-change-required
      --  replies after a password request.  SSH_Lib has explicit
      --  caller-invoked credential helpers, but no automatic password-change
      --  workflow, so it validates the packet shape and lets authentication
      --  fail closed.
      Cursor := Payload'First + 1;
      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_SSH_String
          (Payload, Cursor, Buffer_Value, Next_Index);
      if Status_Value /= Ok then
         return Authentication_Failed;
      end if;
      Cursor := Next_Index;
      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_SSH_String
          (Payload, Cursor, Buffer_Value, Next_Index);
      if Status_Value /= Ok or else Next_Index /= Payload'Last + 1 then
         return Authentication_Failed;
      end if;
      return Ok;
   end Skip_Password_Change_Request;

   function Parse_Keyboard_Interactive_Info_Request
     (Payload : Stream_Element_Array; Result : in out Reply) return Status
   is
      Cursor       : Stream_Element_Offset := Payload'First + 1;
      Next_Index   : Stream_Element_Offset;
      Buffer_Value : Packet_Buffer;
      Prompt_Count : Interfaces.Unsigned_32 := 0;
      Echo_Value   : Boolean := False;
      Status_Value : Status;

      function Store_Text
        (Target : in out Ada.Strings.Unbounded.Unbounded_String) return Status
      is
      begin
         Target := Buffer_To_ASCII_String (Buffer_Value);
         if Length (Buffer_Value) > 0
           and then Ada.Strings.Unbounded.Length (Target) = 0
         then
            return Authentication_Failed;
         end if;
         return Ok;
      end Store_Text;
   begin
      Clear_Keyboard_Interactive_Reply (Result);

      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_SSH_String
          (Payload, Cursor, Buffer_Value, Next_Index);
      if Status_Value /= Ok then
         return Authentication_Failed;
      end if;
      Status_Value := Store_Text (Result.Keyboard_Interactive_Name);
      Clear (Buffer_Value);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Cursor := Next_Index;

      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_SSH_String
          (Payload, Cursor, Buffer_Value, Next_Index);
      if Status_Value /= Ok then
         return Authentication_Failed;
      end if;
      Status_Value := Store_Text (Result.Keyboard_Interactive_Instruction);
      Clear (Buffer_Value);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Cursor := Next_Index;

      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_SSH_String
          (Payload, Cursor, Buffer_Value, Next_Index);
      if Status_Value /= Ok then
         return Authentication_Failed;
      end if;
      Status_Value := Store_Text (Result.Keyboard_Interactive_Language_Tag);
      Clear (Buffer_Value);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Cursor := Next_Index;

      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_Uint32
          (Payload, Cursor, Prompt_Count, Next_Index);
      if Status_Value /= Ok then
         return Authentication_Failed;
      end if;
      Cursor := Next_Index;

      if Prompt_Count
        > Interfaces.Unsigned_32 (Max_Keyboard_Interactive_Prompts)
      then
         return Unsupported_Feature;
      end if;

      for Prompt_Index in 1 .. Natural (Prompt_Count) loop
         Status_Value :=
           SSH_Lib.Protocol.Numbers.Decode_SSH_String
             (Payload, Cursor, Buffer_Value, Next_Index);
         if Status_Value /= Ok then
            return Authentication_Failed;
         end if;
         Status_Value :=
           Store_Text
             (Result.Keyboard_Interactive_Prompt_Items (Prompt_Index).Text);
         Clear (Buffer_Value);
         if Status_Value /= Ok then
            return Status_Value;
         end if;
         Cursor := Next_Index;

         if Cursor > Payload'Last then
            return Authentication_Failed;
         end if;
         Status_Value :=
           SSH_Lib.Protocol.Numbers.Decode_Boolean
             (Payload (Cursor), Echo_Value);
         if Status_Value /= Ok then
            return Authentication_Failed;
         end if;
         Result.Keyboard_Interactive_Prompt_Items (Prompt_Index).Echo :=
           Echo_Value;
         if Echo_Value then
            Result.Keyboard_Interactive_Echoes :=
              Result.Keyboard_Interactive_Echoes + 1;
         end if;
         Cursor := Cursor + 1;
      end loop;

      if Cursor /= Payload'Last + 1 then
         return Authentication_Failed;
      end if;

      Result.Keyboard_Interactive_Prompts := Prompt_Count;
      return Ok;
   exception
      when others =>
         Clear_Keyboard_Interactive_Reply (Result);
         return Internal_Error;
   end Parse_Keyboard_Interactive_Info_Request;

   function Encode_None_Request (User_Name : String) return Packet_Buffer is
      Result       : Packet_Buffer;
      Status_Value : Status;
   begin
      Clear (Result);
      if not Valid_Protocol_Text (User_Name) then
         return Result;
      end if;

      Status_Value := Append_Byte (Result, SSH_MSG_USERAUTH_REQUEST);
      if Status_Value = Ok then
         Status_Value := Append_String (Result, User_Name);
      end if;
      if Status_Value = Ok then
         Status_Value := Append_String (Result, "ssh-connection");
      end if;
      if Status_Value = Ok then
         Status_Value := Append_String (Result, "none");
      end if;

      if Status_Value /= Ok then
         Clear (Result);
      end if;
      return Result;
   exception
      when others =>
         Clear (Result);
         return Result;
   end Encode_None_Request;

   function Encode_Password_Request
     (User_Name : String; Password : String) return Packet_Buffer
   is
      Result       : Packet_Buffer;
      Status_Value : Status;
   begin
      Clear (Result);
      if not Valid_Protocol_Text (User_Name) then
         return Result;
      end if;

      --  SSH password authentication carries the password as an SSH string.
      --  Session authentication does not prompt or load stored credentials
      --  implicitly; callers must opt in by providing Password in
      --  Session_Options.  Keep the same bounded text guard used by the rest
      --  of this userauth encoder so embedded NUL/CR/LF cannot corrupt
      --  deterministic transcripts.
      if Password'Length = 0 or else not Valid_Protocol_Text (Password) then
         return Result;
      end if;

      Status_Value := Append_Byte (Result, SSH_MSG_USERAUTH_REQUEST);
      if Status_Value = Ok then
         Status_Value := Append_String (Result, User_Name);
      end if;
      if Status_Value = Ok then
         Status_Value := Append_String (Result, "ssh-connection");
      end if;
      if Status_Value = Ok then
         Status_Value := Append_String (Result, "password");
      end if;
      if Status_Value = Ok then
         Status_Value :=
           Append_Byte
             (Result, SSH_Lib.Protocol.Numbers.Encode_Boolean (False));
      end if;
      if Status_Value = Ok then
         Status_Value := Append_String (Result, Password);
      end if;

      if Status_Value /= Ok then
         Clear (Result);
      end if;
      return Result;
   exception
      when others =>
         Clear (Result);
         return Result;
   end Encode_Password_Request;

   function Encode_Password_Change_Request
     (User_Name : String; Old_Password : String; New_Password : String)
      return Packet_Buffer
   is
      Result       : Packet_Buffer;
      Status_Value : Status;
   begin
      Clear (Result);
      if not Valid_Protocol_Text (User_Name)
        or else Old_Password'Length = 0
        or else New_Password'Length = 0
        or else not Valid_Protocol_Text (Old_Password)
        or else not Valid_Protocol_Text (New_Password)
      then
         return Result;
      end if;

      Status_Value := Append_Byte (Result, SSH_MSG_USERAUTH_REQUEST);
      if Status_Value = Ok then
         Status_Value := Append_String (Result, User_Name);
      end if;
      if Status_Value = Ok then
         Status_Value := Append_String (Result, "ssh-connection");
      end if;
      if Status_Value = Ok then
         Status_Value := Append_String (Result, "password");
      end if;
      if Status_Value = Ok then
         Status_Value :=
           Append_Byte
             (Result, SSH_Lib.Protocol.Numbers.Encode_Boolean (True));
      end if;
      if Status_Value = Ok then
         Status_Value := Append_String (Result, Old_Password);
      end if;
      if Status_Value = Ok then
         Status_Value := Append_String (Result, New_Password);
      end if;

      if Status_Value /= Ok then
         Clear (Result);
      end if;
      return Result;
   exception
      when others =>
         Clear (Result);
         return Result;
   end Encode_Password_Change_Request;

   function Encode_Keyboard_Interactive_Request
     (User_Name : String) return Packet_Buffer
   is
      Result       : Packet_Buffer;
      Status_Value : Status;
   begin
      Clear (Result);
      if not Valid_Protocol_Text (User_Name) then
         return Result;
      end if;

      Status_Value := Append_Byte (Result, SSH_MSG_USERAUTH_REQUEST);
      if Status_Value = Ok then
         Status_Value := Append_String (Result, User_Name);
      end if;
      if Status_Value = Ok then
         Status_Value := Append_String (Result, "ssh-connection");
      end if;
      if Status_Value = Ok then
         Status_Value := Append_String (Result, "keyboard-interactive");
      end if;
      if Status_Value = Ok then
         Status_Value := Append_String (Result, "");
      end if;
      if Status_Value = Ok then
         Status_Value := Append_String (Result, "");
      end if;

      if Status_Value /= Ok then
         Clear (Result);
      end if;
      return Result;
   exception
      when others =>
         Clear (Result);
         return Result;
   end Encode_Keyboard_Interactive_Request;

   function Encode_Keyboard_Interactive_Response
     (Response : String) return Packet_Buffer
   is
      Responses : Keyboard_Interactive_Response_Array :=
        [others => Ada.Strings.Unbounded.Null_Unbounded_String];
   begin
      if Response'Length = 0 or else not Valid_Protocol_Text (Response) then
         return Responses_To_Buffer : Packet_Buffer do
            Clear (Responses_To_Buffer);
         end return;
      end if;

      Responses (1) := Ada.Strings.Unbounded.To_Unbounded_String (Response);
      return Encode_Keyboard_Interactive_Responses (1, Responses);
   exception
      when others =>
         return Responses_To_Buffer : Packet_Buffer do
            Clear (Responses_To_Buffer);
         end return;
   end Encode_Keyboard_Interactive_Response;

   function Encode_Keyboard_Interactive_Responses
     (Response_Count : Natural;
      Responses      : Keyboard_Interactive_Response_Array)
      return Packet_Buffer
   is
      Result       : Packet_Buffer;
      Status_Value : Status;
   begin
      Clear (Result);
      if Response_Count > Max_Keyboard_Interactive_Prompts then
         return Result;
      end if;

      for Response_Index in 1 .. Response_Count loop
         if not Valid_Keyboard_Interactive_Response_Text
                  (Ada.Strings.Unbounded.To_String
                     (Responses (Response_Index)))
         then
            return Result;
         end if;
      end loop;

      Status_Value := Append_Byte (Result, SSH_MSG_USERAUTH_INFO_RESPONSE);
      if Status_Value = Ok then
         Status_Value :=
           Append_Uint32 (Result, Interfaces.Unsigned_32 (Response_Count));
      end if;
      for Response_Index in 1 .. Response_Count loop
         if Status_Value = Ok then
            Status_Value :=
              Append_String
                (Result,
                 Ada.Strings.Unbounded.To_String (Responses (Response_Index)));
         end if;
      end loop;

      if Status_Value /= Ok then
         Clear (Result);
      end if;
      return Result;
   exception
      when others =>
         Clear (Result);
         return Result;
   end Encode_Keyboard_Interactive_Responses;

   function Parse_Userauth_Reply
     (Payload : Stream_Element_Array;
      Context : Reply_Context;
      Result  : out Reply) return Status
   is
      Status_Value : Status;
   begin
      Result.Kind := Unexpected_Reply;
      Result.Failure.Remaining_Methods :=
        Ada.Strings.Unbounded.Null_Unbounded_String;
      Result.Failure.Partial_Success := False;
      Result.Public_Key_Algorithm :=
        Ada.Strings.Unbounded.Null_Unbounded_String;
      Clear (Result.Public_Key_Blob);
      Result.Keyboard_Interactive_Prompts := 0;
      Result.Keyboard_Interactive_Echoes := 0;

      if Payload'Length < 1 then
         return Authentication_Failed;
      end if;

      case Payload (Payload'First) is
         when SSH_MSG_USERAUTH_SUCCESS =>
            if Payload'Length /= 1 then
               return Authentication_Failed;
            end if;
            Result.Kind := Auth_Success;
            return Ok;

         when SSH_MSG_USERAUTH_FAILURE =>
            Status_Value :=
              SSH_Lib.Protocol.Auth_Methods.Parse_Failure
                (Payload, Result.Failure);
            if Status_Value /= Ok then
               return Status_Value;
            end if;
            Result.Kind := Auth_Failure;
            return Ok;

         when SSH_MSG_USERAUTH_BANNER  =>
            Status_Value := Skip_Banner (Payload);
            if Status_Value /= Ok then
               return Status_Value;
            end if;
            Result.Kind := Auth_Banner;
            return Ok;

         when SSH_MSG_USERAUTH_PK_OK   =>
            if Context = Preflight_Reply then
               Status_Value := Parse_PK_OK (Payload, Result);
               if Status_Value /= Ok then
                  return Status_Value;
               end if;
               Result.Kind := Public_Key_Ok;
               return Ok;
            elsif Context = Password_Reply then
               Status_Value := Skip_Password_Change_Request (Payload);
               if Status_Value /= Ok then
                  return Status_Value;
               end if;
               Result.Kind := Password_Change_Required;
               return Ok;
            elsif Context = Keyboard_Interactive_Reply then
               Status_Value :=
                 Parse_Keyboard_Interactive_Info_Request (Payload, Result);
               if Status_Value /= Ok then
                  return Status_Value;
               end if;
               Result.Kind := Keyboard_Interactive_Info_Request;
               return Ok;
            else
               return Authentication_Failed;
            end if;

         when others                   =>
            Result.Kind := Unexpected_Reply;
            return Authentication_Failed;
      end case;
   exception
      when others =>
         Result.Kind := Unexpected_Reply;
         return Internal_Error;
   end Parse_Userauth_Reply;
end SSH_Lib.Protocol.Userauth;
