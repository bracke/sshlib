with Ada.Streams;
with Ada.Text_IO;
with SSH_Lib.Tests.Fixtures.Identity_Files;
with SSH_Lib.Tests.Fixtures.Temp_Paths;
with SSH_Lib.Identity_Files;
with SSH_Lib.Agent.Protocol;
with SSH_Lib.Agent;
with CryptoLib.Errors;
with SSH_Lib.Protocol.Authentication_Guards;
with SSH_Lib.Protocol.Buffers;
with SSH_Lib.Protocol.Numbers;
with SSH_Lib.Protocol.Userauth;
with SSH_Lib.Tests.Assertions;

package body SSH_Lib.Tests.Fixtures.Auth_Security is

   use Ada.Streams;
   use type CryptoLib.Errors.Status;
   use type SSH_Lib.Identity_Files.Key_Kind;
   use type SSH_Lib.Protocol.Userauth.Reply_Kind;

   procedure Check (Condition : Boolean; Label_Text : String) is
   begin
      if not Condition then
         Ada.Text_IO.Put_Line ("FAILED: " & Label_Text);
         raise Program_Error;
      end if;
   end Check;

   function Bytes (Value : String) return Stream_Element_Array is
      Result : Stream_Element_Array (1 .. Value'Length);
      Cursor : Stream_Element_Offset := Result'First;
   begin
      for Character_Value of Value loop
         Result (Cursor) := Stream_Element (Character'Pos (Character_Value));
         Cursor := Cursor + 1;
      end loop;
      return Result;
   end Bytes;

   function Userauth_Failure
     (Remaining_Methods : String;
      Partial_Success   : Boolean)
      return Stream_Element_Array
   is
      Result : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Methods_Buffer : constant SSH_Lib.Protocol.Buffers.Packet_Buffer :=
        SSH_Lib.Protocol.Numbers.Encode_Name_List (Remaining_Methods);
      Status_Value : CryptoLib.Errors.Status;
   begin
      SSH_Lib.Protocol.Buffers.Clear (Result);
      Status_Value := SSH_Lib.Protocol.Buffers.Append_Byte
        (Result, SSH_Lib.Protocol.Userauth.SSH_MSG_USERAUTH_FAILURE);
      if Status_Value = CryptoLib.Errors.Ok then
         Status_Value := SSH_Lib.Protocol.Buffers.Append
           (Result, SSH_Lib.Protocol.Buffers.To_Array (Methods_Buffer));
      end if;
      if Status_Value = CryptoLib.Errors.Ok then
         Status_Value := SSH_Lib.Protocol.Buffers.Append_Byte
           (Result, SSH_Lib.Protocol.Numbers.Encode_Boolean (Partial_Success));
      end if;
      Check (Status_Value = CryptoLib.Errors.Ok, "partial userauth failure fixture encodes");
      return SSH_Lib.Protocol.Buffers.To_Array (Result);
   end Userauth_Failure;

   function Userauth_Banner return Stream_Element_Array is
      Result : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Message_Buffer : constant SSH_Lib.Protocol.Buffers.Packet_Buffer :=
        SSH_Lib.Protocol.Numbers.Encode_SSH_String (Bytes ("authorized use only"));
      Language_Buffer : constant SSH_Lib.Protocol.Buffers.Packet_Buffer :=
        SSH_Lib.Protocol.Numbers.Encode_SSH_String (Bytes ("en"));
      Status_Value : CryptoLib.Errors.Status;
   begin
      SSH_Lib.Protocol.Buffers.Clear (Result);
      Status_Value := SSH_Lib.Protocol.Buffers.Append_Byte
        (Result, SSH_Lib.Protocol.Userauth.SSH_MSG_USERAUTH_BANNER);
      if Status_Value = CryptoLib.Errors.Ok then
         Status_Value := SSH_Lib.Protocol.Buffers.Append
           (Result, SSH_Lib.Protocol.Buffers.To_Array (Message_Buffer));
      end if;
      if Status_Value = CryptoLib.Errors.Ok then
         Status_Value := SSH_Lib.Protocol.Buffers.Append
           (Result, SSH_Lib.Protocol.Buffers.To_Array (Language_Buffer));
      end if;
      Check (Status_Value = CryptoLib.Errors.Ok, "userauth banner fixture encodes");
      return SSH_Lib.Protocol.Buffers.To_Array (Result);
   end Userauth_Banner;

   function Userauth_Success return Stream_Element_Array is
   begin
      return [1 => SSH_Lib.Protocol.Userauth.SSH_MSG_USERAUTH_SUCCESS];
   end Userauth_Success;

   procedure Assert_Payload_Prefix
     (Payload_Buffer : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Prefix_Buffer  : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Label_Text     : String)
   is
      Payload : constant Stream_Element_Array := SSH_Lib.Protocol.Buffers.To_Array (Payload_Buffer);
      Prefix  : constant Stream_Element_Array := SSH_Lib.Protocol.Buffers.To_Array (Prefix_Buffer);
   begin
      Check (Payload'Length >= Prefix'Length, Label_Text & " has encoded session id prefix");
      for Offset_Value in 0 .. Prefix'Length - 1 loop
         Check (Payload (Payload'First + Stream_Element_Offset (Offset_Value))
                = Prefix (Prefix'First + Stream_Element_Offset (Offset_Value)),
                Label_Text & " begins with first exchange hash session id");
      end loop;
   end Assert_Payload_Prefix;

   procedure Assert_Userauth_Order_And_Signature_Payloads is
      First_Exchange_Hash : constant Stream_Element_Array (1 .. 8) :=
        [16#00#, 16#0A#, 16#0D#, 16#7F#, 16#80#, 16#FF#, 16#55#, 16#AA#];
      Rekey_Exchange_Hash : constant Stream_Element_Array (1 .. 8) :=
        [16#AA#, 16#55#, 16#FF#, 16#80#, 16#7F#, 16#0D#, 16#0A#, 16#00#];
      Public_Blob : constant Stream_Element_Array (1 .. 6) :=
        [16#00#, 16#0A#, 16#7F#, 16#80#, 16#FE#, 16#FF#];
      Other_Blob : constant Stream_Element_Array (1 .. 6) :=
        [16#FF#, 16#FE#, 16#80#, 16#7F#, 16#0A#, 16#00#];
      Expected_Payload : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Rekey_Payload : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Wrong_User_Payload : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Wrong_Blob_Payload : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Session_Id_Prefix : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Reply_Item : SSH_Lib.Protocol.Userauth.Reply;
      Status_Value : CryptoLib.Errors.Status;
   begin
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Protocol.Authentication_Guards.Can_Start_Userauth
           (Encrypted_Mode_Active => False, Host_Key_Trusted => False),
         CryptoLib.Errors.Handshake_Failed,
         "auth security", "userauth before encryption is rejected");
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Protocol.Authentication_Guards.Can_Start_Userauth
           (Encrypted_Mode_Active => True, Host_Key_Trusted => False),
         CryptoLib.Errors.Host_Key_Unknown,
         "auth security", "userauth before host trust is rejected");
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Protocol.Authentication_Guards.Can_Start_Userauth
           (Encrypted_Mode_Active => True, Host_Key_Trusted => True),
         CryptoLib.Errors.Ok,
         "auth security", "userauth may start only after encryption and host trust");

      Status_Value := SSH_Lib.Protocol.Userauth.Parse_Userauth_Reply
        (Userauth_Failure ("publickey", True),
         SSH_Lib.Protocol.Userauth.Signed_Reply,
         Reply_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "auth security", "partial success failure parses safely");
      Check (Reply_Item.Kind = SSH_Lib.Protocol.Userauth.Auth_Failure,
             "partial success remains USERAUTH_FAILURE");
      Check (Reply_Item.Failure.Partial_Success,
             "partial success flag is visible to guard");
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Protocol.Authentication_Guards.Complete_Userauth
           (CryptoLib.Errors.Ok, Reply_Item),
         CryptoLib.Errors.Authentication_Failed,
         "auth security", "partial userauth success is not complete success");

      Status_Value := SSH_Lib.Protocol.Userauth.Parse_Userauth_Reply
        (Userauth_Banner,
         SSH_Lib.Protocol.Userauth.Signed_Reply,
         Reply_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "auth security", "USERAUTH_BANNER parses safely");
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Protocol.Authentication_Guards.Complete_Userauth
           (CryptoLib.Errors.Ok, Reply_Item),
         CryptoLib.Errors.Authentication_Failed,
         "auth security", "USERAUTH_BANNER is not authentication success");

      Status_Value := SSH_Lib.Protocol.Userauth.Parse_Userauth_Reply
        (Userauth_Success,
         SSH_Lib.Protocol.Userauth.Signed_Reply,
         Reply_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "auth security", "USERAUTH_SUCCESS parses safely");
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Protocol.Authentication_Guards.Complete_Userauth
           (CryptoLib.Errors.Handshake_Failed, Reply_Item),
         CryptoLib.Errors.Handshake_Failed,
         "auth security", "success cannot override failed encrypted precondition");
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Protocol.Authentication_Guards.Complete_Userauth
           (CryptoLib.Errors.Host_Key_Unknown, Reply_Item),
         CryptoLib.Errors.Host_Key_Unknown,
         "auth security", "success cannot override failed host-trust precondition");
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Protocol.Authentication_Guards.Complete_Userauth
           (CryptoLib.Errors.Ok, Reply_Item),
         CryptoLib.Errors.Ok,
         "auth security", "only USERAUTH_SUCCESS after guards completes auth");

      Expected_Payload := SSH_Lib.Protocol.Userauth.Build_Publickey_Signature_Payload
        (First_Exchange_Hash, "git", "ssh-ed25519", Public_Blob);
      Rekey_Payload := SSH_Lib.Protocol.Userauth.Build_Publickey_Signature_Payload
        (Rekey_Exchange_Hash, "git", "ssh-ed25519", Public_Blob);
      Wrong_User_Payload := SSH_Lib.Protocol.Userauth.Build_Publickey_Signature_Payload
        (First_Exchange_Hash, "other", "ssh-ed25519", Public_Blob);
      Wrong_Blob_Payload := SSH_Lib.Protocol.Userauth.Build_Publickey_Signature_Payload
        (First_Exchange_Hash, "git", "ssh-ed25519", Other_Blob);
      Session_Id_Prefix := SSH_Lib.Protocol.Numbers.Encode_SSH_String (First_Exchange_Hash);

      Check (not SSH_Lib.Protocol.Buffers.Is_Empty (Expected_Payload),
             "exact userauth signature payload fixture builds");
      Assert_Payload_Prefix
        (Expected_Payload, Session_Id_Prefix,
         "signature payload uses the first exchange hash as session identifier");
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Protocol.Authentication_Guards.Signature_Payloads_Match
           (SSH_Lib.Protocol.Buffers.To_Array (Expected_Payload),
            SSH_Lib.Protocol.Buffers.To_Array (Expected_Payload)),
         CryptoLib.Errors.Ok,
         "auth security", "agent/identity signature payload exact match accepted");
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Protocol.Authentication_Guards.Signature_Payloads_Match
           (SSH_Lib.Protocol.Buffers.To_Array (Expected_Payload),
            SSH_Lib.Protocol.Buffers.To_Array (Rekey_Payload)),
         CryptoLib.Errors.Authentication_Failed,
         "auth security", "rekey exchange hash is rejected as wrong signature payload");
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Protocol.Authentication_Guards.Signature_Payloads_Match
           (SSH_Lib.Protocol.Buffers.To_Array (Expected_Payload),
            SSH_Lib.Protocol.Buffers.To_Array (Wrong_User_Payload)),
         CryptoLib.Errors.Authentication_Failed,
         "auth security", "wrong user is rejected as wrong signature payload");
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Protocol.Authentication_Guards.Signature_Payloads_Match
           (SSH_Lib.Protocol.Buffers.To_Array (Expected_Payload),
            SSH_Lib.Protocol.Buffers.To_Array (Wrong_Blob_Payload)),
         CryptoLib.Errors.Authentication_Failed,
         "auth security", "wrong public key blob is rejected as wrong signature payload");
   end Assert_Userauth_Order_And_Signature_Payloads;

   function SSH_String
     (Payload : Stream_Element_Array)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer is
   begin
      return SSH_Lib.Protocol.Numbers.Encode_SSH_String (Payload);
   end SSH_String;

   function Signature_Blob
     (Algorithm_Name : String;
      Signature_Data : Stream_Element_Array)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer
   is
      Result : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Algorithm_Buffer : constant SSH_Lib.Protocol.Buffers.Packet_Buffer :=
        SSH_Lib.Protocol.Numbers.Encode_SSH_String (Bytes (Algorithm_Name));
      Signature_Buffer : constant SSH_Lib.Protocol.Buffers.Packet_Buffer :=
        SSH_Lib.Protocol.Numbers.Encode_SSH_String (Signature_Data);
      Status_Value : CryptoLib.Errors.Status;
   begin
      SSH_Lib.Protocol.Buffers.Clear (Result);
      Status_Value := SSH_Lib.Protocol.Buffers.Append
        (Result, SSH_Lib.Protocol.Buffers.To_Array (Algorithm_Buffer));
      if Status_Value = CryptoLib.Errors.Ok then
         Status_Value := SSH_Lib.Protocol.Buffers.Append
           (Result, SSH_Lib.Protocol.Buffers.To_Array (Signature_Buffer));
      end if;
      Check (Status_Value = CryptoLib.Errors.Ok, "signature blob fixture encodes");
      return Result;
   end Signature_Blob;

   function Security_Key_Signature_Payload
     (Inner_Signature : Stream_Element_Array)
      return Stream_Element_Array
   is
      Result       : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Status_Value : CryptoLib.Errors.Status;
   begin
      SSH_Lib.Protocol.Buffers.Clear (Result);
      Status_Value := SSH_Lib.Protocol.Buffers.Append
        (Result, SSH_Lib.Protocol.Buffers.To_Array (SSH_String (Inner_Signature)));
      if Status_Value = CryptoLib.Errors.Ok then
         Status_Value := SSH_Lib.Protocol.Buffers.Append_Byte (Result, 1);
      end if;
      if Status_Value = CryptoLib.Errors.Ok then
         Status_Value := SSH_Lib.Protocol.Buffers.Append
           (Result, SSH_Lib.Protocol.Numbers.Encode_Uint32 (7));
      end if;
      Check (Status_Value = CryptoLib.Errors.Ok, "security-key signature payload fixture encodes");
      return SSH_Lib.Protocol.Buffers.To_Array (Result);
   end Security_Key_Signature_Payload;

   function Sign_Response
     (Nested_Signature : SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return Stream_Element_Array
   is
      Encoded_Signature : constant SSH_Lib.Protocol.Buffers.Packet_Buffer :=
        SSH_String (SSH_Lib.Protocol.Buffers.To_Array (Nested_Signature));
      Result : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Status_Value : CryptoLib.Errors.Status;
   begin
      SSH_Lib.Protocol.Buffers.Clear (Result);
      Status_Value := SSH_Lib.Protocol.Buffers.Append_Byte
        (Result, SSH_Lib.Agent.Protocol.SSH_AGENT_SIGN_RESPONSE);
      if Status_Value = CryptoLib.Errors.Ok then
         Status_Value := SSH_Lib.Protocol.Buffers.Append
           (Result, SSH_Lib.Protocol.Buffers.To_Array (Encoded_Signature));
      end if;
      Check (Status_Value = CryptoLib.Errors.Ok, "sign response fixture encodes");
      return SSH_Lib.Protocol.Buffers.To_Array (Result);
   end Sign_Response;

   function Identities_Answer
     (Key_Blob : Stream_Element_Array;
      Comment  : String)
      return Stream_Element_Array
   is
      Result : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Key_Buffer : constant SSH_Lib.Protocol.Buffers.Packet_Buffer := SSH_String (Key_Blob);
      Comment_Buffer : constant SSH_Lib.Protocol.Buffers.Packet_Buffer := SSH_String (Bytes (Comment));
      Status_Value : CryptoLib.Errors.Status;
   begin
      SSH_Lib.Protocol.Buffers.Clear (Result);
      Status_Value := SSH_Lib.Protocol.Buffers.Append_Byte
        (Result, SSH_Lib.Agent.Protocol.SSH_AGENT_IDENTITIES_ANSWER);
      if Status_Value = CryptoLib.Errors.Ok then
         Status_Value := SSH_Lib.Protocol.Buffers.Append
           (Result, SSH_Lib.Protocol.Numbers.Encode_Uint32 (1));
      end if;
      if Status_Value = CryptoLib.Errors.Ok then
         Status_Value := SSH_Lib.Protocol.Buffers.Append
           (Result, SSH_Lib.Protocol.Buffers.To_Array (Key_Buffer));
      end if;
      if Status_Value = CryptoLib.Errors.Ok then
         Status_Value := SSH_Lib.Protocol.Buffers.Append
           (Result, SSH_Lib.Protocol.Buffers.To_Array (Comment_Buffer));
      end if;
      Check (Status_Value = CryptoLib.Errors.Ok, "identity answer fixture encodes");
      return SSH_Lib.Protocol.Buffers.To_Array (Result);
   end Identities_Answer;


   function Userauth_Password_Change_Request return Stream_Element_Array is
      Result : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Prompt_Buffer : constant SSH_Lib.Protocol.Buffers.Packet_Buffer :=
        SSH_Lib.Protocol.Numbers.Encode_SSH_String (Bytes ("new password required"));
      Language_Buffer : constant SSH_Lib.Protocol.Buffers.Packet_Buffer :=
        SSH_Lib.Protocol.Numbers.Encode_SSH_String (Bytes ("en"));
      Status_Value : CryptoLib.Errors.Status;
   begin
      SSH_Lib.Protocol.Buffers.Clear (Result);
      Status_Value := SSH_Lib.Protocol.Buffers.Append_Byte
        (Result, SSH_Lib.Protocol.Userauth.SSH_MSG_USERAUTH_PK_OK);
      if Status_Value = CryptoLib.Errors.Ok then
         Status_Value := SSH_Lib.Protocol.Buffers.Append
           (Result, SSH_Lib.Protocol.Buffers.To_Array (Prompt_Buffer));
      end if;
      if Status_Value = CryptoLib.Errors.Ok then
         Status_Value := SSH_Lib.Protocol.Buffers.Append
           (Result, SSH_Lib.Protocol.Buffers.To_Array (Language_Buffer));
      end if;
      Check (Status_Value = CryptoLib.Errors.Ok, "password change request fixture encodes");
      return SSH_Lib.Protocol.Buffers.To_Array (Result);
   end Userauth_Password_Change_Request;

   procedure Assert_Password_Change_Request_Fails_Closed is
      Reply_Item   : SSH_Lib.Protocol.Userauth.Reply;
      Status_Value : CryptoLib.Errors.Status;
   begin
      Status_Value := SSH_Lib.Protocol.Userauth.Parse_Userauth_Reply
        (Userauth_Password_Change_Request,
         SSH_Lib.Protocol.Userauth.Password_Reply,
         Reply_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "auth password change", "password change request parses in password context");
      Check (Reply_Item.Kind = SSH_Lib.Protocol.Userauth.Password_Change_Required,
             "password change request is not publickey-ok or success");
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Protocol.Authentication_Guards.Complete_Userauth
           (CryptoLib.Errors.Ok, Reply_Item),
         CryptoLib.Errors.Authentication_Failed,
         "auth password change", "password change request never completes authentication");

      Status_Value := SSH_Lib.Protocol.Userauth.Parse_Userauth_Reply
        (Userauth_Password_Change_Request,
         SSH_Lib.Protocol.Userauth.Signed_Reply,
         Reply_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Authentication_Failed,
         "auth password change", "password change request is rejected outside password context");
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Protocol.Authentication_Guards.Complete_Userauth
           (Status_Value, Reply_Item),
         CryptoLib.Errors.Authentication_Failed,
         "auth password change", "rejected password change cannot complete authentication");
   end Assert_Password_Change_Request_Fails_Closed;

   procedure Assert_Malformed_Agent_And_Identity_Fixtures is
      Key_Blob : constant Stream_Element_Array (1 .. 8) :=
        [16#00#, 16#0A#, 16#0D#, 16#7F#, 16#80#, 16#FE#, 16#FF#, 16#55#];
      Signature_Data : constant Stream_Element_Array (1 .. 6) :=
        [16#AA#, 16#55#, 16#00#, 16#80#, 16#FE#, 16#FF#];
      SK_Ed25519_Inner : constant Stream_Element_Array (1 .. 64) :=
        [others => 16#A5#];
      SK_ECDSA_Inner : constant Stream_Element_Array (1 .. 73) :=
        [1 => 16#00#, 2 => 16#00#, 3 => 16#00#, 4 => 16#21#,
         5 => 16#00#, 6 => 16#EA#, 7 => 16#3A#, 8 => 16#EB#,
         9 => 16#32#, 10 => 16#2E#, 11 => 16#3D#, 12 => 16#09#,
         13 => 16#4C#, 14 => 16#7F#, 15 => 16#13#, 16 => 16#AA#,
         17 => 16#5F#, 18 => 16#D8#, 19 => 16#D2#, 20 => 16#3F#,
         21 => 16#F7#, 22 => 16#D4#, 23 => 16#59#, 24 => 16#68#,
         25 => 16#CC#, 26 => 16#C2#, 27 => 16#7A#, 28 => 16#DF#,
         29 => 16#1F#, 30 => 16#65#, 31 => 16#70#, 32 => 16#C3#,
         33 => 16#E3#, 34 => 16#8A#, 35 => 16#69#, 36 => 16#36#,
         37 => 16#1B#, 38 => 16#00#, 39 => 16#00#, 40 => 16#00#,
         41 => 16#20#, 42 => 16#5F#, 43 => 16#B9#, 44 => 16#5B#,
         45 => 16#B4#, 46 => 16#77#, 47 => 16#CF#, 48 => 16#81#,
         49 => 16#7E#, 50 => 16#A2#, 51 => 16#A6#, 52 => 16#E9#,
         53 => 16#2F#, 54 => 16#CF#, 55 => 16#B2#, 56 => 16#53#,
         57 => 16#E8#, 58 => 16#C8#, 59 => 16#94#, 60 => 16#01#,
         61 => 16#5E#, 62 => 16#09#, 63 => 16#1E#, 64 => 16#7F#,
         65 => 16#F4#, 66 => 16#5A#, 67 => 16#E0#, 68 => 16#BC#,
         69 => 16#06#, 70 => 16#EB#, 71 => 16#E7#, 72 => 16#14#,
         73 => 16#FC#];
      SK_Ed25519_Signature_Data : constant Stream_Element_Array :=
        Security_Key_Signature_Payload (SK_Ed25519_Inner);
      SK_ECDSA_Signature_Data : constant Stream_Element_Array :=
        Security_Key_Signature_Payload (SK_ECDSA_Inner);
      Good_Signature : constant SSH_Lib.Protocol.Buffers.Packet_Buffer :=
        Signature_Blob ("ssh-ed25519", Signature_Data);
      Legacy_Signature : constant SSH_Lib.Protocol.Buffers.Packet_Buffer :=
        Signature_Blob ("ssh-rsa", Signature_Data);
      SK_Ed25519_Signature : constant SSH_Lib.Protocol.Buffers.Packet_Buffer :=
        Signature_Blob ("sk-ssh-ed25519@openssh.com", SK_Ed25519_Signature_Data);
      SK_ECDSA_Signature : constant SSH_Lib.Protocol.Buffers.Packet_Buffer :=
        Signature_Blob ("sk-ecdsa-sha2-nistp256@openssh.com", SK_ECDSA_Signature_Data);
      Malformed_SK_Ed25519_Signature : constant SSH_Lib.Protocol.Buffers.Packet_Buffer :=
        Signature_Blob ("sk-ssh-ed25519@openssh.com", Signature_Data);
      SK_Ed25519_Cert_Signature : constant SSH_Lib.Protocol.Buffers.Packet_Buffer :=
        Signature_Blob ("sk-ssh-ed25519-cert-v01@openssh.com", SK_Ed25519_Signature_Data);
      SK_ECDSA_Cert_Signature : constant SSH_Lib.Protocol.Buffers.Packet_Buffer :=
        Signature_Blob ("sk-ecdsa-sha2-nistp256-cert-v01@openssh.com", SK_ECDSA_Signature_Data);
      Empty_Signature_Bytes : constant Stream_Element_Array (1 .. 0) := [others => 0];
      Empty_Nested_Signature : constant SSH_Lib.Protocol.Buffers.Packet_Buffer :=
        Signature_Blob ("ssh-ed25519", Empty_Signature_Bytes);
      Identities : SSH_Lib.Agent.Identity_List;
      Parsed_Signature : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Identity_Item : SSH_Lib.Identity_Files.Identity_Key;
      Status_Value : CryptoLib.Errors.Status;
      Decoded_Length : Natural := 1;
   begin
      Status_Value := SSH_Lib.Agent.Protocol.Decode_Message_Length
        ([1 => 0, 2 => 16, 3 => 0, 4 => 1], Decoded_Length);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Authentication_Failed,
         "auth malformed fixture", "oversized agent response length rejected");
      Check (Decoded_Length = 0, "oversized agent response length clears decoded size");

      Status_Value := SSH_Lib.Agent.Protocol.Parse_Identities_Answer
        ([1 => SSH_Lib.Agent.Protocol.SSH_AGENT_FAILURE], Identities);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Authentication_Failed,
         "auth malformed fixture", "agent failure identities response rejected");
      Check (SSH_Lib.Agent.Count (Identities) = 0,
             "agent failure identities response leaves no identities");

      Status_Value := SSH_Lib.Agent.Protocol.Parse_Identities_Answer
        ([1 => 99, 2 => 0, 3 => 0, 4 => 0, 5 => 0], Identities);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Authentication_Failed,
         "auth malformed fixture", "malformed agent identity message type rejected");
      Check (SSH_Lib.Agent.Count (Identities) = 0,
             "malformed identity message type leaves no identities");

      Status_Value := SSH_Lib.Agent.Protocol.Parse_Identities_Answer
        ([1 => SSH_Lib.Agent.Protocol.SSH_AGENT_IDENTITIES_ANSWER,
          2 => 0, 3 => 0, 4 => 0, 5 => 1,
          6 => 0, 7 => 0, 8 => 0, 9 => 9,
          10 => 1, 11 => 2],
         Identities);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Authentication_Failed,
         "auth malformed fixture", "truncated agent identity list rejected");
      Check (SSH_Lib.Agent.Count (Identities) = 0,
             "truncated agent identity list leaves no identities");

      Status_Value := SSH_Lib.Agent.Protocol.Parse_Identities_Answer
        ([1 => SSH_Lib.Agent.Protocol.SSH_AGENT_IDENTITIES_ANSWER,
          2 => 0, 3 => 0, 4 => 0,
          5 => Stream_Element (SSH_Lib.Agent.Max_Identities + 1)],
         Identities);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Authentication_Failed,
         "auth malformed fixture", "too many agent identities rejected");
      Check (SSH_Lib.Agent.Count (Identities) = 0,
             "too many agent identities leaves no identities");

      Status_Value := SSH_Lib.Agent.Protocol.Parse_Identities_Answer
        (Identities_Answer (Key_Blob, "fixture") & [1 => 0], Identities);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Authentication_Failed,
         "auth malformed fixture", "trailing agent identity bytes rejected");
      Check (SSH_Lib.Agent.Count (Identities) = 0,
             "trailing identity bytes leave no identities");

      Status_Value := SSH_Lib.Agent.Protocol.Parse_Sign_Response
        ([1 => SSH_Lib.Agent.Protocol.SSH_AGENT_FAILURE], Parsed_Signature);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Authentication_Failed,
         "auth malformed fixture", "agent sign failure rejected");
      Check (SSH_Lib.Protocol.Buffers.Is_Empty (Parsed_Signature),
             "agent sign failure leaves empty signature");

      Status_Value := SSH_Lib.Agent.Protocol.Parse_Sign_Response
        ([1 => 99], Parsed_Signature);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Authentication_Failed,
         "auth malformed fixture", "malformed agent signature response type rejected");
      Check (SSH_Lib.Protocol.Buffers.Is_Empty (Parsed_Signature),
             "malformed signature response type leaves empty signature");

      Status_Value := SSH_Lib.Agent.Protocol.Parse_Sign_Response
        (Sign_Response (Good_Signature), Parsed_Signature);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "auth malformed fixture", "well-formed agent signature response accepted");

      Status_Value := SSH_Lib.Agent.Protocol.Validate_Signature_Blob_For_Algorithm
        (Parsed_Signature, "ssh-ed25519");
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "auth malformed fixture", "agent signature expected algorithm accepted");

      Status_Value := SSH_Lib.Agent.Protocol.Validate_Signature_Blob_For_Algorithm
        (Parsed_Signature, "sk-ssh-ed25519@openssh.com");
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Authentication_Failed,
         "auth malformed fixture", "agent signature algorithm mismatch rejected");

      Status_Value := SSH_Lib.Agent.Protocol.Parse_Sign_Response
        (Sign_Response (SK_Ed25519_Signature), Parsed_Signature);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "auth malformed fixture", "SK Ed25519 agent signature parses");

      Status_Value := SSH_Lib.Agent.Protocol.Validate_Signature_Blob_For_Algorithm
        (Parsed_Signature, "sk-ssh-ed25519@openssh.com");
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "auth malformed fixture", "SK Ed25519 agent signature validates");

      Status_Value := SSH_Lib.Agent.Protocol.Parse_Sign_Response
        (Sign_Response (SK_ECDSA_Signature), Parsed_Signature);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "auth malformed fixture", "SK ECDSA agent signature parses");

      Status_Value := SSH_Lib.Agent.Protocol.Validate_Signature_Blob_For_Algorithm
        (Parsed_Signature, "sk-ecdsa-sha2-nistp256@openssh.com");
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "auth malformed fixture", "SK ECDSA agent signature validates");

      Status_Value := SSH_Lib.Agent.Protocol.Parse_Sign_Response
        (Sign_Response (Malformed_SK_Ed25519_Signature), Parsed_Signature);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Authentication_Failed,
         "auth malformed fixture", "malformed SK Ed25519 agent signature is rejected");
      Check (SSH_Lib.Protocol.Buffers.Is_Empty (Parsed_Signature),
             "malformed SK Ed25519 signature leaves empty parsed signature");

      Status_Value := SSH_Lib.Agent.Protocol.Parse_Sign_Response
        (Sign_Response (SK_Ed25519_Cert_Signature), Parsed_Signature);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "auth malformed fixture", "SK Ed25519 certificate agent signature parses");

      Status_Value := SSH_Lib.Agent.Protocol.Validate_Signature_Blob_For_Algorithm
        (Parsed_Signature, "sk-ssh-ed25519-cert-v01@openssh.com");
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "auth malformed fixture", "SK Ed25519 certificate agent signature validates");

      Status_Value := SSH_Lib.Agent.Protocol.Parse_Sign_Response
        (Sign_Response (SK_ECDSA_Cert_Signature), Parsed_Signature);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "auth malformed fixture", "SK ECDSA certificate agent signature parses");

      Status_Value := SSH_Lib.Agent.Protocol.Validate_Signature_Blob_For_Algorithm
        (Parsed_Signature, "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com");
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "auth malformed fixture", "SK ECDSA certificate agent signature validates");

      Status_Value := SSH_Lib.Agent.Protocol.Validate_Signature_Blob_For_Algorithm
        (Parsed_Signature, "sk-ssh-ed25519-cert-v01@openssh.com");
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Authentication_Failed,
         "auth malformed fixture", "wrong SK certificate agent signature algorithm rejected");

      Status_Value := SSH_Lib.Agent.Protocol.Parse_Sign_Response
        (Sign_Response (Good_Signature) & [1 => 0], Parsed_Signature);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Authentication_Failed,
         "auth malformed fixture", "agent signature response trailing bytes rejected");
      Check (SSH_Lib.Protocol.Buffers.Is_Empty (Parsed_Signature),
             "trailing signature response bytes leave empty signature");

      Status_Value := SSH_Lib.Agent.Protocol.Parse_Sign_Response
        (Sign_Response (Legacy_Signature), Parsed_Signature);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "auth malformed fixture", "legacy agent signature response parses");

      Status_Value := SSH_Lib.Agent.Protocol.Validate_Signature_Blob_For_Algorithm
        (Parsed_Signature, "ssh-ed25519");
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Authentication_Failed,
         "auth malformed fixture", "wrong agent signature algorithm rejected");
      Check (not SSH_Lib.Protocol.Buffers.Is_Empty (Parsed_Signature),
             "algorithm mismatch does not erase parsed signature blob");

      Status_Value := SSH_Lib.Agent.Protocol.Parse_Sign_Response
        (Sign_Response (Empty_Nested_Signature), Parsed_Signature);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Authentication_Failed,
         "auth malformed fixture", "empty agent signature bytes rejected");
      Check (SSH_Lib.Protocol.Buffers.Is_Empty (Parsed_Signature),
             "empty nested signature response leaves empty signature");

      declare
         Oversized_Payload : constant Stream_Element_Array
           (1 .. Stream_Element_Offset (SSH_Lib.Agent.Max_Agent_Message_Size + 1)) :=
             [others => SSH_Lib.Agent.Protocol.SSH_AGENT_SIGN_RESPONSE];
      begin
         Status_Value := SSH_Lib.Agent.Protocol.Parse_Sign_Response
           (Oversized_Payload, Parsed_Signature);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Authentication_Failed,
            "auth malformed fixture", "oversized agent signature response rejected before parse");
         Check (SSH_Lib.Protocol.Buffers.Is_Empty (Parsed_Signature),
                "oversized signature response leaves empty signature");
      end;

      Status_Value := SSH_Lib.Agent.Protocol.Decode_Message_Length
        (SSH_Lib.Agent.Protocol.Encode_Message_Length (SSH_Lib.Agent.Max_Agent_Message_Size + 1),
         Decoded_Length);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Authentication_Failed,
         "auth malformed fixture", "oversized encoded agent length rejected");
      Check (Decoded_Length = 0,
             "oversized encoded agent length clears decoded size");

      Status_Value := SSH_Lib.Identity_Files.Parse
        (SSH_Lib.Tests.Fixtures.Identity_Files.Malformed_OpenSSH_Private_Key,
         Identity_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Authentication_Failed,
         "auth malformed fixture", "malformed OpenSSH private key rejected");
      Check (SSH_Lib.Identity_Files.Kind (Identity_Item) = SSH_Lib.Identity_Files.No_Key,
             "malformed OpenSSH private key clears key state");

      Status_Value := SSH_Lib.Identity_Files.Parse
        (SSH_Lib.Tests.Fixtures.Identity_Files.Encrypted_OpenSSH_Cipher_Private_Key,
         Identity_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Authentication_Failed,
         "auth malformed fixture", "encrypted OpenSSH private key without passphrase fails closed");

      Status_Value := SSH_Lib.Identity_Files.Parse
        (SSH_Lib.Tests.Fixtures.Identity_Files.Unsupported_RSA_Private_Key,
         Identity_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Authentication_Failed,
         "auth malformed fixture", "unsupported private-key algorithm rejected");

      Status_Value := SSH_Lib.Identity_Files.Parse
        (SSH_Lib.Tests.Fixtures.Identity_Files.Public_Private_Mismatch_OpenSSH_Private_Key,
         Identity_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Authentication_Failed,
         "auth malformed fixture", "public/private key mismatch rejected");

      Status_Value := SSH_Lib.Identity_Files.Parse
        (SSH_Lib.Tests.Fixtures.Identity_Files.Legacy_PEM_Private_Key,
         Identity_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Authentication_Failed,
         "auth malformed fixture", "unsupported non-RSA legacy PEM private key rejected");

      Status_Value := SSH_Lib.Identity_Files.Parse
        (SSH_Lib.Tests.Fixtures.Identity_Files.Encrypted_Legacy_RSA_AES256_CBC_Private_Key,
         "wrong-passphrase",
         Identity_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Unsupported_Feature,
         "auth encrypted identity fixture",
         "encrypted legacy PEM rejects wrong passphrase before "
           & "unsupported legacy decrypt");
      Check (SSH_Lib.Identity_Files.Kind (Identity_Item) = SSH_Lib.Identity_Files.No_Key,
             "wrong encrypted legacy PEM passphrase clears key state");
      Status_Value := SSH_Lib.Identity_Files.Parse
        (SSH_Lib.Tests.Fixtures.Identity_Files.Encrypted_Legacy_RSA_AES256_CBC_Private_Key,
         "fixture-passphrase",
         Identity_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Unsupported_Feature,
         "auth encrypted identity fixture", "encrypted legacy PEM AES-256-CBC fixture fails closed while unsupported");
      Check (SSH_Lib.Identity_Files.Kind (Identity_Item) = SSH_Lib.Identity_Files.No_Key,
             "unsupported encrypted legacy PEM fixture leaves no identity");

      Status_Value := SSH_Lib.Identity_Files.Parse
        (SSH_Lib.Tests.Fixtures.Identity_Files.Encrypted_PKCS8_RSA_AES256_CBC_Private_Key,
         "wrong-passphrase",
         Identity_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Authentication_Failed,
         "auth encrypted identity fixture", "encrypted PKCS#8 rejects wrong passphrase");
      Check (SSH_Lib.Identity_Files.Kind (Identity_Item) = SSH_Lib.Identity_Files.No_Key,
             "wrong encrypted PKCS#8 passphrase clears key state");

      Status_Value := SSH_Lib.Identity_Files.Parse
        (SSH_Lib.Tests.Fixtures.Identity_Files.Encrypted_PKCS8_RSA_AES256_CBC_Private_Key,
         "fixture-passphrase",
         Identity_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "auth encrypted identity fixture", "encrypted PKCS#8 AES-256-CBC fixture parses");
      Check (SSH_Lib.Identity_Files.Kind (Identity_Item) = SSH_Lib.Identity_Files.RSA_Key,
             "encrypted PKCS#8 fixture becomes RSA identity");

      Status_Value := SSH_Lib.Identity_Files.Parse
        (SSH_Lib.Tests.Fixtures.Identity_Files.RSA_1024_PKCS8_Private_Key,
         Identity_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "auth certificate fixture", "RSA identity fixture parses before certificate attach");

      declare
         Cert_Path : constant String :=
           SSH_Lib.Tests.Fixtures.Temp_Paths.Path ("sk_user_certificate_identity.pub");
         Cert_File : Ada.Text_IO.File_Type;
      begin
         Ada.Text_IO.Create (Cert_File, Ada.Text_IO.Out_File, Cert_Path);
         Ada.Text_IO.Put_Line
           (Cert_File,
            "sk-ssh-ed25519-cert-v01@openssh.com AAAA unsupported-sk-cert-fixture");
         Ada.Text_IO.Close (Cert_File);

         Status_Value := SSH_Lib.Identity_Files.Attach_Public_Certificate
           (Cert_Path, Identity_Item);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Authentication_Failed,
            "auth certificate fixture", "SK Ed25519 certificate is rejected for file identity attach");
         Check (not SSH_Lib.Identity_Files.Has_Public_Certificate (Identity_Item),
                "rejected SK Ed25519 certificate leaves identity without certificate");

         Ada.Text_IO.Create (Cert_File, Ada.Text_IO.Out_File, Cert_Path);
         Ada.Text_IO.Put_Line
           (Cert_File,
            "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com AAAA unsupported-sk-cert-fixture");
         Ada.Text_IO.Close (Cert_File);

         Status_Value := SSH_Lib.Identity_Files.Attach_Public_Certificate
           (Cert_Path, Identity_Item);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Authentication_Failed,
            "auth certificate fixture", "SK ECDSA certificate is rejected for file identity attach");
         Check (not SSH_Lib.Identity_Files.Has_Public_Certificate (Identity_Item),
                "rejected SK ECDSA certificate leaves identity without certificate");
      end;
   end Assert_Malformed_Agent_And_Identity_Fixtures;


   procedure Assert_None_Userauth_Request_Encodes is
      Request_Buffer : constant SSH_Lib.Protocol.Buffers.Packet_Buffer :=
        SSH_Lib.Protocol.Userauth.Encode_None_Request ("git");
      Request_Data   : constant Stream_Element_Array :=
        SSH_Lib.Protocol.Buffers.To_Array (Request_Buffer);
      Decoded        : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Next_Index     : Stream_Element_Offset;
      Cursor         : Stream_Element_Offset;
      Status_Value   : CryptoLib.Errors.Status;
   begin
      Check (not SSH_Lib.Protocol.Buffers.Is_Empty (Request_Buffer),
             "none userauth request encodes");
      Check (Request_Data (Request_Data'First)
             = SSH_Lib.Protocol.Userauth.SSH_MSG_USERAUTH_REQUEST,
             "none userauth request uses USERAUTH_REQUEST message number");

      Cursor := Request_Data'First + 1;
      Status_Value := SSH_Lib.Protocol.Numbers.Decode_SSH_String
        (Request_Data, Cursor, Decoded, Next_Index);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "auth security", "none userauth user decodes");
      Check (SSH_Lib.Protocol.Buffers.To_Array (Decoded) = Bytes ("git"),
             "none userauth preserves requested user");

      Cursor := Next_Index;
      Status_Value := SSH_Lib.Protocol.Numbers.Decode_SSH_String
        (Request_Data, Cursor, Decoded, Next_Index);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "auth security", "none userauth service decodes");
      Check (SSH_Lib.Protocol.Buffers.To_Array (Decoded) = Bytes ("ssh-connection"),
             "none userauth targets ssh-connection service");

      Cursor := Next_Index;
      Status_Value := SSH_Lib.Protocol.Numbers.Decode_SSH_String
        (Request_Data, Cursor, Decoded, Next_Index);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "auth security", "none userauth method decodes");
      Check (SSH_Lib.Protocol.Buffers.To_Array (Decoded) = Bytes ("none"),
             "none userauth carries none method");
      Check (Next_Index = Request_Data'Last + 1,
             "none userauth request has no trailing bytes");

      Check (SSH_Lib.Protocol.Buffers.Is_Empty
               (SSH_Lib.Protocol.Userauth.Encode_None_Request ("bad" & Character'Val (10))),
             "none userauth rejects invalid user text");
   end Assert_None_Userauth_Request_Encodes;

end SSH_Lib.Tests.Fixtures.Auth_Security;
