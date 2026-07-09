with Ada.Characters.Handling;
with Ada.Directories;
with Ada.Strings.Unbounded;
with Interfaces;
with SSH_Lib.Agent;
with SSH_Lib.Agent.Client;
with SSH_Lib.Agent.Protocol;
with SSH_Lib.Identity_Files;
with SSH_Lib.Platform.Environment;
with SSH_Lib.Platform.Paths;
with SSH_Lib.Protocol.Buffers;
with SSH_Lib.Protocol.Certificates;
with SSH_Lib.Protocol.Host_Keys;
with SSH_Lib.Protocol.Numbers;
with SSH_Lib.Protocol.Service;
with SSH_Lib.Protocol.Transport_Messages;
with SSH_Lib.Protocol.Validation;
with SSH_Lib.Protocol.Userauth;
with SSH_Lib.Protocol.Userauth.Agent_Identity;
with SSH_Lib.Protocol.Userauth.Identity;
with SSH_Lib.Keys;

package body SSH_Lib.Sessions.Live_Userauth is
   use Ada.Streams;
   use Ada.Strings.Unbounded;
   use CryptoLib.Errors;
   use SSH_Lib.Protocol.Buffers;
   use type SSH_Lib.Protocol.Userauth.Reply_Kind;
   use type Interfaces.Unsigned_32;
   use type SSH_Lib.Protocol.Transport_Messages.Transport_Message_Kind;

   function Valid_Callback_Secret (Value : String) return Boolean is
   begin
      if Value'Length = 0 then
         return False;
      end if;

      for Char_Value of Value loop
         if Char_Value = Character'Val (0)
           or else Char_Value = Character'Val (10)
           or else Char_Value = Character'Val (13)
         then
            return False;
         end if;
      end loop;
      return True;
   exception
      when others =>
         return False;
   end Valid_Callback_Secret;

   function Valid_Keyboard_Interactive_Response (Value : String) return Boolean
   is
   begin
      for Char_Value of Value loop
         if Char_Value = Character'Val (0)
           or else Char_Value = Character'Val (10)
           or else Char_Value = Character'Val (13)
         then
            return False;
         end if;
      end loop;
      return True;
   exception
      when others =>
         return False;
   end Valid_Keyboard_Interactive_Response;

   procedure Clear_Keyboard_Interactive_Callback_Result
     (Item : in out Keyboard_Interactive_Callback_Result) is
   begin
      Item.Provided := False;
      Item.Response_Count := 0;
      for Response_Index in Keyboard_Interactive_Prompt_Index loop
         Item.Responses (Response_Index) := Null_Unbounded_String;
      end loop;
   exception
      when others =>
         null;
   end Clear_Keyboard_Interactive_Callback_Result;

   function To_Keyboard_Interactive_Challenge
     (Reply_Item : SSH_Lib.Protocol.Userauth.Reply)
      return Keyboard_Interactive_Challenge
   is
      Result : Keyboard_Interactive_Challenge;
      Count  : constant Natural :=
        Natural (Reply_Item.Keyboard_Interactive_Prompts);
   begin
      Result.Name := Reply_Item.Keyboard_Interactive_Name;
      Result.Instruction := Reply_Item.Keyboard_Interactive_Instruction;
      Result.Language_Tag := Reply_Item.Keyboard_Interactive_Language_Tag;
      Result.Prompt_Count := Count;
      for Prompt_Index in Keyboard_Interactive_Prompt_Index loop
         Result.Prompts (Prompt_Index).Text := Null_Unbounded_String;
         Result.Prompts (Prompt_Index).Echo := False;
      end loop;

      for Prompt_Index in 1 .. Count loop
         Result.Prompts (Prompt_Index).Text :=
           Reply_Item.Keyboard_Interactive_Prompt_Items (Prompt_Index).Text;
         Result.Prompts (Prompt_Index).Echo :=
           Reply_Item.Keyboard_Interactive_Prompt_Items (Prompt_Index).Echo;
      end loop;
      return Result;
   exception
      when others =>
         return Result : Keyboard_Interactive_Challenge do
            Result.Prompt_Count := 0;
         end return;
   end To_Keyboard_Interactive_Challenge;

   procedure Clear_Callback_Result (Item : in out Credential_Callback_Result)
   is
   begin
      Item.Provided := False;
      Item.Secret := Null_Unbounded_String;
   exception
      when others =>
         null;
   end Clear_Callback_Result;

   function Effective_Password
     (Options : Session_Options) return Unbounded_String
   is
      Callback_Result : Credential_Callback_Result;
      Explicit_Text   : constant String := To_String (Options.Password);

      function Finish (Result : Unbounded_String) return Unbounded_String is
      begin
         Clear_Callback_Result (Callback_Result);
         return Result;
      end Finish;
   begin
      if Explicit_Text'Length > 0 then
         return Options.Password;
      end if;

      if Options.Password_Callback = null then
         return Finish (Null_Unbounded_String);
      end if;

      Callback_Result :=
        Options.Password_Callback.all
          (To_String (Options.Host), To_String (Options.User));
      if Callback_Result.Provided
        and then Valid_Callback_Secret (To_String (Callback_Result.Secret))
      then
         declare
            Result_Secret : constant Unbounded_String :=
              Callback_Result.Secret;
         begin
            return Finish (Result_Secret);
         end;
      end if;

      return Finish (Null_Unbounded_String);
   exception
      when others =>
         Clear_Callback_Result (Callback_Result);
         return Null_Unbounded_String;
   end Effective_Password;

   function Effective_Identity_Passphrase
     (Options : Session_Options) return Unbounded_String
   is
      Callback_Result : Credential_Callback_Result;
      Explicit_Text   : constant String :=
        To_String (Options.Identity_Passphrase);

      function Finish (Result : Unbounded_String) return Unbounded_String is
      begin
         Clear_Callback_Result (Callback_Result);
         return Result;
      end Finish;
   begin
      if Options.Use_Identity_Passphrase and then Explicit_Text'Length > 0 then
         return Options.Identity_Passphrase;
      end if;

      if Options.Identity_Passphrase_Callback = null
        or else To_String (Options.Identity_File)'Length = 0
      then
         return Finish (Null_Unbounded_String);
      end if;

      Callback_Result :=
        Options.Identity_Passphrase_Callback.all
          (To_String (Options.Host),
           To_String (Options.User),
           To_String (Options.Identity_File));
      if Callback_Result.Provided
        and then Valid_Callback_Secret (To_String (Callback_Result.Secret))
      then
         declare
            Result_Secret : constant Unbounded_String :=
              Callback_Result.Secret;
         begin
            return Finish (Result_Secret);
         end;
      end if;

      return Finish (Null_Unbounded_String);
   exception
      when others =>
         Clear_Callback_Result (Callback_Result);
         return Null_Unbounded_String;
   end Effective_Identity_Passphrase;

   function Effective_New_Password
     (Options : Session_Options; Instruction : String) return Unbounded_String
   is
      Callback_Result : Credential_Callback_Result;

      function Finish (Result : Unbounded_String) return Unbounded_String is
      begin
         Clear_Callback_Result (Callback_Result);
         return Result;
      end Finish;
   begin
      if Options.Password_Change_Callback = null then
         return Finish (Null_Unbounded_String);
      end if;

      Callback_Result :=
        Options.Password_Change_Callback.all
          (To_String (Options.Host), To_String (Options.User), Instruction);
      if Callback_Result.Provided
        and then Valid_Callback_Secret (To_String (Callback_Result.Secret))
      then
         declare
            Result_Secret : constant Unbounded_String :=
              Callback_Result.Secret;
         begin
            return Finish (Result_Secret);
         end;
      end if;

      return Finish (Null_Unbounded_String);
   exception
      when others =>
         Clear_Callback_Result (Callback_Result);
         return Null_Unbounded_String;
   end Effective_New_Password;

   function Key_Algorithm_From_Public_Key_Blob
     (Key_Blob : Stream_Element_Array) return String
   is
      Algorithm_Buffer : Packet_Buffer;
      Next_Index       : Stream_Element_Offset;
      Status_Value     : Status;
   begin
      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_SSH_String
          (Key_Blob, Key_Blob'First, Algorithm_Buffer, Next_Index);
      if Status_Value /= Ok then
         return "";
      end if;

      declare
         Algorithm_Data : constant Stream_Element_Array :=
           To_Array (Algorithm_Buffer);
      begin
         if Algorithm_Data'Length = 0 then
            return "";
         end if;

         for Byte_Value of Algorithm_Data loop
            if Byte_Value > 127 then
               return "";
            end if;
         end loop;

         declare
            Result : String (1 .. Algorithm_Data'Length);
         begin
            for Offset_Value in 0 .. Algorithm_Data'Length - 1 loop
               Result (Result'First + Integer (Offset_Value)) :=
                 Character'Val
                   (Algorithm_Data
                      (Algorithm_Data'First
                       + Stream_Element_Offset (Offset_Value)));
            end loop;

            if not SSH_Lib.Protocol.Validation.Is_ASCII_Protocol_Name (Result)
            then
               return "";
            end if;

            if SSH_Lib.Protocol.Certificates.Is_Certificate_Algorithm (Result)
              or else Result = "ssh-ed25519"
              or else Result = "ecdsa-sha2-nistp256"
              or else Result = "ecdsa-sha2-nistp384"
              or else Result = "ecdsa-sha2-nistp521"
              or else Result = "sk-ssh-ed25519@openssh.com"
              or else Result = "sk-ecdsa-sha2-nistp256@openssh.com"
              or else Result = "ssh-rsa"
            then
               return Result;
            else
               return "";
            end if;
         end;
      end;
   exception
      when others =>
         return "";
   end Key_Algorithm_From_Public_Key_Blob;

   function Validate_Agent_Public_Key_Blob
     (Key_Blob : Stream_Element_Array; Key_Algorithm : String) return Status
   is
      Parsed_Key   : SSH_Lib.Keys.Public_Key;
      Status_Value : Status;
   begin
      if Key_Algorithm'Length = 0 then
         return Authentication_Failed;
      end if;

      if SSH_Lib.Protocol.Certificates.Is_Certificate_Algorithm (Key_Algorithm)
      then
         return
           SSH_Lib.Protocol.Certificates.Validate_User_Certificate_For_Auth
             (Key_Blob, Key_Algorithm);
      end if;

      --  Agent identities are untrusted input from an external process.  Do
      --  not rely solely on the leading algorithm string: parse the full key
      --  blob before publickey preflight or agent signing.  This validates
      --  Ed25519 sizes, RSA structure, ECDSA P-256 points, and OpenSSH
      --  security-key application fields through the shared host-key parser.
      Status_Value :=
        SSH_Lib.Protocol.Host_Keys.Parse (Key_Blob, Key_Algorithm, Parsed_Key);
      if Status_Value = Ok then
         return Ok;
      elsif Status_Value = Internal_Error then
         return Internal_Error;
      else
         return Authentication_Failed;
      end if;
   exception
      when others =>
         return Internal_Error;
   end Validate_Agent_Public_Key_Blob;

   function Userauth_Algorithm_For_Attempt
     (Key_Algorithm : String; Attempt_Count : Positive) return String is
   begin
      if Key_Algorithm = "ssh-rsa" then
         if Attempt_Count = 1 then
            return "rsa-sha2-512";
         elsif Attempt_Count = 2 then
            return "rsa-sha2-256";
         elsif Attempt_Count = 3 then
            return "ssh-rsa";
         else
            return "";
         end if;
      elsif Attempt_Count = 1 then
         return Key_Algorithm;
      else
         return "";
      end if;
   exception
      when others =>
         return "";
   end Userauth_Algorithm_For_Attempt;

   function Signature_Algorithm_For_Userauth
     (Key_Algorithm : String; Userauth_Algorithm : String) return String is
   begin
      if SSH_Lib.Protocol.Certificates.Is_Certificate_Algorithm
           (Userauth_Algorithm)
      then
         return
           SSH_Lib.Protocol.Certificates.Raw_Algorithm_For_Certificate
             (Userauth_Algorithm);
      elsif Key_Algorithm = "ssh-rsa" and then Userauth_Algorithm = "ssh-rsa"
      then
         return "ssh-rsa";
      elsif Key_Algorithm = "ssh-rsa"
        and then Userauth_Algorithm = "rsa-sha2-256"
      then
         return "rsa-sha2-256";
      elsif Key_Algorithm = "ssh-rsa"
        and then Userauth_Algorithm = "rsa-sha2-512"
      then
         return "rsa-sha2-512";
      else
         return Userauth_Algorithm;
      end if;
   exception
      when others =>
         return "";
   end Signature_Algorithm_For_Userauth;

   function Is_Method_Fallback_Status (Value : Status) return Boolean is
   begin
      return Value = Authentication_Failed or else Value = Unsupported_Feature;
   end Is_Method_Fallback_Status;

   function Name_In_Comma_List
     (List_Text : String; Name_Text : String) return Boolean
   is
      Start_Index : Positive := List_Text'First;
      Stop_Index  : Natural;
      Lower_Name  : constant String :=
        Ada.Characters.Handling.To_Lower (Name_Text);
   begin
      if List_Text'Length = 0 then
         return False;
      end if;

      loop
         Stop_Index := Start_Index;
         while Stop_Index <= List_Text'Last
           and then List_Text (Stop_Index) /= ','
         loop
            Stop_Index := Stop_Index + 1;
         end loop;

         if Ada.Characters.Handling.To_Lower
              (List_Text (Start_Index .. Stop_Index - 1))
           = Lower_Name
         then
            return True;
         end if;

         exit when Stop_Index > List_Text'Last;
         Start_Index := Stop_Index + 1;
      end loop;
      return False;
   exception
      when others =>
         return False;
   end Name_In_Comma_List;

   function Authentication_Method_Enabled
     (Options : Session_Options; Method_Name : String) return Boolean
   is
      List_Text : constant String :=
        To_String (Options.Preferred_Authentications);
   begin
      if Method_Name = "publickey" and then not Options.Pubkey_Authentication
      then
         return False;
      elsif Method_Name = "keyboard-interactive"
        and then not Options.Kbd_Interactive_Authentication
      then
         return False;
      elsif Method_Name = "password"
        and then not Options.Password_Authentication
      then
         return False;
      end if;

      return
        List_Text'Length = 0
        or else Name_In_Comma_List (List_Text, Method_Name);
   end Authentication_Method_Enabled;

   function Publickey_Algorithm_Allowed
     (Options : Session_Options; Algorithm_Name : String) return Boolean
   is
      List_Text : constant String :=
        To_String (Options.Pubkey_Accepted_Algorithms);
   begin
      return
        List_Text'Length = 0
        or else Name_In_Comma_List (List_Text, Algorithm_Name);
   end Publickey_Algorithm_Allowed;

   function Record_Last_Userauth_Request
     (Transcript : SSH_Lib.Sessions.Live_Transcript.Driver;
      Item       : in out Session;
      Plain      : Packet_Buffer) return Status
   is
      Status_Value : Status;
   begin
      Status_Value := Set (Item.Live_Last_Plain_Userauth, To_Array (Plain));
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      return
        Set
          (Item.Live_Last_Protected_Userauth,
           SSH_Lib.Sessions.Live_Transcript.Last_Protected_Outbound
             (Transcript));
   exception
      when others =>
         return Internal_Error;
   end Record_Last_Userauth_Request;

   function Record_Last_Password_Userauth_Request
     (Transcript : SSH_Lib.Sessions.Live_Transcript.Driver;
      Item       : in out Session;
      User_Name  : String) return Status
   is
      Redacted_Request : Packet_Buffer;
      Status_Value     : Status;
   begin
      --  Password authentication is the one USERAUTH_REQUEST whose plain
      --  transcript contains a reusable credential.  Keep the protected
      --  outbound packet transcript for boundary debugging, but store only a
      --  structurally equivalent redacted plain request in the session.
      Redacted_Request :=
        SSH_Lib.Protocol.Userauth.Encode_Password_Request
          (User_Name, "<redacted>");
      if Is_Empty (Redacted_Request) then
         return Internal_Error;
      end if;

      Status_Value :=
        Set (Item.Live_Last_Plain_Userauth, To_Array (Redacted_Request));
      Clear (Redacted_Request);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      return
        Set
          (Item.Live_Last_Protected_Userauth,
           SSH_Lib.Sessions.Live_Transcript.Last_Protected_Outbound
             (Transcript));
   exception
      when others =>
         Clear (Redacted_Request);
         return Internal_Error;
   end Record_Last_Password_Userauth_Request;

   function Record_Last_Keyboard_Interactive_Response
     (Transcript     : SSH_Lib.Sessions.Live_Transcript.Driver;
      Item           : in out Session;
      Response_Count : Natural) return Status
   is
      Redacted_Response  : Packet_Buffer;
      Redacted_Responses :
        SSH_Lib.Protocol.Userauth.Keyboard_Interactive_Response_Array :=
          [others => Null_Unbounded_String];
      Status_Value       : Status;
   begin
      if Response_Count > Max_Keyboard_Interactive_Prompts then
         return Internal_Error;
      end if;

      for Response_Index in 1 .. Response_Count loop
         Redacted_Responses (Response_Index) :=
           To_Unbounded_String ("<redacted>");
      end loop;

      Redacted_Response :=
        SSH_Lib.Protocol.Userauth.Encode_Keyboard_Interactive_Responses
          (Response_Count, Redacted_Responses);
      if Is_Empty (Redacted_Response) then
         return Internal_Error;
      end if;

      Status_Value :=
        Set (Item.Live_Last_Plain_Userauth, To_Array (Redacted_Response));
      Clear (Redacted_Response);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      return
        Set
          (Item.Live_Last_Protected_Userauth,
           SSH_Lib.Sessions.Live_Transcript.Last_Protected_Outbound
             (Transcript));
   exception
      when others =>
         Clear (Redacted_Response);
         return Internal_Error;
   end Record_Last_Keyboard_Interactive_Response;

   function Record_Last_Userauth_Response
     (Transcript : SSH_Lib.Sessions.Live_Transcript.Driver;
      Item       : in out Session;
      Plain      : Packet_Buffer) return Status
   is
      Status_Value : Status;
   begin
      Status_Value :=
        Set (Item.Live_Last_Plain_Userauth_Response, To_Array (Plain));
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      return
        Set
          (Item.Live_Last_Protected_Userauth_Response,
           SSH_Lib.Sessions.Live_Transcript.Last_Protected_Inbound
             (Transcript));
   exception
      when others =>
         return Internal_Error;
   end Record_Last_Userauth_Response;

   function Run_Service_Request
     (Transcript : in out SSH_Lib.Sessions.Live_Transcript.Driver;
      Item       : in out Session) return Status
   is
      Request_Buffer : constant Packet_Buffer :=
        SSH_Lib.Protocol.Service.Encode_Userauth_Service_Request;
      Reply_Buffer   : Packet_Buffer;
      Status_Value   : Status;
   begin
      Clear (Item.Live_Last_Plain_Service);
      Clear (Item.Live_Last_Protected_Service);
      Clear (Item.Live_Last_Plain_Service_Response);
      Clear (Item.Live_Last_Protected_Service_Response);

      if Is_Empty (Request_Buffer) then
         return Handshake_Failed;
      end if;

      Status_Value :=
        Set (Item.Live_Last_Plain_Service, To_Array (Request_Buffer));
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      Status_Value :=
        SSH_Lib.Sessions.Live_Transcript.Send_Protected_Packet
          (Transcript, To_Array (Request_Buffer));
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      Status_Value :=
        Set
          (Item.Live_Last_Protected_Service,
           SSH_Lib.Sessions.Live_Transcript.Last_Protected_Outbound
             (Transcript));
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      --  Some SSH peers may interleave transport keepalive/debug packets
      --  before the service accept.  They are not service completion; skip
      --  bounded ignorable transport messages and fail closed on disconnect or
      --  any other unexpected packet.
      for Attempt_Count in 1 .. 8 loop
         Status_Value :=
           SSH_Lib.Sessions.Live_Transcript.Read_Protected_Packet
             (Transcript, Reply_Buffer);
         if Status_Value /= Ok then
            return Status_Value;
         end if;

         Status_Value :=
           Set
             (Item.Live_Last_Plain_Service_Response, To_Array (Reply_Buffer));
         if Status_Value /= Ok then
            return Status_Value;
         end if;

         Status_Value :=
           Set
             (Item.Live_Last_Protected_Service_Response,
              SSH_Lib.Sessions.Live_Transcript.Last_Protected_Inbound
                (Transcript));
         if Status_Value /= Ok then
            return Status_Value;
         end if;

         Status_Value :=
           SSH_Lib.Protocol.Service.Parse_Service_Accept
             (To_Array (Reply_Buffer), "ssh-userauth");
         if Status_Value = Ok then
            exit;
         end if;

         declare
            Reply_Data : constant Stream_Element_Array :=
              To_Array (Reply_Buffer);
         begin
            if SSH_Lib.Protocol.Transport_Messages.Classify (Reply_Data)
              = SSH_Lib.Protocol.Transport_Messages.Transport_Disconnect
            then
               return Connection_Failed;
            elsif SSH_Lib.Protocol.Transport_Messages.Is_Ignorable_During_Wait
                    (Reply_Data)
            then
               if Attempt_Count = 8 then
                  return Handshake_Failed;
               end if;
            else
               return Status_Value;
            end if;
         end;
      end loop;

      Item.Userauth_Service_Accepted := True;
      return Ok;
   exception
      when others =>
         return Internal_Error;
   end Run_Service_Request;

   function Read_Auth_Reply
     (Transcript : in out SSH_Lib.Sessions.Live_Transcript.Driver;
      Item       : in out Session;
      Context    : SSH_Lib.Protocol.Userauth.Reply_Context :=
        SSH_Lib.Protocol.Userauth.Signed_Reply) return Status
   is
      Reply_Buffer : Packet_Buffer;
      Reply_Value  : SSH_Lib.Protocol.Userauth.Reply;
      Status_Value : Status;
   begin
      --  Real servers may send one or more USERAUTH_BANNER messages between
      --  a signed publickey request and the terminal SUCCESS/FAILURE reply.
      --  A banner is protocol data, not authentication completion.  Preserve
      --  the most recent protected/plain response transcript for diagnostics,
      --  but keep reading until a terminal reply arrives or the bounded guard
      --  is exhausted.
      for Attempt_Count in 1 .. 16 loop
         Status_Value :=
           SSH_Lib.Sessions.Live_Transcript.Read_Protected_Packet
             (Transcript, Reply_Buffer);
         if Status_Value /= Ok then
            return Status_Value;
         end if;

         Status_Value :=
           Record_Last_Userauth_Response (Transcript, Item, Reply_Buffer);
         if Status_Value /= Ok then
            return Status_Value;
         end if;

         Status_Value :=
           SSH_Lib.Protocol.Userauth.Parse_Userauth_Reply
             (To_Array (Reply_Buffer), Context, Reply_Value);
         if Status_Value /= Ok then
            declare
               Reply_Data : constant Stream_Element_Array :=
                 To_Array (Reply_Buffer);
            begin
               if SSH_Lib.Protocol.Transport_Messages.Classify (Reply_Data)
                 = SSH_Lib.Protocol.Transport_Messages.Transport_Disconnect
               then
                  return Authentication_Failed;
               elsif SSH_Lib
                       .Protocol
                       .Transport_Messages
                       .Is_Ignorable_During_Wait (Reply_Data)
               then
                  null;
               else
                  return Status_Value;
               end if;
            end;
         elsif Reply_Value.Kind = SSH_Lib.Protocol.Userauth.Auth_Success then
            return Ok;
         elsif Reply_Value.Kind = SSH_Lib.Protocol.Userauth.Auth_Failure then
            return Authentication_Failed;
         elsif Reply_Value.Kind = SSH_Lib.Protocol.Userauth.Auth_Banner then
            null;
         elsif Reply_Value.Kind
           = SSH_Lib.Protocol.Userauth.Password_Change_Required
         then
            return Authentication_Failed;
         else
            return Authentication_Failed;
         end if;
      end loop;

      return Authentication_Failed;
   exception
      when others =>
         return Internal_Error;
   end Read_Auth_Reply;

   function Activate_Post_Auth_Compression
     (Transcript : in out SSH_Lib.Sessions.Live_Transcript.Driver;
      Item       : in out Session) return Status
   is
      Status_Value : constant Status :=
        SSH_Lib.Sessions.Live_Transcript.Activate_Delayed_Compression
          (Transcript);
   begin
      if Status_Value /= Ok then
         Item.Session_Dirty := True;
         Item.Failure_Status := Status_Value;
      end if;
      return Status_Value;
   exception
      when others =>
         Item.Session_Dirty := True;
         Item.Failure_Status := Internal_Error;
         return Internal_Error;
   end Activate_Post_Auth_Compression;

   function Try_None
     (Transcript : in out SSH_Lib.Sessions.Live_Transcript.Driver;
      Options    : Session_Options;
      Item       : in out Session) return Status
   is
      Request_Buffer : Packet_Buffer;
      Status_Value   : Status;

      function Finish (Result : Status) return Status is
      begin
         Clear (Request_Buffer);
         return Result;
      end Finish;
   begin
      Request_Buffer :=
        SSH_Lib.Protocol.Userauth.Encode_None_Request
          (To_String (Options.User));
      if Is_Empty (Request_Buffer) then
         return Finish (Authentication_Failed);
      end if;

      Status_Value :=
        SSH_Lib.Sessions.Live_Transcript.Send_Protected_Packet
          (Transcript, To_Array (Request_Buffer));
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      Status_Value :=
        Record_Last_Userauth_Request (Transcript, Item, Request_Buffer);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      Status_Value :=
        Read_Auth_Reply
          (Transcript, Item, SSH_Lib.Protocol.Userauth.Signed_Reply);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      Status_Value := Activate_Post_Auth_Compression (Transcript, Item);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      Item.User_Authenticated := True;
      Item.Authenticated_User_Name := Options.User;
      Item.Authentication_Method_Used := None_Authentication;
      return Finish (Ok);
   exception
      when others =>
         Clear (Request_Buffer);
         return Internal_Error;
   end Try_None;

   function Run_Publickey_Preflight
     (Transcript : in out SSH_Lib.Sessions.Live_Transcript.Driver;
      Item       : in out Session;
      User_Name  : String;
      Algorithm  : String;
      Key_Blob   : Stream_Element_Array) return Status
   is
      Request_Buffer : Packet_Buffer;
      Reply_Buffer   : Packet_Buffer;
      Reply_Value    : SSH_Lib.Protocol.Userauth.Reply;
      Status_Value   : Status;
   begin
      Request_Buffer :=
        SSH_Lib.Protocol.Userauth.Encode_Publickey_Test_Request
          (User_Name, Algorithm, Key_Blob);
      if Is_Empty (Request_Buffer) then
         return Authentication_Failed;
      end if;

      Status_Value :=
        SSH_Lib.Sessions.Live_Transcript.Send_Protected_Packet
          (Transcript, To_Array (Request_Buffer));
      if Status_Value /= Ok then
         Clear (Request_Buffer);
         return Status_Value;
      end if;

      Status_Value :=
        Record_Last_Userauth_Request (Transcript, Item, Request_Buffer);
      Clear (Request_Buffer);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      --  RFC 4252 lets a client test whether a public key is acceptable
      --  before asking an identity file or agent to produce a signature.  This
      --  keeps the live runtime from needlessly exercising private-key or
      --  agent signing boundaries for keys the server already rejected.  The
      --  loop mirrors the signed-reply reader: banners and transport/debug
      --  packets are not terminal authentication results.
      for Attempt_Count in 1 .. 16 loop
         Status_Value :=
           SSH_Lib.Sessions.Live_Transcript.Read_Protected_Packet
             (Transcript, Reply_Buffer);
         if Status_Value /= Ok then
            return Status_Value;
         end if;

         Status_Value :=
           Record_Last_Userauth_Response (Transcript, Item, Reply_Buffer);
         if Status_Value /= Ok then
            return Status_Value;
         end if;

         Status_Value :=
           SSH_Lib.Protocol.Userauth.Parse_Userauth_Reply
             (To_Array (Reply_Buffer),
              SSH_Lib.Protocol.Userauth.Preflight_Reply,
              Reply_Value);

         if Status_Value = Ok
           and then Reply_Value.Kind = SSH_Lib.Protocol.Userauth.Public_Key_Ok
         then
            if To_String (Reply_Value.Public_Key_Algorithm) /= Algorithm
              or else To_Array (Reply_Value.Public_Key_Blob) /= Key_Blob
            then
               return Authentication_Failed;
            end if;
            return Ok;
         elsif Status_Value = Ok
           and then Reply_Value.Kind = SSH_Lib.Protocol.Userauth.Auth_Failure
         then
            return Authentication_Failed;
         elsif Status_Value = Ok
           and then Reply_Value.Kind = SSH_Lib.Protocol.Userauth.Auth_Banner
         then
            null;
         else
            declare
               Reply_Data : constant Stream_Element_Array :=
                 To_Array (Reply_Buffer);
            begin
               if SSH_Lib.Protocol.Transport_Messages.Classify (Reply_Data)
                 = SSH_Lib.Protocol.Transport_Messages.Transport_Disconnect
               then
                  return Authentication_Failed;
               elsif SSH_Lib
                       .Protocol
                       .Transport_Messages
                       .Is_Ignorable_During_Wait (Reply_Data)
               then
                  null;
               else
                  if Status_Value = Ok then
                     return Authentication_Failed;
                  else
                     return Status_Value;
                  end if;
               end if;
            end;
         end if;
      end loop;

      return Authentication_Failed;
   exception
      when others =>
         Clear (Request_Buffer);
         return Internal_Error;
   end Run_Publickey_Preflight;

   function Try_Identity_File
     (Transcript         : in out SSH_Lib.Sessions.Live_Transcript.Driver;
      Options            : Session_Options;
      Session_Identifier : Stream_Element_Array;
      Item               : in out Session) return Status
   is
      Key_Item       : SSH_Lib.Identity_Files.Identity_Key;
      Request_Buffer : Packet_Buffer;
      Status_Value   : Status;

      function Finish (Result : Status) return Status is
      begin
         SSH_Lib.Identity_Files.Clear (Key_Item);
         Clear (Request_Buffer);
         return Result;
      exception
         when others =>
            return Internal_Error;
      end Finish;
   begin
      if not Authentication_Method_Enabled (Options, "publickey") then
         return Finish (Authentication_Failed);
      end if;

      Status_Value :=
        SSH_Lib.Identity_Files.Load
          (To_String (Options.Identity_File),
           To_String (Effective_Identity_Passphrase (Options)),
           Key_Item);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      declare
         Configured_Certificate : constant String :=
           To_String (Options.Certificate_File);
         Default_Certificate    : constant String :=
           To_String (Options.Identity_File) & "-cert.pub";
         Certificate_Path       : constant String :=
           (if Configured_Certificate'Length > 0
            then Configured_Certificate
            else Default_Certificate);
         Attach_Status          : Status;
      begin
         if Certificate_Path'Length > 0
           and then Ada.Directories.Exists (Certificate_Path)
         then
            Attach_Status :=
              SSH_Lib.Identity_Files.Attach_Public_Certificate
                (Certificate_Path, Key_Item);
            if Attach_Status /= Ok then
               if Configured_Certificate'Length > 0 then
                  --  An explicit CertificateFile is caller-selected
                  --  authentication material.  If it exists but is malformed,
                  --  expired, mismatched with the private key, or uses an
                  --  unsupported certificate policy, fail closed instead of
                  --  silently falling back to the raw private key.
                  return Finish (Attach_Status);
               elsif not Is_Method_Fallback_Status (Attach_Status) then
                  return Finish (Attach_Status);
               end if;
            end if;
         elsif Configured_Certificate'Length > 0 then
            --  An explicit CertificateFile is part of the caller's selected
            --  authentication material.  Unlike the implicit <identity>-cert.pub
            --  convention, a missing explicit certificate is not silently
            --  ignored.
            return Finish (Authentication_Failed);
         end if;
      end;

      declare
         Key_Algorithm_Text         : constant String :=
           (if SSH_Lib.Identity_Files.Has_Public_Certificate (Key_Item)
            then SSH_Lib.Identity_Files.Certificate_Algorithm_Name (Key_Item)
            else SSH_Lib.Identity_Files.Algorithm_Name (Key_Item));
         Signing_Key_Algorithm_Text : constant String :=
           SSH_Lib.Identity_Files.Algorithm_Name (Key_Item);
         Public_Blob                : constant Stream_Element_Array :=
           (if SSH_Lib.Identity_Files.Has_Public_Certificate (Key_Item)
            then SSH_Lib.Identity_Files.Certificate_Public_Key_Blob (Key_Item)
            else SSH_Lib.Identity_Files.Public_Key_Blob (Key_Item));
         Previous_Status            : Status := Authentication_Failed;
      begin
         for Attempt_Count in 1 .. 3 loop
            declare
               Algorithm_Text : constant String :=
                 Userauth_Algorithm_For_Attempt
                   (Key_Algorithm_Text, Attempt_Count);
            begin
               exit when Algorithm_Text'Length = 0;

               if not Publickey_Algorithm_Allowed (Options, Algorithm_Text)
               then
                  Previous_Status := Authentication_Failed;
               else
                  Status_Value :=
                    Run_Publickey_Preflight
                      (Transcript,
                       Item,
                       To_String (Options.User),
                       Algorithm_Text,
                       Public_Blob);

                  if Status_Value = Ok then
                     Status_Value :=
                       SSH_Lib
                         .Protocol
                         .Userauth
                         .Identity
                         .Build_Signed_Request_With_Public_Blob
                            (Key_Item,
                             Session_Identifier,
                             To_String (Options.User),
                             Algorithm_Text,
                             Public_Blob,
                             Signature_Algorithm_For_Userauth
                               (Signing_Key_Algorithm_Text, Algorithm_Text),
                             Request_Buffer);
                  end if;

                  if Status_Value = Ok then
                     exit;
                  elsif Is_Method_Fallback_Status (Status_Value) then
                     Previous_Status := Status_Value;
                  else
                     return Status_Value;
                  end if;
               end if;
            end;
         end loop;

         if Status_Value /= Ok then
            return Finish (Previous_Status);
         end if;
      end;

      Status_Value :=
        SSH_Lib.Sessions.Live_Transcript.Send_Protected_Packet
          (Transcript, To_Array (Request_Buffer));
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      Status_Value :=
        Record_Last_Userauth_Request (Transcript, Item, Request_Buffer);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      Status_Value := Read_Auth_Reply (Transcript, Item);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      Status_Value := Activate_Post_Auth_Compression (Transcript, Item);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      Item.User_Authenticated := True;
      Item.Authenticated_User_Name := Options.User;
      Item.Authentication_Method_Used := Identity_File_Authentication;
      return Finish (Ok);
   exception
      when others =>
         SSH_Lib.Identity_Files.Clear (Key_Item);
         Clear (Request_Buffer);
         return Internal_Error;
   end Try_Identity_File;

   function Try_Default_Identity_Files
     (Transcript         : in out SSH_Lib.Sessions.Live_Transcript.Driver;
      Options            : Session_Options;
      Session_Identifier : Stream_Element_Array;
      Item               : in out Session) return Status
   is
      Home_Text       : constant String :=
        To_String (SSH_Lib.Platform.Paths.Home_Directory);
      Previous_Status : Status := Authentication_Failed;
   begin
      --  OpenSSH normally tries a small set of default identity files when the
      --  caller has not provided an explicit IdentityFile.  Keep this bounded
      --  and data-only: do not glob, do not shell-expand, and do not retain key
      --  material after each method attempt.
      if Home_Text'Length = 0
        or else To_String (Options.Identity_File)'Length > 0
      then
         return Authentication_Failed;
      end if;

      declare
         Candidate_1 : constant String := Home_Text & "/.ssh/id_ed25519";
         Candidate_2 : constant String := Home_Text & "/.ssh/id_rsa";
      begin
         if Ada.Directories.Exists (Candidate_1) then
            declare
               Candidate_Options : Session_Options := Options;
            begin
               Candidate_Options.Identity_File :=
                 To_Unbounded_String (Candidate_1);
               Previous_Status :=
                 Try_Identity_File
                   (Transcript, Candidate_Options, Session_Identifier, Item);
               if Previous_Status = Ok then
                  return Ok;
               elsif not Is_Method_Fallback_Status (Previous_Status) then
                  return Previous_Status;
               end if;
            end;
         end if;

         if Ada.Directories.Exists (Candidate_2) then
            declare
               Candidate_Options : Session_Options := Options;
            begin
               Candidate_Options.Identity_File :=
                 To_Unbounded_String (Candidate_2);
               Previous_Status :=
                 Try_Identity_File
                   (Transcript, Candidate_Options, Session_Identifier, Item);
               if Previous_Status = Ok then
                  return Ok;
               elsif not Is_Method_Fallback_Status (Previous_Status) then
                  return Previous_Status;
               end if;
            end;
         end if;
      end;

      return Previous_Status;
   exception
      when others =>
         return Internal_Error;
   end Try_Default_Identity_Files;

   function Try_Agent
     (Transcript         : in out SSH_Lib.Sessions.Live_Transcript.Driver;
      Options            : Session_Options;
      Session_Identifier : Stream_Element_Array;
      Item               : in out Session) return Status
   is
      Socket_Path    : constant String :=
        (if To_String (Options.Identity_Agent)'Length > 0
         then To_String (Options.Identity_Agent)
         else
           To_String (SSH_Lib.Platform.Environment.Getenv ("SSH_AUTH_SOCK")));
      Identities     : SSH_Lib.Agent.Identity_List;
      Signature_Blob : Packet_Buffer;
      Sign_Payload   : Packet_Buffer;
      Request_Buffer : Packet_Buffer;
      Status_Value   : Status;
   begin
      if not Authentication_Method_Enabled (Options, "publickey") then
         return Authentication_Failed;
      end if;

      if Ada.Characters.Handling.To_Lower (To_String (Options.Identity_Agent))
        = "none"
      then
         return Authentication_Failed;
      end if;

      if Socket_Path'Length = 0 then
         return Authentication_Failed;
      end if;

      Status_Value :=
        SSH_Lib.Agent.Client.Request_Identities
          (Socket_Path, Options.Connect_Timeout_MS, Identities);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      for Index_Value in 1 .. SSH_Lib.Agent.Count (Identities) loop
         declare
            Key_Blob           : constant Stream_Element_Array :=
              SSH_Lib.Agent.Public_Key_Blob (Identities, Index_Value);
            Key_Algorithm_Name : constant String :=
              Key_Algorithm_From_Public_Key_Blob (Key_Blob);
            Use_Identity       : Boolean := True;
         begin
            if Key_Algorithm_Name'Length = 0 then
               --  Malformed, empty, non-ASCII, or unsupported agent identity
               --  algorithms must not reach publickey preflight or signing.
               --  Key_Algorithm_From_Public_Key_Blob already performs the
               --  allow-list check; make the skip explicit here so later
               --  control-flow changes cannot accidentally offer an empty
               --  algorithm name to USERAUTH_REQUEST.
               Use_Identity := False;
            else
               Status_Value :=
                 Validate_Agent_Public_Key_Blob (Key_Blob, Key_Algorithm_Name);
               if Status_Value = Internal_Error then
                  return Internal_Error;
               elsif Status_Value /= Ok then
                  Use_Identity := False;
               end if;
            end if;

            if Use_Identity then
               for Attempt_Count in 1 .. 3 loop
                  declare
                     Algorithm_Name : constant String :=
                       Userauth_Algorithm_For_Attempt
                         (Key_Algorithm_Name, Attempt_Count);
                  begin
                     exit when Algorithm_Name'Length = 0;
                     if not Publickey_Algorithm_Allowed
                              (Options, Algorithm_Name)
                     then
                        null;
                     else
                        Clear (Sign_Payload);
                        Clear (Signature_Blob);
                        Clear (Request_Buffer);

                        Status_Value :=
                          Run_Publickey_Preflight
                            (Transcript,
                             Item,
                             To_String (Options.User),
                             Algorithm_Name,
                             Key_Blob);

                        if Status_Value = Ok then
                           Sign_Payload :=
                             SSH_Lib
                               .Protocol
                               .Userauth
                               .Build_Publickey_Signature_Payload
                                  (Session_Identifier,
                                   To_String (Options.User),
                                   Algorithm_Name,
                                   Key_Blob);
                        end if;

                        if Status_Value = Ok
                          and then not Is_Empty (Sign_Payload)
                        then
                           declare
                              Signature_Algorithm_Name : constant String :=
                                Signature_Algorithm_For_Userauth
                                  (Key_Algorithm_Name, Algorithm_Name);
                           begin
                              Status_Value :=
                                SSH_Lib.Agent.Client.Request_Signature
                                  (Socket_Path,
                                   Options.Connect_Timeout_MS,
                                   Key_Blob,
                                   To_Array (Sign_Payload),
                                   Signature_Algorithm_Name,
                                   Signature_Blob);

                              if Status_Value = Ok then
                                 Status_Value :=
                                   Set
                                     (Item.Live_Last_Agent_Sign_Request,
                                      To_Array
                                        (SSH_Lib
                                           .Agent
                                           .Protocol
                                           .Encode_Sign_Request
                                              (Key_Blob,
                                               To_Array (Sign_Payload),
                                               Signature_Algorithm_Name)));
                                 if Status_Value /= Ok then
                                    return Status_Value;
                                 end if;

                                 Status_Value :=
                                   Set
                                     (Item.Live_Last_Agent_Sign_Response,
                                      To_Array (Signature_Blob));
                                 if Status_Value /= Ok then
                                    return Status_Value;
                                 end if;

                                 Status_Value :=
                                   SSH_Lib
                                     .Protocol
                                     .Userauth
                                     .Agent_Identity
                                     .Build_Signed_Request_From_Agent_Signature
                                        (Key_Blob,
                                         To_Array (Signature_Blob),
                                         Session_Identifier,
                                         To_String (Options.User),
                                         Algorithm_Name,
                                         Request_Buffer);
                                 if Status_Value = Ok then
                                    Status_Value :=
                                      SSH_Lib
                                        .Sessions
                                        .Live_Transcript
                                        .Send_Protected_Packet
                                           (Transcript,
                                            To_Array (Request_Buffer));
                                    if Status_Value /= Ok then
                                       return Status_Value;
                                    end if;

                                    Status_Value :=
                                      Record_Last_Userauth_Request
                                        (Transcript, Item, Request_Buffer);
                                    if Status_Value /= Ok then
                                       return Status_Value;
                                    end if;

                                    Status_Value :=
                                      Read_Auth_Reply (Transcript, Item);
                                    if Status_Value = Ok then
                                       Status_Value :=
                                         Activate_Post_Auth_Compression
                                           (Transcript, Item);
                                       if Status_Value /= Ok then
                                          return Status_Value;
                                       end if;

                                       Item.User_Authenticated := True;
                                       Item.Authenticated_User_Name :=
                                         Options.User;
                                       Item.Authentication_Method_Used :=
                                         Agent_Authentication;
                                       return Ok;
                                    elsif not Is_Method_Fallback_Status
                                                (Status_Value)
                                    then
                                       return Status_Value;
                                    end if;
                                 end if;
                              elsif not Is_Method_Fallback_Status
                                          (Status_Value)
                              then
                                 return Status_Value;
                              end if;
                           end;
                        elsif not Is_Method_Fallback_Status (Status_Value) then
                           return Status_Value;
                        end if;
                     end if;
                  end;
               end loop;
            end if;
         end;
      end loop;

      return Authentication_Failed;
   exception
      when others =>
         return Internal_Error;
   end Try_Agent;

   function Read_Password_Reply
     (Transcript : in out SSH_Lib.Sessions.Live_Transcript.Driver;
      Item       : in out Session;
      Reply_Item : out SSH_Lib.Protocol.Userauth.Reply) return Status
   is
      Reply_Buffer : Packet_Buffer;
      Status_Value : Status;
   begin
      loop
         Status_Value :=
           SSH_Lib.Sessions.Live_Transcript.Read_Protected_Packet
             (Transcript, Reply_Buffer);

         if Status_Value = Ok then
            Status_Value :=
              Record_Last_Userauth_Response (Transcript, Item, Reply_Buffer);
         end if;

         if Status_Value = Ok then
            Status_Value :=
              SSH_Lib.Protocol.Userauth.Parse_Userauth_Reply
                (To_Array (Reply_Buffer),
                 SSH_Lib.Protocol.Userauth.Password_Reply,
                 Reply_Item);
         end if;

         if Status_Value = Ok
           and then Reply_Item.Kind = SSH_Lib.Protocol.Userauth.Auth_Success
         then
            return Ok;
         elsif Status_Value = Ok
           and then
             Reply_Item.Kind
             = SSH_Lib.Protocol.Userauth.Password_Change_Required
         then
            return Ok;
         elsif Status_Value = Ok
           and then Reply_Item.Kind = SSH_Lib.Protocol.Userauth.Auth_Failure
         then
            return Authentication_Failed;
         elsif Status_Value = Ok
           and then Reply_Item.Kind = SSH_Lib.Protocol.Userauth.Auth_Banner
         then
            null;
         else
            declare
               Reply_Data : constant Stream_Element_Array :=
                 To_Array (Reply_Buffer);
            begin
               if SSH_Lib.Protocol.Transport_Messages.Classify (Reply_Data)
                 = SSH_Lib.Protocol.Transport_Messages.Transport_Disconnect
               then
                  return Authentication_Failed;
               elsif SSH_Lib
                       .Protocol
                       .Transport_Messages
                       .Is_Ignorable_During_Wait (Reply_Data)
               then
                  null;
               else
                  if Status_Value = Ok then
                     return Authentication_Failed;
                  else
                     return Status_Value;
                  end if;
               end if;
            end;
         end if;
      end loop;
   exception
      when others =>
         return Internal_Error;
   end Read_Password_Reply;

   function Read_Keyboard_Interactive_Reply
     (Transcript : in out SSH_Lib.Sessions.Live_Transcript.Driver;
      Item       : in out Session;
      Reply_Item : out SSH_Lib.Protocol.Userauth.Reply) return Status
   is
      Reply_Buffer : Packet_Buffer;
      Status_Value : Status;
   begin
      loop
         Status_Value :=
           SSH_Lib.Sessions.Live_Transcript.Read_Protected_Packet
             (Transcript, Reply_Buffer);

         if Status_Value = Ok then
            Status_Value :=
              Record_Last_Userauth_Response (Transcript, Item, Reply_Buffer);
         end if;

         if Status_Value = Ok then
            Status_Value :=
              SSH_Lib.Protocol.Userauth.Parse_Userauth_Reply
                (To_Array (Reply_Buffer),
                 SSH_Lib.Protocol.Userauth.Keyboard_Interactive_Reply,
                 Reply_Item);
         end if;

         if Status_Value = Ok
           and then Reply_Item.Kind = SSH_Lib.Protocol.Userauth.Auth_Success
         then
            return Ok;
         elsif Status_Value = Ok
           and then
             Reply_Item.Kind
             = SSH_Lib.Protocol.Userauth.Keyboard_Interactive_Info_Request
         then
            return Ok;
         elsif Status_Value = Ok
           and then Reply_Item.Kind = SSH_Lib.Protocol.Userauth.Auth_Failure
         then
            return Authentication_Failed;
         elsif Status_Value = Ok
           and then Reply_Item.Kind = SSH_Lib.Protocol.Userauth.Auth_Banner
         then
            null;
         else
            declare
               Reply_Data : constant Stream_Element_Array :=
                 To_Array (Reply_Buffer);
            begin
               if SSH_Lib.Protocol.Transport_Messages.Classify (Reply_Data)
                 = SSH_Lib.Protocol.Transport_Messages.Transport_Disconnect
               then
                  return Authentication_Failed;
               elsif SSH_Lib
                       .Protocol
                       .Transport_Messages
                       .Is_Ignorable_During_Wait (Reply_Data)
               then
                  null;
               else
                  if Status_Value = Ok then
                     return Authentication_Failed;
                  else
                     return Status_Value;
                  end if;
               end if;
            end;
         end if;
      end loop;
   exception
      when others =>
         return Internal_Error;
   end Read_Keyboard_Interactive_Reply;

   function Try_Keyboard_Interactive
     (Transcript : in out SSH_Lib.Sessions.Live_Transcript.Driver;
      Options    : Session_Options;
      Item       : in out Session) return Status
   is
      Request_Buffer   : Packet_Buffer;
      Response_Buffer  : Packet_Buffer;
      Status_Value     : Status;
      Password_Value   : Unbounded_String := Effective_Password (Options);
      Reply_Item       : SSH_Lib.Protocol.Userauth.Reply;
      Callback_Result  : Keyboard_Interactive_Callback_Result;
      Protocol_Replies :
        SSH_Lib.Protocol.Userauth.Keyboard_Interactive_Response_Array :=
          [others => Null_Unbounded_String];
      Response_Count   : Natural := 0;
      Round_Count      : Natural := 0;

      function Finish (Result : Status) return Status is
      begin
         Clear (Request_Buffer);
         Clear (Response_Buffer);
         Password_Value := Null_Unbounded_String;
         Clear_Keyboard_Interactive_Callback_Result (Callback_Result);
         for Response_Index in
           SSH_Lib.Protocol.Userauth.Keyboard_Interactive_Prompt_Index
         loop
            Protocol_Replies (Response_Index) := Null_Unbounded_String;
         end loop;
         return Result;
      end Finish;
   begin
      if not Authentication_Method_Enabled (Options, "keyboard-interactive")
        or else Options.Number_Of_Password_Prompts = 0
        or else
          (Options.Keyboard_Interactive_Callback = null
           and then
             (not Options.Use_Password
              or else To_String (Password_Value)'Length = 0))
      then
         return Finish (Authentication_Failed);
      end if;

      Request_Buffer :=
        SSH_Lib.Protocol.Userauth.Encode_Keyboard_Interactive_Request
          (To_String (Options.User));
      if Is_Empty (Request_Buffer) then
         return Finish (Authentication_Failed);
      end if;

      Status_Value :=
        SSH_Lib.Sessions.Live_Transcript.Send_Protected_Packet
          (Transcript, To_Array (Request_Buffer));
      if Status_Value /= Ok then
         return Finish (Status_Value);
      end if;

      Status_Value :=
        Record_Last_Userauth_Request (Transcript, Item, Request_Buffer);
      if Status_Value /= Ok then
         return Finish (Status_Value);
      end if;

      loop
         if Round_Count >= Options.Number_Of_Password_Prompts
           or else Round_Count >= Max_Keyboard_Interactive_Prompts
         then
            return Finish (Unsupported_Feature);
         end if;
         Round_Count := Round_Count + 1;

         Status_Value :=
           Read_Keyboard_Interactive_Reply (Transcript, Item, Reply_Item);
         if Status_Value /= Ok then
            return Finish (Status_Value);
         end if;

         if Reply_Item.Kind = SSH_Lib.Protocol.Userauth.Auth_Success then
            exit;
         elsif Reply_Item.Kind
           /= SSH_Lib.Protocol.Userauth.Keyboard_Interactive_Info_Request
         then
            return Finish (Authentication_Failed);
         end if;

         for Response_Index in
           SSH_Lib.Protocol.Userauth.Keyboard_Interactive_Prompt_Index
         loop
            Protocol_Replies (Response_Index) := Null_Unbounded_String;
         end loop;

         if Options.Keyboard_Interactive_Callback /= null then
            Callback_Result :=
              Options.Keyboard_Interactive_Callback.all
                (To_String (Options.Host),
                 To_String (Options.User),
                 To_Keyboard_Interactive_Challenge (Reply_Item));
            if not Callback_Result.Provided
              or else
                Callback_Result.Response_Count
                /= Natural (Reply_Item.Keyboard_Interactive_Prompts)
            then
               return Finish (Authentication_Failed);
            end if;

            Response_Count := Callback_Result.Response_Count;
            for Response_Index in 1 .. Response_Count loop
               if not Valid_Keyboard_Interactive_Response
                        (To_String
                           (Callback_Result.Responses (Response_Index)))
               then
                  return Finish (Authentication_Failed);
               end if;
               Protocol_Replies (Response_Index) :=
                 Callback_Result.Responses (Response_Index);
            end loop;
            Clear_Keyboard_Interactive_Callback_Result (Callback_Result);
         else
            if Reply_Item.Keyboard_Interactive_Prompts /= 1
              or else Reply_Item.Keyboard_Interactive_Echoes /= 0
            then
               return Finish (Unsupported_Feature);
            end if;

            Response_Count := 1;
            Protocol_Replies (1) := Password_Value;
         end if;

         Response_Buffer :=
           SSH_Lib.Protocol.Userauth.Encode_Keyboard_Interactive_Responses
             (Response_Count, Protocol_Replies);
         if Is_Empty (Response_Buffer) then
            return Finish (Authentication_Failed);
         end if;

         Status_Value :=
           SSH_Lib.Sessions.Live_Transcript.Send_Protected_Packet
             (Transcript, To_Array (Response_Buffer));
         if Status_Value /= Ok then
            return Finish (Status_Value);
         end if;

         Status_Value :=
           Record_Last_Keyboard_Interactive_Response
             (Transcript, Item, Response_Count);
         if Status_Value /= Ok then
            return Finish (Status_Value);
         end if;
      end loop;

      Status_Value := Activate_Post_Auth_Compression (Transcript, Item);
      if Status_Value /= Ok then
         return Finish (Status_Value);
      end if;

      Item.User_Authenticated := True;
      Item.Authenticated_User_Name := Options.User;
      Item.Authentication_Method_Used := Keyboard_Interactive_Authentication;
      return Finish (Ok);
   exception
      when others =>
         Clear (Request_Buffer);
         Clear (Response_Buffer);
         Password_Value := Null_Unbounded_String;
         Clear_Keyboard_Interactive_Callback_Result (Callback_Result);
         return Internal_Error;
   end Try_Keyboard_Interactive;

   function Try_Password
     (Transcript : in out SSH_Lib.Sessions.Live_Transcript.Driver;
      Options    : Session_Options;
      Item       : in out Session) return Status
   is
      Request_Buffer : Packet_Buffer;
      Status_Value   : Status;
      Password_Value : Unbounded_String := Effective_Password (Options);
      Reply_Item     : SSH_Lib.Protocol.Userauth.Reply;

      function Finish (Result : Status) return Status is
      begin
         Clear (Request_Buffer);
         Password_Value := Null_Unbounded_String;
         return Result;
      end Finish;
   begin
      if not Options.Use_Password
        or else not Authentication_Method_Enabled (Options, "password")
        or else Options.Number_Of_Password_Prompts = 0
        or else To_String (Password_Value)'Length = 0
      then
         return Finish (Authentication_Failed);
      end if;

      Request_Buffer :=
        SSH_Lib.Protocol.Userauth.Encode_Password_Request
          (To_String (Options.User), To_String (Password_Value));
      if Is_Empty (Request_Buffer) then
         return Finish (Authentication_Failed);
      end if;

      Status_Value :=
        SSH_Lib.Sessions.Live_Transcript.Send_Protected_Packet
          (Transcript, To_Array (Request_Buffer));
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      Status_Value :=
        Record_Last_Password_Userauth_Request
          (Transcript, Item, To_String (Options.User));
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      Status_Value := Read_Password_Reply (Transcript, Item, Reply_Item);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      if Reply_Item.Kind = SSH_Lib.Protocol.Userauth.Password_Change_Required
      then
         declare
            New_Password : Unbounded_String :=
              Effective_New_Password
                (Options, "SSH server requires a password change");
         begin
            if To_String (New_Password)'Length = 0 then
               return Finish (Authentication_Failed);
            end if;

            Clear (Request_Buffer);
            Request_Buffer :=
              SSH_Lib.Protocol.Userauth.Encode_Password_Change_Request
                (To_String (Options.User),
                 To_String (Password_Value),
                 To_String (New_Password));
            New_Password := Null_Unbounded_String;

            if Is_Empty (Request_Buffer) then
               return Finish (Authentication_Failed);
            end if;

            Status_Value :=
              SSH_Lib.Sessions.Live_Transcript.Send_Protected_Packet
                (Transcript, To_Array (Request_Buffer));
            if Status_Value /= Ok then
               return Status_Value;
            end if;

            Status_Value :=
              Record_Last_Password_Userauth_Request
                (Transcript, Item, To_String (Options.User));
            if Status_Value /= Ok then
               return Status_Value;
            end if;

            Status_Value :=
              Read_Auth_Reply
                (Transcript, Item, SSH_Lib.Protocol.Userauth.Password_Reply);
            if Status_Value /= Ok then
               return Status_Value;
            end if;
         exception
            when others =>
               New_Password := Null_Unbounded_String;
               return Finish (Internal_Error);
         end;
      end if;

      Status_Value := Activate_Post_Auth_Compression (Transcript, Item);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      Item.User_Authenticated := True;
      Item.Authenticated_User_Name := Options.User;
      Item.Authentication_Method_Used := Password_Authentication;
      return Finish (Ok);
   exception
      when others =>
         Clear (Request_Buffer);
         Password_Value := Null_Unbounded_String;
         return Internal_Error;
   end Try_Password;

   function Authenticate
     (Transcript         : in out SSH_Lib.Sessions.Live_Transcript.Driver;
      Options            : Session_Options;
      Session_Identifier : Stream_Element_Array;
      Item               : in out Session) return Status
   is
      Status_Value : Status;
   begin
      if not Item.Transport_Connected
        or else not Item.Identification_Complete
        or else not Item.Kexinit_Exchanged
        or else not Item.Algorithms_Negotiated
        or else not Item.Kex_Complete
        or else not Item.Keys_Derived
        or else not Item.Newkeys_Sent
        or else not Item.Newkeys_Received
        or else not Item.Encrypted_Outbound_Active
        or else not Item.Encrypted_Inbound_Active
        or else not Item.Host_Key_Signature_Verified
      then
         return Handshake_Failed;
      end if;

      if Options.Verify_Known_Host and then not Item.Known_Host_Trusted then
         return Host_Key_Unknown;
      end if;

      if not Options.Verify_Known_Host then
         Item.Known_Host_Bypassed_Explicitly := True;
      end if;

      Status_Value := Run_Service_Request (Transcript, Item);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      if Authentication_Method_Enabled (Options, "none") then
         Status_Value := Try_None (Transcript, Options, Item);
      else
         Status_Value := Authentication_Failed;
      end if;

      if Status_Value = Ok then
         null;
      elsif Is_Method_Fallback_Status (Status_Value) then
         --  RFC 4252 allows clients to send method "none" after the
         --  ssh-userauth service starts.  Most servers reject it with a
         --  method list, but a server may also accept it for accounts where
         --  no credential is required.  Treat failure as a discovery/fallback
         --  result, never as successful authentication.
         null;
      else
         return Status_Value;
      end if;

      if Status_Value /= Ok
        and then To_String (Options.Identity_File)'Length > 0
      then
         Status_Value :=
           Try_Identity_File (Transcript, Options, Session_Identifier, Item);
         if Status_Value = Ok then
            null;
         elsif Is_Method_Fallback_Status (Status_Value) then
            --  A configured identity may have a wrong/missing passphrase,
            --  be malformed, or use an unsupported private-key algorithm/envelope.
            --  Do not publish success, but do not prevent an explicitly
            --  configured later method such as ssh-agent or password from
            --  authenticating the already encrypted/trusted session.  If no
            --  later method succeeds, the preserved status remains the final
            --  deterministic result.
            null;
         else
            return Status_Value;
         end if;
      end if;

      if Status_Value /= Ok
        and then Options.Use_Agent
        and then
          Ada.Characters.Handling.To_Lower (To_String (Options.Identity_Agent))
          /= "none"
      then
         declare
            Previous_Status : constant Status := Status_Value;
         begin
            Status_Value :=
              Try_Agent (Transcript, Options, Session_Identifier, Item);
            if Status_Value = Ok then
               null;
            elsif Is_Method_Fallback_Status (Status_Value) then
               if Status_Value = Authentication_Failed
                 and then Previous_Status = Unsupported_Feature
               then
                  Status_Value := Previous_Status;
               end if;
            else
               return Status_Value;
            end if;
         end;
      end if;

      if Status_Value /= Ok
        and then To_String (Options.Identity_File)'Length = 0
      then
         declare
            Previous_Status : constant Status := Status_Value;
         begin
            Status_Value :=
              Try_Default_Identity_Files
                (Transcript, Options, Session_Identifier, Item);
            if Status_Value = Ok then
               null;
            elsif Is_Method_Fallback_Status (Status_Value) then
               if Previous_Status /= Authentication_Failed then
                  Status_Value := Previous_Status;
               end if;
            else
               return Status_Value;
            end if;
         end;
      end if;

      if Status_Value /= Ok and then Options.Use_Password then
         declare
            Previous_Status : constant Status := Status_Value;
         begin
            Status_Value :=
              Try_Keyboard_Interactive (Transcript, Options, Item);
            if Status_Value = Ok then
               null;
            elsif Is_Method_Fallback_Status (Status_Value) then
               if Previous_Status /= Authentication_Failed then
                  Status_Value := Previous_Status;
               end if;
            else
               return Status_Value;
            end if;
         end;
      end if;

      if Status_Value /= Ok and then Options.Use_Password then
         Status_Value := Try_Password (Transcript, Options, Item);
      end if;

      if Status_Value /= Ok then
         Item.User_Authenticated := False;
         Item.Current_State := Closed;
         Item.Session_Open := False;
         Item.Session_Closed := True;
         Item.Session_Dirty := True;
         Item.Failure_Status := Status_Value;
         return Status_Value;
      end if;

      Item.Failure_Status := Ok;
      return Ok;
   exception
      when others =>
         Item.Failure_Status := Internal_Error;
         return Internal_Error;
   end Authenticate;
end SSH_Lib.Sessions.Live_Userauth;
