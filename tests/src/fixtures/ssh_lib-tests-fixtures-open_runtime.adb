with Ada.Streams;
with Ada.Strings.Unbounded;
with Ada.Text_IO;
with CryptoLib.Errors;
with SSH_Lib.Sessions;
with SSH_Lib.Sessions.Open_Guards;
with SSH_Lib.Sessions.Test_Support;
with SSH_Lib.Sessions.Userauth_IO;
with SSH_Lib.Protocol.Buffers;
with SSH_Lib.Protocol.Service;
with SSH_Lib.Agent.Protocol;
with SSH_Lib.Protocol.Userauth;
with SSH_Lib.Tests.Assertions;
with SSH_Lib.Tests.Fixtures.Temp_Paths;

package body SSH_Lib.Tests.Fixtures.Open_Runtime is
   use type Ada.Streams.Stream_Element_Offset;

   Valid_OpenSSH_Ed25519 : constant String :=
     "-----BEGIN OPENSSH PRIVATE KEY-----" & Character'Val (10) &
     "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW" & Character'Val (10) &
     "QyNTUxOQAAACABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fIAAAAJYRIjNEESIz" & Character'Val (10) &
     "RAAAAAtzc2gtZWQyNTUxOQAAACABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fIA" & Character'Val (10) &
     "AAAEBlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn+AgYKDhAECAwQFBgcICQoLDA0ODxAR" & Character'Val (10) &
     "EhMUFRYXGBkaGxwdHh8gAAAAD2lnbm9yZWQgY29tbWVudAECAwQ=" & Character'Val (10) &
     "-----END OPENSSH PRIVATE KEY-----" & Character'Val (10);

   procedure Write_Text (Path_Text : String; Data_Text : String) is
      File_Item : Ada.Text_IO.File_Type;
   begin
      Ada.Text_IO.Create (File_Item, Ada.Text_IO.Out_File, Path_Text);
      Ada.Text_IO.Put (File_Item, Data_Text);
      Ada.Text_IO.Close (File_Item);
   exception
      when others =>
         if Ada.Text_IO.Is_Open (File_Item) then
            Ada.Text_IO.Close (File_Item);
         end if;
         raise;
   end Write_Text;

   use Ada.Strings.Unbounded;
   use type Ada.Streams.Stream_Element;
   use type CryptoLib.Errors.Status;

   procedure Check (Condition : Boolean; Label_Text : String) is
   begin
      if not Condition then
         Ada.Text_IO.Put_Line ("FAILED: " & Label_Text);
         raise Program_Error;
      end if;
   end Check;

   function Buffer_Contains_Text
     (Buffer_Item : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Needle      : String)
      return Boolean
   is
      Data : constant Ada.Streams.Stream_Element_Array :=
        SSH_Lib.Protocol.Buffers.To_Array (Buffer_Item);
   begin
      if Needle'Length = 0 then
         return True;
      end if;
      if Data'Length < Needle'Length then
         return False;
      end if;

      for Start_Offset in 0 .. Data'Length - Needle'Length loop
         declare
            Matched : Boolean := True;
         begin
            for Needle_Offset in 0 .. Needle'Length - 1 loop
               if Data (Data'First + Ada.Streams.Stream_Element_Offset
                    (Start_Offset + Needle_Offset))
                 /= Ada.Streams.Stream_Element
                      (Character'Pos
                         (Needle (Needle'First + Needle_Offset)))
               then
                  Matched := False;
                  exit;
               end if;
            end loop;
            if Matched then
               return True;
            end if;
         end;
      end loop;
      return False;
   exception
      when others =>
         return False;
   end Buffer_Contains_Text;

   function Deterministic_Password_Callback
     (Host : String;
      User : String)
      return SSH_Lib.Sessions.Credential_Callback_Result
   is
      pragma Unreferenced (Host, User);
   begin
      return
        (Provided => True,
         Secret   => To_Unbounded_String ("callback-secret"));
   end Deterministic_Password_Callback;

   function Invalid_Password_Callback
     (Host : String;
      User : String)
      return SSH_Lib.Sessions.Credential_Callback_Result
   is
      pragma Unreferenced (Host, User);
   begin
      return
        (Provided => True,
         Secret   => To_Unbounded_String
           ("bad" & Character'Val (10) & "secret"));
   end Invalid_Password_Callback;

   function Deterministic_Keyboard_Interactive_Callback
     (Host      : String;
      User      : String;
      Challenge : SSH_Lib.Sessions.Keyboard_Interactive_Challenge)
      return SSH_Lib.Sessions.Keyboard_Interactive_Callback_Result
   is
      pragma Unreferenced (Host, User);
      Result : SSH_Lib.Sessions.Keyboard_Interactive_Callback_Result;
   begin
      if Challenge.Name = To_Unbounded_String ("password")
        and then Challenge.Instruction
          = To_Unbounded_String ("Password authentication")
        and then Challenge.Prompt_Count = 1
        and then Challenge.Prompts (1).Text = To_Unbounded_String ("Password: ")
        and then not Challenge.Prompts (1).Echo
      then
         Result.Provided := True;
         Result.Response_Count := 1;
         Result.Responses (1) := To_Unbounded_String ("callback-secret");
      end if;
      return Result;
   end Deterministic_Keyboard_Interactive_Callback;

   function Local_Options return SSH_Lib.Sessions.Session_Options is
   begin
      return Result : SSH_Lib.Sessions.Session_Options do
         Result.Host := To_Unbounded_String ("transcript.example.test");
         Result.Port := 22;
         Result.User := To_Unbounded_String ("git");
         Result.Verify_Known_Host := True;
         Result.Strict_Host_Key := True;
         Result.Use_Agent := True;
      end return;
   end Local_Options;

   procedure Assert_Public_Open_Runtime_Gates is
      Session_Item : SSH_Lib.Sessions.Session;
      Options      : SSH_Lib.Sessions.Session_Options := Local_Options;
      Status_Value : CryptoLib.Errors.Status;
   begin
      Check
        (SSH_Lib.Sessions.Test_Support.Expand_Proxy_Command_For_Test
           ("%% %h %n %p %r %x %", "target.example", 2222, "alice")
         = "% target.example target.example 2222 alice %x %",
         "ProxyCommand token expansion covers OpenSSH transport tokens");
      Check
        (SSH_Lib.Sessions.Test_Support.Expand_Proxy_Command_For_Test
           ("connect-%h:%p-as-%r", "host.example", 2200, "git")
         = "connect-host.example:2200-as-git",
         "ProxyCommand token expansion preserves surrounding literal text");

      declare
         None_Options : SSH_Lib.Sessions.Session_Options := Local_Options;
         None_Session : SSH_Lib.Sessions.Session;
         None_Status  : CryptoLib.Errors.Status;
      begin
         None_Options.Proxy_Command := To_Unbounded_String (" none ");
         None_Status := SSH_Lib.Sessions.Open (None_Options, None_Session);
         SSH_Lib.Tests.Assertions.Check_Status
           (None_Status, CryptoLib.Errors.Ok,
            "public open runtime", "Proxy_Command none falls through to direct runtime");
         Check
           (SSH_Lib.Sessions.Test_Support.Is_Open_For_Test (None_Session),
            "Proxy_Command none does not enter subprocess transport");
      end;

      Status_Value := SSH_Lib.Sessions.Open (Options, Session_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "public open runtime", "deterministic local runtime opens");
      Check
        (SSH_Lib.Sessions.Test_Support.Is_Open_For_Test (Session_Item),
         "public Sessions.Open publishes open state only after runtime gates");
      Check
        (SSH_Lib.Sessions.Test_Support.Is_Encrypted_For_Test (Session_Item),
         "public Sessions.Open marks encrypted packet mode active");
      Check
        (SSH_Lib.Sessions.Test_Support.Is_Host_Trusted_For_Test (Session_Item),
         "public Sessions.Open requires host-key signature plus trust");
      Check
        (SSH_Lib.Sessions.Test_Support.Is_Authenticated_For_Test (Session_Item),
         "public Sessions.Open completes userauth before Ok");
      Check
        (SSH_Lib.Sessions.Open_Guards.Public_Open_State_Consistent (Session_Item),
         "public Sessions.Open Ok state satisfies the centralized guard");
      Check
        (not SSH_Lib.Protocol.Buffers.Is_Empty
           (SSH_Lib.Sessions.Userauth_IO.Last_Plain_Service_Request_For_Test
              (Session_Item)),
         "agent runtime emits a plain SERVICE_REQUEST transcript before userauth");
      Check
        (not SSH_Lib.Protocol.Buffers.Is_Empty
           (SSH_Lib.Sessions.Userauth_IO.Last_Protected_Service_Request_For_Test
              (Session_Item)),
         "agent runtime emits protected service-request traffic");
      Check
        (not SSH_Lib.Protocol.Buffers.Is_Empty
           (SSH_Lib.Sessions.Userauth_IO.Last_Protected_Service_Response_For_Test
              (Session_Item)),
         "agent runtime records protected service-accept traffic");
      Check
        (not SSH_Lib.Protocol.Buffers.Is_Empty
           (SSH_Lib.Sessions.Userauth_IO.Last_Plain_Service_Response_For_Test
              (Session_Item)),
         "agent runtime records decoded SERVICE_ACCEPT payload");
      declare
         Service_Request : constant Ada.Streams.Stream_Element_Array :=
           SSH_Lib.Protocol.Buffers.To_Array
             (SSH_Lib.Sessions.Userauth_IO.Last_Plain_Service_Request_For_Test
                (Session_Item));
         Service_Response : constant Ada.Streams.Stream_Element_Array :=
           SSH_Lib.Protocol.Buffers.To_Array
             (SSH_Lib.Sessions.Userauth_IO.Last_Plain_Service_Response_For_Test
                (Session_Item));
      begin
         Check
           (Service_Request'Length > 0
            and then Service_Request (Service_Request'First)
              = SSH_Lib.Protocol.Service.SSH_MSG_SERVICE_REQUEST,
            "agent runtime sends SERVICE_REQUEST before userauth");
         Check
           (Service_Response'Length > 0
            and then Service_Response (Service_Response'First)
              = SSH_Lib.Protocol.Service.SSH_MSG_SERVICE_ACCEPT,
            "agent runtime parses SERVICE_ACCEPT before userauth");
      end;
      Check
        (not SSH_Lib.Protocol.Buffers.Is_Empty
           (SSH_Lib.Sessions.Userauth_IO.Last_Plain_Userauth_Payload_For_Test
              (Session_Item)),
         "agent runtime emits a plain USERAUTH_REQUEST transcript");
      Check
        (not SSH_Lib.Protocol.Buffers.Is_Empty
           (SSH_Lib.Sessions.Userauth_IO.Last_Protected_Userauth_Payload_For_Test
              (Session_Item)),
         "agent runtime emits protected userauth traffic");
      Check
        (not SSH_Lib.Protocol.Buffers.Is_Empty
           (SSH_Lib.Sessions.Userauth_IO.Last_Protected_Userauth_Response_For_Test
              (Session_Item)),
         "agent runtime records protected USERAUTH_SUCCESS traffic");
      Check
        (not SSH_Lib.Protocol.Buffers.Is_Empty
           (SSH_Lib.Sessions.Userauth_IO.Last_Plain_Userauth_Response_For_Test
              (Session_Item)),
         "agent runtime records decoded USERAUTH_SUCCESS payload");
      declare
         Userauth_Request : constant Ada.Streams.Stream_Element_Array :=
           SSH_Lib.Protocol.Buffers.To_Array
             (SSH_Lib.Sessions.Userauth_IO.Last_Plain_Userauth_Payload_For_Test
                (Session_Item));
         Userauth_Response : constant Ada.Streams.Stream_Element_Array :=
           SSH_Lib.Protocol.Buffers.To_Array
             (SSH_Lib.Sessions.Userauth_IO.Last_Plain_Userauth_Response_For_Test
                (Session_Item));
      begin
         Check
           (Userauth_Request'Length > 0
            and then Userauth_Request (Userauth_Request'First)
              = SSH_Lib.Protocol.Userauth.SSH_MSG_USERAUTH_REQUEST,
            "agent runtime sends USERAUTH_REQUEST before authentication state");
         Check
           (Userauth_Response'Length > 0
            and then Userauth_Response (Userauth_Response'First)
              = SSH_Lib.Protocol.Userauth.SSH_MSG_USERAUTH_SUCCESS,
            "agent runtime parses USERAUTH_SUCCESS before authentication state");
      end;
      Check
        (not SSH_Lib.Protocol.Buffers.Is_Empty
           (SSH_Lib.Sessions.Userauth_IO.Last_Agent_Sign_Request_For_Test
              (Session_Item)),
         "agent runtime records the SSH_AGENTC_SIGN_REQUEST transcript");
      Check
        (not SSH_Lib.Protocol.Buffers.Is_Empty
           (SSH_Lib.Sessions.Userauth_IO.Last_Agent_Sign_Response_For_Test
              (Session_Item)),
         "agent runtime records the SSH_AGENT_SIGN_RESPONSE transcript");
      declare
         Agent_Request : constant Ada.Streams.Stream_Element_Array :=
           SSH_Lib.Protocol.Buffers.To_Array
             (SSH_Lib.Sessions.Userauth_IO.Last_Agent_Sign_Request_For_Test
                (Session_Item));
         Agent_Response : constant Ada.Streams.Stream_Element_Array :=
           SSH_Lib.Protocol.Buffers.To_Array
             (SSH_Lib.Sessions.Userauth_IO.Last_Agent_Sign_Response_For_Test
                (Session_Item));
      begin
         Check
           (Agent_Request'Length > 0
            and then Agent_Request (Agent_Request'First)
              = SSH_Lib.Agent.Protocol.SSH_AGENTC_SIGN_REQUEST,
            "agent runtime emits a concrete agent sign request before SSH userauth");
         Check
           (Agent_Response'Length > 0
            and then Agent_Response (Agent_Response'First)
              = SSH_Lib.Agent.Protocol.SSH_AGENT_SIGN_RESPONSE,
            "agent runtime parses a concrete agent sign response before SSH userauth");
      end;


      Options := Local_Options;
      Options.User := To_Unbounded_String ("reject-auth");
      Status_Value := SSH_Lib.Sessions.Open (Options, Session_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Authentication_Failed,
         "public open runtime",
         "deterministic agent runtime maps USERAUTH_FAILURE to Authentication_Failed");
      Check
        (not SSH_Lib.Sessions.Test_Support.Is_Open_For_Test (Session_Item),
         "USERAUTH_FAILURE leaves the public session closed");
      Check
        (not SSH_Lib.Sessions.Test_Support.Is_Authenticated_For_Test (Session_Item),
         "USERAUTH_FAILURE does not publish authenticated state");

      Options := Local_Options;
      Options.Identity_File := To_Unbounded_String
        (SSH_Lib.Tests.Fixtures.Temp_Paths.Path ("open_runtime_valid_ed25519"));
      Options.Use_Agent := False;
      Write_Text (To_String (Options.Identity_File), Valid_OpenSSH_Ed25519);
      Status_Value := SSH_Lib.Sessions.Open (Options, Session_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "public open runtime",
         "identity-file runtime authenticates through the signing backend");
      Check
        (SSH_Lib.Sessions.Test_Support.Is_Open_For_Test (Session_Item),
         "identity-file signing can publish a successful public runtime state");
      Check
        (not SSH_Lib.Protocol.Buffers.Is_Empty
           (SSH_Lib.Sessions.Userauth_IO.Last_Plain_Service_Request_For_Test
              (Session_Item)),
         "identity-file runtime emits a plain SERVICE_REQUEST transcript before userauth");
      Check
        (not SSH_Lib.Protocol.Buffers.Is_Empty
           (SSH_Lib.Sessions.Userauth_IO.Last_Protected_Service_Request_For_Test
              (Session_Item)),
         "identity-file runtime emits protected service-request traffic");
      Check
        (not SSH_Lib.Protocol.Buffers.Is_Empty
           (SSH_Lib.Sessions.Userauth_IO.Last_Protected_Service_Response_For_Test
              (Session_Item)),
         "identity-file runtime records protected service-accept traffic");
      Check
        (not SSH_Lib.Protocol.Buffers.Is_Empty
           (SSH_Lib.Sessions.Userauth_IO.Last_Plain_Service_Response_For_Test
              (Session_Item)),
         "identity-file runtime records decoded SERVICE_ACCEPT payload");
      declare
         Service_Request : constant Ada.Streams.Stream_Element_Array :=
           SSH_Lib.Protocol.Buffers.To_Array
             (SSH_Lib.Sessions.Userauth_IO.Last_Plain_Service_Request_For_Test
                (Session_Item));
         Service_Response : constant Ada.Streams.Stream_Element_Array :=
           SSH_Lib.Protocol.Buffers.To_Array
             (SSH_Lib.Sessions.Userauth_IO.Last_Plain_Service_Response_For_Test
                (Session_Item));
      begin
         Check
           (Service_Request'Length > 0
            and then Service_Request (Service_Request'First)
              = SSH_Lib.Protocol.Service.SSH_MSG_SERVICE_REQUEST,
            "identity-file runtime sends SERVICE_REQUEST before userauth");
         Check
           (Service_Response'Length > 0
            and then Service_Response (Service_Response'First)
              = SSH_Lib.Protocol.Service.SSH_MSG_SERVICE_ACCEPT,
            "identity-file runtime parses SERVICE_ACCEPT before userauth");
      end;
      Check
        (not SSH_Lib.Protocol.Buffers.Is_Empty
           (SSH_Lib.Sessions.Userauth_IO.Last_Plain_Userauth_Payload_For_Test
              (Session_Item)),
         "identity-file runtime emits a plain USERAUTH_REQUEST transcript");
      Check
        (not SSH_Lib.Protocol.Buffers.Is_Empty
           (SSH_Lib.Sessions.Userauth_IO.Last_Protected_Userauth_Payload_For_Test
              (Session_Item)),
         "identity-file runtime emits protected userauth traffic");
      Check
        (not SSH_Lib.Protocol.Buffers.Is_Empty
           (SSH_Lib.Sessions.Userauth_IO.Last_Protected_Userauth_Response_For_Test
              (Session_Item)),
         "identity-file runtime records protected USERAUTH_SUCCESS traffic");
      Check
        (not SSH_Lib.Protocol.Buffers.Is_Empty
           (SSH_Lib.Sessions.Userauth_IO.Last_Plain_Userauth_Response_For_Test
              (Session_Item)),
         "identity-file runtime records decoded USERAUTH_SUCCESS payload");
      declare
         Userauth_Request : constant Ada.Streams.Stream_Element_Array :=
           SSH_Lib.Protocol.Buffers.To_Array
             (SSH_Lib.Sessions.Userauth_IO.Last_Plain_Userauth_Payload_For_Test
                (Session_Item));
         Userauth_Response : constant Ada.Streams.Stream_Element_Array :=
           SSH_Lib.Protocol.Buffers.To_Array
             (SSH_Lib.Sessions.Userauth_IO.Last_Plain_Userauth_Response_For_Test
                (Session_Item));
      begin
         Check
           (Userauth_Request'Length > 0
            and then Userauth_Request (Userauth_Request'First)
              = SSH_Lib.Protocol.Userauth.SSH_MSG_USERAUTH_REQUEST,
            "identity-file runtime sends USERAUTH_REQUEST before authentication state");
         Check
           (Userauth_Response'Length > 0
            and then Userauth_Response (Userauth_Response'First)
              = SSH_Lib.Protocol.Userauth.SSH_MSG_USERAUTH_SUCCESS,
            "identity-file runtime parses USERAUTH_SUCCESS before authentication state");
      end;
      Check
        (SSH_Lib.Protocol.Buffers.Is_Empty
           (SSH_Lib.Sessions.Userauth_IO.Last_Agent_Sign_Request_For_Test
              (Session_Item)),
         "identity-file runtime does not use the agent sign boundary");
      Check
        (SSH_Lib.Protocol.Buffers.Is_Empty
           (SSH_Lib.Sessions.Userauth_IO.Last_Agent_Sign_Response_For_Test
              (Session_Item)),
         "identity-file runtime does not parse agent sign responses");

      Options := Local_Options;
      Options.Identity_File := To_Unbounded_String
        (SSH_Lib.Tests.Fixtures.Temp_Paths.Path ("open_runtime_valid_ed25519"));
      Options.Use_Agent := False;
      Options.User := To_Unbounded_String ("reject-auth");
      Status_Value := SSH_Lib.Sessions.Open (Options, Session_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Authentication_Failed,
         "public open runtime",
         "deterministic identity-file runtime maps USERAUTH_FAILURE to Authentication_Failed");
      Check
        (not SSH_Lib.Sessions.Test_Support.Is_Open_For_Test (Session_Item),
         "identity-file USERAUTH_FAILURE leaves the public session closed");
      Check
        (not SSH_Lib.Sessions.Test_Support.Is_Authenticated_For_Test (Session_Item),
         "identity-file USERAUTH_FAILURE does not publish authenticated state");

      Options := Local_Options;
      Options.Identity_File := To_Unbounded_String
        (SSH_Lib.Tests.Fixtures.Temp_Paths.Path ("open_runtime_valid_ed25519"));
      Options.Use_Agent := True;
      Status_Value := SSH_Lib.Sessions.Open (Options, Session_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "public open runtime",
         "identity-file runtime remains successful when agent use is also allowed");
      Check
        (SSH_Lib.Sessions.Test_Support.Is_Open_For_Test (Session_Item),
         "identity-file plus agent-allowed runtime remains a successful state");

      Options := Local_Options;
      Options.Identity_File := To_Unbounded_String
        (SSH_Lib.Tests.Fixtures.Temp_Paths.Path
           ("open_runtime_preferred_password_ed25519"));
      Options.Use_Agent := True;
      Options.Use_Password := True;
      Options.Password_Callback := Deterministic_Password_Callback'Access;
      Options.Preferred_Authentications := To_Unbounded_String ("password");
      Write_Text (To_String (Options.Identity_File), Valid_OpenSSH_Ed25519);
      Status_Value := SSH_Lib.Sessions.Open (Options, Session_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "public open runtime",
         "deterministic runtime obeys password-only PreferredAuthentications");
      Check
        (SSH_Lib.Sessions.Test_Support.Is_Open_For_Test (Session_Item),
         "password-only preference still publishes a successful open state");
      Check
        (SSH_Lib.Sessions.Test_Support.Stored_Credentials_Clear_For_Test
           (Session_Item),
         "password-only preference does not store credential callbacks");
      Check
        (Buffer_Contains_Text
           (SSH_Lib.Sessions.Userauth_IO.Last_Plain_Userauth_Payload_For_Test
              (Session_Item),
            "password"),
         "password-only preference emits a password USERAUTH_REQUEST");
      Check
        (not Buffer_Contains_Text
           (SSH_Lib.Sessions.Userauth_IO.Last_Plain_Userauth_Payload_For_Test
              (Session_Item),
            "publickey"),
         "password-only preference does not emit publickey userauth");
      Check
        (SSH_Lib.Protocol.Buffers.Is_Empty
           (SSH_Lib.Sessions.Userauth_IO.Last_Agent_Sign_Request_For_Test
              (Session_Item)),
         "password-only preference does not contact the agent boundary");

      Options := Local_Options;
      Options.Use_Agent := True;
      Options.Use_Password := True;
      Options.Password_Callback := Deterministic_Password_Callback'Access;
      Options.Preferred_Authentications :=
        To_Unbounded_String ("keyboard-interactive");
      Write_Text (To_String (Options.Identity_File), Valid_OpenSSH_Ed25519);
      Status_Value := SSH_Lib.Sessions.Open (Options, Session_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "public open runtime",
         "deterministic runtime obeys keyboard-interactive-only PreferredAuthentications");
      Check
        (SSH_Lib.Sessions.Test_Support.Is_Open_For_Test (Session_Item),
         "keyboard-interactive-only preference publishes a successful open state");
      declare
         Last_Userauth : constant Ada.Streams.Stream_Element_Array :=
           SSH_Lib.Protocol.Buffers.To_Array
             (SSH_Lib.Sessions.Userauth_IO.Last_Plain_Userauth_Payload_For_Test
                (Session_Item));
      begin
         Check
           (Last_Userauth'Length > 0
            and then Last_Userauth (Last_Userauth'First)
              = SSH_Lib.Protocol.Userauth.SSH_MSG_USERAUTH_INFO_RESPONSE,
            "keyboard-interactive-only preference emits an info response");
      end;
      Check
        (Buffer_Contains_Text
           (SSH_Lib.Sessions.Userauth_IO.Last_Plain_Userauth_Payload_For_Test
              (Session_Item),
            "<redacted>"),
         "keyboard-interactive-only preference stores redacted response payload");
      Check
        (not Buffer_Contains_Text
           (SSH_Lib.Sessions.Userauth_IO.Last_Plain_Userauth_Payload_For_Test
              (Session_Item),
            "fixture-password"),
         "keyboard-interactive-only preference does not retain password text");
      Check
        (SSH_Lib.Protocol.Buffers.Is_Empty
           (SSH_Lib.Sessions.Userauth_IO.Last_Agent_Sign_Request_For_Test
              (Session_Item)),
         "keyboard-interactive-only preference does not contact the agent boundary");

      Options := Local_Options;
      Options.Use_Agent := True;
      Options.Use_Password := False;
      Options.Keyboard_Interactive_Callback :=
        Deterministic_Keyboard_Interactive_Callback'Access;
      Options.Preferred_Authentications :=
        To_Unbounded_String ("keyboard-interactive");
      Write_Text (To_String (Options.Identity_File), Valid_OpenSSH_Ed25519);
      Status_Value := SSH_Lib.Sessions.Open (Options, Session_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "public open runtime",
         "deterministic runtime authenticates through keyboard-interactive callback");
      Check
        (SSH_Lib.Sessions.Test_Support.Is_Open_For_Test (Session_Item),
         "keyboard-interactive callback publishes a successful open state");
      Check
        (SSH_Lib.Sessions.Test_Support.Stored_Credentials_Clear_For_Test
           (Session_Item),
         "keyboard-interactive callback is not stored after open");
      Check
        (Buffer_Contains_Text
           (SSH_Lib.Sessions.Userauth_IO.Last_Plain_Userauth_Payload_For_Test
              (Session_Item),
            "<redacted>"),
         "keyboard-interactive callback stores redacted response payload");
      Check
        (not Buffer_Contains_Text
           (SSH_Lib.Sessions.Userauth_IO.Last_Plain_Userauth_Payload_For_Test
              (Session_Item),
            "callback-secret"),
         "keyboard-interactive callback secret is not retained in plain transcript");

      Options := Local_Options;
      Options.Identity_Agent := To_Unbounded_String ("none");
      Status_Value := SSH_Lib.Sessions.Open (Options, Session_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Authentication_Failed,
         "public open runtime",
         "deterministic runtime treats IdentityAgent none as disabling ssh-agent auth");
      Check
        (not SSH_Lib.Sessions.Test_Support.Is_Open_For_Test (Session_Item),
         "IdentityAgent none leaves agent-only deterministic runtime closed");
      Check
        (SSH_Lib.Protocol.Buffers.Is_Empty
           (SSH_Lib.Sessions.Userauth_IO.Last_Agent_Sign_Request_For_Test
              (Session_Item)),
         "IdentityAgent none does not contact the agent signing boundary");

      Options := Local_Options;
      Options.Identity_Agent := To_Unbounded_String ("None");
      Status_Value := SSH_Lib.Sessions.Open (Options, Session_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Authentication_Failed,
         "public open runtime",
         "deterministic runtime treats IdentityAgent None as disabling ssh-agent auth");
      Check
        (not SSH_Lib.Sessions.Test_Support.Is_Open_For_Test (Session_Item),
         "IdentityAgent None leaves agent-only deterministic runtime closed");
      Check
        (SSH_Lib.Protocol.Buffers.Is_Empty
           (SSH_Lib.Sessions.Userauth_IO.Last_Agent_Sign_Request_For_Test
              (Session_Item)),
         "IdentityAgent None does not contact the agent signing boundary");

      Options := Local_Options;
      Options.Host_Key_Alias :=
        To_Unbounded_String ("trusted" & Character'Val (10) & "alias");
      Status_Value := SSH_Lib.Sessions.Open (Options, Session_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Host_Key_Unknown,
         "public open runtime",
         "open rejects newline-bearing HostKeyAlias before trust lookup");
      Check
        (not SSH_Lib.Sessions.Test_Support.Is_Open_For_Test (Session_Item),
         "newline-bearing HostKeyAlias leaves session closed");

      Options := Local_Options;
      Options.Allowed_Certificate_Critical_Options :=
        To_Unbounded_String ("force-command,");
      Status_Value := SSH_Lib.Sessions.Open (Options, Session_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Unsupported_Feature,
         "public open runtime",
         "open rejects malformed certificate critical-option allow-list");
      Check
        (not SSH_Lib.Sessions.Test_Support.Is_Open_For_Test (Session_Item),
         "malformed critical-option allow-list leaves session closed");

      Options := Local_Options;
      Options.Gex_Minimum_Bits := 4096;
      Options.Gex_Preferred_Bits := 2048;
      Options.Gex_Maximum_Bits := 8192;
      Status_Value := SSH_Lib.Sessions.Open (Options, Session_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Handshake_Failed,
         "public open runtime",
         "open rejects inconsistent group-exchange bounds before handshake");
      Check
        (not SSH_Lib.Sessions.Test_Support.Is_Open_For_Test (Session_Item),
         "inconsistent group-exchange bounds leave session closed");

      Options := Local_Options;
      Options.Identity_File :=
        To_Unbounded_String ("id" & Character'Val (10) & "ed25519");
      Status_Value := SSH_Lib.Sessions.Open (Options, Session_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Authentication_Failed,
         "public open runtime",
         "open rejects newline-bearing IdentityFile before authentication setup");
      Check
        (not SSH_Lib.Sessions.Test_Support.Is_Open_For_Test (Session_Item),
         "newline-bearing IdentityFile leaves session closed");

      Options := Local_Options;
      Options.Certificate_File :=
        To_Unbounded_String ("id-cert" & Character'Val (13) & ".pub");
      Status_Value := SSH_Lib.Sessions.Open (Options, Session_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Authentication_Failed,
         "public open runtime",
         "open rejects carriage-return-bearing CertificateFile before authentication setup");
      Check
        (not SSH_Lib.Sessions.Test_Support.Is_Open_For_Test (Session_Item),
         "carriage-return-bearing CertificateFile leaves session closed");

      Options := Local_Options;
      Options.Known_Hosts_File :=
        To_Unbounded_String ("known" & Character'Val (10) & "hosts");
      Status_Value := SSH_Lib.Sessions.Open (Options, Session_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Host_Key_Unknown,
         "public open runtime",
         "open rejects newline-bearing KnownHostsFile before trust lookup");
      Check
        (not SSH_Lib.Sessions.Test_Support.Is_Open_For_Test (Session_Item),
         "newline-bearing KnownHostsFile leaves session closed");

      Options := Local_Options;
      Options.User_Known_Hosts_File := To_Unbounded_String ("first,,second");
      Status_Value := SSH_Lib.Sessions.Open (Options, Session_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Host_Key_Unknown,
         "public open runtime",
         "open rejects empty UserKnownHostsFile path-list element");
      Check
        (not SSH_Lib.Sessions.Test_Support.Is_Open_For_Test (Session_Item),
         "empty UserKnownHostsFile path-list element leaves session closed");

      Options := Local_Options;
      Options.Global_Known_Hosts_File := To_Unbounded_String (",global_known_hosts");
      Status_Value := SSH_Lib.Sessions.Open (Options, Session_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Host_Key_Unknown,
         "public open runtime",
         "open rejects empty GlobalKnownHostsFile path-list element");
      Check
        (not SSH_Lib.Sessions.Test_Support.Is_Open_For_Test (Session_Item),
         "empty GlobalKnownHostsFile path-list element leaves session closed");

      Options := Local_Options;
      Options.Revoked_Host_Keys_File := To_Unbounded_String ("revoked,");
      Status_Value := SSH_Lib.Sessions.Open (Options, Session_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Host_Key_Mismatch,
         "public open runtime",
         "open rejects empty RevokedHostKeys path-list element");
      Check
        (not SSH_Lib.Sessions.Test_Support.Is_Open_For_Test (Session_Item),
         "empty RevokedHostKeys path-list element leaves session closed");

      Options := Local_Options;
      Options.Certificate_Authority_File :=
        To_Unbounded_String ("ca" & Character'Val (10) & "keys");
      Status_Value := SSH_Lib.Sessions.Open (Options, Session_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Host_Key_Unknown,
         "public open runtime",
         "open rejects newline-bearing CertificateAuthorityFile before trust lookup");
      Check
        (not SSH_Lib.Sessions.Test_Support.Is_Open_For_Test (Session_Item),
         "newline-bearing CertificateAuthorityFile leaves session closed");

      Options := Local_Options;
      Options.Trusted_User_CA_Keys_File :=
        To_Unbounded_String ("trusted" & Character'Val (10) & "user-ca");
      Status_Value := SSH_Lib.Sessions.Open (Options, Session_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Authentication_Failed,
         "public open runtime",
         "open rejects newline-bearing TrustedUserCAKeys before authentication setup");
      Check
        (not SSH_Lib.Sessions.Test_Support.Is_Open_For_Test (Session_Item),
         "newline-bearing TrustedUserCAKeys leaves session closed");

      Options := Local_Options;
      Options.Host_Key_Algorithms := To_Unbounded_String ("sk-ssh-ed25519-cert-v01@openssh.com");
      Status_Value := SSH_Lib.Sessions.Open (Options, Session_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Unsupported_Feature,
         "public open runtime",
         "open rejects unsupported-only HostKeyAlgorithms before runtime gates");
      Check
        (not SSH_Lib.Sessions.Test_Support.Is_Open_For_Test (Session_Item),
         "unsupported-only HostKeyAlgorithms leaves session closed");

      Options := Local_Options;
      Options.Host_Key_Algorithms := To_Unbounded_String
        ("sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519");
      Status_Value := SSH_Lib.Sessions.Open (Options, Session_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "public open runtime",
         "mixed HostKeyAlgorithms remains usable when an implemented algorithm is present");
      Check
        (SSH_Lib.Sessions.Test_Support.Is_Open_For_Test (Session_Item),
         "mixed HostKeyAlgorithms publishes an open state");

      Options := Local_Options;
      Options.Kex_Algorithms := To_Unbounded_String ("diffie-hellman-group1-sha1");
      Status_Value := SSH_Lib.Sessions.Open (Options, Session_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Unsupported_Feature,
         "public open runtime",
         "open rejects unsupported-only KexAlgorithms before runtime gates");
      Check
        (not SSH_Lib.Sessions.Test_Support.Is_Open_For_Test (Session_Item),
         "unsupported-only KexAlgorithms leaves session closed");

      Options := Local_Options;
      Options.Cipher_Algorithms := To_Unbounded_String ("3des-cbc");
      Status_Value := SSH_Lib.Sessions.Open (Options, Session_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Unsupported_Feature,
         "public open runtime",
         "open rejects unsupported-only Ciphers before runtime gates");
      Check
        (not SSH_Lib.Sessions.Test_Support.Is_Open_For_Test (Session_Item),
         "unsupported-only Ciphers leaves session closed");

      Options := Local_Options;
      Options.Mac_Algorithms := To_Unbounded_String ("hmac-md5");
      Status_Value := SSH_Lib.Sessions.Open (Options, Session_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Unsupported_Feature,
         "public open runtime",
         "open rejects unsupported-only MACs before runtime gates");
      Check
        (not SSH_Lib.Sessions.Test_Support.Is_Open_For_Test (Session_Item),
         "unsupported-only MACs leaves session closed");

      Options := Local_Options;
      Options.Compression_Algorithms := To_Unbounded_String ("zlib@openssh.com,none");
      Status_Value := SSH_Lib.Sessions.Open (Options, Session_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "public open runtime",
         "supported Compression algorithms pass open preflight");
      Check
        (SSH_Lib.Sessions.Test_Support.Is_Open_For_Test (Session_Item),
         "supported Compression algorithms publish an open state");

      Options := Local_Options;
      Options.Preferred_Authentications := To_Unbounded_String ("gssapi-with-mic");
      Status_Value := SSH_Lib.Sessions.Open (Options, Session_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Unsupported_Feature,
         "public open runtime",
         "open rejects unsupported-only PreferredAuthentications before runtime gates");
      Check
        (not SSH_Lib.Sessions.Test_Support.Is_Open_For_Test (Session_Item),
         "unsupported-only PreferredAuthentications leaves session closed");

      Options := Local_Options;
      Options.Kex_Algorithms := To_Unbounded_String ("curve25519-sha256,,diffie-hellman-group14-sha256");
      Status_Value := SSH_Lib.Sessions.Open (Options, Session_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Unsupported_Feature,
         "public open runtime",
         "open rejects malformed KexAlgorithms name-list before runtime gates");
      Check
        (not SSH_Lib.Sessions.Test_Support.Is_Open_For_Test (Session_Item),
         "malformed KexAlgorithms leaves session closed");

      Options := Local_Options;
      Options.Pubkey_Accepted_Algorithms := To_Unbounded_String ("ssh-dss");
      Status_Value := SSH_Lib.Sessions.Open (Options, Session_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Unsupported_Feature,
         "public open runtime",
         "publickey-enabled open rejects unsupported-only PubkeyAcceptedAlgorithms");
      Check
        (not SSH_Lib.Sessions.Test_Support.Is_Open_For_Test (Session_Item),
         "unsupported-only PubkeyAcceptedAlgorithms leaves session closed");

      Options := Local_Options;
      Options.Pubkey_Accepted_Algorithms := To_Unbounded_String
        ("ssh-dss,rsa-sha2-256");
      Status_Value := SSH_Lib.Sessions.Open (Options, Session_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "public open runtime",
         "mixed PubkeyAcceptedAlgorithms remains usable when an implemented algorithm is present");
      Check
        (SSH_Lib.Sessions.Test_Support.Is_Open_For_Test (Session_Item),
         "mixed PubkeyAcceptedAlgorithms publishes an open state");

      Options := Local_Options;
      Options.Pubkey_Accepted_Algorithms := To_Unbounded_String ("ssh-dss");
      Options.Preferred_Authentications := To_Unbounded_String ("password");
      Options.Use_Agent := False;
      Options.Use_Password := True;
      Options.Password_Callback := Deterministic_Password_Callback'Access;
      Status_Value := SSH_Lib.Sessions.Open (Options, Session_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "public open runtime",
         "password-only preference ignores unsupported publickey allow-list");
      Check
        (Buffer_Contains_Text
           (SSH_Lib.Sessions.Userauth_IO.Last_Plain_Userauth_Payload_For_Test
              (Session_Item),
            "password"),
         "password-only PubkeyAcceptedAlgorithms case emits password userauth");

      Options := Local_Options;
      Options.Use_Agent := False;
      Options.Use_Password := True;
      Options.Password_Callback := Deterministic_Password_Callback'Access;
      Status_Value := SSH_Lib.Sessions.Open (Options, Session_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "public open runtime",
         "deterministic password callback runtime authenticates through protected userauth");
      Check
        (SSH_Lib.Sessions.Test_Support.Is_Open_For_Test (Session_Item),
         "password callback runtime publishes a successful open state");
      Check
        (SSH_Lib.Sessions.Test_Support.Stored_Credentials_Clear_For_Test
           (Session_Item),
         "password callback runtime does not store credential callbacks");
      Check
        (not SSH_Lib.Protocol.Buffers.Is_Empty
           (SSH_Lib.Sessions.Userauth_IO.Last_Protected_Userauth_Payload_For_Test
              (Session_Item)),
         "password callback runtime emits protected userauth traffic");
      Check
        (Buffer_Contains_Text
           (SSH_Lib.Sessions.Userauth_IO.Last_Plain_Userauth_Payload_For_Test
              (Session_Item),
            "<redacted>"),
         "password callback runtime stores only a redacted plain transcript");
      Check
        (not Buffer_Contains_Text
           (SSH_Lib.Sessions.Userauth_IO.Last_Plain_Userauth_Payload_For_Test
              (Session_Item),
            "callback-secret"),
         "password callback secret is not retained in the plain transcript");

      Status_Value := SSH_Lib.Sessions.Close (Session_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "public open runtime",
         "close after password callback runtime succeeds");
      Check
        (SSH_Lib.Sessions.Test_Support.Stored_Credentials_Clear_For_Test
           (Session_Item),
         "close after password callback runtime keeps stored credentials clear");

      Options := Local_Options;
      Options.Use_Agent := False;
      Options.Use_Password := True;
      Options.Password_Callback := Invalid_Password_Callback'Access;
      Status_Value := SSH_Lib.Sessions.Open (Options, Session_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Authentication_Failed,
         "public open runtime",
         "deterministic password callback rejects newline-bearing secrets");
      Check
        (not SSH_Lib.Sessions.Test_Support.Is_Open_For_Test (Session_Item),
         "invalid password callback leaves the deterministic runtime closed");
      Check
        (SSH_Lib.Sessions.Test_Support.Stored_Credentials_Clear_For_Test
           (Session_Item),
         "failed password callback open keeps stored credentials clear");

      Options := Local_Options;
      Options.Host := Null_Unbounded_String;
      Status_Value := SSH_Lib.Sessions.Open (Options, Session_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Invalid_Host,
         "public open runtime",
         "open rejects an empty host before runtime setup");
      Check
        (not SSH_Lib.Sessions.Test_Support.Is_Open_For_Test (Session_Item),
         "empty host leaves deterministic local runtime closed");

      Options := Local_Options;
      Options.User := Null_Unbounded_String;
      Status_Value := SSH_Lib.Sessions.Open (Options, Session_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Invalid_User,
         "public open runtime",
         "open rejects an empty user before runtime setup");
      Check
        (not SSH_Lib.Sessions.Test_Support.Is_Open_For_Test (Session_Item),
         "empty user leaves deterministic local runtime closed");

      Options := Local_Options;
      Options.Port := 0;
      Status_Value := SSH_Lib.Sessions.Open (Options, Session_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Invalid_Port,
         "public open runtime",
         "open rejects an invalid port before runtime setup");
      Check
        (not SSH_Lib.Sessions.Test_Support.Is_Open_For_Test (Session_Item),
         "invalid port leaves deterministic local runtime closed");

      Options := Local_Options;
      Options.Proxy_Jump := To_Unbounded_String ("bastion.example,,edge.example");
      Status_Value := SSH_Lib.Sessions.Open (Options, Session_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Invalid_Host,
         "public open runtime",
         "open rejects malformed ProxyJump chains before jump connection");
      Check
        (not SSH_Lib.Sessions.Test_Support.Is_Open_For_Test (Session_Item),
         "malformed ProxyJump leaves deterministic local runtime closed");

      Options := Local_Options;
      Options.Host := To_Unbounded_String ("ordinary.invalid");
      Status_Value := SSH_Lib.Sessions.Open (Options, Session_Item);
      Check
        (Status_Value /= CryptoLib.Errors.Unsupported_Feature,
         "ordinary public-network host enters live transport instead of the old top-level Unsupported_Feature gate");
      Check
        (not SSH_Lib.Sessions.Test_Support.Is_Open_For_Test (Session_Item),
         "incomplete live runtime still leaves public session closed");

      Options := Local_Options;
      Options.Connect_Timeout_MS := 0;
      Status_Value := SSH_Lib.Sessions.Open (Options, Session_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Timeout,
         "public open runtime", "connect timeout preflight is decisive");
      Check
        (not SSH_Lib.Sessions.Test_Support.Is_Open_For_Test (Session_Item),
         "connect timeout leaves deterministic local runtime closed");

      Options := Local_Options;
      Options.Write_Timeout_MS := 0;
      Status_Value := SSH_Lib.Sessions.Open (Options, Session_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Timeout,
         "public open runtime", "write timeout preflight is decisive");
      Check
        (not SSH_Lib.Sessions.Test_Support.Is_Open_For_Test (Session_Item),
         "write timeout leaves deterministic local runtime closed");

      Options := Local_Options;
      Options.Read_Timeout_MS := 0;
      Status_Value := SSH_Lib.Sessions.Open (Options, Session_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Timeout,
         "public open runtime", "read timeout preflight is decisive");
      Check
        (not SSH_Lib.Sessions.Test_Support.Is_Open_For_Test (Session_Item),
         "read timeout leaves deterministic local runtime closed");
   end Assert_Public_Open_Runtime_Gates;
end SSH_Lib.Tests.Fixtures.Open_Runtime;
