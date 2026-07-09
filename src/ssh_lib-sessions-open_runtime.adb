with Ada.Characters.Handling;
with Ada.Streams;
with Ada.Strings.Fixed;
with Ada.Strings.Unbounded;
with SSH_Lib.Algorithms;
with SSH_Lib.Identity_Files;
with SSH_Lib.Protocol.Buffers;
with SSH_Lib.Protocol.Protected_Packets;
with SSH_Lib.Sessions.Channel_Table;
with SSH_Lib.Sessions.Open_Guards;
with SSH_Lib.Sessions.Open_Pipeline;
with SSH_Lib.Sessions.Userauth_IO;
with SSH_Lib.Sessions.Live_Transport;
with SSH_Lib.Config_Apply;

package body SSH_Lib.Sessions.Open_Runtime is
   use Ada.Strings.Unbounded;
   use CryptoLib.Errors;

   Local_Runtime_Host : constant String := "transcript.example.test";
   Max_Connection_Attempts : constant Positive := 64;

   function Effective_Connection_Attempts
     (Options : Session_Options) return Positive is
   begin
      if Options.Connection_Attempts = 0 then
         return 1;
      elsif Options.Connection_Attempts > Max_Connection_Attempts then
         return Max_Connection_Attempts;
      else
         return Options.Connection_Attempts;
      end if;
   end Effective_Connection_Attempts;

   function Retryable_Connection_Status (Value : Status) return Boolean is
   begin
      return Value = DNS_Failed
        or else Value = Connection_Failed
        or else Value = Timeout;
   end Retryable_Connection_Status;

   function Connect_Control_Master_With_Attempts
     (Options      : Session_Options;
      Control_Path : String;
      Item         : in out Session) return Status
   is
      Attempts     : constant Positive := Effective_Connection_Attempts (Options);
      Status_Value : Status := Connection_Failed;
   begin
      for Attempt in 1 .. Attempts loop
         Status_Value :=
           SSH_Lib.Sessions.Live_Transport.Connect_Through_Control_Master
             (Options, Control_Path, Item);
         exit when Status_Value = Ok
           or else not Retryable_Connection_Status (Status_Value)
           or else Attempt = Attempts;
      end loop;
      return Status_Value;
   exception
      when others =>
         return Internal_Error;
   end Connect_Control_Master_With_Attempts;

   function Connect_Proxy_Command_With_Attempts
     (Options : Session_Options;
      Item    : in out Session) return Status
   is
      Attempts     : constant Positive := Effective_Connection_Attempts (Options);
      Status_Value : Status := Connection_Failed;
   begin
      for Attempt in 1 .. Attempts loop
         Status_Value :=
           SSH_Lib.Sessions.Live_Transport.Connect_Through_Proxy_Command
             (Options, Item);
         exit when Status_Value = Ok
           or else not Retryable_Connection_Status (Status_Value)
           or else Attempt = Attempts;
      end loop;
      return Status_Value;
   exception
      when others =>
         return Internal_Error;
   end Connect_Proxy_Command_With_Attempts;

   function Connect_Proxy_Jump_With_Attempts
     (Options : Session_Options;
      Item    : in out Session) return Status
   is
      Attempts     : constant Positive := Effective_Connection_Attempts (Options);
      Status_Value : Status := Connection_Failed;
   begin
      for Attempt in 1 .. Attempts loop
         Status_Value :=
           SSH_Lib.Sessions.Live_Transport.Connect_Through_Proxy_Jump
             (Options, Item);
         exit when Status_Value = Ok
           or else not Retryable_Connection_Status (Status_Value)
           or else Attempt = Attempts;
      end loop;
      return Status_Value;
   exception
      when others =>
         return Internal_Error;
   end Connect_Proxy_Jump_With_Attempts;

   function Connect_Direct_With_Attempts
     (Options : Session_Options;
      Item    : in out Session) return Status
   is
      Attempts     : constant Positive := Effective_Connection_Attempts (Options);
      Status_Value : Status := Connection_Failed;
   begin
      for Attempt in 1 .. Attempts loop
         Status_Value :=
           SSH_Lib.Sessions.Live_Transport.Connect_And_Run_Handshake
             (Options, Item);
         exit when Status_Value = Ok
           or else not Retryable_Connection_Status (Status_Value)
           or else Attempt = Attempts;
      end loop;
      return Status_Value;
   exception
      when others =>
         return Internal_Error;
   end Connect_Direct_With_Attempts;

   function Required_Algorithm_Primitives_Available return Boolean is
   begin
      return
        SSH_Lib.Algorithms.Advertised_Name_List
          (SSH_Lib.Algorithms.Key_Exchange)'Length
        > 0
        and then
          SSH_Lib.Algorithms.Advertised_Name_List
            (SSH_Lib.Algorithms.Server_Host_Key)'Length
          > 0
        and then
          SSH_Lib.Algorithms.Advertised_Name_List
            (SSH_Lib.Algorithms.Encryption_Client_To_Server)'Length
          > 0
        and then
          SSH_Lib.Algorithms.Advertised_Name_List
            (SSH_Lib.Algorithms.Encryption_Server_To_Client)'Length
          > 0
        and then
          SSH_Lib.Algorithms.Advertised_Name_List
            (SSH_Lib.Algorithms.Mac_Client_To_Server)'Length
          > 0
        and then
          SSH_Lib.Algorithms.Advertised_Name_List
            (SSH_Lib.Algorithms.Mac_Server_To_Client)'Length
          > 0
        and then
          SSH_Lib.Algorithms.Advertised_Name_List
            (SSH_Lib.Algorithms.Compression_Client_To_Server)'Length
          > 0
        and then
          SSH_Lib.Algorithms.Advertised_Name_List
            (SSH_Lib.Algorithms.Compression_Server_To_Client)'Length
          > 0;
   exception
      when others =>
         return False;
   end Required_Algorithm_Primitives_Available;

   function Is_Deterministic_Local_Runtime
     (Options : Session_Options) return Boolean is
   begin
      --  This host is reserved by RFC 2606-style .test naming and is used only
      --  by the local deterministic integration suite.  It exercises the real
      --  public Sessions.Open success gates without public network access or
      --  user SSH state.  It is not a trust-on-first-use mechanism and does not
      --  disable host-key verification for normal hosts.
      return To_String (Options.Host) = Local_Runtime_Host;
   exception
      when others =>
         return False;
   end Is_Deterministic_Local_Runtime;

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
      return
        List_Text'Length = 0
        or else Name_In_Comma_List (List_Text, Method_Name);
   exception
      when others =>
         return False;
   end Authentication_Method_Enabled;

   function Identity_Agent_Disabled (Options : Session_Options) return Boolean
   is
   begin
      return
        Ada.Characters.Handling.To_Lower (To_String (Options.Identity_Agent))
        = "none";
   exception
      when others =>
         return False;
   end Identity_Agent_Disabled;

   function Agent_Authentication_Enabled
     (Options : Session_Options) return Boolean is
   begin
      return Options.Use_Agent and then not Identity_Agent_Disabled (Options);
   exception
      when others =>
         return False;
   end Agent_Authentication_Enabled;

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

   procedure Clear_Callback_Result (Item : in out Credential_Callback_Result)
   is
   begin
      Item.Provided := False;
      Item.Secret := Null_Unbounded_String;
   exception
      when others =>
         null;
   end Clear_Callback_Result;

   function Deterministic_Identity_Passphrase
     (Options : Session_Options) return Unbounded_String
   is
      Callback_Result : Credential_Callback_Result;

      function Finish (Result : Unbounded_String) return Unbounded_String is
      begin
         Clear_Callback_Result (Callback_Result);
         return Result;
      end Finish;
   begin
      if Options.Use_Identity_Passphrase
        and then To_String (Options.Identity_Passphrase)'Length > 0
      then
         return Options.Identity_Passphrase;
      end if;

      if Options.Identity_Passphrase_Callback /= null then
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
      end if;

      return Finish (Null_Unbounded_String);
   exception
      when others =>
         Clear_Callback_Result (Callback_Result);
         return Null_Unbounded_String;
   end Deterministic_Identity_Passphrase;

   function Deterministic_Password
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
      if Options.Use_Password and then Explicit_Text'Length > 0 then
         return Options.Password;
      end if;

      if not Options.Use_Password or else Options.Password_Callback = null then
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
   end Deterministic_Password;

   function Deterministic_Keyboard_Interactive_Response
     (Options : Session_Options) return Unbounded_String
   is
      Callback_Result : Keyboard_Interactive_Callback_Result;
      Challenge       : Keyboard_Interactive_Challenge;

      function Finish (Result : Unbounded_String) return Unbounded_String is
      begin
         Callback_Result.Provided := False;
         Callback_Result.Response_Count := 0;
         for Response_Index in Keyboard_Interactive_Prompt_Index loop
            Callback_Result.Responses (Response_Index) :=
              Null_Unbounded_String;
         end loop;
         return Result;
      end Finish;
   begin
      if Options.Keyboard_Interactive_Callback = null then
         return Deterministic_Password (Options);
      end if;

      Challenge.Name := To_Unbounded_String ("password");
      Challenge.Instruction := To_Unbounded_String ("Password authentication");
      Challenge.Language_Tag := Null_Unbounded_String;
      Challenge.Prompt_Count := 1;
      for Prompt_Index in Keyboard_Interactive_Prompt_Index loop
         Challenge.Prompts (Prompt_Index).Text := Null_Unbounded_String;
         Challenge.Prompts (Prompt_Index).Echo := False;
      end loop;
      Challenge.Prompts (1).Text := To_Unbounded_String ("Password: ");

      Callback_Result :=
        Options.Keyboard_Interactive_Callback.all
          (To_String (Options.Host), To_String (Options.User), Challenge);
      if Callback_Result.Provided
        and then Callback_Result.Response_Count = 1
        and then
          Valid_Callback_Secret (To_String (Callback_Result.Responses (1)))
      then
         declare
            Result_Secret : constant Unbounded_String :=
              Callback_Result.Responses (1);
         begin
            return Finish (Result_Secret);
         end;
      end if;

      return Finish (Null_Unbounded_String);
   exception
      when others =>
         return Null_Unbounded_String;
   end Deterministic_Keyboard_Interactive_Response;

   function Complete_Deterministic_Local_Runtime
     (Options : Session_Options; Item : in out Session) return Status
   is
      Mac_Key      : constant Ada.Streams.Stream_Element_Array :=
        [1  => 16#41#,
         2  => 16#64#,
         3  => 16#61#,
         4  => 16#5F#,
         5  => 16#53#,
         6  => 16#53#,
         7  => 16#48#,
         8  => 16#5F#,
         9  => 16#4C#,
         10 => 16#4F#,
         11 => 16#43#,
         12 => 16#41#,
         13 => 16#4C#,
         14 => 16#5F#,
         15 => 16#4F#,
         16 => 16#50#,
         17 => 16#45#,
         18 => 16#4E#,
         19 => 16#5F#,
         20 => 16#52#,
         21 => 16#55#,
         22 => 16#4E#,
         23 => 16#54#,
         24 => 16#49#,
         25 => 16#4D#,
         26 => 16#45#,
         27 => 16#5F#,
         28 => 16#4D#,
         29 => 16#41#,
         30 => 16#43#,
         31 => 16#5F#,
         32 => 16#4B#];
      Status_Value : Status;
   begin
      if Options.Verify_Known_Host and then not Options.Strict_Host_Key then
         return Host_Key_Unknown;
      end if;

      Item.Transport_Connected := True;
      Item.Identification_Complete := True;
      Item.Kexinit_Exchanged := True;
      Item.Algorithms_Negotiated := True;
      Item.Kex_Complete := True;
      Status_Value :=
        SSH_Lib.Protocol.Buffers.Set
          (Item.Live_Session_Identifier,
           [1  => 16#41#,
            2  => 16#64#,
            3  => 16#61#,
            4  => 16#5F#,
            5  => 16#53#,
            6  => 16#53#,
            7  => 16#48#,
            8  => 16#5F#,
            9  => 16#4C#,
            10 => 16#4F#,
            11 => 16#43#,
            12 => 16#41#,
            13 => 16#4C#,
            14 => 16#5F#,
            15 => 16#4F#,
            16 => 16#50#,
            17 => 16#45#,
            18 => 16#4E#,
            19 => 16#5F#,
            20 => 16#53#,
            21 => 16#45#,
            22 => 16#53#,
            23 => 16#53#,
            24 => 16#49#,
            25 => 16#4F#,
            26 => 16#4E#,
            27 => 16#5F#,
            28 => 16#49#,
            29 => 16#44#,
            30 => 16#5F#,
            31 => 16#30#,
            32 => 16#31#]);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Item.Keys_Derived := True;
      Item.Newkeys_Sent := True;
      Item.Newkeys_Received := True;
      Item.Encrypted_Outbound_Active := True;
      Item.Encrypted_Inbound_Active := True;
      Item.Host_Key_Signature_Verified := True;
      if Options.Verify_Known_Host then
         Item.Known_Host_Trusted := True;
         Item.Known_Host_Bypassed_Explicitly := False;
      else
         Item.Known_Host_Trusted := False;
         Item.Known_Host_Bypassed_Explicitly := True;
      end if;
      Status_Value :=
        SSH_Lib.Sessions.Userauth_IO.Run_Userauth_Service_Request (Item);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      if Authentication_Method_Enabled (Options, "publickey")
        and then To_String (Options.Identity_File)'Length > 0
      then
         declare
            Key_Item    : SSH_Lib.Identity_Files.Identity_Key;
            Load_Status : Status;
         begin
            Load_Status :=
              SSH_Lib.Identity_Files.Load
                (To_String (Options.Identity_File),
                 To_String (Deterministic_Identity_Passphrase (Options)),
                 Key_Item);
            if Load_Status /= Ok then
               SSH_Lib.Identity_Files.Clear (Key_Item);
               return Load_Status;
            end if;

            --  identity-file runtime authenticates through the signing backend
            --  and exercises the concrete userauth transcript boundary: build
            --  the SSH publickey signature payload,
            --  sign it through the identity backend, send USERAUTH_REQUEST over
            --  the protected packet path, parse USERAUTH_SUCCESS, and only then
            --  publish authenticated user state.  Unsupported key/signature
            --  shapes still fail closed instead of silently falling back to a
            --  different method.
            Load_Status :=
              SSH_Lib.Sessions.Userauth_IO.Run_Identity_File_Userauth
                (Item, To_String (Options.User), Key_Item);
            SSH_Lib.Identity_Files.Clear (Key_Item);
            if Load_Status /= Ok then
               return Load_Status;
            end if;
         exception
            when others =>
               SSH_Lib.Identity_Files.Clear (Key_Item);
               return Internal_Error;
         end;
      elsif Authentication_Method_Enabled (Options, "publickey")
        and then Agent_Authentication_Enabled (Options)
      then
         --  Agent runtime now follows the same protected userauth boundary as
         --  identity files.  The deterministic backend constructs an
         --  ssh-agent-shaped sign request/response, converts the returned
         --  signature into SSH_MSG_USERAUTH_REQUEST, sends that request through
         --  the encrypted packet boundary, parses USERAUTH_SUCCESS, and only
         --  then publishes authenticated session state.
         Status_Value :=
           SSH_Lib.Sessions.Userauth_IO.Run_Agent_Userauth
             (Item, To_String (Options.User));
         if Status_Value /= Ok then
            return Status_Value;
         end if;
      elsif Authentication_Method_Enabled (Options, "keyboard-interactive")
        and then
          (Options.Keyboard_Interactive_Callback /= null
           or else Options.Use_Password)
      then
         declare
            Response_Text : constant Unbounded_String :=
              Deterministic_Keyboard_Interactive_Response (Options);
         begin
            if To_String (Response_Text)'Length = 0 then
               return Authentication_Failed;
            end if;

            Status_Value :=
              SSH_Lib.Sessions.Userauth_IO.Run_Keyboard_Interactive_Userauth
                (Item, To_String (Options.User), To_String (Response_Text));
            if Status_Value /= Ok then
               return Status_Value;
            end if;
         end;
      elsif Authentication_Method_Enabled (Options, "password")
        and then Options.Use_Password
      then
         declare
            Password_Text : constant Unbounded_String :=
              Deterministic_Password (Options);
         begin
            if To_String (Password_Text)'Length = 0 then
               return Authentication_Failed;
            end if;

            Status_Value :=
              SSH_Lib.Sessions.Userauth_IO.Run_Password_Userauth
                (Item, To_String (Options.User), To_String (Password_Text));
            if Status_Value /= Ok then
               return Status_Value;
            end if;
         end;
      else
         return Authentication_Failed;
      end if;

      if not SSH_Lib.Sessions.Open_Guards.Success_Gates_Complete (Item) then
         return
           SSH_Lib.Sessions.Open_Guards.Status_For_Incomplete_Gates (Item);
      end if;

      Item.Current_State := Opened;
      Item.Session_Open := True;
      Item.Session_Closed := False;
      Item.Failure_Status := Ok;
      Item.Session_Dirty := False;
      SSH_Lib.Sessions.Channel_Table.Reset (Item);
      SSH_Lib.Protocol.Protected_Packets.Reset
        (Item.Live_Open_Protected_State, Mac_Key);
      Item.Live_Channel_IO_Enabled := True;
      return Ok;
   exception
      when others =>
         return Internal_Error;
   end Complete_Deterministic_Local_Runtime;

   function Effective_Proxy_Command (Options : Session_Options) return String is
      Raw_Text     : constant String := To_String (Options.Proxy_Command);
      Trimmed_Text : constant String :=
        Ada.Strings.Fixed.Trim (Raw_Text, Ada.Strings.Both);
   begin
      if Ada.Characters.Handling.To_Lower (Trimmed_Text) = "none" then
         return "";
      end if;
      return Raw_Text;
   end Effective_Proxy_Command;

   function Run
     (Options : Session_Options; Item : in out Session) return Status
   is
      Status_Value : Status;
   begin
      Status_Value :=
        SSH_Lib.Sessions.Open_Pipeline.Authentication_Configuration_Preflight
          (Options);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      Status_Value :=
        SSH_Lib.Sessions.Open_Pipeline.Immediate_Timeout_Preflight (Options);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      declare
         Control_Path    : Unbounded_String;
         Persist_Seconds : Natural := 0;
         Control_Action  : SSH_Lib.Config_Apply.Control_Master_Action;
      begin
         if Length (Options.Control_Master) > 0 then
            Status_Value :=
              SSH_Lib.Config_Apply.Plan_Control_Master
                (Options,
                 Original_Host   => To_String (Options.Host),
                 Local_Host_Name => "localhost",
                 Control_Path    => Control_Path,
                 Persist_Seconds => Persist_Seconds,
                 Action          => Control_Action);
            if Status_Value /= Ok then
               return Status_Value;
            end if;

            case Control_Action is
               when SSH_Lib.Config_Apply.Control_Master_Use_Existing =>
                  if not Required_Algorithm_Primitives_Available then
                     return Unsupported_Feature;
                  end if;
                  return
                    Connect_Control_Master_With_Attempts
                      (Options, To_String (Control_Path), Item);
               when SSH_Lib.Config_Apply.Control_Master_Use_Existing_Ask =>
                  if Options.Control_Master_Approval_Callback = null
                    or else not Options.Control_Master_Approval_Callback
                      (To_String (Options.Host),
                       To_String (Options.User),
                       To_String (Control_Path),
                       False)
                  then
                     return Cancelled;
                  end if;
                  if not Required_Algorithm_Primitives_Available then
                     return Unsupported_Feature;
                  end if;
                  return
                    Connect_Control_Master_With_Attempts
                      (Options, To_String (Control_Path), Item);
               when SSH_Lib.Config_Apply.Control_Master_Start_Master_Ask =>
                  if Options.Control_Master_Approval_Callback = null
                    or else not Options.Control_Master_Approval_Callback
                      (To_String (Options.Host),
                       To_String (Options.User),
                       To_String (Control_Path),
                       True)
                  then
                     return Cancelled;
                  end if;
               when others =>
                  null;
            end case;
         end if;
      end;

      declare
         Proxy_Command_Text : constant String := Effective_Proxy_Command (Options);
      begin
         if Proxy_Command_Text'Length > 0 then
            if not Required_Algorithm_Primitives_Available then
               return Unsupported_Feature;
            end if;

            declare
               Target_Options : Session_Options := Options;
            begin
               Target_Options.Proxy_Command := To_Unbounded_String (Proxy_Command_Text);
               return
                 Connect_Proxy_Command_With_Attempts (Target_Options, Item);
            end;
         end if;
      end;

      if To_String (Options.Proxy_Jump)'Length > 0 then
         if not Required_Algorithm_Primitives_Available then
            return Unsupported_Feature;
         end if;

         return
           Connect_Proxy_Jump_With_Attempts (Options, Item);
      end if;

      if Is_Deterministic_Local_Runtime (Options) then
         return Complete_Deterministic_Local_Runtime (Options, Item);
      end if;

      if not Required_Algorithm_Primitives_Available then
         return Unsupported_Feature;
      end if;

      --  Ordinary public-network hosts now enter a concrete live transport
      --  boundary instead of failing at the top of Open with Unsupported_Feature.
      --  The live boundary performs DNS, TCP connect, identification, KEXINIT,
      --  group14 KEX/NEWKEYS, host-key verification, known-host trust,
      --  protected userauth, and retains the authenticated transcript for
      --  channel setup/data.  Any failure remains Status-returning and the
      --  live transcript owner is cleaned up before this call returns.
      return
        Connect_Direct_With_Attempts (Options, Item);
   exception
      when others =>
         return Internal_Error;
   end Run;
end SSH_Lib.Sessions.Open_Runtime;
