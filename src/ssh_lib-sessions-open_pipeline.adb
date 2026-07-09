with Ada.Characters.Handling;
with Ada.Directories;
with Ada.Strings.Unbounded;
with SSH_Lib.Algorithms;
with SSH_Lib.Internal;
with SSH_Lib.Platform.Paths;

package body SSH_Lib.Sessions.Open_Pipeline is
   use Ada.Strings.Unbounded;
   use CryptoLib.Errors;

   function Invalid_Path_Syntax (Path_Text : String) return Boolean is
   begin
      for Char_Value of Path_Text loop
         if Char_Value = Character'Val (0)
           or else Char_Value = Character'Val (10)
           or else Char_Value = Character'Val (13)
         then
            return True;
         end if;
      end loop;
      return False;
   end Invalid_Path_Syntax;

   function Invalid_Path_List_Syntax (Path_List_Text : String) return Boolean
   is
      Start_Index : Positive;
      Stop_Index  : Natural;
   begin
      if Path_List_Text'Length = 0 then
         return False;
      end if;

      Start_Index := Path_List_Text'First;
      loop
         Stop_Index := Start_Index;
         while Stop_Index <= Path_List_Text'Last
           and then Path_List_Text (Stop_Index) /= ','
         loop
            Stop_Index := Stop_Index + 1;
         end loop;

         if Stop_Index = Start_Index then
            return True;
         end if;

         if Invalid_Path_Syntax
              (Path_List_Text (Start_Index .. Stop_Index - 1))
         then
            return True;
         end if;

         exit when Stop_Index > Path_List_Text'Last;
         Start_Index := Stop_Index + 1;
      end loop;

      return False;
   exception
      when others =>
         return True;
   end Invalid_Path_List_Syntax;

   function Invalid_Gex_Bounds
     (Minimum_Bits : Natural; Preferred_Bits : Natural; Maximum_Bits : Natural)
      return Boolean is
   begin
      return
        Minimum_Bits < 1024
        or else Preferred_Bits < Minimum_Bits
        or else Maximum_Bits < Preferred_Bits
        or else Maximum_Bits > 8192;
   exception
      when others =>
         return True;
   end Invalid_Gex_Bounds;

   function Configured_List_Has_Available_Algorithm
     (Class_Item : SSH_Lib.Algorithms.Algorithm_Class; List_Text : String)
      return Boolean
   is
      Start_Index : Positive := List_Text'First;
      Stop_Index  : Natural;
   begin
      if List_Text'Length = 0 then
         return True;
      end if;

      if not SSH_Lib.Algorithms.Validate_Name_List (List_Text) then
         return False;
      end if;

      loop
         Stop_Index := Start_Index;
         while Stop_Index <= List_Text'Last
           and then List_Text (Stop_Index) /= ','
         loop
            Stop_Index := Stop_Index + 1;
         end loop;

         if SSH_Lib.Algorithms.Is_Supported
              (Class_Item, List_Text (Start_Index .. Stop_Index - 1))
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
   end Configured_List_Has_Available_Algorithm;

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
      --  Match OpenSSH IdentityAgent none semantics case-insensitively:
      --  it disables use of ssh-agent even when Use_Agent is otherwise true.
      --  Treating a differently-cased NONE/None token as a socket path would
      --  make preflight optimistic and can leak into an unintended filesystem
      --  connect attempt.
      return Options.Use_Agent and then not Identity_Agent_Disabled (Options);
   exception
      when others =>
         return False;
   end Agent_Authentication_Enabled;

   function Preferred_Authentications_Has_Implemented_Method
     (List_Text : String) return Boolean is
   begin
      if List_Text'Length = 0 then
         return True;
      end if;

      return
        Name_In_Comma_List (List_Text, "publickey")
        or else Name_In_Comma_List (List_Text, "keyboard-interactive")
        or else Name_In_Comma_List (List_Text, "password")
        or else Name_In_Comma_List (List_Text, "none");
   exception
      when others =>
         return False;
   end Preferred_Authentications_Has_Implemented_Method;

   function Pubkey_Accepted_List_Has_Implemented_Algorithm
     (List_Text : String) return Boolean
   is
      Start_Index : Positive := List_Text'First;
      Stop_Index  : Natural;
   begin
      if List_Text'Length = 0 then
         return True;
      end if;

      if not SSH_Lib.Algorithms.Validate_Name_List (List_Text) then
         return False;
      end if;

      loop
         Stop_Index := Start_Index;
         while Stop_Index <= List_Text'Last
           and then List_Text (Stop_Index) /= ','
         loop
            Stop_Index := Stop_Index + 1;
         end loop;

         if SSH_Lib.Algorithms.Is_Supported
              (SSH_Lib.Algorithms.Server_Host_Key,
               List_Text (Start_Index .. Stop_Index - 1))
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
   end Pubkey_Accepted_List_Has_Implemented_Algorithm;

   function Default_Identity_Candidate_Exists return Boolean is
      Home_Text : constant String :=
        To_String (SSH_Lib.Platform.Paths.Home_Directory);
   begin
      --  Live userauth can try a bounded OpenSSH-compatible default identity
      --  set when the caller did not name Identity_File explicitly.  Keep the
      --  preflight aligned with that behavior: allow Open to proceed only when
      --  at least one concrete default candidate exists, avoiding unnecessary
      --  network handshakes when no authentication source is configured.
      if Home_Text'Length = 0 then
         return False;
      end if;

      return
        Ada.Directories.Exists (Home_Text & "/.ssh/id_ed25519")
        or else Ada.Directories.Exists (Home_Text & "/.ssh/id_rsa");
   exception
      when others =>
         return False;
   end Default_Identity_Candidate_Exists;

   function Validate_Options (Options : Session_Options) return Status is
      Host_Text                       : constant String :=
        To_String (Options.Host);
      User_Text                       : constant String :=
        To_String (Options.User);
      Known_Hosts_Text                : constant String :=
        To_String (Options.Known_Hosts_File);
      User_Known_Hosts_Text           : constant String :=
        To_String (Options.User_Known_Hosts_File);
      Global_Known_Hosts_Text         : constant String :=
        To_String (Options.Global_Known_Hosts_File);
      Host_Key_Alias_Text             : constant String :=
        To_String (Options.Host_Key_Alias);
      Revoked_Host_Keys_Text          : constant String :=
        To_String (Options.Revoked_Host_Keys_File);
      Certificate_Authority_Text      : constant String :=
        To_String (Options.Certificate_Authority_File);
      Trusted_User_CA_Keys_Text       : constant String :=
        To_String (Options.Trusted_User_CA_Keys_File);
      Allowed_Critical_Options_Text   : constant String :=
        To_String (Options.Allowed_Certificate_Critical_Options);
      Preferred_Authentications_Text  : constant String :=
        To_String (Options.Preferred_Authentications);
      Pubkey_Accepted_Algorithms_Text : constant String :=
        To_String (Options.Pubkey_Accepted_Algorithms);
      Identity_File_Text              : constant String :=
        To_String (Options.Identity_File);
      Certificate_File_Text           : constant String :=
        To_String (Options.Certificate_File);
      Update_Host_Keys_Text           : constant String :=
        Ada.Characters.Handling.To_Lower
          (To_String (Options.Update_Host_Keys));
      Verify_Host_Key_DNS_Text        : constant String :=
        Ada.Characters.Handling.To_Lower
          (To_String (Options.Verify_Host_Key_DNS));
      Add_Keys_To_Agent_Text          : constant String :=
        Ada.Characters.Handling.To_Lower
          (To_String (Options.Add_Keys_To_Agent));
      Identity_Agent_Text             : constant String :=
        To_String (Options.Identity_Agent);
      Password_Text                   : constant String :=
        To_String (Options.Password);
      Port_Status                     : constant Status :=
        SSH_Lib.Internal.Validate_Port (Options.Port);
   begin
      if not SSH_Lib.Internal.Valid_Host (Host_Text) then
         return Invalid_Host;
      end if;

      if Port_Status /= Ok then
         return Port_Status;
      end if;

      if not SSH_Lib.Internal.Valid_User (User_Text) then
         return Invalid_User;
      end if;

      if Verify_Host_Key_DNS_Text = "yes"
        or else Verify_Host_Key_DNS_Text = "ask"
      then
         return Unsupported_Feature;
      end if;

      if Options.Check_Host_IP
        or else
          (Update_Host_Keys_Text'Length > 0
           and then Update_Host_Keys_Text /= "no")
      then
         return Unsupported_Feature;
      end if;

      if Options.Hostbased_Authentication
        or else Options.Fork_After_Authentication
        or else Options.Proxy_Use_Fdpass
        or else Options.Enable_SSH_Keysign
        or else Options.GSSAPI_Authentication
        or else Options.GSSAPI_Delegate_Credentials
      then
         return Unsupported_Feature;
      end if;

      if Add_Keys_To_Agent_Text'Length > 0
        and then Add_Keys_To_Agent_Text /= "no"
      then
         return Unsupported_Feature;
      end if;

      if Known_Hosts_Text'Length > 0
        and then Invalid_Path_Syntax (Known_Hosts_Text)
      then
         return Host_Key_Unknown;
      end if;

      if User_Known_Hosts_Text'Length > 0
        and then Invalid_Path_List_Syntax (User_Known_Hosts_Text)
      then
         return Host_Key_Unknown;
      end if;

      if Global_Known_Hosts_Text'Length > 0
        and then Invalid_Path_List_Syntax (Global_Known_Hosts_Text)
      then
         return Host_Key_Unknown;
      end if;

      if Host_Key_Alias_Text'Length > 0
        and then Invalid_Path_Syntax (Host_Key_Alias_Text)
      then
         return Host_Key_Unknown;
      end if;

      if Revoked_Host_Keys_Text'Length > 0
        and then Invalid_Path_List_Syntax (Revoked_Host_Keys_Text)
      then
         return Host_Key_Mismatch;
      end if;

      if Certificate_Authority_Text'Length > 0
        and then Invalid_Path_List_Syntax (Certificate_Authority_Text)
      then
         return Host_Key_Unknown;
      end if;

      if Trusted_User_CA_Keys_Text'Length > 0
        and then Invalid_Path_List_Syntax (Trusted_User_CA_Keys_Text)
      then
         return Authentication_Failed;
      end if;

      if Identity_Agent_Text'Length > 0
        and then
          Ada.Characters.Handling.To_Lower (Identity_Agent_Text) /= "none"
        and then Invalid_Path_Syntax (Identity_Agent_Text)
      then
         return Authentication_Failed;
      end if;

      if Preferred_Authentications_Text'Length > 0 then
         if not SSH_Lib.Algorithms.Validate_Name_List
                  (Preferred_Authentications_Text)
           or else
             not Preferred_Authentications_Has_Implemented_Method
                   (Preferred_Authentications_Text)
         then
            return Unsupported_Feature;
         end if;
      end if;

      if To_String (Options.Kex_Algorithms)'Length > 0
        and then
          not Configured_List_Has_Available_Algorithm
                (SSH_Lib.Algorithms.Key_Exchange,
                 To_String (Options.Kex_Algorithms))
      then
         return Unsupported_Feature;
      end if;
      if To_String (Options.Host_Key_Algorithms)'Length > 0
        and then
          not Configured_List_Has_Available_Algorithm
                (SSH_Lib.Algorithms.Server_Host_Key,
                 To_String (Options.Host_Key_Algorithms))
      then
         return Unsupported_Feature;
      end if;
      if To_String (Options.Cipher_Algorithms)'Length > 0
        and then
          not Configured_List_Has_Available_Algorithm
                (SSH_Lib.Algorithms.Encryption_Client_To_Server,
                 To_String (Options.Cipher_Algorithms))
      then
         return Unsupported_Feature;
      end if;
      if To_String (Options.Mac_Algorithms)'Length > 0
        and then
          not Configured_List_Has_Available_Algorithm
                (SSH_Lib.Algorithms.Mac_Client_To_Server,
                 To_String (Options.Mac_Algorithms))
      then
         return Unsupported_Feature;
      end if;
      if To_String (Options.Compression_Algorithms)'Length > 0
        and then
          not Configured_List_Has_Available_Algorithm
                (SSH_Lib.Algorithms.Compression_Client_To_Server,
                 To_String (Options.Compression_Algorithms))
      then
         return Unsupported_Feature;
      end if;
      if Pubkey_Accepted_Algorithms_Text'Length > 0 then
         if not SSH_Lib.Algorithms.Validate_Name_List
                  (Pubkey_Accepted_Algorithms_Text)
         then
            return Unsupported_Feature;
         end if;

         if Authentication_Method_Enabled (Options, "publickey")
           and then
             not Pubkey_Accepted_List_Has_Implemented_Algorithm
                   (Pubkey_Accepted_Algorithms_Text)
         then
            return Unsupported_Feature;
         end if;
      end if;

      if Allowed_Critical_Options_Text'Length > 0
        and then
          not SSH_Lib.Algorithms.Validate_Name_List
                (Allowed_Critical_Options_Text)
      then
         return Unsupported_Feature;
      end if;

      if Invalid_Gex_Bounds
           (Options.Gex_Minimum_Bits,
            Options.Gex_Preferred_Bits,
            Options.Gex_Maximum_Bits)
      then
         return Handshake_Failed;
      end if;

      if Identity_File_Text'Length > 0
        and then Invalid_Path_Syntax (Identity_File_Text)
      then
         return Authentication_Failed;
      end if;

      if Certificate_File_Text'Length > 0
        and then Invalid_Path_Syntax (Certificate_File_Text)
      then
         return Authentication_Failed;
      end if;

      if Options.Use_Password then
         if Password_Text'Length = 0 and then Options.Password_Callback = null
         then
            return Authentication_Failed;
         end if;

         if Password_Text'Length > 0
           and then Invalid_Path_Syntax (Password_Text)
         then
            return Authentication_Failed;
         end if;
      end if;

      return Ok;
   exception
      when others =>
         return Internal_Error;
   end Validate_Options;

   function Authentication_Configuration_Preflight
     (Options : Session_Options) return Status
   is
      Identity_File_Text : constant String :=
        To_String (Options.Identity_File);
      Password_Text      : constant String := To_String (Options.Password);
   begin
      --  Phase 10 ordering guard.  At session-open entry we may validate that
      --  the caller configured at least one possible authentication method, but we
      --  must not contact ssh-agent, parse private-key material, or sign any
      --  payload before the real pipeline has completed transport setup,
      --  KEX/NEWKEYS, encrypted packet activation, and host-key trust.
      if To_String (Options.Preferred_Authentications)'Length > 0
        and then Authentication_Method_Enabled (Options, "none")
      then
         return Ok;
      end if;

      if Authentication_Method_Enabled (Options, "publickey") then
         if Identity_File_Text'Length > 0 then
            return Ok;
         end if;

         if Agent_Authentication_Enabled (Options) then
            return Ok;
         end if;

         if Default_Identity_Candidate_Exists then
            return Ok;
         end if;
      end if;

      if Authentication_Method_Enabled (Options, "keyboard-interactive")
        and then Options.Number_Of_Password_Prompts > 0
        and then
          (Options.Keyboard_Interactive_Callback /= null
           or else
             (Options.Use_Password
              and then
                (Password_Text'Length > 0
                 or else Options.Password_Callback /= null)))
      then
         return Ok;
      end if;

      if Authentication_Method_Enabled (Options, "password")
        and then Options.Number_Of_Password_Prompts > 0
        and then Options.Use_Password
        and then
          (Password_Text'Length > 0 or else Options.Password_Callback /= null)
      then
         return Ok;
      end if;

      return Authentication_Failed;
   exception
      when others =>
         return Internal_Error;
   end Authentication_Configuration_Preflight;

   function Immediate_Timeout_Preflight
     (Options : Session_Options) return Status is
   begin
      --  Timeout_MS = 0 means an immediate operation deadline, not invalid
      --  options.  Keep syntactic validation and authentication-method
      --  preflight decisive first, then model the first public Open operation
      --  that would be unable to make progress in this scaffold.
      if Options.Connect_Timeout_MS = 0 then
         return Timeout;
      elsif Options.Write_Timeout_MS = 0 then
         --  The first transport write would be the client identification.
         return Timeout;
      elsif Options.Read_Timeout_MS = 0 then
         --  The first transport read would be the server identification.
         return Timeout;
      else
         return Ok;
      end if;
   exception
      when others =>
         return Internal_Error;
   end Immediate_Timeout_Preflight;

end SSH_Lib.Sessions.Open_Pipeline;
