with CryptoLib.Hybrid_PQ_Kex;
with CryptoLib.UMAC;

package body SSH_Lib.Algorithms is
   use Ada.Strings.Unbounded;

   function Is_Valid_Algorithm_Name (Name_Text : String) return Boolean is
   begin
      if Name_Text'Length = 0 then
         return False;
      end if;

      for Character_Value of Name_Text loop
         if Character_Value <= Character'Val (32)
           or else Character_Value = Character'Val (127)
           or else Character'Pos (Character_Value) > 126
           or else Character_Value = ','
         then
            return False;
         end if;
      end loop;

      return True;
   end Is_Valid_Algorithm_Name;

   function Support_For
     (Class_Item : Algorithm_Class;
      Name_Text  : String)
      return Support_Status
   is
   begin
      if not Is_Valid_Algorithm_Name (Name_Text) then
         return Unsupported;
      end if;

      case Class_Item is
         when Key_Exchange =>
            if CryptoLib.Hybrid_PQ_Kex.Is_Implemented (Name_Text) then
               return Available;
            elsif Name_Text = "curve25519-sha256"
              or else Name_Text = "curve25519-sha256@libssh.org"
              or else Name_Text = "ecdh-sha2-nistp256"
              or else Name_Text = "ecdh-sha2-nistp384"
              or else Name_Text = "ecdh-sha2-nistp521"
              or else Name_Text = "diffie-hellman-group18-sha512"
              or else Name_Text = "diffie-hellman-group16-sha512"
              or else Name_Text = "diffie-hellman-group14-sha256"
              or else Name_Text = "diffie-hellman-group-exchange-sha256"
              or else Name_Text = "diffie-hellman-group-exchange-sha1"
              or else Name_Text = "diffie-hellman-group14-sha1"
              or else Name_Text = "diffie-hellman-group1-sha1"
            then
               return Available;
            elsif Name_Text = "ext-info-c"
              or else Name_Text = "kex-strict-c-v00@openssh.com"
            then
               --  Extension/negotiation markers (RFC 8308 ext-info-c and the
               --  Terrapin strict-kex marker).  They are advertised in the KEX
               --  name-list but are not real key-exchange algorithms and must
               --  never be selected as the negotiated KEX.
               return Extension_Only;
            end if;
            return Unsupported;
         when Server_Host_Key =>
            if Name_Text = "ssh-ed25519-cert-v01@openssh.com"
              or else Name_Text = "ecdsa-sha2-nistp256-cert-v01@openssh.com"
              or else Name_Text = "ecdsa-sha2-nistp384-cert-v01@openssh.com"
              or else Name_Text = "ecdsa-sha2-nistp521-cert-v01@openssh.com"
              or else Name_Text = "rsa-sha2-512-cert-v01@openssh.com"
              or else Name_Text = "rsa-sha2-256-cert-v01@openssh.com"
              or else Name_Text = "ssh-rsa-cert-v01@openssh.com"
              or else Name_Text = "sk-ssh-ed25519-cert-v01@openssh.com"
              or else Name_Text = "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com"
              or else Name_Text = "ssh-ed25519"
              or else Name_Text = "ecdsa-sha2-nistp256"
              or else Name_Text = "ecdsa-sha2-nistp384"
              or else Name_Text = "ecdsa-sha2-nistp521"
              or else Name_Text = "sk-ssh-ed25519@openssh.com"
              or else Name_Text = "sk-ecdsa-sha2-nistp256@openssh.com"
              or else Name_Text = "rsa-sha2-512"
              or else Name_Text = "rsa-sha2-256"
              or else Name_Text = "ssh-rsa"
            then
               return Available;
            end if;
            return Unsupported;
         when Encryption_Client_To_Server | Encryption_Server_To_Client =>
            if Name_Text = "chacha20-poly1305@openssh.com"
              or else Name_Text = "aes256-gcm@openssh.com"
              or else Name_Text = "aes128-gcm@openssh.com"
              or else Name_Text = "aes256-ctr"
              or else Name_Text = "aes192-ctr"
              or else Name_Text = "aes128-ctr"
              or else Name_Text = "aes256-cbc"
              or else Name_Text = "aes192-cbc"
              or else Name_Text = "aes128-cbc"
              or else Name_Text = "3des-cbc"
            then
               return Available;
            end if;
            return Unsupported;
         when Mac_Client_To_Server | Mac_Server_To_Client =>
            if CryptoLib.UMAC.Is_OpenSSH_UMAC_Name (Name_Text) then
               return Available;
            elsif Name_Text = "hmac-sha2-512-etm@openssh.com"
              or else Name_Text = "hmac-sha2-256-etm@openssh.com"
              or else Name_Text = "hmac-sha2-512"
              or else Name_Text = "hmac-sha2-256"
              or else Name_Text = "hmac-sha1-etm@openssh.com"
              or else Name_Text = "hmac-sha1"
              or else Name_Text = "hmac-sha1-96-etm@openssh.com"
              or else Name_Text = "hmac-sha1-96"
              or else Name_Text = "hmac-md5-etm@openssh.com"
              or else Name_Text = "hmac-md5"
              or else Name_Text = "hmac-md5-96-etm@openssh.com"
              or else Name_Text = "hmac-md5-96"
            then
               return Available;
            end if;
            return Unsupported;
         when Compression_Client_To_Server | Compression_Server_To_Client =>
            if Name_Text = "none"
              or else Name_Text = "zlib"
              or else Name_Text = "zlib@openssh.com"
            then
               return Available;
            end if;
            return Unsupported;
      end case;
   end Support_For;

   function Is_Supported
     (Class_Item : Algorithm_Class;
      Name_Text  : String)
      return Boolean
   is
   begin
      return Support_For (Class_Item, Name_Text) = Available;
   end Is_Supported;

   function Advertised_Name_List
     (Class_Item : Algorithm_Class)
      return String
   is
   begin
      case Class_Item is
         when Key_Exchange =>
            return "mlkem768x25519-sha256,mlkem768x25519-sha512,sntrup761x25519-sha512@openssh.com"
                     & ",sntrup761x25519-sha512,curve25519-sha256,curve25519-sha256@libssh.org"
                     & ",ecdh-sha2-nistp256,ecdh-sha2-nistp384"
                     & ",ecdh-sha2-nistp521"
                     & ",diffie-hellman-group18-sha512,diffie-hellman-group16-sha512"
                     & ",diffie-hellman-group14-sha256,diffie-hellman-group-exchange-sha256"
                     & ",diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha1"
                     & ",ext-info-c"
                     & ",kex-strict-c-v00@openssh.com";
         when Server_Host_Key =>
            return "ssh-ed25519-cert-v01@openssh.com,ecdsa-sha2-nistp256-cert-v01@openssh.com"
                     & ",ecdsa-sha2-nistp384-cert-v01@openssh.com"
                     & ",ecdsa-sha2-nistp521-cert-v01@openssh.com"
                     & ",rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com"
                     & ",ssh-rsa-cert-v01@openssh.com,sk-ssh-ed25519-cert-v01@openssh.com"
                     & ",sk-ecdsa-sha2-nistp256-cert-v01@openssh.com,ssh-ed25519"
                     & ",ecdsa-sha2-nistp256,ecdsa-sha2-nistp384"
                     & ",ecdsa-sha2-nistp521,rsa-sha2-512"
                     & ",rsa-sha2-256,sk-ssh-ed25519@openssh.com,sk-ecdsa-sha2-nistp256@openssh.com,ssh-rsa";
         when Encryption_Client_To_Server | Encryption_Server_To_Client =>
            --  Security guard baseline with legacy CBC fallback.  3des-cbc is
            --  no longer offered by default (still recognized if configured).
            return "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com"
                     & ",aes256-ctr,aes192-ctr,aes128-ctr,aes256-cbc,aes192-cbc,aes128-cbc";
         when Mac_Client_To_Server | Mac_Server_To_Client =>
            --  UMAC (umac-64/128@openssh.com) is real RFC 4418 UMAC (KAT-verified
            --  against the RFC test vectors and interoperable with OpenSSH); it
            --  is preferred, then the Encrypt-then-MAC and plain HMAC fallbacks.
            --  MD5-based MACs (hmac-md5*) are no longer offered by default
            --  (MD5 is broken); still recognized if explicitly configured.
            return "umac-128-etm@openssh.com,umac-64-etm@openssh.com,umac-128@openssh.com"
                     & ",umac-64@openssh.com,hmac-sha2-512-etm@openssh.com"
                     & ",hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256"
                     & ",hmac-sha1-etm@openssh.com,hmac-sha1,hmac-sha1-96-etm@openssh.com,hmac-sha1-96";
         when Compression_Client_To_Server | Compression_Server_To_Client =>
            --  Match the OpenSSH client default: offer "none" first. SSH-level
            --  compression adds little for a VCS client (Git objects are already
            --  deflated) and this keeps the negotiated algorithm at "none"
            --  unless the peer/user explicitly requests compression.
            return "none,zlib@openssh.com,zlib";
      end case;
   end Advertised_Name_List;

   function Contains_Name
     (List_Text : String;
      Name_Text : String)
      return Boolean
   is
      Start_Index : Positive := List_Text'First;
      Stop_Index  : Natural;
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

         if List_Text (Start_Index .. Stop_Index - 1) = Name_Text then
            return True;
         end if;

         exit when Stop_Index > List_Text'Last;
         Start_Index := Stop_Index + 1;
      end loop;

      return False;
   end Contains_Name;

   function Validate_Name_List (List_Text : String) return Boolean is
      Start_Index : Positive := List_Text'First;
      Stop_Index  : Natural;
   begin
      if List_Text'Length = 0 then
         return True;
      end if;

      loop
         Stop_Index := Start_Index;
         while Stop_Index <= List_Text'Last
           and then List_Text (Stop_Index) /= ','
         loop
            Stop_Index := Stop_Index + 1;
         end loop;

         if Stop_Index = Start_Index then
            return False;
         end if;

         if not Is_Valid_Algorithm_Name (List_Text (Start_Index .. Stop_Index - 1)) then
            return False;
         end if;

         declare
            Candidate : constant String := List_Text (Start_Index .. Stop_Index - 1);
            Scan_Start : Positive := List_Text'First;
            Scan_Stop  : Natural;
         begin
            while Scan_Start < Start_Index loop
               Scan_Stop := Scan_Start;
               while Scan_Stop <= List_Text'Last
                 and then List_Text (Scan_Stop) /= ','
               loop
                  Scan_Stop := Scan_Stop + 1;
               end loop;

               if List_Text (Scan_Start .. Scan_Stop - 1) = Candidate then
                  return False;
               end if;

               exit when Scan_Stop > List_Text'Last;
               Scan_Start := Scan_Stop + 1;
            end loop;
         end;

         exit when Stop_Index > List_Text'Last;
         Start_Index := Stop_Index + 1;
      end loop;

      return True;
   end Validate_Name_List;

   function Select_Algorithm
     (Class_Item        : Algorithm_Class;
      Local_Preferences : String;
      Remote_Offered    : String;
      Result_Name       : out Unbounded_String)
      return CryptoLib.Errors.Status
   is
      Start_Index : Positive := Local_Preferences'First;
      Stop_Index  : Natural;
   begin
      Result_Name := Null_Unbounded_String;

      if Local_Preferences'Length = 0 or else Remote_Offered'Length = 0 then
         return CryptoLib.Errors.Unsupported_Feature;
      end if;

      if not Validate_Name_List (Local_Preferences)
        or else not Validate_Name_List (Remote_Offered)
      then
         return CryptoLib.Errors.Handshake_Failed;
      end if;

      loop
         Stop_Index := Start_Index;
         while Stop_Index <= Local_Preferences'Last
           and then Local_Preferences (Stop_Index) /= ','
         loop
            Stop_Index := Stop_Index + 1;
         end loop;

         declare
            Candidate : constant String := Local_Preferences (Start_Index .. Stop_Index - 1);
         begin
            if Is_Supported (Class_Item, Candidate)
              and then Contains_Name (Remote_Offered, Candidate)
            then
               Result_Name := To_Unbounded_String (Candidate);
               return CryptoLib.Errors.Ok;
            end if;
         end;

         exit when Stop_Index > Local_Preferences'Last;
         Start_Index := Stop_Index + 1;
      end loop;

      return CryptoLib.Errors.Unsupported_Feature;
   end Select_Algorithm;
end SSH_Lib.Algorithms;
