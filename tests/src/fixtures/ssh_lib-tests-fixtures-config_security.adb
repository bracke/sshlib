with Ada.Directories;
with Ada.Strings.Unbounded;
with Ada.Text_IO;
with Ada.Strings.Fixed;
with SSH_Lib.Config;
with SSH_Lib.Platform.Environment;
with CryptoLib.Errors;
with SSH_Lib.Remote_Names;
with SSH_Lib.Sessions;
with SSH_Lib.Tests.Assertions;
with SSH_Lib.Tests.Fixtures.Temp_Paths;

package body SSH_Lib.Tests.Fixtures.Config_Security is

   use Ada.Strings.Unbounded;
   use type CryptoLib.Errors.Status;

   procedure Check (Condition : Boolean; Label_Text : String) is
   begin
      if not Condition then
         Ada.Text_IO.Put_Line ("FAILED: " & Label_Text);
         raise Program_Error;
      end if;
   end Check;

   procedure Remove_If_Exists (Path : String) is
   begin
      if Ada.Directories.Exists (Path) then
         Ada.Directories.Delete_File (Path);
      end if;
   exception
      when others =>
         null;
   end Remove_If_Exists;

   procedure Write_Config
     (Path         : String;
      Proxy_Marker : String;
      Jump_Marker  : String)
   is
      Output_File : Ada.Text_IO.File_Type;
   begin
      Remove_If_Exists (Path);
      Ada.Text_IO.Create (Output_File, Ada.Text_IO.Out_File, Path);
      Ada.Text_IO.Put_Line (Output_File, "Host secure-alias");
      Ada.Text_IO.Put_Line (Output_File, "  HostName secure.example.com");
      Ada.Text_IO.Put_Line (Output_File, "  User configuser");
      Ada.Text_IO.Put_Line (Output_File, "  Port 2222");
      Ada.Text_IO.Put_Line (Output_File, "  IdentityFile $HOME/not-expanded");
      Ada.Text_IO.Put_Line (Output_File, "  CertificateFile $HOME/not-expanded-cert.pub");
      Ada.Text_IO.Put_Line (Output_File, "  StrictHostKeyChecking no");
      Ada.Text_IO.Put_Line (Output_File, "  VerifyKnownHost no");
      Ada.Text_IO.Put_Line (Output_File, "  UserKnownHostsFile /dev/null");
      Ada.Text_IO.Put_Line (Output_File, "  ProxyCommand proxy-tool --write-marker " & Proxy_Marker);
      Ada.Text_IO.Put_Line (Output_File, "  ProxyJump `touch " & Jump_Marker & "`");
      Ada.Text_IO.Put_Line (Output_File, "Host proxycommand-none");
      Ada.Text_IO.Put_Line (Output_File, "  HostName direct.example.com");
      Ada.Text_IO.Put_Line (Output_File, "  ProxyCommand none");
      Ada.Text_IO.Put_Line (Output_File, "Host shell-identity");
      Ada.Text_IO.Put_Line (Output_File, "  IdentityFile `command-substitution`");
      Ada.Text_IO.Put_Line (Output_File, "Host shell-certificate");
      Ada.Text_IO.Put_Line (Output_File, "  IdentityFile ~/id_ed25519");
      Ada.Text_IO.Put_Line (Output_File, "  CertificateFile `certificate-command-substitution`");
      Ada.Text_IO.Put_Line (Output_File, "Host variable-identity");
      Ada.Text_IO.Put_Line (Output_File, "  IdentityFile $HOME/not-expanded");
      Ada.Text_IO.Put_Line (Output_File, "Host home-identity");
      Ada.Text_IO.Put_Line (Output_File, "  IdentityFile ~/id_ed25519");
      Ada.Text_IO.Put_Line (Output_File, "Host canonical-always");
      Ada.Text_IO.Put_Line (Output_File, "  CanonicalizeHostname always");
      Ada.Text_IO.Put_Line (Output_File, "Host algorithm-modifiers");
      Ada.Text_IO.Put_Line (Output_File, "  HostKeyAlgorithms +ecdsa-sha2-nistp256");
      Ada.Text_IO.Put_Line (Output_File, "  KexAlgorithms ^ecdh-sha2-nistp256");
      Ada.Text_IO.Put_Line (Output_File, "  MACs -hmac-sha1");
      Ada.Text_IO.Put_Line (Output_File, "  Compression +zlib");
      Ada.Text_IO.Put_Line (Output_File, "Host pubkey-modifiers");
      Ada.Text_IO.Put_Line (Output_File, "  PubkeyAcceptedAlgorithms ^sk-ssh-ed25519@openssh.com");
      Ada.Text_IO.Put_Line (Output_File, "Host pubkey-sk-cert-defaults");
      Ada.Text_IO.Put_Line (Output_File, "  PubkeyAcceptedAlgorithms -sk-ssh-ed25519@openssh.com"
                                           & ",sk-ecdsa-sha2-nistp256@openssh.com");
      Ada.Text_IO.Put_Line (Output_File, "Match originalhost original-match");
      Ada.Text_IO.Put_Line (Output_File, "  HostName matched-original.example.com");
      Ada.Text_IO.Put_Line (Output_File, "Host !negated-only");
      Ada.Text_IO.Put_Line (Output_File, "  HostName must-not-match.example.com");
      Ada.Text_IO.Close (Output_File);
   exception
      when others =>
         if Ada.Text_IO.Is_Open (Output_File) then
            Ada.Text_IO.Close (Output_File);
         end if;
         raise;
   end Write_Config;

   procedure Assert_No_Marker (Path : String; Label_Text : String) is
   begin
      Check (not Ada.Directories.Exists (Path), Label_Text);
   end Assert_No_Marker;

   procedure Assert_Config_Is_Data_Only is
      Config_Path : constant String :=
        SSH_Lib.Tests.Fixtures.Temp_Paths.Path ("phase19_config_security_config");
      Proxy_Marker : constant String :=
        SSH_Lib.Tests.Fixtures.Temp_Paths.Path ("phase19_proxy_command_ran");
      Jump_Marker : constant String :=
        SSH_Lib.Tests.Fixtures.Temp_Paths.Path ("phase19_proxy_jump_ran");
      Identity_Marker : constant String :=
        SSH_Lib.Tests.Fixtures.Temp_Paths.Path ("phase19_identity_command_ran");
      Home_Path : constant String :=
        SSH_Lib.Tests.Fixtures.Temp_Paths.Path ("phase19_config_home");
      Config_Item : SSH_Lib.Config.Host_Config;
      Options : SSH_Lib.Sessions.Session_Options;
      Remote_Item : SSH_Lib.Remote_Names.Parsed_Remote;
      Status_Value : CryptoLib.Errors.Status;
   begin
      Remove_If_Exists (Proxy_Marker);
      Remove_If_Exists (Jump_Marker);
      Remove_If_Exists (Identity_Marker);
      SSH_Lib.Platform.Environment.Set_Value_For_Test ("HOME", Home_Path);
      Write_Config (Config_Path, Proxy_Marker, Jump_Marker);

      Status_Value := SSH_Lib.Config.Load (Config_Path, Config_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "config security", "config with command-like data loads as data");
      Assert_No_Marker (Proxy_Marker, "ProxyCommand is not executed during Load");
      Assert_No_Marker (Jump_Marker, "ProxyJump is not executed during Load");
      Assert_No_Marker (Identity_Marker, "IdentityFile command substitution is not executed during Load");

      Status_Value := SSH_Lib.Config.Resolve (Config_Item, "secure-alias", Options);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "config security", "direct Resolve ignores unsupported proxy execution text");
      Check (To_String (Options.Host) = "secure.example.com",
             "HostName changes connection target only");
      Check (To_String (Options.User) = "configuser",
             "config User still resolves as data");
      Check (Options.Port = 2222,
             "config Port still resolves as data");
      Check (Options.Verify_Known_Host,
             "config cannot disable Verify_Known_Host");
      Check (Options.Strict_Host_Key,
             "config cannot disable Strict_Host_Key");
      Check (To_String (Options.Identity_File) = "$HOME/not-expanded",
             "IdentityFile $HOME is not shell-expanded");
      Check (To_String (Options.Certificate_File) = "$HOME/not-expanded-cert.pub",
             "CertificateFile $HOME is not shell-expanded");
      Assert_No_Marker (Proxy_Marker, "ProxyCommand is not executed during Resolve");
      Assert_No_Marker (Jump_Marker, "ProxyJump is not executed during Resolve");

      Status_Value := SSH_Lib.Config.Resolve (Config_Item, "proxycommand-none", Options);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "config security", "ProxyCommand none resolves as no proxy command");
      Check (To_String (Options.Host) = "direct.example.com",
             "ProxyCommand none host still resolves normally");
      Check (To_String (Options.Proxy_Command)'Length = 0,
             "ProxyCommand none disables ProxyCommand instead of executing none");

      Status_Value := SSH_Lib.Config.Resolve (Config_Item, "shell-identity", Options);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "config security", "IdentityFile backtick text resolves as literal data");
      Check (To_String (Options.Identity_File) = "`command-substitution`",
             "IdentityFile backtick command is preserved literally");
      Assert_No_Marker (Identity_Marker, "IdentityFile backtick text is not executed during Resolve");

      Status_Value := SSH_Lib.Config.Resolve (Config_Item, "shell-certificate", Options);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "config security", "CertificateFile backtick text resolves as literal data");
      Check (To_String (Options.Certificate_File) = "`certificate-command-substitution`",
             "CertificateFile backtick command is preserved literally");
      Assert_No_Marker (Identity_Marker, "CertificateFile backtick text is not executed during Resolve");

      Status_Value := SSH_Lib.Config.Resolve (Config_Item, "variable-identity", Options);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "config security", "IdentityFile variable text resolves as literal data");
      Check (To_String (Options.Identity_File) = "$HOME/not-expanded",
             "IdentityFile variable syntax is not expanded");

      Status_Value := SSH_Lib.Config.Resolve (Config_Item, "home-identity", Options);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "config security", "IdentityFile tilde expansion remains explicit path handling");
      Check (To_String (Options.Identity_File) = Home_Path & "/id_ed25519",
             "only leading tilde path expansion is applied");

      Status_Value := SSH_Lib.Config.Resolve (Config_Item, "canonical-always", Options);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "config security", "CanonicalizeHostname always resolves as supported policy");
      Check (Options.Canonicalize_Hostname,
             "CanonicalizeHostname always maps to enabled canonicalization policy");

      Status_Value := SSH_Lib.Config.Resolve (Config_Item, "algorithm-modifiers", Options);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "config security", "OpenSSH algorithm list modifiers resolve");
      Check (To_String (Options.Host_Key_Algorithms)'Length > 0,
             "HostKeyAlgorithms +modifier is accepted");
      Check (To_String (Options.Kex_Algorithms)'Length > 0,
             "KexAlgorithms ^modifier is accepted");
      Check (To_String (Options.Mac_Algorithms)'Length > 0,
             "MACs -modifier is accepted");
      Check (To_String (Options.Compression_Algorithms)'Length > 0,
             "Compression +modifier is accepted");

      Status_Value := SSH_Lib.Config.Resolve (Config_Item, "pubkey-modifiers", Options);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "config security", "PubkeyAcceptedAlgorithms modifier resolves");
      Check (To_String (Options.Pubkey_Accepted_Algorithms)'Length > 0,
             "PubkeyAcceptedAlgorithms ^modifier is expanded to a concrete name-list");
      Check (To_String (Options.Pubkey_Accepted_Algorithms)
               (To_String (Options.Pubkey_Accepted_Algorithms)'First
                .. To_String (Options.Pubkey_Accepted_Algorithms)'First + 25)
             = "sk-ssh-ed25519@openssh.com",
             "PubkeyAcceptedAlgorithms ^modifier prepends the requested algorithm");

      Status_Value := SSH_Lib.Config.Resolve (Config_Item, "pubkey-sk-cert-defaults", Options);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "config security", "PubkeyAcceptedAlgorithms -modifier keeps userauth SK cert defaults");
      Check (Ada.Strings.Fixed.Index
               (To_String (Options.Pubkey_Accepted_Algorithms),
                "sk-ssh-ed25519-cert-v01@openssh.com") /= 0,
             "PubkeyAcceptedAlgorithms default list keeps SK Ed25519 certificate userauth algorithm");
      Check (Ada.Strings.Fixed.Index
               (To_String (Options.Pubkey_Accepted_Algorithms),
                "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com") /= 0,
             "PubkeyAcceptedAlgorithms default list keeps SK ECDSA certificate userauth algorithm");
      Check (Ada.Strings.Fixed.Index
               (To_String (Options.Pubkey_Accepted_Algorithms),
                "ecdsa-sha2-nistp384-cert-v01@openssh.com") /= 0,
             "PubkeyAcceptedAlgorithms default list keeps ECDSA P-384 certificate userauth algorithm");
      Check (Ada.Strings.Fixed.Index
               (To_String (Options.Pubkey_Accepted_Algorithms),
                "ecdsa-sha2-nistp521-cert-v01@openssh.com") /= 0,
             "PubkeyAcceptedAlgorithms default list keeps ECDSA P-521 certificate userauth algorithm");
      Check (Ada.Strings.Fixed.Index
               (To_String (Options.Pubkey_Accepted_Algorithms),
                "sk-ssh-ed25519@openssh.com") = 0,
             "PubkeyAcceptedAlgorithms -modifier removes raw SK Ed25519 userauth algorithm");
      Check (Ada.Strings.Fixed.Index
               (To_String (Options.Pubkey_Accepted_Algorithms),
                "sk-ecdsa-sha2-nistp256@openssh.com") = 0,
             "PubkeyAcceptedAlgorithms -modifier removes raw SK ECDSA userauth algorithm");

      Status_Value := SSH_Lib.Config.Resolve (Config_Item, "original-match", Options);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "config security", "Match originalhost resolves against original query name");
      Check (To_String (Options.Host) = "matched-original.example.com",
             "Match originalhost can safely retarget through HostName");

      Status_Value := SSH_Lib.Config.Resolve (Config_Item, "negated-only", Options);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "config security", "negated-only Host pattern does not create positive match");
      Check (To_String (Options.Host) = "negated-only",
             "negated-only Host block cannot retarget host");

      Check (not SSH_Lib.Config.Has_Unsupported_Feature (Config_Item, "secure-alias"),
             "ProxyCommand is supported while ProxyJump remains data-only");
      Assert_No_Marker (Proxy_Marker, "Has_Unsupported_Feature does not execute ProxyCommand");
      Assert_No_Marker (Jump_Marker, "Has_Unsupported_Feature does not execute ProxyJump");

      Status_Value := SSH_Lib.Remote_Names.Parse
        ("ssh://remoteuser@secure-alias:2200/repo.git", Remote_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "config security", "remote parse for config security");
      Status_Value := SSH_Lib.Config.Resolve_Remote
        (Config_Item, "ssh://remoteuser@secure-alias:2200/repo.git", "fallback", Options);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "config security", "Resolve_Remote preserves ProxyCommand without executing");
      Check (To_String (Options.Host) = "secure.example.com",
             "Resolve_Remote applies HostName while preserving repository path");
      Check (To_String (Options.Proxy_Command)'Length > 0,
             "Resolve_Remote carries ProxyCommand into session options");
      Check (SSH_Lib.Remote_Names.Repository_Path (Remote_Item) = "repo.git",
             "HostName cannot alter repository path");
      Assert_No_Marker (Proxy_Marker, "Resolve_Remote does not execute ProxyCommand");
      Assert_No_Marker (Jump_Marker, "Resolve_Remote does not execute ProxyJump");

      SSH_Lib.Platform.Environment.Reset_Provider;
      Remove_If_Exists (Config_Path);
      Remove_If_Exists (Proxy_Marker);
      Remove_If_Exists (Jump_Marker);
      Remove_If_Exists (Identity_Marker);
   exception
      when others =>
         SSH_Lib.Platform.Environment.Reset_Provider;
         Remove_If_Exists (Config_Path);
         Remove_If_Exists (Proxy_Marker);
         Remove_If_Exists (Jump_Marker);
         Remove_If_Exists (Identity_Marker);
         raise;
   end Assert_Config_Is_Data_Only;
end SSH_Lib.Tests.Fixtures.Config_Security;
