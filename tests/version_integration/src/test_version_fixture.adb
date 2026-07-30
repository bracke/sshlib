with Ada.Directories;
with Ada.Strings.Unbounded;
with Ada.Text_IO;
with Hostkit.Fs;
with SSH_Lib.Config;
with CryptoLib.Errors;
with SSH_Lib.Git_Transport;
with SSH_Lib.Remote_Names;
with SSH_Lib.Sessions;

procedure Test_Version_Fixture is
   use Ada.Strings.Unbounded;
   use type CryptoLib.Errors.Status;

   --  Under the host's temporary directory, not the working one. These
   --  names used to be relative, so they were written wherever the test
   --  happened to be started from -- a run launched from a sibling crate
   --  left six of them in that crate's repository root, where sshlib's
   --  .gitignore does not reach.
   Config_Path       : constant String :=
     Ada.Directories.Compose
       (Hostkit.Fs.Temp_Directory, "version_integration_config.tmp");
   Empty_Config_Path : constant String :=
     Ada.Directories.Compose
       (Hostkit.Fs.Temp_Directory, "version_integration_empty_config.tmp");
   Proxy_Command_Config_Path : constant String :=
     Ada.Directories.Compose
       (Hostkit.Fs.Temp_Directory, "version_integration_proxy_command_config.tmp");
   Port_Config_Path  : constant String :=
     Ada.Directories.Compose
       (Hostkit.Fs.Temp_Directory, "version_integration_port_config.tmp");
   File_Item         : Ada.Text_IO.File_Type;
   Config_Item       : SSH_Lib.Config.Host_Config;
   Empty_Config      : SSH_Lib.Config.Host_Config;
   Proxy_Command_Config : SSH_Lib.Config.Host_Config;
   Port_Config        : SSH_Lib.Config.Host_Config;
   Options_Item : SSH_Lib.Sessions.Session_Options;
   Command_Item : Unbounded_String;
   Status_Value : CryptoLib.Errors.Status;
   Remote_Item  : SSH_Lib.Remote_Names.Parsed_Remote;

   procedure Check (Condition_Value : Boolean; Message_Text : String) is
   begin
      if not Condition_Value then
         raise Program_Error with Message_Text;
      end if;
   end Check;

   procedure Write_Config is
   begin
      Ada.Text_IO.Create (File_Item, Ada.Text_IO.Out_File, Config_Path);
      Ada.Text_IO.Put_Line (File_Item, "Host gh");
      Ada.Text_IO.Put_Line (File_Item, "  HostName github.com");
      Ada.Text_IO.Put_Line (File_Item, "  User git");
      Ada.Text_IO.Put_Line (File_Item, "  Port 22");
      Ada.Text_IO.Put_Line (File_Item, "  IdentityFile ~/.ssh/id_ed25519");
      Ada.Text_IO.Close (File_Item);

      Ada.Text_IO.Create (File_Item, Ada.Text_IO.Out_File, Empty_Config_Path);
      Ada.Text_IO.Close (File_Item);

      Ada.Text_IO.Create (File_Item, Ada.Text_IO.Out_File, Proxy_Command_Config_Path);
      Ada.Text_IO.Put_Line (File_Item, "Host gh");
      Ada.Text_IO.Put_Line (File_Item, "  ProxyCommand ssh bastion nc %h %p");
      Ada.Text_IO.Close (File_Item);

      Ada.Text_IO.Create (File_Item, Ada.Text_IO.Out_File, Port_Config_Path);
      Ada.Text_IO.Put_Line (File_Item, "Host gh");
      Ada.Text_IO.Put_Line (File_Item, "  HostName github.com");
      Ada.Text_IO.Put_Line (File_Item, "  User git");
      Ada.Text_IO.Put_Line (File_Item, "  Port 2222");
      Ada.Text_IO.Close (File_Item);
   end Write_Config;
begin
   Write_Config;
   Status_Value := SSH_Lib.Config.Load (Config_Path, Config_Item);
   Check (Status_Value = CryptoLib.Errors.Ok, "config load failed");
   Status_Value := SSH_Lib.Config.Load (Empty_Config_Path, Empty_Config);
   Check (Status_Value = CryptoLib.Errors.Ok, "empty config load failed");
   Status_Value := SSH_Lib.Config.Load (Proxy_Command_Config_Path, Proxy_Command_Config);
   Check (Status_Value = CryptoLib.Errors.Ok, "unsupported config load failed");
   Status_Value := SSH_Lib.Config.Load (Port_Config_Path, Port_Config);
   Check (Status_Value = CryptoLib.Errors.Ok, "port config load failed");

   Check (not SSH_Lib.Remote_Names.Has_Explicit_Port ("ssh://gh/repo.git"),
          "implicit ssh port was reported explicit");
   Check (SSH_Lib.Remote_Names.Has_Explicit_Port ("ssh://gh:22/repo.git"),
          "explicit ssh port 22 was not detected");

   Status_Value := SSH_Lib.Config.Resolve_Remote
     (Config       => Port_Config,
      Remote_Text  => "ssh://gh/repo.git",
      Default_User => "git",
      Item         => Options_Item);
   Check (Status_Value = CryptoLib.Errors.Ok, "text remote resolve failed");
   Check (Options_Item.Port = 2222,
          "implicit remote port should inherit config port");

   Status_Value := SSH_Lib.Config.Resolve_Remote
     (Config       => Port_Config,
      Remote_Text  => "ssh://gh:22/repo.git",
      Default_User => "git",
      Item         => Options_Item);
   Check (Status_Value = CryptoLib.Errors.Ok,
          "text remote resolve with explicit port 22 failed");
   Check (Options_Item.Port = 22,
          "explicit remote port 22 should override config port");

   Status_Value := SSH_Lib.Remote_Names.Parse ("gh:repo.git", Remote_Item);
   Check (Status_Value = CryptoLib.Errors.Ok, "parsed remote for no-user check failed");
   Status_Value := SSH_Lib.Config.Resolve_Remote
     (Config => Empty_Config,
      Remote => Remote_Item,
      Item   => Options_Item);
   Check (Status_Value = CryptoLib.Errors.Invalid_User,
          "parsed remote resolve without user should be Invalid_User");

   Status_Value := SSH_Lib.Remote_Names.Parse ("git@gh:repo.git", Remote_Item);
   Check (Status_Value = CryptoLib.Errors.Ok,
          "parsed remote for ProxyCommand config check failed");

   --  This asked for Unsupported_Feature until the library grew a
   --  ProxyCommand: Resolve carries the command into the options and
   --  open_runtime connects through it, and Has_Unsupported_Feature is
   --  documented as always False because nothing the parser accepts is
   --  unhonoured now. So the config resolves.
   Status_Value := SSH_Lib.Config.Resolve_Remote
     (Config => Proxy_Command_Config,
      Remote => Remote_Item,
      Item   => Options_Item);
   Check (Status_Value = CryptoLib.Errors.Ok,
          "parsed remote resolve rejected a ProxyCommand the library honours");

   Status_Value := SSH_Lib.Git_Transport.Prepare
     (Remote_Text  => "git@gh:repo.git",
      Config       => Config_Item,
      Default_User => "",
      Requested    => SSH_Lib.Git_Transport.Upload_Pack,
      Options      => Options_Item,
      Command      => Command_Item);
   Check (Status_Value = CryptoLib.Errors.Ok, "prepare alias failed");
   Check (To_String (Options_Item.Host) = "github.com", "HostName merge failed");
   Check (To_String (Options_Item.User) = "git", "user merge failed");
   Check (To_String (Command_Item) = "git-upload-pack 'repo.git'", "upload command failed");
   Check (Length (Options_Item.Identity_File) /= 0, "identity file missing");
   Check (Options_Item.Verify_Known_Host, "host-key verification disabled");
   Check (Options_Item.Strict_Host_Key, "strict host-key disabled");

   Status_Value := SSH_Lib.Git_Transport.Prepare
     (Remote_Text  => "ssh://alice@gh/repo.git",
      Config       => Config_Item,
      Default_User => "git",
      Requested    => SSH_Lib.Git_Transport.Upload_Pack,
      Options      => Options_Item,
      Command      => Command_Item);
   Check (Status_Value = CryptoLib.Errors.Ok, "explicit user prepare failed");
   Check (To_String (Options_Item.User) = "alice", "explicit user override failed");

   Status_Value := SSH_Lib.Git_Transport.Prepare
     (Remote_Text  => "ssh://alice@gh/repo.git",
      Config       => Empty_Config,
      Default_User => "invalid:user",
      Requested    => SSH_Lib.Git_Transport.Upload_Pack,
      Options      => Options_Item,
      Command      => Command_Item);
   Check (Status_Value = CryptoLib.Errors.Ok,
          "explicit user should not depend on invalid default user");
   Check (To_String (Options_Item.User) = "alice",
          "explicit user should remain authoritative over default user");

   Status_Value := SSH_Lib.Git_Transport.Prepare
     (Remote_Text  => "ssh://gh:2222/repo.git",
      Config       => Config_Item,
      Default_User => "git",
      Requested    => SSH_Lib.Git_Transport.Upload_Pack,
      Options      => Options_Item,
      Command      => Command_Item);
   Check (Status_Value = CryptoLib.Errors.Ok, "explicit port prepare failed");
   Check (Options_Item.Port = 2222, "explicit port override failed");

   Status_Value := SSH_Lib.Git_Transport.Prepare
     (Remote_Text  => "ssh://gh:22/repo.git",
      Config       => Config_Item,
      Default_User => "git",
      Requested    => SSH_Lib.Git_Transport.Upload_Pack,
      Options      => Options_Item,
      Command      => Command_Item);
   Check (Status_Value = CryptoLib.Errors.Ok, "explicit port 22 prepare failed");
   Check (Options_Item.Port = 22, "explicit port 22 did not override config");

   Status_Value := SSH_Lib.Git_Transport.Prepare
     (Remote_Text  => "gh:repo.git",
      Config       => Config_Item,
      Default_User => "git",
      Requested    => SSH_Lib.Git_Transport.Receive_Pack,
      Options      => Options_Item,
      Command      => Command_Item);
   Check (Status_Value = CryptoLib.Errors.Ok, "receive-pack prepare failed");
   Check (To_String (Command_Item) = "git-receive-pack 'repo.git'", "receive command failed");

   Status_Value := SSH_Lib.Git_Transport.Prepare
     (Remote_Text  => "gh:repo.git",
      Config       => Empty_Config,
      Default_User => "git",
      Requested    => SSH_Lib.Git_Transport.Upload_Pack,
      Options      => Options_Item,
      Command      => Command_Item);
   Check (Status_Value = CryptoLib.Errors.Ok, "default user prepare failed");
   Check (To_String (Options_Item.User) = "git", "default user merge failed");

   Status_Value := SSH_Lib.Git_Transport.Prepare
     (Remote_Text  => "gh:repo.git",
      Config       => Empty_Config,
      Default_User => "",
      Requested    => SSH_Lib.Git_Transport.Upload_Pack,
      Options      => Options_Item,
      Command      => Command_Item);
   Check (Status_Value = CryptoLib.Errors.Invalid_User, "missing user was not rejected");

   Status_Value := SSH_Lib.Git_Transport.Prepare
     (Remote_Text  => "git@gh:repo.git",
      Config       => Proxy_Command_Config,
      Default_User => "git",
      Requested    => SSH_Lib.Git_Transport.Upload_Pack,
      Options      => Options_Item,
      Command      => Command_Item);
   Check (Status_Value = CryptoLib.Errors.Ok,
          "git transport rejected a ProxyCommand the library honours");

   Status_Value := SSH_Lib.Git_Transport.Prepare
     (Remote_Text  => "git@bad/host:repo.git",
      Config       => Config_Item,
      Default_User => "git",
      Requested    => SSH_Lib.Git_Transport.Upload_Pack,
      Options      => Options_Item,
      Command      => Command_Item);
   Check (Status_Value = CryptoLib.Errors.Invalid_Host, "bad host was not rejected");

   Status_Value := SSH_Lib.Git_Transport.Prepare
     (Remote_Text  => "ssh://gh:notaport/repo.git",
      Config       => Config_Item,
      Default_User => "git",
      Requested    => SSH_Lib.Git_Transport.Upload_Pack,
      Options      => Options_Item,
      Command      => Command_Item);
   Check (Status_Value = CryptoLib.Errors.Invalid_Port, "bad port was not rejected");

   Status_Value := SSH_Lib.Git_Transport.Prepare
     (Remote_Text  => "git@gh:repo'with.git",
      Config       => Config_Item,
      Default_User => "git",
      Requested    => SSH_Lib.Git_Transport.Upload_Pack,
      Options      => Options_Item,
      Command      => Command_Item);
   Check (Status_Value = CryptoLib.Errors.Ok, "quoted repo prepare failed");
   Check
     (To_String (Command_Item) = "git-upload-pack 'repo'\''with.git'",
      "single quote was not safely quoted");

   Status_Value := SSH_Lib.Git_Transport.Prepare
     (Remote_Text  => "git@gh:bad" & Character'Val (10) & "repo.git",
      Config       => Config_Item,
      Default_User => "git",
      Requested    => SSH_Lib.Git_Transport.Upload_Pack,
      Options      => Options_Item,
      Command      => Command_Item);
   Check (Status_Value = CryptoLib.Errors.Invalid_Command, "LF path was not rejected");

   Status_Value := SSH_Lib.Config.Resolve_Remote
     (Config       => Config_Item,
      Remote_Text  => "git@gh:bad" & Character'Val (10) & "repo.git",
      Default_User => "git",
      Item         => Options_Item);
   Check (Status_Value = CryptoLib.Errors.Invalid_Command,
          "direct remote resolve did not map repository LF to Invalid_Command");

   Ada.Text_IO.Put_Line ("version integration fixture checks passed");
end Test_Version_Fixture;
