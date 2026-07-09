with Ada.Strings.Unbounded;
with Ada.Containers.Vectors;
with CryptoLib.Errors;
with SSH_Lib.Remote_Names;
with SSH_Lib.Sessions;

--  @summary Parser and per-host resolver for OpenSSH-style ssh_config files.
--
--  Loads an ssh_config file into an in-memory model of global directives and
--  Host/Match blocks, then resolves the effective transport settings for a
--  given host or remote name into a Sessions.Session_Options record, matching
--  OpenSSH precedence (first value wins, host-pattern matching, defaults).
package SSH_Lib.Config is
   type Host_Config is private;

   --  Load the user's default ssh_config (~/.ssh/config); on any error return
   --  an empty-but-loaded configuration rather than failing.
   --  @return the parsed configuration, or an empty loaded model on error
   function Load_Default return Host_Config;

   --  Parse the ssh_config file at Path into a configuration model.
   --  @param Path the filesystem path of the ssh_config file to read
   --  @param Item the resulting parsed configuration
   --  @return Ok on success, or an error status on read/parse failure
   function Load
     (Path : String;
      Item : out Host_Config)
      return CryptoLib.Errors.Status;

   --  Resolve the effective session options for Host, falling back to built-in
   --  defaults when resolution fails.
   --  @param Config the parsed configuration to resolve against
   --  @param Host   the host alias/name to look up
   --  @return the resolved session options (defaults on resolution error)
   function Resolve
     (Config : Host_Config;
      Host   : String)
      return SSH_Lib.Sessions.Session_Options;

   --  Resolve the effective session options for Host, reporting failures via a
   --  status code instead of substituting defaults.
   --  @param Config the parsed configuration to resolve against
   --  @param Host   the host alias/name to look up
   --  @param Item   the resolved session options on success
   --  @return Ok on success, Invalid_Host or another error status otherwise
   function Resolve
     (Config : Host_Config;
      Host   : String;
      Item   : out SSH_Lib.Sessions.Session_Options)
      return CryptoLib.Errors.Status;

   --  Resolve the effective session options for Host, applying Default_User
   --  when no User directive matched.
   --  @param Config       the parsed configuration to resolve against
   --  @param Host         the host alias/name to look up
   --  @param Default_User the user to apply when config sets no User
   --  @param Item         the resolved session options on success
   --  @return Ok on success, Invalid_Host/Invalid_User or another error otherwise
   function Resolve
     (Config       : Host_Config;
      Host         : String;
      Default_User : String;
      Item         : out SSH_Lib.Sessions.Session_Options)
      return CryptoLib.Errors.Status;

   --  Resolve session options from a parsed Remote_Name value.
   --  @param Config the parsed configuration to resolve against
   --  @param Remote the parsed remote name providing host/user/port selectors
   --  @param Item   the resolved session options on success
   --  @return Ok on success, or an error status otherwise
   function Resolve_Remote
     (Config : Host_Config;
      Remote : SSH_Lib.Remote_Names.Remote_Name;
      Item   : out SSH_Lib.Sessions.Session_Options)
      return CryptoLib.Errors.Status;

   --  Resolve directly from the original remote-name text so callers can
   --  preserve explicit ssh://host:22/repo.git port overrides.  Parsed_Remote
   --  intentionally keeps Port as the effective value for compatibility, so
   --  the text-aware overload is the deterministic shape for version-style
   --  remote/config composition.
   --  @param Config       the parsed configuration to resolve against
   --  @param Remote_Text  the original remote-name text (may carry ssh:// and port)
   --  @param Default_User the user to apply when neither text nor config sets one
   --  @param Item         the resolved session options on success
   --  @return Ok on success, or an error status otherwise
   function Resolve_Remote
     (Config       : Host_Config;
      Remote_Text  : String;
      Default_User : String;
      Item         : out SSH_Lib.Sessions.Session_Options)
      return CryptoLib.Errors.Status;

   --  Report whether the configuration selects a feature this library cannot
   --  honour for Host (currently always False; True is returned only on error).
   --  @param Config the parsed configuration to inspect
   --  @param Host   the host alias/name whose resolved features are checked
   --  @return True if an unsupported feature is required, False otherwise
   function Has_Unsupported_Feature
     (Config : Host_Config;
      Host   : String)
      return Boolean;

private
   subtype Stored_Text is Ada.Strings.Unbounded.Unbounded_String;

   function Equal_Text (Left, Right : Stored_Text) return Boolean;

   type Directive_Kind is
     (Host_Name_Directive,
      User_Directive,
      Port_Directive,
      Identity_File_Directive,
      Certificate_File_Directive,
      User_Known_Hosts_File_Directive,
      Global_Known_Hosts_File_Directive,
      Host_Key_Alias_Directive,
      Revoked_Host_Keys_Directive,
      Identity_Agent_Directive,
      Preferred_Authentications_Directive,
      Pubkey_Accepted_Algorithms_Directive,
      Host_Key_Algorithms_Directive,
      Kex_Algorithms_Directive,
      Ciphers_Directive,
      Macs_Directive,
      Compression_Directive,
      Canonicalize_Hostname_Directive,
      Batch_Mode_Directive,
      Forward_Agent_Directive,
      Forward_X11_Directive,
      Request_TTY_Directive,
      Remote_Command_Directive,
      Server_Alive_Interval_Directive,
      Server_Alive_Count_Max_Directive,
      TCP_Keep_Alive_Directive,
      Log_Level_Directive,
      Visual_Host_Key_Directive,
      Update_Host_Keys_Directive,
      Password_Authentication_Directive,
      Pubkey_Authentication_Directive,
      Kbd_Interactive_Authentication_Directive,
      Number_Of_Password_Prompts_Directive,
      Strict_Host_Key_Checking_Directive,
      Check_Host_IP_Directive,
      Hash_Known_Hosts_Directive,
      Canonical_Domains_Directive,
      Canonicalize_Max_Dots_Directive,
      Canonicalize_Fallback_Local_Directive,
      Canonicalize_Permitted_CNAMEs_Directive,
      Hostbased_Authentication_Directive,
      No_Host_Authentication_For_Localhost_Directive,
      Address_Family_Directive,
      Bind_Address_Directive,
      Bind_Interface_Directive,
      IP_QoS_Directive,
      Escape_Char_Directive,
      Session_Type_Directive,
      Stdin_Null_Directive,
      Fork_After_Authentication_Directive,
      Proxy_Use_Fdpass_Directive,
      Enable_SSH_Keysign_Directive,
      GSSAPI_Authentication_Directive,
      GSSAPI_Delegate_Credentials_Directive,
      Log_Verbose_Directive,
      Verify_Host_Key_DNS_Directive,
      Fingerprint_Hash_Directive,
      Connection_Attempts_Directive,
      Rekey_Limit_Directive,
      CA_Signature_Algorithms_Directive,
      Known_Hosts_Command_Directive,
      Permit_Local_Command_Directive,
      Local_Command_Directive,
      Add_Keys_To_Agent_Directive,
      Clear_All_Forwardings_Directive,
      Exit_On_Forward_Failure_Directive,
      Certificate_Authority_File_Directive,
      Trusted_User_CA_Keys_Directive,
      Allowed_Cert_Critical_Options_Directive,
      Reject_Unknown_Cert_Critical_Options_Directive,
      Identities_Only_Directive,
      Proxy_Jump_Directive,
      Proxy_Command_Directive,
      Control_Master_Directive,
      Control_Path_Directive,
      Control_Persist_Directive,
      Local_Forward_Directive,
      Remote_Forward_Directive,
      Dynamic_Forward_Directive,
      Send_Env_Directive,
      Set_Env_Directive);

   type Config_Directive is record
      Kind   : Directive_Kind := Host_Name_Directive;
      Value  : Stored_Text;
      Status : CryptoLib.Errors.Status := CryptoLib.Errors.Ok;
   end record;

   package Pattern_Vectors is new Ada.Containers.Vectors
     (Index_Type   => Natural,
      Element_Type => Stored_Text,
      "="          => Equal_Text);

   function Equal_Directive
     (Left  : Config_Directive;
      Right : Config_Directive)
      return Boolean;

   package Directive_Vectors is new Ada.Containers.Vectors
     (Index_Type   => Natural,
      Element_Type => Config_Directive,
      "="          => Equal_Directive);

   type Host_Block is record
      Patterns   : Pattern_Vectors.Vector;
      Directives : Directive_Vectors.Vector;
   end record;

   function Equal_Block
     (Left  : Host_Block;
      Right : Host_Block)
      return Boolean;

   package Block_Vectors is new Ada.Containers.Vectors
     (Index_Type   => Natural,
      Element_Type => Host_Block,
      "="          => Equal_Block);

   type Host_Config is record
      Loaded  : Boolean := False;
      Globals : Directive_Vectors.Vector;
      Blocks  : Block_Vectors.Vector;
   end record;
end SSH_Lib.Config;
