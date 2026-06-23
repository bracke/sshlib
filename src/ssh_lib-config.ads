with Ada.Strings.Unbounded;
with Ada.Containers.Vectors;
with CryptoLib.Errors;
with SSH_Lib.Remote_Names;
with SSH_Lib.Sessions;

package SSH_Lib.Config is
   type Host_Config is private;

   function Load_Default return Host_Config;

   function Load
     (Path : String;
      Item : out Host_Config)
      return CryptoLib.Errors.Status;

   function Resolve
     (Config : Host_Config;
      Host   : String)
      return SSH_Lib.Sessions.Session_Options;

   function Resolve
     (Config : Host_Config;
      Host   : String;
      Item   : out SSH_Lib.Sessions.Session_Options)
      return CryptoLib.Errors.Status;

   function Resolve
     (Config       : Host_Config;
      Host         : String;
      Default_User : String;
      Item         : out SSH_Lib.Sessions.Session_Options)
      return CryptoLib.Errors.Status;

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
   function Resolve_Remote
     (Config       : Host_Config;
      Remote_Text  : String;
      Default_User : String;
      Item         : out SSH_Lib.Sessions.Session_Options)
      return CryptoLib.Errors.Status;

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
