with Ada.Strings.Unbounded;
with CryptoLib.Errors;
with SSH_Lib.Sessions;

package SSH_Lib.Remote_Names is
   type Remote_Kind is (Ssh_Uri, Scp_Like);

   type Parsed_Remote is record
      Kind       : Remote_Kind := Ssh_Uri;
      Host       : Ada.Strings.Unbounded.Unbounded_String;
      Port       : Natural := 22;
      User       : Ada.Strings.Unbounded.Unbounded_String;
      Repository : Ada.Strings.Unbounded.Unbounded_String;
   end record;

   subtype Remote_Name is Parsed_Remote;

   --  Parse common Git-over-SSH remote names.  The ssh:// scheme is
   --  matched case-insensitively; query strings and fragments are
   --  intentionally rejected in this phase rather than interpreted.
   --  For ssh:// URLs, the separator slash after the authority is not
   --  included in Repository_Path; a double slash intentionally produces
   --  an absolute remote path such as /srv/git/repo.git.  Bracketed IPv6
   --  literals are accepted for ssh:// URLs and are returned without
   --  brackets, for example ssh://[::1]/repo.git yields host ::1.
   --  Host text rejects
   --  path/query/fragment delimiters so local-looking paths are not accepted
   --  as hosts.  To_Session_Options with Default_User only copies a valid
   --  non-empty default user; otherwise the user remains empty and Sessions.Open
   --  will reject it deterministically.  ssh:// URL userinfo rejects
   --  colon-delimited credential-like text; this package never stores
   --  passwords or other credentials from remote names.
   function Parse
     (Value : String; Item : out Parsed_Remote) return CryptoLib.Errors.Status;

   function Kind (Item : Parsed_Remote) return Remote_Kind;

   function Kind_Image (Value : Remote_Kind) return String;

   --  Return a deterministic, display-safe remote-name image for a parsed
   --  value.  The image preserves the parsed remote kind: ssh:// values are
   --  emitted as ssh:// remotes, bracketed when an IPv6-like host contains a
   --  colon, and scp-like values are emitted as [user@]host:path.  This is
   --  not a percent-encoder.  Invalid records produce an empty string instead
   --  of exposing unchecked host/user/repository text.
   function Image (Item : Parsed_Remote) return String;

   --  Return True when a parsed remote record is internally valid.  Parse
   --  only returns valid values on Ok, but this helper also protects callers
   --  that construct Parsed_Remote records directly because the current public
   --  type shape is retained for API compatibility.
   function Is_Valid (Item : Parsed_Remote) return Boolean;

   function Host (Item : Parsed_Remote) return String;

   function User (Item : Parsed_Remote) return String;

   function Repository_Path (Item : Parsed_Remote) return String;

   function Port (Item : Parsed_Remote) return Natural;

   --  Return True when the original remote-name text contains an explicit
   --  ssh:// authority port.  This preserves the distinction between
   --  ssh://host/repo.git, which should inherit a configured Port, and
   --  ssh://host:22/repo.git, which explicitly overrides configuration with
   --  port 22.  Scp-like remote names do not carry a port and return False.
   function Has_Explicit_Port (Value : String) return Boolean;

   function Has_User (Item : Parsed_Remote) return Boolean;

   function To_Session_Options
     (Item : Parsed_Remote) return SSH_Lib.Sessions.Session_Options;

   function To_Session_Options
     (Item : Parsed_Remote; Default_User : String)
      return SSH_Lib.Sessions.Session_Options;
end SSH_Lib.Remote_Names;
