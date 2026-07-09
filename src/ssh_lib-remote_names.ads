with Ada.Strings.Unbounded;
with CryptoLib.Errors;
with SSH_Lib.Sessions;

--  @summary Parse and re-render Git-over-SSH remote names (ssh:// URLs and
--  scp-like user@host:path forms) into structured host/user/port/path fields.
--
--  Treats remote names as untrusted data: it never stores passwords or other
--  credentials, rejects path/query/fragment delimiters in host text, and
--  produces empty strings rather than exposing unchecked fields for invalid
--  records.  The parsed record maps to Sessions.Session_Options for connecting.
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
   --  @param Value the remote-name text to parse (ssh:// URL or scp-like form)
   --  @param Item  the resulting parsed remote, valid only when Ok is returned
   --  @return Ok when the name parses to a valid remote, a non-Ok Status
   --          otherwise
   function Parse
     (Value : String; Item : out Parsed_Remote) return CryptoLib.Errors.Status;

   --  Return the remote kind (ssh:// URI or scp-like) of a parsed record.
   --  @param Item the parsed remote to inspect
   --  @return the Remote_Kind stored in the record
   function Kind (Item : Parsed_Remote) return Remote_Kind;

   --  Return a stable textual image of a remote kind for display or logging.
   --  @param Value the remote-kind enumeration value to render
   --  @return the display label for the kind
   function Kind_Image (Value : Remote_Kind) return String;

   --  Return a deterministic, display-safe remote-name image for a parsed
   --  value.  The image preserves the parsed remote kind: ssh:// values are
   --  emitted as ssh:// remotes, bracketed when an IPv6-like host contains a
   --  colon, and scp-like values are emitted as [user@]host:path.  This is
   --  not a percent-encoder.  Invalid records produce an empty string instead
   --  of exposing unchecked host/user/repository text.
   --  @param Item the parsed remote to render
   --  @return the display-safe remote-name image, or an empty string when Item
   --          is invalid
   function Image (Item : Parsed_Remote) return String;

   --  Return True when a parsed remote record is internally valid.  Parse
   --  only returns valid values on Ok, but this helper also protects callers
   --  that construct Parsed_Remote records directly because the current public
   --  type shape is retained for API compatibility.
   --  @param Item the parsed remote record to check
   --  @return True when the record is internally valid, False otherwise
   function Is_Valid (Item : Parsed_Remote) return Boolean;

   --  Return the host component of a parsed remote (IPv6 literals unbracketed).
   --  @param Item the parsed remote to inspect
   --  @return the host text
   function Host (Item : Parsed_Remote) return String;

   --  Return the user component of a parsed remote (empty when none was given).
   --  @param Item the parsed remote to inspect
   --  @return the user text, or the empty string when no user is present
   function User (Item : Parsed_Remote) return String;

   --  Return the repository path component of a parsed remote.
   --  @param Item the parsed remote to inspect
   --  @return the repository path text
   function Repository_Path (Item : Parsed_Remote) return String;

   --  Return the port of a parsed remote (defaults to 22 when unspecified).
   --  @param Item the parsed remote to inspect
   --  @return the TCP port number
   function Port (Item : Parsed_Remote) return Natural;

   --  Return True when the original remote-name text contains an explicit
   --  ssh:// authority port.  This preserves the distinction between
   --  ssh://host/repo.git, which should inherit a configured Port, and
   --  ssh://host:22/repo.git, which explicitly overrides configuration with
   --  port 22.  Scp-like remote names do not carry a port and return False.
   --  @param Value the original remote-name text to inspect
   --  @return True when the text carries an explicit ssh:// authority port,
   --          False otherwise
   function Has_Explicit_Port (Value : String) return Boolean;

   --  Return True when a parsed remote carries a non-empty user component.
   --  @param Item the parsed remote to inspect
   --  @return True when a user is present, False otherwise
   function Has_User (Item : Parsed_Remote) return Boolean;

   --  Convert a parsed remote into session options for opening a connection.
   --  @param Item the parsed remote to convert
   --  @return the Session_Options describing the connection target
   function To_Session_Options
     (Item : Parsed_Remote) return SSH_Lib.Sessions.Session_Options;

   --  Convert a parsed remote into session options, filling in a default user
   --  when the remote itself carries none (only a valid non-empty default is
   --  applied; otherwise the user stays empty and Sessions.Open rejects it).
   --  @param Item         the parsed remote to convert
   --  @param Default_User the fallback user applied when the remote has none
   --  @return the Session_Options describing the connection target
   function To_Session_Options
     (Item : Parsed_Remote; Default_User : String)
      return SSH_Lib.Sessions.Session_Options;
end SSH_Lib.Remote_Names;
