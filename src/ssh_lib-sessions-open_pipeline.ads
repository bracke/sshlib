with CryptoLib.Errors;

--  @summary Pre-connect validation and preflight checks for opening a session.
--
--  Decides, before any network activity, whether a session's configured
--  options are syntactically valid, name a supported algorithm/authentication
--  method, and could plausibly authenticate -- so that Open fails fast with a
--  precise status instead of starting an unwinnable handshake.
package SSH_Lib.Sessions.Open_Pipeline is
   --  Syntactically validate all session options (host, port, user, path
   --  syntax, algorithm lists, GEX bounds, unsupported features).
   --  @param Options the session options to validate
   --  @return Ok when all options are valid, otherwise the first specific
   --          failure status (Invalid_Host, Unsupported_Feature, etc.)
   function Validate_Options
     (Options : Session_Options)
      return CryptoLib.Errors.Status;

   --  Check that at least one usable authentication method is configured
   --  without contacting ssh-agent or touching key material.
   --  @param Options the session options describing enabled auth methods and credentials
   --  @return Ok when some method (none/publickey/keyboard-interactive/password)
   --          is viable, otherwise Authentication_Failed
   function Authentication_Configuration_Preflight
     (Options : Session_Options)
      return CryptoLib.Errors.Status;

   --  Report an immediate timeout when a connect/read/write timeout is zero,
   --  modeling the first operation that could not make progress.
   --  @param Options the session options carrying the connect/read/write timeouts
   --  @return Timeout when any relevant timeout is zero, otherwise Ok
   function Immediate_Timeout_Preflight
     (Options : Session_Options)
      return CryptoLib.Errors.Status;

end SSH_Lib.Sessions.Open_Pipeline;
