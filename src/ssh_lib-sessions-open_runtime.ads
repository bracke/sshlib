with CryptoLib.Errors;

--  @summary Runs the full session-open sequence against a live server.
--
--  Orchestrates connecting a session end to end -- transport connect, version
--  exchange, key exchange and host-key verification, and user authentication --
--  leaving the session either open or reset to closed with a failure status.
package SSH_Lib.Sessions.Open_Runtime is
   --  Execute the complete open sequence (transport, KEX, host-key check, and
   --  userauth) for the session using the given options.
   --  @param Options the session options controlling the connection and auth
   --  @param Item    the session advanced to open, or reset to closed on failure
   --  @return Ok when the session is fully open, an error status otherwise
   function Run
     (Options : Session_Options;
      Item    : in out Session)
      return CryptoLib.Errors.Status;
end SSH_Lib.Sessions.Open_Runtime;
