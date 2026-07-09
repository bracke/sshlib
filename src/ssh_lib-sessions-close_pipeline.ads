with CryptoLib.Errors;

--  @summary Session teardown: credential scrubbing and reset to closed state.
--
--  The plumbing that returns a session to a clean closed state on close or
--  failure -- wiping secret credential material and resetting every transport,
--  key-exchange, userauth, channel, and live-IO flag and buffer.
package SSH_Lib.Sessions.Close_Pipeline is
   --  Erase all secret credential material (passwords, passphrases, and the
   --  interactive credential callbacks) from the session options.
   --  @param Options the option set whose secrets are cleared in place
   procedure Scrub_Credentials (Options : in out Session_Options);

   --  Return the session to a fully closed state: detach live IO, reset every
   --  transport/KEX/userauth/channel flag and buffer, scrub stored credentials,
   --  and record the given failure status.
   --  @param Item         the session to reset in place
   --  @param Status_Value the failure status to record on the closed session
   procedure Reset_To_Closed
     (Item         : in out Session;
      Status_Value : CryptoLib.Errors.Status);
end SSH_Lib.Sessions.Close_Pipeline;
