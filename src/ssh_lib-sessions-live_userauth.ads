with Ada.Streams;
with CryptoLib.Errors;
with SSH_Lib.Sessions.Live_Transcript;

--  @summary Drives user authentication over a live encrypted transport.
--
--  Runs the userauth exchange against a real connected server through the live
--  transcript driver, trying the configured methods (password, public key,
--  agent, security key, keyboard-interactive) and updating the session state.
package SSH_Lib.Sessions.Live_Userauth is
   --  Perform user authentication over the live transport, driving the userauth
   --  method exchange until the server accepts or all methods are exhausted.
   --  @param Transcript         the live transcript driver for encrypted packet IO
   --  @param Options            the session options selecting credentials and methods
   --  @param Session_Identifier the SSH session identifier bound into signatures
   --  @param Item               the session updated with the authentication outcome
   --  @return Ok when authenticated, an error status otherwise
   function Authenticate
     (Transcript         : in out SSH_Lib.Sessions.Live_Transcript.Driver;
      Options            : Session_Options;
      Session_Identifier : Ada.Streams.Stream_Element_Array;
      Item               : in out Session)
      return CryptoLib.Errors.Status;
end SSH_Lib.Sessions.Live_Userauth;
