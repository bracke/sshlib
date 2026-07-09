with Ada.Streams;
with CryptoLib.Errors;
with SSH_Lib.Protocol.Userauth;

--  @summary Precondition guards that gate the SSH userauth phase.
--
--  Pure decision functions the session pipeline calls before and after
--  user authentication: userauth may only begin over an encrypted transport
--  against a trusted host key, and only an explicit USERAUTH_SUCCESS reply may
--  promote a session to authenticated state.  Any unexpected condition maps to
--  a conservative failure status rather than an optimistic success.
package SSH_Lib.Protocol.Authentication_Guards is
   --  Decide whether the SSH userauth phase may start given the transport's
   --  current security posture.
   --  @param Encrypted_Mode_Active whether encrypted packet mode is active in both directions
   --  @param Host_Key_Trusted      whether the server host key has been verified/trusted
   --  @return Ok when both preconditions hold, Handshake_Failed if not yet
   --          encrypted, Host_Key_Unknown if the host key is untrusted
   function Can_Start_Userauth
     (Encrypted_Mode_Active : Boolean;
      Host_Key_Trusted      : Boolean)
      return CryptoLib.Errors.Status;

   --  Decide the authentication outcome from a userauth reply, refusing to
   --  promote anything but an explicit success to authenticated state.
   --  @param Precondition_Status status carried from an earlier guard; a non-Ok value is returned unchanged
   --  @param Reply               the parsed userauth reply to interpret
   --  @return Ok only for Auth_Success, Authentication_Failed for any other
   --          reply kind, or the propagated non-Ok precondition status
   function Complete_Userauth
     (Precondition_Status : CryptoLib.Errors.Status;
      Reply               : SSH_Lib.Protocol.Userauth.Reply)
      return CryptoLib.Errors.Status;

   --  Compare two signature payloads for exact byte-for-byte equality.
   --  @param Expected_Payload the reference payload the signature was expected to cover
   --  @param Actual_Payload   the payload actually presented for verification
   --  @return Ok when the payloads have equal length and identical bytes,
   --          otherwise Authentication_Failed
   function Signature_Payloads_Match
     (Expected_Payload : Ada.Streams.Stream_Element_Array;
      Actual_Payload   : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;
end SSH_Lib.Protocol.Authentication_Guards;
