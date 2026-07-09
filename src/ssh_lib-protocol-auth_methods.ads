with Ada.Streams;
with Ada.Strings.Unbounded;
with CryptoLib.Errors;

--  @summary Parsing of SSH_MSG_USERAUTH_FAILURE responses.
--
--  Decodes a userauth-failure message into the still-available authentication
--  methods and the partial-success flag, and tests whether the "publickey"
--  method remains offered so the client can decide whether to keep trying keys.
package SSH_Lib.Protocol.Auth_Methods is

   type Failure_Info is record
      Remaining_Methods : Ada.Strings.Unbounded.Unbounded_String;
      Partial_Success   : Boolean := False;
   end record;

   --  Parse an SSH_MSG_USERAUTH_FAILURE packet into the remaining-methods list
   --  and the partial-success flag.
   --  @param Payload the raw userauth-failure message body
   --  @param Info    the decoded remaining methods and partial-success flag
   --  @return Ok on a well-formed message, an error status otherwise
   function Parse_Failure
     (Payload : Ada.Streams.Stream_Element_Array;
      Info    : out Failure_Info)
      return CryptoLib.Errors.Status;

   --  True when "publickey" appears in the failure's remaining-methods list,
   --  i.e. the server will still accept a public-key authentication attempt.
   --  @param Info a parsed userauth-failure result
   --  @return True if the "publickey" method is still offered
   function Contains_Publickey
     (Info : Failure_Info)
      return Boolean;
end SSH_Lib.Protocol.Auth_Methods;
