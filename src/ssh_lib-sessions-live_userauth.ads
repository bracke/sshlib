with Ada.Streams;
with CryptoLib.Errors;
with SSH_Lib.Sessions.Live_Transcript;

package SSH_Lib.Sessions.Live_Userauth is
   function Authenticate
     (Transcript         : in out SSH_Lib.Sessions.Live_Transcript.Driver;
      Options            : Session_Options;
      Session_Identifier : Ada.Streams.Stream_Element_Array;
      Item               : in out Session)
      return CryptoLib.Errors.Status;
end SSH_Lib.Sessions.Live_Userauth;
