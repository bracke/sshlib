with Ada.Streams;
with Ada.Strings.Unbounded;
with CryptoLib.Errors;

package SSH_Lib.Protocol.Auth_Methods is

   type Failure_Info is record
      Remaining_Methods : Ada.Strings.Unbounded.Unbounded_String;
      Partial_Success   : Boolean := False;
   end record;

   function Parse_Failure
     (Payload : Ada.Streams.Stream_Element_Array;
      Info    : out Failure_Info)
      return CryptoLib.Errors.Status;

   function Contains_Publickey
     (Info : Failure_Info)
      return Boolean;
end SSH_Lib.Protocol.Auth_Methods;
