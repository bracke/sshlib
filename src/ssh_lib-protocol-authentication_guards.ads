with Ada.Streams;
with CryptoLib.Errors;
with SSH_Lib.Protocol.Userauth;

package SSH_Lib.Protocol.Authentication_Guards is
   function Can_Start_Userauth
     (Encrypted_Mode_Active : Boolean;
      Host_Key_Trusted      : Boolean)
      return CryptoLib.Errors.Status;

   function Complete_Userauth
     (Precondition_Status : CryptoLib.Errors.Status;
      Reply               : SSH_Lib.Protocol.Userauth.Reply)
      return CryptoLib.Errors.Status;

   function Signature_Payloads_Match
     (Expected_Payload : Ada.Streams.Stream_Element_Array;
      Actual_Payload   : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;
end SSH_Lib.Protocol.Authentication_Guards;
