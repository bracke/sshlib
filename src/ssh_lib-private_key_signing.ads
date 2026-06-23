with Ada.Streams;
with CryptoLib.Errors;
with SSH_Lib.Identity_Files;
with CryptoLib.Buffers;

package SSH_Lib.Private_Key_Signing is
   function Can_Sign_Userauth
     (Key                  : SSH_Lib.Identity_Files.Identity_Key;
      Public_Key_Algorithm : String)
      return Boolean;

   function Sign_Userauth
     (Key                 : SSH_Lib.Identity_Files.Identity_Key;
      Public_Key_Algorithm : String;
      Payload             : Ada.Streams.Stream_Element_Array;
      Signature_Blob      : out CryptoLib.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;
end SSH_Lib.Private_Key_Signing;
