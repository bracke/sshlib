with Ada.Streams;
with CryptoLib.Errors;
with SSH_Lib.Protocol.Buffers;

package SSH_Lib.Security_Keys is
   type Security_Key_Sign_Result is record
      Provided       : Boolean := False;
      Signature_Blob : SSH_Lib.Protocol.Buffers.Packet_Buffer;
   end record;

   type Security_Key_Signer is access function
     (Application          : String;
      Public_Key_Algorithm : String;
      Public_Key_Blob      : Ada.Streams.Stream_Element_Array;
      Data_To_Sign         : Ada.Streams.Stream_Element_Array)
      return Security_Key_Sign_Result;

   function Build_Signed_Request
     (Signer               : Security_Key_Signer;
      Application          : String;
      Session_Identifier   : Ada.Streams.Stream_Element_Array;
      User_Name            : String;
      Public_Key_Algorithm : String;
      Public_Key_Blob      : Ada.Streams.Stream_Element_Array;
      Request              : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;
end SSH_Lib.Security_Keys;
