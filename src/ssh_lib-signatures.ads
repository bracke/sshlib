with Ada.Streams;
with CryptoLib.Errors;

package SSH_Lib.Signatures is

   function Verify
     (Algorithm_Name : String;
      Public_Key_Blob : Ada.Streams.Stream_Element_Array;
      Signature_Bytes : Ada.Streams.Stream_Element_Array;
      Message_Bytes   : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;
end SSH_Lib.Signatures;
