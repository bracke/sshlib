with Ada.Streams;
with CryptoLib.Errors;

package SSH_Lib.Diagnostics.Safe_Trace is
   function Status_Label
     (Value : CryptoLib.Errors.Status)
      return String;

   function Redacted_Bytes_Label
     (Data : Ada.Streams.Stream_Element_Array)
      return String;

   function Secret_Label return String;
end SSH_Lib.Diagnostics.Safe_Trace;
