with Ada.Streams;

package SSH_Lib.Diagnostics.Redaction is
   pragma Pure;

   function Bytes_Redacted
     (Data : Ada.Streams.Stream_Element_Array)
      return String;

   function Secret_Redacted return String;

   function Text_Redacted (Label_Text : String) return String;
end SSH_Lib.Diagnostics.Redaction;
