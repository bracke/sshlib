with Ada.Streams;

--  @summary Secret-safe placeholders for byte and text values in diagnostics.
--
--  Produces fixed redaction strings so that key material, ciphertext, and other
--  sensitive values never reach a log.  Byte arrays are replaced by their
--  length only; secret text is dropped entirely.
package SSH_Lib.Diagnostics.Redaction is
   pragma Pure;

   --  Render a byte array as "<redacted N bytes>", disclosing only its length.
   --  @param Data the sensitive byte array whose contents must not be logged
   --  @return the placeholder string carrying only Data'Length
   function Bytes_Redacted
     (Data : Ada.Streams.Stream_Element_Array)
      return String;

   --  Return the fixed "<redacted>" placeholder for an unspecified secret.
   --  @return the constant redaction string "<redacted>"
   function Secret_Redacted return String;

   --  Discard secret text and return the fixed "<redacted>" placeholder.
   --  @param Label_Text the sensitive text, ignored and never included
   --  @return the constant redaction string "<redacted>"
   function Text_Redacted (Label_Text : String) return String;
end SSH_Lib.Diagnostics.Redaction;
