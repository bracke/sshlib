with Ada.Streams;
with CryptoLib.Errors;

--  @summary Secret-safe, exception-proof labels for trace/log output.
--
--  Turns status codes and sensitive byte arrays into short strings that are
--  safe to log: values are redacted to length only, and any unexpected
--  exception is swallowed and replaced with a fixed fallback label so tracing
--  never disrupts the caller.
package SSH_Lib.Diagnostics.Safe_Trace is
   --  Render a status code as its enumeration image, or "INTERNAL_ERROR" if the
   --  image cannot be produced.
   --  @param Value the CryptoLib status code to label
   --  @return the status name, or "INTERNAL_ERROR" on any exception
   function Status_Label
     (Value : CryptoLib.Errors.Status)
      return String;

   --  Render a byte array as "<redacted N bytes>", or "<redacted bytes>" if the
   --  length cannot be formatted, disclosing only its length.
   --  @param Data the sensitive byte array whose contents must not be logged
   --  @return the length-only placeholder, or "<redacted bytes>" on any exception
   function Redacted_Bytes_Label
     (Data : Ada.Streams.Stream_Element_Array)
      return String;

   --  Return the fixed "<secret redacted>" placeholder for an unspecified secret.
   --  @return the constant label "<secret redacted>"
   function Secret_Label return String;
end SSH_Lib.Diagnostics.Safe_Trace;
