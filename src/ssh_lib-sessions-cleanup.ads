with CryptoLib.Errors;

--  @summary Error-path helper that closes a session and propagates the status.
--
--  Used on failure paths to tear the session down to a clean closed state and
--  return the originating error unchanged, so callers can close-and-return in a
--  single expression.
package SSH_Lib.Sessions.Cleanup is
   --  Close the session (resetting it to the closed state) and return the given
   --  failure status.
   --  @param Item         the session to close in place
   --  @param Status_Value the failure status recorded and returned
   --  @return the same Status_Value, for direct propagation by the caller
   function Close_After_Failure
     (Item         : in out Session;
      Status_Value : CryptoLib.Errors.Status)
      return CryptoLib.Errors.Status;
end SSH_Lib.Sessions.Cleanup;
