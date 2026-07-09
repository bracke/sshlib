with CryptoLib.Errors;

--  @summary First-failure-wins combinators for chaining status values.
--
--  Lets a sequence of steps be reduced to the first decisive failure,
--  preserving the earliest error rather than letting a later Ok mask it.
package SSH_Lib.Diagnostics.Safe_Status is
   pragma Pure;

   --  Return the first status that represents a decisive failure, keeping the
   --  earlier error when one is already present.
   --  @param Current_Status the status accumulated so far
   --  @param Next_Status    the status of the next step
   --  @return Current_Status if it is a failure, otherwise Next_Status
   function First_Decisive
     (Current_Status : CryptoLib.Errors.Status;
      Next_Status    : CryptoLib.Errors.Status)
      return CryptoLib.Errors.Status;

   --  Report whether a status value denotes a decisive failure.
   --  @param Value the status to classify
   --  @return True if Value is anything other than Ok
   function Is_Decisive_Failure
     (Value : CryptoLib.Errors.Status)
      return Boolean;
end SSH_Lib.Diagnostics.Safe_Status;
