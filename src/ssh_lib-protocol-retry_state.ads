with CryptoLib.Errors;

--  @summary Track write progress to decide whether a failed write may be safely retried.
--
--  Remembers how many bytes a write attempt has committed to the wire and whether
--  a failure left the outcome ambiguous, so a retry is only permitted when no
--  bytes were sent and nothing could have been partially transmitted.
package SSH_Lib.Protocol.Retry_State is
   type Write_Attempt_State is private;

   --  Reset the attempt to no bytes sent and no ambiguous failure.
   --  @param Item the write-attempt state to reset
   procedure Reset
     (Item : out Write_Attempt_State);

   --  Record additional bytes committed to the wire, saturating at Natural'Last.
   --  @param Item       the write-attempt state to update
   --  @param Byte_Count the number of bytes just sent
   procedure Record_Progress
     (Item        : in out Write_Attempt_State;
      Byte_Count  : Natural);

   --  Mark that a failure left the send outcome ambiguous, forbidding retry.
   --  @param Item the write-attempt state to mark
   procedure Record_Ambiguous_Failure
     (Item : in out Write_Attempt_State);

   --  Return the total number of bytes recorded as sent.
   --  @param Item the write-attempt state
   --  @return the cumulative bytes sent
   function Bytes_Sent
     (Item : Write_Attempt_State)
      return Natural;

   --  Report whether an ambiguous failure has been recorded.
   --  @param Item the write-attempt state
   --  @return True if an ambiguous failure was recorded
   function Has_Ambiguous_Failure
     (Item : Write_Attempt_State)
      return Boolean;

   --  Decide whether the failed write may be safely retried without duplicating data.
   --  @param Item         the write-attempt state
   --  @param Status_Value the failing status of the write attempt
   --  @return True only if no bytes were sent, the failure is unambiguous, and the status is retryable
   function Retry_Allowed
     (Item         : Write_Attempt_State;
      Status_Value : CryptoLib.Errors.Status)
      return Boolean;

private
   type Write_Attempt_State is record
      Sent_Count          : Natural := 0;
      Ambiguous_Failure   : Boolean := False;
   end record;
end SSH_Lib.Protocol.Retry_State;
