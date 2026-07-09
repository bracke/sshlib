--  @summary Cooperative cancellation token for aborting long-running SSH operations.
--
--  A caller shares a Cancellation_State with an in-progress operation; the
--  operation polls Is_Cancelled at safe points and unwinds when a cancel has
--  been requested.  The token is one-shot until Reset returns it to the
--  not-cancelled state for reuse.
package SSH_Lib.Cancellation is
   type Cancellation_State is limited private;

   --  Signal that the operation observing this token should abort at its next
   --  cooperative cancellation point.
   --  @param Item the cancellation token to mark as cancel-requested
   procedure Request_Cancel
     (Item : in out Cancellation_State);

   --  Clear a previously requested cancellation so the token can be reused.
   --  @param Item the cancellation token to return to the not-cancelled state
   procedure Reset
     (Item : in out Cancellation_State);

   --  Report whether a cancel has been requested on this token.
   --  @param Item the cancellation token to inspect
   --  @return True if Request_Cancel has been called since the last Reset
   function Is_Cancelled
     (Item : Cancellation_State)
      return Boolean;

private
   type Cancellation_State is limited record
      Cancel_Requested : Boolean := False;
   end record;
end SSH_Lib.Cancellation;
