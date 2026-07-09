with SSH_Lib.Cancellation;
with SSH_Lib.Deadlines;
with CryptoLib.Errors;

--  @summary Per-operation timeout deadline and cancellation state.
--
--  Bundles a timeout deadline with a cancellation flag so long-running SSH
--  operations can be bounded and aborted.  Nested operations clamp their
--  deadline to the tighter of their own timeout and the caller's, and inherit
--  the parent's cancellation; Check reports whether the operation may proceed.
package SSH_Lib.Operation_Control is
   type Operation_State is limited private;

   --  Start a top-level operation with a timeout, clearing any cancellation.
   --  @param Item       the operation state to (re)initialize
   --  @param Timeout_MS the operation timeout in milliseconds from now
   procedure Begin_Operation
     (Item       : in out Operation_State;
      Timeout_MS : Natural);

   --  Start a nested operation bounded by the tighter of its timeout and a caller deadline.
   --  @param Item            the operation state to initialize
   --  @param Timeout_MS      this operation's own timeout in milliseconds from now
   --  @param Caller_Deadline the caller's deadline to clamp against
   procedure Begin_Nested_Operation
     (Item            : in out Operation_State;
      Timeout_MS      : Natural;
      Caller_Deadline : SSH_Lib.Deadlines.Deadline);

   --  Start a nested operation under a parent, inheriting its deadline and cancellation.
   --  @param Item       the operation state to initialize
   --  @param Timeout_MS this operation's own timeout in milliseconds from now
   --  @param Parent     the parent operation whose deadline and cancel state are inherited
   procedure Begin_Nested_Operation
     (Item       : in out Operation_State;
      Timeout_MS : Natural;
      Parent     : Operation_State);

   --  Request cancellation of the operation, so subsequent Check calls report Cancelled.
   --  @param Item the operation state to cancel
   procedure Request_Cancel
     (Item : in out Operation_State);

   --  Return the operation's effective deadline.
   --  @param Item the operation state
   --  @return the deadline at which the operation times out
   function Deadline
     (Item : Operation_State)
      return SSH_Lib.Deadlines.Deadline;

   --  Report whether the operation may proceed, or has been cancelled or timed out.
   --  @param Item the operation state
   --  @return Cancelled if cancelled, Timeout if the deadline expired, Ok otherwise
   function Check
     (Item : Operation_State)
      return CryptoLib.Errors.Status;

private
   type Operation_State is limited record
      Limit  : SSH_Lib.Deadlines.Deadline := SSH_Lib.Deadlines.From_Now (0);
      Cancel : SSH_Lib.Cancellation.Cancellation_State;
   end record;
end SSH_Lib.Operation_Control;
