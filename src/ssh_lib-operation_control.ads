with SSH_Lib.Cancellation;
with SSH_Lib.Deadlines;
with CryptoLib.Errors;

package SSH_Lib.Operation_Control is
   type Operation_State is limited private;

   procedure Begin_Operation
     (Item       : in out Operation_State;
      Timeout_MS : Natural);

   procedure Begin_Nested_Operation
     (Item            : in out Operation_State;
      Timeout_MS      : Natural;
      Caller_Deadline : SSH_Lib.Deadlines.Deadline);

   procedure Begin_Nested_Operation
     (Item       : in out Operation_State;
      Timeout_MS : Natural;
      Parent     : Operation_State);

   procedure Request_Cancel
     (Item : in out Operation_State);

   function Deadline
     (Item : Operation_State)
      return SSH_Lib.Deadlines.Deadline;

   function Check
     (Item : Operation_State)
      return CryptoLib.Errors.Status;

private
   type Operation_State is limited record
      Limit  : SSH_Lib.Deadlines.Deadline := SSH_Lib.Deadlines.From_Now (0);
      Cancel : SSH_Lib.Cancellation.Cancellation_State;
   end record;
end SSH_Lib.Operation_Control;
