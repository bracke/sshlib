
package body SSH_Lib.Operation_Control is
   procedure Begin_Operation
     (Item       : in out Operation_State;
      Timeout_MS : Natural) is
   begin
      Item.Limit := SSH_Lib.Deadlines.From_Now (Timeout_MS);
      SSH_Lib.Cancellation.Reset (Item.Cancel);
   end Begin_Operation;

   procedure Begin_Nested_Operation
     (Item            : in out Operation_State;
      Timeout_MS      : Natural;
      Caller_Deadline : SSH_Lib.Deadlines.Deadline)
   is
   begin
      Item.Limit := SSH_Lib.Deadlines.Minimum
        (SSH_Lib.Deadlines.From_Now (Timeout_MS), Caller_Deadline);
      SSH_Lib.Cancellation.Reset (Item.Cancel);
   exception
      when others =>
         Item.Limit := SSH_Lib.Deadlines.From_Now (0);
         SSH_Lib.Cancellation.Reset (Item.Cancel);
   end Begin_Nested_Operation;

   procedure Begin_Nested_Operation
     (Item       : in out Operation_State;
      Timeout_MS : Natural;
      Parent     : Operation_State)
   is
   begin
      Begin_Nested_Operation
        (Item,
         Timeout_MS,
         Parent.Limit);
      if SSH_Lib.Cancellation.Is_Cancelled (Parent.Cancel) then
         SSH_Lib.Cancellation.Request_Cancel (Item.Cancel);
      end if;
   exception
      when others =>
         Item.Limit := SSH_Lib.Deadlines.From_Now (0);
         SSH_Lib.Cancellation.Reset (Item.Cancel);
         SSH_Lib.Cancellation.Request_Cancel (Item.Cancel);
   end Begin_Nested_Operation;

   procedure Request_Cancel
     (Item : in out Operation_State) is
   begin
      SSH_Lib.Cancellation.Request_Cancel (Item.Cancel);
   end Request_Cancel;

   function Deadline
     (Item : Operation_State)
      return SSH_Lib.Deadlines.Deadline is
   begin
      return Item.Limit;
   end Deadline;

   function Check
     (Item : Operation_State)
      return CryptoLib.Errors.Status is
   begin
      if SSH_Lib.Cancellation.Is_Cancelled (Item.Cancel) then
         return CryptoLib.Errors.Cancelled;
      elsif SSH_Lib.Deadlines.Expired (Item.Limit) then
         return CryptoLib.Errors.Timeout;
      else
         return CryptoLib.Errors.Ok;
      end if;
   end Check;
end SSH_Lib.Operation_Control;
