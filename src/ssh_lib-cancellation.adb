package body SSH_Lib.Cancellation is
   procedure Request_Cancel
     (Item : in out Cancellation_State) is
   begin
      Item.Cancel_Requested := True;
   end Request_Cancel;

   procedure Reset
     (Item : in out Cancellation_State) is
   begin
      Item.Cancel_Requested := False;
   end Reset;

   function Is_Cancelled
     (Item : Cancellation_State)
      return Boolean is
   begin
      return Item.Cancel_Requested;
   end Is_Cancelled;
end SSH_Lib.Cancellation;
