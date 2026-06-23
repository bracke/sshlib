package SSH_Lib.Cancellation is
   type Cancellation_State is limited private;

   procedure Request_Cancel
     (Item : in out Cancellation_State);

   procedure Reset
     (Item : in out Cancellation_State);

   function Is_Cancelled
     (Item : Cancellation_State)
      return Boolean;

private
   type Cancellation_State is limited record
      Cancel_Requested : Boolean := False;
   end record;
end SSH_Lib.Cancellation;
