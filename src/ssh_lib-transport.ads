with CryptoLib.Errors;

--  @summary Tri-state (closed/open/dirty) lifecycle tracker for an SSH transport.
--
--  A Transport_Handle records only the abstract connection state and the status
--  that last poisoned it, so protocol code can distinguish a cleanly closed
--  transport from one left dirty by a partial or failed I/O and refuse further
--  use accordingly.
package SSH_Lib.Transport is
   type Transport_Handle is limited private;

   --  Mark the transport as open and usable.
   --  @param Item the transport handle to open
   procedure Mark_Open
     (Item : in out Transport_Handle);

   --  Poison the transport, recording the failure that made it unusable.
   --  @param Item   the transport handle to mark dirty
   --  @param Reason the status describing why the transport is now unusable
   procedure Mark_Dirty
     (Item   : in out Transport_Handle;
      Reason : CryptoLib.Errors.Status);

   --  Move the transport to the closed state.
   --  @param Item the transport handle to close
   --  @return Ok on a clean close, otherwise the recorded failure status
   function Close
     (Item : in out Transport_Handle)
      return CryptoLib.Errors.Status;

   --  Report whether the transport is currently open.
   --  @param Item the transport handle to inspect
   --  @return True when the state is open, False when closed or dirty
   function Is_Open
     (Item : Transport_Handle)
      return Boolean;

   --  Report whether the transport has been poisoned by a failure.
   --  @param Item the transport handle to inspect
   --  @return True when the state is dirty
   function Is_Dirty
     (Item : Transport_Handle)
      return Boolean;

   --  Return the status that last marked the transport dirty.
   --  @param Item the transport handle to inspect
   --  @return the recorded failure status, or Ok if never poisoned
   function Last_Failure
     (Item : Transport_Handle)
      return CryptoLib.Errors.Status;

private
   type Transport_State is (Transport_Closed, Transport_Open, Transport_Dirty);

   type Transport_Handle is limited record
      Current_State : Transport_State := Transport_Closed;
      Failure       : CryptoLib.Errors.Status := CryptoLib.Errors.Ok;
   end record;
end SSH_Lib.Transport;
