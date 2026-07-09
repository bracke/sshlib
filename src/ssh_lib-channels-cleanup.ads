with CryptoLib.Errors;

--  @summary Terminal state transitions for a channel: mark failed or close.
--
--  Drives a channel to a final state -- either the failed state carrying a
--  cause, or the locally closed state with all pending buffers cleared -- so no
--  stale data or flags survive teardown.
package SSH_Lib.Channels.Cleanup is
   --  Move the channel to the failed state and record the cause of failure.
   --  @param Item   the channel to mark failed and flag dirty
   --  @param Reason the failure cause; Ok is coerced to Internal_Error
   procedure Mark_Failed
     (Item   : in out Channel;
      Reason : CryptoLib.Errors.Status);

   --  Reset the channel to the locally closed state, clearing every pending
   --  buffer, counter, and handshake flag.
   --  @param Item the channel to close and scrub
   --  @return Ok once the channel has been reset
   function Close_Local
     (Item : in out Channel)
      return CryptoLib.Errors.Status;
end SSH_Lib.Channels.Cleanup;
