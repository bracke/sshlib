with SSH_Lib.Deadlines;
with CryptoLib.Errors;

--  @summary Deadline- and failure-aware completion checks for transport I/O.
--
--  Each function folds a pending I/O outcome, the operation deadline, and the
--  transport's open state into a single status, marking the transport dirty on
--  a decisive failure so a partially consumed byte stream cannot be reused.
package SSH_Lib.Transport.Wait is
   --  Decide whether the transport is ready to proceed with an I/O operation.
   --  @param Transport the transport handle, marked dirty on failure or timeout
   --  @param Limit     the deadline governing the operation
   --  @param Failure   a pre-existing failure to propagate; Ok means none
   --  @return Failure if non-Ok, Timeout if the deadline expired,
   --          Connection_Failed if the transport is closed, else Ok
   function Check_Readiness
     (Transport : in out SSH_Lib.Transport.Transport_Handle;
      Limit     : SSH_Lib.Deadlines.Deadline;
      Failure   : CryptoLib.Errors.Status := CryptoLib.Errors.Ok)
      return CryptoLib.Errors.Status;

   --  Resolve the outcome of a read, dirtying the transport only when bytes
   --  were already consumed so the stream cannot desynchronize.
   --  @param Transport    the transport handle, marked dirty on partial failure
   --  @param Limit        the deadline governing the read
   --  @param Bytes_Read   the number of bytes read so far
   --  @param Failure      a pre-existing failure to propagate; Ok means none
   --  @param Partial_Read whether a partial read has already occurred
   --  @return Failure if non-Ok, Timeout if the deadline expired,
   --          Connection_Failed if the transport is closed, else Ok
   function Complete_Read
     (Transport    : in out SSH_Lib.Transport.Transport_Handle;
      Limit        : SSH_Lib.Deadlines.Deadline;
      Bytes_Read   : Natural;
      Failure      : CryptoLib.Errors.Status := CryptoLib.Errors.Ok;
      Partial_Read : Boolean := False)
      return CryptoLib.Errors.Status;

   --  Resolve the outcome of a write, distinguishing a fully written buffer
   --  from a partial write that leaves the stream mid-message.
   --  @param Transport     the transport handle, marked dirty on partial failure
   --  @param Limit         the deadline governing the write
   --  @param Bytes_Written the number of bytes written so far
   --  @param Total_Bytes   the total number of bytes to be written
   --  @param Failure       a pre-existing failure to propagate; Ok means none
   --  @param Partial_Write whether a partial write has already occurred
   --  @return Ok when all bytes were written, Failure if non-Ok,
   --          Connection_Failed if closed, Write_Failed on a stalled partial
   --          write, else Timeout
   function Complete_Write
     (Transport     : in out SSH_Lib.Transport.Transport_Handle;
      Limit         : SSH_Lib.Deadlines.Deadline;
      Bytes_Written : Natural;
      Total_Bytes   : Natural;
      Failure       : CryptoLib.Errors.Status := CryptoLib.Errors.Ok;
      Partial_Write : Boolean := False)
      return CryptoLib.Errors.Status;
end SSH_Lib.Transport.Wait;
