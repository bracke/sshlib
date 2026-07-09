with SSH_Lib.Deadlines;

--  @summary Constructors for connect/read/write operation deadlines.
--
--  Thin named wrappers that turn a relative millisecond timeout into an
--  absolute Deadline anchored at the current time, one per transport operation
--  class, so call sites read intently (Connect/Read/Write) rather than reusing
--  a bare From_Now.
package SSH_Lib.Timeouts is
   --  Compute the absolute deadline for a connect operation.
   --  @param Timeout_MS the connect timeout in milliseconds, relative to now
   --  @return a deadline that expires Timeout_MS milliseconds from now
   function Connect_Deadline
     (Timeout_MS : Natural)
      return SSH_Lib.Deadlines.Deadline;

   --  Compute the absolute deadline for a read operation.
   --  @param Timeout_MS the read timeout in milliseconds, relative to now
   --  @return a deadline that expires Timeout_MS milliseconds from now
   function Read_Deadline
     (Timeout_MS : Natural)
      return SSH_Lib.Deadlines.Deadline;

   --  Compute the absolute deadline for a write operation.
   --  @param Timeout_MS the write timeout in milliseconds, relative to now
   --  @return a deadline that expires Timeout_MS milliseconds from now
   function Write_Deadline
     (Timeout_MS : Natural)
      return SSH_Lib.Deadlines.Deadline;
end SSH_Lib.Timeouts;
