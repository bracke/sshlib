with SSH_Lib.Deadlines;

package SSH_Lib.Timeouts is
   function Connect_Deadline
     (Timeout_MS : Natural)
      return SSH_Lib.Deadlines.Deadline;

   function Read_Deadline
     (Timeout_MS : Natural)
      return SSH_Lib.Deadlines.Deadline;

   function Write_Deadline
     (Timeout_MS : Natural)
      return SSH_Lib.Deadlines.Deadline;
end SSH_Lib.Timeouts;
