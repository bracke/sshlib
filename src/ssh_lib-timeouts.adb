
package body SSH_Lib.Timeouts is
   function Connect_Deadline
     (Timeout_MS : Natural)
      return SSH_Lib.Deadlines.Deadline
   is
   begin
      return SSH_Lib.Deadlines.From_Now (Timeout_MS);
   end Connect_Deadline;

   function Read_Deadline
     (Timeout_MS : Natural)
      return SSH_Lib.Deadlines.Deadline
   is
   begin
      return SSH_Lib.Deadlines.From_Now (Timeout_MS);
   end Read_Deadline;

   function Write_Deadline
     (Timeout_MS : Natural)
      return SSH_Lib.Deadlines.Deadline
   is
   begin
      return SSH_Lib.Deadlines.From_Now (Timeout_MS);
   end Write_Deadline;
end SSH_Lib.Timeouts;
