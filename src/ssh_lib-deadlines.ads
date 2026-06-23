with Ada.Calendar;

package SSH_Lib.Deadlines is
   type Deadline is private;

   function From_Now
     (Timeout_MS : Natural)
      return Deadline;

   function Expired
     (Item : Deadline)
      return Boolean;

   function Remaining_MS
     (Item : Deadline)
      return Natural;

   function Minimum
     (Left  : Deadline;
      Right : Deadline)
      return Deadline;

private
   type Deadline is record
      Due_Time            : Ada.Calendar.Time := Ada.Calendar.Clock;
      Immediate_Deadline  : Boolean := True;
   end record;
end SSH_Lib.Deadlines;
