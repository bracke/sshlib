with Ada.Calendar;

--  @summary Monotonic-style absolute deadlines derived from millisecond timeouts.
--
--  A Deadline captures the wall-clock instant at which a relative timeout
--  expires, so that a single timeout can be checked and subdivided across
--  several blocking operations without re-reading the original duration.
package SSH_Lib.Deadlines is
   type Deadline is private;

   --  Construct a deadline that expires Timeout_MS milliseconds from now.
   --  @param Timeout_MS the relative timeout in milliseconds
   --  @return a deadline due Timeout_MS from the current clock
   function From_Now
     (Timeout_MS : Natural)
      return Deadline;

   --  Report whether the deadline's instant has already passed.
   --  @param Item the deadline to test
   --  @return True if the current time is at or past Item's due time
   function Expired
     (Item : Deadline)
      return Boolean;

   --  Return the time left until the deadline, clamped to zero once passed.
   --  @param Item the deadline to query
   --  @return the remaining time in milliseconds (0 if expired)
   function Remaining_MS
     (Item : Deadline)
      return Natural;

   --  Return whichever of two deadlines expires first.
   --  @param Left  the first deadline
   --  @param Right the second deadline
   --  @return the earlier-expiring of Left and Right
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
