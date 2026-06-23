package body SSH_Lib.Deadlines is
   use Ada.Calendar;

   function From_Now
     (Timeout_MS : Natural)
      return Deadline
   is
      Now_Value : constant Time := Clock;
   begin
      if Timeout_MS = 0 then
         return (Due_Time => Now_Value, Immediate_Deadline => True);
      else
         return
           (Due_Time => Now_Value + Duration (Long_Float (Timeout_MS) / 1000.0),
            Immediate_Deadline => False);
      end if;
   exception
      when others =>
         return (Due_Time => Clock, Immediate_Deadline => True);
   end From_Now;

   function Expired
     (Item : Deadline)
      return Boolean
   is
   begin
      return Item.Immediate_Deadline or else Clock >= Item.Due_Time;
   exception
      when others =>
         return True;
   end Expired;

   function Remaining_MS
     (Item : Deadline)
      return Natural
   is
      Remaining_Duration : Duration;
      Remaining_Value    : Long_Float;
   begin
      if Item.Immediate_Deadline then
         return 0;
      end if;

      Remaining_Duration := Item.Due_Time - Clock;
      if Remaining_Duration <= 0.0 then
         return 0;
      end if;

      Remaining_Value := Long_Float (Remaining_Duration) * 1000.0;
      if Remaining_Value >= Long_Float (Natural'Last) then
         return Natural'Last;
      elsif Remaining_Value <= 0.0 then
         return 0;
      else
         return Natural (Remaining_Value);
      end if;
   exception
      when others =>
         return 0;
   end Remaining_MS;

   function Minimum
     (Left  : Deadline;
      Right : Deadline)
      return Deadline
   is
   begin
      if Left.Immediate_Deadline then
         return Left;
      elsif Right.Immediate_Deadline then
         return Right;
      elsif Left.Due_Time <= Right.Due_Time then
         return Left;
      else
         return Right;
      end if;
   exception
      when others =>
         return From_Now (0);
   end Minimum;
end SSH_Lib.Deadlines;
