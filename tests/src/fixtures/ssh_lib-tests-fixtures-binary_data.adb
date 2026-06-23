package body SSH_Lib.Tests.Fixtures.Binary_Data is

   use type Ada.Streams.Stream_Element;
   use type Ada.Streams.Stream_Element_Offset;
   function Same_Bytes
     (Left  : Ada.Streams.Stream_Element_Array;
      Right : Ada.Streams.Stream_Element_Array) return Boolean
   is
      Right_Index : Ada.Streams.Stream_Element_Offset;
   begin
      if Left'Length /= Right'Length then
         return False;
      end if;

      Right_Index := Right'First;
      for Left_Index in Left'Range loop
         if Left (Left_Index) /= Right (Right_Index) then
            return False;
         end if;
         Right_Index := Right_Index + 1;
      end loop;
      return True;
   end Same_Bytes;

   function First_Mismatch
     (Left  : Ada.Streams.Stream_Element_Array;
      Right : Ada.Streams.Stream_Element_Array) return Natural
   is
      Right_Index : Ada.Streams.Stream_Element_Offset := Right'First;
      Offset      : Natural := 0;
   begin
      if Left'Length = 0 or else Right'Length = 0 then
         if Left'Length = Right'Length then
            return 0;
         else
            return 1;
         end if;
      end if;

      for Left_Index in Left'Range loop
         if Right_Index > Right'Last then
            return Offset + 1;
         end if;
         if Left (Left_Index) /= Right (Right_Index) then
            return Offset + 1;
         end if;
         Right_Index := Right_Index + 1;
         Offset := Offset + 1;
      end loop;

      if Right_Index <= Right'Last then
         return Offset + 1;
      end if;
      return 0;
   end First_Mismatch;
end SSH_Lib.Tests.Fixtures.Binary_Data;
