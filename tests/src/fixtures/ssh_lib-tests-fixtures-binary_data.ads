with Ada.Streams;

package SSH_Lib.Tests.Fixtures.Binary_Data is
   Git_Request : constant Ada.Streams.Stream_Element_Array
     (Ada.Streams.Stream_Element_Offset'(1) ..
      Ada.Streams.Stream_Element_Offset'(6)) :=
     [Ada.Streams.Stream_Element_Offset'(1) => Ada.Streams.Stream_Element'(16#00#),
      Ada.Streams.Stream_Element_Offset'(2) => Ada.Streams.Stream_Element'(16#0A#),
      Ada.Streams.Stream_Element_Offset'(3) => Ada.Streams.Stream_Element'(16#0D#),
      Ada.Streams.Stream_Element_Offset'(4) => Ada.Streams.Stream_Element'(16#7F#),
      Ada.Streams.Stream_Element_Offset'(5) => Ada.Streams.Stream_Element'(16#80#),
      Ada.Streams.Stream_Element_Offset'(6) => Ada.Streams.Stream_Element'(16#FF#)];

   Git_Response : constant Ada.Streams.Stream_Element_Array
     (Ada.Streams.Stream_Element_Offset'(1) ..
      Ada.Streams.Stream_Element_Offset'(6)) := Git_Request;

   function Same_Bytes
     (Left  : Ada.Streams.Stream_Element_Array;
      Right : Ada.Streams.Stream_Element_Array) return Boolean;

   function First_Mismatch
     (Left  : Ada.Streams.Stream_Element_Array;
      Right : Ada.Streams.Stream_Element_Array) return Natural;
end SSH_Lib.Tests.Fixtures.Binary_Data;
