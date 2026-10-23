with Ada.Finalization;
with Ada.Streams;

--  @summary Room for a buffer, or any one object, held on the heap and let
--  go when its holder ends however its scope ends.
--
--  A task's stack is two megabytes unless it says otherwise. The git
--  routines read a worktree file, a commit or an index entry into a buffer
--  of the largest such file -- a megabyte -- and held several in a frame,
--  up to three megabytes: past any task's stack of the default size.
--  Declared where the buffer was, the buffer renamed from it:
--
--     Data_Room : Heap_Rooms.Room (Stream_Element_Offset (Maximum_Worktree_File_Length));
--     Data      : Stream_Element_Array renames Data_Room.Data.all;
package SSH_Lib.Heap_Rooms is

   type Byte_Access is access Ada.Streams.Stream_Element_Array;

   --  Length bytes, 1 .. Length.
   type Room (Length : Ada.Streams.Stream_Element_Offset) is
     new Ada.Finalization.Limited_Controlled with record
      Data : Byte_Access;
   end record;

   overriding procedure Initialize (Item : in out Room);
   overriding procedure Finalize (Item : in out Room);

   --  Any one object so held: a mux message carries its payload's whole
   --  room, a quarter of a megabyte, and two in a frame were half of one.
   generic
      type Element is limited private;
   package Holders is
      type Element_Access is access Element;

      type Holder is new Ada.Finalization.Limited_Controlled with record
         Data : Element_Access;
      end record;

      overriding procedure Initialize (Item : in out Holder);
      overriding procedure Finalize (Item : in out Holder);
   end Holders;

end SSH_Lib.Heap_Rooms;
