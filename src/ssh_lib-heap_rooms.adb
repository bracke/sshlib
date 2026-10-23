with Ada.Unchecked_Deallocation;

package body SSH_Lib.Heap_Rooms is

   procedure Free is new Ada.Unchecked_Deallocation (Ada.Streams.Stream_Element_Array, Byte_Access);

   overriding procedure Initialize (Item : in out Room) is
   begin
      Item.Data := new Ada.Streams.Stream_Element_Array (1 .. Item.Length);
   end Initialize;

   overriding procedure Finalize (Item : in out Room) is
   begin
      Free (Item.Data);
   end Finalize;

   package body Holders is
      procedure Free is new Ada.Unchecked_Deallocation (Element, Element_Access);

      overriding procedure Initialize (Item : in out Holder) is
      begin
         Item.Data := new Element;
      end Initialize;

      overriding procedure Finalize (Item : in out Holder) is
      begin
         Free (Item.Data);
      end Finalize;
   end Holders;

end SSH_Lib.Heap_Rooms;
