
package body SSH_Lib.Agent is
   use Ada.Strings.Unbounded;
   use CryptoLib.Errors;
   use SSH_Lib.Protocol.Buffers;

   procedure Clear (Item : out Identity_List) is
   begin
      Item.Item_Count := 0;
      for Index_Value in Item.Items'Range loop
         SSH_Lib.Protocol.Buffers.Clear (Item.Items (Index_Value).Key_Blob);
         Item.Items (Index_Value).Comment := Null_Unbounded_String;
      end loop;
   end Clear;

   function Count (Item : Identity_List) return Natural is
   begin
      return Item.Item_Count;
   end Count;

   function Add_Identity
     (Item     : in out Identity_List;
      Key_Blob : Ada.Streams.Stream_Element_Array;
      Comment  : String)
      return Status
   is
      Status_Value : Status;
   begin
      if Item.Item_Count >= Max_Identities then
         return Authentication_Failed;
      end if;

      if Key_Blob'Length > Max_Public_Key_Blob
        or else Comment'Length > Max_Comment_Length
      then
         return Authentication_Failed;
      end if;

      Status_Value := Set (Item.Items (Item.Item_Count + 1).Key_Blob, Key_Blob);
      if Status_Value /= Ok then
         return Authentication_Failed;
      end if;

      Item.Items (Item.Item_Count + 1).Comment := To_Unbounded_String (Comment);
      Item.Item_Count := Item.Item_Count + 1;
      return Ok;
   exception
      when others =>
         return Internal_Error;
   end Add_Identity;

   function Public_Key_Blob
     (Item  : Identity_List;
      Index : Positive)
      return Ada.Streams.Stream_Element_Array
   is
   begin
      if Index > Item.Item_Count then
         return Empty : Ada.Streams.Stream_Element_Array (1 .. 0) do
            null;
         end return;
      end if;

      return To_Array (Item.Items (Index).Key_Blob);
   end Public_Key_Blob;

   function Comment
     (Item  : Identity_List;
      Index : Positive)
      return String
   is
   begin
      if Index > Item.Item_Count then
         return "";
      end if;

      return To_String (Item.Items (Index).Comment);
   end Comment;
end SSH_Lib.Agent;
