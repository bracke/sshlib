with Ada.Strings.Unbounded;
with SSH_Lib.Protocol.Buffers;

package body SSH_Lib.Keys.Internal is
   use Ada.Strings.Unbounded;
   use CryptoLib.Errors;

   function Raw_Blob
     (Item : Public_Key)
      return Ada.Streams.Stream_Element_Array
   is
   begin
      return SSH_Lib.Protocol.Buffers.To_Array (Item.Blob_Data);
   end Raw_Blob;

   procedure Clear (Item : out Public_Key) is
   begin
      Item.Present := False;
      Item.Algorithm_Text := Null_Unbounded_String;
      SSH_Lib.Protocol.Buffers.Clear (Item.Blob_Data);
   end Clear;

   function Set_Public_Key
     (Item           : out Public_Key;
      Algorithm_Name : String;
      Blob           : Ada.Streams.Stream_Element_Array)
      return Status
   is
      Status_Value : Status;
   begin
      Clear (Item);
      if Algorithm_Name'Length = 0 or else Blob'Length = 0 then
         return Handshake_Failed;
      end if;

      Status_Value := SSH_Lib.Protocol.Buffers.Set (Item.Blob_Data, Blob);
      if Status_Value /= Ok then
         Clear (Item);
         return Status_Value;
      end if;

      Item.Algorithm_Text := To_Unbounded_String (Algorithm_Name);
      Item.Present := True;
      return Ok;
   exception
      when others =>
         Clear (Item);
         return Internal_Error;
   end Set_Public_Key;
end SSH_Lib.Keys.Internal;
