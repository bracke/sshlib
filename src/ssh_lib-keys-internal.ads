with Ada.Streams;
with CryptoLib.Errors;

package SSH_Lib.Keys.Internal is
   function Raw_Blob
     (Item : Public_Key)
      return Ada.Streams.Stream_Element_Array;

   procedure Clear (Item : out Public_Key);

   function Set_Public_Key
     (Item           : out Public_Key;
      Algorithm_Name : String;
      Blob           : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;
end SSH_Lib.Keys.Internal;
