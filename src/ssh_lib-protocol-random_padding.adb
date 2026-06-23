with CryptoLib.Random;

package body SSH_Lib.Protocol.Random_Padding is
   use type CryptoLib.Errors.Status;
   Source_Item : CryptoLib.Random.Random_Source;
   Initialized : Boolean := False;

   procedure Ensure_Initialized is
   begin
      if not Initialized then
         CryptoLib.Random.Initialize_Production (Source_Item);
         Initialized := True;
      end if;
   end Ensure_Initialized;

   function Next_Byte
     (Value : out Ada.Streams.Stream_Element)
      return CryptoLib.Errors.Status
   is
      Buffer : Ada.Streams.Stream_Element_Array (1 .. 1);
      Status_Value : CryptoLib.Errors.Status;
   begin
      Ensure_Initialized;
      Status_Value := CryptoLib.Random.Fill (Source_Item, Buffer);
      if Status_Value /= CryptoLib.Errors.Ok then
         Value := 0;
         return Status_Value;
      end if;

      Value := Buffer (Buffer'First);
      return CryptoLib.Errors.Ok;
   exception
      when others =>
         Value := 0;
         return CryptoLib.Errors.Internal_Error;
   end Next_Byte;
end SSH_Lib.Protocol.Random_Padding;
