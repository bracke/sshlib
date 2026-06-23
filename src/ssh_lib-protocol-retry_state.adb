package body SSH_Lib.Protocol.Retry_State is
   use CryptoLib.Errors;

   procedure Reset
     (Item : out Write_Attempt_State) is
   begin
      Item.Sent_Count := 0;
      Item.Ambiguous_Failure := False;
   end Reset;

   procedure Record_Progress
     (Item        : in out Write_Attempt_State;
      Byte_Count  : Natural) is
   begin
      if Natural'Last - Item.Sent_Count < Byte_Count then
         Item.Sent_Count := Natural'Last;
      else
         Item.Sent_Count := Item.Sent_Count + Byte_Count;
      end if;
   end Record_Progress;

   procedure Record_Ambiguous_Failure
     (Item : in out Write_Attempt_State) is
   begin
      Item.Ambiguous_Failure := True;
   end Record_Ambiguous_Failure;

   function Bytes_Sent
     (Item : Write_Attempt_State)
      return Natural is
   begin
      return Item.Sent_Count;
   end Bytes_Sent;

   function Has_Ambiguous_Failure
     (Item : Write_Attempt_State)
      return Boolean is
   begin
      return Item.Ambiguous_Failure;
   exception
      when others =>
         return True;
   end Has_Ambiguous_Failure;

   function Retry_Allowed
     (Item         : Write_Attempt_State;
      Status_Value : CryptoLib.Errors.Status)
      return Boolean is
   begin
      if Status_Value = Ok then
         return False;
      end if;

      return not Item.Ambiguous_Failure
        and then Item.Sent_Count = 0
        and then Status_Value /= Timeout
        and then Status_Value /= Cancelled
        and then Status_Value /= Write_Failed;
   exception
      when others =>
         return False;
   end Retry_Allowed;
end SSH_Lib.Protocol.Retry_State;
