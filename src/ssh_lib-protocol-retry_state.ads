with CryptoLib.Errors;

package SSH_Lib.Protocol.Retry_State is
   type Write_Attempt_State is private;

   procedure Reset
     (Item : out Write_Attempt_State);

   procedure Record_Progress
     (Item        : in out Write_Attempt_State;
      Byte_Count  : Natural);

   procedure Record_Ambiguous_Failure
     (Item : in out Write_Attempt_State);

   function Bytes_Sent
     (Item : Write_Attempt_State)
      return Natural;

   function Has_Ambiguous_Failure
     (Item : Write_Attempt_State)
      return Boolean;

   function Retry_Allowed
     (Item         : Write_Attempt_State;
      Status_Value : CryptoLib.Errors.Status)
      return Boolean;

private
   type Write_Attempt_State is record
      Sent_Count          : Natural := 0;
      Ambiguous_Failure   : Boolean := False;
   end record;
end SSH_Lib.Protocol.Retry_State;
