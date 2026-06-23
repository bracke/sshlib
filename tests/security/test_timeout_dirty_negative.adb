with Ada.Text_IO;
with CryptoLib.Errors;
with SSH_Lib.Protocol.Negative_Tests;
with SSH_Lib.Tests.Fixtures.Timeout_Dirty;

procedure Test_Timeout_Dirty_Negative is
   use type CryptoLib.Errors.Status;
   type Case_Array is array (Positive range <>) of SSH_Lib.Protocol.Negative_Tests.Negative_Case;

   Cases : constant Case_Array :=
     [SSH_Lib.Protocol.Negative_Tests.Timeout_Identification,
      SSH_Lib.Protocol.Negative_Tests.Timeout_Kex,
      SSH_Lib.Protocol.Negative_Tests.Timeout_Auth,
      SSH_Lib.Protocol.Negative_Tests.Timeout_Channel_Open,
      SSH_Lib.Protocol.Negative_Tests.Timeout_Channel_Read,
      SSH_Lib.Protocol.Negative_Tests.Timeout_Window_Write,
      SSH_Lib.Protocol.Negative_Tests.Partial_Write_Socket_Failure,
      SSH_Lib.Protocol.Negative_Tests.Partial_Write_Dirties_Channel,
      SSH_Lib.Protocol.Negative_Tests.Dirty_Session_Cannot_Open_Channel,
      SSH_Lib.Protocol.Negative_Tests.Dirty_Channel_Cannot_Write,
      SSH_Lib.Protocol.Negative_Tests.Close_After_Dirty_State,
      SSH_Lib.Protocol.Negative_Tests.Partial_Write_Timeout,
      SSH_Lib.Protocol.Negative_Tests.Retry_After_Dirty_Write,
      SSH_Lib.Protocol.Negative_Tests.Timeout_Does_Not_Reset_Per_Byte,
      SSH_Lib.Protocol.Negative_Tests.Partial_Write_No_Ok,
      SSH_Lib.Protocol.Negative_Tests.Failed_Open_Leaves_Session_Closed];

   procedure Check_Case
     (Case_Item : SSH_Lib.Protocol.Negative_Tests.Negative_Case)
   is
      Actual : constant CryptoLib.Errors.Status :=
        SSH_Lib.Protocol.Negative_Tests.Expected_Status (Case_Item);
   begin
      if SSH_Lib.Protocol.Negative_Tests.Is_Preservation_Case (Case_Item) then
         if Actual /= CryptoLib.Errors.Ok then
            Ada.Text_IO.Put_Line
              ("FAILED preservation: "
               & SSH_Lib.Protocol.Negative_Tests.Case_Label (Case_Item));
            raise Program_Error;
         end if;
      elsif Actual = CryptoLib.Errors.Ok
        or else Actual = CryptoLib.Errors.End_Of_Stream
        or else Actual = CryptoLib.Errors.Cancelled
        or else Actual = CryptoLib.Errors.Remote_Exit_Nonzero
      then
         Ada.Text_IO.Put_Line
           ("FAILED failure mapping: "
            & SSH_Lib.Protocol.Negative_Tests.Case_Label (Case_Item));
         raise Program_Error;
      end if;
   end Check_Case;
begin
   for Case_Item of Cases loop
      Check_Case (Case_Item);
   end loop;
   SSH_Lib.Tests.Fixtures.Timeout_Dirty.Assert_All_Timeout_And_Dirty_State_Behavior;
   Ada.Text_IO.Put_Line ("test_timeout_dirty_negative passed");
end Test_Timeout_Dirty_Negative;
