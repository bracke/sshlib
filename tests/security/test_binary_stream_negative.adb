with Ada.Text_IO;
with CryptoLib.Errors;
with SSH_Lib.Protocol.Negative_Tests;
with SSH_Lib.Tests.Fixtures.Binary_Matrix;

procedure Test_Binary_Stream_Negative is
   use type CryptoLib.Errors.Status;
   type Case_Array is array (Positive range <>) of SSH_Lib.Protocol.Negative_Tests.Negative_Case;

   Cases : constant Case_Array :=
     [SSH_Lib.Protocol.Negative_Tests.Binary_Nul_Preserved,
      SSH_Lib.Protocol.Negative_Tests.Binary_Cr_Lf_Preserved,
      SSH_Lib.Protocol.Negative_Tests.Binary_High_Bytes_Preserved,
      SSH_Lib.Protocol.Negative_Tests.Binary_Write_Exact,
      SSH_Lib.Protocol.Negative_Tests.Git_Protocol_Text_Conversion_Disallowed,
      SSH_Lib.Protocol.Negative_Tests.Queued_Data_Before_Eof,
      SSH_Lib.Protocol.Negative_Tests.Stderr_Not_Returned_As_Stdout];

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
   SSH_Lib.Tests.Fixtures.Binary_Matrix.Assert_All_Production_Paths_Preserve;
   Ada.Text_IO.Put_Line ("test_binary_stream_negative passed");
end Test_Binary_Stream_Negative;
