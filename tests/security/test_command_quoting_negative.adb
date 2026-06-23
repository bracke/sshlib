with Ada.Text_IO;
with CryptoLib.Errors;
with SSH_Lib.Protocol.Negative_Tests;
with SSH_Lib.Tests.Fixtures.Command_Quoting;

procedure Test_Command_Quoting_Negative is
   use type CryptoLib.Errors.Status;
   type Case_Array is array (Positive range <>) of SSH_Lib.Protocol.Negative_Tests.Negative_Case;

   Cases : constant Case_Array :=
     [SSH_Lib.Protocol.Negative_Tests.Repository_Path_Lf,
      SSH_Lib.Protocol.Negative_Tests.Repository_Path_Cr,
      SSH_Lib.Protocol.Negative_Tests.Repository_Path_Nul,
      SSH_Lib.Protocol.Negative_Tests.Empty_Repository_Path,
      SSH_Lib.Protocol.Negative_Tests.Oversized_Repository_Path,
      SSH_Lib.Protocol.Negative_Tests.Shell_Metacharacters_Quoted,
      SSH_Lib.Protocol.Negative_Tests.Single_Quote_Escaped,
      SSH_Lib.Protocol.Negative_Tests.Subprocess_Fallback_Disallowed,
      SSH_Lib.Protocol.Negative_Tests.Maximum_Command_Length_Exceeded];

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
   SSH_Lib.Tests.Fixtures.Command_Quoting.Assert_Git_Command_Quoting_And_Validation;
   Ada.Text_IO.Put_Line ("test_command_quoting_negative passed");
end Test_Command_Quoting_Negative;
