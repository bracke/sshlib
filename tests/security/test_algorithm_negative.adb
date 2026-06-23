with Ada.Text_IO;
with CryptoLib.Errors;
with SSH_Lib.Protocol.Negative_Tests;
with SSH_Lib.Tests.Fixtures.Algorithm_Security;

procedure Test_Algorithm_Negative is
   use type CryptoLib.Errors.Status;
   type Case_Array is array (Positive range <>) of SSH_Lib.Protocol.Negative_Tests.Negative_Case;

   Cases : constant Case_Array :=
     [SSH_Lib.Protocol.Negative_Tests.No_Supported_Kex,
      SSH_Lib.Protocol.Negative_Tests.No_Supported_Host_Key,
      SSH_Lib.Protocol.Negative_Tests.No_Supported_Cipher,
      SSH_Lib.Protocol.Negative_Tests.No_Supported_Mac,
      SSH_Lib.Protocol.Negative_Tests.Compression_Not_None,
      SSH_Lib.Protocol.Negative_Tests.Unexpected_Algorithm,
      SSH_Lib.Protocol.Negative_Tests.Inconsistent_Kex_Reply,
      SSH_Lib.Protocol.Negative_Tests.Legacy_Ssh_Rsa_Sha1,
      SSH_Lib.Protocol.Negative_Tests.Weak_Algorithm_Offered,
      SSH_Lib.Protocol.Negative_Tests.Weak_Algorithm_Not_Selected,
      SSH_Lib.Protocol.Negative_Tests.Unsupported_Selected_Algorithm];

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
   SSH_Lib.Tests.Fixtures.Algorithm_Security.Assert_Algorithm_Negotiation_Security;
   Ada.Text_IO.Put_Line ("test_algorithm_negative passed");
end Test_Algorithm_Negative;
