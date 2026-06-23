with Ada.Text_IO;
with CryptoLib.Errors;
with SSH_Lib.Protocol.Negative_Tests;
with SSH_Lib.Tests.Fixtures.Host_Key_Security;

procedure Test_Host_Key_Negative is
   use type CryptoLib.Errors.Status;
   type Case_Array is array (Positive range <>) of SSH_Lib.Protocol.Negative_Tests.Negative_Case;

   Cases : constant Case_Array :=
     [SSH_Lib.Protocol.Negative_Tests.Host_Absent_From_Known_Hosts,
      SSH_Lib.Protocol.Negative_Tests.Host_Key_Mismatch,
      SSH_Lib.Protocol.Negative_Tests.Invalid_Host_Key_Signature,
      SSH_Lib.Protocol.Negative_Tests.Unsupported_Known_Host_Key_Type,
      SSH_Lib.Protocol.Negative_Tests.Malformed_Known_Hosts_Line,
      SSH_Lib.Protocol.Negative_Tests.Hashed_Known_Hosts_Entry,
      SSH_Lib.Protocol.Negative_Tests.Wildcard_Known_Hosts_Entry,
      SSH_Lib.Protocol.Negative_Tests.Nonstandard_Port_Not_Trusted_By_Bare_Host,
      SSH_Lib.Protocol.Negative_Tests.Host_Port_Mismatch,
      SSH_Lib.Protocol.Negative_Tests.Known_Hosts_Check_After_Invalid_Signature,
      SSH_Lib.Protocol.Negative_Tests.Host_Key_Verification_Disabled_Bypass];

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

   SSH_Lib.Tests.Fixtures.Host_Key_Security.Assert_Host_Key_Verification_Order_And_Trust;

   Ada.Text_IO.Put_Line ("test_host_key_negative passed");
end Test_Host_Key_Negative;
