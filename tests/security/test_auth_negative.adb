with Ada.Text_IO;
with CryptoLib.Errors;
with SSH_Lib.Protocol.Negative_Tests;
with SSH_Lib.Tests.Fixtures.Auth_Security;

procedure Test_Auth_Negative is
   use type CryptoLib.Errors.Status;
   type Case_Array is array (Positive range <>) of SSH_Lib.Protocol.Negative_Tests.Negative_Case;

   Cases : constant Case_Array :=
     [SSH_Lib.Protocol.Negative_Tests.Service_Request_Before_Encryption,
      SSH_Lib.Protocol.Negative_Tests.Service_Accept_Before_Encryption,
      SSH_Lib.Protocol.Negative_Tests.Userauth_Before_Host_Trust,
      SSH_Lib.Protocol.Negative_Tests.Userauth_Partial_Success,
      SSH_Lib.Protocol.Negative_Tests.Userauth_Banner,
      SSH_Lib.Protocol.Negative_Tests.Cipher_Not_Active_Before_Userauth,
      SSH_Lib.Protocol.Negative_Tests.Agent_Signature_Wrong_Payload,
      SSH_Lib.Protocol.Negative_Tests.Identity_Signature_Wrong_Payload,
      SSH_Lib.Protocol.Negative_Tests.Session_Id_Not_First_Exchange_Hash,
      SSH_Lib.Protocol.Negative_Tests.Missing_Agent,
      SSH_Lib.Protocol.Negative_Tests.Agent_Connection_Failure,
      SSH_Lib.Protocol.Negative_Tests.Oversized_Agent_Response,
      SSH_Lib.Protocol.Negative_Tests.Malformed_Agent_Identity_List,
      SSH_Lib.Protocol.Negative_Tests.Malformed_Agent_Response,
      SSH_Lib.Protocol.Negative_Tests.Wrong_Agent_Signature_Algorithm,
      SSH_Lib.Protocol.Negative_Tests.Missing_Identity_File,
      SSH_Lib.Protocol.Negative_Tests.Unreadable_Identity_File,
      SSH_Lib.Protocol.Negative_Tests.Malformed_Identity_File,
      SSH_Lib.Protocol.Negative_Tests.Encrypted_Identity_File,
      SSH_Lib.Protocol.Negative_Tests.Unsupported_Private_Key_Algorithm,
      SSH_Lib.Protocol.Negative_Tests.Public_Private_Key_Mismatch,
      SSH_Lib.Protocol.Negative_Tests.Legacy_Pem_Identity_File];

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
   SSH_Lib.Tests.Fixtures.Auth_Security.Assert_Userauth_Order_And_Signature_Payloads;
   SSH_Lib.Tests.Fixtures.Auth_Security.Assert_Malformed_Agent_And_Identity_Fixtures;
   Ada.Text_IO.Put_Line ("test_auth_negative passed");
end Test_Auth_Negative;
