with Ada.Text_IO;
with SSH_Lib.Tests.Fixtures.Auth_Security;

procedure Test_Auth_Security is
begin
   SSH_Lib.Tests.Fixtures.Auth_Security.Assert_Userauth_Order_And_Signature_Payloads;
   SSH_Lib.Tests.Fixtures.Auth_Security.Assert_Malformed_Agent_And_Identity_Fixtures;
   SSH_Lib.Tests.Fixtures.Auth_Security.Assert_Password_Change_Request_Fails_Closed;
   SSH_Lib.Tests.Fixtures.Auth_Security.Assert_None_Userauth_Request_Encodes;
   Ada.Text_IO.Put_Line ("test_auth_security passed");
end Test_Auth_Security;
