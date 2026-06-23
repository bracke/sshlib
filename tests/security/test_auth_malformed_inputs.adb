with Ada.Text_IO;
with SSH_Lib.Tests.Fixtures.Auth_Security;

procedure Test_Auth_Malformed_Inputs is
begin
   SSH_Lib.Tests.Fixtures.Auth_Security.Assert_Malformed_Agent_And_Identity_Fixtures;
   Ada.Text_IO.Put_Line ("test_auth_malformed_inputs passed");
end Test_Auth_Malformed_Inputs;
