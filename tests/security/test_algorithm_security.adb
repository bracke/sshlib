with Ada.Text_IO;
with SSH_Lib.Tests.Fixtures.Algorithm_Security;

procedure Test_Algorithm_Security is
begin
   SSH_Lib.Tests.Fixtures.Algorithm_Security.Assert_Algorithm_Negotiation_Security;
   Ada.Text_IO.Put_Line ("test_algorithm_security passed");
end Test_Algorithm_Security;
