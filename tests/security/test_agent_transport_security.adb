with Ada.Text_IO;
with SSH_Lib.Tests.Fixtures.Agent_Transport;

procedure Test_Agent_Transport_Security is
begin
   SSH_Lib.Tests.Fixtures.Agent_Transport.Assert_Agent_Transport_And_Client_Boundaries;
   Ada.Text_IO.Put_Line ("test_agent_transport_security passed");
end Test_Agent_Transport_Security;
