with Ada.Text_IO;
with SSH_Lib.Tests.Fixtures.PQ_External_KATs;

procedure Test_PQ_External_KATs is
begin
   SSH_Lib.Tests.Fixtures.PQ_External_KATs.Assert_PQ_External_KATs;
   Ada.Text_IO.Put_Line ("test_pq_external_kats passed");
end Test_PQ_External_KATs;
