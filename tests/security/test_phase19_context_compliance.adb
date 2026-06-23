with Ada.Text_IO;
with SSH_Lib.Tests.Fixtures.Phase19_Context;

procedure Test_Phase19_Context_Compliance is
begin
   SSH_Lib.Tests.Fixtures.Phase19_Context.Assert_Initial_Context_Coverage;
   Ada.Text_IO.Put_Line ("test_phase19_context_compliance passed");
end Test_Phase19_Context_Compliance;
