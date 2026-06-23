with Ada.Text_IO;
with SSH_Lib.Tests.Fixtures.Version_Adapter_Consumption;

procedure Test_Version_Adapter_Consumption is
begin
   SSH_Lib.Tests.Fixtures.Version_Adapter_Consumption.Assert_Deterministic_Version_Adapter_Consumption;
   Ada.Text_IO.Put_Line ("test_version_adapter_consumption passed");
end Test_Version_Adapter_Consumption;
