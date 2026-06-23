with Ada.Text_IO;
with SSH_Lib.Tests.Fixtures.Config_Security;

procedure Test_Config_Security is
begin
   SSH_Lib.Tests.Fixtures.Config_Security.Assert_Config_Is_Data_Only;
   Ada.Text_IO.Put_Line ("test_config_security passed");
end Test_Config_Security;
