with Ada.Text_IO;
with SSH_Lib.Tests.Fixtures.Side_Channel_Assurance;

procedure Test_Side_Channel_Assurance is
begin
   SSH_Lib.Tests.Fixtures.Side_Channel_Assurance.Assert_Side_Channel_Assurance;
   Ada.Text_IO.Put_Line ("test_side_channel_assurance passed");
end Test_Side_Channel_Assurance;
