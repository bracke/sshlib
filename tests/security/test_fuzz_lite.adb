with Ada.Text_IO;
with SSH_Lib.Tests.Fixtures.Fuzz_Lite;

procedure Test_Fuzz_Lite is
begin
   SSH_Lib.Tests.Fixtures.Fuzz_Lite.Assert_Deterministic_Malformed_Input_Sweep;
   Ada.Text_IO.Put_Line ("test_fuzz_lite passed");
end Test_Fuzz_Lite;
