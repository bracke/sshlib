with AUnit.Reporter.Text;
with AUnit.Run;
with SSH_Lib.Tests.Suite;

procedure Main is
   procedure Run is new AUnit.Run.Test_Runner (SSH_Lib.Tests.Suite.Suite);
   Reporter : AUnit.Reporter.Text.Text_Reporter;
begin
   Run (Reporter);
end Main;
