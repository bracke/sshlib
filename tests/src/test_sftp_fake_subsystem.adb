with AUnit.Reporter.Text;
with AUnit.Run;
with AUnit.Test_Suites;

with SSH_Lib.Tests.Fixtures.SFTP_Fake_Subsystem;

procedure Test_SFTP_Fake_Subsystem is
   type SFTP_Fake_Subsystem_Access is
     access all SSH_Lib.Tests.Fixtures.SFTP_Fake_Subsystem.Test_Case;

   function Suite return AUnit.Test_Suites.Access_Test_Suite is
      Result : constant AUnit.Test_Suites.Access_Test_Suite :=
        AUnit.Test_Suites.New_Suite;
      Test   : constant SFTP_Fake_Subsystem_Access :=
        new SSH_Lib.Tests.Fixtures.SFTP_Fake_Subsystem.Test_Case;
   begin
      AUnit.Test_Suites.Add_Test (Result, Test);
      return Result;
   end Suite;

   procedure Run is new AUnit.Run.Test_Runner (Suite);
   Reporter : AUnit.Reporter.Text.Text_Reporter;
begin
   Run (Reporter);
end Test_SFTP_Fake_Subsystem;
