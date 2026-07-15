with Ada.Command_Line;

with AUnit;
with AUnit.Reporter.Text;
with AUnit.Run;
with AUnit.Test_Suites;

with SSH_Lib.Tests.Fixtures.SFTP_Fake_Subsystem;

--  Report the status, so a failing test fails the run rather than exiting zero.
procedure Test_SFTP_Fake_Subsystem is
   use type AUnit.Status;
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

   function Run is new AUnit.Run.Test_Runner_With_Status (Suite);
   Reporter : AUnit.Reporter.Text.Text_Reporter;
begin
   if Run (Reporter) /= AUnit.Success then
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
   end if;
end Test_SFTP_Fake_Subsystem;
