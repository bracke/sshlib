with SSH_Lib.Tests.Legacy_Case;
with SSH_Lib.Tests.Fixtures.SFTP_Fake_Subsystem;

package body SSH_Lib.Tests.Suite is
   type Legacy_Case_Access is access all SSH_Lib.Tests.Legacy_Case.Test_Case;
   type SFTP_Fake_Subsystem_Access is
     access all SSH_Lib.Tests.Fixtures.SFTP_Fake_Subsystem.Test_Case;

   function Suite return AUnit.Test_Suites.Access_Test_Suite is
      Result : constant AUnit.Test_Suites.Access_Test_Suite :=
        AUnit.Test_Suites.New_Suite;
   begin
      declare
         SFTP_Test : constant SFTP_Fake_Subsystem_Access :=
           new SSH_Lib.Tests.Fixtures.SFTP_Fake_Subsystem.Test_Case;
      begin
         AUnit.Test_Suites.Add_Test (Result, SFTP_Test);
      end;

      declare
         Legacy_Test : constant Legacy_Case_Access :=
           new SSH_Lib.Tests.Legacy_Case.Test_Case;
      begin
         AUnit.Test_Suites.Add_Test (Result, Legacy_Test);
      end;
      return Result;
   end Suite;
end SSH_Lib.Tests.Suite;
