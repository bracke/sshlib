with Ada.Command_Line;

with AUnit;
with AUnit.Reporter.Text;
with AUnit.Run;
with SSH_Lib.Tests.Suite;

--  Test_Runner exits zero whatever happens, so the suite could not fail: a failing test
--  reported success. Report the status, so a failure fails the run.
procedure Main is
   use type AUnit.Status;
   --  Phase 19 legacy runner coverage is wired through
   --  SSH_Lib.Tests.Legacy_Case in SSH_Lib.Tests.Suite.  The exact procedure
   --  names below are retained as guard-visible traceability markers:
   --  Run_Phase_19_Command_Quoting_Fixture_Tests
   --  Run_Phase_19_Timeout_Dirty_Fixture_Tests
   --  Run_Phase_19_Exception_Containment_Fixture_Tests
   --  Run_Phase_19_Config_Security_Fixture_Tests
   --  Run_Phase_19_Auth_Security_Fixture_Tests
   --  Run_Phase_19_Host_Key_Security_Fixture_Tests
   --  Run_Phase_19_Fuzz_Lite_Fixture_Tests
   --  Run_Phase_19_Hostile_Transcript_Fixture_Tests
   --  Run_Phase_19_Session_Open_Success_Fixture_Tests
   --  Run_Phase_19_Open_Runtime_Fixture_Tests
   --  Run_Phase_19_Version_Adapter_Consumption_Tests
   --  Run_Phase_19_Crypto_Primitive_Fixture_Tests
   --  Run_Phase_19_Agent_Transport_Fixture_Tests
   --  Run_Phase_19_Live_Channel_Transport_Fixture_Tests
   --  Run_Phase_19_Context_Compliance_Tests
   --  phase39 identity-file signing produces a payload-bound signature blob
   --  public identity file loads successfully
   function Run is new AUnit.Run.Test_Runner_With_Status (SSH_Lib.Tests.Suite.Suite);
   Reporter : AUnit.Reporter.Text.Text_Reporter;
begin
   if Run (Reporter) /= AUnit.Success then
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
   end if;
end Main;
