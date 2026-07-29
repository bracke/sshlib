with Ada.Command_Line;
with Ada.Text_IO;

with Project_Tools.Files;

procedure Check_Phase19_Context is

   Failure_Count : Natural := 0;

   procedure Fail (Message_Text : String) is
   begin
      Ada.Text_IO.Put_Line ("FAIL: " & Message_Text);
      Failure_Count := Failure_Count + 1;
   end Fail;

   --  Delegates to the shared project_tools helpers; File_Exists preserves the
   --  previous "missing file => not present" behaviour (rather than raising).
   function File_Contains (Path : String; Needle : String) return Boolean is
   begin
      return Project_Tools.Files.File_Exists (Path)
        and then Project_Tools.Files.File_Contains (Path, Needle);
   end File_Contains;

   procedure Require_File (Path : String) is
   begin
      if not Project_Tools.Files.File_Exists (Path) then
         Fail ("missing Phase 19 context file: " & Path);
      end if;
   end Require_File;

   procedure Require_Text (Path : String; Needle : String) is
   begin
      if not File_Contains (Path, Needle) then
         Fail ("missing Phase 19 context text in " & Path & ": " & Needle);
      end if;
   end Require_Text;

   procedure Require_Absent (Path : String; Needle : String) is
   begin
      if File_Contains (Path, Needle) then
         Fail ("forbidden stale Phase 19 context text in " & Path & ": " & Needle);
      end if;
   end Require_Absent;

   procedure Require_Security_Test (Base_Name : String) is
   begin
      Require_File ("tests/security/" & Base_Name & ".adb");
      Require_Text ("tests/security/security_tests.gpr", Base_Name & ".adb");
      Require_Text ("docs/TESTING.md", "../ssh_lib_build/bin/tests_security/" & Base_Name);
   end Require_Security_Test;

begin
   --  Phase 19 initial-context compliance guard.  This tool checks that the
   --  original hardening context is represented by concrete packages, tests,
   --  docs, and release-path commands.  It is intentionally a source/document
   --  guard and must not replace the real Alire/GPR/GNAT build.

   Require_File ("src/ssh_lib-security_audit.ads");
   Require_File ("src/ssh_lib-security_audit.adb");
   Require_File ("src/ssh_lib-diagnostics-redaction.ads");
   Require_File ("src/ssh_lib-diagnostics-redaction.adb");
   Require_File ("src/ssh_lib-protocol-negative_tests.ads");
   Require_File ("src/ssh_lib-protocol-negative_tests.adb");
   Require_File ("tests/src/fixtures/ssh_lib-tests-fixtures-fuzz_lite.ads");
   Require_File ("tests/src/fixtures/ssh_lib-tests-fixtures-fuzz_lite.adb");
   Require_File ("docs/SECURITY_REVIEW.md");
   Require_File ("docs/THREAT_MODEL.md");
   Require_File ("docs/PHASE_19_CONTEXT_COMPLIANCE.md");

   Require_Security_Test ("test_host_key_negative");
   Require_Security_Test ("test_algorithm_negative");
   Require_Security_Test ("test_auth_negative");
   Require_Security_Test ("test_command_quoting_negative");
   Require_Security_Test ("test_binary_stream_negative");
   Require_Security_Test ("test_timeout_dirty_negative");
   Require_Security_Test ("test_resource_bounds");
   Require_Security_Test ("test_exception_mapping");
   Require_Security_Test ("test_packet_protection_negative");
   Require_Security_Test ("test_config_security");
   Require_Security_Test ("test_fuzz_lite");
   Require_Security_Test ("test_hostile_transcripts");
   Require_Security_Test ("test_session_open_success_security");
   Require_Security_Test ("test_live_channel_transport");
   Require_Security_Test ("test_live_git_e2e");
   Require_Security_Test ("test_phase19_context_compliance");

   Require_File ("tools/check_security.adb");
   Require_File ("tools/check_no_subprocess.adb");
   Require_File ("tools/check_binary_paths.adb");
   Require_File ("tools/check_sensitive_logging.adb");
   Require_File ("tools/check_phase19_context.adb");
   Require_Text ("tools/tools.gpr", "check_phase19_context.adb");

   Require_Text ("docs/THREAT_MODEL.md", "Assets");
   Require_Text ("docs/THREAT_MODEL.md", "Trusted inputs");
   Require_Text ("docs/THREAT_MODEL.md", "Untrusted inputs");
   Require_Text ("docs/THREAT_MODEL.md", "Attacker capabilities");
   Require_Text ("docs/THREAT_MODEL.md", "Out-of-scope threats");
   Require_Text ("docs/THREAT_MODEL.md", "Security boundaries");
   Require_Text ("docs/THREAT_MODEL.md", "Host-key verification model");
   Require_Text ("docs/THREAT_MODEL.md", "Authentication model");
   Require_Text ("docs/THREAT_MODEL.md", "Git command construction model");
   Require_Text ("docs/THREAT_MODEL.md", "Binary stream model");
   Require_Text ("docs/THREAT_MODEL.md", "Failure/timeout model");
   Require_Text ("docs/THREAT_MODEL.md", "Remote SSH server traffic is untrusted until authenticated and verified.");
   Require_Text ("docs/THREAT_MODEL.md", "SSH config is local configuration input but must not execute commands.");
   Require_Text ("docs/THREAT_MODEL.md", "Channel bytes are opaque Git protocol data.");

   Require_Text ("docs/SECURITY_REVIEW.md", "Review checklist");
   Require_Text ("docs/SECURITY_REVIEW.md", "Algorithm support");
   Require_Text ("docs/SECURITY_REVIEW.md", "Host-key verification");
   Require_Text ("docs/SECURITY_REVIEW.md", "Known-host trust");
   Require_Text ("docs/SECURITY_REVIEW.md", "Authentication");
   Require_Text ("docs/SECURITY_REVIEW.md", "Command quoting");
   Require_Text ("docs/SECURITY_REVIEW.md", "Remote/config parsing");
   Require_Text ("docs/SECURITY_REVIEW.md", "Binary stream preservation");
   Require_Text ("docs/SECURITY_REVIEW.md", "Timeout and dirty-state behavior");
   Require_Text ("docs/SECURITY_REVIEW.md", "Resource bounds");
   Require_Text ("docs/SECURITY_REVIEW.md", "Unsupported features");
   Require_Text ("docs/SECURITY_REVIEW.md", "Security regression tests");

   Require_Text ("README.md", "Host-key verification is enabled by default.");
   Require_Text ("README.md", "Unknown hosts are rejected by default.");
   Require_Text ("README.md", "Changed host keys are rejected by default.");
   Require_Text ("README.md", "Sessions.Open never invokes local ssh/git fallback implicitly");
   Require_Text ("README.md", "Git protocol bytes remain opaque binary data.");
   Require_Text ("README.md", "Live runtime completion status");
   Require_Text ("README.md", "full live backend remains explicitly fail-closed");
   Require_Absent ("README.md", "- authenticated encrypted `Sessions.Open`");

   Require_Text ("docs/TESTING.md", "alr build");
   Require_Text ("docs/TESTING.md", "cd tests && alr exec -- gprbuild -P tests.gpr");
   Require_Text ("docs/TESTING.md", "cd tests && alr exec -- gprbuild -P security/security_tests.gpr");
   Require_Text ("docs/TESTING.md", "alr exec -- gprbuild -P tests/version_integration/version_integration.gpr");
   Require_Text ("docs/TESTING.md", "alr exec -- gprbuild -P examples/examples.gpr");
   Require_Text ("docs/TESTING.md", "alr exec -- gprbuild -P tools/tools.gpr");
   Require_Text ("docs/TESTING.md", "../ssh_lib_build/bin/tools/check_phase19_context");
   Require_Text ("docs/TESTING.md", "../ssh_lib_build/bin/tools/check_no_subprocess --self-test");
   Require_Text ("docs/TESTING.md", "../ssh_lib_build/bin/tools/check_sensitive_logging --self-test");

   Require_Text ("tests/src/main.adb", "Run_Phase_19_Security_Audit_Tests");
   Require_Text ("tests/src/main.adb", "Run_Phase_19_Fuzz_Lite_Fixture_Tests");
   Require_Text ("tests/src/main.adb", "Run_Phase_19_Session_Open_Success_Fixture_Tests");
   Require_Text ("tests/src/main.adb", "Run_Phase_19_Open_Runtime_Fixture_Tests");
   Require_Text ("tests/src/main.adb", "Run_Phase_19_Live_Channel_Transport_Fixture_Tests");
   Require_Text ("tests/src/main.adb", "Run_Phase_19_Context_Compliance_Tests");

   Require_File ("PHASE_19_COMPLETENESS_PASS_33.md");
   Require_File ("PHASE_19_COMPLETENESS_PASS_34.md");
   Require_File ("PHASE_19_COMPLETENESS_PASS_35.md");

   Require_File ("tools/check_runtime_boundaries.adb");
   Require_File ("docs/RUNTIME_BOUNDARIES.md");
   Require_File ("src/ssh_lib-sessions-userauth_io.ads");
   Require_File ("src/ssh_lib-sessions-userauth_io.adb");
   Require_File ("src/ssh_lib-sessions-live_transport.ads");
   Require_File ("src/ssh_lib-sessions-live_transport.adb");
   Require_File ("src/ssh_lib-sessions-live_attachment.ads");
   Require_File ("src/ssh_lib-sessions-live_attachment.adb");
   Require_File ("src/ssh_lib-protocol-userauth-agent_identity.ads");
   Require_File ("src/ssh_lib-protocol-userauth-agent_identity.adb");
   Require_Text ("tools/tools.gpr", "check_runtime_boundaries.adb");
   Require_Text ("tools/check_runtime_boundaries.adb", "runtime boundary guard passed");
   Require_Text ("README.md", "Phase 19 completeness pass 42");
   Require_Text ("README.md", "Phase 19 completeness pass 43");
   Require_Text ("README.md", "Phase 19 completeness pass 44");
   Require_Text ("docs/TESTING.md", "check_runtime_boundaries");
   Require_Text ("docs/TESTING.md", "SSH_LIB_LIVE_GIT_E2E=1");
   Require_Text ("docs/TESTING.md", "Phase 19 completeness pass 43");
   Require_Text ("docs/TESTING.md", "Phase 19 completeness pass 44");
   Require_Text ("docs/SECURITY_REVIEW.md", "Runtime boundary inventory");
   Require_Text ("docs/SECURITY_REVIEW.md", "Phase 19 completeness pass 44");
   Require_Text ("docs/THREAT_MODEL.md", "runtime boundary inventory");
   Require_Text ("docs/THREAT_MODEL.md", "Phase 19 completeness pass 44");
   Require_Text ("tests/security/README.md", "Phase 19 completeness pass 42");
   Require_File ("PHASE_19_COMPLETENESS_PASS_42.md");
   Require_File ("PHASE_19_COMPLETENESS_PASS_43.md");
   Require_File ("PHASE_19_COMPLETENESS_PASS_44.md");
   Require_File ("PHASE_19_COMPLETENESS_PASS_49.md");
   Require_File ("PHASE_19_COMPLETENESS_PASS_71.md");

   if Failure_Count = 0 then
      Ada.Text_IO.Put_Line ("phase19 initial-context compliance guard passed");
   else
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
   end if;
end Check_Phase19_Context;
