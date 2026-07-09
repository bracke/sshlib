with Ada.Command_Line;
with Ada.Directories;
with Ada.Text_IO;

with Project_Tools.Files;

procedure Check_Release_Sequence is
   --  Phase 19 release sequence guard.
   --  This guard does not spawn commands. It verifies that the documented
   --  deterministic release command sequence is complete, ordered, and keeps
   --  manual/public-network examples outside the default automated path.

   Failure_Count : Natural := 0;
   Last_Line     : Natural := 0;

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

   function Active_Text (Line_Text : String) return String is
   begin
      if Line_Text'Length = 0 then
         return "";
      elsif Line_Text (Line_Text'First) = '#' then
         return "";
      else
         return Line_Text;
      end if;
   end Active_Text;

   function Active_Line_Number (Path : String; Needle : String) return Natural is
      File_Item   : Ada.Text_IO.File_Type;
      Line_Number : Natural := 0;
   begin
      if not Ada.Directories.Exists (Path) then
         return 0;
      end if;

      Ada.Text_IO.Open (File_Item, Ada.Text_IO.In_File, Path);
      while not Ada.Text_IO.End_Of_File (File_Item) loop
         declare
            Line_Text : constant String := Ada.Text_IO.Get_Line (File_Item);
         begin
            Line_Number := Line_Number + 1;
            if Active_Text (Line_Text) = Needle then
               Ada.Text_IO.Close (File_Item);
               return Line_Number;
            end if;
         end;
      end loop;
      Ada.Text_IO.Close (File_Item);
      return 0;
   exception
      when others =>
         if Ada.Text_IO.Is_Open (File_Item) then
            Ada.Text_IO.Close (File_Item);
         end if;
         return 0;
   end Active_Line_Number;

   procedure Require_File (Path : String) is
   begin
      if not Ada.Directories.Exists (Path) then
         Fail ("missing release sequence file: " & Path);
      end if;
   end Require_File;

   procedure Require_Text (Path : String; Needle : String) is
   begin
      if not File_Contains (Path, Needle) then
         Fail ("missing release sequence text in " & Path & ": " & Needle);
      end if;
   end Require_Text;

   procedure Require_Command_After (Needle : String) is
      Line_Number : constant Natural := Active_Line_Number ("docs/TESTING.md", Needle);
   begin
      if Line_Number = 0 then
         Fail ("missing active release command: " & Needle);
      elsif Line_Number <= Last_Line then
         Fail ("release command is out of order: " & Needle);
      else
         Last_Line := Line_Number;
      end if;
   end Require_Command_After;

   procedure Require_Manual_Command_Commented (Needle : String) is
      Active_Line : constant Natural := Active_Line_Number ("docs/TESTING.md", Needle);
   begin
      if Active_Line /= 0 then
         Fail ("manual/public-network command is active in default release path: " & Needle);
      elsif not File_Contains ("docs/TESTING.md", "# " & Needle) then
         Fail ("manual/public-network command is not documented as commented optional: " & Needle);
      end if;
   end Require_Manual_Command_Commented;

begin
   Require_File ("README.md");
   Require_File ("docs/TESTING.md");
   Require_File ("tools/tools.gpr");
   Require_File ("tools/check_release_sequence.adb");
   Require_File ("tools/check_release_runner.adb");
   Require_File ("tools/run_release_validation.adb");

   Require_Text ("tools/tools.gpr", "check_release_sequence.adb");
   Require_Text ("tools/tools.gpr", "check_release_runner.adb");
   Require_Text ("tools/tools.gpr", "run_release_validation.adb");
   Require_Text ("tools/tools.gpr", "check_runtime_boundaries.adb");
   Require_Text ("tools/tools.gpr", "check_live_git_matrix_report.adb");
   Require_Text ("tools/tools.gpr", "check_live_proxycommand_report.adb");
   Require_Text ("docs/TESTING.md", "run_release_validation");
   Require_Text ("docs/TESTING.md", "run_release_validation");
   Require_Text ("README.md", "check_release_sequence");
   Require_Text ("docs/SECURITY_REVIEW.md", "Release sequence guard");
   Require_Text ("docs/THREAT_MODEL.md", "release sequence boundary");

   Require_Command_After ("alr build");
   Require_Command_After ("cd tests && alr exec -- gprbuild -P tests.gpr");
   Require_Command_After ("../ssh_lib_build/bin/tests/main");
   Require_Command_After ("cd tests && alr exec -- gprbuild -P security/security_tests.gpr");

   Require_Command_After ("../ssh_lib_build/bin/tests_security/test_host_key_negative");
   Require_Command_After ("../ssh_lib_build/bin/tests_security/test_algorithm_negative");
   Require_Command_After ("../ssh_lib_build/bin/tests_security/test_algorithm_security");
   Require_Command_After ("../ssh_lib_build/bin/tests_security/test_crypto_primitives");
   Require_Command_After ("../ssh_lib_build/bin/tests_security/test_pq_external_kats");
   Require_Command_After ("../ssh_lib_build/bin/tests_security/test_hybrid_pq_readiness");
   Require_Command_After ("../ssh_lib_build/bin/tests_security/test_hybrid_pq_openssh_transcripts");
   Require_Command_After ("../ssh_lib_build/bin/tests_security/test_side_channel_assurance");
   Require_Command_After ("../ssh_lib_build/bin/tests_security/test_auth_negative");
   Require_Command_After ("../ssh_lib_build/bin/tests_security/test_packet_protection_negative");
   Require_Command_After ("../ssh_lib_build/bin/tests_security/test_command_quoting_negative");
   Require_Command_After ("../ssh_lib_build/bin/tests_security/test_binary_stream_negative");
   Require_Command_After ("../ssh_lib_build/bin/tests_security/test_timeout_dirty_negative");
   Require_Command_After ("../ssh_lib_build/bin/tests_security/test_resource_bounds");
   Require_Command_After ("../ssh_lib_build/bin/tests_security/test_exception_mapping");
   Require_Command_After ("../ssh_lib_build/bin/tests_security/test_config_security");
   Require_Command_After ("../ssh_lib_build/bin/tests_security/test_auth_security");
   Require_Command_After ("../ssh_lib_build/bin/tests_security/test_auth_malformed_inputs");
   Require_Command_After ("../ssh_lib_build/bin/tests_security/test_agent_transport_security");
   Require_Command_After ("../ssh_lib_build/bin/tests_security/test_live_channel_transport");
   Require_Command_After ("../ssh_lib_build/bin/tests_security/test_live_git_e2e");
   Require_Command_After ("../ssh_lib_build/bin/tests_security/test_live_git_interop_matrix");
   Require_Command_After ("../ssh_lib_build/bin/tests_security/test_live_proxyjump_transport");
   Require_Command_After ("../ssh_lib_build/bin/tests_security/test_live_rekey_transport");
   Require_Command_After ("../ssh_lib_build/bin/tests_security/test_transport_messages");
   Require_Command_After ("../ssh_lib_build/bin/tests_security/test_fuzz_lite");
   Require_Command_After ("../ssh_lib_build/bin/tests_security/test_hostile_transcripts");
   Require_Command_After ("../ssh_lib_build/bin/tests_security/test_session_open_success_security");
   Require_Command_After ("../ssh_lib_build/bin/tests_security/test_open_runtime_security");
   Require_Command_After ("../ssh_lib_build/bin/tests_security/test_phase19_matrix_coverage");
   Require_Command_After ("../ssh_lib_build/bin/tests_security/test_phase19_invariant_coverage");
   Require_Command_After ("../ssh_lib_build/bin/tests_security/test_status_mapping_matrix");
   Require_Command_After ("../ssh_lib_build/bin/tests_security/test_phase19_context_compliance");
   Require_Command_After ("alr exec -- gprbuild -P tests/api_stability/api_stability.gpr");
   Require_Command_After ("alr exec -- gprbuild -P tests/package_smoke/package_smoke.gpr");
   Require_Command_After ("alr exec -- gprbuild -P tests/version_integration/version_integration.gpr");
   Require_Command_After ("../ssh_lib_build/bin/version_integration/test_version_adapter_consumption");
   Require_Command_After ("alr exec -- gprbuild -P examples/examples.gpr");

   Require_Manual_Command_Commented ("alr exec -- gprbuild -P examples/manual_examples.gpr");

   Require_Command_After ("alr exec -- gprbuild -P tools/tools.gpr");
   Require_Command_After ("../ssh_lib_build/bin/tools/check_release_toolchain");
   Require_Command_After ("../ssh_lib_build/bin/tools/check_release_artifacts");
   Require_Command_After ("../ssh_lib_build/bin/tools/check_release_sequence");
   Require_Command_After ("../ssh_lib_build/bin/tools/check_release_runner");
   Require_Command_After ("../ssh_lib_build/bin/tools/check_public_api");
   Require_Command_After ("../ssh_lib_build/bin/tools/check_package_tree");
   Require_Command_After ("../ssh_lib_build/bin/tools/check_release");
   Require_Command_After ("../ssh_lib_build/bin/tools/check_compile_preflight");
   Require_Command_After ("../ssh_lib_build/bin/tools/check_phase17_regressions");
   Require_Command_After ("../ssh_lib_build/bin/tools/check_release_manifest");
   Require_Command_After ("../ssh_lib_build/bin/tools/check_release_package");
   Require_Command_After ("../ssh_lib_build/bin/tools/check_security");
   Require_Command_After ("../ssh_lib_build/bin/tools/check_side_channel_assurance");
   Require_Command_After ("../ssh_lib_build/bin/tools/check_formal_side_channel_proof");
   Require_Command_After ("../ssh_lib_build/bin/tools/check_pq_hybrid_state");
   Require_Command_After ("../ssh_lib_build/bin/tools/check_hybrid_pq_readiness");
   Require_Command_After ("../ssh_lib_build/bin/tools/check_phase19_context");
   Require_Command_After ("../ssh_lib_build/bin/tools/check_runtime_boundaries");
   Require_Command_After ("../ssh_lib_build/bin/tools/check_live_git_matrix_report");
   Require_Command_After ("../ssh_lib_build/bin/tools/check_live_proxycommand_report");
   Require_Command_After ("../ssh_lib_build/bin/tools/check_binary_paths");
   Require_Command_After ("../ssh_lib_build/bin/tools/check_no_subprocess --self-test");
   Require_Command_After ("../ssh_lib_build/bin/tools/check_no_subprocess");
   Require_Command_After ("../ssh_lib_build/bin/tools/check_sensitive_logging --self-test");
   Require_Command_After ("../ssh_lib_build/bin/tools/check_sensitive_logging");

   if Failure_Count = 0 then
      Ada.Text_IO.Put_Line ("release sequence guard passed");
   else
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
   end if;
end Check_Release_Sequence;
