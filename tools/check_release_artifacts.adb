with Ada.Command_Line;
with Ada.Text_IO;

with Project_Tools.Files;

procedure Check_Release_Artifacts is
   Failure_Count : Natural := 0;

   procedure Fail (Message_Text : String) is
   begin
      Ada.Text_IO.Put_Line ("FAIL: " & Message_Text);
      Failure_Count := Failure_Count + 1;
   end Fail;

   --  Delegates to the shared project_tools helper; Files.Exists matches the
   --  previous Ada.Directories.Exists any-entry semantics.
   function Exists_Executable (Path : String) return Boolean is
   begin
      return Project_Tools.Files.Exists (Path)
        or else Project_Tools.Files.Exists (Path & ".exe");
   end Exists_Executable;

   procedure Require_Executable (Path : String) is
   begin
      if not Exists_Executable (Path) then
         Fail ("missing built release executable: " & Path);
      end if;
   end Require_Executable;

   procedure Require_Executable_One_Of (Primary_Path : String; Fallback_Path : String) is
   begin
      if not Exists_Executable (Primary_Path)
        and then not Exists_Executable (Fallback_Path)
      then
         Fail
           ("missing built release executable: " & Primary_Path
            & " or " & Fallback_Path);
      end if;
   end Require_Executable_One_Of;

   procedure Require_Tool (Name_Text : String) is
   begin
      Require_Executable ("../ssh_lib_build/bin/tools/" & Name_Text);
   end Require_Tool;

   procedure Require_Security_Test (Name_Text : String) is
   begin
      Require_Executable ("../ssh_lib_build/bin/tests_security/" & Name_Text);
   end Require_Security_Test;

begin
   Ada.Text_IO.Put_Line ("Phase 19 release artifact guard");
   Ada.Text_IO.Put_Line ("Run this after all release gprbuild commands and before accepting the release run.");

   Require_Executable_One_Of ("../ssh_lib_build/bin/tests/main", "tests/bin/main");
   Require_Executable ("../ssh_lib_build/bin/api_stability/api_stability_main");
   Require_Executable ("../ssh_lib_build/bin/package_smoke/package_smoke_main");
   Require_Executable ("../ssh_lib_build/bin/version_integration/version_ssh_shape");
   Require_Executable ("../ssh_lib_build/bin/version_integration/test_version_fixture");
   Require_Executable ("../ssh_lib_build/bin/version_integration/test_version_adapter_consumption");
   Require_Executable ("../ssh_lib_build/bin/examples/git_remote_prepare");
   Require_Executable ("../ssh_lib_build/bin/examples/git_remote_resolve");
   Require_Executable ("../ssh_lib_build/bin/examples/git_command_quote");
   Require_Executable ("../ssh_lib_build/bin/examples/local_fixture_upload_pack");

   Require_Security_Test ("test_host_key_negative");
   Require_Security_Test ("test_algorithm_negative");
   Require_Security_Test ("test_algorithm_security");
   Require_Security_Test ("test_crypto_primitives");
   Require_Security_Test ("test_pq_external_kats");
   Require_Security_Test ("test_hybrid_pq_readiness");
   Require_Security_Test ("test_hybrid_pq_openssh_transcripts");
   Require_Security_Test ("test_side_channel_assurance");
   Require_Security_Test ("test_auth_negative");
   Require_Security_Test ("test_packet_protection_negative");
   Require_Security_Test ("test_command_quoting_negative");
   Require_Security_Test ("test_binary_stream_negative");
   Require_Security_Test ("test_timeout_dirty_negative");
   Require_Security_Test ("test_resource_bounds");
   Require_Security_Test ("test_exception_mapping");
   Require_Security_Test ("test_config_security");
   Require_Security_Test ("test_auth_security");
   Require_Security_Test ("test_auth_malformed_inputs");
   Require_Security_Test ("test_agent_transport_security");
   Require_Security_Test ("test_live_channel_transport");
   Require_Security_Test ("test_live_git_e2e");
   Require_Security_Test ("test_live_git_interop_matrix");
   Require_Security_Test ("test_live_proxyjump_transport");
   Require_Security_Test ("test_live_proxycommand_transport");
   Require_Security_Test ("test_live_rekey_transport");
   Require_Security_Test ("test_transport_messages");
   Require_Security_Test ("test_fuzz_lite");
   Require_Security_Test ("test_hostile_transcripts");
   Require_Security_Test ("test_session_open_success_security");
   Require_Security_Test ("test_open_runtime_security");
   Require_Security_Test ("test_phase19_matrix_coverage");
   Require_Security_Test ("test_phase19_invariant_coverage");
   Require_Security_Test ("test_status_mapping_matrix");
   Require_Security_Test ("test_phase19_context_compliance");

   Require_Tool ("check_release_toolchain");
   Require_Tool ("check_release_artifacts");
   Require_Tool ("check_release_sequence");
   Require_Tool ("check_release_runner");
   Require_Tool ("check_public_api");
   Require_Tool ("check_package_tree");
   Require_Tool ("check_release");
   Require_Tool ("check_compile_preflight");
   Require_Tool ("check_phase17_regressions");
   Require_Tool ("check_release_manifest");
   Require_Tool ("check_release_package");
   Require_Tool ("check_security");
   Require_Tool ("check_side_channel_assurance");
   Require_Tool ("check_formal_side_channel_proof");
   Require_Tool ("check_pq_hybrid_state");
   Require_Tool ("check_hybrid_pq_readiness");
   Require_Tool ("check_phase19_context");
   Require_Tool ("check_runtime_boundaries");
   Require_Tool ("check_live_git_matrix_report");
   Require_Tool ("check_live_proxycommand_report");
   Require_Tool ("check_sftp_v4_v6_interop_report");
   Require_Tool ("check_binary_paths");
   Require_Tool ("check_no_subprocess");
   Require_Tool ("check_sensitive_logging");


   if Failure_Count = 0 then
      Ada.Text_IO.Put_Line ("release artifact guard passed");
   else
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
   end if;
end Check_Release_Artifacts;
