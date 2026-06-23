with Ada.Command_Line;
with Ada.Directories;
with Ada.Strings.Fixed;
with Ada.Text_IO;

procedure Check_Release_Package is
   use Ada.Strings.Fixed;

   Failure_Count : Natural := 0;

   procedure Fail (Message_Text : String) is
   begin
      Ada.Text_IO.Put_Line ("FAIL: " & Message_Text);
      Failure_Count := Failure_Count + 1;
   end Fail;

   function File_Contains (Path : String; Needle : String) return Boolean is
      File_Item : Ada.Text_IO.File_Type;
   begin
      if not Ada.Directories.Exists (Path) then
         return False;
      end if;

      Ada.Text_IO.Open (File_Item, Ada.Text_IO.In_File, Path);
      while not Ada.Text_IO.End_Of_File (File_Item) loop
         declare
            Line_Text : constant String := Ada.Text_IO.Get_Line (File_Item);
         begin
            if Index (Line_Text, Needle) /= 0 then
               Ada.Text_IO.Close (File_Item);
               return True;
            end if;
         end;
      end loop;
      Ada.Text_IO.Close (File_Item);
      return False;
   exception
      when others =>
         if Ada.Text_IO.Is_Open (File_Item) then
            Ada.Text_IO.Close (File_Item);
         end if;
         return False;
   end File_Contains;

   procedure Require_File (Path : String) is
   begin
      if not Ada.Directories.Exists (Path) then
         Fail ("missing release-package file: " & Path);
      end if;
   end Require_File;

   procedure Require_Text (Path : String; Needle : String) is
   begin
      if not File_Contains (Path, Needle) then
         Fail ("missing release-package text in " & Path & ": " & Needle);
      end if;
   end Require_Text;

   procedure Forbid_Text (Path : String; Needle : String) is
   begin
      if File_Contains (Path, Needle) then
         Fail ("stale release-package text in " & Path & ": " & Needle);
      end if;
   end Forbid_Text;

   procedure Require_Tool (Name_Text : String) is
   begin
      Require_File ("tools/" & Name_Text & ".adb");
      Require_Text ("tools/tools.gpr", Name_Text & ".adb");
      Require_Text ("docs/TESTING.md", Name_Text);
   end Require_Tool;

   procedure Require_Security_Test (Name_Text : String) is
   begin
      Require_File ("tests/security/" & Name_Text & ".adb");
      Require_Text ("tests/security/security_tests.gpr", Name_Text & ".adb");
      Require_Text ("docs/TESTING.md", Name_Text);
      Require_Text ("tests/security/README.md", Name_Text);
   end Require_Security_Test;

   procedure Require_Version_Test (Name_Text : String) is
   begin
      Require_File ("tests/version_integration/src/" & Name_Text & ".adb");
      Require_Text ("tests/version_integration/version_integration.gpr", Name_Text & ".adb");
      Require_Text ("docs/TESTING.md", Name_Text);
   end Require_Version_Test;

begin
   Require_File ("alire.toml");
   Require_File ("SSH_Lib.gpr");
   Require_File ("README.md");
   Require_File ("RELEASE_NOTES.md");
   Require_File (".gitignore");
   Require_File ("release_artifacts/README.md");

   Require_File ("docs/API.md");
   Require_File ("docs/CONFIG.md");
   Require_File ("docs/GIT_OVER_SSH.md");
   Require_File ("docs/RUNTIME_BOUNDARIES.md");
   Require_File ("docs/SECURITY.md");
   Require_File ("docs/SECURITY_REVIEW.md");
   Require_File ("docs/TESTING.md");
   Require_File ("docs/THREAT_MODEL.md");
   Require_File ("docs/VERSION_INTEGRATION.md");

   Require_File ("tests/tests.gpr");
   Require_File ("tests/security/security_tests.gpr");
   Require_File ("tests/api_stability/api_stability.gpr");
   Require_File ("tests/package_smoke/package_smoke.gpr");
   Require_File ("tests/version_integration/version_integration.gpr");
   Require_File ("tests/fuzz/fuzz_tests.gpr");
   Require_File ("examples/examples.gpr");
   Require_File ("examples/manual_examples.gpr");
   Require_File ("tools/tools.gpr");
   Require_File ("tools/run_release_validation.adb");

   Require_File ("../cryptolib/cryptolib.gpr");
   Require_File ("../cryptolib/src/cryptolib.ads");
   Require_File ("../cryptolib/src/cryptolib-errors.ads");
   Require_File ("../cryptolib/src/cryptolib-hashes.ads");
   Require_File ("../cryptolib/src/cryptolib-ciphers.ads");
   Require_File ("../cryptolib/src/cryptolib-hybrid_pq_kex.ads");
   Require_File ("src/ssh_lib-private_key_signing.ads");
   Require_File ("src/ssh_lib-rsa.ads");
   Forbid_Text ("tools/run_release_validation.adb", "tests/ssh_lib_tests.gpr");
   Forbid_Text ("docs/TESTING.md", "tests/ssh_lib_tests.gpr");
   Forbid_Text ("README.md", "tests/ssh_lib_tests.gpr");

   Require_Text ("SSH_Lib.gpr", "Library_Interface");
   Require_Text ("SSH_Lib.gpr", "SSH_Lib.File_Transfer");
   Require_Text ("SSH_Lib.gpr", "SSH_Lib.SFTP");
   Require_Text ("SSH_Lib.gpr", "SSH_Lib.Git_Transport");
   Require_Text ("tests/tests.gpr", "for Main use");
   Require_Text ("tests/tests.gpr", "main.adb");
   Require_Text ("tests/tests.gpr", "test_file_transfer_workflows.adb");
   Require_Text ("tests/security/security_tests.gpr", "test_live_proxycommand_transport.adb");
   Require_Text ("tests/version_integration/version_integration.gpr", "version_ssh_shape.adb");
   Require_Text ("tools/run_release_validation.adb", "tests/tests.gpr");

   Require_Tool ("check_public_api");
   Require_Tool ("check_package_tree");
   Require_Tool ("check_release");
   Require_Tool ("check_compile_preflight");
   Require_Tool ("check_release_manifest");
   Require_Tool ("check_release_package");
   Require_Tool ("check_release_toolchain");
   Require_Tool ("check_release_artifacts");
   Require_Tool ("check_release_sequence");
   Require_Tool ("check_release_runner");
   Require_Tool ("check_security");
   Require_Tool ("check_side_channel_assurance");
   Require_Tool ("check_formal_side_channel_proof");
   Require_Tool ("check_pq_hybrid_state");
   Require_Tool ("check_hybrid_pq_readiness");
   Require_Tool ("check_runtime_boundaries");
   Require_Tool ("check_live_git_matrix_report");
   Require_Tool ("check_live_proxycommand_report");
   Require_Tool ("check_sftp_v4_v6_interop_report");
   Require_Tool ("check_no_subprocess");
   Require_Tool ("check_binary_paths");
   Require_Tool ("check_sensitive_logging");

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

   Require_Version_Test ("version_ssh_shape");
   Require_Version_Test ("test_version_fixture");
   Require_Version_Test ("test_version_adapter_consumption");

   Require_Text ("src/ssh_lib-file_transfer.ads", "Link_Target");
   Require_Text ("src/ssh_lib-file_transfer.adb", "Create_Local_Symlink");
   Require_Text ("src/ssh_lib-file_transfer.adb", "SSH_LIB_INVENTORY" & Character'Val (9) & "3");
   Require_Text ("tests/src/test_file_transfer_workflows.adb", "restore creates local symlink from inventory target");
   Require_Text ("release_artifacts/README.md", "live_proxycommand_report.txt");
   Require_Text ("release_artifacts/README.md", "live_git_matrix_report.txt");
   Require_Text ("release_artifacts/README.md", "sftp_v4_v6_interop_report.txt");
   Require_Text ("release_artifacts/README.md", "sftp_fuzzer_seed_report.txt");
   Require_Text ("docs/TESTING.md", "release_artifacts/live_git_matrix_report.txt");
   Require_Text ("docs/TESTING.md", "release_artifacts/sftp_v4_v6_interop_report.txt");
   Require_Text ("docs/RUNTIME_BOUNDARIES.md", "release_artifacts/live_proxycommand_report.txt");

   if Failure_Count = 0 then
      Ada.Text_IO.Put_Line ("release package hygiene guard passed");
   else
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
   end if;
end Check_Release_Package;
