with Ada.Command_Line;
with Ada.Directories;
with Ada.Strings.Fixed;
with Ada.Strings.Maps.Constants;
with Ada.Strings.Unbounded;
with Ada.Text_IO;

with Project_Tools.Files;

procedure Check_Security is
   use Ada.Strings.Fixed;

   Failure_Count : Natural := 0;

   procedure Fail (Message_Text : String) is
   begin
      Ada.Text_IO.Put_Line ("FAIL: " & Message_Text);
      Failure_Count := Failure_Count + 1;
   end Fail;

   function Lower (Value : String) return String is
   begin
      return Translate (Value, Ada.Strings.Maps.Constants.Lower_Case_Map);
   end Lower;

   --  Per-line scan (some needles are multi-line and must never match);
   --  Files.Line_Contains provides exactly those semantics, unlike the
   --  whole-file Files.File_Contains.
   function File_Contains (Path : String; Needle : String) return Boolean is
   begin
      return Project_Tools.Files.Line_Contains (Path, Needle);
   end File_Contains;

   procedure Require_File (Path : String) is
   begin
      if not Ada.Directories.Exists (Path) then
         Fail ("missing required file: " & Path);
      end if;
   end Require_File;

   procedure Require_Text (Path : String; Needle : String) is
   begin
      if not File_Contains (Path, Needle) then
         Fail ("missing security token in " & Path & ": " & Needle);
      end if;
   end Require_Text;

   procedure Scan_Source_File (Path : String) is
      File_Item : Ada.Text_IO.File_Type;
      Line_Number : Natural := 0;
   begin
      Ada.Text_IO.Open (File_Item, Ada.Text_IO.In_File, Path);
      while not Ada.Text_IO.End_Of_File (File_Item) loop
         declare
            Line_Text : constant String := Ada.Text_IO.Get_Line (File_Item);
            Lower_Line : constant String := Lower (Line_Text);
         begin
            Line_Number := Line_Number + 1;
            if Path /= "src/ssh_lib-sessions-live_transcript.adb"
              and then Path /= "src/ssh_lib-sessions-live_transcript.ads"
              and then Path /= "src/ssh_lib-git.adb"
              and then Path /= "src/ssh_lib-git_transport.adb"
              and then
                (Index (Lower_Line, "gnat.os_lib.spawn") /= 0
                 or else Index (Lower_Line, "non_blocking_spawn") /= 0
                 or else Index (Lower_Line, "popen") /= 0
                 or else Index (Lower_Line, "system(") /= 0
                 or else Index (Lower_Line, "/bin/sh") /= 0
                 or else Index (Lower_Line, "cmd.exe") /= 0)
            then
               Fail ("subprocess-like API in source: " & Path & ":" & Natural'Image (Line_Number));
            end if;
         end;
      end loop;
      Ada.Text_IO.Close (File_Item);
   exception
      when others =>
         if Ada.Text_IO.Is_Open (File_Item) then
            Ada.Text_IO.Close (File_Item);
         end if;
         Fail ("unable to scan source: " & Path);
   end Scan_Source_File;

   procedure Scan_Directory (Directory_Path : String) is
   begin
      --  Recursive file walk via the shared project_tools helper, applying the
      --  same .adb/.ads filter; the file set, order, and output are unchanged.
      for Path_Item of Project_Tools.Files.List_Tree (Directory_Path) loop
         declare
            Path_Text : constant String :=
              Ada.Strings.Unbounded.To_String (Path_Item);
            Name_Text : constant String :=
              Ada.Directories.Simple_Name (Path_Text);
            Lower_Name : constant String := Lower (Name_Text);
         begin
            if Lower_Name'Length >= 4
              and then (Lower_Name (Lower_Name'Last - 3 .. Lower_Name'Last) = ".adb"
                        or else Lower_Name (Lower_Name'Last - 3 .. Lower_Name'Last) = ".ads")
            then
               Scan_Source_File (Path_Text);
            end if;
         end;
      end loop;
   exception
      when others =>
         Fail ("unable to scan directory: " & Directory_Path);
   end Scan_Directory;

begin
   Require_Text ("src/ssh_lib-sessions.ads", "Verify_Known_Host    : Boolean := True");
   Require_Text ("src/ssh_lib-sessions.ads", "Strict_Host_Key      : Boolean := True");
   Require_Text ("src/ssh_lib-sessions.ads", "Use_Agent            : Boolean := True");
   Require_Text ("README.md", "Host-key verification is enabled by default.");
   Require_Text ("README.md", "Sessions.Open never invokes local ssh/git fallback implicitly");
   Require_Text ("docs/SECURITY_REVIEW.md", "Security regression tests");
   Require_Text ("docs/THREAT_MODEL.md", "Repository path is untrusted command argument data.");
   Require_Text ("src/ssh_lib-security_audit.ads", "function Status_Matrix_Status");
   Require_Text ("src/ssh_lib-security_audit.ads", "function Status_Matrix_Label");
   Require_Text ("src/ssh_lib-security_audit.ads", "type Status_Matrix_Case");
   Require_Text ("src/ssh_lib-protocol-negative_tests.ads", "type Negative_Category");
   Require_Text ("src/ssh_lib-protocol-negative_tests.ads", "function Case_Category");
   Require_Text ("src/ssh_lib-protocol-negative_tests.ads", "function Category_Label");
   Require_Text ("src/ssh_lib-protocol-negative_tests.ads", "function Is_Preservation_Case");
   Require_Text ("src/ssh_lib-protocol-negative_tests.ads", "function Is_Hostile_Case");
   Require_Text ("src/ssh_lib-protocol-negative_tests.ads", "function Invariant_Label");
   Require_Text ("src/ssh_lib-protocol-negative_tests.ads", "function Case_Invariant");
   Require_Text ("src/ssh_lib-protocol-negative_tests.ads", "type Negative_Invariant");
   Require_Text ("src/ssh_lib-protocol-negative_tests.ads", "Known_Hosts_Check_After_Invalid_Signature");
   Require_Text ("src/ssh_lib-protocol-negative_tests.ads", "Service_Request_Before_Encryption");
   Require_Text ("src/ssh_lib-protocol-negative_tests.ads", "Config_Cannot_Disable_Verify_Known_Host");
   Require_Text ("src/ssh_lib-protocol-negative_tests.ads", "Partial_Write_Dirties_Channel");
   Require_Text ("src/ssh_lib-protocol-negative_tests.ads", "Subprocess_Fallback_Disallowed");
   Require_Text ("src/ssh_lib-protocol-negative_tests.ads", "Git_Protocol_Text_Conversion_Disallowed");
   Require_Text ("src/ssh_lib-protocol-negative_tests.ads", "Mac_Failure_Dirties_Session");
   Require_Text ("src/ssh_lib-protocol-negative_tests.ads", "Timeout_Does_Not_Reset_Per_Byte");
   Require_Text ("src/ssh_lib-protocol-negative_tests.ads", "Max_Stdout_Pending_Bound");
   Require_File ("src/ssh_lib-protocol-protected_packets.ads");
   Require_File ("src/ssh_lib-protocol-protected_packets.adb");
   Require_File ("src/ssh_lib-protocol-protected_packets-test_support.ads");
   Require_File ("src/ssh_lib-protocol-protected_packets-test_support.adb");
   Require_Text ("src/ssh_lib-protocol-protected_packets.ads", "function Decode_Protected_Packet");
   Require_Text ("src/ssh_lib-protocol-protected_packets.ads", "function Is_Dirty");
   Require_Text ("src/ssh_lib-protocol-protected_packets.ads", "function Last_Failure");
   Require_Text ("tests/security/test_packet_protection_negative.adb", "Decode_Protected_Packet");
   Require_Text ("tests/security/test_packet_protection_negative.adb", "bad MAC dirties protected packet state");
   Require_Text ("tests/security/test_packet_protection_negative.adb", "wrong sequence MAC dirties protected state");
   Require_Text ("tests/security/test_packet_protection_negative.adb", "invalid padding rejected after MAC verification");
   Require_File ("tests/security/test_host_key_negative.adb");
   Require_File ("tests/src/fixtures/ssh_lib-tests-fixtures-host_key_security.ads");
   Require_File ("tests/src/fixtures/ssh_lib-tests-fixtures-host_key_security.adb");
   Require_File ("src/ssh_lib-protocol-host_key_guards.ads");
   Require_File ("src/ssh_lib-protocol-host_key_guards.adb");
   Require_Text ("src/ssh_lib-protocol-host_key_guards.ads", "Trust_After_Signature");
   Require_Text ("src/ssh_lib-protocol-host_key_guards.ads", "May_Authenticate");
   Require_Text ("tests/src/fixtures/ssh_lib-tests-fixtures-host_key_security.adb", "Assert_Host_Key_Verification_Order_And_Trust");
   Require_Text ("tests/src/fixtures/ssh_lib-tests-fixtures-host_key_security.adb", "valid signature plus absent known_hosts returns Host_Key_Unknown");
   Require_Text ("tests/src/fixtures/ssh_lib-tests-fixtures-host_key_security.adb", "valid signature plus changed known_hosts returns Host_Key_Mismatch");
   Require_Text ("tests/src/fixtures/ssh_lib-tests-fixtures-host_key_security.adb", "invalid signature is rejected before known_hosts trust");
   Require_Text ("tests/src/fixtures/ssh_lib-tests-fixtures-host_key_security.adb", "known_hosts trust is checked before authentication");
   Require_Text ("tests/security/test_host_key_negative.adb", "Assert_Host_Key_Verification_Order_And_Trust");
   Require_File ("tests/security/test_algorithm_negative.adb");
   Require_File ("tests/security/test_algorithm_security.adb");
   Require_File ("src/ssh_lib-protocol-algorithm_guards.ads"); -- Algorithm_Guards
   Require_File ("src/ssh_lib-protocol-algorithm_guards.adb");
   Require_File ("tests/src/fixtures/ssh_lib-tests-fixtures-algorithm_security.ads");
   Require_File ("tests/src/fixtures/ssh_lib-tests-fixtures-algorithm_security.adb");
   Require_Text ("src/ssh_lib-protocol-algorithm_guards.ads", "Selected_Algorithm_Accepted");
   Require_Text ("src/ssh_lib-protocol-algorithm_guards.ads", "Kex_Reply_Consistent");
   Require_Text ("src/ssh_lib-protocol-algorithm_guards.ads", "Compression_Is_None");
   Require_Text ("tests/src/fixtures/ssh_lib-tests-fixtures-algorithm_security.adb", "Assert_Algorithm_Negotiation_Security");
   Require_Text ("tests/src/fixtures/ssh_lib-tests-fixtures-algorithm_security.adb", "advertised only implemented algorithm");
   Require_Text ("tests/src/fixtures/ssh_lib-tests-fixtures-algorithm_security.adb", "client preference order is preserved");
   Require_Text ("tests/src/fixtures/ssh_lib-tests-fixtures-algorithm_security.adb", "server offers no supported KEX");
   Require_Text ("tests/src/fixtures/ssh_lib-tests-fixtures-algorithm_security.adb", "server-selected algorithm not advertised by client is rejected");
   Require_Text ("tests/src/fixtures/ssh_lib-tests-fixtures-algorithm_security.adb", "legacy ssh-rsa SHA-1 host-key signatures retained as last-resort interoperability fallback");
   Require_Text ("tests/security/test_algorithm_security.adb", "Assert_Algorithm_Negotiation_Security");
   Require_File ("tests/security/test_auth_negative.adb");
   Require_File ("tests/security/test_packet_protection_negative.adb");
   Require_File ("tests/security/test_command_quoting_negative.adb");
   Require_File ("tests/src/fixtures/ssh_lib-tests-fixtures-command_quoting.ads");
   Require_File ("tests/src/fixtures/ssh_lib-tests-fixtures-command_quoting.adb");
   Require_Text ("tests/src/fixtures/ssh_lib-tests-fixtures-command_quoting.adb", "Assert_Git_Command_Quoting_And_Validation");
   Require_Text ("tests/src/fixtures/ssh_lib-tests-fixtures-command_quoting.adb", "repository path quoted exactly for upload-pack");
   Require_Text ("tests/src/fixtures/ssh_lib-tests-fixtures-command_quoting.adb", "shell-looking repository path is quoted as data and not executed");
   Require_Text ("tests/src/fixtures/ssh_lib-tests-fixtures-command_quoting.adb", "generated command accepted by production Open_Exec");
   Require_Text ("tests/src/fixtures/ssh_lib-tests-fixtures-command_quoting.adb", "exec request command bytes are exact");
   Require_Text ("tests/src/fixtures/ssh_lib-tests-fixtures-command_quoting.adb", "quoted command would exceed Open_Exec limit");
   Require_Text ("tests/security/test_command_quoting_negative.adb", "Assert_Git_Command_Quoting_And_Validation");
   Require_Text ("tests/src/main.adb", "Run_Phase_19_Command_Quoting_Fixture_Tests");
   Require_File ("tests/security/test_binary_stream_negative.adb");
   Require_File ("tests/src/fixtures/ssh_lib-tests-fixtures-binary_matrix.ads");
   Require_File ("tests/src/fixtures/ssh_lib-tests-fixtures-binary_matrix.adb");
   Require_Text ("tests/src/fixtures/ssh_lib-tests-fixtures-binary_matrix.adb", "Assert_All_Production_Paths_Preserve");
   Require_Text ("tests/src/fixtures/ssh_lib-tests-fixtures-binary_matrix.adb", "packet framing byte path");
   Require_Text ("tests/src/fixtures/ssh_lib-tests-fixtures-binary_matrix.adb", "encrypted packet byte path");
   Require_Text ("tests/src/fixtures/ssh_lib-tests-fixtures-binary_matrix.adb", "channel Write byte path");
   Require_Text ("tests/src/fixtures/ssh_lib-tests-fixtures-binary_matrix.adb", "pending stdout first chunk");
   Require_Text ("tests/src/fixtures/ssh_lib-tests-fixtures-binary_matrix.adb", "stderr is not returned as stdout");
   Require_Text ("tests/src/fixtures/ssh_lib-tests-fixtures-binary_matrix.adb", "agent identity parser byte path");
   Require_Text ("tests/src/fixtures/ssh_lib-tests-fixtures-binary_matrix.adb", "identity-file decoded public binary field");
   Require_Text ("tests/src/fixtures/ssh_lib-tests-fixtures-binary_matrix.adb", "known-host raw key blob byte path");
   Require_Text ("tests/security/test_binary_stream_negative.adb", "Assert_All_Production_Paths_Preserve");
   Require_File ("tests/security/test_timeout_dirty_negative.adb");
   Require_File ("tests/src/fixtures/ssh_lib-tests-fixtures-timeout_dirty.ads");
   Require_File ("tests/src/fixtures/ssh_lib-tests-fixtures-timeout_dirty.adb");
   Require_Text ("tests/src/fixtures/ssh_lib-tests-fixtures-timeout_dirty.adb", "Assert_All_Timeout_And_Dirty_State_Behavior");
   Require_Text ("tests/src/fixtures/ssh_lib-tests-fixtures-timeout_dirty.adb", "silent server during channel open maps to Timeout");
   Require_Text ("tests/src/fixtures/ssh_lib-tests-fixtures-timeout_dirty.adb", "partial write timeout dirties channel");
   Require_Text ("tests/src/fixtures/ssh_lib-tests-fixtures-timeout_dirty.adb", "dirty session cannot open channel");
   Require_Text ("tests/src/fixtures/ssh_lib-tests-fixtures-timeout_dirty.adb", "failed Open_Exec leaves returned channel closed/unusable");
   Require_Text ("tests/security/test_timeout_dirty_negative.adb", "Assert_All_Timeout_And_Dirty_State_Behavior");
   Require_Text ("tests/src/main.adb", "Run_Phase_19_Timeout_Dirty_Fixture_Tests");
   Require_File ("tests/security/test_resource_bounds.adb");
   Require_File ("tests/src/fixtures/ssh_lib-tests-fixtures-resource_bounds.ads");
   Require_File ("tests/src/fixtures/ssh_lib-tests-fixtures-resource_bounds.adb");
   Require_Text ("tests/src/fixtures/ssh_lib-tests-fixtures-resource_bounds.adb", "Assert_All_Production_Bounds_Reject_Oversized_Input");
   Require_Text ("tests/src/fixtures/ssh_lib-tests-fixtures-resource_bounds.adb", "oversized SSH packet header rejected before allocation");
   Require_Text ("tests/src/fixtures/ssh_lib-tests-fixtures-resource_bounds.adb", "oversized agent message length rejected");
   Require_Text ("tests/src/fixtures/ssh_lib-tests-fixtures-resource_bounds.adb", "oversized identity file rejected before parsing");
   Require_Text ("tests/src/fixtures/ssh_lib-tests-fixtures-resource_bounds.adb", "oversized known_hosts line is ignored, not trusted");
   Require_Text ("tests/src/fixtures/ssh_lib-tests-fixtures-resource_bounds.adb", "too many open channels rejected");
   Require_Text ("tests/security/test_resource_bounds.adb", "Assert_All_Production_Bounds_Reject_Oversized_Input");
   Require_File ("tests/security/test_exception_mapping.adb");
   Require_File ("tests/src/fixtures/ssh_lib-tests-fixtures-exception_containment.ads");
   Require_File ("tests/src/fixtures/ssh_lib-tests-fixtures-exception_containment.adb");
   Require_Text ("tests/src/fixtures/ssh_lib-tests-fixtures-exception_containment.adb", "Assert_Public_Api_Exception_Boundaries");
   Require_Text ("tests/src/fixtures/ssh_lib-tests-fixtures-exception_containment.adb", "Sessions public API leaked exception");
   Require_Text ("tests/src/fixtures/ssh_lib-tests-fixtures-exception_containment.adb", "Channels public API leaked exception");
   Require_Text ("tests/src/fixtures/ssh_lib-tests-fixtures-exception_containment.adb", "file/config/remote exception containment leaked exception");
   Require_Text ("tests/security/test_exception_mapping.adb", "Assert_Public_Api_Exception_Boundaries");
   Require_File ("tests/security/test_auth_security.adb");
   Require_File ("tests/security/test_auth_malformed_inputs.adb");
   Require_File ("tests/src/fixtures/ssh_lib-tests-fixtures-auth_security.ads");
   Require_File ("tests/src/fixtures/ssh_lib-tests-fixtures-auth_security.adb");
   Require_File ("src/ssh_lib-protocol-authentication_guards.ads");
   Require_File ("src/ssh_lib-protocol-authentication_guards.adb");
   Require_Text ("src/ssh_lib-protocol-authentication_guards.ads", "Can_Start_Userauth");
   Require_Text ("src/ssh_lib-protocol-authentication_guards.ads", "Complete_Userauth");
   Require_Text ("src/ssh_lib-protocol-authentication_guards.ads", "Signature_Payloads_Match");
   Require_Text ("tests/src/fixtures/ssh_lib-tests-fixtures-auth_security.adb", "Assert_Userauth_Order_And_Signature_Payloads");
   Require_Text ("tests/src/fixtures/ssh_lib-tests-fixtures-auth_security.adb", "Assert_Malformed_Agent_And_Identity_Fixtures");
   Require_Text ("tests/src/fixtures/ssh_lib-tests-fixtures-auth_security.adb", "wrong agent signature algorithm rejected");
   Require_Text ("tests/src/fixtures/ssh_lib-tests-fixtures-auth_security.adb", "public/private key mismatch rejected");
   Require_Text ("tests/src/fixtures/ssh_lib-tests-fixtures-identity_files.adb", "Public_Private_Mismatch_OpenSSH_Private_Key");
   Require_Text ("tests/src/fixtures/ssh_lib-tests-fixtures-auth_security.adb", "userauth before encryption is rejected");
   Require_Text ("tests/src/fixtures/ssh_lib-tests-fixtures-auth_security.adb", "partial userauth success is not complete success");
   Require_Text ("tests/src/fixtures/ssh_lib-tests-fixtures-auth_security.adb", "USERAUTH_BANNER is not authentication success");
   Require_Text ("tests/src/fixtures/ssh_lib-tests-fixtures-auth_security.adb", "rekey exchange hash is rejected as wrong signature payload");
   Require_Text ("tests/security/test_auth_security.adb", "Assert_Userauth_Order_And_Signature_Payloads");
   Require_Text ("tests/security/test_auth_malformed_inputs.adb", "Assert_Malformed_Agent_And_Identity_Fixtures");
   Require_File ("tests/security/test_config_security.adb");
   Require_File ("tests/src/fixtures/ssh_lib-tests-fixtures-config_security.ads");
   Require_File ("tests/src/fixtures/ssh_lib-tests-fixtures-config_security.adb");
   Require_Text ("tests/src/fixtures/ssh_lib-tests-fixtures-config_security.adb", "Assert_Config_Is_Data_Only");
   Require_Text ("tests/src/fixtures/ssh_lib-tests-fixtures-config_security.adb", "ProxyCommand is not executed during Resolve");
   Require_Text ("tests/src/fixtures/ssh_lib-tests-fixtures-config_security.adb", "IdentityFile $HOME is not shell-expanded");
   Require_Text ("tests/src/fixtures/ssh_lib-tests-fixtures-config_security.adb", "config cannot disable Verify_Known_Host");
   Require_Text ("tests/src/fixtures/ssh_lib-tests-fixtures-config_security.adb", "HostName cannot alter repository path");
   Require_Text ("tests/security/test_config_security.adb", "Assert_Config_Is_Data_Only");
   Require_Text ("tests/src/main.adb", "Run_Phase_19_Exception_Containment_Fixture_Tests");
   Require_Text ("tests/src/main.adb", "Run_Phase_19_Config_Security_Fixture_Tests");
   Require_Text ("tests/src/main.adb", "Run_Phase_19_Auth_Security_Fixture_Tests");
   Require_Text ("tests/src/main.adb", "Run_Phase_19_Host_Key_Security_Fixture_Tests");
   Require_File ("tests/security/test_phase19_matrix_coverage.adb");
   Require_File ("tests/security/test_status_mapping_matrix.adb");
   Require_File ("tests/security/test_phase19_invariant_coverage.adb");
   Require_File ("tests/security/security_tests.gpr");
   Require_Text ("tests/security/security_tests.gpr", "test_algorithm_security.adb");
   Require_Text ("tests/security/security_tests.gpr", "test_config_security.adb");
   Require_Text ("tests/security/security_tests.gpr", "test_auth_security.adb");
   Require_Text ("tests/security/security_tests.gpr", "test_auth_malformed_inputs.adb");
   Require_Text ("tests/security/security_tests.gpr", "test_phase19_matrix_coverage.adb");
   Require_Text ("tests/security/security_tests.gpr", "test_status_mapping_matrix.adb");
   Require_Text ("tests/security/security_tests.gpr", "test_phase19_invariant_coverage.adb");
   Require_File ("tools/check_no_subprocess.adb");
   Require_Text ("tools/check_no_subprocess.adb", "Scan_Tree (""examples"")");
   Require_Text ("tools/check_no_subprocess.adb", "Scan_Tree (""tests"")");
   Require_Text ("tools/check_no_subprocess.adb", "Scan_Tree (""tools"")");
   Require_Text ("tools/check_no_subprocess.adb", "Is_Excluded_Audit_File");
   Require_Text ("tools/check_no_subprocess.adb", "Scan_String_Literals");
   Require_Text ("tools/check_no_subprocess.adb", "Contains_Call");
   Require_Text ("tools/check_no_subprocess.adb", "ssh-add");
   Require_Text ("tools/check_no_subprocess.adb", "cmd.exe");
   Require_Text ("tools/check_no_subprocess.adb", "powershell");
   Require_Text ("tools/check_no_subprocess.adb", "--self-test");
   Require_Text ("tools/check_no_subprocess.adb", "Run_Self_Tests");
   Require_Text ("tools/check_no_subprocess.adb", "Line_Has_Forbidden_Subprocess");
   Require_Text ("tools/check_no_subprocess.adb", "self-test did not block subprocess fixture");
   Require_Text ("docs/TESTING.md", "../ssh_lib_build/bin/tools/check_no_subprocess --self-test");
   Require_Text ("docs/SECURITY_REVIEW.md", "No-subprocess audit scope");
   Require_Text ("docs/SECURITY_REVIEW.md", "Release verification now treats the split security suite as mandatory");
   Require_Text ("docs/TESTING.md", "Phase 19 security release path");
   Require_Text ("docs/TESTING.md", "alr exec -- gprbuild -P tests/security/security_tests.gpr");
   Require_Text ("docs/TESTING.md", "../ssh_lib_build/bin/tests_security/test_packet_protection_negative");
   Require_Text ("docs/TESTING.md", "../ssh_lib_build/bin/tests_security/test_binary_stream_negative");
   Require_Text ("docs/TESTING.md", "../ssh_lib_build/bin/tests_security/test_resource_bounds");
   Require_Text ("docs/TESTING.md", "../ssh_lib_build/bin/tools/check_security");
   Require_Text ("docs/TESTING.md", "../ssh_lib_build/bin/tools/check_no_subprocess");
   Require_Text ("docs/TESTING.md", "../ssh_lib_build/bin/tools/check_binary_paths");
   Require_Text ("docs/TESTING.md", "../ssh_lib_build/bin/tools/check_sensitive_logging");
   Require_Text ("tools/check_sensitive_logging.adb", "Scan_Tree (""tests"")");
   Require_Text ("tools/check_sensitive_logging.adb", "Scan_Tree (""tools"")");
   Require_Text ("tools/check_sensitive_logging.adb", "Is_Excluded_Audit_Tool");
   Require_Text ("tools/check_sensitive_logging.adb", "Strip_Comment_Outside_String");
   Require_Text ("tools/check_sensitive_logging.adb", "Has_Output_Or_Log_Sink");
   Require_Text ("tools/check_sensitive_logging.adb", "Has_Explicit_Redaction");
   Require_Text ("tools/check_sensitive_logging.adb", "private_key");
   Require_Text ("tools/check_sensitive_logging.adb", "shared_secret");
   Require_Text ("tools/check_sensitive_logging.adb", "signature_payload");
   Require_Text ("tools/check_sensitive_logging.adb", "src/examples/tests/non-audit-tools scanned");
   Require_Text ("tools/check_sensitive_logging.adb", "--self-test");
   Require_Text ("tools/check_sensitive_logging.adb", "Run_Self_Tests");
   Require_Text ("tools/check_sensitive_logging.adb", "Line_Has_Sensitive_Logging");
   Require_Text ("tools/check_sensitive_logging.adb", "self-test did not block sensitive logging fixture");
   Require_Text ("docs/TESTING.md", "../ssh_lib_build/bin/tools/check_sensitive_logging --self-test");
   Require_Text ("docs/TESTING.md", "../ssh_lib_build/bin/tools/check_side_channel_assurance");
   Require_Text ("docs/SECURITY_REVIEW.md", "Audit-tool self-tests");
   Require_Text ("tests/security/README.md", "Audit-tool self-tests");
   Require_File ("PHASE_19_COMPLETENESS_PASS_23.md");
   Require_Text ("docs/SECURITY_REVIEW.md", "Sensitive logging audit scope");
   Require_Text ("docs/THREAT_MODEL.md", "Phase 19 sensitive-logging audit boundary");
   Require_Text ("tests/security/README.md", "Phase 19 Completeness Pass 20");
   Require_Text ("README.md", "Phase 19 completeness pass 20");
   Require_File ("PHASE_19_COMPLETENESS_PASS_20.md");
   Require_Text ("tests/security/README.md", "Release split runner");
   Require_Text ("tests/security/README.md", "Phase 19 completeness pass 10");
   Require_Text ("tests/security/README.md", "Phase 19 Completeness Pass 12");
   Require_Text ("tests/security/README.md", "Phase 19 Completeness Pass 13");
   Require_Text ("tests/security/README.md", "Phase 19 Completeness Pass 15");
   Require_Text ("README.md", "Phase 19 completeness pass 11");
   Require_Text ("docs/SECURITY_REVIEW.md", "Exception-containment fixture coverage");
   Require_Text ("docs/SECURITY_REVIEW.md", "Phase 19 config-security fixture depth");
   Require_Text ("docs/SECURITY_REVIEW.md", "Authentication-order fixture depth");
   Require_Text ("docs/THREAT_MODEL.md", "Phase 19 config parsing boundary fixture");
   Require_Text ("docs/THREAT_MODEL.md", "Phase 19 authentication-order fixture");
   Require_Text ("tests/security/README.md", "Exception-containment fixture coverage");
   Require_Text ("README.md", "Phase 19 completeness pass 13");
   Require_Text ("README.md", "Phase 19 completeness pass 18");
   Require_Text ("README.md", "Phase 19 completeness pass 14");
   Require_Text ("docs/TESTING.md", "../ssh_lib_build/bin/tests_security/test_algorithm_security");
   Require_Text ("docs/TESTING.md", "../ssh_lib_build/bin/tests_security/test_auth_security");
   Require_Text ("docs/TESTING.md", "../ssh_lib_build/bin/tests_security/test_auth_malformed_inputs");
   Require_Text ("docs/SECURITY_REVIEW.md", "Malformed agent and identity-file fixture depth");
   Require_Text ("docs/THREAT_MODEL.md", "Phase 19 malformed authentication-input fixture");
   Require_Text ("tests/security/README.md", "Phase 19 Completeness Pass 18");
   Require_File ("tests/security/test_fuzz_lite.adb");
   Require_File ("tests/src/fixtures/ssh_lib-tests-fixtures-fuzz_lite.ads");
   Require_File ("tests/src/fixtures/ssh_lib-tests-fixtures-fuzz_lite.adb");
   Require_Text ("tests/src/fixtures/ssh_lib-tests-fixtures-fuzz_lite.adb", "Assert_Deterministic_Malformed_Input_Sweep");
   Require_Text ("tests/src/fixtures/ssh_lib-tests-fixtures-fuzz_lite.adb", "fuzz-lite packet framing");
   Require_Text ("tests/src/fixtures/ssh_lib-tests-fixtures-fuzz_lite.adb", "fuzz-lite SSH string");
   Require_Text ("tests/src/fixtures/ssh_lib-tests-fixtures-fuzz_lite.adb", "fuzz-lite known_hosts malformed records are not trusted");
   Require_Text ("tests/src/fixtures/ssh_lib-tests-fixtures-fuzz_lite.adb", "fuzz-lite config");
   Require_Text ("tests/src/fixtures/ssh_lib-tests-fixtures-fuzz_lite.adb", "fuzz-lite agent framing");
   Require_Text ("tests/src/fixtures/ssh_lib-tests-fixtures-fuzz_lite.adb", "fuzz-lite identity-file section framing rejects malformed key");
   Require_Text ("tests/security/test_fuzz_lite.adb", "Assert_Deterministic_Malformed_Input_Sweep");
   Require_Text ("tests/security/security_tests.gpr", "test_fuzz_lite.adb");
   Require_Text ("tests/src/main.adb", "Run_Phase_19_Fuzz_Lite_Fixture_Tests");
   Require_Text ("docs/TESTING.md", "../ssh_lib_build/bin/tests_security/test_fuzz_lite");
   Require_Text ("docs/SECURITY_REVIEW.md", "Fuzz_Lite fixture depth");
   Require_Text ("docs/THREAT_MODEL.md", "Phase 19 Fuzz_Lite malformed-input fixture");
   Require_Text ("tests/security/README.md", "Phase 19 Completeness Pass 19");
   Require_File ("PHASE_19_COMPLETENESS_PASS_19.md");
   Require_File ("PHASE_19_COMPLETENESS_PASS_18.md");
   Require_File ("tests/security/test_hostile_transcripts.adb");
   Require_File ("tests/src/fixtures/ssh_lib-tests-fixtures-hostile_transcripts.ads");
   Require_File ("tests/src/fixtures/ssh_lib-tests-fixtures-hostile_transcripts.adb");
   Require_Text ("src/ssh_lib-sessions-test_support.ads", "type Hostile_Open_Transcript");
   Require_Text ("src/ssh_lib-sessions-test_support.ads", "Run_Hostile_Open_Transcript_For_Test");
   Require_Text ("src/ssh_lib-sessions-test_support.ads", "Is_Host_Trusted_For_Test");
   Require_Text ("tests/src/fixtures/ssh_lib-tests-fixtures-hostile_transcripts.adb", "Assert_Hostile_Session_Open_Transcripts");
   Require_Text ("tests/src/fixtures/ssh_lib-tests-fixtures-hostile_transcripts.adb", "malformed identification");
   Require_Text ("tests/src/fixtures/ssh_lib-tests-fixtures-hostile_transcripts.adb", "service-accept-before-encryption");
   Require_Text ("tests/src/fixtures/ssh_lib-tests-fixtures-hostile_transcripts.adb", "failed open cannot open channels");
   Require_Text ("tests/security/test_hostile_transcripts.adb", "Assert_Hostile_Session_Open_Transcripts");
   Require_Text ("tests/security/security_tests.gpr", "test_hostile_transcripts.adb");
   Require_Text ("tests/src/main.adb", "Run_Phase_19_Hostile_Transcript_Fixture_Tests");
   Require_Text ("README.md", "Phase 19 completeness pass 21");
   Require_Text ("docs/TESTING.md", "../ssh_lib_build/bin/tests_security/test_hostile_transcripts");
   Require_Text ("docs/SECURITY_REVIEW.md", "hostile session-open transcript");
   Require_Text ("docs/THREAT_MODEL.md", "Hostile transcript model");
   Require_Text ("tests/security/README.md", "test_hostile_transcripts.adb");
   Require_File ("PHASE_19_COMPLETENESS_PASS_21.md");
   Require_File ("src/ssh_lib-sessions-open_guards.ads");
   Require_File ("src/ssh_lib-sessions-open_guards.adb");
   Require_File ("tests/security/test_session_open_success_security.adb");
   Require_File ("tests/security/test_open_runtime_security.adb");
   Require_File ("tests/src/fixtures/ssh_lib-tests-fixtures-session_open_success.ads");
   Require_File ("tests/src/fixtures/ssh_lib-tests-fixtures-open_runtime.ads");
   Require_File ("tests/src/fixtures/ssh_lib-tests-fixtures-session_open_success.adb");
   Require_File ("tests/src/fixtures/ssh_lib-tests-fixtures-open_runtime.adb");
   Require_Text ("src/ssh_lib-sessions-open_guards.ads", "Open_Success_Gate");

   Require_Text ("src/ssh_lib-sessions-open_runtime.ads", "package SSH_Lib.Sessions.Open_Runtime");
   Require_Text ("src/ssh_lib-sessions-open_runtime.adb", "Required_Algorithm_Primitives_Available");
   Require_Text ("src/ssh_lib-sessions.adb", "SSH_Lib.Sessions.Open_Runtime.Run");   Require_Text ("src/ssh_lib-sessions-open_guards.ads", "Success_Gates_Complete");
   Require_Text ("src/ssh_lib-sessions-open_guards.ads", "Public_Open_State_Consistent");
   Require_Text ("src/ssh_lib-sessions.adb", "SSH_Lib.Sessions.Open_Guards.Success_Gates_Complete");
   Require_Text ("tests/src/fixtures/ssh_lib-tests-fixtures-session_open_success.adb", "Assert_Session_Open_Success_Gates");
   Require_Text ("tests/src/fixtures/ssh_lib-tests-fixtures-session_open_success.adb", "missing gate blocks Sessions.Open Ok");
   Require_Text ("tests/security/test_session_open_success_security.adb", "Assert_Session_Open_Success_Gates");
   Require_Text ("tests/security/security_tests.gpr", "test_session_open_success_security.adb");
   Require_Text ("tests/security/security_tests.gpr", "test_open_runtime_security.adb");
   Require_Text ("tests/src/main.adb", "Run_Phase_19_Session_Open_Success_Fixture_Tests");
   Require_Text ("tests/src/main.adb", "Run_Phase_19_Open_Runtime_Fixture_Tests");
   Require_Text ("README.md", "Phase 19 completeness pass 22");
   Require_Text ("docs/TESTING.md", "../ssh_lib_build/bin/tests_security/test_session_open_success_security");
   Require_Text ("docs/TESTING.md", "../ssh_lib_build/bin/tests_security/test_open_runtime_security");
   Require_Text ("docs/SECURITY_REVIEW.md", "Session.Open success-state guard");
   Require_Text ("docs/THREAT_MODEL.md", "Session open success boundary");
   Require_Text ("tests/security/README.md", "test_session_open_success_security.adb");
   Require_Text ("tests/security/README.md", "test_open_runtime_security.adb");
   Require_File ("PHASE_19_COMPLETENESS_PASS_22.md");
   Scan_Directory ("src");


   Require_File ("PHASE_19_COMPLETENESS_PASS_24.md");
   Require_File ("tests/src/fixtures/ssh_lib-tests-fixtures-version_adapter_consumption.ads");
   Require_File ("tests/src/fixtures/ssh_lib-tests-fixtures-version_adapter_consumption.adb");
   Require_File ("tests/version_integration/src/test_version_adapter_consumption.adb");
   Require_Text ("tests/src/fixtures/ssh_lib-tests-fixtures-version_adapter_consumption.adb", "Assert_Deterministic_Version_Adapter_Consumption");
   Require_Text ("tests/src/fixtures/ssh_lib-tests-fixtures-version_adapter_consumption.adb", "git-upload-pack 'repo.git'");
   Require_Text ("tests/src/fixtures/ssh_lib-tests-fixtures-version_adapter_consumption.adb", "git-receive-pack 'repo.git'");
   Require_Text ("tests/src/fixtures/ssh_lib-tests-fixtures-version_adapter_consumption.adb", "SSH_Lib.Channels.Write");
   Require_Text ("tests/src/fixtures/ssh_lib-tests-fixtures-version_adapter_consumption.adb", "SSH_Lib.Channels.Read_Some");
   Require_Text ("tests/src/fixtures/ssh_lib-tests-fixtures-version_adapter_consumption.adb", "keeps host-key verification enabled");
   Require_Text ("tests/version_integration/version_integration.gpr", "test_version_adapter_consumption.adb");
   Require_Text ("tests/version_integration/src/test_version_adapter_consumption.adb", "Assert_Deterministic_Version_Adapter_Consumption");
   Require_Text ("tests/src/main.adb", "Run_Phase_19_Version_Adapter_Consumption_Tests");
   Require_Text ("README.md", "Phase 19 completeness pass 24");
   Require_Text ("docs/TESTING.md", "test_version_adapter_consumption");
   Require_Text ("docs/VERSION_INTEGRATION.md", "Deterministic adapter consumption fixture");
   Require_Text ("docs/SECURITY_REVIEW.md", "Phase 19 completeness pass 24");
   Require_Text ("docs/THREAT_MODEL.md", "Phase 19 completeness pass 24");

   Require_File ("tools/check_compile_preflight.adb");
   Require_Text ("tools/tools.gpr", "check_compile_preflight.adb");
   Require_Text ("tools/check_compile_preflight.adb", "Phase 19 compile-preflight guard");
   Require_Text ("tools/check_compile_preflight.adb", "package body has no same-unit spec");
   Require_Text ("tools/check_compile_preflight.adb", "library source depends on test fixture");
   Require_Text ("README.md", "Phase 19 completeness pass 25");
   Require_Text ("docs/TESTING.md", "check_compile_preflight");
   Require_Text ("docs/SECURITY_REVIEW.md", "Compile preflight guard");
   Require_Text ("docs/THREAT_MODEL.md", "Phase 19 compile-preflight boundary");
   Require_Text ("tests/security/README.md", "Phase 19 Completeness Pass 25");
   Require_File ("PHASE_19_COMPLETENESS_PASS_25.md");

   Require_File ("tools/check_release_package.adb");
   Require_Text ("tools/tools.gpr", "check_release_package.adb");
   Require_Text ("tools/check_release_package.adb", "Phase 19 release-package hygiene guard");
   Require_Text ("tools/check_release_package.adb", "manual_git_upload_pack_probe.adb");
   Require_Text ("tools/check_release_package.adb", "Require_Security_Test");
   Require_Text ("README.md", "Phase 19 completeness pass 26");
   Require_Text ("README.md", "manual examples are not part of default release verification");
   Require_Text ("docs/TESTING.md", "check_release_package");
   Require_Text ("docs/SECURITY_REVIEW.md", "Release-package hygiene guard");
   Require_Text ("docs/THREAT_MODEL.md", "release-package hygiene boundary");
   Require_Text ("tests/security/README.md", "Phase 19 Completeness Pass 26");
   Require_File ("PHASE_19_COMPLETENESS_PASS_26.md");

   Require_Text ("../cryptolib/src/cryptolib-diffie_hellman.ads", "Generate_Group14_Keypair");
   Require_Text ("../cryptolib/src/cryptolib-diffie_hellman.adb", "Group14_Prime");
   Require_Text ("../cryptolib/src/cryptolib-diffie_hellman.adb", "Compute_Group14_Shared_Secret");
   Require_Text ("src/ssh_lib-rsa.adb", "Matches_PKCS1_V15_SHA256");
   Require_Text ("src/ssh_lib-rsa.adb", "DigestInfo_SHA256");
   Require_Text ("tests/src/fixtures/ssh_lib-tests-fixtures-crypto_primitives.adb", "Assert_Crypto_Primitives");
   Require_Text ("tests/src/fixtures/ssh_lib-tests-fixtures-crypto_primitives.adb", "group14 shared secrets match both directions");
   Require_Text ("tests/src/fixtures/ssh_lib-tests-fixtures-crypto_primitives.adb", "RSA SHA-256 PKCS1v15 signature verifies");
   Require_Text ("tests/security/test_crypto_primitives.adb", "Assert_Crypto_Primitives");
   Require_Text ("src/ssh_lib-algorithms.adb", "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com");
   Require_Text ("src/ssh_lib-algorithms.adb", "aes256-ctr,aes192-ctr,aes128-ctr,aes256-cbc,aes192-cbc,aes128-cbc,3des-cbc");
   Require_Text ("src/ssh_lib-algorithms.adb", "diffie-hellman-group14-sha256");
   Require_Text ("src/ssh_lib-algorithms.adb", "rsa-sha2-256");
   Require_Text ("src/ssh_lib-algorithms.adb", "rsa-sha2-512");
   Require_Text ("tests/src/fixtures/ssh_lib-tests-fixtures-algorithm_security.adb", "full implemented negotiation succeeds");
   Require_Text ("../cryptolib/src/cryptolib-ciphers.adb", "aes128-ctr");
   Require_Text ("tests/src/fixtures/ssh_lib-tests-fixtures-crypto_primitives.adb", "AES-128-CTR known-vector");
   Require_Text ("tests/security/security_tests.gpr", "test_crypto_primitives.adb");
   Require_Text ("tests/src/main.adb", "Run_Phase_19_Crypto_Primitive_Fixture_Tests");
   Require_Text ("README.md", "Phase 19 completeness pass 28");
   Require_Text ("docs/TESTING.md", "test_crypto_primitives");
   Require_Text ("docs/SECURITY_REVIEW.md", "Crypto primitive hardening fixture");
   Require_Text ("docs/THREAT_MODEL.md", "Cryptographic primitive boundary");
   Require_Text ("tests/security/README.md", "Phase 19 Completeness Pass 28");
   Require_File ("src/ssh_lib-agent-client.ads");
   Require_File ("src/ssh_lib-agent-client.adb");
   Require_Text ("src/ssh_lib-agent-transport.adb", "Unix_Socket_Address");
   Require_Text ("src/ssh_lib-agent-transport.adb", "Encode_Message_Length");
   Require_Text ("src/ssh_lib-agent-transport.adb", "Decode_Message_Length");
   Require_File ("tests/src/fixtures/ssh_lib-tests-fixtures-agent_transport.ads");
   Require_File ("tests/src/fixtures/ssh_lib-tests-fixtures-agent_transport.adb");
   Require_File ("tests/security/test_agent_transport_security.adb");
   Require_Text ("tests/security/security_tests.gpr", "test_agent_transport_security.adb");
   Require_Text ("tests/src/main.adb", "Run_Phase_19_Agent_Transport_Fixture_Tests");
   Require_Text ("README.md", "Phase 19 completeness pass 29");
   Require_Text ("docs/TESTING.md", "test_agent_transport_security");
   Require_Text ("docs/SECURITY_REVIEW.md", "Phase 19 completeness pass 29");
   Require_Text ("docs/THREAT_MODEL.md", "Phase 19 completeness pass 29");
   Require_Text ("tests/security/README.md", "Phase 19 Completeness Pass 29");
   Require_File ("PHASE_19_COMPLETENESS_PASS_29.md");
   Require_File ("tests/src/fixtures/ssh_lib-tests-fixtures-live_channel_transport.ads");
   Require_File ("tests/src/fixtures/ssh_lib-tests-fixtures-live_channel_transport.adb");
   Require_File ("tests/security/test_live_channel_transport.adb");
   Require_Text ("tests/security/security_tests.gpr", "test_live_channel_transport.adb");
   Require_Text ("tests/src/main.adb", "Run_Phase_19_Live_Channel_Transport_Fixture_Tests");
   Require_Text ("tests/src/fixtures/ssh_lib-tests-fixtures-live_channel_transport.ads", "Assert_Live_Channel_Exit_Status_And_Close");
   Require_Text ("tests/security/test_live_channel_transport.adb", "Assert_Live_Channel_Exit_Status_And_Close");
   Require_Text ("src/ssh_lib-channels.adb", "Live_Last_Protected_Outbound");
   Require_Text ("src/ssh_lib-sessions-channel_io.ads", "Send_Channel_Payload");
   Require_Text ("src/ssh_lib-sessions-userauth_io.ads", "Run_Identity_File_Userauth");
   Require_Text ("src/ssh_lib-sessions-channel_table.adb", "SSH_Lib.Sessions.Channel_IO.Send_Channel_Payload");
   Require_Text ("src/ssh_lib-channels.adb", "Live_Channel_IO_Enabled");
   Require_Text ("README.md", "Phase 19 completeness pass 30");
   Require_Text ("README.md", "Phase 19 completeness pass 40");
   Require_Text ("docs/TESTING.md", "test_live_channel_transport");
   Require_Text ("docs/SECURITY_REVIEW.md", "Phase 19 completeness pass 30");
   Require_Text ("docs/THREAT_MODEL.md", "Phase 19 completeness pass 30");
   Require_Text ("tests/security/README.md", "Phase 19 Completeness Pass 30");
   Require_File ("PHASE_19_COMPLETENESS_PASS_30.md");

   Require_File ("tools/check_release_toolchain.adb");
   Require_File ("tools/check_release_artifacts.adb");
   Require_Text ("tools/tools.gpr", "check_release_toolchain.adb");
   Require_Text ("tools/tools.gpr", "check_release_artifacts.adb");
   Require_Text ("tools/check_release_toolchain.adb", "Phase 19 release toolchain guard");
   Require_Text ("tools/check_release_artifacts.adb", "Phase 19 release artifact guard");
   Require_Text ("README.md", "Phase 19 completeness pass 31");
   Require_Text ("README.md", "../ssh_lib_build/bin/tools/check_release_toolchain");
   Require_Text ("README.md", "../ssh_lib_build/bin/tools/check_release_artifacts");
   Require_Text ("docs/TESTING.md", "check_release_toolchain");
   Require_Text ("docs/TESTING.md", "check_release_artifacts");
   Require_Text ("docs/SECURITY_REVIEW.md", "Release execution guard");
   Require_Text ("docs/THREAT_MODEL.md", "release execution boundary");
   Require_Text ("tests/security/README.md", "Phase 19 Completeness Pass 31");
   Require_File ("PHASE_19_COMPLETENESS_PASS_31.md");


   Require_File ("tools/check_release_sequence.adb");
   Require_File ("tools/check_release_runner.adb");
   Require_File ("tools/run_release_validation.adb");
   Require_Text ("tools/tools.gpr", "check_release_sequence.adb");
   Require_Text ("tools/tools.gpr", "check_release_runner.adb");
   Require_Text ("tools/tools.gpr", "run_release_validation.adb");
   Require_Text ("tools/check_release_sequence.adb", "Phase 19 release sequence guard");
   Require_Text ("tools/check_release_sequence.adb", "manual/public-network command is active");
   Require_Text ("tools/check_release_runner.adb", "release runner guard passed");
   Require_Text ("tools/check_release_runner.adb", "manual_git_upload_pack_probe");
   Require_Text ("README.md", "check_release_sequence");
   Require_Text ("README.md", "check_release_runner");
   Require_Text ("README.md", "run_release_validation");
   Require_Text ("README.md", "run_release_validation");
   Require_Text ("docs/TESTING.md", "../ssh_lib_build/bin/tools/check_release_sequence");
   Require_Text ("docs/TESTING.md", "../ssh_lib_build/bin/tools/check_release_runner");
   Require_Text ("docs/TESTING.md", "run_release_validation");
   Require_Text ("docs/TESTING.md", "run_release_validation");
   Require_Text ("docs/SECURITY_REVIEW.md", "Release sequence guard");
   Require_Text ("docs/THREAT_MODEL.md", "release sequence boundary");
   Require_Text ("tests/security/README.md", "Phase 19 Completeness Pass 32");
   Require_File ("PHASE_19_COMPLETENESS_PASS_32.md");



   Require_File ("tools/check_side_channel_assurance.adb");
   Require_File ("tools/check_phase19_context.adb");
   Require_Text ("tools/tools.gpr", "check_side_channel_assurance.adb");
   Require_Text ("tools/tools.gpr", "check_phase19_context.adb");
   Require_Text ("tools/check_phase19_context.adb", "Phase 19 initial-context compliance guard");
   Require_File ("tests/security/test_side_channel_assurance.adb");
   Require_File ("../cryptolib/src/cryptolib-constant_time_assurance.ads");
   Require_File ("../cryptolib/src/cryptolib-constant_time_assurance.adb");
   Require_File ("tests/vectors/security/SIDE_CHANNEL_ASSURANCE_MANIFEST.txt");
   Require_File ("docs/security/SIDE_CHANNEL_ASSURANCE.md");
   Require_Text ("../cryptolib/src/cryptolib-constant_time_assurance.ads", "type Crypto_Primitive");
   Require_Text ("../cryptolib/src/cryptolib-constant_time_assurance.ads", "All_Primitives_Assessed");
   Require_Text ("tests/security/test_side_channel_assurance.adb", "Assert_Side_Channel_Assurance");
   Require_Text ("tests/security/security_tests.gpr", "test_side_channel_assurance.adb");
   Require_Text ("tests/vectors/security/SIDE_CHANNEL_ASSURANCE_MANIFEST.txt", "external_review_required: true");
   Require_Text ("docs/security/SIDE_CHANNEL_ASSURANCE.md", "not an independent mathematical proof");

   Require_File ("tests/security/test_phase19_context_compliance.adb");
   Require_File ("tests/src/fixtures/ssh_lib-tests-fixtures-phase19_context.ads");
   Require_File ("tests/src/fixtures/ssh_lib-tests-fixtures-phase19_context.adb");
   Require_Text ("tests/security/security_tests.gpr", "test_phase19_context_compliance.adb");
   Require_Text ("tests/src/main.adb", "Run_Phase_19_Context_Compliance_Tests");
   Require_Text ("docs/TESTING.md", "test_phase19_context_compliance");
   Require_Text ("docs/TESTING.md", "check_phase19_context");
   Require_Text ("README.md", "Live runtime completion status");
   Require_Text ("README.md", "full live backend remains explicitly fail-closed");
   Require_Text ("docs/SECURITY_REVIEW.md", "Phase 19 completeness pass 33");
   Require_Text ("docs/THREAT_MODEL.md", "Phase 19 completeness pass 33");
   Require_Text ("tests/security/README.md", "Phase 19 completeness pass 33");
   Require_File ("docs/PHASE_19_CONTEXT_COMPLIANCE.md");
   Require_File ("PHASE_19_COMPLETENESS_PASS_33.md");
   Require_File ("PHASE_19_COMPLETENESS_PASS_34.md");
   Require_File ("PHASE_19_COMPLETENESS_PASS_35.md");
   Require_File ("PHASE_19_COMPLETENESS_PASS_36.md");
   Require_File ("PHASE_19_COMPLETENESS_PASS_37.md");
   Require_File ("PHASE_19_COMPLETENESS_PASS_38.md");
   Require_File ("PHASE_19_COMPLETENESS_PASS_39.md");
   Require_File ("src/ssh_lib-identity_files-signing_access.ads");
   Require_File ("src/ssh_lib-identity_files-signing_access.adb");
   Require_Text ("src/ssh_lib-private_key_signing.adb", "Build_Ed25519_Signature");
   Require_Text ("tests/src/main.adb", "phase39 identity-file signing produces a payload-bound signature blob");
   Require_Text ("tests/src/fixtures/ssh_lib-tests-fixtures-open_runtime.adb", "identity-file runtime authenticates through the signing backend");
   Require_Text ("src/ssh_lib-private_key_signing.ads", "Can_Sign_Userauth");
   Require_Text ("src/ssh_lib-sessions-open_runtime.adb", "identity-file runtime authenticates through the signing backend");
   Require_Text ("src/ssh_lib-keys.adb", "Max_Public_Identity_Line_Length");
   Require_Text ("tests/src/main.adb", "public identity file loads successfully");
   Require_Text ("README.md", "Phase 19 completeness pass 36");
   Require_Text ("docs/SECURITY_REVIEW.md", "completeness pass 36 public identity loading");


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

   if Failure_Count = 0 then
      Ada.Text_IO.Put_Line ("security guard passed");
   else
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
   end if;
end Check_Security;
