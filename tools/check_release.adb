with Ada.Command_Line;
with Ada.Directories;
with Ada.Strings.Fixed;
with Ada.Strings.Maps.Constants;
with Ada.Strings.Unbounded;
with Ada.Text_IO;

with Project_Tools.Files;

procedure Check_Release is
   use Ada.Strings.Fixed;

   Failure_Count : Natural := 0;

   procedure Fail (Message_Text : String) is
   begin
      Ada.Text_IO.Put_Line ("FAIL: " & Message_Text);
      Failure_Count := Failure_Count + 1;
   end Fail;

   function Lower (Value : String) return String is
   begin
      return Ada.Strings.Fixed.Translate
        (Value, Ada.Strings.Maps.Constants.Lower_Case_Map);
   end Lower;

   function Has_Suffix (Value : String; Suffix : String) return Boolean is
   begin
      return Value'Length >= Suffix'Length
        and then Value (Value'Last - Suffix'Length + 1 .. Value'Last) = Suffix;
   end Has_Suffix;

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
         Fail ("missing release file: " & Path);
      end if;
   end Require_File;

   procedure Require_Text (Path : String; Needle : String) is
   begin
      if not File_Contains (Path, Needle) then
         Fail ("missing required release text in " & Path & ": " & Needle);
      end if;
   end Require_Text;

   procedure Forbid_Text (Path : String; Needle : String) is
   begin
      if File_Contains (Path, Needle) then
         Fail ("stale release text in " & Path & ": " & Needle);
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
   end Require_Security_Test;

   function Is_C_Source (Name_Text : String) return Boolean is
      Lower_Name : constant String := Lower (Name_Text);
   begin
      return Has_Suffix (Lower_Name, ".c")
        or else Has_Suffix (Lower_Name, ".h")
        or else Has_Suffix (Lower_Name, ".cc")
        or else Has_Suffix (Lower_Name, ".cpp")
        or else Has_Suffix (Lower_Name, ".cxx");
   end Is_C_Source;

   function Is_Allowed_Generated_C_Header (Path : String) return Boolean is
      Lower_Path : constant String := Lower (Path);
   begin
      return Has_Suffix (Lower_Path, "/config/ssh_lib_config.h")
        or else Has_Suffix (Lower_Path, "/tests/config/tests_config.h");
   end Is_Allowed_Generated_C_Header;

   function Is_Explicit_Subprocess_Boundary_File (Path : String) return Boolean is
      Lower_Path : constant String := Lower (Path);
   begin
      return Has_Suffix (Lower_Path, "/src/ssh_lib-sessions-live_transcript.adb")
        or else Has_Suffix (Lower_Path, "/src/ssh_lib-sessions-live_transcript.ads")
        or else Has_Suffix (Lower_Path, "/src/ssh_lib-git.adb");
   end Is_Explicit_Subprocess_Boundary_File;

   function Contains_Subprocess_Text (Line_Text : String) return Boolean is
      Lower_Line : constant String := Lower (Line_Text);
   begin
      return Index (Lower_Line, "gnat.os_lib.spawn") /= 0
        or else Index (Lower_Line, "non_blocking_spawn") /= 0
        or else Index (Lower_Line, "popen") /= 0
        or else Index (Lower_Line, "system(") /= 0
        or else Index (Lower_Line, "gnat.expect") /= 0
        or else Index (Lower_Line, "create_process") /= 0
        or else Index (Lower_Line, "execve") /= 0
        or else Index (Lower_Line, "cmd.exe") /= 0
        or else Index (Lower_Line, "local_exec") /= 0;
   end Contains_Subprocess_Text;

   procedure Scan_Source_File (Path : String) is
      File_Item : Ada.Text_IO.File_Type;
   begin
      Ada.Text_IO.Open (File_Item, Ada.Text_IO.In_File, Path);
      while not Ada.Text_IO.End_Of_File (File_Item) loop
         declare
            Line_Text : constant String := Ada.Text_IO.Get_Line (File_Item);
         begin
            if (Index (Path, "/src/") /= 0 or else Index (Path, "/examples/") /= 0)
              and then not Is_Explicit_Subprocess_Boundary_File (Path)
              and then Contains_Subprocess_Text (Line_Text)
            then
               Fail ("library/example source mentions subprocess execution: " & Path);
            end if;
         end;
      end loop;
      Ada.Text_IO.Close (File_Item);
   exception
      when others =>
         if Ada.Text_IO.Is_Open (File_Item) then
            Ada.Text_IO.Close (File_Item);
         end if;
         Fail ("unable to scan source file: " & Path);
   end Scan_Source_File;

   Skip_Dirs : constant Project_Tools.Files.Name_List :=
     [Ada.Strings.Unbounded.To_Unbounded_String (".git"),
      Ada.Strings.Unbounded.To_Unbounded_String ("obj"),
      Ada.Strings.Unbounded.To_Unbounded_String ("bin"),
      Ada.Strings.Unbounded.To_Unbounded_String ("alire"),
      Ada.Strings.Unbounded.To_Unbounded_String ("release_artifacts")];

   procedure Scan_Source_Tree (Directory_Path : String) is
   begin
      --  Recursive file walk via the shared project_tools helper (skipping the
      --  same build/VCS directories); the file set, order, and output match the
      --  previous hand-rolled Ada.Directories recursion.
      for Path_Item of
        Project_Tools.Files.List_Tree (Directory_Path, "*", Skip_Dirs)
      loop
         declare
            Full_Path : constant String :=
              Ada.Strings.Unbounded.To_String (Path_Item);
            Name_Text : constant String :=
              Ada.Directories.Simple_Name (Full_Path);
         begin
            if Is_C_Source (Name_Text)
              and then not Is_Allowed_Generated_C_Header (Full_Path)
            then
               Fail ("C or C-family source is not allowed: " & Full_Path);
            end if;

            if Has_Suffix (Lower (Name_Text), ".adb")
              or else Has_Suffix (Lower (Name_Text), ".ads")
            then
               Scan_Source_File (Full_Path);
            end if;
         end;
      end loop;
   exception
      when others =>
         Fail ("unable to scan source tree: " & Directory_Path);
   end Scan_Source_Tree;

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
   Require_File ("examples/examples.gpr");
   Require_File ("examples/manual_examples.gpr");
   Require_File ("tools/tools.gpr");
   Require_File ("tools/run_release_validation.adb");

   Require_File ("../cryptolib/cryptolib.gpr");
   Require_File ("../cryptolib/src/cryptolib-ciphers.adb");
   Require_File ("../cryptolib/src/cryptolib-diffie_hellman.ads");
   Require_File ("../cryptolib/src/cryptolib-hashes.adb");
   Require_File ("../cryptolib/src/cryptolib-hybrid_pq_kex.ads");
   Require_File ("src/ssh_lib-private_key_signing.adb");
   Require_File ("src/ssh_lib-rsa.adb");
   Require_Text ("../cryptolib/src/cryptolib-ciphers.adb", "aes128-ctr");
   Require_Text ("../cryptolib/src/cryptolib-diffie_hellman.ads", "Generate_Group14_Keypair");
   Require_Text ("../cryptolib/src/cryptolib-hybrid_pq_kex.ads", "Readiness_Of");
   Require_Text ("src/ssh_lib-private_key_signing.adb", "Build_Ed25519_Signature");
   Require_Text ("src/ssh_lib-rsa.adb", "Matches_PKCS1_V15_SHA256");

   Forbid_Text ("tools/run_release_validation.adb", "tests/ssh_lib_tests.gpr");
   Forbid_Text ("docs/TESTING.md", "tests/ssh_lib_tests.gpr");
   Forbid_Text ("README.md", "tests/ssh_lib_tests.gpr");

   Require_Text ("SSH_Lib.gpr", "Library_Interface");
   Require_Text ("tests/tests.gpr", "test_file_transfer_workflows.adb");
   Require_Text ("tools/run_release_validation.adb", "tests/tests.gpr");
   Require_Text ("src/ssh_lib-file_transfer.ads", "Link_Target");
   Require_Text ("src/ssh_lib-file_transfer.adb", "Create_Local_Symlink");
   Require_Text ("tests/src/test_file_transfer_workflows.adb", "restore creates local symlink from inventory target");
   Require_Text ("release_artifacts/README.md", "live_proxycommand_report.txt");
   Require_Text ("release_artifacts/README.md", "live_git_matrix_report.txt");
   Require_Text ("release_artifacts/README.md", "sftp_v4_v6_interop_report.txt");
   Require_Text ("release_artifacts/README.md", "sftp_fuzzer_seed_report.txt");

   Require_Tool ("check_release_toolchain");
   Require_Tool ("check_release_artifacts");
   Require_Tool ("check_release_sequence");
   Require_Tool ("check_release_runner");
   Require_Tool ("check_public_api");
   Require_Tool ("check_package_tree");
   Require_Tool ("check_release");
   Require_Tool ("check_compile_preflight");
   Require_Tool ("check_release_manifest");
   Require_Tool ("check_release_package");
   Require_Tool ("check_security");
   Require_Tool ("check_side_channel_assurance");
   Require_Tool ("check_formal_side_channel_proof");
   Require_Tool ("check_pq_hybrid_state");
   Require_Tool ("check_hybrid_pq_readiness");
   Require_Tool ("check_runtime_boundaries");
   Require_Tool ("check_live_git_matrix_report");
   Require_Tool ("check_live_proxycommand_report");
   Require_Tool ("check_sftp_v4_v6_interop_report");
   Require_Tool ("check_binary_paths");
   Require_Tool ("check_no_subprocess");
   Require_Tool ("check_sensitive_logging");

   Require_Security_Test ("test_host_key_negative");
   Require_Security_Test ("test_algorithm_negative");
   Require_Security_Test ("test_algorithm_security");
   Require_Security_Test ("test_crypto_primitives");
   Require_Security_Test ("test_live_proxycommand_transport");
   Require_Security_Test ("test_live_git_interop_matrix");
   Require_Security_Test ("test_live_proxyjump_transport");
   Require_Security_Test ("test_fuzz_lite");
   Require_Security_Test ("test_phase19_context_compliance");

   Scan_Source_Tree ("src");
   Scan_Source_Tree ("examples");
   Scan_Source_Tree ("tests/src");
   Scan_Source_Tree ("tests/security");
   Scan_Source_Tree ("tools");

   if Failure_Count = 0 then
      Ada.Text_IO.Put_Line ("release guard passed");
   else
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
   end if;
end Check_Release;
