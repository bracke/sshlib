with Ada.Command_Line;
with Ada.Directories;
with Ada.Strings.Fixed;
with Ada.Text_IO;

procedure Check_Release_Runner is
   --  Phase 19 release runner guard.
   --  Verifies that the Ada-native release validation runner and SFTP helper
   --  runners own the deterministic build/test/audit workflows. Shell script
   --  wrappers are intentionally not part of the release surface.

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
         Fail ("missing release runner file: " & Path);
      end if;
   end Require_File;

   procedure Require_Text (Path : String; Needle : String) is
   begin
      if not File_Contains (Path, Needle) then
         Fail ("missing release runner text in " & Path & ": " & Needle);
      end if;
   end Require_Text;

begin
   Require_File ("tools/run_release_validation.adb");
   Require_File ("tools/run_sftp_fuzzer_seed_corpus.adb");
   Require_File ("tools/run_sftp_v4_v6_interop.adb");
   Require_File ("tools/check_sftp_v4_v6_interop_report.adb");
   Require_File ("tools/check_release_runner.adb");

   Require_Text ("tools/tools.gpr", "check_release_runner.adb");
   Require_Text ("tools/tools.gpr", "run_release_validation.adb");
   Require_Text ("tools/tools.gpr", "run_sftp_fuzzer_seed_corpus.adb");
   Require_Text ("tools/tools.gpr", "run_sftp_v4_v6_interop.adb");
   Require_Text ("tools/tools.gpr", "check_sftp_v4_v6_interop_report.adb");

   Require_Text ("README.md", "run_release_validation");
   Require_Text ("docs/TESTING.md", "run_release_validation");
   Require_Text ("docs/sftp.md", "run_sftp_fuzzer_seed_corpus");
   Require_Text ("docs/sftp.md", "run_sftp_v4_v6_interop");
   Require_Text ("docs/sftp.md", "check_sftp_v4_v6_interop_report");

   Require_Text ("tools/run_release_validation.adb", "GNAT.OS_Lib.Spawn");
   Require_Text ("tools/run_release_validation.adb", "--dry-run");
   Require_Text ("tools/run_release_validation.adb", "SSH_LIB_BUILD_ROOT");
   Require_Text ("tools/run_release_validation.adb", "Require_Tool (""alr"")");
   Require_Text ("tools/run_release_validation.adb", "Require_Tool (""gprbuild"")");
   Require_Text ("tools/run_release_validation.adb", "Require_Tool (""gnatmake"")");
   Require_Text ("tools/run_release_validation.adb", "Require_Tool (""gcc"")");
   Require_Text ("tools/run_release_validation.adb", "Run_Alr_Build");
   Require_Text ("tools/run_release_validation.adb", "tests/tests.gpr");
   Require_Text ("tools/run_release_validation.adb", "Test_Bin & ""/main""");
   Require_Text ("tools/run_release_validation.adb", "tests/security/security_tests.gpr");
   Require_Text ("tools/run_release_validation.adb", "test_fuzz_lite");
   Require_Text ("tools/run_release_validation.adb", "tests/version_integration/version_integration.gpr");
   Require_Text ("tools/run_release_validation.adb", "examples/examples.gpr");
   Require_Text ("tools/run_release_validation.adb", "tools/tools.gpr");
   Require_Text ("tools/run_release_validation.adb", "check_no_subprocess");
   Require_Text ("tools/run_release_validation.adb", "check_sensitive_logging");
   Require_Text ("tools/run_release_validation.adb", "--self-test");

   Require_Text ("tools/run_sftp_fuzzer_seed_corpus.adb", "SSH_LIB_SFTP_FUZZ_REPORT");
   Require_Text ("tools/run_sftp_fuzzer_seed_corpus.adb", "sftp_packet_fuzzer");
   Require_Text ("tools/run_sftp_v4_v6_interop.adb", "SSH_LIB_TEST_SFTP_V4_REQUEST_VERSIONS");
   Require_Text ("tools/run_sftp_v4_v6_interop.adb", "SSH_LIB_TEST_SFTP_V4_ENABLE");
   Require_Text ("tools/check_sftp_v4_v6_interop_report.adb", "SSH_LIB_REQUIRE_SFTP_V4_REPORT");


   if Failure_Count = 0 then
      Ada.Text_IO.Put_Line ("release runner guard passed");
   else
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
   end if;
end Check_Release_Runner;
