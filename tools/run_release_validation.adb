with Ada.Command_Line;
with Ada.Directories;
with Ada.Environment_Variables;
with Ada.Strings.Fixed;
with Ada.Strings.Unbounded;
with Ada.Text_IO;
with GNAT.OS_Lib;
with GNAT.Strings;

with Project_Tools.Processes;

procedure Run_Release_Validation is
   --   Ada-native release validation runner.
   --
   --   This executable intentionally runs the deterministic build, test, and
   --   audit sequence without invoking a shell. It fails closed when the
   --   GNAT/Alire toolchain or any expected built executable is missing.
   --   Opt-in public-network live tests remain controlled by their own
   --   environment gates and are not enabled by this runner.

   use Ada.Strings.Unbounded;
   use type GNAT.Strings.String_Access;

   Failure_Count : Natural := 0;
   Dry_Run       : Boolean := False;

   Build_Root : constant String :=
     (if Ada.Environment_Variables.Exists ("SSH_LIB_BUILD_ROOT")
      then Ada.Environment_Variables.Value ("SSH_LIB_BUILD_ROOT")
      else "../ssh_lib_build");

   Test_Bin     : constant String := "tests/bin";
   Security_Bin : constant String := Build_Root & "/bin/tests_security";
   Version_Bin  : constant String := Build_Root & "/bin/version_integration";
   Tools_Bin    : constant String := Build_Root & "/bin/tools";

   procedure Fail (Message_Text : String) is
   begin
      Ada.Text_IO.Put_Line ("FAIL: " & Message_Text);
      Failure_Count := Failure_Count + 1;
   end Fail;

   function Exists_Executable (Path : String) return Boolean is
   begin
      return Ada.Directories.Exists (Path)
        or else Ada.Directories.Exists (Path & ".exe");
   end Exists_Executable;

   function Join_Path (Directory_Text : String; Name_Text : String) return String is
   begin
      if Directory_Text'Length = 0 then
         return Name_Text;
      elsif Directory_Text (Directory_Text'Last) = '/'
        or else Directory_Text (Directory_Text'Last) = '\'
      then
         return Directory_Text & Name_Text;
      else
         return Directory_Text & "/" & Name_Text;
      end if;
   end Join_Path;

   function Find_In_Path (Program_Name : String) return Boolean is
      Path_Text : constant String :=
        (if Ada.Environment_Variables.Exists ("PATH")
         then Ada.Environment_Variables.Value ("PATH")
         else "");
      Start_Index : Positive := Path_Text'First;
      Stop_Index  : Natural;
   begin
      if Exists_Executable (Program_Name) then
         return True;
      end if;

      if Path_Text'Length = 0 then
         return False;
      end if;

      while Start_Index <= Path_Text'Last loop
         Stop_Index := Start_Index;
         while Stop_Index <= Path_Text'Last
           and then Path_Text (Stop_Index) /= ':'
           and then Path_Text (Stop_Index) /= ';'
         loop
            Stop_Index := Stop_Index + 1;
         end loop;

         declare
            Directory_Text : constant String :=
              Path_Text (Start_Index .. Stop_Index - 1);
         begin
            if Directory_Text'Length > 0
              and then Exists_Executable (Join_Path (Directory_Text, Program_Name))
            then
               return True;
            end if;
         end;

         Start_Index := Stop_Index + 1;
      end loop;

      return False;
   end Find_In_Path;

   procedure Require_Tool (Program_Name : String) is
   begin
      if not Find_In_Path (Program_Name) then
         Fail ("required release tool is missing: " & Program_Name);
      end if;
   end Require_Tool;

   procedure Require_Alire_GNAT_15 is
      Alr_Path : constant String := Project_Tools.Processes.Locate_Command ("alr");
      Root     : constant String := Ada.Directories.Current_Directory;
      Output : Unbounded_String;
      Status : constant Integer :=
        Project_Tools.Processes.Run_Status
          (Label   => "GNAT 15 version check",
           Dir     => Root,
           Program => Alr_Path,
           Args    =>
             [1 => new String'("-C"),
              2 => new String'(Root),
              3 => new String'("exec"),
              4 => new String'("--"),
              5 => new String'("gnatls"),
              6 => new String'("--version")],
           Output  => Output,
           Quiet   => True);
      Output_Text : constant String := To_String (Output);
   begin
      if Alr_Path = "" then
         Fail ("required release tool is missing: alr");
      elsif Status /= 0 then
         Fail ("could not run `alr exec -- gnatls --version`");
      elsif Ada.Strings.Fixed.Index (Output_Text, "GNATLS 15.") = 0 then
         Fail ("wrong Ada compiler: release validation must use Alire GNAT 15; got: "
               & Output_Text);
      end if;
   end Require_Alire_GNAT_15;

   procedure Put_Command
     (Program_Name : String;
      Args         : GNAT.OS_Lib.Argument_List) is
   begin
      Ada.Text_IO.Put ("+ " & Program_Name);
      for Index in Args'Range loop
         if Args (Index) /= null then
            Ada.Text_IO.Put (" " & Args (Index).all);
         end if;
      end loop;
      Ada.Text_IO.New_Line;
   end Put_Command;

   procedure Run_Command
     (Program_Name : String;
      Args         : GNAT.OS_Lib.Argument_List) is
      Result_Code : Integer;
   begin
      Put_Command (Program_Name, Args);
      if Dry_Run then
         return;
      end if;

      --   Resolve on PATH via the shared project_tools helper (Locate_Command
      --   returns "" exactly when the program is not found, matching the prior
      --   Locate_Exec_On_Path null check); direct spawn is unchanged.
      declare
         Located_Path : constant String :=
           (if Ada.Strings.Fixed.Index (Program_Name, "/") = 0
              and then Ada.Strings.Fixed.Index (Program_Name, "\") = 0
            then Project_Tools.Processes.Locate_Command (Program_Name)
            else "");
      begin
         if Located_Path /= "" then
            Result_Code := GNAT.OS_Lib.Spawn (Located_Path, Args);
         else
            Result_Code := GNAT.OS_Lib.Spawn (Program_Name, Args);
         end if;
      end;

      if Result_Code /= 0 then
         Fail ("command failed with status"
               & Integer'Image (Result_Code) & ": " & Program_Name);
      end if;
   end Run_Command;

   procedure Run_Binary
     (Executable_Path : String;
      Args            : GNAT.OS_Lib.Argument_List := []) is
   begin
      if not Dry_Run and then not Exists_Executable (Executable_Path) then
         Fail ("expected release executable is missing: " & Executable_Path);
         return;
      end if;

      Run_Command (Executable_Path, Args);
   end Run_Binary;

   procedure Run_Alr_Build is
   begin
      Run_Command ("alr", [1 => new String'("build")]);
   end Run_Alr_Build;

   procedure Build_Project (Project_Path : String) is
   begin
      Run_Command
        ("alr",
         [1 => new String'("exec"),
          2 => new String'("--"),
          3 => new String'("gprbuild"),
          4 => new String'("-P"),
          5 => new String'(Project_Path)]);
   end Build_Project;

   procedure Build_Tests_Project (Project_Path : String) is
   begin
      Run_Command
        ("alr",
         [1 => new String'("-C"),
          2 => new String'("tests"),
          3 => new String'("exec"),
          4 => new String'("--"),
          5 => new String'("gprbuild"),
          6 => new String'("-P"),
          7 => new String'(Project_Path)]);
   end Build_Tests_Project;

   procedure Run_Security_Tests is
      type Name_List is array (Positive range <>) of Unbounded_String;
      Test_Names : constant Name_List :=
        [To_Unbounded_String ("test_host_key_negative"),
         To_Unbounded_String ("test_algorithm_negative"),
         To_Unbounded_String ("test_algorithm_security"),
         To_Unbounded_String ("test_crypto_primitives"),
         To_Unbounded_String ("test_pq_external_kats"),
         To_Unbounded_String ("test_hybrid_pq_readiness"),
         To_Unbounded_String ("test_hybrid_pq_openssh_transcripts"),
         To_Unbounded_String ("test_side_channel_assurance"),
         To_Unbounded_String ("test_auth_negative"),
         To_Unbounded_String ("test_packet_protection_negative"),
         To_Unbounded_String ("test_command_quoting_negative"),
         To_Unbounded_String ("test_binary_stream_negative"),
         To_Unbounded_String ("test_timeout_dirty_negative"),
         To_Unbounded_String ("test_resource_bounds"),
         To_Unbounded_String ("test_exception_mapping"),
         To_Unbounded_String ("test_config_security"),
         To_Unbounded_String ("test_auth_security"),
         To_Unbounded_String ("test_auth_malformed_inputs"),
         To_Unbounded_String ("test_agent_transport_security"),
         To_Unbounded_String ("test_live_channel_transport"),
         To_Unbounded_String ("test_live_git_e2e"),
         To_Unbounded_String ("test_live_git_interop_matrix"),
         To_Unbounded_String ("test_live_proxyjump_transport"),
         To_Unbounded_String ("test_live_rekey_transport"),
         To_Unbounded_String ("test_transport_messages"),
         To_Unbounded_String ("test_fuzz_lite"),
         To_Unbounded_String ("test_hostile_transcripts"),
         To_Unbounded_String ("test_session_open_success_security"),
         To_Unbounded_String ("test_open_runtime_security"),
         To_Unbounded_String ("test_phase19_matrix_coverage"),
         To_Unbounded_String ("test_phase19_invariant_coverage"),
         To_Unbounded_String ("test_status_mapping_matrix"),
         To_Unbounded_String ("test_phase19_context_compliance")];
   begin
      for Test_Name of Test_Names loop
         Run_Binary (Security_Bin & "/" & To_String (Test_Name));
      end loop;
   end Run_Security_Tests;

   procedure Run_Tools is
      type Name_List is array (Positive range <>) of Unbounded_String;
      Tool_Names : constant Name_List :=
        [To_Unbounded_String ("check_release_toolchain"),
         To_Unbounded_String ("check_release_artifacts"),
         To_Unbounded_String ("check_release_sequence"),
         To_Unbounded_String ("check_release_runner"),
         To_Unbounded_String ("check_public_api"),
         To_Unbounded_String ("check_package_tree"),
         To_Unbounded_String ("check_release"),
         To_Unbounded_String ("check_compile_preflight"),
         To_Unbounded_String ("check_phase17_regressions"),
         To_Unbounded_String ("check_release_manifest"),
         To_Unbounded_String ("check_release_package"),
         To_Unbounded_String ("check_security"),
         To_Unbounded_String ("check_side_channel_assurance"),
         To_Unbounded_String ("check_formal_side_channel_proof"),
         To_Unbounded_String ("check_pq_hybrid_state"),
         To_Unbounded_String ("check_hybrid_pq_readiness"),
         To_Unbounded_String ("check_phase19_context"),
         To_Unbounded_String ("check_runtime_boundaries"),
         To_Unbounded_String ("check_live_git_matrix_report"),
         To_Unbounded_String ("check_live_proxycommand_report"),
         To_Unbounded_String ("check_binary_paths")];
   begin
      for Tool_Name of Tool_Names loop
         Run_Binary (Tools_Bin & "/" & To_String (Tool_Name));
      end loop;

      Run_Binary (Tools_Bin & "/check_no_subprocess",
                  [1 => new String'("--self-test")]);
      Run_Binary (Tools_Bin & "/check_no_subprocess");
      Run_Binary (Tools_Bin & "/check_sensitive_logging",
                  [1 => new String'("--self-test")]);
      Run_Binary (Tools_Bin & "/check_sensitive_logging");
   end Run_Tools;

   procedure Parse_Arguments is
   begin
      for Index in 1 .. Ada.Command_Line.Argument_Count loop
         declare
            Item_Text : constant String := Ada.Command_Line.Argument (Index);
         begin
            if Item_Text = "--dry-run" then
               Dry_Run := True;
            else
               Fail ("unknown release validation argument: " & Item_Text);
            end if;
         end;
      end loop;
   end Parse_Arguments;

begin
   Parse_Arguments;

   Ada.Text_IO.Put_Line ("SSH_Lib release validation runner");
   Ada.Text_IO.Put_Line ("Build root: " & Build_Root);
   if Dry_Run then
      Ada.Text_IO.Put_Line ("Dry run: commands will be printed but not executed");
   end if;

   Require_Tool ("alr");
   Require_Alire_GNAT_15;

   if Failure_Count = 0 then
      Run_Alr_Build;
      --  Release guards require the repo-relative project path: tests/tests.gpr.
      Build_Tests_Project ("tests.gpr");
      Run_Binary (Test_Bin & "/main");

      --  Release guards require the repo-relative project path:
      --  tests/security/security_tests.gpr.
      Build_Tests_Project ("security/security_tests.gpr");
      Run_Security_Tests;

      Build_Project ("tests/api_stability/api_stability.gpr");
      Build_Project ("tests/package_smoke/package_smoke.gpr");
      Build_Project ("tests/version_integration/version_integration.gpr");
      Run_Binary (Version_Bin & "/test_version_adapter_consumption");
      Build_Project ("examples/examples.gpr");
      Build_Project ("tools/tools.gpr");
      Run_Tools;
   end if;

   if Failure_Count = 0 then
      Ada.Text_IO.Put_Line ("release validation passed");
   else
      Ada.Text_IO.Put_Line ("release validation failed");
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
   end if;
end Run_Release_Validation;
