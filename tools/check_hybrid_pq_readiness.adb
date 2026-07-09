with Ada.Command_Line;
with Ada.Text_IO;

with Project_Tools.Files;

procedure Check_Hybrid_PQ_Readiness is
   Failure_Count : Natural := 0;

   procedure Fail (Message_Text : String) is
   begin
      Ada.Text_IO.Put_Line ("FAIL: " & Message_Text);
      Failure_Count := Failure_Count + 1;
   end Fail;

   --  A required token is present only when the file exists and contains it;
   --  a missing file is treated as "not present" (graceful Fail, not a crash),
   --  matching the previous hand-rolled File_Contains behavior.
   procedure Require_Text (Path : String; Needle : String) is
   begin
      if not (Project_Tools.Files.File_Exists (Path)
              and then Project_Tools.Files.File_Contains (Path, Needle))
      then
         Fail ("missing readiness token in " & Path & ": " & Needle);
      end if;
   end Require_Text;

begin
   Require_Text ("../cryptolib/src/cryptolib-hybrid_pq_kex.ads", "type Hybrid_PQ_Readiness");
   Require_Text ("../cryptolib/src/cryptolib-hybrid_pq_kex.ads", "External_KAT_Gate_Pending");
   Require_Text ("../cryptolib/src/cryptolib-hybrid_pq_kex.ads", "Advertised_And_Selectable");
   Require_Text ("../cryptolib/src/cryptolib-hybrid_pq_kex.ads", "Readiness_Of");
   Require_Text ("../cryptolib/src/cryptolib-hybrid_pq_kex.ads", "Readiness_Image");
   Require_Text ("../cryptolib/src/cryptolib-hybrid_pq_kex.adb", "external-kat-gate-pending");
   Require_Text ("../cryptolib/src/cryptolib-hybrid_pq_kex.adb", "advertised-and-selectable");
   Require_Text ("tests/vectors/pq/ML-KEM-keyGen-FIPS203/expectedResults.json", "testGroups");
   Require_Text ("tests/vectors/pq/ML-KEM-encapDecap-FIPS203/expectedResults.json", "testGroups");
   Require_Text ("tests/vectors/pq/SNTRUP761_OPENSSH_EXTERNAL_KATS.manifest", "external-kat-corpus-bundled");
   Require_Text ("tests/vectors/pq/SNTRUP761_OPENSSH_EXTERNAL_KATS.manifest", "SNTRUP761_OPENSSH_KAT_004.txt");
   Require_Text ("tests/security/test_hybrid_pq_readiness.adb", "sntrup761x25519-sha512@openssh.com");
   Require_Text ("../cryptolib/src/cryptolib-hybrid_pq_kex.adb", "return Is_OpenSSH_Hybrid_PQ_Kex_Name");
   Require_Text ("tests/security/test_hybrid_pq_openssh_transcripts.adb", "Assert_Hybrid_PQ_OpenSSH_Transcripts");
   Require_Text ("tests/vectors/pq/openssh_transcripts/OPENSSH_HYBRID_PQ_TRANSCRIPTS.manifest", "recorded-openssh-transcript-gate-ready");
   Require_Text ("tests/security/test_hybrid_pq_readiness.adb", "Check_Gated");
   Require_Text ("tests/security/security_tests.gpr", "test_hybrid_pq_readiness.adb");
   Require_Text ("tests/security/README.md", "hybrid/PQ readiness");
   Require_Text ("README.md", "hybrid/PQ readiness");

   if Failure_Count /= 0 then
      Ada.Text_IO.Put_Line
        ("check_hybrid_pq_readiness failed with" & Natural'Image (Failure_Count) & " issue(s)");
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
   else
      Ada.Text_IO.Put_Line ("check_hybrid_pq_readiness passed");
   end if;
end Check_Hybrid_PQ_Readiness;
