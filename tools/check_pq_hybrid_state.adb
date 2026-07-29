with Ada.Command_Line;
with Ada.Text_IO;

with Project_Tools.Files;

procedure Check_PQ_Hybrid_State is

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
         Fail ("missing PQ hybrid state file: " & Path);
      end if;
   end Require_File;

   procedure Require_Text (Path : String; Needle : String) is
   begin
      if not File_Contains (Path, Needle) then
         Fail ("missing PQ hybrid state token in " & Path & ": " & Needle);
      end if;
   end Require_Text;

   procedure Forbid_Text (Path : String; Needle : String) is
   begin
      if File_Contains (Path, Needle) then
         Fail ("stale PQ hybrid documentation token in " & Path & ": " & Needle);
      end if;
   end Forbid_Text;

begin
   Require_File ("../cryptolib/src/cryptolib-mlkem768.ads");
   Require_File ("../cryptolib/src/cryptolib-sntrup761.ads");
   Require_File ("../cryptolib/src/cryptolib-hybrid_pq_kex.ads");
   Require_File ("tests/vectors/pq/MLKEM768_ACVP_KAT_001.txt");
   Require_File ("tests/vectors/pq/ML-KEM-keyGen-FIPS203/README.md");
   Require_File ("tests/vectors/pq/ML-KEM-encapDecap-FIPS203/README.md");
   Require_File ("tests/vectors/pq/SNTRUP761_OPENSSH_KAT_001.txt");
   Require_File ("tests/vectors/pq/SNTRUP761_OPENSSH_KAT_002.txt");
   Require_File ("tests/vectors/pq/SNTRUP761_OPENSSH_KAT_003.txt");
   Require_File ("tests/vectors/pq/SNTRUP761_OPENSSH_KAT_004.txt");
   Require_File ("tests/security/test_pq_external_kats.adb");
   Require_File ("tools/check_hybrid_pq_readiness.adb");
   Require_File ("tests/security/test_hybrid_pq_readiness.adb");
   Require_File ("tests/security/test_hybrid_pq_openssh_transcripts.adb");
   Require_File ("tests/vectors/pq/openssh_transcripts/OPENSSH_HYBRID_PQ_TRANSCRIPTS.manifest");

   Require_Text ("../cryptolib/src/cryptolib-mlkem768.ads", "Ciphertext_Length");
   Require_Text ("../cryptolib/src/cryptolib-mlkem768.ads", "Shared_Secret_Length");
   Require_Text ("../cryptolib/src/cryptolib-sntrup761.ads", "Ciphertext_Length");
   Require_Text ("../cryptolib/src/cryptolib-sntrup761.ads", "Shared_Secret_Length");
   Require_Text ("../cryptolib/src/cryptolib-hybrid_pq_kex.ads", "Client_Init_Total_Length");
   Require_Text ("../cryptolib/src/cryptolib-hybrid_pq_kex.ads", "Server_Reply_Total_Length");
   Require_Text ("../cryptolib/src/cryptolib-hybrid_pq_kex.ads", "Readiness_Of");
   Require_Text ("../cryptolib/src/cryptolib-hybrid_pq_kex.ads", "External_KAT_Gate_Pending");
   Require_Text ("src/ssh_lib-sessions-live_transport.adb", "Run_Hybrid_PQ_Kex");
   Require_Text ("src/ssh_lib-sessions-live_transport.adb", "Compute_Hybrid_PQ_SHA512");
   Require_Text ("README.md", "recorded OpenSSH hybrid/PQ transcript gate");
   Require_Text ("README.md", "SNTRUP761 now has a deterministic KEM boundary");
   Require_Text ("tests/security/README.md", "SNTRUP761 now has a deterministic KEM boundary");
   Require_Text
        ("tests/vectors/pq/MLKEM768_ACVP_EXTERNAL_KATS.manifest",
         "required_vector_file=MLKEM768_ACVP_KAT_001.txt");
   Require_Text ("tests/src/fixtures/ssh_lib-tests-fixtures-pq_external_kats.adb", "Assert_MLKEM768_ACVP_Vector");
   Require_Text ("tests/src/fixtures/ssh_lib-tests-fixtures-pq_external_kats.adb", "Assert_MLKEM768_ACVP_JSON_Vectors");
   Require_Text
        ("tests/vectors/pq/MLKEM768_ACVP_EXTERNAL_KATS.manifest",
         "required_json_keygen_prompt=ML-KEM-keyGen-FIPS203/prompt.json");
   Require_Text ("tests/vectors/pq/MLKEM768_ACVP_EXTERNAL_KATS.manifest", "acvp-json-expected-results-execution");
   Require_Text ("tests/vectors/pq/SNTRUP761_OPENSSH_EXTERNAL_KATS.manifest", "external-kat-corpus-bundled");
   Require_Text ("tests/vectors/pq/SNTRUP761_OPENSSH_EXTERNAL_KATS.manifest", "SNTRUP761_OPENSSH_KAT_004.txt");
   Require_Text ("tests/src/fixtures/ssh_lib-tests-fixtures-pq_external_kats.adb", "SNTRUP761_OPENSSH_KAT_004.txt");
   Require_Text
        ("tests/src/fixtures/ssh_lib-tests-fixtures-hybrid_pq_openssh_transcripts.adb",
         "host_key_signature_verified=yes");
   Require_Text
        ("tests/src/fixtures/ssh_lib-tests-fixtures-hybrid_pq_openssh_transcripts.adb",
         "git_receive_pack_exec=yes");
   Require_Text ("../cryptolib/src/cryptolib-hybrid_pq_kex.adb", "Advertised_And_Selectable");

   Forbid_Text ("README.md", "SNTRUP761 is still not implemented");
   Forbid_Text ("CHANGELOG.md", "SNTRUP761 is still not implemented");
   Forbid_Text ("tests/security/README.md", "SNTRUP761 is still not implemented");
   Forbid_Text ("../cryptolib/src/cryptolib-hybrid_pq_kex.adb", "primitive bodies remain fail-closed");

   --  Pass 300 guard: after pass 296 the four OpenSSH hybrid/PQ KEX
   --  spellings are implemented, advertised, and selectable.  Historical
   --  notes may still explain the earlier guardrail, but release docs must
   --  not reintroduce current-state wording that says these names are
   --  unadvertised, fail-closed, or gated on still-missing live transcript
   --  proof.
   Forbid_Text ("README.md", "OpenSSH hybrid/PQ KEX names remain unadvertised");
   Forbid_Text ("README.md", "recognized but fail closed until the library contains real ML-KEM-768");
   Forbid_Text ("README.md", "not advertised without real KEM primitives");
   Forbid_Text ("README.md", "advertisement remains gated");
   Forbid_Text ("README.md", "advertisement is still gated");
   Forbid_Text ("README.md", "Hybrid/PQ KEX advertisement remains disabled");
   Forbid_Text ("README.md", "The four OpenSSH hybrid/PQ names are still recognized but not advertised");
   Forbid_Text ("README.md", "them unsupported and unadvertised because this");
   Forbid_Text ("README.md", "Ada-only crate does not yet contain real SNTRUP761 or ML-KEM768 primitives");
   Forbid_Text ("README.md", "The guarded SHA-512 ML-KEM spelling remains unsupported and unadvertised");
   Forbid_Text ("CHANGELOG.md", "OpenSSH hybrid/PQ KEX names remain unadvertised");
   Forbid_Text ("CHANGELOG.md", "Hybrid/PQ advertisement remains disabled");
   Forbid_Text ("CHANGELOG.md", "Kept all four hybrid/PQ KEX names unadvertised");
   Forbid_Text ("tests/security/README.md", "OpenSSH hybrid/PQ KEX names remain unadvertised");
   Forbid_Text ("tests/security/README.md", "Hybrid/PQ KEX advertisement remains disabled");
   Forbid_Text ("tests/security/README.md", "advertisement remains gated");

   --  Pass 304 guard: release-facing algorithm documentation must match the
   --  current advertised KEX and host-key lists, including hybrid/PQ and
   --  ECDSA P-256/P-384/P-521 raw/certificate names.  Earlier guides in SECURITY_REVIEW,
   --  TESTING, and THREAT_MODEL had stale classical-only KEX lists after
   --  hybrid/PQ advertisement was enabled.
   Require_Text
        ("docs/SECURITY_REVIEW.md",
         "mlkem768x25519-sha256,mlkem768x25519-sha512,sntrup761x25519-sha512@openssh.com,sntrup761x25519-sha512");
   Require_Text ("docs/SECURITY_REVIEW.md", "ecdsa-sha2-nistp256-cert-v01@openssh.com");
   Require_Text ("docs/SECURITY_REVIEW.md", "ecdsa-sha2-nistp384-cert-v01@openssh.com");
   Require_Text ("docs/SECURITY_REVIEW.md", "ecdsa-sha2-nistp521-cert-v01@openssh.com");
   Require_Text
        ("docs/TESTING.md",
         "mlkem768x25519-sha256,mlkem768x25519-sha512,sntrup761x25519-sha512@openssh.com,sntrup761x25519-sha512");
   Require_Text ("docs/TESTING.md", "ecdsa-sha2-nistp256-cert-v01@openssh.com");
   Require_Text ("docs/TESTING.md", "ecdsa-sha2-nistp384-cert-v01@openssh.com");
   Require_Text ("docs/TESTING.md", "ecdsa-sha2-nistp521-cert-v01@openssh.com");
   Require_Text
        ("docs/THREAT_MODEL.md",
         "mlkem768x25519-sha256,mlkem768x25519-sha512,sntrup761x25519-sha512@openssh.com,sntrup761x25519-sha512");
   Require_Text ("docs/THREAT_MODEL.md", "ecdsa-sha2-nistp256-cert-v01@openssh.com");
   Require_Text ("docs/THREAT_MODEL.md", "ecdsa-sha2-nistp384-cert-v01@openssh.com");
   Require_Text ("docs/THREAT_MODEL.md", "ecdsa-sha2-nistp521-cert-v01@openssh.com");
   Forbid_Text ("docs/SECURITY_REVIEW.md", "The client advertises `curve25519-sha256,curve25519-sha256@libssh.org");
   Forbid_Text ("docs/TESTING.md", "The client advertises `curve25519-sha256,curve25519-sha256@libssh.org");
   Forbid_Text ("docs/THREAT_MODEL.md", "The client advertises `curve25519-sha256,curve25519-sha256@libssh.org");

   if Failure_Count /= 0 then
      Ada.Text_IO.Put_Line
        ("check_pq_hybrid_state failed with" & Natural'Image (Failure_Count) & " issue(s)");
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
   else
      Ada.Text_IO.Put_Line ("check_pq_hybrid_state passed");
   end if;
end Check_PQ_Hybrid_State;
