with Ada.Command_Line;
with Ada.Text_IO;
with SSH_Lib.Tests.Fixtures.Hybrid_PQ_OpenSSH_Transcripts;

procedure Test_Hybrid_PQ_OpenSSH_Transcripts is
begin
   SSH_Lib.Tests.Fixtures.Hybrid_PQ_OpenSSH_Transcripts.Assert_Hybrid_PQ_OpenSSH_Transcripts;
   Ada.Text_IO.Put_Line ("test_hybrid_pq_openssh_transcripts passed");
exception
   when others =>
      Ada.Text_IO.Put_Line ("test_hybrid_pq_openssh_transcripts failed");
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
end Test_Hybrid_PQ_OpenSSH_Transcripts;
