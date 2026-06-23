with Ada.Command_Line;
with Ada.Directories;
with Ada.Strings.Fixed;
with Ada.Text_IO;

procedure Check_Runtime_Boundaries is
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
         Fail ("missing runtime-boundary file: " & Path);
      end if;
   end Require_File;

   procedure Require_Text (Path : String; Needle : String) is
   begin
      if not File_Contains (Path, Needle) then
         Fail ("missing runtime-boundary text in " & Path & ": " & Needle);
      end if;
   end Require_Text;

   procedure Require_Absent (Path : String; Needle : String) is
   begin
      if File_Contains (Path, Needle) then
         Fail ("stale runtime-boundary text in " & Path & ": " & Needle);
      end if;
   end Require_Absent;

begin
   --  Phase 19 runtime boundary guard.  This tool records the exact runtime
   --  areas that are still allowed to fail closed and rejects vague stale
   --  placeholder wording.  It is a deterministic source/document guard, not a
   --  substitute for the GNAT/GPR/Alire release run.

   Require_File ("src/ssh_lib-sessions-open_runtime.adb");
   Require_File ("../cryptolib/src/cryptolib-ciphers.adb");
   Require_File ("src/ssh_lib-private_key_signing.adb");
   Require_File ("src/ssh_lib-sessions-channel_io.adb");
   Require_File ("src/ssh_lib-sessions-userauth_io.adb");
   Require_File ("src/ssh_lib-sessions-live_transport.adb");
   Require_File ("src/ssh_lib-sessions-live_attachment.ads");
   Require_File ("src/ssh_lib-sessions-live_attachment.adb");
   Require_File ("src/ssh_lib-sessions-live_transcript.adb");
   Require_File ("src/ssh_lib-protocol-userauth-agent_identity.adb");
   Require_File ("docs/RUNTIME_BOUNDARIES.md");

   Require_Text ("src/ssh_lib-sessions-open_runtime.adb", "transcript.example.test");
   Require_Text ("src/ssh_lib-sessions-open_runtime.adb", "Connect_And_Run_Handshake");
   Require_Text ("../cryptolib/src/cryptolib-ciphers.adb", "aes128-ctr");
   Require_Text ("../cryptolib/src/cryptolib-ciphers.adb", "aes256-ctr");
   Require_Text ("src/ssh_lib-private_key_signing.adb", "Build_Ed25519_Signature");
   Require_Text ("src/ssh_lib-sessions-channel_io.adb", "Send_Channel_Payload");
   Require_Text ("src/ssh_lib-sessions-userauth_io.adb", "Run_Identity_File_Userauth");
   Require_Text ("src/ssh_lib-sessions-userauth_io.adb", "Run_Agent_Userauth");
   Require_Text ("src/ssh_lib-sessions-userauth_io.adb", "SSH_AGENTC_SIGN_REQUEST");
   Require_Text ("src/ssh_lib-sessions-userauth_io.adb", "Live_Last_Protected_Service_Response");
   Require_Text ("src/ssh_lib-sessions-userauth_io.adb", "Live_Last_Plain_Userauth_Response");
   Require_Text ("src/ssh_lib-sessions-userauth_io.adb", "SSH_MSG_USERAUTH_SUCCESS");
   Require_Text ("src/ssh_lib-sessions-userauth_io.adb", "Queue_Userauth_Failure_For_Test");
   Require_Text ("src/ssh_lib-sessions-userauth_io.adb", "SSH_MSG_USERAUTH_FAILURE");
   Require_Text ("src/ssh_lib-protocol-userauth-agent_identity.adb", "Build_Signed_Request_From_Agent_Signature");
   Require_Text ("src/ssh_lib-sessions-live_transcript.adb", "Local_Identification_Line");
   Require_Text ("src/ssh_lib-sessions-live_transcript.adb", "Parse_Remote_Identification");
   Require_Text ("src/ssh_lib-sessions-live_transcript.adb", "Send_Protected_Packet");
   Require_Text ("src/ssh_lib-sessions-live_transcript.adb", "Read_Protected_Packet");
   Require_Text ("src/ssh_lib-sessions-live_transcript.adb", "Read_Exact");
   Require_Text ("src/ssh_lib-sessions-live_transport.adb", "Exchange_Kexinit");
   Require_Text ("src/ssh_lib-sessions-live_transport.adb", "Construct_Client");
   Require_Text ("src/ssh_lib-sessions-live_transcript.adb", "Encode_Cleartext_Packet");
   Require_Text ("src/ssh_lib-sessions-live_transcript.adb", "Read_Cleartext_Packet");
   Require_Text ("src/ssh_lib-sessions-live_transport.adb", "SSH_Lib.Protocol.Kex.Negotiate");
   Require_Text ("src/ssh_lib-sessions-live_transport.adb", "Run_Group14_Kex");
   Require_Text ("src/ssh_lib-sessions-live_transport.adb", "Encode_Group14_Init");
   Require_Text ("src/ssh_lib-sessions-live_transport.adb", "Parse_Group14_Reply");
   Require_Text ("src/ssh_lib-sessions-live_transport.adb", "Receive_Newkeys");
   Require_Text ("src/ssh_lib-protocol-kexdh.adb", "SSH_MSG_KEXDH_REPLY");
   Require_Text ("src/ssh_lib-sessions-live_transport.adb", "Verify_Presented_Host_Key");
   Require_Text ("src/ssh_lib-sessions-live_transport.adb", "SSH_Lib.Known_Hosts.Verify");
   Require_Text ("src/ssh_lib-sessions-live_transport.adb", "Host_Key_Blob");
   Require_Text ("src/ssh_lib-channels.adb", "Dispatch_Non_Channel_Protected_Payload");
   Require_Text ("src/ssh_lib-channels.adb", "SSH_Lib.Protocol.Global_Requests.SSH_MSG_GLOBAL_REQUEST");
   Require_File ("tests/security/test_live_git_e2e.adb");
   Require_Text ("tests/security/test_live_git_e2e.adb", "SSH_LIB_LIVE_GIT_E2E");
   Require_Text ("tests/security/test_live_git_e2e.adb", "SSH_Lib.Channels.Write");
   Require_Text ("tests/security/test_live_git_e2e.adb", "SSH_Lib.Channels.Read_Some");

   Require_Text ("docs/RUNTIME_BOUNDARIES.md", "Implemented runtime boundaries");
   Require_Text ("docs/RUNTIME_BOUNDARIES.md", "Deterministic public Sessions.Open runtime");
   Require_Text ("docs/RUNTIME_BOUNDARIES.md", "AES-CTR and AES-CBC cipher primitives");
   Require_Text ("docs/RUNTIME_BOUNDARIES.md", "Ed25519 identity-file signing fixture path");
   Require_Text ("docs/RUNTIME_BOUNDARIES.md", "Identity-file userauth protected-packet boundary");
   Require_Text ("docs/RUNTIME_BOUNDARIES.md", "agent userauth protected-packet boundary");
   Require_Text ("docs/RUNTIME_BOUNDARIES.md", "inbound service/userauth response transcripts");
   Require_Text ("docs/RUNTIME_BOUNDARIES.md", "protected userauth failure path");
   Require_Text ("docs/RUNTIME_BOUNDARIES.md", "Live TCP identification boundary");
   Require_Text ("docs/RUNTIME_BOUNDARIES.md", "Live cleartext KEXINIT boundary");
   Require_Text ("docs/RUNTIME_BOUNDARIES.md", "Socket-backed transcript driver");
   Require_Text ("docs/RUNTIME_BOUNDARIES.md", "Live channel protected-packet boundary");
   Require_Text ("docs/RUNTIME_BOUNDARIES.md", "Remaining explicit fail-closed boundaries");
   Require_Text ("docs/RUNTIME_BOUNDARIES.md", "Live KEXDH/NEWKEYS boundary");
   Require_Text ("docs/RUNTIME_BOUNDARIES.md", "Full production userauth transcript driver");
   Require_Text ("docs/RUNTIME_BOUNDARIES.md", "Phase 19 completeness pass 54");
   Require_Text ("docs/RUNTIME_BOUNDARIES.md", "Phase 19 completeness pass 57");
   Require_Text ("docs/RUNTIME_BOUNDARIES.md", "Phase 19 completeness pass 66");
   Require_Text ("docs/RUNTIME_BOUNDARIES.md", "Phase 19 completeness pass 71");
   Require_Text ("src/ssh_lib-sessions-live_attachment.adb", "Close_Attached");
   Require_Text ("src/ssh_lib-sessions-channel_io.adb", "Live_Attached_Transport");
   Require_Text ("src/ssh_lib-sessions-live_transport.adb", "Live_Attachment.Attach");
   Require_Text ("docs/RUNTIME_BOUNDARIES.md", "Verify_Presented_Host_Key");
   Require_Text ("docs/RUNTIME_BOUNDARIES.md", "RSA private-key signing");
   Require_Text ("docs/RUNTIME_BOUNDARIES.md", "Ed25519 host-key verification");
   Require_Text ("docs/RUNTIME_BOUNDARIES.md", "RSA SHA-512 verification");

   Require_Text ("README.md", "Runtime boundary inventory");
   Require_Text ("README.md", "Phase 19 completeness pass 43");
   Require_Text ("README.md", "Phase 19 completeness pass 44");
   Require_Text ("README.md", "Phase 19 completeness pass 47");
   Require_Text ("README.md", "Phase 19 completeness pass 48");
   Require_Text ("README.md", "Phase 19 completeness pass 49");
   Require_Text ("README.md", "Phase 19 completeness pass 50");
   Require_Text ("README.md", "Phase 19 completeness pass 51");
   Require_Text ("README.md", "Phase 19 completeness pass 52");
   Require_Text ("README.md", "Phase 19 completeness pass 54");
   Require_Text ("README.md", "docs/RUNTIME_BOUNDARIES.md");
   Require_Text ("docs/TESTING.md", "check_runtime_boundaries");
   Require_Text ("docs/TESTING.md", "Phase 19 completeness pass 43");
   Require_Text ("docs/TESTING.md", "Phase 19 completeness pass 44");
   Require_Text ("docs/TESTING.md", "Phase 19 completeness pass 47");
   Require_Text ("docs/TESTING.md", "Phase 19 completeness pass 48");
   Require_Text ("docs/TESTING.md", "Phase 19 completeness pass 49");
   Require_Text ("docs/TESTING.md", "Phase 19 completeness pass 50");
   Require_Text ("docs/TESTING.md", "Phase 19 completeness pass 51");
   Require_Text ("docs/TESTING.md", "Phase 19 completeness pass 52");
   Require_Text ("docs/TESTING.md", "Phase 19 completeness pass 54");
   Require_Text ("docs/SECURITY_REVIEW.md", "Runtime boundary inventory");
   Require_Text ("docs/SECURITY_REVIEW.md", "Phase 19 completeness pass 43");
   Require_Text ("docs/SECURITY_REVIEW.md", "Phase 19 completeness pass 44");
   Require_Text ("docs/SECURITY_REVIEW.md", "Phase 19 completeness pass 47");
   Require_Text ("docs/SECURITY_REVIEW.md", "Phase 19 completeness pass 48");
   Require_Text ("docs/SECURITY_REVIEW.md", "Phase 19 completeness pass 49");
   Require_Text ("docs/SECURITY_REVIEW.md", "Phase 19 completeness pass 50");
   Require_Text ("docs/SECURITY.md", "Phase 19 completeness pass 51");
   Require_Text ("docs/SECURITY.md", "Phase 19 completeness pass 54");
   Require_Text ("docs/THREAT_MODEL.md", "runtime boundary inventory");
   Require_Text ("docs/THREAT_MODEL.md", "Phase 19 completeness pass 43");
   Require_Text ("docs/THREAT_MODEL.md", "Phase 19 completeness pass 44");
   Require_Text ("docs/THREAT_MODEL.md", "Phase 19 completeness pass 47");
   Require_Text ("docs/THREAT_MODEL.md", "Phase 19 completeness pass 48");
   Require_Text ("docs/THREAT_MODEL.md", "Phase 19 completeness pass 49");
   Require_Text ("docs/THREAT_MODEL.md", "Phase 19 completeness pass 50");
   Require_Text ("docs/THREAT_MODEL.md", "Phase 19 completeness pass 51");
   Require_Text ("docs/THREAT_MODEL.md", "Phase 19 completeness pass 52");
   Require_Text ("docs/THREAT_MODEL.md", "Phase 19 completeness pass 54");
   Require_Text ("docs/SECURITY_REVIEW.md", "Phase 19 completeness pass 54");

   Require_Absent ("src/ssh_lib-sessions.adb", "Missing_Encrypted_Transport_Boundary");
   Require_Absent ("README.md", "authenticated encrypted `Sessions.Open` is fully implemented for arbitrary hosts");
   Require_Absent ("README.md", "public-network SSH is complete");
   Require_Absent ("README.md", "still-missing live KEX/NEWKEYS boundary");
   Require_Absent ("README.md", "OpenSSH bcrypt-encrypted keys currently fail closed");
   Require_Absent ("README.md", "future full KDF implementation");
   Require_Absent ("docs/RUNTIME_BOUNDARIES.md", "This is still not a complete arbitrary-host SSH session implementation");
   Require_Absent ("docs/THREAT_MODEL.md", "per-channel data/EOF/close path, which still needs to be wired");

   if Failure_Count = 0 then
      Ada.Text_IO.Put_Line ("runtime boundary guard passed");
   else
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
   end if;
end Check_Runtime_Boundaries;
