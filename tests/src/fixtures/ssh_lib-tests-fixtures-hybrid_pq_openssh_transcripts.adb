with Ada.Directories;
with Ada.Strings.Fixed;
with Ada.Strings.Unbounded;
with Ada.Text_IO;
with CryptoLib.Hybrid_PQ_Kex;

package body SSH_Lib.Tests.Fixtures.Hybrid_PQ_OpenSSH_Transcripts is

   procedure Check (Condition : Boolean; Label_Text : String) is
   begin
      if not Condition then
         Ada.Text_IO.Put_Line ("FAILED: " & Label_Text);
         raise Program_Error;
      end if;
   end Check;

   function Read_All (Path_Text : String) return String is
      File_Item : Ada.Text_IO.File_Type;
      Result    : Ada.Strings.Unbounded.Unbounded_String;
   begin
      Ada.Text_IO.Open (File_Item, Ada.Text_IO.In_File, Path_Text);
      while not Ada.Text_IO.End_Of_File (File_Item) loop
         Ada.Strings.Unbounded.Append (Result, Ada.Text_IO.Get_Line (File_Item));
         Ada.Strings.Unbounded.Append (Result, ASCII.LF);
      end loop;
      Ada.Text_IO.Close (File_Item);
      return Ada.Strings.Unbounded.To_String (Result);
   exception
      when others =>
         if Ada.Text_IO.Is_Open (File_Item) then
            Ada.Text_IO.Close (File_Item);
         end if;
         return "";
   end Read_All;

   function Existing_Path (Relative_Path : String) return String is
      Candidate_1 : constant String := Relative_Path;
      Candidate_2 : constant String := "../" & Relative_Path;
      Candidate_3 : constant String := "../../" & Relative_Path;
      Candidate_4 : constant String := "../../../" & Relative_Path;
   begin
      if Ada.Directories.Exists (Candidate_1) then
         return Candidate_1;
      elsif Ada.Directories.Exists (Candidate_2) then
         return Candidate_2;
      elsif Ada.Directories.Exists (Candidate_3) then
         return Candidate_3;
      elsif Ada.Directories.Exists (Candidate_4) then
         return Candidate_4;
      else
         return "";
      end if;
   end Existing_Path;

   function Field_Value
     (Content_Text : String;
      Field_Text   : String)
      return String
   is
      Prefix_Text : constant String := Field_Text & "=";
      Start_Index : constant Natural := Ada.Strings.Fixed.Index (Content_Text, Prefix_Text);
      Stop_Index  : Natural;
   begin
      if Start_Index = 0 then
         return "";
      end if;

      Stop_Index := Start_Index + Prefix_Text'Length;
      while Stop_Index <= Content_Text'Last and then Content_Text (Stop_Index) /= ASCII.LF loop
         Stop_Index := Stop_Index + 1;
      end loop;

      return Content_Text (Start_Index + Prefix_Text'Length .. Stop_Index - 1);
   end Field_Value;

   function Natural_Image (Value : Natural) return String is
      Image_Text : constant String := Natural'Image (Value);
   begin
      if Image_Text'Length > 0 and then Image_Text (Image_Text'First) = ' ' then
         return Image_Text (Image_Text'First + 1 .. Image_Text'Last);
      end if;
      return Image_Text;
   end Natural_Image;

   function Is_Hex (Text : String) return Boolean is
   begin
      if Text'Length = 0 then
         return False;
      end if;

      for Character_Value of Text loop
         if not (Character_Value in '0' .. '9'
                 or else Character_Value in 'a' .. 'f'
                 or else Character_Value in 'A' .. 'F')
         then
            return False;
         end if;
      end loop;
      return True;
   end Is_Hex;

   procedure Require_Field
     (Content_Text : String;
      Field_Text   : String;
      Label_Text   : String)
   is
   begin
      Check
        (Ada.Strings.Fixed.Index (Content_Text, Field_Text) /= 0,
         Label_Text & " contains " & Field_Text);
   end Require_Field;

   procedure Assert_Transcript
     (Relative_Path        : String;
      Algorithm_Text       : String;
      Expected_Init_Length : Natural;
      Expected_Reply_Length : Natural;
      Expected_Hash_Length : Natural)
   is
      Path_Text    : constant String := Existing_Path (Relative_Path);
      Content_Text : constant String := (if Path_Text = "" then "" else Read_All (Path_Text));
      Exchange_Hash_Text : constant String := Field_Value (Content_Text, "exchange_hash_hex");
      Transcript_Digest_Text : constant String := Field_Value (Content_Text, "captured_transport_transcript_sha3_256");
      Shared_Secret_Text : constant String := Field_Value (Content_Text, "hybrid_shared_secret_hex");
   begin
      Check (Path_Text /= "", "OpenSSH hybrid/PQ transcript fixture exists: " & Relative_Path);
      Check (Content_Text /= "", "OpenSSH hybrid/PQ transcript fixture is readable: " & Relative_Path);
      Require_Field (Content_Text, "algorithm=" & Algorithm_Text, Relative_Path);
      Require_Field (Content_Text, "source_family=OpenSSH-live-interop-transcript", Relative_Path);
      Require_Field (Content_Text, "openssh_client=OpenSSH_9.9p2", Relative_Path);
      Require_Field (Content_Text, "openssh_server=OpenSSH_9.9p2", Relative_Path);
      Require_Field (Content_Text, "client_init_total_length=" & Natural_Image (Expected_Init_Length), Relative_Path);
      Require_Field (Content_Text, "server_reply_total_length=" & Natural_Image (Expected_Reply_Length), Relative_Path);
      Require_Field (Content_Text, "host_key_signature_verified=yes", Relative_Path);
      Require_Field (Content_Text, "known_hosts_result=trusted", Relative_Path);
      Require_Field (Content_Text, "newkeys_seen=yes", Relative_Path);
      Require_Field (Content_Text, "userauth_success_seen=yes", Relative_Path);
      Require_Field (Content_Text, "rekey_validated=yes", Relative_Path);
      Require_Field (Content_Text, "git_upload_pack_exec=yes", Relative_Path);
      Require_Field (Content_Text, "git_receive_pack_exec=yes", Relative_Path);
      Require_Field (Content_Text, "stdin_stdout_binary_safe=yes", Relative_Path);
      Require_Field (Content_Text, "packet_boundaries_verified=yes", Relative_Path);
      Check (Exchange_Hash_Text'Length = Expected_Hash_Length and then Is_Hex (Exchange_Hash_Text),
             Relative_Path & " has expected exchange hash width");
      Check (Transcript_Digest_Text'Length = 64 and then Is_Hex (Transcript_Digest_Text),
             Relative_Path & " has a captured transcript digest");
      Check (Shared_Secret_Text'Length = 64 and then Is_Hex (Shared_Secret_Text),
             Relative_Path & " has a 32-byte hybrid shared secret");
      Check
        (Ada.Strings.Fixed.Index (Content_Text, "TODO") = 0 and then
         Ada.Strings.Fixed.Index (Content_Text, "TBD") = 0 and then
         Ada.Strings.Fixed.Index (Content_Text, "placeholder") = 0,
         Relative_Path & " has no placeholder markers");
   end Assert_Transcript;

   procedure Assert_Manifest is
      Relative_Path : constant String :=
        "tests/vectors/pq/openssh_transcripts/OPENSSH_HYBRID_PQ_TRANSCRIPTS.manifest";
      Path_Text    : constant String := Existing_Path (Relative_Path);
      Content_Text : constant String := (if Path_Text = "" then "" else Read_All (Path_Text));
   begin
      Check (Path_Text /= "", "OpenSSH hybrid/PQ transcript manifest exists");
      Check (Content_Text /= "", "OpenSSH hybrid/PQ transcript manifest is readable");
      Require_Field (Content_Text, "source_family=OpenSSH-live-interop-transcript", Relative_Path);
      Require_Field (Content_Text, "required_algorithms=mlkem768x25519-sha256,mlkem768x25519-sha512"
                                     & ",sntrup761x25519-sha512@openssh.com,sntrup761x25519-sha512", Relative_Path);
      Require_Field (Content_Text, "required_checks=negotiation,hybrid-init-reply-lengths,exchange-hash"
                                     & ",host-key-signature,known-hosts,userauth,"
                                     & "channel-exec,rekey,binary-stdin-stdout",
                                    Relative_Path);
      Require_Field (Content_Text, "status=recorded-openssh-transcript-gate-ready", Relative_Path);
   end Assert_Manifest;

   procedure Assert_Hybrid_PQ_OpenSSH_Transcripts is
   begin
      Assert_Manifest;
      Assert_Transcript
        ("tests/vectors/pq/openssh_transcripts/MLKEM768_X25519_SHA256_OPENSSH_TRANSCRIPT_001.txt",
         "mlkem768x25519-sha256",
         CryptoLib.Hybrid_PQ_Kex.Client_Init_Total_Length ("mlkem768x25519-sha256"),
         CryptoLib.Hybrid_PQ_Kex.Server_Reply_Total_Length ("mlkem768x25519-sha256"),
         64);
      Assert_Transcript
        ("tests/vectors/pq/openssh_transcripts/MLKEM768_X25519_SHA512_OPENSSH_TRANSCRIPT_001.txt",
         "mlkem768x25519-sha512",
         CryptoLib.Hybrid_PQ_Kex.Client_Init_Total_Length ("mlkem768x25519-sha512"),
         CryptoLib.Hybrid_PQ_Kex.Server_Reply_Total_Length ("mlkem768x25519-sha512"),
         128);
      Assert_Transcript
        ("tests/vectors/pq/openssh_transcripts/SNTRUP761_X25519_SHA512_OPENSSH_COM_TRANSCRIPT_001.txt",
         "sntrup761x25519-sha512@openssh.com",
         CryptoLib.Hybrid_PQ_Kex.Client_Init_Total_Length ("sntrup761x25519-sha512@openssh.com"),
         CryptoLib.Hybrid_PQ_Kex.Server_Reply_Total_Length ("sntrup761x25519-sha512@openssh.com"),
         128);
      Assert_Transcript
        ("tests/vectors/pq/openssh_transcripts/SNTRUP761_X25519_SHA512_OPENSSH_TRANSCRIPT_001.txt",
         "sntrup761x25519-sha512",
         CryptoLib.Hybrid_PQ_Kex.Client_Init_Total_Length ("sntrup761x25519-sha512"),
         CryptoLib.Hybrid_PQ_Kex.Server_Reply_Total_Length ("sntrup761x25519-sha512"),
         128);
   end Assert_Hybrid_PQ_OpenSSH_Transcripts;

end SSH_Lib.Tests.Fixtures.Hybrid_PQ_OpenSSH_Transcripts;
