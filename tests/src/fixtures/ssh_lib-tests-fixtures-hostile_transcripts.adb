with Ada.Text_IO;
with SSH_Lib.Channels;
with CryptoLib.Errors;
with SSH_Lib.Sessions;
with SSH_Lib.Sessions.Test_Support;
with SSH_Lib.Tests.Assertions;

package body SSH_Lib.Tests.Fixtures.Hostile_Transcripts is

   use type CryptoLib.Errors.Status;
   use type SSH_Lib.Sessions.Test_Support.Hostile_Open_Transcript;

   procedure Check (Condition : Boolean; Label_Text : String) is
   begin
      if not Condition then
         Ada.Text_IO.Put_Line ("FAILED: " & Label_Text);
         raise Program_Error;
      end if;
   end Check;

   function Expected
     (Scenario : SSH_Lib.Sessions.Test_Support.Hostile_Open_Transcript)
      return CryptoLib.Errors.Status
   is
      use SSH_Lib.Sessions.Test_Support;
   begin
      case Scenario is
         when Transcript_Happy_Path =>
            return CryptoLib.Errors.Ok;
         when Transcript_Malformed_Identification =>
            return CryptoLib.Errors.Handshake_Failed;
         when Transcript_Silent_Identification =>
            return CryptoLib.Errors.Timeout;
         when Transcript_No_Supported_Kex
            | Transcript_No_Supported_Host_Key
            | Transcript_No_Supported_Cipher =>
            return CryptoLib.Errors.Unsupported_Feature;
         when Transcript_Bad_Kex_Signature =>
            return CryptoLib.Errors.Handshake_Failed;
         when Transcript_Unknown_Host_Key =>
            return CryptoLib.Errors.Host_Key_Unknown;
         when Transcript_Changed_Host_Key =>
            return CryptoLib.Errors.Host_Key_Mismatch;
         when Transcript_Newkeys_Not_Received =>
            return CryptoLib.Errors.Timeout;
         when Transcript_Service_Accept_Before_Encryption =>
            return CryptoLib.Errors.Handshake_Failed;
         when Transcript_Userauth_Before_Host_Trust =>
            return CryptoLib.Errors.Host_Key_Unknown;
         when Transcript_Userauth_Partial_Success
            | Transcript_Userauth_Rejected
            | Transcript_Channel_Open_Before_Auth =>
            return CryptoLib.Errors.Authentication_Failed;
         when Transcript_Channel_Open_Rejected
            | Transcript_Malformed_Channel_Open =>
            return CryptoLib.Errors.Channel_Open_Failed;
      end case;
   end Expected;

   function Label
     (Scenario : SSH_Lib.Sessions.Test_Support.Hostile_Open_Transcript)
      return String
   is
      Raw_Text : constant String :=
        SSH_Lib.Sessions.Test_Support.Hostile_Open_Transcript'Image (Scenario);
      Result_Text : String (Raw_Text'Range) := Raw_Text;
   begin
      for Index_Value in Result_Text'Range loop
         if Result_Text (Index_Value) = '_' then
            Result_Text (Index_Value) := '-';
         elsif Result_Text (Index_Value) in 'A' .. 'Z' then
            Result_Text (Index_Value) :=
              Character'Val
                (Character'Pos (Result_Text (Index_Value))
                 - Character'Pos ('A') + Character'Pos ('a'));
         end if;
      end loop;
      return Result_Text;
   end Label;

   procedure Assert_Hostile_Session_Open_Transcripts is
      Session_Item : SSH_Lib.Sessions.Session;
      Channel_Item : SSH_Lib.Channels.Channel;
      Status_Value : CryptoLib.Errors.Status;
   begin
      --  These scenarios are scripted hostile SSH peer transcripts through the
      --  real Session private lifecycle flags.  They prove whole-session gates:
      --  malformed identification, algorithm/KEX failures, NEWKEYS/service
      --  ordering including service-accept-before-encryption, userauth
      --  failures, and channel-open failures never leave an open or reusable
      --  authenticated session behind.
      for Scenario in SSH_Lib.Sessions.Test_Support.Hostile_Open_Transcript loop
         Status_Value :=
           SSH_Lib.Sessions.Test_Support.Run_Hostile_Open_Transcript_For_Test
             (Session_Item, Scenario);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, Expected (Scenario),
            "hostile session-open transcript", Label (Scenario));

         if Scenario = SSH_Lib.Sessions.Test_Support.Transcript_Happy_Path then
            Check
              (SSH_Lib.Sessions.Test_Support.Is_Open_For_Test (Session_Item),
               "happy hostile transcript opens the session only after every security gate");
            Check
              (SSH_Lib.Sessions.Test_Support.Is_Encrypted_For_Test (Session_Item),
               "happy hostile transcript activates encrypted inbound and outbound packet mode");
            Check
              (SSH_Lib.Sessions.Test_Support.Is_Host_Trusted_For_Test (Session_Item),
               "happy hostile transcript verifies host-key signature and known-host trust");
            Check
              (SSH_Lib.Sessions.Test_Support.Is_Authenticated_For_Test (Session_Item),
               "happy hostile transcript authenticates only after host trust");

            Status_Value := SSH_Lib.Channels.Open_Exec
              (Session_Item, "git-upload-pack 'repo.git'", Channel_Item);
            SSH_Lib.Tests.Assertions.Check_Status
              (Status_Value, CryptoLib.Errors.Channel_Open_Failed,
               "hostile session-open transcript", "happy path still requires channel-open peer response");
         else
            Check
              (not SSH_Lib.Sessions.Test_Support.Is_Open_For_Test (Session_Item),
               "hostile transcript failure leaves Session.Open state closed: " & Label (Scenario));
            Status_Value := SSH_Lib.Channels.Open_Exec
              (Session_Item, "git-upload-pack 'repo.git'", Channel_Item);
            SSH_Lib.Tests.Assertions.Check_Status
              (Status_Value, CryptoLib.Errors.Channel_Open_Failed,
               "hostile session-open transcript", "failed open cannot open channels after " & Label (Scenario));
         end if;
      end loop;
   end Assert_Hostile_Session_Open_Transcripts;
end SSH_Lib.Tests.Fixtures.Hostile_Transcripts;
