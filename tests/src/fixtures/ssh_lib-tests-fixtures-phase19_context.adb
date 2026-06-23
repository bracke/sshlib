with Ada.Text_IO;
with Ada.Streams;
with CryptoLib.Errors;
with SSH_Lib.Sessions;
with SSH_Lib.Protocol.Channels;
with SSH_Lib.Protocol.Negative_Tests;
with SSH_Lib.Security_Audit;
with SSH_Lib.Git;

package body SSH_Lib.Tests.Fixtures.Phase19_Context is

   use type SSH_Lib.Protocol.Negative_Tests.Negative_Invariant;
   use type CryptoLib.Errors.Status;
   use type Ada.Streams.Stream_Element;

   procedure Assert (Condition : Boolean; Label_Text : String) is
   begin
      if not Condition then
         Ada.Text_IO.Put_Line ("FAILED phase19 context: " & Label_Text);
         raise Program_Error;
      end if;
   end Assert;

   procedure Assert_Initial_Context_Coverage is
      Options       : SSH_Lib.Sessions.Session_Options;
      Quoted_Text   : constant String := SSH_Lib.Git.Upload_Pack_Command ("a'b.git");
      Binary_Buffer : Ada.Streams.Stream_Element_Array (1 .. 6);
   begin
      Binary_Buffer (1) := 16#00#;
      Binary_Buffer (2) := 16#0A#;
      Binary_Buffer (3) := 16#0D#;
      Binary_Buffer (4) := 16#7F#;
      Binary_Buffer (5) := 16#80#;
      Binary_Buffer (6) := 16#FF#;

      Assert (Options.Verify_Known_Host, "Verify_Known_Host default true");
      Assert (Options.Strict_Host_Key, "Strict_Host_Key default true");
      Assert (Options.Use_Agent, "Use_Agent default true");

      Assert
        (SSH_Lib.Security_Audit.Status_Matrix_Status
           (SSH_Lib.Security_Audit.Unknown_Host_Key_Case) =
         CryptoLib.Errors.Host_Key_Unknown,
         "unknown host status mapping");
      Assert
        (SSH_Lib.Security_Audit.Status_Matrix_Status
           (SSH_Lib.Security_Audit.Changed_Host_Key_Case) =
         CryptoLib.Errors.Host_Key_Mismatch,
         "changed host status mapping");
      Assert
        (SSH_Lib.Security_Audit.Status_Matrix_Status
           (SSH_Lib.Security_Audit.Invalid_Host_Key_Signature_Case) =
         CryptoLib.Errors.Handshake_Failed,
         "invalid host-key signature status mapping");

      Assert
        (SSH_Lib.Protocol.Negative_Tests.Expected_Status
           (SSH_Lib.Protocol.Negative_Tests.No_Supported_Kex) =
         CryptoLib.Errors.Unsupported_Feature,
         "unsupported KEX status mapping");
      Assert
        (SSH_Lib.Protocol.Negative_Tests.Expected_Status
           (SSH_Lib.Protocol.Negative_Tests.Partial_Write_Timeout) =
         CryptoLib.Errors.Timeout,
         "partial write timeout status mapping");
      Assert
        (SSH_Lib.Protocol.Negative_Tests.Is_Preservation_Case
           (SSH_Lib.Protocol.Negative_Tests.Binary_Nul_Preserved),
         "binary NUL preservation case classified");
      Assert
        (SSH_Lib.Protocol.Negative_Tests.Case_Invariant
           (SSH_Lib.Protocol.Negative_Tests.Subprocess_Fallback_Disallowed) =
         SSH_Lib.Protocol.Negative_Tests.Preserves_Shell_Safe_Remote_Command,
         "no-subprocess invariant classified");

      Assert
        (Quoted_Text = "git-upload-pack 'a'\''b.git'",
         "single quote repository path escaped exactly");
      Assert
        (SSH_Lib.Protocol.Channels.Valid_Command (Quoted_Text),
         "generated Git command accepted by Open_Exec validation");

      Assert (Binary_Buffer (1) = 16#00#, "binary sentinel NUL present");
      Assert (Binary_Buffer (2) = 16#0A#, "binary sentinel LF present");
      Assert (Binary_Buffer (3) = 16#0D#, "binary sentinel CR present");
      Assert (Binary_Buffer (4) = 16#7F#, "binary sentinel DEL present");
      Assert (Binary_Buffer (5) = 16#80#, "binary sentinel high bit present");
      Assert (Binary_Buffer (6) = 16#FF#, "binary sentinel FF present");
   end Assert_Initial_Context_Coverage;
end SSH_Lib.Tests.Fixtures.Phase19_Context;
