package body SSH_Lib.Tests.Fixtures.Protocol_Scripts is

   function Expected_Status (Item : Scenario) return CryptoLib.Errors.Status is
   begin
      case Item is
         when Happy_Path =>
            return CryptoLib.Errors.Ok;
         when Host_Key_Unknown =>
            return CryptoLib.Errors.Host_Key_Unknown;
         when Host_Key_Mismatch =>
            return CryptoLib.Errors.Host_Key_Mismatch;
         when Bad_Kex_Signature =>
            return CryptoLib.Errors.Handshake_Failed;
         when Unsupported_Host_Key =>
            return CryptoLib.Errors.Unsupported_Feature;
         when Auth_Rejected =>
            return CryptoLib.Errors.Authentication_Failed;
         when Channel_Open_Rejected =>
            return CryptoLib.Errors.Channel_Open_Failed;
         when Malformed_Open_Confirmation =>
            return CryptoLib.Errors.Channel_Open_Failed;
         when Exec_Rejected =>
            return CryptoLib.Errors.Channel_Request_Failed;
         when Exec_Timeout =>
            return CryptoLib.Errors.Timeout;
         when Close_Before_Exec =>
            return CryptoLib.Errors.Channel_Request_Failed;
         when Wrong_Exec_Channel =>
            return CryptoLib.Errors.Channel_Request_Failed;
         when Read_Timeout =>
            return CryptoLib.Errors.Timeout;
         when Write_Window_Timeout =>
            return CryptoLib.Errors.Timeout;
         when Malformed_Channel_Data =>
            return CryptoLib.Errors.Read_Failed;
         when Nonzero_Exit =>
            return CryptoLib.Errors.Remote_Exit_Nonzero;
         when Partial_Write_Failure =>
            return CryptoLib.Errors.Timeout;
         when Remote_Close_During_Write =>
            return CryptoLib.Errors.Write_Failed;
         when Window_Adjust_Overflow =>
            return CryptoLib.Errors.Write_Failed;
         when Dirty_Session =>
            return CryptoLib.Errors.Channel_Open_Failed;
         when Dirty_Channel =>
            return CryptoLib.Errors.Write_Failed;
         when Userauth_Banner_Ignored =>
            return CryptoLib.Errors.Ok;
         when Userauth_Partial_Success =>
            return CryptoLib.Errors.Authentication_Failed;
      end case;
   end Expected_Status;

   function Name (Item : Scenario) return String is
   begin
      case Item is
         when Happy_Path => return "happy-path";
         when Host_Key_Unknown => return "host-key-unknown";
         when Host_Key_Mismatch => return "host-key-mismatch";
         when Bad_Kex_Signature => return "bad-kex-signature";
         when Unsupported_Host_Key => return "unsupported-host-key";
         when Auth_Rejected => return "auth-rejected";
         when Channel_Open_Rejected => return "channel-open-rejected";
         when Malformed_Open_Confirmation => return "malformed-open-confirmation";
         when Exec_Rejected => return "exec-rejected";
         when Exec_Timeout => return "exec-timeout";
         when Close_Before_Exec => return "close-before-exec";
         when Wrong_Exec_Channel => return "wrong-exec-channel";
         when Read_Timeout => return "read-timeout";
         when Write_Window_Timeout => return "write-window-timeout";
         when Malformed_Channel_Data => return "malformed-channel-data";
         when Nonzero_Exit => return "nonzero-exit";
         when Partial_Write_Failure => return "partial-write-failure";
         when Remote_Close_During_Write => return "remote-close-during-write";
         when Window_Adjust_Overflow => return "window-adjust-overflow";
         when Dirty_Session => return "dirty-session";
         when Dirty_Channel => return "dirty-channel";
         when Userauth_Banner_Ignored => return "userauth-banner-ignored";
         when Userauth_Partial_Success => return "userauth-partial-success";
      end case;
   end Name;
end SSH_Lib.Tests.Fixtures.Protocol_Scripts;
