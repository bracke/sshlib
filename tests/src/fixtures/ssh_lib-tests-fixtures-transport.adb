
package body SSH_Lib.Tests.Fixtures.Transport is

   function Status_For (With_Mode : Behavior) return CryptoLib.Errors.Status is
   begin
      case With_Mode is
         when Succeed => return CryptoLib.Errors.Ok;
         when Timeout => return CryptoLib.Errors.Timeout;
         when Malformed_Packet | Wrong_Message_Number | Mac_Failure =>
            return CryptoLib.Errors.Handshake_Failed;
         when Unsupported_Algorithm => return CryptoLib.Errors.Unsupported_Feature;
         when Host_Key_Unknown => return CryptoLib.Errors.Host_Key_Unknown;
         when Host_Key_Mismatch => return CryptoLib.Errors.Host_Key_Mismatch;
         when Bad_Signature => return CryptoLib.Errors.Handshake_Failed;
         when Verify_Bypass => return CryptoLib.Errors.Ok;
         when Auth_Rejected => return CryptoLib.Errors.Authentication_Failed;
         when Auth_Partial_Success => return CryptoLib.Errors.Authentication_Failed;
         when Userauth_Banner => return CryptoLib.Errors.Ok;
         when Channel_Rejected => return CryptoLib.Errors.Channel_Open_Failed;
         when Exec_Rejected => return CryptoLib.Errors.Channel_Request_Failed;
      end case;
   end Status_For;

   procedure Start
     (Item      : out Fixture;
      At_Stage  : Stage;
      With_Mode : Behavior) is
   begin
      Item.Fault_Stage := At_Stage;
      Item.Mode := With_Mode;
   end Start;

   function Step
     (Item     : Fixture;
      At_Stage : Stage) return CryptoLib.Errors.Status is
   begin
      if At_Stage = Item.Fault_Stage then
         return Status_For (Item.Mode);
      end if;
      return CryptoLib.Errors.Ok;
   end Step;

   function Dirty_After_Step
     (Item     : Fixture;
      At_Stage : Stage) return Boolean is
   begin
      if At_Stage /= Item.Fault_Stage then
         return False;
      end if;

      return Item.Mode in Malformed_Packet | Wrong_Message_Number | Mac_Failure | Bad_Signature;
   end Dirty_After_Step;

   function Stage_Name (At_Stage : Stage) return String is
   begin
      case At_Stage is
         when Identification => return "identification";
         when Kexinit => return "kexinit";
         when Kex_Reply => return "kex-reply";
         when Host_Key_Verification => return "host-key-verification";
         when Newkeys => return "newkeys";
         when Userauth => return "userauth";
         when Channel_Open => return "channel-open";
         when Exec_Request => return "exec-request";
         when Read_Stream => return "read-stream";
         when Write_Stream => return "write-stream";
      end case;
   end Stage_Name;

   function Behavior_Name (With_Mode : Behavior) return String is
   begin
      case With_Mode is
         when Succeed => return "succeed";
         when Timeout => return "timeout";
         when Malformed_Packet => return "malformed-packet";
         when Wrong_Message_Number => return "wrong-message-number";
         when Mac_Failure => return "mac-failure";
         when Unsupported_Algorithm => return "unsupported-algorithm";
         when Host_Key_Unknown => return "host-key-unknown";
         when Host_Key_Mismatch => return "host-key-mismatch";
         when Bad_Signature => return "bad-signature";
         when Verify_Bypass => return "verify-bypass";
         when Auth_Rejected => return "auth-rejected";
         when Auth_Partial_Success => return "auth-partial-success";
         when Userauth_Banner => return "userauth-banner";
         when Channel_Rejected => return "channel-rejected";
         when Exec_Rejected => return "exec-rejected";
      end case;
   end Behavior_Name;
end SSH_Lib.Tests.Fixtures.Transport;
