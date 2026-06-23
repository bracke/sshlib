with CryptoLib.Errors;

package SSH_Lib.Tests.Fixtures.Transport is
   type Stage is
     (Identification,
      Kexinit,
      Kex_Reply,
      Host_Key_Verification,
      Newkeys,
      Userauth,
      Channel_Open,
      Exec_Request,
      Read_Stream,
      Write_Stream);

   type Behavior is
     (Succeed,
      Timeout,
      Malformed_Packet,
      Wrong_Message_Number,
      Mac_Failure,
      Unsupported_Algorithm,
      Host_Key_Unknown,
      Host_Key_Mismatch,
      Bad_Signature,
      Verify_Bypass,
      Auth_Rejected,
      Auth_Partial_Success,
      Userauth_Banner,
      Channel_Rejected,
      Exec_Rejected);

   type Fixture is private;

   procedure Start
     (Item      : out Fixture;
      At_Stage  : Stage;
      With_Mode : Behavior);

   function Step
     (Item     : Fixture;
      At_Stage : Stage) return CryptoLib.Errors.Status;

   function Dirty_After_Step
     (Item     : Fixture;
      At_Stage : Stage) return Boolean;

   function Stage_Name (At_Stage : Stage) return String;
   function Behavior_Name (With_Mode : Behavior) return String;

private
   type Fixture is record
      Fault_Stage : Stage := Identification;
      Mode        : Behavior := Succeed;
   end record;
end SSH_Lib.Tests.Fixtures.Transport;
