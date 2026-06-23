with CryptoLib.Errors;

package SSH_Lib.Tests.Fixtures.Protocol_Scripts is
   type Scenario is
     (Happy_Path,
      Host_Key_Unknown,
      Host_Key_Mismatch,
      Bad_Kex_Signature,
      Unsupported_Host_Key,
      Auth_Rejected,
      Channel_Open_Rejected,
      Malformed_Open_Confirmation,
      Exec_Rejected,
      Exec_Timeout,
      Close_Before_Exec,
      Wrong_Exec_Channel,
      Read_Timeout,
      Write_Window_Timeout,
      Malformed_Channel_Data,
      Nonzero_Exit,
      Partial_Write_Failure,
      Remote_Close_During_Write,
      Window_Adjust_Overflow,
      Dirty_Session,
      Dirty_Channel,
      Userauth_Banner_Ignored,
      Userauth_Partial_Success);

   function Expected_Status (Item : Scenario) return CryptoLib.Errors.Status;
   function Name (Item : Scenario) return String;
end SSH_Lib.Tests.Fixtures.Protocol_Scripts;
