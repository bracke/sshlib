with Ada.Streams;
with Interfaces;
with CryptoLib.Errors;
with SSH_Lib.Sessions.Open_Guards;

package SSH_Lib.Sessions.Test_Support is
   procedure Mark_Authenticated_Open_For_Test (Item : in out Session);

   function Queue_Channel_Open_Response_For_Test
     (Item    : in out Session;
      Payload : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   function Queue_Exec_Response_For_Test
     (Item    : in out Session;
      Payload : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   function Queue_Global_Response_For_Test
     (Item    : in out Session;
      Payload : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   function Queue_Inbound_Forwarded_Open_For_Test
     (Item    : in out Session;
      Payload : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   function Last_Channel_Open_Payload_For_Test
     (Item : Session)
      return Ada.Streams.Stream_Element_Array;

   function Last_Exec_Request_Payload_For_Test
     (Item : Session)
      return Ada.Streams.Stream_Element_Array;

   function Last_Plain_Channel_Payload_For_Test
     (Item : Session)
      return Ada.Streams.Stream_Element_Array;

   function Queue_Next_Channel_Stdout_For_Test
     (Item : in out Session;
      Data : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   procedure Set_Channel_Write_Failure_For_Test
     (Item  : in out Session;
      Value : Boolean);

   procedure Set_Channel_Read_Open_Failure_For_Test
     (Item  : in out Session;
      Value : Boolean);

   procedure Set_Channel_Read_Exec_Failure_For_Test
     (Item  : in out Session;
      Value : Boolean);

   procedure Set_Channel_Open_Timeout_For_Test
     (Item  : in out Session;
      Value : Boolean);

   procedure Set_Channel_Exec_Timeout_For_Test
     (Item  : in out Session;
      Value : Boolean);

   procedure Set_Open_Cancelled_For_Test
     (Item  : in out Session;
      Value : Boolean);

   procedure Set_Exec_Cancelled_For_Test
     (Item  : in out Session;
      Value : Boolean);

   procedure Set_Channel_Exec_Write_Timeout_For_Test
     (Item  : in out Session;
      Value : Boolean);

   procedure Set_Partial_Channel_Write_Failure_For_Test
     (Item  : in out Session;
      Value : Boolean);

   procedure Set_Timeouts_For_Test
     (Item               : in out Session;
      Connect_Timeout_MS : Natural;
      Read_Timeout_MS    : Natural;
      Write_Timeout_MS   : Natural);

   procedure Mark_Dirty_For_Test
     (Item   : in out Session;
      Reason : CryptoLib.Errors.Status := CryptoLib.Errors.Connection_Failed);

   function Is_Dirty_For_Test (Item : Session) return Boolean;

   function Last_Failure_For_Test
     (Item : Session)
      return CryptoLib.Errors.Status;

   procedure Set_Channel_Limit_For_Test
     (Item  : in out Session;
      Value : Natural);


   type Hostile_Open_Transcript is
     (Transcript_Happy_Path,
      Transcript_Malformed_Identification,
      Transcript_Silent_Identification,
      Transcript_No_Supported_Kex,
      Transcript_No_Supported_Host_Key,
      Transcript_No_Supported_Cipher,
      Transcript_Bad_Kex_Signature,
      Transcript_Unknown_Host_Key,
      Transcript_Changed_Host_Key,
      Transcript_Newkeys_Not_Received,
      Transcript_Service_Accept_Before_Encryption,
      Transcript_Userauth_Before_Host_Trust,
      Transcript_Userauth_Partial_Success,
      Transcript_Userauth_Rejected,
      Transcript_Channel_Open_Before_Auth,
      Transcript_Channel_Open_Rejected,
      Transcript_Malformed_Channel_Open);

   function Run_Hostile_Open_Transcript_For_Test
     (Item     : in out Session;
      Scenario : Hostile_Open_Transcript)
      return CryptoLib.Errors.Status;

   function Is_Open_For_Test (Item : Session) return Boolean;

   function Is_Encrypted_For_Test (Item : Session) return Boolean;

   function Is_Host_Trusted_For_Test (Item : Session) return Boolean;

   function Is_Authenticated_For_Test (Item : Session) return Boolean;

   function Stored_Credentials_Clear_For_Test (Item : Session) return Boolean;


   procedure Mark_Open_Success_Gates_For_Test (Item : in out Session);

   procedure Clear_Open_Success_Gate_For_Test
     (Item : in out Session;
      Gate : SSH_Lib.Sessions.Open_Guards.Open_Success_Gate);


   procedure Enable_Live_Channel_IO_For_Test (Item : in out Session);

   function Last_Protected_Channel_Payload_For_Test
     (Item : Session)
      return Ada.Streams.Stream_Element_Array;

   procedure Configure_Rekey_For_Test
     (Item                  : in out Session;
      Automatic_Rekey       : Boolean;
      Rekey_After_Packets   : Natural;
      Rekey_After_Bytes     : Interfaces.Unsigned_64;
      Rekey_After_Seconds   : Natural);

   procedure Force_Rekey_Start_Age_For_Test
     (Item        : in out Session;
      Seconds_Ago : Natural);

   function Automatic_Rekey_Needed_For_Test
     (Item : Session)
      return Boolean;

   function Check_Automatic_Rekey_For_Test
     (Item : in out Session)
      return CryptoLib.Errors.Status;

   function Expand_Proxy_Command_For_Test
     (Command_Text : String;
      Host         : String;
      Port         : Natural;
      User         : String) return String;

   function Active_Channel_Count_For_Test (Item : Session) return Natural;
end SSH_Lib.Sessions.Test_Support;
