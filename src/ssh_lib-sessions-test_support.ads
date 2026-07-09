with Ada.Streams;
with Interfaces;
with CryptoLib.Errors;
with SSH_Lib.Sessions.Open_Guards;

--  @summary Test-only harness for driving a Session through handshake, channel, and rekey states in the suite.
--
--  These helpers exist purely for the AUnit suite: they force a Session into a
--  fully-open authenticated state, queue synthetic peer responses, replay
--  hostile open-handshake transcripts, toggle fault-injection flags, and expose
--  internal gate/rekey state so tests can assert behaviour without a live SSH
--  server.
package SSH_Lib.Sessions.Test_Support is
   --  Force the session into a fully connected, encrypted, host-trusted, and
   --  authenticated open state ready for channel operations.
   --  @param Item the session to mutate
   procedure Mark_Authenticated_Open_For_Test (Item : in out Session);

   --  Queue a synthetic CHANNEL_OPEN_CONFIRMATION/failure response for the next
   --  channel-open exchange.
   --  @param Item    the session to mutate
   --  @param Payload the channel-open response bytes to enqueue
   --  @return Ok on success, or the store failure status
   function Queue_Channel_Open_Response_For_Test
     (Item    : in out Session;
      Payload : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Queue a synthetic exec-request response for the next exec exchange.
   --  @param Item    the session to mutate
   --  @param Payload the exec response bytes to enqueue
   --  @return Ok on success, or the store failure status
   function Queue_Exec_Response_For_Test
     (Item    : in out Session;
      Payload : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Queue a synthetic global-request response for the next global exchange.
   --  @param Item    the session to mutate
   --  @param Payload the global response bytes to enqueue
   --  @return Ok on success, or the store failure status
   function Queue_Global_Response_For_Test
     (Item    : in out Session;
      Payload : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Queue a synthetic inbound forwarded CHANNEL_OPEN, protecting it with the
   --  live cipher state when live channel IO is enabled.
   --  @param Item    the session to mutate
   --  @param Payload the forwarded channel-open bytes to enqueue
   --  @return Ok on success, or the encode/store failure status
   function Queue_Inbound_Forwarded_Open_For_Test
     (Item    : in out Session;
      Payload : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Return the last CHANNEL_OPEN payload the session emitted.
   --  @param Item the session to inspect
   --  @return the last channel-open payload bytes, or empty if none
   function Last_Channel_Open_Payload_For_Test
     (Item : Session)
      return Ada.Streams.Stream_Element_Array;

   --  Return the last exec-request payload the session emitted.
   --  @param Item the session to inspect
   --  @return the last exec-request payload bytes, or empty if none
   function Last_Exec_Request_Payload_For_Test
     (Item : Session)
      return Ada.Streams.Stream_Element_Array;

   --  Return the last plaintext channel payload the session emitted.
   --  @param Item the session to inspect
   --  @return the last plaintext channel payload bytes, or empty if none
   function Last_Plain_Channel_Payload_For_Test
     (Item : Session)
      return Ada.Streams.Stream_Element_Array;

   --  Queue stdout bytes to be returned by the next simulated channel read.
   --  @param Item the session to mutate
   --  @param Data the stdout bytes to enqueue
   --  @return Ok on success, Internal_Error if the store fails
   function Queue_Next_Channel_Stdout_For_Test
     (Item : in out Session;
      Data : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Toggle injecting a channel write failure.
   --  @param Item  the session to mutate
   --  @param Value True to arm the fault, False to clear it
   procedure Set_Channel_Write_Failure_For_Test
     (Item  : in out Session;
      Value : Boolean);

   --  Toggle injecting a read failure during channel open.
   --  @param Item  the session to mutate
   --  @param Value True to arm the fault, False to clear it
   procedure Set_Channel_Read_Open_Failure_For_Test
     (Item  : in out Session;
      Value : Boolean);

   --  Toggle injecting a read failure during exec.
   --  @param Item  the session to mutate
   --  @param Value True to arm the fault, False to clear it
   procedure Set_Channel_Read_Exec_Failure_For_Test
     (Item  : in out Session;
      Value : Boolean);

   --  Toggle injecting a timeout during channel open.
   --  @param Item  the session to mutate
   --  @param Value True to arm the fault, False to clear it
   procedure Set_Channel_Open_Timeout_For_Test
     (Item  : in out Session;
      Value : Boolean);

   --  Toggle injecting a timeout during exec.
   --  @param Item  the session to mutate
   --  @param Value True to arm the fault, False to clear it
   procedure Set_Channel_Exec_Timeout_For_Test
     (Item  : in out Session;
      Value : Boolean);

   --  Toggle simulating cancellation during channel open.
   --  @param Item  the session to mutate
   --  @param Value True to arm the cancellation, False to clear it
   procedure Set_Open_Cancelled_For_Test
     (Item  : in out Session;
      Value : Boolean);

   --  Toggle simulating cancellation during exec.
   --  @param Item  the session to mutate
   --  @param Value True to arm the cancellation, False to clear it
   procedure Set_Exec_Cancelled_For_Test
     (Item  : in out Session;
      Value : Boolean);

   --  Toggle injecting a write timeout during the exec request.
   --  @param Item  the session to mutate
   --  @param Value True to arm the fault, False to clear it
   procedure Set_Channel_Exec_Write_Timeout_For_Test
     (Item  : in out Session;
      Value : Boolean);

   --  Toggle injecting a failure after a partial channel write.
   --  @param Item  the session to mutate
   --  @param Value True to arm the fault, False to clear it
   procedure Set_Partial_Channel_Write_Failure_For_Test
     (Item  : in out Session;
      Value : Boolean);

   --  Set the session's stored connect, read, and write timeout budgets.
   --  @param Item               the session to mutate
   --  @param Connect_Timeout_MS the connect timeout in milliseconds
   --  @param Read_Timeout_MS    the read timeout in milliseconds
   --  @param Write_Timeout_MS   the write timeout in milliseconds
   procedure Set_Timeouts_For_Test
     (Item               : in out Session;
      Connect_Timeout_MS : Natural;
      Read_Timeout_MS    : Natural;
      Write_Timeout_MS   : Natural);

   --  Mark the session dirty with the given failure reason.
   --  @param Item   the session to mutate
   --  @param Reason the failure status to record
   procedure Mark_Dirty_For_Test
     (Item   : in out Session;
      Reason : CryptoLib.Errors.Status := CryptoLib.Errors.Connection_Failed);

   --  Report whether the session has been marked dirty.
   --  @param Item the session to inspect
   --  @return True if the session is dirty, False otherwise
   function Is_Dirty_For_Test (Item : Session) return Boolean;

   --  Return the session's last recorded failure status.
   --  @param Item the session to inspect
   --  @return the last failure status (Internal_Error on unexpected exception)
   function Last_Failure_For_Test
     (Item : Session)
      return CryptoLib.Errors.Status;

   --  Set the maximum number of channels the session may open concurrently.
   --  @param Item  the session to mutate
   --  @param Value the maximum concurrent open-channel count
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

   --  Replay a scripted hostile-peer open handshake and drive the session's
   --  open pipeline through the given failure (or happy-path) scenario.
   --  @param Item     the session to drive
   --  @param Scenario the hostile-transcript scenario to replay
   --  @return Ok for the happy path, or the failure status the scenario forces
   function Run_Hostile_Open_Transcript_For_Test
     (Item     : in out Session;
      Scenario : Hostile_Open_Transcript)
      return CryptoLib.Errors.Status;

   --  Report whether the session is in the fully open, not-closed state.
   --  @param Item the session to inspect
   --  @return True if the session is open, False otherwise
   function Is_Open_For_Test (Item : Session) return Boolean;

   --  Report whether both inbound and outbound encryption are active.
   --  @param Item the session to inspect
   --  @return True if the transport is encrypted in both directions
   function Is_Encrypted_For_Test (Item : Session) return Boolean;

   --  Report whether the host key is signature-verified and trusted (or
   --  explicitly bypassed).
   --  @param Item the session to inspect
   --  @return True if the host is trusted, False otherwise
   function Is_Host_Trusted_For_Test (Item : Session) return Boolean;

   --  Report whether userauth has been accepted and the user authenticated.
   --  @param Item the session to inspect
   --  @return True if the user is authenticated, False otherwise
   function Is_Authenticated_For_Test (Item : Session) return Boolean;

   --  Report whether all stored secret credentials and credential callbacks
   --  have been cleared from the session's options.
   --  @param Item the session to inspect
   --  @return True if no stored credentials or callbacks remain
   function Stored_Credentials_Clear_For_Test (Item : Session) return Boolean;

   --  Set every open-success gate flag so the session presents as fully open.
   --  @param Item the session to mutate
   procedure Mark_Open_Success_Gates_For_Test (Item : in out Session);

   --  Clear one specified open-success gate to model a single missing
   --  precondition.
   --  @param Item the session to mutate
   --  @param Gate the open-success gate to clear
   procedure Clear_Open_Success_Gate_For_Test
     (Item : in out Session;
      Gate : SSH_Lib.Sessions.Open_Guards.Open_Success_Gate);

   --  Enable the live protected-packet channel IO path for the session.
   --  @param Item the session to mutate
   procedure Enable_Live_Channel_IO_For_Test (Item : in out Session);

   --  Return the last protected channel payload emitted on the live-IO path.
   --  @param Item the session to inspect
   --  @return the last protected channel payload bytes, or empty if none
   function Last_Protected_Channel_Payload_For_Test
     (Item : Session)
      return Ada.Streams.Stream_Element_Array;

   --  Configure the session's automatic-rekey thresholds.
   --  @param Item                the session to mutate
   --  @param Automatic_Rekey     whether automatic rekey is enabled
   --  @param Rekey_After_Packets the packet-count rekey threshold
   --  @param Rekey_After_Bytes   the byte-count rekey threshold
   --  @param Rekey_After_Seconds the elapsed-time rekey threshold in seconds
   procedure Configure_Rekey_For_Test
     (Item                  : in out Session;
      Automatic_Rekey       : Boolean;
      Rekey_After_Packets   : Natural;
      Rekey_After_Bytes     : Interfaces.Unsigned_64;
      Rekey_After_Seconds   : Natural);

   --  Backdate the last-rekey timestamp so the age-based rekey trigger fires.
   --  @param Item        the session to mutate
   --  @param Seconds_Ago how many seconds in the past to set the rekey start
   procedure Force_Rekey_Start_Age_For_Test
     (Item        : in out Session;
      Seconds_Ago : Natural);

   --  Report whether the session currently needs an automatic rekey.
   --  @param Item the session to inspect
   --  @return True if an automatic rekey is due, False otherwise
   function Automatic_Rekey_Needed_For_Test
     (Item : Session)
      return Boolean;

   --  Run the automatic-rekey check, initiating a rekey if one is due.
   --  @param Item the session to evaluate and possibly rekey
   --  @return Ok on success, or the failure status of the rekey attempt
   function Check_Automatic_Rekey_For_Test
     (Item : in out Session)
      return CryptoLib.Errors.Status;

   --  Expand an OpenSSH-style ProxyCommand template's percent tokens.
   --  @param Command_Text the ProxyCommand template containing %h/%p/%r tokens
   --  @param Host         the host substituted for %h
   --  @param Port         the port substituted for %p
   --  @param User         the user substituted for %r
   --  @return the command text with its percent tokens expanded
   function Expand_Proxy_Command_For_Test
     (Command_Text : String;
      Host         : String;
      Port         : Natural;
      User         : String) return String;

   --  Return the number of channels currently active on the session.
   --  @param Item the session to inspect
   --  @return the count of active channels
   function Active_Channel_Count_For_Test (Item : Session) return Natural;
end SSH_Lib.Sessions.Test_Support;
