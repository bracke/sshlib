with Ada.Strings.Unbounded;
with Ada.Streams;
with SSH_Lib.Config;
with CryptoLib.Errors;
with SSH_Lib.Channels;
with SSH_Lib.Git;
with SSH_Lib.Sessions;

--  @summary git-over-SSH transport: runs git-upload-pack / git-receive-pack
--  on the remote over an SSH session channel for fetch/clone and push.
package SSH_Lib.Git_Transport is
   type Service is
     (Upload_Pack,
      Receive_Pack);

   type Git_Workflow_Summary is record
      Requested            : Service := Upload_Pack;
      Request_Bytes        : Natural := 0;
      Response_Bytes       : Natural := 0;
      Exit_Code            : Integer := 0;
      Remote_Exit_Observed : Boolean := False;
      Response_Validated   : Boolean := False;
      Upload_Response      : SSH_Lib.Git.Upload_Pack_Response_Summary;
      Receive_Report       : SSH_Lib.Git.Receive_Pack_Report_Summary;
   end record;

   --  Resolve a remote spec into the session options and git command for a service.
   --  @param Remote_Text  the remote spec (user@host:path form)
   --  @param Config       the ssh_config host configuration to apply
   --  @param Default_User the fallback username when none is given in the spec
   --  @param Requested    the git service (upload-pack or receive-pack) to run
   --  @param Options      the derived session options for connecting
   --  @param Command      the derived remote git command line to exec
   --  @return Ok on success, an error status if the remote spec is invalid
   function Prepare
     (Remote_Text  : String;
      Config       : SSH_Lib.Config.Host_Config;
      Default_User : String;
      Requested    : Service;
      Options      : out SSH_Lib.Sessions.Session_Options;
      Command      : out Ada.Strings.Unbounded.Unbounded_String)
      return CryptoLib.Errors.Status;

   --  Open an exec channel running the git service command on an open session.
   --  @param Session   the open, authenticated session to open the channel on
   --  @param Requested the git service being started
   --  @param Command   the remote git command line to exec
   --  @param Channel   the opened service channel
   --  @return Ok on success, an error status on channel-open failure
   function Open_Service
     (Session   : in out SSH_Lib.Sessions.Session;
      Requested : Service;
      Command   : String;
      Channel   : in out SSH_Lib.Channels.Channel)
      return CryptoLib.Errors.Status;

   --  Send the request and read the full response over an already-open service channel.
   --  @param Channel   the open git service channel
   --  @param Requested the git service in progress
   --  @param Request   the request bytes to send to the remote git process
   --  @param Response  the buffer receiving the response bytes
   --  @param Last      the offset of the last valid byte written to Response
   --  @param Summary   the collected workflow summary (byte counts, exit code, validation)
   --  @return Ok on success, an error status on failure
   function Complete_Service
     (Channel  : in out SSH_Lib.Channels.Channel;
      Requested : Service;
      Request  : Ada.Streams.Stream_Element_Array;
      Response : out Ada.Streams.Stream_Element_Array;
      Last     : out Ada.Streams.Stream_Element_Offset;
      Summary  : out Git_Workflow_Summary)
      return CryptoLib.Errors.Status;

   --  Open a git service channel and run the full request/response exchange on a session.
   --  @param Session   the open, authenticated session to run on
   --  @param Requested the git service to run
   --  @param Command   the remote git command line to exec
   --  @param Request   the request bytes to send
   --  @param Response  the buffer receiving the response bytes
   --  @param Last      the offset of the last valid byte written to Response
   --  @param Summary   the collected workflow summary
   --  @return Ok on success, an error status on failure
   function Run_Service
     (Session   : in out SSH_Lib.Sessions.Session;
      Requested : Service;
      Command   : String;
      Request   : Ada.Streams.Stream_Element_Array;
      Response  : out Ada.Streams.Stream_Element_Array;
      Last      : out Ada.Streams.Stream_Element_Offset;
      Summary   : out Git_Workflow_Summary)
      return CryptoLib.Errors.Status;

   --  Run a git service against a local repository via a git subprocess (no SSH).
   --  @param Repository_Path the path to the local git repository
   --  @param Requested       the git service to run
   --  @param Request         the request bytes to feed the git process
   --  @param Response        the buffer receiving the response bytes
   --  @param Last            the offset of the last valid byte written to Response
   --  @param Summary         the collected workflow summary
   --  @param Timeout_MS      the subprocess timeout in milliseconds
   --  @return Ok on success, an error status on failure or timeout
   function Run_Service_With_Local_Git
     (Repository_Path : String;
      Requested       : Service;
      Request         : Ada.Streams.Stream_Element_Array;
      Response        : out Ada.Streams.Stream_Element_Array;
      Last            : out Ada.Streams.Stream_Element_Offset;
      Summary         : out Git_Workflow_Summary;
      Timeout_MS      : Natural := 30_000)
      return CryptoLib.Errors.Status;

   --  Run a git service by launching a local ssh subprocess for the session.
   --  @param Options    the session options describing the remote endpoint
   --  @param Command    the remote git command line to exec
   --  @param Requested  the git service to run
   --  @param Request    the request bytes to send
   --  @param Response   the buffer receiving the response bytes
   --  @param Last       the offset of the last valid byte written to Response
   --  @param Summary    the collected workflow summary
   --  @param Timeout_MS the subprocess timeout in milliseconds
   --  @return Ok on success, an error status on failure or timeout
   function Run_Service_With_Local_SSH
     (Options    : SSH_Lib.Sessions.Session_Options;
      Command    : String;
      Requested  : Service;
      Request    : Ada.Streams.Stream_Element_Array;
      Response   : out Ada.Streams.Stream_Element_Array;
      Last       : out Ada.Streams.Stream_Element_Offset;
      Summary    : out Git_Workflow_Summary;
      Timeout_MS : Natural := 30_000)
      return CryptoLib.Errors.Status;
end SSH_Lib.Git_Transport;
