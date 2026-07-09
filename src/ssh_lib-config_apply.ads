with Ada.Strings.Unbounded;
with CryptoLib.Errors;
with Interfaces;
with SSH_Lib.Channels;
with SSH_Lib.Forwarding;
with SSH_Lib.Known_Hosts;
with SSH_Lib.Mux;
with SSH_Lib.Sessions;

--  @summary Apply parsed ssh_config options to a live session.
--
--  Interprets Session_Options into concrete actions: ControlMaster planning and
--  startup, token-expanded command/path strings (ControlPath, LocalCommand,
--  KnownHostsCommand), configured local/dynamic/remote port forwards, and
--  channel setup (environment, exec, subsystem, shell/PTY).
package SSH_Lib.Config_Apply is
   Max_Configured_Forwards : constant Positive := 16;

   type Managed_Forward_Service_Array is array (Positive range <>)
     of SSH_Lib.Forwarding.Managed_Forward_Service;

   type Bound_Port_Array is array (Positive range <>) of Natural;

   type Control_Master_Mode is
     (Control_Master_Disabled,
      Control_Master_No,
      Control_Master_Yes,
      Control_Master_Ask,
      Control_Master_Auto,
      Control_Master_Auto_Ask,
      Control_Master_Invalid);

   type Control_Master_Action is
     (Control_Master_Do_Not_Use,
      Control_Master_Use_Existing,
      Control_Master_Use_Existing_Ask,
      Control_Master_Start_Master,
      Control_Master_Start_Master_Ask,
      Control_Master_Invalid_Action);

   type Request_TTY_Mode is
     (Request_TTY_Auto,
      Request_TTY_No,
      Request_TTY_Yes,
      Request_TTY_Force,
      Request_TTY_Invalid);

   type Session_Type_Mode is
     (Session_Type_Default,
      Session_Type_None,
      Session_Type_Subsystem,
      Session_Type_Invalid);

   --  Classify the ControlMaster option value into a mode enumerator.
   --  @param Options the session options to inspect
   --  @return the ControlMaster mode (Control_Master_Invalid if unrecognized)
   function Control_Master_Mode_Of
     (Options : SSH_Lib.Sessions.Session_Options)
      return Control_Master_Mode;

   --  Classify the RequestTTY option value into a mode enumerator.
   --  @param Options the session options to inspect
   --  @return the RequestTTY mode (Request_TTY_Invalid if unrecognized)
   function Request_TTY_Mode_Of
     (Options : SSH_Lib.Sessions.Session_Options)
      return Request_TTY_Mode;

   --  Classify the SessionType option value into a mode enumerator.
   --  @param Options the session options to inspect
   --  @return the SessionType mode (Session_Type_Invalid if unrecognized)
   function Session_Type_Mode_Of
     (Options : SSH_Lib.Sessions.Session_Options)
      return Session_Type_Mode;

   --  Expand the ControlPath option, substituting %-tokens (host, user, port,
   --  local host, hash) to a concrete socket path.
   --  @param Options         the session options holding ControlPath
   --  @param Original_Host   the host name as given on the command line
   --  @param Local_Host_Name the local host name for %l expansion
   --  @param Result          the expanded control-path string
   --  @return Ok on success, or an error Status on an invalid token/path
   function Expand_Control_Path
     (Options         : SSH_Lib.Sessions.Session_Options;
      Original_Host   : String;
      Local_Host_Name : String;
      Result          : out Ada.Strings.Unbounded.Unbounded_String)
      return CryptoLib.Errors.Status;

   --  Resolve the ControlPersist option into a number of seconds.
   --  @param Options the session options holding ControlPersist
   --  @param Seconds the resolved persist duration in seconds (0 = no persist)
   --  @return Ok on success, or an error Status if the value is invalid
   function Control_Persist_Seconds
     (Options : SSH_Lib.Sessions.Session_Options;
      Seconds : out Natural)
      return CryptoLib.Errors.Status;

   --  Decide, from ControlMaster/ControlPath/ControlPersist, whether to use an
   --  existing master, start a new one, or connect directly.
   --  @param Options         the session options to evaluate
   --  @param Original_Host   the host name as given on the command line
   --  @param Local_Host_Name the local host name for token expansion
   --  @param Control_Path    the expanded control-socket path
   --  @param Persist_Seconds the resolved ControlPersist duration in seconds
   --  @param Action          the planned ControlMaster action
   --  @return Ok on success, or an error Status on failure
   function Plan_Control_Master
     (Options         : SSH_Lib.Sessions.Session_Options;
      Original_Host   : String;
      Local_Host_Name : String;
      Control_Path    : out Ada.Strings.Unbounded.Unbounded_String;
      Persist_Seconds : out Natural;
      Action          : out Control_Master_Action)
      return CryptoLib.Errors.Status;

   --  Execute the plan from Plan_Control_Master, starting the mux master and
   --  binding its control socket when the action calls for it.
   --  @param Options          the session options to evaluate
   --  @param Original_Host    the host name as given on the command line
   --  @param Local_Host_Name  the local host name for token expansion
   --  @param Master           the mux master to start and bind
   --  @param Control_Path     the expanded control-socket path
   --  @param Persist_Seconds  the resolved ControlPersist duration in seconds
   --  @param Action           the planned ControlMaster action taken
   --  @param Replace_Existing when True, replace a stale existing master socket
   --  @param Server_Pid       the server process id to record (0 if unknown)
   --  @return Ok on success, or an error Status on failure
   function Start_Planned_Control_Master
     (Options          : SSH_Lib.Sessions.Session_Options;
      Original_Host    : String;
      Local_Host_Name  : String;
      Master           : in out SSH_Lib.Mux.Mux_Master;
      Control_Path     : out Ada.Strings.Unbounded.Unbounded_String;
      Persist_Seconds  : out Natural;
      Action           : out Control_Master_Action;
      Replace_Existing : Boolean := False;
      Server_Pid       : Interfaces.Unsigned_32 := 0)
      return CryptoLib.Errors.Status;

   --  Expand the LocalCommand option, substituting %-tokens to a command string.
   --  @param Options         the session options holding LocalCommand
   --  @param Original_Host   the host name as given on the command line
   --  @param Local_Host_Name the local host name for %l expansion
   --  @param Result          the expanded command string
   --  @return Ok on success, or an error Status on an invalid token
   function Expand_Local_Command
     (Options         : SSH_Lib.Sessions.Session_Options;
      Original_Host   : String;
      Local_Host_Name : String;
      Result          : out Ada.Strings.Unbounded.Unbounded_String)
      return CryptoLib.Errors.Status;

   --  Expand the KnownHostsCommand option, substituting %-tokens including the
   --  presented key and lookup reason.
   --  @param Options         the session options holding KnownHostsCommand
   --  @param Original_Host   the host name as given on the command line
   --  @param Local_Host_Name the local host name for %l expansion
   --  @param Reason          the lookup reason token to substitute
   --  @param Presented_Key   the host key being checked, for key tokens
   --  @param Result          the expanded command string
   --  @return Ok on success, or an error Status on an invalid token
   function Expand_Known_Hosts_Command
     (Options         : SSH_Lib.Sessions.Session_Options;
      Original_Host   : String;
      Local_Host_Name : String;
      Reason          : String;
      Presented_Key   : SSH_Lib.Known_Hosts.Host_Key;
      Result          : out Ada.Strings.Unbounded.Unbounded_String)
      return CryptoLib.Errors.Status;

   --  Start all configured LocalForward listeners on the session.
   --  @param Session  the session to attach the forwards to
   --  @param Options  the session options holding LocalForward entries
   --  @param Services the array receiving the started forward services
   --  @param Started  the number of forwards actually started
   --  @return Ok on success, or an error Status on failure
   function Start_Configured_Local_Forwards
     (Session  : in out SSH_Lib.Sessions.Session;
      Options  : SSH_Lib.Sessions.Session_Options;
      Services : in out Managed_Forward_Service_Array;
      Started  : out Natural)
      return CryptoLib.Errors.Status;

   --  Start all configured DynamicForward (SOCKS) listeners on the session.
   --  @param Session  the session to attach the forwards to
   --  @param Options  the session options holding DynamicForward entries
   --  @param Services the array receiving the started forward services
   --  @param Started  the number of forwards actually started
   --  @return Ok on success, or an error Status on failure
   function Start_Configured_Dynamic_Forwards
     (Session  : in out SSH_Lib.Sessions.Session;
      Options  : SSH_Lib.Sessions.Session_Options;
      Services : in out Managed_Forward_Service_Array;
      Started  : out Natural)
      return CryptoLib.Errors.Status;

   --  Send remote-forward (RemoteForward) requests to the server, recording the
   --  ports the server bound.
   --  @param Session     the session to issue the requests on
   --  @param Options     the session options holding RemoteForward entries
   --  @param Bound_Ports the array receiving each server-bound port
   --  @param Requested   the number of remote forwards requested
   --  @return Ok on success, or an error Status on failure
   function Request_Configured_Remote_Forwards
     (Session     : in out SSH_Lib.Sessions.Session;
      Options     : SSH_Lib.Sessions.Session_Options;
      Bound_Ports : out Bound_Port_Array;
      Requested   : out Natural)
      return CryptoLib.Errors.Status;

   --  Request configured RemoteForwards and start the local services that
   --  handle their inbound channels.
   --  @param Session     the session to attach the forwards to
   --  @param Options     the session options holding RemoteForward entries
   --  @param Services    the array receiving the started forward services
   --  @param Bound_Ports the array receiving each server-bound port
   --  @param Started     the number of remote forwards started
   --  @return Ok on success, or an error Status on failure
   function Start_Configured_Remote_Forwards
     (Session     : in out SSH_Lib.Sessions.Session;
      Options     : SSH_Lib.Sessions.Session_Options;
      Services    : in out Managed_Forward_Service_Array;
      Bound_Ports : out Bound_Port_Array;
      Started     : out Natural)
      return CryptoLib.Errors.Status;

   --  Start all configured forwards (local, dynamic, and remote) in one call.
   --  @param Session          the session to attach the forwards to
   --  @param Options          the session options holding all forward entries
   --  @param Local_Services   the array receiving started local forward services
   --  @param Dynamic_Services the array receiving started dynamic forward services
   --  @param Remote_Services  the array receiving started remote forward services
   --  @param Remote_Ports     the array receiving each server-bound remote port
   --  @param Local_Started    the number of local forwards started
   --  @param Dynamic_Started  the number of dynamic forwards started
   --  @param Remote_Started   the number of remote forwards started
   --  @return Ok on success, or an error Status on failure
   function Start_Configured_Forwards
     (Session          : in out SSH_Lib.Sessions.Session;
      Options          : SSH_Lib.Sessions.Session_Options;
      Local_Services   : in out Managed_Forward_Service_Array;
      Dynamic_Services : in out Managed_Forward_Service_Array;
      Remote_Services  : in out Managed_Forward_Service_Array;
      Remote_Ports     : out Bound_Port_Array;
      Local_Started    : out Natural;
      Dynamic_Started  : out Natural;
      Remote_Started   : out Natural)
      return CryptoLib.Errors.Status;

   --  Send the SetEnv/SendEnv configured environment variables on a channel.
   --  @param Session the session owning the channel
   --  @param Channel the channel to send env requests on
   --  @param Options the session options holding SetEnv/SendEnv entries
   --  @return Ok on success, or an error Status on failure
   function Apply_Configured_Environment
     (Session : in out SSH_Lib.Sessions.Session;
      Channel : in out SSH_Lib.Channels.Channel;
      Options : SSH_Lib.Sessions.Session_Options)
      return CryptoLib.Errors.Status;

   --  Open an exec channel running the configured RemoteCommand, or the given
   --  default command when none is configured.
   --  @param Session         the session to open the channel on
   --  @param Options         the session options holding RemoteCommand
   --  @param Default_Command the command to run when none is configured
   --  @param Channel         the opened exec channel
   --  @return Ok on success, or an error Status on failure
   function Open_Configured_Exec
     (Session         : in out SSH_Lib.Sessions.Session;
      Options         : SSH_Lib.Sessions.Session_Options;
      Default_Command : String;
      Channel         : in out SSH_Lib.Channels.Channel)
      return CryptoLib.Errors.Status;

   --  Open a subsystem channel for the configured subsystem, or the given
   --  default subsystem when none is configured.
   --  @param Session           the session to open the channel on
   --  @param Options           the session options holding the subsystem name
   --  @param Default_Subsystem the subsystem to request when none is configured
   --  @param Channel           the opened subsystem channel
   --  @return Ok on success, or an error Status on failure
   function Open_Configured_Subsystem
     (Session           : in out SSH_Lib.Sessions.Session;
      Options           : SSH_Lib.Sessions.Session_Options;
      Default_Subsystem : String;
      Channel           : in out SSH_Lib.Channels.Channel)
      return CryptoLib.Errors.Status;

   --  Open an interactive shell channel, requesting a PTY per the RequestTTY
   --  option and the given terminal geometry and modes.
   --  @param Session        the session to open the channel on
   --  @param Options        the session options governing PTY/TTY behavior
   --  @param Channel        the opened shell channel
   --  @param Terminal_Type  the terminal type to request (e.g. "xterm")
   --  @param Columns        the terminal width in columns
   --  @param Rows           the terminal height in rows
   --  @param Width_Pixels   the terminal width in pixels (0 if unspecified)
   --  @param Height_Pixels  the terminal height in pixels (0 if unspecified)
   --  @param Terminal_Modes the encoded terminal-mode settings
   --  @return Ok on success, or an error Status on failure
   function Open_Configured_Shell
     (Session        : in out SSH_Lib.Sessions.Session;
      Options        : SSH_Lib.Sessions.Session_Options;
      Channel        : in out SSH_Lib.Channels.Channel;
      Terminal_Type  : String := "xterm";
      Columns        : Natural := 80;
      Rows           : Natural := 24;
      Width_Pixels   : Natural := 0;
      Height_Pixels  : Natural := 0;
      Terminal_Modes : SSH_Lib.Channels.Terminal_Mode_Array :=
        SSH_Lib.Channels.Empty_Terminal_Modes)
      return CryptoLib.Errors.Status;
end SSH_Lib.Config_Apply;
