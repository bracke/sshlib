with Ada.Streams;
with Ada.Strings.Unbounded;
with Interfaces;
with CryptoLib.Errors;
with GNAT.Sockets;
with SSH_Lib.Platform.FD_Passing;

--  @summary OpenSSH ControlMaster multiplexing protocol: client and master
--  sides of the Unix-domain control socket, message codec, and FD passing.
--
--  Implements the mux protocol version 4 spoken over a ControlMaster control
--  socket (mux.c compatible): encoding/decoding and framing of MUX_* messages,
--  the client request/response helpers (hello, alive check, new session,
--  forwarding, terminate/stop), stdio and channel file-descriptor passing over
--  SCM_RIGHTS, and the master-side accept/route/serve loop that dispatches
--  client requests to installed handlers.
package SSH_Lib.Mux is
   Max_Mux_Packet_Length : constant Natural := 256 * 1024;
   Mux_Unix_Socket_Port : constant Interfaces.Unsigned_32 := 16#FFFF_FFFE#;
   Mux_Protocol_Version : constant Interfaces.Unsigned_32 := 4;
   Max_Mux_Environment : constant Natural := 4096;

   type Mux_Message_Kind is
     (Mux_Hello,
      Mux_Alive_Check,
      Mux_New_Session,
      Mux_Terminate,
      Mux_Open_Fwd,
      Mux_Close_Fwd,
      Mux_New_Stdio_Fwd,
      Mux_Stop_Listening,
      Mux_Proxy,
      Mux_Ext_Info,
      Mux_Ok,
      Mux_Permission_Denied,
      Mux_Failure,
      Mux_Exit_Message,
      Mux_Remote_Port,
      Mux_TTY_Alloc_Fail,
      Mux_Session_Open,
      Mux_Alive,
      Mux_Proxy_Response,
      Mux_Ext_Info_Response,
      Mux_Unknown);

   type Mux_Master_Decision is
     (Mux_Continue,
      Mux_New_Session_Decision,
      Mux_Open_Forward_Decision,
      Mux_Close_Forward_Decision,
      Mux_New_Stdio_Forward_Decision,
      Mux_Proxy_Decision,
      Mux_Ext_Info_Decision,
      Mux_Stop_Listening_Decision,
      Mux_Terminate_Decision,
      Mux_Reject_Decision);

   type Mux_Forward_Type is
     (Mux_Forward_Local,
      Mux_Forward_Remote,
      Mux_Forward_Dynamic,
      Mux_Forward_Unknown);

   type Mux_Forward_Request is record
      Forward_Type : Mux_Forward_Type := Mux_Forward_Unknown;
      Listen_Host  : Ada.Strings.Unbounded.Unbounded_String;
      Listen_Port  : Interfaces.Unsigned_32 := 0;
      Connect_Host : Ada.Strings.Unbounded.Unbounded_String;
      Connect_Port : Interfaces.Unsigned_32 := 0;
   end record;

   subtype Mux_Environment_Range is Positive range 1 .. Max_Mux_Environment;
   type Mux_Environment_Array is
     array (Mux_Environment_Range) of Ada.Strings.Unbounded.Unbounded_String;

   type Mux_New_Session_Request is record
      Reserved      : Ada.Strings.Unbounded.Unbounded_String;
      Want_TTY      : Boolean := False;
      Want_X11      : Boolean := False;
      Want_Agent    : Boolean := False;
      Is_Subsystem  : Boolean := False;
      Escape_Char   : Interfaces.Unsigned_32 := 16#FFFF_FFFF#;
      Terminal_Type : Ada.Strings.Unbounded.Unbounded_String;
      Command       : Ada.Strings.Unbounded.Unbounded_String;
      Environment   : Mux_Environment_Array;
      Environment_Count : Natural := 0;
   end record;

   type Mux_Message is record
      Kind       : Mux_Message_Kind := Mux_Unknown;
      Request_Id : Interfaces.Unsigned_32 := 0;
      Reason     : Interfaces.Unsigned_32 := 0;
      Payload    : Ada.Streams.Stream_Element_Array
        (1 .. Ada.Streams.Stream_Element_Offset (Max_Mux_Packet_Length));
      Payload_Length : Natural := 0;
   end record;

   type Mux_Client is limited private;
   type Mux_Master is limited private;

   type Mux_Request_Handler is access function
     (Master   : in out Mux_Master;
      Client   : in out Mux_Client;
      Request  : Mux_Message;
      Response : out Mux_Message)
      return CryptoLib.Errors.Status;

   type Mux_Master_Handlers is record
      New_Session       : Mux_Request_Handler := null;
      Open_Forward      : Mux_Request_Handler := null;
      Close_Forward     : Mux_Request_Handler := null;
      New_Stdio_Forward : Mux_Request_Handler := null;
      Proxy             : Mux_Request_Handler := null;
   end record;

   --  Return the on-the-wire numeric code for a mux message kind.
   --  @param Kind the message kind to translate
   --  @return the MUX_* protocol code for the kind
   function Kind_Code
     (Kind : Mux_Message_Kind) return Interfaces.Unsigned_32;

   --  Return the message kind for an on-the-wire numeric code (Mux_Unknown
   --  for unrecognized codes).
   --  @param Code the MUX_* protocol code to translate
   --  @return the matching message kind, or Mux_Unknown if not recognized
   function Kind_For_Code
     (Code : Interfaces.Unsigned_32) return Mux_Message_Kind;

   --  Build a Mux_Message record from a kind, request id, and payload bytes.
   --  @param Kind       the message kind to set
   --  @param Request_Id the request identifier to embed
   --  @param Payload    the message payload bytes to copy in
   --  @param Packet     the assembled message record
   --  @return Ok on success, a non-Ok Status when the payload is too large
   function Encode
     (Kind       : Mux_Message_Kind;
      Request_Id : Interfaces.Unsigned_32;
      Payload    : Ada.Streams.Stream_Element_Array;
      Packet      : out Mux_Message)
      return CryptoLib.Errors.Status;

   --  Parse a mux packet body (without the outer length prefix) into a message.
   --  @param Data   the raw packet bytes to parse
   --  @param Packet the decoded message record
   --  @return Ok on success, a non-Ok Status on malformed or oversized input
   function Decode
     (Data   : Ada.Streams.Stream_Element_Array;
      Packet : out Mux_Message)
      return CryptoLib.Errors.Status;

   --  Serialize a message to wire bytes with its 4-byte length prefix.
   --  @param Packet the message to serialize
   --  @param Data   the buffer receiving the framed bytes
   --  @param Last   the index of the last byte written into Data
   --  @return Ok on success, a non-Ok Status when Data is too small
   function Frame
     (Packet : Mux_Message;
      Data   : out Ada.Streams.Stream_Element_Array;
      Last   : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   --  Return True when the client's control socket is currently connected.
   --  @param Client the mux client to inspect
   --  @return True when connected, False otherwise
   function Is_Connected (Client : Mux_Client) return Boolean;

   --  Close the client's control socket and mark it disconnected.
   --  @param Client the mux client to close
   procedure Close (Client : in out Mux_Client);

   --  Hand ownership of the client's control socket to the caller, detaching it
   --  from the client so Close will not touch it.
   --  @param Client the mux client to detach from
   --  @param Socket the detached underlying socket
   --  @return Ok on success, a non-Ok Status when the client is not connected
   function Detach_Control_Socket
     (Client : in out Mux_Client;
      Socket : out GNAT.Sockets.Socket_Type)
      return CryptoLib.Errors.Status;

   --  Connect to a running master's Unix-domain control socket.
   --  @param Socket_Path the filesystem path of the master's control socket
   --  @param Client      the resulting connected mux client
   --  @return Ok on success, a non-Ok Status when the connection fails
   function Connect_Control
     (Socket_Path : String;
      Client      : out Mux_Client)
      return CryptoLib.Errors.Status;

   --  Frame and send one message over the client's control socket.
   --  @param Client the connected mux client
   --  @param Packet the message to send
   --  @return Ok on success, a non-Ok Status on a send failure
   function Send_Message
     (Client : in out Mux_Client;
      Packet : Mux_Message)
      return CryptoLib.Errors.Status;

   --  Receive and decode one message from the client's control socket.
   --  @param Client the connected mux client
   --  @param Packet the received, decoded message
   --  @return Ok on success, a non-Ok Status on a receive or decode failure
   function Receive_Message
     (Client : in out Mux_Client;
      Packet : out Mux_Message)
      return CryptoLib.Errors.Status;

   --  Send file descriptors to the peer over the control socket via SCM_RIGHTS.
   --  @param Client      the connected mux client
   --  @param Descriptors the file descriptors to pass to the peer
   --  @return Ok on success, a non-Ok Status on a send failure
   function Send_File_Descriptors
     (Client      : in out Mux_Client;
      Descriptors : SSH_Lib.Platform.FD_Passing.File_Descriptor_Array)
      return CryptoLib.Errors.Status;

   --  Receive file descriptors passed by the peer over the control socket.
   --  @param Client         the connected mux client
   --  @param Descriptors    the buffer receiving the passed descriptors
   --  @param Received_Count the number of descriptors actually received
   --  @return Ok on success, a non-Ok Status on a receive failure
   function Receive_File_Descriptors
     (Client         : in out Mux_Client;
      Descriptors    : out SSH_Lib.Platform.FD_Passing.File_Descriptor_Array;
      Received_Count : out Natural)
      return CryptoLib.Errors.Status;

   --  Pass a session's stdin, stdout, and stderr descriptors to the peer.
   --  @param Client    the connected mux client
   --  @param Stdin_FD  the standard-input descriptor to pass
   --  @param Stdout_FD the standard-output descriptor to pass
   --  @param Stderr_FD the standard-error descriptor to pass
   --  @return Ok on success, a non-Ok Status on a send failure
   function Send_Stdio_File_Descriptors
     (Client    : in out Mux_Client;
      Stdin_FD  : SSH_Lib.Platform.FD_Passing.File_Descriptor;
      Stdout_FD : SSH_Lib.Platform.FD_Passing.File_Descriptor;
      Stderr_FD : SSH_Lib.Platform.FD_Passing.File_Descriptor)
      return CryptoLib.Errors.Status;

   --  Receive a session's stdin, stdout, and stderr descriptors from the peer.
   --  @param Client    the connected mux client
   --  @param Stdin_FD  the received standard-input descriptor
   --  @param Stdout_FD the received standard-output descriptor
   --  @param Stderr_FD the received standard-error descriptor
   --  @return Ok on success, a non-Ok Status on a receive failure
   function Receive_Stdio_File_Descriptors
     (Client    : in out Mux_Client;
      Stdin_FD  : out SSH_Lib.Platform.FD_Passing.File_Descriptor;
      Stdout_FD : out SSH_Lib.Platform.FD_Passing.File_Descriptor;
      Stderr_FD : out SSH_Lib.Platform.FD_Passing.File_Descriptor)
      return CryptoLib.Errors.Status;

   --  Send a request message and read back the master's reply in one call.
   --  @param Client     the connected mux client
   --  @param Kind       the request message kind to send
   --  @param Request_Id the request identifier to embed
   --  @param Payload    the request payload bytes
   --  @param Response   the master's reply message
   --  @return Ok on success, a non-Ok Status on a transport failure
   function Request
     (Client     : in out Mux_Client;
      Kind       : Mux_Message_Kind;
      Request_Id : Interfaces.Unsigned_32;
      Payload    : Ada.Streams.Stream_Element_Array;
      Response   : out Mux_Message)
      return CryptoLib.Errors.Status;

   --  Send a MUX_C_ALIVE_CHECK and read the master's alive response.
   --  @param Client     the connected mux client
   --  @param Request_Id the request identifier to embed
   --  @param Response   the master's alive response message
   --  @return Ok on success, a non-Ok Status on a transport failure
   function Alive_Check
     (Client     : in out Mux_Client;
      Request_Id : Interfaces.Unsigned_32;
      Response   : out Mux_Message)
      return CryptoLib.Errors.Status;

   --  Build a MUX_MSG_HELLO message advertising a protocol version.
   --  @param Version the mux protocol version to advertise
   --  @param Packet  the assembled hello message
   --  @return Ok on success, a non-Ok Status on an encoding failure
   function Encode_Hello
     (Version : Interfaces.Unsigned_32;
      Packet  : out Mux_Message)
      return CryptoLib.Errors.Status;

   --  Extract the advertised protocol version from a hello message.
   --  @param Packet  the hello message to decode
   --  @param Version the peer's advertised protocol version
   --  @return Ok on success, a non-Ok Status when the message is not a hello
   function Decode_Hello
     (Packet  : Mux_Message;
      Version : out Interfaces.Unsigned_32)
      return CryptoLib.Errors.Status;

   --  Perform the client-side hello handshake, returning the peer's version.
   --  @param Client       the connected mux client
   --  @param Peer_Version the peer's advertised protocol version
   --  @return Ok on a successful handshake, a non-Ok Status otherwise
   function Exchange_Hello
     (Client       : in out Mux_Client;
      Peer_Version : out Interfaces.Unsigned_32)
      return CryptoLib.Errors.Status;

   --  Ask the master to terminate, reading back its response.
   --  @param Client     the connected mux client
   --  @param Request_Id the request identifier to embed
   --  @param Response   the master's response message
   --  @return Ok on success, a non-Ok Status on a transport failure
   function Terminate_Master
     (Client     : in out Mux_Client;
      Request_Id : Interfaces.Unsigned_32;
      Response   : out Mux_Message)
      return CryptoLib.Errors.Status;

   --  Ask the master to stop accepting new connections, reading its response.
   --  @param Client     the connected mux client
   --  @param Request_Id the request identifier to embed
   --  @param Response   the master's response message
   --  @return Ok on success, a non-Ok Status on a transport failure
   function Stop_Listening
     (Client     : in out Mux_Client;
      Request_Id : Interfaces.Unsigned_32;
      Response   : out Mux_Message)
      return CryptoLib.Errors.Status;

   --  Serialize a port-forwarding request into a message payload.
   --  @param Request the forwarding request (type, listen and connect endpoints)
   --  @param Payload the buffer receiving the encoded payload bytes
   --  @param Last    the index of the last byte written into Payload
   --  @return Ok on success, a non-Ok Status when Payload is too small
   function Encode_Forward_Request
     (Request : Mux_Forward_Request;
      Payload : out Ada.Streams.Stream_Element_Array;
      Last    : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   --  Parse a port-forwarding request from a message payload.
   --  @param Payload the encoded forwarding-request payload bytes
   --  @param Request the decoded forwarding request
   --  @return Ok on success, a non-Ok Status on malformed input
   function Decode_Forward_Request
     (Payload : Ada.Streams.Stream_Element_Array;
      Request : out Mux_Forward_Request)
      return CryptoLib.Errors.Status;

   --  Build a reason-carrying response (failure or permission-denied) message.
   --  @param Kind       the response message kind to build
   --  @param Request_Id the request identifier being answered
   --  @param Reason     the human-readable reason string to embed
   --  @param Response   the assembled response message
   --  @return Ok on success, a non-Ok Status on an encoding failure
   function Encode_Reason_Response
     (Kind       : Mux_Message_Kind;
      Request_Id : Interfaces.Unsigned_32;
      Reason     : String;
      Response   : out Mux_Message)
      return CryptoLib.Errors.Status;

   --  Extract the reason string from a reason-carrying response payload.
   --  @param Payload the response payload bytes to parse
   --  @param Reason  the decoded reason string
   --  @return Ok on success, a non-Ok Status on malformed input
   function Decode_Reason
     (Payload : Ada.Streams.Stream_Element_Array;
      Reason  : out Ada.Strings.Unbounded.Unbounded_String)
      return CryptoLib.Errors.Status;

   --  Serialize a new-session request into a message payload.
   --  @param Request the new-session request (tty/x11/agent flags, command, env)
   --  @param Payload the buffer receiving the encoded payload bytes
   --  @param Last    the index of the last byte written into Payload
   --  @return Ok on success, a non-Ok Status when Payload is too small
   function Encode_New_Session_Request
     (Request : Mux_New_Session_Request;
      Payload : out Ada.Streams.Stream_Element_Array;
      Last    : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   --  Parse a new-session request from a message payload.
   --  @param Payload the encoded new-session-request payload bytes
   --  @param Request the decoded new-session request
   --  @return Ok on success, a non-Ok Status on malformed input
   function Decode_New_Session_Request
     (Payload : Ada.Streams.Stream_Element_Array;
      Request : out Mux_New_Session_Request)
      return CryptoLib.Errors.Status;

   --  Build a MUX_S_SESSION_OPENED response carrying the assigned session id.
   --  @param Request_Id the request identifier being answered
   --  @param Session_Id the session identifier assigned by the master
   --  @param Response   the assembled response message
   --  @return Ok on success, a non-Ok Status on an encoding failure
   function Encode_Session_Opened
     (Request_Id : Interfaces.Unsigned_32;
      Session_Id : Interfaces.Unsigned_32;
      Response   : out Mux_Message)
      return CryptoLib.Errors.Status;

   --  Extract the assigned session id from a session-opened response.
   --  @param Packet     the session-opened message to decode
   --  @param Session_Id the decoded session identifier
   --  @return Ok on success, a non-Ok Status when the message is not the
   --          expected kind
   function Decode_Session_Opened
     (Packet     : Mux_Message;
      Session_Id : out Interfaces.Unsigned_32)
      return CryptoLib.Errors.Status;

   --  Build a MUX_S_REMOTE_PORT response reporting an allocated remote port.
   --  @param Request_Id  the request identifier being answered
   --  @param Remote_Port the remote port allocated by the server
   --  @param Response     the assembled response message
   --  @return Ok on success, a non-Ok Status on an encoding failure
   function Encode_Remote_Port
     (Request_Id  : Interfaces.Unsigned_32;
      Remote_Port : Interfaces.Unsigned_32;
      Response    : out Mux_Message)
      return CryptoLib.Errors.Status;

   --  Extract the allocated remote port from a remote-port response.
   --  @param Packet      the remote-port message to decode
   --  @param Remote_Port the decoded remote port
   --  @return Ok on success, a non-Ok Status when the message is not the
   --          expected kind
   function Decode_Remote_Port
     (Packet      : Mux_Message;
      Remote_Port : out Interfaces.Unsigned_32)
      return CryptoLib.Errors.Status;

   --  Build a MUX_S_EXIT_MESSAGE reporting a session's exit status.
   --  @param Session_Id the session that exited
   --  @param Exit_Value the exit status value to report
   --  @param Response   the assembled response message
   --  @return Ok on success, a non-Ok Status on an encoding failure
   function Encode_Exit_Message
     (Session_Id : Interfaces.Unsigned_32;
      Exit_Value : Interfaces.Unsigned_32;
      Response   : out Mux_Message)
      return CryptoLib.Errors.Status;

   --  Extract the session id and exit status from an exit-message.
   --  @param Packet     the exit message to decode
   --  @param Session_Id the decoded session identifier
   --  @param Exit_Value the decoded exit status value
   --  @return Ok on success, a non-Ok Status when the message is not the
   --          expected kind
   function Decode_Exit_Message
     (Packet     : Mux_Message;
      Session_Id : out Interfaces.Unsigned_32;
      Exit_Value : out Interfaces.Unsigned_32)
      return CryptoLib.Errors.Status;

   --  Build a MUX_S_TTY_ALLOC_FAIL notifying that TTY allocation failed.
   --  @param Session_Id the session whose TTY allocation failed
   --  @param Response   the assembled response message
   --  @return Ok on success, a non-Ok Status on an encoding failure
   function Encode_TTY_Alloc_Fail
     (Session_Id : Interfaces.Unsigned_32;
      Response   : out Mux_Message)
      return CryptoLib.Errors.Status;

   --  Extract the session id from a TTY-allocation-failure message.
   --  @param Packet     the TTY-alloc-fail message to decode
   --  @param Session_Id the decoded session identifier
   --  @return Ok on success, a non-Ok Status when the message is not the
   --          expected kind
   function Decode_TTY_Alloc_Fail
     (Packet     : Mux_Message;
      Session_Id : out Interfaces.Unsigned_32)
      return CryptoLib.Errors.Status;

   --  Build an ext-info response advertising supported extension flags.
   --  @param Request_Id the request identifier being answered
   --  @param Extensions the extension flags bitmask to advertise
   --  @param Response   the assembled response message
   --  @return Ok on success, a non-Ok Status on an encoding failure
   function Encode_Ext_Info
     (Request_Id : Interfaces.Unsigned_32;
      Extensions : Interfaces.Unsigned_32;
      Response   : out Mux_Message)
      return CryptoLib.Errors.Status;

   --  Extract the advertised extension flags from an ext-info response.
   --  @param Packet     the ext-info message to decode
   --  @param Extensions the decoded extension flags bitmask
   --  @return Ok on success, a non-Ok Status when the message is not the
   --          expected kind
   function Decode_Ext_Info
     (Packet     : Mux_Message;
      Extensions : out Interfaces.Unsigned_32)
      return CryptoLib.Errors.Status;

   --  Build a proxy-mode acknowledgement response for a request.
   --  @param Request_Id the request identifier being answered
   --  @param Response   the assembled response message
   --  @return Ok on success, a non-Ok Status on an encoding failure
   function Encode_Proxy_Response
     (Request_Id : Interfaces.Unsigned_32;
      Response   : out Mux_Message)
      return CryptoLib.Errors.Status;

   --  Return True when the master's control socket is bound and listening.
   --  @param Master the mux master to inspect
   --  @return True when the master is listening, False otherwise
   function Is_Listening (Master : Mux_Master) return Boolean;

   --  Close the master's control socket and remove its socket file.
   --  @param Master the mux master to shut down
   procedure Close_Master (Master : in out Mux_Master);

   --  Create and bind a master control socket, optionally replacing an existing
   --  one, and record persistence and server-pid metadata.
   --  @param Socket_Path      the filesystem path to bind the control socket at
   --  @param Master           the resulting listening master
   --  @param Replace_Existing whether to remove a stale socket already present
   --  @param Persist_Seconds  the idle-persistence timeout in seconds (0 = none)
   --  @param Server_Pid       the SSH server process id to record with the master
   --  @return Ok on success, a non-Ok Status when binding fails
   function Start_Master
     (Socket_Path      : String;
      Master           : out Mux_Master;
      Replace_Existing : Boolean := False;
      Persist_Seconds  : Natural := 0;
      Server_Pid       : Interfaces.Unsigned_32 := 0)
      return CryptoLib.Errors.Status;

   --  Accept one incoming control-socket connection, returning a mux client.
   --  @param Master the listening mux master
   --  @param Client the accepted client connection
   --  @return Ok on success, a non-Ok Status when accepting fails
   function Accept_Control
     (Master : in out Mux_Master;
      Client : out Mux_Client)
      return CryptoLib.Errors.Status;

   --  Close a client accepted from the master and drop it from the active count.
   --  @param Master the mux master owning the client
   --  @param Client the accepted client to release
   procedure Release_Control
     (Master : in out Mux_Master;
      Client : in out Mux_Client);

   --  Update the master's idle-persistence timeout.
   --  @param Master          the mux master to reconfigure
   --  @param Persist_Seconds the new idle-persistence timeout in seconds
   procedure Configure_Persist
     (Master          : in out Mux_Master;
      Persist_Seconds : Natural);

   --  Return the master's configured idle-persistence timeout.
   --  @param Master the mux master to inspect
   --  @return the idle-persistence timeout in seconds (0 when disabled)
   function Persist_Seconds_Of (Master : Mux_Master) return Natural;

   --  Return the SSH server process id recorded with the master.
   --  @param Master the mux master to inspect
   --  @return the recorded server process id
   function Server_Pid_Of (Master : Mux_Master) return Interfaces.Unsigned_32;

   --  Return the number of clients currently attached to the master.
   --  @param Master the mux master to inspect
   --  @return the active client count
   function Active_Client_Count (Master : Mux_Master) return Natural;

   --  Decide whether the master should terminate given its idle time and its
   --  configured persistence timeout and active-client count.
   --  @param Master       the mux master to evaluate
   --  @param Idle_Seconds how long the master has been idle, in seconds
   --  @return True when the master should terminate, False to keep running
   function Should_Terminate_When_Idle
     (Master       : Mux_Master;
      Idle_Seconds : Natural)
      return Boolean;

   --  Classify a client request into the master decision it should trigger,
   --  without acting on it.
   --  @param Request  the client request message to classify
   --  @param Decision the resulting master decision
   --  @return Ok on success, a non-Ok Status when the request is malformed
   function Classify_Master_Request
     (Request  : Mux_Message;
      Decision : out Mux_Master_Decision)
      return CryptoLib.Errors.Status;

   --  Route a client request through the master's built-in default handling,
   --  producing a response and the decision taken.
   --  @param Master   the mux master handling the request
   --  @param Request  the client request message
   --  @param Response the response message to send back
   --  @param Decision the master decision taken for the request
   --  @return Ok on success, a non-Ok Status on a processing failure
   function Route_Master_Request
     (Master   : in out Mux_Master;
      Request  : Mux_Message;
      Response : out Mux_Message;
      Decision : out Mux_Master_Decision)
      return CryptoLib.Errors.Status;

   --  Route a client request through caller-supplied handlers, producing a
   --  response and the decision taken.
   --  @param Master   the mux master handling the request
   --  @param Client   the client the request arrived on
   --  @param Request  the client request message
   --  @param Handlers the application handlers to dispatch the request to
   --  @param Response the response message to send back
   --  @param Decision the master decision taken for the request
   --  @return Ok on success, a non-Ok Status on a processing failure
   function Route_Master_Request
     (Master   : in out Mux_Master;
      Client   : in out Mux_Client;
      Request  : Mux_Message;
      Handlers : Mux_Master_Handlers;
      Response : out Mux_Message;
      Decision : out Mux_Master_Decision)
      return CryptoLib.Errors.Status;

   --  Run the hello handshake and service up to Max_Requests requests from one
   --  connected client, dispatching each through the supplied handlers.
   --  @param Master       the mux master owning the client
   --  @param Client       the connected client to service
   --  @param Handlers     the application handlers to dispatch requests to
   --  @param Decision     the final master decision reached for the client
   --  @param Max_Requests the maximum number of requests to service
   --  @return Ok on success, a non-Ok Status on a processing failure
   function Process_Control_Client
     (Master       : in out Mux_Master;
      Client       : in out Mux_Client;
      Handlers     : Mux_Master_Handlers;
      Decision     : out Mux_Master_Decision;
      Max_Requests : Positive := 1)
      return CryptoLib.Errors.Status;

   --  Accept one client, service up to Max_Requests requests, and release it.
   --  @param Master       the listening mux master
   --  @param Handlers     the application handlers to dispatch requests to
   --  @param Decision     the final master decision reached for the client
   --  @param Max_Requests the maximum number of requests to service
   --  @return Ok on success, a non-Ok Status on an accept or processing failure
   function Serve_One_Control
     (Master       : in out Mux_Master;
      Handlers     : Mux_Master_Handlers;
      Decision     : out Mux_Master_Decision;
      Max_Requests : Positive := 1)
      return CryptoLib.Errors.Status;

   --  Accept one client and service up to Max_Requests requests, returning the
   --  client to the caller instead of releasing it (for FD passing follow-up).
   --  @param Master       the listening mux master
   --  @param Handlers     the application handlers to dispatch requests to
   --  @param Decision     the final master decision reached for the client
   --  @param Client       the accepted client, left open for the caller
   --  @param Max_Requests the maximum number of requests to service
   --  @return Ok on success, a non-Ok Status on an accept or processing failure
   function Serve_One_Control
     (Master       : in out Mux_Master;
      Handlers     : Mux_Master_Handlers;
      Decision     : out Mux_Master_Decision;
      Client       : out Mux_Client;
      Max_Requests : Positive := 1)
      return CryptoLib.Errors.Status;

   --  Run the master accept loop, serving up to Max_Clients clients each for up
   --  to Max_Requests_Per_Client requests, until a terminating decision.
   --  @param Master                  the listening mux master
   --  @param Handlers                the application handlers to dispatch to
   --  @param Final_Decision          the decision that ended the serve loop
   --  @param Max_Clients             the maximum number of clients to serve
   --  @param Max_Requests_Per_Client the request cap applied to each client
   --  @return Ok on success, a non-Ok Status on a processing failure
   function Serve_Control_Master
     (Master                  : in out Mux_Master;
      Handlers                : Mux_Master_Handlers;
      Final_Decision          : out Mux_Master_Decision;
      Max_Clients             : Positive := 1;
      Max_Requests_Per_Client : Positive := 1)
      return CryptoLib.Errors.Status;

private
   type Mux_Client is limited record
      Socket    : GNAT.Sockets.Socket_Type;
      Connected : Boolean := False;
      Counted   : Boolean := False;
   end record;

   type Mux_Master is limited record
      Socket          : GNAT.Sockets.Socket_Type;
      Control_Path    : Ada.Strings.Unbounded.Unbounded_String :=
        Ada.Strings.Unbounded.Null_Unbounded_String;
      Listening       : Boolean := False;
      Active_Clients  : Natural := 0;
      Persist_Seconds : Natural := 0;
      Server_Pid      : Interfaces.Unsigned_32 := 0;
   end record;
end SSH_Lib.Mux;
