with Ada.Streams;
with CryptoLib.Errors;
with GNAT.Sockets;
with System;
with SSH_Lib.Channels;
with SSH_Lib.Sessions;

--  @summary TCP port forwarding over SSH: local, dynamic (SOCKS5) and remote.
--
--  Implements OpenSSH-style forwarding on top of SSH channels: local forwards
--  (-L) that bind a local listener and open a direct-tcpip channel per accepted
--  connection, dynamic forwards (-D) that speak the SOCKS5 CONNECT protocol to
--  learn each target, and remote forwards (-R) driven from server-initiated
--  channels, plus X11 display forwarding helpers.  Low-level building blocks
--  (listener/accept, read/write, byte pumping) are exposed alongside two
--  turnkey drivers: a single-connection Forward_Service and a concurrent,
--  worker-pooled Managed_Forward_Service, each with status/counter accessors.
package SSH_Lib.Forwarding is
   type Local_Forward_Listener is limited private;
   type Local_Forward_Connection is limited private;
   type Forward_Service is limited private;
   type Managed_Forward_Service is limited private;
   type SOCKS5_Target is private;
   type X11_Display_Target is private;
   type Pump_Direction is (Local_To_Channel, Channel_To_Local);
   type Forward_Service_Mode is
     (Local_Forward_Service,
      Dynamic_Forward_Service,
      Remote_Forward_Service);
   type X11_Display_Transport is (X11_Unix_Domain, X11_TCP);

   type Local_Forward_Handler is access procedure
     (Connection : in out Local_Forward_Connection;
      Channel    : in out SSH_Lib.Channels.Channel;
      Status     : CryptoLib.Errors.Status);

   type Dynamic_Forward_Handler is access procedure
     (Connection : in out Local_Forward_Connection;
      Channel    : in out SSH_Lib.Channels.Channel;
      Target     : SOCKS5_Target;
      Status     : CryptoLib.Errors.Status);

   --  Return the target host requested by a parsed SOCKS5 CONNECT.
   --  @param Target the parsed SOCKS5 target
   --  @return the target host name or address string
   function SOCKS5_Host (Target : SOCKS5_Target) return String;

   --  Return the target port requested by a parsed SOCKS5 CONNECT.
   --  @param Target the parsed SOCKS5 target
   --  @return the target port number
   function SOCKS5_Port (Target : SOCKS5_Target) return Natural;

   --  Parse an X11 DISPLAY specification (e.g. "localhost:10.0") into a target.
   --  @param Display the DISPLAY string to parse
   --  @param Target the parsed X11 display target on success
   --  @return Ok on success, or an error status when the DISPLAY is malformed
   function Parse_X11_Display
     (Display : String;
      Target  : out X11_Display_Target)
      return CryptoLib.Errors.Status;

   --  Parse the X11 display from the process DISPLAY environment variable.
   --  @param Target the parsed X11 display target on success
   --  @return Ok on success, or an error status when DISPLAY is unset/malformed
   function Parse_X11_Display_From_Environment
     (Target : out X11_Display_Target)
      return CryptoLib.Errors.Status;

   --  Report whether an X11 display target uses a Unix socket or TCP transport.
   --  @param Target the parsed X11 display target
   --  @return X11_Unix_Domain or X11_TCP
   function X11_Display_Kind
     (Target : X11_Display_Target)
      return X11_Display_Transport;

   --  Return the TCP host of an X11 display target.
   --  @param Target the parsed X11 display target
   --  @return the display host name or address
   function X11_Display_Host (Target : X11_Display_Target) return String;

   --  Return the TCP port an X11 display target connects to.
   --  @param Target the parsed X11 display target
   --  @return the resolved X11 TCP port (6000 + display number)
   function X11_Display_Port (Target : X11_Display_Target) return Natural;

   --  Return the Unix-domain socket path of an X11 display target.
   --  @param Target the parsed X11 display target
   --  @return the X11 socket path, empty for a TCP display
   function X11_Display_Socket_Path
     (Target : X11_Display_Target) return String;

   --  Return the X11 display number of a display target.
   --  @param Target the parsed X11 display target
   --  @return the display number (the N in ":N")
   function X11_Display_Number (Target : X11_Display_Target) return Natural;

   --  Return the X11 screen number of a display target.
   --  @param Target the parsed X11 display target
   --  @return the screen number (the S in ":N.S")
   function X11_Display_Screen (Target : X11_Display_Target) return Natural;

   --  Connect to the local X server named by a parsed X11 display target.
   --  @param Target the parsed X11 display target to connect to
   --  @param Connection the opened local connection to the X server
   --  @return Ok on success, or an error status on connection failure
   function Open_X11_Display
     (Target     : X11_Display_Target;
      Connection : out Local_Forward_Connection)
      return CryptoLib.Errors.Status;

   --  Parse a DISPLAY string and connect to the local X server it names.
   --  @param Display the DISPLAY string identifying the X server
   --  @param Connection the opened local connection to the X server
   --  @return Ok on success, or an error status on parse or connection failure
   function Open_X11_Display
     (Display    : String;
      Connection : out Local_Forward_Connection)
      return CryptoLib.Errors.Status;

   --  Parse a raw SOCKS5 CONNECT request buffer into a target.
   --  @param Request the raw SOCKS5 CONNECT request bytes
   --  @param Target the parsed target host and port on success
   --  @return Ok on success, or an error status when the request is malformed
   function Parse_SOCKS5_CONNECT_Request
     (Request : Ada.Streams.Stream_Element_Array;
      Target  : out SOCKS5_Target)
      return CryptoLib.Errors.Status;

   --  Read and parse a SOCKS5 greeting and CONNECT request from a connection.
   --  @param Connection the local client connection to read the request from
   --  @param Target the parsed target host and port on success
   --  @return Ok on success, or an error status on I/O or protocol failure
   function Read_SOCKS5_CONNECT_Request
     (Connection : in out Local_Forward_Connection;
      Target     : out SOCKS5_Target)
      return CryptoLib.Errors.Status;

   --  Send a SOCKS5 reply reporting the outcome of a CONNECT to the client.
   --  @param Connection the local client connection to reply on
   --  @param Reply_Status the CONNECT outcome mapped to a SOCKS5 reply code
   --  @param Bind_Address the bound address reported in the reply
   --  @param Bind_Port the bound port reported in the reply
   --  @return Ok on success, or an error status on write failure
   function Send_SOCKS5_Reply
     (Connection   : in out Local_Forward_Connection;
      Reply_Status : CryptoLib.Errors.Status;
      Bind_Address : String := "0.0.0.0";
      Bind_Port    : Natural := 0)
      return CryptoLib.Errors.Status;

   --  Bind a local listening socket for a local (-L) forward to a fixed target.
   --  @param Bind_Address the local address to bind the listener to
   --  @param Bind_Port the local port to listen on (0 picks an ephemeral port)
   --  @param Target_Host the remote host each connection is forwarded to
   --  @param Target_Port the remote port each connection is forwarded to
   --  @param Listener the opened listener on success
   --  @param Backlog the socket listen backlog
   --  @return Ok on success, or an error status on validation or bind failure
   function Open_Local_Forward_Listener
     (Bind_Address : String;
      Bind_Port    : Natural;
      Target_Host  : String;
      Target_Port  : Natural;
      Listener     : out Local_Forward_Listener;
      Backlog      : Natural := 16)
      return CryptoLib.Errors.Status;

   --  Bind a local listening socket for a dynamic (-D) SOCKS5 forward.
   --  @param Bind_Address the local address to bind the listener to
   --  @param Bind_Port the local port to listen on (0 picks an ephemeral port)
   --  @param Listener the opened listener on success
   --  @param Backlog the socket listen backlog
   --  @return Ok on success, or an error status on validation or bind failure
   function Open_Dynamic_Forward_Listener
     (Bind_Address : String;
      Bind_Port    : Natural;
      Listener     : out Local_Forward_Listener;
      Backlog      : Natural := 16)
      return CryptoLib.Errors.Status;

   --  Return the local port a listener is actually bound to.
   --  @param Listener the opened forward listener
   --  @return the bound local port number
   function Bound_Port (Listener : Local_Forward_Listener) return Natural;

   --  Accept one local-forward connection and open its direct-tcpip channel.
   --  @param Session the SSH session used to open the forwarding channel
   --  @param Listener the local-forward listener to accept on
   --  @param Connection the accepted local client connection
   --  @param Channel the opened direct-tcpip channel to the fixed target
   --  @return Ok on success, or an error status on accept or channel failure
   function Accept_Local_Forward
     (Session    : in out SSH_Lib.Sessions.Session;
      Listener   : in out Local_Forward_Listener;
      Connection : out Local_Forward_Connection;
      Channel    : in out SSH_Lib.Channels.Channel)
      return CryptoLib.Errors.Status;

   --  Accept one dynamic-forward connection, read its SOCKS5 CONNECT and open
   --  a direct-tcpip channel to the requested target, replying to the client.
   --  @param Session the SSH session used to open the forwarding channel
   --  @param Listener the dynamic-forward listener to accept on
   --  @param Connection the accepted local client connection
   --  @param Channel the opened direct-tcpip channel to the SOCKS5 target
   --  @param Target the target host and port parsed from the SOCKS5 request
   --  @return Ok on success, or an error status on accept, SOCKS5 or channel
   --  failure
   function Accept_Dynamic_Forward
     (Session    : in out SSH_Lib.Sessions.Session;
      Listener   : in out Local_Forward_Listener;
      Connection : out Local_Forward_Connection;
      Channel    : in out SSH_Lib.Channels.Channel;
      Target     : out SOCKS5_Target)
      return CryptoLib.Errors.Status;

   --  Read available bytes from the local side of a forward connection.
   --  @param Connection the local connection to read from
   --  @param Buffer the buffer to receive the bytes read
   --  @param Last the index of the last byte written into Buffer
   --  @return Ok on success, or an error status on read failure
   function Read_Local
     (Connection : in out Local_Forward_Connection;
      Buffer     : out Ada.Streams.Stream_Element_Array;
      Last       : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   --  Write bytes to the local side of a forward connection.
   --  @param Connection the local connection to write to
   --  @param Data the bytes to write
   --  @return Ok on success, or an error status on write failure
   function Write_Local
     (Connection : in out Local_Forward_Connection;
      Data       : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Move up to one chunk of bytes in one direction between local and channel.
   --  @param Connection the local side of the forward
   --  @param Channel the SSH channel side of the forward
   --  @param Direction which way to move data (Local_To_Channel or reverse)
   --  @param Bytes_Moved the number of bytes transferred this call
   --  @param Max_Chunk_Size the maximum bytes to move in one call
   --  @return Ok on progress, Timeout when no data was available, else an error
   function Pump_Once
     (Connection     : in out Local_Forward_Connection;
      Channel        : in out SSH_Lib.Channels.Channel;
      Direction      : Pump_Direction;
      Bytes_Moved    : out Natural;
      Max_Chunk_Size : Natural := 4096)
      return CryptoLib.Errors.Status;

   --  Pump both directions for a bounded number of iterations without blocking.
   --  @param Connection the local side of the forward
   --  @param Channel the SSH channel side of the forward
   --  @param Local_To_Channel_Bytes the total bytes moved local-to-channel
   --  @param Channel_To_Local_Bytes the total bytes moved channel-to-local
   --  @param Max_Iterations the maximum bidirectional pump iterations to run
   --  @param Max_Chunk_Size the maximum bytes moved per direction per iteration
   --  @return Ok when progress was made, Timeout when idle, else an error
   function Pump_Bounded
     (Connection               : in out Local_Forward_Connection;
      Channel                  : in out SSH_Lib.Channels.Channel;
      Local_To_Channel_Bytes   : out Natural;
      Channel_To_Local_Bytes   : out Natural;
      Max_Iterations           : Natural := 64;
      Max_Chunk_Size           : Natural := 4096)
      return CryptoLib.Errors.Status;

   --  Start a background single-connection local (-L) forward service that
   --  invokes Handler for each accepted connection.
   --  @param Session the SSH session the forwarding channels are opened on
   --  @param Bind_Address the local address to bind the listener to
   --  @param Bind_Port the local port to listen on (0 picks an ephemeral port)
   --  @param Target_Host the remote host connections are forwarded to
   --  @param Target_Port the remote port connections are forwarded to
   --  @param Handler the callback run per accepted connection and channel
   --  @param Service the forward service handle to start
   --  @param Backlog the socket listen backlog
   --  @param Max_Accepted the connection cap before the service stops (0 = none)
   --  @return Ok on success, or an error status on validation or start failure
   function Start_Local_Forward_Service
     (Session      : in out SSH_Lib.Sessions.Session;
      Bind_Address : String;
      Bind_Port    : Natural;
      Target_Host  : String;
      Target_Port  : Natural;
      Handler      : Local_Forward_Handler;
      Service      : in out Forward_Service;
      Backlog      : Natural := 16;
      Max_Accepted : Natural := 0)
      return CryptoLib.Errors.Status;

   --  Start a background single-connection dynamic (-D) SOCKS5 forward service
   --  that invokes Handler for each accepted connection.
   --  @param Session the SSH session the forwarding channels are opened on
   --  @param Bind_Address the local address to bind the listener to
   --  @param Bind_Port the local port to listen on (0 picks an ephemeral port)
   --  @param Handler the callback run per accepted connection, channel and
   --  SOCKS5 target
   --  @param Service the forward service handle to start
   --  @param Backlog the socket listen backlog
   --  @param Max_Accepted the connection cap before the service stops (0 = none)
   --  @return Ok on success, or an error status on validation or start failure
   function Start_Dynamic_Forward_Service
     (Session      : in out SSH_Lib.Sessions.Session;
      Bind_Address : String;
      Bind_Port    : Natural;
      Handler      : Dynamic_Forward_Handler;
      Service      : in out Forward_Service;
      Backlog      : Natural := 16;
      Max_Accepted : Natural := 0)
      return CryptoLib.Errors.Status;

   --  Start a concurrent, worker-pooled local (-L) forward service that pumps
   --  each accepted connection to its fixed target automatically.
   --  @param Session the SSH session the forwarding channels are opened on
   --  @param Bind_Address the local address to bind the listener to
   --  @param Bind_Port the local port to listen on (0 picks an ephemeral port)
   --  @param Target_Host the remote host connections are forwarded to
   --  @param Target_Port the remote port connections are forwarded to
   --  @param Service the managed forward service handle to start
   --  @param Backlog the socket listen backlog
   --  @param Max_Concurrent the maximum number of connections pumped at once
   --  @param Max_Accepted the connection cap before the service stops (0 = none)
   --  @param Max_Pump_Iterations the pump iterations per worker scheduling slice
   --  @param Max_Chunk_Size the maximum bytes moved per direction per iteration
   --  @return Ok on success, or an error status on validation or start failure
   function Start_Managed_Local_Forward_Service
     (Session             : in out SSH_Lib.Sessions.Session;
      Bind_Address        : String;
      Bind_Port           : Natural;
      Target_Host         : String;
      Target_Port         : Natural;
      Service             : in out Managed_Forward_Service;
      Backlog             : Natural := 16;
      Max_Concurrent      : Natural := 4;
      Max_Accepted        : Natural := 0;
      Max_Pump_Iterations : Natural := 64;
      Max_Chunk_Size      : Natural := 4096)
      return CryptoLib.Errors.Status;

   --  Start a concurrent, worker-pooled dynamic (-D) SOCKS5 forward service
   --  that pumps each accepted connection automatically.
   --  @param Session the SSH session the forwarding channels are opened on
   --  @param Bind_Address the local address to bind the listener to
   --  @param Bind_Port the local port to listen on (0 picks an ephemeral port)
   --  @param Service the managed forward service handle to start
   --  @param Backlog the socket listen backlog
   --  @param Max_Concurrent the maximum number of connections pumped at once
   --  @param Max_Accepted the connection cap before the service stops (0 = none)
   --  @param Max_Pump_Iterations the pump iterations per worker scheduling slice
   --  @param Max_Chunk_Size the maximum bytes moved per direction per iteration
   --  @return Ok on success, or an error status on validation or start failure
   function Start_Managed_Dynamic_Forward_Service
     (Session             : in out SSH_Lib.Sessions.Session;
      Bind_Address        : String;
      Bind_Port           : Natural;
      Service             : in out Managed_Forward_Service;
      Backlog             : Natural := 16;
      Max_Concurrent      : Natural := 4;
      Max_Accepted        : Natural := 0;
      Max_Pump_Iterations : Natural := 64;
      Max_Chunk_Size      : Natural := 4096)
      return CryptoLib.Errors.Status;

   --  Start a concurrent, worker-pooled remote (-R) forward service that
   --  requests a remote listener and pumps each server-initiated connection to
   --  the local target.
   --  @param Session the SSH session used to request the remote forward
   --  @param Bind_Address the remote address the server binds the listener to
   --  @param Bind_Port the remote port the server listens on (0 = server picks)
   --  @param Target_Host the local host each forwarded connection is sent to
   --  @param Target_Port the local port each forwarded connection is sent to
   --  @param Service the managed forward service handle to start
   --  @param Max_Accepted the connection cap before the service stops (0 = none)
   --  @param Max_Pump_Iterations the pump iterations per worker scheduling slice
   --  @param Max_Chunk_Size the maximum bytes moved per direction per iteration
   --  @return Ok on success, or an error status on validation or start failure
   function Start_Managed_Remote_Forward_Service
     (Session             : in out SSH_Lib.Sessions.Session;
      Bind_Address        : String;
      Bind_Port           : Natural;
      Target_Host         : String;
      Target_Port         : Natural;
      Service             : in out Managed_Forward_Service;
      Max_Accepted        : Natural := 0;
      Max_Pump_Iterations : Natural := 64;
      Max_Chunk_Size      : Natural := 4096)
      return CryptoLib.Errors.Status;

   --  Report whether a single-connection forward service is still running.
   --  @param Service the forward service to query
   --  @return True while the service task is running
   function Forward_Service_Running (Service : Forward_Service) return Boolean;

   --  Return the last status recorded by a single-connection forward service.
   --  @param Service the forward service to query
   --  @return the most recent status, Ok when no error has occurred
   function Forward_Service_Status
     (Service : Forward_Service) return CryptoLib.Errors.Status;

   --  Return the number of connections a forward service has accepted.
   --  @param Service the forward service to query
   --  @return the count of accepted connections
   function Forward_Service_Accepted_Count
     (Service : Forward_Service) return Natural;

   --  Return the accepted-connection cap configured for a forward service.
   --  @param Service the forward service to query
   --  @return the configured cap, 0 for unlimited
   function Forward_Service_Max_Accepted
     (Service : Forward_Service) return Natural;

   --  Return the local port a forward service's listener is bound to.
   --  @param Service the forward service to query
   --  @return the bound local port number
   function Forward_Service_Bound_Port (Service : Forward_Service) return Natural;

   --  Return whether a forward service is a local, dynamic or remote forward.
   --  @param Service the forward service to query
   --  @return the service mode
   function Forward_Service_Kind
     (Service : Forward_Service) return Forward_Service_Mode;

   --  Report whether a managed forward service is still running.
   --  @param Service the managed forward service to query
   --  @return True while the service is running
   function Managed_Forward_Service_Running
     (Service : Managed_Forward_Service) return Boolean;

   --  Return the last status recorded by a managed forward service.
   --  @param Service the managed forward service to query
   --  @return the most recent status, Ok when no error has occurred
   function Managed_Forward_Service_Status
     (Service : Managed_Forward_Service) return CryptoLib.Errors.Status;

   --  Return the number of connections a managed forward service has accepted.
   --  @param Service the managed forward service to query
   --  @return the count of accepted connections
   function Managed_Forward_Service_Accepted_Count
     (Service : Managed_Forward_Service) return Natural;

   --  Return the number of connections a managed service has finished pumping.
   --  @param Service the managed forward service to query
   --  @return the count of completed connections
   function Managed_Forward_Service_Completed_Count
     (Service : Managed_Forward_Service) return Natural;

   --  Return the number of connections a managed service is actively pumping.
   --  @param Service the managed forward service to query
   --  @return the count of currently active connections
   function Managed_Forward_Service_Active_Count
     (Service : Managed_Forward_Service) return Natural;

   --  Return the number of connections a managed service ended with an error.
   --  @param Service the managed forward service to query
   --  @return the count of failed connections
   function Managed_Forward_Service_Failed_Count
     (Service : Managed_Forward_Service) return Natural;

   --  Return the concurrency limit configured for a managed forward service.
   --  @param Service the managed forward service to query
   --  @return the maximum number of connections pumped at once
   function Managed_Forward_Service_Max_Concurrent
     (Service : Managed_Forward_Service) return Natural;

   --  Return the accepted-connection cap configured for a managed service.
   --  @param Service the managed forward service to query
   --  @return the configured cap, 0 for unlimited
   function Managed_Forward_Service_Max_Accepted
     (Service : Managed_Forward_Service) return Natural;

   --  Return the port a managed service's listener is bound to (local for
   --  local/dynamic forwards, remote for remote forwards).
   --  @param Service the managed forward service to query
   --  @return the bound port number
   function Managed_Forward_Service_Bound_Port
     (Service : Managed_Forward_Service) return Natural;

   --  Return whether a managed service is a local, dynamic or remote forward.
   --  @param Service the managed forward service to query
   --  @return the service mode
   function Managed_Forward_Service_Kind
     (Service : Managed_Forward_Service) return Forward_Service_Mode;

   --  Stop a single-connection forward service and release its listener.
   --  @param Service the forward service to stop
   --  @return Ok on success, or an error status on shutdown failure
   function Stop (Service : in out Forward_Service)
      return CryptoLib.Errors.Status;

   --  Stop a managed forward service, its workers and its listener.
   --  @param Service the managed forward service to stop
   --  @return Ok on success, or an error status on shutdown failure
   function Stop (Service : in out Managed_Forward_Service)
      return CryptoLib.Errors.Status;

   --  Close the socket of a local forward connection.
   --  @param Connection the connection to close
   --  @return Ok on success, or an error status on close failure
   function Close (Connection : in out Local_Forward_Connection)
      return CryptoLib.Errors.Status;

   --  Close a forward listener's socket and mark it unopened.
   --  @param Listener the listener to close
   --  @return Ok on success, or an error status on close failure
   function Close (Listener : in out Local_Forward_Listener)
      return CryptoLib.Errors.Status;

private
   type SOCKS5_Target is record
      Host_Text   : String (1 .. 255) := [others => Character'Val (0)];
      Host_Length : Natural := 0;
      Port_Value  : Natural := 0;
   end record;

   type X11_Display_Target is record
      Valid        : Boolean := False;
      Kind         : X11_Display_Transport := X11_Unix_Domain;
      Host_Text    : String (1 .. 255) := [others => Character'Val (0)];
      Host_Length  : Natural := 0;
      Socket_Path  : String (1 .. 255) := [others => Character'Val (0)];
      Path_Length  : Natural := 0;
      Port_Value   : Natural := 0;
      Display_Num  : Natural := 0;
      Screen_Num   : Natural := 0;
   end record;

   type Local_Forward_Listener is limited record
      Opened      : Boolean := False;
      Socket      : GNAT.Sockets.Socket_Type;
      Bound_Port_Value : Natural := 0;
      Target_Host_Text : String (1 .. 255) := [others => Character'Val (0)];
      Target_Host_Length : Natural := 0;
      Target_Port_Value  : Natural := 0;
   end record;

   type Local_Forward_Connection is limited record
      Connected : Boolean := False;
      Socket    : GNAT.Sockets.Socket_Type;
   end record;

   task type Forward_Service_Task is
      entry Start
        (Service_Address : System.Address;
         Session_Address : System.Address);
   end Forward_Service_Task;

   type Forward_Service_Task_Access is access Forward_Service_Task;

   Maximum_Managed_Forward_Workers : constant Positive := 32;

   task type Managed_Forward_Worker is
      entry Start
        (Service_Address : System.Address;
         Session_Address : System.Address);
   end Managed_Forward_Worker;

   type Managed_Forward_Worker_Access is access Managed_Forward_Worker;
   type Managed_Forward_Worker_Array is array
     (Positive range 1 .. Maximum_Managed_Forward_Workers)
      of Managed_Forward_Worker_Access;

   type Forward_Service is limited record
      Mode                : Forward_Service_Mode := Local_Forward_Service;
      Listener            : Local_Forward_Listener;
      Task_Item           : Forward_Service_Task_Access := null;
      Local_Handler       : Local_Forward_Handler := null;
      Dynamic_Handler     : Dynamic_Forward_Handler := null;
      Running             : Boolean := False;
      Stop_Requested      : Boolean := False;
      Last_Status         : CryptoLib.Errors.Status := CryptoLib.Errors.Ok;
      Accepted_Count      : Natural := 0;
      Max_Accepted_Count  : Natural := 0;
   end record;

   type Managed_Forward_Service is limited record
      Mode                : Forward_Service_Mode := Local_Forward_Service;
      Listener            : Local_Forward_Listener;
      Workers             : Managed_Forward_Worker_Array := [others => null];
      Running             : Boolean := False;
      Stop_Requested      : Boolean := False;
      Last_Status         : CryptoLib.Errors.Status := CryptoLib.Errors.Ok;
      Accepted_Count      : Natural := 0;
      Completed_Count     : Natural := 0;
      Active_Count        : Natural := 0;
      Failed_Count        : Natural := 0;
      Max_Concurrent_Count : Natural := 0;
      Max_Accepted_Count  : Natural := 0;
      Max_Pump_Iterations_Value : Natural := 64;
      Max_Chunk_Size_Value : Natural := 4096;
      Remote_Bind_Host_Text : String (1 .. 255) := [others => Character'Val (0)];
      Remote_Bind_Host_Length : Natural := 0;
      Remote_Bind_Port_Value  : Natural := 0;
      Remote_Bound_Port_Value : Natural := 0;
      Remote_Target_Host_Text : String (1 .. 255) := [others => Character'Val (0)];
      Remote_Target_Host_Length : Natural := 0;
      Remote_Target_Port_Value  : Natural := 0;
   end record;
end SSH_Lib.Forwarding;
