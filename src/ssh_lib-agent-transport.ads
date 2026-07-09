with Ada.Streams;
with GNAT.Sockets;
with CryptoLib.Errors;
with SSH_Lib.Protocol.Buffers;

--  @summary Unix-socket transport to a running ssh-agent.
--
--  Wraps a connection to the agent's Unix-domain socket and exchanges the
--  length-prefixed agent protocol messages: connect (optionally with a
--  connect timeout), send a request, receive a reply (optionally with a read
--  timeout), and close.  An Agent_Connection is limited and owns its socket.
package SSH_Lib.Agent.Transport is
   type Agent_Connection is limited private;

   --  Open a connection to the ssh-agent at the given socket path.
   --  @param Socket_Path the filesystem path of the agent's Unix socket
   --  @param Item        the opened agent connection
   --  @return Ok on success, or a connection failure status
   function Connect
     (Socket_Path : String;
      Item        : out Agent_Connection)
      return CryptoLib.Errors.Status;

   --  Open a connection to the ssh-agent with a bounded connect timeout.
   --  @param Socket_Path the filesystem path of the agent's Unix socket
   --  @param Timeout_MS  the connect timeout in milliseconds
   --  @param Item        the opened agent connection
   --  @return Ok on success, Timeout on expiry, or a connection failure status
   function Connect
     (Socket_Path : String;
      Timeout_MS  : Natural;
      Item        : out Agent_Connection)
      return CryptoLib.Errors.Status;

   --  Send a length-prefixed agent request message.
   --  @param Item    the agent connection to send on
   --  @param Payload the agent message body to frame and send
   --  @return Ok on success, or a write failure status
   function Send_Message
     (Item    : in out Agent_Connection;
      Payload : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Send a length-prefixed agent request message with a write timeout.
   --  @param Item       the agent connection to send on
   --  @param Payload    the agent message body to frame and send
   --  @param Timeout_MS the write timeout in milliseconds
   --  @return Ok on success, Timeout on expiry, or a write failure status
   function Send_Message
     (Item       : in out Agent_Connection;
      Payload    : Ada.Streams.Stream_Element_Array;
      Timeout_MS : Natural)
      return CryptoLib.Errors.Status;

   --  Receive one length-prefixed agent reply message.
   --  @param Item    the agent connection to read from
   --  @param Payload the received agent message body
   --  @return Ok on success, or a read failure status
   function Receive_Message
     (Item    : in out Agent_Connection;
      Payload : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;

   --  Receive one length-prefixed agent reply message with a read timeout.
   --  @param Item       the agent connection to read from
   --  @param Payload    the received agent message body
   --  @param Timeout_MS the read timeout in milliseconds
   --  @return Ok on success, Timeout on expiry, or a read failure status
   function Receive_Message
     (Item       : in out Agent_Connection;
      Payload    : out SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Timeout_MS : Natural)
      return CryptoLib.Errors.Status;

   --  Close the agent connection and release its socket.
   --  @param Item the agent connection to close
   --  @return Ok on success, or a failure status
   function Close
     (Item : in out Agent_Connection)
      return CryptoLib.Errors.Status;

private
   type Agent_Connection is limited record
      Connected : Boolean := False;
      Socket    : GNAT.Sockets.Socket_Type;
   end record;
end SSH_Lib.Agent.Transport;
