with CryptoLib.Errors;
with SSH_Lib.Protocol.Buffers;

--  @summary Socket transport for a live SSH session: connect, handshake, rekey.
--
--  Opens the TCP connection (directly, through a ProxyJump hop, a ProxyCommand
--  subprocess, or an existing control-master socket), runs the version and key
--  exchange handshake, and manages rekeying.  It also accumulates protected
--  wire byte counts so time- and data-based automatic rekeys can be triggered.
package SSH_Lib.Sessions.Live_Transport is
   --  Open a direct TCP connection and run the full SSH handshake.
   --  @param Options the connection options (host, port, algorithms, etc.)
   --  @param Item    the session to connect and populate
   --  @return Ok on success, or a connection/handshake failure status
   function Connect_And_Run_Handshake
     (Options : Session_Options;
      Item    : in out Session)
      return CryptoLib.Errors.Status;

   --  Connect through the configured ProxyJump chain, then run the handshake.
   --  @param Options the connection options including the ProxyJump chain
   --  @param Item    the session to connect and populate
   --  @return Ok on success, or a connection/handshake failure status
   function Connect_Through_Proxy_Jump
     (Options : Session_Options;
      Item    : in out Session)
      return CryptoLib.Errors.Status;

   --  Connect through a ProxyCommand subprocess, then run the handshake.
   --  @param Options the connection options including the ProxyCommand
   --  @param Item    the session to connect and populate
   --  @return Ok on success, or a connection/handshake failure status
   function Connect_Through_Proxy_Command
     (Options : Session_Options;
      Item    : in out Session)
      return CryptoLib.Errors.Status;

   --  Attach to an existing multiplexing control-master socket.
   --  @param Options      the connection options
   --  @param Control_Path the filesystem path of the control-master socket
   --  @param Item         the session to connect and populate
   --  @return Ok on success, or a connection failure status
   function Connect_Through_Control_Master
     (Options      : Session_Options;
      Control_Path : String;
      Item         : in out Session)
      return CryptoLib.Errors.Status;

   --  Initiate a client-driven rekey by sending a fresh KEXINIT.
   --  @param Item the session to rekey
   --  @return Ok on success, or a handshake failure status
   function Rekey
     (Item : in out Session)
      return CryptoLib.Errors.Status;

   --  Complete a rekey where the server already sent its KEXINIT first.
   --  @param Item           the session to rekey
   --  @param Server_Kexinit the peer's already-received KEXINIT payload
   --  @return Ok on success, or a handshake failure status
   function Rekey_With_Peer_Kexinit
     (Item           : in out Session;
      Server_Kexinit : SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;

   --  Add to the outbound protected wire byte counter used for rekey thresholds.
   --  @param Item            the session whose counter to advance
   --  @param Wire_Byte_Count the number of protected outbound bytes just sent
   procedure Note_Protected_Outbound
     (Item            : in out Session;
      Wire_Byte_Count : Natural);

   --  Add to the inbound protected wire byte counter used for rekey thresholds.
   --  @param Item            the session whose counter to advance
   --  @param Wire_Byte_Count the number of protected inbound bytes just received
   procedure Note_Protected_Inbound
     (Item            : in out Session;
      Wire_Byte_Count : Natural);

   --  Report whether an automatic rekey is due (time or data threshold reached).
   --  @param Item the session to query
   --  @return True if a rekey should be performed
   function Automatic_Rekey_Needed
     (Item : Session)
      return Boolean;

   --  Perform a rekey if one is due, otherwise do nothing.
   --  @param Item the session to check and possibly rekey
   --  @return Ok on success (including no-op), or a handshake failure status
   function Check_Automatic_Rekey
     (Item : in out Session)
      return CryptoLib.Errors.Status;
end SSH_Lib.Sessions.Live_Transport;
