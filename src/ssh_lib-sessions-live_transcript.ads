with Ada.Streams;
with GNAT.Expect;
with GNAT.Sockets;
with Interfaces;
with Ada.Strings.Unbounded;
with CryptoLib.Errors;
with SSH_Lib.Protocol.Buffers;
with SSH_Lib.Protocol.Packets;
with SSH_Lib.Protocol.Protected_Packets;

--  @summary Socket-backed driver that carries the full SSH packet transcript.
--
--  Owns the transport connection (direct socket, jump-host channel, ProxyCommand
--  subprocess, or mux ProxyJump) and moves packets through every phase:
--  identification strings, cleartext and key-exchange packets, and post-NEWKEYS
--  protected packets once cipher/MAC keys are installed.  Tracks per-direction
--  state, ServerAliveInterval keepalives, delayed compression, and Terrapin
--  strict-kex sequence-number reset, retaining the last packet in each direction
--  for inspection.
package SSH_Lib.Sessions.Live_Transcript is
   type Driver is limited private;
   type Driver_Access is access all Driver;

   --  Reset the driver to its initial disconnected state, releasing resources.
   --  @param Item the driver to reset
   procedure Reset (Item : out Driver);

   --  Configure ServerAliveInterval keepalives and the ServerAliveCountMax
   --  threshold, wiring the interval into the socket read timeout when the
   --  caller has not set one.
   --  @param Item             the driver to configure
   --  @param Interval_Seconds the keepalive interval in seconds (0 disables)
   --  @param Count_Max        the number of unanswered keepalives tolerated
   procedure Configure_Server_Alive
     (Item             : in out Driver;
      Interval_Seconds : Natural;
      Count_Max        : Natural);

   --  Open a direct TCP socket connection to Host:Port, applying the connect
   --  and I/O timeouts and the requested address-family and binding options.
   --  @param Item               the driver to connect
   --  @param Host               the target host name or address
   --  @param Port               the target TCP port
   --  @param Connect_Timeout_MS the connect timeout in milliseconds (0 = none)
   --  @param Read_Timeout_MS    the read timeout in milliseconds (0 = none)
   --  @param Write_Timeout_MS   the write timeout in milliseconds (0 = none)
   --  @param Address_Family     "inet"/"inet6" to force a family, "" for any
   --  @param Bind_Address       the local source address to bind, "" for none
   --  @param TCP_Keep_Alive     whether to enable TCP keepalive on the socket
   --  @param IP_QoS             the IP QoS/DSCP setting, "" for default
   --  @param Bind_Interface     the local interface to bind to, "" for none
   --  @return Ok on success, or an error Status on failure
   function Connect
     (Item               : in out Driver;
      Host               : String;
      Port               : Natural;
      Connect_Timeout_MS : Natural := 0;
      Read_Timeout_MS    : Natural := 0;
      Write_Timeout_MS   : Natural := 0;
      Address_Family     : String := "";
      Bind_Address       : String := "";
      TCP_Keep_Alive     : Boolean := True;
      IP_QoS             : String := "";
      Bind_Interface     : String := "") return CryptoLib.Errors.Status;

   --  Tunnel this driver through an already-connected outer driver's channel
   --  (ProxyJump), carrying packets over the given jump channel pair.
   --  @param Item             the inner driver to connect
   --  @param Outer            the connected outer driver providing the tunnel
   --  @param Local_Channel    the local channel id of the jump channel
   --  @param Remote_Channel   the remote channel id of the jump channel
   --  @param Own_Outer        when True, this driver owns and closes Outer
   --  @param Read_Timeout_MS  the read timeout in milliseconds (0 = none)
   --  @param Write_Timeout_MS the write timeout in milliseconds (0 = none)
   --  @return Ok on success, or an error Status on failure
   function Connect_Through_Jump
     (Item             : in out Driver;
      Outer            : Driver_Access;
      Local_Channel    : Interfaces.Unsigned_32;
      Remote_Channel   : Interfaces.Unsigned_32;
      Own_Outer        : Boolean := False;
      Read_Timeout_MS  : Natural := 0;
      Write_Timeout_MS : Natural := 0) return CryptoLib.Errors.Status;

   --  Connect by spawning a ProxyCommand subprocess and speaking SSH over its
   --  stdio, after expanding %h/%p/%r tokens in the command text.
   --  @param Item               the driver to connect
   --  @param Command_Text       the ProxyCommand template to run
   --  @param Host               the host substituted for %h/%n
   --  @param Port               the port substituted for %p
   --  @param User               the user substituted for %r
   --  @param Connect_Timeout_MS the connect timeout in milliseconds (0 = none)
   --  @param Read_Timeout_MS    the read timeout in milliseconds (0 = none)
   --  @param Write_Timeout_MS   the write timeout in milliseconds (0 = none)
   --  @return Ok on success, or an error Status on failure
   function Connect_Through_Proxy_Command
     (Item               : in out Driver;
      Command_Text       : String;
      Host               : String;
      Port               : Natural;
      User               : String;
      Connect_Timeout_MS : Natural := 0;
      Read_Timeout_MS    : Natural := 0;
      Write_Timeout_MS   : Natural := 0) return CryptoLib.Errors.Status;

   --  Connect by asking an existing mux master (at Control_Path) to proxy a new
   --  session, taking over its detached control socket as the transport.
   --  @param Item             the driver to connect
   --  @param Control_Path     the filesystem path of the mux control socket
   --  @param Read_Timeout_MS  the read timeout in milliseconds (0 = none)
   --  @param Write_Timeout_MS the write timeout in milliseconds (0 = none)
   --  @return Ok on success, or an error Status on failure
   function Connect_Through_Mux_Proxy
     (Item             : in out Driver;
      Control_Path     : String;
      Read_Timeout_MS  : Natural := 0;
      Write_Timeout_MS : Natural := 0) return CryptoLib.Errors.Status;

   --  Test helper: expand a ProxyCommand template's %-tokens against the given
   --  host, port, and user.
   --  @param Command_Text the ProxyCommand template to expand
   --  @param Host         the host substituted for %h/%n
   --  @param Port         the port substituted for %p
   --  @param User         the user substituted for %r
   --  @return the expanded command string
   function Expand_Proxy_Command_For_Test
     (Command_Text : String;
      Host         : String;
      Port         : Natural;
      User         : String) return String;

   --  The diagnostics recorded by the most recent ProxyCommand connect attempt.
   --  @param Item the driver to query
   --  @return the last ProxyCommand diagnostic record
   function Last_Proxy_Command_Diagnostics
     (Item : Driver) return SSH_Lib.Sessions.Proxy_Command_Diagnostic;

   --  Send this end's SSH identification string ("SSH-2.0-...") to the peer.
   --  @param Item the driver to send on
   --  @return Ok on success, or an error Status on failure
   function Send_Identification
     (Item : in out Driver) return CryptoLib.Errors.Status;

   --  Read and store the peer's SSH identification string.
   --  @param Item the driver to read on
   --  @return Ok on success, or an error Status on failure
   function Read_Identification
     (Item : in out Driver) return CryptoLib.Errors.Status;

   --  Send one cleartext (pre-encryption) binary packet.
   --  @param Item    the driver to send on
   --  @param Payload the packet payload to send
   --  @return Ok on success, or an error Status on failure
   function Send_Cleartext_Packet
     (Item : in out Driver; Payload : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Read one cleartext (pre-encryption) binary packet.
   --  @param Item    the driver to read on
   --  @param Payload the received packet payload
   --  @return Ok on success, or an error Status on failure
   function Read_Cleartext_Packet
     (Item    : in out Driver;
      Payload : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;

   --  Send one cleartext key-exchange packet, tracking the KEX sequence number.
   --  @param Item    the driver to send on
   --  @param Payload the key-exchange packet payload to send
   --  @return Ok on success, or an error Status on failure
   function Send_Key_Exchange_Packet
     (Item : in out Driver; Payload : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Read one cleartext key-exchange packet, tracking the KEX sequence number.
   --  @param Item    the driver to read on
   --  @param Payload the received key-exchange packet payload
   --  @return Ok on success, or an error Status on failure
   function Read_Key_Exchange_Packet
     (Item    : in out Driver;
      Payload : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;

   --  Install a MAC-only protected state (no cipher) with one shared MAC key,
   --  enabling protected-packet framing.
   --  @param Item    the driver to configure
   --  @param Mac_Key the MAC key applied to both directions
   --  @return Ok on success, or an error Status on failure
   function Install_Protected_Keys
     (Item : in out Driver; Mac_Key : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Install protected keys for a single cipher (both directions) with the
   --  default hmac-sha2-256 MAC and no compression.
   --  @param Item              the driver to configure
   --  @param Cipher_Name       the cipher algorithm name for both directions
   --  @param Outbound_Mac_Key  the outbound MAC key
   --  @param Inbound_Mac_Key   the inbound MAC key
   --  @param Outbound_Key_Data the outbound cipher key
   --  @param Outbound_IV_Data  the outbound cipher IV
   --  @param Inbound_Key_Data  the inbound cipher key
   --  @param Inbound_IV_Data   the inbound cipher IV
   --  @return Ok on success, or an error Status on failure
   function Install_Protected_Keys
     (Item              : in out Driver;
      Cipher_Name       : String;
      Outbound_Mac_Key  : Ada.Streams.Stream_Element_Array;
      Inbound_Mac_Key   : Ada.Streams.Stream_Element_Array;
      Outbound_Key_Data : Ada.Streams.Stream_Element_Array;
      Outbound_IV_Data  : Ada.Streams.Stream_Element_Array;
      Inbound_Key_Data  : Ada.Streams.Stream_Element_Array;
      Inbound_IV_Data   : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Install protected keys for independent inbound/outbound ciphers and MACs
   --  with no compression.
   --  @param Item                 the driver to configure
   --  @param Outbound_Cipher_Name the outbound cipher algorithm name
   --  @param Inbound_Cipher_Name  the inbound cipher algorithm name
   --  @param Outbound_Mac_Name    the outbound MAC algorithm name
   --  @param Inbound_Mac_Name     the inbound MAC algorithm name
   --  @param Outbound_Mac_Key     the outbound MAC key
   --  @param Inbound_Mac_Key      the inbound MAC key
   --  @param Outbound_Key_Data    the outbound cipher key
   --  @param Outbound_IV_Data     the outbound cipher IV
   --  @param Inbound_Key_Data     the inbound cipher key
   --  @param Inbound_IV_Data      the inbound cipher IV
   --  @return Ok on success, or an error Status on failure
   function Install_Protected_Keys
     (Item                 : in out Driver;
      Outbound_Cipher_Name : String;
      Inbound_Cipher_Name  : String;
      Outbound_Mac_Name    : String;
      Inbound_Mac_Name     : String;
      Outbound_Mac_Key     : Ada.Streams.Stream_Element_Array;
      Inbound_Mac_Key      : Ada.Streams.Stream_Element_Array;
      Outbound_Key_Data    : Ada.Streams.Stream_Element_Array;
      Outbound_IV_Data     : Ada.Streams.Stream_Element_Array;
      Inbound_Key_Data     : Ada.Streams.Stream_Element_Array;
      Inbound_IV_Data      : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Install protected keys for independent inbound/outbound ciphers, MACs, and
   --  compression algorithms, applying the strict-kex sequence reset when set.
   --  @param Item                 the driver to configure
   --  @param Outbound_Cipher_Name the outbound cipher algorithm name
   --  @param Inbound_Cipher_Name  the inbound cipher algorithm name
   --  @param Outbound_Mac_Name    the outbound MAC algorithm name
   --  @param Inbound_Mac_Name     the inbound MAC algorithm name
   --  @param Outbound_Compression the outbound compression algorithm name
   --  @param Inbound_Compression  the inbound compression algorithm name
   --  @param Outbound_Mac_Key     the outbound MAC key
   --  @param Inbound_Mac_Key      the inbound MAC key
   --  @param Outbound_Key_Data    the outbound cipher key
   --  @param Outbound_IV_Data     the outbound cipher IV
   --  @param Inbound_Key_Data     the inbound cipher key
   --  @param Inbound_IV_Data      the inbound cipher IV
   --  @return Ok on success, or an error Status on failure
   function Install_Protected_Keys
     (Item                 : in out Driver;
      Outbound_Cipher_Name : String;
      Inbound_Cipher_Name  : String;
      Outbound_Mac_Name    : String;
      Inbound_Mac_Name     : String;
      Outbound_Compression : String;
      Inbound_Compression  : String;
      Outbound_Mac_Key     : Ada.Streams.Stream_Element_Array;
      Inbound_Mac_Key      : Ada.Streams.Stream_Element_Array;
      Outbound_Key_Data    : Ada.Streams.Stream_Element_Array;
      Outbound_IV_Data     : Ada.Streams.Stream_Element_Array;
      Inbound_Key_Data     : Ada.Streams.Stream_Element_Array;
      Inbound_IV_Data      : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Seal and send one protected (encrypted, authenticated) packet.
   --  @param Item    the driver to send on
   --  @param Payload the cleartext payload to seal and send
   --  @return Ok on success, or an error Status on failure
   function Send_Protected_Packet
     (Item : in out Driver; Payload : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Read and open one protected (encrypted, authenticated) packet.
   --  @param Item    the driver to read on
   --  @param Payload the recovered cleartext payload
   --  @return Ok on success, or an error Status on failure
   function Read_Protected_Packet
     (Item    : in out Driver;
      Payload : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;

   --  Activate delayed (post-authentication) zlib compression on the protected
   --  state.
   --  @param Item the driver to modify
   --  @return Ok on success, or an error Status on failure
   function Activate_Delayed_Compression
     (Item : in out Driver) return CryptoLib.Errors.Status;

   --  This end's SSH identification string.
   --  @param Item the driver to query
   --  @return the local identification string
   function Local_Identification (Item : Driver) return String;

   --  The peer's SSH identification string as read from the wire.
   --  @param Item the driver to query
   --  @return the remote identification string
   function Remote_Identification (Item : Driver) return String;

   --  The bytes of the most recently sent cleartext packet.
   --  @param Item the driver to query
   --  @return the last outbound cleartext packet bytes
   function Last_Cleartext_Outbound
     (Item : Driver) return Ada.Streams.Stream_Element_Array;

   --  The bytes of the most recently received cleartext packet.
   --  @param Item the driver to query
   --  @return the last inbound cleartext packet bytes
   function Last_Cleartext_Inbound
     (Item : Driver) return Ada.Streams.Stream_Element_Array;

   --  The bytes of the most recently sent protected packet.
   --  @param Item the driver to query
   --  @return the last outbound protected packet bytes
   function Last_Protected_Outbound
     (Item : Driver) return Ada.Streams.Stream_Element_Array;

   --  The bytes of the most recently received protected packet.
   --  @param Item the driver to query
   --  @return the last inbound protected packet bytes
   function Last_Protected_Inbound
     (Item : Driver) return Ada.Streams.Stream_Element_Array;

   --  Whether the driver currently has a live transport connection.
   --  @param Item the driver to query
   --  @return True if connected
   function Is_Connected (Item : Driver) return Boolean;

   --  Enable Terrapin strict-kex sequence handling for the connection.
   --  Terrapin strict-kex (CVE-2023-48795).  Enabled once, for the connection,
   --  when the peer advertises kex-strict-s-v00@openssh.com in the initial
   --  KEXINIT; never cleared (the marker is absent from rekey KEXINITs).
   --  @param Item the driver to mark as strict-kex
   procedure Set_Strict_Kex (Item : in out Driver);

   --  Whether strict-kex has been enabled for this connection.
   --  @param Item the driver to query
   --  @return True if strict-kex is enabled
   function Is_Strict_Kex (Item : Driver) return Boolean;

   --  Close the transport connection and release its resources.
   --  @param Item the driver to close
   procedure Close (Item : in out Driver);

private
   type Driver_Mode is (Socket_Mode, Jump_Channel_Mode, Proxy_Command_Mode);

   type Driver is limited record
      Mode                       : Driver_Mode := Socket_Mode;
      Outer_Driver               : Driver_Access := null;
      Owns_Outer_Driver          : Boolean := False;
      Jump_Local_Channel         : Interfaces.Unsigned_32 := 0;
      Jump_Remote_Channel        : Interfaces.Unsigned_32 := 0;
      Jump_Read_Buffer           : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Socket_Item                : GNAT.Sockets.Socket_Type;
      Proxy_Process              : GNAT.Expect.Process_Descriptor;
      Proxy_Process_Open         : Boolean := False;
      Connected                  : Boolean := False;
      Clear_State                : SSH_Lib.Protocol.Packets.Protocol_State;
      Protected_State            :
        SSH_Lib.Protocol.Protected_Packets.Protected_State;
      Protected_Installed        : Boolean := False;
      --  Terrapin (CVE-2023-48795) strict-kex: when negotiated, the packet
      --  sequence number is reset to zero after NEWKEYS instead of continuing
      --  from the cleartext handshake count.
      Strict_Kex                 : Boolean := False;
      Local_Identification_Text  : Ada.Strings.Unbounded.Unbounded_String;
      Remote_Identification_Text : Ada.Strings.Unbounded.Unbounded_String;
      Last_Clear_Out             : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Last_Clear_In              : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Last_Protected_Out         : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Last_Protected_In          : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Read_Timeout_Configured    : Boolean := False;
      Write_Timeout_Configured   : Boolean := False;
      Read_Timeout_MS            : Natural := 0;
      Write_Timeout_MS           : Natural := 0;
      Caller_Read_Timeout_Configured : Boolean := False;
      Server_Alive_Interval_MS   : Natural := 0;
      Server_Alive_Count_Max     : Natural := 3;
      Server_Alive_Missed        : Natural := 0;
      Server_Alive_Awaiting_Reply : Boolean := False;
      Proxy_Command_Diagnostic_Item :
        SSH_Lib.Sessions.Proxy_Command_Diagnostic;
   end record;
end SSH_Lib.Sessions.Live_Transcript;
