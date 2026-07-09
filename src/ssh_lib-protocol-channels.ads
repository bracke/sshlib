with Ada.Streams;
with Interfaces; use Interfaces;
with CryptoLib.Errors;
with SSH_Lib.Protocol.Buffers;

--  @summary Encodes and parses the SSH connection-protocol channel messages.
--
--  Builds and decodes the SSH_MSG_CHANNEL_* payloads of RFC 4254 -- channel
--  open/confirmation/failure, window adjust, data and extended data, EOF and
--  close, and the channel requests (exec, shell, subsystem, env, pty, x11,
--  window-change, exit-status) with their success/failure replies.  Encoders
--  return a ready-to-send Packet_Buffer; parsers validate the expected message
--  type and recipient channel and fill a typed event record.
package SSH_Lib.Protocol.Channels is

   SSH_MSG_CHANNEL_OPEN              : constant Ada.Streams.Stream_Element :=
     90;
   SSH_MSG_CHANNEL_OPEN_CONFIRMATION : constant Ada.Streams.Stream_Element :=
     91;
   SSH_MSG_CHANNEL_OPEN_FAILURE      : constant Ada.Streams.Stream_Element :=
     92;
   SSH_MSG_CHANNEL_WINDOW_ADJUST     : constant Ada.Streams.Stream_Element :=
     93;
   SSH_MSG_CHANNEL_DATA              : constant Ada.Streams.Stream_Element :=
     94;
   SSH_MSG_CHANNEL_EXTENDED_DATA     : constant Ada.Streams.Stream_Element :=
     95;
   SSH_MSG_CHANNEL_EOF               : constant Ada.Streams.Stream_Element :=
     96;
   SSH_MSG_CHANNEL_CLOSE             : constant Ada.Streams.Stream_Element :=
     97;
   SSH_MSG_CHANNEL_REQUEST           : constant Ada.Streams.Stream_Element :=
     98;
   SSH_MSG_CHANNEL_SUCCESS           : constant Ada.Streams.Stream_Element :=
     99;
   SSH_MSG_CHANNEL_FAILURE           : constant Ada.Streams.Stream_Element :=
     100;

   Default_Initial_Window_Size : constant Interfaces.Unsigned_32 :=
     2 * 1024 * 1024;
   Default_Maximum_Packet_Size : constant Interfaces.Unsigned_32 := 32 * 1024;
   Maximum_Command_Length      : constant Natural := 64 * 1024;

   Extended_Data_Stderr    : constant Interfaces.Unsigned_32 := 1;
   Window_Adjust_Threshold : constant Interfaces.Unsigned_32 := 1024 * 1024;

   type Channel_Data_Event is record
      Recipient_Channel : Interfaces.Unsigned_32 := 0;
      Data              : SSH_Lib.Protocol.Buffers.Packet_Buffer;
   end record;

   type Channel_Extended_Data_Event is record
      Recipient_Channel : Interfaces.Unsigned_32 := 0;
      Data_Type_Code    : Interfaces.Unsigned_32 := 0;
      Data              : SSH_Lib.Protocol.Buffers.Packet_Buffer;
   end record;

   type Channel_Window_Adjust_Event is record
      Recipient_Channel : Interfaces.Unsigned_32 := 0;
      Bytes_To_Add      : Interfaces.Unsigned_32 := 0;
   end record;

   type Channel_Request_Event is record
      Recipient_Channel : Interfaces.Unsigned_32 := 0;
      Request_Name      : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Want_Reply        : Boolean := False;
      Exit_Status       : Interfaces.Unsigned_32 := 0;
   end record;

   type Open_Confirmation is record
      Recipient_Channel   : Interfaces.Unsigned_32 := 0;
      Sender_Channel      : Interfaces.Unsigned_32 := 0;
      Initial_Window_Size : Interfaces.Unsigned_32 := 0;
      Maximum_Packet_Size : Interfaces.Unsigned_32 := 0;
   end record;

   type Open_Failure is record
      Recipient_Channel : Interfaces.Unsigned_32 := 0;
      Reason_Code       : Interfaces.Unsigned_32 := 0;
      Description       : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Language_Tag      : SSH_Lib.Protocol.Buffers.Packet_Buffer;
   end record;

   type Forwarded_TCPIP_Open is record
      Sender_Channel       : Interfaces.Unsigned_32 := 0;
      Initial_Window_Size  : Interfaces.Unsigned_32 := 0;
      Maximum_Packet_Size  : Interfaces.Unsigned_32 := 0;
      Connected_Address    : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Connected_Port       : Interfaces.Unsigned_32 := 0;
      Originator_Address   : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Originator_Port      : Interfaces.Unsigned_32 := 0;
   end record;

   type X11_Open is record
      Sender_Channel       : Interfaces.Unsigned_32 := 0;
      Initial_Window_Size  : Interfaces.Unsigned_32 := 0;
      Maximum_Packet_Size  : Interfaces.Unsigned_32 := 0;
      Originator_Address   : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Originator_Port      : Interfaces.Unsigned_32 := 0;
   end record;

   type Exec_Reply is (Exec_Request_Success, Exec_Request_Failure);

   type Terminal_Mode is record
      Opcode : Ada.Streams.Stream_Element := 0;
      Value  : Interfaces.Unsigned_32 := 0;
   end record;

   type Terminal_Mode_Array is array (Natural range <>) of Terminal_Mode;

   Empty_Terminal_Modes : constant Terminal_Mode_Array (1 .. 0) := [];

   --  Report whether a command string is a valid channel exec command.
   --  @param Command the candidate command string
   --  @return True when Command is non-empty and within the allowed length
   function Valid_Command (Command : String) return Boolean;

   --  Encode an SSH_MSG_CHANNEL_OPEN for a "session" channel.
   --  @param Sender_Channel the local channel id being opened
   --  @param Initial_Window_Size the initial flow-control window offered
   --  @param Maximum_Packet_Size the largest channel data packet accepted
   --  @return the encoded CHANNEL_OPEN packet
   function Encode_Channel_Open
     (Sender_Channel      : Interfaces.Unsigned_32;
      Initial_Window_Size : Interfaces.Unsigned_32 :=
        Default_Initial_Window_Size;
      Maximum_Packet_Size : Interfaces.Unsigned_32 :=
        Default_Maximum_Packet_Size)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;

   --  Encode an SSH_MSG_CHANNEL_OPEN of type "direct-tcpip" for forwarding.
   --  @param Sender_Channel the local channel id being opened
   --  @param Target_Host the host the server should connect the channel to
   --  @param Target_Port the port on Target_Host to connect to
   --  @param Originator_Address the source address reported to the server
   --  @param Originator_Port the source port reported to the server
   --  @param Initial_Window_Size the initial flow-control window offered
   --  @param Maximum_Packet_Size the largest channel data packet accepted
   --  @return the encoded direct-tcpip CHANNEL_OPEN packet
   function Encode_Direct_TCPIP_Open
     (Sender_Channel      : Interfaces.Unsigned_32;
      Target_Host         : String;
      Target_Port         : Natural;
      Originator_Address  : String := "127.0.0.1";
      Originator_Port     : Natural := 0;
      Initial_Window_Size : Interfaces.Unsigned_32 :=
        Default_Initial_Window_Size;
      Maximum_Packet_Size : Interfaces.Unsigned_32 :=
        Default_Maximum_Packet_Size)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;

   --  Parse an SSH_MSG_CHANNEL_OPEN_CONFIRMATION, checking the recipient id.
   --  @param Payload the raw message payload to parse
   --  @param Expected_Recipient the local channel id the confirmation must name
   --  @param Item the decoded confirmation (sender channel, window, packet size)
   --  @return Ok on success, or an error status on mismatch or malformed input
   function Parse_Channel_Open_Confirmation
     (Payload            : Ada.Streams.Stream_Element_Array;
      Expected_Recipient : Interfaces.Unsigned_32;
      Item               : out Open_Confirmation) return CryptoLib.Errors.Status;

   --  Parse an SSH_MSG_CHANNEL_OPEN_FAILURE, checking the recipient id.
   --  @param Payload the raw message payload to parse
   --  @param Expected_Recipient the local channel id the failure must name
   --  @param Item the decoded failure (reason code, description, language tag)
   --  @return Ok on success, or an error status on mismatch or malformed input
   function Parse_Channel_Open_Failure
     (Payload            : Ada.Streams.Stream_Element_Array;
      Expected_Recipient : Interfaces.Unsigned_32;
      Item               : out Open_Failure) return CryptoLib.Errors.Status;

   --  Parse a server-initiated "forwarded-tcpip" CHANNEL_OPEN request.
   --  @param Payload the raw message payload to parse
   --  @param Item the decoded forwarded-tcpip open (address/port fields)
   --  @return Ok on success, or an error status on malformed input
   function Parse_Forwarded_TCPIP_Open
     (Payload : Ada.Streams.Stream_Element_Array;
      Item    : out Forwarded_TCPIP_Open)
      return CryptoLib.Errors.Status;

   --  Parse a server-initiated "x11" CHANNEL_OPEN request.
   --  @param Payload the raw message payload to parse
   --  @param Item the decoded x11 open (originator address and port)
   --  @return Ok on success, or an error status on malformed input
   function Parse_X11_Open
     (Payload : Ada.Streams.Stream_Element_Array;
      Item    : out X11_Open)
      return CryptoLib.Errors.Status;

   --  Encode an SSH_MSG_CHANNEL_OPEN_CONFIRMATION accepting a channel open.
   --  @param Recipient_Channel the peer's channel id being confirmed
   --  @param Sender_Channel the local channel id assigned to the channel
   --  @param Initial_Window_Size the initial flow-control window offered
   --  @param Maximum_Packet_Size the largest channel data packet accepted
   --  @return the encoded CHANNEL_OPEN_CONFIRMATION packet
   function Encode_Channel_Open_Confirmation
     (Recipient_Channel   : Interfaces.Unsigned_32;
      Sender_Channel      : Interfaces.Unsigned_32;
      Initial_Window_Size : Interfaces.Unsigned_32 :=
        Default_Initial_Window_Size;
      Maximum_Packet_Size : Interfaces.Unsigned_32 :=
        Default_Maximum_Packet_Size)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;

   --  Encode a CHANNEL_REQUEST of type "exec" to run a remote command.
   --  @param Recipient_Channel the peer's channel id to run the command on
   --  @param Command the command line to execute remotely
   --  @return the encoded exec CHANNEL_REQUEST packet
   function Encode_Exec_Request
     (Recipient_Channel : Interfaces.Unsigned_32; Command : String)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;

   --  Encode a CHANNEL_REQUEST of type "subsystem" (e.g. "sftp").
   --  @param Recipient_Channel the peer's channel id to start the subsystem on
   --  @param Subsystem_Name the name of the subsystem to invoke
   --  @return the encoded subsystem CHANNEL_REQUEST packet
   function Encode_Subsystem_Request
     (Recipient_Channel : Interfaces.Unsigned_32; Subsystem_Name : String)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;

   --  Encode a CHANNEL_REQUEST of type "shell" to start an interactive shell.
   --  @param Recipient_Channel the peer's channel id to start the shell on
   --  @return the encoded shell CHANNEL_REQUEST packet
   function Encode_Shell_Request
     (Recipient_Channel : Interfaces.Unsigned_32)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;

   --  Encode a CHANNEL_REQUEST of type "env" to set a remote environment var.
   --  @param Recipient_Channel the peer's channel id to set the variable on
   --  @param Name the environment variable name
   --  @param Value the environment variable value
   --  @return the encoded env CHANNEL_REQUEST packet
   function Encode_Environment_Request
     (Recipient_Channel : Interfaces.Unsigned_32;
      Name              : String;
      Value             : String)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;

   --  Encode a CHANNEL_REQUEST of type "x11-req" to request X11 forwarding.
   --  @param Recipient_Channel the peer's channel id to enable X11 on
   --  @param Single_Connection request that only a single X11 connection be
   --  forwarded
   --  @param Auth_Protocol the X11 authentication protocol name
   --  @param Auth_Cookie the (hex) X11 authentication cookie
   --  @param Screen_Number the X11 screen number to forward
   --  @return the encoded x11-req CHANNEL_REQUEST packet
   function Encode_X11_Request
     (Recipient_Channel : Interfaces.Unsigned_32;
      Single_Connection : Boolean;
      Auth_Protocol     : String;
      Auth_Cookie       : String;
      Screen_Number     : Interfaces.Unsigned_32 := 0)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;

   --  Encode a CHANNEL_REQUEST of type "pty-req" to allocate a pseudo-terminal.
   --  @param Recipient_Channel the peer's channel id to allocate the pty on
   --  @param Terminal_Type the TERM environment value (e.g. "xterm-256color")
   --  @param Columns the terminal width in character columns
   --  @param Rows the terminal height in character rows
   --  @param Width_Pixels the terminal width in pixels
   --  @param Height_Pixels the terminal height in pixels
   --  @param Terminal_Modes the encoded terminal mode opcode/value pairs
   --  @return the encoded pty-req CHANNEL_REQUEST packet
   function Encode_PTY_Request
     (Recipient_Channel : Interfaces.Unsigned_32;
      Terminal_Type     : String;
      Columns           : Interfaces.Unsigned_32;
      Rows              : Interfaces.Unsigned_32;
      Width_Pixels      : Interfaces.Unsigned_32 := 0;
      Height_Pixels     : Interfaces.Unsigned_32 := 0;
      Terminal_Modes    : Terminal_Mode_Array := Empty_Terminal_Modes)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;

   --  Encode a CHANNEL_REQUEST of type "window-change" to resize the pty.
   --  @param Recipient_Channel the peer's channel id whose terminal is resized
   --  @param Columns the new terminal width in character columns
   --  @param Rows the new terminal height in character rows
   --  @param Width_Pixels the new terminal width in pixels
   --  @param Height_Pixels the new terminal height in pixels
   --  @return the encoded window-change CHANNEL_REQUEST packet
   function Encode_Window_Change_Request
     (Recipient_Channel : Interfaces.Unsigned_32;
      Columns           : Interfaces.Unsigned_32;
      Rows              : Interfaces.Unsigned_32;
      Width_Pixels      : Interfaces.Unsigned_32 := 0;
      Height_Pixels     : Interfaces.Unsigned_32 := 0)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;

   --  Parse an SSH_MSG_CHANNEL_SUCCESS or SSH_MSG_CHANNEL_FAILURE reply.
   --  Expected_Recipient is the local channel id originally sent as
   --  CHANNEL_OPEN.sender_channel.  It is not the remote channel id used as
   --  CHANNEL_REQUEST.recipient_channel.
   --  @param Payload the raw message payload to parse
   --  @param Expected_Recipient the local channel id the reply must name
   --  @param Reply set to Exec_Request_Success or Exec_Request_Failure
   --  @return Ok on success, or an error status on mismatch or malformed input
   function Parse_Exec_Reply
     (Payload            : Ada.Streams.Stream_Element_Array;
      Expected_Recipient : Interfaces.Unsigned_32;
      Reply              : out Exec_Reply) return CryptoLib.Errors.Status;

   --  Encode an SSH_MSG_CHANNEL_DATA packet carrying channel payload bytes.
   --  @param Recipient_Channel the peer's channel id to send the data on
   --  @param Data the channel data bytes to send
   --  @return the encoded CHANNEL_DATA packet
   function Encode_Channel_Data
     (Recipient_Channel : Interfaces.Unsigned_32;
      Data              : Ada.Streams.Stream_Element_Array)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;

   --  Parse an SSH_MSG_CHANNEL_DATA packet, checking the recipient id.
   --  @param Payload the raw message payload to parse
   --  @param Expected_Recipient the local channel id the data must name
   --  @param Item the decoded data event (recipient id and data bytes)
   --  @return Ok on success, or an error status on mismatch or malformed input
   function Parse_Channel_Data
     (Payload            : Ada.Streams.Stream_Element_Array;
      Expected_Recipient : Interfaces.Unsigned_32;
      Item               : out Channel_Data_Event)
      return CryptoLib.Errors.Status;

   --  Encode an SSH_MSG_CHANNEL_EXTENDED_DATA packet (e.g. stderr).
   --  @param Recipient_Channel the peer's channel id to send the data on
   --  @param Data_Type_Code the extended data type (e.g. Extended_Data_Stderr)
   --  @param Data the extended data bytes to send
   --  @return the encoded CHANNEL_EXTENDED_DATA packet
   function Encode_Channel_Extended_Data
     (Recipient_Channel : Interfaces.Unsigned_32;
      Data_Type_Code    : Interfaces.Unsigned_32;
      Data              : Ada.Streams.Stream_Element_Array)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;

   --  Parse an SSH_MSG_CHANNEL_EXTENDED_DATA packet, checking the recipient id.
   --  @param Payload the raw message payload to parse
   --  @param Expected_Recipient the local channel id the data must name
   --  @param Item the decoded extended-data event (type code and data bytes)
   --  @return Ok on success, or an error status on mismatch or malformed input
   function Parse_Channel_Extended_Data
     (Payload            : Ada.Streams.Stream_Element_Array;
      Expected_Recipient : Interfaces.Unsigned_32;
      Item               : out Channel_Extended_Data_Event)
      return CryptoLib.Errors.Status;

   --  Encode an SSH_MSG_CHANNEL_WINDOW_ADJUST to grant more flow-control window.
   --  @param Recipient_Channel the peer's channel id whose window is extended
   --  @param Bytes_To_Add the number of bytes to add to the peer's send window
   --  @return the encoded CHANNEL_WINDOW_ADJUST packet
   function Encode_Channel_Window_Adjust
     (Recipient_Channel : Interfaces.Unsigned_32;
      Bytes_To_Add      : Interfaces.Unsigned_32)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;

   --  Parse an SSH_MSG_CHANNEL_WINDOW_ADJUST packet, checking the recipient id.
   --  @param Payload the raw message payload to parse
   --  @param Expected_Recipient the local channel id the adjustment must name
   --  @param Item the decoded window-adjust event (recipient id and byte count)
   --  @return Ok on success, or an error status on mismatch or malformed input
   function Parse_Channel_Window_Adjust
     (Payload            : Ada.Streams.Stream_Element_Array;
      Expected_Recipient : Interfaces.Unsigned_32;
      Item               : out Channel_Window_Adjust_Event)
      return CryptoLib.Errors.Status;

   --  Encode an SSH_MSG_CHANNEL_EOF signalling no more data will be sent.
   --  @param Recipient_Channel the peer's channel id being closed for writes
   --  @return the encoded CHANNEL_EOF packet
   function Encode_Channel_EOF
     (Recipient_Channel : Interfaces.Unsigned_32)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;

   --  Encode an SSH_MSG_CHANNEL_CLOSE requesting the channel be torn down.
   --  @param Recipient_Channel the peer's channel id being closed
   --  @return the encoded CHANNEL_CLOSE packet
   function Encode_Channel_Close
     (Recipient_Channel : Interfaces.Unsigned_32)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;

   --  Parse a bare single-id channel message (EOF or CLOSE) of a given type.
   --  @param Payload the raw message payload to parse
   --  @param Expected_Message the message type byte the payload must carry
   --  @param Expected_Recipient the local channel id the message must name
   --  @return Ok on success, or an error status on mismatch or malformed input
   function Parse_Channel_One_Id
     (Payload            : Ada.Streams.Stream_Element_Array;
      Expected_Message   : Ada.Streams.Stream_Element;
      Expected_Recipient : Interfaces.Unsigned_32)
      return CryptoLib.Errors.Status;

   --  Parse an SSH_MSG_CHANNEL_REQUEST, checking the recipient id.
   --  Parses the common CHANNEL_REQUEST header plus strict known terminal
   --  payloads for exit-status and exit-signal.
   --  Unknown request types are accepted with trailing request-specific fields
   --  preserved only as the request name/want-reply decision boundary; callers
   --  can then send CHANNEL_FAILURE when want-reply is set.
   --  @param Payload the raw message payload to parse
   --  @param Expected_Recipient the local channel id the request must name
   --  @param Item the decoded request event (name, want-reply, exit status)
   --  @return Ok on success, or an error status on mismatch or malformed input
   function Parse_Channel_Request
     (Payload            : Ada.Streams.Stream_Element_Array;
      Expected_Recipient : Interfaces.Unsigned_32;
      Item               : out Channel_Request_Event)
      return CryptoLib.Errors.Status;

   --  Report whether a parsed channel request is an "exit-status" request.
   --  @param Item the parsed channel request event to inspect
   --  @return True when the request carries an exit status
   function Request_Is_Exit_Status
     (Item : Channel_Request_Event) return Boolean;

   --  Report whether a parsed channel request is an "exit-signal" request.
   --  @param Item the parsed channel request event to inspect
   --  @return True when the request reports termination by a signal
   function Request_Is_Exit_Signal
     (Item : Channel_Request_Event) return Boolean;

   --  Encode a CHANNEL_REQUEST of type "exit-status" reporting a command's code.
   --  @param Recipient_Channel the peer's channel id the status applies to
   --  @param Want_Reply whether a success/failure reply is requested
   --  @param Exit_Status the remote command's exit code
   --  @return the encoded exit-status CHANNEL_REQUEST packet
   function Encode_Exit_Status_Request
     (Recipient_Channel : Interfaces.Unsigned_32;
      Want_Reply        : Boolean;
      Exit_Status       : Interfaces.Unsigned_32)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;

   --  Encode an SSH_MSG_CHANNEL_SUCCESS reply to a channel request.
   --  @param Recipient_Channel the peer's channel id the reply is for
   --  @return the encoded CHANNEL_SUCCESS packet
   function Encode_Channel_Success
     (Recipient_Channel : Interfaces.Unsigned_32)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;

   --  Encode an SSH_MSG_CHANNEL_FAILURE reply to a channel request.
   --  @param Recipient_Channel the peer's channel id the reply is for
   --  @return the encoded CHANNEL_FAILURE packet
   function Encode_Channel_Failure
     (Recipient_Channel : Interfaces.Unsigned_32)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;
end SSH_Lib.Protocol.Channels;
