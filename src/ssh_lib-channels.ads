with Ada.Streams;
with Ada.Strings.Unbounded;
with Interfaces;
with System;
with CryptoLib.Errors;
with SSH_Lib.Protocol.Buffers;
with SSH_Lib.Protocol.Protected_Packets;
with SSH_Lib.Sessions;
with SSH_Lib.Sessions.Live_Attachment;

package SSH_Lib.Channels is
   type Channel is limited private;

   type Terminal_Mode is record
      Opcode : Ada.Streams.Stream_Element := 0;
      Value  : Interfaces.Unsigned_32 := 0;
   end record;

   type Terminal_Mode_Array is array (Natural range <>) of Terminal_Mode;

   Empty_Terminal_Modes : constant Terminal_Mode_Array (1 .. 0) := [];

   type Environment_Variable is record
      Name  : Ada.Strings.Unbounded.Unbounded_String;
      Value : Ada.Strings.Unbounded.Unbounded_String;
   end record;

   type Environment_Variable_Array is
     array (Natural range <>) of Environment_Variable;

   Empty_Environment : constant Environment_Variable_Array (1 .. 0) := [];

   function Open_Exec
     (Session : in out SSH_Lib.Sessions.Session;
      Command : String;
      Item    : in out Channel)
      return CryptoLib.Errors.Status;

   function Open_Exec_With_Environment
     (Session     : in out SSH_Lib.Sessions.Session;
      Command     : String;
      Environment : Environment_Variable_Array;
      Item        : in out Channel)
      return CryptoLib.Errors.Status;

   function Open_Subsystem
     (Session        : in out SSH_Lib.Sessions.Session;
      Subsystem_Name : String;
      Item           : in out Channel)
      return CryptoLib.Errors.Status;

   function Open_Shell
     (Session : in out SSH_Lib.Sessions.Session;
      Item    : in out Channel)
      return CryptoLib.Errors.Status;

   function Open_PTY_Shell
     (Session        : in out SSH_Lib.Sessions.Session;
      Item           : in out Channel;
      Terminal_Type  : String := "xterm";
      Columns        : Natural := 80;
      Rows           : Natural := 24;
      Width_Pixels   : Natural := 0;
      Height_Pixels  : Natural := 0;
      Terminal_Modes : Terminal_Mode_Array := Empty_Terminal_Modes)
      return CryptoLib.Errors.Status;

   function Resize_PTY
     (Session       : in out SSH_Lib.Sessions.Session;
      Item          : in out Channel;
      Columns       : Natural;
      Rows          : Natural;
      Width_Pixels  : Natural := 0;
      Height_Pixels : Natural := 0)
      return CryptoLib.Errors.Status;

   --  Send an RFC 4254 env channel request on an opened session channel.
   --  Callers own ordering and policy: most servers require env requests
   --  before the exec/shell/subsystem request, and may reject names not
   --  allowed by server-side AcceptEnv policy.
   function Set_Environment
     (Session : in out SSH_Lib.Sessions.Session;
      Item    : in out Channel;
      Name    : String;
      Value   : String)
      return CryptoLib.Errors.Status;

   --  Send an RFC 4254 x11-req channel request on an opened session channel.
   --  This enables server-side X11 forwarding setup; accepting inbound x11
   --  channels and local X server policy remain caller-managed.
   function Request_X11_Forwarding
     (Session           : in out SSH_Lib.Sessions.Session;
      Item              : in out Channel;
      Single_Connection : Boolean;
      Auth_Protocol     : String;
      Auth_Cookie       : String;
      Screen_Number     : Natural := 0)
      return CryptoLib.Errors.Status;

   function Valid_X11_MIT_Magic_Cookie (Cookie : String) return Boolean;

   function X11_MIT_Magic_Cookies_Match
     (Expected  : String;
      Presented : String)
      return Boolean;

   --  Open an RFC 4254 direct-tcpip channel through an authenticated session.
   --  This is the SSH channel primitive used by local port forwarding.
   --  SSH_Lib.Forwarding provides listener and SOCKS5 CONNECT helpers; callers
   --  still own byte-pump policy through Read_Some/Write on the returned
   --  channel.
   function Open_Direct_TCPIP
     (Session            : in out SSH_Lib.Sessions.Session;
      Target_Host        : String;
      Target_Port        : Natural;
      Item               : in out Channel;
      Originator_Address : String := "127.0.0.1";
      Originator_Port    : Natural := 0)
      return CryptoLib.Errors.Status;

   --  Accept one pending RFC 4254 forwarded-tcpip channel opened by the server
   --  after a remote tcpip-forward request, draining the protected session
   --  stream as needed.  Callers still own accept-loop scheduling, policy, and
   --  byte pumping through Read_Some/Write.
   function Accept_Forwarded_TCPIP
     (Session : in out SSH_Lib.Sessions.Session;
      Item    : in out Channel)
      return CryptoLib.Errors.Status;

   --  Accept one pending RFC 4254 x11 channel opened by the server after an
   --  x11-req setup request.  Callers still own X11 cookie validation, local
   --  X server connection policy, scheduling, and byte pumping.
   function Accept_X11
     (Session : in out SSH_Lib.Sessions.Session;
      Item    : in out Channel)
      return CryptoLib.Errors.Status;

   function Read_Some
     (Item   : in out Channel;
      Buffer : out Ada.Streams.Stream_Element_Array;
      Last   : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   --  Read SSH extended-data type 1 (stderr) without mixing it into stdout.
   --  This is primarily for exec-channel diagnostics; forwarded direct-tcpip
   --  and subsystem channels normally use Read_Some.
   function Read_Stderr
     (Item   : in out Channel;
      Buffer : out Ada.Streams.Stream_Element_Array;
      Last   : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   function Write
     (Item : in out Channel;
      Data : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   function Send_EOF
     (Item : in out Channel)
      return CryptoLib.Errors.Status;

   function Close
     (Item : in out Channel)
      return CryptoLib.Errors.Status;

   function Exit_Status
     (Item : Channel;
      Code : out Integer)
      return CryptoLib.Errors.Status;

   --  Start an optional background reader task for a live exec channel.
   --  The task drains protected inbound packets into the channel's existing
   --  pending stdout/control state so callers can observe exit-status and EOF
   --  without driving every transport read explicitly.  The default remains
   --  caller-driven Read_Some; this helper never changes binary payload bytes.
   function Start_Background_Reader
     (Item : in out Channel)
      return CryptoLib.Errors.Status;

   --  Stop the optional background reader.  Close calls this automatically.
   function Stop_Background_Reader
     (Item : in out Channel)
      return CryptoLib.Errors.Status;

   function Background_Reader_Running
     (Item : Channel)
      return Boolean;

   function Background_Reader_Status
     (Item : Channel)
      return CryptoLib.Errors.Status;

private
   task type Background_Reader is
      entry Start (Target_Address : System.Address);
      entry Stop;
   end Background_Reader;

   type Background_Reader_Access is access Background_Reader;

   type Channel_State is
     (Channel_Closed,
      Channel_Opening,
      Channel_Opened,
      Channel_Exec_Requested,
      Channel_Exec_Active,
      Channel_Eof_Sent,
      Channel_Eof_Received,
      Channel_Close_Sent,
      Channel_Close_Received,
      Channel_Failed);

   type Channel is limited record
      Current_State              : Channel_State := Channel_Closed;
      Allocated                  : Boolean := False;
      Channel_Open_Confirmed     : Boolean := False;
      Exec_Request_Confirmed     : Boolean := False;
      Local_Channel_Id           : Interfaces.Unsigned_32 := 0;
      Remote_Channel_Id          : Interfaces.Unsigned_32 := 0;
      Local_Initial_Window_Size  : Interfaces.Unsigned_32 := 0;
      Local_Remaining_Window     : Interfaces.Unsigned_32 := 0;
      Local_Maximum_Packet_Size  : Interfaces.Unsigned_32 := 0;
      Remote_Remaining_Window    : Interfaces.Unsigned_32 := 0;
      Remote_Maximum_Packet_Size : Interfaces.Unsigned_32 := 0;
      Eof_Sent                   : Boolean := False;
      Eof_Received               : Boolean := False;
      Close_Sent                 : Boolean := False;
      Close_Received             : Boolean := False;
      Remote_Exit_Status_Known   : Boolean := False;
      Remote_Exit_Status         : Integer := 0;
      Owning_Session_Generation  : Interfaces.Unsigned_32 := 0;
      Owning_Session_Address     : System.Address := System.Null_Address;

      Pending_Stdout             : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Pending_Stderr             : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Last_Channel_Data          : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Last_EOF                   : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Last_Close                 : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Last_Window_Adjust         : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Last_Channel_Success       : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Last_Channel_Failure       : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Live_Channel_IO_Enabled    : Boolean := False;
      Live_Outbound_State        : SSH_Lib.Protocol.Protected_Packets.Protected_State;
      Live_Inbound_State         : SSH_Lib.Protocol.Protected_Packets.Protected_State;
      Live_Last_Protected_Outbound : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Live_Next_Protected_Inbound  : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Live_Has_Protected_Inbound   : Boolean := False;
      Live_Transcript_Ptr           : SSH_Lib.Sessions.Live_Attachment.Transcript_Access := null;
      Background_Task               : Background_Reader_Access := null;
      Background_Requested          : Boolean := False;
      Background_Running            : Boolean := False;
      Background_Last_Status        : CryptoLib.Errors.Status := CryptoLib.Errors.Ok;
      Outbound_Data_Bytes        : Natural := 0;
      Outbound_Data_Packets      : Natural := 0;
      Last_Failure_Status        : CryptoLib.Errors.Status := CryptoLib.Errors.Ok;
      Read_Timeout_MS            : Natural := 30_000;
      Write_Timeout_MS           : Natural := 30_000;
      Dirty                      : Boolean := False;
      Test_Write_Timeout_After_Partial : Boolean := False;
      Test_Send_EOF_Timeout      : Boolean := False;
      Test_Remote_Close_After_Partial : Boolean := False;
      Test_Close_Timeout      : Boolean := False;
      Test_Close_Exception_For_Cleanup : Boolean := False;
      Test_Stop_Background_Exception_For_Cleanup : Boolean := False;
      Test_Background_Task_Exception_For_Cleanup : Boolean := False;
      Test_Background_Drain_Terminal_Failure : Boolean := False;
      Test_Start_Background_Exception_For_Cleanup : Boolean := False;
   end record;
end SSH_Lib.Channels;
