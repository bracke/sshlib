with Ada.Streams;
with Interfaces; use Interfaces;
with CryptoLib.Errors;
with SSH_Lib.Protocol.Buffers;

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

   function Valid_Command (Command : String) return Boolean;

   function Encode_Channel_Open
     (Sender_Channel      : Interfaces.Unsigned_32;
      Initial_Window_Size : Interfaces.Unsigned_32 :=
        Default_Initial_Window_Size;
      Maximum_Packet_Size : Interfaces.Unsigned_32 :=
        Default_Maximum_Packet_Size)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;

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

   function Parse_Channel_Open_Confirmation
     (Payload            : Ada.Streams.Stream_Element_Array;
      Expected_Recipient : Interfaces.Unsigned_32;
      Item               : out Open_Confirmation) return CryptoLib.Errors.Status;

   function Parse_Channel_Open_Failure
     (Payload            : Ada.Streams.Stream_Element_Array;
      Expected_Recipient : Interfaces.Unsigned_32;
      Item               : out Open_Failure) return CryptoLib.Errors.Status;

   function Parse_Forwarded_TCPIP_Open
     (Payload : Ada.Streams.Stream_Element_Array;
      Item    : out Forwarded_TCPIP_Open)
      return CryptoLib.Errors.Status;

   function Parse_X11_Open
     (Payload : Ada.Streams.Stream_Element_Array;
      Item    : out X11_Open)
      return CryptoLib.Errors.Status;

   function Encode_Channel_Open_Confirmation
     (Recipient_Channel   : Interfaces.Unsigned_32;
      Sender_Channel      : Interfaces.Unsigned_32;
      Initial_Window_Size : Interfaces.Unsigned_32 :=
        Default_Initial_Window_Size;
      Maximum_Packet_Size : Interfaces.Unsigned_32 :=
        Default_Maximum_Packet_Size)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;

   function Encode_Exec_Request
     (Recipient_Channel : Interfaces.Unsigned_32; Command : String)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;

   function Encode_Subsystem_Request
     (Recipient_Channel : Interfaces.Unsigned_32; Subsystem_Name : String)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;

   function Encode_Shell_Request
     (Recipient_Channel : Interfaces.Unsigned_32)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;

   function Encode_Environment_Request
     (Recipient_Channel : Interfaces.Unsigned_32;
      Name              : String;
      Value             : String)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;

   function Encode_X11_Request
     (Recipient_Channel : Interfaces.Unsigned_32;
      Single_Connection : Boolean;
      Auth_Protocol     : String;
      Auth_Cookie       : String;
      Screen_Number     : Interfaces.Unsigned_32 := 0)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;

   function Encode_PTY_Request
     (Recipient_Channel : Interfaces.Unsigned_32;
      Terminal_Type     : String;
      Columns           : Interfaces.Unsigned_32;
      Rows              : Interfaces.Unsigned_32;
      Width_Pixels      : Interfaces.Unsigned_32 := 0;
      Height_Pixels     : Interfaces.Unsigned_32 := 0;
      Terminal_Modes    : Terminal_Mode_Array := Empty_Terminal_Modes)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;

   function Encode_Window_Change_Request
     (Recipient_Channel : Interfaces.Unsigned_32;
      Columns           : Interfaces.Unsigned_32;
      Rows              : Interfaces.Unsigned_32;
      Width_Pixels      : Interfaces.Unsigned_32 := 0;
      Height_Pixels     : Interfaces.Unsigned_32 := 0)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;

   --  Parse SSH_MSG_CHANNEL_SUCCESS / SSH_MSG_CHANNEL_FAILURE.
   --  Expected_Recipient is the local channel id originally sent as
   --  CHANNEL_OPEN.sender_channel.  It is not the remote channel id used as
   --  CHANNEL_REQUEST.recipient_channel.
   function Parse_Exec_Reply
     (Payload            : Ada.Streams.Stream_Element_Array;
      Expected_Recipient : Interfaces.Unsigned_32;
      Reply              : out Exec_Reply) return CryptoLib.Errors.Status;

   function Encode_Channel_Data
     (Recipient_Channel : Interfaces.Unsigned_32;
      Data              : Ada.Streams.Stream_Element_Array)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;

   function Parse_Channel_Data
     (Payload            : Ada.Streams.Stream_Element_Array;
      Expected_Recipient : Interfaces.Unsigned_32;
      Item               : out Channel_Data_Event)
      return CryptoLib.Errors.Status;

   function Encode_Channel_Extended_Data
     (Recipient_Channel : Interfaces.Unsigned_32;
      Data_Type_Code    : Interfaces.Unsigned_32;
      Data              : Ada.Streams.Stream_Element_Array)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;

   function Parse_Channel_Extended_Data
     (Payload            : Ada.Streams.Stream_Element_Array;
      Expected_Recipient : Interfaces.Unsigned_32;
      Item               : out Channel_Extended_Data_Event)
      return CryptoLib.Errors.Status;

   function Encode_Channel_Window_Adjust
     (Recipient_Channel : Interfaces.Unsigned_32;
      Bytes_To_Add      : Interfaces.Unsigned_32)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;

   function Parse_Channel_Window_Adjust
     (Payload            : Ada.Streams.Stream_Element_Array;
      Expected_Recipient : Interfaces.Unsigned_32;
      Item               : out Channel_Window_Adjust_Event)
      return CryptoLib.Errors.Status;

   function Encode_Channel_EOF
     (Recipient_Channel : Interfaces.Unsigned_32)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;

   function Encode_Channel_Close
     (Recipient_Channel : Interfaces.Unsigned_32)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;

   function Parse_Channel_One_Id
     (Payload            : Ada.Streams.Stream_Element_Array;
      Expected_Message   : Ada.Streams.Stream_Element;
      Expected_Recipient : Interfaces.Unsigned_32)
      return CryptoLib.Errors.Status;

   --  Parses the common CHANNEL_REQUEST header plus strict known terminal
   --  payloads for exit-status and exit-signal.
   --  Unknown request types are accepted with trailing request-specific fields
   --  preserved only as the request name/want-reply decision boundary; callers
   --  can then send CHANNEL_FAILURE when want-reply is set.
   function Parse_Channel_Request
     (Payload            : Ada.Streams.Stream_Element_Array;
      Expected_Recipient : Interfaces.Unsigned_32;
      Item               : out Channel_Request_Event)
      return CryptoLib.Errors.Status;

   function Request_Is_Exit_Status
     (Item : Channel_Request_Event) return Boolean;

   function Request_Is_Exit_Signal
     (Item : Channel_Request_Event) return Boolean;

   function Encode_Exit_Status_Request
     (Recipient_Channel : Interfaces.Unsigned_32;
      Want_Reply        : Boolean;
      Exit_Status       : Interfaces.Unsigned_32)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;

   function Encode_Channel_Success
     (Recipient_Channel : Interfaces.Unsigned_32)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;

   function Encode_Channel_Failure
     (Recipient_Channel : Interfaces.Unsigned_32)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;
end SSH_Lib.Protocol.Channels;
