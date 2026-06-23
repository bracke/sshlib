with Ada.Streams;
with GNAT.Expect;
with GNAT.Sockets;
with Interfaces;
with Ada.Strings.Unbounded;
with CryptoLib.Errors;
with SSH_Lib.Protocol.Buffers;
with SSH_Lib.Protocol.Packets;
with SSH_Lib.Protocol.Protected_Packets;

package SSH_Lib.Sessions.Live_Transcript is
   type Driver is limited private;
   type Driver_Access is access all Driver;

   procedure Reset (Item : out Driver);

   function Connect
     (Item               : in out Driver;
      Host               : String;
      Port               : Natural;
      Connect_Timeout_MS : Natural := 0;
      Read_Timeout_MS    : Natural := 0;
      Write_Timeout_MS   : Natural := 0) return CryptoLib.Errors.Status;

   function Connect_Through_Jump
     (Item             : in out Driver;
      Outer            : Driver_Access;
      Local_Channel    : Interfaces.Unsigned_32;
      Remote_Channel   : Interfaces.Unsigned_32;
      Own_Outer        : Boolean := False;
      Read_Timeout_MS  : Natural := 0;
      Write_Timeout_MS : Natural := 0) return CryptoLib.Errors.Status;

   function Connect_Through_Proxy_Command
     (Item               : in out Driver;
      Command_Text       : String;
      Host               : String;
      Port               : Natural;
      User               : String;
      Connect_Timeout_MS : Natural := 0;
      Read_Timeout_MS    : Natural := 0;
      Write_Timeout_MS   : Natural := 0) return CryptoLib.Errors.Status;

   function Expand_Proxy_Command_For_Test
     (Command_Text : String;
      Host         : String;
      Port         : Natural;
      User         : String) return String;

   function Last_Proxy_Command_Diagnostics
     (Item : Driver) return SSH_Lib.Sessions.Proxy_Command_Diagnostic;

   function Send_Identification
     (Item : in out Driver) return CryptoLib.Errors.Status;

   function Read_Identification
     (Item : in out Driver) return CryptoLib.Errors.Status;

   function Send_Cleartext_Packet
     (Item : in out Driver; Payload : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   function Read_Cleartext_Packet
     (Item    : in out Driver;
      Payload : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;

   function Send_Key_Exchange_Packet
     (Item : in out Driver; Payload : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   function Read_Key_Exchange_Packet
     (Item    : in out Driver;
      Payload : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;

   function Install_Protected_Keys
     (Item : in out Driver; Mac_Key : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

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

   function Send_Protected_Packet
     (Item : in out Driver; Payload : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   function Read_Protected_Packet
     (Item    : in out Driver;
      Payload : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;

   function Activate_Delayed_Compression
     (Item : in out Driver) return CryptoLib.Errors.Status;

   function Local_Identification (Item : Driver) return String;

   function Remote_Identification (Item : Driver) return String;

   function Last_Cleartext_Outbound
     (Item : Driver) return Ada.Streams.Stream_Element_Array;

   function Last_Cleartext_Inbound
     (Item : Driver) return Ada.Streams.Stream_Element_Array;

   function Last_Protected_Outbound
     (Item : Driver) return Ada.Streams.Stream_Element_Array;

   function Last_Protected_Inbound
     (Item : Driver) return Ada.Streams.Stream_Element_Array;

   function Is_Connected (Item : Driver) return Boolean;

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
      Proxy_Command_Diagnostic_Item :
        SSH_Lib.Sessions.Proxy_Command_Diagnostic;
   end record;
end SSH_Lib.Sessions.Live_Transcript;
