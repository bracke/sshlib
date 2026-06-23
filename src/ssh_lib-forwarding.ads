with Ada.Streams;
with CryptoLib.Errors;
with GNAT.Sockets;
with System;
with SSH_Lib.Channels;
with SSH_Lib.Sessions;

package SSH_Lib.Forwarding is
   type Local_Forward_Listener is limited private;
   type Local_Forward_Connection is limited private;
   type Forward_Service is limited private;
   type Managed_Forward_Service is limited private;
   type SOCKS5_Target is private;
   type X11_Display_Target is private;
   type Pump_Direction is (Local_To_Channel, Channel_To_Local);
   type Forward_Service_Mode is (Local_Forward_Service, Dynamic_Forward_Service);
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

   function SOCKS5_Host (Target : SOCKS5_Target) return String;
   function SOCKS5_Port (Target : SOCKS5_Target) return Natural;

   function Parse_X11_Display
     (Display : String;
      Target  : out X11_Display_Target)
      return CryptoLib.Errors.Status;

   function Parse_X11_Display_From_Environment
     (Target : out X11_Display_Target)
      return CryptoLib.Errors.Status;

   function X11_Display_Kind
     (Target : X11_Display_Target)
      return X11_Display_Transport;

   function X11_Display_Host (Target : X11_Display_Target) return String;
   function X11_Display_Port (Target : X11_Display_Target) return Natural;
   function X11_Display_Socket_Path
     (Target : X11_Display_Target) return String;
   function X11_Display_Number (Target : X11_Display_Target) return Natural;
   function X11_Display_Screen (Target : X11_Display_Target) return Natural;

   function Open_X11_Display
     (Target     : X11_Display_Target;
      Connection : out Local_Forward_Connection)
      return CryptoLib.Errors.Status;

   function Open_X11_Display
     (Display    : String;
      Connection : out Local_Forward_Connection)
      return CryptoLib.Errors.Status;

   function Parse_SOCKS5_CONNECT_Request
     (Request : Ada.Streams.Stream_Element_Array;
      Target  : out SOCKS5_Target)
      return CryptoLib.Errors.Status;

   function Read_SOCKS5_CONNECT_Request
     (Connection : in out Local_Forward_Connection;
      Target     : out SOCKS5_Target)
      return CryptoLib.Errors.Status;

   function Send_SOCKS5_Reply
     (Connection   : in out Local_Forward_Connection;
      Reply_Status : CryptoLib.Errors.Status;
      Bind_Address : String := "0.0.0.0";
      Bind_Port    : Natural := 0)
      return CryptoLib.Errors.Status;

   function Open_Local_Forward_Listener
     (Bind_Address : String;
      Bind_Port    : Natural;
      Target_Host  : String;
      Target_Port  : Natural;
      Listener     : out Local_Forward_Listener;
      Backlog      : Natural := 16)
      return CryptoLib.Errors.Status;

   function Open_Dynamic_Forward_Listener
     (Bind_Address : String;
      Bind_Port    : Natural;
      Listener     : out Local_Forward_Listener;
      Backlog      : Natural := 16)
      return CryptoLib.Errors.Status;

   function Bound_Port (Listener : Local_Forward_Listener) return Natural;

   function Accept_Local_Forward
     (Session    : in out SSH_Lib.Sessions.Session;
      Listener   : in out Local_Forward_Listener;
      Connection : out Local_Forward_Connection;
      Channel    : in out SSH_Lib.Channels.Channel)
      return CryptoLib.Errors.Status;

   function Accept_Dynamic_Forward
     (Session    : in out SSH_Lib.Sessions.Session;
      Listener   : in out Local_Forward_Listener;
      Connection : out Local_Forward_Connection;
      Channel    : in out SSH_Lib.Channels.Channel;
      Target     : out SOCKS5_Target)
      return CryptoLib.Errors.Status;

   function Read_Local
     (Connection : in out Local_Forward_Connection;
      Buffer     : out Ada.Streams.Stream_Element_Array;
      Last       : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   function Write_Local
     (Connection : in out Local_Forward_Connection;
      Data       : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   function Pump_Once
     (Connection     : in out Local_Forward_Connection;
      Channel        : in out SSH_Lib.Channels.Channel;
      Direction      : Pump_Direction;
      Bytes_Moved    : out Natural;
      Max_Chunk_Size : Natural := 4096)
      return CryptoLib.Errors.Status;

   function Pump_Bounded
     (Connection               : in out Local_Forward_Connection;
      Channel                  : in out SSH_Lib.Channels.Channel;
      Local_To_Channel_Bytes   : out Natural;
      Channel_To_Local_Bytes   : out Natural;
      Max_Iterations           : Natural := 64;
      Max_Chunk_Size           : Natural := 4096)
      return CryptoLib.Errors.Status;

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

   function Start_Dynamic_Forward_Service
     (Session      : in out SSH_Lib.Sessions.Session;
      Bind_Address : String;
      Bind_Port    : Natural;
      Handler      : Dynamic_Forward_Handler;
      Service      : in out Forward_Service;
      Backlog      : Natural := 16;
      Max_Accepted : Natural := 0)
      return CryptoLib.Errors.Status;

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

   function Forward_Service_Running (Service : Forward_Service) return Boolean;
   function Forward_Service_Status
     (Service : Forward_Service) return CryptoLib.Errors.Status;
   function Forward_Service_Accepted_Count
     (Service : Forward_Service) return Natural;
   function Forward_Service_Max_Accepted
     (Service : Forward_Service) return Natural;
   function Forward_Service_Bound_Port (Service : Forward_Service) return Natural;
   function Forward_Service_Kind
     (Service : Forward_Service) return Forward_Service_Mode;

   function Managed_Forward_Service_Running
     (Service : Managed_Forward_Service) return Boolean;
   function Managed_Forward_Service_Status
     (Service : Managed_Forward_Service) return CryptoLib.Errors.Status;
   function Managed_Forward_Service_Accepted_Count
     (Service : Managed_Forward_Service) return Natural;
   function Managed_Forward_Service_Completed_Count
     (Service : Managed_Forward_Service) return Natural;
   function Managed_Forward_Service_Active_Count
     (Service : Managed_Forward_Service) return Natural;
   function Managed_Forward_Service_Failed_Count
     (Service : Managed_Forward_Service) return Natural;
   function Managed_Forward_Service_Max_Concurrent
     (Service : Managed_Forward_Service) return Natural;
   function Managed_Forward_Service_Max_Accepted
     (Service : Managed_Forward_Service) return Natural;
   function Managed_Forward_Service_Bound_Port
     (Service : Managed_Forward_Service) return Natural;
   function Managed_Forward_Service_Kind
     (Service : Managed_Forward_Service) return Forward_Service_Mode;

   function Stop (Service : in out Forward_Service)
      return CryptoLib.Errors.Status;

   function Stop (Service : in out Managed_Forward_Service)
      return CryptoLib.Errors.Status;

   function Close (Connection : in out Local_Forward_Connection)
      return CryptoLib.Errors.Status;

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
   end record;
end SSH_Lib.Forwarding;
