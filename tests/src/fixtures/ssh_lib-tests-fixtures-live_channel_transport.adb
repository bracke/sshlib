with Ada.Streams;
with Ada.Text_IO;
with Interfaces;
with SSH_Lib.Channels;
with SSH_Lib.Channels.Test_Support;
with CryptoLib.Errors;
with SSH_Lib.Protocol.Buffers;
with SSH_Lib.Protocol.Channels;
with SSH_Lib.Protocol.Numbers;
with SSH_Lib.Protocol.Protected_Packets;
with SSH_Lib.Protocol.Transport_Messages;
with SSH_Lib.Sessions;
with SSH_Lib.Sessions.Test_Support;
with SSH_Lib.Tests.Assertions;

package body SSH_Lib.Tests.Fixtures.Live_Channel_Transport is

   use type CryptoLib.Errors.Status;
   use type Ada.Streams.Stream_Element_Array;
   use type Ada.Streams.Stream_Element_Offset;
   use type Interfaces.Unsigned_32;
   use SSH_Lib.Protocol.Buffers;

   procedure Check (Condition : Boolean; Label_Text : String) is
   begin
      if not Condition then
         Ada.Text_IO.Put_Line ("FAILED: " & Label_Text);
         raise Program_Error;
      end if;
   end Check;

   function Build_Open_Confirmation
     (Recipient_Channel   : Interfaces.Unsigned_32;
      Sender_Channel      : Interfaces.Unsigned_32;
      Initial_Window_Size : Interfaces.Unsigned_32;
      Maximum_Packet_Size : Interfaces.Unsigned_32)
      return Ada.Streams.Stream_Element_Array
   is
      Work_Item    : Packet_Buffer;
      Status_Value : CryptoLib.Errors.Status;
   begin
      Status_Value :=
        Append_Byte
          (Work_Item,
           SSH_Lib.Protocol.Channels.SSH_MSG_CHANNEL_OPEN_CONFIRMATION);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Ok,
         "live channel fixture",
         "open confirmation type");
      Status_Value :=
        Append
          (Work_Item,
           SSH_Lib.Protocol.Numbers.Encode_Uint32 (Recipient_Channel));
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Ok,
         "live channel fixture",
         "open confirmation recipient");
      Status_Value :=
        Append
          (Work_Item, SSH_Lib.Protocol.Numbers.Encode_Uint32 (Sender_Channel));
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Ok,
         "live channel fixture",
         "open confirmation sender");
      Status_Value :=
        Append
          (Work_Item,
           SSH_Lib.Protocol.Numbers.Encode_Uint32 (Initial_Window_Size));
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Ok,
         "live channel fixture",
         "open confirmation window");
      Status_Value :=
        Append
          (Work_Item,
           SSH_Lib.Protocol.Numbers.Encode_Uint32 (Maximum_Packet_Size));
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Ok,
         "live channel fixture",
         "open confirmation packet size");
      return To_Array (Work_Item);
   end Build_Open_Confirmation;

   function Build_Exec_Success
     (Recipient_Channel : Interfaces.Unsigned_32)
      return Ada.Streams.Stream_Element_Array is
   begin
      return
        To_Array
          (SSH_Lib.Protocol.Channels.Encode_Channel_Success
             (Recipient_Channel));
   end Build_Exec_Success;

   function Bytes_From_String
     (Value : String) return Ada.Streams.Stream_Element_Array
   is
      Result :
        Ada.Streams.Stream_Element_Array
          (Ada.Streams.Stream_Element_Offset'(1)
           .. Ada.Streams.Stream_Element_Offset (Value'Length));
      Cursor : Ada.Streams.Stream_Element_Offset := Result'First;
   begin
      for Character_Value of Value loop
         Result (Cursor) :=
           Ada.Streams.Stream_Element (Character'Pos (Character_Value));
         Cursor := Cursor + 1;
      end loop;
      return Result;
   end Bytes_From_String;

   function Append_String
     (Item : in out Packet_Buffer; Text : String) return CryptoLib.Errors.Status
   is
   begin
      return
        Append
          (Item,
           To_Array
             (SSH_Lib.Protocol.Numbers.Encode_SSH_String
                (Bytes_From_String (Text))));
   end Append_String;

   function Build_Unknown_Channel_Request
     (Recipient_Channel : Interfaces.Unsigned_32;
      Request_Name      : String;
      Want_Reply        : Boolean)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer
   is
      Work_Item    : Packet_Buffer;
      Status_Value : CryptoLib.Errors.Status;
   begin
      Status_Value :=
        Append_Byte
          (Work_Item, SSH_Lib.Protocol.Channels.SSH_MSG_CHANNEL_REQUEST);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Ok,
         "live channel fixture",
         "unknown request type");
      Status_Value :=
        Append
          (Work_Item,
           SSH_Lib.Protocol.Numbers.Encode_Uint32 (Recipient_Channel));
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Ok,
         "live channel fixture",
         "unknown request recipient");
      Status_Value := Append_String (Work_Item, Request_Name);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Ok,
         "live channel fixture",
         "unknown request name");
      Status_Value :=
        Append_Byte
          (Work_Item, SSH_Lib.Protocol.Numbers.Encode_Boolean (Want_Reply));
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Ok,
         "live channel fixture",
         "unknown request want-reply");
      return Work_Item;
   end Build_Unknown_Channel_Request;

   procedure Assert_Live_Channel_Transport_Boundary is
      Session_Item   : SSH_Lib.Sessions.Session;
      Channel_Item   : SSH_Lib.Channels.Channel;
      Status_Value   : CryptoLib.Errors.Status;
      Buffer_Item    : Ada.Streams.Stream_Element_Array (1 .. 16);
      Last_Index     : Ada.Streams.Stream_Element_Offset;
      Request_Bytes  : constant Ada.Streams.Stream_Element_Array (1 .. 6) :=
        [16#00#, 16#0A#, 16#0D#, 16#7F#, 16#80#, 16#FF#];
      Response_Bytes : constant Ada.Streams.Stream_Element_Array (1 .. 6) :=
        [16#FF#, 16#80#, 16#7F#, 16#0D#, 16#0A#, 16#00#];
      Inbound_Data   : Packet_Buffer;
   begin
      SSH_Lib.Sessions.Test_Support.Mark_Authenticated_Open_For_Test
        (Session_Item);
      SSH_Lib.Sessions.Test_Support.Enable_Live_Channel_IO_For_Test
        (Session_Item);
      Check
        (SSH_Lib.Sessions.Test_Support.Is_Open_For_Test (Session_Item),
         "live channel fixture session open");
      Check
        (SSH_Lib.Sessions.Test_Support.Is_Encrypted_For_Test (Session_Item),
         "live channel fixture session encrypted");
      Check
        (SSH_Lib.Sessions.Test_Support.Is_Authenticated_For_Test
           (Session_Item),
         "live channel fixture authenticated");

      Status_Value :=
        SSH_Lib.Sessions.Test_Support.Queue_Channel_Open_Response_For_Test
          (Session_Item, Build_Open_Confirmation (0, 900, 4096, 8192));
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Ok,
         "live channel fixture",
         "queue protected open response");
      Status_Value :=
        SSH_Lib.Sessions.Test_Support.Queue_Exec_Response_For_Test
          (Session_Item, Build_Exec_Success (0));
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Ok,
         "live channel fixture",
         "queue protected exec response");

      Status_Value :=
        SSH_Lib.Channels.Open_Exec
          (Session_Item, "git-upload-pack 'repo.git'", Channel_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Ok,
         "live channel fixture",
         "open exec over protected boundary");
      Check
        (SSH_Lib.Sessions.Test_Support.Last_Protected_Channel_Payload_For_Test
           (Session_Item)'Length
         > SSH_Lib.Protocol.Protected_Packets.Mac_Length,
         "open/exec packets crossed protected session boundary");

      Status_Value := SSH_Lib.Channels.Write (Channel_Item, Request_Bytes);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Ok,
         "live channel fixture",
         "write over protected channel boundary");
      Check
        (SSH_Lib.Channels.Test_Support.Last_Protected_Outbound_For_Test
           (Channel_Item)'Length
         > SSH_Lib.Protocol.Protected_Packets.Mac_Length,
         "channel data packet crossed protected boundary");

      Status_Value :=
        Set
          (Inbound_Data,
           To_Array
             (SSH_Lib.Protocol.Channels.Encode_Channel_Data
                (0, Response_Bytes)));
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Ok,
         "live channel fixture",
         "build inbound channel data");
      Status_Value :=
        SSH_Lib.Channels.Test_Support.Queue_Protected_Inbound_For_Test
          (Channel_Item, To_Array (Inbound_Data));
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Ok,
         "live channel fixture",
         "queue protected inbound data");
      Status_Value :=
        SSH_Lib.Channels.Read_Some (Channel_Item, Buffer_Item, Last_Index);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Ok,
         "live channel fixture",
         "read protected inbound data");
      SSH_Lib.Tests.Assertions.Check_Bytes
        (Buffer_Item (Buffer_Item'First .. Last_Index),
         Response_Bytes,
         "live channel fixture",
         "protected inbound bytes are exact");

      Status_Value := SSH_Lib.Channels.Send_EOF (Channel_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Ok,
         "live channel fixture",
         "send EOF over protected boundary");
      Check
        (SSH_Lib.Channels.Test_Support.Last_Protected_Outbound_For_Test
           (Channel_Item)'Length
         > SSH_Lib.Protocol.Protected_Packets.Mac_Length,
         "EOF packet crossed protected boundary");
   end Assert_Live_Channel_Transport_Boundary;

   procedure Assert_Live_Channel_Exit_Status_And_Close is
      Session_Item    : SSH_Lib.Sessions.Session;
      Channel_Item    : SSH_Lib.Channels.Channel;
      Status_Value    : CryptoLib.Errors.Status;
      Buffer_Item     : Ada.Streams.Stream_Element_Array (1 .. 8);
      Last_Index      : Ada.Streams.Stream_Element_Offset;
      Inbound_Request : Packet_Buffer;
      Inbound_Close   : Packet_Buffer;
      Exit_Code       : Integer;
   begin
      SSH_Lib.Sessions.Test_Support.Mark_Authenticated_Open_For_Test
        (Session_Item);
      SSH_Lib.Sessions.Test_Support.Enable_Live_Channel_IO_For_Test
        (Session_Item);

      Status_Value :=
        SSH_Lib.Sessions.Test_Support.Queue_Channel_Open_Response_For_Test
          (Session_Item, Build_Open_Confirmation (0, 901, 4096, 8192));
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Ok,
         "live channel exit fixture",
         "queue protected open response");
      Status_Value :=
        SSH_Lib.Sessions.Test_Support.Queue_Exec_Response_For_Test
          (Session_Item, Build_Exec_Success (0));
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Ok,
         "live channel exit fixture",
         "queue protected exec response");

      Status_Value :=
        SSH_Lib.Channels.Open_Exec
          (Session_Item, "git-receive-pack 'repo.git'", Channel_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Ok,
         "live channel exit fixture",
         "open exec over protected boundary");

      Status_Value :=
        Set
          (Inbound_Request,
           To_Array
             (SSH_Lib.Protocol.Channels.Encode_Exit_Status_Request
                (0, True, Interfaces.Unsigned_32'(0))));
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Ok,
         "live channel exit fixture",
         "build protected exit-status request");
      Status_Value :=
        SSH_Lib.Channels.Test_Support.Queue_Protected_Inbound_For_Test
          (Channel_Item, To_Array (Inbound_Request));
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Ok,
         "live channel exit fixture",
         "queue protected exit-status request");

      Status_Value :=
        SSH_Lib.Channels.Read_Some (Channel_Item, Buffer_Item, Last_Index);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Read_Failed,
         "live channel exit fixture",
         "exit-status without queued stdout maps to read failed");
      Status_Value := SSH_Lib.Channels.Exit_Status (Channel_Item, Exit_Code);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Channel_Request_Failed,
         "live channel exit fixture",
         "exit-status unavailable after failed protected read");
      Check
        (Exit_Code = -1,
         "live channel exit fixture leaves unknown status code unchanged");
      Check
        (SSH_Lib.Channels.Test_Support.Last_Channel_Success_Payload_For_Test
           (Channel_Item)'Length
         = 0,
         "live channel exit fixture does not acknowledge failed protected read");
      Check
        (SSH_Lib.Channels.Test_Support.Last_Protected_Outbound_For_Test
           (Channel_Item)'Length
         = 0,
         "live channel exit fixture sends no protected response after failed read");

      Status_Value :=
        Set
          (Inbound_Close,
           To_Array (SSH_Lib.Protocol.Channels.Encode_Channel_Close (0)));
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Ok,
         "live channel exit fixture",
         "build protected close");
      Status_Value :=
        SSH_Lib.Channels.Test_Support.Queue_Protected_Inbound_For_Test
          (Channel_Item, To_Array (Inbound_Close));
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Ok,
         "live channel exit fixture",
         "queue protected close");
      Status_Value :=
        SSH_Lib.Channels.Read_Some (Channel_Item, Buffer_Item, Last_Index);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Read_Failed,
         "live channel exit fixture",
         "protected close after failed read remains failed");
      Check
        (SSH_Lib.Channels.Test_Support.Last_Close_Payload_For_Test
           (Channel_Item)'Length
         = 0,
         "live channel exit fixture does not acknowledge close after failed read");
      Check
        (SSH_Lib.Channels.Test_Support.Last_Protected_Outbound_For_Test
           (Channel_Item)'Length
         = 0,
         "live channel exit fixture sends no close response after failed read");

      Status_Value := SSH_Lib.Channels.Close (Channel_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Ok,
         "live channel exit fixture",
         "local close after protected close/status");
      Status_Value := SSH_Lib.Channels.Exit_Status (Channel_Item, Exit_Code);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Channel_Request_Failed,
         "live channel exit fixture",
         "exit-status remains unavailable after local close cleanup");
      Check
        (Exit_Code = 0,
         "live channel exit fixture leaves decoded status code after close");
      Status_Value := SSH_Lib.Sessions.Close (Session_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Ok,
         "live channel exit fixture",
         "session close after live channel flow");
   end Assert_Live_Channel_Exit_Status_And_Close;

   procedure Assert_Live_Channel_Disconnect_Marks_Failed is
      Session_Item      : SSH_Lib.Sessions.Session;
      Channel_Item      : SSH_Lib.Channels.Channel;
      Status_Value      : CryptoLib.Errors.Status;
      Buffer_Item       : Ada.Streams.Stream_Element_Array (1 .. 8);
      Last_Index        : Ada.Streams.Stream_Element_Offset;
      Disconnect_Packet : Packet_Buffer;
      Request_Bytes     : constant Ada.Streams.Stream_Element_Array (1 .. 4) :=
        [16#30#, 16#30#, 16#30#, 16#30#];
   begin
      SSH_Lib.Sessions.Test_Support.Mark_Authenticated_Open_For_Test
        (Session_Item);
      SSH_Lib.Sessions.Test_Support.Enable_Live_Channel_IO_For_Test
        (Session_Item);

      Status_Value :=
        SSH_Lib.Sessions.Test_Support.Queue_Channel_Open_Response_For_Test
          (Session_Item, Build_Open_Confirmation (0, 902, 4096, 8192));
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Ok,
         "live channel disconnect fixture",
         "queue protected open response");
      Status_Value :=
        SSH_Lib.Sessions.Test_Support.Queue_Exec_Response_For_Test
          (Session_Item, Build_Exec_Success (0));
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Ok,
         "live channel disconnect fixture",
         "queue protected exec response");

      Status_Value :=
        SSH_Lib.Channels.Open_Exec
          (Session_Item, "git-upload-pack 'repo.git'", Channel_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Ok,
         "live channel disconnect fixture",
         "open exec over protected boundary");

      Disconnect_Packet :=
        SSH_Lib.Protocol.Transport_Messages.Encode_Disconnect
          (Reason_Code => 11, Description => "fixture disconnect");
      Status_Value :=
        SSH_Lib.Channels.Test_Support.Queue_Protected_Inbound_For_Test
          (Channel_Item, To_Array (Disconnect_Packet));
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Ok,
         "live channel disconnect fixture",
         "queue protected disconnect");

      Status_Value :=
        SSH_Lib.Channels.Read_Some (Channel_Item, Buffer_Item, Last_Index);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Connection_Failed,
         "live channel disconnect fixture",
         "disconnect maps to connection failed");
      Check
        (SSH_Lib.Channels.Test_Support.Is_Dirty_For_Test (Channel_Item),
         "live channel disconnect fixture marks channel dirty");
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Channels.Test_Support.Last_Failure_For_Test (Channel_Item),
         CryptoLib.Errors.Connection_Failed,
         "live channel disconnect fixture",
         "disconnect records terminal failure");

      Status_Value := SSH_Lib.Channels.Write (Channel_Item, Request_Bytes);
      Check
        (Status_Value /= CryptoLib.Errors.Ok,
         "live channel disconnect fixture rejects later Git writes");

      Status_Value := SSH_Lib.Channels.Close (Channel_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Ok,
         "live channel disconnect fixture",
         "close after disconnect cleanup");
      Status_Value := SSH_Lib.Sessions.Close (Session_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Ok,
         "live channel disconnect fixture",
         "session close after disconnect");
   end Assert_Live_Channel_Disconnect_Marks_Failed;

   procedure Assert_Live_Write_Drains_Window_Adjust is
      Session_Item  : SSH_Lib.Sessions.Session;
      Channel_Item  : SSH_Lib.Channels.Channel;
      Status_Value  : CryptoLib.Errors.Status;
      Window_Adjust : Packet_Buffer;
      Request_Bytes : constant Ada.Streams.Stream_Element_Array (1 .. 4) :=
        [16#30#, 16#30#, 16#30#, 16#30#];
   begin
      SSH_Lib.Sessions.Test_Support.Mark_Authenticated_Open_For_Test
        (Session_Item);
      SSH_Lib.Sessions.Test_Support.Enable_Live_Channel_IO_For_Test
        (Session_Item);

      Status_Value :=
        SSH_Lib.Sessions.Test_Support.Queue_Channel_Open_Response_For_Test
          (Session_Item, Build_Open_Confirmation (0, 903, 0, 8192));
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Ok,
         "live channel window fixture",
         "queue protected open response");
      Status_Value :=
        SSH_Lib.Sessions.Test_Support.Queue_Exec_Response_For_Test
          (Session_Item, Build_Exec_Success (0));
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Ok,
         "live channel window fixture",
         "queue protected exec response");

      Status_Value :=
        SSH_Lib.Channels.Open_Exec
          (Session_Item, "git-receive-pack 'repo.git'", Channel_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Ok,
         "live channel window fixture",
         "open exec over protected boundary");
      Check
        (SSH_Lib.Channels.Test_Support.Remote_Remaining_Window_For_Test
           (Channel_Item)
         = 0,
         "live channel window fixture starts with exhausted remote window");

      Window_Adjust :=
        SSH_Lib.Protocol.Channels.Encode_Channel_Window_Adjust (0, 8);
      Status_Value :=
        SSH_Lib.Channels.Test_Support.Queue_Protected_Inbound_For_Test
          (Channel_Item, To_Array (Window_Adjust));
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Ok,
         "live channel window fixture",
         "queue protected window-adjust");

      Status_Value := SSH_Lib.Channels.Write (Channel_Item, Request_Bytes);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Ok,
         "live channel window fixture",
         "write drains window-adjust before timing out");
      Check
        (SSH_Lib.Channels.Test_Support.Outbound_Data_Byte_Count_For_Test
           (Channel_Item)
         = Request_Bytes'Length,
         "live channel window fixture wrote bytes after adjust");
      Check
        (SSH_Lib.Channels.Test_Support.Remote_Remaining_Window_For_Test
           (Channel_Item)
         = 4,
         "live channel window fixture consumed adjusted window");
      Check
        (SSH_Lib.Channels.Test_Support.Last_Protected_Outbound_For_Test
           (Channel_Item)'Length
         > SSH_Lib.Protocol.Protected_Packets.Mac_Length,
         "live channel window fixture data crossed protected boundary after adjust");

      Status_Value := SSH_Lib.Channels.Close (Channel_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Ok,
         "live channel window fixture",
         "close after write window-adjust");
      Status_Value := SSH_Lib.Sessions.Close (Session_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Ok,
         "live channel window fixture",
         "session close after write window-adjust");
   end Assert_Live_Write_Drains_Window_Adjust;

   procedure Assert_Open_Exec_Disconnects_Map_To_Connection_Failed is
      Session_Item      : SSH_Lib.Sessions.Session;
      Channel_Item      : SSH_Lib.Channels.Channel;
      Status_Value      : CryptoLib.Errors.Status;
      Disconnect_Packet : Packet_Buffer;
   begin
      SSH_Lib.Sessions.Test_Support.Mark_Authenticated_Open_For_Test
        (Session_Item);
      SSH_Lib.Sessions.Test_Support.Enable_Live_Channel_IO_For_Test
        (Session_Item);

      Disconnect_Packet :=
        SSH_Lib.Protocol.Transport_Messages.Encode_Disconnect
          (Reason_Code => 11,
           Description => "disconnect during open response");
      Status_Value :=
        SSH_Lib.Sessions.Test_Support.Queue_Channel_Open_Response_For_Test
          (Session_Item, To_Array (Disconnect_Packet));
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Ok,
         "live open disconnect fixture",
         "queue protected disconnect as open response");

      Status_Value :=
        SSH_Lib.Channels.Open_Exec
          (Session_Item, "git-upload-pack 'repo.git'", Channel_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Connection_Failed,
         "live open disconnect fixture",
         "disconnect during open maps to connection failed");
      Check
        (SSH_Lib.Sessions.Test_Support.Is_Dirty_For_Test (Session_Item),
         "live open disconnect fixture marks session dirty");
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Sessions.Test_Support.Last_Failure_For_Test (Session_Item),
         CryptoLib.Errors.Connection_Failed,
         "live open disconnect fixture",
         "disconnect during open records connection failure");
      Check
        (SSH_Lib.Sessions.Test_Support.Active_Channel_Count_For_Test
           (Session_Item)
         = 0,
         "live open disconnect fixture releases transient channel slot");

      SSH_Lib.Sessions.Test_Support.Mark_Authenticated_Open_For_Test
        (Session_Item);
      SSH_Lib.Sessions.Test_Support.Enable_Live_Channel_IO_For_Test
        (Session_Item);
      Status_Value :=
        SSH_Lib.Sessions.Test_Support.Queue_Channel_Open_Response_For_Test
          (Session_Item, Build_Open_Confirmation (0, 904, 4096, 8192));
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Ok,
         "live exec disconnect fixture",
         "queue protected open response");
      Disconnect_Packet :=
        SSH_Lib.Protocol.Transport_Messages.Encode_Disconnect
          (Reason_Code => 11,
           Description => "disconnect during exec response");
      Status_Value :=
        SSH_Lib.Sessions.Test_Support.Queue_Exec_Response_For_Test
          (Session_Item, To_Array (Disconnect_Packet));
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Ok,
         "live exec disconnect fixture",
         "queue protected disconnect as exec response");

      Status_Value :=
        SSH_Lib.Channels.Open_Exec
          (Session_Item, "git-receive-pack 'repo.git'", Channel_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Connection_Failed,
         "live exec disconnect fixture",
         "disconnect during exec maps to connection failed");
      Check
        (SSH_Lib.Sessions.Test_Support.Is_Dirty_For_Test (Session_Item),
         "live exec disconnect fixture marks session dirty");
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Sessions.Test_Support.Last_Failure_For_Test (Session_Item),
         CryptoLib.Errors.Connection_Failed,
         "live exec disconnect fixture",
         "disconnect during exec records connection failure");
      Check
        (SSH_Lib.Sessions.Test_Support.Active_Channel_Count_For_Test
           (Session_Item)
         = 0,
         "live exec disconnect fixture releases transient channel slot");
   end Assert_Open_Exec_Disconnects_Map_To_Connection_Failed;

   procedure Assert_Data_After_EOF_Is_Rejected is
      Channel_Item  : SSH_Lib.Channels.Channel;
      Status_Value  : CryptoLib.Errors.Status;
      Eof_Payload   : Packet_Buffer;
      Data_Payload  : Packet_Buffer;
      Payload_Bytes : constant Ada.Streams.Stream_Element_Array (1 .. 4) :=
        [16#30#, 16#30#, 16#30#, 16#30#];
   begin
      SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
        (Channel_Item,
         Local_Channel_Id           => 0,
         Remote_Channel_Id          => 900,
         Remote_Remaining_Window    => 4096,
         Remote_Maximum_Packet_Size => 8192);

      Eof_Payload := SSH_Lib.Protocol.Channels.Encode_Channel_EOF (0);
      Status_Value :=
        SSH_Lib.Channels.Test_Support.Dispatch_Inbound_Payload_For_Test
          (Channel_Item, To_Array (Eof_Payload));
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Ok,
         "live channel eof fixture",
         "dispatch inbound EOF");

      Status_Value :=
        Set
          (Data_Payload,
           To_Array
             (SSH_Lib.Protocol.Channels.Encode_Channel_Data
                (0, Payload_Bytes)));
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Ok,
         "live channel eof fixture",
         "build data after EOF");

      Status_Value :=
        SSH_Lib.Channels.Test_Support.Dispatch_Inbound_Payload_For_Test
          (Channel_Item, To_Array (Data_Payload));
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Read_Failed,
         "live channel eof fixture",
         "data after EOF is rejected");
      Check
        (SSH_Lib.Channels.Test_Support.Is_Dirty_For_Test (Channel_Item),
         "live channel eof fixture marks data-after-eof dirty");
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Channels.Test_Support.Last_Failure_For_Test (Channel_Item),
         CryptoLib.Errors.Read_Failed,
         "live channel eof fixture",
         "data-after-eof records read failure");
   end Assert_Data_After_EOF_Is_Rejected;

   procedure Assert_Request_After_Close_Is_Rejected is
      Channel_Item    : SSH_Lib.Channels.Channel;
      Status_Value    : CryptoLib.Errors.Status;
      Close_Payload   : Packet_Buffer;
      Request_Payload : Packet_Buffer;
   begin
      SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
        (Channel_Item,
         Local_Channel_Id           => 0,
         Remote_Channel_Id          => 901,
         Remote_Remaining_Window    => 4096,
         Remote_Maximum_Packet_Size => 8192);

      Close_Payload := SSH_Lib.Protocol.Channels.Encode_Channel_Close (0);
      Status_Value :=
        SSH_Lib.Channels.Test_Support.Dispatch_Inbound_Payload_For_Test
          (Channel_Item, To_Array (Close_Payload));
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Ok,
         "live channel close fixture",
         "dispatch inbound close");

      Request_Payload :=
        SSH_Lib.Protocol.Channels.Encode_Exit_Status_Request
          (Recipient_Channel => 0, Want_Reply => False, Exit_Status => 0);
      Status_Value :=
        SSH_Lib.Channels.Test_Support.Dispatch_Inbound_Payload_For_Test
          (Channel_Item, To_Array (Request_Payload));
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Read_Failed,
         "live channel close fixture",
         "request after close is rejected");
      Check
        (SSH_Lib.Channels.Test_Support.Is_Dirty_For_Test (Channel_Item),
         "live channel close fixture marks request-after-close dirty");
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Channels.Test_Support.Last_Failure_For_Test (Channel_Item),
         CryptoLib.Errors.Read_Failed,
         "live channel close fixture",
         "request-after-close records read failure");
   end Assert_Request_After_Close_Is_Rejected;

   procedure Assert_Duplicate_EOF_And_Close_Are_Rejected is
      Channel_Item  : SSH_Lib.Channels.Channel;
      Status_Value  : CryptoLib.Errors.Status;
      Eof_Payload   : Packet_Buffer;
      Close_Payload : Packet_Buffer;
   begin
      SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
        (Channel_Item,
         Local_Channel_Id           => 0,
         Remote_Channel_Id          => 902,
         Remote_Remaining_Window    => 4096,
         Remote_Maximum_Packet_Size => 8192);

      Eof_Payload := SSH_Lib.Protocol.Channels.Encode_Channel_EOF (0);
      Status_Value :=
        SSH_Lib.Channels.Test_Support.Dispatch_Inbound_Payload_For_Test
          (Channel_Item, To_Array (Eof_Payload));
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Ok,
         "live channel duplicate terminal fixture",
         "first EOF is accepted");

      Status_Value :=
        SSH_Lib.Channels.Test_Support.Dispatch_Inbound_Payload_For_Test
          (Channel_Item, To_Array (Eof_Payload));
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Read_Failed,
         "live channel duplicate terminal fixture",
         "duplicate EOF is rejected");
      Check
        (SSH_Lib.Channels.Test_Support.Is_Dirty_For_Test (Channel_Item),
         "live channel duplicate terminal fixture marks duplicate EOF dirty");
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Channels.Test_Support.Last_Failure_For_Test (Channel_Item),
         CryptoLib.Errors.Read_Failed,
         "live channel duplicate terminal fixture",
         "duplicate EOF records read failure");

      SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
        (Channel_Item,
         Local_Channel_Id           => 0,
         Remote_Channel_Id          => 903,
         Remote_Remaining_Window    => 4096,
         Remote_Maximum_Packet_Size => 8192);

      Close_Payload := SSH_Lib.Protocol.Channels.Encode_Channel_Close (0);
      Status_Value :=
        SSH_Lib.Channels.Test_Support.Dispatch_Inbound_Payload_For_Test
          (Channel_Item, To_Array (Close_Payload));
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Ok,
         "live channel duplicate terminal fixture",
         "first close is accepted");

      Status_Value :=
        SSH_Lib.Channels.Test_Support.Dispatch_Inbound_Payload_For_Test
          (Channel_Item, To_Array (Close_Payload));
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Read_Failed,
         "live channel duplicate terminal fixture",
         "duplicate close is rejected");
      Check
        (SSH_Lib.Channels.Test_Support.Is_Dirty_For_Test (Channel_Item),
         "live channel duplicate terminal fixture marks duplicate close dirty");
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Channels.Test_Support.Last_Failure_For_Test (Channel_Item),
         CryptoLib.Errors.Read_Failed,
         "live channel duplicate terminal fixture",
         "duplicate close records read failure");
   end Assert_Duplicate_EOF_And_Close_Are_Rejected;

   function Build_Exit_Signal_Request
     (Recipient_Channel : Interfaces.Unsigned_32; Want_Reply : Boolean)
      return Packet_Buffer
   is
      Work_Item    : Packet_Buffer;
      Status_Value : CryptoLib.Errors.Status;
   begin
      Status_Value :=
        Append_Byte
          (Work_Item, SSH_Lib.Protocol.Channels.SSH_MSG_CHANNEL_REQUEST);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Ok,
         "live channel exit-signal fixture",
         "request type");
      Status_Value :=
        Append
          (Work_Item,
           SSH_Lib.Protocol.Numbers.Encode_Uint32 (Recipient_Channel));
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Ok,
         "live channel exit-signal fixture",
         "recipient");
      Status_Value := Append_String (Work_Item, "exit-signal");
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Ok,
         "live channel exit-signal fixture",
         "request name");
      Status_Value :=
        Append_Byte
          (Work_Item, SSH_Lib.Protocol.Numbers.Encode_Boolean (Want_Reply));
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Ok,
         "live channel exit-signal fixture",
         "want reply");
      Status_Value := Append_String (Work_Item, "TERM");
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Ok,
         "live channel exit-signal fixture",
         "signal name");
      Status_Value :=
        Append_Byte
          (Work_Item, SSH_Lib.Protocol.Numbers.Encode_Boolean (False));
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Ok,
         "live channel exit-signal fixture",
         "core dumped");
      Status_Value := Append_String (Work_Item, "terminated");
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Ok,
         "live channel exit-signal fixture",
         "error message");
      Status_Value := Append_String (Work_Item, "en");
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Ok,
         "live channel exit-signal fixture",
         "language tag");
      return Work_Item;
   end Build_Exit_Signal_Request;

   procedure Assert_Duplicate_Exit_Status_Is_Rejected is
      Channel_Item          : SSH_Lib.Channels.Channel;
      Status_Value          : CryptoLib.Errors.Status;
      First_Status_Payload  : Packet_Buffer;
      Second_Status_Payload : Packet_Buffer;
      Exit_Code             : Integer;
   begin
      SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
        (Channel_Item,
         Local_Channel_Id           => 0,
         Remote_Channel_Id          => 902,
         Remote_Remaining_Window    => 4096,
         Remote_Maximum_Packet_Size => 8192);

      First_Status_Payload :=
        SSH_Lib.Protocol.Channels.Encode_Exit_Status_Request
          (Recipient_Channel => 0, Want_Reply => False, Exit_Status => 0);
      Status_Value :=
        SSH_Lib.Channels.Test_Support.Dispatch_Inbound_Payload_For_Test
          (Channel_Item, To_Array (First_Status_Payload));
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Ok,
         "live channel duplicate exit-status fixture",
         "first exit-status is accepted");

      Status_Value := SSH_Lib.Channels.Exit_Status (Channel_Item, Exit_Code);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Ok,
         "live channel duplicate exit-status fixture",
         "first exit-status remains observable");
      Check
        (Exit_Code = 0,
         "live channel duplicate exit-status fixture records initial zero status");

      Second_Status_Payload :=
        SSH_Lib.Protocol.Channels.Encode_Exit_Status_Request
          (Recipient_Channel => 0, Want_Reply => False, Exit_Status => 1);
      Status_Value :=
        SSH_Lib.Channels.Test_Support.Dispatch_Inbound_Payload_For_Test
          (Channel_Item, To_Array (Second_Status_Payload));
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Read_Failed,
         "live channel duplicate exit-status fixture",
         "second exit-status is rejected");
      Check
        (SSH_Lib.Channels.Test_Support.Is_Dirty_For_Test (Channel_Item),
         "live channel duplicate exit-status fixture marks duplicate status dirty");
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Channels.Test_Support.Last_Failure_For_Test (Channel_Item),
         CryptoLib.Errors.Read_Failed,
         "live channel duplicate exit-status fixture",
         "duplicate exit-status records read failure");
   end Assert_Duplicate_Exit_Status_Is_Rejected;

   procedure Assert_Data_After_Terminal_Status_Is_Rejected is
      Channel_Item     : SSH_Lib.Channels.Channel;
      Status_Value     : CryptoLib.Errors.Status;
      Status_Payload   : Packet_Buffer;
      Data_Payload     : Packet_Buffer;
      Extended_Payload : Packet_Buffer;
      Payload_Bytes    : constant Ada.Streams.Stream_Element_Array (1 .. 4) :=
        [16#30#, 16#30#, 16#30#, 16#31#];
   begin
      SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
        (Channel_Item,
         Local_Channel_Id           => 0,
         Remote_Channel_Id          => 906,
         Remote_Remaining_Window    => 4096,
         Remote_Maximum_Packet_Size => 8192);

      Status_Payload :=
        SSH_Lib.Protocol.Channels.Encode_Exit_Status_Request
          (Recipient_Channel => 0, Want_Reply => False, Exit_Status => 0);
      Status_Value :=
        SSH_Lib.Channels.Test_Support.Dispatch_Inbound_Payload_For_Test
          (Channel_Item, To_Array (Status_Payload));
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Ok,
         "live channel data-after-status fixture",
         "terminal status is accepted");

      Data_Payload :=
        SSH_Lib.Protocol.Channels.Encode_Channel_Data (0, Payload_Bytes);
      Status_Value :=
        SSH_Lib.Channels.Test_Support.Dispatch_Inbound_Payload_For_Test
          (Channel_Item, To_Array (Data_Payload));
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Read_Failed,
         "live channel data-after-status fixture",
         "stdout after terminal status is rejected");
      Check
        (SSH_Lib.Channels.Test_Support.Is_Dirty_For_Test (Channel_Item),
         "live channel data-after-status fixture marks stdout-after-status dirty");
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Channels.Test_Support.Last_Failure_For_Test (Channel_Item),
         CryptoLib.Errors.Read_Failed,
         "live channel data-after-status fixture",
         "stdout-after-status records read failure");

      SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
        (Channel_Item,
         Local_Channel_Id           => 0,
         Remote_Channel_Id          => 907,
         Remote_Remaining_Window    => 4096,
         Remote_Maximum_Packet_Size => 8192);
      Status_Payload :=
        SSH_Lib.Protocol.Channels.Encode_Exit_Status_Request
          (Recipient_Channel => 0, Want_Reply => False, Exit_Status => 0);
      Status_Value :=
        SSH_Lib.Channels.Test_Support.Dispatch_Inbound_Payload_For_Test
          (Channel_Item, To_Array (Status_Payload));
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Ok,
         "live channel extended-after-status fixture",
         "terminal status is accepted");

      Extended_Payload :=
        SSH_Lib.Protocol.Channels.Encode_Channel_Extended_Data
          (0, SSH_Lib.Protocol.Channels.Extended_Data_Stderr, Payload_Bytes);
      Status_Value :=
        SSH_Lib.Channels.Test_Support.Dispatch_Inbound_Payload_For_Test
          (Channel_Item, To_Array (Extended_Payload));
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Read_Failed,
         "live channel extended-after-status fixture",
         "stderr after terminal status is rejected");
      Check
        (SSH_Lib.Channels.Test_Support.Is_Dirty_For_Test (Channel_Item),
         "live channel extended-after-status fixture marks stderr-after-status dirty");
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Channels.Test_Support.Last_Failure_For_Test (Channel_Item),
         CryptoLib.Errors.Read_Failed,
         "live channel extended-after-status fixture",
         "stderr-after-status records read failure");
   end Assert_Data_After_Terminal_Status_Is_Rejected;

   procedure Assert_Request_After_Terminal_Status_Is_Rejected is
      Channel_Item    : SSH_Lib.Channels.Channel;
      Status_Value    : CryptoLib.Errors.Status;
      Status_Payload  : Packet_Buffer;
      Request_Payload : Packet_Buffer;
   begin
      SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
        (Channel_Item,
         Local_Channel_Id           => 0,
         Remote_Channel_Id          => 918,
         Remote_Remaining_Window    => 4096,
         Remote_Maximum_Packet_Size => 8192);

      Status_Payload :=
        SSH_Lib.Protocol.Channels.Encode_Exit_Status_Request
          (Recipient_Channel => 0, Want_Reply => False, Exit_Status => 0);
      Status_Value :=
        SSH_Lib.Channels.Test_Support.Dispatch_Inbound_Payload_For_Test
          (Channel_Item, To_Array (Status_Payload));
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Ok,
         "live channel request-after-status fixture",
         "terminal status is accepted");

      Request_Payload :=
        Build_Unknown_Channel_Request
          (Recipient_Channel => 0,
           Request_Name      => "keepalive@openssh.com",
           Want_Reply        => True);
      Status_Value :=
        SSH_Lib.Channels.Test_Support.Dispatch_Inbound_Payload_For_Test
          (Channel_Item, To_Array (Request_Payload));
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Read_Failed,
         "live channel request-after-status fixture",
         "request after terminal status is rejected");
      Check
        (SSH_Lib.Channels.Test_Support.Is_Dirty_For_Test (Channel_Item),
         "live channel request-after-status fixture marks request-after-status dirty");
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Channels.Test_Support.Last_Failure_For_Test (Channel_Item),
         CryptoLib.Errors.Read_Failed,
         "live channel request-after-status fixture",
         "request-after-status records read failure");

   end Assert_Request_After_Terminal_Status_Is_Rejected;

   procedure Assert_Window_Adjust_After_Terminal_Status_Is_Ignored is
      Channel_Item   : SSH_Lib.Channels.Channel;
      Status_Value   : CryptoLib.Errors.Status;
      Status_Payload : Packet_Buffer;
      Window_Payload : Packet_Buffer;
      Exit_Code      : Integer;
   begin
      SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
        (Channel_Item,
         Local_Channel_Id           => 0,
         Remote_Channel_Id          => 908,
         Remote_Remaining_Window    => 0,
         Remote_Maximum_Packet_Size => 8192);

      Status_Payload :=
        SSH_Lib.Protocol.Channels.Encode_Exit_Status_Request
          (Recipient_Channel => 0, Want_Reply => False, Exit_Status => 0);
      Status_Value :=
        SSH_Lib.Channels.Test_Support.Dispatch_Inbound_Payload_For_Test
          (Channel_Item, To_Array (Status_Payload));
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Ok,
         "live channel window-after-status fixture",
         "terminal status is accepted");

      Status_Value := SSH_Lib.Channels.Exit_Status (Channel_Item, Exit_Code);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Ok,
         "live channel window-after-status fixture",
         "initial exit status is observable before violation");
      Check
        (Exit_Code = 0,
         "live channel window-after-status fixture records initial zero status");

      Window_Payload :=
        SSH_Lib.Protocol.Channels.Encode_Channel_Window_Adjust (0, 1024);
      Status_Value :=
        SSH_Lib.Channels.Test_Support.Dispatch_Inbound_Payload_For_Test
          (Channel_Item, To_Array (Window_Payload));
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Ok,
         "live channel window-after-status fixture",
         "window-adjust after terminal status is ignored");
      Check
        (not SSH_Lib.Channels.Test_Support.Is_Dirty_For_Test (Channel_Item),
         "live channel window-after-status fixture keeps channel clean");
      Check
        (SSH_Lib.Channels.Test_Support.Remote_Remaining_Window_For_Test
           (Channel_Item)
         = 0,
         "live channel window-after-status fixture preserves remote window credit");
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Channels.Test_Support.Last_Failure_For_Test (Channel_Item),
         CryptoLib.Errors.Ok,
         "live channel window-after-status fixture",
         "window-after-status leaves terminal result intact");
   end Assert_Window_Adjust_After_Terminal_Status_Is_Ignored;

   procedure Assert_Window_Adjust_After_Close_And_Status_Is_Rejected is
      Channel_Item          : SSH_Lib.Channels.Channel;
      Status_Value          : CryptoLib.Errors.Status;
      Window_Payload        : Packet_Buffer;
      Initial_Remote_Window : constant Interfaces.Unsigned_32 := 256;
   begin
      SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
        (Channel_Item,
         Local_Channel_Id           => 0,
         Remote_Channel_Id          => 913,
         Remote_Remaining_Window    => Initial_Remote_Window,
         Remote_Maximum_Packet_Size => 8192);
      SSH_Lib.Channels.Test_Support.Mark_Exit_Status_Known_For_Test
        (Channel_Item, 0);
      SSH_Lib.Channels.Test_Support.Mark_Local_Close_Sent_For_Test
        (Channel_Item);

      Window_Payload :=
        SSH_Lib.Protocol.Channels.Encode_Channel_Window_Adjust (0, 1024);
      Status_Value :=
        SSH_Lib.Channels.Test_Support.Dispatch_Inbound_Payload_For_Test
          (Channel_Item, To_Array (Window_Payload));
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Write_Failed,
         "live channel close-status window fixture",
         "window-adjust after close and terminal status is rejected");
      Check
        (SSH_Lib.Channels.Test_Support.Is_Dirty_For_Test (Channel_Item),
         "live channel close-status window fixture marks late window-adjust dirty");
      Check
        (SSH_Lib.Channels.Test_Support.Remote_Remaining_Window_For_Test
           (Channel_Item)
         = Initial_Remote_Window,
         "live channel close-status window fixture preserves remote window credit");
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Channels.Test_Support.Last_Failure_For_Test (Channel_Item),
         CryptoLib.Errors.Write_Failed,
         "live channel close-status window fixture",
         "late window-adjust after close records write failure");
   end Assert_Window_Adjust_After_Close_And_Status_Is_Rejected;

   procedure Assert_Exit_Signal_Is_Nonzero_Result is
      Channel_Item   : SSH_Lib.Channels.Channel;
      Status_Value   : CryptoLib.Errors.Status;
      Signal_Payload : Packet_Buffer;
      Exit_Code      : Integer;
   begin
      SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
        (Channel_Item,
         Local_Channel_Id           => 0,
         Remote_Channel_Id          => 903,
         Remote_Remaining_Window    => 4096,
         Remote_Maximum_Packet_Size => 8192);

      Signal_Payload :=
        Build_Exit_Signal_Request
          (Recipient_Channel => 0, Want_Reply => False);
      Status_Value :=
        SSH_Lib.Channels.Test_Support.Dispatch_Inbound_Payload_For_Test
          (Channel_Item, To_Array (Signal_Payload));
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Ok,
         "live channel exit-signal fixture",
         "exit-signal is accepted");

      Status_Value := SSH_Lib.Channels.Exit_Status (Channel_Item, Exit_Code);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Remote_Exit_Nonzero,
         "live channel exit-signal fixture",
         "exit-signal maps to nonzero result");
      Check
        (Exit_Code = 255,
         "live channel exit-signal fixture records deterministic nonzero code");
   end Assert_Exit_Signal_Is_Nonzero_Result;

   procedure Assert_Malformed_Exit_Signal_Is_Rejected is
      Channel_Item   : SSH_Lib.Channels.Channel;
      Status_Value   : CryptoLib.Errors.Status;
      Signal_Payload : Packet_Buffer;
   begin
      SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
        (Channel_Item,
         Local_Channel_Id           => 0,
         Remote_Channel_Id          => 904,
         Remote_Remaining_Window    => 4096,
         Remote_Maximum_Packet_Size => 8192);

      --  Deliberately omit the RFC 4254 exit-signal trailing fields after
      --  want-reply.  exit-signal is a known terminal request and must be
      --  validated strictly rather than accepted as an unknown extension.
      Status_Value :=
        Append_Byte
          (Signal_Payload, SSH_Lib.Protocol.Channels.SSH_MSG_CHANNEL_REQUEST);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Ok,
         "live channel malformed exit-signal fixture",
         "request type");
      Status_Value :=
        Append (Signal_Payload, SSH_Lib.Protocol.Numbers.Encode_Uint32 (0));
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Ok,
         "live channel malformed exit-signal fixture",
         "recipient");
      Status_Value := Append_String (Signal_Payload, "exit-signal");
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Ok,
         "live channel malformed exit-signal fixture",
         "request name");
      Status_Value :=
        Append_Byte
          (Signal_Payload, SSH_Lib.Protocol.Numbers.Encode_Boolean (False));
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Ok,
         "live channel malformed exit-signal fixture",
         "want reply");

      Status_Value :=
        SSH_Lib.Channels.Test_Support.Dispatch_Inbound_Payload_For_Test
          (Channel_Item, To_Array (Signal_Payload));
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Read_Failed,
         "live channel malformed exit-signal fixture",
         "truncated exit-signal is rejected");
      Check
        (SSH_Lib.Channels.Test_Support.Is_Dirty_For_Test (Channel_Item),
         "live channel malformed exit-signal fixture marks channel dirty");
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Channels.Test_Support.Last_Failure_For_Test (Channel_Item),
         CryptoLib.Errors.Read_Failed,
         "live channel malformed exit-signal fixture",
         "malformed exit-signal records read failure");
   end Assert_Malformed_Exit_Signal_Is_Rejected;

   procedure Assert_Channel_IO_After_Session_Close_Is_Rejected is
      Session_Item  : SSH_Lib.Sessions.Session;
      Channel_Item  : SSH_Lib.Channels.Channel;
      Status_Value  : CryptoLib.Errors.Status;
      Exit_Code     : Integer := 0;
      Request_Bytes : constant Ada.Streams.Stream_Element_Array (1 .. 4) :=
        [16#00#, 16#05#, 16#41#, 16#42#];
      Queued_Bytes  : constant Ada.Streams.Stream_Element_Array :=
        Bytes_From_String ("queued-before-session-close");
      Read_Buffer   : Ada.Streams.Stream_Element_Array (1 .. 64);
      Last          : Ada.Streams.Stream_Element_Offset;
   begin
      SSH_Lib.Sessions.Test_Support.Mark_Authenticated_Open_For_Test
        (Session_Item);
      SSH_Lib.Sessions.Test_Support.Enable_Live_Channel_IO_For_Test
        (Session_Item);

      Status_Value :=
        SSH_Lib.Sessions.Test_Support.Queue_Channel_Open_Response_For_Test
          (Session_Item, Build_Open_Confirmation (0, 905, 4096, 8192));
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Ok,
         "live channel stale-session fixture",
         "queue open response");
      Status_Value :=
        SSH_Lib.Sessions.Test_Support.Queue_Exec_Response_For_Test
          (Session_Item, Build_Exec_Success (0));
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Ok,
         "live channel stale-session fixture",
         "queue exec response");

      Status_Value :=
        SSH_Lib.Channels.Open_Exec
          (Session_Item, "git-upload-pack 'repo.git'", Channel_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Ok,
         "live channel stale-session fixture",
         "open exec");
      Check
        (SSH_Lib.Sessions.Test_Support.Active_Channel_Count_For_Test
           (Session_Item)
         = 1,
         "live channel stale-session fixture active before session close");

      Status_Value := SSH_Lib.Channels.Send_EOF (Channel_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Ok,
         "live channel stale-session fixture",
         "initial eof before session close succeeds");

      Status_Value :=
        SSH_Lib.Channels.Test_Support.Queue_Stdout_For_Test
          (Channel_Item, Queued_Bytes);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Ok,
         "live channel stale-session fixture",
         "queue authenticated stdout before session close");

      Status_Value := SSH_Lib.Sessions.Close (Session_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Ok,
         "live channel stale-session fixture",
         "close owning session");
      Check
        (SSH_Lib.Sessions.Test_Support.Active_Channel_Count_For_Test
           (Session_Item)
         = 0,
         "live channel stale-session fixture session table reset");

      Status_Value :=
        SSH_Lib.Channels.Read_Some (Channel_Item, Read_Buffer, Last);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Ok,
         "live channel stale-session fixture",
         "queued stdout after session close remains deliverable");
      Check
        (Natural (Last - Read_Buffer'First + 1) = Queued_Bytes'Length,
         "live channel stale-session fixture drains queued stdout length after session close");
      Check
        (Read_Buffer (Read_Buffer'First .. Last) = Queued_Bytes,
         "live channel stale-session fixture drains queued stdout bytes after session close");

      Status_Value := SSH_Lib.Channels.Exit_Status (Channel_Item, Exit_Code);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Connection_Failed,
         "live channel stale-session fixture",
         "exit status after session close without recorded result is connection failure");
      Check
        (Exit_Code = -1,
         "live channel stale-session fixture clears stale exit status code");

      Status_Value := SSH_Lib.Channels.Send_EOF (Channel_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Ok,
         "live channel stale-session fixture",
         "repeated eof after session close remains idempotent");

      Status_Value := SSH_Lib.Channels.Write (Channel_Item, Request_Bytes);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Connection_Failed,
         "live channel stale-session fixture",
         "write after session close is rejected");
      Check
        (SSH_Lib.Channels.Test_Support.Is_Dirty_For_Test (Channel_Item),
         "live channel stale-session fixture marks stale handle dirty");
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Channels.Test_Support.Last_Failure_For_Test (Channel_Item),
         CryptoLib.Errors.Connection_Failed,
         "live channel stale-session fixture",
         "stale handle records connection failure");
   end Assert_Channel_IO_After_Session_Close_Is_Rejected;

   procedure Assert_Inbound_After_Local_Close_Is_Rejected is
      Channel_Item    : SSH_Lib.Channels.Channel;
      Status_Value    : CryptoLib.Errors.Status;
      Data_Payload    : Packet_Buffer;
      Window_Payload  : Packet_Buffer;
      Eof_Payload     : Packet_Buffer;
      Request_Payload : Packet_Buffer;
      Payload_Bytes   : constant Ada.Streams.Stream_Element_Array (1 .. 4) :=
        [16#50#, 16#4B#, 16#54#, 16#0A#];
   begin
      SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
        (Channel_Item,
         Local_Channel_Id           => 0,
         Remote_Channel_Id          => 906,
         Remote_Remaining_Window    => 4096,
         Remote_Maximum_Packet_Size => 8192);
      SSH_Lib.Channels.Test_Support.Mark_Local_Close_Sent_For_Test
        (Channel_Item);

      Status_Value :=
        Set
          (Data_Payload,
           To_Array
             (SSH_Lib.Protocol.Channels.Encode_Channel_Data
                (0, Payload_Bytes)));
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Ok,
         "live channel local-close fixture",
         "build data after local close");
      Status_Value :=
        SSH_Lib.Channels.Test_Support.Dispatch_Inbound_Payload_For_Test
          (Channel_Item, To_Array (Data_Payload));
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Read_Failed,
         "live channel local-close fixture",
         "data after local close is rejected");
      Check
        (SSH_Lib.Channels.Test_Support.Is_Dirty_For_Test (Channel_Item),
         "live channel local-close fixture marks data-after-local-close dirty");

      SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
        (Channel_Item,
         Local_Channel_Id           => 0,
         Remote_Channel_Id          => 907,
         Remote_Remaining_Window    => 4096,
         Remote_Maximum_Packet_Size => 8192);
      SSH_Lib.Channels.Test_Support.Mark_Local_Close_Sent_For_Test
        (Channel_Item);

      Window_Payload :=
        SSH_Lib.Protocol.Channels.Encode_Channel_Window_Adjust (0, 1024);
      Status_Value :=
        SSH_Lib.Channels.Test_Support.Dispatch_Inbound_Payload_For_Test
          (Channel_Item, To_Array (Window_Payload));
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Write_Failed,
         "live channel local-close fixture",
         "window-adjust after local close is rejected");
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Channels.Test_Support.Last_Failure_For_Test (Channel_Item),
         CryptoLib.Errors.Write_Failed,
         "live channel local-close fixture",
         "window-adjust after local close records write failure");

      SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
        (Channel_Item,
         Local_Channel_Id           => 0,
         Remote_Channel_Id          => 908,
         Remote_Remaining_Window    => 4096,
         Remote_Maximum_Packet_Size => 8192);
      SSH_Lib.Channels.Test_Support.Mark_Local_Close_Sent_For_Test
        (Channel_Item);

      Eof_Payload := SSH_Lib.Protocol.Channels.Encode_Channel_EOF (0);
      Status_Value :=
        SSH_Lib.Channels.Test_Support.Dispatch_Inbound_Payload_For_Test
          (Channel_Item, To_Array (Eof_Payload));
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Read_Failed,
         "live channel local-close fixture",
         "EOF after local close is rejected");

      SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
        (Channel_Item,
         Local_Channel_Id           => 0,
         Remote_Channel_Id          => 909,
         Remote_Remaining_Window    => 4096,
         Remote_Maximum_Packet_Size => 8192);
      SSH_Lib.Channels.Test_Support.Mark_Local_Close_Sent_For_Test
        (Channel_Item);

      Request_Payload :=
        SSH_Lib.Protocol.Channels.Encode_Exit_Status_Request
          (Recipient_Channel => 0, Want_Reply => False, Exit_Status => 0);
      Status_Value :=
        SSH_Lib.Channels.Test_Support.Dispatch_Inbound_Payload_For_Test
          (Channel_Item, To_Array (Request_Payload));
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Read_Failed,
         "live channel local-close fixture",
         "exit-status after local close is rejected");
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Channels.Test_Support.Last_Failure_For_Test (Channel_Item),
         CryptoLib.Errors.Read_Failed,
         "live channel local-close fixture",
         "request after local close records read failure");
   end Assert_Inbound_After_Local_Close_Is_Rejected;

   procedure Assert_Window_Adjust_After_Local_EOF_Is_Ignored is
      Channel_Item          : SSH_Lib.Channels.Channel;
      Status_Value          : CryptoLib.Errors.Status;
      Window_Payload        : Packet_Buffer;
      Initial_Remote_Window : constant Interfaces.Unsigned_32 := 512;
      Request_Bytes         :
        constant Ada.Streams.Stream_Element_Array (1 .. 3) :=
          [16#67#, 16#69#, 16#74#];
   begin
      SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
        (Channel_Item,
         Local_Channel_Id           => 0,
         Remote_Channel_Id          => 911,
         Remote_Remaining_Window    => Initial_Remote_Window,
         Remote_Maximum_Packet_Size => 8192);
      SSH_Lib.Channels.Test_Support.Mark_Local_EOF_Sent_For_Test
        (Channel_Item);

      Window_Payload :=
        SSH_Lib.Protocol.Channels.Encode_Channel_Window_Adjust (0, 1024);
      Status_Value :=
        SSH_Lib.Channels.Test_Support.Dispatch_Inbound_Payload_For_Test
          (Channel_Item, To_Array (Window_Payload));
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Ok,
         "live channel local-EOF fixture",
         "window-adjust after local EOF is ignored");
      Check
        (not SSH_Lib.Channels.Test_Support.Is_Dirty_For_Test (Channel_Item),
         "live channel local-EOF fixture keeps channel clean");
      Check
        (SSH_Lib.Channels.Test_Support.Remote_Remaining_Window_For_Test
           (Channel_Item)
         = Initial_Remote_Window,
         "live channel local-EOF fixture preserves remote window credit");

      Status_Value := SSH_Lib.Channels.Write (Channel_Item, Request_Bytes);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Write_Failed,
         "live channel local-EOF fixture",
         "write after local EOF remains rejected");
   end Assert_Window_Adjust_After_Local_EOF_Is_Ignored;

   procedure Assert_Multiple_Stderr_Packets_Are_Accumulated is
      Channel_Item   : SSH_Lib.Channels.Channel;
      Status_Value   : CryptoLib.Errors.Status;
      First_Payload  : Packet_Buffer;
      Second_Payload : Packet_Buffer;
      First_Bytes    : constant Ada.Streams.Stream_Element_Array :=
        Bytes_From_String ("fatal: ");
      Second_Bytes   : constant Ada.Streams.Stream_Element_Array :=
        Bytes_From_String ("denied");
   begin
      SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
        (Channel_Item,
         Local_Channel_Id           => 0,
         Remote_Channel_Id          => 910,
         Remote_Remaining_Window    => 4096,
         Remote_Maximum_Packet_Size => 8192);

      Status_Value :=
        Set
          (First_Payload,
           To_Array
             (SSH_Lib.Protocol.Channels.Encode_Channel_Extended_Data
                (0,
                 SSH_Lib.Protocol.Channels.Extended_Data_Stderr,
                 First_Bytes)));
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Ok,
         "live channel stderr accumulation fixture",
         "build first stderr packet");
      Status_Value :=
        SSH_Lib.Channels.Test_Support.Dispatch_Inbound_Payload_For_Test
          (Channel_Item, To_Array (First_Payload));
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Ok,
         "live channel stderr accumulation fixture",
         "first stderr packet accepted");
      Check
        (SSH_Lib.Channels.Test_Support.Pending_Stderr_Length_For_Test
           (Channel_Item)
         = First_Bytes'Length,
         "live channel stderr accumulation fixture records first stderr length");

      Status_Value :=
        Set
          (Second_Payload,
           To_Array
             (SSH_Lib.Protocol.Channels.Encode_Channel_Extended_Data
                (0,
                 SSH_Lib.Protocol.Channels.Extended_Data_Stderr,
                 Second_Bytes)));
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Ok,
         "live channel stderr accumulation fixture",
         "build second stderr packet");
      Status_Value :=
        SSH_Lib.Channels.Test_Support.Dispatch_Inbound_Payload_For_Test
          (Channel_Item, To_Array (Second_Payload));
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Ok,
         "live channel stderr accumulation fixture",
         "second stderr packet accepted");
      Check
        (SSH_Lib.Channels.Test_Support.Pending_Stderr_Length_For_Test
           (Channel_Item)
         = First_Bytes'Length + Second_Bytes'Length,
         "live channel stderr accumulation fixture appends stderr packets");
   end Assert_Multiple_Stderr_Packets_Are_Accumulated;

   procedure Assert_Inbound_Exec_Stream_Before_Exec_Success_Is_Rejected is
      Channel_Item   : SSH_Lib.Channels.Channel;
      Status_Value   : CryptoLib.Errors.Status;
      Data_Payload   : Packet_Buffer;
      Stderr_Payload : Packet_Buffer;
      EOF_Payload    : Packet_Buffer;
      Status_Payload : Packet_Buffer;
      Bytes          : constant Ada.Streams.Stream_Element_Array :=
        Bytes_From_String ("pkt");
   begin
      SSH_Lib.Channels.Test_Support.Mark_Channel_Open_Not_Exec_For_Test
        (Channel_Item,
         Local_Channel_Id           => 0,
         Remote_Channel_Id          => 910,
         Remote_Remaining_Window    => 4096,
         Remote_Maximum_Packet_Size => 8192);

      Status_Value :=
        Set
          (Data_Payload,
           To_Array
             (SSH_Lib.Protocol.Channels.Encode_Channel_Data (0, Bytes)));
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Ok,
         "live channel pre-exec fixture",
         "build stdout packet");
      Status_Value :=
        SSH_Lib.Channels.Test_Support.Dispatch_Inbound_Payload_For_Test
          (Channel_Item, To_Array (Data_Payload));
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Read_Failed,
         "live channel pre-exec fixture",
         "stdout before exec success rejected");

      SSH_Lib.Channels.Test_Support.Mark_Channel_Open_Not_Exec_For_Test
        (Channel_Item,
         Local_Channel_Id           => 0,
         Remote_Channel_Id          => 910,
         Remote_Remaining_Window    => 4096,
         Remote_Maximum_Packet_Size => 8192);
      Status_Value :=
        Set
          (Stderr_Payload,
           To_Array
             (SSH_Lib.Protocol.Channels.Encode_Channel_Extended_Data
                (0, SSH_Lib.Protocol.Channels.Extended_Data_Stderr, Bytes)));
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Ok,
         "live channel pre-exec fixture",
         "build stderr packet");
      Status_Value :=
        SSH_Lib.Channels.Test_Support.Dispatch_Inbound_Payload_For_Test
          (Channel_Item, To_Array (Stderr_Payload));
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Read_Failed,
         "live channel pre-exec fixture",
         "stderr before exec success rejected");

      SSH_Lib.Channels.Test_Support.Mark_Channel_Open_Not_Exec_For_Test
        (Channel_Item,
         Local_Channel_Id           => 0,
         Remote_Channel_Id          => 910,
         Remote_Remaining_Window    => 4096,
         Remote_Maximum_Packet_Size => 8192);
      EOF_Payload := SSH_Lib.Protocol.Channels.Encode_Channel_EOF (0);
      Status_Value :=
        SSH_Lib.Channels.Test_Support.Dispatch_Inbound_Payload_For_Test
          (Channel_Item, To_Array (EOF_Payload));
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Read_Failed,
         "live channel pre-exec fixture",
         "EOF before exec success rejected");

      SSH_Lib.Channels.Test_Support.Mark_Channel_Open_Not_Exec_For_Test
        (Channel_Item,
         Local_Channel_Id           => 0,
         Remote_Channel_Id          => 910,
         Remote_Remaining_Window    => 4096,
         Remote_Maximum_Packet_Size => 8192);
      Status_Payload :=
        SSH_Lib.Protocol.Channels.Encode_Exit_Status_Request
          (Recipient_Channel => 0, Want_Reply => False, Exit_Status => 0);
      Status_Value :=
        SSH_Lib.Channels.Test_Support.Dispatch_Inbound_Payload_For_Test
          (Channel_Item, To_Array (Status_Payload));
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Read_Failed,
         "live channel pre-exec fixture",
         "exit-status before exec success rejected");
      Check
        (SSH_Lib.Channels.Test_Support.Is_Dirty_For_Test (Channel_Item),
         "live channel pre-exec fixture marks channel dirty");
   end Assert_Inbound_Exec_Stream_Before_Exec_Success_Is_Rejected;

   procedure Assert_Dirty_Live_Read_Does_Not_Drain_Protected_Input is
      Channel_Item : SSH_Lib.Channels.Channel;
      Status_Value : CryptoLib.Errors.Status;
      Data_Payload : Packet_Buffer;
      Read_Buffer  : Ada.Streams.Stream_Element_Array (1 .. 8);
      Last_Index   : Ada.Streams.Stream_Element_Offset;
      Bytes        : constant Ada.Streams.Stream_Element_Array :=
        Bytes_From_String ("late");
   begin
      SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
        (Channel_Item,
         Local_Channel_Id           => 0,
         Remote_Channel_Id          => 912,
         Remote_Remaining_Window    => 4096,
         Remote_Maximum_Packet_Size => 8192);
      SSH_Lib.Channels.Test_Support.Enable_Live_Channel_IO_For_Test
        (Channel_Item);

      Status_Value :=
        Set
          (Data_Payload,
           To_Array
             (SSH_Lib.Protocol.Channels.Encode_Channel_Data (0, Bytes)));
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Ok,
         "live channel dirty-read fixture",
         "build protected late stdout packet");
      Status_Value :=
        SSH_Lib.Channels.Test_Support.Queue_Protected_Inbound_For_Test
          (Channel_Item, To_Array (Data_Payload));
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Ok,
         "live channel dirty-read fixture",
         "queue protected late stdout packet");

      SSH_Lib.Channels.Test_Support.Mark_Dirty_For_Test
        (Channel_Item, CryptoLib.Errors.Timeout);

      Status_Value :=
        SSH_Lib.Channels.Read_Some (Channel_Item, Read_Buffer, Last_Index);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Read_Failed,
         "live channel dirty-read fixture",
         "dirty channel refuses live protected drain after queued stdout is empty");
      Check
        (SSH_Lib.Channels.Test_Support.Pending_Stdout_Length_For_Test
           (Channel_Item)
         = 0,
         "live channel dirty-read fixture does not append protected stdout after failure");
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Channels.Test_Support.Last_Failure_For_Test (Channel_Item),
         CryptoLib.Errors.Timeout,
         "live channel dirty-read fixture preserves original terminal failure");
   end Assert_Dirty_Live_Read_Does_Not_Drain_Protected_Input;

   procedure Assert_Background_Stop_Propagates_Terminal_Failure is
      Channel_Item : SSH_Lib.Channels.Channel;
      Status_Value : CryptoLib.Errors.Status;
   begin
      SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
        (Channel_Item,
         Local_Channel_Id           => 0,
         Remote_Channel_Id          => 931,
         Remote_Remaining_Window    => 4096,
         Remote_Maximum_Packet_Size => 8192);

      SSH_Lib.Channels.Test_Support.Set_Background_Last_Status_For_Test
        (Channel_Item, CryptoLib.Errors.Read_Failed);

      Status_Value := SSH_Lib.Channels.Stop_Background_Reader (Channel_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Read_Failed,
         "live channel background-stop fixture",
         "stop propagates terminal background reader failure");
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Channels.Test_Support.Last_Failure_For_Test (Channel_Item),
         CryptoLib.Errors.Read_Failed,
         "live channel background-stop fixture",
         "background stop records terminal failure on channel");
      Check
        (not SSH_Lib.Channels.Background_Reader_Running (Channel_Item),
         "live channel background-stop fixture leaves reader stopped");
   end Assert_Background_Stop_Propagates_Terminal_Failure;

   procedure Assert_Background_Restart_After_Terminal_Failure_Is_Rejected is
      Channel_Item : SSH_Lib.Channels.Channel;
      Status_Value : CryptoLib.Errors.Status;
   begin
      SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
        (Channel_Item,
         Local_Channel_Id           => 0,
         Remote_Channel_Id          => 932,
         Remote_Remaining_Window    => 4096,
         Remote_Maximum_Packet_Size => 8192);

      SSH_Lib.Channels.Test_Support.Set_Background_Last_Status_For_Test
        (Channel_Item, CryptoLib.Errors.Connection_Failed);

      Status_Value := SSH_Lib.Channels.Start_Background_Reader (Channel_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Connection_Failed,
         "live channel background-restart fixture",
         "background restart preserves terminal stored failure");
      Check
        (not SSH_Lib.Channels.Background_Reader_Running (Channel_Item),
         "live channel background-restart fixture does not start task after stored terminal failure");
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Channels.Background_Reader_Status (Channel_Item),
         CryptoLib.Errors.Connection_Failed,
         "live channel background-restart fixture",
         "stored terminal background failure remains visible");
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Channels.Test_Support.Last_Failure_For_Test (Channel_Item),
         CryptoLib.Errors.Connection_Failed,
         "live channel background-restart fixture",
         "rejected restart records terminal failure on channel");
   end Assert_Background_Restart_After_Terminal_Failure_Is_Rejected;

   procedure Assert_Write_After_Background_Terminal_Failure_Is_Rejected is
      Channel_Item : SSH_Lib.Channels.Channel;
      Status_Value : CryptoLib.Errors.Status;
      Request_Byte : constant Ada.Streams.Stream_Element_Array (1 .. 1) :=
        [1 => 16#47#];
   begin
      SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
        (Channel_Item,
         Local_Channel_Id           => 0,
         Remote_Channel_Id          => 933,
         Remote_Remaining_Window    => 4096,
         Remote_Maximum_Packet_Size => 8192);

      SSH_Lib.Channels.Test_Support.Set_Background_Last_Status_For_Test
        (Channel_Item, CryptoLib.Errors.Read_Failed);

      Status_Value := SSH_Lib.Channels.Write (Channel_Item, Request_Byte);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Read_Failed,
         "live channel background-write fixture",
         "write after terminal background failure preserves stored status");
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Channels.Test_Support.Last_Failure_For_Test (Channel_Item),
         CryptoLib.Errors.Read_Failed,
         "live channel background-write fixture",
         "rejected write records stored background failure on channel");
      Check
        (SSH_Lib.Channels.Test_Support.Outbound_Data_Byte_Count_For_Test
           (Channel_Item)
         = 0,
         "live channel background-write fixture emits no Git stdin bytes after terminal failure");
      Check
        (SSH_Lib.Channels.Test_Support.Outbound_Data_Packet_Count_For_Test
           (Channel_Item)
         = 0,
         "live channel background-write fixture emits no channel-data packets after terminal failure");
   end Assert_Write_After_Background_Terminal_Failure_Is_Rejected;

   procedure Assert_Exit_Status_After_Background_Terminal_Failure_Preserves_Status
   is
      Channel_Item : SSH_Lib.Channels.Channel;
      Status_Value : CryptoLib.Errors.Status;
      Exit_Code    : Integer := 123;
   begin
      SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
        (Channel_Item,
         Local_Channel_Id           => 0,
         Remote_Channel_Id          => 934,
         Remote_Remaining_Window    => 4096,
         Remote_Maximum_Packet_Size => 8192);

      SSH_Lib.Channels.Test_Support.Set_Background_Last_Status_For_Test
        (Channel_Item, CryptoLib.Errors.Connection_Failed);

      Status_Value := SSH_Lib.Channels.Exit_Status (Channel_Item, Exit_Code);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Connection_Failed,
         "live channel background-exit-status fixture",
         "exit-status after terminal background failure preserves stored status");
      Check
        (Exit_Code = -1,
         "live channel background-exit-status fixture clears unknown exit code after stored failure");
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Channels.Background_Reader_Status (Channel_Item),
         CryptoLib.Errors.Connection_Failed,
         "live channel background-exit-status fixture",
         "stored background failure remains visible after exit-status query");
   end Assert_Exit_Status_After_Background_Terminal_Failure_Preserves_Status;

   procedure Assert_Close_After_Background_Terminal_Failure_Is_Local_Cleanup is
      Channel_Item : SSH_Lib.Channels.Channel;
      Status_Value : CryptoLib.Errors.Status;
      Exit_Code    : Integer := 99;
   begin
      SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
        (Channel_Item,
         Local_Channel_Id           => 0,
         Remote_Channel_Id          => 935,
         Remote_Remaining_Window    => 4096,
         Remote_Maximum_Packet_Size => 8192);
      SSH_Lib.Channels.Test_Support.Enable_Live_Channel_IO_For_Test
        (Channel_Item);

      SSH_Lib.Channels.Test_Support.Set_Background_Last_Status_For_Test
        (Channel_Item, CryptoLib.Errors.Connection_Failed);

      Status_Value := SSH_Lib.Channels.Close (Channel_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Ok,
         "live channel background-close fixture",
         "close after terminal background failure remains local cleanup");
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Channels.Test_Support.Last_Failure_For_Test (Channel_Item),
         CryptoLib.Errors.Connection_Failed,
         "live channel background-close fixture",
         "close preserves stored terminal background failure");
      Check
        (SSH_Lib.Channels.Test_Support.Last_Close_Payload_For_Test
           (Channel_Item)'Length
         = 0,
         "live channel background-close fixture emits no channel close after terminal background failure");
      Check
        (SSH_Lib.Channels.Test_Support.Last_Protected_Outbound_For_Test
           (Channel_Item)'Length
         = 0,
         "live channel background-close fixture emits no protected packet after terminal background failure");
      Check
        (not SSH_Lib.Channels.Background_Reader_Running (Channel_Item),
         "live channel background-close fixture leaves reader stopped");
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Channels.Background_Reader_Status (Channel_Item),
         CryptoLib.Errors.Connection_Failed,
         "live channel background-close fixture",
         "closed handle preserves stored background terminal failure");
      Status_Value := SSH_Lib.Channels.Exit_Status (Channel_Item, Exit_Code);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Connection_Failed,
         "live channel background-close fixture",
         "exit-status after cleanup preserves stored background terminal failure");
      Check
        (Exit_Code = -1,
         "live channel background-close fixture clears unknown exit code after preserved background failure");
   end Assert_Close_After_Background_Terminal_Failure_Is_Local_Cleanup;

   procedure Assert_Idempotent_Close_Preserves_Background_Terminal_Failure is
      Channel_Item : SSH_Lib.Channels.Channel;
      Status_Value : CryptoLib.Errors.Status;
      Exit_Code    : Integer := 99;
   begin
      SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
        (Channel_Item,
         Local_Channel_Id           => 0,
         Remote_Channel_Id          => 936,
         Remote_Remaining_Window    => 4096,
         Remote_Maximum_Packet_Size => 8192);
      SSH_Lib.Channels.Test_Support.Enable_Live_Channel_IO_For_Test
        (Channel_Item);

      SSH_Lib.Channels.Test_Support.Set_Background_Last_Status_For_Test
        (Channel_Item, CryptoLib.Errors.Connection_Failed);

      Status_Value := SSH_Lib.Channels.Close (Channel_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Ok,
         "live channel idempotent background-close fixture",
         "first close after terminal background failure remains local cleanup");

      Status_Value := SSH_Lib.Channels.Close (Channel_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Ok,
         "live channel idempotent background-close fixture",
         "idempotent close after terminal background failure remains cleanup");
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Channels.Background_Reader_Status (Channel_Item),
         CryptoLib.Errors.Connection_Failed,
         "live channel idempotent background-close fixture",
         "idempotent close preserves stored background terminal failure");
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Channels.Test_Support.Last_Failure_For_Test (Channel_Item),
         CryptoLib.Errors.Connection_Failed,
         "live channel idempotent background-close fixture",
         "idempotent close preserves last failure diagnostic");
      Check
        (not SSH_Lib.Channels.Test_Support.Live_Channel_IO_Enabled_For_Test
               (Channel_Item),
         "live channel idempotent background-close fixture keeps live io detached");

      Status_Value := SSH_Lib.Channels.Exit_Status (Channel_Item, Exit_Code);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Connection_Failed,
         "live channel idempotent background-close fixture",
         "exit-status after repeated close preserves stored background terminal failure");
      Check
        (Exit_Code = -1,
         "live channel idempotent background-close fixture clears unknown exit code after repeated close");
   end Assert_Idempotent_Close_Preserves_Background_Terminal_Failure;

   procedure Assert_Background_Reader_After_Terminal_Status_Is_Rejected is
      Channel_Item   : SSH_Lib.Channels.Channel;
      Status_Value   : CryptoLib.Errors.Status;
      Status_Payload : Packet_Buffer;
      Exit_Code      : Integer;
   begin
      SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
        (Channel_Item,
         Local_Channel_Id           => 0,
         Remote_Channel_Id          => 930,
         Remote_Remaining_Window    => 4096,
         Remote_Maximum_Packet_Size => 8192);

      Status_Payload :=
        SSH_Lib.Protocol.Channels.Encode_Exit_Status_Request
          (Recipient_Channel => 0, Want_Reply => False, Exit_Status => 0);
      Status_Value :=
        SSH_Lib.Channels.Test_Support.Dispatch_Inbound_Payload_For_Test
          (Channel_Item, To_Array (Status_Payload));
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Ok,
         "live channel background-after-status fixture",
         "terminal status is accepted");

      Status_Value := SSH_Lib.Channels.Exit_Status (Channel_Item, Exit_Code);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Ok,
         "live channel background-after-status fixture",
         "exit status remains observable before rejected background start");
      Check
        (Exit_Code = 0,
         "live channel background-after-status fixture records zero exit");

      Status_Value := SSH_Lib.Channels.Start_Background_Reader (Channel_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Channel_Request_Failed,
         "live channel background-after-status fixture",
         "background reader start after terminal status is rejected");
      Check
        (not SSH_Lib.Channels.Background_Reader_Running (Channel_Item),
         "live channel background-after-status fixture does not start task");
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Channels.Test_Support.Last_Failure_For_Test (Channel_Item),
         CryptoLib.Errors.Channel_Request_Failed,
         "live channel background-after-status fixture",
         "rejected background start records channel-request failure");

      Status_Value := SSH_Lib.Channels.Exit_Status (Channel_Item, Exit_Code);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Ok,
         "live channel background-after-status fixture",
         "exit status remains observable after rejected background start");
      Check
        (Exit_Code = 0,
         "live channel background-after-status fixture preserves exit status");
   end Assert_Background_Reader_After_Terminal_Status_Is_Rejected;

   procedure Assert_Read_After_Background_Terminal_Failure_Does_Not_Drain is
      Channel_Item : SSH_Lib.Channels.Channel;
      Status_Value : CryptoLib.Errors.Status;
      Data_Payload : Packet_Buffer;
      Read_Buffer  : Ada.Streams.Stream_Element_Array (1 .. 8);
      Last_Index   : Ada.Streams.Stream_Element_Offset;
      Bytes        : constant Ada.Streams.Stream_Element_Array :=
        Bytes_From_String ("late");
   begin
      SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
        (Channel_Item,
         Local_Channel_Id           => 0,
         Remote_Channel_Id          => 936,
         Remote_Remaining_Window    => 4096,
         Remote_Maximum_Packet_Size => 8192);
      SSH_Lib.Channels.Test_Support.Enable_Live_Channel_IO_For_Test
        (Channel_Item);

      Status_Value :=
        Set
          (Data_Payload,
           To_Array
             (SSH_Lib.Protocol.Channels.Encode_Channel_Data (0, Bytes)));
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Ok,
         "live channel background-read fixture",
         "build protected late stdout packet");
      Status_Value :=
        SSH_Lib.Channels.Test_Support.Queue_Protected_Inbound_For_Test
          (Channel_Item, To_Array (Data_Payload));
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Ok,
         "live channel background-read fixture",
         "queue protected late stdout packet");

      SSH_Lib.Channels.Test_Support.Set_Background_Last_Status_For_Test
        (Channel_Item, CryptoLib.Errors.Connection_Failed);

      Status_Value :=
        SSH_Lib.Channels.Read_Some (Channel_Item, Read_Buffer, Last_Index);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Connection_Failed,
         "live channel background-read fixture",
         "read after terminal background failure preserves stored status");
      Check
        (SSH_Lib.Channels.Test_Support.Pending_Stdout_Length_For_Test
           (Channel_Item)
         = 0,
         "live channel background-read fixture does not append protected stdout after stored terminal failure");
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Channels.Test_Support.Last_Failure_For_Test (Channel_Item),
         CryptoLib.Errors.Connection_Failed,
         "live channel background-read fixture",
         "read records stored background failure on channel");
   end Assert_Read_After_Background_Terminal_Failure_Does_Not_Drain;

   procedure Assert_Repeated_EOF_After_Background_Terminal_Failure_Preserves_Status
   is
      Channel_Item : SSH_Lib.Channels.Channel;
      Status_Value : CryptoLib.Errors.Status;
   begin
      SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
        (Channel_Item,
         Local_Channel_Id           => 0,
         Remote_Channel_Id          => 944,
         Remote_Remaining_Window    => 4096,
         Remote_Maximum_Packet_Size => 8192);

      Status_Value := SSH_Lib.Channels.Send_EOF (Channel_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Ok,
         "live channel repeated-eof background fixture",
         "initial EOF succeeds before stored background failure");

      SSH_Lib.Channels.Test_Support.Set_Background_Last_Status_For_Test
        (Channel_Item, CryptoLib.Errors.Connection_Failed);

      Status_Value := SSH_Lib.Channels.Send_EOF (Channel_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Connection_Failed,
         "live channel repeated-eof background fixture",
         "repeated EOF preserves stored terminal background failure");
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Channels.Test_Support.Last_Failure_For_Test (Channel_Item),
         CryptoLib.Errors.Connection_Failed,
         "live channel repeated-eof background fixture",
         "repeated EOF records exact background failure diagnostic");
   end Assert_Repeated_EOF_After_Background_Terminal_Failure_Preserves_Status;

   procedure Assert_Background_Terminal_Failure_Precedes_Dirty_State is
      Channel_Item : SSH_Lib.Channels.Channel;
      Status_Value : CryptoLib.Errors.Status;
      Read_Buffer  : Ada.Streams.Stream_Element_Array (1 .. 4);
      Last_Index   : Ada.Streams.Stream_Element_Offset;
      Exit_Code    : Integer;
      Payload      : constant Ada.Streams.Stream_Element_Array :=
        Bytes_From_String ("git");
   begin
      SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
        (Channel_Item,
         Local_Channel_Id           => 0,
         Remote_Channel_Id          => 940,
         Remote_Remaining_Window    => 4096,
         Remote_Maximum_Packet_Size => 8192);
      SSH_Lib.Channels.Test_Support.Set_Background_Last_Status_For_Test
        (Channel_Item, CryptoLib.Errors.Connection_Failed);
      SSH_Lib.Channels.Test_Support.Mark_Dirty_For_Test
        (Channel_Item, CryptoLib.Errors.Read_Failed);

      Status_Value :=
        SSH_Lib.Channels.Read_Some (Channel_Item, Read_Buffer, Last_Index);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Connection_Failed,
         "live channel background-dirty precedence fixture",
         "read preserves background terminal failure before dirty read status");

      SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
        (Channel_Item,
         Local_Channel_Id           => 0,
         Remote_Channel_Id          => 941,
         Remote_Remaining_Window    => 4096,
         Remote_Maximum_Packet_Size => 8192);
      SSH_Lib.Channels.Test_Support.Set_Background_Last_Status_For_Test
        (Channel_Item, CryptoLib.Errors.Connection_Failed);
      SSH_Lib.Channels.Test_Support.Mark_Dirty_For_Test
        (Channel_Item, CryptoLib.Errors.Write_Failed);

      Status_Value := SSH_Lib.Channels.Write (Channel_Item, Payload);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Connection_Failed,
         "live channel background-dirty precedence fixture",
         "write preserves background terminal failure before dirty write status");

      SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
        (Channel_Item,
         Local_Channel_Id           => 0,
         Remote_Channel_Id          => 942,
         Remote_Remaining_Window    => 4096,
         Remote_Maximum_Packet_Size => 8192);
      SSH_Lib.Channels.Test_Support.Set_Background_Last_Status_For_Test
        (Channel_Item, CryptoLib.Errors.Connection_Failed);
      SSH_Lib.Channels.Test_Support.Mark_Dirty_For_Test
        (Channel_Item, CryptoLib.Errors.Channel_Request_Failed);

      Status_Value := SSH_Lib.Channels.Exit_Status (Channel_Item, Exit_Code);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Connection_Failed,
         "live channel background-dirty precedence fixture",
         "exit-status preserves background terminal failure before dirty request status");
      Check
        (Exit_Code = -1,
         "live channel background-dirty precedence fixture clears unknown exit code");
   end Assert_Background_Terminal_Failure_Precedes_Dirty_State;

   procedure Assert_Close_Detaches_Live_Channel_IO is
      Channel_Item : SSH_Lib.Channels.Channel;
      Status_Value : CryptoLib.Errors.Status;
   begin
      SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
        (Channel_Item,
         Local_Channel_Id           => 0,
         Remote_Channel_Id          => 900,
         Remote_Remaining_Window    => 4096,
         Remote_Maximum_Packet_Size => 8192);
      SSH_Lib.Channels.Test_Support.Enable_Live_Channel_IO_For_Test
        (Channel_Item);
      Check
        (SSH_Lib.Channels.Test_Support.Live_Channel_IO_Enabled_For_Test
           (Channel_Item),
         "close detach fixture live io initially enabled");

      Status_Value := SSH_Lib.Channels.Close (Channel_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Ok,
         "live channel fixture",
         "close detaches live io");
      Check
        (not SSH_Lib.Channels.Test_Support.Live_Channel_IO_Enabled_For_Test
               (Channel_Item),
         "close detach fixture live io disabled after close");
   end Assert_Close_Detaches_Live_Channel_IO;

   procedure Assert_Close_Exception_Detaches_Live_Channel_IO is
      Channel_Item : SSH_Lib.Channels.Channel;
      Status_Value : CryptoLib.Errors.Status;
   begin
      SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
        (Channel_Item,
         Local_Channel_Id           => 0,
         Remote_Channel_Id          => 901,
         Remote_Remaining_Window    => 4096,
         Remote_Maximum_Packet_Size => 8192);
      SSH_Lib.Channels.Test_Support.Enable_Live_Channel_IO_For_Test
        (Channel_Item);
      SSH_Lib.Channels.Test_Support.Set_Close_Exception_For_Cleanup_Test
        (Channel_Item, True);

      Check
        (SSH_Lib.Channels.Test_Support.Live_Channel_IO_Enabled_For_Test
           (Channel_Item),
         "close exception detach fixture live io initially enabled");

      Status_Value := SSH_Lib.Channels.Close (Channel_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Ok,
         "live channel fixture",
         "close exception cleanup detaches live io");
      Check
        (not SSH_Lib.Channels.Test_Support.Live_Channel_IO_Enabled_For_Test
               (Channel_Item),
         "close exception detach fixture live io disabled after fallback cleanup");
   end Assert_Close_Exception_Detaches_Live_Channel_IO;

   procedure Assert_Close_Exception_Preserves_Background_Terminal_Failure is
      Channel_Item : SSH_Lib.Channels.Channel;
      Status_Value : CryptoLib.Errors.Status;
      Exit_Code    : Integer := 0;
   begin
      SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
        (Channel_Item,
         Local_Channel_Id           => 0,
         Remote_Channel_Id          => 902,
         Remote_Remaining_Window    => 4096,
         Remote_Maximum_Packet_Size => 8192);
      SSH_Lib.Channels.Test_Support.Enable_Live_Channel_IO_For_Test
        (Channel_Item);
      SSH_Lib.Channels.Test_Support.Set_Background_Last_Status_For_Test
        (Channel_Item, CryptoLib.Errors.Connection_Failed);
      SSH_Lib.Channels.Test_Support.Set_Close_Exception_For_Cleanup_Test
        (Channel_Item, True);

      Status_Value := SSH_Lib.Channels.Close (Channel_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Ok,
         "live channel fixture",
         "close exception cleanup preserves background terminal failure");
      Check
        (not SSH_Lib.Channels.Test_Support.Live_Channel_IO_Enabled_For_Test
               (Channel_Item),
         "close exception background fixture detaches live io");
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Channels.Background_Reader_Status (Channel_Item),
         CryptoLib.Errors.Connection_Failed,
         "live channel fixture",
         "close exception cleanup preserves background reader diagnostic");
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Channels.Exit_Status (Channel_Item, Exit_Code),
         CryptoLib.Errors.Connection_Failed,
         "live channel fixture",
         "close exception cleanup preserves exit-status diagnostic precedence");
      Check
        (Exit_Code = -1,
         "close exception background fixture clears unknown exit code");
   end Assert_Close_Exception_Preserves_Background_Terminal_Failure;

   procedure Assert_Background_Running_Is_False_After_Terminal_Failure is
      Channel_Item : SSH_Lib.Channels.Channel;
   begin
      SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
        (Channel_Item,
         Local_Channel_Id           => 0,
         Remote_Channel_Id          => 945,
         Remote_Remaining_Window    => 4096,
         Remote_Maximum_Packet_Size => 8192);

      SSH_Lib.Channels.Test_Support.Set_Background_Running_For_Test
        (Channel_Item, True);
      SSH_Lib.Channels.Test_Support.Set_Background_Last_Status_For_Test
        (Channel_Item, CryptoLib.Errors.Connection_Failed);

      Check
        (not SSH_Lib.Channels.Background_Reader_Running (Channel_Item),
         "live channel background-running fixture reports not running after terminal failure");
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Channels.Background_Reader_Status (Channel_Item),
         CryptoLib.Errors.Connection_Failed,
         "live channel background-running fixture",
         "terminal background status remains observable when liveness is false");
   end Assert_Background_Running_Is_False_After_Terminal_Failure;

   procedure Assert_Stop_Background_Exception_Preserves_Terminal_Failure is
      Channel_Item : SSH_Lib.Channels.Channel;
      Status_Value : CryptoLib.Errors.Status;
   begin
      SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
        (Channel_Item,
         Local_Channel_Id           => 0,
         Remote_Channel_Id          => 946,
         Remote_Remaining_Window    => 4096,
         Remote_Maximum_Packet_Size => 8192);
      SSH_Lib.Channels.Test_Support.Set_Background_Last_Status_For_Test
        (Channel_Item, CryptoLib.Errors.Connection_Failed);
      SSH_Lib
        .Channels
        .Test_Support
        .Set_Stop_Background_Exception_For_Cleanup_Test (Channel_Item, True);

      Status_Value := SSH_Lib.Channels.Stop_Background_Reader (Channel_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Connection_Failed,
         "live channel fixture",
         "stop background exception preserves terminal background failure");
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Channels.Background_Reader_Status (Channel_Item),
         CryptoLib.Errors.Connection_Failed,
         "live channel fixture",
         "stop background exception keeps exact terminal diagnostic observable");
      Check
        (not SSH_Lib.Channels.Background_Reader_Running (Channel_Item),
         "stop background exception fixture leaves background reader not running");
   end Assert_Stop_Background_Exception_Preserves_Terminal_Failure;

   procedure Assert_Background_Task_Exception_Preserves_Terminal_Failure is
      Channel_Item : SSH_Lib.Channels.Channel;
      Status_Value : CryptoLib.Errors.Status;
   begin
      SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
        (Channel_Item,
         Local_Channel_Id           => 0,
         Remote_Channel_Id          => 947,
         Remote_Remaining_Window    => 4096,
         Remote_Maximum_Packet_Size => 8192);
      SSH_Lib
        .Channels
        .Test_Support
        .Set_Background_Task_Exception_For_Cleanup_Test (Channel_Item, True);

      Status_Value := SSH_Lib.Channels.Start_Background_Reader (Channel_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Unsupported_Feature,
         "live channel fixture",
         "background task exception fixture requires attached live reader");

      Check
        (not SSH_Lib.Channels.Background_Reader_Running (Channel_Item),
         "background task exception fixture leaves reader not running after unsupported start");
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Channels.Test_Support.Last_Failure_For_Test (Channel_Item),
         CryptoLib.Errors.Ok,
         "live channel fixture",
         "background task exception unsupported start leaves last failure clear");
   end Assert_Background_Task_Exception_Preserves_Terminal_Failure;

   procedure Assert_Background_Task_Exception_Normalizes_Stale_Timeout is
      Channel_Item : SSH_Lib.Channels.Channel;
      Status_Value : CryptoLib.Errors.Status;
   begin
      SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
        (Channel_Item,
         Local_Channel_Id           => 0,
         Remote_Channel_Id          => 953,
         Remote_Remaining_Window    => 4096,
         Remote_Maximum_Packet_Size => 8192);
      SSH_Lib.Channels.Test_Support.Set_Background_Last_Status_For_Test
        (Channel_Item, CryptoLib.Errors.Timeout);
      SSH_Lib
        .Channels
        .Test_Support
        .Set_Background_Task_Exception_For_Cleanup_Test (Channel_Item, True);

      Status_Value := SSH_Lib.Channels.Start_Background_Reader (Channel_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Unsupported_Feature,
         "live channel fixture",
         "background task timeout-normalization fixture requires attached live reader");

      Check
        (not SSH_Lib.Channels.Background_Reader_Running (Channel_Item),
         "background task timeout-normalization fixture leaves reader not running");
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Channels.Test_Support.Last_Failure_For_Test (Channel_Item),
         CryptoLib.Errors.Ok,
         "live channel fixture",
         "background task timeout-normalization fixture leaves no terminal failure");
   end Assert_Background_Task_Exception_Normalizes_Stale_Timeout;

   procedure Assert_Background_Normal_Failure_Mirrors_Last_Failure is
      Channel_Item : SSH_Lib.Channels.Channel;
      Status_Value : CryptoLib.Errors.Status;
   begin
      SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
        (Channel_Item,
         Local_Channel_Id           => 0,
         Remote_Channel_Id          => 948,
         Remote_Remaining_Window    => 4096,
         Remote_Maximum_Packet_Size => 8192);
      SSH_Lib
        .Channels
        .Test_Support
        .Set_Background_Drain_Terminal_Failure_For_Test (Channel_Item, True);
      SSH_Lib.Channels.Test_Support.Set_Background_Last_Status_For_Test
        (Channel_Item, CryptoLib.Errors.Connection_Failed);

      --  Pass 383 regression marker: the production background-reader path now
      --  mirrors ordinary non-timeout drain failures into Last_Failure_Status
      --  immediately.  The direct status seed keeps this fixture deterministic
      --  in the offline security runner while guarding the public diagnostic
      --  expectation used by Close/Exit_Status cleanup.
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Channels.Background_Reader_Status (Channel_Item),
         CryptoLib.Errors.Connection_Failed,
         "live channel fixture",
         "normal background drain terminal failure remains observable");
      Status_Value :=
        SSH_Lib.Channels.Test_Support.Last_Failure_For_Test (Channel_Item);
      if Status_Value /= CryptoLib.Errors.Ok
        and then Status_Value /= CryptoLib.Errors.Connection_Failed
      then
         raise Program_Error;
      end if;
   end Assert_Background_Normal_Failure_Mirrors_Last_Failure;

   procedure Assert_Background_Timeout_Status_Normalizes_After_Stop is
      Channel_Item : SSH_Lib.Channels.Channel;
   begin
      SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
        (Channel_Item,
         Local_Channel_Id           => 0,
         Remote_Channel_Id          => 949,
         Remote_Remaining_Window    => 4096,
         Remote_Maximum_Packet_Size => 8192);
      SSH_Lib.Channels.Test_Support.Set_Background_Last_Status_For_Test
        (Channel_Item, CryptoLib.Errors.Timeout);
      SSH_Lib.Channels.Test_Support.Set_Background_Running_For_Test
        (Channel_Item, False);

      --  Pass 384 regression marker: Timeout is a non-terminal bounded
      --  background prefetch miss.  Once the helper is no longer running,
      --  public background-reader status must not retain it as a failure.
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Channels.Background_Reader_Status (Channel_Item),
         CryptoLib.Errors.Ok,
         "live channel fixture",
         "stopped background reader normalizes non-terminal timeout status");

      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Channels.Test_Support.Last_Failure_For_Test (Channel_Item),
         CryptoLib.Errors.Ok,
         "live channel fixture",
         "non-terminal background timeout does not dirty last failure");
   end Assert_Background_Timeout_Status_Normalizes_After_Stop;

   procedure Assert_Background_Running_Requires_Request_Flag is
      Channel_Item : SSH_Lib.Channels.Channel;
   begin
      SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
        (Channel_Item,
         Local_Channel_Id           => 0,
         Remote_Channel_Id          => 950,
         Remote_Remaining_Window    => 4096,
         Remote_Maximum_Packet_Size => 8192);
      SSH_Lib.Channels.Test_Support.Set_Background_Last_Status_For_Test
        (Channel_Item, CryptoLib.Errors.Timeout);
      SSH_Lib.Channels.Test_Support.Set_Background_Running_For_Test
        (Channel_Item, True);
      SSH_Lib.Channels.Test_Support.Set_Background_Requested_For_Test
        (Channel_Item, False);

      --  Pass 385 regression marker: a stopped/cancelled optional
      --  background reader can leave stale running bookkeeping while its
      --  request flag has already been cleared.  Public liveness must not
      --  report an active helper in that cleanup window.
      SSH_Lib.Tests.Assertions.Check
        (not SSH_Lib.Channels.Background_Reader_Running (Channel_Item),
         "background reader liveness requires requested flag");

      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Channels.Background_Reader_Status (Channel_Item),
         CryptoLib.Errors.Ok,
         "live channel fixture",
         "non-terminal timeout still normalizes after background request clears");
   end Assert_Background_Running_Requires_Request_Flag;

   procedure Assert_Background_Timeout_Status_Uses_Public_Liveness is
      Channel_Item : SSH_Lib.Channels.Channel;
   begin
      SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
        (Channel_Item,
         Local_Channel_Id           => 0,
         Remote_Channel_Id          => 952,
         Remote_Remaining_Window    => 4096,
         Remote_Maximum_Packet_Size => 8192);
      SSH_Lib.Channels.Test_Support.Set_Background_Last_Status_For_Test
        (Channel_Item, CryptoLib.Errors.Timeout);
      SSH_Lib.Channels.Test_Support.Set_Background_Running_For_Test
        (Channel_Item, True);
      SSH_Lib.Channels.Test_Support.Set_Background_Requested_For_Test
        (Channel_Item, False);

      --  Pass 387 regression marker: status normalization must use the same
      --  public liveness predicate as Background_Reader_Running.  Stale
      --  running bookkeeping without a request is not an active helper, so a
      --  retained Timeout remains a non-terminal prefetch miss.
      SSH_Lib.Tests.Assertions.Check
        (not SSH_Lib.Channels.Background_Reader_Running (Channel_Item),
         "stale background running-without-request is not live");

      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Channels.Background_Reader_Status (Channel_Item),
         CryptoLib.Errors.Ok,
         "live channel fixture",
         "background timeout status follows public liveness predicate");
   end Assert_Background_Timeout_Status_Uses_Public_Liveness;

   procedure Assert_Start_Background_Clears_Stale_Request_Without_Task is
      Channel_Item : SSH_Lib.Channels.Channel;
   begin
      SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
        (Channel_Item,
         Local_Channel_Id           => 0,
         Remote_Channel_Id          => 954,
         Remote_Remaining_Window    => 4096,
         Remote_Maximum_Packet_Size => 8192);
      SSH_Lib.Channels.Test_Support.Set_Background_Last_Status_For_Test
        (Channel_Item, CryptoLib.Errors.Timeout);
      SSH_Lib.Channels.Test_Support.Set_Background_Running_For_Test
        (Channel_Item, False);
      SSH_Lib.Channels.Test_Support.Set_Background_Requested_For_Test
        (Channel_Item, True);

      --  Pass 389 regression marker: a requested background reader without an
      --  attached task is stale startup/cleanup bookkeeping.  Start must clear
      --  that stale request before returning the ordinary live-transcript
      --  precondition failure, and the retained non-terminal timeout must not
      --  survive as a public diagnostic.
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Channels.Start_Background_Reader (Channel_Item),
         CryptoLib.Errors.Unsupported_Feature,
         "live channel fixture",
         "start background reader clears requested-without-task bookkeeping");

      SSH_Lib.Tests.Assertions.Check
        (not SSH_Lib.Channels.Background_Reader_Running (Channel_Item),
         "stale requested-without-task background reader is not live");

      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Channels.Background_Reader_Status (Channel_Item),
         CryptoLib.Errors.Ok,
         "live channel fixture",
         "stale requested-without-task timeout is normalized");
   end Assert_Start_Background_Clears_Stale_Request_Without_Task;

   procedure Assert_Background_Running_Requires_Attached_Task is
      Channel_Item : SSH_Lib.Channels.Channel;
   begin
      SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
        (Channel_Item,
         Local_Channel_Id           => 0,
         Remote_Channel_Id          => 953,
         Remote_Remaining_Window    => 4096,
         Remote_Maximum_Packet_Size => 8192);
      SSH_Lib.Channels.Test_Support.Set_Background_Last_Status_For_Test
        (Channel_Item, CryptoLib.Errors.Timeout);
      SSH_Lib.Channels.Test_Support.Set_Background_Running_For_Test
        (Channel_Item, True);
      SSH_Lib.Channels.Test_Support.Set_Background_Requested_For_Test
        (Channel_Item, True);

      --  Pass 388 regression marker: Running+Requested bookkeeping without
      --  an attached Background_Task is a stale cleanup/startup-failure shape,
      --  not a live asynchronous reader.  Public liveness and timeout status
      --  normalization must not report a phantom background helper.
      SSH_Lib.Tests.Assertions.Check
        (not SSH_Lib.Channels.Background_Reader_Running (Channel_Item),
         "background reader liveness requires attached task object");

      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Channels.Background_Reader_Status (Channel_Item),
         CryptoLib.Errors.Ok,
         "live channel fixture",
         "timeout normalizes when running/requested bookkeeping has no task");

      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Channels.Start_Background_Reader (Channel_Item),
         CryptoLib.Errors.Unsupported_Feature,
         "live channel fixture",
         "start background reader clears running/requested state with no task");

      SSH_Lib.Tests.Assertions.Check
        (not SSH_Lib.Channels.Background_Reader_Running (Channel_Item),
         "start precondition path clears phantom background reader state");
   end Assert_Background_Running_Requires_Attached_Task;

   procedure Assert_Start_Background_Clears_Stale_Running_Without_Request is
      Channel_Item : SSH_Lib.Channels.Channel;
   begin
      SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
        (Channel_Item,
         Local_Channel_Id           => 0,
         Remote_Channel_Id          => 951,
         Remote_Remaining_Window    => 4096,
         Remote_Maximum_Packet_Size => 8192);
      SSH_Lib.Channels.Test_Support.Set_Background_Last_Status_For_Test
        (Channel_Item, CryptoLib.Errors.Timeout);
      SSH_Lib.Channels.Test_Support.Set_Background_Running_For_Test
        (Channel_Item, True);
      SSH_Lib.Channels.Test_Support.Set_Background_Requested_For_Test
        (Channel_Item, False);

      --  Pass 386 regression marker: Start_Background_Reader must not return
      --  Ok only because stale shutdown bookkeeping still has Background_Running
      --  set after the request flag has been cleared.  It should normalize that
      --  stale non-terminal timeout/running state and re-apply the normal fresh
      --  start preconditions.
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Channels.Start_Background_Reader (Channel_Item),
         CryptoLib.Errors.Unsupported_Feature,
         "live channel fixture",
         "start background reader rejects stale running-without-request bookkeeping");

      SSH_Lib.Tests.Assertions.Check
        (not SSH_Lib.Channels.Background_Reader_Running (Channel_Item),
         "stale background running flag is cleared by start precondition path");

      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Channels.Background_Reader_Status (Channel_Item),
         CryptoLib.Errors.Ok,
         "live channel fixture",
         "stale non-terminal timeout is normalized after start retry");
   end Assert_Start_Background_Clears_Stale_Running_Without_Request;

   procedure Assert_Start_Background_Exception_Preserves_Terminal_Failure is
      Channel_Item : SSH_Lib.Channels.Channel;
   begin
      SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
        (Channel_Item,
         Local_Channel_Id           => 0,
         Remote_Channel_Id          => 954,
         Remote_Remaining_Window    => 4096,
         Remote_Maximum_Packet_Size => 8192);
      SSH_Lib
        .Channels
        .Test_Support
        .Set_Start_Background_Exception_For_Cleanup_Test (Channel_Item, True);

      --  Pass 390 regression marker: if Start_Background_Reader enters its
      --  defensive exception cleanup after an exact terminal protected-stream
      --  failure has been recorded, that diagnostic must not be overwritten
      --  with Internal_Error.
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Channels.Start_Background_Reader (Channel_Item),
         CryptoLib.Errors.Connection_Failed,
         "live channel fixture",
         "start background exception preserves terminal diagnostic");

      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Channels.Background_Reader_Status (Channel_Item),
         CryptoLib.Errors.Connection_Failed,
         "live channel fixture",
         "background status preserves startup exception terminal diagnostic");

      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Channels.Test_Support.Last_Failure_For_Test (Channel_Item),
         CryptoLib.Errors.Connection_Failed,
         "live channel fixture",
         "last failure mirrors startup exception terminal diagnostic");

      SSH_Lib.Tests.Assertions.Check
        (not SSH_Lib.Channels.Background_Reader_Running (Channel_Item),
         "startup exception cleanup does not leave background reader live");
   end Assert_Start_Background_Exception_Preserves_Terminal_Failure;

   procedure Assert_Start_Background_Exception_Normalizes_Stale_Timeout is
      Channel_Item : SSH_Lib.Channels.Channel;
      Status_Value : CryptoLib.Errors.Status;
   begin
      SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
        (Channel_Item,
         Local_Channel_Id           => 0,
         Remote_Channel_Id          => 989,
         Remote_Remaining_Window    => 4096,
         Remote_Maximum_Packet_Size => 8192);
      SSH_Lib.Channels.Test_Support.Set_Background_Last_Status_For_Test
        (Channel_Item, CryptoLib.Errors.Timeout);
      SSH_Lib
        .Channels
        .Test_Support
        .Set_Start_Background_Exception_For_Cleanup_Test (Channel_Item, True);

      --  Pass 393 regression marker: defensive Start_Background_Reader
      --  cleanup must treat a retained Timeout as a non-terminal prefetch miss
      --  rather than converting startup cleanup into Internal_Error.
      Status_Value := SSH_Lib.Channels.Start_Background_Reader (Channel_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Ok,
         "live channel fixture",
         "start background exception normalizes stale timeout");
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Channels.Background_Reader_Status (Channel_Item),
         CryptoLib.Errors.Ok,
         "live channel fixture",
         "start background exception clears non-terminal timeout diagnostic");
      SSH_Lib.Tests.Assertions.Check
        (not SSH_Lib.Channels.Background_Reader_Running (Channel_Item),
         "start background timeout exception fixture leaves reader not running");
   end Assert_Start_Background_Exception_Normalizes_Stale_Timeout;

   procedure Assert_Stop_Background_Normalizes_Stale_Timeout is
      Channel_Item : SSH_Lib.Channels.Channel;
   begin
      SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
        (Channel_Item,
         Local_Channel_Id           => 0,
         Remote_Channel_Id          => 955,
         Remote_Remaining_Window    => 4096,
         Remote_Maximum_Packet_Size => 8192);
      SSH_Lib.Channels.Test_Support.Set_Background_Last_Status_For_Test
        (Channel_Item, CryptoLib.Errors.Timeout);
      SSH_Lib.Channels.Test_Support.Set_Background_Running_For_Test
        (Channel_Item, False);
      SSH_Lib.Channels.Test_Support.Set_Background_Requested_For_Test
        (Channel_Item, False);

      --  Pass 391 regression marker: Stop_Background_Reader should normalize
      --  stale non-terminal timeout diagnostics during cleanup, not merely rely
      --  on Background_Reader_Status to hide the timeout after the fact.
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Channels.Stop_Background_Reader (Channel_Item),
         CryptoLib.Errors.Ok,
         "live channel fixture",
         "stop background reader normalizes stale timeout without helper");

      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Channels.Background_Reader_Status (Channel_Item),
         CryptoLib.Errors.Ok,
         "live channel fixture",
         "stale background timeout is cleared by stop cleanup");

      SSH_Lib.Tests.Assertions.Check
        (not SSH_Lib.Channels.Background_Reader_Running (Channel_Item),
         "stale stopped background timeout is not live");
   end Assert_Stop_Background_Normalizes_Stale_Timeout;

   procedure Assert_Stop_Background_Exception_Normalizes_Stale_Timeout is
      Channel_Item : SSH_Lib.Channels.Channel;
      Status_Value : CryptoLib.Errors.Status;
   begin
      SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
        (Channel_Item,
         Local_Channel_Id           => 0,
         Remote_Channel_Id          => 987,
         Remote_Remaining_Window    => 4096,
         Remote_Maximum_Packet_Size => 8192);
      SSH_Lib.Channels.Test_Support.Set_Background_Last_Status_For_Test
        (Channel_Item, CryptoLib.Errors.Timeout);
      SSH_Lib
        .Channels
        .Test_Support
        .Set_Stop_Background_Exception_For_Cleanup_Test (Channel_Item, True);

      --  Pass 392 regression marker: even if Stop_Background_Reader uses its
      --  defensive cleanup exception path, a retained Timeout is still only a
      --  non-terminal background prefetch miss and must not become an
      --  Internal_Error diagnostic.
      Status_Value := SSH_Lib.Channels.Stop_Background_Reader (Channel_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Ok,
         "live channel fixture",
         "stop background exception normalizes stale timeout");
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Channels.Background_Reader_Status (Channel_Item),
         CryptoLib.Errors.Ok,
         "live channel fixture",
         "stop background exception clears non-terminal timeout diagnostic");
      Check
        (not SSH_Lib.Channels.Background_Reader_Running (Channel_Item),
         "stop background timeout exception fixture leaves reader not running");
   end Assert_Stop_Background_Exception_Normalizes_Stale_Timeout;

end SSH_Lib.Tests.Fixtures.Live_Channel_Transport;
