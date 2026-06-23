with SSH_Lib.Channels.Test_Support;
with SSH_Lib.Protocol.Buffers;
with SSH_Lib.Protocol.Channels;
with SSH_Lib.Protocol.Numbers;
with SSH_Lib.Sessions.Test_Support;

package body SSH_Lib.Tests.Fixtures.Server is

   use type Ada.Streams.Stream_Element_Offset;
   use type CryptoLib.Errors.Status;
   use type SSH_Lib.Tests.Fixtures.Protocol_Scripts.Scenario;

   function To_String (Data : Ada.Streams.Stream_Element_Array) return String is
      Result : String (1 .. Data'Length);
      Index  : Natural := Result'First;
   begin
      for Byte_Index in Data'Range loop
         Result (Index) := Character'Val (Natural (Data (Byte_Index)));
         Index := Index + 1;
      end loop;
      return Result;
   end To_String;

   function Open_Confirmation
     (Local_Channel  : Interfaces.Unsigned_32;
      Remote_Channel : Interfaces.Unsigned_32)
      return Ada.Streams.Stream_Element_Array
   is
      Payload : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Status_Value : CryptoLib.Errors.Status;
   begin
      Status_Value := SSH_Lib.Protocol.Buffers.Append_Byte
        (Payload, SSH_Lib.Protocol.Channels.SSH_MSG_CHANNEL_OPEN_CONFIRMATION);
      if Status_Value /= CryptoLib.Errors.Ok then
         return [1 .. 0 => 0];
      end if;
      Status_Value := SSH_Lib.Protocol.Buffers.Append
        (Payload, SSH_Lib.Protocol.Numbers.Encode_Uint32 (Local_Channel));
      if Status_Value /= CryptoLib.Errors.Ok then
         return [1 .. 0 => 0];
      end if;
      Status_Value := SSH_Lib.Protocol.Buffers.Append
        (Payload, SSH_Lib.Protocol.Numbers.Encode_Uint32 (Remote_Channel));
      if Status_Value /= CryptoLib.Errors.Ok then
         return [1 .. 0 => 0];
      end if;
      Status_Value := SSH_Lib.Protocol.Buffers.Append
        (Payload,
         SSH_Lib.Protocol.Numbers.Encode_Uint32
           (SSH_Lib.Protocol.Channels.Default_Initial_Window_Size));
      if Status_Value /= CryptoLib.Errors.Ok then
         return [1 .. 0 => 0];
      end if;
      Status_Value := SSH_Lib.Protocol.Buffers.Append
        (Payload,
         SSH_Lib.Protocol.Numbers.Encode_Uint32
           (SSH_Lib.Protocol.Channels.Default_Maximum_Packet_Size));
      if Status_Value /= CryptoLib.Errors.Ok then
         return [1 .. 0 => 0];
      end if;
      return SSH_Lib.Protocol.Buffers.To_Array (Payload);
   end Open_Confirmation;

   function Exec_Reply
     (Message_Value : Ada.Streams.Stream_Element;
      Local_Channel : Interfaces.Unsigned_32) return Ada.Streams.Stream_Element_Array
   is
      Payload : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Status_Value : CryptoLib.Errors.Status;
   begin
      Status_Value := SSH_Lib.Protocol.Buffers.Append_Byte (Payload, Message_Value);
      if Status_Value /= CryptoLib.Errors.Ok then
         return [1 .. 0 => 0];
      end if;
      Status_Value := SSH_Lib.Protocol.Buffers.Append
        (Payload, SSH_Lib.Protocol.Numbers.Encode_Uint32 (Local_Channel));
      if Status_Value /= CryptoLib.Errors.Ok then
         return [1 .. 0 => 0];
      end if;
      return SSH_Lib.Protocol.Buffers.To_Array (Payload);
   end Exec_Reply;

   procedure Start (Item : out Fixture; Selected_Scenario : Scenario) is
   begin
      Item.Active_Scenario := Selected_Scenario;
   end Start;

   function Scenario_Name (Item : Fixture) return String is
   begin
      return SSH_Lib.Tests.Fixtures.Protocol_Scripts.Name (Item.Active_Scenario);
   end Scenario_Name;

   procedure Prepare_Authenticated_Session
     (Item    : Fixture;
      Session : in out SSH_Lib.Sessions.Session) is
   begin
      if Item.Active_Scenario = SSH_Lib.Tests.Fixtures.Protocol_Scripts.Dirty_Session then
         SSH_Lib.Sessions.Test_Support.Mark_Dirty_For_Test
           (Session, CryptoLib.Errors.Handshake_Failed);
      else
         SSH_Lib.Sessions.Test_Support.Mark_Authenticated_Open_For_Test (Session);
      end if;
   end Prepare_Authenticated_Session;

   function Open_Exec
     (Item    : Fixture;
      Session : in out SSH_Lib.Sessions.Session;
      Command : String;
      Channel : out SSH_Lib.Channels.Channel) return CryptoLib.Errors.Status
   is
      Status_Value : CryptoLib.Errors.Status;
   begin
      case Item.Active_Scenario is
         when SSH_Lib.Tests.Fixtures.Protocol_Scripts.Channel_Open_Rejected =>
            Status_Value := SSH_Lib.Sessions.Test_Support.Queue_Channel_Open_Response_For_Test
              (Session,
               [1 => SSH_Lib.Protocol.Channels.SSH_MSG_CHANNEL_OPEN_FAILURE,
                2 => 0, 3 => 0, 4 => 0, 5 => 0]);
         when SSH_Lib.Tests.Fixtures.Protocol_Scripts.Malformed_Open_Confirmation =>
            Status_Value := SSH_Lib.Sessions.Test_Support.Queue_Channel_Open_Response_For_Test
              (Session,
               [1 => SSH_Lib.Protocol.Channels.SSH_MSG_CHANNEL_OPEN_CONFIRMATION,
                2 => 0]);
         when SSH_Lib.Tests.Fixtures.Protocol_Scripts.Exec_Timeout =>
            Status_Value := SSH_Lib.Sessions.Test_Support.Queue_Channel_Open_Response_For_Test
              (Session, Open_Confirmation (0, 1));
            SSH_Lib.Sessions.Test_Support.Set_Channel_Exec_Timeout_For_Test
              (Session, True);
         when SSH_Lib.Tests.Fixtures.Protocol_Scripts.Close_Before_Exec =>
            Status_Value := SSH_Lib.Sessions.Test_Support.Queue_Channel_Open_Response_For_Test
              (Session, Open_Confirmation (0, 1));
            if Status_Value = CryptoLib.Errors.Ok then
               Status_Value := SSH_Lib.Sessions.Test_Support.Queue_Exec_Response_For_Test
                 (Session,
                  SSH_Lib.Protocol.Buffers.To_Array
                    (SSH_Lib.Protocol.Channels.Encode_Channel_Close (0)));
            end if;
         when SSH_Lib.Tests.Fixtures.Protocol_Scripts.Wrong_Exec_Channel =>
            Status_Value := SSH_Lib.Sessions.Test_Support.Queue_Channel_Open_Response_For_Test
              (Session, Open_Confirmation (0, 1));
            if Status_Value = CryptoLib.Errors.Ok then
               Status_Value := SSH_Lib.Sessions.Test_Support.Queue_Exec_Response_For_Test
                 (Session,
                  Exec_Reply
                    (SSH_Lib.Protocol.Channels.SSH_MSG_CHANNEL_SUCCESS, 1));
            end if;
         when SSH_Lib.Tests.Fixtures.Protocol_Scripts.Exec_Rejected =>
            Status_Value := SSH_Lib.Sessions.Test_Support.Queue_Channel_Open_Response_For_Test
              (Session, Open_Confirmation (0, 1));
            if Status_Value = CryptoLib.Errors.Ok then
               Status_Value := SSH_Lib.Sessions.Test_Support.Queue_Exec_Response_For_Test
                 (Session,
                  Exec_Reply
                    (SSH_Lib.Protocol.Channels.SSH_MSG_CHANNEL_FAILURE, 0));
            end if;
         when others =>
            Status_Value := SSH_Lib.Sessions.Test_Support.Queue_Channel_Open_Response_For_Test
              (Session, Open_Confirmation (0, 1));
            if Status_Value = CryptoLib.Errors.Ok then
               Status_Value := SSH_Lib.Sessions.Test_Support.Queue_Exec_Response_For_Test
                 (Session,
                  Exec_Reply
                    (SSH_Lib.Protocol.Channels.SSH_MSG_CHANNEL_SUCCESS, 0));
            end if;
      end case;

      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      return SSH_Lib.Channels.Open_Exec (Session, Command, Channel);
   end Open_Exec;

   function Feed_Stdout
     (Item    : Fixture;
      Channel : in out SSH_Lib.Channels.Channel;
      Data    : Ada.Streams.Stream_Element_Array) return CryptoLib.Errors.Status
   is
      pragma Unreferenced (Item);
   begin
      return SSH_Lib.Channels.Test_Support.Dispatch_Inbound_Payload_For_Test
        (Channel,
         SSH_Lib.Protocol.Buffers.To_Array
           (SSH_Lib.Protocol.Channels.Encode_Channel_Data (0, Data)));
   end Feed_Stdout;

   function Feed_Stderr
     (Item    : Fixture;
      Channel : in out SSH_Lib.Channels.Channel;
      Data    : Ada.Streams.Stream_Element_Array) return CryptoLib.Errors.Status
   is
      pragma Unreferenced (Item);
   begin
      return SSH_Lib.Channels.Test_Support.Dispatch_Inbound_Payload_For_Test
        (Channel,
         SSH_Lib.Protocol.Buffers.To_Array
           (SSH_Lib.Protocol.Channels.Encode_Channel_Extended_Data
              (0, SSH_Lib.Protocol.Channels.Extended_Data_Stderr, Data)));
   end Feed_Stderr;

   function Feed_EOF
     (Item    : Fixture;
      Channel : in out SSH_Lib.Channels.Channel) return CryptoLib.Errors.Status
   is
      pragma Unreferenced (Item);
   begin
      return SSH_Lib.Channels.Test_Support.Dispatch_Inbound_Payload_For_Test
        (Channel,
         SSH_Lib.Protocol.Buffers.To_Array
           (SSH_Lib.Protocol.Channels.Encode_Channel_EOF (0)));
   end Feed_EOF;

   function Feed_Window_Adjust
     (Item         : Fixture;
      Channel      : in out SSH_Lib.Channels.Channel;
      Bytes_To_Add : Interfaces.Unsigned_32) return CryptoLib.Errors.Status
   is
      pragma Unreferenced (Item);
   begin
      return SSH_Lib.Channels.Test_Support.Dispatch_Inbound_Payload_For_Test
        (Channel,
         SSH_Lib.Protocol.Buffers.To_Array
           (SSH_Lib.Protocol.Channels.Encode_Channel_Window_Adjust
              (0, Bytes_To_Add)));
   end Feed_Window_Adjust;

   function Feed_Close
     (Item    : Fixture;
      Channel : in out SSH_Lib.Channels.Channel) return CryptoLib.Errors.Status
   is
      pragma Unreferenced (Item);
   begin
      return SSH_Lib.Channels.Test_Support.Dispatch_Inbound_Payload_For_Test
        (Channel,
         SSH_Lib.Protocol.Buffers.To_Array
           (SSH_Lib.Protocol.Channels.Encode_Channel_Close (0)));
   end Feed_Close;

   function Feed_Exit_Status
     (Item    : Fixture;
      Channel : in out SSH_Lib.Channels.Channel;
      Code    : Natural) return CryptoLib.Errors.Status
   is
      pragma Unreferenced (Item);
   begin
      return SSH_Lib.Channels.Test_Support.Dispatch_Inbound_Payload_For_Test
        (Channel,
         SSH_Lib.Protocol.Buffers.To_Array
           (SSH_Lib.Protocol.Channels.Encode_Exit_Status_Request
              (0, False, Interfaces.Unsigned_32 (Code))));
   end Feed_Exit_Status;

   function Last_Exec_Command
     (Session : SSH_Lib.Sessions.Session) return String
   is
      Payload : constant Ada.Streams.Stream_Element_Array :=
        SSH_Lib.Sessions.Test_Support.Last_Exec_Request_Payload_For_Test (Session);
   begin
      if Payload'Length <= 18 then
         return "";
      end if;
      return To_String (Payload (Payload'First + 18 .. Payload'Last));
   end Last_Exec_Command;
end SSH_Lib.Tests.Fixtures.Server;
