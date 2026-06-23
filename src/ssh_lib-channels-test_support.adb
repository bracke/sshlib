with System;
with SSH_Lib.Protocol.Buffers;
with SSH_Lib.Protocol.Channels;
with SSH_Lib.Protocol.Numbers;
with SSH_Lib.Protocol.Protected_Packets;

package body SSH_Lib.Channels.Test_Support is
   use Ada.Streams;
   use CryptoLib.Errors;
   use SSH_Lib.Protocol.Buffers;
   use type Interfaces.Unsigned_32;

   Channel_Boundary_Key : constant Stream_Element_Array (1 .. 32) :=
     [1  => 16#43#, 2  => 16#48#, 3  => 16#41#, 4  => 16#4E#,
      5  => 16#4E#, 6  => 16#45#, 7  => 16#4C#, 8  => 16#2D#,
      9  => 16#53#, 10 => 16#54#, 11 => 16#52#, 12 => 16#45#,
      13 => 16#41#, 14 => 16#4D#, 15 => 16#2D#, 16 => 16#4B#,
      17 => 16#45#, 18 => 16#59#, 19 => 16#2D#, 20 => 16#30#,
      21 => 16#30#, 22 => 16#30#, 23 => 16#30#, 24 => 16#30#,
      25 => 16#30#, 26 => 16#30#, 27 => 16#30#, 28 => 16#30#,
      29 => 16#30#, 30 => 16#30#, 31 => 16#30#, 32 => 16#32#];

   procedure Mark_Channel_Failed
     (Item         : in out Channel;
      Status_Value : Status)
   is
   begin
      Item.Dirty := True;
      Item.Current_State := Channel_Failed;
      if Status_Value = Ok then
         Item.Last_Failure_Status := Internal_Error;
      else
         Item.Last_Failure_Status := Status_Value;
      end if;
   end Mark_Channel_Failed;

   function Control_Send_Allowed
     (Item         : in out Channel;
      Failure_Code : Status;
      Dirty_On_Timeout : Boolean)
      return Status
   is
   begin
      if Item.Write_Timeout_MS = 0 then
         Item.Last_Failure_Status := Timeout;
         if Dirty_On_Timeout then
            Mark_Channel_Failed (Item, Timeout);
         end if;
         return Timeout;
      end if;
      if Item.Dirty or else Item.Current_State = Channel_Failed then
         return Channel_Request_Failed;
      end if;
      return Ok;
   exception
      when others =>
         Mark_Channel_Failed (Item, Failure_Code);
         return Failure_Code;
   end Control_Send_Allowed;

   procedure Mark_Exec_Active_For_Test
     (Item                         : in out Channel;
      Local_Channel_Id             : Interfaces.Unsigned_32 := 0;
      Remote_Channel_Id            : Interfaces.Unsigned_32 := 1;
      Remote_Remaining_Window      : Interfaces.Unsigned_32 := 2_097_152;
      Remote_Maximum_Packet_Size   : Interfaces.Unsigned_32 := 32_768)
   is
   begin
      Item.Current_State := Channel_Exec_Active;
      Item.Allocated := True;
      Item.Channel_Open_Confirmed := True;
      Item.Exec_Request_Confirmed := True;
      Item.Local_Channel_Id := Local_Channel_Id;
      Item.Remote_Channel_Id := Remote_Channel_Id;
      Item.Local_Initial_Window_Size := SSH_Lib.Protocol.Channels.Default_Initial_Window_Size;
      Item.Local_Remaining_Window := SSH_Lib.Protocol.Channels.Default_Initial_Window_Size;
      Item.Local_Maximum_Packet_Size := SSH_Lib.Protocol.Channels.Default_Maximum_Packet_Size;
      Item.Remote_Remaining_Window := Remote_Remaining_Window;
      Item.Remote_Maximum_Packet_Size := Remote_Maximum_Packet_Size;
      Item.Eof_Sent := False;
      Item.Eof_Received := False;
      Item.Close_Sent := False;
      Item.Close_Received := False;
      Item.Remote_Exit_Status_Known := False;
      Item.Remote_Exit_Status := 0;
      Clear (Item.Pending_Stdout);
      Clear (Item.Pending_Stderr);
      Clear (Item.Last_Channel_Data);
      Clear (Item.Last_EOF);
      Clear (Item.Last_Close);
      Clear (Item.Last_Window_Adjust);
      Clear (Item.Last_Channel_Success);
      Clear (Item.Last_Channel_Failure);
      Item.Outbound_Data_Bytes := 0;
      Item.Outbound_Data_Packets := 0;
      Item.Last_Failure_Status := Ok;
      Item.Read_Timeout_MS := 30_000;
      Item.Write_Timeout_MS := 30_000;
      Item.Dirty := False;
      Item.Test_Write_Timeout_After_Partial := False;
      Item.Test_Send_EOF_Timeout := False;
      Item.Test_Remote_Close_After_Partial := False;
      Item.Test_Close_Timeout := False;
      Item.Test_Stop_Background_Exception_For_Cleanup := False;
      Item.Test_Background_Task_Exception_For_Cleanup := False;
      Item.Live_Channel_IO_Enabled := False;
      SSH_Lib.Protocol.Protected_Packets.Reset (Item.Live_Outbound_State, Channel_Boundary_Key);
      SSH_Lib.Protocol.Protected_Packets.Reset (Item.Live_Inbound_State, Channel_Boundary_Key);
      Clear (Item.Live_Last_Protected_Outbound);
      Clear (Item.Live_Next_Protected_Inbound);
      Item.Live_Has_Protected_Inbound := False;
      Item.Live_Transcript_Ptr := null;
      Item.Owning_Session_Address := System.Null_Address;
   end Mark_Exec_Active_For_Test;


   procedure Mark_Channel_Open_Not_Exec_For_Test
     (Item                         : in out Channel;
      Local_Channel_Id             : Interfaces.Unsigned_32 := 0;
      Remote_Channel_Id            : Interfaces.Unsigned_32 := 1;
      Remote_Remaining_Window      : Interfaces.Unsigned_32 := 2_097_152;
      Remote_Maximum_Packet_Size   : Interfaces.Unsigned_32 := 32_768)
   is
   begin
      --  Model a channel after CHANNEL_OPEN_CONFIRMATION but before the exec
      --  CHANNEL_SUCCESS reply.  This lets fixtures verify that stdout,
      --  stderr, EOF, and terminal request metadata cannot race ahead of a
      --  successfully accepted remote command.
      Mark_Exec_Active_For_Test
        (Item,
         Local_Channel_Id,
         Remote_Channel_Id,
         Remote_Remaining_Window,
         Remote_Maximum_Packet_Size);
      Item.Current_State := Channel_Exec_Requested;
      Item.Exec_Request_Confirmed := False;
      Item.Remote_Exit_Status_Known := False;
      Item.Remote_Exit_Status := 0;
   end Mark_Channel_Open_Not_Exec_For_Test;

   procedure Mark_Exit_Status_Known_For_Test
     (Item : in out Channel;
      Code : Integer) is
   begin
      Item.Remote_Exit_Status_Known := True;
      Item.Remote_Exit_Status := Code;
   end Mark_Exit_Status_Known_For_Test;

   procedure Mark_Local_Close_Sent_For_Test
     (Item : in out Channel) is
   begin
      --  Test hook for validating peer messages that arrive after the local
      --  endpoint has already sent CHANNEL_CLOSE but before the peer close
      --  acknowledgement is observed.
      Item.Close_Sent := True;
      Item.Current_State := Channel_Close_Sent;
   end Mark_Local_Close_Sent_For_Test;

   procedure Mark_Local_EOF_Sent_For_Test
     (Item : in out Channel) is
   begin
      --  Test hook for validating peer messages that arrive after the local
      --  endpoint has already sent CHANNEL_EOF.  SSH EOF is directional, but
      --  after local EOF the client must not accept new outbound window credit
      --  for Git stdin bytes it has already promised not to send.
      Item.Eof_Sent := True;
      Item.Current_State := Channel_Eof_Sent;
   end Mark_Local_EOF_Sent_For_Test;

   function Queue_Stdout_For_Test
     (Item : in out Channel;
      Data : Stream_Element_Array)
      return Status
   is
   begin
      return Append (Item.Pending_Stdout, Data);
   exception
      when others =>
         return Internal_Error;
   end Queue_Stdout_For_Test;

   function Queue_Stderr_For_Test
     (Item : in out Channel;
      Data : Stream_Element_Array)
      return Status
   is
   begin
      return Append (Item.Pending_Stderr, Data);
   exception
      when others =>
         return Internal_Error;
   end Queue_Stderr_For_Test;

   function Dispatch_Inbound_Payload_For_Test
     (Item    : in out Channel;
      Payload : Stream_Element_Array)
      return Status
   is
      Data_Event : SSH_Lib.Protocol.Channels.Channel_Data_Event;
      Extended_Event : SSH_Lib.Protocol.Channels.Channel_Extended_Data_Event;
      Window_Event : SSH_Lib.Protocol.Channels.Channel_Window_Adjust_Event;
      Request_Event : SSH_Lib.Protocol.Channels.Channel_Request_Event;
      Status_Value : Status;
      Data_Length : Natural := 0;
      Adjustment_Amount : Interfaces.Unsigned_32 := 0;
      Window_Data_Consumed : Boolean := False;

      function Raw_Channel_Request_Wants_Reply return Boolean is
         Cursor_Value : Stream_Element_Offset := Payload'First + 1;
         Recipient_Value : Interfaces.Unsigned_32;
         Name_Value : Packet_Buffer;
         Want_Reply_Value : Boolean := False;
         Decode_Status : Status;
      begin
         if Payload'Length < 10
           or else Payload (Payload'First) /=
             SSH_Lib.Protocol.Channels.SSH_MSG_CHANNEL_REQUEST
         then
            return False;
         end if;

         Decode_Status := SSH_Lib.Protocol.Numbers.Decode_Uint32
           (Payload, Cursor_Value, Recipient_Value, Cursor_Value);
         if Decode_Status /= Ok then
            return False;
         end if;

         Decode_Status := SSH_Lib.Protocol.Numbers.Decode_SSH_String
           (Payload, Cursor_Value, Name_Value, Cursor_Value);
         if Decode_Status /= Ok or else Cursor_Value > Payload'Last then
            return False;
         end if;

         Decode_Status := SSH_Lib.Protocol.Numbers.Decode_Boolean
           (Payload (Cursor_Value), Want_Reply_Value);
         return Decode_Status = Ok and then Want_Reply_Value;
      exception
         when others =>
            return False;
      end Raw_Channel_Request_Wants_Reply;
   begin
      if Payload'Length = 0 then
         Item.Dirty := True;
            Item.Current_State := Channel_Failed;
         return Read_Failed;
      end if;

      case Payload (Payload'First) is
         when SSH_Lib.Protocol.Channels.SSH_MSG_CHANNEL_DATA =>
            if not Item.Exec_Request_Confirmed then
               --  Git stdout bytes are only valid after the exec request has
               --  been accepted.  Do not let authenticated channel data race
               --  ahead of CHANNEL_SUCCESS and enter the pkt-line/packfile
               --  stream before Open_Exec has actually completed.
               Mark_Channel_Failed (Item, Read_Failed);
               return Read_Failed;
            elsif Item.Remote_Exit_Status_Known then
               Mark_Channel_Failed (Item, Read_Failed);
               return Read_Failed;
            elsif Item.Eof_Received or else Item.Close_Sent or else Item.Close_Received then
               Mark_Channel_Failed (Item, Read_Failed);
               return Read_Failed;
            end if;

            Status_Value := SSH_Lib.Protocol.Channels.Parse_Channel_Data
              (Payload, Item.Local_Channel_Id, Data_Event);
            if Status_Value /= Ok then
               Item.Dirty := True;
            Item.Current_State := Channel_Failed;
               return Read_Failed;
            end if;
            declare
               Data_Value : constant Stream_Element_Array := To_Array (Data_Event.Data);
            begin
               Data_Length := Data_Value'Length;
               if Interfaces.Unsigned_32 (Data_Length) > Item.Local_Maximum_Packet_Size then
                  Mark_Channel_Failed (Item, Read_Failed);
                  return Read_Failed;
               end if;
               if Length (Item.Pending_Stdout) + Data_Length > SSH_Lib.Protocol.Buffers.Max_Packet_Length then
                  --  Reject a stdout fragment that cannot be queued before
                  --  consuming SSH receive-window credit.  The peer must not
                  --  shrink this side's window with bytes that are discarded
                  --  because the Version-facing stdout buffer is already full.
                  Mark_Channel_Failed (Item, Read_Failed);
                  return Read_Failed;
               end if;
               if Interfaces.Unsigned_32 (Data_Length) > Item.Local_Remaining_Window then
                  Item.Dirty := True;
            Item.Current_State := Channel_Failed;
                  return Read_Failed;
               end if;
               Item.Local_Remaining_Window :=
                 Item.Local_Remaining_Window - Interfaces.Unsigned_32 (Data_Length);
               Window_Data_Consumed := Data_Length > 0;
               Status_Value := Append (Item.Pending_Stdout, Data_Value);
               if Status_Value /= Ok then
                  Item.Dirty := True;
            Item.Current_State := Channel_Failed;
                  return Read_Failed;
               end if;
            end;

         when SSH_Lib.Protocol.Channels.SSH_MSG_CHANNEL_EXTENDED_DATA =>
            if not Item.Exec_Request_Confirmed then
               --  Stderr is also part of the exec command stream.  Reject it
               --  before exec confirmation so diagnostic bytes cannot be
               --  associated with a command request the server has not yet
               --  accepted.
               Mark_Channel_Failed (Item, Read_Failed);
               return Read_Failed;
            elsif Item.Remote_Exit_Status_Known then
               Mark_Channel_Failed (Item, Read_Failed);
               return Read_Failed;
            elsif Item.Eof_Received or else Item.Close_Sent or else Item.Close_Received then
               Mark_Channel_Failed (Item, Read_Failed);
               return Read_Failed;
            end if;

            Status_Value := SSH_Lib.Protocol.Channels.Parse_Channel_Extended_Data
              (Payload, Item.Local_Channel_Id, Extended_Event);
            if Status_Value /= Ok then
               Item.Dirty := True;
            Item.Current_State := Channel_Failed;
               return Read_Failed;
            end if;
            declare
               Data_Value : constant Stream_Element_Array := To_Array (Extended_Event.Data);
            begin
               Data_Length := Data_Value'Length;
               if Extended_Event.Data_Type_Code /= SSH_Lib.Protocol.Channels.Extended_Data_Stderr then
                  --  RFC 4254 reserves extended-data type 1 for stderr.  The
                  --  Version-facing channel API exposes stdout bytes and keeps
                  --  stderr diagnostic bytes separate; silently consuming an
                  --  unknown extended-data stream would discard authenticated
                  --  protected channel data while still advancing flow-control.
                  --  Reject unsupported extended-data types before consuming
                  --  receive-window credit or updating auto-adjust state.
                  Mark_Channel_Failed (Item, Read_Failed);
                  return Read_Failed;
               end if;
               if Interfaces.Unsigned_32 (Data_Length) > Item.Local_Maximum_Packet_Size then
                  Mark_Channel_Failed (Item, Read_Failed);
                  return Read_Failed;
               end if;
               if Length (Item.Pending_Stderr) + Data_Length > SSH_Lib.Protocol.Buffers.Max_Packet_Length then
                  --  Reject stderr that cannot be retained before consuming
                  --  receive-window credit.  Diagnostic extended data is still
                  --  authenticated channel data; discarding it must not also
                  --  debit the local SSH receive window.
                  Mark_Channel_Failed (Item, Read_Failed);
                  return Read_Failed;
               end if;
               if Interfaces.Unsigned_32 (Data_Length) > Item.Local_Remaining_Window then
                  Item.Dirty := True;
            Item.Current_State := Channel_Failed;
                  return Read_Failed;
               end if;
               Item.Local_Remaining_Window :=
                 Item.Local_Remaining_Window - Interfaces.Unsigned_32 (Data_Length);
               Window_Data_Consumed := Data_Length > 0;

               --  Multiple extended-data packets are one stderr stream; keep
               --  previously queued diagnostics instead of replacing them with
               --  the latest protected packet.
               Status_Value := Append (Item.Pending_Stderr, Data_Value);
               if Status_Value /= Ok then
                  Item.Dirty := True;
                  Item.Current_State := Channel_Failed;
                  return Read_Failed;
               end if;
            end;

         when SSH_Lib.Protocol.Channels.SSH_MSG_CHANNEL_WINDOW_ADJUST =>
            Status_Value := SSH_Lib.Protocol.Channels.Parse_Channel_Window_Adjust
              (Payload, Item.Local_Channel_Id, Window_Event);
            if Status_Value /= Ok then
               Item.Dirty := True;
               Item.Current_State := Channel_Failed;
               return Write_Failed;
            end if;

            if Item.Close_Sent or else Item.Close_Received then
               --  CHANNEL_CLOSE terminates the channel once either side has
               --  sent it.  This terminal teardown state must dominate both a
               --  previously observed exit-status/exit-signal and a local EOF;
               --  otherwise a late in-flight WINDOW_ADJUST ordered after close
               --  could be mistaken for harmless pre-close credit metadata.
               --  Reject it without reopening write capacity.
               Mark_Channel_Failed (Item, Write_Failed);
               return Write_Failed;
            elsif Item.Remote_Exit_Status_Known then
               --  Once exit-status/exit-signal has reported remote command
               --  termination, outbound Git stdin is no longer permitted.  A
               --  late WINDOW_ADJUST may still be an in-flight credit update
               --  for stdin bytes consumed before termination.  Validate the
               --  recipient above, but do not mutate outbound credit or dirty
               --  the channel after the exec result is known; Write remains
               --  rejected by the public Remote_Exit_Status_Known guard.
               return Ok;
            elsif Item.Eof_Sent then
               --  Local EOF is only the client-to-server data half-close.  A
               --  peer may still have an in-flight WINDOW_ADJUST queued for
               --  earlier stdin bytes.  Validate the recipient above, but do
               --  not mutate outbound credit or dirty the channel after EOF;
               --  Write remains rejected by the public Eof_Sent guard.
               return Ok;
            end if;

            if Interfaces.Unsigned_32'Last - Item.Remote_Remaining_Window < Window_Event.Bytes_To_Add then
               Item.Dirty := True;
               Item.Current_State := Channel_Failed;
               return Write_Failed;
            end if;
            Item.Remote_Remaining_Window := Item.Remote_Remaining_Window + Window_Event.Bytes_To_Add;

         when SSH_Lib.Protocol.Channels.SSH_MSG_CHANNEL_EOF =>
            if not Item.Exec_Request_Confirmed then
               --  EOF terminates the receive side of the exec stream.  Before
               --  exec success there is no Git stdout/stderr stream to close.
               Mark_Channel_Failed (Item, Read_Failed);
               return Read_Failed;
            elsif Item.Close_Sent or else Item.Close_Received then
               --  CHANNEL_CLOSE is terminal once either side has sent it.
               --  Accepting later EOF would allow impossible state transitions
               --  after local or peer close.
               Mark_Channel_Failed (Item, Read_Failed);
               return Read_Failed;
            elsif Item.Eof_Received then
               --  CHANNEL_EOF is a receive-side half-close marker.  Duplicate
               --  peer EOF must not be accepted as a second clean stream
               --  transition.
               Mark_Channel_Failed (Item, Read_Failed);
               return Read_Failed;
            end if;

            Status_Value := SSH_Lib.Protocol.Channels.Parse_Channel_One_Id
              (Payload, SSH_Lib.Protocol.Channels.SSH_MSG_CHANNEL_EOF, Item.Local_Channel_Id);
            if Status_Value /= Ok then
               Item.Dirty := True;
            Item.Current_State := Channel_Failed;
               return Read_Failed;
            end if;
            Item.Eof_Received := True;
            Item.Current_State := Channel_Eof_Received;

         when SSH_Lib.Protocol.Channels.SSH_MSG_CHANNEL_CLOSE =>
            if Item.Close_Received then
               --  Duplicate peer close after the terminal close marker is a
               --  protocol error, not another cleanup acknowledgement.
               Mark_Channel_Failed (Item, Read_Failed);
               return Read_Failed;
            end if;

            Status_Value := SSH_Lib.Protocol.Channels.Parse_Channel_One_Id
              (Payload, SSH_Lib.Protocol.Channels.SSH_MSG_CHANNEL_CLOSE, Item.Local_Channel_Id);
            if Status_Value /= Ok then
               Item.Dirty := True;
            Item.Current_State := Channel_Failed;
               return Read_Failed;
            end if;
            Item.Close_Received := True;
            if not Item.Close_Sent then
               --  Replying to a peer CHANNEL_CLOSE is part of best-effort
               --  cleanup, but it is still an outbound control send and must
               --  observe the owning write deadline.  A pre-emission timeout
               --  leaves the channel in a terminal, locally recoverable state:
               --  no close packet is retained and no later write is permitted.
               Status_Value := Control_Send_Allowed
                 (Item, Channel_Request_Failed, Dirty_On_Timeout => False);
               if Status_Value /= Ok then
                  Item.Current_State := Channel_Close_Received;
                  return Status_Value;
               end if;
               Item.Last_Close := SSH_Lib.Protocol.Channels.Encode_Channel_Close (Item.Remote_Channel_Id);
               if Is_Empty (Item.Last_Close) then
                  Item.Last_Failure_Status := Channel_Request_Failed;
                  Item.Current_State := Channel_Close_Received;
                  return Channel_Request_Failed;
               end if;
               Item.Close_Sent := True;
            end if;
            Item.Current_State := Channel_Close_Received;

         when SSH_Lib.Protocol.Channels.SSH_MSG_CHANNEL_REQUEST =>
            if not Item.Exec_Request_Confirmed then
               --  exit-status/exit-signal and vendor channel requests are part
               --  of an established exec channel lifecycle.  Reject them before
               --  CHANNEL_SUCCESS so an exec failure cannot be hidden by early
               --  terminal metadata.
               Mark_Channel_Failed (Item, Read_Failed);
               return Read_Failed;
            elsif Item.Close_Sent or else Item.Close_Received then
               --  No channel requests, including late exit-status or
               --  exit-signal, are valid after CHANNEL_CLOSE has been sent by
               --  either side.  Exit status is preserved if it arrived before
               --  close; late requests after local/peer close are protocol
               --  errors.
               Mark_Channel_Failed (Item, Read_Failed);
               return Read_Failed;
            end if;

            Status_Value := SSH_Lib.Protocol.Channels.Parse_Channel_Request
              (Payload, Item.Local_Channel_Id, Request_Event);
            if Status_Value /= Ok then
               if Raw_Channel_Request_Wants_Reply then
                  Item.Dirty := True;
                  Item.Current_State := Channel_Failed;
               else
                  Mark_Channel_Failed (Item, Read_Failed);
               end if;
               return Read_Failed;
            end if;
            if Item.Remote_Exit_Status_Known then
               --  Once exit-status/exit-signal has reported remote program
               --  termination, no further channel request can affect the Git
               --  command lifecycle.  Reject even unknown request types here
               --  instead of acknowledging a request after the exec result is
               --  already final.  The first recorded status remains observable.
               Mark_Channel_Failed (Item, Read_Failed);
               return Read_Failed;
            end if;
            if SSH_Lib.Protocol.Channels.Request_Is_Exit_Status (Request_Event) then
               if Item.Remote_Exit_Status_Known then
                  --  RFC 4254 defines exit-status as the remote program status
                  --  for the channel.  Treat a second exit-status request as a
                  --  protocol error rather than allowing it to rewrite the Git
                  --  command result already observed for this channel.
                  Mark_Channel_Failed (Item, Read_Failed);
                  return Read_Failed;
               end if;
               if Request_Event.Exit_Status > 2_147_483_647 then
                  Item.Dirty := True;
            Item.Current_State := Channel_Failed;
                  return Read_Failed;
               end if;
               Item.Remote_Exit_Status_Known := True;
               Item.Remote_Exit_Status := Integer (Request_Event.Exit_Status);
               if Request_Event.Want_Reply then
                  Status_Value := Control_Send_Allowed
                    (Item, Channel_Request_Failed, Dirty_On_Timeout => True);
                  if Status_Value /= Ok then
                     return Status_Value;
                  end if;
                  Item.Last_Channel_Success := SSH_Lib.Protocol.Channels.Encode_Channel_Success
                    (Item.Remote_Channel_Id);
                  if Is_Empty (Item.Last_Channel_Success) then
                     Mark_Channel_Failed (Item, Channel_Request_Failed);
                     return Channel_Request_Failed;
                  end if;
               end if;
            elsif SSH_Lib.Protocol.Channels.Request_Is_Exit_Signal (Request_Event) then
               if Item.Remote_Exit_Status_Known then
                  --  exit-signal is an alternate remote-program termination
                  --  result.  It must not rewrite an already observed
                  --  exit-status; preserve the first terminal result.
                  Mark_Channel_Failed (Item, Read_Failed);
                  return Read_Failed;
               end if;

               --  The public API exposes an integer exit code, not signal
               --  metadata.  Treat exit-signal as a deterministic nonzero
               --  command result so Git transport callers do not mistake a
               --  signal-terminated remote service for missing status.
               Item.Remote_Exit_Status_Known := True;
               Item.Remote_Exit_Status := 255;

               if Request_Event.Want_Reply then
                  Status_Value := Control_Send_Allowed
                    (Item, Channel_Request_Failed, Dirty_On_Timeout => True);
                  if Status_Value /= Ok then
                     return Status_Value;
                  end if;
                  Item.Last_Channel_Success := SSH_Lib.Protocol.Channels.Encode_Channel_Success
                    (Item.Remote_Channel_Id);
                  if Is_Empty (Item.Last_Channel_Success) then
                     Mark_Channel_Failed (Item, Channel_Request_Failed);
                     return Channel_Request_Failed;
                  end if;
               end if;
            elsif Request_Event.Want_Reply then
               Status_Value := Control_Send_Allowed
                 (Item, Channel_Request_Failed, Dirty_On_Timeout => True);
               if Status_Value /= Ok then
                  return Status_Value;
               end if;
               Item.Last_Channel_Failure := SSH_Lib.Protocol.Channels.Encode_Channel_Failure
                 (Item.Remote_Channel_Id);
               if Is_Empty (Item.Last_Channel_Failure) then
                  Mark_Channel_Failed (Item, Channel_Request_Failed);
                  return Channel_Request_Failed;
               end if;
            end if;

         when others =>
            Item.Dirty := True;
            Item.Current_State := Channel_Failed;
            return Read_Failed;
      end case;

      if Window_Data_Consumed
        and then not Item.Eof_Received
        and then not Item.Close_Received
        and then Item.Local_Remaining_Window < SSH_Lib.Protocol.Channels.Window_Adjust_Threshold
        and then Item.Local_Initial_Window_Size > Item.Local_Remaining_Window
      then
         Adjustment_Amount := Item.Local_Initial_Window_Size - Item.Local_Remaining_Window;
         Status_Value := Control_Send_Allowed
           (Item, Write_Failed, Dirty_On_Timeout => True);
         if Status_Value /= Ok then
            --  Window_Data_Consumed means stdout/stderr bytes have already
            --  been accepted and Local_Remaining_Window was debited.  If the
            --  automatic replenishing CHANNEL_WINDOW_ADJUST cannot be emitted,
            --  the peer and local channel flow-control views may diverge.
            --  Preserve already queued Git stdout for delivery, but make the
            --  channel terminal-failed so no later network read/write proceeds
            --  with inconsistent receive-window accounting.
            if Item.Last_Failure_Status = Ok then
               Item.Last_Failure_Status := Status_Value;
            end if;
            return Status_Value;
         end if;
         Item.Last_Window_Adjust := SSH_Lib.Protocol.Channels.Encode_Channel_Window_Adjust
           (Item.Remote_Channel_Id, Adjustment_Amount);
         if Is_Empty (Item.Last_Window_Adjust) then
            Item.Dirty := True;
            Item.Current_State := Channel_Failed;
            return Read_Failed;
         end if;
         Item.Local_Remaining_Window := Item.Local_Remaining_Window + Adjustment_Amount;
      end if;
      return Ok;
   exception
      when others =>
         Item.Dirty := True;
            Item.Current_State := Channel_Failed;
         return Internal_Error;
   end Dispatch_Inbound_Payload_For_Test;

   function Last_Channel_Data_Payload_For_Test
     (Item : Channel)
      return Stream_Element_Array is
   begin
      return To_Array (Item.Last_Channel_Data);
   end Last_Channel_Data_Payload_For_Test;

   function Last_EOF_Payload_For_Test
     (Item : Channel)
      return Stream_Element_Array is
   begin
      return To_Array (Item.Last_EOF);
   end Last_EOF_Payload_For_Test;

   function Last_Close_Payload_For_Test
     (Item : Channel)
      return Stream_Element_Array is
   begin
      return To_Array (Item.Last_Close);
   end Last_Close_Payload_For_Test;

   function Last_Window_Adjust_Payload_For_Test
     (Item : Channel)
      return Stream_Element_Array is
   begin
      return To_Array (Item.Last_Window_Adjust);
   end Last_Window_Adjust_Payload_For_Test;

   function Last_Channel_Success_Payload_For_Test
     (Item : Channel)
      return Stream_Element_Array is
   begin
      return To_Array (Item.Last_Channel_Success);
   end Last_Channel_Success_Payload_For_Test;

   function Last_Channel_Failure_Payload_For_Test
     (Item : Channel)
      return Stream_Element_Array is
   begin
      return To_Array (Item.Last_Channel_Failure);
   end Last_Channel_Failure_Payload_For_Test;

   function Outbound_Data_Byte_Count_For_Test (Item : Channel) return Natural is
   begin
      return Item.Outbound_Data_Bytes;
   end Outbound_Data_Byte_Count_For_Test;

   function Outbound_Data_Packet_Count_For_Test (Item : Channel) return Natural is
   begin
      return Item.Outbound_Data_Packets;
   end Outbound_Data_Packet_Count_For_Test;

   function Local_Remaining_Window_For_Test
     (Item : Channel)
      return Interfaces.Unsigned_32
   is
   begin
      return Item.Local_Remaining_Window;
   end Local_Remaining_Window_For_Test;

   function Remote_Remaining_Window_For_Test
     (Item : Channel)
      return Interfaces.Unsigned_32
   is
   begin
      return Item.Remote_Remaining_Window;
   end Remote_Remaining_Window_For_Test;

   procedure Set_Local_Window_For_Test
     (Item                  : in out Channel;
      Initial_Window_Size   : Interfaces.Unsigned_32;
      Remaining_Window_Size : Interfaces.Unsigned_32)
   is
   begin
      Item.Local_Initial_Window_Size := Initial_Window_Size;
      Item.Local_Remaining_Window := Remaining_Window_Size;
   end Set_Local_Window_For_Test;


   procedure Set_Write_Timeout_After_Partial_For_Test
     (Item  : in out Channel;
      Value : Boolean)
   is
   begin
      Item.Test_Write_Timeout_After_Partial := Value;
   end Set_Write_Timeout_After_Partial_For_Test;

   procedure Set_Send_EOF_Timeout_For_Test
     (Item  : in out Channel;
      Value : Boolean)
   is
   begin
      Item.Test_Send_EOF_Timeout := Value;
   end Set_Send_EOF_Timeout_For_Test;

   procedure Set_Remote_Close_After_Partial_For_Test
     (Item  : in out Channel;
      Value : Boolean)
   is
   begin
      Item.Test_Remote_Close_After_Partial := Value;
   end Set_Remote_Close_After_Partial_For_Test;

   procedure Set_Close_Timeout_For_Test
     (Item  : in out Channel;
      Value : Boolean)
   is
   begin
      Item.Test_Close_Timeout := Value;
   end Set_Close_Timeout_For_Test;

   procedure Set_Close_Exception_For_Cleanup_Test
     (Item  : in out Channel;
      Value : Boolean)
   is
   begin
      Item.Test_Close_Exception_For_Cleanup := Value;
   end Set_Close_Exception_For_Cleanup_Test;

   procedure Set_Timeouts_For_Test
     (Item             : in out Channel;
      Read_Timeout_MS  : Natural;
      Write_Timeout_MS : Natural)
   is
   begin
      Item.Read_Timeout_MS := Read_Timeout_MS;
      Item.Write_Timeout_MS := Write_Timeout_MS;
   end Set_Timeouts_For_Test;

   procedure Mark_Dirty_For_Test
     (Item   : in out Channel;
      Reason : CryptoLib.Errors.Status := CryptoLib.Errors.Read_Failed)
   is
   begin
      Item.Dirty := True;
      Item.Current_State := Channel_Failed;
      Item.Last_Failure_Status := Reason;
   end Mark_Dirty_For_Test;

   function Is_Dirty_For_Test (Item : Channel) return Boolean is
   begin
      return Item.Dirty;
   end Is_Dirty_For_Test;

   function Last_Failure_For_Test (Item : Channel) return Status is
   begin
      return Item.Last_Failure_Status;
   end Last_Failure_For_Test;


   procedure Enable_Live_Channel_IO_For_Test (Item : in out Channel) is
   begin
      Item.Live_Channel_IO_Enabled := True;
      SSH_Lib.Protocol.Protected_Packets.Reset (Item.Live_Outbound_State, Channel_Boundary_Key);
      SSH_Lib.Protocol.Protected_Packets.Reset (Item.Live_Inbound_State, Channel_Boundary_Key);
      Clear (Item.Live_Last_Protected_Outbound);
      Clear (Item.Live_Next_Protected_Inbound);
      Item.Live_Has_Protected_Inbound := False;
   exception
      when others =>
         Item.Live_Channel_IO_Enabled := False;
   end Enable_Live_Channel_IO_For_Test;

   function Queue_Protected_Inbound_For_Test
     (Item    : in out Channel;
      Payload : Stream_Element_Array)
      return Status
   is
      Peer_State : SSH_Lib.Protocol.Protected_Packets.Protected_State;
      Packet_Value : Packet_Buffer;
      Status_Value : Status;
   begin
      SSH_Lib.Protocol.Protected_Packets.Reset (Peer_State, Channel_Boundary_Key);
      SSH_Lib.Protocol.Protected_Packets.Set_Sequences_For_Test
        (Peer_State,
         Inbound_Value => 0,
         Outbound_Value => SSH_Lib.Protocol.Protected_Packets.Inbound_Sequence
           (Item.Live_Inbound_State));
      Status_Value := SSH_Lib.Protocol.Protected_Packets.Encode_Protected_Packet
        (Peer_State, Payload, Packet_Value, Use_Test_Padding => True, Test_Padding_Byte => 0);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Status_Value := Set (Item.Live_Next_Protected_Inbound, To_Array (Packet_Value));
      Item.Live_Has_Protected_Inbound := Status_Value = Ok;
      return Status_Value;
   exception
      when others =>
         return Internal_Error;
   end Queue_Protected_Inbound_For_Test;

   function Last_Protected_Outbound_For_Test
     (Item : Channel)
      return Stream_Element_Array is
   begin
      return To_Array (Item.Live_Last_Protected_Outbound);
   end Last_Protected_Outbound_For_Test;

   function Pending_Stdout_Length_For_Test (Item : Channel) return Natural is
   begin
      return Length (Item.Pending_Stdout);
   end Pending_Stdout_Length_For_Test;

   function Live_Channel_IO_Enabled_For_Test (Item : Channel) return Boolean is
   begin
      return Item.Live_Channel_IO_Enabled;
   end Live_Channel_IO_Enabled_For_Test;

   procedure Set_Background_Last_Status_For_Test
     (Item   : in out Channel;
      Status_Value : CryptoLib.Errors.Status)
   is
   begin
      Item.Background_Last_Status := Status_Value;
   end Set_Background_Last_Status_For_Test;

   procedure Set_Background_Running_For_Test
     (Item  : in out Channel;
      Value : Boolean)
   is
   begin
      Item.Background_Running := Value;
   end Set_Background_Running_For_Test;

   procedure Set_Background_Requested_For_Test
     (Item  : in out Channel;
      Value : Boolean)
   is
   begin
      Item.Background_Requested := Value;
   end Set_Background_Requested_For_Test;

   procedure Set_Stop_Background_Exception_For_Cleanup_Test
     (Item  : in out Channel;
      Value : Boolean)
   is
   begin
      Item.Test_Stop_Background_Exception_For_Cleanup := Value;
   end Set_Stop_Background_Exception_For_Cleanup_Test;

   procedure Set_Background_Task_Exception_For_Cleanup_Test
     (Item  : in out Channel;
      Value : Boolean)
   is
   begin
      Item.Test_Background_Task_Exception_For_Cleanup := Value;
   end Set_Background_Task_Exception_For_Cleanup_Test;

   procedure Set_Background_Drain_Terminal_Failure_For_Test
     (Item  : in out Channel;
      Value : Boolean)
   is
   begin
      Item.Test_Background_Drain_Terminal_Failure := Value;
   end Set_Background_Drain_Terminal_Failure_For_Test;

   procedure Set_Start_Background_Exception_For_Cleanup_Test
     (Item  : in out Channel;
      Value : Boolean)
   is
   begin
      Item.Test_Start_Background_Exception_For_Cleanup := Value;
   end Set_Start_Background_Exception_For_Cleanup_Test;

   function Pending_Stderr_Length_For_Test (Item : Channel) return Natural is
   begin
      return Length (Item.Pending_Stderr);
   end Pending_Stderr_Length_For_Test;
end SSH_Lib.Channels.Test_Support;
