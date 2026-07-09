with System;                              use System;
with System.Address_To_Access_Conversions;
with SSH_Lib.Protocol.Channels;
with SSH_Lib.Protocol.Failure_State;
with SSH_Lib.Protocol.Global_Requests;
with SSH_Lib.Protocol.Transport_Messages;
use SSH_Lib.Protocol.Transport_Messages;
with SSH_Lib.Sessions.Channel_IO;
with SSH_Lib.Sessions.Channel_Table;
with SSH_Lib.Sessions.State;
with SSH_Lib.Sessions.Live_Transcript;
with SSH_Lib.Sessions.Live_Transport;
with SSH_Lib.Protocol.Messages;

package body SSH_Lib.Channels is
   use Ada.Streams;
   use Ada.Strings.Unbounded;
   use CryptoLib.Errors;
   use SSH_Lib.Protocol.Buffers;
   use type Interfaces.Unsigned_32;
   use type SSH_Lib.Protocol.Channels.Exec_Reply;
   use type SSH_Lib.Sessions.Live_Attachment.Transcript_Access;

   package Session_Address_Conversions is new
     System.Address_To_Access_Conversions (SSH_Lib.Sessions.Session);
   use type Session_Address_Conversions.Object_Pointer;

   package Channel_Address_Conversions is new
     System.Address_To_Access_Conversions (Channel);
   use type Channel_Address_Conversions.Object_Pointer;

   X11_MIT_Magic_Cookie_Hex_Length : constant Natural := 32;

   Channel_Boundary_Key : constant Stream_Element_Array (1 .. 32) :=
     [1  => 16#43#,
      2  => 16#48#,
      3  => 16#41#,
      4  => 16#4E#,
      5  => 16#4E#,
      6  => 16#45#,
      7  => 16#4C#,
      8  => 16#2D#,
      9  => 16#53#,
      10 => 16#54#,
      11 => 16#52#,
      12 => 16#45#,
      13 => 16#41#,
      14 => 16#4D#,
      15 => 16#2D#,
      16 => 16#4B#,
      17 => 16#45#,
      18 => 16#59#,
      19 => 16#2D#,
      20 => 16#30#,
      21 => 16#30#,
      22 => 16#30#,
      23 => 16#30#,
      24 => 16#30#,
      25 => 16#30#,
      26 => 16#30#,
      27 => 16#30#,
      28 => 16#30#,
      29 => 16#30#,
      30 => 16#30#,
      31 => 16#30#,
      32 => 16#32#];

   function Hex_Value (Item : Character) return Integer is
   begin
      if Item in '0' .. '9' then
         return Character'Pos (Item) - Character'Pos ('0');
      elsif Item in 'a' .. 'f' then
         return 10 + Character'Pos (Item) - Character'Pos ('a');
      elsif Item in 'A' .. 'F' then
         return 10 + Character'Pos (Item) - Character'Pos ('A');
      else
         return 16;
      end if;
   end Hex_Value;

   function Valid_X11_MIT_Magic_Cookie (Cookie : String) return Boolean is
   begin
      if Cookie'Length /= X11_MIT_Magic_Cookie_Hex_Length then
         return False;
      end if;

      for Ch of Cookie loop
         if Hex_Value (Ch) > 15 then
            return False;
         end if;
      end loop;

      return True;
   exception
      when others =>
         return False;
   end Valid_X11_MIT_Magic_Cookie;

   function X11_MIT_Magic_Cookies_Match
     (Expected  : String;
      Presented : String)
      return Boolean
   is
      Difference : Integer := 0;
      Expected_Value : Integer;
      Presented_Value : Integer;
   begin
      for Offset in 0 .. X11_MIT_Magic_Cookie_Hex_Length - 1 loop
         if Expected'Length = X11_MIT_Magic_Cookie_Hex_Length then
            Expected_Value := Hex_Value (Expected (Expected'First + Offset));
         else
            Expected_Value := 16;
         end if;

         if Presented'Length = X11_MIT_Magic_Cookie_Hex_Length then
            Presented_Value :=
              Hex_Value (Presented (Presented'First + Offset));
         else
            Presented_Value := 16;
         end if;

         Difference := Difference + abs (Expected_Value - Presented_Value);
      end loop;

      return
        Difference = 0
        and then Valid_X11_MIT_Magic_Cookie (Expected)
        and then Valid_X11_MIT_Magic_Cookie (Presented);
   exception
      when others =>
         return False;
   end X11_MIT_Magic_Cookies_Match;

   procedure Reset_Live_Channel_IO (Item : in out Channel) is
   begin
      Item.Live_Channel_IO_Enabled := False;
      SSH_Lib.Protocol.Protected_Packets.Reset
        (Item.Live_Outbound_State, Channel_Boundary_Key);
      SSH_Lib.Protocol.Protected_Packets.Reset
        (Item.Live_Inbound_State, Channel_Boundary_Key);
      Clear (Item.Live_Last_Protected_Outbound);
      Clear (Item.Live_Next_Protected_Inbound);
      Item.Live_Has_Protected_Inbound := False;
      Item.Live_Transcript_Ptr := null;
      Item.Background_Requested := False;
      Item.Background_Running := False;
      Item.Background_Last_Status := Ok;
      Item.Owning_Session_Address := System.Null_Address;
   exception
      when others =>
         Item.Live_Channel_IO_Enabled := False;
   end Reset_Live_Channel_IO;

   procedure Clear_Transient_Buffers (Item : in out Channel) is
   begin
      --  These buffers may contain raw Git pkt-line or packfile bytes, stderr
      --  diagnostics, channel control packets, or payloads that were prepared
      --  immediately before a timeout/failure.  Clear all retained packet
      --  buffers during reset/close cleanup so a closed channel does not keep
      --  user payload bytes alive for later diagnostics or accidental reuse.
      Clear (Item.Pending_Stdout);
      Clear (Item.Pending_Stderr);
      Clear (Item.Last_Channel_Data);
      Clear (Item.Last_EOF);
      Clear (Item.Last_Close);
      Clear (Item.Last_Window_Adjust);
      Clear (Item.Last_Channel_Success);
      Clear (Item.Last_Channel_Failure);
      Clear (Item.Live_Last_Protected_Outbound);
      Clear (Item.Live_Next_Protected_Inbound);
   exception
      when others =>
         null;
   end Clear_Transient_Buffers;

   procedure Apply_Queued_Test_Stdout
     (Session : in out SSH_Lib.Sessions.Session; Item : in out Channel)
   is
      Pending_Data  : constant SSH_Lib.Protocol.Buffers.Packet_Buffer :=
        SSH_Lib.Sessions.Channel_Table.Take_Next_Channel_Stdout_For_Test
          (Session);
      Pending_Array : constant Stream_Element_Array := To_Array (Pending_Data);
      Status_Value  : Status;
   begin
      if Pending_Array'Length = 0 then
         return;
      end if;

      Status_Value := Append (Item.Pending_Stdout, Pending_Array);
      if Status_Value /= Ok then
         Item.Dirty := True;
         Item.Current_State := Channel_Failed;
         Item.Last_Failure_Status := Status_Value;
      end if;
   exception
      when others =>
         Item.Dirty := True;
         Item.Current_State := Channel_Failed;
         Item.Last_Failure_Status := Internal_Error;
   end Apply_Queued_Test_Stdout;

   procedure Reset_Channel (Item : out Channel) is
   begin
      Item.Current_State := Channel_Closed;
      Item.Allocated := False;
      Item.Channel_Open_Confirmed := False;
      Item.Exec_Request_Confirmed := False;
      Item.Local_Channel_Id := 0;
      Item.Remote_Channel_Id := 0;
      Item.Local_Initial_Window_Size := 0;
      Item.Local_Remaining_Window := 0;
      Item.Local_Maximum_Packet_Size := 0;
      Item.Remote_Remaining_Window := 0;
      Item.Remote_Maximum_Packet_Size := 0;
      Item.Eof_Sent := False;
      Item.Eof_Received := False;
      Item.Close_Sent := False;
      Item.Close_Received := False;
      Item.Remote_Exit_Status_Known := False;
      Item.Remote_Exit_Status := 0;
      Item.Owning_Session_Generation := 0;
      Clear_Transient_Buffers (Item);
      Reset_Live_Channel_IO (Item);
      Item.Background_Task := null;
      Item.Background_Requested := False;
      Item.Background_Running := False;
      Item.Background_Last_Status := Ok;
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
      Item.Test_Close_Exception_For_Cleanup := False;
      Item.Test_Stop_Background_Exception_For_Cleanup := False;
      Item.Test_Background_Task_Exception_For_Cleanup := False;
      Item.Test_Background_Drain_Terminal_Failure := False;
      Item.Test_Start_Background_Exception_For_Cleanup := False;
   end Reset_Channel;

   procedure Mark_Channel_Failed (Item : in out Channel; Status_Value : Status)
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

   procedure Release_Owning_Channel_Slot (Item : in out Channel) is
      Session_Ptr : Session_Address_Conversions.Object_Pointer := null;
   begin
      if Item.Allocated
        and then Item.Owning_Session_Address /= System.Null_Address
      then
         Session_Ptr :=
           Session_Address_Conversions.To_Pointer
             (Item.Owning_Session_Address);
         if Session_Ptr /= null
           and then
             SSH_Lib.Sessions.Channel_Table.Current_Generation
               (Session_Ptr.all)
             = Item.Owning_Session_Generation
         then
            SSH_Lib.Sessions.Channel_Table.Release
              (Session_Ptr.all, Item.Local_Channel_Id);
         end if;
      end if;
      Item.Allocated := False;
      Item.Owning_Session_Address := System.Null_Address;
      Item.Owning_Session_Generation := 0;
   exception
      when others =>
         --  Close must remain best-effort cleanup.  If the owning session has
         --  already been torn down or the saved address is no longer usable,
         --  make this channel handle locally closed and non-releasable rather
         --  than surfacing an exception from cleanup.
         Item.Allocated := False;
         Item.Owning_Session_Address := System.Null_Address;
         Item.Owning_Session_Generation := 0;
   end Release_Owning_Channel_Slot;

   function Owning_Session_Still_Current_Open (Item : Channel) return Boolean
   is
      Session_Ptr : Session_Address_Conversions.Object_Pointer := null;
   begin
      --  Test-only detached channels and already locally closed handles have
      --  no owning live session to validate here.  Open_Exec records a session
      --  address/generation for real handles; once Session.Close resets the
      --  channel table and advances the generation, further I/O on that stale
      --  handle must fail instead of continuing with locally retained channel
      --  state.
      if not Item.Allocated
        or else Item.Owning_Session_Address = System.Null_Address
      then
         return True;
      end if;

      Session_Ptr :=
        Session_Address_Conversions.To_Pointer (Item.Owning_Session_Address);
      if Session_Ptr = null then
         return False;
      end if;

      return
        SSH_Lib.Sessions.Channel_Table.Current_Generation (Session_Ptr.all)
        = Item.Owning_Session_Generation
        and then
          SSH_Lib.Sessions.Channel_Table.Contains
            (Session_Ptr.all, Item.Local_Channel_Id)
        and then
          SSH_Lib.Sessions.State.Is_Authenticated_Open (Session_Ptr.all);
   exception
      when others =>
         return False;
   end Owning_Session_Still_Current_Open;

   function Fail_Stale_Channel
     (Item : in out Channel; Status_Value : Status := Connection_Failed)
      return Status is
   begin
      --  A channel handle whose owning session generation no longer matches is
      --  stale.  Mark it failed so subsequent calls use the ordinary dirty
      --  failure mapping instead of replaying buffered channel state after the
      --  authenticated transport has been closed/reset.
      Mark_Channel_Failed (Item, Status_Value);
      return Status_Value;
   end Fail_Stale_Channel;

   function Control_Send_Allowed
     (Item : in out Channel; Failure_Code : Status; Dirty_On_Timeout : Boolean)
      return Status is
   begin
      if Item.Write_Timeout_MS = 0 then
         Item.Last_Failure_Status := Timeout;
         if Dirty_On_Timeout then
            Mark_Channel_Failed (Item, Timeout);
         end if;
         return Timeout;
      end if;
      if Item.Dirty or else Item.Current_State = Channel_Failed then
         return SSH_Lib.Protocol.Failure_State.Dirty_Channel_Request_Status;
      end if;
      return Ok;
   exception
      when others =>
         Mark_Channel_Failed (Item, Failure_Code);
         return Failure_Code;
   end Control_Send_Allowed;

   function Has_Attached_Live_Transcript (Item : Channel) return Boolean is
   begin
      return
        Item.Live_Channel_IO_Enabled and then Item.Live_Transcript_Ptr /= null;
   exception
      when others =>
         return False;
   end Has_Attached_Live_Transcript;

   function Send_Channel_Packet
     (Item : in out Channel; Payload : Packet_Buffer) return Status
   is
      Status_Value : Status;
   begin
      if Has_Attached_Live_Transcript (Item) then
         declare
            Session_Ptr : Session_Address_Conversions.Object_Pointer := null;
         begin
            if Item.Owning_Session_Address /= System.Null_Address then
               Session_Ptr :=
                 Session_Address_Conversions.To_Pointer
                   (Item.Owning_Session_Address);
            end if;
            if Session_Ptr /= null then
               Status_Value :=
                 SSH_Lib.Sessions.Live_Transport.Check_Automatic_Rekey
                   (Session_Ptr.all);
               if Status_Value /= Ok then
                  Mark_Channel_Failed (Item, Status_Value);
                  return Status_Value;
               end if;
            end if;
         end;

         Status_Value :=
           SSH_Lib.Sessions.Live_Transcript.Send_Protected_Packet
             (Item.Live_Transcript_Ptr.all, To_Array (Payload));
         if Status_Value = Ok then
            Status_Value :=
              Set
                (Item.Live_Last_Protected_Outbound,
                 SSH_Lib.Sessions.Live_Transcript.Last_Protected_Outbound
                   (Item.Live_Transcript_Ptr.all));
            if Status_Value = Ok
              and then Item.Owning_Session_Address /= System.Null_Address
            then
               declare
                  Session_Ptr :
                    constant Session_Address_Conversions.Object_Pointer :=
                      Session_Address_Conversions.To_Pointer
                        (Item.Owning_Session_Address);
               begin
                  if Session_Ptr /= null then
                     SSH_Lib.Sessions.Live_Transport.Note_Protected_Outbound
                       (Session_Ptr.all,
                        Length (Item.Live_Last_Protected_Outbound));
                  end if;
               end;
            end if;
         end if;
      elsif Item.Live_Channel_IO_Enabled then
         Status_Value :=
           SSH_Lib.Protocol.Protected_Packets.Encode_Protected_Packet
             (Item.Live_Outbound_State,
              To_Array (Payload),
              Item.Live_Last_Protected_Outbound,
              Use_Test_Padding  => True,
              Test_Padding_Byte => 16#00#);
      else
         Status_Value := Ok;
      end if;

      if Status_Value /= Ok then
         Mark_Channel_Failed (Item, Status_Value);
      end if;
      return Status_Value;
   exception
      when others =>
         Mark_Channel_Failed (Item, Internal_Error);
         return Internal_Error;
   end Send_Channel_Packet;

   function Read_Channel_Packet
     (Item : in out Channel; Payload : out Packet_Buffer) return Status
   is
      Status_Value : Status;
   begin
      Clear (Payload);
      if Has_Attached_Live_Transcript (Item) then
         Status_Value :=
           SSH_Lib.Sessions.Live_Transcript.Read_Protected_Packet
             (Item.Live_Transcript_Ptr.all, Payload);
         if Status_Value = Ok then
            Status_Value :=
              Set
                (Item.Live_Next_Protected_Inbound,
                 SSH_Lib.Sessions.Live_Transcript.Last_Protected_Inbound
                   (Item.Live_Transcript_Ptr.all));
            if Status_Value = Ok
              and then Item.Owning_Session_Address /= System.Null_Address
            then
               declare
                  Session_Ptr :
                    constant Session_Address_Conversions.Object_Pointer :=
                      Session_Address_Conversions.To_Pointer
                        (Item.Owning_Session_Address);
               begin
                  if Session_Ptr /= null then
                     SSH_Lib.Sessions.Live_Transport.Note_Protected_Inbound
                       (Session_Ptr.all,
                        Length (Item.Live_Next_Protected_Inbound));
                  end if;
               end;
            end if;
            Item.Live_Has_Protected_Inbound := False;
         end if;
      elsif Item.Live_Channel_IO_Enabled
        and then Item.Live_Has_Protected_Inbound
      then
         Status_Value :=
           SSH_Lib.Protocol.Protected_Packets.Decode_Protected_Packet
             (Item.Live_Inbound_State,
              To_Array (Item.Live_Next_Protected_Inbound),
              Payload,
              Failure_When_Malformed => Read_Failed);
         Clear (Item.Live_Next_Protected_Inbound);
         Item.Live_Has_Protected_Inbound := False;
      else
         Status_Value := Timeout;
      end if;

      if Status_Value /= Ok and then Status_Value /= Timeout then
         Mark_Channel_Failed (Item, Status_Value);
      end if;
      return Status_Value;
   exception
      when others =>
         Clear (Payload);
         Mark_Channel_Failed (Item, Internal_Error);
         return Internal_Error;
   end Read_Channel_Packet;

   function Handle_Peer_Initiated_Rekey
     (Item : in out Channel; Payload : Packet_Buffer) return Status
   is
      Session_Ptr : Session_Address_Conversions.Object_Pointer;
   begin
      if Item.Owning_Session_Address = System.Null_Address then
         Mark_Channel_Failed (Item, Handshake_Failed);
         return Handshake_Failed;
      end if;

      Session_Ptr :=
        Session_Address_Conversions.To_Pointer (Item.Owning_Session_Address);
      if Session_Ptr = null then
         Mark_Channel_Failed (Item, Handshake_Failed);
         return Handshake_Failed;
      end if;

      declare
         Status_Value : constant Status :=
           SSH_Lib.Sessions.Live_Transport.Rekey_With_Peer_Kexinit
             (Session_Ptr.all, Payload);
      begin
         if Status_Value /= Ok then
            Mark_Channel_Failed (Item, Status_Value);
         end if;
         return Status_Value;
      end;
   exception
      when others =>
         Mark_Channel_Failed (Item, Internal_Error);
         return Internal_Error;
   end Handle_Peer_Initiated_Rekey;

   function Dispatch_Non_Channel_Protected_Payload
     (Item : in out Channel; Payload : Packet_Buffer) return Status
   is
      Data          : constant Stream_Element_Array := To_Array (Payload);
      Request_Item  : SSH_Lib.Protocol.Global_Requests.Global_Request;
      Reply_Payload : Packet_Buffer;
      Status_Value  : Status;
   begin
      if Data'Length = 0 then
         return Read_Failed;
      end if;

      if Natural (Data (Data'First))
        = SSH_Lib.Protocol.Messages.SSH_MSG_KEXINIT
      then
         return Handle_Peer_Initiated_Rekey (Item, Payload);
      elsif Data (Data'First)
        = SSH_Lib.Protocol.Global_Requests.SSH_MSG_GLOBAL_REQUEST
      then
         Status_Value :=
           SSH_Lib.Protocol.Global_Requests.Parse_Global_Request
             (Data, Request_Item);
         if Status_Value /= Ok then
            return Read_Failed;
         end if;

         if Request_Item.Want_Reply then
            Reply_Payload :=
              SSH_Lib.Protocol.Global_Requests.Encode_Request_Failure;
            if Is_Empty (Reply_Payload) then
               return Write_Failed;
            end if;

            Status_Value := Send_Channel_Packet (Item, Reply_Payload);
            if Status_Value /= Ok then
               return Status_Value;
            end if;
         end if;
         return Ok;
      end if;

      if SSH_Lib.Protocol.Transport_Messages.Classify (Data)
        = SSH_Lib.Protocol.Transport_Messages.Transport_Disconnect
      then
         --  SSH_MSG_DISCONNECT is a terminal transport condition, not a
         --  channel-level short read.  Once it is observed while a channel
         --  operation is draining the protected stream, the channel must be
         --  marked failed so later Read_Some/Write/Send_EOF attempts cannot
         --  continue against a dead authenticated transport or replay Git
         --  bytes ambiguously.
         Mark_Channel_Failed (Item, Connection_Failed);
         return Connection_Failed;
      end if;

      if SSH_Lib
           .Protocol
           .Global_Requests
           .Ignorable_While_Waiting_For_Channel_Response (Data)
      then
         return Ok;
      end if;

      return Read_Failed;
   exception
      when others =>
         return Internal_Error;
   end Dispatch_Non_Channel_Protected_Payload;

   function Consume_Inbound_Payload_For_Test
     (Item : in out Channel; Payload : Stream_Element_Array) return Status;

   function Drain_Inbound_Until_Remote_Window_Open
     (Item : in out Channel) return Status
   is
      Decoded     : Packet_Buffer;
      Read_Status : Status;
   begin
      if Item.Remote_Remaining_Window > 0 then
         return Ok;
      end if;

      if Item.Dirty or else Item.Current_State = Channel_Failed then
         return SSH_Lib.Protocol.Failure_State.Dirty_Channel_Write_Status;
      end if;

      if not Item.Live_Channel_IO_Enabled
        or else
          not (Item.Live_Has_Protected_Inbound
               or else Has_Attached_Live_Transcript (Item))
      then
         return Timeout;
      end if;

      --  A long Git push can exhaust the peer receive window.  SSH flow
      --  control expects the sender to keep reading protected packets so it
      --  can observe CHANNEL_WINDOW_ADJUST while waiting to write more data.
      --  Drain a bounded number of inbound packets; this may also queue stdout
      --  or stderr, process peer close/EOF, service global requests, or run a
      --  peer-initiated rekey.  It must not spin forever on a malicious peer
      --  that never reopens the window.
      for Attempt_Count in 1 .. 64 loop
         Read_Status := Read_Channel_Packet (Item, Decoded);
         if Read_Status = Timeout then
            return Timeout;
         elsif Read_Status /= Ok then
            return Read_Status;
         end if;

         declare
            Decoded_Data : constant Stream_Element_Array := To_Array (Decoded);
         begin
            if Decoded_Data'Length > 0
              and then
                (Natural (Decoded_Data (Decoded_Data'First))
                 = SSH_Lib.Protocol.Messages.SSH_MSG_KEXINIT
                 or else
                   Decoded_Data (Decoded_Data'First)
                   = SSH_Lib.Protocol.Global_Requests.SSH_MSG_GLOBAL_REQUEST
                 or else
                   SSH_Lib
                     .Protocol
                     .Global_Requests
                     .Ignorable_While_Waiting_For_Channel_Response
                        (Decoded_Data)
                 or else
                   SSH_Lib.Protocol.Transport_Messages.Classify (Decoded_Data)
                   = SSH_Lib.Protocol.Transport_Messages.Transport_Disconnect)
            then
               Read_Status :=
                 Dispatch_Non_Channel_Protected_Payload (Item, Decoded);
            else
               Read_Status :=
                 Consume_Inbound_Payload_For_Test (Item, Decoded_Data);
            end if;
         end;

         if Read_Status /= Ok then
            return Read_Status;
         end if;

         if Item.Close_Received then
            Item.Last_Failure_Status := Write_Failed;
            return Write_Failed;
         end if;

         if Item.Remote_Exit_Status_Known then
            --  A remote exit-status/exit-signal means the exec'd Git service has
            --  already terminated.  While EOF is directional and still allows
            --  client writes, a terminal remote-program result must stop
            --  outbound stdin: additional pkt-line/packfile bytes cannot be
            --  consumed by the remote command.
            Item.Last_Failure_Status := Write_Failed;
            return Write_Failed;
         end if;

         if Item.Remote_Remaining_Window > 0 then
            return Ok;
         end if;
      end loop;

      Item.Last_Failure_Status := Timeout;
      return Timeout;
   exception
      when others =>
         Mark_Channel_Failed (Item, Internal_Error);
         return Internal_Error;
   end Drain_Inbound_Until_Remote_Window_Open;

   function Background_Drain_One (Item : in out Channel) return Status is
      Decoded     : Packet_Buffer;
      Read_Status : Status;
   begin
      if Item.Test_Background_Drain_Terminal_Failure then
         --  Pass 383 test hook: model an ordinary background drain failure
         --  returned from protected-packet/channel dispatch, not an exception.
         --  Production code below must mirror that terminal status into the
         --  channel failure diagnostic before the task exits.
         Item.Test_Background_Drain_Terminal_Failure := False;
         return Connection_Failed;
      end if;

      if Item.Dirty or else Item.Current_State = Channel_Failed then
         return
           SSH_Lib.Protocol.Failure_State.Dirty_Channel_Read_Status
             (Queued_Data_Available => Length (Item.Pending_Stdout) > 0);
      end if;

      if Item.Remote_Exit_Status_Known
        and then Length (Item.Pending_Stdout) = 0
      then
         --  The background reader is only a prefetch/drain helper for a live
         --  exec stream.  Once exit-status/exit-signal has finalized the
         --  remote Git command and no stdout remains queued, there is no more
         --  Version-facing byte stream to prefetch.  Stop cleanly instead of
         --  polling protected input forever for a later CHANNEL_CLOSE.
         return End_Of_Stream;
      end if;

      if not Item.Live_Channel_IO_Enabled
        or else
          not (Item.Live_Has_Protected_Inbound
               or else Has_Attached_Live_Transcript (Item))
      then
         return Timeout;
      end if;

      Read_Status := Read_Channel_Packet (Item, Decoded);
      if Read_Status /= Ok then
         return Read_Status;
      end if;

      declare
         Decoded_Data : constant Stream_Element_Array := To_Array (Decoded);
      begin
         if Decoded_Data'Length > 0
           and then
             (Natural (Decoded_Data (Decoded_Data'First))
              = SSH_Lib.Protocol.Messages.SSH_MSG_KEXINIT
              or else
                Decoded_Data (Decoded_Data'First)
                = SSH_Lib.Protocol.Global_Requests.SSH_MSG_GLOBAL_REQUEST
              or else
                SSH_Lib
                  .Protocol
                  .Global_Requests
                  .Ignorable_While_Waiting_For_Channel_Response (Decoded_Data)
              or else
                SSH_Lib.Protocol.Transport_Messages.Classify (Decoded_Data)
                = SSH_Lib.Protocol.Transport_Messages.Transport_Disconnect)
         then
            return Dispatch_Non_Channel_Protected_Payload (Item, Decoded);
         else
            return Consume_Inbound_Payload_For_Test (Item, Decoded_Data);
         end if;
      end;
   exception
      when others =>
         Mark_Channel_Failed (Item, Internal_Error);
         return Internal_Error;
   end Background_Drain_One;

   task body Background_Reader is
      Target               : Channel_Address_Conversions.Object_Pointer :=
        null;
      Target_Address_Value : System.Address := System.Null_Address;
      Status_Value         : Status := Ok;
   begin
      accept Start (Target_Address : System.Address) do
         Target_Address_Value := Target_Address;
      end Start;

      if Target_Address_Value /= System.Null_Address then
         Target :=
           Channel_Address_Conversions.To_Pointer (Target_Address_Value);
      end if;

      if Target /= null then
         Target.Background_Running := True;
         Target.Background_Last_Status := Ok;

         if Target.Test_Background_Task_Exception_For_Cleanup then
            --  Test-only fault injection for pass 382/394: model a background
            --  reader unwinding after it has already recorded either the
            --  precise protected-stream failure that foreground APIs must
            --  preserve, or a retained non-terminal timeout that cleanup must
            --  normalize rather than promote to Internal_Error.
            Target.Test_Background_Task_Exception_For_Cleanup := False;
            if Target.Background_Last_Status = Ok then
               Target.Background_Last_Status := Connection_Failed;
            end if;
            raise Program_Error;
         end if;

         loop
            select
               accept Stop;
               exit;
            else
               if not Target.Background_Requested
                 or else Target.Current_State = Channel_Closed
                 or else Target.Current_State = Channel_Failed
                 or else
                   (Target.Remote_Exit_Status_Known
                    and then Length (Target.Pending_Stdout) = 0)
               then
                  --  A terminal remote-program result closes the useful
                  --  background prefetch lifetime.  Read_Some still exposes
                  --  End_Of_Stream and Exit_Status remains observable; the
                  --  task must not continue draining post-status channel
                  --  traffic behind the caller's back.
                  exit;
               end if;

               Status_Value := Background_Drain_One (Target.all);
               if Status_Value = Timeout then
                  delay 0.010;
               elsif Status_Value /= Ok then
                  Target.Background_Last_Status := Status_Value;
                  if Status_Value /= Timeout then
                     --  Pass 383: normal background-reader terminal failures
                     --  must be mirrored immediately into Last_Failure_Status,
                     --  not only after a later foreground API call observes
                     --  Background_Last_Status.  This keeps Close/Exit_Status
                     --  diagnostics stable even if cleanup detaches live I/O
                     --  before another operation runs.
                     Target.Last_Failure_Status := Status_Value;
                     if Status_Value /= End_Of_Stream then
                        Target.Dirty := True;
                        Target.Current_State := Channel_Failed;
                     end if;
                  end if;
                  exit;
               elsif Target.Close_Received then
                  exit;
               else
                  delay 0.000;
               end if;
            end select;
         end loop;

         Target.Background_Running := False;
         Target.Background_Requested := False;
      end if;
   exception
      when others =>
         if Target /= null then
            declare
               Preserved_Background_Status : constant Status :=
                 Target.Background_Last_Status;
            begin
               Target.Background_Running := False;
               Target.Background_Requested := False;
               Target.Test_Background_Task_Exception_For_Cleanup := False;
               if Preserved_Background_Status /= Ok
                 and then Preserved_Background_Status /= Timeout
               then
                  --  Pass 382: if the helper had already captured the exact
                  --  protected-stream failure before an unexpected task unwind,
                  --  do not replace it with Internal_Error.  Foreground API
                  --  calls and Close/Exit_Status diagnostics should see the
                  --  original transport/protocol reason.
                  Target.Background_Last_Status := Preserved_Background_Status;
                  Mark_Channel_Failed
                    (Target.all, Preserved_Background_Status);
               elsif Preserved_Background_Status = Timeout then
                  --  Pass 394: Timeout is a bounded background prefetch miss,
                  --  not a terminal task-failure diagnostic.  If task unwind
                  --  cleanup sees only a retained timeout, normalize it to Ok
                  --  instead of promoting stale prefetch state to Internal_Error.
                  Target.Background_Last_Status := Ok;
                  Target.Last_Failure_Status := Ok;
               else
                  Target.Background_Last_Status := Internal_Error;
                  Mark_Channel_Failed (Target.all, Internal_Error);
               end if;
            end;
         end if;
   end Background_Reader;

   function Open_Exec_Internal
     (Session : in out SSH_Lib.Sessions.Session;
      Command : String;
      Item    : in out Channel;
      Environment : Environment_Variable_Array)
      return CryptoLib.Errors.Status
   is
      Local_Id           : Interfaces.Unsigned_32 := 0;
      Open_Payload       : Packet_Buffer;
      Exec_Payload       : Packet_Buffer;
      Open_Status        : Status := Channel_Open_Failed;
      Confirmation       : SSH_Lib.Protocol.Channels.Open_Confirmation;
      Failure_Info       : SSH_Lib.Protocol.Channels.Open_Failure;
      Open_Failure_Reply : Boolean := False;
      Exec_Reply_Value   : SSH_Lib.Protocol.Channels.Exec_Reply :=
        SSH_Lib.Protocol.Channels.Exec_Request_Failure;
      Status_Value       : Status;
      Allocation_Done    : Boolean := False;
   begin
      if not SSH_Lib.Protocol.Channels.Valid_Command (Command) then
         return Invalid_Command;
      end if;

      if not SSH_Lib.Sessions.State.Is_Authenticated_Open (Session) then
         return Channel_Open_Failed;
      end if;

      Reset_Channel (Item);

      Status_Value :=
        SSH_Lib.Sessions.Channel_Table.Allocate (Session, Local_Id);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Allocation_Done := True;

      Item.Allocated := True;
      Item.Current_State := Channel_Opening;
      Item.Local_Channel_Id := Local_Id;
      Item.Local_Initial_Window_Size :=
        SSH_Lib.Protocol.Channels.Default_Initial_Window_Size;
      Item.Local_Remaining_Window :=
        SSH_Lib.Protocol.Channels.Default_Initial_Window_Size;
      Item.Local_Maximum_Packet_Size :=
        SSH_Lib.Protocol.Channels.Default_Maximum_Packet_Size;
      Item.Owning_Session_Generation :=
        SSH_Lib.Sessions.Channel_Table.Current_Generation (Session);
      Item.Owning_Session_Address := Session'Address;
      Item.Read_Timeout_MS :=
        SSH_Lib.Sessions.Channel_Table.Session_Read_Timeout_MS (Session);
      Item.Write_Timeout_MS :=
        SSH_Lib.Sessions.Channel_Table.Session_Write_Timeout_MS (Session);
      if SSH_Lib.Sessions.Channel_Table.Live_Channel_IO_Enabled (Session) then
         Item.Live_Channel_IO_Enabled := True;
         SSH_Lib.Protocol.Protected_Packets.Reset
           (Item.Live_Outbound_State, Channel_Boundary_Key);
         SSH_Lib.Protocol.Protected_Packets.Reset
           (Item.Live_Inbound_State, Channel_Boundary_Key);
         if SSH_Lib.Sessions.Live_Attachment.Attached (Session) then
            Item.Live_Transcript_Ptr :=
              SSH_Lib.Sessions.Live_Attachment.Transcript (Session);
         end if;
      end if;

      Open_Payload :=
        SSH_Lib.Protocol.Channels.Encode_Channel_Open
          (Local_Id,
           SSH_Lib.Protocol.Channels.Default_Initial_Window_Size,
           SSH_Lib.Protocol.Channels.Default_Maximum_Packet_Size);
      if Is_Empty (Open_Payload) then
         SSH_Lib.Sessions.Channel_Table.Release (Session, Local_Id);
         Allocation_Done := False;
         Reset_Channel (Item);
         return Channel_Open_Failed;
      end if;

      Status_Value :=
        SSH_Lib.Sessions.Channel_Table.Send_Open_Payload
          (Session, Open_Payload);
      if Status_Value /= Ok then
         SSH_Lib.Sessions.Channel_Table.Release (Session, Local_Id);
         Allocation_Done := False;
         Reset_Channel (Item);
         if Status_Value = Write_Failed then
            return Write_Failed;
         else
            return Status_Value;
         end if;
      end if;

      declare
         Response_Buffer : Packet_Buffer;
      begin
         Status_Value :=
           SSH_Lib.Sessions.Channel_Table.Read_Open_Response
             (Session, Local_Id, Response_Buffer);
         if Status_Value /= Ok then
            SSH_Lib.Sessions.Channel_Table.Release (Session, Local_Id);
            Allocation_Done := False;
            Reset_Channel (Item);
            return Status_Value;
         end if;

         declare
            Response : constant Stream_Element_Array :=
              To_Array (Response_Buffer);
         begin
            if Response'Length = 0 then
               Open_Status := Channel_Open_Failed;
            elsif Classify (Response) = Transport_Disconnect then
               Open_Status := Connection_Failed;
            elsif Response (Response'First)
              = SSH_Lib.Protocol.Channels.SSH_MSG_CHANNEL_OPEN_CONFIRMATION
            then
               Open_Status :=
                 SSH_Lib.Protocol.Channels.Parse_Channel_Open_Confirmation
                   (Response, Local_Id, Confirmation);
            elsif Response (Response'First)
              = SSH_Lib.Protocol.Channels.SSH_MSG_CHANNEL_OPEN_FAILURE
            then
               Open_Failure_Reply := True;
               Open_Status :=
                 SSH_Lib.Protocol.Channels.Parse_Channel_Open_Failure
                   (Response, Local_Id, Failure_Info);
               if Open_Status = Ok then
                  Open_Status := Channel_Open_Failed;
               end if;
            else
               Open_Status := Channel_Open_Failed;
            end if;
         end;
      end;

      if Open_Status /= Ok then
         if not Open_Failure_Reply then
            SSH_Lib.Sessions.Channel_Table.Mark_Failed (Session, Open_Status);
         end if;
         SSH_Lib.Sessions.Channel_Table.Release (Session, Local_Id);
         Allocation_Done := False;
         Reset_Channel (Item);
         return Open_Status;
      end if;

      Item.Channel_Open_Confirmed := True;
      Item.Current_State := Channel_Opened;
      Item.Remote_Channel_Id := Confirmation.Sender_Channel;
      Item.Remote_Remaining_Window := Confirmation.Initial_Window_Size;
      Item.Remote_Maximum_Packet_Size := Confirmation.Maximum_Packet_Size;

      for Variable of Environment loop
         Status_Value :=
           Set_Environment
             (Session,
              Item,
              To_String (Variable.Name),
              To_String (Variable.Value));
         if Status_Value /= Ok then
            SSH_Lib.Sessions.Channel_Table.Release (Session, Local_Id);
            Allocation_Done := False;
            Reset_Channel (Item);
            return Status_Value;
         end if;
      end loop;

      Exec_Payload :=
        SSH_Lib.Protocol.Channels.Encode_Exec_Request
          (Item.Remote_Channel_Id, Command);
      if Is_Empty (Exec_Payload) then
         SSH_Lib.Sessions.Channel_Table.Release (Session, Local_Id);
         Allocation_Done := False;
         Reset_Channel (Item);
         return Channel_Request_Failed;
      end if;

      Item.Current_State := Channel_Exec_Requested;
      Status_Value :=
        SSH_Lib.Sessions.Channel_Table.Send_Exec_Payload
          (Session, Exec_Payload);
      if Status_Value /= Ok then
         SSH_Lib.Sessions.Channel_Table.Release (Session, Local_Id);
         Allocation_Done := False;
         Reset_Channel (Item);
         if Status_Value = Write_Failed then
            return Write_Failed;
         else
            return Status_Value;
         end if;
      end if;

      declare
         Response_Buffer : Packet_Buffer;
      begin
         Status_Value :=
           SSH_Lib.Sessions.Channel_Table.Read_Exec_Response
             (Session, Item.Local_Channel_Id, Response_Buffer);
         if Status_Value /= Ok then
            SSH_Lib.Sessions.Channel_Table.Release (Session, Local_Id);
            Allocation_Done := False;
            Reset_Channel (Item);
            return Status_Value;
         end if;

         declare
            Response : constant Stream_Element_Array :=
              To_Array (Response_Buffer);
         begin
            if Classify (Response) = Transport_Disconnect then
               Status_Value := Connection_Failed;
            else
               Status_Value :=
                 SSH_Lib.Protocol.Channels.Parse_Exec_Reply
                   (Response, Item.Local_Channel_Id, Exec_Reply_Value);
            end if;
         end;
      end;

      if Status_Value /= Ok then
         SSH_Lib.Sessions.Channel_Table.Mark_Failed (Session, Status_Value);
         SSH_Lib.Sessions.Channel_Table.Release (Session, Local_Id);
         Allocation_Done := False;
         Reset_Channel (Item);
         if Status_Value = Connection_Failed then
            return Connection_Failed;
         end if;
         return Channel_Request_Failed;
      elsif Exec_Reply_Value /= SSH_Lib.Protocol.Channels.Exec_Request_Success
      then
         SSH_Lib.Sessions.Channel_Table.Release (Session, Local_Id);
         Allocation_Done := False;
         Reset_Channel (Item);
         return Channel_Request_Failed;
      end if;

      Item.Exec_Request_Confirmed := True;
      declare
         Early_Window_Adjust : Interfaces.Unsigned_32 := 0;
      begin
         if SSH_Lib.Sessions.Channel_IO.Take_Pending_Window_Adjust
              (Session, Local_Id, Early_Window_Adjust)
         then
            if Interfaces.Unsigned_32'Last - Item.Remote_Remaining_Window
              < Early_Window_Adjust
            then
               Item.Remote_Remaining_Window := Interfaces.Unsigned_32'Last;
            else
               Item.Remote_Remaining_Window :=
                 Item.Remote_Remaining_Window + Early_Window_Adjust;
            end if;
         end if;
      end;
      Item.Current_State := Channel_Exec_Active;
      Apply_Queued_Test_Stdout (Session, Item);
      if Item.Dirty then
         declare
            Failure_Status : constant Status := Item.Last_Failure_Status;
         begin
            SSH_Lib.Sessions.Channel_Table.Mark_Failed
              (Session, Failure_Status);
            SSH_Lib.Sessions.Channel_Table.Release (Session, Local_Id);
            Allocation_Done := False;
            Reset_Channel (Item);
            return Failure_Status;
         end;
      end if;
      if SSH_Lib.Sessions.Channel_Table.Background_Channel_Reader_Enabled
           (Session)
      then
         Status_Value := Start_Background_Reader (Item);
         if Status_Value /= Ok then
            SSH_Lib.Sessions.Channel_Table.Mark_Failed (Session, Status_Value);
            SSH_Lib.Sessions.Channel_Table.Release (Session, Local_Id);
            Allocation_Done := False;
            Reset_Channel (Item);
            return Status_Value;
         end if;
      end if;
      return Ok;
   exception
      when others =>
         SSH_Lib.Sessions.Channel_Table.Mark_Failed (Session, Internal_Error);
         if Allocation_Done then
            SSH_Lib.Sessions.Channel_Table.Release (Session, Local_Id);
         end if;
         Reset_Channel (Item);
         return Internal_Error;
   end Open_Exec_Internal;

   function Open_Exec
     (Session : in out SSH_Lib.Sessions.Session;
      Command : String;
      Item    : in out Channel) return CryptoLib.Errors.Status
   is
   begin
      return Open_Exec_Internal (Session, Command, Item, Empty_Environment);
   end Open_Exec;

   function Open_Exec_With_Environment
     (Session     : in out SSH_Lib.Sessions.Session;
      Command     : String;
      Environment : Environment_Variable_Array;
      Item        : in out Channel)
      return CryptoLib.Errors.Status
   is
   begin
      return Open_Exec_Internal (Session, Command, Item, Environment);
   end Open_Exec_With_Environment;

   function Open_Subsystem_Internal
     (Session        : in out SSH_Lib.Sessions.Session;
      Subsystem_Name : String;
      Environment    : Environment_Variable_Array;
      Item           : in out Channel) return CryptoLib.Errors.Status
   is
      Local_Id           : Interfaces.Unsigned_32 := 0;
      Open_Payload       : Packet_Buffer;
      Exec_Payload       : Packet_Buffer;
      Open_Status        : Status := Channel_Open_Failed;
      Confirmation       : SSH_Lib.Protocol.Channels.Open_Confirmation;
      Failure_Info       : SSH_Lib.Protocol.Channels.Open_Failure;
      Open_Failure_Reply : Boolean := False;
      Exec_Reply_Value   : SSH_Lib.Protocol.Channels.Exec_Reply :=
        SSH_Lib.Protocol.Channels.Exec_Request_Failure;
      Status_Value       : Status;
      Allocation_Done    : Boolean := False;
   begin
      if not SSH_Lib.Protocol.Channels.Valid_Command (Subsystem_Name) then
         return Invalid_Command;
      end if;

      if not SSH_Lib.Sessions.State.Is_Authenticated_Open (Session) then
         return Channel_Open_Failed;
      end if;

      Reset_Channel (Item);

      Status_Value :=
        SSH_Lib.Sessions.Channel_Table.Allocate (Session, Local_Id);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Allocation_Done := True;

      Item.Allocated := True;
      Item.Current_State := Channel_Opening;
      Item.Local_Channel_Id := Local_Id;
      Item.Local_Initial_Window_Size :=
        SSH_Lib.Protocol.Channels.Default_Initial_Window_Size;
      Item.Local_Remaining_Window :=
        SSH_Lib.Protocol.Channels.Default_Initial_Window_Size;
      Item.Local_Maximum_Packet_Size :=
        SSH_Lib.Protocol.Channels.Default_Maximum_Packet_Size;
      Item.Owning_Session_Generation :=
        SSH_Lib.Sessions.Channel_Table.Current_Generation (Session);
      Item.Owning_Session_Address := Session'Address;
      Item.Read_Timeout_MS :=
        SSH_Lib.Sessions.Channel_Table.Session_Read_Timeout_MS (Session);
      Item.Write_Timeout_MS :=
        SSH_Lib.Sessions.Channel_Table.Session_Write_Timeout_MS (Session);
      if SSH_Lib.Sessions.Channel_Table.Live_Channel_IO_Enabled (Session) then
         Item.Live_Channel_IO_Enabled := True;
         SSH_Lib.Protocol.Protected_Packets.Reset
           (Item.Live_Outbound_State, Channel_Boundary_Key);
         SSH_Lib.Protocol.Protected_Packets.Reset
           (Item.Live_Inbound_State, Channel_Boundary_Key);
         if SSH_Lib.Sessions.Live_Attachment.Attached (Session) then
            Item.Live_Transcript_Ptr :=
              SSH_Lib.Sessions.Live_Attachment.Transcript (Session);
         end if;
      end if;

      Open_Payload :=
        SSH_Lib.Protocol.Channels.Encode_Channel_Open
          (Local_Id,
           SSH_Lib.Protocol.Channels.Default_Initial_Window_Size,
           SSH_Lib.Protocol.Channels.Default_Maximum_Packet_Size);
      if Is_Empty (Open_Payload) then
         SSH_Lib.Sessions.Channel_Table.Release (Session, Local_Id);
         Allocation_Done := False;
         Reset_Channel (Item);
         return Channel_Open_Failed;
      end if;

      Status_Value :=
        SSH_Lib.Sessions.Channel_Table.Send_Open_Payload
          (Session, Open_Payload);
      if Status_Value /= Ok then
         SSH_Lib.Sessions.Channel_Table.Release (Session, Local_Id);
         Allocation_Done := False;
         Reset_Channel (Item);
         if Status_Value = Write_Failed then
            return Write_Failed;
         else
            return Status_Value;
         end if;
      end if;

      declare
         Response_Buffer : Packet_Buffer;
      begin
         Status_Value :=
           SSH_Lib.Sessions.Channel_Table.Read_Open_Response
             (Session, Local_Id, Response_Buffer);
         if Status_Value /= Ok then
            SSH_Lib.Sessions.Channel_Table.Release (Session, Local_Id);
            Allocation_Done := False;
            Reset_Channel (Item);
            return Status_Value;
         end if;

         declare
            Response : constant Stream_Element_Array :=
              To_Array (Response_Buffer);
         begin
            if Response'Length = 0 then
               Open_Status := Channel_Open_Failed;
            elsif Classify (Response) = Transport_Disconnect then
               Open_Status := Connection_Failed;
            elsif Response (Response'First)
              = SSH_Lib.Protocol.Channels.SSH_MSG_CHANNEL_OPEN_CONFIRMATION
            then
               Open_Status :=
                 SSH_Lib.Protocol.Channels.Parse_Channel_Open_Confirmation
                   (Response, Local_Id, Confirmation);
            elsif Response (Response'First)
              = SSH_Lib.Protocol.Channels.SSH_MSG_CHANNEL_OPEN_FAILURE
            then
               Open_Failure_Reply := True;
               Open_Status :=
                 SSH_Lib.Protocol.Channels.Parse_Channel_Open_Failure
                   (Response, Local_Id, Failure_Info);
               if Open_Status = Ok then
                  Open_Status := Channel_Open_Failed;
               end if;
            else
               Open_Status := Channel_Open_Failed;
            end if;
         end;
      end;

      if Open_Status /= Ok then
         if not Open_Failure_Reply then
            SSH_Lib.Sessions.Channel_Table.Mark_Failed (Session, Open_Status);
         end if;
         SSH_Lib.Sessions.Channel_Table.Release (Session, Local_Id);
         Allocation_Done := False;
         Reset_Channel (Item);
         return Open_Status;
      end if;

      Item.Channel_Open_Confirmed := True;
      Item.Current_State := Channel_Opened;
      Item.Remote_Channel_Id := Confirmation.Sender_Channel;
      Item.Remote_Remaining_Window := Confirmation.Initial_Window_Size;
      Item.Remote_Maximum_Packet_Size := Confirmation.Maximum_Packet_Size;

      for Variable of Environment loop
         Status_Value :=
           Set_Environment
             (Session,
              Item,
              To_String (Variable.Name),
              To_String (Variable.Value));
         if Status_Value /= Ok then
            SSH_Lib.Sessions.Channel_Table.Release (Session, Local_Id);
            Allocation_Done := False;
            Reset_Channel (Item);
            return Status_Value;
         end if;
      end loop;

      Exec_Payload :=
        SSH_Lib.Protocol.Channels.Encode_Subsystem_Request
          (Item.Remote_Channel_Id, Subsystem_Name);
      if Is_Empty (Exec_Payload) then
         SSH_Lib.Sessions.Channel_Table.Release (Session, Local_Id);
         Allocation_Done := False;
         Reset_Channel (Item);
         return Channel_Request_Failed;
      end if;

      Item.Current_State := Channel_Exec_Requested;
      Status_Value :=
        SSH_Lib.Sessions.Channel_Table.Send_Exec_Payload
          (Session, Exec_Payload);
      if Status_Value /= Ok then
         SSH_Lib.Sessions.Channel_Table.Release (Session, Local_Id);
         Allocation_Done := False;
         Reset_Channel (Item);
         if Status_Value = Write_Failed then
            return Write_Failed;
         else
            return Status_Value;
         end if;
      end if;

      declare
         Response_Buffer : Packet_Buffer;
      begin
         Status_Value :=
           SSH_Lib.Sessions.Channel_Table.Read_Exec_Response
             (Session, Item.Local_Channel_Id, Response_Buffer);
         if Status_Value /= Ok then
            SSH_Lib.Sessions.Channel_Table.Release (Session, Local_Id);
            Allocation_Done := False;
            Reset_Channel (Item);
            return Status_Value;
         end if;

         declare
            Response : constant Stream_Element_Array :=
              To_Array (Response_Buffer);
         begin
            if Classify (Response) = Transport_Disconnect then
               Status_Value := Connection_Failed;
            else
               Status_Value :=
                 SSH_Lib.Protocol.Channels.Parse_Exec_Reply
                   (Response, Item.Local_Channel_Id, Exec_Reply_Value);
            end if;
         end;
      end;

      if Status_Value /= Ok then
         SSH_Lib.Sessions.Channel_Table.Mark_Failed (Session, Status_Value);
         SSH_Lib.Sessions.Channel_Table.Release (Session, Local_Id);
         Allocation_Done := False;
         Reset_Channel (Item);
         if Status_Value = Connection_Failed then
            return Connection_Failed;
         end if;
         return Channel_Request_Failed;
      elsif Exec_Reply_Value /= SSH_Lib.Protocol.Channels.Exec_Request_Success
      then
         SSH_Lib.Sessions.Channel_Table.Release (Session, Local_Id);
         Allocation_Done := False;
         Reset_Channel (Item);
         return Channel_Request_Failed;
      end if;

      Item.Exec_Request_Confirmed := True;
      declare
         Early_Window_Adjust : Interfaces.Unsigned_32 := 0;
      begin
         if SSH_Lib.Sessions.Channel_IO.Take_Pending_Window_Adjust
              (Session, Local_Id, Early_Window_Adjust)
         then
            if Interfaces.Unsigned_32'Last - Item.Remote_Remaining_Window
              < Early_Window_Adjust
            then
               Item.Remote_Remaining_Window := Interfaces.Unsigned_32'Last;
            else
               Item.Remote_Remaining_Window :=
                 Item.Remote_Remaining_Window + Early_Window_Adjust;
            end if;
         end if;
      end;
      Item.Current_State := Channel_Exec_Active;
      Apply_Queued_Test_Stdout (Session, Item);
      if Item.Dirty then
         declare
            Failure_Status : constant Status := Item.Last_Failure_Status;
         begin
            SSH_Lib.Sessions.Channel_Table.Mark_Failed
              (Session, Failure_Status);
            SSH_Lib.Sessions.Channel_Table.Release (Session, Local_Id);
            Allocation_Done := False;
            Reset_Channel (Item);
            return Failure_Status;
         end;
      end if;
      if SSH_Lib.Sessions.Channel_Table.Background_Channel_Reader_Enabled
           (Session)
      then
         Status_Value := Start_Background_Reader (Item);
         if Status_Value /= Ok then
            SSH_Lib.Sessions.Channel_Table.Mark_Failed (Session, Status_Value);
            SSH_Lib.Sessions.Channel_Table.Release (Session, Local_Id);
            Allocation_Done := False;
            Reset_Channel (Item);
            return Status_Value;
         end if;
      end if;
      return Ok;
   exception
      when others =>
         SSH_Lib.Sessions.Channel_Table.Mark_Failed (Session, Internal_Error);
         if Allocation_Done then
            SSH_Lib.Sessions.Channel_Table.Release (Session, Local_Id);
         end if;
         Reset_Channel (Item);
         return Internal_Error;
   end Open_Subsystem_Internal;

   function Open_Subsystem
     (Session        : in out SSH_Lib.Sessions.Session;
      Subsystem_Name : String;
      Item           : in out Channel) return CryptoLib.Errors.Status
   is
   begin
      return Open_Subsystem_Internal
        (Session, Subsystem_Name, Empty_Environment, Item);
   end Open_Subsystem;

   function Open_Subsystem_With_Environment
     (Session        : in out SSH_Lib.Sessions.Session;
      Subsystem_Name : String;
      Environment    : Environment_Variable_Array;
      Item           : in out Channel)
      return CryptoLib.Errors.Status
   is
   begin
      return Open_Subsystem_Internal
        (Session, Subsystem_Name, Environment, Item);
   end Open_Subsystem_With_Environment;

   function Open_Direct_TCPIP
     (Session            : in out SSH_Lib.Sessions.Session;
      Target_Host        : String;
      Target_Port        : Natural;
      Item               : in out Channel;
      Originator_Address : String := "127.0.0.1";
      Originator_Port    : Natural := 0)
      return CryptoLib.Errors.Status
   is
      Local_Id           : Interfaces.Unsigned_32 := 0;
      Open_Payload       : Packet_Buffer;
      Open_Status        : Status := Channel_Open_Failed;
      Confirmation       : SSH_Lib.Protocol.Channels.Open_Confirmation;
      Failure_Info       : SSH_Lib.Protocol.Channels.Open_Failure;
      Open_Failure_Reply : Boolean := False;
      Status_Value       : Status;
      Allocation_Done    : Boolean := False;
   begin
      if Target_Port = 0 or else Target_Port > 65_535
        or else Originator_Port > 65_535
      then
         return Invalid_Port;
      end if;

      Open_Payload :=
        SSH_Lib.Protocol.Channels.Encode_Direct_TCPIP_Open
          (0, Target_Host, Target_Port, Originator_Address, Originator_Port);
      if Is_Empty (Open_Payload) then
         return Invalid_Host;
      end if;

      if not SSH_Lib.Sessions.State.Is_Authenticated_Open (Session) then
         return Channel_Open_Failed;
      end if;

      Reset_Channel (Item);

      Status_Value :=
        SSH_Lib.Sessions.Channel_Table.Allocate (Session, Local_Id);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Allocation_Done := True;

      Item.Allocated := True;
      Item.Current_State := Channel_Opening;
      Item.Local_Channel_Id := Local_Id;
      Item.Local_Initial_Window_Size :=
        SSH_Lib.Protocol.Channels.Default_Initial_Window_Size;
      Item.Local_Remaining_Window :=
        SSH_Lib.Protocol.Channels.Default_Initial_Window_Size;
      Item.Local_Maximum_Packet_Size :=
        SSH_Lib.Protocol.Channels.Default_Maximum_Packet_Size;
      Item.Owning_Session_Generation :=
        SSH_Lib.Sessions.Channel_Table.Current_Generation (Session);
      Item.Owning_Session_Address := Session'Address;
      Item.Read_Timeout_MS :=
        SSH_Lib.Sessions.Channel_Table.Session_Read_Timeout_MS (Session);
      Item.Write_Timeout_MS :=
        SSH_Lib.Sessions.Channel_Table.Session_Write_Timeout_MS (Session);
      if SSH_Lib.Sessions.Channel_Table.Live_Channel_IO_Enabled (Session) then
         Item.Live_Channel_IO_Enabled := True;
         SSH_Lib.Protocol.Protected_Packets.Reset
           (Item.Live_Outbound_State, Channel_Boundary_Key);
         SSH_Lib.Protocol.Protected_Packets.Reset
           (Item.Live_Inbound_State, Channel_Boundary_Key);
         if SSH_Lib.Sessions.Live_Attachment.Attached (Session) then
            Item.Live_Transcript_Ptr :=
              SSH_Lib.Sessions.Live_Attachment.Transcript (Session);
         end if;
      end if;

      Open_Payload :=
        SSH_Lib.Protocol.Channels.Encode_Direct_TCPIP_Open
          (Local_Id,
           Target_Host,
           Target_Port,
           Originator_Address,
           Originator_Port,
           SSH_Lib.Protocol.Channels.Default_Initial_Window_Size,
           SSH_Lib.Protocol.Channels.Default_Maximum_Packet_Size);
      if Is_Empty (Open_Payload) then
         SSH_Lib.Sessions.Channel_Table.Release (Session, Local_Id);
         Allocation_Done := False;
         Reset_Channel (Item);
         return Invalid_Host;
      end if;

      Status_Value :=
        SSH_Lib.Sessions.Channel_Table.Send_Open_Payload
          (Session, Open_Payload);
      if Status_Value /= Ok then
         SSH_Lib.Sessions.Channel_Table.Release (Session, Local_Id);
         Allocation_Done := False;
         Reset_Channel (Item);
         if Status_Value = Write_Failed then
            return Write_Failed;
         else
            return Status_Value;
         end if;
      end if;

      declare
         Response_Buffer : Packet_Buffer;
      begin
         Status_Value :=
           SSH_Lib.Sessions.Channel_Table.Read_Open_Response
             (Session, Local_Id, Response_Buffer);
         if Status_Value /= Ok then
            SSH_Lib.Sessions.Channel_Table.Release (Session, Local_Id);
            Allocation_Done := False;
            Reset_Channel (Item);
            return Status_Value;
         end if;

         declare
            Response : constant Stream_Element_Array :=
              To_Array (Response_Buffer);
         begin
            if Response'Length = 0 then
               Open_Status := Channel_Open_Failed;
            elsif Classify (Response) = Transport_Disconnect then
               Open_Status := Connection_Failed;
            elsif Response (Response'First)
              = SSH_Lib.Protocol.Channels.SSH_MSG_CHANNEL_OPEN_CONFIRMATION
            then
               Open_Status :=
                 SSH_Lib.Protocol.Channels.Parse_Channel_Open_Confirmation
                   (Response, Local_Id, Confirmation);
            elsif Response (Response'First)
              = SSH_Lib.Protocol.Channels.SSH_MSG_CHANNEL_OPEN_FAILURE
            then
               Open_Failure_Reply := True;
               Open_Status :=
                 SSH_Lib.Protocol.Channels.Parse_Channel_Open_Failure
                   (Response, Local_Id, Failure_Info);
               if Open_Status = Ok then
                  Open_Status := Channel_Open_Failed;
               end if;
            else
               Open_Status := Channel_Open_Failed;
            end if;
         end;
      end;

      if Open_Status /= Ok then
         if not Open_Failure_Reply then
            SSH_Lib.Sessions.Channel_Table.Mark_Failed (Session, Open_Status);
         end if;
         SSH_Lib.Sessions.Channel_Table.Release (Session, Local_Id);
         Allocation_Done := False;
         Reset_Channel (Item);
         return Open_Status;
      end if;

      Item.Channel_Open_Confirmed := True;
      Item.Exec_Request_Confirmed := True;
      Item.Current_State := Channel_Exec_Active;
      Item.Remote_Channel_Id := Confirmation.Sender_Channel;
      Item.Remote_Remaining_Window := Confirmation.Initial_Window_Size;
      Item.Remote_Maximum_Packet_Size := Confirmation.Maximum_Packet_Size;
      return Ok;
   exception
      when others =>
         SSH_Lib.Sessions.Channel_Table.Mark_Failed (Session, Internal_Error);
         if Allocation_Done then
            SSH_Lib.Sessions.Channel_Table.Release (Session, Local_Id);
         end if;
         Reset_Channel (Item);
         return Internal_Error;
   end Open_Direct_TCPIP;

   function Accept_Forwarded_TCPIP
     (Session : in out SSH_Lib.Sessions.Session;
      Item    : in out Channel)
      return CryptoLib.Errors.Status
   is
      Local_Id        : Interfaces.Unsigned_32 := 0;
      Inbound_Payload : Packet_Buffer;
      Confirm_Payload : Packet_Buffer;
      Open_Request    : SSH_Lib.Protocol.Channels.Forwarded_TCPIP_Open;
      Status_Value    : Status;
      Allocation_Done : Boolean := False;
   begin
      if not SSH_Lib.Sessions.State.Is_Authenticated_Open (Session) then
         return Channel_Open_Failed;
      end if;

      Reset_Channel (Item);

      Status_Value :=
        SSH_Lib.Sessions.Channel_Table.Read_Inbound_Forwarded_Open
          (Session, Inbound_Payload);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Channels.Parse_Forwarded_TCPIP_Open
          (To_Array (Inbound_Payload), Open_Request);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      Status_Value :=
        SSH_Lib.Sessions.Channel_Table.Allocate (Session, Local_Id);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Allocation_Done := True;

      Confirm_Payload :=
        SSH_Lib.Protocol.Channels.Encode_Channel_Open_Confirmation
          (Open_Request.Sender_Channel,
           Local_Id,
           SSH_Lib.Protocol.Channels.Default_Initial_Window_Size,
           SSH_Lib.Protocol.Channels.Default_Maximum_Packet_Size);
      if Is_Empty (Confirm_Payload) then
         SSH_Lib.Sessions.Channel_Table.Release (Session, Local_Id);
         Allocation_Done := False;
         Reset_Channel (Item);
         return Channel_Open_Failed;
      end if;

      Status_Value :=
        SSH_Lib.Sessions.Channel_IO.Send_Channel_Payload
          (Session, Confirm_Payload);
      if Status_Value /= Ok then
         SSH_Lib.Sessions.Channel_Table.Release (Session, Local_Id);
         Allocation_Done := False;
         Reset_Channel (Item);
         return Status_Value;
      end if;

      Item.Allocated := True;
      Item.Channel_Open_Confirmed := True;
      Item.Exec_Request_Confirmed := True;
      Item.Current_State := Channel_Exec_Active;
      Item.Local_Channel_Id := Local_Id;
      Item.Remote_Channel_Id := Open_Request.Sender_Channel;
      Item.Local_Initial_Window_Size :=
        SSH_Lib.Protocol.Channels.Default_Initial_Window_Size;
      Item.Local_Remaining_Window :=
        SSH_Lib.Protocol.Channels.Default_Initial_Window_Size;
      Item.Local_Maximum_Packet_Size :=
        SSH_Lib.Protocol.Channels.Default_Maximum_Packet_Size;
      Item.Remote_Remaining_Window := Open_Request.Initial_Window_Size;
      Item.Remote_Maximum_Packet_Size := Open_Request.Maximum_Packet_Size;
      Item.Owning_Session_Generation :=
        SSH_Lib.Sessions.Channel_Table.Current_Generation (Session);
      Item.Owning_Session_Address := Session'Address;
      Item.Read_Timeout_MS :=
        SSH_Lib.Sessions.Channel_Table.Session_Read_Timeout_MS (Session);
      Item.Write_Timeout_MS :=
        SSH_Lib.Sessions.Channel_Table.Session_Write_Timeout_MS (Session);
      if SSH_Lib.Sessions.Channel_Table.Live_Channel_IO_Enabled (Session) then
         Item.Live_Channel_IO_Enabled := True;
         SSH_Lib.Protocol.Protected_Packets.Reset
           (Item.Live_Outbound_State, Channel_Boundary_Key);
         SSH_Lib.Protocol.Protected_Packets.Reset
           (Item.Live_Inbound_State, Channel_Boundary_Key);
         if SSH_Lib.Sessions.Live_Attachment.Attached (Session) then
            Item.Live_Transcript_Ptr :=
              SSH_Lib.Sessions.Live_Attachment.Transcript (Session);
         end if;
      end if;
      return Ok;
   exception
      when others =>
         SSH_Lib.Sessions.Channel_Table.Mark_Failed (Session, Internal_Error);
         if Allocation_Done then
            SSH_Lib.Sessions.Channel_Table.Release (Session, Local_Id);
         end if;
         Reset_Channel (Item);
         return Internal_Error;
   end Accept_Forwarded_TCPIP;

   function Accept_X11
     (Session : in out SSH_Lib.Sessions.Session;
      Item    : in out Channel)
      return CryptoLib.Errors.Status
   is
      Local_Id        : Interfaces.Unsigned_32 := 0;
      Inbound_Payload : Packet_Buffer;
      Confirm_Payload : Packet_Buffer;
      Open_Request    : SSH_Lib.Protocol.Channels.X11_Open;
      Status_Value    : Status;
      Allocation_Done : Boolean := False;
   begin
      if not SSH_Lib.Sessions.State.Is_Authenticated_Open (Session) then
         return Channel_Open_Failed;
      end if;

      Reset_Channel (Item);

      Status_Value :=
        SSH_Lib.Sessions.Channel_Table.Read_Inbound_Forwarded_Open
          (Session, Inbound_Payload);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Channels.Parse_X11_Open
          (To_Array (Inbound_Payload), Open_Request);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      Status_Value :=
        SSH_Lib.Sessions.Channel_Table.Allocate (Session, Local_Id);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Allocation_Done := True;

      Confirm_Payload :=
        SSH_Lib.Protocol.Channels.Encode_Channel_Open_Confirmation
          (Open_Request.Sender_Channel,
           Local_Id,
           SSH_Lib.Protocol.Channels.Default_Initial_Window_Size,
           SSH_Lib.Protocol.Channels.Default_Maximum_Packet_Size);
      if Is_Empty (Confirm_Payload) then
         SSH_Lib.Sessions.Channel_Table.Release (Session, Local_Id);
         Allocation_Done := False;
         Reset_Channel (Item);
         return Channel_Open_Failed;
      end if;

      Status_Value :=
        SSH_Lib.Sessions.Channel_IO.Send_Channel_Payload
          (Session, Confirm_Payload);
      if Status_Value /= Ok then
         SSH_Lib.Sessions.Channel_Table.Release (Session, Local_Id);
         Allocation_Done := False;
         Reset_Channel (Item);
         return Status_Value;
      end if;

      Item.Allocated := True;
      Item.Channel_Open_Confirmed := True;
      Item.Exec_Request_Confirmed := True;
      Item.Current_State := Channel_Exec_Active;
      Item.Local_Channel_Id := Local_Id;
      Item.Remote_Channel_Id := Open_Request.Sender_Channel;
      Item.Local_Initial_Window_Size :=
        SSH_Lib.Protocol.Channels.Default_Initial_Window_Size;
      Item.Local_Remaining_Window :=
        SSH_Lib.Protocol.Channels.Default_Initial_Window_Size;
      Item.Local_Maximum_Packet_Size :=
        SSH_Lib.Protocol.Channels.Default_Maximum_Packet_Size;
      Item.Remote_Remaining_Window := Open_Request.Initial_Window_Size;
      Item.Remote_Maximum_Packet_Size := Open_Request.Maximum_Packet_Size;
      Item.Owning_Session_Generation :=
        SSH_Lib.Sessions.Channel_Table.Current_Generation (Session);
      Item.Owning_Session_Address := Session'Address;
      Item.Read_Timeout_MS :=
        SSH_Lib.Sessions.Channel_Table.Session_Read_Timeout_MS (Session);
      Item.Write_Timeout_MS :=
        SSH_Lib.Sessions.Channel_Table.Session_Write_Timeout_MS (Session);
      if SSH_Lib.Sessions.Channel_Table.Live_Channel_IO_Enabled (Session) then
         Item.Live_Channel_IO_Enabled := True;
         SSH_Lib.Protocol.Protected_Packets.Reset
           (Item.Live_Outbound_State, Channel_Boundary_Key);
         SSH_Lib.Protocol.Protected_Packets.Reset
           (Item.Live_Inbound_State, Channel_Boundary_Key);
         if SSH_Lib.Sessions.Live_Attachment.Attached (Session) then
            Item.Live_Transcript_Ptr :=
              SSH_Lib.Sessions.Live_Attachment.Transcript (Session);
         end if;
      end if;
      return Ok;
   exception
      when others =>
         SSH_Lib.Sessions.Channel_Table.Mark_Failed (Session, Internal_Error);
         if Allocation_Done then
            SSH_Lib.Sessions.Channel_Table.Release (Session, Local_Id);
         end if;
         Reset_Channel (Item);
         return Internal_Error;
   end Accept_X11;

   function Open_Shell_Internal
     (Session : in out SSH_Lib.Sessions.Session;
      Environment : Environment_Variable_Array;
      Item    : in out Channel)
      return CryptoLib.Errors.Status
   is
      Local_Id           : Interfaces.Unsigned_32 := 0;
      Open_Payload       : Packet_Buffer;
      Shell_Payload      : Packet_Buffer;
      Open_Status        : Status := Channel_Open_Failed;
      Confirmation       : SSH_Lib.Protocol.Channels.Open_Confirmation;
      Failure_Info       : SSH_Lib.Protocol.Channels.Open_Failure;
      Open_Failure_Reply : Boolean := False;
      Reply_Value        : SSH_Lib.Protocol.Channels.Exec_Reply :=
        SSH_Lib.Protocol.Channels.Exec_Request_Failure;
      Status_Value       : Status;
      Allocation_Done    : Boolean := False;
   begin
      if not SSH_Lib.Sessions.State.Is_Authenticated_Open (Session) then
         return Channel_Open_Failed;
      end if;

      Reset_Channel (Item);

      Status_Value :=
        SSH_Lib.Sessions.Channel_Table.Allocate (Session, Local_Id);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Allocation_Done := True;

      Item.Allocated := True;
      Item.Current_State := Channel_Opening;
      Item.Local_Channel_Id := Local_Id;
      Item.Local_Initial_Window_Size :=
        SSH_Lib.Protocol.Channels.Default_Initial_Window_Size;
      Item.Local_Remaining_Window :=
        SSH_Lib.Protocol.Channels.Default_Initial_Window_Size;
      Item.Local_Maximum_Packet_Size :=
        SSH_Lib.Protocol.Channels.Default_Maximum_Packet_Size;
      Item.Owning_Session_Generation :=
        SSH_Lib.Sessions.Channel_Table.Current_Generation (Session);
      Item.Owning_Session_Address := Session'Address;
      Item.Read_Timeout_MS :=
        SSH_Lib.Sessions.Channel_Table.Session_Read_Timeout_MS (Session);
      Item.Write_Timeout_MS :=
        SSH_Lib.Sessions.Channel_Table.Session_Write_Timeout_MS (Session);
      if SSH_Lib.Sessions.Channel_Table.Live_Channel_IO_Enabled (Session) then
         Item.Live_Channel_IO_Enabled := True;
         SSH_Lib.Protocol.Protected_Packets.Reset
           (Item.Live_Outbound_State, Channel_Boundary_Key);
         SSH_Lib.Protocol.Protected_Packets.Reset
           (Item.Live_Inbound_State, Channel_Boundary_Key);
         if SSH_Lib.Sessions.Live_Attachment.Attached (Session) then
            Item.Live_Transcript_Ptr :=
              SSH_Lib.Sessions.Live_Attachment.Transcript (Session);
         end if;
      end if;

      Open_Payload :=
        SSH_Lib.Protocol.Channels.Encode_Channel_Open
          (Local_Id,
           SSH_Lib.Protocol.Channels.Default_Initial_Window_Size,
           SSH_Lib.Protocol.Channels.Default_Maximum_Packet_Size);
      if Is_Empty (Open_Payload) then
         SSH_Lib.Sessions.Channel_Table.Release (Session, Local_Id);
         Allocation_Done := False;
         Reset_Channel (Item);
         return Channel_Open_Failed;
      end if;

      Status_Value :=
        SSH_Lib.Sessions.Channel_Table.Send_Open_Payload
          (Session, Open_Payload);
      if Status_Value /= Ok then
         SSH_Lib.Sessions.Channel_Table.Release (Session, Local_Id);
         Allocation_Done := False;
         Reset_Channel (Item);
         return Status_Value;
      end if;

      declare
         Response_Buffer : Packet_Buffer;
      begin
         Status_Value :=
           SSH_Lib.Sessions.Channel_Table.Read_Open_Response
             (Session, Local_Id, Response_Buffer);
         if Status_Value /= Ok then
            SSH_Lib.Sessions.Channel_Table.Release (Session, Local_Id);
            Allocation_Done := False;
            Reset_Channel (Item);
            return Status_Value;
         end if;

         declare
            Response : constant Stream_Element_Array :=
              To_Array (Response_Buffer);
         begin
            if Response'Length = 0 then
               Open_Status := Channel_Open_Failed;
            elsif Classify (Response) = Transport_Disconnect then
               Open_Status := Connection_Failed;
            elsif Response (Response'First)
              = SSH_Lib.Protocol.Channels.SSH_MSG_CHANNEL_OPEN_CONFIRMATION
            then
               Open_Status :=
                 SSH_Lib.Protocol.Channels.Parse_Channel_Open_Confirmation
                   (Response, Local_Id, Confirmation);
            elsif Response (Response'First)
              = SSH_Lib.Protocol.Channels.SSH_MSG_CHANNEL_OPEN_FAILURE
            then
               Open_Failure_Reply := True;
               Open_Status :=
                 SSH_Lib.Protocol.Channels.Parse_Channel_Open_Failure
                   (Response, Local_Id, Failure_Info);
               if Open_Status = Ok then
                  Open_Status := Channel_Open_Failed;
               end if;
            else
               Open_Status := Channel_Open_Failed;
            end if;
         end;
      end;

      if Open_Status /= Ok then
         if not Open_Failure_Reply then
            SSH_Lib.Sessions.Channel_Table.Mark_Failed (Session, Open_Status);
         end if;
         SSH_Lib.Sessions.Channel_Table.Release (Session, Local_Id);
         Allocation_Done := False;
         Reset_Channel (Item);
         return Open_Status;
      end if;

      Item.Channel_Open_Confirmed := True;
      Item.Current_State := Channel_Opened;
      Item.Remote_Channel_Id := Confirmation.Sender_Channel;
      Item.Remote_Remaining_Window := Confirmation.Initial_Window_Size;
      Item.Remote_Maximum_Packet_Size := Confirmation.Maximum_Packet_Size;

      for Variable of Environment loop
         Status_Value :=
           Set_Environment
             (Session,
              Item,
              To_String (Variable.Name),
              To_String (Variable.Value));
         if Status_Value /= Ok then
            SSH_Lib.Sessions.Channel_Table.Release (Session, Local_Id);
            Allocation_Done := False;
            Reset_Channel (Item);
            return Status_Value;
         end if;
      end loop;

      Shell_Payload :=
        SSH_Lib.Protocol.Channels.Encode_Shell_Request
          (Item.Remote_Channel_Id);
      if Is_Empty (Shell_Payload) then
         SSH_Lib.Sessions.Channel_Table.Release (Session, Local_Id);
         Allocation_Done := False;
         Reset_Channel (Item);
         return Channel_Request_Failed;
      end if;

      Item.Current_State := Channel_Exec_Requested;
      Status_Value :=
        SSH_Lib.Sessions.Channel_Table.Send_Exec_Payload
          (Session, Shell_Payload);
      if Status_Value /= Ok then
         SSH_Lib.Sessions.Channel_Table.Release (Session, Local_Id);
         Allocation_Done := False;
         Reset_Channel (Item);
         return Status_Value;
      end if;

      declare
         Response_Buffer : Packet_Buffer;
      begin
         Status_Value :=
           SSH_Lib.Sessions.Channel_Table.Read_Exec_Response
             (Session, Item.Local_Channel_Id, Response_Buffer);
         if Status_Value /= Ok then
            SSH_Lib.Sessions.Channel_Table.Release (Session, Local_Id);
            Allocation_Done := False;
            Reset_Channel (Item);
            return Status_Value;
         end if;

         declare
            Response : constant Stream_Element_Array :=
              To_Array (Response_Buffer);
         begin
            if Classify (Response) = Transport_Disconnect then
               Status_Value := Connection_Failed;
            else
               Status_Value :=
                 SSH_Lib.Protocol.Channels.Parse_Exec_Reply
                   (Response, Item.Local_Channel_Id, Reply_Value);
            end if;
         end;
      end;

      if Status_Value /= Ok then
         SSH_Lib.Sessions.Channel_Table.Mark_Failed (Session, Status_Value);
         SSH_Lib.Sessions.Channel_Table.Release (Session, Local_Id);
         Allocation_Done := False;
         Reset_Channel (Item);
         if Status_Value = Connection_Failed then
            return Connection_Failed;
         end if;
         return Channel_Request_Failed;
      elsif Reply_Value /= SSH_Lib.Protocol.Channels.Exec_Request_Success then
         SSH_Lib.Sessions.Channel_Table.Release (Session, Local_Id);
         Allocation_Done := False;
         Reset_Channel (Item);
         return Channel_Request_Failed;
      end if;

      Item.Exec_Request_Confirmed := True;
      Item.Current_State := Channel_Exec_Active;
      Apply_Queued_Test_Stdout (Session, Item);
      if Item.Dirty then
         declare
            Failure_Status : constant Status := Item.Last_Failure_Status;
         begin
            SSH_Lib.Sessions.Channel_Table.Mark_Failed
              (Session, Failure_Status);
            SSH_Lib.Sessions.Channel_Table.Release (Session, Local_Id);
            Allocation_Done := False;
            Reset_Channel (Item);
            return Failure_Status;
         end;
      end if;
      return Ok;
   exception
      when others =>
         SSH_Lib.Sessions.Channel_Table.Mark_Failed (Session, Internal_Error);
         if Allocation_Done then
            SSH_Lib.Sessions.Channel_Table.Release (Session, Local_Id);
         end if;
         Reset_Channel (Item);
         return Internal_Error;
   end Open_Shell_Internal;

   function Open_Shell
     (Session : in out SSH_Lib.Sessions.Session;
      Item    : in out Channel)
      return CryptoLib.Errors.Status
   is
   begin
      return Open_Shell_Internal (Session, Empty_Environment, Item);
   end Open_Shell;

   function Open_Shell_With_Environment
     (Session     : in out SSH_Lib.Sessions.Session;
      Environment : Environment_Variable_Array;
      Item        : in out Channel)
      return CryptoLib.Errors.Status
   is
   begin
      return Open_Shell_Internal (Session, Environment, Item);
   end Open_Shell_With_Environment;

   function Open_PTY_Shell_Internal
     (Session        : in out SSH_Lib.Sessions.Session;
      Environment    : Environment_Variable_Array;
      Exec_Command   : String;
      Use_Exec       : Boolean;
      Item           : in out Channel;
      Terminal_Type  : String := "xterm";
      Columns        : Natural := 80;
      Rows           : Natural := 24;
      Width_Pixels   : Natural := 0;
      Height_Pixels  : Natural := 0;
      Terminal_Modes : Terminal_Mode_Array := Empty_Terminal_Modes)
      return CryptoLib.Errors.Status
   is
      Local_Id           : Interfaces.Unsigned_32 := 0;
      Open_Payload       : Packet_Buffer;
      PTY_Payload        : Packet_Buffer;
      Shell_Payload      : Packet_Buffer;
      Open_Status        : Status := Channel_Open_Failed;
      Confirmation       : SSH_Lib.Protocol.Channels.Open_Confirmation;
      Failure_Info       : SSH_Lib.Protocol.Channels.Open_Failure;
      Open_Failure_Reply : Boolean := False;
      Reply_Value        : SSH_Lib.Protocol.Channels.Exec_Reply :=
        SSH_Lib.Protocol.Channels.Exec_Request_Failure;
      Status_Value       : Status;
      Allocation_Done    : Boolean := False;

      function Read_Channel_Request_Reply return Status is
         Response_Buffer : Packet_Buffer;
         Response_Status : Status;
      begin
         Response_Status :=
           SSH_Lib.Sessions.Channel_Table.Read_Exec_Response
             (Session, Item.Local_Channel_Id, Response_Buffer);
         if Response_Status /= Ok then
            return Response_Status;
         end if;

         declare
            Response : constant Stream_Element_Array :=
              To_Array (Response_Buffer);
         begin
            if Classify (Response) = Transport_Disconnect then
               return Connection_Failed;
            end if;

            Response_Status :=
              SSH_Lib.Protocol.Channels.Parse_Exec_Reply
                (Response, Item.Local_Channel_Id, Reply_Value);
            if Response_Status /= Ok then
               return Response_Status;
            elsif Reply_Value /=
              SSH_Lib.Protocol.Channels.Exec_Request_Success
            then
               return Channel_Request_Failed;
            end if;
         end;

         return Ok;
      end Read_Channel_Request_Reply;
   begin
      if not SSH_Lib.Protocol.Channels.Valid_Command (Terminal_Type)
        or else Columns = 0
        or else Rows = 0
      then
         return Invalid_Command;
      elsif Use_Exec
        and then not SSH_Lib.Protocol.Channels.Valid_Command (Exec_Command)
      then
         return Invalid_Command;
      end if;

      if not SSH_Lib.Sessions.State.Is_Authenticated_Open (Session) then
         return Channel_Open_Failed;
      end if;

      Reset_Channel (Item);

      Status_Value :=
        SSH_Lib.Sessions.Channel_Table.Allocate (Session, Local_Id);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Allocation_Done := True;

      Item.Allocated := True;
      Item.Current_State := Channel_Opening;
      Item.Local_Channel_Id := Local_Id;
      Item.Local_Initial_Window_Size :=
        SSH_Lib.Protocol.Channels.Default_Initial_Window_Size;
      Item.Local_Remaining_Window :=
        SSH_Lib.Protocol.Channels.Default_Initial_Window_Size;
      Item.Local_Maximum_Packet_Size :=
        SSH_Lib.Protocol.Channels.Default_Maximum_Packet_Size;
      Item.Owning_Session_Generation :=
        SSH_Lib.Sessions.Channel_Table.Current_Generation (Session);
      Item.Owning_Session_Address := Session'Address;
      Item.Read_Timeout_MS :=
        SSH_Lib.Sessions.Channel_Table.Session_Read_Timeout_MS (Session);
      Item.Write_Timeout_MS :=
        SSH_Lib.Sessions.Channel_Table.Session_Write_Timeout_MS (Session);
      if SSH_Lib.Sessions.Channel_Table.Live_Channel_IO_Enabled (Session) then
         Item.Live_Channel_IO_Enabled := True;
         SSH_Lib.Protocol.Protected_Packets.Reset
           (Item.Live_Outbound_State, Channel_Boundary_Key);
         SSH_Lib.Protocol.Protected_Packets.Reset
           (Item.Live_Inbound_State, Channel_Boundary_Key);
         if SSH_Lib.Sessions.Live_Attachment.Attached (Session) then
            Item.Live_Transcript_Ptr :=
              SSH_Lib.Sessions.Live_Attachment.Transcript (Session);
         end if;
      end if;

      Open_Payload :=
        SSH_Lib.Protocol.Channels.Encode_Channel_Open
          (Local_Id,
           SSH_Lib.Protocol.Channels.Default_Initial_Window_Size,
           SSH_Lib.Protocol.Channels.Default_Maximum_Packet_Size);
      if Is_Empty (Open_Payload) then
         SSH_Lib.Sessions.Channel_Table.Release (Session, Local_Id);
         Allocation_Done := False;
         Reset_Channel (Item);
         return Channel_Open_Failed;
      end if;

      Status_Value :=
        SSH_Lib.Sessions.Channel_Table.Send_Open_Payload
          (Session, Open_Payload);
      if Status_Value /= Ok then
         SSH_Lib.Sessions.Channel_Table.Release (Session, Local_Id);
         Allocation_Done := False;
         Reset_Channel (Item);
         return Status_Value;
      end if;

      declare
         Response_Buffer : Packet_Buffer;
      begin
         Status_Value :=
           SSH_Lib.Sessions.Channel_Table.Read_Open_Response
             (Session, Local_Id, Response_Buffer);
         if Status_Value /= Ok then
            SSH_Lib.Sessions.Channel_Table.Release (Session, Local_Id);
            Allocation_Done := False;
            Reset_Channel (Item);
            return Status_Value;
         end if;

         declare
            Response : constant Stream_Element_Array :=
              To_Array (Response_Buffer);
         begin
            if Response'Length = 0 then
               Open_Status := Channel_Open_Failed;
            elsif Classify (Response) = Transport_Disconnect then
               Open_Status := Connection_Failed;
            elsif Response (Response'First)
              = SSH_Lib.Protocol.Channels.SSH_MSG_CHANNEL_OPEN_CONFIRMATION
            then
               Open_Status :=
                 SSH_Lib.Protocol.Channels.Parse_Channel_Open_Confirmation
                   (Response, Local_Id, Confirmation);
            elsif Response (Response'First)
              = SSH_Lib.Protocol.Channels.SSH_MSG_CHANNEL_OPEN_FAILURE
            then
               Open_Failure_Reply := True;
               Open_Status :=
                 SSH_Lib.Protocol.Channels.Parse_Channel_Open_Failure
                   (Response, Local_Id, Failure_Info);
               if Open_Status = Ok then
                  Open_Status := Channel_Open_Failed;
               end if;
            else
               Open_Status := Channel_Open_Failed;
            end if;
         end;
      end;

      if Open_Status /= Ok then
         if not Open_Failure_Reply then
            SSH_Lib.Sessions.Channel_Table.Mark_Failed (Session, Open_Status);
         end if;
         SSH_Lib.Sessions.Channel_Table.Release (Session, Local_Id);
         Allocation_Done := False;
         Reset_Channel (Item);
         return Open_Status;
      end if;

      Item.Channel_Open_Confirmed := True;
      Item.Current_State := Channel_Opened;
      Item.Remote_Channel_Id := Confirmation.Sender_Channel;
      Item.Remote_Remaining_Window := Confirmation.Initial_Window_Size;
      Item.Remote_Maximum_Packet_Size := Confirmation.Maximum_Packet_Size;

      for Variable of Environment loop
         Status_Value :=
           Set_Environment
             (Session,
              Item,
              To_String (Variable.Name),
              To_String (Variable.Value));
         if Status_Value /= Ok then
            SSH_Lib.Sessions.Channel_Table.Release (Session, Local_Id);
            Allocation_Done := False;
            Reset_Channel (Item);
            return Status_Value;
         end if;
      end loop;

      declare
         Protocol_Modes :
           SSH_Lib.Protocol.Channels.Terminal_Mode_Array
             (Terminal_Modes'Range);
      begin
         for Index in Terminal_Modes'Range loop
            Protocol_Modes (Index) :=
              (Opcode => Terminal_Modes (Index).Opcode,
               Value  => Terminal_Modes (Index).Value);
         end loop;

         PTY_Payload :=
           SSH_Lib.Protocol.Channels.Encode_PTY_Request
             (Item.Remote_Channel_Id,
              Terminal_Type,
              Interfaces.Unsigned_32 (Columns),
              Interfaces.Unsigned_32 (Rows),
              Interfaces.Unsigned_32 (Width_Pixels),
              Interfaces.Unsigned_32 (Height_Pixels),
              Protocol_Modes);
      end;
      if Is_Empty (PTY_Payload) then
         SSH_Lib.Sessions.Channel_Table.Release (Session, Local_Id);
         Allocation_Done := False;
         Reset_Channel (Item);
         return Channel_Request_Failed;
      end if;

      Item.Current_State := Channel_Exec_Requested;
      Status_Value :=
        SSH_Lib.Sessions.Channel_Table.Send_Exec_Payload
          (Session, PTY_Payload);
      if Status_Value /= Ok then
         SSH_Lib.Sessions.Channel_Table.Release (Session, Local_Id);
         Allocation_Done := False;
         Reset_Channel (Item);
         return Status_Value;
      end if;

      Status_Value := Read_Channel_Request_Reply;
      if Status_Value /= Ok then
         SSH_Lib.Sessions.Channel_Table.Mark_Failed (Session, Status_Value);
         SSH_Lib.Sessions.Channel_Table.Release (Session, Local_Id);
         Allocation_Done := False;
         Reset_Channel (Item);
         if Status_Value = Connection_Failed then
            return Connection_Failed;
         end if;
         return Channel_Request_Failed;
      end if;

      if Use_Exec then
         Shell_Payload :=
           SSH_Lib.Protocol.Channels.Encode_Exec_Request
             (Item.Remote_Channel_Id, Exec_Command);
      else
         Shell_Payload :=
           SSH_Lib.Protocol.Channels.Encode_Shell_Request
             (Item.Remote_Channel_Id);
      end if;
      if Is_Empty (Shell_Payload) then
         SSH_Lib.Sessions.Channel_Table.Release (Session, Local_Id);
         Allocation_Done := False;
         Reset_Channel (Item);
         return Channel_Request_Failed;
      end if;

      Status_Value :=
        SSH_Lib.Sessions.Channel_Table.Send_Exec_Payload
          (Session, Shell_Payload);
      if Status_Value /= Ok then
         SSH_Lib.Sessions.Channel_Table.Release (Session, Local_Id);
         Allocation_Done := False;
         Reset_Channel (Item);
         return Status_Value;
      end if;

      Status_Value := Read_Channel_Request_Reply;
      if Status_Value /= Ok then
         SSH_Lib.Sessions.Channel_Table.Mark_Failed (Session, Status_Value);
         SSH_Lib.Sessions.Channel_Table.Release (Session, Local_Id);
         Allocation_Done := False;
         Reset_Channel (Item);
         if Status_Value = Connection_Failed then
            return Connection_Failed;
         end if;
         return Channel_Request_Failed;
      end if;

      Item.Exec_Request_Confirmed := True;
      Item.Current_State := Channel_Exec_Active;
      Apply_Queued_Test_Stdout (Session, Item);
      if Item.Dirty then
         declare
            Failure_Status : constant Status := Item.Last_Failure_Status;
         begin
            SSH_Lib.Sessions.Channel_Table.Mark_Failed
              (Session, Failure_Status);
            SSH_Lib.Sessions.Channel_Table.Release (Session, Local_Id);
            Allocation_Done := False;
            Reset_Channel (Item);
            return Failure_Status;
         end;
      end if;
      return Ok;
   exception
      when others =>
         SSH_Lib.Sessions.Channel_Table.Mark_Failed (Session, Internal_Error);
         if Allocation_Done then
            SSH_Lib.Sessions.Channel_Table.Release (Session, Local_Id);
         end if;
         Reset_Channel (Item);
         return Internal_Error;
   end Open_PTY_Shell_Internal;

   function Open_PTY_Shell
     (Session        : in out SSH_Lib.Sessions.Session;
      Item           : in out Channel;
      Terminal_Type  : String := "xterm";
      Columns        : Natural := 80;
      Rows           : Natural := 24;
      Width_Pixels   : Natural := 0;
      Height_Pixels  : Natural := 0;
      Terminal_Modes : Terminal_Mode_Array := Empty_Terminal_Modes)
      return CryptoLib.Errors.Status
   is
   begin
      return Open_PTY_Shell_Internal
        (Session,
         Empty_Environment,
         "",
         False,
         Item,
         Terminal_Type,
         Columns,
         Rows,
         Width_Pixels,
         Height_Pixels,
         Terminal_Modes);
   end Open_PTY_Shell;

   function Open_PTY_Shell_With_Environment
     (Session        : in out SSH_Lib.Sessions.Session;
      Environment    : Environment_Variable_Array;
      Item           : in out Channel;
      Terminal_Type  : String := "xterm";
      Columns        : Natural := 80;
      Rows           : Natural := 24;
      Width_Pixels   : Natural := 0;
      Height_Pixels  : Natural := 0;
      Terminal_Modes : Terminal_Mode_Array := Empty_Terminal_Modes)
      return CryptoLib.Errors.Status
   is
   begin
      return Open_PTY_Shell_Internal
        (Session,
         Environment,
         "",
         False,
         Item,
         Terminal_Type,
         Columns,
         Rows,
         Width_Pixels,
         Height_Pixels,
         Terminal_Modes);
   end Open_PTY_Shell_With_Environment;

   function Open_PTY_Exec_With_Environment
     (Session        : in out SSH_Lib.Sessions.Session;
      Command        : String;
      Environment    : Environment_Variable_Array;
      Item           : in out Channel;
      Terminal_Type  : String := "xterm";
      Columns        : Natural := 80;
      Rows           : Natural := 24;
      Width_Pixels   : Natural := 0;
      Height_Pixels  : Natural := 0;
      Terminal_Modes : Terminal_Mode_Array := Empty_Terminal_Modes)
      return CryptoLib.Errors.Status
   is
   begin
      return Open_PTY_Shell_Internal
        (Session,
         Environment,
         Command,
         True,
         Item,
         Terminal_Type,
         Columns,
         Rows,
         Width_Pixels,
         Height_Pixels,
         Terminal_Modes);
   end Open_PTY_Exec_With_Environment;

   function Resize_PTY
     (Session       : in out SSH_Lib.Sessions.Session;
      Item          : in out Channel;
      Columns       : Natural;
      Rows          : Natural;
      Width_Pixels  : Natural := 0;
      Height_Pixels : Natural := 0)
      return CryptoLib.Errors.Status
   is
      Payload      : Packet_Buffer;
      Status_Value : Status;
   begin
      if Columns = 0 or else Rows = 0 then
         return Invalid_Command;
      end if;

      if not SSH_Lib.Sessions.State.Is_Authenticated_Open (Session) then
         return Channel_Open_Failed;
      end if;

      if not Owning_Session_Still_Current_Open (Item)
        or else Item.Owning_Session_Address /= Session'Address
        or else not SSH_Lib.Sessions.Channel_Table.Contains
          (Session, Item.Local_Channel_Id)
      then
         return Connection_Failed;
      end if;

      if Item.Dirty or else Item.Current_State = Channel_Failed then
         return SSH_Lib.Protocol.Failure_State.Dirty_Channel_Request_Status;
      end if;

      if Item.Current_State /= Channel_Exec_Active
        and then Item.Current_State /= Channel_Eof_Received
      then
         return Channel_Request_Failed;
      end if;

      Payload :=
        SSH_Lib.Protocol.Channels.Encode_Window_Change_Request
          (Item.Remote_Channel_Id,
           Interfaces.Unsigned_32 (Columns),
           Interfaces.Unsigned_32 (Rows),
           Interfaces.Unsigned_32 (Width_Pixels),
           Interfaces.Unsigned_32 (Height_Pixels));
      if Is_Empty (Payload) then
         return Channel_Request_Failed;
      end if;

      Status_Value :=
        SSH_Lib.Sessions.Channel_Table.Send_Exec_Payload (Session, Payload);
      if Status_Value /= Ok then
         if Status_Value /= Timeout then
            Item.Dirty := True;
            Item.Current_State := Channel_Failed;
            Item.Last_Failure_Status := Status_Value;
         end if;
         return Status_Value;
      end if;

      return Ok;
   exception
      when others =>
         Item.Dirty := True;
         Item.Current_State := Channel_Failed;
         Item.Last_Failure_Status := Internal_Error;
         SSH_Lib.Sessions.Channel_Table.Mark_Failed (Session, Internal_Error);
         return Internal_Error;
   end Resize_PTY;

   function Set_Environment
     (Session : in out SSH_Lib.Sessions.Session;
      Item    : in out Channel;
      Name    : String;
      Value   : String)
      return CryptoLib.Errors.Status
   is
      Payload          : Packet_Buffer;
      Status_Value     : Status;
      Exec_Reply_Value : SSH_Lib.Protocol.Channels.Exec_Reply :=
        SSH_Lib.Protocol.Channels.Exec_Request_Failure;
      Has_Tracked_Owner : constant Boolean :=
        Item.Owning_Session_Address /= System.Null_Address;
   begin
      Payload :=
        SSH_Lib.Protocol.Channels.Encode_Environment_Request
          (Item.Remote_Channel_Id, Name, Value);
      if Is_Empty (Payload) then
         return Invalid_Command;
      end if;

      if not SSH_Lib.Sessions.State.Is_Authenticated_Open (Session) then
         return Channel_Open_Failed;
      end if;

      if Has_Tracked_Owner
        and then
          (not Owning_Session_Still_Current_Open (Item)
           or else Item.Owning_Session_Address /= Session'Address
           or else not SSH_Lib.Sessions.Channel_Table.Contains
             (Session, Item.Local_Channel_Id))
      then
         return Connection_Failed;
      end if;

      if Item.Dirty or else Item.Current_State = Channel_Failed then
         return SSH_Lib.Protocol.Failure_State.Dirty_Channel_Request_Status;
      end if;

      if not Item.Channel_Open_Confirmed
        or else
          (Item.Current_State /= Channel_Opened
           and then Item.Current_State /= Channel_Exec_Requested)
      then
         return Channel_Request_Failed;
      end if;

      Status_Value :=
        SSH_Lib.Sessions.Channel_Table.Send_Exec_Payload (Session, Payload);
      if Status_Value /= Ok then
         if Status_Value /= Timeout then
            Mark_Channel_Failed (Item, Status_Value);
            SSH_Lib.Sessions.Channel_Table.Mark_Failed (Session, Status_Value);
         end if;
         return Status_Value;
      end if;

      declare
         Response_Buffer : Packet_Buffer;
      begin
         Status_Value :=
           SSH_Lib.Sessions.Channel_Table.Read_Exec_Response
             (Session, Item.Local_Channel_Id, Response_Buffer);
         if Status_Value /= Ok then
            if Status_Value /= Timeout then
               Mark_Channel_Failed (Item, Status_Value);
               SSH_Lib.Sessions.Channel_Table.Mark_Failed
                 (Session, Status_Value);
            end if;
            return Status_Value;
         end if;

         declare
            Response : constant Stream_Element_Array :=
              To_Array (Response_Buffer);
         begin
            if Classify (Response) = Transport_Disconnect then
               Mark_Channel_Failed (Item, Connection_Failed);
               SSH_Lib.Sessions.Channel_Table.Mark_Failed
                 (Session, Connection_Failed);
               return Connection_Failed;
            end if;

            Status_Value :=
              SSH_Lib.Protocol.Channels.Parse_Exec_Reply
                (Response, Item.Local_Channel_Id, Exec_Reply_Value);
         end;
      end;

      if Status_Value /= Ok then
         Mark_Channel_Failed (Item, Status_Value);
         SSH_Lib.Sessions.Channel_Table.Mark_Failed (Session, Status_Value);
         return Channel_Request_Failed;
      elsif Exec_Reply_Value
        /= SSH_Lib.Protocol.Channels.Exec_Request_Success
      then
         return Channel_Request_Failed;
      end if;

      return Ok;
   exception
      when others =>
         Mark_Channel_Failed (Item, Internal_Error);
         SSH_Lib.Sessions.Channel_Table.Mark_Failed (Session, Internal_Error);
         return Internal_Error;
   end Set_Environment;

   function Request_X11_Forwarding
     (Session           : in out SSH_Lib.Sessions.Session;
      Item              : in out Channel;
      Single_Connection : Boolean;
      Auth_Protocol     : String;
      Auth_Cookie       : String;
      Screen_Number     : Natural := 0)
      return CryptoLib.Errors.Status
   is
      Payload          : Packet_Buffer;
      Status_Value     : Status;
      Exec_Reply_Value : SSH_Lib.Protocol.Channels.Exec_Reply :=
        SSH_Lib.Protocol.Channels.Exec_Request_Failure;
      Has_Tracked_Owner : constant Boolean :=
        Item.Owning_Session_Address /= System.Null_Address;
   begin
      Payload :=
        SSH_Lib.Protocol.Channels.Encode_X11_Request
          (Item.Remote_Channel_Id,
           Single_Connection,
           Auth_Protocol,
           Auth_Cookie,
           Interfaces.Unsigned_32 (Screen_Number));
      if Is_Empty (Payload) then
         return Invalid_Command;
      end if;

      if not SSH_Lib.Sessions.State.Is_Authenticated_Open (Session) then
         return Channel_Open_Failed;
      end if;

      if Has_Tracked_Owner
        and then
          (not Owning_Session_Still_Current_Open (Item)
           or else Item.Owning_Session_Address /= Session'Address
           or else not SSH_Lib.Sessions.Channel_Table.Contains
             (Session, Item.Local_Channel_Id))
      then
         return Connection_Failed;
      end if;

      if Item.Dirty or else Item.Current_State = Channel_Failed then
         return SSH_Lib.Protocol.Failure_State.Dirty_Channel_Request_Status;
      end if;

      if not Item.Channel_Open_Confirmed
        or else
          (Item.Current_State /= Channel_Opened
           and then Item.Current_State /= Channel_Exec_Requested)
      then
         return Channel_Request_Failed;
      end if;

      Status_Value :=
        SSH_Lib.Sessions.Channel_Table.Send_Exec_Payload (Session, Payload);
      if Status_Value /= Ok then
         if Status_Value /= Timeout then
            Mark_Channel_Failed (Item, Status_Value);
            SSH_Lib.Sessions.Channel_Table.Mark_Failed (Session, Status_Value);
         end if;
         return Status_Value;
      end if;

      declare
         Response_Buffer : Packet_Buffer;
      begin
         Status_Value :=
           SSH_Lib.Sessions.Channel_Table.Read_Exec_Response
             (Session, Item.Local_Channel_Id, Response_Buffer);
         if Status_Value /= Ok then
            if Status_Value /= Timeout then
               Mark_Channel_Failed (Item, Status_Value);
               SSH_Lib.Sessions.Channel_Table.Mark_Failed
                 (Session, Status_Value);
            end if;
            return Status_Value;
         end if;

         declare
            Response : constant Stream_Element_Array :=
              To_Array (Response_Buffer);
         begin
            if Classify (Response) = Transport_Disconnect then
               Mark_Channel_Failed (Item, Connection_Failed);
               SSH_Lib.Sessions.Channel_Table.Mark_Failed
                 (Session, Connection_Failed);
               return Connection_Failed;
            end if;

            Status_Value :=
              SSH_Lib.Protocol.Channels.Parse_Exec_Reply
                (Response, Item.Local_Channel_Id, Exec_Reply_Value);
         end;
      end;

      if Status_Value /= Ok then
         Mark_Channel_Failed (Item, Status_Value);
         SSH_Lib.Sessions.Channel_Table.Mark_Failed (Session, Status_Value);
         return Channel_Request_Failed;
      elsif Exec_Reply_Value
        /= SSH_Lib.Protocol.Channels.Exec_Request_Success
      then
         return Channel_Request_Failed;
      end if;

      return Ok;
   exception
      when others =>
         Mark_Channel_Failed (Item, Internal_Error);
         SSH_Lib.Sessions.Channel_Table.Mark_Failed (Session, Internal_Error);
         return Internal_Error;
   end Request_X11_Forwarding;

   function Copy_From_Pending
     (Item   : in out Channel;
      Buffer : out Stream_Element_Array;
      Last   : out Stream_Element_Offset) return Status
   is
      Pending    : constant Stream_Element_Array :=
        To_Array (Item.Pending_Stdout);
      Copy_Count : Natural;
   begin
      if Buffer'First = Stream_Element_Offset'First then
         Last := Buffer'First;
      else
         Last := Buffer'First - 1;
      end if;

      if Buffer'Length = 0 then
         return Read_Failed;
      end if;

      if Pending'Length = 0 then
         return End_Of_Stream;
      end if;

      if Pending'Length < Buffer'Length then
         Copy_Count := Pending'Length;
      else
         Copy_Count := Buffer'Length;
      end if;

      for Offset_Value in 0 .. Copy_Count - 1 loop
         Buffer (Buffer'First + Stream_Element_Offset (Offset_Value)) :=
           Pending (Pending'First + Stream_Element_Offset (Offset_Value));
      end loop;
      Last := Buffer'First + Stream_Element_Offset (Copy_Count) - 1;

      Clear (Item.Pending_Stdout);
      if Copy_Count < Pending'Length then
         declare
            Remainder_First : constant Stream_Element_Offset :=
              Pending'First + Stream_Element_Offset (Copy_Count);
         begin
            if Set
                 (Item.Pending_Stdout,
                  Pending (Remainder_First .. Pending'Last))
              /= Ok
            then
               Item.Dirty := True;
               Item.Current_State := Channel_Failed;
               return Read_Failed;
            end if;
         end;
      end if;
      return Ok;
   exception
      when others =>
         if Buffer'First = Stream_Element_Offset'First then
            Last := Buffer'First;
         else
            Last := Buffer'First - 1;
         end if;
         Item.Dirty := True;
         Item.Current_State := Channel_Failed;
         return Internal_Error;
   end Copy_From_Pending;

   function Copy_From_Pending_Stderr
     (Item   : in out Channel;
      Buffer : out Stream_Element_Array;
      Last   : out Stream_Element_Offset) return Status
   is
      Pending    : constant Stream_Element_Array :=
        To_Array (Item.Pending_Stderr);
      Copy_Count : Natural;
   begin
      if Buffer'First = Stream_Element_Offset'First then
         Last := Buffer'First;
      else
         Last := Buffer'First - 1;
      end if;

      if Buffer'Length = 0 then
         return Read_Failed;
      end if;

      if Pending'Length = 0 then
         return End_Of_Stream;
      end if;

      if Pending'Length < Buffer'Length then
         Copy_Count := Pending'Length;
      else
         Copy_Count := Buffer'Length;
      end if;

      for Offset_Value in 0 .. Copy_Count - 1 loop
         Buffer (Buffer'First + Stream_Element_Offset (Offset_Value)) :=
           Pending (Pending'First + Stream_Element_Offset (Offset_Value));
      end loop;
      Last := Buffer'First + Stream_Element_Offset (Copy_Count) - 1;

      Clear (Item.Pending_Stderr);
      if Copy_Count < Pending'Length then
         declare
            Remainder_First : constant Stream_Element_Offset :=
              Pending'First + Stream_Element_Offset (Copy_Count);
         begin
            if Set
                 (Item.Pending_Stderr,
                  Pending (Remainder_First .. Pending'Last))
              /= Ok
            then
               Item.Dirty := True;
               Item.Current_State := Channel_Failed;
               return Read_Failed;
            end if;
         end;
      end if;
      return Ok;
   exception
      when others =>
         if Buffer'First = Stream_Element_Offset'First then
            Last := Buffer'First;
         else
            Last := Buffer'First - 1;
         end if;
         Item.Dirty := True;
         Item.Current_State := Channel_Failed;
         return Internal_Error;
   end Copy_From_Pending_Stderr;

   function Append_Stdout
     (Item : in out Channel; Data : Stream_Element_Array) return Status is
   begin
      if Data'Length = 0 then
         return Ok;
      end if;
      if Length (Item.Pending_Stdout) + Data'Length
        > SSH_Lib.Protocol.Buffers.Max_Packet_Length
      then
         Item.Dirty := True;
         Item.Current_State := Channel_Failed;
         return Read_Failed;
      end if;
      return Append (Item.Pending_Stdout, Data);
   exception
      when others =>
         Item.Dirty := True;
         Item.Current_State := Channel_Failed;
         return Internal_Error;
   end Append_Stdout;

   function Append_Stderr
     (Item : in out Channel; Data : Stream_Element_Array) return Status is
   begin
      if Data'Length = 0 then
         return Ok;
      end if;
      if Length (Item.Pending_Stderr) + Data'Length
        > SSH_Lib.Protocol.Buffers.Max_Packet_Length
      then
         Item.Dirty := True;
         Item.Current_State := Channel_Failed;
         return Read_Failed;
      end if;
      return Append (Item.Pending_Stderr, Data);
   exception
      when others =>
         Item.Dirty := True;
         Item.Current_State := Channel_Failed;
         return Internal_Error;
   end Append_Stderr;

   function Consume_Inbound_Payload_For_Test
     (Item : in out Channel; Payload : Stream_Element_Array) return Status
   is
      Data_Event           : SSH_Lib.Protocol.Channels.Channel_Data_Event;
      Extended_Event       :
        SSH_Lib.Protocol.Channels.Channel_Extended_Data_Event;
      Window_Event         :
        SSH_Lib.Protocol.Channels.Channel_Window_Adjust_Event;
      Request_Event        : SSH_Lib.Protocol.Channels.Channel_Request_Event;
      Status_Value         : Status;
      Data_Length          : Natural;
      Adjustment_Amount    : Interfaces.Unsigned_32;
      Window_Data_Consumed : Boolean := False;
   begin
      if Payload'Length = 0 then
         Item.Dirty := True;
         Item.Current_State := Channel_Failed;
         return Read_Failed;
      end if;

      case Payload (Payload'First) is
         when SSH_Lib.Protocol.Channels.SSH_MSG_CHANNEL_DATA          =>
            if not Item.Exec_Request_Confirmed then
               --  Git stdout bytes are only valid after the exec request has
               --  been accepted.  Do not let authenticated channel data race
               --  ahead of CHANNEL_SUCCESS and enter the pkt-line/packfile
               --  stream before Open_Exec has actually completed.
               Mark_Channel_Failed (Item, Read_Failed);
               return Read_Failed;
            elsif Item.Remote_Exit_Status_Known then
               --  exit-status/exit-signal is the terminal remote-program
               --  result for the exec request.  Channel data ordered after that
               --  result would append bytes to the Git pkt-line/packfile stream
               --  after command termination has already been observed.
               Mark_Channel_Failed (Item, Read_Failed);
               return Read_Failed;
            elsif Item.Eof_Received
              or else Item.Close_Sent
              or else Item.Close_Received
            then
               --  RFC 4254 EOF means no more data will be sent on the
               --  channel, and CHANNEL_CLOSE is terminal once either side has
               --  sent it.  CHANNEL_DATA after EOF or after local/peer close is
               --  a protocol violation.  Accepting it would let a peer append
               --  bytes to a Git pkt-line/packfile stream after the caller has
               --  observed end-of-stream or initiated channel teardown.
               Mark_Channel_Failed (Item, Read_Failed);
               return Read_Failed;
            end if;

            Status_Value :=
              SSH_Lib.Protocol.Channels.Parse_Channel_Data
                (Payload, Item.Local_Channel_Id, Data_Event);
            if Status_Value /= Ok then
               Item.Dirty := True;
               Item.Current_State := Channel_Failed;
               return Read_Failed;
            end if;
            declare
               Data_Value : constant Stream_Element_Array :=
                 To_Array (Data_Event.Data);
            begin
               Data_Length := Data_Value'Length;
               if Interfaces.Unsigned_32 (Data_Length)
                 > Item.Local_Maximum_Packet_Size
               then
                  --  The peer must not send a channel data payload larger
                  --  than the maximum packet size this side advertised when
                  --  the channel was opened.  Reject it before consuming
                  --  receive-window credit or appending bytes to the Git
                  --  stdout stream.
                  Mark_Channel_Failed (Item, Read_Failed);
                  return Read_Failed;
               end if;
               if Length (Item.Pending_Stdout) + Data_Length
                 > SSH_Lib.Protocol.Buffers.Max_Packet_Length
               then
                  --  Reject a stdout fragment that cannot be queued before
                  --  consuming SSH receive-window credit.  The peer must not
                  --  shrink this side's window with bytes that are discarded
                  --  because the Version-facing stdout buffer is already full.
                  Mark_Channel_Failed (Item, Read_Failed);
                  return Read_Failed;
               end if;
               if Interfaces.Unsigned_32 (Data_Length)
                 > Item.Local_Remaining_Window
               then
                  Item.Dirty := True;
                  Item.Current_State := Channel_Failed;
                  return Read_Failed;
               end if;
               Item.Local_Remaining_Window :=
                 Item.Local_Remaining_Window
                 - Interfaces.Unsigned_32 (Data_Length);
               Window_Data_Consumed := Data_Length > 0;
               Status_Value := Append_Stdout (Item, Data_Value);
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
               --  Extended data is also ordered channel data.  Do not accept
               --  stderr after the remote program result has already been
               --  recorded for the exec channel.
               Mark_Channel_Failed (Item, Read_Failed);
               return Read_Failed;
            elsif Item.Eof_Received
              or else Item.Close_Sent
              or else Item.Close_Received
            then
               --  Extended data consumes the same channel window as stdout.
               --  Treat stderr after EOF or local/peer close as the same
               --  terminal protocol violation as ordinary data after EOF/close.
               Mark_Channel_Failed (Item, Read_Failed);
               return Read_Failed;
            end if;

            Status_Value :=
              SSH_Lib.Protocol.Channels.Parse_Channel_Extended_Data
                (Payload, Item.Local_Channel_Id, Extended_Event);
            if Status_Value /= Ok then
               Item.Dirty := True;
               Item.Current_State := Channel_Failed;
               return Read_Failed;
            end if;
            declare
               Data_Value : constant Stream_Element_Array :=
                 To_Array (Extended_Event.Data);
            begin
               Data_Length := Data_Value'Length;
               if Extended_Event.Data_Type_Code
                 /= SSH_Lib.Protocol.Channels.Extended_Data_Stderr
               then
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
               if Interfaces.Unsigned_32 (Data_Length)
                 > Item.Local_Maximum_Packet_Size
               then
                  --  Extended data consumes the same channel receive packet
                  --  budget as ordinary channel data.  Do not silently accept
                  --  oversized stderr fragments, because that violates the
                  --  channel maximum-packet-size contract and can desynchronise
                  --  flow-control accounting for protected Git diagnostics.
                  Mark_Channel_Failed (Item, Read_Failed);
                  return Read_Failed;
               end if;
               if Length (Item.Pending_Stderr) + Data_Length
                 > SSH_Lib.Protocol.Buffers.Max_Packet_Length
               then
                  --  Reject stderr that cannot be retained before consuming
                  --  receive-window credit.  Diagnostic extended data is still
                  --  authenticated channel data; discarding it must not also
                  --  debit the local SSH receive window.
                  Mark_Channel_Failed (Item, Read_Failed);
                  return Read_Failed;
               end if;
               if Interfaces.Unsigned_32 (Data_Length)
                 > Item.Local_Remaining_Window
               then
                  Item.Dirty := True;
                  Item.Current_State := Channel_Failed;
                  return Read_Failed;
               end if;
               Item.Local_Remaining_Window :=
                 Item.Local_Remaining_Window
                 - Interfaces.Unsigned_32 (Data_Length);
               Window_Data_Consumed := Data_Length > 0;

               --  Multiple SSH_MSG_CHANNEL_EXTENDED_DATA packets form a
               --  single authenticated stderr stream.  Preserve earlier
               --  diagnostic bytes instead of replacing them with the latest
               --  packet; otherwise a Git server that emits stderr in chunks
               --  would lose all but the last protected diagnostic fragment.
               Status_Value := Append_Stderr (Item, Data_Value);
               if Status_Value /= Ok then
                  return Status_Value;
               end if;
            end;

         when SSH_Lib.Protocol.Channels.SSH_MSG_CHANNEL_WINDOW_ADJUST =>
            Status_Value :=
              SSH_Lib.Protocol.Channels.Parse_Channel_Window_Adjust
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

            if Interfaces.Unsigned_32'Last - Item.Remote_Remaining_Window
              < Window_Event.Bytes_To_Add
            then
               Item.Dirty := True;
               Item.Current_State := Channel_Failed;
               return Write_Failed;
            end if;
            Item.Remote_Remaining_Window :=
              Item.Remote_Remaining_Window + Window_Event.Bytes_To_Add;

         when SSH_Lib.Protocol.Channels.SSH_MSG_CHANNEL_EOF           =>
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
               --  CHANNEL_EOF is a receive-side half-close marker.  Once the
               --  peer has declared that no more stdout/stderr will be sent, a
               --  second EOF is not new stream state and must not be accepted as
               --  another clean teardown event.
               Mark_Channel_Failed (Item, Read_Failed);
               return Read_Failed;
            end if;

            Status_Value :=
              SSH_Lib.Protocol.Channels.Parse_Channel_One_Id
                (Payload,
                 SSH_Lib.Protocol.Channels.SSH_MSG_CHANNEL_EOF,
                 Item.Local_Channel_Id);
            if Status_Value /= Ok then
               Item.Dirty := True;
               Item.Current_State := Channel_Failed;
               return Read_Failed;
            end if;
            Item.Eof_Received := True;
            if Item.Current_State = Channel_Exec_Active then
               Item.Current_State := Channel_Eof_Received;
            end if;

         when SSH_Lib.Protocol.Channels.SSH_MSG_CHANNEL_CLOSE         =>
            if Item.Close_Received then
               --  CHANNEL_CLOSE is terminal for the remote side of the channel.
               --  A duplicate peer close must not replay cleanup, overwrite
               --  retained close payloads, or otherwise mutate the final channel
               --  state after the first close has been observed.
               Mark_Channel_Failed (Item, Read_Failed);
               return Read_Failed;
            end if;

            Status_Value :=
              SSH_Lib.Protocol.Channels.Parse_Channel_One_Id
                (Payload,
                 SSH_Lib.Protocol.Channels.SSH_MSG_CHANNEL_CLOSE,
                 Item.Local_Channel_Id);
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
               Status_Value :=
                 Control_Send_Allowed
                   (Item, Channel_Request_Failed, Dirty_On_Timeout => False);
               if Status_Value /= Ok then
                  Item.Current_State := Channel_Close_Received;
                  return Status_Value;
               end if;
               Item.Last_Close :=
                 SSH_Lib.Protocol.Channels.Encode_Channel_Close
                   (Item.Remote_Channel_Id);
               if Is_Empty (Item.Last_Close) then
                  Item.Last_Failure_Status := Channel_Request_Failed;
                  Item.Current_State := Channel_Close_Received;
                  return Channel_Request_Failed;
               end if;
               Status_Value := Send_Channel_Packet (Item, Item.Last_Close);
               if Status_Value /= Ok then
                  Item.Current_State := Channel_Close_Received;
                  return Status_Value;
               end if;
               Item.Close_Sent := True;
            end if;
            Item.Current_State := Channel_Close_Received;

         when SSH_Lib.Protocol.Channels.SSH_MSG_CHANNEL_REQUEST       =>
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

            Status_Value :=
              SSH_Lib.Protocol.Channels.Parse_Channel_Request
                (Payload, Item.Local_Channel_Id, Request_Event);
            if Status_Value /= Ok then
               Mark_Channel_Failed (Item, Read_Failed);
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
            if SSH_Lib.Protocol.Channels.Request_Is_Exit_Status (Request_Event)
            then
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
                  Status_Value :=
                    Control_Send_Allowed
                      (Item, Channel_Request_Failed, Dirty_On_Timeout => True);
                  if Status_Value /= Ok then
                     return Status_Value;
                  end if;
                  Item.Last_Channel_Success :=
                    SSH_Lib.Protocol.Channels.Encode_Channel_Success
                      (Item.Remote_Channel_Id);
                  if Is_Empty (Item.Last_Channel_Success) then
                     Mark_Channel_Failed (Item, Channel_Request_Failed);
                     return Channel_Request_Failed;
                  end if;
                  Status_Value :=
                    Send_Channel_Packet (Item, Item.Last_Channel_Success);
                  if Status_Value /= Ok then
                     return Status_Value;
                  end if;
               end if;
            elsif SSH_Lib.Protocol.Channels.Request_Is_Exit_Signal
                    (Request_Event)
            then
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
                  Status_Value :=
                    Control_Send_Allowed
                      (Item, Channel_Request_Failed, Dirty_On_Timeout => True);
                  if Status_Value /= Ok then
                     return Status_Value;
                  end if;
                  Item.Last_Channel_Success :=
                    SSH_Lib.Protocol.Channels.Encode_Channel_Success
                      (Item.Remote_Channel_Id);
                  if Is_Empty (Item.Last_Channel_Success) then
                     Mark_Channel_Failed (Item, Channel_Request_Failed);
                     return Channel_Request_Failed;
                  end if;
                  Status_Value :=
                    Send_Channel_Packet (Item, Item.Last_Channel_Success);
                  if Status_Value /= Ok then
                     return Status_Value;
                  end if;
               end if;
            elsif Request_Event.Want_Reply then
               Status_Value :=
                 Control_Send_Allowed
                   (Item, Channel_Request_Failed, Dirty_On_Timeout => True);
               if Status_Value /= Ok then
                  return Status_Value;
               end if;
               Item.Last_Channel_Failure :=
                 SSH_Lib.Protocol.Channels.Encode_Channel_Failure
                   (Item.Remote_Channel_Id);
               if Is_Empty (Item.Last_Channel_Failure) then
                  Mark_Channel_Failed (Item, Channel_Request_Failed);
                  return Channel_Request_Failed;
               end if;
               Status_Value :=
                 Send_Channel_Packet (Item, Item.Last_Channel_Failure);
               if Status_Value /= Ok then
                  return Status_Value;
               end if;
            end if;

         when others                                                  =>
            Item.Dirty := True;
            Item.Current_State := Channel_Failed;
            return Read_Failed;
      end case;

      if Window_Data_Consumed
        and then not Item.Eof_Received
        and then not Item.Close_Received
        and then
          Item.Local_Remaining_Window
          < SSH_Lib.Protocol.Channels.Window_Adjust_Threshold
        and then Item.Local_Initial_Window_Size > Item.Local_Remaining_Window
      then
         Adjustment_Amount :=
           Item.Local_Initial_Window_Size - Item.Local_Remaining_Window;
         Status_Value :=
           Control_Send_Allowed (Item, Write_Failed, Dirty_On_Timeout => True);
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
         Item.Last_Window_Adjust :=
           SSH_Lib.Protocol.Channels.Encode_Channel_Window_Adjust
             (Item.Remote_Channel_Id, Adjustment_Amount);
         if Is_Empty (Item.Last_Window_Adjust) then
            Item.Dirty := True;
            Item.Current_State := Channel_Failed;
            return Read_Failed;
         end if;
         Status_Value := Send_Channel_Packet (Item, Item.Last_Window_Adjust);
         if Status_Value /= Ok then
            return Status_Value;
         end if;
         Item.Local_Remaining_Window :=
           Item.Local_Remaining_Window + Adjustment_Amount;
      end if;

      return Ok;
   exception
      when others =>
         Item.Dirty := True;
         Item.Current_State := Channel_Failed;
         return Internal_Error;
   end Consume_Inbound_Payload_For_Test;

   function Read_Some
     (Item   : in out Channel;
      Buffer : out Ada.Streams.Stream_Element_Array;
      Last   : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status is
   begin
      if Buffer'First = Stream_Element_Offset'First then
         Last := Buffer'First;
      else
         Last := Buffer'First - 1;
      end if;

      if Buffer'Length = 0 then
         return Read_Failed;
      end if;

      --  Complete stdout packets already queued in the channel are safe to
      --  deliver even after a later operation dirties the channel or the
      --  owning session has already been closed.  The bytes were accepted from
      --  the protected channel stream before teardown; returning them avoids
      --  silently dropping authenticated Git pkt-line/packfile bytes during
      --  cleanup while still preventing any new network read or protocol
      --  dispatch on a stale handle after the queue is drained.
      if Length (Item.Pending_Stdout) > 0 then
         return Copy_From_Pending (Item, Buffer, Last);
      end if;

      if not Owning_Session_Still_Current_Open (Item) then
         return Fail_Stale_Channel (Item, Connection_Failed);
      end if;

      if Item.Background_Last_Status /= Ok
        and then Item.Background_Last_Status /= Timeout
      then
         --  Pass 373: a terminal background-reader failure has more specific
         --  meaning than the generic dirty/failed channel gate it may also
         --  have tripped.  Preserve the exact protected-stream status before
         --  foreground Read_Some reports a generic dirty-channel result.
         Item.Last_Failure_Status := Item.Background_Last_Status;
         return Item.Background_Last_Status;
      end if;

      if Item.Dirty or else Item.Current_State = Channel_Failed then
         --  After already queued stdout has been delivered, a terminal channel
         --  failure must prevent any further protected transport reads.  In
         --  particular, a receive-window-adjust failure may leave additional
         --  live packets queued; consuming them after the channel is dirty
         --  would append post-failure Git bytes or mutate channel state with
         --  flow-control accounting that is already known to be inconsistent.
         return
           SSH_Lib.Protocol.Failure_State.Dirty_Channel_Read_Status
             (Queued_Data_Available => False);
      end if;

      if Item.Live_Channel_IO_Enabled
        and then not Item.Background_Running
        and then
          (Item.Live_Has_Protected_Inbound
           or else Has_Attached_Live_Transcript (Item))
      then
         declare
            Decoded     : Packet_Buffer;
            Read_Status : Status;
         begin
            loop
               Read_Status := Read_Channel_Packet (Item, Decoded);
               if Read_Status = Timeout then
                  exit;
               elsif Read_Status /= Ok then
                  return Read_Status;
               end if;

               declare
                  Decoded_Data : constant Stream_Element_Array :=
                    To_Array (Decoded);
               begin
                  if Decoded_Data'Length > 0
                    and then
                      (Natural (Decoded_Data (Decoded_Data'First))
                       = SSH_Lib.Protocol.Messages.SSH_MSG_KEXINIT
                       or else
                         Decoded_Data (Decoded_Data'First)
                         = SSH_Lib
                             .Protocol
                             .Global_Requests
                             .SSH_MSG_GLOBAL_REQUEST
                       or else
                         SSH_Lib
                           .Protocol
                           .Global_Requests
                           .Ignorable_While_Waiting_For_Channel_Response
                              (Decoded_Data)
                       or else
                         SSH_Lib.Protocol.Transport_Messages.Classify
                           (Decoded_Data)
                         = SSH_Lib
                             .Protocol
                             .Transport_Messages
                             .Transport_Disconnect)
                  then
                     Read_Status :=
                       Dispatch_Non_Channel_Protected_Payload (Item, Decoded);
                  else
                     Read_Status :=
                       Consume_Inbound_Payload_For_Test (Item, Decoded_Data);
                  end if;
               end;
               if Read_Status /= Ok then
                  return Read_Status;
               end if;
               if Length (Item.Pending_Stdout) > 0 then
                  return Copy_From_Pending (Item, Buffer, Last);
               end if;

               --  An SSH server may send stdout EOF before the channel request
               --  carrying exit-status.  Because Exit_Status is an observation
               --  function and cannot perform I/O, the caller-driven read loop
               --  must continue draining protected channel-control packets after
               --  EOF until an exit-status or close packet is seen, or until the
               --  read boundary reports no immediately queued/live packet.
               if Item.Close_Received then
                  return End_Of_Stream;
               elsif Item.Remote_Exit_Status_Known then
                  --  exit-status/exit-signal is the terminal remote-program
                  --  result for an exec channel.  If no stdout is queued after
                  --  dispatching the protected packet, surface stream EOF
                  --  instead of timing out waiting for a separate CHANNEL_EOF.
                  --  A later queued CHANNEL_CLOSE is still drained by a future
                  --  read/close call before local cleanup.
                  return End_Of_Stream;
               elsif Item.Eof_Received
                 and then not Has_Attached_Live_Transcript (Item)
               then
                  return End_Of_Stream;
               end if;
            end loop;
         end;
      end if;

      --  Pass 365: keep the pass-364 dirty-read ordering without weakening
      --  the ordinary channel-state gate.  A clean channel with no queued
      --  stdout may only report EOF/timeout from states that can legally read
      --  Git stdout/control messages; opening, failed, or locally closed
      --  handles must still fail deterministically before EOF checks.
      if Item.Current_State /= Channel_Exec_Active
        and then Item.Current_State /= Channel_Eof_Sent
        and then Item.Current_State /= Channel_Eof_Received
        and then Item.Current_State /= Channel_Close_Received
      then
         return Read_Failed;
      end if;

      if Item.Eof_Received or else Item.Close_Received then
         return End_Of_Stream;
      end if;
      if Item.Remote_Exit_Status_Known then
         --  The remote exec command has already terminated and no stdout is
         --  queued.  Do not force Git transport callers to wait for an
         --  additional EOF marker that some peers may order after exit-status
         --  or omit before close.
         return End_Of_Stream;
      end if;

      --  The uploaded scaffold has no socket-backed wait path.  Preserve the
      --  public operation-level timeout contract by returning Timeout only
      --  when no queued stdout bytes or EOF can be delivered before the read
      --  deadline.
      Item.Last_Failure_Status := Timeout;
      return Timeout;
   exception
      when others =>
         if Buffer'First = Stream_Element_Offset'First then
            Last := Buffer'First;
         else
            Last := Buffer'First - 1;
         end if;
         Item.Dirty := True;
         Item.Current_State := Channel_Failed;
         Item.Last_Failure_Status := Internal_Error;
         return Internal_Error;
   end Read_Some;

   function Read_Stderr
     (Item   : in out Channel;
      Buffer : out Ada.Streams.Stream_Element_Array;
      Last   : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status is
   begin
      if Buffer'First = Stream_Element_Offset'First then
         Last := Buffer'First;
      else
         Last := Buffer'First - 1;
      end if;

      if Buffer'Length = 0 then
         return Read_Failed;
      end if;

      if Length (Item.Pending_Stderr) > 0 then
         return Copy_From_Pending_Stderr (Item, Buffer, Last);
      end if;

      if not Owning_Session_Still_Current_Open (Item) then
         return Fail_Stale_Channel (Item, Connection_Failed);
      end if;

      if Item.Background_Last_Status /= Ok
        and then Item.Background_Last_Status /= Timeout
      then
         Item.Last_Failure_Status := Item.Background_Last_Status;
         return Item.Background_Last_Status;
      end if;

      if Item.Dirty or else Item.Current_State = Channel_Failed then
         return
           SSH_Lib.Protocol.Failure_State.Dirty_Channel_Read_Status
             (Queued_Data_Available => False);
      end if;

      if Item.Live_Channel_IO_Enabled
        and then not Item.Background_Running
        and then
          (Item.Live_Has_Protected_Inbound
           or else Has_Attached_Live_Transcript (Item))
      then
         declare
            Decoded     : Packet_Buffer;
            Read_Status : Status;
         begin
            loop
               Read_Status := Read_Channel_Packet (Item, Decoded);
               if Read_Status = Timeout then
                  exit;
               elsif Read_Status /= Ok then
                  return Read_Status;
               end if;

               declare
                  Decoded_Data : constant Stream_Element_Array :=
                    To_Array (Decoded);
               begin
                  if Decoded_Data'Length > 0
                    and then
                      (Natural (Decoded_Data (Decoded_Data'First))
                       = SSH_Lib.Protocol.Messages.SSH_MSG_KEXINIT
                       or else
                         Decoded_Data (Decoded_Data'First)
                         = SSH_Lib
                             .Protocol
                             .Global_Requests
                             .SSH_MSG_GLOBAL_REQUEST
                       or else
                         SSH_Lib
                           .Protocol
                           .Global_Requests
                           .Ignorable_While_Waiting_For_Channel_Response
                              (Decoded_Data)
                       or else
                         SSH_Lib.Protocol.Transport_Messages.Classify
                           (Decoded_Data)
                         = SSH_Lib
                             .Protocol
                             .Transport_Messages
                             .Transport_Disconnect)
                  then
                     Read_Status :=
                       Dispatch_Non_Channel_Protected_Payload (Item, Decoded);
                  else
                     Read_Status :=
                       Consume_Inbound_Payload_For_Test (Item, Decoded_Data);
                  end if;
               end;
               if Read_Status /= Ok then
                  return Read_Status;
               end if;
               if Length (Item.Pending_Stderr) > 0 then
                  return Copy_From_Pending_Stderr (Item, Buffer, Last);
               end if;

               if Item.Close_Received then
                  return End_Of_Stream;
               elsif Item.Remote_Exit_Status_Known then
                  return End_Of_Stream;
               elsif Item.Eof_Received
                 and then not Has_Attached_Live_Transcript (Item)
               then
                  return End_Of_Stream;
               end if;
            end loop;
         end;
      end if;

      if Item.Current_State /= Channel_Exec_Active
        and then Item.Current_State /= Channel_Eof_Sent
        and then Item.Current_State /= Channel_Eof_Received
        and then Item.Current_State /= Channel_Close_Received
      then
         return Read_Failed;
      end if;

      if Item.Eof_Received or else Item.Close_Received then
         return End_Of_Stream;
      end if;
      if Item.Remote_Exit_Status_Known then
         return End_Of_Stream;
      end if;

      Item.Last_Failure_Status := Timeout;
      return Timeout;
   exception
      when others =>
         if Buffer'First = Stream_Element_Offset'First then
            Last := Buffer'First;
         else
            Last := Buffer'First - 1;
         end if;
         Item.Dirty := True;
         Item.Current_State := Channel_Failed;
         Item.Last_Failure_Status := Internal_Error;
         return Internal_Error;
   end Read_Stderr;

   function Write
     (Item : in out Channel; Data : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status
   is
      Position_Index  : Stream_Element_Offset := Data'First;
      Remaining_Count : Natural := Data'Length;
      Chunk_Count     : Natural;
      Packet_Value    : Packet_Buffer;
      Status_Value    : Status;
   begin
      if not Owning_Session_Still_Current_Open (Item) then
         return Fail_Stale_Channel (Item, Connection_Failed);
      end if;
      if Item.Background_Last_Status /= Ok
        and then Item.Background_Last_Status /= Timeout
      then
         --  Pass 373: preserve a terminal background-reader failure before
         --  the generic dirty/failed write gate can mask it.  Background
         --  protocol/transport failures commonly mark the channel failed too,
         --  but Git transport callers need the precise terminal status.
         Item.Last_Failure_Status := Item.Background_Last_Status;
         return Item.Background_Last_Status;
      end if;
      if Item.Dirty or else Item.Current_State = Channel_Failed then
         return SSH_Lib.Protocol.Failure_State.Dirty_Channel_Write_Status;
      end if;
      if Item.Current_State /= Channel_Exec_Active
        and then Item.Current_State /= Channel_Eof_Received
      then
         return Write_Failed;
      end if;
      if Item.Eof_Sent or else Item.Close_Sent or else Item.Close_Received then
         return Write_Failed;
      end if;
      if Item.Remote_Exit_Status_Known then
         --  The peer has already reported the remote exec result.  Do not send
         --  more Git stdin after git-upload-pack/git-receive-pack has ended.
         Item.Last_Failure_Status := Write_Failed;
         return Write_Failed;
      end if;
      if Data'Length = 0 then
         return Ok;
      end if;
      if Item.Write_Timeout_MS = 0 then
         --  Immediate deadline before any channel-data packet is emitted.
         Item.Last_Failure_Status := Timeout;
         return Timeout;
      end if;
      if Item.Remote_Maximum_Packet_Size = 0 then
         return Write_Failed;
      end if;

      while Remaining_Count > 0 loop
         if Item.Remote_Remaining_Window = 0 then
            Status_Value := Drain_Inbound_Until_Remote_Window_Open (Item);
            if Status_Value /= Ok then
               if Remaining_Count < Data'Length then
                  Mark_Channel_Failed (Item, Status_Value);
               elsif Status_Value /= Timeout then
                  Item.Last_Failure_Status := Status_Value;
               else
                  Item.Last_Failure_Status := Timeout;
               end if;
               return Status_Value;
            end if;

            if Item.Remote_Remaining_Window = 0 then
               if Remaining_Count < Data'Length then
                  Mark_Channel_Failed (Item, Timeout);
               else
                  Item.Last_Failure_Status := Timeout;
               end if;
               return Timeout;
            end if;
         end if;
         Chunk_Count := Remaining_Count;

         if Item.Remote_Maximum_Packet_Size
           < Interfaces.Unsigned_32 (Remaining_Count)
         then
            Chunk_Count := Natural (Item.Remote_Maximum_Packet_Size);
         end if;

         if Item.Remote_Remaining_Window < Interfaces.Unsigned_32 (Chunk_Count)
         then
            Chunk_Count := Natural (Item.Remote_Remaining_Window);
         end if;

         if Chunk_Count = 0 then
            if Remaining_Count < Data'Length then
               Item.Dirty := True;
               Item.Current_State := Channel_Failed;
            end if;
            Item.Last_Failure_Status := Timeout;
            return Timeout;
         end if;

         Packet_Value :=
           SSH_Lib.Protocol.Channels.Encode_Channel_Data
             (Item.Remote_Channel_Id,
              Data
                (Position_Index
                 .. Position_Index + Stream_Element_Offset (Chunk_Count) - 1));
         if Is_Empty (Packet_Value) then
            Item.Dirty := True;
            Item.Current_State := Channel_Failed;
            return Write_Failed;
         end if;
         Status_Value := Set (Item.Last_Channel_Data, To_Array (Packet_Value));
         if Status_Value /= Ok then
            Item.Dirty := True;
            Item.Current_State := Channel_Failed;
            return Write_Failed;
         end if;

         Status_Value := Send_Channel_Packet (Item, Packet_Value);
         if Status_Value /= Ok then
            --  Preserve the precise transport failure reported by the protected
            --  send path.  A live disconnect, timeout, or rekey/write failure
            --  has already marked the channel failed in Send_Channel_Packet;
            --  collapsing it to Write_Failed would hide the terminal reason
            --  from Git transport callers and retry policy.
            return Status_Value;
         end if;
         if Natural'Last - Item.Outbound_Data_Bytes < Chunk_Count then
            Item.Dirty := True;
            Item.Current_State := Channel_Failed;
            return Write_Failed;
         end if;
         Item.Outbound_Data_Bytes := Item.Outbound_Data_Bytes + Chunk_Count;
         if Item.Outbound_Data_Packets < Natural'Last then
            Item.Outbound_Data_Packets := Item.Outbound_Data_Packets + 1;
         end if;
         Item.Remote_Remaining_Window :=
           Item.Remote_Remaining_Window - Interfaces.Unsigned_32 (Chunk_Count);
         Position_Index :=
           Position_Index + Stream_Element_Offset (Chunk_Count);
         Remaining_Count := Remaining_Count - Chunk_Count;
         if Item.Test_Remote_Close_After_Partial and then Remaining_Count > 0
         then
            --  The peer closed the channel after some caller bytes may have
            --  been emitted.  The caller must see a deterministic failure,
            --  and the channel must become unusable so Git request bytes are
            --  never replayed ambiguously.
            Item.Close_Received := True;
            Item.Dirty := True;
            Item.Current_State := Channel_Failed;
            Item.Last_Failure_Status := Write_Failed;
            return Write_Failed;
         end if;
         if Item.Test_Write_Timeout_After_Partial and then Remaining_Count > 0
         then
            Item.Dirty := True;
            Item.Current_State := Channel_Failed;
            Item.Last_Failure_Status := Timeout;
            return Timeout;
         end if;
      end loop;
      return Ok;
   exception
      when others =>
         Item.Dirty := True;
         Item.Current_State := Channel_Failed;
         Item.Last_Failure_Status := Internal_Error;
         return Internal_Error;
   end Write;

   function Send_EOF (Item : in out Channel) return CryptoLib.Errors.Status is
   begin
      if Item.Eof_Sent then
         if Item.Background_Last_Status /= Ok
           and then Item.Background_Last_Status /= Timeout
         then
            --  Pass 379: repeated EOF is still a no-op with respect to
            --  transport I/O, but it must not hide a terminal protected-stream
            --  failure already observed by the optional background reader.
            --  Preserve the exact diagnostic while keeping the already-sent
            --  EOF idempotent and avoiding stale session writes.
            Item.Last_Failure_Status := Item.Background_Last_Status;
            return Item.Background_Last_Status;
         end if;
         --  Public EOF is idempotent once the local send side has already
         --  been closed.  Preserve that no-op behaviour even if the owning
         --  session has since been closed/reset by cleanup; a repeated EOF
         --  call must not attempt stale protected transport I/O or report a
         --  connection failure after the EOF packet was already emitted.
         return Ok;
      end if;
      if not Owning_Session_Still_Current_Open (Item) then
         return Fail_Stale_Channel (Item, Connection_Failed);
      end if;
      if Item.Background_Last_Status /= Ok
        and then Item.Background_Last_Status /= Timeout
      then
         --  Pass 373: preserve a terminal background-reader failure before
         --  generic dirty-channel request handling can collapse it.
         Item.Last_Failure_Status := Item.Background_Last_Status;
         return Item.Background_Last_Status;
      end if;
      if Item.Dirty or else Item.Current_State = Channel_Failed then
         return SSH_Lib.Protocol.Failure_State.Dirty_Channel_Request_Status;
      end if;
      if Item.Current_State /= Channel_Exec_Active
        and then Item.Current_State /= Channel_Eof_Sent
        and then Item.Current_State /= Channel_Eof_Received
      then
         return Channel_Request_Failed;
      end if;
      if Item.Close_Sent or else Item.Close_Received then
         return Channel_Request_Failed;
      end if;
      if Item.Remote_Exit_Status_Known then
         --  Sending EOF for the first time after the remote command has
         --  already reported its terminal result is no longer meaningful stdin
         --  shutdown; reject it without mutating the preserved exit status.
         Item.Last_Failure_Status := Channel_Request_Failed;
         return Channel_Request_Failed;
      end if;
      if Item.Write_Timeout_MS = 0 then
         --  Immediate deadline before the EOF packet is emitted.  No bytes are
         --  ambiguous, so the channel remains clean and the caller may close it
         --  or retry with a different owning operation in future API variants.
         Item.Last_Failure_Status := Timeout;
         return Timeout;
      end if;
      if Item.Test_Send_EOF_Timeout then
         Item.Dirty := True;
         Item.Current_State := Channel_Failed;
         Item.Last_Failure_Status := Timeout;
         return Timeout;
      end if;
      Item.Last_EOF :=
        SSH_Lib.Protocol.Channels.Encode_Channel_EOF (Item.Remote_Channel_Id);
      if Is_Empty (Item.Last_EOF) then
         Item.Dirty := True;
         Item.Current_State := Channel_Failed;
         Item.Last_Failure_Status := Channel_Request_Failed;
         return Channel_Request_Failed;
      end if;
      declare
         Status_Value : constant Status :=
           Send_Channel_Packet (Item, Item.Last_EOF);
      begin
         if Status_Value /= Ok then
            --  EOF is sent over the same protected transport as channel data.
            --  Preserve the exact send failure so callers can distinguish a
            --  dead connection from an ordinary channel-request problem.
            return Status_Value;
         end if;
      end;
      Item.Eof_Sent := True;
      Item.Current_State := Channel_Eof_Sent;
      return Ok;
   exception
      when others =>
         Item.Dirty := True;
         Item.Current_State := Channel_Failed;
         Item.Last_Failure_Status := Internal_Error;
         return Internal_Error;
   end Send_EOF;

   function Close (Item : in out Channel) return CryptoLib.Errors.Status is
      Status_Value : Status;
      Decoded      : Packet_Buffer;
   begin
      if Item.Current_State = Channel_Closed then
         Release_Owning_Channel_Slot (Item);
         --  Idempotent close still performs erasure, because callers may close
         --  a locally closed handle after a best-effort cleanup path.
         Item.Outbound_Data_Bytes := 0;
         Item.Outbound_Data_Packets := 0;
         --  Preserve an observed remote exit-status across idempotent close.
         --  Git transport callers commonly drain stdout, close cleanup, then
         --  inspect the remote command result; Close must not erase that
         --  already-received channel request.
         Item.Dirty := False;
         Item.Test_Write_Timeout_After_Partial := False;
         Item.Test_Send_EOF_Timeout := False;
         Item.Test_Remote_Close_After_Partial := False;
         Item.Test_Close_Timeout := False;
         Item.Test_Close_Exception_For_Cleanup := False;
         Item.Test_Stop_Background_Exception_For_Cleanup := False;
         Item.Test_Background_Task_Exception_For_Cleanup := False;
         Clear_Transient_Buffers (Item);
         declare
            Preserved_Background_Status : constant Status :=
              Item.Background_Last_Status;
         begin
            --  Pass 374: a closed channel must not retain live protected
            --  transport attachment state, background-reader flags, or the owning
            --  session address.  Idempotent close is still local cleanup, but it
            --  should erase any stale live-channel references before returning.
            --
            --  Pass 377: if a previous close preserved a terminal background
            --  reader failure for diagnostics, a later idempotent Close must
            --  not erase that public status while detaching stale live I/O.
            Reset_Live_Channel_IO (Item);
            if Preserved_Background_Status /= Ok
              and then Preserved_Background_Status /= Timeout
            then
               Item.Background_Last_Status := Preserved_Background_Status;
               Item.Last_Failure_Status := Preserved_Background_Status;
            end if;
         end;
         return Ok;
      end if;

      if Item.Allocated
        and then Item.Owning_Session_Address /= System.Null_Address
        and then not Owning_Session_Still_Current_Open (Item)
      then
         --  The owning authenticated session has already been closed or reset.
         --  Close is local cleanup in this state; do not attempt to send
         --  CHANNEL_CLOSE through stale protected transport state or drain
         --  protected packets from a generation that no longer owns this
         --  handle.  Preserve any remote exit-status/exit-signal observed
         --  before teardown so callers may still query it after cleanup.
         --
         --  Pass 367: stale-session cleanup must still quiesce the optional
         --  background reader before the channel releases/reset live state.
         --  Otherwise a retained reader task could keep a dangling channel
         --  address after Sessions.Close advanced the owner generation.
         Status_Value := Stop_Background_Reader (Item);
         if Status_Value /= Ok then
            Item.Last_Failure_Status := Status_Value;
         else
            Item.Last_Failure_Status := Connection_Failed;
         end if;
         Item.Close_Received := True;
         Item.Current_State := Channel_Closed;
         Release_Owning_Channel_Slot (Item);
         Item.Channel_Open_Confirmed := False;
         Item.Exec_Request_Confirmed := False;
         Item.Outbound_Data_Bytes := 0;
         Item.Outbound_Data_Packets := 0;
         Item.Dirty := False;
         Item.Test_Write_Timeout_After_Partial := False;
         Item.Test_Send_EOF_Timeout := False;
         Item.Test_Remote_Close_After_Partial := False;
         Item.Test_Close_Timeout := False;
         Item.Test_Close_Exception_For_Cleanup := False;
         Item.Test_Stop_Background_Exception_For_Cleanup := False;
         Item.Test_Background_Task_Exception_For_Cleanup := False;
         Clear_Transient_Buffers (Item);
         declare
            Preserved_Background_Status : constant Status := Status_Value;
         begin
            Reset_Live_Channel_IO (Item);
            if Preserved_Background_Status /= Ok
              and then Preserved_Background_Status /= Timeout
            then
               --  Pass 376: stale-session Close is local cleanup, but if the
               --  background reader had already recorded a terminal protected
               --  stream failure, preserve that diagnostic across live-state
               --  detachment instead of replacing it with generic stale
               --  connection cleanup.
               Item.Background_Last_Status := Preserved_Background_Status;
               Item.Last_Failure_Status := Preserved_Background_Status;
            end if;
         end;
         return Ok;
      end if;

      Status_Value := Stop_Background_Reader (Item);
      if Status_Value /= Ok then
         Item.Last_Failure_Status := Status_Value;
         if Status_Value /= Timeout then
            declare
               Preserved_Background_Status : constant Status := Status_Value;
            begin
               --  Pass 371: a terminal background-reader failure means the
               --  protected channel stream has already observed a transport or
               --  protocol fault.  Close is still local cleanup, but it must not
               --  emit a fresh CHANNEL_CLOSE or drain more protected packets on
               --  the same failed stream; doing so could mutate channel state
               --  after the exact terminal failure was preserved for Write and
               --  Exit_Status.
               Item.Close_Received := True;
               Item.Current_State := Channel_Closed;
               Release_Owning_Channel_Slot (Item);
               Item.Channel_Open_Confirmed := False;
               Item.Exec_Request_Confirmed := False;
               Item.Outbound_Data_Bytes := 0;
               Item.Outbound_Data_Packets := 0;
               Item.Dirty := False;
               Item.Test_Write_Timeout_After_Partial := False;
               Item.Test_Send_EOF_Timeout := False;
               Item.Test_Remote_Close_After_Partial := False;
               Item.Test_Close_Timeout := False;
               Item.Test_Close_Exception_For_Cleanup := False;
               Item.Test_Stop_Background_Exception_For_Cleanup := False;
               Item.Test_Background_Task_Exception_For_Cleanup := False;
               Clear_Transient_Buffers (Item);
               Reset_Live_Channel_IO (Item);
               --  Pass 376: Reset_Live_Channel_IO intentionally clears
               --  background attachment state for closed handles, but a
               --  terminal background-reader failure is public diagnostic
               --  state.  Preserve it across local close cleanup so later
               --  Exit_Status / Background_Reader_Status queries do not lose
               --  the exact protected-stream failure.
               Item.Background_Last_Status := Preserved_Background_Status;
               Item.Last_Failure_Status := Preserved_Background_Status;
               return Ok;
            end;
         end if;
      end if;

      if Item.Test_Close_Exception_For_Cleanup then
         --  Test-only fault injection for the best-effort Close exception
         --  cleanup path.  The handler below must detach live protected
         --  channel state just like ordinary graceful and idempotent close.
         raise Program_Error;
      end if;

      if not Item.Close_Sent then
         if Item.Write_Timeout_MS = 0 or else Item.Test_Close_Timeout then
            --  Close is a cleanup operation: a graceful close send may time
            --  out, but local cleanup must still complete and return Ok.
            --  No retained close packet is exposed after cleanup.
            Item.Last_Failure_Status := Timeout;
         else
            Item.Last_Close :=
              SSH_Lib.Protocol.Channels.Encode_Channel_Close
                (Item.Remote_Channel_Id);
            if Is_Empty (Item.Last_Close) then
               Item.Last_Failure_Status := Channel_Request_Failed;
            else
               Status_Value := Send_Channel_Packet (Item, Item.Last_Close);
               if Status_Value /= Ok then
                  Item.Last_Failure_Status := Status_Value;
               else
                  Item.Close_Sent := True;
               end if;
            end if;
         end if;
      end if;

      --  When live protected channel I/O is enabled, a graceful close should
      --  opportunistically consume the peer close acknowledgement and any
      --  interleaved transport/global/rekey control packets before local cleanup.
      --  This is intentionally bounded and best-effort: Close remains
      --  idempotent cleanup, so timeout or malformed late data must not keep
      --  the handle open or surface queued Git bytes after the caller closes.
      if Item.Live_Channel_IO_Enabled
        and then
          (Item.Live_Has_Protected_Inbound
           or else Has_Attached_Live_Transcript (Item))
        and then not Item.Close_Received
      then
         for Attempt_Count in 1 .. 8 loop
            Status_Value := Read_Channel_Packet (Item, Decoded);
            exit when Status_Value /= Ok;

            declare
               Decoded_Data : constant Stream_Element_Array :=
                 To_Array (Decoded);
            begin
               if Decoded_Data'Length > 0
                 and then
                   (Natural (Decoded_Data (Decoded_Data'First))
                    = SSH_Lib.Protocol.Messages.SSH_MSG_KEXINIT
                    or else
                      Decoded_Data (Decoded_Data'First)
                      = SSH_Lib.Protocol.Global_Requests.SSH_MSG_GLOBAL_REQUEST
                    or else
                      SSH_Lib
                        .Protocol
                        .Global_Requests
                        .Ignorable_While_Waiting_For_Channel_Response
                           (Decoded_Data)
                    or else
                      SSH_Lib.Protocol.Transport_Messages.Classify
                        (Decoded_Data)
                      = SSH_Lib
                          .Protocol
                          .Transport_Messages
                          .Transport_Disconnect)
               then
                  Status_Value :=
                    Dispatch_Non_Channel_Protected_Payload (Item, Decoded);
               else
                  Status_Value :=
                    Consume_Inbound_Payload_For_Test (Item, Decoded_Data);
               end if;
            end;

            exit when Status_Value /= Ok or else Item.Close_Received;
         end loop;
      end if;

      Item.Close_Received := True;
      Item.Current_State := Channel_Closed;
      Release_Owning_Channel_Slot (Item);
      Item.Channel_Open_Confirmed := False;
      Item.Exec_Request_Confirmed := False;
      --  Do not clear Remote_Exit_Status[_Known] here.  Close is local
      --  resource cleanup; it must not destroy an already parsed remote
      --  command status that the caller may query immediately after close.
      Item.Outbound_Data_Bytes := 0;
      Item.Outbound_Data_Packets := 0;
      Item.Dirty := False;
      Item.Test_Write_Timeout_After_Partial := False;
      Item.Test_Send_EOF_Timeout := False;
      Item.Test_Remote_Close_After_Partial := False;
      Item.Test_Close_Timeout := False;
      Item.Test_Close_Exception_For_Cleanup := False;
      Item.Test_Stop_Background_Exception_For_Cleanup := False;
      Item.Test_Background_Task_Exception_For_Cleanup := False;
      Clear_Transient_Buffers (Item);
      --  Pass 374: normal graceful close now mirrors the stale-session and
      --  background-failure cleanup paths by detaching live protected channel
      --  state.  Remote_Exit_Status[_Known] is intentionally preserved above;
      --  Reset_Live_Channel_IO only removes transport attachment state and
      --  retained protected packet buffers from the closed handle.
      Reset_Live_Channel_IO (Item);
      return Ok;
   exception
      when others =>
         declare
            Preserved_Background_Status : constant Status :=
              Item.Background_Last_Status;
         begin
            --  Close is best-effort cleanup, but it must still release the
            --  session channel-table ownership recorded by Open_Exec.  Without
            --  this fallback an exception raised while draining late protected
            --  input or clearing transient buffers could leave the owning
            --  session believing the channel slot is still active, eventually
            --  exhausting a long-lived Git-over-SSH session.
            Release_Owning_Channel_Slot (Item);
            Item.Current_State := Channel_Closed;
            Item.Channel_Open_Confirmed := False;
            Item.Exec_Request_Confirmed := False;
            Item.Outbound_Data_Bytes := 0;
            Item.Outbound_Data_Packets := 0;
            Item.Dirty := False;
            Item.Test_Write_Timeout_After_Partial := False;
            Item.Test_Send_EOF_Timeout := False;
            Item.Test_Remote_Close_After_Partial := False;
            Item.Test_Close_Timeout := False;
            Item.Test_Close_Exception_For_Cleanup := False;
            Item.Test_Stop_Background_Exception_For_Cleanup := False;
            Item.Test_Background_Task_Exception_For_Cleanup := False;
            Clear_Transient_Buffers (Item);
            --  Pass 375: the emergency Close exception fallback must detach
            --  the same live protected channel state as the ordinary cleanup
            --  paths.  Otherwise a rare cleanup exception could leave stale
            --  protected buffers, transcript attachments, background-reader
            --  flags, or an owning-session address on a closed handle.
            --
            --  Pass 378: Reset_Live_Channel_IO clears attachment state and
            --  background-reader bookkeeping.  If the exception path was
            --  entered after a terminal background-reader status had already
            --  been recorded, preserve that public diagnostic exactly like the
            --  ordinary, stale-session, background-failure, and idempotent
            --  close paths do.
            Reset_Live_Channel_IO (Item);
            if Preserved_Background_Status /= Ok
              and then Preserved_Background_Status /= Timeout
            then
               Item.Background_Last_Status := Preserved_Background_Status;
               Item.Last_Failure_Status := Preserved_Background_Status;
            end if;
            return Ok;
         end;
   end Close;

   function Start_Background_Reader
     (Item : in out Channel) return CryptoLib.Errors.Status is
   begin
      if not Owning_Session_Still_Current_Open (Item) then
         return Fail_Stale_Channel (Item, Connection_Failed);
      end if;
      if Item.Background_Last_Status /= Ok
        and then Item.Background_Last_Status /= Timeout
      then
         --  Pass 373: preserve a terminal status left by a previous
         --  background prefetch attempt before the generic dirty/failed
         --  request gate can mask it.
         Item.Last_Failure_Status := Item.Background_Last_Status;
         return Item.Background_Last_Status;
      end if;
      if Item.Dirty or else Item.Current_State = Channel_Failed then
         return SSH_Lib.Protocol.Failure_State.Dirty_Channel_Request_Status;
      end if;
      if Item.Current_State /= Channel_Exec_Active
        and then Item.Current_State /= Channel_Eof_Sent
        and then Item.Current_State /= Channel_Eof_Received
      then
         return Channel_Request_Failed;
      end if;
      if Item.Remote_Exit_Status_Known
        or else Item.Close_Sent
        or else Item.Close_Received
      then
         --  Do not start a background prefetch task after the remote Git
         --  command has already produced a terminal result or the channel is
         --  closing/closed.  Foreground Read_Some/Close retain deterministic
         --  cleanup semantics; a new background task here could consume late
         --  control packets after the public stream has ended.
         Item.Last_Failure_Status := Channel_Request_Failed;
         return Channel_Request_Failed;
      end if;
      if Item.Background_Running then
         if Item.Background_Requested and then Item.Background_Task /= null
         then
            return Ok;
         end if;

         --  Pass 388: an attached helper is the only shape that may satisfy
         --  the already-running fast path.  Defensive cleanup or interrupted
         --  task startup can leave Running/Requested bookkeeping set while
         --  Background_Task is null.  Treat that as stale state, clear it, and
         --  re-apply the normal fresh-start preconditions instead of reporting
         --  a phantom running reader.
         Item.Background_Running := False;
         Item.Background_Requested := False;
         Item.Background_Task := null;
         if Item.Background_Last_Status = Timeout then
            Item.Background_Last_Status := Ok;
         end if;
      elsif Item.Background_Requested then
         if Item.Background_Task /= null then
            --  Pass 389: a task object that has been requested but has not yet
            --  published Background_Running represents an in-flight startup.
            --  Do not allocate a second task for the same channel handle.
            return Ok;
         end if;

         --  Pass 389: a requested helper without an attached task is stale
         --  startup/cleanup bookkeeping.  Normalize it before the live
         --  transcript precondition below so an Unsupported_Feature result does
         --  not leave a phantom background request behind.
         Item.Background_Requested := False;
         if Item.Background_Last_Status = Timeout then
            Item.Background_Last_Status := Ok;
         end if;
      elsif Item.Background_Task /= null then
         --  Pass 389: an orphan task pointer with no request/running state is
         --  stale cleanup residue.  Clear it before retrying a fresh start.
         Item.Background_Task := null;
         if Item.Background_Last_Status = Timeout then
            Item.Background_Last_Status := Ok;
         end if;
      end if;

      if Item.Test_Start_Background_Exception_For_Cleanup then
         --  Pass 390/393 regression hook: exercise the defensive startup
         --  exception cleanup after startup has retained either an exact
         --  terminal protected-stream status or a stale non-terminal timeout.
         if Item.Background_Last_Status = Ok then
            Item.Background_Last_Status := Connection_Failed;
         end if;
         raise Program_Error;
      end if;

      if not Has_Attached_Live_Transcript (Item) then
         return Unsupported_Feature;
      end if;

      Item.Background_Last_Status := Ok;
      Item.Background_Requested := True;
      Item.Background_Task := new Background_Reader;
      Item.Background_Task.Start (Item'Address);
      return Ok;
   exception
      when others =>
         declare
            Preserved_Background_Status : constant Status :=
              Item.Background_Last_Status;
         begin
            Item.Background_Requested := False;
            Item.Background_Running := False;
            Item.Background_Task := null;
            Item.Test_Start_Background_Exception_For_Cleanup := False;
            if Preserved_Background_Status /= Ok
              and then Preserved_Background_Status /= Timeout
            then
               --  Pass 390: startup exception cleanup must not overwrite an
               --  already recorded terminal background-reader/protected-stream
               --  diagnostic with Internal_Error.
               Item.Background_Last_Status := Preserved_Background_Status;
               Item.Last_Failure_Status := Preserved_Background_Status;
               return Preserved_Background_Status;
            elsif Preserved_Background_Status = Timeout then
               --  Pass 393: Timeout is a bounded background prefetch miss,
               --  not a terminal startup diagnostic.  If defensive startup
               --  cleanup trips while only a stale timeout was retained,
               --  normalize it like stale stop/background status paths instead
               --  of converting cleanup into Internal_Error.
               Item.Background_Last_Status := Ok;
               return Ok;
            end if;
            Item.Background_Last_Status := Internal_Error;
            Item.Last_Failure_Status := Internal_Error;
            return Internal_Error;
         end;
   end Start_Background_Reader;

   function Stop_Background_Reader
     (Item : in out Channel) return CryptoLib.Errors.Status is
   begin
      if Item.Test_Stop_Background_Exception_For_Cleanup then
         --  Test hook for pass 381: exercise the defensive Stop exception
         --  cleanup path after a terminal background-reader diagnostic has
         --  already been recorded.
         raise Program_Error;
      end if;

      if Item.Background_Task = null then
         declare
            Stored_Status : constant Status := Item.Background_Last_Status;
         begin
            Item.Background_Requested := False;
            Item.Background_Running := False;
            if Stored_Status = Timeout then
               --  Pass 391: a timeout is only a bounded background prefetch
               --  miss.  When no helper is attached, Stop should normalize the
               --  stale diagnostic immediately rather than relying on the
               --  public status accessor to hide it later.
               Item.Background_Last_Status := Ok;
            elsif Stored_Status /= Ok then
               Item.Last_Failure_Status := Stored_Status;
               return Stored_Status;
            end if;
            return Ok;
         end;
      end if;

      if (not Item.Background_Requested) and then (not Item.Background_Running)
      then
         declare
            Stored_Status : constant Status := Item.Background_Last_Status;
         begin
            --  Pass 391: an attached task object with neither requested nor
            --  running bookkeeping is stale startup/cleanup residue.  Do not
            --  call into the task entry and risk a bounded wait on a helper
            --  that is no longer part of the Version-facing byte stream.
            Item.Background_Task := null;
            if Stored_Status = Timeout then
               Item.Background_Last_Status := Ok;
            elsif Stored_Status /= Ok then
               Item.Last_Failure_Status := Stored_Status;
               return Stored_Status;
            end if;
            return Ok;
         end;
      end if;

      Item.Background_Requested := False;
      select
         Item.Background_Task.Stop;
      or
         delay 0.250;
         --  Do not block Close indefinitely.  The task observes
         --  Background_Requested and will terminate after the current bounded
         --  protected-packet read returns.
         null;
      end select;
      Item.Background_Running := False;
      Item.Background_Task := null;
      if Item.Background_Last_Status = Timeout then
         Item.Background_Last_Status := Ok;
      elsif Item.Background_Last_Status /= Ok then
         Item.Last_Failure_Status := Item.Background_Last_Status;
         return Item.Background_Last_Status;
      end if;
      return Ok;
   exception
      when others =>
         declare
            Preserved_Background_Status : constant Status :=
              Item.Background_Last_Status;
         begin
            Item.Background_Requested := False;
            Item.Background_Running := False;
            Item.Background_Task := null;
            Item.Test_Stop_Background_Exception_For_Cleanup := False;
            Item.Test_Background_Task_Exception_For_Cleanup := False;
            Item.Test_Background_Drain_Terminal_Failure := False;
            Item.Test_Start_Background_Exception_For_Cleanup := False;
            if Preserved_Background_Status /= Ok
              and then Preserved_Background_Status /= Timeout
            then
               --  Pass 381: Stop_Background_Reader is often called from
               --  Close cleanup.  If the helper had already recorded a
               --  terminal protected-stream failure, a defensive cleanup
               --  exception must not overwrite the exact diagnostic with
               --  Internal_Error.
               Item.Background_Last_Status := Preserved_Background_Status;
               Item.Last_Failure_Status := Preserved_Background_Status;
               return Preserved_Background_Status;
            elsif Preserved_Background_Status = Timeout then
               --  Pass 392: Timeout is a bounded background prefetch miss,
               --  not a terminal protected-stream diagnostic.  If defensive
               --  Stop cleanup trips while only a stale timeout was retained,
               --  normalize it exactly like the ordinary stale-stop path
               --  instead of converting cleanup into Internal_Error.
               Item.Background_Last_Status := Ok;
               return Ok;
            end if;
            Item.Background_Last_Status := Internal_Error;
            Item.Last_Failure_Status := Internal_Error;
            return Internal_Error;
         end;
   end Stop_Background_Reader;

   function Background_Reader_Running (Item : Channel) return Boolean is
   begin
      if Item.Background_Last_Status /= Ok
        and then Item.Background_Last_Status /= Timeout
      then
         --  Pass 380: once the background reader has recorded a terminal
         --  protocol/transport failure, public liveness must not report the
         --  helper as running even if a stale bookkeeping flag remains set
         --  during defensive cleanup.  The failure status is authoritative;
         --  callers should observe it through Background_Reader_Status and
         --  foreground operations rather than wait for more background work.
         return False;
      end if;

      if not Item.Background_Requested then
         --  Pass 385: shutdown/cleanup can clear the request flag before stale
         --  task bookkeeping has fully quiesced.  Public liveness should
         --  reflect that no background reader is still requested for the
         --  Version-facing byte stream, not expose stale helper state.
         return False;
      end if;

      if Item.Background_Task = null then
         --  Pass 388: public liveness must also require a real attached task.
         --  Running+Requested bookkeeping without Background_Task can arise
         --  from defensive cleanup/startup-failure paths and must not make
         --  callers believe an asynchronous protected-stream reader exists.
         return False;
      end if;

      return Item.Background_Running;
   exception
      when others =>
         return False;
   end Background_Reader_Running;

   function Background_Reader_Status
     (Item : Channel) return CryptoLib.Errors.Status is
   begin
      if Item.Background_Last_Status = Timeout
        and then not Background_Reader_Running (Item)
      then
         --  Pass 387: use the same public liveness predicate that callers see.
         --  A stale cleanup window can leave Background_Running set after the
         --  request flag was cleared; Background_Reader_Running already treats
         --  that shape as inactive.  The retained Timeout is still only a
         --  bounded prefetch miss and must not surface as a persistent failure.
         return Ok;
      end if;

      return Item.Background_Last_Status;
   exception
      when others =>
         return Internal_Error;
   end Background_Reader_Status;

   function Exit_Status
     (Item : Channel; Code : out Integer) return CryptoLib.Errors.Status is
   begin
      Code := Item.Remote_Exit_Status;
      if (not Item.Remote_Exit_Status_Known)
        and then Item.Background_Last_Status /= Ok
        and then Item.Background_Last_Status /= Timeout
      then
         --  Pass 373: preserve an exact terminal background-reader failure
         --  even if that failure also dirtied the channel.  A generic
         --  Channel_Request_Failed result would hide the protected transport
         --  failure from callers that query Exit_Status during cleanup.
         Code := -1;
         return Item.Background_Last_Status;
      end if;

      if Item.Dirty or else Item.Current_State = Channel_Failed then
         Code := -1;
         return Channel_Request_Failed;
      end if;

      if (not Item.Remote_Exit_Status_Known)
        and then (not Owning_Session_Still_Current_Open (Item))
      then
         --  A retained channel handle whose owning authenticated session has
         --  been closed cannot later learn a remote command status.  Report
         --  the transport loss deterministically instead of presenting this as
         --  an ordinary missing channel request.  If an exit-status or
         --  exit-signal was already recorded before session teardown, preserve
         --  the post-close query behavior below.
         Code := -1;
         return Connection_Failed;
      end if;

      if Item.Remote_Exit_Status_Known then
         if Item.Remote_Exit_Status = 0 then
            return Ok;
         else
            return Remote_Exit_Nonzero;
         end if;
      else
         --  Unknown exit status is not an unsupported SSH feature: it means
         --  the peer has not sent (or the caller has not yet drained) an
         --  exit-status channel request.  Return a deterministic channel
         --  request failure so callers do not treat a normal protocol timing
         --  condition as a missing library capability.
         return Channel_Request_Failed;
      end if;
   exception
      when others =>
         Code := -1;
         return Internal_Error;
   end Exit_Status;
end SSH_Lib.Channels;
