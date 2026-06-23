with Ada.Streams;
with Interfaces;
with SSH_Lib.Protocol.Channels;
with SSH_Lib.Protocol.Protected_Packets;
with SSH_Lib.Protocol.Global_Requests;
with SSH_Lib.Protocol.Messages;
with SSH_Lib.Protocol.Transport_Messages;
with SSH_Lib.Sessions.Open_Guards;
with SSH_Lib.Sessions.Live_Attachment;
with SSH_Lib.Sessions.Live_Transcript;
with SSH_Lib.Sessions.Live_Transport;

package body SSH_Lib.Sessions.Channel_IO is
   use Ada.Streams;
   use CryptoLib.Errors;
   use type Interfaces.Unsigned_32;
   use type SSH_Lib.Sessions.Live_Transcript.Driver_Access;
   use type SSH_Lib.Protocol.Transport_Messages.Transport_Message_Kind;
   use SSH_Lib.Protocol.Buffers;

   Boundary_Key : constant Stream_Element_Array (1 .. 32) :=
     [1  => 16#43#, 2  => 16#48#, 3  => 16#41#, 4  => 16#4E#,
      5  => 16#4E#, 6  => 16#45#, 7  => 16#4C#, 8  => 16#2D#,
      9  => 16#42#, 10 => 16#4F#, 11 => 16#55#, 12 => 16#4E#,
      13 => 16#44#, 14 => 16#41#, 15 => 16#52#, 16 => 16#59#,
      17 => 16#2D#, 18 => 16#4B#, 19 => 16#45#, 20 => 16#59#,
      21 => 16#2D#, 22 => 16#30#, 23 => 16#30#, 24 => 16#30#,
      25 => 16#30#, 26 => 16#30#, 27 => 16#30#, 28 => 16#30#,
      29 => 16#30#, 30 => 16#30#, 31 => 16#30#, 32 => 16#31#];

   function Ready_For_Channel_IO (Item : Session) return Boolean is
   begin
      return Item.Current_State = Opened
        and then Item.Session_Open
        and then not Item.Session_Closed
        and then not Item.Session_Dirty
        and then SSH_Lib.Sessions.Open_Guards.Success_Gates_Complete (Item)
        and then Item.Encrypted_Outbound_Active
        and then Item.Encrypted_Inbound_Active
        and then Item.User_Authenticated;
   exception
      when others =>
         return False;
   end Ready_For_Channel_IO;

   function Enabled (Item : Session) return Boolean is
   begin
      return Item.Live_Channel_IO_Enabled and then Ready_For_Channel_IO (Item);
   exception
      when others =>
         return False;
   end Enabled;

   function Live_Attached_Transport (Item : Session) return Boolean is
   begin
      return Enabled (Item) and then SSH_Lib.Sessions.Live_Attachment.Attached (Item);
   exception
      when others =>
         return False;
   end Live_Attached_Transport;

   procedure Enable_For_Test (Item : in out Session) is
   begin
      SSH_Lib.Protocol.Protected_Packets.Reset
        (Item.Live_Open_Protected_State, Boundary_Key);
      Clear (Item.Live_Last_Protected_Channel);
      Clear (Item.Live_Last_Plain_Channel);
      Item.Live_Channel_IO_Enabled := True;
   exception
      when others =>
         Item.Live_Channel_IO_Enabled := False;
   end Enable_For_Test;

   function Send_Channel_Payload
     (Item    : in out Session;
      Payload : Packet_Buffer)
      return Status
   is
      Status_Value : Status;
   begin
      if not Enabled (Item) then
         return Set (Item.Live_Last_Plain_Channel, To_Array (Payload));
      end if;

      Status_Value := Set (Item.Live_Last_Plain_Channel, To_Array (Payload));
      if Status_Value /= Ok then
         Item.Session_Dirty := True;
         Item.Failure_Status := Status_Value;
         return Status_Value;
      end if;

      if Live_Attached_Transport (Item) then
         declare
            Transcript_Ptr : constant SSH_Lib.Sessions.Live_Attachment.Transcript_Access :=
              SSH_Lib.Sessions.Live_Attachment.Transcript (Item);
         begin
            if Transcript_Ptr = null then
               Item.Session_Dirty := True;
               Item.Failure_Status := Write_Failed;
               return Write_Failed;
            end if;
            Status_Value := SSH_Lib.Sessions.Live_Transport.Check_Automatic_Rekey (Item);
            if Status_Value /= Ok then
               Item.Session_Dirty := True;
               Item.Failure_Status := Status_Value;
               return Status_Value;
            end if;

            Status_Value := SSH_Lib.Sessions.Live_Transcript.Send_Protected_Packet
              (Transcript_Ptr.all, To_Array (Payload));
            if Status_Value = Ok then
               Status_Value := Set
                 (Item.Live_Last_Protected_Channel,
                  SSH_Lib.Sessions.Live_Transcript.Last_Protected_Outbound
                    (Transcript_Ptr.all));
               if Status_Value = Ok then
                  SSH_Lib.Sessions.Live_Transport.Note_Protected_Outbound
                    (Item, Length (Item.Live_Last_Protected_Channel));
               end if;
            end if;
            if Status_Value /= Ok then
               Item.Session_Dirty := True;
               Item.Failure_Status := Status_Value;
            end if;
            return Status_Value;
         end;
      end if;

      Status_Value := SSH_Lib.Protocol.Protected_Packets.Encode_Protected_Packet
        (Item.Live_Open_Protected_State,
         To_Array (Payload),
         Item.Live_Last_Protected_Channel,
         Use_Test_Padding => True,
         Test_Padding_Byte => 16#00#);
      if Status_Value /= Ok then
         Item.Session_Dirty := True;
         Item.Failure_Status := Status_Value;
      end if;
      return Status_Value;
   exception
      when others =>
         Item.Session_Dirty := True;
         Item.Failure_Status := Internal_Error;
         return Internal_Error;
   end Send_Channel_Payload;

   function Queue_Channel_Response_For_Test
     (Item    : in out Session;
      Kind    : Channel_Response_Kind;
      Payload : Packet_Buffer)
      return Status
   is
      Encoded : Packet_Buffer;
      Peer_State : SSH_Lib.Protocol.Protected_Packets.Protected_State;
      Status_Value : Status;
   begin
      if not Item.Live_Channel_IO_Enabled then
         if Kind = Open_Response then
            return Set (Item.Test_Channel_Open_Response, To_Array (Payload));
         else
            return Set (Item.Test_Channel_Exec_Response, To_Array (Payload));
         end if;
      end if;

      SSH_Lib.Protocol.Protected_Packets.Reset (Peer_State, Boundary_Key);
      SSH_Lib.Protocol.Protected_Packets.Set_Sequences_For_Test
        (Peer_State,
         Inbound_Value => 0,
         Outbound_Value => SSH_Lib.Protocol.Protected_Packets.Inbound_Sequence
           (Item.Live_Open_Protected_State)
           + Interfaces.Unsigned_32'(if Kind = Exec_Response then 1 else 0));

      Status_Value := SSH_Lib.Protocol.Protected_Packets.Encode_Protected_Packet
        (Peer_State,
         To_Array (Payload),
         Encoded,
         Use_Test_Padding => True,
         Test_Padding_Byte => 16#00#);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      if Kind = Open_Response then
         return Set (Item.Test_Channel_Open_Response, To_Array (Encoded));
      else
         return Set (Item.Test_Channel_Exec_Response, To_Array (Encoded));
      end if;
   exception
      when others =>
         return Internal_Error;
   end Queue_Channel_Response_For_Test;

   function Read_Channel_Response
     (Item                      : in out Session;
      Kind                      : Channel_Response_Kind;
      Expected_Local_Channel_Id : Interfaces.Unsigned_32;
      Payload                   : out Packet_Buffer)
      return Status
   is
      Decoded : Packet_Buffer;
      Status_Value : Status;

      function U32_At
        (Data  : Stream_Element_Array;
         First : Stream_Element_Offset)
         return Interfaces.Unsigned_32
      is
      begin
         return Interfaces.Shift_Left (Interfaces.Unsigned_32 (Data (First)), 24)
           or Interfaces.Shift_Left (Interfaces.Unsigned_32 (Data (First + 1)), 16)
           or Interfaces.Shift_Left (Interfaces.Unsigned_32 (Data (First + 2)), 8)
           or Interfaces.Unsigned_32 (Data (First + 3));
      end U32_At;

      function Recipient_Matches
        (Candidate : Packet_Buffer)
         return Boolean
      is
         Data : constant Stream_Element_Array := To_Array (Candidate);
      begin
         return Data'Length >= 5
           and then U32_At (Data, Data'First + 1) = Expected_Local_Channel_Id;
      exception
         when others =>
            return False;
      end Recipient_Matches;

      function Is_Channel_Close_For_Expected
        (Candidate : Packet_Buffer)
         return Boolean
      is
         Data : constant Stream_Element_Array := To_Array (Candidate);
      begin
         return Data'Length >= 5
           and then Data (Data'First) = SSH_Lib.Protocol.Channels.SSH_MSG_CHANNEL_CLOSE
           and then U32_At (Data, Data'First + 1) = Expected_Local_Channel_Id;
      exception
         when others =>
            return False;
      end Is_Channel_Close_For_Expected;

      function Record_Channel_Window_Adjust_For_Expected
        (Candidate : Packet_Buffer)
         return Boolean
      is
         Data         : constant Stream_Element_Array := To_Array (Candidate);
         Bytes_To_Add : Interfaces.Unsigned_32;
      begin
         if Data'Length < 9
           or else Data (Data'First) /=
             SSH_Lib.Protocol.Channels.SSH_MSG_CHANNEL_WINDOW_ADJUST
           or else U32_At (Data, Data'First + 1) /= Expected_Local_Channel_Id
         then
            return False;
         end if;

         Bytes_To_Add := U32_At (Data, Data'First + 5);
         Item.Live_Pending_Window_Adjust_Known := True;
         Item.Live_Pending_Window_Adjust_Id := Expected_Local_Channel_Id;
         if Interfaces.Unsigned_32'Last
           - Item.Live_Pending_Window_Adjust_Bytes < Bytes_To_Add
         then
            Item.Live_Pending_Window_Adjust_Bytes := Interfaces.Unsigned_32'Last;
         else
            Item.Live_Pending_Window_Adjust_Bytes :=
              Item.Live_Pending_Window_Adjust_Bytes + Bytes_To_Add;
         end if;
         return True;
      exception
         when others =>
            return False;
      end Record_Channel_Window_Adjust_For_Expected;

      function Is_Stale_Channel_Teardown_For_Other_Channel
        (Candidate : Packet_Buffer)
         return Boolean
      is
         Data : constant Stream_Element_Array := To_Array (Candidate);
         Message : Stream_Element;
      begin
         if Data'Length < 5 then
            return False;
         end if;

         Message := Data (Data'First);
         return U32_At (Data, Data'First + 1) /= Expected_Local_Channel_Id
           and then
             (Message = SSH_Lib.Protocol.Channels.SSH_MSG_CHANNEL_EOF
              or else Message = SSH_Lib.Protocol.Channels.SSH_MSG_CHANNEL_CLOSE
              or else Message =
                SSH_Lib.Protocol.Channels.SSH_MSG_CHANNEL_WINDOW_ADJUST);
      exception
         when others =>
            return False;
      end Is_Stale_Channel_Teardown_For_Other_Channel;

      function Is_Expected_Channel_Response
        (Candidate : Packet_Buffer)
         return Boolean
      is
         Data : constant Stream_Element_Array := To_Array (Candidate);
      begin
         if Data'Length = 0 then
            return False;
         elsif not Recipient_Matches (Candidate) then
            return False;
         elsif Kind = Open_Response then
            return Data (Data'First) = 91 or else Data (Data'First) = 92;
         else
            return Data (Data'First) = 99 or else Data (Data'First) = 100;
         end if;
      exception
         when others =>
            return False;
      end Is_Expected_Channel_Response;

      function Reply_To_Global_Request_If_Needed
        (Transcript_Ptr : SSH_Lib.Sessions.Live_Attachment.Transcript_Access;
         Candidate      : Packet_Buffer)
         return Status
      is
         Data          : constant Stream_Element_Array := To_Array (Candidate);
         Request_Item  : SSH_Lib.Protocol.Global_Requests.Global_Request;
         Reply_Payload : Packet_Buffer;
         Reply_Status  : Status;
      begin
         if Data'Length = 0
           or else Data (Data'First) /=
             SSH_Lib.Protocol.Global_Requests.SSH_MSG_GLOBAL_REQUEST
         then
            return Ok;
         end if;

         Reply_Status := SSH_Lib.Protocol.Global_Requests.Parse_Global_Request
           (Data, Request_Item);
         if Reply_Status /= Ok then
            return Reply_Status;
         end if;

         if Request_Item.Want_Reply then
            Reply_Payload := SSH_Lib.Protocol.Global_Requests.Encode_Request_Failure;
            if Is_Empty (Reply_Payload) then
               return Write_Failed;
            end if;

            Reply_Status := SSH_Lib.Sessions.Live_Transcript.Send_Protected_Packet
              (Transcript_Ptr.all, To_Array (Reply_Payload));
            if Reply_Status = Ok then
               Reply_Status := Set
                 (Item.Live_Last_Protected_Channel,
                  SSH_Lib.Sessions.Live_Transcript.Last_Protected_Outbound
                    (Transcript_Ptr.all));
               if Reply_Status = Ok then
                  SSH_Lib.Sessions.Live_Transport.Note_Protected_Outbound
                    (Item, Length (Item.Live_Last_Protected_Channel));
               end if;
            end if;
            return Reply_Status;
         end if;

         return Ok;
      exception
         when others =>
            return Internal_Error;
      end Reply_To_Global_Request_If_Needed;

   begin
      Clear (Payload);
      if not Item.Live_Channel_IO_Enabled then
         if Kind = Open_Response then
            return Set (Payload, To_Array (Item.Test_Channel_Open_Response));
         else
            return Set (Payload, To_Array (Item.Test_Channel_Exec_Response));
         end if;
      end if;
      if not Enabled (Item) then
         Item.Session_Dirty := True;
         Item.Failure_Status := Read_Failed;
         return Read_Failed;
      end if;
      if Live_Attached_Transport (Item) then
         declare
            Transcript_Ptr : constant SSH_Lib.Sessions.Live_Attachment.Transcript_Access :=
              SSH_Lib.Sessions.Live_Attachment.Transcript (Item);
         begin
            if Transcript_Ptr = null then
               Item.Session_Dirty := True;
               Item.Failure_Status := Read_Failed;
               return Read_Failed;
            end if;

            for Attempt_Count in 1 .. 16 loop
               Status_Value := SSH_Lib.Sessions.Live_Transcript.Read_Protected_Packet
                 (Transcript_Ptr.all, Decoded);
               if Status_Value = Ok then
                  Status_Value := Set
                    (Item.Live_Last_Protected_Channel,
                     SSH_Lib.Sessions.Live_Transcript.Last_Protected_Inbound
                       (Transcript_Ptr.all));
                  if Status_Value = Ok then
                     SSH_Lib.Sessions.Live_Transport.Note_Protected_Inbound
                       (Item, Length (Item.Live_Last_Protected_Channel));
                  end if;
               end if;
               if Status_Value /= Ok then
                  Item.Session_Dirty := True;
                  Item.Failure_Status := Status_Value;
                  return Status_Value;
               end if;

               if Is_Expected_Channel_Response (Decoded) then
                  return Set (Payload, To_Array (Decoded));
               end if;

               declare
                  Decoded_Data : constant Stream_Element_Array := To_Array (Decoded);
               begin
                  if Is_Channel_Close_For_Expected (Decoded) then
                     --  A peer CHANNEL_CLOSE for the channel currently being
                     --  opened/executed is a channel-level refusal/teardown,
                     --  not a transport corruption.  Surface it as the
                     --  operation failure so Open_Exec can release the
                     --  transient slot while leaving the authenticated session
                     --  usable for later Git commands.
                     if Kind = Open_Response then
                        return Channel_Open_Failed;
                     else
                        return Channel_Request_Failed;
                     end if;
                  elsif Record_Channel_Window_Adjust_For_Expected (Decoded) then
                     null;
                  elsif Is_Stale_Channel_Teardown_For_Other_Channel (Decoded) then
                     null;
                  elsif Decoded_Data'Length > 0
                    and then Natural (Decoded_Data (Decoded_Data'First)) =
                      SSH_Lib.Protocol.Messages.SSH_MSG_KEXINIT
                  then
                     --  RFC 4253 permits either peer to initiate rekey after
                     --  authentication.  A server KEXINIT can legally arrive
                     --  while the client is synchronizing CHANNEL_OPEN or exec
                     --  CHANNEL_SUCCESS/FAILURE.  Complete the peer-initiated
                     --  rekey and continue waiting for the requested channel
                     --  response instead of treating the transport control
                     --  packet as a malformed channel reply.
                     Status_Value := SSH_Lib.Sessions.Live_Transport.Rekey_With_Peer_Kexinit
                       (Item, Decoded);
                     if Status_Value /= Ok then
                        Item.Session_Dirty := True;
                        Item.Failure_Status := Status_Value;
                        return Status_Value;
                     end if;
                  elsif Decoded_Data'Length > 0
                    and then Decoded_Data (Decoded_Data'First) =
                      SSH_Lib.Protocol.Global_Requests.SSH_MSG_GLOBAL_REQUEST
                  then
                     Status_Value := Reply_To_Global_Request_If_Needed
                       (Transcript_Ptr, Decoded);
                     if Status_Value /= Ok then
                        Item.Session_Dirty := True;
                        Item.Failure_Status := Status_Value;
                        return Status_Value;
                     end if;
                  elsif SSH_Lib.Protocol.Transport_Messages.Classify (Decoded_Data) =
                    SSH_Lib.Protocol.Transport_Messages.Transport_Disconnect
                  then
                     --  A transport disconnect received while synchronizing
                     --  CHANNEL_OPEN_CONFIRMATION or exec CHANNEL_SUCCESS is
                     --  a connection-level terminal condition, not a generic
                     --  channel-open/request failure.  Mark the authenticated
                     --  session dirty so a caller cannot continue Git I/O on a
                     --  transport the peer has explicitly closed.
                     Item.Session_Dirty := True;
                     Item.Failure_Status := Connection_Failed;
                     return Connection_Failed;
                  elsif not SSH_Lib.Protocol.Global_Requests.Ignorable_While_Waiting_For_Channel_Response
                    (Decoded_Data)
                  then
                     Item.Session_Dirty := True;
                     if Kind = Open_Response then
                        Item.Failure_Status := Channel_Open_Failed;
                        return Channel_Open_Failed;
                     else
                        Item.Failure_Status := Channel_Request_Failed;
                        return Channel_Request_Failed;
                     end if;
                  end if;
               end;
            end loop;

            Item.Session_Dirty := True;
            Item.Failure_Status := Timeout;
            return Timeout;
         end;
      end if;
      if Kind = Open_Response then
         Status_Value := SSH_Lib.Protocol.Protected_Packets.Decode_Protected_Packet
           (Item.Live_Open_Protected_State,
            To_Array (Item.Test_Channel_Open_Response),
            Decoded,
            Failure_When_Malformed => Read_Failed);
      else
         Status_Value := SSH_Lib.Protocol.Protected_Packets.Decode_Protected_Packet
           (Item.Live_Open_Protected_State,
            To_Array (Item.Test_Channel_Exec_Response),
            Decoded,
            Failure_When_Malformed => Read_Failed);
      end if;
      if Status_Value /= Ok then
         Item.Session_Dirty := True;
         Item.Failure_Status := Status_Value;
         return Status_Value;
      end if;
      declare
         Decoded_Data : constant Stream_Element_Array := To_Array (Decoded);
      begin
         if Is_Channel_Close_For_Expected (Decoded) then
            if Kind = Open_Response then
               return Channel_Open_Failed;
            else
               return Channel_Request_Failed;
            end if;
         elsif Record_Channel_Window_Adjust_For_Expected (Decoded) then
            null;
         elsif Is_Stale_Channel_Teardown_For_Other_Channel (Decoded) then
            null;
         elsif SSH_Lib.Protocol.Transport_Messages.Classify (Decoded_Data) =
           SSH_Lib.Protocol.Transport_Messages.Transport_Disconnect
         then
            Item.Session_Dirty := True;
            Item.Failure_Status := Connection_Failed;
            return Connection_Failed;
         elsif not Is_Expected_Channel_Response (Decoded) then
            Item.Session_Dirty := True;
            if Kind = Open_Response then
               Item.Failure_Status := Channel_Open_Failed;
               return Channel_Open_Failed;
            else
               Item.Failure_Status := Channel_Request_Failed;
               return Channel_Request_Failed;
            end if;
         end if;
      end;
      return Set (Payload, To_Array (Decoded));
   exception
      when others =>
         Clear (Payload);
         Item.Session_Dirty := True;
         Item.Failure_Status := Internal_Error;
         return Internal_Error;
   end Read_Channel_Response;

   function Take_Pending_Window_Adjust
     (Item             : in out Session;
      Local_Channel_Id : Interfaces.Unsigned_32;
      Bytes_To_Add     : out Interfaces.Unsigned_32)
      return Boolean
   is
   begin
      Bytes_To_Add := 0;
      if Item.Live_Pending_Window_Adjust_Known
        and then Item.Live_Pending_Window_Adjust_Id = Local_Channel_Id
      then
         Bytes_To_Add := Item.Live_Pending_Window_Adjust_Bytes;
         Item.Live_Pending_Window_Adjust_Known := False;
         Item.Live_Pending_Window_Adjust_Id := 0;
         Item.Live_Pending_Window_Adjust_Bytes := 0;
         return Bytes_To_Add > 0;
      end if;
      return False;
   exception
      when others =>
         Bytes_To_Add := 0;
         Item.Live_Pending_Window_Adjust_Known := False;
         Item.Live_Pending_Window_Adjust_Id := 0;
         Item.Live_Pending_Window_Adjust_Bytes := 0;
         return False;
   end Take_Pending_Window_Adjust;

   function Last_Plain_Channel_Payload_For_Test
     (Item : Session)
      return Packet_Buffer is
   begin
      return Item.Live_Last_Plain_Channel;
   end Last_Plain_Channel_Payload_For_Test;

   function Last_Protected_Channel_Payload_For_Test
     (Item : Session)
      return Packet_Buffer is
   begin
      return Item.Live_Last_Protected_Channel;
   end Last_Protected_Channel_Payload_For_Test;
end SSH_Lib.Sessions.Channel_IO;
