with Ada.Streams;
with SSH_Lib.Protocol.Failure_State;
with SSH_Lib.Protocol.Channels;
with SSH_Lib.Protocol.Global_Requests;
with SSH_Lib.Protocol.Messages;
with SSH_Lib.Protocol.Protected_Packets;
with SSH_Lib.Protocol.Transport_Messages;
with SSH_Lib.Sessions.Channel_IO;
with SSH_Lib.Sessions.Live_Attachment;
with SSH_Lib.Sessions.Live_Transcript;
with SSH_Lib.Sessions.Live_Transport;

package body SSH_Lib.Sessions.Channel_Table is
   use Interfaces;
   use CryptoLib.Errors;
   use type Ada.Streams.Stream_Element;
   use type SSH_Lib.Sessions.Live_Transcript.Driver_Access;
   use type SSH_Lib.Protocol.Transport_Messages.Transport_Message_Kind;

   function Effective_Limit (Item : Session) return Natural is
   begin
      if Item.Channel_Max_Open_Count > Max_Channel_Table_Slots then
         return Max_Channel_Table_Slots;
      else
         return Item.Channel_Max_Open_Count;
      end if;
   end Effective_Limit;

   function Contains
     (Item : Session; Local_Channel_Id : Unsigned_32) return Boolean is
   begin
      for Slot_Index in Item.Channel_Id_Used'Range loop
         if Item.Channel_Id_Used (Slot_Index)
           and then Item.Channel_Id_Slots (Slot_Index) = Local_Channel_Id
         then
            return True;
         end if;
      end loop;
      return False;
   end Contains;

   function Active_Count (Item : Session) return Natural is
   begin
      return Item.Channel_Active_Count;
   end Active_Count;

   function Allocate
     (Item : in out Session; Local_Channel_Id : out Unsigned_32) return Status
   is
      Candidate   : Unsigned_32;
      Free_Slot   : Natural := 0;
      Limit_Value : constant Natural := Effective_Limit (Item);
   begin
      Local_Channel_Id := 0;

      if Item.Session_Dirty then
         return
           SSH_Lib.Protocol.Failure_State.Dirty_Session_Operation_Status
             (Channel_Open_Failed);
      end if;

      if Limit_Value = 0 or else Item.Channel_Active_Count >= Limit_Value then
         return Channel_Open_Failed;
      end if;

      for Slot_Index in 1 .. Limit_Value loop
         if not Item.Channel_Id_Used (Slot_Index) then
            Free_Slot := Slot_Index;
            exit;
         end if;
      end loop;

      if Free_Slot = 0 then
         return Channel_Open_Failed;
      end if;

      Candidate := Item.Channel_Next_Local_Id;
      for Attempt_Count in 1 .. Max_Channel_Table_Slots loop
         exit when not Contains (Item, Candidate);
         Candidate := Candidate + 1;
      end loop;

      if Contains (Item, Candidate) then
         return Channel_Open_Failed;
      end if;

      Item.Channel_Id_Used (Free_Slot) := True;
      Item.Channel_Id_Slots (Free_Slot) := Candidate;
      Item.Channel_Next_Local_Id := Candidate + 1;
      Item.Channel_Active_Count := Item.Channel_Active_Count + 1;
      Local_Channel_Id := Candidate;
      return Ok;
   exception
      when others =>
         Local_Channel_Id := 0;
         return Internal_Error;
   end Allocate;

   procedure Release (Item : in out Session; Local_Channel_Id : Unsigned_32) is
   begin
      for Slot_Index in Item.Channel_Id_Used'Range loop
         if Item.Channel_Id_Used (Slot_Index)
           and then Item.Channel_Id_Slots (Slot_Index) = Local_Channel_Id
         then
            Item.Channel_Id_Used (Slot_Index) := False;
            Item.Channel_Id_Slots (Slot_Index) := 0;
            if Item.Channel_Active_Count > 0 then
               Item.Channel_Active_Count := Item.Channel_Active_Count - 1;
            end if;
            exit;
         end if;
      end loop;
   exception
      when others =>
         Item.Channel_Active_Count := 0;
         Item.Channel_Id_Used := [others => False];
         Item.Channel_Id_Slots := [others => 0];
   end Release;

   function Current_Generation (Item : Session) return Unsigned_32 is
   begin
      return Item.Channel_Generation;
   end Current_Generation;

   function Live_Channel_IO_Enabled (Item : Session) return Boolean is
   begin
      return SSH_Lib.Sessions.Channel_IO.Enabled (Item);
   exception
      when others =>
         return False;
   end Live_Channel_IO_Enabled;

   function Session_Read_Timeout_MS (Item : Session) return Natural is
   begin
      return Item.Stored_Options.Read_Timeout_MS;
   exception
      when others =>
         return 0;
   end Session_Read_Timeout_MS;

   function Session_Write_Timeout_MS (Item : Session) return Natural is
   begin
      return Item.Stored_Options.Write_Timeout_MS;
   exception
      when others =>
         return 0;
   end Session_Write_Timeout_MS;

   function Background_Channel_Reader_Enabled (Item : Session) return Boolean
   is
   begin
      return Item.Stored_Options.Enable_Background_Channel_Reader;
   exception
      when others =>
         return False;
   end Background_Channel_Reader_Enabled;

   function Send_Open_Payload
     (Item : in out Session; Payload : SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return Status is
   begin
      if Item.Session_Dirty then
         return
           SSH_Lib.Protocol.Failure_State.Dirty_Session_Operation_Status
             (Write_Failed);
      elsif Item.Stored_Options.Write_Timeout_MS = 0 then
         --  Immediate deadline before the CHANNEL_OPEN packet is emitted.
         --  No SSH bytes have become ambiguous, so record the cause but keep
         --  the authenticated session clean for caller-driven cleanup/retry.
         Item.Failure_Status := Timeout;
         return Timeout;
      elsif Item.Test_Partial_Channel_Write_Fails then
         Item.Session_Dirty := True;
         Item.Failure_Status := Write_Failed;
         return Write_Failed;
      elsif Item.Test_Write_Fails then
         --  Deterministic write failure before the CHANNEL_OPEN packet is
         --  emitted.  Because no SSH bytes are ambiguous, keep the
         --  authenticated session reusable after Open_Exec releases the
         --  transient channel slot.
         Item.Failure_Status := Write_Failed;
         return Write_Failed;
      end if;
      declare
         Store_Status : constant Status :=
           SSH_Lib.Protocol.Buffers.Set
             (Item.Test_Last_Channel_Open,
              SSH_Lib.Protocol.Buffers.To_Array (Payload));
      begin
         if Store_Status /= Ok then
            Mark_Failed (Item, Store_Status);
            return Store_Status;
         end if;
      end;
      return SSH_Lib.Sessions.Channel_IO.Send_Channel_Payload (Item, Payload);
   exception
      when others =>
         Mark_Failed (Item, Internal_Error);
         return Internal_Error;
   end Send_Open_Payload;

   function Send_Exec_Payload
     (Item : in out Session; Payload : SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return Status is
   begin
      if Item.Session_Dirty then
         return
           SSH_Lib.Protocol.Failure_State.Dirty_Session_Operation_Status
             (Write_Failed);
      elsif Item.Stored_Options.Write_Timeout_MS = 0
        or else Item.Test_Exec_Write_Timeout
      then
         --  Immediate deadline before the exec request packet is emitted.
         --  The stream is not ambiguous; the public Open_Exec fails without
         --  exposing a partially usable channel.
         Item.Failure_Status := Timeout;
         return Timeout;
      elsif Item.Test_Partial_Channel_Write_Fails then
         Item.Session_Dirty := True;
         Item.Failure_Status := Write_Failed;
         return Write_Failed;
      elsif Item.Test_Write_Fails then
         --  Deterministic write failure before the exec request packet is
         --  emitted.  The channel setup fails, but the session packet stream
         --  is still synchronized because no partial request is ambiguous.
         Item.Failure_Status := Write_Failed;
         return Write_Failed;
      end if;
      declare
         Store_Status : constant Status :=
           SSH_Lib.Protocol.Buffers.Set
             (Item.Test_Last_Exec_Request,
              SSH_Lib.Protocol.Buffers.To_Array (Payload));
      begin
         if Store_Status /= Ok then
            Mark_Failed (Item, Store_Status);
            return Store_Status;
         end if;
      end;
      return SSH_Lib.Sessions.Channel_IO.Send_Channel_Payload (Item, Payload);
   exception
      when others =>
         Mark_Failed (Item, Internal_Error);
         return Internal_Error;
   end Send_Exec_Payload;

   function Read_Inbound_Forwarded_Open
     (Item    : in out Session;
      Payload : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return Status
   is
      Decoded      : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Status_Value : Status;

      function Looks_Like_Channel_Open
        (Candidate : SSH_Lib.Protocol.Buffers.Packet_Buffer)
         return Boolean
      is
         Data : constant Ada.Streams.Stream_Element_Array :=
           SSH_Lib.Protocol.Buffers.To_Array (Candidate);
      begin
         return Data'Length > 0
           and then Data (Data'First) =
             SSH_Lib.Protocol.Channels.SSH_MSG_CHANNEL_OPEN;
      exception
         when others =>
            return False;
      end Looks_Like_Channel_Open;

      function Reply_To_Global_Request_If_Needed
        (Transcript_Ptr : SSH_Lib.Sessions.Live_Attachment.Transcript_Access;
         Candidate      : SSH_Lib.Protocol.Buffers.Packet_Buffer)
         return Status
      is
         Data          : constant Ada.Streams.Stream_Element_Array :=
           SSH_Lib.Protocol.Buffers.To_Array (Candidate);
         Request_Item  : SSH_Lib.Protocol.Global_Requests.Global_Request;
         Reply_Payload : SSH_Lib.Protocol.Buffers.Packet_Buffer;
         Reply_Status  : Status;
      begin
         if Data'Length = 0
           or else Data (Data'First) /=
             SSH_Lib.Protocol.Global_Requests.SSH_MSG_GLOBAL_REQUEST
         then
            return Ok;
         end if;

         Reply_Status :=
           SSH_Lib.Protocol.Global_Requests.Parse_Global_Request
             (Data, Request_Item);
         if Reply_Status /= Ok then
            return Reply_Status;
         end if;

         if Request_Item.Want_Reply then
            Reply_Payload :=
              SSH_Lib.Protocol.Global_Requests.Encode_Request_Failure;
            if SSH_Lib.Protocol.Buffers.Is_Empty (Reply_Payload) then
               return Write_Failed;
            end if;

            Reply_Status :=
              SSH_Lib.Sessions.Live_Transcript.Send_Protected_Packet
                (Transcript_Ptr.all,
                 SSH_Lib.Protocol.Buffers.To_Array (Reply_Payload));
            if Reply_Status = Ok then
               Reply_Status :=
                 SSH_Lib.Protocol.Buffers.Set
                   (Item.Live_Last_Protected_Channel,
                    SSH_Lib.Sessions.Live_Transcript
                      .Last_Protected_Outbound (Transcript_Ptr.all));
               if Reply_Status = Ok then
                  SSH_Lib.Sessions.Live_Transport.Note_Protected_Outbound
                    (Item,
                     SSH_Lib.Protocol.Buffers.Length
                       (Item.Live_Last_Protected_Channel));
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
      SSH_Lib.Protocol.Buffers.Clear (Payload);
      if Item.Session_Dirty then
         return
           SSH_Lib.Protocol.Failure_State.Dirty_Session_Operation_Status
             (Channel_Open_Failed);
      elsif not Item.Test_Has_Inbound_Forwarded_Open
        and then not SSH_Lib.Sessions.Live_Attachment.Attached (Item)
      then
         return Channel_Open_Failed;
      end if;

      if Item.Test_Has_Inbound_Forwarded_Open then
         if not Item.Live_Channel_IO_Enabled then
            Status_Value :=
              SSH_Lib.Protocol.Buffers.Set
                (Payload,
                 SSH_Lib.Protocol.Buffers.To_Array
                   (Item.Test_Inbound_Forwarded_Open));
         else
            Status_Value :=
              SSH_Lib.Protocol.Protected_Packets.Decode_Protected_Packet
                (Item.Live_Open_Protected_State,
                 SSH_Lib.Protocol.Buffers.To_Array
                   (Item.Test_Inbound_Forwarded_Open),
                 Payload,
                 Failure_When_Malformed => Read_Failed);
         end if;

         if Status_Value = Ok then
            SSH_Lib.Protocol.Buffers.Clear (Item.Test_Inbound_Forwarded_Open);
            Item.Test_Has_Inbound_Forwarded_Open := False;
         else
            Mark_Failed (Item, Status_Value);
         end if;
         return Status_Value;
      end if;

      declare
         Transcript_Ptr :
           constant SSH_Lib.Sessions.Live_Attachment.Transcript_Access :=
             SSH_Lib.Sessions.Live_Attachment.Transcript (Item);
      begin
         if Transcript_Ptr = null
           or else not SSH_Lib.Sessions.Channel_IO.Enabled (Item)
         then
            Mark_Failed (Item, Read_Failed);
            return Read_Failed;
         end if;

         for Attempt_Count in 1 .. 16 loop
            Status_Value :=
              SSH_Lib.Sessions.Live_Transcript.Read_Protected_Packet
                (Transcript_Ptr.all, Decoded);
            if Status_Value = Ok then
               Status_Value :=
                 SSH_Lib.Protocol.Buffers.Set
                   (Item.Live_Last_Protected_Channel,
                    SSH_Lib.Sessions.Live_Transcript
                      .Last_Protected_Inbound (Transcript_Ptr.all));
               if Status_Value = Ok then
                  SSH_Lib.Sessions.Live_Transport.Note_Protected_Inbound
                    (Item,
                     SSH_Lib.Protocol.Buffers.Length
                       (Item.Live_Last_Protected_Channel));
               end if;
            end if;
            if Status_Value /= Ok then
               Mark_Failed (Item, Status_Value);
               return Status_Value;
            end if;

            if Looks_Like_Channel_Open (Decoded) then
               return SSH_Lib.Protocol.Buffers.Set
                 (Payload, SSH_Lib.Protocol.Buffers.To_Array (Decoded));
            end if;

            declare
               Data : constant Ada.Streams.Stream_Element_Array :=
                 SSH_Lib.Protocol.Buffers.To_Array (Decoded);
            begin
               if Data'Length > 0
                 and then Natural (Data (Data'First)) =
                   SSH_Lib.Protocol.Messages.SSH_MSG_KEXINIT
               then
                  Status_Value :=
                    SSH_Lib.Sessions.Live_Transport.Rekey_With_Peer_Kexinit
                      (Item, Decoded);
               elsif Data'Length > 0
                 and then Data (Data'First) =
                   SSH_Lib.Protocol.Global_Requests.SSH_MSG_GLOBAL_REQUEST
               then
                  Status_Value :=
                    Reply_To_Global_Request_If_Needed
                      (Transcript_Ptr, Decoded);
               elsif SSH_Lib.Protocol.Transport_Messages.Classify (Data) =
                 SSH_Lib.Protocol.Transport_Messages.Transport_Disconnect
               then
                  Mark_Failed (Item, Connection_Failed);
                  return Connection_Failed;
               elsif SSH_Lib.Protocol.Global_Requests
                 .Ignorable_While_Waiting_For_Channel_Response (Data)
               then
                  Status_Value := Ok;
               else
                  Mark_Failed (Item, Channel_Open_Failed);
                  return Channel_Open_Failed;
               end if;
            end;

            if Status_Value /= Ok then
               Mark_Failed (Item, Status_Value);
               return Status_Value;
            end if;
         end loop;

         Item.Failure_Status := Timeout;
         return Timeout;
      end;
   exception
      when others =>
         SSH_Lib.Protocol.Buffers.Clear (Payload);
         Mark_Failed (Item, Internal_Error);
         return Internal_Error;
   end Read_Inbound_Forwarded_Open;

   procedure Mark_Failed (Item : in out Session; Status_Value : Status) is
   begin
      Item.Session_Dirty := True;
      if Status_Value = Ok then
         Item.Failure_Status := Internal_Error;
      else
         Item.Failure_Status := Status_Value;
      end if;
      if Status_Value = Cancelled then
         Item.Last_Operation_Cancelled := True;
      end if;
   end Mark_Failed;

   function Take_Next_Channel_Stdout_For_Test
     (Item : in out Session) return SSH_Lib.Protocol.Buffers.Packet_Buffer
   is
      Result : SSH_Lib.Protocol.Buffers.Packet_Buffer :=
        Item.Test_Next_Channel_Stdout;
   begin
      SSH_Lib.Protocol.Buffers.Clear (Item.Test_Next_Channel_Stdout);
      return Result;
   exception
      when others =>
         SSH_Lib.Protocol.Buffers.Clear (Result);
         SSH_Lib.Protocol.Buffers.Clear (Item.Test_Next_Channel_Stdout);
         return Result;
   end Take_Next_Channel_Stdout_For_Test;

   procedure Mark_Synchronization_Failed
     (Item : in out Session; Status_Value : Status) is
   begin
      Mark_Failed (Item, Status_Value);
   end Mark_Synchronization_Failed;

   function Read_Open_Response
     (Item                      : in out Session;
      Expected_Local_Channel_Id : Interfaces.Unsigned_32;
      Payload                   : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return Status is
   begin
      SSH_Lib.Protocol.Buffers.Clear (Payload);
      if Item.Session_Dirty then
         return
           SSH_Lib.Protocol.Failure_State.Dirty_Session_Operation_Status
             (Channel_Open_Failed);
      elsif Item.Test_Open_Cancelled then
         Mark_Synchronization_Failed (Item, Cancelled);
         return Cancelled;
      elsif Item.Test_Open_Timeout then
         Mark_Synchronization_Failed (Item, Timeout);
         return Timeout;
      elsif Item.Test_Read_Open_Fails then
         Mark_Synchronization_Failed (Item, Read_Failed);
         return Read_Failed;
      elsif not Item.Test_Has_Open_Response
        and then not SSH_Lib.Sessions.Live_Attachment.Attached (Item)
      then
         Mark_Synchronization_Failed (Item, Channel_Open_Failed);
         return Channel_Open_Failed;
      else
         return
           SSH_Lib.Sessions.Channel_IO.Read_Channel_Response
             (Item,
              SSH_Lib.Sessions.Channel_IO.Open_Response,
              Expected_Local_Channel_Id,
              Payload);
      end if;
   exception
      when others =>
         SSH_Lib.Protocol.Buffers.Clear (Payload);
         Mark_Synchronization_Failed (Item, Internal_Error);
         return Internal_Error;
   end Read_Open_Response;

   function Read_Exec_Response
     (Item                      : in out Session;
      Expected_Local_Channel_Id : Interfaces.Unsigned_32;
      Payload                   : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return Status is
   begin
      SSH_Lib.Protocol.Buffers.Clear (Payload);
      if Item.Session_Dirty then
         return
           SSH_Lib.Protocol.Failure_State.Dirty_Session_Operation_Status
             (Channel_Request_Failed);
      elsif Item.Test_Exec_Cancelled then
         Mark_Synchronization_Failed (Item, Cancelled);
         return Cancelled;
      elsif Item.Test_Exec_Timeout then
         Mark_Synchronization_Failed (Item, Timeout);
         return Timeout;
      elsif Item.Test_Read_Exec_Fails then
         Mark_Synchronization_Failed (Item, Read_Failed);
         return Read_Failed;
      elsif not Item.Test_Has_Exec_Response
        and then not SSH_Lib.Sessions.Live_Attachment.Attached (Item)
      then
         Mark_Synchronization_Failed (Item, Channel_Request_Failed);
         return Channel_Request_Failed;
      else
         return
           SSH_Lib.Sessions.Channel_IO.Read_Channel_Response
             (Item,
              SSH_Lib.Sessions.Channel_IO.Exec_Response,
              Expected_Local_Channel_Id,
              Payload);
      end if;
   exception
      when others =>
         SSH_Lib.Protocol.Buffers.Clear (Payload);
         Mark_Synchronization_Failed (Item, Internal_Error);
         return Internal_Error;
   end Read_Exec_Response;

   procedure Reset (Item : in out Session) is
   begin
      Item.Channel_Next_Local_Id := 0;
      Item.Channel_Active_Count := 0;
      Item.Channel_Id_Slots := [others => 0];
      Item.Channel_Id_Used := [others => False];
      if Item.Channel_Generation = Unsigned_32'Last then
         Item.Channel_Generation := 1;
      else
         Item.Channel_Generation := Item.Channel_Generation + 1;
      end if;
   exception
      when others =>
         Item.Channel_Next_Local_Id := 0;
         Item.Channel_Active_Count := 0;
         Item.Channel_Id_Slots := [others => 0];
         Item.Channel_Id_Used := [others => False];
         Item.Channel_Generation := 1;
   end Reset;
end SSH_Lib.Sessions.Channel_Table;
