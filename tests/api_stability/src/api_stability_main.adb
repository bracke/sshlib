with Ada.Command_Line;
with Ada.Directories;
with Ada.Streams;
with Ada.Strings.Unbounded;
with Ada.Text_IO;
with CryptoLib.Errors;
with CryptoLib.Hashes;
with SSH_Lib.Clients;
with SSH_Lib.Sessions;
with SSH_Lib.Channels;
with SSH_Lib.Known_Hosts;
with SSH_Lib.Keys;
with SSH_Lib.Config;
with SSH_Lib.Git;
with SSH_Lib.Remote_Names;
with SSH_Lib.Git_Transport;
with SSH_Lib.Forwarding;
with SSH_Lib.Config_Apply;
with SSH_Lib.Security_Keys;
with SSH_Lib.Protocol.Buffers;

procedure API_Stability_Main is
   use Ada.Strings.Unbounded;
   use type Ada.Streams.Stream_Element;
   use type Ada.Streams.Stream_Element_Array;
   use type Ada.Streams.Stream_Element_Offset;
   use type CryptoLib.Errors.Status;
   use type SSH_Lib.Forwarding.X11_Display_Transport;
   use type SSH_Lib.Git.Pkt_Line_Kind;
   use type SSH_Lib.Git.Pack_Object_Kind;
   use type SSH_Lib.Git.Porcelain_Path_Status;
   use type SSH_Lib.Git.Ref_Name_Kind;
   use type SSH_Lib.Git.Side_Band_Kind;
   use type SSH_Lib.Git.Status_Report_Kind;
   use type SSH_Lib.Git.Upload_Pack_ACK_Kind;
   use type SSH_Lib.Git.Fetch_Workflow_State;
   use type SSH_Lib.Git.Push_Workflow_State;
   use type SSH_Lib.Git.Fetch_Policy_Decision;
   use type SSH_Lib.Git.Push_Policy_Decision;
   use type SSH_Lib.Config_Apply.Control_Master_Mode;
   use type SSH_Lib.Config_Apply.Request_TTY_Mode;
   use type SSH_Lib.Config_Apply.Session_Type_Mode;

   Client_Item : SSH_Lib.Clients.Client := SSH_Lib.Clients.Create;
   pragma Unreferenced (Client_Item);

   Options : SSH_Lib.Sessions.Session_Options;
   Session_Item : SSH_Lib.Sessions.Session;
   Channel_Item : SSH_Lib.Channels.Channel;
   Listener_Item : SSH_Lib.Forwarding.Local_Forward_Listener;
   Connection_Item : SSH_Lib.Forwarding.Local_Forward_Connection;
   Service_Item : SSH_Lib.Forwarding.Forward_Service;
   Managed_Service_Item : SSH_Lib.Forwarding.Managed_Forward_Service;
   Config_Local_Services :
     SSH_Lib.Config_Apply.Managed_Forward_Service_Array (1 .. 1);
   Config_Dynamic_Services :
     SSH_Lib.Config_Apply.Managed_Forward_Service_Array (1 .. 1);
   Config_Remote_Services :
     SSH_Lib.Config_Apply.Managed_Forward_Service_Array (1 .. 1);
   Config_Bound_Ports : SSH_Lib.Config_Apply.Bound_Port_Array (1 .. 1);
   Security_Key_Request : SSH_Lib.Protocol.Buffers.Packet_Buffer;
   SOCKS_Target : SSH_Lib.Forwarding.SOCKS5_Target;
   X11_Target : SSH_Lib.Forwarding.X11_Display_Target;
   Status_Value : CryptoLib.Errors.Status := CryptoLib.Errors.Ok;
   Exit_Code : Integer := 0;
   Bound_Port : Natural := 0;
   Accepted_Count : Natural := 0;
   Completed_Count : Natural := 0;
   Active_Count : Natural := 0;
   Failed_Count : Natural := 0;
   Max_Concurrent : Natural := 0;
   Max_Accepted : Natural := 0;
   Config_Started : Natural := 0;
   Config_Requested : Natural := 0;
   Service_Kind : SSH_Lib.Forwarding.Forward_Service_Mode :=
     SSH_Lib.Forwarding.Local_Forward_Service;
   Last : Ada.Streams.Stream_Element_Offset;
   Pumped_Bytes : Natural := 0;
   Local_Pumped_Bytes : Natural := 0;
   Channel_Pumped_Bytes : Natural := 0;
   Request_Bytes : constant Ada.Streams.Stream_Element_Array (1 .. 6) :=
     [1 => 16#00#,
      2 => 16#0A#,
      3 => 16#0D#,
      4 => 16#7F#,
      5 => 16#80#,
      6 => 16#FF#];
   Buffer : Ada.Streams.Stream_Element_Array (1 .. 4096);
   Terminal_Modes : constant SSH_Lib.Channels.Terminal_Mode_Array :=
     [1 => (Opcode => 53, Value => 1),
      2 => (Opcode => 128, Value => 9_600)];
   Environment : constant SSH_Lib.Channels.Environment_Variable_Array :=
     [1 =>
        (Name  => To_Unbounded_String ("LANG"),
         Value => To_Unbounded_String ("C"))];

   Config_Path : constant String := "api_stability_empty_config.tmp";
   Config_File : Ada.Text_IO.File_Type;
   Config_Item : SSH_Lib.Config.Host_Config;
   Remote_Item : SSH_Lib.Remote_Names.Parsed_Remote;
   Unsupported_Config : Boolean := False;
   Explicit_Port     : Boolean := False;
   Transport_Command : Unbounded_String;
   Git_Workflow_Summary : SSH_Lib.Git_Transport.Git_Workflow_Summary;
   Forward_Text : Unbounded_String;
   Known_Hosts_Path : Ada.Strings.Unbounded.Unbounded_String;
   X11_Cookie_OK : Boolean := False;
   Pkt_Kind : SSH_Lib.Git.Pkt_Line_Kind := SSH_Lib.Git.Pkt_Data;
   Pkt_Cursor : SSH_Lib.Git.Pkt_Line_Cursor;
   Pkt_Length : Natural := 0;
   Pkt_Last : Ada.Streams.Stream_Element_Offset;
   Pkt_Packet_First : Ada.Streams.Stream_Element_Offset;
   Pkt_Packet_Last : Ada.Streams.Stream_Element_Offset;
   Pkt_Payload_First : Ada.Streams.Stream_Element_Offset;
   Pkt_Payload_Last : Ada.Streams.Stream_Element_Offset;
   Pkt_Buffer : Ada.Streams.Stream_Element_Array (1 .. 64);
   Pack_Version : Natural := 0;
   Pack_Index_Version : Natural := 0;
   Pack_Index_Count : Natural := 0;
   Pack_Index_CRC : Natural := 0;
   Pack_Index_Offset : Natural := 0;
   Pack_Index_Large_Offset : Natural := 0;
   Pack_Index_Large_Offset_Value : Natural := 0;
   Pack_Index_Uses_Large_Offset : Boolean := False;
   Pack_Index_Layout : SSH_Lib.Git.Pack_Index_Layout;
   Pack_Index_Object_IDs : SSH_Lib.Git.Object_ID_Hex_Array (1 .. 4);
   Pack_Index_Object_ID_Count : Natural := 0;
   Pack_Object_Counts : SSH_Lib.Git.Pack_Object_Counts;
   Pack_Count : Natural := 0;
   Pack_Sequence_Count : Natural := 0;
   Pack_Verified_Count : Natural := 0;
   Pack_Resolved_Count : Natural := 0;
   Pack_Kind : SSH_Lib.Git.Pack_Object_Kind := SSH_Lib.Git.Pack_Blob;
   Pack_Size : Natural := 0;
   Pack_Header_Length : Natural := 0;
   Pack_Payload_Offset : Natural := 0;
   Pack_Next_Offset : Natural := 0;
   Pack_Consumed_Length : Natural := 0;
   Pack_Inflated_Last : Ada.Streams.Stream_Element_Offset;
   Pack_Delta_Last : Ada.Streams.Stream_Element_Offset;
   Pack_Delta_Workspace : Ada.Streams.Stream_Element_Array (1 .. 64);
   Pack_Base_ID : Ada.Streams.Stream_Element_Array (1 .. 20);
   Pack_Base_Last : Ada.Streams.Stream_Element_Offset;
   Pack_Consumed : Natural := 0;
   Pack_Object_Index : Natural := 0;
   Pack_Offset : Natural := 0;
   Ref_Kind : SSH_Lib.Git.Ref_Name_Kind := SSH_Lib.Git.Ref_Other;
   Side_Kind : SSH_Lib.Git.Side_Band_Kind := SSH_Lib.Git.Side_Band_Data;
   Side_Band_Summary : SSH_Lib.Git.Side_Band_Stream_Summary;
   Report_Kind : SSH_Lib.Git.Status_Report_Kind :=
     SSH_Lib.Git.Status_Unpack_Error;
   Ack_Kind : SSH_Lib.Git.Upload_Pack_ACK_Kind :=
     SSH_Lib.Git.Upload_Pack_NAK;
   Negotiation_Summary : SSH_Lib.Git.Upload_Pack_Negotiation_Summary;
   ACK_Stream_Summary : SSH_Lib.Git.Upload_Pack_ACK_Stream_Summary;
   Receive_Summary : SSH_Lib.Git.Receive_Pack_Request_Summary;
   Upload_Response_Summary : SSH_Lib.Git.Upload_Pack_Response_Summary;
   Receive_Report_Summary : SSH_Lib.Git.Receive_Pack_Report_Summary;
   Fetch_Workflow : SSH_Lib.Git.Fetch_Workflow;
   Push_Workflow : SSH_Lib.Git.Push_Workflow;
   Git_Request_Buffer : SSH_Lib.Protocol.Buffers.Packet_Buffer;
   Porcelain_Status_Summary : SSH_Lib.Git.Porcelain_Status_Summary;
   Porcelain_Model : SSH_Lib.Git.Porcelain_Index_Worktree_Model;
   Database_Summary : SSH_Lib.Git.Repository_Database_Summary;
   Fetch_Decision : SSH_Lib.Git.Fetch_Policy_Decision;
   Push_Decision : SSH_Lib.Git.Push_Policy_Decision;
   Protocol_V2_Summary : SSH_Lib.Git.Protocol_V2_Request_Summary;
   Protocol_V2_Capability_Summary :
     SSH_Lib.Git.Protocol_V2_Capability_Summary;
   Protocol_V2_Response_Summary : SSH_Lib.Git.Protocol_V2_Response_Summary;
   Ref_Advertisement_Summary : SSH_Lib.Git.Ref_Advertisement_Summary;
   Object_ID_Text : SSH_Lib.Git.Object_ID_Hex_Text :=
     [others => Character'Pos ('0')];
   Ref_Object_Buffer : Ada.Streams.Stream_Element_Array (1 .. 40);
   Ref_Object_Last : Ada.Streams.Stream_Element_Offset;
   Ack_Buffer : Ada.Streams.Stream_Element_Array (1 .. 40);
   Ack_Last : Ada.Streams.Stream_Element_Offset;
   Status_Ref_Buffer : Ada.Streams.Stream_Element_Array (1 .. 32);
   Status_Ref_Last : Ada.Streams.Stream_Element_Offset;
   Status_Message_Buffer : Ada.Streams.Stream_Element_Array (1 .. 32);
   Status_Message_Last : Ada.Streams.Stream_Element_Offset;
   Capability_Name : Ada.Streams.Stream_Element_Array (1 .. 32);
   Capability_Name_Last : Ada.Streams.Stream_Element_Offset;
   Capability_Value : Ada.Streams.Stream_Element_Array (1 .. 32);
   Capability_Value_Last : Ada.Streams.Stream_Element_Offset;
   Capability_Has_Value : Boolean := False;
   Capability_Cursor : Ada.Streams.Stream_Element_Offset := 0;
   Capability_Token : Ada.Streams.Stream_Element_Array (1 .. 32);
   Capability_Token_Last : Ada.Streams.Stream_Element_Offset;
   Ref_Has_Caps : Boolean := False;
   Ref_Is_Peeled : Boolean := False;
   Ref_Is_Symref : Boolean := False;
   Capability_List_Has_Token : Boolean := False;
   Host_Key_Item : SSH_Lib.Known_Hosts.Host_Key;
   Fingerprint_Item : SSH_Lib.Keys.Fingerprint;
   Identity_Item : SSH_Lib.Keys.Identity;
   Host_Database : SSH_Lib.Known_Hosts.Database;
   pragma Unreferenced
     (Host_Key_Item, Fingerprint_Item, Identity_Item, Host_Database);

   procedure Touch (Value : CryptoLib.Errors.Status) is
   begin
      if Value = CryptoLib.Errors.Internal_Error then
         raise Program_Error;
      end if;
   end Touch;
begin
   Ada.Text_IO.Create (Config_File, Ada.Text_IO.Out_File, Config_Path);
   Ada.Text_IO.Close (Config_File);
   Status_Value := SSH_Lib.Config.Load (Config_Path, Config_Item);
   Touch (Status_Value);

   if not CryptoLib.Errors.Is_Success (CryptoLib.Errors.Ok) then
      raise Program_Error;
   end if;

   if CryptoLib.Errors.Is_Success (CryptoLib.Errors.Invalid_Host) then
      raise Program_Error;
   end if;

   if Options.Port /= 22
     or else Options.Connect_Timeout_MS /= 30_000
     or else Options.Read_Timeout_MS /= 30_000
     or else Options.Write_Timeout_MS /= 30_000
     or else not Options.Verify_Known_Host
     or else not Options.Use_Agent
     or else not Options.Strict_Host_Key
   then
      raise Program_Error;
   end if;

   Status_Value := SSH_Lib.Remote_Names.Parse
     ("git@example.com:repo.git", Remote_Item);
   if Status_Value = CryptoLib.Errors.Ok then
      Unsupported_Config := SSH_Lib.Config.Has_Unsupported_Feature
        (Config_Item, SSH_Lib.Remote_Names.Host (Remote_Item));
      Explicit_Port := SSH_Lib.Remote_Names.Has_Explicit_Port
        ("ssh://example.com:22/repo.git");
      if not Explicit_Port then
         raise Program_Error;
      end if;
      Status_Value := SSH_Lib.Config.Resolve_Remote
        (Config_Item, "ssh://example.com:22/repo.git", "git", Options);
      Touch (Status_Value);
      Options := SSH_Lib.Config.Resolve
        (Config_Item, SSH_Lib.Remote_Names.Host (Remote_Item));
      Options.Host := To_Unbounded_String
        (SSH_Lib.Remote_Names.Host (Remote_Item));
      Options.Port := SSH_Lib.Remote_Names.Port (Remote_Item);
      Options.User := To_Unbounded_String
        (SSH_Lib.Remote_Names.User (Remote_Item));
   else
      Options.Host := To_Unbounded_String ("example.com");
      Options.User := To_Unbounded_String ("git");
   end if;

   Status_Value := SSH_Lib.Git_Transport.Prepare
     ("git@example.com:repo.git", Config_Item, "git",
      SSH_Lib.Git_Transport.Upload_Pack, Options, Transport_Command);
   Touch (Status_Value);
   Status_Value := SSH_Lib.Git_Transport.Open_Service
     (Session_Item,
      SSH_Lib.Git_Transport.Upload_Pack,
      To_String (Transport_Command),
      Channel_Item);
   Touch (Status_Value);
   Status_Value := SSH_Lib.Git_Transport.Complete_Service
     (Channel_Item,
      SSH_Lib.Git_Transport.Upload_Pack,
      Request_Bytes,
      Buffer,
      Last,
      Git_Workflow_Summary);
   Touch (Status_Value);
   Status_Value := SSH_Lib.Git_Transport.Run_Service
     (Session_Item,
      SSH_Lib.Git_Transport.Receive_Pack,
      To_String (Transport_Command),
      Request_Bytes,
      Buffer,
      Last,
      Git_Workflow_Summary);
   Touch (Status_Value);
   Status_Value := SSH_Lib.Git_Transport.Run_Service_With_Local_Git
     ("",
      SSH_Lib.Git_Transport.Upload_Pack,
      Request_Bytes,
      Buffer,
      Last,
      Git_Workflow_Summary);
   Touch (Status_Value);
   Status_Value := SSH_Lib.Git_Transport.Run_Service_With_Local_SSH
     (Options,
      "",
      SSH_Lib.Git_Transport.Receive_Pack,
      Request_Bytes,
      Buffer,
      Last,
      Git_Workflow_Summary);
   Touch (Status_Value);
   declare
      Pkt_Data : constant Ada.Streams.Stream_Element_Array :=
        SSH_Lib.Protocol.Buffers.To_Array
          (SSH_Lib.Git.Encode_Pkt_Line
             ([Character'Pos ('w'), Character'Pos ('a'),
               Character'Pos ('n'), Character'Pos ('t')]));
   begin
      Status_Value :=
        SSH_Lib.Git.Parse_Pkt_Line_Header
          (Pkt_Data, Pkt_Kind, Pkt_Length);
      Touch (Status_Value);
      Status_Value :=
        SSH_Lib.Git.Copy_Pkt_Line_Payload
          (Pkt_Data, Pkt_Buffer, Pkt_Last);
      Touch (Status_Value);
      SSH_Lib.Git.Reset_Pkt_Line_Cursor (Pkt_Data, Pkt_Cursor);
      Status_Value :=
        SSH_Lib.Git.Next_Pkt_Line
          (Pkt_Data,
           Pkt_Cursor,
           Pkt_Kind,
           Pkt_Packet_First,
           Pkt_Packet_Last,
           Pkt_Payload_First,
           Pkt_Payload_Last);
      Touch (Status_Value);
      if Pkt_Kind /= SSH_Lib.Git.Pkt_Data
        or else Pkt_Length /= 8
        or else Pkt_Last < Pkt_Buffer'First
        or else Pkt_Packet_First /= Pkt_Data'First
        or else Pkt_Packet_Last /= Pkt_Data'Last
        or else Pkt_Payload_First /= Pkt_Data'First + 4
        or else Pkt_Payload_Last /= Pkt_Data'Last
        or else not SSH_Lib.Git.Pkt_Line_Cursor_Done (Pkt_Cursor)
      then
         raise Program_Error;
      end if;
      Status_Value :=
        SSH_Lib.Git.Parse_Pkt_Line_Header
          (SSH_Lib.Protocol.Buffers.To_Array (SSH_Lib.Git.Encode_Pkt_Flush),
           Pkt_Kind,
           Pkt_Length);
      Touch (Status_Value);
      if Pkt_Kind /= SSH_Lib.Git.Pkt_Flush
        or else Pkt_Length /= 0
        or else SSH_Lib.Protocol.Buffers.To_Array
          (SSH_Lib.Git.Encode_Pkt_Delimiter)'Length /= 4
        or else SSH_Lib.Protocol.Buffers.To_Array
          (SSH_Lib.Git.Encode_Pkt_Response_End)'Length /= 4
      then
         raise Program_Error;
      end if;
      Status_Value :=
        SSH_Lib.Git.Parse_Pack_Header
          ([Character'Pos ('P'), Character'Pos ('A'),
            Character'Pos ('C'), Character'Pos ('K'),
            0, 0, 0, 2,
            0, 0, 0, 1],
           Pack_Version,
           Pack_Count);
      Touch (Status_Value);
      Status_Value :=
        SSH_Lib.Git.Parse_Pack_Object_Header
          ([16#30#], Pack_Kind, Pack_Size, Pack_Header_Length);
      Touch (Status_Value);
      Status_Value :=
        SSH_Lib.Git.Parse_Pack_Index_Header
          ([16#FF#, Character'Pos ('t'), Character'Pos ('O'),
            Character'Pos ('c'), 0, 0, 0, 2],
           Pack_Index_Version);
      Touch (Status_Value);
      declare
         Fanout : Ada.Streams.Stream_Element_Array (1 .. 1024) :=
           [others => 0];
      begin
         Fanout (1024) := 1;
         Status_Value :=
           SSH_Lib.Git.Parse_Pack_Index_Fanout
             (Fanout, Pack_Index_Count);
         Touch (Status_Value);
      end;
      Status_Value :=
        SSH_Lib.Git.Copy_Pack_Index_Object_ID
          ([1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
            11, 12, 13, 14, 15, 16, 17, 18, 19, 20],
           0,
           Pack_Base_ID,
           Pack_Base_Last);
      Touch (Status_Value);
      Status_Value :=
        SSH_Lib.Git.Parse_Pack_Index_CRC
          ([16#12#, 16#34#, 16#56#, 16#78#],
           0,
           Pack_Index_CRC);
      Touch (Status_Value);
      Status_Value :=
        SSH_Lib.Git.Parse_Pack_Index_Offset
          ([0, 0, 1, 16#23#],
           0,
           Pack_Index_Offset,
           Pack_Index_Large_Offset,
           Pack_Index_Uses_Large_Offset);
      Touch (Status_Value);
      Status_Value :=
        SSH_Lib.Git.Parse_Pack_Index_Large_Offset
          ([0, 0, 0, 0, 0, 0, 4, 16#56#],
           0,
           Pack_Index_Large_Offset_Value);
      Touch (Status_Value);
      Status_Value :=
        SSH_Lib.Git.Copy_Pack_Index_Checksum
          ([1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
            11, 12, 13, 14, 15, 16, 17, 18, 19, 20],
           Pack_Base_ID,
           Pack_Base_Last);
      Touch (Status_Value);
      Status_Value :=
        SSH_Lib.Git.Compute_Pack_Index_Layout
          (1, 0, Pack_Index_Layout);
      Touch (Status_Value);
      Status_Value :=
        SSH_Lib.Git.Validate_Pack_Index_Object_ID_Order
          ([1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
            11, 12, 13, 14, 15, 16, 17, 18, 19, 20],
           1);
      Touch (Status_Value);
      declare
         Fanout : Ada.Streams.Stream_Element_Array (1 .. 1024) :=
           [others => 0];
      begin
         for Index in 1 .. 255 loop
            Fanout (Ada.Streams.Stream_Element_Offset (Index * 4 + 4)) := 1;
         end loop;

         Status_Value :=
           SSH_Lib.Git.Validate_Pack_Index_Fanout_Matches_Object_IDs
             (Fanout,
              [1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
               11, 12, 13, 14, 15, 16, 17, 18, 19, 20],
              1);
         Touch (Status_Value);
      end;
      Status_Value :=
        SSH_Lib.Git.Validate_Pack_Index_Large_Offset_Count
          ([0, 0, 1, 16#23#],
           1,
           0);
      Touch (Status_Value);
      declare
         Index_Data : Ada.Streams.Stream_Element_Array (1 .. 1100) :=
           [others => 0];
         Full_Count : Natural := 0;
         Full_Large_Count : Natural := 0;
         Full_Layout : SSH_Lib.Git.Pack_Index_Layout;
      begin
         Index_Data (1 .. 8) :=
           [16#FF#, Character'Pos ('t'), Character'Pos ('O'),
            Character'Pos ('c'), 0, 0, 0, 2];
         for Bucket in 1 .. 255 loop
            Index_Data
              (Ada.Streams.Stream_Element_Offset (8 + Bucket * 4 + 4)) := 1;
         end loop;
         Index_Data (1033) := 1;
         Index_Data (1057 .. 1060) := [0, 0, 0, 16#0C#];

         Status_Value :=
           SSH_Lib.Git.Validate_Pack_Index
             (Index_Data, Full_Count, Full_Large_Count, Full_Layout);
         Touch (Status_Value);
         if Full_Count = Natural'Last
           or else Full_Large_Count = Natural'Last
           or else Full_Layout.Total_Length = Natural'Last
         then
            raise Program_Error;
         end if;

	         Status_Value :=
	           SSH_Lib.Git.Find_Pack_Index_Object
	             (Index_Data,
	              [1 => 1, 2 .. 20 => 0],
	              Pack_Object_Index,
	              Pack_Offset);
	         Touch (Status_Value);

	         Status_Value :=
	           SSH_Lib.Git.Find_Pack_Index_Object_Hex
	             (Index_Data,
	              [1 => Character'Pos ('0'),
	               2 => Character'Pos ('1'),
	               3 .. 40 => Character'Pos ('0')],
	              Pack_Object_Index,
	              Pack_Offset);
	         Touch (Status_Value);

         Status_Value :=
           SSH_Lib.Git.List_Pack_Index_Object_IDs
             (Index_Data,
              Pack_Index_Object_IDs,
              Pack_Index_Object_ID_Count);
         Touch (Status_Value);

	         Status_Value :=
	           SSH_Lib.Git.Validate_Pack_Index_Offsets
             (Index_Data,
              [Character'Pos ('P'), Character'Pos ('A'), Character'Pos ('C'),
               Character'Pos ('K'), 0, 0, 0, 2, 0, 0, 0, 1,
               16#30#, 16#78#, 16#9C#, 16#03#, 16#00#, 16#00#,
               16#00#, 16#00#, 16#01#, 0, 0, 0, 0, 0, 0, 0,
               0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
              Pkt_Buffer,
              Pack_Sequence_Count,
              Pack_Offset);
         Touch (Status_Value);

         Status_Value :=
           SSH_Lib.Git.Validate_Pack_Index_CRCs
             (Index_Data,
              [Character'Pos ('P'), Character'Pos ('A'), Character'Pos ('C'),
               Character'Pos ('K'), 0, 0, 0, 2, 0, 0, 0, 1,
               16#30#, 16#78#, 16#9C#, 16#03#, 16#00#, 16#00#,
               16#00#, 16#00#, 16#01#, 0, 0, 0, 0, 0, 0, 0,
               0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
              Pkt_Buffer,
              Pack_Sequence_Count,
              Pack_Offset);
         Touch (Status_Value);

         Status_Value :=
           SSH_Lib.Git.Validate_Pack_Delta_Bases
             (Index_Data,
              [Character'Pos ('P'), Character'Pos ('A'), Character'Pos ('C'),
               Character'Pos ('K'), 0, 0, 0, 2, 0, 0, 0, 1,
               16#30#, 16#78#, 16#9C#, 16#03#, 16#00#, 16#00#,
               16#00#, 16#00#, 16#01#, 0, 0, 0, 0, 0, 0, 0,
               0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
              Pkt_Buffer,
              Pack_Sequence_Count,
              Pack_Offset);
         Touch (Status_Value);

         Status_Value :=
           SSH_Lib.Git.Validate_Pack_Delta_Graph
             (Index_Data,
              [Character'Pos ('P'), Character'Pos ('A'), Character'Pos ('C'),
               Character'Pos ('K'), 0, 0, 0, 2, 0, 0, 0, 1,
               16#30#, 16#78#, 16#9C#, 16#03#, 16#00#, 16#00#,
               16#00#, 16#00#, 16#01#, 0, 0, 0, 0, 0, 0, 0,
               0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
              Pkt_Buffer,
              Pack_Sequence_Count,
              Pack_Offset);
         Touch (Status_Value);

         Status_Value :=
           SSH_Lib.Git.Validate_Pack_Non_Delta_Object_IDs
             (Index_Data,
              [Character'Pos ('P'), Character'Pos ('A'), Character'Pos ('C'),
               Character'Pos ('K'), 0, 0, 0, 2, 0, 0, 0, 1,
               16#30#, 16#78#, 16#9C#, 16#03#, 16#00#, 16#00#,
               16#00#, 16#00#, 16#01#, 0, 0, 0, 0, 0, 0, 0,
               0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
              Pkt_Buffer,
              Pack_Sequence_Count,
              Pack_Verified_Count,
              Pack_Offset);
         Touch (Status_Value);

         Status_Value :=
           SSH_Lib.Git.Validate_Pack_Immediate_Delta_Object_IDs
             (Index_Data,
              [Character'Pos ('P'), Character'Pos ('A'), Character'Pos ('C'),
               Character'Pos ('K'), 0, 0, 0, 2, 0, 0, 0, 1,
               16#30#, 16#78#, 16#9C#, 16#03#, 16#00#, 16#00#,
               16#00#, 16#00#, 16#01#, 0, 0, 0, 0, 0, 0, 0,
              0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
              Pkt_Buffer,
              Pack_Delta_Workspace,
              Status_Message_Buffer,
              Pack_Sequence_Count,
              Pack_Resolved_Count,
              Pack_Offset);
         Touch (Status_Value);

         Status_Value :=
           SSH_Lib.Git.Validate_Pack_Delta_Chain_Object_IDs
             (Index_Data,
              [Character'Pos ('P'), Character'Pos ('A'), Character'Pos ('C'),
               Character'Pos ('K'), 0, 0, 0, 2, 0, 0, 0, 1,
               16#30#, 16#78#, 16#9C#, 16#03#, 16#00#, 16#00#,
               16#00#, 16#00#, 16#01#, 0, 0, 0, 0, 0, 0, 0,
               0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
              Pkt_Buffer,
              Pack_Delta_Workspace,
              Status_Ref_Buffer,
              Status_Message_Buffer,
              Pack_Sequence_Count,
              Pack_Resolved_Count,
              Pack_Offset);
         Touch (Status_Value);

         Status_Value :=
           SSH_Lib.Git.Validate_Pack_Object_IDs
             (Index_Data,
              [Character'Pos ('P'), Character'Pos ('A'), Character'Pos ('C'),
               Character'Pos ('K'), 0, 0, 0, 2, 0, 0, 0, 1,
               16#30#, 16#78#, 16#9C#, 16#03#, 16#00#, 16#00#,
               16#00#, 16#00#, 16#01#, 0, 0, 0, 0, 0, 0, 0,
               0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
              Pkt_Buffer,
              Pack_Delta_Workspace,
              Status_Ref_Buffer,
              Status_Message_Buffer,
              Pack_Sequence_Count,
              Pack_Verified_Count,
              Pack_Resolved_Count,
              Pack_Offset);
         Touch (Status_Value);

	         Status_Value :=
	           SSH_Lib.Git.Validate_Pack_Integrity
             (Index_Data,
              [Character'Pos ('P'), Character'Pos ('A'), Character'Pos ('C'),
               Character'Pos ('K'), 0, 0, 0, 2, 0, 0, 0, 1,
               16#30#, 16#78#, 16#9C#, 16#03#, 16#00#, 16#00#,
               16#00#, 16#00#, 16#01#, 0, 0, 0, 0, 0, 0, 0,
               0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
              Pkt_Buffer,
              Pack_Delta_Workspace,
              Status_Ref_Buffer,
              Status_Message_Buffer,
              Pack_Sequence_Count,
              Pack_Verified_Count,
              Pack_Resolved_Count,
	              Pack_Offset);
	         Touch (Status_Value);

	         Status_Value :=
	           SSH_Lib.Git.Inventory_Pack_Objects
	             ([Character'Pos ('P'), Character'Pos ('A'), Character'Pos ('C'),
	               Character'Pos ('K'), 0, 0, 0, 2, 0, 0, 0, 1,
	               16#30#, 16#78#, 16#9C#, 16#03#, 16#00#, 16#00#,
	               16#00#, 16#00#, 16#01#, 0, 0, 0, 0, 0, 0, 0,
	               0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
	              Pkt_Buffer,
	              Pack_Object_Counts,
	              Pack_Sequence_Count,
	              Pack_Offset);
	         Touch (Status_Value);

	         Status_Value :=
	           SSH_Lib.Git.Compute_Object_ID
	             (SSH_Lib.Git.Pack_Blob,
	              [Character'Pos ('h'), Character'Pos ('e'),
	               Character'Pos ('l'), Character'Pos ('l'),
	               Character'Pos ('o')],
	              Pack_Base_ID,
	              Pack_Base_Last);
	         Touch (Status_Value);

	         Status_Value :=
	           SSH_Lib.Git.Encode_Object_ID_Hex
	             (Pack_Base_ID,
	              Pkt_Buffer,
	              Pkt_Last);
	         Touch (Status_Value);

	         Status_Value :=
	           SSH_Lib.Git.Parse_Object_ID_Hex
	             (Pkt_Buffer (1 .. 40),
	              Pack_Base_ID,
	              Pack_Base_Last);
	         Touch (Status_Value);
	      end;
      Status_Value :=
        SSH_Lib.Git.Inflate_Pack_Object_Data
          ([16#78#, 16#9C#, 16#03#, 16#00#, 16#00#, 16#00#,
            16#00#, 16#01#],
           0,
           Pkt_Buffer,
           Pack_Inflated_Last);
      Touch (Status_Value);
      Status_Value :=
        SSH_Lib.Git.Inflate_Pack_Object_Data
          ([16#78#, 16#9C#, 16#03#, 16#00#, 16#00#, 16#00#,
            16#00#, 16#01#],
           0,
           Pkt_Buffer,
           Pack_Inflated_Last,
           Pack_Consumed_Length);
      Touch (Status_Value);
      Status_Value :=
        SSH_Lib.Git.Inflate_Pack_Object_At_Offset
          ([Character'Pos ('P'), Character'Pos ('A'), Character'Pos ('C'),
            Character'Pos ('K'), 0, 0, 0, 2, 0, 0, 0, 1,
            16#30#, 16#78#, 16#9C#, 16#03#, 16#00#, 16#00#,
            16#00#, 16#00#, 16#01#],
           12,
           Pack_Kind,
           Pack_Size,
           Pack_Header_Length,
           Pack_Payload_Offset,
           Pkt_Buffer,
           Pack_Inflated_Last);
      Touch (Status_Value);
      Status_Value :=
        SSH_Lib.Git.Inflate_Pack_Object_At_Offset
          ([Character'Pos ('P'), Character'Pos ('A'), Character'Pos ('C'),
            Character'Pos ('K'), 0, 0, 0, 2, 0, 0, 0, 1,
            16#30#, 16#78#, 16#9C#, 16#03#, 16#00#, 16#00#,
            16#00#, 16#00#, 16#01#],
           12,
           Pack_Kind,
           Pack_Size,
           Pack_Header_Length,
           Pack_Payload_Offset,
           Pkt_Buffer,
           Pack_Inflated_Last,
           Pack_Next_Offset);
      Touch (Status_Value);
      Status_Value :=
        SSH_Lib.Git.Validate_Pack_Object_Sequence
          ([Character'Pos ('P'), Character'Pos ('A'), Character'Pos ('C'),
            Character'Pos ('K'), 0, 0, 0, 2, 0, 0, 0, 1,
            16#30#, 16#78#, 16#9C#, 16#03#, 16#00#, 16#00#,
           16#00#, 16#00#, 16#01#, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
           Pkt_Buffer,
           Pack_Sequence_Count,
           Pack_Offset);
      Touch (Status_Value);
      Status_Value :=
        SSH_Lib.Git.Apply_Pack_Delta
          ([Character'Pos ('a')],
           [1, 1, 16#90#, 1],
           Pkt_Buffer,
           Pack_Delta_Last);
      Touch (Status_Value);
      Status_Value :=
        SSH_Lib.Git.Apply_Pack_Delta_Chain
          ([Character'Pos ('a')],
           [1 .. 4 => 1],
           [(First => 1, Last => 4)],
           Pack_Delta_Workspace,
           Pkt_Buffer,
           Pack_Delta_Last);
      Touch (Status_Value);
      if Pack_Version /= 2
        or else Pack_Count /= 1
        or else Pack_Index_Version /= 2
        or else Pack_Index_Count /= 1
        or else Pack_Index_CRC /= 16#12345678#
        or else Pack_Index_Offset /= 16#123#
        or else Pack_Index_Large_Offset /= 0
        or else Pack_Index_Large_Offset_Value /= 16#456#
        or else Pack_Index_Layout.Total_Length /= 1_100
        or else Pack_Index_Uses_Large_Offset
        or else Pack_Base_Last < Pack_Base_ID'First
        or else Pack_Kind /= SSH_Lib.Git.Pack_Blob
        or else Pack_Header_Length /= 1
      then
         raise Program_Error;
      end if;
      Status_Value :=
        SSH_Lib.Git.Parse_Pack_REF_Delta_Base
          ([1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
            11, 12, 13, 14, 15, 16, 17, 18, 19, 20],
           Pack_Base_ID, Pack_Base_Last, Pack_Consumed);
      Touch (Status_Value);
      Status_Value :=
        SSH_Lib.Git.Parse_Pack_OFS_Delta_Base
          ([16#80#, 16#00#], Pack_Offset, Pack_Consumed);
      Touch (Status_Value);
      if Pack_Base_Last < Pack_Base_ID'First
        or else Pack_Offset /= 128
      then
         raise Program_Error;
      end if;
      Status_Value :=
        SSH_Lib.Git.Classify_Ref_Name ("refs/heads/main", Ref_Kind);
      Touch (Status_Value);
      if not SSH_Lib.Git.Valid_Object_ID
          ("0123456789abcdef0123456789ABCDEF01234567")
        or else not SSH_Lib.Git.Valid_Ref_Name ("refs/tags/v1")
        or else Ref_Kind /= SSH_Lib.Git.Ref_Branch
      then
         raise Program_Error;
      end if;
      Status_Value :=
        SSH_Lib.Git.Parse_Side_Band_Packet
          ([Character'Pos ('0'), Character'Pos ('0'),
            Character'Pos ('0'), Character'Pos ('6'),
            2, Character'Pos ('!')],
           Side_Kind, Pkt_Buffer, Pkt_Last);
      Touch (Status_Value);
      if Side_Kind /= SSH_Lib.Git.Side_Band_Progress
        or else Pkt_Last /= Pkt_Buffer'First
      then
         raise Program_Error;
      end if;
      Status_Value :=
        SSH_Lib.Git.Validate_Side_Band_Stream
          (SSH_Lib.Protocol.Buffers.To_Array
             (SSH_Lib.Git.Encode_Pkt_Line
                ([1 => 2, 2 => Character'Pos ('!')]))
           & SSH_Lib.Protocol.Buffers.To_Array
               (SSH_Lib.Git.Encode_Pkt_Flush),
           Side_Band_Summary);
      Touch (Status_Value);
      if Side_Band_Summary.Progress_Count /= 1
        or else not Side_Band_Summary.Has_Flush
      then
         raise Program_Error;
      end if;
      Status_Value :=
        SSH_Lib.Git.Parse_Status_Report_Packet
          ([Character'Pos ('0'), Character'Pos ('0'),
            Character'Pos ('0'), Character'Pos ('e'),
            Character'Pos ('u'), Character'Pos ('n'),
            Character'Pos ('p'), Character'Pos ('a'),
            Character'Pos ('c'), Character'Pos ('k'),
            Character'Pos (' '), Character'Pos ('o'),
            Character'Pos ('k'), Character'Pos (Character'Val (10))],
           Report_Kind,
           Status_Ref_Buffer, Status_Ref_Last,
           Status_Message_Buffer, Status_Message_Last);
      Touch (Status_Value);
      if Report_Kind /= SSH_Lib.Git.Status_Unpack_Ok
        or else Status_Ref_Last >= Status_Ref_Buffer'First
        or else Status_Message_Last >= Status_Message_Buffer'First
      then
         raise Program_Error;
      end if;
      Status_Value :=
        SSH_Lib.Git.Parse_Capability_Token
          ([Character'Pos ('a'), Character'Pos ('g'),
            Character'Pos ('e'), Character'Pos ('n'),
            Character'Pos ('t'), Character'Pos ('='),
            Character'Pos ('s'), Character'Pos ('s'),
            Character'Pos ('h'), Character'Pos ('l'),
            Character'Pos ('i'), Character'Pos ('b')],
           Capability_Name, Capability_Name_Last,
           Capability_Value, Capability_Value_Last,
           Capability_Has_Value);
      Touch (Status_Value);
      if not Capability_Has_Value
        or else Capability_Name_Last < Capability_Name'First
        or else Capability_Value_Last < Capability_Value'First
      then
         raise Program_Error;
      end if;
      declare
         Capability_List : constant Ada.Streams.Stream_Element_Array :=
           [Character'Pos ('m'), Character'Pos ('u'),
            Character'Pos ('l'), Character'Pos ('t'),
            Character'Pos ('i'), Character'Pos ('_'),
            Character'Pos ('a'), Character'Pos ('c'),
            Character'Pos ('k'), Character'Pos (' '),
            Character'Pos ('a'), Character'Pos ('g'),
            Character'Pos ('e'), Character'Pos ('n'),
            Character'Pos ('t'), Character'Pos ('='),
            Character'Pos ('s'), Character'Pos ('s'),
            Character'Pos ('h'), Character'Pos ('l'),
            Character'Pos ('i'), Character'Pos ('b')];
      begin
         Capability_Cursor := Capability_List'First;
         Status_Value :=
           SSH_Lib.Git.Copy_Next_Capability_Token
             (Capability_List,
              Capability_Cursor,
              Capability_Token, Capability_Token_Last,
              Capability_List_Has_Token);
         Touch (Status_Value);
         if not Capability_List_Has_Token
           or else Capability_Token_Last < Capability_Token'First
         then
            raise Program_Error;
         end if;
      end;
      declare
         Object_Hex : constant Ada.Streams.Stream_Element_Array :=
           [Character'Pos ('3'), Character'Pos ('b'),
            Character'Pos ('1'), Character'Pos ('8'),
            Character'Pos ('e'), Character'Pos ('5'),
            Character'Pos ('1'), Character'Pos ('2'),
            Character'Pos ('d'), Character'Pos ('b'),
            Character'Pos ('a'), Character'Pos ('7'),
            Character'Pos ('9'), Character'Pos ('e'),
            Character'Pos ('4'), Character'Pos ('c'),
            Character'Pos ('8'), Character'Pos ('3'),
            Character'Pos ('0'), Character'Pos ('0'),
            Character'Pos ('d'), Character'Pos ('d'),
            Character'Pos ('0'), Character'Pos ('8'),
            Character'Pos ('a'), Character'Pos ('e'),
            Character'Pos ('b'), Character'Pos ('3'),
            Character'Pos ('7'), Character'Pos ('f'),
            Character'Pos ('8'), Character'Pos ('e'),
            Character'Pos ('7'), Character'Pos ('2'),
            Character'Pos ('8'), Character'Pos ('b'),
            Character'Pos ('8'), Character'Pos ('d'),
            Character'Pos ('a'), Character'Pos ('d')];
         Caps : constant Ada.Streams.Stream_Element_Array :=
           [Character'Pos ('m'), Character'Pos ('u'),
            Character'Pos ('l'), Character'Pos ('t'),
            Character'Pos ('i'), Character'Pos ('_'),
            Character'Pos ('a'), Character'Pos ('c'),
            Character'Pos ('k')];
         Want_Line : constant Ada.Streams.Stream_Element_Array :=
           SSH_Lib.Protocol.Buffers.To_Array
             (SSH_Lib.Git.Encode_Upload_Pack_Want_Line
                (Object_Hex, Caps));
         Done_Line : constant Ada.Streams.Stream_Element_Array :=
           SSH_Lib.Protocol.Buffers.To_Array
             (SSH_Lib.Git.Encode_Upload_Pack_Done_Line);
      begin
         if SSH_Lib.Protocol.Buffers.To_Array
              (SSH_Lib.Git.Encode_Upload_Pack_Have_Line (Object_Hex))'Length
            = 0
           or else SSH_Lib.Protocol.Buffers.To_Array
              (SSH_Lib.Git.Encode_Upload_Pack_Deepen_Line (1))'Length = 0
           or else SSH_Lib.Protocol.Buffers.To_Array
              (SSH_Lib.Git.Encode_Upload_Pack_Shallow_Line (Object_Hex))'Length
              = 0
           or else SSH_Lib.Protocol.Buffers.To_Array
              (SSH_Lib.Git.Encode_Upload_Pack_Filter_Line
                 ([Character'Pos ('b'), Character'Pos ('l'),
                   Character'Pos ('o'), Character'Pos ('b'),
                   Character'Pos (':'), Character'Pos ('n'),
                   Character'Pos ('o'), Character'Pos ('n'),
                   Character'Pos ('e')]))'Length = 0
         then
            raise Program_Error;
         end if;

         Status_Value :=
           SSH_Lib.Git.Validate_Upload_Pack_Negotiation_Request
             (Want_Line & Done_Line, Negotiation_Summary);
         Touch (Status_Value);
         if Negotiation_Summary.Want_Count = 0
           or else not Negotiation_Summary.Has_Done
         then
            raise Program_Error;
         end if;

         Status_Value :=
           SSH_Lib.Git.Parse_Upload_Pack_ACK_Packet
             ([Character'Pos ('0'), Character'Pos ('0'),
               Character'Pos ('0'), Character'Pos ('8'),
               Character'Pos ('N'), Character'Pos ('A'),
               Character'Pos ('K'), Character'Pos (Character'Val (10))],
              Ack_Kind, Ack_Buffer, Ack_Last);
         Touch (Status_Value);
         if Ack_Kind /= SSH_Lib.Git.Upload_Pack_NAK
           or else Ack_Last >= Ack_Buffer'First
         then
            raise Program_Error;
         end if;
         declare
            ACK_Stream : constant Ada.Streams.Stream_Element_Array (1 .. 8) :=
              [Character'Pos ('0'), Character'Pos ('0'),
               Character'Pos ('0'), Character'Pos ('8'),
               Character'Pos ('N'), Character'Pos ('A'),
               Character'Pos ('K'), Character'Pos (Character'Val (10))];
         begin
            Status_Value :=
              SSH_Lib.Git.Validate_Upload_Pack_ACK_Stream
                (ACK_Stream, ACK_Stream_Summary);
            Touch (Status_Value);
            if ACK_Stream_Summary.NAK_Count /= 1 then
               raise Program_Error;
            end if;
         end;

         for Index in Object_ID_Text'Range loop
            Object_ID_Text (Index) :=
              Object_Hex
                (Object_Hex'First
                 + Ada.Streams.Stream_Element_Offset (Index - 1));
         end loop;

         declare
            Repo_Root : constant String := "api_stability_git_state_repo";
            Stored_Hex : Ada.Streams.Stream_Element_Array (1 .. 40);
            Stored_Last : Ada.Streams.Stream_Element_Offset;
            Deleted_Loose_Hex : Ada.Streams.Stream_Element_Array (1 .. 40);
            Deleted_Loose_Last : Ada.Streams.Stream_Element_Offset;
            Listed_Loose_Object_IDs :
              SSH_Lib.Git.Object_ID_Hex_Array (1 .. 16);
            Listed_Loose_Object_Count : Natural := 0;
            Read_Hex : Ada.Streams.Stream_Element_Array (1 .. 40);
            Read_Hex_Last : Ada.Streams.Stream_Element_Offset;
            Symbolic_Target : Ada.Streams.Stream_Element_Array (1 .. 64);
            Symbolic_Target_Last : Ada.Streams.Stream_Element_Offset;
            Listed_Ref_Names : Ada.Streams.Stream_Element_Array (1 .. 256);
            Listed_Ref_Name_Lasts :
              SSH_Lib.Git.Ref_Name_Last_Array (1 .. 8);
            Listed_Ref_IDs : SSH_Lib.Git.Object_ID_Hex_Array (1 .. 8);
            Listed_Ref_Count : Natural := 0;
            Ref_Found : Boolean := False;
            Head_Attached : Boolean := False;
            Commit_Is_Ancestor : Boolean := False;
            Branch_Updated : Boolean := False;
            Read_Data : Ada.Streams.Stream_Element_Array (1 .. 32);
            Read_Last : Ada.Streams.Stream_Element_Offset;
            Read_Kind : SSH_Lib.Git.Pack_Object_Kind :=
              SSH_Lib.Git.Pack_Tree;
            Config_Value : Ada.Streams.Stream_Element_Array (1 .. 64);
            Config_Value_Last : Ada.Streams.Stream_Element_Offset;
            Config_Values : Ada.Streams.Stream_Element_Array (1 .. 128);
            Config_Value_Lasts :
              SSH_Lib.Git.Config_Value_Last_Array (1 .. 4);
            Config_Value_Count : Natural := 0;
            Config_Removed : Boolean := False;
            Config_Found : Boolean := False;
            Core_Bare : Boolean := False;
            Core_Filemode : Boolean := False;
            Core_Log_All_Ref_Updates : Boolean := False;
            Index_Version : Natural := 0;
            Index_Entry_Count : Natural := 0;
            Built_Index_Entry : Ada.Streams.Stream_Element_Array (1 .. 128);
            Built_Index_Entry_Last : Ada.Streams.Stream_Element_Offset;
            Parsed_Index_Mode : Natural := 0;
            Parsed_Index_Path : Ada.Streams.Stream_Element_Array (1 .. 32);
            Parsed_Index_Path_Last : Ada.Streams.Stream_Element_Offset;
            Parsed_Index_Object_ID :
              Ada.Streams.Stream_Element_Array (1 .. 20);
            Parsed_Index_Object_Last : Ada.Streams.Stream_Element_Offset;
            Parsed_Index_File_Size : Natural := 0;
            Parsed_Index_Next_Offset : Natural := 0;
            Index_Found : Boolean := False;
            Index_Removed : Boolean := False;
            Worktree_Found : Boolean := False;
            Worktree_Removed : Boolean := False;
            Worktree_Written : Boolean := False;
            Worktree_Written_Count : Natural := 0;
            Worktree_Path_State : SSH_Lib.Git.Worktree_Path_Status :=
              SSH_Lib.Git.Worktree_Path_Missing;
            Porcelain_Path_State : SSH_Lib.Git.Porcelain_Path_Status :=
              SSH_Lib.Git.Porcelain_Path_Absent;
            Porcelain_Absent_Count : Natural := 0;
            Porcelain_Untracked_Count : Natural := 0;
            Worktree_Missing_Count : Natural := 0;
            Worktree_Unchanged_Count : Natural := 0;
            Worktree_Modified_Count : Natural := 0;
            Listed_Index_Paths : Ada.Streams.Stream_Element_Array (1 .. 64);
            Listed_Index_Path_Lasts :
              SSH_Lib.Git.Index_Path_Last_Array (1 .. 4);
            Listed_Index_Path_Count : Natural := 0;
            Tree_Data : Ada.Streams.Stream_Element_Array (1 .. 36) :=
              [Character'Pos ('1'), Character'Pos ('0'),
               Character'Pos ('0'), Character'Pos ('6'),
               Character'Pos ('4'), Character'Pos ('4'),
               Character'Pos (' '),
               Character'Pos ('f'), Character'Pos ('i'),
               Character'Pos ('l'), Character'Pos ('e'),
               Character'Pos ('.'), Character'Pos ('t'),
               Character'Pos ('x'), Character'Pos ('t'),
               0, others => 0];
            Tree_Mode : Natural := 0;
            Tree_Name : Ada.Streams.Stream_Element_Array (1 .. 32);
            Tree_Name_Last : Ada.Streams.Stream_Element_Offset;
            Tree_Object_ID : Ada.Streams.Stream_Element_Array (1 .. 20);
            Tree_Object_Last : Ada.Streams.Stream_Element_Offset;
            Built_Tree_Entry : Ada.Streams.Stream_Element_Array (1 .. 64);
            Built_Tree_Entry_Last : Ada.Streams.Stream_Element_Offset;
            Built_Commit_Data : Ada.Streams.Stream_Element_Array (1 .. 128);
            Built_Commit_Last : Ada.Streams.Stream_Element_Offset;
            Built_Tag_Data : Ada.Streams.Stream_Element_Array (1 .. 128);
            Built_Tag_Last : Ada.Streams.Stream_Element_Offset;
            Merge_Result : SSH_Lib.Git.Three_Way_Merge_Result :=
              SSH_Lib.Git.Merge_Conflict;
            Tree_Next_Offset : Natural := 0;
            Tree_Entry_Count : Natural := 0;
            Tree_Found_Mode : Natural := 0;
            Tree_Found_ID : Ada.Streams.Stream_Element_Array (1 .. 20);
            Tree_Found_Last : Ada.Streams.Stream_Element_Offset;
            Tree_Found_Hex_Mode : Natural := 0;
            Tree_Found_Hex : Ada.Streams.Stream_Element_Array (1 .. 40);
            Tree_Found_Hex_Last : Ada.Streams.Stream_Element_Offset;
            Listed_Tree_Names : Ada.Streams.Stream_Element_Array (1 .. 32);
            Listed_Tree_Name_Lasts :
              SSH_Lib.Git.Tree_Entry_Name_Last_Array (1 .. 2);
            Listed_Tree_Modes : SSH_Lib.Git.Tree_Entry_Mode_Array (1 .. 2);
            Listed_Tree_IDs : SSH_Lib.Git.Object_ID_Hex_Array (1 .. 2);
            Listed_Tree_Count : Natural := 0;
            Stored_List_Tree_Data :
              Ada.Streams.Stream_Element_Array (1 .. 128);
            Stored_List_Tree_Last : Ada.Streams.Stream_Element_Offset;
            Stored_List_Names : Ada.Streams.Stream_Element_Array (1 .. 32);
            Stored_List_Name_Lasts :
              SSH_Lib.Git.Tree_Entry_Name_Last_Array (1 .. 2);
            Stored_List_Modes : SSH_Lib.Git.Tree_Entry_Mode_Array (1 .. 2);
            Stored_List_IDs : SSH_Lib.Git.Object_ID_Hex_Array (1 .. 2);
            Stored_List_Count : Natural := 0;

            function Bytes_From_String
              (Text : String) return Ada.Streams.Stream_Element_Array
            is
               Result : Ada.Streams.Stream_Element_Array
                 (1 .. Ada.Streams.Stream_Element_Offset (Text'Length));
               Cursor : Ada.Streams.Stream_Element_Offset := Result'First;
            begin
               for Ch of Text loop
                  Result (Cursor) := Character'Pos (Ch);
                  Cursor := Cursor + 1;
               end loop;
               return Result;
            end Bytes_From_String;

	            Commit_Data : constant Ada.Streams.Stream_Element_Array :=
	              Bytes_From_String
	                ("tree 0000000000000000000000000000000000000000"
	                 & Character'Val (10)
	                 & "parent 1111111111111111111111111111111111111111"
	                 & Character'Val (10)
	                 & "author A <a@example.test> 0 +0000"
	                 & Character'Val (10)
	                 & "committer A <a@example.test> 0 +0000"
	                 & Character'Val (10)
	                 & Character'Val (10));
	            Commit_Tree_Hex : Ada.Streams.Stream_Element_Array (1 .. 40);
	            Commit_Tree_Last : Ada.Streams.Stream_Element_Offset;
	            Commit_Parent_Hex : Ada.Streams.Stream_Element_Array (1 .. 40);
	            Commit_Parent_Last : Ada.Streams.Stream_Element_Offset;
	            Commit_Author_Line : Ada.Streams.Stream_Element_Array (1 .. 64);
	            Commit_Author_Last : Ada.Streams.Stream_Element_Offset;
	            Commit_Committer_Line : Ada.Streams.Stream_Element_Array (1 .. 64);
	            Commit_Committer_Last : Ada.Streams.Stream_Element_Offset;
	            Commit_Message_Offset : Natural := 0;
	            Commit_Parent_Count : Natural := 0;
	            Tag_Data : constant Ada.Streams.Stream_Element_Array :=
	              Bytes_From_String
	                ("object 0000000000000000000000000000000000000000"
	                 & Character'Val (10)
	                 & "type blob"
	                 & Character'Val (10)
	                 & "tag v1.0.0"
	                 & Character'Val (10)
	                 & Character'Val (10));
	            Tag_Target_Hex : Ada.Streams.Stream_Element_Array (1 .. 40);
	            Tag_Target_Last : Ada.Streams.Stream_Element_Offset;
	            Tag_Target_Kind : SSH_Lib.Git.Pack_Object_Kind :=
	              SSH_Lib.Git.Pack_Blob;
	            Tag_Name : Ada.Streams.Stream_Element_Array (1 .. 32);
	            Tag_Name_Last : Ada.Streams.Stream_Element_Offset;
	            Tag_Message_Offset : Natural := 0;
            Pack_Data : Ada.Streams.Stream_Element_Array (1 .. 32) :=
              [Character'Pos ('P'), Character'Pos ('A'),
               Character'Pos ('C'), Character'Pos ('K'),
               0, 0, 0, 2, 0, 0, 0, 0, others => 0];
            Pack_Checksum : Ada.Streams.Stream_Element_Array (1 .. 40);
            Pack_Checksum_Last : Ada.Streams.Stream_Element_Offset;
            Deleted_Pack_File : Boolean := False;
            Deleted_Pack_Index : Boolean := False;
            Built_Index : Ada.Streams.Stream_Element_Array (1 .. 1100);
            Built_Index_Last : Ada.Streams.Stream_Element_Offset;
            Pack_Index_Scratch : Ada.Streams.Stream_Element_Array (1 .. 64);
            Read_Index : Ada.Streams.Stream_Element_Array (1 .. 1100);
            Read_Index_Last : Ada.Streams.Stream_Element_Offset;
            Listed_Packed_Index : Ada.Streams.Stream_Element_Array (1 .. 1100);
            Listed_Packed_Index_Last : Ada.Streams.Stream_Element_Offset;
            Listed_Packed_Object_IDs :
              SSH_Lib.Git.Object_ID_Hex_Array (1 .. 4);
            Listed_Packed_Object_Count : Natural := 0;
            Exists_Pack_Index : Ada.Streams.Stream_Element_Array (1 .. 1100);
            Exists_Pack_Checksums : Ada.Streams.Stream_Element_Array (1 .. 80);
            Exists_Pack_Checksums_Last : Ada.Streams.Stream_Element_Offset;
            Exists_Pack_Checksum : Ada.Streams.Stream_Element_Array (1 .. 40);
            Exists_Pack_Checksum_Last : Ada.Streams.Stream_Element_Offset;
            Stored_Object_Found : Boolean := False;
            Stored_Object_IDs : SSH_Lib.Git.Object_ID_Hex_Array (1 .. 32);
            Stored_Object_Count : Natural := 0;
            Stored_Object_Pack_Checksums :
              Ada.Streams.Stream_Element_Array (1 .. 80);
            Stored_Object_Pack_Checksums_Last :
              Ada.Streams.Stream_Element_Offset;
            Stored_Object_Index : Ada.Streams.Stream_Element_Array (1 .. 1100);
            Stored_Object_Index_Last : Ada.Streams.Stream_Element_Offset;
            Packed_Read_Data : Ada.Streams.Stream_Element_Array (1 .. 32);
            Packed_Read_Last : Ada.Streams.Stream_Element_Offset;
            Reflog_Line : Ada.Streams.Stream_Element_Array (1 .. 256);
            Reflog_Last : Ada.Streams.Stream_Element_Offset;
            Pack_Index_List : Ada.Streams.Stream_Element_Array (1 .. 80);
            Pack_Index_List_Last : Ada.Streams.Stream_Element_Offset;
            Pack_Index_List_Count : Natural := 0;
            Found_Pack_Checksum : Ada.Streams.Stream_Element_Array (1 .. 40);
            Found_Pack_Checksum_Last : Ada.Streams.Stream_Element_Offset;
            Validated_Stored_Hex : Ada.Streams.Stream_Element_Array (1 .. 40);
            Validated_Stored_Last : Ada.Streams.Stream_Element_Offset;
            Stored_Tree_Hex : Ada.Streams.Stream_Element_Array (1 .. 40);
            Stored_Tree_Last : Ada.Streams.Stream_Element_Offset;
            Stored_Tree_Raw_ID : Ada.Streams.Stream_Element_Array (1 .. 20);
            Stored_Tree_Raw_Last : Ada.Streams.Stream_Element_Offset;
            Path_List_Root_Tree_Hex :
              Ada.Streams.Stream_Element_Array (1 .. 40);
            Path_List_Root_Tree_Last :
              Ada.Streams.Stream_Element_Offset;
            Path_List_Parent_Tree_Data :
              Ada.Streams.Stream_Element_Array (1 .. 64);
            Path_List_Parent_Tree_Last :
              Ada.Streams.Stream_Element_Offset;
            Path_List_Mode : Natural := 0;
            Path_List_Tree_Data :
              Ada.Streams.Stream_Element_Array (1 .. 128);
            Path_List_Tree_Last : Ada.Streams.Stream_Element_Offset;
            Path_List_Names : Ada.Streams.Stream_Element_Array (1 .. 32);
            Path_List_Path_Lasts :
              SSH_Lib.Git.Index_Path_Last_Array (1 .. 2);
            Path_List_Name_Lasts :
              SSH_Lib.Git.Tree_Entry_Name_Last_Array (1 .. 2);
            Path_List_Modes : SSH_Lib.Git.Tree_Entry_Mode_Array (1 .. 2);
            Path_List_IDs : SSH_Lib.Git.Object_ID_Hex_Array (1 .. 2);
            Path_List_Count : Natural := 0;
            Stored_Commit_Hex : Ada.Streams.Stream_Element_Array (1 .. 40);
            Stored_Commit_Last : Ada.Streams.Stream_Element_Offset;
            Stored_Tag_Hex : Ada.Streams.Stream_Element_Array (1 .. 40);
            Stored_Tag_Last : Ada.Streams.Stream_Element_Offset;
            Traversed_Tree_Data : Ada.Streams.Stream_Element_Array (1 .. 128);
            Traversed_Tree_Last : Ada.Streams.Stream_Element_Offset;
            Traversed_Mode : Natural := 0;
            Traversed_Data : Ada.Streams.Stream_Element_Array (1 .. 64);
            Traversed_Last : Ada.Streams.Stream_Element_Offset;
            Path_Tree_Data : Ada.Streams.Stream_Element_Array (1 .. 128);
            Path_Tree_Last : Ada.Streams.Stream_Element_Offset;
            Path_Mode : Natural := 0;
            Path_Data : Ada.Streams.Stream_Element_Array (1 .. 64);
            Path_Last : Ada.Streams.Stream_Element_Offset;
            Resolved_Path_Tree_Data :
              Ada.Streams.Stream_Element_Array (1 .. 128);
            Resolved_Path_Tree_Last : Ada.Streams.Stream_Element_Offset;
            Resolved_Path_Mode : Natural := 0;
            Resolved_Path_ID : Ada.Streams.Stream_Element_Array (1 .. 40);
            Resolved_Path_ID_Last : Ada.Streams.Stream_Element_Offset;
            Commit_Path_Commit_Data :
              Ada.Streams.Stream_Element_Array (1 .. 256);
            Commit_Path_Commit_Last : Ada.Streams.Stream_Element_Offset;
            Commit_Path_Tree_ID : Ada.Streams.Stream_Element_Array (1 .. 40);
            Commit_Path_Tree_ID_Last : Ada.Streams.Stream_Element_Offset;
            Commit_Path_Tree_Data : Ada.Streams.Stream_Element_Array (1 .. 128);
            Commit_Path_Tree_Last : Ada.Streams.Stream_Element_Offset;
            Commit_Path_Mode : Natural := 0;
            Commit_Path_Data : Ada.Streams.Stream_Element_Array (1 .. 64);
            Commit_Path_Last : Ada.Streams.Stream_Element_Offset;
            Commit_Resolved_Path_Commit_Data :
              Ada.Streams.Stream_Element_Array (1 .. 256);
            Commit_Resolved_Path_Commit_Last :
              Ada.Streams.Stream_Element_Offset;
            Commit_Resolved_Path_Tree_ID :
              Ada.Streams.Stream_Element_Array (1 .. 40);
            Commit_Resolved_Path_Tree_ID_Last :
              Ada.Streams.Stream_Element_Offset;
            Commit_Resolved_Path_Tree_Data :
              Ada.Streams.Stream_Element_Array (1 .. 128);
            Commit_Resolved_Path_Tree_Last :
              Ada.Streams.Stream_Element_Offset;
            Commit_Resolved_Path_Mode : Natural := 0;
            Commit_Resolved_Path_ID :
              Ada.Streams.Stream_Element_Array (1 .. 40);
            Commit_Resolved_Path_ID_Last :
              Ada.Streams.Stream_Element_Offset;
            Commit_Tree_Read_Commit_Data :
              Ada.Streams.Stream_Element_Array (1 .. 256);
            Commit_Tree_Read_Commit_Last :
              Ada.Streams.Stream_Element_Offset;
            Commit_Tree_Read_ID :
              Ada.Streams.Stream_Element_Array (1 .. 40);
            Commit_Tree_Read_ID_Last : Ada.Streams.Stream_Element_Offset;
            Commit_Tree_Read_Data :
              Ada.Streams.Stream_Element_Array (1 .. 128);
            Commit_Tree_Read_Last : Ada.Streams.Stream_Element_Offset;
            Commit_Tree_Read_Count : Natural := 0;
            Commit_List_Commit_Data :
              Ada.Streams.Stream_Element_Array (1 .. 256);
            Commit_List_Commit_Last : Ada.Streams.Stream_Element_Offset;
            Commit_List_Tree_ID :
              Ada.Streams.Stream_Element_Array (1 .. 40);
            Commit_List_Tree_ID_Last : Ada.Streams.Stream_Element_Offset;
            Commit_List_Tree_Data :
              Ada.Streams.Stream_Element_Array (1 .. 128);
            Commit_List_Tree_Last : Ada.Streams.Stream_Element_Offset;
            Commit_List_Names : Ada.Streams.Stream_Element_Array (1 .. 32);
            Commit_List_Name_Lasts :
              SSH_Lib.Git.Tree_Entry_Name_Last_Array (1 .. 2);
            Commit_List_Modes : SSH_Lib.Git.Tree_Entry_Mode_Array (1 .. 2);
            Commit_List_IDs : SSH_Lib.Git.Object_ID_Hex_Array (1 .. 2);
            Commit_List_Count : Natural := 0;
            Commit_Path_List_Hex :
              Ada.Streams.Stream_Element_Array (1 .. 40);
            Commit_Path_List_Last :
              Ada.Streams.Stream_Element_Offset;
            Commit_Path_List_Commit_Data :
              Ada.Streams.Stream_Element_Array (1 .. 256);
            Commit_Path_List_Commit_Last :
              Ada.Streams.Stream_Element_Offset;
            Commit_Path_List_Tree_ID :
              Ada.Streams.Stream_Element_Array (1 .. 40);
            Commit_Path_List_Tree_ID_Last :
              Ada.Streams.Stream_Element_Offset;
            Commit_Path_List_Parent_Tree_Data :
              Ada.Streams.Stream_Element_Array (1 .. 64);
            Commit_Path_List_Parent_Tree_Last :
              Ada.Streams.Stream_Element_Offset;
            Commit_Path_List_Mode : Natural := 0;
            Commit_Path_List_Tree_Data :
              Ada.Streams.Stream_Element_Array (1 .. 128);
            Commit_Path_List_Tree_Last :
              Ada.Streams.Stream_Element_Offset;
            Commit_Path_List_Names :
              Ada.Streams.Stream_Element_Array (1 .. 32);
            Commit_Path_List_Name_Lasts :
              SSH_Lib.Git.Tree_Entry_Name_Last_Array (1 .. 2);
            Commit_Path_List_Modes :
              SSH_Lib.Git.Tree_Entry_Mode_Array (1 .. 2);
            Commit_Path_List_IDs :
              SSH_Lib.Git.Object_ID_Hex_Array (1 .. 2);
            Commit_Path_List_Count : Natural := 0;
            Ref_Path_List_Resolved_ID :
              Ada.Streams.Stream_Element_Array (1 .. 40);
            Ref_Path_List_Resolved_Last :
              Ada.Streams.Stream_Element_Offset;
            Ref_Path_List_Commit_Data :
              Ada.Streams.Stream_Element_Array (1 .. 256);
            Ref_Path_List_Commit_Last :
              Ada.Streams.Stream_Element_Offset;
            Ref_Path_List_Tree_ID :
              Ada.Streams.Stream_Element_Array (1 .. 40);
            Ref_Path_List_Tree_ID_Last :
              Ada.Streams.Stream_Element_Offset;
            Ref_Path_List_Parent_Tree_Data :
              Ada.Streams.Stream_Element_Array (1 .. 64);
            Ref_Path_List_Parent_Tree_Last :
              Ada.Streams.Stream_Element_Offset;
            Ref_Path_List_Mode : Natural := 0;
            Ref_Path_List_Tree_Data :
              Ada.Streams.Stream_Element_Array (1 .. 128);
            Ref_Path_List_Tree_Last :
              Ada.Streams.Stream_Element_Offset;
            Ref_Path_List_Names :
              Ada.Streams.Stream_Element_Array (1 .. 32);
            Ref_Path_List_Name_Lasts :
              SSH_Lib.Git.Tree_Entry_Name_Last_Array (1 .. 2);
            Ref_Path_List_Modes :
              SSH_Lib.Git.Tree_Entry_Mode_Array (1 .. 2);
            Ref_Path_List_IDs :
              SSH_Lib.Git.Object_ID_Hex_Array (1 .. 2);
            Ref_Path_List_Count : Natural := 0;
            Ref_Path_Resolved_ID : Ada.Streams.Stream_Element_Array (1 .. 40);
            Ref_Path_Resolved_Last : Ada.Streams.Stream_Element_Offset;
            Ref_Path_Commit_Data :
              Ada.Streams.Stream_Element_Array (1 .. 256);
            Ref_Path_Commit_Last : Ada.Streams.Stream_Element_Offset;
            Ref_Path_Tree_ID : Ada.Streams.Stream_Element_Array (1 .. 40);
            Ref_Path_Tree_ID_Last : Ada.Streams.Stream_Element_Offset;
            Ref_Path_Tree_Data : Ada.Streams.Stream_Element_Array (1 .. 128);
            Ref_Path_Tree_Last : Ada.Streams.Stream_Element_Offset;
            Ref_Path_Mode : Natural := 0;
            Ref_Path_Data : Ada.Streams.Stream_Element_Array (1 .. 64);
            Ref_Path_Last : Ada.Streams.Stream_Element_Offset;
            Ref_Resolved_Path_Resolved_ID :
              Ada.Streams.Stream_Element_Array (1 .. 40);
            Ref_Resolved_Path_Resolved_Last :
              Ada.Streams.Stream_Element_Offset;
            Ref_Resolved_Path_Commit_Data :
              Ada.Streams.Stream_Element_Array (1 .. 256);
            Ref_Resolved_Path_Commit_Last :
              Ada.Streams.Stream_Element_Offset;
            Ref_Resolved_Path_Tree_ID :
              Ada.Streams.Stream_Element_Array (1 .. 40);
            Ref_Resolved_Path_Tree_ID_Last :
              Ada.Streams.Stream_Element_Offset;
            Ref_Resolved_Path_Tree_Data :
              Ada.Streams.Stream_Element_Array (1 .. 128);
            Ref_Resolved_Path_Tree_Last :
              Ada.Streams.Stream_Element_Offset;
            Ref_Resolved_Path_Mode : Natural := 0;
            Ref_Resolved_Path_ID :
              Ada.Streams.Stream_Element_Array (1 .. 40);
            Ref_Resolved_Path_ID_Last :
              Ada.Streams.Stream_Element_Offset;
            Tagged_Path_Peeled_ID :
              Ada.Streams.Stream_Element_Array (1 .. 40);
            Tagged_Path_Peeled_Last : Ada.Streams.Stream_Element_Offset;
            Tagged_Path_Tag_Data :
              Ada.Streams.Stream_Element_Array (1 .. 256);
            Tagged_Path_Tag_Last : Ada.Streams.Stream_Element_Offset;
            Tagged_Path_Commit_Data :
              Ada.Streams.Stream_Element_Array (1 .. 256);
            Tagged_Path_Commit_Last : Ada.Streams.Stream_Element_Offset;
            Tagged_Path_Tree_ID : Ada.Streams.Stream_Element_Array (1 .. 40);
            Tagged_Path_Tree_ID_Last : Ada.Streams.Stream_Element_Offset;
            Tagged_Path_Tree_Data :
              Ada.Streams.Stream_Element_Array (1 .. 128);
            Tagged_Path_Tree_Last : Ada.Streams.Stream_Element_Offset;
            Tagged_Path_Mode : Natural := 0;
            Tagged_Path_Data : Ada.Streams.Stream_Element_Array (1 .. 64);
            Tagged_Path_Last : Ada.Streams.Stream_Element_Offset;
            Tagged_Resolved_Path_Peeled_ID :
              Ada.Streams.Stream_Element_Array (1 .. 40);
            Tagged_Resolved_Path_Peeled_Last :
              Ada.Streams.Stream_Element_Offset;
            Tagged_Resolved_Path_Tag_Data :
              Ada.Streams.Stream_Element_Array (1 .. 256);
            Tagged_Resolved_Path_Tag_Last :
              Ada.Streams.Stream_Element_Offset;
            Tagged_Resolved_Path_Commit_Data :
              Ada.Streams.Stream_Element_Array (1 .. 256);
            Tagged_Resolved_Path_Commit_Last :
              Ada.Streams.Stream_Element_Offset;
            Tagged_Resolved_Path_Tree_ID :
              Ada.Streams.Stream_Element_Array (1 .. 40);
            Tagged_Resolved_Path_Tree_ID_Last :
              Ada.Streams.Stream_Element_Offset;
            Tagged_Resolved_Path_Tree_Data :
              Ada.Streams.Stream_Element_Array (1 .. 128);
            Tagged_Resolved_Path_Tree_Last :
              Ada.Streams.Stream_Element_Offset;
            Tagged_Resolved_Path_Mode : Natural := 0;
            Tagged_Resolved_Path_ID :
              Ada.Streams.Stream_Element_Array (1 .. 40);
            Tagged_Resolved_Path_ID_Last :
              Ada.Streams.Stream_Element_Offset;
            Tag_Path_List_Hex :
              Ada.Streams.Stream_Element_Array (1 .. 40);
            Tag_Path_List_Last :
              Ada.Streams.Stream_Element_Offset;
            Tag_Path_List_Peeled_ID :
              Ada.Streams.Stream_Element_Array (1 .. 40);
            Tag_Path_List_Peeled_Last :
              Ada.Streams.Stream_Element_Offset;
            Tag_Path_List_Tag_Data :
              Ada.Streams.Stream_Element_Array (1 .. 256);
            Tag_Path_List_Tag_Last :
              Ada.Streams.Stream_Element_Offset;
            Tag_Path_List_Commit_Data :
              Ada.Streams.Stream_Element_Array (1 .. 256);
            Tag_Path_List_Commit_Last :
              Ada.Streams.Stream_Element_Offset;
            Tag_Path_List_Tree_ID :
              Ada.Streams.Stream_Element_Array (1 .. 40);
            Tag_Path_List_Tree_ID_Last :
              Ada.Streams.Stream_Element_Offset;
            Tag_Path_List_Parent_Tree_Data :
              Ada.Streams.Stream_Element_Array (1 .. 64);
            Tag_Path_List_Parent_Tree_Last :
              Ada.Streams.Stream_Element_Offset;
            Tag_Path_List_Mode : Natural := 0;
            Tag_Path_List_Tree_Data :
              Ada.Streams.Stream_Element_Array (1 .. 128);
            Tag_Path_List_Tree_Last :
              Ada.Streams.Stream_Element_Offset;
            Tag_Path_List_Names :
              Ada.Streams.Stream_Element_Array (1 .. 32);
            Tag_Path_List_Name_Lasts :
              SSH_Lib.Git.Tree_Entry_Name_Last_Array (1 .. 2);
            Tag_Path_List_Modes :
              SSH_Lib.Git.Tree_Entry_Mode_Array (1 .. 2);
            Tag_Path_List_IDs :
              SSH_Lib.Git.Object_ID_Hex_Array (1 .. 2);
            Tag_Path_List_Count : Natural := 0;
            Commitish_Path_Resolved_ID :
              Ada.Streams.Stream_Element_Array (1 .. 40);
            Commitish_Path_Resolved_Last : Ada.Streams.Stream_Element_Offset;
            Commitish_Path_Peeled_ID :
              Ada.Streams.Stream_Element_Array (1 .. 40);
            Commitish_Path_Peeled_Last : Ada.Streams.Stream_Element_Offset;
            Commitish_Path_Tag_Data :
              Ada.Streams.Stream_Element_Array (1 .. 256);
            Commitish_Path_Tag_Last : Ada.Streams.Stream_Element_Offset;
            Commitish_Path_Commit_Data :
              Ada.Streams.Stream_Element_Array (1 .. 256);
            Commitish_Path_Commit_Last : Ada.Streams.Stream_Element_Offset;
            Commitish_Path_Tree_ID :
              Ada.Streams.Stream_Element_Array (1 .. 40);
            Commitish_Path_Tree_ID_Last : Ada.Streams.Stream_Element_Offset;
            Commitish_Path_Tree_Data :
              Ada.Streams.Stream_Element_Array (1 .. 128);
            Commitish_Path_Tree_Last : Ada.Streams.Stream_Element_Offset;
            Commitish_Path_Mode : Natural := 0;
            Commitish_Path_Data : Ada.Streams.Stream_Element_Array (1 .. 64);
            Commitish_Path_Last : Ada.Streams.Stream_Element_Offset;
            Commitish_Resolved_Path_Resolved_ID :
              Ada.Streams.Stream_Element_Array (1 .. 40);
            Commitish_Resolved_Path_Resolved_Last :
              Ada.Streams.Stream_Element_Offset;
            Commitish_Resolved_Path_Peeled_ID :
              Ada.Streams.Stream_Element_Array (1 .. 40);
            Commitish_Resolved_Path_Peeled_Last :
              Ada.Streams.Stream_Element_Offset;
            Commitish_Resolved_Path_Tag_Data :
              Ada.Streams.Stream_Element_Array (1 .. 256);
            Commitish_Resolved_Path_Tag_Last :
              Ada.Streams.Stream_Element_Offset;
            Commitish_Resolved_Path_Commit_Data :
              Ada.Streams.Stream_Element_Array (1 .. 256);
            Commitish_Resolved_Path_Commit_Last :
              Ada.Streams.Stream_Element_Offset;
            Commitish_Resolved_Path_Tree_ID :
              Ada.Streams.Stream_Element_Array (1 .. 40);
            Commitish_Resolved_Path_Tree_ID_Last :
              Ada.Streams.Stream_Element_Offset;
            Commitish_Resolved_Path_Tree_Data :
              Ada.Streams.Stream_Element_Array (1 .. 128);
            Commitish_Resolved_Path_Tree_Last :
              Ada.Streams.Stream_Element_Offset;
            Commitish_Resolved_Path_Mode : Natural := 0;
            Commitish_Resolved_Path_ID :
              Ada.Streams.Stream_Element_Array (1 .. 40);
            Commitish_Resolved_Path_ID_Last :
              Ada.Streams.Stream_Element_Offset;
            Commitish_Tree_Resolved_ID :
              Ada.Streams.Stream_Element_Array (1 .. 40);
            Commitish_Tree_Resolved_Last : Ada.Streams.Stream_Element_Offset;
            Commitish_Tree_Peeled_ID :
              Ada.Streams.Stream_Element_Array (1 .. 40);
            Commitish_Tree_Peeled_Last : Ada.Streams.Stream_Element_Offset;
            Commitish_Tree_Tag_Data :
              Ada.Streams.Stream_Element_Array (1 .. 256);
            Commitish_Tree_Tag_Last : Ada.Streams.Stream_Element_Offset;
            Commitish_Tree_Commit_Data :
              Ada.Streams.Stream_Element_Array (1 .. 256);
            Commitish_Tree_Commit_Last : Ada.Streams.Stream_Element_Offset;
            Commitish_Tree_ID :
              Ada.Streams.Stream_Element_Array (1 .. 40);
            Commitish_Tree_ID_Last : Ada.Streams.Stream_Element_Offset;
            Commitish_Tree_Data :
              Ada.Streams.Stream_Element_Array (1 .. 128);
            Commitish_Tree_Last : Ada.Streams.Stream_Element_Offset;
            Commitish_Tree_Count : Natural := 0;
            Commitish_List_Resolved_ID :
              Ada.Streams.Stream_Element_Array (1 .. 40);
            Commitish_List_Resolved_Last : Ada.Streams.Stream_Element_Offset;
            Commitish_List_Peeled_ID :
              Ada.Streams.Stream_Element_Array (1 .. 40);
            Commitish_List_Peeled_Last : Ada.Streams.Stream_Element_Offset;
            Commitish_List_Tag_Data :
              Ada.Streams.Stream_Element_Array (1 .. 256);
            Commitish_List_Tag_Last : Ada.Streams.Stream_Element_Offset;
            Commitish_List_Commit_Data :
              Ada.Streams.Stream_Element_Array (1 .. 256);
            Commitish_List_Commit_Last : Ada.Streams.Stream_Element_Offset;
            Commitish_List_Tree_ID :
              Ada.Streams.Stream_Element_Array (1 .. 40);
            Commitish_List_Tree_ID_Last : Ada.Streams.Stream_Element_Offset;
            Commitish_List_Tree_Data :
              Ada.Streams.Stream_Element_Array (1 .. 128);
            Commitish_List_Tree_Last : Ada.Streams.Stream_Element_Offset;
            Commitish_List_Names : Ada.Streams.Stream_Element_Array (1 .. 32);
            Commitish_List_Name_Lasts :
              SSH_Lib.Git.Tree_Entry_Name_Last_Array (1 .. 2);
            Commitish_List_Modes : SSH_Lib.Git.Tree_Entry_Mode_Array (1 .. 2);
            Commitish_List_IDs : SSH_Lib.Git.Object_ID_Hex_Array (1 .. 2);
            Commitish_List_Count : Natural := 0;

            procedure Store_SHA1
              (Digest : CryptoLib.Hashes.SHA1_Digest;
               Target : in out Ada.Streams.Stream_Element_Array)
            is
               Cursor : Ada.Streams.Stream_Element_Offset := Target'First;
            begin
               for Digest_Index in Digest'Range loop
                  Target (Cursor) := Digest (Digest_Index);
                  Cursor := Cursor + 1;
               end loop;
            end Store_SHA1;
         begin
            Store_SHA1
              (CryptoLib.Hashes.SHA1 (Pack_Data (1 .. 12)),
               Pack_Data (13 .. 32));
            Tree_Data (17 .. 36) := Pack_Data (13 .. 32);
            if Ada.Directories.Exists (Repo_Root) then
               Ada.Directories.Delete_Tree (Repo_Root);
            end if;
            Status_Value := SSH_Lib.Git.Initialize_Repository_State (Repo_Root);
            Touch (Status_Value);
            if not SSH_Lib.Git.Valid_Worktree_Path ("file.txt") then
               raise Program_Error;
            end if;
            Status_Value :=
              SSH_Lib.Git.Pathspec_Matches
                ("file.txt", "*.txt", Config_Found);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Write_Worktree_File
                (Repo_Root,
                 "file.txt",
                 [Character'Pos ('o'), Character'Pos ('k')]);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Read_Worktree_File
                (Repo_Root, "file.txt", Read_Data, Read_Last);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Worktree_File_Exists
                (Repo_Root, "file.txt", Worktree_Found);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Stage_Worktree_File
                (Repo_Root, "file.txt", Stored_Hex, Stored_Last);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Delete_Worktree_File
                (Repo_Root, "file.txt", Worktree_Removed);
            Touch (Status_Value);
            Status_Value := SSH_Lib.Git.Write_Empty_Index (Repo_Root);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Read_Index_Header
                (Repo_Root, Index_Version, Index_Entry_Count);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Build_Index_Entry
                (8#100644#,
                 "file.txt",
                 [1 => 1, 2 .. 20 => 0],
                 12,
                 Built_Index_Entry,
                 Built_Index_Entry_Last);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Write_Index
                (Repo_Root,
                 Built_Index_Entry
                   (Built_Index_Entry'First .. Built_Index_Entry_Last),
                 1);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Parse_Index_Entry
                (Built_Index_Entry
                   (Built_Index_Entry'First .. Built_Index_Entry_Last),
                 0,
                 Parsed_Index_Mode,
                 Parsed_Index_Path,
                 Parsed_Index_Path_Last,
                 Parsed_Index_Object_ID,
                 Parsed_Index_Object_Last,
                 Parsed_Index_File_Size,
                 Parsed_Index_Next_Offset);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Read_Index_Entry
                (Repo_Root,
                 0,
                 Parsed_Index_Mode,
                 Parsed_Index_Path,
                 Parsed_Index_Path_Last,
                 Parsed_Index_Object_ID,
                 Parsed_Index_Object_Last,
                 Parsed_Index_File_Size);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Find_Index_Entry
                (Repo_Root,
                 Bytes_From_String ("file.txt"),
                 Parsed_Index_Mode,
                 Parsed_Index_Object_ID,
                 Parsed_Index_Object_Last,
                 Parsed_Index_File_Size,
                 Index_Found);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Read_Index_Path_Object
                (Repo_Root,
                 Bytes_From_String ("file.txt"),
                 Read_Kind,
                 Read_Data,
                 Read_Last,
                 Index_Found);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.List_Index_Paths
                (Repo_Root,
                 Listed_Index_Paths,
                 Listed_Index_Path_Lasts,
                 Listed_Index_Path_Count);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Checkout_Index_Path
                (Repo_Root,
                 Bytes_From_String ("file.txt"),
                 Worktree_Written);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Checkout_Index_All
                (Repo_Root, Worktree_Written_Count);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Compare_Index_Path_To_Worktree
                (Repo_Root,
                 Bytes_From_String ("file.txt"),
                 Worktree_Path_State);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Summarize_Index_Worktree
                (Repo_Root,
                 Worktree_Missing_Count,
                 Worktree_Unchanged_Count,
                 Worktree_Modified_Count);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Classify_Worktree_Path
                (Repo_Root, "file.txt", Porcelain_Path_State);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Summarize_Worktree_Paths
                (Repo_Root,
                 Bytes_From_String ("file.txt"),
                 [1 => 8],
                 1,
                 Porcelain_Absent_Count,
                 Porcelain_Untracked_Count,
                 Worktree_Missing_Count,
                 Worktree_Unchanged_Count,
                 Worktree_Modified_Count);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.List_Worktree_Files
                (Repo_Root,
                 Listed_Index_Paths,
                 Listed_Index_Path_Lasts,
                 Listed_Index_Path_Count);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Summarize_Worktree_Status
                (Repo_Root,
                 Porcelain_Untracked_Count,
                 Worktree_Missing_Count,
                 Worktree_Unchanged_Count,
                 Worktree_Modified_Count);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Summarize_Worktree_Status_Matching
                (Repo_Root,
                 ".",
                 Porcelain_Untracked_Count,
                 Worktree_Missing_Count,
                 Worktree_Unchanged_Count,
                 Worktree_Modified_Count);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Worktree_Path_Ignored
                (Repo_Root, "file.txt", Config_Found);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Summarize_Worktree_Status_With_Ignored
                (Repo_Root,
                 Porcelain_Untracked_Count,
                 Porcelain_Absent_Count,
                 Worktree_Missing_Count,
                 Worktree_Unchanged_Count,
                 Worktree_Modified_Count);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Detect_Worktree_Rename
                (Repo_Root,
                 Config_Value,
                 Config_Value_Last,
                 Reflog_Line,
                 Reflog_Last,
                 Config_Found);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Detect_Worktree_Copy
                (Repo_Root,
                 Config_Value,
                 Config_Value_Last,
                 Reflog_Line,
                 Reflog_Last,
                 Config_Found);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Clean_Worktree_Not_In_Index
                (Repo_Root, Worktree_Written_Count);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Remove_Index_Path
                (Repo_Root, "missing.txt", Index_Removed);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Commit_Index_To_Branch
                (Repo_Root,
                 "main",
                 "A <a@example.test> 0 +0000",
                 "A <a@example.test> 0 +0000",
                 "stage" & Character'Val (10),
                 Stored_Commit_Hex,
                 Stored_Commit_Last);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Write_Worktree_File
                (Repo_Root,
                 "api-porcelain.txt",
                 Bytes_From_String ("api"));
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Stage_And_Commit_Worktree_File
                (Repo_Root,
                 "main",
                 "api-porcelain.txt",
                 "A <a@example.test> 1 +0000",
                 "A <a@example.test> 1 +0000",
                 "api" & Character'Val (10),
                 Stored_Commit_Hex,
                 Stored_Commit_Last);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.List_Commit_Tree_Paths_Hex
                (Repo_Root,
                 Stored_Commit_Hex,
                 Path_List_Names,
                 Path_List_Path_Lasts,
                 Path_List_Modes,
                 Path_List_IDs,
                 Path_List_Count);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.List_Commit_Tree_Paths_Matching_Hex
                (Repo_Root,
                 Stored_Commit_Hex,
                 ".",
                 Path_List_Names,
                 Path_List_Path_Lasts,
                 Path_List_Modes,
                 Path_List_IDs,
                 Path_List_Count);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.List_Ref_Commitish_Tree_Paths_Hex
                (Repo_Root,
                 "refs/heads/main",
                 Path_List_Names,
                 Path_List_Path_Lasts,
                 Path_List_Modes,
                 Path_List_IDs,
                 Path_List_Count);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.List_Ref_Commitish_Tree_Paths_Matching_Hex
                (Repo_Root,
                 "refs/heads/main",
                 ".",
                 Path_List_Names,
                 Path_List_Path_Lasts,
                 Path_List_Modes,
                 Path_List_IDs,
                 Path_List_Count);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.List_HEAD_Tree_Paths_Hex
                (Repo_Root,
                 Path_List_Names,
                 Path_List_Path_Lasts,
                 Path_List_Modes,
                 Path_List_IDs,
                 Path_List_Count);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.List_HEAD_Tree_Paths_Matching_Hex
                (Repo_Root,
                 ".",
                 Path_List_Names,
                 Path_List_Path_Lasts,
                 Path_List_Modes,
                 Path_List_IDs,
                 Path_List_Count);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.List_Branch_Tree_Paths_Hex
                (Repo_Root,
                 "main",
                 Path_List_Names,
                 Path_List_Path_Lasts,
                 Path_List_Modes,
                 Path_List_IDs,
                 Path_List_Count);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.List_Branch_Tree_Paths_Matching_Hex
                (Repo_Root,
                 "main",
                 ".",
                 Path_List_Names,
                 Path_List_Path_Lasts,
                 Path_List_Modes,
                 Path_List_IDs,
                 Path_List_Count);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Write_Tag_Ref
                (Repo_Root, "main-tree", Stored_Commit_Hex);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.List_Tag_Tree_Paths_Hex
                (Repo_Root,
                 "main-tree",
                 Path_List_Names,
                 Path_List_Path_Lasts,
                 Path_List_Modes,
                 Path_List_IDs,
                 Path_List_Count);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.List_Tag_Tree_Paths_Matching_Hex
                (Repo_Root,
                 "main-tree",
                 ".",
                 Path_List_Names,
                 Path_List_Path_Lasts,
                 Path_List_Modes,
                 Path_List_IDs,
                 Path_List_Count);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Reset_Index_To_Commit_Root
                (Repo_Root, Stored_Commit_Hex, Index_Entry_Count);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Checkout_Branch
                (Repo_Root, "main", Worktree_Written_Count);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Evaluate_Porcelain_Status
                (Repo_Root, ".", False, Porcelain_Status_Summary);
            Touch (Status_Value);
            if Porcelain_Status_Summary.Has_Ignored then
               raise Program_Error;
            end if;
            Status_Value :=
              SSH_Lib.Git.Read_Porcelain_Index_Worktree_Model
                (Repo_Root, ".", False, Porcelain_Model);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Summarize_Repository_Database
                (Repo_Root, Database_Summary);
            Touch (Status_Value);
            if Database_Summary.Has_Missing_Ref_Targets then
               raise Program_Error;
            end if;
            Status_Value :=
              SSH_Lib.Git.Is_Ancestor_First_Parent
                (Repo_Root,
                 Stored_Commit_Hex,
                 Stored_Commit_Hex,
                 Commit_Is_Ancestor);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Fast_Forward_Branch
                (Repo_Root, "main", Stored_Commit_Hex, Branch_Updated);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Apply_Push_Branch_Update
                (Repo_Root,
                 "main",
                 Stored_Commit_Hex,
                 Stored_Commit_Hex,
                 False,
                 Branch_Updated);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Apply_Fetch_Ref_Update
                (Repo_Root,
                 "origin",
                 "main",
                 Stored_Commit_Hex,
                 False,
                 Branch_Updated);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Build_Tree_Entry
                (8#100644#,
                 "built.txt",
                 [1 => 1, 2 .. 20 => 0],
                 Built_Tree_Entry,
                 Built_Tree_Entry_Last);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Build_Commit_Object
                ([1 .. 40 => Character'Pos ('0')],
                 False,
                 [1 .. 40 => Character'Pos ('0')],
                 "A <a@example.test> 0 +0000",
                 "A <a@example.test> 0 +0000",
                 "message" & Character'Val (10),
                 Built_Commit_Data,
                 Built_Commit_Last);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Build_Merge_Conflict_File
                ("ours",
                 Bytes_From_String ("a"),
                 "theirs",
                 Bytes_From_String ("b"),
                 Config_Value,
                 Config_Value_Last);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Classify_Three_Way_Blob_Merge
                ([1 .. 40 => Character'Pos ('0')],
                 [1 .. 40 => Character'Pos ('0')],
                 [1 .. 40 => Character'Pos ('1')],
                 Merge_Result);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Build_Sequencer_Pick_Line
                ([1 .. 40 => Character'Pos ('0')],
                 "subject",
                 Config_Value,
                 Config_Value_Last);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Build_Tag_Object
                ([1 .. 40 => Character'Pos ('0')],
                 SSH_Lib.Git.Pack_Blob,
                 "v1.0.0",
                 "A <a@example.test> 0 +0000",
                 "message" & Character'Val (10),
                 Built_Tag_Data,
                 Built_Tag_Last);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Read_Config_Value
                (Repo_Root,
                 "core",
                 "bare",
                 Config_Value,
                 Config_Value_Last,
                 Config_Found);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Write_Config_Value
                (Repo_Root, "core", "bare", "true");
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Write_Remote_URL
                (Repo_Root, "origin", "ssh://example.invalid/repo.git");
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Read_Remote_URL
                (Repo_Root,
                 "origin",
                 Config_Value,
                 Config_Value_Last,
                 Config_Found);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Delete_Remote_URL
                (Repo_Root, "origin", Config_Removed);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Write_Remote_Fetch_Refspec
                (Repo_Root,
                 "origin",
                 "+refs/heads/*:refs/remotes/origin/*");
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Read_Remote_Fetch_Refspec
                (Repo_Root,
                 "origin",
                 Config_Value,
                 Config_Value_Last,
                 Config_Found);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Append_Remote_Fetch_Refspec
                (Repo_Root,
                 "origin",
                 "+refs/tags/*:refs/tags/*");
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Read_Config_Values
                (Repo_Root,
                 "remote origin",
                 "fetch",
                 Config_Values,
                 Config_Value_Lasts,
                 Config_Value_Count);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Read_Remote_Fetch_Refspecs
                (Repo_Root,
                 "origin",
                 Config_Values,
                 Config_Value_Lasts,
                 Config_Value_Count);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Delete_Remote_Fetch_Refspecs
                (Repo_Root, "origin", Config_Removed);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Write_Remote_Push_Refspec
                (Repo_Root,
                 "origin",
                 "refs/heads/main:refs/heads/main");
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Read_Remote_Push_Refspec
                (Repo_Root,
                 "origin",
                 Config_Value,
                 Config_Value_Last,
                 Config_Found);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Append_Remote_Push_Refspec
                (Repo_Root,
                 "origin",
                 "+refs/tags/*:refs/tags/*");
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Read_Remote_Push_Refspecs
                (Repo_Root,
                 "origin",
                 Config_Values,
                 Config_Value_Lasts,
                 Config_Value_Count);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Delete_Remote_Push_Refspecs
                (Repo_Root, "origin", Config_Removed);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Append_Config_Value
                (Repo_Root,
                 "remote backup",
                 "fetch",
                 "+refs/heads/*:refs/remotes/backup/*");
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Delete_Config_Value
                (Repo_Root, "remote backup", "fetch", Config_Removed);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Write_Credential_Helper
                (Repo_Root, "cache --timeout=60");
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Read_Credential_Helper
                (Repo_Root,
                 Config_Value,
                 Config_Value_Last,
                 Config_Found);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Append_Credential_Helper
                (Repo_Root, "store --file=/tmp/creds");
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Read_Credential_Helpers
                (Repo_Root,
                 Config_Values,
                 Config_Value_Lasts,
                 Config_Value_Count);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Delete_Credential_Helper
                (Repo_Root, Config_Removed);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Write_Credential_Username
                (Repo_Root, "alice");
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Read_Credential_Username
                (Repo_Root,
                 Config_Value,
                 Config_Value_Last,
                 Config_Found);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Delete_Credential_Username
                (Repo_Root, Config_Removed);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Build_Credential_Helper_Request
                ("https",
                 "example.invalid",
                 "owner/repo",
                 "alice",
                 "",
                 Config_Values,
                 Config_Value_Last);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Parse_Credential_Helper_Response
                (Bytes_From_String
                   ("username=bob" & Character'Val (10)
                    & "password=secret" & Character'Val (10)
                    & Character'Val (10)),
                 Config_Value,
                 Config_Value_Last,
                 Config_Found,
                 Reflog_Line,
                 Reflog_Last,
                 Ref_Found);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Execute_Credential_Helper
                ("",
                 "https",
                 "example.invalid",
                 "owner/repo",
                 "alice",
                 "",
                 1,
                 Config_Value,
                 Config_Value_Last,
                 Config_Found,
                 Reflog_Line,
                 Reflog_Last,
                 Ref_Found);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Build_Credential_Password_Prompt
                ("https",
                 "example.invalid",
                 "owner/repo",
                 "alice",
                 Config_Values,
                 Config_Value_Last);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Prompt_Credential_Password
                ("https",
                 "",
                 "",
                 "",
                 Config_Values,
                 Config_Value_Last);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Write_Credential_Store
                (Repo_Root,
                 "https",
                 "example.invalid",
                 "owner/repo",
                 "alice",
                 "stored-secret");
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Read_Credential_Store
                (Repo_Root,
                 "https",
                 "example.invalid",
                 "owner/repo",
                 "alice",
                 Reflog_Line,
                 Reflog_Last,
                 Ref_Found);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Delete_Credential_Store
                (Repo_Root,
                 "https",
                 "example.invalid",
                 "owner/repo",
                 "alice",
                 Config_Removed);
            Touch (Status_Value);
            SSH_Lib.Git.Clear_Credential_Data (Config_Values);
            Status_Value :=
              SSH_Lib.Git.Write_User_Name
                (Repo_Root, "Ada Lovelace");
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Read_User_Name
                (Repo_Root,
                 Config_Value,
                 Config_Value_Last,
                 Config_Found);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Delete_User_Name
                (Repo_Root, Config_Removed);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Write_User_Email
                (Repo_Root, "ada@example.invalid");
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Read_User_Email
                (Repo_Root,
                 Config_Value,
                 Config_Value_Last,
                 Config_Found);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Delete_User_Email
                (Repo_Root, Config_Removed);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Write_Init_Default_Branch
                (Repo_Root, "trunk");
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Read_Init_Default_Branch
                (Repo_Root,
                 Config_Value,
                 Config_Value_Last,
                 Config_Found);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Delete_Init_Default_Branch
                (Repo_Root, Config_Removed);
            Touch (Status_Value);
            if not SSH_Lib.Git.Valid_Push_Default_Mode ("simple") then
               raise Program_Error;
            end if;
            Status_Value :=
              SSH_Lib.Git.Write_Push_Default
                (Repo_Root, "simple");
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Read_Push_Default
                (Repo_Root,
                 Config_Value,
                 Config_Value_Last,
                 Config_Found);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Delete_Push_Default
                (Repo_Root, Config_Removed);
            Touch (Status_Value);
            if not SSH_Lib.Git.Valid_Pull_Rebase_Mode ("merges") then
               raise Program_Error;
            end if;
            Status_Value :=
              SSH_Lib.Git.Write_Pull_Rebase
                (Repo_Root, "merges");
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Read_Pull_Rebase
                (Repo_Root,
                 Config_Value,
                 Config_Value_Last,
                 Config_Found);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Delete_Pull_Rebase
                (Repo_Root, Config_Removed);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Write_Core_Bare
                (Repo_Root, False);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Read_Core_Bare
                (Repo_Root, Core_Bare, Config_Found);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Delete_Core_Bare
                (Repo_Root, Config_Removed);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Write_Core_Filemode
                (Repo_Root, True);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Read_Core_Filemode
                (Repo_Root, Core_Filemode, Config_Found);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Delete_Core_Filemode
                (Repo_Root, Config_Removed);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Write_Core_Log_All_Ref_Updates
                (Repo_Root, True);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Read_Core_Log_All_Ref_Updates
                (Repo_Root,
                 Core_Log_All_Ref_Updates,
                 Config_Found);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Delete_Core_Log_All_Ref_Updates
                (Repo_Root, Config_Removed);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Write_Branch_Upstream
                (Repo_Root, "main", "origin", "refs/heads/main");
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Read_Branch_Upstream
                (Repo_Root,
                 "main",
                 Config_Value,
                 Config_Value_Last,
                 Symbolic_Target,
                 Symbolic_Target_Last,
                 Config_Found);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Delete_Branch_Upstream
                (Repo_Root, "main", Config_Removed);
            Touch (Status_Value);
	            Status_Value :=
	              SSH_Lib.Git.Store_Loose_Object
	                (Repo_Root,
	                 SSH_Lib.Git.Pack_Blob,
	                 [Character'Pos ('o'), Character'Pos ('k')],
	                 Stored_Hex,
	                 Stored_Last);
	            Touch (Status_Value);
	            Status_Value :=
	              SSH_Lib.Git.Store_Loose_Object_Validated
	                (Repo_Root,
	                 SSH_Lib.Git.Pack_Blob,
	                 [Character'Pos ('o'), Character'Pos ('k')],
	                 Validated_Stored_Hex,
	                 Validated_Stored_Last);
	            Touch (Status_Value);
	            Status_Value :=
	              SSH_Lib.Git.List_Loose_Object_IDs
	                (Repo_Root,
	                 Listed_Loose_Object_IDs,
	                 Listed_Loose_Object_Count);
	            Touch (Status_Value);
	            Status_Value :=
	              SSH_Lib.Git.Read_Loose_Object
	                (Repo_Root, Stored_Hex, Read_Kind, Read_Data, Read_Last);
	            Touch (Status_Value);
	            Status_Value :=
	              SSH_Lib.Git.Store_Loose_Object
	                (Repo_Root,
	                 SSH_Lib.Git.Pack_Blob,
	                 [Character'Pos ('d'), Character'Pos ('e')],
	                 Deleted_Loose_Hex,
	                 Deleted_Loose_Last);
	            Touch (Status_Value);
	            Status_Value :=
	              SSH_Lib.Git.Delete_Loose_Object
	                (Repo_Root, Deleted_Loose_Hex);
	            Touch (Status_Value);
	            Status_Value :=
	              SSH_Lib.Git.Read_Loose_Object_Validated
	                (Repo_Root, Stored_Hex, Read_Kind, Read_Data, Read_Last);
	            Touch (Status_Value);
	            Status_Value :=
	              SSH_Lib.Git.Parse_Tree_Entry
                (Tree_Data,
                 0,
                 Tree_Mode,
                 Tree_Name,
                 Tree_Name_Last,
                 Tree_Object_ID,
                 Tree_Object_Last,
                 Tree_Next_Offset);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Validate_Tree_Object
                (Tree_Data, Tree_Entry_Count);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Validate_Object_Data
                (SSH_Lib.Git.Pack_Blob,
                 [Character'Pos ('o'), Character'Pos ('k')]);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Validate_Object_Data
                (SSH_Lib.Git.Pack_Tree, Tree_Data);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Find_Tree_Entry
                (Tree_Data,
                 Bytes_From_String ("hello.txt"),
                 Tree_Found_Mode,
                 Tree_Found_ID,
                 Tree_Found_Last);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Find_Tree_Entry_Hex
                (Tree_Data,
                 Bytes_From_String ("hello.txt"),
                 Tree_Found_Hex_Mode,
                 Tree_Found_Hex,
                 Tree_Found_Hex_Last);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.List_Tree_Entries_Hex
                (Tree_Data,
                 Listed_Tree_Names,
                 Listed_Tree_Name_Lasts,
                 Listed_Tree_Modes,
                 Listed_Tree_IDs,
                 Listed_Tree_Count);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Store_Loose_Object_Validated
                (Repo_Root,
                 SSH_Lib.Git.Pack_Tree,
                 Tree_Data,
                 Stored_Tree_Hex,
                 Stored_Tree_Last);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Read_Tree_Entries_Hex
                (Repo_Root,
                 Stored_Tree_Hex,
                 Pack_Index_List,
                 Pack_Data,
                 Built_Index,
                 Found_Pack_Checksum,
                 Found_Pack_Checksum_Last,
                 Stored_List_Tree_Data,
                 Stored_List_Tree_Last,
                 Stored_List_Names,
                 Stored_List_Name_Lasts,
                 Stored_List_Modes,
                 Stored_List_IDs,
                 Stored_List_Count);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.List_Tree_Paths_Hex
                (Repo_Root,
                 Stored_Tree_Hex,
                 Path_List_Names,
                 Path_List_Path_Lasts,
                 Path_List_Modes,
                 Path_List_IDs,
                 Path_List_Count);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.List_Tree_Paths_Matching_Hex
                (Repo_Root,
                 Stored_Tree_Hex,
                 ".",
                 Path_List_Names,
                 Path_List_Path_Lasts,
                 Path_List_Modes,
                 Path_List_IDs,
                 Path_List_Count);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Parse_Object_ID_Hex
                (Stored_Tree_Hex,
                 Stored_Tree_Raw_ID,
                 Stored_Tree_Raw_Last);
            Touch (Status_Value);
            declare
               Path_List_Root_Tree_Data :
                 constant Ada.Streams.Stream_Element_Array :=
                   Bytes_From_String
                     ("40000 sub" & Character'Val (0))
                   & Stored_Tree_Raw_ID;
            begin
               Status_Value :=
                 SSH_Lib.Git.Store_Loose_Object_Validated
                   (Repo_Root,
                    SSH_Lib.Git.Pack_Tree,
                    Path_List_Root_Tree_Data,
                    Path_List_Root_Tree_Hex,
                    Path_List_Root_Tree_Last);
               Touch (Status_Value);
               Status_Value :=
                 SSH_Lib.Git.Read_Path_Tree_Entries_Hex
                   (Repo_Root,
                    Path_List_Root_Tree_Hex,
                    Bytes_From_String ("sub"),
                    Pack_Index_List,
                    Pack_Data,
                    Built_Index,
                    Found_Pack_Checksum,
                    Found_Pack_Checksum_Last,
                    Path_List_Parent_Tree_Data,
                    Path_List_Parent_Tree_Last,
                    Path_List_Mode,
                    Path_List_Tree_Data,
                    Path_List_Tree_Last,
                    Path_List_Names,
                    Path_List_Name_Lasts,
                    Path_List_Modes,
                    Path_List_IDs,
                    Path_List_Count);
               Touch (Status_Value);
            end;
            Status_Value :=
              SSH_Lib.Git.Read_Tree_Entry_Object
                (Repo_Root,
                 Stored_Tree_Hex,
                 Bytes_From_String ("hello.txt"),
                 Pack_Index_List,
                 Pack_Data,
                 Built_Index,
                 Found_Pack_Checksum,
                 Found_Pack_Checksum_Last,
                 Traversed_Tree_Data,
                 Traversed_Tree_Last,
                 Traversed_Mode,
                 Read_Kind,
                 Traversed_Data,
                 Traversed_Last);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Read_Path_Object
                (Repo_Root,
                 Stored_Tree_Hex,
                 Bytes_From_String ("hello.txt"),
                 Pack_Index_List,
                 Pack_Data,
                 Built_Index,
                 Found_Pack_Checksum,
                 Found_Pack_Checksum_Last,
                 Path_Tree_Data,
                 Path_Tree_Last,
                 Path_Mode,
                 Read_Kind,
                 Path_Data,
                 Path_Last);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Resolve_Path_Entry_Hex
                (Repo_Root,
                 Stored_Tree_Hex,
                 Bytes_From_String ("hello.txt"),
                 Pack_Index_List,
                 Pack_Data,
                 Built_Index,
                 Found_Pack_Checksum,
                 Found_Pack_Checksum_Last,
                 Resolved_Path_Tree_Data,
                 Resolved_Path_Tree_Last,
                 Resolved_Path_Mode,
                 Resolved_Path_ID,
                 Resolved_Path_ID_Last);
            Touch (Status_Value);
            declare
               Stored_Commit_Data :
                 constant Ada.Streams.Stream_Element_Array :=
                   Bytes_From_String ("tree ")
                   & Stored_Tree_Hex
                   & Bytes_From_String
                       (Character'Val (10)
                        & "author A <a@example.test> 0 +0000"
                        & Character'Val (10)
                        & "committer A <a@example.test> 0 +0000"
                        & Character'Val (10)
                        & Character'Val (10)
                        & "message"
                        & Character'Val (10));
            begin
               Status_Value :=
                 SSH_Lib.Git.Store_Loose_Object_Validated
                   (Repo_Root,
                    SSH_Lib.Git.Pack_Commit,
                    Stored_Commit_Data,
                    Stored_Commit_Hex,
                    Stored_Commit_Last);
               Touch (Status_Value);
               Status_Value :=
                 SSH_Lib.Git.Read_Commit_Tree_Object
                   (Repo_Root,
                    Stored_Commit_Hex,
                    Pack_Index_List,
                    Pack_Data,
                    Built_Index,
                    Found_Pack_Checksum,
                    Found_Pack_Checksum_Last,
                    Commit_Tree_Read_Commit_Data,
                    Commit_Tree_Read_Commit_Last,
                    Commit_Tree_Read_ID,
                    Commit_Tree_Read_ID_Last,
                    Commit_Tree_Read_Data,
                    Commit_Tree_Read_Last,
                    Commit_Tree_Read_Count);
               Touch (Status_Value);
               Status_Value :=
                 SSH_Lib.Git.Read_Commit_Tree_Entries_Hex
                   (Repo_Root,
                    Stored_Commit_Hex,
                    Pack_Index_List,
                    Pack_Data,
                    Built_Index,
                    Found_Pack_Checksum,
                    Found_Pack_Checksum_Last,
                    Commit_List_Commit_Data,
                    Commit_List_Commit_Last,
                    Commit_List_Tree_ID,
                    Commit_List_Tree_ID_Last,
                    Commit_List_Tree_Data,
                    Commit_List_Tree_Last,
                    Commit_List_Names,
                    Commit_List_Name_Lasts,
                    Commit_List_Modes,
                    Commit_List_IDs,
                    Commit_List_Count);
               Touch (Status_Value);
               declare
                  Commit_Path_List_Data :
                    constant Ada.Streams.Stream_Element_Array :=
                      Bytes_From_String ("tree ")
                      & Path_List_Root_Tree_Hex
                      & Bytes_From_String
                          (Character'Val (10)
                           & "author A <a@example.test> 0 +0000"
                           & Character'Val (10)
                           & "committer A <a@example.test> 0 +0000"
                           & Character'Val (10)
                           & Character'Val (10)
                           & "nested"
                           & Character'Val (10));
               begin
                  Status_Value :=
                    SSH_Lib.Git.Store_Loose_Object_Validated
                      (Repo_Root,
                       SSH_Lib.Git.Pack_Commit,
                       Commit_Path_List_Data,
                       Commit_Path_List_Hex,
                       Commit_Path_List_Last);
                  Touch (Status_Value);
                  Status_Value :=
                    SSH_Lib.Git.Read_Commit_Path_Tree_Entries_Hex
                      (Repo_Root,
                       Commit_Path_List_Hex,
                       Bytes_From_String ("sub"),
                       Pack_Index_List,
                       Pack_Data,
                       Built_Index,
                       Found_Pack_Checksum,
                       Found_Pack_Checksum_Last,
                       Commit_Path_List_Commit_Data,
                       Commit_Path_List_Commit_Last,
                       Commit_Path_List_Tree_ID,
                       Commit_Path_List_Tree_ID_Last,
                       Commit_Path_List_Parent_Tree_Data,
                       Commit_Path_List_Parent_Tree_Last,
                       Commit_Path_List_Mode,
                       Commit_Path_List_Tree_Data,
                       Commit_Path_List_Tree_Last,
                       Commit_Path_List_Names,
                       Commit_Path_List_Name_Lasts,
                       Commit_Path_List_Modes,
                       Commit_Path_List_IDs,
                       Commit_Path_List_Count);
                  Touch (Status_Value);
                  Status_Value :=
                    SSH_Lib.Git.Write_Direct_Ref
                      (Repo_Root,
                       "refs/heads/nested",
                       Commit_Path_List_Hex);
                  Touch (Status_Value);
                  Status_Value :=
                    SSH_Lib.Git.Read_Ref_Path_Tree_Entries_Hex
                      (Repo_Root,
                       "refs/heads/nested",
                       Bytes_From_String ("sub"),
                       Ref_Path_List_Resolved_ID,
                       Ref_Path_List_Resolved_Last,
                       Pack_Index_List,
                       Pack_Data,
                       Built_Index,
                       Found_Pack_Checksum,
                       Found_Pack_Checksum_Last,
                       Ref_Path_List_Commit_Data,
                       Ref_Path_List_Commit_Last,
                       Ref_Path_List_Tree_ID,
                       Ref_Path_List_Tree_ID_Last,
                       Ref_Path_List_Parent_Tree_Data,
                       Ref_Path_List_Parent_Tree_Last,
                       Ref_Path_List_Mode,
                       Ref_Path_List_Tree_Data,
                       Ref_Path_List_Tree_Last,
                       Ref_Path_List_Names,
                       Ref_Path_List_Name_Lasts,
                       Ref_Path_List_Modes,
                       Ref_Path_List_IDs,
                       Ref_Path_List_Count);
                  Touch (Status_Value);
                  declare
                     Tag_Path_List_Data :
                       constant Ada.Streams.Stream_Element_Array :=
                         Bytes_From_String ("object ")
                         & Commit_Path_List_Hex
                         & Bytes_From_String
                             (Character'Val (10)
                              & "type commit"
                              & Character'Val (10)
                              & "tag nested"
                              & Character'Val (10)
                              & Character'Val (10));
                  begin
                     Status_Value :=
                       SSH_Lib.Git.Store_Loose_Object_Validated
                         (Repo_Root,
                          SSH_Lib.Git.Pack_Tag,
                          Tag_Path_List_Data,
                          Tag_Path_List_Hex,
                          Tag_Path_List_Last);
                     Touch (Status_Value);
                     Status_Value :=
                       SSH_Lib.Git.Read_Tag_Path_Tree_Entries_Hex
                         (Repo_Root,
                          Tag_Path_List_Hex,
                          Bytes_From_String ("sub"),
                          Tag_Path_List_Peeled_ID,
                          Tag_Path_List_Peeled_Last,
                          Pack_Index_List,
                          Pack_Data,
                          Built_Index,
                          Found_Pack_Checksum,
                          Found_Pack_Checksum_Last,
                          Tag_Path_List_Tag_Data,
                          Tag_Path_List_Tag_Last,
                          Tag_Path_List_Commit_Data,
                          Tag_Path_List_Commit_Last,
                          Tag_Path_List_Tree_ID,
                          Tag_Path_List_Tree_ID_Last,
                          Tag_Path_List_Parent_Tree_Data,
                          Tag_Path_List_Parent_Tree_Last,
                          Tag_Path_List_Mode,
                          Tag_Path_List_Tree_Data,
                          Tag_Path_List_Tree_Last,
                          Tag_Path_List_Names,
                          Tag_Path_List_Name_Lasts,
                          Tag_Path_List_Modes,
                          Tag_Path_List_IDs,
                          Tag_Path_List_Count);
                     Touch (Status_Value);
                     Status_Value :=
                       SSH_Lib.Git.Write_Direct_Ref
                         (Repo_Root,
                          "refs/tags/nested",
                          Tag_Path_List_Hex);
                     Touch (Status_Value);
                     Status_Value :=
                       SSH_Lib.Git.Read_Ref_Commitish_Path_Tree_Entries_Hex
                         (Repo_Root,
                          "refs/tags/nested",
                          Bytes_From_String ("sub"),
                          Ref_Path_List_Resolved_ID,
                          Ref_Path_List_Resolved_Last,
                          Tag_Path_List_Peeled_ID,
                          Tag_Path_List_Peeled_Last,
                          Pack_Index_List,
                          Pack_Data,
                          Built_Index,
                          Found_Pack_Checksum,
                          Found_Pack_Checksum_Last,
                          Tag_Path_List_Tag_Data,
                          Tag_Path_List_Tag_Last,
                          Tag_Path_List_Commit_Data,
                          Tag_Path_List_Commit_Last,
                          Tag_Path_List_Tree_ID,
                          Tag_Path_List_Tree_ID_Last,
                          Tag_Path_List_Parent_Tree_Data,
                          Tag_Path_List_Parent_Tree_Last,
                          Tag_Path_List_Mode,
                          Tag_Path_List_Tree_Data,
                          Tag_Path_List_Tree_Last,
                          Tag_Path_List_Names,
                          Tag_Path_List_Name_Lasts,
                          Tag_Path_List_Modes,
                          Tag_Path_List_IDs,
                          Tag_Path_List_Count);
                     Touch (Status_Value);
                  end;
               end;
               Status_Value :=
                 SSH_Lib.Git.Read_Commit_Path_Object
                   (Repo_Root,
                    Stored_Commit_Hex,
                    Bytes_From_String ("hello.txt"),
                    Pack_Index_List,
                    Pack_Data,
                    Built_Index,
                    Found_Pack_Checksum,
                    Found_Pack_Checksum_Last,
                    Commit_Path_Commit_Data,
                    Commit_Path_Commit_Last,
                    Commit_Path_Tree_ID,
                    Commit_Path_Tree_ID_Last,
                    Commit_Path_Tree_Data,
                    Commit_Path_Tree_Last,
                    Commit_Path_Mode,
                    Read_Kind,
                    Commit_Path_Data,
                    Commit_Path_Last);
               Touch (Status_Value);
               Status_Value :=
                 SSH_Lib.Git.Resolve_Commit_Path_Entry_Hex
                   (Repo_Root,
                    Stored_Commit_Hex,
                    Bytes_From_String ("hello.txt"),
                    Pack_Index_List,
                    Pack_Data,
                    Built_Index,
                    Found_Pack_Checksum,
                    Found_Pack_Checksum_Last,
                    Commit_Resolved_Path_Commit_Data,
                    Commit_Resolved_Path_Commit_Last,
                    Commit_Resolved_Path_Tree_ID,
                    Commit_Resolved_Path_Tree_ID_Last,
                    Commit_Resolved_Path_Tree_Data,
                    Commit_Resolved_Path_Tree_Last,
                    Commit_Resolved_Path_Mode,
                    Commit_Resolved_Path_ID,
                    Commit_Resolved_Path_ID_Last);
               Touch (Status_Value);
               Status_Value :=
                 SSH_Lib.Git.Write_Direct_Ref
                   (Repo_Root, "refs/heads/main", Stored_Commit_Hex);
               Touch (Status_Value);
               Status_Value :=
                 SSH_Lib.Git.Read_Ref_Path_Object
                   (Repo_Root,
                    "refs/heads/main",
                    Bytes_From_String ("hello.txt"),
                    Ref_Path_Resolved_ID,
                    Ref_Path_Resolved_Last,
                    Pack_Index_List,
                    Pack_Data,
                    Built_Index,
                    Found_Pack_Checksum,
                    Found_Pack_Checksum_Last,
                    Ref_Path_Commit_Data,
                    Ref_Path_Commit_Last,
                    Ref_Path_Tree_ID,
                    Ref_Path_Tree_ID_Last,
                    Ref_Path_Tree_Data,
                    Ref_Path_Tree_Last,
                    Ref_Path_Mode,
                    Read_Kind,
                    Ref_Path_Data,
                    Ref_Path_Last);
               Touch (Status_Value);
               Status_Value :=
                 SSH_Lib.Git.Resolve_Ref_Path_Entry_Hex
                   (Repo_Root,
                    "refs/heads/main",
                    Bytes_From_String ("hello.txt"),
                    Ref_Resolved_Path_Resolved_ID,
                    Ref_Resolved_Path_Resolved_Last,
                    Pack_Index_List,
                    Pack_Data,
                    Built_Index,
                    Found_Pack_Checksum,
                    Found_Pack_Checksum_Last,
                    Ref_Resolved_Path_Commit_Data,
                    Ref_Resolved_Path_Commit_Last,
                    Ref_Resolved_Path_Tree_ID,
                    Ref_Resolved_Path_Tree_ID_Last,
                    Ref_Resolved_Path_Tree_Data,
                    Ref_Resolved_Path_Tree_Last,
                    Ref_Resolved_Path_Mode,
                    Ref_Resolved_Path_ID,
                    Ref_Resolved_Path_ID_Last);
               Touch (Status_Value);
               declare
                  Stored_Tag_Data :
                    constant Ada.Streams.Stream_Element_Array :=
                      Bytes_From_String ("object ")
                      & Stored_Commit_Hex
                      & Bytes_From_String
                          (Character'Val (10)
                           & "type commit"
                           & Character'Val (10)
                           & "tag v1.0.0"
                           & Character'Val (10)
                           & "tagger A <a@example.test> 0 +0000"
                           & Character'Val (10)
                           & Character'Val (10)
                           & "message"
                           & Character'Val (10));
               begin
                  Status_Value :=
                    SSH_Lib.Git.Store_Loose_Object_Validated
                      (Repo_Root,
                       SSH_Lib.Git.Pack_Tag,
                       Stored_Tag_Data,
                       Stored_Tag_Hex,
                       Stored_Tag_Last);
                  Touch (Status_Value);
                  Status_Value :=
                    SSH_Lib.Git.Read_Tag_Path_Object
                      (Repo_Root,
                       Stored_Tag_Hex,
                       Bytes_From_String ("hello.txt"),
                       Tagged_Path_Peeled_ID,
                       Tagged_Path_Peeled_Last,
                       Pack_Index_List,
                       Pack_Data,
                       Built_Index,
                       Found_Pack_Checksum,
                       Found_Pack_Checksum_Last,
                       Tagged_Path_Tag_Data,
                       Tagged_Path_Tag_Last,
                       Tagged_Path_Commit_Data,
                       Tagged_Path_Commit_Last,
                       Tagged_Path_Tree_ID,
                       Tagged_Path_Tree_ID_Last,
                       Tagged_Path_Tree_Data,
                       Tagged_Path_Tree_Last,
                       Tagged_Path_Mode,
                       Read_Kind,
                       Tagged_Path_Data,
                       Tagged_Path_Last);
                  Touch (Status_Value);
                  Status_Value :=
                    SSH_Lib.Git.Resolve_Tag_Path_Entry_Hex
                      (Repo_Root,
                       Stored_Tag_Hex,
                       Bytes_From_String ("hello.txt"),
                       Tagged_Resolved_Path_Peeled_ID,
                       Tagged_Resolved_Path_Peeled_Last,
                       Pack_Index_List,
                       Pack_Data,
                       Built_Index,
                       Found_Pack_Checksum,
                       Found_Pack_Checksum_Last,
                       Tagged_Resolved_Path_Tag_Data,
                       Tagged_Resolved_Path_Tag_Last,
                       Tagged_Resolved_Path_Commit_Data,
                       Tagged_Resolved_Path_Commit_Last,
                       Tagged_Resolved_Path_Tree_ID,
                       Tagged_Resolved_Path_Tree_ID_Last,
                       Tagged_Resolved_Path_Tree_Data,
                       Tagged_Resolved_Path_Tree_Last,
                       Tagged_Resolved_Path_Mode,
                       Tagged_Resolved_Path_ID,
                       Tagged_Resolved_Path_ID_Last);
                  Touch (Status_Value);
                  Status_Value :=
                    SSH_Lib.Git.Write_Direct_Ref
                      (Repo_Root, "refs/tags/v1.0.0", Stored_Tag_Hex);
                  Touch (Status_Value);
                  Status_Value :=
                    SSH_Lib.Git.Read_Ref_Commitish_Path_Object
                      (Repo_Root,
                       "refs/tags/v1.0.0",
                       Bytes_From_String ("hello.txt"),
                       Commitish_Path_Resolved_ID,
                       Commitish_Path_Resolved_Last,
                       Commitish_Path_Peeled_ID,
                       Commitish_Path_Peeled_Last,
                       Pack_Index_List,
                       Pack_Data,
                       Built_Index,
                       Found_Pack_Checksum,
                       Found_Pack_Checksum_Last,
                       Commitish_Path_Tag_Data,
                       Commitish_Path_Tag_Last,
                       Commitish_Path_Commit_Data,
                       Commitish_Path_Commit_Last,
                       Commitish_Path_Tree_ID,
                       Commitish_Path_Tree_ID_Last,
                       Commitish_Path_Tree_Data,
                       Commitish_Path_Tree_Last,
                       Commitish_Path_Mode,
                       Read_Kind,
                       Commitish_Path_Data,
                       Commitish_Path_Last);
                  Touch (Status_Value);
                  Status_Value :=
                    SSH_Lib.Git.Resolve_Ref_Commitish_Path_Entry_Hex
                      (Repo_Root,
                       "refs/tags/v1.0.0",
                       Bytes_From_String ("hello.txt"),
                       Commitish_Resolved_Path_Resolved_ID,
                       Commitish_Resolved_Path_Resolved_Last,
                       Commitish_Resolved_Path_Peeled_ID,
                       Commitish_Resolved_Path_Peeled_Last,
                       Pack_Index_List,
                       Pack_Data,
                       Built_Index,
                       Found_Pack_Checksum,
                       Found_Pack_Checksum_Last,
                       Commitish_Resolved_Path_Tag_Data,
                       Commitish_Resolved_Path_Tag_Last,
                       Commitish_Resolved_Path_Commit_Data,
                       Commitish_Resolved_Path_Commit_Last,
                       Commitish_Resolved_Path_Tree_ID,
                       Commitish_Resolved_Path_Tree_ID_Last,
                       Commitish_Resolved_Path_Tree_Data,
                       Commitish_Resolved_Path_Tree_Last,
                       Commitish_Resolved_Path_Mode,
                       Commitish_Resolved_Path_ID,
                       Commitish_Resolved_Path_ID_Last);
                  Touch (Status_Value);
                  Status_Value :=
                    SSH_Lib.Git.Read_Ref_Commitish_Tree_Object
                      (Repo_Root,
                       "refs/tags/v1.0.0",
                       Commitish_Tree_Resolved_ID,
                       Commitish_Tree_Resolved_Last,
                       Commitish_Tree_Peeled_ID,
                       Commitish_Tree_Peeled_Last,
                       Pack_Index_List,
                       Pack_Data,
                       Built_Index,
                       Found_Pack_Checksum,
                       Found_Pack_Checksum_Last,
                       Commitish_Tree_Tag_Data,
                       Commitish_Tree_Tag_Last,
                       Commitish_Tree_Commit_Data,
                       Commitish_Tree_Commit_Last,
                       Commitish_Tree_ID,
                       Commitish_Tree_ID_Last,
                       Commitish_Tree_Data,
                       Commitish_Tree_Last,
                       Commitish_Tree_Count);
                  Touch (Status_Value);
                  Status_Value :=
                    SSH_Lib.Git.Read_Ref_Commitish_Tree_Entries_Hex
                      (Repo_Root,
                       "refs/tags/v1.0.0",
                       Commitish_List_Resolved_ID,
                       Commitish_List_Resolved_Last,
                       Commitish_List_Peeled_ID,
                       Commitish_List_Peeled_Last,
                       Pack_Index_List,
                       Pack_Data,
                       Built_Index,
                       Found_Pack_Checksum,
                       Found_Pack_Checksum_Last,
                       Commitish_List_Tag_Data,
                       Commitish_List_Tag_Last,
                       Commitish_List_Commit_Data,
                       Commitish_List_Commit_Last,
                       Commitish_List_Tree_ID,
                       Commitish_List_Tree_ID_Last,
                       Commitish_List_Tree_Data,
                       Commitish_List_Tree_Last,
                       Commitish_List_Names,
                       Commitish_List_Name_Lasts,
                       Commitish_List_Modes,
                       Commitish_List_IDs,
                       Commitish_List_Count);
                  Touch (Status_Value);
               end;
            end;
            Status_Value :=
              SSH_Lib.Git.Parse_Commit_Tree_ID
                (Commit_Data, Commit_Tree_Hex, Commit_Tree_Last);
            Touch (Status_Value);
	            Status_Value :=
	              SSH_Lib.Git.Parse_Commit_Parent_ID
	                (Commit_Data, 1, Commit_Parent_Hex, Commit_Parent_Last);
	            Touch (Status_Value);
	            Status_Value :=
	              SSH_Lib.Git.Parse_Commit_Author_Line
	                (Commit_Data, Commit_Author_Line, Commit_Author_Last);
	            Touch (Status_Value);
	            Status_Value :=
	              SSH_Lib.Git.Parse_Commit_Committer_Line
	                (Commit_Data,
	                 Commit_Committer_Line,
	                 Commit_Committer_Last);
	            Touch (Status_Value);
	            Status_Value :=
	              SSH_Lib.Git.Parse_Commit_Message_Offset
	                (Commit_Data, Commit_Message_Offset);
	            Touch (Status_Value);
	            Status_Value :=
	              SSH_Lib.Git.Validate_Commit_Object
	                (Commit_Data, Commit_Parent_Count);
	            Touch (Status_Value);
	            Status_Value :=
	              SSH_Lib.Git.Validate_Object_Data
	                (SSH_Lib.Git.Pack_Commit, Commit_Data);
	            Touch (Status_Value);
	            Status_Value :=
	              SSH_Lib.Git.Parse_Tag_Target
	                (Tag_Data,
	                 Tag_Target_Hex,
	                 Tag_Target_Last,
	                 Tag_Target_Kind);
	            Touch (Status_Value);
	            Status_Value :=
	              SSH_Lib.Git.Parse_Tag_Name
	                (Tag_Data, Tag_Name, Tag_Name_Last);
	            Touch (Status_Value);
	            Status_Value :=
	              SSH_Lib.Git.Parse_Tag_Message_Offset
	                (Tag_Data, Tag_Message_Offset);
	            Touch (Status_Value);
	            Status_Value :=
	              SSH_Lib.Git.Validate_Tag_Object
	                (Tag_Data, Tag_Target_Kind);
	            Touch (Status_Value);
	            Status_Value :=
	              SSH_Lib.Git.Validate_Object_Data
	                (SSH_Lib.Git.Pack_Tag, Tag_Data);
	            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Store_Pack_File
                (Repo_Root, Pack_Data, Pack_Checksum, Pack_Checksum_Last);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Read_Pack_File
                (Repo_Root, Pack_Checksum, Read_Data, Read_Last);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Delete_Pack_File
                (Repo_Root, Pack_Checksum);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Store_Pack_File
                (Repo_Root, Pack_Data, Pack_Checksum, Pack_Checksum_Last);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Build_Pack_Index
                (Pack_Data,
                 Pack_Index_Scratch,
                 Built_Index,
                 Built_Index_Last);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Store_Pack_Index
                (Repo_Root,
                 Pack_Checksum,
                 Built_Index (Built_Index'First .. Built_Index_Last));
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Read_Pack_Index
                (Repo_Root, Pack_Checksum, Read_Index, Read_Index_Last);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Delete_Pack_Index
                (Repo_Root, Pack_Checksum);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Store_Pack_Index
                (Repo_Root,
                 Pack_Checksum,
                 Built_Index (Built_Index'First .. Built_Index_Last));
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Delete_Stored_Pack
                (Repo_Root,
                 Pack_Checksum,
                 Deleted_Pack_File,
                 Deleted_Pack_Index);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Store_Pack_File
                (Repo_Root, Pack_Data, Pack_Checksum, Pack_Checksum_Last);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Store_Pack_Index
                (Repo_Root,
                 Pack_Checksum,
                 Built_Index (Built_Index'First .. Built_Index_Last));
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.List_Packed_Object_IDs
                (Repo_Root,
                 Pack_Checksum,
                 Listed_Packed_Index,
                 Listed_Packed_Index_Last,
                 Listed_Packed_Object_IDs,
                 Listed_Packed_Object_Count);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.List_Pack_Index_Checksums
                (Repo_Root,
                 Pack_Index_List,
                 Pack_Index_List_Last,
                 Pack_Index_List_Count);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Stored_Object_Exists
                (Repo_Root,
                 Stored_Hex,
                 Exists_Pack_Checksums,
                 Exists_Pack_Checksums_Last,
                 Exists_Pack_Checksum,
                 Exists_Pack_Checksum_Last,
                 Exists_Pack_Index,
                 Stored_Object_Found);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.List_Stored_Object_IDs
                (Repo_Root,
                 Stored_Object_Pack_Checksums,
                 Stored_Object_Pack_Checksums_Last,
                 Stored_Object_Index,
                 Stored_Object_Index_Last,
                 Stored_Object_IDs,
                 Stored_Object_Count);
            Touch (Status_Value);
	            Status_Value :=
	              SSH_Lib.Git.Read_Packed_Object
	                (Repo_Root,
	                 Pack_Checksum,
	                 Stored_Hex,
                 Pack_Data,
                 Built_Index,
                 Read_Kind,
	                 Packed_Read_Data,
	                 Packed_Read_Last);
	            Touch (Status_Value);
	            Status_Value :=
	              SSH_Lib.Git.Read_Packed_Object_Validated
	                (Repo_Root,
	                 Pack_Checksum,
	                 Stored_Hex,
	                 Pack_Data,
	                 Built_Index,
	                 Read_Kind,
	                 Packed_Read_Data,
	                 Packed_Read_Last);
	            Touch (Status_Value);
	            Status_Value :=
	              SSH_Lib.Git.Read_Packed_Object_Resolved
	                (Repo_Root,
	                 Pack_Checksum,
	                 Stored_Hex,
	                 Pack_Data,
	                 Built_Index,
	                 Pack_Delta_Workspace,
	                 Pack_Index_Scratch,
	                 Pkt_Buffer,
	                 Read_Kind,
	                 Packed_Read_Data,
	                 Packed_Read_Last);
	            Touch (Status_Value);
	            Status_Value :=
	              SSH_Lib.Git.Read_Packed_Object_Resolved_Validated
	                (Repo_Root,
	                 Pack_Checksum,
	                 Stored_Hex,
	                 Pack_Data,
	                 Built_Index,
	                 Pack_Delta_Workspace,
	                 Pack_Index_Scratch,
	                 Pkt_Buffer,
	                 Read_Kind,
	                 Packed_Read_Data,
	                 Packed_Read_Last);
	            Touch (Status_Value);
	            Status_Value :=
	              SSH_Lib.Git.Read_Stored_Object
	                (Repo_Root,
	                 Stored_Hex,
	                 Pack_Checksum,
                 Pack_Data,
                 Built_Index,
                 Read_Kind,
	                 Packed_Read_Data,
	                 Packed_Read_Last);
	            Touch (Status_Value);
	            Status_Value :=
	              SSH_Lib.Git.Read_Stored_Object_Resolved
	                (Repo_Root,
	                 Stored_Hex,
	                 Pack_Checksum,
	                 Pack_Data,
	                 Built_Index,
	                 Pack_Delta_Workspace,
	                 Pack_Index_Scratch,
	                 Pkt_Buffer,
	                 Read_Kind,
	                 Packed_Read_Data,
	                 Packed_Read_Last);
	            Touch (Status_Value);
	            Status_Value :=
	              SSH_Lib.Git.Read_Stored_Object_Resolved_Validated
	                (Repo_Root,
	                 Stored_Hex,
	                 Pack_Checksum,
	                 Pack_Data,
	                 Built_Index,
	                 Pack_Delta_Workspace,
	                 Pack_Index_Scratch,
	                 Pkt_Buffer,
	                 Read_Kind,
	                 Packed_Read_Data,
	                 Packed_Read_Last);
	            Touch (Status_Value);
	            Status_Value :=
	              SSH_Lib.Git.Read_Stored_Object_Validated
	                (Repo_Root,
	                 Stored_Hex,
	                 Pack_Checksum,
	                 Pack_Data,
	                 Built_Index,
	                 Read_Kind,
	                 Packed_Read_Data,
	                 Packed_Read_Last);
	            Touch (Status_Value);
	            Status_Value :=
	              SSH_Lib.Git.Read_Any_Stored_Object
	                (Repo_Root,
	                 Stored_Hex,
	                 Pack_Index_List,
                 Pack_Data,
                 Built_Index,
                 Found_Pack_Checksum,
                 Found_Pack_Checksum_Last,
                 Read_Kind,
	                 Packed_Read_Data,
	                 Packed_Read_Last);
	            Touch (Status_Value);
	            Status_Value :=
	              SSH_Lib.Git.Read_Any_Stored_Object_Resolved
	                (Repo_Root,
	                 Stored_Hex,
	                 Pack_Index_List,
	                 Pack_Data,
	                 Built_Index,
	                 Pack_Delta_Workspace,
	                 Pack_Index_Scratch,
	                 Pkt_Buffer,
	                 Found_Pack_Checksum,
	                 Found_Pack_Checksum_Last,
	                 Read_Kind,
	                 Packed_Read_Data,
	                 Packed_Read_Last);
	            Touch (Status_Value);
	            Status_Value :=
	              SSH_Lib.Git.Read_Any_Stored_Object_Resolved_Validated
	                (Repo_Root,
	                 Stored_Hex,
	                 Pack_Index_List,
	                 Pack_Data,
	                 Built_Index,
	                 Pack_Delta_Workspace,
	                 Pack_Index_Scratch,
	                 Pkt_Buffer,
	                 Found_Pack_Checksum,
	                 Found_Pack_Checksum_Last,
	                 Read_Kind,
	                 Packed_Read_Data,
	                 Packed_Read_Last);
	            Touch (Status_Value);
	            Status_Value :=
	              SSH_Lib.Git.Read_Any_Stored_Object_Validated
	                (Repo_Root,
	                 Stored_Hex,
	                 Pack_Index_List,
	                 Pack_Data,
	                 Built_Index,
	                 Found_Pack_Checksum,
	                 Found_Pack_Checksum_Last,
	                 Read_Kind,
	                 Packed_Read_Data,
	                 Packed_Read_Last);
	            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Write_Direct_Ref
                (Repo_Root, "refs/heads/main", Stored_Hex);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Append_Reflog_Entry
                (Repo_Root,
                 "refs/heads/main",
                 Stored_Hex,
                 Stored_Hex,
                 "Tester <tester@example.invalid> 0 +0000",
                 "api stability");
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Read_Reflog_Last_Entry
                (Repo_Root,
                 "refs/heads/main",
                 Reflog_Line,
                 Reflog_Last);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Write_Branch
                (Repo_Root, "feature/api", Stored_Hex);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Read_Branch
                (Repo_Root, "feature/api", Read_Hex, Read_Hex_Last);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Resolve_Branch
                (Repo_Root, "feature/api", Read_Hex, Read_Hex_Last);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Branch_Exists
                (Repo_Root,
                 "feature/api",
                 Read_Hex,
                 Read_Hex_Last,
                 Ref_Found);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Delete_Branch (Repo_Root, "feature/api");
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Write_Remote_Tracking_Branch
                (Repo_Root, "origin/main", Stored_Hex);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Read_Remote_Tracking_Branch
                (Repo_Root, "origin/main", Read_Hex, Read_Hex_Last);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Resolve_Remote_Tracking_Branch
                (Repo_Root, "origin/main", Read_Hex, Read_Hex_Last);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Remote_Tracking_Branch_Exists
                (Repo_Root, "origin/main", Read_Hex, Read_Hex_Last, Ref_Found);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Delete_Remote_Tracking_Branch
                (Repo_Root, "origin/main");
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Read_Direct_Ref
                (Repo_Root, "refs/heads/main", Read_Hex, Read_Hex_Last);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Write_Direct_Ref
                (Repo_Root, "refs/heads/delete-me", Stored_Hex);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Delete_Direct_Ref
                (Repo_Root, "refs/heads/delete-me");
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Read_Symbolic_Ref
                (Repo_Root, "HEAD", Symbolic_Target, Symbolic_Target_Last);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Write_Symbolic_Ref
                (Repo_Root,
                 "refs/remotes/origin/HEAD",
                 "refs/remotes/origin/main");
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Read_Symbolic_Ref
                (Repo_Root,
                 "refs/remotes/origin/HEAD",
                 Symbolic_Target,
                 Symbolic_Target_Last);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Delete_Symbolic_Ref
                (Repo_Root,
                 "refs/remotes/origin/HEAD",
                 Symbolic_Target,
                 Symbolic_Target_Last);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Write_Packed_Ref
                (Repo_Root, "refs/tags/v1", Stored_Hex);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Write_Tag_Ref
                (Repo_Root, "lightweight/v1", Stored_Hex);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Read_Tag_Ref
                (Repo_Root, "lightweight/v1", Read_Hex, Read_Hex_Last);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Resolve_Tag_Ref
                (Repo_Root, "lightweight/v1", Read_Hex, Read_Hex_Last);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Tag_Ref_Exists
                (Repo_Root,
                 "lightweight/v1",
                 Read_Hex,
                 Read_Hex_Last,
                 Ref_Found);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Delete_Tag_Ref (Repo_Root, "lightweight/v1");
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Read_Packed_Ref
                (Repo_Root, "refs/tags/v1", Read_Hex, Read_Hex_Last);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Write_Packed_Ref
                (Repo_Root, "refs/tags/delete-me", Stored_Hex);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Delete_Packed_Ref
                (Repo_Root, "refs/tags/delete-me");
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.List_Refs
                (Repo_Root,
                 Listed_Ref_Names,
                 Listed_Ref_Name_Lasts,
                 Listed_Ref_IDs,
                 Listed_Ref_Count);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.List_Branches
                (Repo_Root,
                 Listed_Ref_Names,
                 Listed_Ref_Name_Lasts,
                 Listed_Ref_IDs,
                 Listed_Ref_Count);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.List_Tag_Refs
                (Repo_Root,
                 Listed_Ref_Names,
                 Listed_Ref_Name_Lasts,
                 Listed_Ref_IDs,
                 Listed_Ref_Count);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.List_Remote_Tracking_Branches
                (Repo_Root,
                 Listed_Ref_Names,
                 Listed_Ref_Name_Lasts,
                 Listed_Ref_IDs,
                 Listed_Ref_Count);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Resolve_Ref
                (Repo_Root, "HEAD", Read_Hex, Read_Hex_Last);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Resolve_HEAD
                (Repo_Root, Read_Hex, Read_Hex_Last);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Read_HEAD_Target
                (Repo_Root,
                 Symbolic_Target,
                 Symbolic_Target_Last,
                 Head_Attached);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Read_Current_Branch
                (Repo_Root,
                 Symbolic_Target,
                 Symbolic_Target_Last,
                 Ref_Found);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Detach_HEAD (Repo_Root, Stored_Hex);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Read_HEAD_Target
                (Repo_Root,
                 Symbolic_Target,
                 Symbolic_Target_Last,
                 Head_Attached);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Read_Current_Branch
                (Repo_Root,
                 Symbolic_Target,
                 Symbolic_Target_Last,
                 Ref_Found);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Attach_HEAD (Repo_Root, "refs/heads/main");
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Attach_HEAD_To_Branch (Repo_Root, "main");
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Create_Branch_From_HEAD
                (Repo_Root, "from-head");
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Create_Tag_Ref_From_HEAD
                (Repo_Root, "head-tag");
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Create_Remote_Tracking_Branch_From_HEAD
                (Repo_Root, "origin/from-head");
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Read_HEAD_Target
                (Repo_Root,
                 Symbolic_Target,
                 Symbolic_Target_Last,
                 Head_Attached);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Read_Current_Branch
                (Repo_Root,
                 Symbolic_Target,
                 Symbolic_Target_Last,
                 Ref_Found);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Resolve_Ref
                (Repo_Root, "refs/tags/v1", Read_Hex, Read_Hex_Last);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Ref_Exists
                (Repo_Root,
                 "refs/tags/v1",
                 Read_Hex,
                 Read_Hex_Last,
                 Ref_Found);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Write_Direct_Ref_Atomic
                (Repo_Root, "refs/heads/atomic", Stored_Hex);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Compare_And_Swap_Direct_Ref
                (Repo_Root,
                 "refs/heads/atomic",
                 Stored_Hex,
                 Stored_Hex);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Write_Direct_Ref_Atomic
                (Repo_Root, "refs/heads/delete-atomic", Stored_Hex);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Compare_And_Delete_Direct_Ref
                (Repo_Root,
                 "refs/heads/delete-atomic",
                 Stored_Hex);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Write_Direct_Ref_Atomic
                (Repo_Root, "refs/heads/delete-atomic", Stored_Hex);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Delete_Direct_Ref_Atomic
                (Repo_Root, "refs/heads/delete-atomic");
            Touch (Status_Value);
            if Stored_Last /= Stored_Hex'Last
              or else Read_Hex_Last /= Read_Hex'Last
              or else Symbolic_Target_Last < Symbolic_Target'First
              or else Pack_Checksum_Last /= Pack_Checksum'Last
              or else Read_Kind /= SSH_Lib.Git.Pack_Blob
              or else Read_Last < Read_Data'First + 1
              or else Read_Hex /= Stored_Hex
            then
               raise Program_Error;
            end if;
            if Ada.Directories.Exists (Repo_Root) then
               Ada.Directories.Delete_Tree (Repo_Root);
            end if;
         end;

         declare
            Fetch_Request : constant Ada.Streams.Stream_Element_Array :=
              SSH_Lib.Protocol.Buffers.To_Array
                (SSH_Lib.Git.Encode_Upload_Pack_Fetch_Request
                   (Wants        => [1 => Object_ID_Text],
                    Haves        => [1 .. 0 => Object_ID_Text],
                    Shallows     => [1 .. 0 => Object_ID_Text],
                    Capabilities => Caps,
                    Depth        => 0,
                    Filter_Spec  => [1 .. 0 => 0],
                    Include_Done => True));
            Update_Line : constant Ada.Streams.Stream_Element_Array :=
              SSH_Lib.Protocol.Buffers.To_Array
                (SSH_Lib.Git.Encode_Receive_Pack_Update_Line
                   (Old_ID_Hex   => Object_ID_Text,
                    New_ID_Hex   => Object_ID_Text,
                    Ref_Name     =>
                      [Character'Pos ('r'), Character'Pos ('e'),
                       Character'Pos ('f'), Character'Pos ('s'),
                       Character'Pos ('/'), Character'Pos ('h'),
                       Character'Pos ('e'), Character'Pos ('a'),
                       Character'Pos ('d'), Character'Pos ('s'),
                       Character'Pos ('/'), Character'Pos ('m'),
                       Character'Pos ('a'), Character'Pos ('i'),
                       Character'Pos ('n')],
                    Capabilities => Caps));
            V2_Request : constant Ada.Streams.Stream_Element_Array :=
              SSH_Lib.Protocol.Buffers.To_Array
                (SSH_Lib.Git.Encode_Protocol_V2_Command_Request
                   (Command_Name =>
                      [Character'Pos ('l'), Character'Pos ('s'),
                       Character'Pos ('-'), Character'Pos ('r'),
                       Character'Pos ('e'), Character'Pos ('f'),
                       Character'Pos ('s')],
                    Capabilities =>
                      [Character'Pos ('a'), Character'Pos ('g'),
                       Character'Pos ('e'), Character'Pos ('n'),
                       Character'Pos ('t'), Character'Pos ('='),
                       Character'Pos ('s'), Character'Pos ('s'),
                       Character'Pos ('h'), Character'Pos ('l'),
                       Character'Pos ('i'), Character'Pos ('b'),
                       Character'Pos (Character'Val (10))],
                    Arguments =>
                      [Character'Pos ('s'), Character'Pos ('y'),
                       Character'Pos ('m'), Character'Pos ('r'),
                       Character'Pos ('e'), Character'Pos ('f'),
                       Character'Pos ('s')]));
         begin
            Status_Value :=
              SSH_Lib.Git.Validate_Upload_Pack_Negotiation_Request
                (Fetch_Request, Negotiation_Summary);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Validate_Receive_Pack_Request
                (Update_Line
                 & SSH_Lib.Protocol.Buffers.To_Array
                     (SSH_Lib.Git.Encode_Pkt_Flush),
                 Receive_Summary);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Validate_Protocol_V2_Command_Request
                (V2_Request, Protocol_V2_Summary);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Validate_Upload_Pack_Response
                ([Character'Pos ('0'), Character'Pos ('0'),
                  Character'Pos ('0'), Character'Pos ('8'),
                  Character'Pos ('N'), Character'Pos ('A'),
                  Character'Pos ('K'), Character'Pos (Character'Val (10))],
                 Upload_Response_Summary);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Validate_Receive_Pack_Report
                (SSH_Lib.Protocol.Buffers.To_Array
                   (SSH_Lib.Git.Encode_Pkt_Line
                      ([Character'Pos ('u'), Character'Pos ('n'),
                        Character'Pos ('p'), Character'Pos ('a'),
                        Character'Pos ('c'), Character'Pos ('k'),
                        Character'Pos (' '), Character'Pos ('o'),
                        Character'Pos ('k'),
                        Character'Pos (Character'Val (10))])),
                 Receive_Report_Summary);
            Touch (Status_Value);
            SSH_Lib.Git.Reset_Fetch_Workflow (Fetch_Workflow);
            Status_Value :=
              SSH_Lib.Git.Fetch_Build_Request
                (Fetch_Workflow,
                 Wants        => [1 => Object_ID_Text],
                 Haves        => [1 .. 0 => Object_ID_Text],
                 Shallows     => [1 .. 0 => Object_ID_Text],
                 Capabilities => Caps,
                 Depth        => 0,
                 Filter_Spec  => [1 .. 0 => 0],
                 Include_Done => True,
                 Request      => Git_Request_Buffer);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Fetch_Accept_Response
                (Fetch_Workflow,
                 [Character'Pos ('0'), Character'Pos ('0'),
                  Character'Pos ('0'), Character'Pos ('8'),
                  Character'Pos ('N'), Character'Pos ('A'),
                  Character'Pos ('K'), Character'Pos (Character'Val (10))]);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Decide_Fetch_Policy
                (Fetch_Workflow, 1, 2, 0, Fetch_Decision);
            Touch (Status_Value);
            if Fetch_Decision = SSH_Lib.Git.Fetch_Policy_Retry then
               raise Program_Error;
            end if;
            Status_Value := SSH_Lib.Git.Fetch_Finish (Fetch_Workflow);
            Touch (Status_Value);
            if Fetch_Workflow.State /= SSH_Lib.Git.Fetch_Finished then
               raise Program_Error;
            end if;

            SSH_Lib.Git.Reset_Push_Workflow (Push_Workflow);
            Status_Value :=
              SSH_Lib.Git.Push_Build_Request
                (Push_Workflow,
                 Updates   => Update_Line,
                 Pack_Data => [1 .. 0 => 0],
                 Request   => Git_Request_Buffer);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Decide_Push_Policy
                (Push_Workflow, 1, 2, Push_Decision);
            Touch (Status_Value);
            if Push_Decision = SSH_Lib.Git.Push_Policy_Retry then
               raise Program_Error;
            end if;
            Status_Value :=
              SSH_Lib.Git.Push_Accept_Report
                (Push_Workflow,
                 SSH_Lib.Protocol.Buffers.To_Array
                   (SSH_Lib.Git.Encode_Pkt_Line
                      ([Character'Pos ('u'), Character'Pos ('n'),
                        Character'Pos ('p'), Character'Pos ('a'),
                        Character'Pos ('c'), Character'Pos ('k'),
                        Character'Pos (' '), Character'Pos ('o'),
                        Character'Pos ('k'),
                        Character'Pos (Character'Val (10))])));
            Touch (Status_Value);
            Status_Value := SSH_Lib.Git.Push_Finish (Push_Workflow);
            Touch (Status_Value);
            if Push_Workflow.State /= SSH_Lib.Git.Push_Finished then
               raise Program_Error;
            end if;

            Status_Value :=
              SSH_Lib.Git.Validate_Protocol_V2_Capability_Advertisement
                (SSH_Lib.Protocol.Buffers.To_Array
                   (SSH_Lib.Git.Encode_Pkt_Line
                      ([Character'Pos ('l'), Character'Pos ('s'),
                        Character'Pos ('-'), Character'Pos ('r'),
                        Character'Pos ('e'), Character'Pos ('f'),
                        Character'Pos ('s'),
                        Character'Pos (Character'Val (10))]))
                 & SSH_Lib.Protocol.Buffers.To_Array
                     (SSH_Lib.Git.Encode_Pkt_Flush),
                 Protocol_V2_Capability_Summary);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Validate_Protocol_V2_Response
                (SSH_Lib.Protocol.Buffers.To_Array
                   (SSH_Lib.Git.Encode_Pkt_Line
                      ([Character'Pos ('o'), Character'Pos ('k'),
                        Character'Pos (Character'Val (10))]))
                 & SSH_Lib.Protocol.Buffers.To_Array
                     (SSH_Lib.Git.Encode_Pkt_Delimiter)
                 & SSH_Lib.Protocol.Buffers.To_Array
                    (SSH_Lib.Git.Encode_Pkt_Line
                       ([Character'Pos ('d'), Character'Pos ('o'),
                         Character'Pos ('n'), Character'Pos ('e'),
                         Character'Pos (Character'Val (10))]))
                 & SSH_Lib.Protocol.Buffers.To_Array
                    (SSH_Lib.Git.Encode_Pkt_Line
                       ([Character'Pos ('E'), Character'Pos ('R'),
                         Character'Pos ('R'), Character'Pos (' '),
                         Character'Pos ('x'),
                         Character'Pos (Character'Val (10))]))
                 & SSH_Lib.Protocol.Buffers.To_Array
                     (SSH_Lib.Git.Encode_Pkt_Response_End),
                 Protocol_V2_Response_Summary);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Parse_Ref_Advertisement_Packet
                (SSH_Lib.Protocol.Buffers.To_Array
                   (SSH_Lib.Git.Encode_Pkt_Line
                      ([Character'Pos ('1'), Character'Pos ('1'),
                        Character'Pos ('1'), Character'Pos ('1'),
                        Character'Pos ('1'), Character'Pos ('1'),
                        Character'Pos ('1'), Character'Pos ('1'),
                        Character'Pos ('1'), Character'Pos ('1'),
                        Character'Pos ('1'), Character'Pos ('1'),
                        Character'Pos ('1'), Character'Pos ('1'),
                        Character'Pos ('1'), Character'Pos ('1'),
                        Character'Pos ('1'), Character'Pos ('1'),
                        Character'Pos ('1'), Character'Pos ('1'),
                        Character'Pos ('1'), Character'Pos ('1'),
                        Character'Pos ('1'), Character'Pos ('1'),
                        Character'Pos ('1'), Character'Pos ('1'),
                        Character'Pos ('1'), Character'Pos ('1'),
                        Character'Pos ('1'), Character'Pos ('1'),
                        Character'Pos ('1'), Character'Pos ('1'),
                        Character'Pos ('1'), Character'Pos ('1'),
                        Character'Pos ('1'), Character'Pos ('1'),
                        Character'Pos ('1'), Character'Pos ('1'),
                        Character'Pos ('1'), Character'Pos ('1'),
                        Character'Pos (' '), Character'Pos ('H'),
                        Character'Pos ('E'), Character'Pos ('A'),
                        Character'Pos ('D'),
                        Character'Pos (Character'Val (10))])),
                 Ref_Object_Buffer,
                 Ref_Object_Last,
                 Status_Ref_Buffer,
                 Status_Ref_Last,
                 Capability_Token,
                 Capability_Token_Last,
                 Ref_Has_Caps,
                 Ref_Is_Peeled,
                 Ref_Is_Symref);
            Touch (Status_Value);
            Status_Value :=
              SSH_Lib.Git.Validate_Ref_Advertisement_Stream
                (SSH_Lib.Protocol.Buffers.To_Array
                   (SSH_Lib.Git.Encode_Pkt_Line
                      ([Character'Pos ('1'), Character'Pos ('1'),
                        Character'Pos ('1'), Character'Pos ('1'),
                        Character'Pos ('1'), Character'Pos ('1'),
                        Character'Pos ('1'), Character'Pos ('1'),
                        Character'Pos ('1'), Character'Pos ('1'),
                        Character'Pos ('1'), Character'Pos ('1'),
                        Character'Pos ('1'), Character'Pos ('1'),
                        Character'Pos ('1'), Character'Pos ('1'),
                        Character'Pos ('1'), Character'Pos ('1'),
                        Character'Pos ('1'), Character'Pos ('1'),
                        Character'Pos ('1'), Character'Pos ('1'),
                        Character'Pos ('1'), Character'Pos ('1'),
                        Character'Pos ('1'), Character'Pos ('1'),
                        Character'Pos ('1'), Character'Pos ('1'),
                        Character'Pos ('1'), Character'Pos ('1'),
                        Character'Pos ('1'), Character'Pos ('1'),
                        Character'Pos ('1'), Character'Pos ('1'),
                        Character'Pos ('1'), Character'Pos ('1'),
                        Character'Pos ('1'), Character'Pos ('1'),
                        Character'Pos ('1'), Character'Pos ('1'),
                        Character'Pos (' '), Character'Pos ('H'),
                        Character'Pos ('E'), Character'Pos ('A'),
                        Character'Pos ('D'),
                        Character'Pos (Character'Val (10))]))
                 & SSH_Lib.Protocol.Buffers.To_Array
                     (SSH_Lib.Git.Encode_Pkt_Response_End),
                 Ref_Advertisement_Summary);
            Touch (Status_Value);
            if Fetch_Request'Length = 0
              or else Update_Line'Length = 0
              or else V2_Request'Length = 0
              or else Receive_Summary.Update_Count = 0
              or else Protocol_V2_Summary.Command_Count = 0
              or else not Protocol_V2_Summary.Has_Ls_Refs
              or else not Protocol_V2_Summary.Has_Agent
              or else not Protocol_V2_Summary.Has_Symrefs
              or else not Upload_Response_Summary.Has_NAK
              or else not Receive_Report_Summary.Has_Unpack_OK
              or else not Protocol_V2_Capability_Summary.Has_Ls_Refs
              or else not Protocol_V2_Response_Summary.Has_Delimiter
              or else not Protocol_V2_Response_Summary.Has_Error_Line
              or else not Protocol_V2_Response_Summary.Has_Response_End
              or else Ref_Object_Last = Ref_Object_Buffer'First - 1
              or else Ref_Advertisement_Summary.Ref_Count = 0
            then
               raise Program_Error;
            end if;
         end;
      end;
   end;
   if Unsupported_Config and then Length (Transport_Command) = 0 then
      raise Program_Error;
   end if;
   Options.Local_Forwards := To_Unbounded_String ("127.0.0.1:0 target:22");
   Options.Remote_Forwards := To_Unbounded_String ("0.0.0.0:0 target:22");
   Options.Dynamic_Forwards := To_Unbounded_String ("127.0.0.1:0");
   Options.Send_Env := To_Unbounded_String ("LANG LC_*");
   Options.Set_Env := To_Unbounded_String ("TERM=xterm-256color");
   Options.Control_Master := To_Unbounded_String ("auto");
   Options.Control_Path := To_Unbounded_String ("~/.ssh/cm-%r@%h:%p");
   Options.Control_Persist := To_Unbounded_String ("10m");
   Options.Batch_Mode := True;
   Options.Forward_Agent := True;
   Options.Forward_X11 := True;
   Options.Request_TTY := To_Unbounded_String ("force");
   Options.Remote_Command := To_Unbounded_String ("git status --porcelain");
   Options.Server_Alive_Interval := 15;
   Options.Server_Alive_Count_Max := 4;
   Options.TCP_Keep_Alive := False;
   Options.Log_Level := To_Unbounded_String ("VERBOSE");
   Options.Visual_Host_Key := True;
   Options.Update_Host_Keys := To_Unbounded_String ("ask");
   Options.Permit_Local_Command := True;
   Options.Local_Command := To_Unbounded_String ("printf ready");
   Options.Add_Keys_To_Agent := To_Unbounded_String ("confirm");
   Options.Clear_All_Forwardings := True;
   Options.Exit_On_Forward_Failure := True;
   Forward_Text :=
     Options.Local_Forwards
     & Options.Remote_Forwards
     & Options.Dynamic_Forwards
     & Options.Send_Env
     & Options.Set_Env
     & Options.Control_Master
     & Options.Control_Path
     & Options.Control_Persist
     & Options.Request_TTY
     & Options.Remote_Command
     & Options.Log_Level
     & Options.Update_Host_Keys
     & Options.Local_Command
     & Options.Add_Keys_To_Agent;
   if Length (Forward_Text) = 0 then
      raise Program_Error;
   end if;
   if not Options.Batch_Mode
     or else not Options.Forward_Agent
     or else not Options.Forward_X11
     or else Options.Server_Alive_Interval /= 15
     or else Options.Server_Alive_Count_Max /= 4
     or else Options.TCP_Keep_Alive
     or else not Options.Visual_Host_Key
     or else not Options.Permit_Local_Command
     or else not Options.Clear_All_Forwardings
     or else not Options.Exit_On_Forward_Failure
   then
      raise Program_Error;
   end if;
   X11_Cookie_OK :=
     SSH_Lib.Channels.Valid_X11_MIT_Magic_Cookie
       ("0123456789abcdef0123456789ABCDEF")
     and then SSH_Lib.Channels.X11_MIT_Magic_Cookies_Match
       ("0123456789abcdef0123456789abcdef",
        "0123456789ABCDEF0123456789ABCDEF");
   if not X11_Cookie_OK then
      raise Program_Error;
   end if;
   Status_Value := SSH_Lib.Forwarding.Parse_X11_Display
     (":0.0", X11_Target);
   Touch (Status_Value);
   if SSH_Lib.Forwarding.X11_Display_Kind (X11_Target)
        /= SSH_Lib.Forwarding.X11_Unix_Domain
     or else SSH_Lib.Forwarding.X11_Display_Socket_Path (X11_Target) = ""
     or else SSH_Lib.Forwarding.X11_Display_Number (X11_Target) /= 0
   then
      raise Program_Error;
   end if;
   Status_Value := SSH_Lib.Forwarding.Parse_X11_Display
     ("localhost:10.1", X11_Target);
   Touch (Status_Value);
   if SSH_Lib.Forwarding.X11_Display_Kind (X11_Target)
        /= SSH_Lib.Forwarding.X11_TCP
     or else SSH_Lib.Forwarding.X11_Display_Host (X11_Target)
        /= "localhost"
     or else SSH_Lib.Forwarding.X11_Display_Port (X11_Target) /= 6010
     or else SSH_Lib.Forwarding.X11_Display_Screen (X11_Target) /= 1
   then
      raise Program_Error;
   end if;

   Known_Hosts_Path := SSH_Lib.Known_Hosts.Default_File;
   pragma Unreferenced (Known_Hosts_Path);

   --  Keep the full channel/session call shape compiled without making the
   --  API-stability executable depend on network availability or future
   --  completion of the real transport path.
   if Ada.Command_Line.Argument_Count = Natural'Last then
      Status_Value := SSH_Lib.Sessions.Open (Options, Session_Item);
      Touch (Status_Value);
      Status_Value := SSH_Lib.Channels.Open_Exec
        (Session_Item,
         SSH_Lib.Git.Upload_Pack_Command ("repo.git"),
         Channel_Item);
      Touch (Status_Value);
      Status_Value := SSH_Lib.Channels.Open_Exec_With_Environment
        (Session_Item,
         SSH_Lib.Git.Upload_Pack_Command ("repo.git"),
         Environment,
         Channel_Item);
      Touch (Status_Value);
      Status_Value := SSH_Lib.Channels.Set_Environment
        (Session_Item, Channel_Item, "LANG", "C");
      Touch (Status_Value);
      Status_Value := SSH_Lib.Channels.Request_X11_Forwarding
        (Session_Item,
         Channel_Item,
         Single_Connection => True,
         Auth_Protocol     => "MIT-MAGIC-COOKIE-1",
         Auth_Cookie       => "0123456789abcdef",
         Screen_Number     => 0);
      Touch (Status_Value);
      Status_Value := SSH_Lib.Channels.Accept_X11
        (Session_Item, Channel_Item);
      Touch (Status_Value);
      Status_Value := SSH_Lib.Channels.Write (Channel_Item, Request_Bytes);
      Touch (Status_Value);
      Status_Value := SSH_Lib.Channels.Read_Some
        (Channel_Item, Buffer, Last);
      Touch (Status_Value);
      Status_Value := SSH_Lib.Channels.Read_Stderr
        (Channel_Item, Buffer, Last);
      Touch (Status_Value);
      if Last >= Buffer'First and then Buffer (Buffer'First) = 16#FF# then
         raise Program_Error;
      end if;
      Status_Value := SSH_Lib.Channels.Send_EOF (Channel_Item);
      Touch (Status_Value);
      Status_Value := SSH_Lib.Channels.Exit_Status (Channel_Item, Exit_Code);
      Touch (Status_Value);
      Status_Value := SSH_Lib.Channels.Close (Channel_Item);
      Touch (Status_Value);
      Status_Value := SSH_Lib.Channels.Open_Shell
        (Session_Item, Channel_Item);
      Touch (Status_Value);
      Status_Value := SSH_Lib.Channels.Close (Channel_Item);
      Touch (Status_Value);
      Status_Value := SSH_Lib.Channels.Open_PTY_Shell
        (Session_Item,
         Channel_Item,
         "xterm-256color",
         100,
         40,
         Terminal_Modes => Terminal_Modes);
      Touch (Status_Value);
      Status_Value := SSH_Lib.Channels.Resize_PTY
        (Session_Item, Channel_Item, 120, 50, 800, 600);
      Touch (Status_Value);
      Status_Value := SSH_Lib.Channels.Close (Channel_Item);
      Touch (Status_Value);
      Status_Value := SSH_Lib.Channels.Open_Direct_TCPIP
        (Session_Item,
         "target.example",
         443,
         Channel_Item,
         "127.0.0.1",
         55_555);
      Touch (Status_Value);
      Status_Value := SSH_Lib.Channels.Close (Channel_Item);
      Touch (Status_Value);
      Status_Value := SSH_Lib.Sessions.Request_Remote_Forward
        (Session_Item, "0.0.0.0", 0, Bound_Port);
      Touch (Status_Value);
      Status_Value := SSH_Lib.Sessions.Cancel_Remote_Forward
        (Session_Item, "0.0.0.0", Bound_Port);
      Touch (Status_Value);
      Status_Value := SSH_Lib.Channels.Accept_Forwarded_TCPIP
        (Session_Item, Channel_Item);
      Touch (Status_Value);
      Status_Value := SSH_Lib.Channels.Close (Channel_Item);
      Touch (Status_Value);
      Status_Value := SSH_Lib.Forwarding.Open_Local_Forward_Listener
        ("127.0.0.1", 0, "target.example", 443, Listener_Item);
      Touch (Status_Value);
      Status_Value := SSH_Lib.Forwarding.Open_Dynamic_Forward_Listener
        ("127.0.0.1", 0, Listener_Item);
      Touch (Status_Value);
      Status_Value := SSH_Lib.Forwarding.Parse_SOCKS5_CONNECT_Request
        ([16#05#, 16#01#, 16#00#, 16#03#, 16#0E#,
          Character'Pos ('t'), Character'Pos ('a'), Character'Pos ('r'),
          Character'Pos ('g'), Character'Pos ('e'), Character'Pos ('t'),
          Character'Pos ('.'), Character'Pos ('e'), Character'Pos ('x'),
          Character'Pos ('a'), Character'Pos ('m'), Character'Pos ('p'),
          Character'Pos ('l'), Character'Pos ('e'), 16#01#, 16#BB#],
         SOCKS_Target);
      Touch (Status_Value);
      if SSH_Lib.Forwarding.SOCKS5_Host (SOCKS_Target) = ""
        or else SSH_Lib.Forwarding.SOCKS5_Port (SOCKS_Target) = 0
      then
         raise Program_Error;
      end if;
      Bound_Port := SSH_Lib.Forwarding.Bound_Port (Listener_Item);
      Status_Value := SSH_Lib.Forwarding.Accept_Local_Forward
        (Session_Item, Listener_Item, Connection_Item, Channel_Item);
      Touch (Status_Value);
      Status_Value := SSH_Lib.Forwarding.Accept_Dynamic_Forward
        (Session_Item, Listener_Item, Connection_Item, Channel_Item, SOCKS_Target);
      Touch (Status_Value);
      Status_Value := SSH_Lib.Forwarding.Parse_X11_Display_From_Environment
        (X11_Target);
      Touch (Status_Value);
      Status_Value := SSH_Lib.Forwarding.Open_X11_Display
        (X11_Target, Connection_Item);
      Touch (Status_Value);
      Status_Value := SSH_Lib.Forwarding.Open_X11_Display
        (":0", Connection_Item);
      Touch (Status_Value);
      Status_Value := SSH_Lib.Forwarding.Read_SOCKS5_CONNECT_Request
        (Connection_Item, SOCKS_Target);
      Touch (Status_Value);
      Status_Value := SSH_Lib.Forwarding.Send_SOCKS5_Reply
        (Connection_Item, CryptoLib.Errors.Ok);
      Touch (Status_Value);
      Status_Value := SSH_Lib.Forwarding.Pump_Once
        (Connection_Item,
         Channel_Item,
         SSH_Lib.Forwarding.Local_To_Channel,
         Pumped_Bytes);
      Touch (Status_Value);
      Status_Value := SSH_Lib.Forwarding.Pump_Once
        (Connection_Item,
         Channel_Item,
         SSH_Lib.Forwarding.Channel_To_Local,
         Pumped_Bytes);
      Touch (Status_Value);
      Status_Value := SSH_Lib.Forwarding.Pump_Bounded
        (Connection_Item,
         Channel_Item,
         Local_Pumped_Bytes,
         Channel_Pumped_Bytes);
      Touch (Status_Value);
      Status_Value := SSH_Lib.Forwarding.Start_Local_Forward_Service
        (Session_Item,
         "127.0.0.1",
         0,
         "target.example",
         443,
         null,
         Service_Item,
         Max_Accepted => 1);
      Touch (Status_Value);
      Status_Value := SSH_Lib.Forwarding.Start_Dynamic_Forward_Service
        (Session_Item,
         "127.0.0.1",
         0,
         null,
         Service_Item,
         Max_Accepted => 1);
      Touch (Status_Value);
      if SSH_Lib.Forwarding.Forward_Service_Running (Service_Item) then
         raise Program_Error;
      end if;
      Status_Value := SSH_Lib.Forwarding.Forward_Service_Status (Service_Item);
      Touch (Status_Value);
      Accepted_Count :=
        SSH_Lib.Forwarding.Forward_Service_Accepted_Count (Service_Item);
      Max_Accepted :=
        SSH_Lib.Forwarding.Forward_Service_Max_Accepted (Service_Item);
      Bound_Port := SSH_Lib.Forwarding.Forward_Service_Bound_Port (Service_Item);
      Service_Kind := SSH_Lib.Forwarding.Forward_Service_Kind (Service_Item);
      case Service_Kind is
         when SSH_Lib.Forwarding.Local_Forward_Service
            | SSH_Lib.Forwarding.Dynamic_Forward_Service
            | SSH_Lib.Forwarding.Remote_Forward_Service =>
            null;
      end case;
      if Accepted_Count /= 0
        or else Max_Accepted /= 0
        or else Bound_Port /= 0
      then
         raise Program_Error;
      end if;

      Status_Value := SSH_Lib.Forwarding.Start_Managed_Local_Forward_Service
        (Session_Item,
         "127.0.0.1",
         0,
         "target.example",
         443,
         Managed_Service_Item,
         Max_Concurrent => 0);
      Touch (Status_Value);
      Status_Value := SSH_Lib.Forwarding.Start_Managed_Dynamic_Forward_Service
        (Session_Item,
         "127.0.0.1",
         0,
         Managed_Service_Item,
         Max_Concurrent => 0);
      Touch (Status_Value);
      Status_Value := SSH_Lib.Forwarding.Start_Managed_Remote_Forward_Service
        (Session_Item,
         "0.0.0.0",
         0,
         "target.example",
         22,
         Managed_Service_Item,
         Max_Accepted => 1);
      Touch (Status_Value);
      if SSH_Lib.Forwarding.Managed_Forward_Service_Running
        (Managed_Service_Item)
      then
         raise Program_Error;
      end if;
      Status_Value :=
        SSH_Lib.Forwarding.Managed_Forward_Service_Status
          (Managed_Service_Item);
      Touch (Status_Value);
      Accepted_Count :=
        SSH_Lib.Forwarding.Managed_Forward_Service_Accepted_Count
          (Managed_Service_Item);
      Max_Accepted :=
        SSH_Lib.Forwarding.Managed_Forward_Service_Max_Accepted
          (Managed_Service_Item);
      Bound_Port :=
        SSH_Lib.Forwarding.Managed_Forward_Service_Bound_Port
          (Managed_Service_Item);
      Service_Kind :=
        SSH_Lib.Forwarding.Managed_Forward_Service_Kind
          (Managed_Service_Item);
      Completed_Count :=
        SSH_Lib.Forwarding.Managed_Forward_Service_Completed_Count
          (Managed_Service_Item);
      Active_Count :=
        SSH_Lib.Forwarding.Managed_Forward_Service_Active_Count
          (Managed_Service_Item);
      Failed_Count :=
        SSH_Lib.Forwarding.Managed_Forward_Service_Failed_Count
          (Managed_Service_Item);
      Max_Concurrent :=
        SSH_Lib.Forwarding.Managed_Forward_Service_Max_Concurrent
          (Managed_Service_Item);
      case Service_Kind is
         when SSH_Lib.Forwarding.Local_Forward_Service
            | SSH_Lib.Forwarding.Dynamic_Forward_Service
            | SSH_Lib.Forwarding.Remote_Forward_Service =>
            null;
      end case;
      if Accepted_Count /= 0
        or else Completed_Count /= 0
        or else Active_Count /= 0
        or else Failed_Count /= 0
        or else Max_Concurrent /= 0
        or else Max_Accepted /= 0
        or else Bound_Port /= 0
      then
         raise Program_Error;
      end if;
      Status_Value := SSH_Lib.Config_Apply.Start_Configured_Local_Forwards
        (Session_Item,
         Options,
         Config_Local_Services,
         Config_Started);
      Touch (Status_Value);
      Status_Value := SSH_Lib.Config_Apply.Start_Configured_Dynamic_Forwards
        (Session_Item,
         Options,
         Config_Dynamic_Services,
         Config_Started);
      Touch (Status_Value);
      Status_Value := SSH_Lib.Config_Apply.Request_Configured_Remote_Forwards
        (Session_Item,
         Options,
         Config_Bound_Ports,
         Config_Requested);
      Touch (Status_Value);
      Status_Value := SSH_Lib.Config_Apply.Start_Configured_Remote_Forwards
        (Session_Item,
         Options,
         Config_Remote_Services,
         Config_Bound_Ports,
         Config_Started);
      Touch (Status_Value);
      Status_Value := SSH_Lib.Config_Apply.Apply_Configured_Environment
        (Session_Item,
         Channel_Item,
         Options);
      Touch (Status_Value);
      if SSH_Lib.Config_Apply.Control_Master_Mode_Of (Options)
        = SSH_Lib.Config_Apply.Control_Master_Invalid
      then
         raise Program_Error;
      end if;
      if SSH_Lib.Config_Apply.Request_TTY_Mode_Of (Options)
        = SSH_Lib.Config_Apply.Request_TTY_Invalid
      then
         raise Program_Error;
      end if;
      if SSH_Lib.Config_Apply.Session_Type_Mode_Of (Options)
        = SSH_Lib.Config_Apply.Session_Type_Invalid
      then
         raise Program_Error;
      end if;
      declare
         Expanded_Control_Path : Unbounded_String;
         Persist_Seconds : Natural := 0;
      begin
         Status_Value := SSH_Lib.Config_Apply.Expand_Control_Path
           (Options,
            Original_Host   => "alias",
            Local_Host_Name => "localhost",
            Result          => Expanded_Control_Path);
         Touch (Status_Value);
         if Length (Expanded_Control_Path) > 4096 then
            raise Program_Error;
         end if;
         Status_Value := SSH_Lib.Config_Apply.Control_Persist_Seconds
           (Options, Persist_Seconds);
         Touch (Status_Value);
         Pumped_Bytes := Pumped_Bytes + Persist_Seconds mod 1;
         Status_Value := SSH_Lib.Config_Apply.Expand_Local_Command
           (Options,
            Original_Host   => "alias",
            Local_Host_Name => "localhost",
            Result          => Expanded_Control_Path);
         Touch (Status_Value);
         if Length (Expanded_Control_Path) > 4096 then
            raise Program_Error;
         end if;
      end;
      Status_Value := SSH_Lib.Config_Apply.Open_Configured_Exec
        (Session_Item,
         Options,
         "true",
         Channel_Item);
      Touch (Status_Value);
      Status_Value := SSH_Lib.Security_Keys.Build_Signed_Request
        (null,
         "ssh:",
         Request_Bytes,
         "git",
         "sk-ssh-ed25519@openssh.com",
         Request_Bytes,
         Security_Key_Request);
      Touch (Status_Value);
      Status_Value := SSH_Lib.Forwarding.Stop (Service_Item);
      Touch (Status_Value);
      Status_Value := SSH_Lib.Forwarding.Close (Connection_Item);
      Touch (Status_Value);
      Status_Value := SSH_Lib.Forwarding.Close (Listener_Item);
      Touch (Status_Value);
      Status_Value := SSH_Lib.Sessions.Close (Session_Item);
      Touch (Status_Value);
   end if;

   if Exit_Code = Integer'First then
      raise Program_Error;
   end if;
   if Bound_Port = Natural'Last then
      raise Program_Error;
   end if;
   if Pumped_Bytes = Natural'Last
     or else Local_Pumped_Bytes = Natural'Last
     or else Channel_Pumped_Bytes = Natural'Last
   then
      raise Program_Error;
   end if;

   Ada.Text_IO.Put_Line ("SSH_Lib public API stability compile check");
end API_Stability_Main;
