with Ada.Streams;
with Ada.Text_IO;
with SSH_Lib.Agent;
with SSH_Lib.Agent.Protocol;
with SSH_Lib.Channels;
with SSH_Lib.Channels.Test_Support;
with SSH_Lib.Public_Key_Blobs;
with CryptoLib.Errors;
with SSH_Lib.Identity_Files;
with SSH_Lib.Keys;
with SSH_Lib.Keys.Internal;
with SSH_Lib.Known_Hosts;
with SSH_Lib.Protocol.Buffers;
with SSH_Lib.Protocol.Channels;
with SSH_Lib.Protocol.Host_Keys;
with SSH_Lib.Protocol.Numbers;
with SSH_Lib.Protocol.Packets;
with SSH_Lib.Protocol.Protected_Packets;
with Ada.Strings.Unbounded;
with SSH_Lib.Tests.Fixtures.Binary_Data;

package body SSH_Lib.Tests.Fixtures.Binary_Matrix is

   use type Ada.Streams.Stream_Element;
   use type Ada.Streams.Stream_Element_Offset;
   use type CryptoLib.Errors.Status;

   Byte_Set : constant Ada.Streams.Stream_Element_Array
     (Ada.Streams.Stream_Element_Offset'(1) ..
      Ada.Streams.Stream_Element_Offset'(6)) :=
     [Ada.Streams.Stream_Element_Offset'(1) => Ada.Streams.Stream_Element'(16#00#),
      Ada.Streams.Stream_Element_Offset'(2) => Ada.Streams.Stream_Element'(16#0A#),
      Ada.Streams.Stream_Element_Offset'(3) => Ada.Streams.Stream_Element'(16#0D#),
      Ada.Streams.Stream_Element_Offset'(4) => Ada.Streams.Stream_Element'(16#7F#),
      Ada.Streams.Stream_Element_Offset'(5) => Ada.Streams.Stream_Element'(16#80#),
      Ada.Streams.Stream_Element_Offset'(6) => Ada.Streams.Stream_Element'(16#FF#)];

   Key_Data : constant Ada.Streams.Stream_Element_Array
     (Ada.Streams.Stream_Element_Offset'(1) ..
      Ada.Streams.Stream_Element_Offset'(32)) :=
     [Ada.Streams.Stream_Element_Offset'(1) => 16#00#,
      Ada.Streams.Stream_Element_Offset'(2) => 16#0A#,
      Ada.Streams.Stream_Element_Offset'(3) => 16#0D#,
      Ada.Streams.Stream_Element_Offset'(4) => 16#7F#,
      Ada.Streams.Stream_Element_Offset'(5) => 16#80#,
      Ada.Streams.Stream_Element_Offset'(6) => 16#FF#,
      Ada.Streams.Stream_Element_Offset'(7) => 16#06#,
      Ada.Streams.Stream_Element_Offset'(8) => 16#07#,
      Ada.Streams.Stream_Element_Offset'(9) => 16#08#,
      Ada.Streams.Stream_Element_Offset'(10) => 16#09#,
      Ada.Streams.Stream_Element_Offset'(11) => 16#0A#,
      Ada.Streams.Stream_Element_Offset'(12) => 16#0B#,
      Ada.Streams.Stream_Element_Offset'(13) => 16#0C#,
      Ada.Streams.Stream_Element_Offset'(14) => 16#0D#,
      Ada.Streams.Stream_Element_Offset'(15) => 16#0E#,
      Ada.Streams.Stream_Element_Offset'(16) => 16#0F#,
      Ada.Streams.Stream_Element_Offset'(17) => 16#10#,
      Ada.Streams.Stream_Element_Offset'(18) => 16#11#,
      Ada.Streams.Stream_Element_Offset'(19) => 16#12#,
      Ada.Streams.Stream_Element_Offset'(20) => 16#13#,
      Ada.Streams.Stream_Element_Offset'(21) => 16#14#,
      Ada.Streams.Stream_Element_Offset'(22) => 16#15#,
      Ada.Streams.Stream_Element_Offset'(23) => 16#16#,
      Ada.Streams.Stream_Element_Offset'(24) => 16#17#,
      Ada.Streams.Stream_Element_Offset'(25) => 16#18#,
      Ada.Streams.Stream_Element_Offset'(26) => 16#19#,
      Ada.Streams.Stream_Element_Offset'(27) => 16#1A#,
      Ada.Streams.Stream_Element_Offset'(28) => 16#1B#,
      Ada.Streams.Stream_Element_Offset'(29) => 16#1C#,
      Ada.Streams.Stream_Element_Offset'(30) => 16#1D#,
      Ada.Streams.Stream_Element_Offset'(31) => 16#1E#,
      Ada.Streams.Stream_Element_Offset'(32) => 16#1F#];

   Valid_OpenSSH_Ed25519 : constant String :=
     "-----BEGIN OPENSSH PRIVATE KEY-----" & Character'Val (10) &
     "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW" & Character'Val (10) &
     "QyNTUxOQAAACABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fIAAAAJYRIjNEESIz" & Character'Val (10) &
     "RAAAAAtzc2gtZWQyNTUxOQAAACABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fIA" & Character'Val (10) &
     "AAAEBlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn+AgYKDhAECAwQFBgcICQoLDA0ODxAR" & Character'Val (10) &
     "EhMUFRYXGBkaGxwdHh8gAAAAD2lnbm9yZWQgY29tbWVudAECAwQ=" & Character'Val (10) &
     "-----END OPENSSH PRIVATE KEY-----" & Character'Val (10);

   procedure Assert (Condition : Boolean; Label_Text : String) is
   begin
      if not Condition then
         Ada.Text_IO.Put_Line ("FAILED binary matrix: " & Label_Text);
         raise Program_Error;
      end if;
   end Assert;

   procedure Assert_Status
     (Actual_Status   : CryptoLib.Errors.Status;
      Expected_Status : CryptoLib.Errors.Status;
      Label_Text      : String)
   is
   begin
      Assert (Actual_Status = Expected_Status, Label_Text);
   end Assert_Status;

   function Bytes_From_String (Text : String) return Ada.Streams.Stream_Element_Array is
      Result : Ada.Streams.Stream_Element_Array
        (Ada.Streams.Stream_Element_Offset'(1) ..
         Ada.Streams.Stream_Element_Offset (Text'Length));
      Cursor : Ada.Streams.Stream_Element_Offset := Result'First;
   begin
      for Character_Value of Text loop
         Result (Cursor) := Ada.Streams.Stream_Element (Character'Pos (Character_Value));
         Cursor := Cursor + 1;
      end loop;
      return Result;
   end Bytes_From_String;

   function SSH_String
     (Payload : Ada.Streams.Stream_Element_Array)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer
   is
   begin
      return SSH_Lib.Protocol.Numbers.Encode_SSH_String (Payload);
   end SSH_String;

   function Host_Key_Blob
     (Algorithm_Name : String;
      Key_Bytes      : Ada.Streams.Stream_Element_Array)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer
   is
      Result       : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Status_Value : CryptoLib.Errors.Status;
   begin
      SSH_Lib.Protocol.Buffers.Clear (Result);
      Status_Value := SSH_Lib.Protocol.Buffers.Append
        (Result,
         SSH_Lib.Protocol.Buffers.To_Array
           (SSH_String (Bytes_From_String (Algorithm_Name))));
      Assert_Status (Status_Value, CryptoLib.Errors.Ok, "host key algorithm append");
      Status_Value := SSH_Lib.Protocol.Buffers.Append
        (Result, SSH_Lib.Protocol.Buffers.To_Array (SSH_String (Key_Bytes)));
      Assert_Status (Status_Value, CryptoLib.Errors.Ok, "host key byte append");
      return Result;
   end Host_Key_Blob;

   function Signature_Blob
     (Algorithm_Name  : String;
      Signature_Bytes : Ada.Streams.Stream_Element_Array)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer
   is
      Result       : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Status_Value : CryptoLib.Errors.Status;
   begin
      SSH_Lib.Protocol.Buffers.Clear (Result);
      Status_Value := SSH_Lib.Protocol.Buffers.Append
        (Result,
         SSH_Lib.Protocol.Buffers.To_Array
           (SSH_String (Bytes_From_String (Algorithm_Name))));
      Assert_Status (Status_Value, CryptoLib.Errors.Ok, "signature algorithm append");
      Status_Value := SSH_Lib.Protocol.Buffers.Append
        (Result, SSH_Lib.Protocol.Buffers.To_Array (SSH_String (Signature_Bytes)));
      Assert_Status (Status_Value, CryptoLib.Errors.Ok, "signature byte append");
      return Result;
   end Signature_Blob;

   procedure Assert_Same_Bytes
     (Actual_Bytes   : Ada.Streams.Stream_Element_Array;
      Expected_Bytes : Ada.Streams.Stream_Element_Array;
      Label_Text     : String)
   is
   begin
      Assert
        (SSH_Lib.Tests.Fixtures.Binary_Data.Same_Bytes
           (Actual_Bytes, Expected_Bytes),
         Label_Text & " mismatch at byte"
         & Natural'Image
             (SSH_Lib.Tests.Fixtures.Binary_Data.First_Mismatch
                (Actual_Bytes, Expected_Bytes)));
   end Assert_Same_Bytes;

   procedure Assert_Buffer_Round_Trip is
      Buffer_Item  : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Status_Value : CryptoLib.Errors.Status;
   begin
      Status_Value := SSH_Lib.Protocol.Buffers.Set (Buffer_Item, Byte_Set);
      Assert_Status (Status_Value, CryptoLib.Errors.Ok, "packet buffer set byte set");
      Assert_Same_Bytes
        (SSH_Lib.Protocol.Buffers.To_Array (Buffer_Item), Byte_Set,
         "packet buffer byte path");
   end Assert_Buffer_Round_Trip;

   procedure Assert_SSH_String_Round_Trip is
      Encoded_Buffer : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Decoded_Buffer : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Next_Index     : Ada.Streams.Stream_Element_Offset;
      Status_Value   : CryptoLib.Errors.Status;
   begin
      Encoded_Buffer := SSH_Lib.Protocol.Numbers.Encode_SSH_String (Byte_Set);
      Status_Value := SSH_Lib.Protocol.Numbers.Decode_SSH_String
        (SSH_Lib.Protocol.Buffers.To_Array (Encoded_Buffer),
         Ada.Streams.Stream_Element_Offset'(1), Decoded_Buffer, Next_Index);
      Assert_Status (Status_Value, CryptoLib.Errors.Ok, "ssh string decode byte set");
      Assert (Next_Index = Ada.Streams.Stream_Element_Offset
                (SSH_Lib.Protocol.Buffers.Length (Encoded_Buffer)) + 1,
              "ssh string consumes exact byte count");
      Assert_Same_Bytes
        (SSH_Lib.Protocol.Buffers.To_Array (Decoded_Buffer), Byte_Set,
         "ssh string byte path");
   end Assert_SSH_String_Round_Trip;

   procedure Assert_Cleartext_Packet_Round_Trip is
      Encode_State   : SSH_Lib.Protocol.Packets.Protocol_State;
      Decode_State   : SSH_Lib.Protocol.Packets.Protocol_State;
      Packet_Buffer  : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Payload_Buffer : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Status_Value   : CryptoLib.Errors.Status;
   begin
      SSH_Lib.Protocol.Packets.Reset (Encode_State);
      SSH_Lib.Protocol.Packets.Reset (Decode_State);
      Status_Value := SSH_Lib.Protocol.Packets.Encode_Cleartext_Packet
        (Encode_State, Byte_Set, Packet_Buffer, True, 16#AA#);
      Assert_Status (Status_Value, CryptoLib.Errors.Ok, "cleartext packet encode byte set");
      Status_Value := SSH_Lib.Protocol.Packets.Decode_Cleartext_Packet
        (Decode_State, SSH_Lib.Protocol.Buffers.To_Array (Packet_Buffer), Payload_Buffer);
      Assert_Status (Status_Value, CryptoLib.Errors.Ok, "cleartext packet decode byte set");
      Assert_Same_Bytes
        (SSH_Lib.Protocol.Buffers.To_Array (Payload_Buffer), Byte_Set,
         "packet framing byte path");
   end Assert_Cleartext_Packet_Round_Trip;

   procedure Assert_Protected_Packet_Round_Trip is
      Encode_State   : SSH_Lib.Protocol.Protected_Packets.Protected_State;
      Decode_State   : SSH_Lib.Protocol.Protected_Packets.Protected_State;
      Packet_Buffer  : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Payload_Buffer : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Status_Value   : CryptoLib.Errors.Status;
   begin
      SSH_Lib.Protocol.Protected_Packets.Reset (Encode_State, Key_Data);
      SSH_Lib.Protocol.Protected_Packets.Reset (Decode_State, Key_Data);
      Status_Value := SSH_Lib.Protocol.Protected_Packets.Encode_Protected_Packet
        (Encode_State, Byte_Set, Packet_Buffer, True, 16#AA#);
      Assert_Status (Status_Value, CryptoLib.Errors.Ok, "protected packet encode byte set");
      Status_Value := SSH_Lib.Protocol.Protected_Packets.Decode_Protected_Packet
        (Decode_State, SSH_Lib.Protocol.Buffers.To_Array (Packet_Buffer), Payload_Buffer);
      Assert_Status (Status_Value, CryptoLib.Errors.Ok, "protected packet decode byte set");
      Assert_Same_Bytes
        (SSH_Lib.Protocol.Buffers.To_Array (Payload_Buffer), Byte_Set,
         "encrypted packet byte path");
   end Assert_Protected_Packet_Round_Trip;

   procedure Assert_Channel_Protocol_Round_Trip is
      Packet_Buffer : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Data_Event    : SSH_Lib.Protocol.Channels.Channel_Data_Event;
      Stderr_Event  : SSH_Lib.Protocol.Channels.Channel_Extended_Data_Event;
      Status_Value  : CryptoLib.Errors.Status;
   begin
      Packet_Buffer := SSH_Lib.Protocol.Channels.Encode_Channel_Data (7, Byte_Set);
      Status_Value := SSH_Lib.Protocol.Channels.Parse_Channel_Data
        (SSH_Lib.Protocol.Buffers.To_Array (Packet_Buffer), 7, Data_Event);
      Assert_Status (Status_Value, CryptoLib.Errors.Ok, "channel data parse byte set");
      Assert_Same_Bytes
        (SSH_Lib.Protocol.Buffers.To_Array (Data_Event.Data), Byte_Set,
         "channel-data protocol byte path");

      Packet_Buffer := SSH_Lib.Protocol.Channels.Encode_Channel_Extended_Data
        (7, SSH_Lib.Protocol.Channels.Extended_Data_Stderr, Byte_Set);
      Status_Value := SSH_Lib.Protocol.Channels.Parse_Channel_Extended_Data
        (SSH_Lib.Protocol.Buffers.To_Array (Packet_Buffer), 7, Stderr_Event);
      Assert_Status (Status_Value, CryptoLib.Errors.Ok, "channel stderr parse byte set");
      Assert_Same_Bytes
        (SSH_Lib.Protocol.Buffers.To_Array (Stderr_Event.Data), Byte_Set,
         "stderr protocol byte path");
   end Assert_Channel_Protocol_Round_Trip;

   procedure Assert_Channel_API_Round_Trip is
      Channel_Item : SSH_Lib.Channels.Channel;
      Status_Value : CryptoLib.Errors.Status;
      Read_Buffer  : Ada.Streams.Stream_Element_Array (1 .. 3);
      Last_Index   : Ada.Streams.Stream_Element_Offset;
      Packet_Buffer : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Data_Event    : SSH_Lib.Protocol.Channels.Channel_Data_Event;
      Remainder     : Ada.Streams.Stream_Element_Array (1 .. 3);
   begin
      SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
        (Channel_Item,
         Local_Channel_Id           => 7,
         Remote_Channel_Id          => 9,
         Remote_Remaining_Window    => 64,
         Remote_Maximum_Packet_Size => 64);
      Status_Value := SSH_Lib.Channels.Write (Channel_Item, Byte_Set);
      Assert_Status (Status_Value, CryptoLib.Errors.Ok, "channel write byte set");
      Status_Value := SSH_Lib.Protocol.Channels.Parse_Channel_Data
        (SSH_Lib.Channels.Test_Support.Last_Channel_Data_Payload_For_Test (Channel_Item),
         9, Data_Event);
      Assert_Status (Status_Value, CryptoLib.Errors.Ok, "channel write packet parse");
      Assert_Same_Bytes
        (SSH_Lib.Protocol.Buffers.To_Array (Data_Event.Data), Byte_Set,
         "channel Write byte path");
      Assert (SSH_Lib.Channels.Test_Support.Outbound_Data_Byte_Count_For_Test
                (Channel_Item) = Byte_Set'Length,
              "channel write exact byte count");

      SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
        (Channel_Item,
         Local_Channel_Id           => 7,
         Remote_Channel_Id          => 9,
         Remote_Remaining_Window    => 64,
         Remote_Maximum_Packet_Size => 64);
      Packet_Buffer := SSH_Lib.Protocol.Channels.Encode_Channel_Data (7, Byte_Set);
      Status_Value := SSH_Lib.Channels.Test_Support.Dispatch_Inbound_Payload_For_Test
        (Channel_Item, SSH_Lib.Protocol.Buffers.To_Array (Packet_Buffer));
      Assert_Status (Status_Value, CryptoLib.Errors.Ok, "channel dispatch stdout byte set");
      Status_Value := SSH_Lib.Channels.Read_Some (Channel_Item, Read_Buffer, Last_Index);
      Assert_Status (Status_Value, CryptoLib.Errors.Ok, "channel read first chunk");
      Assert_Same_Bytes
        (Read_Buffer (Read_Buffer'First .. Last_Index),
         Byte_Set (Byte_Set'First .. Byte_Set'First + 2),
         "pending stdout first chunk");
      Status_Value := SSH_Lib.Channels.Read_Some (Channel_Item, Remainder, Last_Index);
      Assert_Status (Status_Value, CryptoLib.Errors.Ok, "channel read second chunk");
      Assert_Same_Bytes
        (Remainder (Remainder'First .. Last_Index),
         Byte_Set (Byte_Set'First + 3 .. Byte_Set'Last),
         "pending stdout second chunk");

      SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
        (Channel_Item,
         Local_Channel_Id           => 7,
         Remote_Channel_Id          => 9,
         Remote_Remaining_Window    => 64,
         Remote_Maximum_Packet_Size => 64);
      Packet_Buffer := SSH_Lib.Protocol.Channels.Encode_Channel_Extended_Data
        (7, SSH_Lib.Protocol.Channels.Extended_Data_Stderr, Byte_Set);
      Status_Value := SSH_Lib.Channels.Test_Support.Dispatch_Inbound_Payload_For_Test
        (Channel_Item, SSH_Lib.Protocol.Buffers.To_Array (Packet_Buffer));
      Assert_Status (Status_Value, CryptoLib.Errors.Ok, "channel dispatch stderr byte set");
      Assert (SSH_Lib.Channels.Test_Support.Pending_Stderr_Length_For_Test
                (Channel_Item) = Byte_Set'Length,
              "stderr drain path records exact binary byte count");
      Status_Value := SSH_Lib.Channels.Read_Some (Channel_Item, Read_Buffer, Last_Index);
      Assert_Status (Status_Value, CryptoLib.Errors.Timeout,
                     "stderr is not returned as stdout");
   end Assert_Channel_API_Round_Trip;

   procedure Assert_Agent_Round_Trips is
      use SSH_Lib.Protocol.Buffers;
      Request_Buffer : Packet_Buffer;
      Signature_Wire : Packet_Buffer;
      Response_Wire  : Packet_Buffer;
      Parsed_Blob    : Packet_Buffer;
      Data_Buffer    : Packet_Buffer;
      Key_Buffer     : Packet_Buffer;
      Comment_Buffer : Packet_Buffer;
      Identity_List  : SSH_Lib.Agent.Identity_List;
      Cursor         : Ada.Streams.Stream_Element_Offset;
      Next_Index     : Ada.Streams.Stream_Element_Offset;
      Status_Value   : CryptoLib.Errors.Status;
   begin
      Request_Buffer := SSH_Lib.Agent.Protocol.Encode_Sign_Request
        (Byte_Set, Byte_Set, "ssh-ed25519");
      declare
         Request_Data : constant Ada.Streams.Stream_Element_Array :=
           To_Array (Request_Buffer);
      begin
         Assert (Request_Data'Length > 0, "agent sign request not empty");
         Assert (Request_Data (Request_Data'First) =
                 SSH_Lib.Agent.Protocol.SSH_AGENTC_SIGN_REQUEST,
                 "agent sign request message byte");
         Cursor := Request_Data'First + 1;
         Status_Value := SSH_Lib.Protocol.Numbers.Decode_SSH_String
           (Request_Data, Cursor, Key_Buffer, Next_Index);
         Assert_Status (Status_Value, CryptoLib.Errors.Ok, "agent key string decode");
         Assert_Same_Bytes (To_Array (Key_Buffer), Byte_Set, "agent key blob byte path");
         Cursor := Next_Index;
         Status_Value := SSH_Lib.Protocol.Numbers.Decode_SSH_String
           (Request_Data, Cursor, Data_Buffer, Next_Index);
         Assert_Status (Status_Value, CryptoLib.Errors.Ok, "agent data string decode");
         Assert_Same_Bytes (To_Array (Data_Buffer), Byte_Set, "agent signature payload byte path");
      end;

      Status_Value := Append_Byte
        (Signature_Wire, SSH_Lib.Agent.Protocol.SSH_AGENT_SIGN_RESPONSE);
      Assert_Status (Status_Value, CryptoLib.Errors.Ok, "agent sign response byte append");
      Status_Value := Append
        (Signature_Wire,
         To_Array (SSH_String (To_Array (Signature_Blob ("ssh-ed25519", Byte_Set)))));
      Assert_Status (Status_Value, CryptoLib.Errors.Ok, "agent sign response append");
      Status_Value := SSH_Lib.Agent.Protocol.Parse_Sign_Response
        (To_Array (Signature_Wire), Parsed_Blob);
      Assert_Status (Status_Value, CryptoLib.Errors.Ok, "agent sign response parse");
      Assert_Same_Bytes
        (To_Array (Parsed_Blob), To_Array (Signature_Blob ("ssh-ed25519", Byte_Set)),
         "agent signature blob byte path");

      SSH_Lib.Protocol.Buffers.Clear (Response_Wire);
      Status_Value := Append_Byte
        (Response_Wire, SSH_Lib.Agent.Protocol.SSH_AGENT_IDENTITIES_ANSWER);
      Assert_Status (Status_Value, CryptoLib.Errors.Ok, "agent identities response byte append");
      Status_Value := Append
        (Response_Wire, SSH_Lib.Protocol.Numbers.Encode_Uint32 (1));
      Assert_Status (Status_Value, CryptoLib.Errors.Ok, "agent identities count append");
      Status_Value := Append (Response_Wire, To_Array (SSH_String (Byte_Set)));
      Assert_Status (Status_Value, CryptoLib.Errors.Ok, "agent identity key append");
      Status_Value := Append
        (Response_Wire, To_Array (SSH_String (Bytes_From_String ("comment"))));
      Assert_Status (Status_Value, CryptoLib.Errors.Ok, "agent identity comment append");
      Status_Value := SSH_Lib.Agent.Protocol.Parse_Identities_Answer
        (To_Array (Response_Wire), Identity_List);
      Assert_Status (Status_Value, CryptoLib.Errors.Ok, "agent identities parse");
      Assert (SSH_Lib.Agent.Count (Identity_List) = 1, "agent identity count");
      Assert_Same_Bytes
        (SSH_Lib.Agent.Public_Key_Blob (Identity_List, 1), Byte_Set,
         "agent identity parser byte path");
      Status_Value := SSH_Lib.Protocol.Numbers.Decode_SSH_String
        (To_Array (Response_Wire),
         Ada.Streams.Stream_Element_Offset'(6), Comment_Buffer, Next_Index);
      Assert_Status (Status_Value, CryptoLib.Errors.Ok, "agent identity standalone key decode");
      Assert_Same_Bytes
        (To_Array (Comment_Buffer), Byte_Set,
         "agent identity decoded key standalone byte path");
   end Assert_Agent_Round_Trips;

   procedure Assert_Key_And_Identity_Round_Trips is
      Host_Blob        : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Key_Item         : SSH_Lib.Keys.Public_Key;
      Known_Host_Item  : SSH_Lib.Known_Hosts.Host_Key;
      Identity_Item    : SSH_Lib.Identity_Files.Identity_Key;
      Algorithm_Text   : Ada.Strings.Unbounded.Unbounded_String;
      Status_Value     : CryptoLib.Errors.Status;
      Expected_Raw     : Ada.Streams.Stream_Element_Array (1 .. 32);
   begin
      Host_Blob := Host_Key_Blob ("ssh-ed25519", Key_Data);
      Status_Value := SSH_Lib.Protocol.Host_Keys.Parse
        (SSH_Lib.Protocol.Buffers.To_Array (Host_Blob), "ssh-ed25519", Key_Item);
      Assert_Status (Status_Value, CryptoLib.Errors.Ok, "host key blob parse");
      Assert_Same_Bytes
        (SSH_Lib.Keys.Internal.Raw_Blob (Key_Item),
         SSH_Lib.Protocol.Buffers.To_Array (Host_Blob),
         "known-host raw key blob byte path");
      Status_Value := SSH_Lib.Known_Hosts.From_Public_Key (Key_Item, Known_Host_Item);
      Assert_Status (Status_Value, CryptoLib.Errors.Ok, "known-host export from raw blob");
      Assert (SSH_Lib.Known_Hosts.Is_Valid (Known_Host_Item),
              "known-host exported blob remains valid");
      Status_Value := SSH_Lib.Public_Key_Blobs.Algorithm_Name
        (SSH_Lib.Keys.Internal.Raw_Blob (Key_Item), Algorithm_Text);
      Assert_Status (Status_Value, CryptoLib.Errors.Ok, "public key blob algorithm parse");
      Assert (Ada.Strings.Unbounded.To_String (Algorithm_Text) = "ssh-ed25519",
              "public key blob algorithm stable");

      Status_Value := SSH_Lib.Identity_Files.Parse (Valid_OpenSSH_Ed25519, Identity_Item);
      Assert_Status (Status_Value, CryptoLib.Errors.Ok, "identity fixture parses");
      declare
         Public_Blob : constant Ada.Streams.Stream_Element_Array :=
           SSH_Lib.Identity_Files.Public_Key_Blob (Identity_Item);
      begin
         for Index_Value in Expected_Raw'Range loop
            Expected_Raw (Index_Value) := Ada.Streams.Stream_Element (Index_Value);
         end loop;
         declare
            Expected_Public : constant Ada.Streams.Stream_Element_Array :=
              SSH_Lib.Protocol.Buffers.To_Array
                (Host_Key_Blob ("ssh-ed25519", Expected_Raw));
         begin
            Assert (Public_Blob'Length = Expected_Public'Length,
                    "identity public key field length");
            Assert_Same_Bytes
              (Public_Blob, Expected_Public,
               "identity-file decoded public binary field");
         end;
      end;
   end Assert_Key_And_Identity_Round_Trips;

   procedure Assert_Git_Fixture_Payloads is
   begin
      Assert_Same_Bytes
        (SSH_Lib.Tests.Fixtures.Binary_Data.Git_Request, Byte_Set,
         "git request fixture byte set");
      Assert_Same_Bytes
        (SSH_Lib.Tests.Fixtures.Binary_Data.Git_Response, Byte_Set,
         "git response fixture byte set");
   end Assert_Git_Fixture_Payloads;

   procedure Assert_All_Production_Paths_Preserve is
   begin
      Assert_Buffer_Round_Trip;
      Assert_SSH_String_Round_Trip;
      Assert_Cleartext_Packet_Round_Trip;
      Assert_Protected_Packet_Round_Trip;
      Assert_Channel_Protocol_Round_Trip;
      Assert_Channel_API_Round_Trip;
      Assert_Agent_Round_Trips;
      Assert_Key_And_Identity_Round_Trips;
      Assert_Git_Fixture_Payloads;
   end Assert_All_Production_Paths_Preserve;
end SSH_Lib.Tests.Fixtures.Binary_Matrix;
