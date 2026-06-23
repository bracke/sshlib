with Ada.Calendar;
with Ada.Strings.Unbounded;
with SSH_Lib.Protocol.Buffers;
with SSH_Lib.Protocol.Protected_Packets;
with SSH_Lib.Sessions.Close_Pipeline;
with SSH_Lib.Sessions.Channel_Table;
with SSH_Lib.Sessions.Channel_IO;
with SSH_Lib.Sessions.Live_Transport;
with SSH_Lib.Sessions.Live_Transcript;

package body SSH_Lib.Sessions.Test_Support is
   use Ada.Strings.Unbounded;
   use CryptoLib.Errors;
   use SSH_Lib.Protocol.Buffers;
   use type Ada.Calendar.Time;

   Boundary_Key : constant Ada.Streams.Stream_Element_Array (1 .. 32) :=
     [1  => 16#43#, 2  => 16#48#, 3  => 16#41#, 4  => 16#4E#,
      5  => 16#4E#, 6  => 16#45#, 7  => 16#4C#, 8  => 16#2D#,
      9  => 16#42#, 10 => 16#4F#, 11 => 16#55#, 12 => 16#4E#,
      13 => 16#44#, 14 => 16#41#, 15 => 16#52#, 16 => 16#59#,
      17 => 16#2D#, 18 => 16#4B#, 19 => 16#45#, 20 => 16#59#,
      21 => 16#2D#, 22 => 16#30#, 23 => 16#30#, 24 => 16#30#,
      25 => 16#30#, 26 => 16#30#, 27 => 16#30#, 28 => 16#30#,
      29 => 16#30#, 30 => 16#30#, 31 => 16#30#, 32 => 16#31#];

   procedure Mark_Authenticated_Open_For_Test (Item : in out Session) is
   begin
      Item.Channel_Max_Open_Count := 32;
      SSH_Lib.Sessions.Channel_Table.Reset (Item);
      Clear (Item.Test_Channel_Open_Response);
      Clear (Item.Test_Channel_Exec_Response);
      Clear (Item.Test_Global_Response);
      Clear (Item.Test_Inbound_Forwarded_Open);
      Clear (Item.Test_Last_Channel_Open);
      Clear (Item.Test_Last_Exec_Request);
      Clear (Item.Test_Next_Channel_Stdout);
      Item.Test_Has_Open_Response := False;
      Item.Test_Has_Exec_Response := False;
      Item.Test_Has_Global_Response := False;
      Item.Test_Has_Inbound_Forwarded_Open := False;
      Item.Test_Write_Fails := False;
      Item.Test_Read_Open_Fails := False;
      Item.Test_Read_Exec_Fails := False;
      Item.Test_Open_Timeout := False;
      Item.Test_Exec_Timeout := False;
      Item.Test_Open_Cancelled := False;
      Item.Test_Exec_Cancelled := False;
      Item.Test_Partial_Channel_Write_Fails := False;
      Item.Test_Exec_Write_Timeout := False;
      Item.Live_Channel_IO_Enabled := False;
      Item.Live_Rekey_Started := Ada.Calendar.Clock;
      Clear (Item.Live_Last_Protected_Channel);
      Clear (Item.Live_Last_Plain_Channel);
      Item.Live_Userauth_IO_Enabled := False;
      Clear (Item.Live_Last_Protected_Userauth);
      Clear (Item.Live_Last_Plain_Userauth);
      Clear (Item.Live_Last_Protected_Userauth_Response);
      Clear (Item.Live_Last_Plain_Userauth_Response);
      Clear (Item.Live_Last_Protected_Service);
      Clear (Item.Live_Last_Plain_Service);
      Clear (Item.Live_Last_Protected_Service_Response);
      Clear (Item.Live_Last_Plain_Service_Response);
      Clear (Item.Live_Last_Agent_Sign_Request);
      Clear (Item.Live_Last_Agent_Sign_Response);
      Clear (Item.Test_Userauth_Response);
      Item.Current_State := Opened;
      Item.Transport_Connected := True;
      Item.Identification_Complete := True;
      Item.Kexinit_Exchanged := True;
      Item.Algorithms_Negotiated := True;
      Item.Kex_Complete := True;
      Item.Keys_Derived := True;
      Item.Newkeys_Sent := True;
      Item.Newkeys_Received := True;
      Item.Encrypted_Outbound_Active := True;
      Item.Encrypted_Inbound_Active := True;
      Item.Host_Key_Signature_Verified := True;
      Item.Known_Host_Trusted := True;
      Item.Known_Host_Bypassed_Explicitly := False;
      Item.Userauth_Service_Accepted := True;
      Item.User_Authenticated := True;
      Item.Session_Open := True;
      Item.Session_Closed := False;
      Item.Failure_Status := Ok;
      Item.Session_Dirty := False;
      Item.Live_Rekey_Started := Ada.Calendar.Clock;
      Item.Last_Operation_Cancelled := False;
      Item.Authenticated_User_Name := To_Unbounded_String ("test");
      Item.Authentication_Method_Used := Agent_Authentication;
   end Mark_Authenticated_Open_For_Test;

   function Queue_Channel_Open_Response_For_Test
     (Item    : in out Session;
      Payload : Ada.Streams.Stream_Element_Array)
      return Status
   is
      Buffer_Value : Packet_Buffer;
      Status_Value : Status;
   begin
      Status_Value := Set (Buffer_Value, Payload);
      if Status_Value = Ok then
         Status_Value := SSH_Lib.Sessions.Channel_IO.Queue_Channel_Response_For_Test
           (Item, SSH_Lib.Sessions.Channel_IO.Open_Response, Buffer_Value);
      end if;
      Item.Test_Has_Open_Response := Status_Value = Ok;
      return Status_Value;
   end Queue_Channel_Open_Response_For_Test;

   function Queue_Exec_Response_For_Test
     (Item    : in out Session;
      Payload : Ada.Streams.Stream_Element_Array)
      return Status
   is
      Buffer_Value : Packet_Buffer;
      Status_Value : Status;
   begin
      Status_Value := Set (Buffer_Value, Payload);
      if Status_Value = Ok then
         Status_Value := SSH_Lib.Sessions.Channel_IO.Queue_Channel_Response_For_Test
           (Item, SSH_Lib.Sessions.Channel_IO.Exec_Response, Buffer_Value);
      end if;
      Item.Test_Has_Exec_Response := Status_Value = Ok;
      return Status_Value;
   end Queue_Exec_Response_For_Test;

   function Queue_Global_Response_For_Test
     (Item    : in out Session;
      Payload : Ada.Streams.Stream_Element_Array)
      return Status
   is
      Status_Value : Status;
   begin
      Status_Value := Set (Item.Test_Global_Response, Payload);
      Item.Test_Has_Global_Response := Status_Value = Ok;
      return Status_Value;
   end Queue_Global_Response_For_Test;

   function Queue_Inbound_Forwarded_Open_For_Test
     (Item    : in out Session;
      Payload : Ada.Streams.Stream_Element_Array)
      return Status
   is
      Encoded      : Packet_Buffer;
      Peer_State   : SSH_Lib.Protocol.Protected_Packets.Protected_State;
      Status_Value : Status;
   begin
      if Item.Live_Channel_IO_Enabled then
         SSH_Lib.Protocol.Protected_Packets.Reset (Peer_State, Boundary_Key);
         SSH_Lib.Protocol.Protected_Packets.Set_Sequences_For_Test
           (Peer_State,
            Inbound_Value => 0,
            Outbound_Value =>
              SSH_Lib.Protocol.Protected_Packets.Inbound_Sequence
                (Item.Live_Open_Protected_State));
         Status_Value :=
           SSH_Lib.Protocol.Protected_Packets.Encode_Protected_Packet
             (Peer_State,
              Payload,
              Encoded,
              Use_Test_Padding  => True,
              Test_Padding_Byte => 16#00#);
         if Status_Value = Ok then
            Status_Value :=
              Set (Item.Test_Inbound_Forwarded_Open, To_Array (Encoded));
         end if;
      else
         Status_Value := Set (Item.Test_Inbound_Forwarded_Open, Payload);
      end if;
      Item.Test_Has_Inbound_Forwarded_Open := Status_Value = Ok;
      return Status_Value;
   end Queue_Inbound_Forwarded_Open_For_Test;

   function Last_Channel_Open_Payload_For_Test
     (Item : Session)
      return Ada.Streams.Stream_Element_Array
   is
   begin
      return To_Array (Item.Test_Last_Channel_Open);
   end Last_Channel_Open_Payload_For_Test;

   function Last_Exec_Request_Payload_For_Test
     (Item : Session)
      return Ada.Streams.Stream_Element_Array
   is
   begin
      return To_Array (Item.Test_Last_Exec_Request);
   end Last_Exec_Request_Payload_For_Test;

   function Last_Plain_Channel_Payload_For_Test
     (Item : Session)
      return Ada.Streams.Stream_Element_Array
   is
   begin
      return To_Array
        (SSH_Lib.Sessions.Channel_IO.Last_Plain_Channel_Payload_For_Test (Item));
   end Last_Plain_Channel_Payload_For_Test;

   function Queue_Next_Channel_Stdout_For_Test
     (Item : in out Session;
      Data : Ada.Streams.Stream_Element_Array)
      return Status
   is
   begin
      return Set (Item.Test_Next_Channel_Stdout, Data);
   exception
      when others =>
         Clear (Item.Test_Next_Channel_Stdout);
         return Internal_Error;
   end Queue_Next_Channel_Stdout_For_Test;

   procedure Set_Channel_Write_Failure_For_Test
     (Item  : in out Session;
      Value : Boolean)
   is
   begin
      Item.Test_Write_Fails := Value;
   end Set_Channel_Write_Failure_For_Test;

   procedure Set_Channel_Read_Open_Failure_For_Test
     (Item  : in out Session;
      Value : Boolean)
   is
   begin
      Item.Test_Read_Open_Fails := Value;
   end Set_Channel_Read_Open_Failure_For_Test;

   procedure Set_Channel_Read_Exec_Failure_For_Test
     (Item  : in out Session;
      Value : Boolean)
   is
   begin
      Item.Test_Read_Exec_Fails := Value;
   end Set_Channel_Read_Exec_Failure_For_Test;

   procedure Set_Channel_Open_Timeout_For_Test
     (Item  : in out Session;
      Value : Boolean)
   is
   begin
      Item.Test_Open_Timeout := Value;
   end Set_Channel_Open_Timeout_For_Test;

   procedure Set_Channel_Exec_Timeout_For_Test
     (Item  : in out Session;
      Value : Boolean)
   is
   begin
      Item.Test_Exec_Timeout := Value;
   end Set_Channel_Exec_Timeout_For_Test;


   procedure Set_Open_Cancelled_For_Test
     (Item  : in out Session;
      Value : Boolean)
   is
   begin
      Item.Test_Open_Cancelled := Value;
   end Set_Open_Cancelled_For_Test;

   procedure Set_Exec_Cancelled_For_Test
     (Item  : in out Session;
      Value : Boolean)
   is
   begin
      Item.Test_Exec_Cancelled := Value;
   end Set_Exec_Cancelled_For_Test;

   procedure Set_Channel_Exec_Write_Timeout_For_Test
     (Item  : in out Session;
      Value : Boolean)
   is
   begin
      Item.Test_Exec_Write_Timeout := Value;
   end Set_Channel_Exec_Write_Timeout_For_Test;

   procedure Set_Partial_Channel_Write_Failure_For_Test
     (Item  : in out Session;
      Value : Boolean)
   is
   begin
      Item.Test_Partial_Channel_Write_Fails := Value;
   end Set_Partial_Channel_Write_Failure_For_Test;

   procedure Set_Timeouts_For_Test
     (Item               : in out Session;
      Connect_Timeout_MS : Natural;
      Read_Timeout_MS    : Natural;
      Write_Timeout_MS   : Natural)
   is
   begin
      Item.Stored_Options.Connect_Timeout_MS := Connect_Timeout_MS;
      Item.Stored_Options.Read_Timeout_MS := Read_Timeout_MS;
      Item.Stored_Options.Write_Timeout_MS := Write_Timeout_MS;
   end Set_Timeouts_For_Test;

   procedure Mark_Dirty_For_Test
     (Item   : in out Session;
      Reason : CryptoLib.Errors.Status := CryptoLib.Errors.Connection_Failed)
   is
   begin
      Item.Session_Dirty := True;
      Item.Failure_Status := Reason;
   end Mark_Dirty_For_Test;

   function Is_Dirty_For_Test (Item : Session) return Boolean is
   begin
      return Item.Session_Dirty;
   end Is_Dirty_For_Test;

   function Last_Failure_For_Test
     (Item : Session)
      return CryptoLib.Errors.Status
   is
   begin
      return Item.Failure_Status;
   exception
      when others =>
         return Internal_Error;
   end Last_Failure_For_Test;

   procedure Set_Channel_Limit_For_Test
     (Item  : in out Session;
      Value : Natural)
   is
   begin
      Item.Channel_Max_Open_Count := Value;
   end Set_Channel_Limit_For_Test;


   function Run_Hostile_Open_Transcript_For_Test
     (Item     : in out Session;
      Scenario : Hostile_Open_Transcript)
      return CryptoLib.Errors.Status
   is
      procedure Reset_Transcript is
      begin
         SSH_Lib.Sessions.Close_Pipeline.Reset_To_Closed (Item, Ok);
         Item.Stored_Options.Host := To_Unbounded_String ("transcript.example.test");
         Item.Stored_Options.User := To_Unbounded_String ("git");
         Item.Stored_Options.Port := 22;
         Item.Stored_Options.Verify_Known_Host := True;
         Item.Stored_Options.Strict_Host_Key := True;
         Item.Stored_Options.Use_Agent := True;
      end Reset_Transcript;

      function Transcript_Fail (Status_Value : Status) return Status is
      begin
         SSH_Lib.Sessions.Close_Pipeline.Reset_To_Closed (Item, Status_Value);
         if Status_Value in Handshake_Failed | Read_Failed | Write_Failed | Timeout then
            Item.Session_Dirty := True;
         end if;
         return Status_Value;
      end Transcript_Fail;
   begin
      Reset_Transcript;

      --  Transport connection and server identification are the first public
      --  open-pipeline gates.  Hostile transcript failures must leave no open
      --  authenticated session behind.
      Item.Transport_Connected := True;
      if Scenario = Transcript_Silent_Identification then
         return Transcript_Fail (Timeout);
      elsif Scenario = Transcript_Malformed_Identification then
         return Transcript_Fail (Handshake_Failed);
      end if;
      Item.Identification_Complete := True;

      Item.Kexinit_Exchanged := True;
      if Scenario = Transcript_No_Supported_Kex
        or else Scenario = Transcript_No_Supported_Host_Key
        or else Scenario = Transcript_No_Supported_Cipher
      then
         return Transcript_Fail (Unsupported_Feature);
      end if;
      Item.Algorithms_Negotiated := True;

      if Scenario = Transcript_Bad_Kex_Signature then
         return Transcript_Fail (Handshake_Failed);
      end if;
      Item.Kex_Complete := True;
      Item.Keys_Derived := True;
      Item.Host_Key_Signature_Verified := True;

      if Scenario = Transcript_Unknown_Host_Key then
         return Transcript_Fail (Host_Key_Unknown);
      elsif Scenario = Transcript_Changed_Host_Key then
         return Transcript_Fail (Host_Key_Mismatch);
      end if;
      Item.Known_Host_Trusted := True;

      Item.Newkeys_Sent := True;
      if Scenario = Transcript_Newkeys_Not_Received then
         return Transcript_Fail (Timeout);
      end if;
      Item.Newkeys_Received := True;
      Item.Encrypted_Outbound_Active := True;
      Item.Encrypted_Inbound_Active := True;

      if Scenario = Transcript_Service_Accept_Before_Encryption then
         --  Model a hostile peer that sends service accept before NEWKEYS by
         --  explicitly clearing encrypted mode before the userauth gate.
         Item.Encrypted_Inbound_Active := False;
         Item.Encrypted_Outbound_Active := False;
         return Transcript_Fail (Handshake_Failed);
      end if;

      if Scenario = Transcript_Userauth_Before_Host_Trust then
         Item.Known_Host_Trusted := False;
         return Transcript_Fail (Host_Key_Unknown);
      end if;

      Item.Userauth_Service_Accepted := True;
      if Scenario = Transcript_Userauth_Partial_Success
        or else Scenario = Transcript_Userauth_Rejected
      then
         return Transcript_Fail (Authentication_Failed);
      end if;
      Item.User_Authenticated := True;
      Item.Authenticated_User_Name := To_Unbounded_String ("git");
      Item.Authentication_Method_Used := Agent_Authentication;

      if Scenario = Transcript_Channel_Open_Before_Auth then
         Item.User_Authenticated := False;
         return Transcript_Fail (Authentication_Failed);
      elsif Scenario = Transcript_Channel_Open_Rejected then
         return Transcript_Fail (Channel_Open_Failed);
      elsif Scenario = Transcript_Malformed_Channel_Open then
         return Transcript_Fail (Channel_Open_Failed);
      end if;

      Item.Current_State := Opened;
      Item.Session_Open := True;
      Item.Session_Closed := False;
      Item.Failure_Status := Ok;
      Item.Session_Dirty := False;
      Item.Live_Rekey_Started := Ada.Calendar.Clock;
      SSH_Lib.Sessions.Channel_Table.Reset (Item);
      return Ok;
   exception
      when others =>
         SSH_Lib.Sessions.Close_Pipeline.Reset_To_Closed (Item, Internal_Error);
         return Internal_Error;
   end Run_Hostile_Open_Transcript_For_Test;

   function Is_Open_For_Test (Item : Session) return Boolean is
   begin
      return Item.Current_State = Opened
        and then Item.Session_Open
        and then not Item.Session_Closed;
   end Is_Open_For_Test;

   function Is_Encrypted_For_Test (Item : Session) return Boolean is
   begin
      return Item.Encrypted_Outbound_Active and then Item.Encrypted_Inbound_Active;
   end Is_Encrypted_For_Test;

   function Is_Host_Trusted_For_Test (Item : Session) return Boolean is
   begin
      return Item.Host_Key_Signature_Verified
        and then (Item.Known_Host_Trusted or else Item.Known_Host_Bypassed_Explicitly);
   end Is_Host_Trusted_For_Test;

   function Is_Authenticated_For_Test (Item : Session) return Boolean is
   begin
      return Item.Userauth_Service_Accepted and then Item.User_Authenticated;
   end Is_Authenticated_For_Test;

   function Stored_Credentials_Clear_For_Test (Item : Session) return Boolean is
   begin
      return To_String (Item.Stored_Options.Password)'Length = 0
        and then To_String (Item.Stored_Options.Identity_Passphrase)'Length = 0
        and then Item.Stored_Options.Password_Callback = null
        and then Item.Stored_Options.Identity_Passphrase_Callback = null
        and then Item.Stored_Options.Password_Change_Callback = null
        and then Item.Stored_Options.Keyboard_Interactive_Callback = null;
   exception
      when others =>
         return False;
   end Stored_Credentials_Clear_For_Test;


   procedure Mark_Open_Success_Gates_For_Test (Item : in out Session) is
   begin
      Item.Transport_Connected := True;
      Item.Identification_Complete := True;
      Item.Kexinit_Exchanged := True;
      Item.Algorithms_Negotiated := True;
      Item.Kex_Complete := True;
      Item.Keys_Derived := True;
      Item.Newkeys_Sent := True;
      Item.Newkeys_Received := True;
      Item.Encrypted_Outbound_Active := True;
      Item.Encrypted_Inbound_Active := True;
      Item.Host_Key_Signature_Verified := True;
      Item.Known_Host_Trusted := True;
      Item.Known_Host_Bypassed_Explicitly := False;
      Item.Userauth_Service_Accepted := True;
      Item.User_Authenticated := True;
      Item.Current_State := Opened;
      Item.Session_Open := True;
      Item.Session_Closed := False;
      Item.Session_Dirty := False;
      Item.Failure_Status := Ok;
      Item.Live_Rekey_Started := Ada.Calendar.Clock;
      Item.Authenticated_User_Name := To_Unbounded_String ("git");
      Item.Authentication_Method_Used := Agent_Authentication;
   end Mark_Open_Success_Gates_For_Test;

   procedure Clear_Open_Success_Gate_For_Test
     (Item : in out Session;
      Gate : SSH_Lib.Sessions.Open_Guards.Open_Success_Gate)
   is
   begin
      case Gate is
         when SSH_Lib.Sessions.Open_Guards.Gate_Transport_Connected =>
            Item.Transport_Connected := False;
         when SSH_Lib.Sessions.Open_Guards.Gate_Identification_Complete =>
            Item.Identification_Complete := False;
         when SSH_Lib.Sessions.Open_Guards.Gate_Kexinit_Exchanged =>
            Item.Kexinit_Exchanged := False;
         when SSH_Lib.Sessions.Open_Guards.Gate_Algorithms_Negotiated =>
            Item.Algorithms_Negotiated := False;
         when SSH_Lib.Sessions.Open_Guards.Gate_Kex_Complete =>
            Item.Kex_Complete := False;
         when SSH_Lib.Sessions.Open_Guards.Gate_Keys_Derived =>
            Item.Keys_Derived := False;
         when SSH_Lib.Sessions.Open_Guards.Gate_Newkeys_Sent =>
            Item.Newkeys_Sent := False;
         when SSH_Lib.Sessions.Open_Guards.Gate_Newkeys_Received =>
            Item.Newkeys_Received := False;
         when SSH_Lib.Sessions.Open_Guards.Gate_Encrypted_Outbound_Active =>
            Item.Encrypted_Outbound_Active := False;
         when SSH_Lib.Sessions.Open_Guards.Gate_Encrypted_Inbound_Active =>
            Item.Encrypted_Inbound_Active := False;
         when SSH_Lib.Sessions.Open_Guards.Gate_Host_Key_Signature_Verified =>
            Item.Host_Key_Signature_Verified := False;
         when SSH_Lib.Sessions.Open_Guards.Gate_Known_Host_Trusted =>
            Item.Known_Host_Trusted := False;
            Item.Known_Host_Bypassed_Explicitly := False;
         when SSH_Lib.Sessions.Open_Guards.Gate_Userauth_Service_Accepted =>
            Item.Userauth_Service_Accepted := False;
         when SSH_Lib.Sessions.Open_Guards.Gate_User_Authenticated =>
            Item.User_Authenticated := False;
      end case;
   end Clear_Open_Success_Gate_For_Test;


   procedure Enable_Live_Channel_IO_For_Test (Item : in out Session) is
   begin
      SSH_Lib.Sessions.Channel_IO.Enable_For_Test (Item);
   end Enable_Live_Channel_IO_For_Test;

   function Last_Protected_Channel_Payload_For_Test
     (Item : Session)
      return Ada.Streams.Stream_Element_Array
   is
   begin
      return To_Array
        (SSH_Lib.Sessions.Channel_IO.Last_Protected_Channel_Payload_For_Test (Item));
   end Last_Protected_Channel_Payload_For_Test;

   procedure Configure_Rekey_For_Test
     (Item                  : in out Session;
      Automatic_Rekey       : Boolean;
      Rekey_After_Packets   : Natural;
      Rekey_After_Bytes     : Interfaces.Unsigned_64;
      Rekey_After_Seconds   : Natural)
   is
   begin
      Item.Stored_Options.Automatic_Rekey := Automatic_Rekey;
      Item.Stored_Options.Rekey_After_Packets := Rekey_After_Packets;
      Item.Stored_Options.Rekey_After_Bytes := Rekey_After_Bytes;
      Item.Stored_Options.Rekey_After_Seconds := Rekey_After_Seconds;
   end Configure_Rekey_For_Test;

   procedure Force_Rekey_Start_Age_For_Test
     (Item        : in out Session;
      Seconds_Ago : Natural)
   is
   begin
      Item.Live_Rekey_Started := Ada.Calendar.Clock - Duration (Seconds_Ago);
   exception
      when others =>
         Item.Live_Rekey_Started := Ada.Calendar.Clock;
   end Force_Rekey_Start_Age_For_Test;

   function Automatic_Rekey_Needed_For_Test
     (Item : Session)
      return Boolean
   is
   begin
      return SSH_Lib.Sessions.Live_Transport.Automatic_Rekey_Needed (Item);
   end Automatic_Rekey_Needed_For_Test;

   function Check_Automatic_Rekey_For_Test
     (Item : in out Session)
      return CryptoLib.Errors.Status
   is
   begin
      return SSH_Lib.Sessions.Live_Transport.Check_Automatic_Rekey (Item);
   end Check_Automatic_Rekey_For_Test;

   function Expand_Proxy_Command_For_Test
     (Command_Text : String;
      Host         : String;
      Port         : Natural;
      User         : String) return String is
   begin
      return SSH_Lib.Sessions.Live_Transcript.Expand_Proxy_Command_For_Test
        (Command_Text, Host, Port, User);
   end Expand_Proxy_Command_For_Test;

   function Active_Channel_Count_For_Test (Item : Session) return Natural is
   begin
      return SSH_Lib.Sessions.Channel_Table.Active_Count (Item);
   end Active_Channel_Count_For_Test;
end SSH_Lib.Sessions.Test_Support;
