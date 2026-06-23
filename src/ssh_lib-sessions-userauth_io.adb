with Ada.Streams;
with Ada.Strings.Unbounded;
with Interfaces;
with SSH_Lib.Agent.Protocol;
with SSH_Lib.Protocol.Numbers;
with SSH_Lib.Protocol.Protected_Packets;
with SSH_Lib.Protocol.Service;
with SSH_Lib.Protocol.Userauth;
with SSH_Lib.Protocol.Userauth.Agent_Identity;
with SSH_Lib.Protocol.Userauth.Identity;

package body SSH_Lib.Sessions.Userauth_IO is
   use Ada.Streams;
   use Ada.Strings.Unbounded;
   use CryptoLib.Errors;
   use SSH_Lib.Protocol.Buffers;
   use type SSH_Lib.Protocol.Userauth.Reply_Kind;
   use type Interfaces.Unsigned_32;

   Boundary_Key : constant Stream_Element_Array (1 .. 32) :=
     [1  => 16#55#,
      2  => 16#53#,
      3  => 16#45#,
      4  => 16#52#,
      5  => 16#41#,
      6  => 16#55#,
      7  => 16#54#,
      8  => 16#48#,
      9  => 16#2D#,
      10 => 16#42#,
      11 => 16#4F#,
      12 => 16#55#,
      13 => 16#4E#,
      14 => 16#44#,
      15 => 16#41#,
      16 => 16#52#,
      17 => 16#59#,
      18 => 16#2D#,
      19 => 16#4B#,
      20 => 16#45#,
      21 => 16#59#,
      22 => 16#2D#,
      23 => 16#30#,
      24 => 16#30#,
      25 => 16#30#,
      26 => 16#30#,
      27 => 16#30#,
      28 => 16#30#,
      29 => 16#30#,
      30 => 16#30#,
      31 => 16#30#,
      32 => 16#31#];

   Session_Identifier : constant Stream_Element_Array (1 .. 16) :=
     [1  => 16#41#,
      2  => 16#64#,
      3  => 16#61#,
      4  => 16#5F#,
      5  => 16#53#,
      6  => 16#53#,
      7  => 16#48#,
      8  => 16#5F#,
      9  => 16#55#,
      10 => 16#41#,
      11 => 16#55#,
      12 => 16#54#,
      13 => 16#48#,
      14 => 16#5F#,
      15 => 16#49#,
      16 => 16#44#];

   Rejecting_Runtime_User : constant String := "reject-auth";

   function Bytes_From_String (Value : String) return Stream_Element_Array is
      Result : Stream_Element_Array (1 .. Value'Length);
      Cursor : Stream_Element_Offset := Result'First;
   begin
      for Character_Value of Value loop
         Result (Cursor) := Stream_Element (Character'Pos (Character_Value));
         Cursor := Cursor + 1;
      end loop;
      return Result;
   end Bytes_From_String;

   function Append_SSH_String
     (Item : in out Packet_Buffer; Value : String) return Status
   is
      Encoded_Value : constant Packet_Buffer :=
        SSH_Lib.Protocol.Numbers.Encode_SSH_String (Bytes_From_String (Value));
   begin
      return Append (Item, To_Array (Encoded_Value));
   end Append_SSH_String;

   function Should_Reject_For_Test (User_Name : String) return Boolean is
   begin
      return User_Name = Rejecting_Runtime_User;
   exception
      when others =>
         return False;
   end Should_Reject_For_Test;

   function Ready_For_Userauth_IO (Item : Session) return Boolean is
   begin
      return
        Item.Transport_Connected
        and then Item.Identification_Complete
        and then Item.Kexinit_Exchanged
        and then Item.Algorithms_Negotiated
        and then Item.Kex_Complete
        and then Item.Keys_Derived
        and then Item.Newkeys_Sent
        and then Item.Newkeys_Received
        and then Item.Encrypted_Outbound_Active
        and then Item.Encrypted_Inbound_Active
        and then Item.Host_Key_Signature_Verified
        and then
          (Item.Known_Host_Trusted or else Item.Known_Host_Bypassed_Explicitly)
        and then Item.Userauth_Service_Accepted
        and then not Item.User_Authenticated
        and then not Item.Session_Dirty;
   exception
      when others =>
         return False;
   end Ready_For_Userauth_IO;

   function Enabled (Item : Session) return Boolean is
   begin
      return
        Item.Live_Userauth_IO_Enabled and then Ready_For_Userauth_IO (Item);
   exception
      when others =>
         return False;
   end Enabled;

   procedure Enable_For_Test (Item : in out Session) is
   begin
      SSH_Lib.Protocol.Protected_Packets.Reset
        (Item.Live_Userauth_Protected_State, Boundary_Key);
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
      Item.Live_Userauth_IO_Enabled := True;
   exception
      when others =>
         Item.Live_Userauth_IO_Enabled := False;
   end Enable_For_Test;

   function Send_Userauth_Payload
     (Item : in out Session; Payload : Packet_Buffer) return Status
   is
      Status_Value : Status;
   begin
      if not Enabled (Item) then
         Item.Session_Dirty := True;
         Item.Failure_Status := Write_Failed;
         return Write_Failed;
      end if;

      Status_Value := Set (Item.Live_Last_Plain_Userauth, To_Array (Payload));
      if Status_Value /= Ok then
         Item.Session_Dirty := True;
         Item.Failure_Status := Status_Value;
         return Status_Value;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Protected_Packets.Encode_Protected_Packet
          (Item.Live_Userauth_Protected_State,
           To_Array (Payload),
           Item.Live_Last_Protected_Userauth,
           Use_Test_Padding  => True,
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
   end Send_Userauth_Payload;

   function Queue_Userauth_Success_For_Test
     (Item : in out Session) return Status
   is
      Success_Payload : Packet_Buffer;
      Peer_State      : SSH_Lib.Protocol.Protected_Packets.Protected_State;
      Status_Value    : Status;
   begin
      Status_Value :=
        Append_Byte
          (Success_Payload,
           SSH_Lib.Protocol.Userauth.SSH_MSG_USERAUTH_SUCCESS);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      SSH_Lib.Protocol.Protected_Packets.Reset (Peer_State, Boundary_Key);
      SSH_Lib.Protocol.Protected_Packets.Set_Sequences_For_Test
        (Peer_State,
         0,
         SSH_Lib.Protocol.Protected_Packets.Inbound_Sequence
           (Item.Live_Userauth_Protected_State));
      Status_Value :=
        SSH_Lib.Protocol.Protected_Packets.Encode_Protected_Packet
          (Peer_State,
           To_Array (Success_Payload),
           Item.Test_Userauth_Response,
           Use_Test_Padding  => True,
           Test_Padding_Byte => 16#00#);
      return Status_Value;
   exception
      when others =>
         return Internal_Error;
   end Queue_Userauth_Success_For_Test;

   function Queue_Userauth_Failure_For_Test
     (Item : in out Session) return Status
   is
      Failure_Payload : Packet_Buffer;
      Methods         : constant Packet_Buffer :=
        SSH_Lib.Protocol.Numbers.Encode_Name_List ("publickey");
      Peer_State      : SSH_Lib.Protocol.Protected_Packets.Protected_State;
      Status_Value    : Status;
   begin
      Status_Value :=
        Append_Byte
          (Failure_Payload,
           SSH_Lib.Protocol.Userauth.SSH_MSG_USERAUTH_FAILURE);
      if Status_Value = Ok then
         Status_Value := Append (Failure_Payload, To_Array (Methods));
      end if;
      if Status_Value = Ok then
         Status_Value :=
           Append_Byte
             (Failure_Payload,
              SSH_Lib.Protocol.Numbers.Encode_Boolean (False));
      end if;
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      SSH_Lib.Protocol.Protected_Packets.Reset (Peer_State, Boundary_Key);
      SSH_Lib.Protocol.Protected_Packets.Set_Sequences_For_Test
        (Peer_State,
         0,
         SSH_Lib.Protocol.Protected_Packets.Inbound_Sequence
           (Item.Live_Userauth_Protected_State));
      Status_Value :=
        SSH_Lib.Protocol.Protected_Packets.Encode_Protected_Packet
          (Peer_State,
           To_Array (Failure_Payload),
           Item.Test_Userauth_Response,
           Use_Test_Padding  => True,
           Test_Padding_Byte => 16#00#);
      return Status_Value;
   exception
      when others =>
         return Internal_Error;
   end Queue_Userauth_Failure_For_Test;

   function Queue_Keyboard_Interactive_Info_Request_For_Test
     (Item : in out Session) return Status
   is
      Info_Payload : Packet_Buffer;
      Peer_State   : SSH_Lib.Protocol.Protected_Packets.Protected_State;
      Status_Value : Status;
   begin
      Status_Value :=
        Append_Byte
          (Info_Payload,
           SSH_Lib.Protocol.Userauth.SSH_MSG_USERAUTH_INFO_REQUEST);
      if Status_Value = Ok then
         Status_Value := Append_SSH_String (Info_Payload, "password");
      end if;
      if Status_Value = Ok then
         Status_Value :=
           Append_SSH_String (Info_Payload, "Password authentication");
      end if;
      if Status_Value = Ok then
         Status_Value := Append_SSH_String (Info_Payload, "");
      end if;
      if Status_Value = Ok then
         Status_Value :=
           Append (Info_Payload, SSH_Lib.Protocol.Numbers.Encode_Uint32 (1));
      end if;
      if Status_Value = Ok then
         Status_Value := Append_SSH_String (Info_Payload, "Password: ");
      end if;
      if Status_Value = Ok then
         Status_Value :=
           Append_Byte
             (Info_Payload, SSH_Lib.Protocol.Numbers.Encode_Boolean (False));
      end if;
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      SSH_Lib.Protocol.Protected_Packets.Reset (Peer_State, Boundary_Key);
      SSH_Lib.Protocol.Protected_Packets.Set_Sequences_For_Test
        (Peer_State,
         0,
         SSH_Lib.Protocol.Protected_Packets.Inbound_Sequence
           (Item.Live_Userauth_Protected_State));
      Status_Value :=
        SSH_Lib.Protocol.Protected_Packets.Encode_Protected_Packet
          (Peer_State,
           To_Array (Info_Payload),
           Item.Test_Userauth_Response,
           Use_Test_Padding  => True,
           Test_Padding_Byte => 16#00#);
      return Status_Value;
   exception
      when others =>
         return Internal_Error;
   end Queue_Keyboard_Interactive_Info_Request_For_Test;

   function Read_Userauth_Response
     (Item : in out Session; Payload : out Packet_Buffer) return Status
   is
      Status_Value : Status;
   begin
      Clear (Payload);
      if not Enabled (Item) then
         Item.Session_Dirty := True;
         Item.Failure_Status := Read_Failed;
         return Read_Failed;
      end if;

      Status_Value :=
        Set
          (Item.Live_Last_Protected_Userauth_Response,
           To_Array (Item.Test_Userauth_Response));
      if Status_Value /= Ok then
         Item.Session_Dirty := True;
         Item.Failure_Status := Status_Value;
         return Status_Value;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Protected_Packets.Decode_Protected_Packet
          (Item.Live_Userauth_Protected_State,
           To_Array (Item.Test_Userauth_Response),
           Payload,
           Failure_When_Malformed => Authentication_Failed);
      if Status_Value /= Ok then
         Item.Session_Dirty := True;
         Item.Failure_Status := Status_Value;
         return Status_Value;
      end if;

      Status_Value :=
        Set (Item.Live_Last_Plain_Userauth_Response, To_Array (Payload));
      if Status_Value /= Ok then
         Item.Session_Dirty := True;
         Item.Failure_Status := Status_Value;
      end if;
      return Status_Value;
   exception
      when others =>
         Clear (Payload);
         Item.Session_Dirty := True;
         Item.Failure_Status := Internal_Error;
         return Internal_Error;
   end Read_Userauth_Response;

   function Ready_For_Service_IO (Item : Session) return Boolean is
   begin
      return
        Item.Transport_Connected
        and then Item.Identification_Complete
        and then Item.Kexinit_Exchanged
        and then Item.Algorithms_Negotiated
        and then Item.Kex_Complete
        and then Item.Keys_Derived
        and then Item.Newkeys_Sent
        and then Item.Newkeys_Received
        and then Item.Encrypted_Outbound_Active
        and then Item.Encrypted_Inbound_Active
        and then Item.Host_Key_Signature_Verified
        and then
          (Item.Known_Host_Trusted or else Item.Known_Host_Bypassed_Explicitly)
        and then not Item.Userauth_Service_Accepted
        and then not Item.User_Authenticated
        and then not Item.Session_Dirty;
   exception
      when others =>
         return False;
   end Ready_For_Service_IO;

   function Service_IO_Enabled (Item : Session) return Boolean is
   begin
      return
        Item.Live_Userauth_IO_Enabled and then Ready_For_Service_IO (Item);
   exception
      when others =>
         return False;
   end Service_IO_Enabled;

   function Queue_Service_Accept_For_Test (Item : in out Session) return Status
   is
      Accept_Payload : Packet_Buffer;
      Service_Name   : constant Stream_Element_Array :=
        [1  => 16#73#,
         2  => 16#73#,
         3  => 16#68#,
         4  => 16#2D#,
         5  => 16#75#,
         6  => 16#73#,
         7  => 16#65#,
         8  => 16#72#,
         9  => 16#61#,
         10 => 16#75#,
         11 => 16#74#,
         12 => 16#68#];
      Encoded_Name   : constant Packet_Buffer :=
        SSH_Lib.Protocol.Numbers.Encode_SSH_String (Service_Name);
      Peer_State     : SSH_Lib.Protocol.Protected_Packets.Protected_State;
      Status_Value   : Status;
   begin
      Clear (Item.Test_Userauth_Response);
      Status_Value :=
        Append_Byte
          (Accept_Payload, SSH_Lib.Protocol.Service.SSH_MSG_SERVICE_ACCEPT);
      if Status_Value = Ok then
         Status_Value := Append (Accept_Payload, To_Array (Encoded_Name));
      end if;
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      SSH_Lib.Protocol.Protected_Packets.Reset (Peer_State, Boundary_Key);
      Status_Value :=
        SSH_Lib.Protocol.Protected_Packets.Encode_Protected_Packet
          (Peer_State,
           To_Array (Accept_Payload),
           Item.Test_Userauth_Response,
           Use_Test_Padding  => True,
           Test_Padding_Byte => 16#00#);
      return Status_Value;
   exception
      when others =>
         return Internal_Error;
   end Queue_Service_Accept_For_Test;

   function Run_Userauth_Service_Request (Item : in out Session) return Status
   is
      Request_Buffer : Packet_Buffer;
      Reply_Buffer   : Packet_Buffer;
      Status_Value   : Status;
   begin
      if not Item.Live_Userauth_IO_Enabled then
         Enable_For_Test (Item);
      end if;

      if not Service_IO_Enabled (Item) then
         Item.Session_Dirty := True;
         Item.Failure_Status := Write_Failed;
         return Write_Failed;
      end if;

      Request_Buffer :=
        SSH_Lib.Protocol.Service.Encode_Userauth_Service_Request;
      if Is_Empty (Request_Buffer) then
         Item.Session_Dirty := True;
         Item.Failure_Status := Handshake_Failed;
         return Handshake_Failed;
      end if;

      Status_Value :=
        Set (Item.Live_Last_Plain_Service, To_Array (Request_Buffer));
      if Status_Value /= Ok then
         Item.Session_Dirty := True;
         Item.Failure_Status := Status_Value;
         return Status_Value;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Protected_Packets.Encode_Protected_Packet
          (Item.Live_Userauth_Protected_State,
           To_Array (Request_Buffer),
           Item.Live_Last_Protected_Service,
           Use_Test_Padding  => True,
           Test_Padding_Byte => 16#00#);
      if Status_Value /= Ok then
         Item.Session_Dirty := True;
         Item.Failure_Status := Status_Value;
         return Status_Value;
      end if;

      Status_Value := Queue_Service_Accept_For_Test (Item);
      if Status_Value /= Ok then
         Item.Session_Dirty := True;
         Item.Failure_Status := Status_Value;
         return Status_Value;
      end if;

      Status_Value :=
        Set
          (Item.Live_Last_Protected_Service_Response,
           To_Array (Item.Test_Userauth_Response));
      if Status_Value /= Ok then
         Item.Session_Dirty := True;
         Item.Failure_Status := Status_Value;
         return Status_Value;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Protected_Packets.Decode_Protected_Packet
          (Item.Live_Userauth_Protected_State,
           To_Array (Item.Test_Userauth_Response),
           Reply_Buffer,
           Failure_When_Malformed => Handshake_Failed);
      if Status_Value /= Ok then
         Item.Session_Dirty := True;
         Item.Failure_Status := Status_Value;
         return Status_Value;
      end if;

      Status_Value :=
        Set (Item.Live_Last_Plain_Service_Response, To_Array (Reply_Buffer));
      if Status_Value /= Ok then
         Item.Session_Dirty := True;
         Item.Failure_Status := Status_Value;
         return Status_Value;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Service.Parse_Service_Accept
          (To_Array (Reply_Buffer), "ssh-userauth");
      if Status_Value /= Ok then
         Item.Session_Dirty := True;
         Item.Failure_Status := Status_Value;
         return Status_Value;
      end if;

      Item.Userauth_Service_Accepted := True;
      Clear (Item.Test_Userauth_Response);
      return Ok;
   exception
      when others =>
         Item.Session_Dirty := True;
         Item.Failure_Status := Internal_Error;
         return Internal_Error;
   end Run_Userauth_Service_Request;

   function Deterministic_Agent_Public_Key_Blob return Packet_Buffer is
      Result       : Packet_Buffer;
      Algorithm    : constant Stream_Element_Array :=
        [1  => 16#73#,
         2  => 16#73#,
         3  => 16#68#,
         4  => 16#2D#,
         5  => 16#65#,
         6  => 16#64#,
         7  => 16#32#,
         8  => 16#35#,
         9  => 16#35#,
         10 => 16#31#,
         11 => 16#39#];
      Public_Bytes : constant Stream_Element_Array (1 .. 32) :=
        [1  => 16#10#,
         2  => 16#11#,
         3  => 16#12#,
         4  => 16#13#,
         5  => 16#14#,
         6  => 16#15#,
         7  => 16#16#,
         8  => 16#17#,
         9  => 16#18#,
         10 => 16#19#,
         11 => 16#1A#,
         12 => 16#1B#,
         13 => 16#1C#,
         14 => 16#1D#,
         15 => 16#1E#,
         16 => 16#1F#,
         17 => 16#20#,
         18 => 16#21#,
         19 => 16#22#,
         20 => 16#23#,
         21 => 16#24#,
         22 => 16#25#,
         23 => 16#26#,
         24 => 16#27#,
         25 => 16#28#,
         26 => 16#29#,
         27 => 16#2A#,
         28 => 16#2B#,
         29 => 16#2C#,
         30 => 16#2D#,
         31 => 16#2E#,
         32 => 16#2F#];
      Status_Value : Status;
   begin
      Clear (Result);
      Status_Value :=
        Append
          (Result,
           To_Array (SSH_Lib.Protocol.Numbers.Encode_SSH_String (Algorithm)));
      if Status_Value = Ok then
         Status_Value :=
           Append
             (Result,
              To_Array
                (SSH_Lib.Protocol.Numbers.Encode_SSH_String (Public_Bytes)));
      end if;
      if Status_Value /= Ok then
         Clear (Result);
      end if;
      return Result;
   exception
      when others =>
         Clear (Result);
         return Result;
   end Deterministic_Agent_Public_Key_Blob;

   function Deterministic_Agent_Signature_Blob return Packet_Buffer is
      Result          : Packet_Buffer;
      Algorithm       : constant Stream_Element_Array :=
        [1  => 16#73#,
         2  => 16#73#,
         3  => 16#68#,
         4  => 16#2D#,
         5  => 16#65#,
         6  => 16#64#,
         7  => 16#32#,
         8  => 16#35#,
         9  => 16#35#,
         10 => 16#31#,
         11 => 16#39#];
      Signature_Bytes : constant Stream_Element_Array (1 .. 64) :=
        [1  => 16#A0#,
         2  => 16#A1#,
         3  => 16#A2#,
         4  => 16#A3#,
         5  => 16#A4#,
         6  => 16#A5#,
         7  => 16#A6#,
         8  => 16#A7#,
         9  => 16#A8#,
         10 => 16#A9#,
         11 => 16#AA#,
         12 => 16#AB#,
         13 => 16#AC#,
         14 => 16#AD#,
         15 => 16#AE#,
         16 => 16#AF#,
         17 => 16#B0#,
         18 => 16#B1#,
         19 => 16#B2#,
         20 => 16#B3#,
         21 => 16#B4#,
         22 => 16#B5#,
         23 => 16#B6#,
         24 => 16#B7#,
         25 => 16#B8#,
         26 => 16#B9#,
         27 => 16#BA#,
         28 => 16#BB#,
         29 => 16#BC#,
         30 => 16#BD#,
         31 => 16#BE#,
         32 => 16#BF#,
         33 => 16#C0#,
         34 => 16#C1#,
         35 => 16#C2#,
         36 => 16#C3#,
         37 => 16#C4#,
         38 => 16#C5#,
         39 => 16#C6#,
         40 => 16#C7#,
         41 => 16#C8#,
         42 => 16#C9#,
         43 => 16#CA#,
         44 => 16#CB#,
         45 => 16#CC#,
         46 => 16#CD#,
         47 => 16#CE#,
         48 => 16#CF#,
         49 => 16#D0#,
         50 => 16#D1#,
         51 => 16#D2#,
         52 => 16#D3#,
         53 => 16#D4#,
         54 => 16#D5#,
         55 => 16#D6#,
         56 => 16#D7#,
         57 => 16#D8#,
         58 => 16#D9#,
         59 => 16#DA#,
         60 => 16#DB#,
         61 => 16#DC#,
         62 => 16#DD#,
         63 => 16#DE#,
         64 => 16#DF#];
      Status_Value    : Status;
   begin
      Clear (Result);
      Status_Value :=
        Append
          (Result,
           To_Array (SSH_Lib.Protocol.Numbers.Encode_SSH_String (Algorithm)));
      if Status_Value = Ok then
         Status_Value :=
           Append
             (Result,
              To_Array
                (SSH_Lib.Protocol.Numbers.Encode_SSH_String
                   (Signature_Bytes)));
      end if;
      if Status_Value /= Ok then
         Clear (Result);
      end if;
      return Result;
   exception
      when others =>
         Clear (Result);
         return Result;
   end Deterministic_Agent_Signature_Blob;

   function Deterministic_Agent_Sign_Response
     (Signature_Blob : Packet_Buffer) return Packet_Buffer
   is
      Result       : Packet_Buffer;
      Status_Value : Status;
   begin
      Clear (Result);
      Status_Value :=
        Append_Byte (Result, SSH_Lib.Agent.Protocol.SSH_AGENT_SIGN_RESPONSE);
      if Status_Value = Ok then
         Status_Value :=
           Append
             (Result,
              To_Array
                (SSH_Lib.Protocol.Numbers.Encode_SSH_String
                   (To_Array (Signature_Blob))));
      end if;
      if Status_Value /= Ok then
         Clear (Result);
      end if;
      return Result;
   exception
      when others =>
         Clear (Result);
         return Result;
   end Deterministic_Agent_Sign_Response;

   function Run_Agent_Userauth
     (Item : in out Session; User_Name : String) return Status
   is
      Public_Blob      : Packet_Buffer;
      Signature_Blob   : Packet_Buffer;
      Sign_Payload     : Packet_Buffer;
      Sign_Request     : Packet_Buffer;
      Sign_Response    : Packet_Buffer;
      Parsed_Signature : Packet_Buffer;
      Request_Buffer   : Packet_Buffer;
      Reply_Buffer     : Packet_Buffer;
      Reply_Value      : SSH_Lib.Protocol.Userauth.Reply;
      Status_Value     : Status;
   begin
      if not Item.Live_Userauth_IO_Enabled then
         Enable_For_Test (Item);
      end if;

      Public_Blob := Deterministic_Agent_Public_Key_Blob;
      Signature_Blob := Deterministic_Agent_Signature_Blob;
      if Is_Empty (Public_Blob) or else Is_Empty (Signature_Blob) then
         return Authentication_Failed;
      end if;

      Sign_Payload :=
        SSH_Lib.Protocol.Userauth.Build_Publickey_Signature_Payload
          (Session_Identifier,
           User_Name,
           "ssh-ed25519",
           To_Array (Public_Blob));
      if Is_Empty (Sign_Payload) then
         return Authentication_Failed;
      end if;

      --  Encode_Sign_Request produces SSH_AGENTC_SIGN_REQUEST; the
      --  deterministic reply below is then parsed exactly like an
      --  SSH_AGENT_SIGN_RESPONSE before userauth packet construction.
      Sign_Request :=
        SSH_Lib.Agent.Protocol.Encode_Sign_Request
          (To_Array (Public_Blob), To_Array (Sign_Payload), "ssh-ed25519");
      if Is_Empty (Sign_Request) then
         return Authentication_Failed;
      end if;

      Status_Value :=
        Set (Item.Live_Last_Agent_Sign_Request, To_Array (Sign_Request));
      if Status_Value /= Ok then
         Item.Session_Dirty := True;
         Item.Failure_Status := Status_Value;
         return Status_Value;
      end if;

      Sign_Response := Deterministic_Agent_Sign_Response (Signature_Blob);
      if Is_Empty (Sign_Response) then
         Item.Session_Dirty := True;
         Item.Failure_Status := Authentication_Failed;
         return Authentication_Failed;
      end if;

      Status_Value :=
        Set (Item.Live_Last_Agent_Sign_Response, To_Array (Sign_Response));
      if Status_Value /= Ok then
         Item.Session_Dirty := True;
         Item.Failure_Status := Status_Value;
         return Status_Value;
      end if;

      Status_Value :=
        SSH_Lib.Agent.Protocol.Parse_Sign_Response
          (To_Array (Sign_Response), Parsed_Signature);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      Status_Value :=
        SSH_Lib
          .Protocol
          .Userauth
          .Agent_Identity
          .Build_Signed_Request_From_Agent_Signature
             (To_Array (Public_Blob),
              To_Array (Parsed_Signature),
              Session_Identifier,
              User_Name,
              "ssh-ed25519",
              Request_Buffer);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      Status_Value := Send_Userauth_Payload (Item, Request_Buffer);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      if Should_Reject_For_Test (User_Name) then
         Status_Value := Queue_Userauth_Failure_For_Test (Item);
      else
         Status_Value := Queue_Userauth_Success_For_Test (Item);
      end if;
      if Status_Value /= Ok then
         Item.Session_Dirty := True;
         Item.Failure_Status := Status_Value;
         return Status_Value;
      end if;

      Status_Value := Read_Userauth_Response (Item, Reply_Buffer);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Userauth.Parse_Userauth_Reply
          (To_Array (Reply_Buffer),
           SSH_Lib.Protocol.Userauth.Signed_Reply,
           Reply_Value);
      if Status_Value /= Ok then
         Item.Session_Dirty := True;
         Item.Failure_Status := Status_Value;
         return Status_Value;
      end if;

      if Reply_Value.Kind /= SSH_Lib.Protocol.Userauth.Auth_Success then
         Item.User_Authenticated := False;
         Item.Current_State := Closed;
         Item.Session_Open := False;
         Item.Session_Closed := True;
         Item.Session_Dirty := True;
         Item.Failure_Status := Authentication_Failed;
         return Authentication_Failed;
      end if;

      Item.User_Authenticated := True;
      Item.Authenticated_User_Name := To_Unbounded_String (User_Name);
      Item.Authentication_Method_Used := Agent_Authentication;
      return Ok;
   exception
      when others =>
         Item.Session_Dirty := True;
         Item.Failure_Status := Internal_Error;
         return Internal_Error;
   end Run_Agent_Userauth;

   function Run_Identity_File_Userauth
     (Item      : in out Session;
      User_Name : String;
      Key       : SSH_Lib.Identity_Files.Identity_Key) return Status
   is
      Request_Buffer : Packet_Buffer;
      Reply_Buffer   : Packet_Buffer;
      Reply_Value    : SSH_Lib.Protocol.Userauth.Reply;
      Status_Value   : Status;
   begin
      if not Item.Live_Userauth_IO_Enabled then
         Enable_For_Test (Item);
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Userauth.Identity.Build_Signed_Request_From_Identity
          (Key, Session_Identifier, User_Name, Request_Buffer);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      Status_Value := Send_Userauth_Payload (Item, Request_Buffer);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      if Should_Reject_For_Test (User_Name) then
         Status_Value := Queue_Userauth_Failure_For_Test (Item);
      else
         Status_Value := Queue_Userauth_Success_For_Test (Item);
      end if;
      if Status_Value /= Ok then
         Item.Session_Dirty := True;
         Item.Failure_Status := Status_Value;
         return Status_Value;
      end if;

      Status_Value := Read_Userauth_Response (Item, Reply_Buffer);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Userauth.Parse_Userauth_Reply
          (To_Array (Reply_Buffer),
           SSH_Lib.Protocol.Userauth.Signed_Reply,
           Reply_Value);
      if Status_Value /= Ok then
         Item.Session_Dirty := True;
         Item.Failure_Status := Status_Value;
         return Status_Value;
      end if;

      if Reply_Value.Kind /= SSH_Lib.Protocol.Userauth.Auth_Success then
         Item.User_Authenticated := False;
         Item.Current_State := Closed;
         Item.Session_Open := False;
         Item.Session_Closed := True;
         Item.Session_Dirty := True;
         Item.Failure_Status := Authentication_Failed;
         return Authentication_Failed;
      end if;

      Item.User_Authenticated := True;
      Item.Authenticated_User_Name := To_Unbounded_String (User_Name);
      Item.Authentication_Method_Used := Identity_File_Authentication;
      return Ok;
   exception
      when others =>
         Item.Session_Dirty := True;
         Item.Failure_Status := Internal_Error;
         return Internal_Error;
   end Run_Identity_File_Userauth;

   function Send_Password_Userauth_Payload
     (Item            : in out Session;
      Actual_Payload  : Packet_Buffer;
      Redacted_Record : Packet_Buffer) return Status
   is
      Status_Value : Status;
   begin
      if not Enabled (Item) then
         Item.Session_Dirty := True;
         Item.Failure_Status := Write_Failed;
         return Write_Failed;
      end if;

      --  Password authentication is the deterministic runtime's only
      --  USERAUTH_REQUEST form that contains a reusable credential.  Encode
      --  and send the real payload over the protected-packet boundary, but
      --  retain only the redacted request in the test-visible plain transcript.
      --  This mirrors the live userauth path and keeps callback/explicit
      --  password material out of stored diagnostics.
      Status_Value :=
        Set (Item.Live_Last_Plain_Userauth, To_Array (Redacted_Record));
      if Status_Value /= Ok then
         Item.Session_Dirty := True;
         Item.Failure_Status := Status_Value;
         return Status_Value;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Protected_Packets.Encode_Protected_Packet
          (Item.Live_Userauth_Protected_State,
           To_Array (Actual_Payload),
           Item.Live_Last_Protected_Userauth,
           Use_Test_Padding  => True,
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
   end Send_Password_Userauth_Payload;

   function Run_Password_Userauth
     (Item : in out Session; User_Name : String; Password : String)
      return Status
   is
      Request_Buffer  : Packet_Buffer;
      Redacted_Buffer : Packet_Buffer;
      Reply_Buffer    : Packet_Buffer;
      Reply_Value     : SSH_Lib.Protocol.Userauth.Reply;
      Status_Value    : Status;
   begin
      if not Item.Live_Userauth_IO_Enabled then
         Enable_For_Test (Item);
      end if;

      Request_Buffer :=
        SSH_Lib.Protocol.Userauth.Encode_Password_Request
          (User_Name, Password);
      Redacted_Buffer :=
        SSH_Lib.Protocol.Userauth.Encode_Password_Request
          (User_Name, "<redacted>");
      if Is_Empty (Request_Buffer) or else Is_Empty (Redacted_Buffer) then
         Item.Session_Dirty := True;
         Item.Failure_Status := Authentication_Failed;
         return Authentication_Failed;
      end if;

      Status_Value :=
        Send_Password_Userauth_Payload (Item, Request_Buffer, Redacted_Buffer);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      if Should_Reject_For_Test (User_Name) then
         Status_Value := Queue_Userauth_Failure_For_Test (Item);
      else
         Status_Value := Queue_Userauth_Success_For_Test (Item);
      end if;
      if Status_Value /= Ok then
         Item.Session_Dirty := True;
         Item.Failure_Status := Status_Value;
         return Status_Value;
      end if;

      Status_Value := Read_Userauth_Response (Item, Reply_Buffer);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Userauth.Parse_Userauth_Reply
          (To_Array (Reply_Buffer),
           SSH_Lib.Protocol.Userauth.Password_Reply,
           Reply_Value);
      if Status_Value /= Ok then
         Item.Session_Dirty := True;
         Item.Failure_Status := Status_Value;
         return Status_Value;
      end if;

      if Reply_Value.Kind /= SSH_Lib.Protocol.Userauth.Auth_Success then
         Item.User_Authenticated := False;
         Item.Current_State := Closed;
         Item.Session_Open := False;
         Item.Session_Closed := True;
         Item.Session_Dirty := True;
         Item.Failure_Status := Authentication_Failed;
         return Authentication_Failed;
      end if;

      Item.User_Authenticated := True;
      Item.Authenticated_User_Name := To_Unbounded_String (User_Name);
      Item.Authentication_Method_Used := Password_Authentication;
      return Ok;
   exception
      when others =>
         Item.Session_Dirty := True;
         Item.Failure_Status := Internal_Error;
         return Internal_Error;
   end Run_Password_Userauth;

   function Run_Keyboard_Interactive_Userauth
     (Item : in out Session; User_Name : String; Password : String)
      return Status
   is
      Request_Buffer          : Packet_Buffer;
      Response_Buffer         : Packet_Buffer;
      Redacted_Response       : Packet_Buffer;
      Server_Challenge_Buffer : Packet_Buffer;
      Server_Final_Buffer     : Packet_Buffer;
      Reply_Value             : SSH_Lib.Protocol.Userauth.Reply;
      Status_Value            : Status;
   begin
      if not Item.Live_Userauth_IO_Enabled then
         Enable_For_Test (Item);
      end if;

      Request_Buffer :=
        SSH_Lib.Protocol.Userauth.Encode_Keyboard_Interactive_Request
          (User_Name);
      if Is_Empty (Request_Buffer) then
         Item.Session_Dirty := True;
         Item.Failure_Status := Authentication_Failed;
         return Authentication_Failed;
      end if;

      Status_Value := Send_Userauth_Payload (Item, Request_Buffer);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      Status_Value := Queue_Keyboard_Interactive_Info_Request_For_Test (Item);
      if Status_Value /= Ok then
         Item.Session_Dirty := True;
         Item.Failure_Status := Status_Value;
         return Status_Value;
      end if;

      Status_Value := Read_Userauth_Response (Item, Server_Challenge_Buffer);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Userauth.Parse_Userauth_Reply
          (To_Array (Server_Challenge_Buffer),
           SSH_Lib.Protocol.Userauth.Keyboard_Interactive_Reply,
           Reply_Value);
      if Status_Value /= Ok
        or else
          Reply_Value.Kind
          /= SSH_Lib.Protocol.Userauth.Keyboard_Interactive_Info_Request
        or else Reply_Value.Keyboard_Interactive_Prompts /= 1
        or else Reply_Value.Keyboard_Interactive_Echoes /= 0
      then
         Item.Session_Dirty := True;
         Item.Failure_Status := Authentication_Failed;
         return Authentication_Failed;
      end if;

      Response_Buffer :=
        SSH_Lib.Protocol.Userauth.Encode_Keyboard_Interactive_Response
          (Password);
      Redacted_Response :=
        SSH_Lib.Protocol.Userauth.Encode_Keyboard_Interactive_Response
          ("<redacted>");
      if Is_Empty (Response_Buffer) or else Is_Empty (Redacted_Response) then
         Item.Session_Dirty := True;
         Item.Failure_Status := Authentication_Failed;
         return Authentication_Failed;
      end if;

      Status_Value :=
        Send_Password_Userauth_Payload
          (Item, Response_Buffer, Redacted_Response);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      if Should_Reject_For_Test (User_Name) then
         Status_Value := Queue_Userauth_Failure_For_Test (Item);
      else
         Status_Value := Queue_Userauth_Success_For_Test (Item);
      end if;
      if Status_Value /= Ok then
         Item.Session_Dirty := True;
         Item.Failure_Status := Status_Value;
         return Status_Value;
      end if;

      Status_Value := Read_Userauth_Response (Item, Server_Final_Buffer);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Userauth.Parse_Userauth_Reply
          (To_Array (Server_Final_Buffer),
           SSH_Lib.Protocol.Userauth.Signed_Reply,
           Reply_Value);
      if Status_Value /= Ok then
         Item.Session_Dirty := True;
         Item.Failure_Status := Status_Value;
         return Status_Value;
      end if;

      if Reply_Value.Kind /= SSH_Lib.Protocol.Userauth.Auth_Success then
         Item.User_Authenticated := False;
         Item.Current_State := Closed;
         Item.Session_Open := False;
         Item.Session_Closed := True;
         Item.Session_Dirty := True;
         Item.Failure_Status := Authentication_Failed;
         return Authentication_Failed;
      end if;

      Item.User_Authenticated := True;
      Item.Authenticated_User_Name := To_Unbounded_String (User_Name);
      Item.Authentication_Method_Used := Keyboard_Interactive_Authentication;
      return Ok;
   exception
      when others =>
         Item.Session_Dirty := True;
         Item.Failure_Status := Internal_Error;
         return Internal_Error;
   end Run_Keyboard_Interactive_Userauth;

   function Last_Plain_Service_Request_For_Test
     (Item : Session) return Packet_Buffer is
   begin
      return Item.Live_Last_Plain_Service;
   end Last_Plain_Service_Request_For_Test;

   function Last_Protected_Service_Request_For_Test
     (Item : Session) return Packet_Buffer is
   begin
      return Item.Live_Last_Protected_Service;
   end Last_Protected_Service_Request_For_Test;

   function Last_Plain_Userauth_Payload_For_Test
     (Item : Session) return Packet_Buffer is
   begin
      return Item.Live_Last_Plain_Userauth;
   end Last_Plain_Userauth_Payload_For_Test;

   function Last_Protected_Userauth_Payload_For_Test
     (Item : Session) return Packet_Buffer is
   begin
      return Item.Live_Last_Protected_Userauth;
   end Last_Protected_Userauth_Payload_For_Test;

   function Last_Plain_Service_Response_For_Test
     (Item : Session) return Packet_Buffer is
   begin
      return Item.Live_Last_Plain_Service_Response;
   end Last_Plain_Service_Response_For_Test;

   function Last_Protected_Service_Response_For_Test
     (Item : Session) return Packet_Buffer is
   begin
      return Item.Live_Last_Protected_Service_Response;
   end Last_Protected_Service_Response_For_Test;

   function Last_Plain_Userauth_Response_For_Test
     (Item : Session) return Packet_Buffer is
   begin
      return Item.Live_Last_Plain_Userauth_Response;
   end Last_Plain_Userauth_Response_For_Test;

   function Last_Protected_Userauth_Response_For_Test
     (Item : Session) return Packet_Buffer is
   begin
      return Item.Live_Last_Protected_Userauth_Response;
   end Last_Protected_Userauth_Response_For_Test;

   function Last_Agent_Sign_Request_For_Test
     (Item : Session) return Packet_Buffer is
   begin
      return Item.Live_Last_Agent_Sign_Request;
   end Last_Agent_Sign_Request_For_Test;

   function Last_Agent_Sign_Response_For_Test
     (Item : Session) return Packet_Buffer is
   begin
      return Item.Live_Last_Agent_Sign_Response;
   end Last_Agent_Sign_Response_For_Test;
end SSH_Lib.Sessions.Userauth_IO;
