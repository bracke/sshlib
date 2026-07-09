with Ada.Directories;
with GNAT.OS_Lib;
with SSH_Lib.Protocol.Numbers;

package body SSH_Lib.Mux is
   use Ada.Streams;
   use Ada.Strings.Unbounded;
   use CryptoLib.Errors;
   use type Interfaces.Unsigned_32;

   function Kind_Code
     (Kind : Mux_Message_Kind) return Interfaces.Unsigned_32
   is
   begin
      case Kind is
         when Mux_Hello =>
            return 16#0000_0001#;
         when Mux_Alive_Check =>
            return 16#1000_0004#;
         when Mux_New_Session =>
            return 16#1000_0002#;
         when Mux_Terminate =>
            return 16#1000_0005#;
         when Mux_Open_Fwd =>
            return 16#1000_0006#;
         when Mux_Close_Fwd =>
            return 16#1000_0007#;
         when Mux_New_Stdio_Fwd =>
            return 16#1000_0008#;
         when Mux_Stop_Listening =>
            return 16#1000_0009#;
         when Mux_Proxy =>
            return 16#1000_000F#;
         when Mux_Ext_Info =>
            return 16#2000_0001#;
         when Mux_Ok =>
            return 16#8000_0001#;
         when Mux_Permission_Denied =>
            return 16#8000_0002#;
         when Mux_Failure =>
            return 16#8000_0003#;
         when Mux_Exit_Message =>
            return 16#8000_0004#;
         when Mux_Alive =>
            return 16#8000_0005#;
         when Mux_Session_Open =>
            return 16#8000_0006#;
         when Mux_Remote_Port =>
            return 16#8000_0007#;
         when Mux_TTY_Alloc_Fail =>
            return 16#8000_0008#;
         when Mux_Proxy_Response =>
            return 16#8000_000F#;
         when Mux_Ext_Info_Response =>
            return 16#9000_0001#;
         when Mux_Unknown =>
            return 0;
      end case;
   end Kind_Code;

   function Kind_For_Code
     (Code : Interfaces.Unsigned_32) return Mux_Message_Kind
   is
   begin
      case Code is
         when 16#0000_0001# =>
            return Mux_Hello;
         when 16#1000_0004# =>
            return Mux_Alive_Check;
         when 16#1000_0002# =>
            return Mux_New_Session;
         when 16#1000_0005# =>
            return Mux_Terminate;
         when 16#1000_0006# =>
            return Mux_Open_Fwd;
         when 16#1000_0007# =>
            return Mux_Close_Fwd;
         when 16#1000_0008# =>
            return Mux_New_Stdio_Fwd;
         when 16#1000_0009# =>
            return Mux_Stop_Listening;
         when 16#1000_000F# =>
            return Mux_Proxy;
         when 16#2000_0001# =>
            return Mux_Ext_Info;
         when 16#8000_0001# =>
            return Mux_Ok;
         when 16#8000_0002# =>
            return Mux_Permission_Denied;
         when 16#8000_0003# =>
            return Mux_Failure;
         when 16#8000_0004# =>
            return Mux_Exit_Message;
         when 16#8000_0005# =>
            return Mux_Alive;
         when 16#8000_0006# =>
            return Mux_Session_Open;
         when 16#8000_0007# =>
            return Mux_Remote_Port;
         when 16#8000_0008# =>
            return Mux_TTY_Alloc_Fail;
         when 16#8000_000F# =>
            return Mux_Proxy_Response;
         when 16#9000_0001# =>
            return Mux_Ext_Info_Response;
         when others =>
            return Mux_Unknown;
      end case;
   end Kind_For_Code;

   procedure Reset (Packet : out Mux_Message) is
   begin
      Packet.Kind := Mux_Unknown;
      Packet.Request_Id := 0;
      Packet.Reason := 0;
      Packet.Payload_Length := 0;
      Packet.Payload := [others => 0];
   end Reset;

   procedure Reset (Client : in out Mux_Client) is
   begin
      if Client.Connected then
         begin
            GNAT.Sockets.Close_Socket (Client.Socket);
         exception
            when others =>
               null;
         end;
      end if;
      Client.Connected := False;
      Client.Counted := False;
   end Reset;

   procedure Reset (Master : in out Mux_Master) is
   begin
      if Master.Listening then
         begin
            GNAT.Sockets.Close_Socket (Master.Socket);
         exception
            when others =>
               null;
         end;
      end if;
      if Length (Master.Control_Path) > 0 then
         declare
            Path_Text : constant String := To_String (Master.Control_Path);
            Deleted   : Boolean := False;
         begin
            GNAT.OS_Lib.Delete_File (Path_Text, Deleted);
         exception
            when others =>
               null;
         end;
      end if;
      Master.Listening := False;
      Master.Active_Clients := 0;
      Master.Control_Path := Null_Unbounded_String;
      Master.Server_Pid := 0;
   end Reset;

   function Forward_Type_Code
     (Kind : Mux_Forward_Type) return Interfaces.Unsigned_32
   is
   begin
      case Kind is
         when Mux_Forward_Local =>
            return 1;
         when Mux_Forward_Remote =>
            return 2;
         when Mux_Forward_Dynamic =>
            return 3;
         when Mux_Forward_Unknown =>
            return 0;
      end case;
   end Forward_Type_Code;

   function Forward_Type_For_Code
     (Code : Interfaces.Unsigned_32) return Mux_Forward_Type
   is
   begin
      case Code is
         when 1 =>
            return Mux_Forward_Local;
         when 2 =>
            return Mux_Forward_Remote;
         when 3 =>
            return Mux_Forward_Dynamic;
         when others =>
            return Mux_Forward_Unknown;
      end case;
   end Forward_Type_For_Code;

   function Append_U32
     (Target : in out Stream_Element_Array;
      Cursor : in out Stream_Element_Offset;
      Value  : Interfaces.Unsigned_32)
      return Status
   is
      Encoded : constant Stream_Element_Array :=
        SSH_Lib.Protocol.Numbers.Encode_Uint32 (Value);
   begin
      if Target'Last - Cursor + 1 < Encoded'Length then
         return Unsupported_Feature;
      end if;

      for Byte_Value of Encoded loop
         Target (Cursor) := Byte_Value;
         Cursor := Cursor + 1;
      end loop;
      return Ok;
   exception
      when others =>
         return Internal_Error;
   end Append_U32;

   function Append_String
     (Target : in out Stream_Element_Array;
      Cursor : in out Stream_Element_Offset;
      Value  : String)
      return Status
   is
      State : Status;
   begin
      if Value'Length > Max_Mux_Packet_Length
        or else Target'Last - Cursor + 1
          < Stream_Element_Offset (4 + Value'Length)
      then
         return Unsupported_Feature;
      end if;

      State := Append_U32
        (Target, Cursor, Interfaces.Unsigned_32 (Value'Length));
      if State /= Ok then
         return State;
      end if;

      for Character_Value of Value loop
         Target (Cursor) := Character'Pos (Character_Value);
         Cursor := Cursor + 1;
      end loop;
      return Ok;
   exception
      when others =>
         return Internal_Error;
   end Append_String;

   function Append_Flag
     (Target : in out Stream_Element_Array;
      Cursor : in out Stream_Element_Offset;
      Value  : Boolean)
      return Status
   is
   begin
      return Append_U32 (Target, Cursor, (if Value then 1 else 0));
   exception
      when others =>
         return Internal_Error;
   end Append_Flag;

   function Decode_Flag
     (Payload : Stream_Element_Array;
      Cursor  : in out Stream_Element_Offset;
      Value   : out Boolean)
      return Status
   is
      Flag_Value  : Interfaces.Unsigned_32 := 0;
      Next_Cursor : Stream_Element_Offset := Cursor;
   begin
      Value := False;
      if SSH_Lib.Protocol.Numbers.Decode_Uint32
           (Payload, Cursor, Flag_Value, Next_Cursor) /= Ok
      then
         return Invalid_Command;
      elsif Flag_Value = 0 then
         Value := False;
      elsif Flag_Value = 1 then
         Value := True;
      else
         return Invalid_Command;
      end if;
      Cursor := Next_Cursor;
      return Ok;
   exception
      when others =>
         Value := False;
         return Internal_Error;
   end Decode_Flag;

   procedure Reset_New_Session_Request
     (Request : out Mux_New_Session_Request)
   is
   begin
      Request.Reserved := Null_Unbounded_String;
      Request.Want_TTY := False;
      Request.Want_X11 := False;
      Request.Want_Agent := False;
      Request.Is_Subsystem := False;
      Request.Escape_Char := 16#FFFF_FFFF#;
      Request.Terminal_Type := Null_Unbounded_String;
      Request.Command := Null_Unbounded_String;
      Request.Environment := [others => Null_Unbounded_String];
      Request.Environment_Count := 0;
   end Reset_New_Session_Request;

   function Decode_String
     (Payload : Stream_Element_Array;
      Cursor  : in out Stream_Element_Offset;
      Value   : out Unbounded_String)
      return Status
   is
      Length_Value : Interfaces.Unsigned_32 := 0;
      Next_Cursor  : Stream_Element_Offset := Cursor;
   begin
      Value := Null_Unbounded_String;
      if SSH_Lib.Protocol.Numbers.Decode_Uint32
           (Payload, Cursor, Length_Value, Next_Cursor) /= Ok
      then
         return Invalid_Command;
      end if;

      Cursor := Next_Cursor;
      if Length_Value > Interfaces.Unsigned_32 (Max_Mux_Packet_Length)
        or else Payload'Last - Cursor + 1 < Stream_Element_Offset (Length_Value)
      then
         return Invalid_Command;
      end if;

      declare
         Text : String (1 .. Natural (Length_Value));
      begin
         for Index in Text'Range loop
            Text (Index) := Character'Val (Payload (Cursor));
            Cursor := Cursor + 1;
         end loop;
         Value := To_Unbounded_String (Text);
      end;
      return Ok;
   exception
      when others =>
         Value := Null_Unbounded_String;
         return Internal_Error;
   end Decode_String;

   function Send_All
     (Client : in out Mux_Client;
      Data   : Stream_Element_Array)
      return Status
   is
      First_Index : Stream_Element_Offset := Data'First;
      Last_Index  : Stream_Element_Offset;
   begin
      if Data'Length = 0 then
         return Ok;
      elsif not Client.Connected then
         return Write_Failed;
      end if;

      while First_Index <= Data'Last loop
         GNAT.Sockets.Send_Socket
           (Client.Socket, Data (First_Index .. Data'Last), Last_Index);
         if Last_Index < First_Index then
            Reset (Client);
            return Write_Failed;
         end if;
         First_Index := Last_Index + 1;
      end loop;
      return Ok;
   exception
      when GNAT.Sockets.Socket_Error =>
         Reset (Client);
         return Write_Failed;
      when others =>
         Reset (Client);
         return Internal_Error;
   end Send_All;

   function Read_Exact
     (Client : in out Mux_Client;
      Data   : out Stream_Element_Array)
      return Status
   is
      First_Index : Stream_Element_Offset := Data'First;
      Last_Index  : Stream_Element_Offset;
   begin
      if Data'Length = 0 then
         return Ok;
      elsif not Client.Connected then
         return Read_Failed;
      end if;

      while First_Index <= Data'Last loop
         GNAT.Sockets.Receive_Socket
           (Client.Socket, Data (First_Index .. Data'Last), Last_Index);
         if Last_Index < First_Index then
            Reset (Client);
            return Read_Failed;
         end if;
         First_Index := Last_Index + 1;
      end loop;
      return Ok;
   exception
      when GNAT.Sockets.Socket_Error =>
         Reset (Client);
         return Read_Failed;
      when others =>
         Reset (Client);
         return Internal_Error;
   end Read_Exact;

   function Encode
     (Kind       : Mux_Message_Kind;
      Request_Id : Interfaces.Unsigned_32;
      Payload    : Stream_Element_Array;
      Packet      : out Mux_Message)
      return Status
   is
   begin
      Reset (Packet);
      if Kind = Mux_Unknown then
         return Unsupported_Feature;
      elsif Payload'Length > Max_Mux_Packet_Length then
         return Unsupported_Feature;
      end if;

      Packet.Kind := Kind;
      Packet.Request_Id := Request_Id;
      Packet.Payload_Length := Payload'Length;
      for Offset in 0 .. Payload'Length - 1 loop
         Packet.Payload (Stream_Element_Offset (1 + Offset)) :=
           Payload (Payload'First + Stream_Element_Offset (Offset));
      end loop;
      return Ok;
   exception
      when others =>
         Reset (Packet);
         return Internal_Error;
   end Encode;

   function Decode
     (Data   : Stream_Element_Array;
      Packet : out Mux_Message)
      return Status
   is
      Cursor      : Stream_Element_Offset := Data'First;
      Next_Cursor : Stream_Element_Offset;
      Length      : Interfaces.Unsigned_32 := 0;
      Kind_Value  : Interfaces.Unsigned_32 := 0;
      Request     : Interfaces.Unsigned_32 := 0;
      Body_Length : Natural := 0;
   begin
      Reset (Packet);
      if Data'Length < 8 then
         return Invalid_Command;
      end if;

      if SSH_Lib.Protocol.Numbers.Decode_Uint32
           (Data, Cursor, Length, Next_Cursor) /= Ok
      then
         return Invalid_Command;
      end if;
      Cursor := Next_Cursor;

      if Natural (Length) /= Data'Length - 4
        or else Natural (Length) > Max_Mux_Packet_Length
        or else Natural (Length) < 4
      then
         return Invalid_Command;
      end if;

      if SSH_Lib.Protocol.Numbers.Decode_Uint32
           (Data, Cursor, Kind_Value, Next_Cursor) /= Ok
      then
         return Invalid_Command;
      end if;
      Cursor := Next_Cursor;

      Packet.Kind := Kind_For_Code (Kind_Value);
      if Packet.Kind = Mux_Unknown then
         return Unsupported_Feature;
      end if;

      Body_Length := Data'Length - Natural (Cursor - Data'First);
      if Packet.Kind /= Mux_Hello then
         if Body_Length < 4 then
            return Invalid_Command;
         end if;
         if SSH_Lib.Protocol.Numbers.Decode_Uint32
              (Data, Cursor, Request, Next_Cursor) /= Ok
         then
            return Invalid_Command;
         end if;
         Cursor := Next_Cursor;
         Packet.Request_Id := Request;
      end if;

      Packet.Payload_Length := Data'Length - Natural (Cursor - Data'First);
      for Offset in 0 .. Packet.Payload_Length - 1 loop
         Packet.Payload (Stream_Element_Offset (1 + Offset)) :=
           Data (Cursor + Stream_Element_Offset (Offset));
      end loop;
      return Ok;
   exception
      when others =>
         Reset (Packet);
         return Internal_Error;
   end Decode;

   function Frame
     (Packet : Mux_Message;
      Data   : out Stream_Element_Array;
      Last   : out Stream_Element_Offset)
      return Status
   is
      Request_Length : constant Natural :=
        (if Packet.Kind = Mux_Hello then 0 else 4);
      Needed : constant Natural := 8 + Request_Length + Packet.Payload_Length;
      Cursor : Stream_Element_Offset := Data'First;

      procedure Append (Bytes : Stream_Element_Array) is
      begin
         for Byte_Value of Bytes loop
            Data (Cursor) := Byte_Value;
            Cursor := Cursor + 1;
         end loop;
      end Append;
   begin
      Last := Data'First - 1;
      if Packet.Kind = Mux_Unknown
        or else Packet.Payload_Length > Max_Mux_Packet_Length
      then
         return Unsupported_Feature;
      elsif Data'Length < Needed then
         return Unsupported_Feature;
      end if;

      Append
        (SSH_Lib.Protocol.Numbers.Encode_Uint32
           (Interfaces.Unsigned_32 (Needed - 4)));
      Append (SSH_Lib.Protocol.Numbers.Encode_Uint32 (Kind_Code (Packet.Kind)));
      if Packet.Kind /= Mux_Hello then
         Append (SSH_Lib.Protocol.Numbers.Encode_Uint32 (Packet.Request_Id));
      end if;
      for Index in 1 .. Packet.Payload_Length loop
         Data (Cursor) := Packet.Payload (Stream_Element_Offset (Index));
         Cursor := Cursor + 1;
      end loop;
      Last := Cursor - 1;
      return Ok;
   exception
      when others =>
         Last := Data'First - 1;
         return Internal_Error;
   end Frame;

   function Is_Connected (Client : Mux_Client) return Boolean is
   begin
      return Client.Connected;
   end Is_Connected;

   procedure Close (Client : in out Mux_Client) is
   begin
      Reset (Client);
   end Close;

   function Detach_Control_Socket
     (Client : in out Mux_Client;
      Socket : out GNAT.Sockets.Socket_Type)
      return Status
   is
   begin
      if not Client.Connected then
         return Connection_Failed;
      end if;
      Socket := Client.Socket;
      Client.Connected := False;
      return Ok;
   exception
      when others =>
         return Internal_Error;
   end Detach_Control_Socket;

   function Connect_Control
     (Socket_Path : String;
      Client      : out Mux_Client)
      return Status
   is
      Address_Value : GNAT.Sockets.Sock_Addr_Type;
      Socket_Open   : Boolean := False;
   begin
      Client.Connected := False;
      Client.Counted := False;
      if Socket_Path'Length = 0 then
         return Connection_Failed;
      end if;

      GNAT.Sockets.Create_Socket
        (Client.Socket, GNAT.Sockets.Family_Unix, GNAT.Sockets.Socket_Stream);
      Socket_Open := True;
      Address_Value := GNAT.Sockets.Unix_Socket_Address (Socket_Path);
      GNAT.Sockets.Connect_Socket (Client.Socket, Address_Value);
      Client.Connected := True;
      return Ok;
   exception
      when GNAT.Sockets.Socket_Error =>
         if Socket_Open then
            begin
               GNAT.Sockets.Close_Socket (Client.Socket);
            exception
               when others =>
                  null;
            end;
         end if;
         Reset (Client);
         return Connection_Failed;
      when others =>
         if Socket_Open then
            begin
               GNAT.Sockets.Close_Socket (Client.Socket);
            exception
               when others =>
                  null;
            end;
         end if;
         Reset (Client);
         return Internal_Error;
   end Connect_Control;

   function Send_Message
     (Client : in out Mux_Client;
      Packet : Mux_Message)
      return Status
   is
      Request_Length : constant Natural :=
        (if Packet.Kind = Mux_Hello then 0 else 4);
      Data  : Stream_Element_Array
        (1 .. Stream_Element_Offset
          (8 + Request_Length + Packet.Payload_Length));
      Last  : Stream_Element_Offset := 0;
      State : Status;
   begin
      if not Client.Connected then
         return Write_Failed;
      end if;

      State := Frame (Packet, Data, Last);
      if State /= Ok then
         return State;
      end if;
      return Send_All (Client, Data (Data'First .. Last));
   exception
      when others =>
         Reset (Client);
         return Internal_Error;
   end Send_Message;

   function Receive_Message
     (Client : in out Mux_Client;
      Packet : out Mux_Message)
      return Status
   is
      Header      : Stream_Element_Array (1 .. 4);
      Cursor      : constant Stream_Element_Offset := Header'First;
      Next_Cursor : Stream_Element_Offset := Header'First;
      Length      : Interfaces.Unsigned_32 := 0;
      State       : Status;
   begin
      Reset (Packet);
      if not Client.Connected then
         return Read_Failed;
      end if;

      State := Read_Exact (Client, Header);
      if State /= Ok then
         Header := [others => 0];
         return State;
      end if;

      State :=
        SSH_Lib.Protocol.Numbers.Decode_Uint32
          (Header, Cursor, Length, Next_Cursor);
      Header := [others => 0];
      if State /= Ok
        or else Natural (Length) < 4
        or else Natural (Length) > Max_Mux_Packet_Length
      then
         Reset (Client);
         return Invalid_Command;
      end if;

      declare
         Body_Data : Stream_Element_Array
           (1 .. Stream_Element_Offset (Natural (Length)));
         Full : Stream_Element_Array
           (1 .. Stream_Element_Offset (Natural (Length) + 4));
      begin
         State := Read_Exact (Client, Body_Data);
         if State /= Ok then
            Body_Data := [others => 0];
            Full := [others => 0];
            return State;
         end if;

         Full (1 .. 4) := SSH_Lib.Protocol.Numbers.Encode_Uint32 (Length);
         Full (5 .. Full'Last) := Body_Data;
         Body_Data := [others => 0];
         State := Decode (Full, Packet);
         Full := [others => 0];
         if State /= Ok then
            Reset (Client);
         end if;
         return State;
      end;
   exception
      when others =>
         Reset (Client);
         Reset (Packet);
         return Internal_Error;
   end Receive_Message;

   function Send_File_Descriptors
     (Client      : in out Mux_Client;
      Descriptors : SSH_Lib.Platform.FD_Passing.File_Descriptor_Array)
      return Status
   is
   begin
      if not Client.Connected then
         return Write_Failed;
      end if;
      return SSH_Lib.Platform.FD_Passing.Send_File_Descriptors
        (Client.Socket, Descriptors);
   exception
      when others =>
         Reset (Client);
         return Internal_Error;
   end Send_File_Descriptors;

   function Receive_File_Descriptors
     (Client         : in out Mux_Client;
      Descriptors    : out SSH_Lib.Platform.FD_Passing.File_Descriptor_Array;
      Received_Count : out Natural)
      return Status
   is
      State : Status;
   begin
      Descriptors :=
        [others => SSH_Lib.Platform.FD_Passing.File_Descriptor (-1)];
      Received_Count := 0;
      if not Client.Connected then
         return Read_Failed;
      end if;

      State := SSH_Lib.Platform.FD_Passing.Receive_File_Descriptors
        (Client.Socket, Descriptors, Received_Count);
      if State /= Ok then
         Reset (Client);
      end if;
      return State;
   exception
      when others =>
         Descriptors :=
           [others => SSH_Lib.Platform.FD_Passing.File_Descriptor (-1)];
         Received_Count := 0;
         Reset (Client);
         return Internal_Error;
   end Receive_File_Descriptors;

   function Send_Stdio_File_Descriptors
     (Client    : in out Mux_Client;
      Stdin_FD  : SSH_Lib.Platform.FD_Passing.File_Descriptor;
      Stdout_FD : SSH_Lib.Platform.FD_Passing.File_Descriptor;
      Stderr_FD : SSH_Lib.Platform.FD_Passing.File_Descriptor)
      return Status
   is
      State : Status;
   begin
      State := Send_File_Descriptors (Client, [1 => Stdin_FD]);
      if State /= Ok then
         return State;
      end if;
      State := Send_File_Descriptors (Client, [1 => Stdout_FD]);
      if State /= Ok then
         return State;
      end if;
      return Send_File_Descriptors (Client, [1 => Stderr_FD]);
   exception
      when others =>
         Reset (Client);
         return Internal_Error;
   end Send_Stdio_File_Descriptors;

   function Receive_Stdio_File_Descriptors
     (Client    : in out Mux_Client;
      Stdin_FD  : out SSH_Lib.Platform.FD_Passing.File_Descriptor;
      Stdout_FD : out SSH_Lib.Platform.FD_Passing.File_Descriptor;
      Stderr_FD : out SSH_Lib.Platform.FD_Passing.File_Descriptor)
      return Status
   is
      Descriptors : SSH_Lib.Platform.FD_Passing.File_Descriptor_Array (1 .. 1);
      Count       : Natural := 0;
      State       : Status;
   begin
      Stdin_FD := SSH_Lib.Platform.FD_Passing.File_Descriptor (-1);
      Stdout_FD := SSH_Lib.Platform.FD_Passing.File_Descriptor (-1);
      Stderr_FD := SSH_Lib.Platform.FD_Passing.File_Descriptor (-1);

      State := Receive_File_Descriptors (Client, Descriptors, Count);
      if State /= Ok then
         return State;
      elsif Count /= 1 then
         Reset (Client);
         return Invalid_Command;
      end if;
      Stdin_FD := Descriptors (1);

      State := Receive_File_Descriptors (Client, Descriptors, Count);
      if State /= Ok then
         return State;
      elsif Count /= 1 then
         Reset (Client);
         return Invalid_Command;
      end if;
      Stdout_FD := Descriptors (1);

      State := Receive_File_Descriptors (Client, Descriptors, Count);
      if State /= Ok then
         return State;
      elsif Count /= 1 then
         Reset (Client);
         return Invalid_Command;
      end if;
      Stderr_FD := Descriptors (1);
      return Ok;
   exception
      when others =>
         Stdin_FD := SSH_Lib.Platform.FD_Passing.File_Descriptor (-1);
         Stdout_FD := SSH_Lib.Platform.FD_Passing.File_Descriptor (-1);
         Stderr_FD := SSH_Lib.Platform.FD_Passing.File_Descriptor (-1);
         Reset (Client);
         return Internal_Error;
   end Receive_Stdio_File_Descriptors;

   function Request
     (Client     : in out Mux_Client;
      Kind       : Mux_Message_Kind;
      Request_Id : Interfaces.Unsigned_32;
      Payload    : Stream_Element_Array;
      Response   : out Mux_Message)
      return Status
   is
      Packet : Mux_Message;
      State  : Status;
   begin
      State := Encode (Kind, Request_Id, Payload, Packet);
      if State /= Ok then
         Reset (Response);
         return State;
      end if;

      State := Send_Message (Client, Packet);
      if State /= Ok then
         Reset (Response);
         return State;
      end if;
      return Receive_Message (Client, Response);
   exception
      when others =>
         Reset (Client);
         Reset (Response);
         return Internal_Error;
   end Request;

   function Alive_Check
     (Client     : in out Mux_Client;
      Request_Id : Interfaces.Unsigned_32;
      Response   : out Mux_Message)
      return Status
   is
      Empty_Payload : constant Stream_Element_Array (1 .. 0) := [others => 0];
   begin
      return Request
        (Client, Mux_Alive_Check, Request_Id, Empty_Payload, Response);
   end Alive_Check;

   function Encode_Hello
     (Version : Interfaces.Unsigned_32;
      Packet  : out Mux_Message)
      return Status
   is
      Payload : Stream_Element_Array (1 .. 4);
   begin
      Payload := SSH_Lib.Protocol.Numbers.Encode_Uint32 (Version);
      return Encode (Mux_Hello, 0, Payload, Packet);
   exception
      when others =>
         Reset (Packet);
         return Internal_Error;
   end Encode_Hello;

   function Decode_Hello
     (Packet  : Mux_Message;
      Version : out Interfaces.Unsigned_32)
      return Status
   is
      Cursor      : constant Stream_Element_Offset := Packet.Payload'First;
      Next_Cursor : Stream_Element_Offset := Packet.Payload'First;
   begin
      Version := 0;
      if Packet.Kind /= Mux_Hello or else Packet.Payload_Length < 4 then
         return Invalid_Command;
      end if;

      if SSH_Lib.Protocol.Numbers.Decode_Uint32
           (Packet.Payload
              (Packet.Payload'First
               .. Packet.Payload'First
                  + Stream_Element_Offset (Packet.Payload_Length)
                  - 1),
            Cursor,
            Version,
            Next_Cursor) /= Ok
      then
         Version := 0;
         return Invalid_Command;
      end if;

      return Ok;
   exception
      when others =>
         Version := 0;
         return Internal_Error;
   end Decode_Hello;

   function Exchange_Hello
     (Client       : in out Mux_Client;
      Peer_Version : out Interfaces.Unsigned_32)
      return Status
   is
      Hello_Message : Mux_Message;
      Peer_Hello    : Mux_Message;
      State         : Status;
   begin
      Peer_Version := 0;
      State := Encode_Hello (Mux_Protocol_Version, Hello_Message);
      if State /= Ok then
         return State;
      end if;

      State := Send_Message (Client, Hello_Message);
      if State /= Ok then
         return State;
      end if;

      State := Receive_Message (Client, Peer_Hello);
      if State /= Ok then
         return State;
      end if;

      State := Decode_Hello (Peer_Hello, Peer_Version);
      if State /= Ok then
         return State;
      elsif Peer_Version /= Mux_Protocol_Version then
         return Unsupported_Feature;
      end if;
      return Ok;
   exception
      when others =>
         Peer_Version := 0;
         Reset (Client);
         return Internal_Error;
   end Exchange_Hello;

   function Terminate_Master
     (Client     : in out Mux_Client;
      Request_Id : Interfaces.Unsigned_32;
      Response   : out Mux_Message)
      return Status
   is
      Empty_Payload : constant Stream_Element_Array (1 .. 0) := [others => 0];
   begin
      return Request
        (Client, Mux_Terminate, Request_Id, Empty_Payload, Response);
   end Terminate_Master;

   function Stop_Listening
     (Client     : in out Mux_Client;
      Request_Id : Interfaces.Unsigned_32;
      Response   : out Mux_Message)
      return Status
   is
      Empty_Payload : constant Stream_Element_Array (1 .. 0) := [others => 0];
   begin
      return Request
        (Client, Mux_Stop_Listening, Request_Id, Empty_Payload, Response);
   end Stop_Listening;

   function Encode_Forward_Request
     (Request : Mux_Forward_Request;
      Payload : out Stream_Element_Array;
      Last    : out Stream_Element_Offset)
      return Status
   is
      Cursor : Stream_Element_Offset := Payload'First;
      State  : Status;
   begin
      Last := Payload'First - 1;
      Payload := [others => 0];
      if Request.Forward_Type = Mux_Forward_Unknown then
         return Unsupported_Feature;
      end if;

      State := Append_U32
        (Payload, Cursor, Forward_Type_Code (Request.Forward_Type));
      if State /= Ok then
         return State;
      end if;

      State := Append_String (Payload, Cursor, To_String (Request.Listen_Host));
      if State /= Ok then
         return State;
      end if;

      State := Append_U32 (Payload, Cursor, Request.Listen_Port);
      if State /= Ok then
         return State;
      end if;

      State := Append_String (Payload, Cursor, To_String (Request.Connect_Host));
      if State /= Ok then
         return State;
      end if;

      State := Append_U32 (Payload, Cursor, Request.Connect_Port);
      if State /= Ok then
         return State;
      end if;

      Last := Cursor - 1;
      return Ok;
   exception
      when others =>
         Last := Payload'First - 1;
         Payload := [others => 0];
         return Internal_Error;
   end Encode_Forward_Request;

   function Decode_Forward_Request
     (Payload : Stream_Element_Array;
      Request : out Mux_Forward_Request)
      return Status
   is
      Cursor      : Stream_Element_Offset := Payload'First;
      Next_Cursor : Stream_Element_Offset := Payload'First;
      Kind_Code   : Interfaces.Unsigned_32 := 0;
      State       : Status;
   begin
      Request.Forward_Type := Mux_Forward_Unknown;
      Request.Listen_Host := Null_Unbounded_String;
      Request.Listen_Port := 0;
      Request.Connect_Host := Null_Unbounded_String;
      Request.Connect_Port := 0;

      State := SSH_Lib.Protocol.Numbers.Decode_Uint32
        (Payload, Cursor, Kind_Code, Next_Cursor);
      if State /= Ok then
         return Invalid_Command;
      end if;
      Cursor := Next_Cursor;
      Request.Forward_Type := Forward_Type_For_Code (Kind_Code);
      if Request.Forward_Type = Mux_Forward_Unknown then
         return Unsupported_Feature;
      end if;

      State := Decode_String (Payload, Cursor, Request.Listen_Host);
      if State /= Ok then
         return State;
      end if;

      State := SSH_Lib.Protocol.Numbers.Decode_Uint32
        (Payload, Cursor, Request.Listen_Port, Next_Cursor);
      if State /= Ok then
         return Invalid_Command;
      end if;
      Cursor := Next_Cursor;

      State := Decode_String (Payload, Cursor, Request.Connect_Host);
      if State /= Ok then
         return State;
      end if;

      State := SSH_Lib.Protocol.Numbers.Decode_Uint32
        (Payload, Cursor, Request.Connect_Port, Next_Cursor);
      if State /= Ok then
         return Invalid_Command;
      end if;
      Cursor := Next_Cursor;

      if Cursor /= Payload'Last + 1 then
         return Invalid_Command;
      end if;
      return Ok;
   exception
      when others =>
         Request.Forward_Type := Mux_Forward_Unknown;
         Request.Listen_Host := Null_Unbounded_String;
         Request.Listen_Port := 0;
         Request.Connect_Host := Null_Unbounded_String;
         Request.Connect_Port := 0;
         return Internal_Error;
   end Decode_Forward_Request;

   function Encode_Reason_Response
     (Kind       : Mux_Message_Kind;
      Request_Id : Interfaces.Unsigned_32;
      Reason     : String;
      Response   : out Mux_Message)
      return Status
   is
      Payload : Stream_Element_Array
        (1 .. Stream_Element_Offset (4 + Reason'Length)) := [others => 0];
      Cursor  : Stream_Element_Offset := Payload'First;
      State   : Status;
   begin
      if Kind not in Mux_Permission_Denied | Mux_Failure then
         Reset (Response);
         return Unsupported_Feature;
      end if;

      State := Append_String (Payload, Cursor, Reason);
      if State /= Ok then
         Reset (Response);
         return State;
      end if;

      return Encode
        (Kind, Request_Id, Payload (Payload'First .. Cursor - 1), Response);
   exception
      when others =>
         Reset (Response);
         return Internal_Error;
   end Encode_Reason_Response;

   function Decode_Reason
     (Payload : Stream_Element_Array;
      Reason  : out Unbounded_String)
      return Status
   is
      Cursor : Stream_Element_Offset := Payload'First;
      State  : Status;
   begin
      Reason := Null_Unbounded_String;
      State := Decode_String (Payload, Cursor, Reason);
      if State /= Ok then
         return State;
      elsif Cursor /= Payload'Last + 1 then
         Reason := Null_Unbounded_String;
         return Invalid_Command;
      end if;
      return Ok;
   exception
      when others =>
         Reason := Null_Unbounded_String;
         return Internal_Error;
   end Decode_Reason;

   function Encode_New_Session_Request
     (Request : Mux_New_Session_Request;
      Payload : out Stream_Element_Array;
      Last    : out Stream_Element_Offset)
      return Status
   is
      Cursor : Stream_Element_Offset := Payload'First;
      State  : Status;
   begin
      Last := Payload'First - 1;
      Payload := [others => 0];
      if Request.Environment_Count > Max_Mux_Environment then
         return Unsupported_Feature;
      end if;

      State := Append_String (Payload, Cursor, To_String (Request.Reserved));
      if State /= Ok then
         return State;
      end if;
      State := Append_Flag (Payload, Cursor, Request.Want_TTY);
      if State /= Ok then
         return State;
      end if;
      State := Append_Flag (Payload, Cursor, Request.Want_X11);
      if State /= Ok then
         return State;
      end if;
      State := Append_Flag (Payload, Cursor, Request.Want_Agent);
      if State /= Ok then
         return State;
      end if;
      State := Append_Flag (Payload, Cursor, Request.Is_Subsystem);
      if State /= Ok then
         return State;
      end if;
      State := Append_U32 (Payload, Cursor, Request.Escape_Char);
      if State /= Ok then
         return State;
      end if;
      State := Append_String (Payload, Cursor, To_String (Request.Terminal_Type));
      if State /= Ok then
         return State;
      end if;
      State := Append_String (Payload, Cursor, To_String (Request.Command));
      if State /= Ok then
         return State;
      end if;

      for Index in 1 .. Request.Environment_Count loop
         State := Append_String
           (Payload, Cursor, To_String (Request.Environment (Index)));
         if State /= Ok then
            return State;
         end if;
      end loop;

      Last := Cursor - 1;
      return Ok;
   exception
      when others =>
         Last := Payload'First - 1;
         Payload := [others => 0];
         return Internal_Error;
   end Encode_New_Session_Request;

   function Decode_New_Session_Request
     (Payload : Stream_Element_Array;
      Request : out Mux_New_Session_Request)
      return Status
   is
      Cursor      : Stream_Element_Offset := Payload'First;
      Next_Cursor : Stream_Element_Offset := Payload'First;
      State       : Status;
   begin
      Reset_New_Session_Request (Request);

      State := Decode_String (Payload, Cursor, Request.Reserved);
      if State /= Ok then
         return State;
      end if;
      State := Decode_Flag (Payload, Cursor, Request.Want_TTY);
      if State /= Ok then
         return State;
      end if;
      State := Decode_Flag (Payload, Cursor, Request.Want_X11);
      if State /= Ok then
         return State;
      end if;
      State := Decode_Flag (Payload, Cursor, Request.Want_Agent);
      if State /= Ok then
         return State;
      end if;
      State := Decode_Flag (Payload, Cursor, Request.Is_Subsystem);
      if State /= Ok then
         return State;
      end if;
      State := SSH_Lib.Protocol.Numbers.Decode_Uint32
        (Payload, Cursor, Request.Escape_Char, Next_Cursor);
      if State /= Ok then
         return Invalid_Command;
      end if;
      Cursor := Next_Cursor;
      State := Decode_String (Payload, Cursor, Request.Terminal_Type);
      if State /= Ok then
         return State;
      end if;
      State := Decode_String (Payload, Cursor, Request.Command);
      if State /= Ok then
         return State;
      end if;

      while Cursor <= Payload'Last loop
         if Request.Environment_Count >= Max_Mux_Environment then
            Reset_New_Session_Request (Request);
            return Unsupported_Feature;
         end if;
         Request.Environment_Count := Request.Environment_Count + 1;
         State := Decode_String
           (Payload,
            Cursor,
            Request.Environment (Request.Environment_Count));
         if State /= Ok then
            Reset_New_Session_Request (Request);
            return State;
         end if;
      end loop;

      return Ok;
   exception
      when others =>
         Reset_New_Session_Request (Request);
         return Internal_Error;
   end Decode_New_Session_Request;

   function Decode_Single_U32_Payload
     (Packet        : Mux_Message;
      Expected_Kind : Mux_Message_Kind;
      Value         : out Interfaces.Unsigned_32)
      return Status
   is
      Cursor      : constant Stream_Element_Offset := Packet.Payload'First;
      Next_Cursor : Stream_Element_Offset := Packet.Payload'First;
   begin
      Value := 0;
      if Packet.Kind /= Expected_Kind or else Packet.Payload_Length /= 4 then
         return Invalid_Command;
      end if;

      if SSH_Lib.Protocol.Numbers.Decode_Uint32
           (Packet.Payload
              (Packet.Payload'First
               .. Packet.Payload'First
                  + Stream_Element_Offset (Packet.Payload_Length)
                  - 1),
            Cursor,
            Value,
            Next_Cursor) /= Ok
      then
         Value := 0;
         return Invalid_Command;
      end if;
      return Ok;
   exception
      when others =>
         Value := 0;
         return Internal_Error;
   end Decode_Single_U32_Payload;

   function Encode_Session_Opened
     (Request_Id : Interfaces.Unsigned_32;
      Session_Id : Interfaces.Unsigned_32;
      Response   : out Mux_Message)
      return Status
   is
      Payload : constant Stream_Element_Array :=
        SSH_Lib.Protocol.Numbers.Encode_Uint32 (Session_Id);
   begin
      return Encode (Mux_Session_Open, Request_Id, Payload, Response);
   exception
      when others =>
         Reset (Response);
         return Internal_Error;
   end Encode_Session_Opened;

   function Decode_Session_Opened
     (Packet     : Mux_Message;
      Session_Id : out Interfaces.Unsigned_32)
      return Status
   is
   begin
      return Decode_Single_U32_Payload
        (Packet, Mux_Session_Open, Session_Id);
   end Decode_Session_Opened;

   function Encode_Remote_Port
     (Request_Id  : Interfaces.Unsigned_32;
      Remote_Port : Interfaces.Unsigned_32;
      Response    : out Mux_Message)
      return Status
   is
      Payload : constant Stream_Element_Array :=
        SSH_Lib.Protocol.Numbers.Encode_Uint32 (Remote_Port);
   begin
      return Encode (Mux_Remote_Port, Request_Id, Payload, Response);
   exception
      when others =>
         Reset (Response);
         return Internal_Error;
   end Encode_Remote_Port;

   function Decode_Remote_Port
     (Packet      : Mux_Message;
      Remote_Port : out Interfaces.Unsigned_32)
      return Status
   is
   begin
      return Decode_Single_U32_Payload
        (Packet, Mux_Remote_Port, Remote_Port);
   end Decode_Remote_Port;

   function Encode_Exit_Message
     (Session_Id : Interfaces.Unsigned_32;
      Exit_Value : Interfaces.Unsigned_32;
      Response   : out Mux_Message)
      return Status
   is
      Payload : constant Stream_Element_Array :=
        SSH_Lib.Protocol.Numbers.Encode_Uint32 (Exit_Value);
   begin
      return Encode (Mux_Exit_Message, Session_Id, Payload, Response);
   exception
      when others =>
         Reset (Response);
         return Internal_Error;
   end Encode_Exit_Message;

   function Decode_Exit_Message
     (Packet     : Mux_Message;
      Session_Id : out Interfaces.Unsigned_32;
      Exit_Value : out Interfaces.Unsigned_32)
      return Status
   is
      State : Status;
   begin
      Session_Id := 0;
      Exit_Value := 0;
      State := Decode_Single_U32_Payload
        (Packet, Mux_Exit_Message, Exit_Value);
      if State /= Ok then
         return State;
      end if;
      Session_Id := Packet.Request_Id;
      return Ok;
   exception
      when others =>
         Session_Id := 0;
         Exit_Value := 0;
         return Internal_Error;
   end Decode_Exit_Message;

   function Encode_TTY_Alloc_Fail
     (Session_Id : Interfaces.Unsigned_32;
      Response   : out Mux_Message)
      return Status
   is
      Empty_Payload : constant Stream_Element_Array (1 .. 0) := [others => 0];
   begin
      return Encode (Mux_TTY_Alloc_Fail, Session_Id, Empty_Payload, Response);
   exception
      when others =>
         Reset (Response);
         return Internal_Error;
   end Encode_TTY_Alloc_Fail;

   function Decode_TTY_Alloc_Fail
     (Packet     : Mux_Message;
      Session_Id : out Interfaces.Unsigned_32)
      return Status
   is
   begin
      Session_Id := 0;
      if Packet.Kind /= Mux_TTY_Alloc_Fail or else Packet.Payload_Length /= 0 then
         return Invalid_Command;
      end if;
      Session_Id := Packet.Request_Id;
      return Ok;
   exception
      when others =>
         Session_Id := 0;
         return Internal_Error;
   end Decode_TTY_Alloc_Fail;

   function Encode_Ext_Info
     (Request_Id : Interfaces.Unsigned_32;
      Extensions : Interfaces.Unsigned_32;
      Response   : out Mux_Message)
      return Status
   is
      Payload : constant Stream_Element_Array :=
        SSH_Lib.Protocol.Numbers.Encode_Uint32 (Extensions);
   begin
      return Encode (Mux_Ext_Info_Response, Request_Id, Payload, Response);
   exception
      when others =>
         Reset (Response);
         return Internal_Error;
   end Encode_Ext_Info;

   function Decode_Ext_Info
     (Packet     : Mux_Message;
      Extensions : out Interfaces.Unsigned_32)
      return Status
   is
   begin
      return Decode_Single_U32_Payload
        (Packet, Mux_Ext_Info_Response, Extensions);
   end Decode_Ext_Info;

   function Encode_Proxy_Response
     (Request_Id : Interfaces.Unsigned_32;
      Response   : out Mux_Message)
      return Status
   is
      Empty_Payload : constant Stream_Element_Array (1 .. 0) := [others => 0];
   begin
      return Encode (Mux_Proxy_Response, Request_Id, Empty_Payload, Response);
   exception
      when others =>
         Reset (Response);
         return Internal_Error;
   end Encode_Proxy_Response;

   function Validate_Backend_Response
     (Decision : Mux_Master_Decision;
      Request  : Mux_Message;
      Response : Mux_Message)
      return Status
   is
   begin
      if Response.Kind in Mux_Failure | Mux_Permission_Denied then
         if Response.Request_Id /= Request.Request_Id then
            return Invalid_Command;
         end if;
         return Ok;
      end if;

      case Decision is
         when Mux_New_Session_Decision =>
            if Response.Kind /= Mux_Session_Open then
               return Invalid_Command;
            end if;
         when Mux_Open_Forward_Decision =>
            if Response.Kind not in Mux_Ok | Mux_Remote_Port then
               return Invalid_Command;
            end if;
         when Mux_Close_Forward_Decision
            | Mux_New_Stdio_Forward_Decision =>
            if Response.Kind /= Mux_Ok then
               return Invalid_Command;
            end if;
         when Mux_Proxy_Decision =>
            if Response.Kind /= Mux_Proxy_Response then
               return Invalid_Command;
            end if;
         when others =>
            return Ok;
      end case;

      if Response.Request_Id /= Request.Request_Id then
         return Invalid_Command;
      end if;
      return Ok;
   exception
      when others =>
         return Internal_Error;
   end Validate_Backend_Response;

   function Is_Listening (Master : Mux_Master) return Boolean is
   begin
      return Master.Listening;
   end Is_Listening;

   procedure Close_Master (Master : in out Mux_Master) is
   begin
      Reset (Master);
   end Close_Master;

   function Start_Master
     (Socket_Path      : String;
      Master           : out Mux_Master;
      Replace_Existing : Boolean := False;
      Persist_Seconds  : Natural := 0;
      Server_Pid       : Interfaces.Unsigned_32 := 0)
      return Status
   is
      Address_Value : GNAT.Sockets.Sock_Addr_Type;
      Socket_Open   : Boolean := False;
   begin
      Master.Listening := False;
      Master.Active_Clients := 0;
      Master.Control_Path := Null_Unbounded_String;
      Master.Persist_Seconds := Persist_Seconds;
      Master.Server_Pid := Server_Pid;
      if Socket_Path'Length = 0 then
         return Connection_Failed;
      elsif Ada.Directories.Exists (Socket_Path) then
         if Replace_Existing then
            Ada.Directories.Delete_File (Socket_Path);
         else
            return Connection_Failed;
         end if;
      end if;

      Master.Control_Path := To_Unbounded_String (Socket_Path);
      GNAT.Sockets.Create_Socket
        (Master.Socket, GNAT.Sockets.Family_Unix, GNAT.Sockets.Socket_Stream);
      Socket_Open := True;
      Address_Value := GNAT.Sockets.Unix_Socket_Address (Socket_Path);
      GNAT.Sockets.Bind_Socket (Master.Socket, Address_Value);
      GNAT.Sockets.Listen_Socket (Master.Socket, 16);
      Master.Listening := True;
      Master.Persist_Seconds := Persist_Seconds;
      Master.Server_Pid := Server_Pid;
      return Ok;
   exception
      when GNAT.Sockets.Socket_Error =>
         if Socket_Open then
            begin
               GNAT.Sockets.Close_Socket (Master.Socket);
            exception
               when others =>
                  null;
            end;
         end if;
         Reset (Master);
         return Connection_Failed;
      when others =>
         if Socket_Open then
            begin
               GNAT.Sockets.Close_Socket (Master.Socket);
            exception
               when others =>
                  null;
            end;
         end if;
         Reset (Master);
         return Internal_Error;
   end Start_Master;

   function Accept_Control
     (Master : in out Mux_Master;
      Client : out Mux_Client)
      return Status
   is
      Peer_Address : GNAT.Sockets.Sock_Addr_Type;
   begin
      Client.Connected := False;
      Client.Counted := False;
      if not Master.Listening then
         return Connection_Failed;
      end if;

      GNAT.Sockets.Accept_Socket (Master.Socket, Client.Socket, Peer_Address);
      Client.Connected := True;
      Client.Counted := True;
      if Master.Active_Clients < Natural'Last then
         Master.Active_Clients := Master.Active_Clients + 1;
      end if;
      return Ok;
   exception
      when GNAT.Sockets.Socket_Error =>
         Reset (Client);
         return Connection_Failed;
      when others =>
         Reset (Client);
         return Internal_Error;
   end Accept_Control;

   procedure Release_Control
     (Master : in out Mux_Master;
      Client : in out Mux_Client)
   is
   begin
      if Client.Counted and then Master.Active_Clients > 0 then
         Master.Active_Clients := Master.Active_Clients - 1;
      end if;
      Close (Client);
   end Release_Control;

   procedure Configure_Persist
     (Master          : in out Mux_Master;
      Persist_Seconds : Natural)
   is
   begin
      Master.Persist_Seconds := Persist_Seconds;
   end Configure_Persist;

   function Persist_Seconds_Of (Master : Mux_Master) return Natural is
   begin
      return Master.Persist_Seconds;
   end Persist_Seconds_Of;

   function Server_Pid_Of (Master : Mux_Master) return Interfaces.Unsigned_32 is
   begin
      return Master.Server_Pid;
   end Server_Pid_Of;

   function Active_Client_Count (Master : Mux_Master) return Natural is
   begin
      return Master.Active_Clients;
   end Active_Client_Count;

   function Should_Terminate_When_Idle
     (Master       : Mux_Master;
      Idle_Seconds : Natural)
      return Boolean
   is
   begin
      if Master.Active_Clients > 0 then
         return False;
      elsif Master.Persist_Seconds = Natural'Last then
         return False;
      end if;
      return Idle_Seconds >= Master.Persist_Seconds;
   end Should_Terminate_When_Idle;

   function Classify_Master_Request
     (Request  : Mux_Message;
      Decision : out Mux_Master_Decision)
      return Status
   is
      Forward_Request : Mux_Forward_Request;
      Session_Request : Mux_New_Session_Request;
      Payload_First   : constant Stream_Element_Offset := Request.Payload'First;
      Payload_Last    : constant Stream_Element_Offset :=
        Request.Payload'First + Stream_Element_Offset (Request.Payload_Length) - 1;
   begin
      Decision := Mux_Reject_Decision;
      case Request.Kind is
         when Mux_Alive_Check =>
            if Request.Payload_Length /= 0 then
               return Invalid_Command;
            end if;
            Decision := Mux_Continue;
            return Ok;
         when Mux_Terminate =>
            if Request.Payload_Length /= 0 then
               return Invalid_Command;
            end if;
            Decision := Mux_Terminate_Decision;
            return Ok;
         when Mux_Stop_Listening =>
            if Request.Payload_Length /= 0 then
               return Invalid_Command;
            end if;
            Decision := Mux_Stop_Listening_Decision;
            return Ok;
         when Mux_New_Session =>
            if Request.Payload_Length = 0 then
               return Invalid_Command;
            end if;
            declare
               State : constant Status :=
                 Decode_New_Session_Request
                   (Request.Payload (Payload_First .. Payload_Last),
                    Session_Request);
            begin
               if State /= Ok then
                  return State;
               end if;
            end;
            Decision := Mux_New_Session_Decision;
            return Ok;
         when Mux_Open_Fwd | Mux_Close_Fwd =>
            if Request.Payload_Length = 0 then
               return Invalid_Command;
            end if;
            declare
               State : constant Status :=
                 Decode_Forward_Request
                   (Request.Payload (Payload_First .. Payload_Last),
                    Forward_Request);
            begin
               if State /= Ok then
                  return State;
               end if;
            end;
            Decision :=
              (if Request.Kind = Mux_Open_Fwd
               then Mux_Open_Forward_Decision
               else Mux_Close_Forward_Decision);
            return Ok;
         when Mux_New_Stdio_Fwd =>
            if Request.Payload_Length = 0 then
               return Invalid_Command;
            end if;
            declare
               State : constant Status :=
                 Decode_Forward_Request
                   (Request.Payload (Payload_First .. Payload_Last),
                    Forward_Request);
            begin
               if State /= Ok then
                  return State;
               end if;
            end;
            Decision := Mux_New_Stdio_Forward_Decision;
            return Ok;
         when Mux_Proxy =>
            if Request.Payload_Length /= 0 then
               return Invalid_Command;
            end if;
            Decision := Mux_Proxy_Decision;
            return Ok;
         when Mux_Ext_Info =>
            if Request.Payload_Length /= 0 then
               return Invalid_Command;
            end if;
            Decision := Mux_Ext_Info_Decision;
            return Ok;
         when others =>
            return Unsupported_Feature;
      end case;
   exception
      when others =>
         Decision := Mux_Reject_Decision;
         return Internal_Error;
   end Classify_Master_Request;

   function Route_Master_Request
     (Master   : in out Mux_Master;
      Request  : Mux_Message;
      Response : out Mux_Message;
      Decision : out Mux_Master_Decision)
      return Status
   is
      Empty_Payload : constant Stream_Element_Array (1 .. 0) := [others => 0];
      State         : Status;
   begin
      Decision := Mux_Reject_Decision;
      Reset (Response);
      State := Classify_Master_Request (Request, Decision);
      if State /= Ok then
         Decision := Mux_Reject_Decision;
         return State;
      end if;

      case Request.Kind is
         when Mux_Alive_Check =>
            declare
               Pid_Payload : constant Stream_Element_Array :=
                 SSH_Lib.Protocol.Numbers.Encode_Uint32 (Master.Server_Pid);
            begin
               return Encode
                 (Mux_Alive, Request.Request_Id, Pid_Payload, Response);
            end;
         when Mux_Terminate =>
            return Encode
              (Mux_Ok, Request.Request_Id, Empty_Payload, Response);
         when Mux_Stop_Listening =>
            return Encode
              (Mux_Ok, Request.Request_Id, Empty_Payload, Response);
         when Mux_Ext_Info =>
            return Encode_Ext_Info (Request.Request_Id, 0, Response);
         when Mux_New_Session
            | Mux_Open_Fwd
            | Mux_Close_Fwd
            | Mux_New_Stdio_Fwd
            | Mux_Proxy =>
            return Encode_Reason_Response
              (Mux_Failure,
               Request.Request_Id,
               "mux request requires caller backend",
               Response);
         when others =>
            Decision := Mux_Reject_Decision;
            return Unsupported_Feature;
      end case;
   exception
      when others =>
         Reset (Response);
         Decision := Mux_Reject_Decision;
         return Internal_Error;
   end Route_Master_Request;

   function Route_Master_Request
     (Master   : in out Mux_Master;
      Client   : in out Mux_Client;
      Request  : Mux_Message;
      Handlers : Mux_Master_Handlers;
      Response : out Mux_Message;
      Decision : out Mux_Master_Decision)
      return Status
   is
      State : Status;
   begin
      Decision := Mux_Reject_Decision;
      Reset (Response);
      State := Classify_Master_Request (Request, Decision);
      if State /= Ok then
         Decision := Mux_Reject_Decision;
         return State;
      end if;

      case Decision is
         when Mux_New_Session_Decision =>
            if Handlers.New_Session /= null then
               State :=
                 Handlers.New_Session (Master, Client, Request, Response);
               if State /= Ok then
                  Reset (Response);
                  return State;
               end if;
               return Validate_Backend_Response
                 (Decision, Request, Response);
            end if;
         when Mux_Open_Forward_Decision =>
            if Handlers.Open_Forward /= null then
               State :=
                 Handlers.Open_Forward (Master, Client, Request, Response);
               if State /= Ok then
                  Reset (Response);
                  return State;
               end if;
               return Validate_Backend_Response
                 (Decision, Request, Response);
            end if;
         when Mux_Close_Forward_Decision =>
            if Handlers.Close_Forward /= null then
               State :=
                 Handlers.Close_Forward (Master, Client, Request, Response);
               if State /= Ok then
                  Reset (Response);
                  return State;
               end if;
               return Validate_Backend_Response
                 (Decision, Request, Response);
            end if;
         when Mux_New_Stdio_Forward_Decision =>
            if Handlers.New_Stdio_Forward /= null then
               State := Handlers.New_Stdio_Forward
                 (Master, Client, Request, Response);
               if State /= Ok then
                  Reset (Response);
                  return State;
               end if;
               return Validate_Backend_Response
                 (Decision, Request, Response);
            end if;
         when Mux_Proxy_Decision =>
            if Handlers.Proxy /= null then
               State := Handlers.Proxy (Master, Client, Request, Response);
               if State /= Ok then
                  Reset (Response);
                  return State;
               end if;
               return Validate_Backend_Response
                 (Decision, Request, Response);
            end if;
         when others =>
            return Route_Master_Request (Master, Request, Response, Decision);
      end case;

      Decision := Mux_Reject_Decision;
      return Encode_Reason_Response
        (Mux_Failure,
         Request.Request_Id,
         "mux backend handler not configured",
         Response);
   exception
      when others =>
         Reset (Response);
         Decision := Mux_Reject_Decision;
         return Internal_Error;
   end Route_Master_Request;

   function Process_Control_Client
     (Master       : in out Mux_Master;
      Client       : in out Mux_Client;
      Handlers     : Mux_Master_Handlers;
      Decision     : out Mux_Master_Decision;
      Max_Requests : Positive := 1)
      return Status
   is
      Request      : Mux_Message;
      Response     : Mux_Message;
      Peer_Version : Interfaces.Unsigned_32 := 0;
      State        : Status;
      Request_Count : Natural := 0;
   begin
      Decision := Mux_Reject_Decision;
      if not Client.Connected then
         return Connection_Failed;
      end if;

      State := Receive_Message (Client, Request);
      if State /= Ok then
         return State;
      elsif Request.Kind /= Mux_Hello then
         return Invalid_Command;
      end if;

      State := Decode_Hello (Request, Peer_Version);
      if State /= Ok then
         return State;
      elsif Peer_Version /= Mux_Protocol_Version then
         return Unsupported_Feature;
      end if;

      State := Encode_Hello (Mux_Protocol_Version, Response);
      if State /= Ok then
         return State;
      end if;
      State := Send_Message (Client, Response);
      if State /= Ok then
         return State;
      end if;

      while Request_Count < Max_Requests loop
         State := Receive_Message (Client, Request);
         if State /= Ok then
            return State;
         end if;

         State := Route_Master_Request
           (Master, Client, Request, Handlers, Response, Decision);
         if State /= Ok then
            return State;
         end if;

         State := Send_Message (Client, Response);
         if State /= Ok then
            return State;
         end if;

         Request_Count := Request_Count + 1;
         exit when Decision in Mux_Terminate_Decision
           | Mux_Stop_Listening_Decision
           | Mux_Proxy_Decision;
      end loop;

      if Request_Count = 0 then
         Decision := Mux_Continue;
      end if;
      return Ok;
   exception
      when others =>
         Decision := Mux_Reject_Decision;
         return Internal_Error;
   end Process_Control_Client;

   function Serve_One_Control
     (Master       : in out Mux_Master;
      Handlers     : Mux_Master_Handlers;
      Decision     : out Mux_Master_Decision;
      Max_Requests : Positive := 1)
      return Status
   is
      Client : Mux_Client;
      State  : Status;
   begin
      State := Serve_One_Control
        (Master, Handlers, Decision, Client, Max_Requests);
      if State = Ok and then Decision = Mux_Proxy_Decision then
         Release_Control (Master, Client);
      end if;
      return State;
   exception
      when others =>
         Release_Control (Master, Client);
         Decision := Mux_Reject_Decision;
         return Internal_Error;
   end Serve_One_Control;

   function Serve_One_Control
     (Master       : in out Mux_Master;
      Handlers     : Mux_Master_Handlers;
      Decision     : out Mux_Master_Decision;
      Client       : out Mux_Client;
      Max_Requests : Positive := 1)
      return Status
   is
      State  : Status;
   begin
      Decision := Mux_Reject_Decision;
      State := Accept_Control (Master, Client);
      if State /= Ok then
         return State;
      end if;

      State := Process_Control_Client
        (Master, Client, Handlers, Decision, Max_Requests);
      if State /= Ok or else Decision /= Mux_Proxy_Decision then
         Release_Control (Master, Client);
      end if;
      return State;
   exception
      when others =>
         Release_Control (Master, Client);
         Decision := Mux_Reject_Decision;
         return Internal_Error;
   end Serve_One_Control;

   function Serve_Control_Master
     (Master                  : in out Mux_Master;
      Handlers                : Mux_Master_Handlers;
      Final_Decision          : out Mux_Master_Decision;
      Max_Clients             : Positive := 1;
      Max_Requests_Per_Client : Positive := 1)
      return Status
   is
      Decision : Mux_Master_Decision := Mux_Reject_Decision;
      State    : Status;
   begin
      Final_Decision := Mux_Reject_Decision;
      if not Master.Listening then
         return Connection_Failed;
      end if;

      for Client_Index in 1 .. Max_Clients loop
         exit when not Master.Listening;
         State :=
           Serve_One_Control
             (Master,
              Handlers,
              Decision,
              Max_Requests => Max_Requests_Per_Client);
         if State /= Ok then
            Final_Decision := Decision;
            return State;
         end if;

         Final_Decision := Decision;
         case Decision is
            when Mux_Stop_Listening_Decision | Mux_Terminate_Decision =>
               Close_Master (Master);
               return Ok;
            when others =>
               null;
         end case;
      end loop;

      if Final_Decision = Mux_Reject_Decision then
         Final_Decision := Mux_Continue;
      end if;
      return Ok;
   exception
      when others =>
         Final_Decision := Mux_Reject_Decision;
         return Internal_Error;
   end Serve_Control_Master;
end SSH_Lib.Mux;
