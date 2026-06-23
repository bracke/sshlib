with SSH_Lib.Protocol.Numbers;

package body SSH_Lib.Protocol.Channels is

   use Ada.Streams;
   use CryptoLib.Errors;
   use SSH_Lib.Protocol.Buffers;

   function String_To_Bytes (Value : String) return Stream_Element_Array is
      Result :
        Stream_Element_Array
          (Stream_Element_Offset'(1) .. Stream_Element_Offset (Value'Length));
      Cursor : Stream_Element_Offset := Result'First;
   begin
      for Character_Value of Value loop
         Result (Cursor) := Stream_Element (Character'Pos (Character_Value));
         Cursor := Cursor + 1;
      end loop;
      return Result;
   end String_To_Bytes;

   function Append_Buffer
     (Target : in out Packet_Buffer; Source : Packet_Buffer) return Status is
   begin
      return Append (Target, To_Array (Source));
   end Append_Buffer;

   function Append_String
     (Target : in out Packet_Buffer; Value : String) return Status
   is
      Encoded : constant Packet_Buffer :=
        SSH_Lib.Protocol.Numbers.Encode_SSH_String (String_To_Bytes (Value));
   begin
      return Append_Buffer (Target, Encoded);
   end Append_String;

   function Valid_Command (Command : String) return Boolean is
   begin
      if Command'Length = 0 or else Command'Length > Maximum_Command_Length
      then
         return False;
      end if;

      for Character_Value of Command loop
         if Character_Value = Character'Val (0)
           or else Character_Value = Character'Val (10)
           or else Character_Value = Character'Val (13)
         then
            return False;
         end if;
      end loop;

      return True;
   end Valid_Command;

   function Encode_Channel_Open
     (Sender_Channel      : Unsigned_32;
      Initial_Window_Size : Unsigned_32 := Default_Initial_Window_Size;
      Maximum_Packet_Size : Unsigned_32 := Default_Maximum_Packet_Size)
      return Packet_Buffer
   is
      Result       : Packet_Buffer;
      Status_Value : Status;
   begin
      Clear (Result);

      if Maximum_Packet_Size = 0 then
         --  A zero local maximum packet size would advertise a session
         --  channel that can never legally receive CHANNEL_DATA.  Refuse to
         --  encode such an open request rather than creating a malformed
         --  Git exec channel boundary.
         return Result;
      end if;

      Status_Value := Append_Byte (Result, SSH_MSG_CHANNEL_OPEN);
      if Status_Value /= Ok then
         return Result;
      end if;

      Status_Value := Append_String (Result, "session");
      if Status_Value /= Ok then
         Clear (Result);
         return Result;
      end if;

      Status_Value :=
        Append
          (Result, SSH_Lib.Protocol.Numbers.Encode_Uint32 (Sender_Channel));
      if Status_Value /= Ok then
         Clear (Result);
         return Result;
      end if;

      Status_Value :=
        Append
          (Result,
           SSH_Lib.Protocol.Numbers.Encode_Uint32 (Initial_Window_Size));
      if Status_Value /= Ok then
         Clear (Result);
         return Result;
      end if;

      Status_Value :=
        Append
          (Result,
           SSH_Lib.Protocol.Numbers.Encode_Uint32 (Maximum_Packet_Size));
      if Status_Value /= Ok then
         Clear (Result);
      end if;
      return Result;
   exception
      when others =>
         Clear (Result);
         return Result;
   end Encode_Channel_Open;

   function Encode_Direct_TCPIP_Open
     (Sender_Channel      : Unsigned_32;
      Target_Host         : String;
      Target_Port         : Natural;
      Originator_Address  : String := "127.0.0.1";
      Originator_Port     : Natural := 0;
      Initial_Window_Size : Unsigned_32 := Default_Initial_Window_Size;
      Maximum_Packet_Size : Unsigned_32 := Default_Maximum_Packet_Size)
      return Packet_Buffer
   is
      Result       : Packet_Buffer;
      Status_Value : Status;
   begin
      Clear (Result);

      if Target_Host'Length = 0
        or else Target_Port = 0
        or else Maximum_Packet_Size = 0
      then
         --  direct-tcpip opens are also SSH channels and must not advertise
         --  a zero local maximum packet size.  Keep the ProxyJump transport
         --  path from constructing a channel that cannot legally carry data.
         return Result;
      end if;

      for Character_Value of Target_Host loop
         if Character_Value = Character'Val (0)
           or else Character_Value = Character'Val (10)
           or else Character_Value = Character'Val (13)
         then
            return Result;
         end if;
      end loop;

      for Character_Value of Originator_Address loop
         if Character_Value = Character'Val (0)
           or else Character_Value = Character'Val (10)
           or else Character_Value = Character'Val (13)
         then
            return Result;
         end if;
      end loop;

      Status_Value := Append_Byte (Result, SSH_MSG_CHANNEL_OPEN);
      if Status_Value /= Ok then
         return Result;
      end if;

      Status_Value := Append_String (Result, "direct-tcpip");
      if Status_Value /= Ok then
         Clear (Result);
         return Result;
      end if;

      Status_Value :=
        Append
          (Result, SSH_Lib.Protocol.Numbers.Encode_Uint32 (Sender_Channel));
      if Status_Value /= Ok then
         Clear (Result);
         return Result;
      end if;

      Status_Value :=
        Append
          (Result,
           SSH_Lib.Protocol.Numbers.Encode_Uint32 (Initial_Window_Size));
      if Status_Value /= Ok then
         Clear (Result);
         return Result;
      end if;

      Status_Value :=
        Append
          (Result,
           SSH_Lib.Protocol.Numbers.Encode_Uint32 (Maximum_Packet_Size));
      if Status_Value /= Ok then
         Clear (Result);
         return Result;
      end if;

      Status_Value := Append_String (Result, Target_Host);
      if Status_Value /= Ok then
         Clear (Result);
         return Result;
      end if;

      Status_Value :=
        Append
          (Result,
           SSH_Lib.Protocol.Numbers.Encode_Uint32 (Unsigned_32 (Target_Port)));
      if Status_Value /= Ok then
         Clear (Result);
         return Result;
      end if;

      Status_Value := Append_String (Result, Originator_Address);
      if Status_Value /= Ok then
         Clear (Result);
         return Result;
      end if;

      Status_Value :=
        Append
          (Result,
           SSH_Lib.Protocol.Numbers.Encode_Uint32
             (Unsigned_32 (Originator_Port)));
      if Status_Value /= Ok then
         Clear (Result);
      end if;

      return Result;
   exception
      when others =>
         Clear (Result);
         return Result;
   end Encode_Direct_TCPIP_Open;

   function Parse_Channel_Open_Confirmation
     (Payload            : Stream_Element_Array;
      Expected_Recipient : Unsigned_32;
      Item               : out Open_Confirmation) return Status
   is
      Cursor       : Stream_Element_Offset := Payload'First;
      Status_Value : Status;
   begin
      Item := (others => 0);
      if Payload'Length < 17
        or else Payload (Cursor) /= SSH_MSG_CHANNEL_OPEN_CONFIRMATION
      then
         return Channel_Open_Failed;
      end if;
      Cursor := Cursor + 1;

      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_Uint32
          (Payload, Cursor, Item.Recipient_Channel, Cursor);
      if Status_Value /= Ok
        or else Item.Recipient_Channel /= Expected_Recipient
      then
         return Channel_Open_Failed;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_Uint32
          (Payload, Cursor, Item.Sender_Channel, Cursor);
      if Status_Value /= Ok then
         return Channel_Open_Failed;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_Uint32
          (Payload, Cursor, Item.Initial_Window_Size, Cursor);
      if Status_Value /= Ok then
         return Channel_Open_Failed;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_Uint32
          (Payload, Cursor, Item.Maximum_Packet_Size, Cursor);
      if Status_Value /= Ok then
         return Channel_Open_Failed;
      end if;

      if Item.Maximum_Packet_Size = 0 then
         --  A zero maximum packet size would make the remote channel
         --  permanently unable to accept CHANNEL_DATA while still appearing
         --  successfully opened.  Reject the confirmation at parse time so
         --  Open_Exec surfaces a channel-open failure instead of creating a
         --  half-open Git stream that fails only when the first request byte
         --  is written.
         return Channel_Open_Failed;
      end if;

      if Cursor /= Payload'Last + 1 then
         return Channel_Open_Failed;
      end if;
      return Ok;
   exception
      when others =>
         Item := (others => 0);
         return Channel_Open_Failed;
   end Parse_Channel_Open_Confirmation;

   function Parse_Channel_Open_Failure
     (Payload            : Stream_Element_Array;
      Expected_Recipient : Unsigned_32;
      Item               : out Open_Failure) return Status
   is
      Cursor       : Stream_Element_Offset := Payload'First;
      Status_Value : Status;
   begin
      Item.Recipient_Channel := 0;
      Item.Reason_Code := 0;
      Clear (Item.Description);
      Clear (Item.Language_Tag);

      if Payload'Length < 13
        or else Payload (Cursor) /= SSH_MSG_CHANNEL_OPEN_FAILURE
      then
         return Channel_Open_Failed;
      end if;
      Cursor := Cursor + 1;

      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_Uint32
          (Payload, Cursor, Item.Recipient_Channel, Cursor);
      if Status_Value /= Ok
        or else Item.Recipient_Channel /= Expected_Recipient
      then
         return Channel_Open_Failed;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_Uint32
          (Payload, Cursor, Item.Reason_Code, Cursor);
      if Status_Value /= Ok then
         return Channel_Open_Failed;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_SSH_String
          (Payload, Cursor, Item.Description, Cursor);
      if Status_Value /= Ok then
         return Channel_Open_Failed;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_SSH_String
          (Payload, Cursor, Item.Language_Tag, Cursor);
      if Status_Value /= Ok then
         return Channel_Open_Failed;
      end if;

      if Cursor /= Payload'Last + 1 then
         return Channel_Open_Failed;
      end if;
      return Ok;
   exception
      when others =>
         Clear (Item.Description);
         Clear (Item.Language_Tag);
         return Channel_Open_Failed;
   end Parse_Channel_Open_Failure;

   function Parse_Forwarded_TCPIP_Open
     (Payload : Stream_Element_Array;
      Item    : out Forwarded_TCPIP_Open)
      return Status
   is
      Cursor       : Stream_Element_Offset := Payload'First;
      Type_Buffer  : Packet_Buffer;
      Status_Value : Status;
   begin
      Item := (others => <>);
      if Payload'Length < 35 or else Payload (Cursor) /= SSH_MSG_CHANNEL_OPEN
      then
         return Channel_Open_Failed;
      end if;
      Cursor := Cursor + 1;

      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_SSH_String
          (Payload, Cursor, Type_Buffer, Cursor);
      if Status_Value /= Ok
        or else To_Array (Type_Buffer) /= String_To_Bytes ("forwarded-tcpip")
      then
         return Channel_Open_Failed;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_Uint32
          (Payload, Cursor, Item.Sender_Channel, Cursor);
      if Status_Value /= Ok then
         return Channel_Open_Failed;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_Uint32
          (Payload, Cursor, Item.Initial_Window_Size, Cursor);
      if Status_Value /= Ok then
         return Channel_Open_Failed;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_Uint32
          (Payload, Cursor, Item.Maximum_Packet_Size, Cursor);
      if Status_Value /= Ok or else Item.Maximum_Packet_Size = 0 then
         return Channel_Open_Failed;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_SSH_String
          (Payload, Cursor, Item.Connected_Address, Cursor);
      if Status_Value /= Ok then
         return Channel_Open_Failed;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_Uint32
          (Payload, Cursor, Item.Connected_Port, Cursor);
      if Status_Value /= Ok
        or else Item.Connected_Port = 0
        or else Item.Connected_Port > 65_535
      then
         return Channel_Open_Failed;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_SSH_String
          (Payload, Cursor, Item.Originator_Address, Cursor);
      if Status_Value /= Ok then
         return Channel_Open_Failed;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_Uint32
          (Payload, Cursor, Item.Originator_Port, Cursor);
      if Status_Value /= Ok
        or else Item.Originator_Port > 65_535
        or else Cursor /= Payload'Last + 1
      then
         return Channel_Open_Failed;
      end if;

      if Length (Item.Connected_Address) = 0
        or else Length (Item.Originator_Address) = 0
      then
         return Channel_Open_Failed;
      end if;

      return Ok;
   exception
      when others =>
         Item := (others => <>);
         return Channel_Open_Failed;
   end Parse_Forwarded_TCPIP_Open;

   function Parse_X11_Open
     (Payload : Stream_Element_Array;
      Item    : out X11_Open)
      return Status
   is
      Cursor       : Stream_Element_Offset := Payload'First;
      Type_Buffer  : Packet_Buffer;
      Status_Value : Status;
   begin
      Item := (others => <>);
      if Payload'Length < 23 or else Payload (Cursor) /= SSH_MSG_CHANNEL_OPEN
      then
         return Channel_Open_Failed;
      end if;
      Cursor := Cursor + 1;

      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_SSH_String
          (Payload, Cursor, Type_Buffer, Cursor);
      if Status_Value /= Ok
        or else To_Array (Type_Buffer) /= String_To_Bytes ("x11")
      then
         return Channel_Open_Failed;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_Uint32
          (Payload, Cursor, Item.Sender_Channel, Cursor);
      if Status_Value /= Ok then
         return Channel_Open_Failed;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_Uint32
          (Payload, Cursor, Item.Initial_Window_Size, Cursor);
      if Status_Value /= Ok then
         return Channel_Open_Failed;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_Uint32
          (Payload, Cursor, Item.Maximum_Packet_Size, Cursor);
      if Status_Value /= Ok or else Item.Maximum_Packet_Size = 0 then
         return Channel_Open_Failed;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_SSH_String
          (Payload, Cursor, Item.Originator_Address, Cursor);
      if Status_Value /= Ok then
         return Channel_Open_Failed;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_Uint32
          (Payload, Cursor, Item.Originator_Port, Cursor);
      if Status_Value /= Ok
        or else Item.Originator_Port > 65_535
        or else Cursor /= Payload'Last + 1
      then
         return Channel_Open_Failed;
      end if;

      if Length (Item.Originator_Address) = 0 then
         return Channel_Open_Failed;
      end if;

      return Ok;
   exception
      when others =>
         Item := (others => <>);
         return Channel_Open_Failed;
   end Parse_X11_Open;

   function Encode_Channel_Open_Confirmation
     (Recipient_Channel   : Unsigned_32;
      Sender_Channel      : Unsigned_32;
      Initial_Window_Size : Unsigned_32 := Default_Initial_Window_Size;
      Maximum_Packet_Size : Unsigned_32 := Default_Maximum_Packet_Size)
      return Packet_Buffer
   is
      Result       : Packet_Buffer;
      Status_Value : Status;
   begin
      Clear (Result);
      if Maximum_Packet_Size = 0 then
         return Result;
      end if;

      Status_Value := Append_Byte (Result, SSH_MSG_CHANNEL_OPEN_CONFIRMATION);
      if Status_Value /= Ok then
         return Result;
      end if;

      Status_Value :=
        Append
          (Result, SSH_Lib.Protocol.Numbers.Encode_Uint32 (Recipient_Channel));
      if Status_Value /= Ok then
         Clear (Result);
         return Result;
      end if;

      Status_Value :=
        Append (Result, SSH_Lib.Protocol.Numbers.Encode_Uint32 (Sender_Channel));
      if Status_Value /= Ok then
         Clear (Result);
         return Result;
      end if;

      Status_Value :=
        Append
          (Result,
           SSH_Lib.Protocol.Numbers.Encode_Uint32 (Initial_Window_Size));
      if Status_Value /= Ok then
         Clear (Result);
         return Result;
      end if;

      Status_Value :=
        Append
          (Result,
           SSH_Lib.Protocol.Numbers.Encode_Uint32 (Maximum_Packet_Size));
      if Status_Value /= Ok then
         Clear (Result);
      end if;
      return Result;
   exception
      when others =>
         Clear (Result);
         return Result;
   end Encode_Channel_Open_Confirmation;

   function Encode_Channel_Request_With_String
     (Recipient_Channel : Unsigned_32;
      Request_Name      : String;
      Argument_Value    : String) return Packet_Buffer
   is
      Result       : Packet_Buffer;
      Status_Value : Status;
   begin
      Clear (Result);
      if not Valid_Command (Argument_Value) then
         return Result;
      end if;

      Status_Value := Append_Byte (Result, SSH_MSG_CHANNEL_REQUEST);
      if Status_Value /= Ok then
         return Result;
      end if;

      Status_Value :=
        Append
          (Result, SSH_Lib.Protocol.Numbers.Encode_Uint32 (Recipient_Channel));
      if Status_Value /= Ok then
         Clear (Result);
         return Result;
      end if;

      Status_Value := Append_String (Result, Request_Name);
      if Status_Value /= Ok then
         Clear (Result);
         return Result;
      end if;

      Status_Value :=
        Append_Byte (Result, SSH_Lib.Protocol.Numbers.Encode_Boolean (True));
      if Status_Value /= Ok then
         Clear (Result);
         return Result;
      end if;

      Status_Value := Append_String (Result, Argument_Value);
      if Status_Value /= Ok then
         Clear (Result);
      end if;
      return Result;
   exception
      when others =>
         Clear (Result);
         return Result;
   end Encode_Channel_Request_With_String;

   function Encode_Exec_Request
     (Recipient_Channel : Unsigned_32; Command : String) return Packet_Buffer
   is
   begin
      return Encode_Channel_Request_With_String
        (Recipient_Channel, "exec", Command);
   end Encode_Exec_Request;

   function Encode_Subsystem_Request
     (Recipient_Channel : Unsigned_32; Subsystem_Name : String)
      return Packet_Buffer
   is
   begin
      return Encode_Channel_Request_With_String
        (Recipient_Channel, "subsystem", Subsystem_Name);
   end Encode_Subsystem_Request;

   function Encode_Shell_Request
     (Recipient_Channel : Unsigned_32)
      return Packet_Buffer
   is
      Result       : Packet_Buffer;
      Status_Value : Status;
   begin
      Clear (Result);
      Status_Value := Append_Byte (Result, SSH_MSG_CHANNEL_REQUEST);
      if Status_Value /= Ok then
         return Result;
      end if;

      Status_Value :=
        Append
          (Result, SSH_Lib.Protocol.Numbers.Encode_Uint32 (Recipient_Channel));
      if Status_Value /= Ok then
         Clear (Result);
         return Result;
      end if;

      Status_Value := Append_String (Result, "shell");
      if Status_Value /= Ok then
         Clear (Result);
         return Result;
      end if;

      Status_Value :=
        Append_Byte (Result, SSH_Lib.Protocol.Numbers.Encode_Boolean (True));
      if Status_Value /= Ok then
         Clear (Result);
      end if;
      return Result;
   exception
      when others =>
         Clear (Result);
      return Result;
   end Encode_Shell_Request;

   function Encode_Environment_Request
     (Recipient_Channel : Unsigned_32;
      Name              : String;
      Value             : String)
      return Packet_Buffer
   is
      Result       : Packet_Buffer;
      Status_Value : Status;

      function Valid_Environment_Value (Item : String) return Boolean is
      begin
         if Item'Length > Maximum_Command_Length then
            return False;
         end if;

         for Character_Value of Item loop
            if Character_Value = Character'Val (0)
              or else Character_Value = Character'Val (10)
              or else Character_Value = Character'Val (13)
            then
               return False;
            end if;
         end loop;

         return True;
      end Valid_Environment_Value;
   begin
      Clear (Result);
      if not Valid_Command (Name)
        or else not Valid_Environment_Value (Value)
      then
         return Result;
      end if;

      for Character_Value of Name loop
         if Character_Value = '=' then
            return Result;
         end if;
      end loop;

      Status_Value := Append_Byte (Result, SSH_MSG_CHANNEL_REQUEST);
      if Status_Value /= Ok then
         return Result;
      end if;

      Status_Value :=
        Append
          (Result, SSH_Lib.Protocol.Numbers.Encode_Uint32 (Recipient_Channel));
      if Status_Value /= Ok then
         Clear (Result);
         return Result;
      end if;

      Status_Value := Append_String (Result, "env");
      if Status_Value /= Ok then
         Clear (Result);
         return Result;
      end if;

      Status_Value :=
        Append_Byte (Result, SSH_Lib.Protocol.Numbers.Encode_Boolean (True));
      if Status_Value /= Ok then
         Clear (Result);
         return Result;
      end if;

      Status_Value := Append_String (Result, Name);
      if Status_Value /= Ok then
         Clear (Result);
         return Result;
      end if;

      Status_Value := Append_String (Result, Value);
      if Status_Value /= Ok then
         Clear (Result);
      end if;
      return Result;
   exception
      when others =>
         Clear (Result);
         return Result;
   end Encode_Environment_Request;

   function Encode_X11_Request
     (Recipient_Channel : Unsigned_32;
      Single_Connection : Boolean;
      Auth_Protocol     : String;
      Auth_Cookie       : String;
      Screen_Number     : Unsigned_32 := 0)
      return Packet_Buffer
   is
      Result       : Packet_Buffer;
      Status_Value : Status;
   begin
      Clear (Result);
      if not Valid_Command (Auth_Protocol)
        or else not Valid_Command (Auth_Cookie)
      then
         return Result;
      end if;

      Status_Value := Append_Byte (Result, SSH_MSG_CHANNEL_REQUEST);
      if Status_Value /= Ok then
         return Result;
      end if;

      Status_Value :=
        Append
          (Result, SSH_Lib.Protocol.Numbers.Encode_Uint32 (Recipient_Channel));
      if Status_Value /= Ok then
         Clear (Result);
         return Result;
      end if;

      Status_Value := Append_String (Result, "x11-req");
      if Status_Value /= Ok then
         Clear (Result);
         return Result;
      end if;

      Status_Value :=
        Append_Byte (Result, SSH_Lib.Protocol.Numbers.Encode_Boolean (True));
      if Status_Value /= Ok then
         Clear (Result);
         return Result;
      end if;

      Status_Value :=
        Append_Byte
          (Result, SSH_Lib.Protocol.Numbers.Encode_Boolean
             (Single_Connection));
      if Status_Value /= Ok then
         Clear (Result);
         return Result;
      end if;

      Status_Value := Append_String (Result, Auth_Protocol);
      if Status_Value /= Ok then
         Clear (Result);
         return Result;
      end if;

      Status_Value := Append_String (Result, Auth_Cookie);
      if Status_Value /= Ok then
         Clear (Result);
         return Result;
      end if;

      Status_Value :=
        Append (Result, SSH_Lib.Protocol.Numbers.Encode_Uint32
          (Screen_Number));
      if Status_Value /= Ok then
         Clear (Result);
      end if;
      return Result;
   exception
      when others =>
         Clear (Result);
         return Result;
   end Encode_X11_Request;

   function Encode_PTY_Request
     (Recipient_Channel : Unsigned_32;
      Terminal_Type     : String;
      Columns           : Unsigned_32;
      Rows              : Unsigned_32;
      Width_Pixels      : Unsigned_32 := 0;
      Height_Pixels     : Unsigned_32 := 0;
      Terminal_Modes    : Terminal_Mode_Array := Empty_Terminal_Modes)
      return Packet_Buffer
   is
      Result       : Packet_Buffer;
      Status_Value : Status;

      function Valid_Terminal_Modes return Boolean is
      begin
         for Mode_Item of Terminal_Modes loop
            if Mode_Item.Opcode = 0 or else Mode_Item.Opcode >= 160 then
               return False;
            end if;
         end loop;
         return True;
      end Valid_Terminal_Modes;

      function Encode_Terminal_Modes return Packet_Buffer is
         Modes_Buffer : Packet_Buffer;
         Encode_Status : Status;
      begin
         Clear (Modes_Buffer);
         for Mode_Item of Terminal_Modes loop
            Encode_Status := Append_Byte (Modes_Buffer, Mode_Item.Opcode);
            if Encode_Status /= Ok then
               Clear (Modes_Buffer);
               return Modes_Buffer;
            end if;

            Encode_Status :=
              Append
                (Modes_Buffer,
                 SSH_Lib.Protocol.Numbers.Encode_Uint32 (Mode_Item.Value));
            if Encode_Status /= Ok then
               Clear (Modes_Buffer);
               return Modes_Buffer;
            end if;
         end loop;

         Encode_Status := Append_Byte (Modes_Buffer, 0);
         if Encode_Status /= Ok then
            Clear (Modes_Buffer);
         end if;
         return Modes_Buffer;
      exception
         when others =>
            Clear (Modes_Buffer);
            return Modes_Buffer;
      end Encode_Terminal_Modes;
   begin
      Clear (Result);
      if not Valid_Command (Terminal_Type)
        or else Columns = 0
        or else Rows = 0
        or else not Valid_Terminal_Modes
      then
         return Result;
      end if;

      Status_Value := Append_Byte (Result, SSH_MSG_CHANNEL_REQUEST);
      if Status_Value /= Ok then
         return Result;
      end if;

      Status_Value :=
        Append
          (Result, SSH_Lib.Protocol.Numbers.Encode_Uint32 (Recipient_Channel));
      if Status_Value /= Ok then
         Clear (Result);
         return Result;
      end if;

      Status_Value := Append_String (Result, "pty-req");
      if Status_Value /= Ok then
         Clear (Result);
         return Result;
      end if;

      Status_Value :=
        Append_Byte (Result, SSH_Lib.Protocol.Numbers.Encode_Boolean (True));
      if Status_Value /= Ok then
         Clear (Result);
         return Result;
      end if;

      Status_Value := Append_String (Result, Terminal_Type);
      if Status_Value /= Ok then
         Clear (Result);
         return Result;
      end if;

      Status_Value :=
        Append (Result, SSH_Lib.Protocol.Numbers.Encode_Uint32 (Columns));
      if Status_Value /= Ok then
         Clear (Result);
         return Result;
      end if;

      Status_Value :=
        Append (Result, SSH_Lib.Protocol.Numbers.Encode_Uint32 (Rows));
      if Status_Value /= Ok then
         Clear (Result);
         return Result;
      end if;

      Status_Value :=
        Append (Result, SSH_Lib.Protocol.Numbers.Encode_Uint32 (Width_Pixels));
      if Status_Value /= Ok then
         Clear (Result);
         return Result;
      end if;

      Status_Value :=
        Append (Result, SSH_Lib.Protocol.Numbers.Encode_Uint32 (Height_Pixels));
      if Status_Value /= Ok then
         Clear (Result);
         return Result;
      end if;

      Status_Value :=
        Append_Buffer
          (Result,
           SSH_Lib.Protocol.Numbers.Encode_SSH_String
             (To_Array (Encode_Terminal_Modes)));
      if Status_Value /= Ok then
         Clear (Result);
      end if;
      return Result;
   exception
      when others =>
         Clear (Result);
         return Result;
   end Encode_PTY_Request;

   function Encode_Window_Change_Request
     (Recipient_Channel : Unsigned_32;
      Columns           : Unsigned_32;
      Rows              : Unsigned_32;
      Width_Pixels      : Unsigned_32 := 0;
      Height_Pixels     : Unsigned_32 := 0)
      return Packet_Buffer
   is
      Result       : Packet_Buffer;
      Status_Value : Status;
   begin
      Clear (Result);
      if Columns = 0 or else Rows = 0 then
         return Result;
      end if;

      Status_Value := Append_Byte (Result, SSH_MSG_CHANNEL_REQUEST);
      if Status_Value /= Ok then
         return Result;
      end if;

      Status_Value :=
        Append
          (Result, SSH_Lib.Protocol.Numbers.Encode_Uint32 (Recipient_Channel));
      if Status_Value /= Ok then
         Clear (Result);
         return Result;
      end if;

      Status_Value := Append_String (Result, "window-change");
      if Status_Value /= Ok then
         Clear (Result);
         return Result;
      end if;

      Status_Value :=
        Append_Byte (Result, SSH_Lib.Protocol.Numbers.Encode_Boolean (False));
      if Status_Value /= Ok then
         Clear (Result);
         return Result;
      end if;

      Status_Value :=
        Append (Result, SSH_Lib.Protocol.Numbers.Encode_Uint32 (Columns));
      if Status_Value /= Ok then
         Clear (Result);
         return Result;
      end if;

      Status_Value :=
        Append (Result, SSH_Lib.Protocol.Numbers.Encode_Uint32 (Rows));
      if Status_Value /= Ok then
         Clear (Result);
         return Result;
      end if;

      Status_Value :=
        Append (Result, SSH_Lib.Protocol.Numbers.Encode_Uint32 (Width_Pixels));
      if Status_Value /= Ok then
         Clear (Result);
         return Result;
      end if;

      Status_Value :=
        Append (Result, SSH_Lib.Protocol.Numbers.Encode_Uint32 (Height_Pixels));
      if Status_Value /= Ok then
         Clear (Result);
      end if;
      return Result;
   exception
      when others =>
         Clear (Result);
         return Result;
   end Encode_Window_Change_Request;

   function Parse_Exec_Reply
     (Payload            : Stream_Element_Array;
      Expected_Recipient : Unsigned_32;
      Reply              : out Exec_Reply) return Status
   is
      Cursor          : Stream_Element_Offset;
      Recipient_Value : Unsigned_32 := 0;
      Status_Value    : Status;
   begin
      Reply := Exec_Request_Failure;
      if Payload'Length /= 5 then
         return Channel_Request_Failed;
      end if;

      Cursor := Payload'First + 1;

      if Payload (Payload'First) = SSH_MSG_CHANNEL_SUCCESS then
         Reply := Exec_Request_Success;
      elsif Payload (Payload'First) = SSH_MSG_CHANNEL_FAILURE then
         Reply := Exec_Request_Failure;
      else
         return Channel_Request_Failed;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_Uint32
          (Payload, Cursor, Recipient_Value, Cursor);
      if Status_Value /= Ok
        or else Cursor /= Payload'Last + 1
        or else Recipient_Value /= Expected_Recipient
      then
         Reply := Exec_Request_Failure;
         return Channel_Request_Failed;
      end if;

      if Reply = Exec_Request_Success then
         return Ok;
      else
         return Channel_Request_Failed;
      end if;
   exception
      when others =>
         Reply := Exec_Request_Failure;
         return Channel_Request_Failed;
   end Parse_Exec_Reply;
   function Append_Message_And_Channel
     (Message_Value : Stream_Element; Recipient_Channel : Unsigned_32)
      return Packet_Buffer
   is
      Result       : Packet_Buffer;
      Status_Value : Status;
   begin
      Clear (Result);
      Status_Value := Append_Byte (Result, Message_Value);
      if Status_Value /= Ok then
         return Result;
      end if;
      Status_Value :=
        Append
          (Result, SSH_Lib.Protocol.Numbers.Encode_Uint32 (Recipient_Channel));
      if Status_Value /= Ok then
         Clear (Result);
      end if;
      return Result;
   exception
      when others =>
         Clear (Result);
         return Result;
   end Append_Message_And_Channel;

   function Encode_Channel_Data
     (Recipient_Channel : Unsigned_32; Data : Stream_Element_Array)
      return Packet_Buffer
   is
      Result       : Packet_Buffer :=
        Append_Message_And_Channel (SSH_MSG_CHANNEL_DATA, Recipient_Channel);
      String_Value : Packet_Buffer;
      Status_Value : Status;
   begin
      if Is_Empty (Result) then
         return Result;
      end if;
      String_Value := SSH_Lib.Protocol.Numbers.Encode_SSH_String (Data);
      if Data'Length /= 0 and then Is_Empty (String_Value) then
         Clear (Result);
         return Result;
      end if;
      Status_Value := Append (Result, To_Array (String_Value));
      if Status_Value /= Ok then
         Clear (Result);
      end if;
      return Result;
   exception
      when others =>
         Clear (Result);
         return Result;
   end Encode_Channel_Data;

   function Parse_Channel_Data
     (Payload            : Stream_Element_Array;
      Expected_Recipient : Unsigned_32;
      Item               : out Channel_Data_Event) return Status
   is
      Cursor       : Stream_Element_Offset := Payload'First;
      Status_Value : Status;
   begin
      Item.Recipient_Channel := 0;
      Clear (Item.Data);
      if Payload'Length < 9 or else Payload (Cursor) /= SSH_MSG_CHANNEL_DATA
      then
         return Read_Failed;
      end if;
      Cursor := Cursor + 1;
      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_Uint32
          (Payload, Cursor, Item.Recipient_Channel, Cursor);
      if Status_Value /= Ok
        or else Item.Recipient_Channel /= Expected_Recipient
      then
         return Read_Failed;
      end if;
      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_SSH_String
          (Payload, Cursor, Item.Data, Cursor);
      if Status_Value /= Ok or else Cursor /= Payload'Last + 1 then
         Clear (Item.Data);
         return Read_Failed;
      end if;
      return Ok;
   exception
      when others =>
         Clear (Item.Data);
         return Read_Failed;
   end Parse_Channel_Data;

   function Encode_Channel_Extended_Data
     (Recipient_Channel : Unsigned_32;
      Data_Type_Code    : Unsigned_32;
      Data              : Stream_Element_Array) return Packet_Buffer
   is
      Result       : Packet_Buffer :=
        Append_Message_And_Channel
          (SSH_MSG_CHANNEL_EXTENDED_DATA, Recipient_Channel);
      String_Value : Packet_Buffer;
      Status_Value : Status;
   begin
      if Is_Empty (Result) then
         return Result;
      end if;

      Status_Value :=
        Append
          (Result, SSH_Lib.Protocol.Numbers.Encode_Uint32 (Data_Type_Code));
      if Status_Value /= Ok then
         Clear (Result);
         return Result;
      end if;

      String_Value := SSH_Lib.Protocol.Numbers.Encode_SSH_String (Data);
      if Data'Length /= 0 and then Is_Empty (String_Value) then
         Clear (Result);
         return Result;
      end if;

      Status_Value := Append (Result, To_Array (String_Value));
      if Status_Value /= Ok then
         Clear (Result);
      end if;
      return Result;
   exception
      when others =>
         Clear (Result);
         return Result;
   end Encode_Channel_Extended_Data;

   function Parse_Channel_Extended_Data
     (Payload            : Stream_Element_Array;
      Expected_Recipient : Unsigned_32;
      Item               : out Channel_Extended_Data_Event) return Status
   is
      Cursor       : Stream_Element_Offset := Payload'First;
      Status_Value : Status;
   begin
      Item.Recipient_Channel := 0;
      Item.Data_Type_Code := 0;
      Clear (Item.Data);
      if Payload'Length < 13
        or else Payload (Cursor) /= SSH_MSG_CHANNEL_EXTENDED_DATA
      then
         return Read_Failed;
      end if;
      Cursor := Cursor + 1;
      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_Uint32
          (Payload, Cursor, Item.Recipient_Channel, Cursor);
      if Status_Value /= Ok
        or else Item.Recipient_Channel /= Expected_Recipient
      then
         return Read_Failed;
      end if;
      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_Uint32
          (Payload, Cursor, Item.Data_Type_Code, Cursor);
      if Status_Value /= Ok then
         return Read_Failed;
      end if;
      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_SSH_String
          (Payload, Cursor, Item.Data, Cursor);
      if Status_Value /= Ok or else Cursor /= Payload'Last + 1 then
         Clear (Item.Data);
         return Read_Failed;
      end if;
      return Ok;
   exception
      when others =>
         Clear (Item.Data);
         return Read_Failed;
   end Parse_Channel_Extended_Data;

   function Encode_Channel_Window_Adjust
     (Recipient_Channel : Unsigned_32; Bytes_To_Add : Unsigned_32)
      return Packet_Buffer
   is
      Result       : Packet_Buffer :=
        Append_Message_And_Channel
          (SSH_MSG_CHANNEL_WINDOW_ADJUST, Recipient_Channel);
      Status_Value : Status;
   begin
      if Is_Empty (Result) then
         return Result;
      end if;

      if Bytes_To_Add = 0 then
         --  A zero CHANNEL_WINDOW_ADJUST does not open any outbound credit.
         --  Refuse to encode it so local code never emits a no-op flow-control
         --  message that can confuse channel write-state accounting.
         Clear (Result);
         return Result;
      end if;

      Status_Value :=
        Append (Result, SSH_Lib.Protocol.Numbers.Encode_Uint32 (Bytes_To_Add));
      if Status_Value /= Ok then
         Clear (Result);
      end if;
      return Result;
   exception
      when others =>
         Clear (Result);
         return Result;
   end Encode_Channel_Window_Adjust;

   function Parse_Channel_Window_Adjust
     (Payload            : Stream_Element_Array;
      Expected_Recipient : Unsigned_32;
      Item               : out Channel_Window_Adjust_Event) return Status
   is
      Cursor       : Stream_Element_Offset := Payload'First;
      Status_Value : Status;
   begin
      Item := (others => 0);
      if Payload'Length /= 9
        or else Payload (Cursor) /= SSH_MSG_CHANNEL_WINDOW_ADJUST
      then
         return Write_Failed;
      end if;
      Cursor := Cursor + 1;
      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_Uint32
          (Payload, Cursor, Item.Recipient_Channel, Cursor);
      if Status_Value /= Ok
        or else Item.Recipient_Channel /= Expected_Recipient
      then
         return Write_Failed;
      end if;
      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_Uint32
          (Payload, Cursor, Item.Bytes_To_Add, Cursor);
      if Status_Value /= Ok
        or else Cursor /= Payload'Last + 1
        or else Item.Bytes_To_Add = 0
      then
         --  RFC channel window adjust is a positive credit increase.  A zero
         --  adjust would be accepted by the packet shape but must not wake or
         --  mutate a stalled Git stdin writer as if capacity had changed.
         return Write_Failed;
      end if;
      return Ok;
   exception
      when others =>
         Item := (others => 0);
         return Write_Failed;
   end Parse_Channel_Window_Adjust;

   function Encode_Channel_EOF
     (Recipient_Channel : Unsigned_32) return Packet_Buffer is
   begin
      return
        Append_Message_And_Channel (SSH_MSG_CHANNEL_EOF, Recipient_Channel);
   end Encode_Channel_EOF;

   function Encode_Channel_Close
     (Recipient_Channel : Unsigned_32) return Packet_Buffer is
   begin
      return
        Append_Message_And_Channel (SSH_MSG_CHANNEL_CLOSE, Recipient_Channel);
   end Encode_Channel_Close;

   function Parse_Channel_One_Id
     (Payload            : Stream_Element_Array;
      Expected_Message   : Stream_Element;
      Expected_Recipient : Unsigned_32) return Status
   is
      Cursor          : Stream_Element_Offset := Payload'First;
      Recipient_Value : Unsigned_32 := 0;
      Status_Value    : Status;
   begin
      if Payload'Length /= 5 or else Payload (Cursor) /= Expected_Message then
         return Read_Failed;
      end if;
      Cursor := Cursor + 1;
      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_Uint32
          (Payload, Cursor, Recipient_Value, Cursor);
      if Status_Value /= Ok
        or else Cursor /= Payload'Last + 1
        or else Recipient_Value /= Expected_Recipient
      then
         return Read_Failed;
      end if;
      return Ok;
   exception
      when others =>
         return Read_Failed;
   end Parse_Channel_One_Id;

   function Parse_Channel_Request
     (Payload            : Stream_Element_Array;
      Expected_Recipient : Unsigned_32;
      Item               : out Channel_Request_Event) return Status
   is
      Cursor         : Stream_Element_Offset := Payload'First;
      Status_Value   : Status;
      Is_Exit_Status : Boolean := False;
      Is_Exit_Signal : Boolean := False;
   begin
      Item.Recipient_Channel := 0;
      Clear (Item.Request_Name);
      Item.Want_Reply := False;
      Item.Exit_Status := 0;
      if Payload'Length < 10
        or else Payload (Cursor) /= SSH_MSG_CHANNEL_REQUEST
      then
         return Read_Failed;
      end if;
      Cursor := Cursor + 1;
      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_Uint32
          (Payload, Cursor, Item.Recipient_Channel, Cursor);
      if Status_Value /= Ok
        or else Item.Recipient_Channel /= Expected_Recipient
      then
         return Read_Failed;
      end if;
      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_SSH_String
          (Payload, Cursor, Item.Request_Name, Cursor);
      if Status_Value /= Ok or else Cursor > Payload'Last then
         Clear (Item.Request_Name);
         return Read_Failed;
      end if;
      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_Boolean
          (Payload (Cursor), Item.Want_Reply);
      if Status_Value /= Ok then
         Clear (Item.Request_Name);
         return Read_Failed;
      end if;
      Cursor := Cursor + 1;

      declare
         Name_Data   : constant Stream_Element_Array :=
           To_Array (Item.Request_Name);
         Exit_Name   : constant Stream_Element_Array (1 .. 11) :=
           [Stream_Element (Character'Pos ('e')),
            Stream_Element (Character'Pos ('x')),
            Stream_Element (Character'Pos ('i')),
            Stream_Element (Character'Pos ('t')),
            Stream_Element (Character'Pos ('-')),
            Stream_Element (Character'Pos ('s')),
            Stream_Element (Character'Pos ('t')),
            Stream_Element (Character'Pos ('a')),
            Stream_Element (Character'Pos ('t')),
            Stream_Element (Character'Pos ('u')),
            Stream_Element (Character'Pos ('s'))];
         Signal_Name : constant Stream_Element_Array (1 .. 11) :=
           [Stream_Element (Character'Pos ('e')),
            Stream_Element (Character'Pos ('x')),
            Stream_Element (Character'Pos ('i')),
            Stream_Element (Character'Pos ('t')),
            Stream_Element (Character'Pos ('-')),
            Stream_Element (Character'Pos ('s')),
            Stream_Element (Character'Pos ('i')),
            Stream_Element (Character'Pos ('g')),
            Stream_Element (Character'Pos ('n')),
            Stream_Element (Character'Pos ('a')),
            Stream_Element (Character'Pos ('l'))];
      begin
         if Name_Data'Length = Exit_Name'Length then
            Is_Exit_Status := True;
            Is_Exit_Signal := True;
            for Offset_Value in 0 .. Name_Data'Length - 1 loop
               if Name_Data
                    (Name_Data'First + Stream_Element_Offset (Offset_Value))
                 /= Exit_Name
                      (Exit_Name'First + Stream_Element_Offset (Offset_Value))
               then
                  Is_Exit_Status := False;
               end if;
               if Name_Data
                    (Name_Data'First + Stream_Element_Offset (Offset_Value))
                 /= Signal_Name
                      (Signal_Name'First
                       + Stream_Element_Offset (Offset_Value))
               then
                  Is_Exit_Signal := False;
               end if;
            end loop;
         end if;
      end;

      if Is_Exit_Status then
         if Item.Want_Reply then
            --  RFC 4254 defines exit-status as terminal server-to-client
            --  command-result metadata with want-reply set to FALSE.  Do not
            --  accept or acknowledge a non-standard request that asks for a
            --  reply, because doing so can make terminal-result handling depend
            --  on a follow-up control exchange after the remote command has
            --  already ended.
            Clear (Item.Request_Name);
            return Read_Failed;
         end if;

         Status_Value :=
           SSH_Lib.Protocol.Numbers.Decode_Uint32
             (Payload, Cursor, Item.Exit_Status, Cursor);
         if Status_Value /= Ok or else Cursor /= Payload'Last + 1 then
            Clear (Item.Request_Name);
            return Read_Failed;
         end if;
      elsif Is_Exit_Signal then
         if Item.Want_Reply then
            --  Like exit-status, exit-signal is terminal remote-command result
            --  metadata and is defined with want-reply FALSE.  Reject
            --  reply-requesting variants before recording a signal-derived
            --  failure result or sending CHANNEL_SUCCESS for a terminal event.
            Clear (Item.Request_Name);
            return Read_Failed;
         end if;

         --  RFC 4254 defines exit-signal as a known channel request with a
         --  fixed typed payload: signal name, core-dumped flag, error message,
         --  and language tag.  Accept valid OpenSSH signal termination records,
         --  but reject truncated or overlong variants instead of treating them
         --  as arbitrary unknown extension data.
         declare
            Ignored_String : Packet_Buffer;
            Ignored_Core   : Boolean;
         begin
            Status_Value :=
              SSH_Lib.Protocol.Numbers.Decode_SSH_String
                (Payload, Cursor, Ignored_String, Cursor);
            if Status_Value /= Ok or else Cursor > Payload'Last then
               Clear (Item.Request_Name);
               return Read_Failed;
            end if;

            Status_Value :=
              SSH_Lib.Protocol.Numbers.Decode_Boolean
                (Payload (Cursor), Ignored_Core);
            if Status_Value /= Ok then
               Clear (Item.Request_Name);
               return Read_Failed;
            end if;
            Cursor := Cursor + 1;

            Status_Value :=
              SSH_Lib.Protocol.Numbers.Decode_SSH_String
                (Payload, Cursor, Ignored_String, Cursor);
            if Status_Value /= Ok or else Cursor > Payload'Last then
               Clear (Item.Request_Name);
               return Read_Failed;
            end if;

            Status_Value :=
              SSH_Lib.Protocol.Numbers.Decode_SSH_String
                (Payload, Cursor, Ignored_String, Cursor);
            if Status_Value /= Ok or else Cursor /= Payload'Last + 1 then
               Clear (Item.Request_Name);
               return Read_Failed;
            end if;
         end;
      else
         --  RFC 4254 channel requests are extensible: request-specific data
         --  may follow want-reply.  Unknown vendor requests carry typed
         --  trailing fields that this layer must not try to interpret.  The
         --  channel layer only needs the recipient, request name, and
         --  want-reply bit so it can send CHANNEL_FAILURE when requested.
         null;
      end if;
      return Ok;
   exception
      when others =>
         Clear (Item.Request_Name);
         return Read_Failed;
   end Parse_Channel_Request;

   function Request_Is_Exit_Status
     (Item : Channel_Request_Event) return Boolean
   is
      Name_Data : constant Stream_Element_Array :=
        To_Array (Item.Request_Name);
      Exit_Name : constant Stream_Element_Array (1 .. 11) :=
        [Stream_Element (Character'Pos ('e')),
         Stream_Element (Character'Pos ('x')),
         Stream_Element (Character'Pos ('i')),
         Stream_Element (Character'Pos ('t')),
         Stream_Element (Character'Pos ('-')),
         Stream_Element (Character'Pos ('s')),
         Stream_Element (Character'Pos ('t')),
         Stream_Element (Character'Pos ('a')),
         Stream_Element (Character'Pos ('t')),
         Stream_Element (Character'Pos ('u')),
         Stream_Element (Character'Pos ('s'))];
   begin
      if Name_Data'Length /= Exit_Name'Length then
         return False;
      end if;

      for Offset_Value in 0 .. Name_Data'Length - 1 loop
         if Name_Data (Name_Data'First + Stream_Element_Offset (Offset_Value))
           /= Exit_Name
                (Exit_Name'First + Stream_Element_Offset (Offset_Value))
         then
            return False;
         end if;
      end loop;
      return True;
   exception
      when others =>
         return False;
   end Request_Is_Exit_Status;

   function Request_Is_Exit_Signal
     (Item : Channel_Request_Event) return Boolean
   is
      Name_Data   : constant Stream_Element_Array :=
        To_Array (Item.Request_Name);
      Signal_Name : constant Stream_Element_Array (1 .. 11) :=
        [Stream_Element (Character'Pos ('e')),
         Stream_Element (Character'Pos ('x')),
         Stream_Element (Character'Pos ('i')),
         Stream_Element (Character'Pos ('t')),
         Stream_Element (Character'Pos ('-')),
         Stream_Element (Character'Pos ('s')),
         Stream_Element (Character'Pos ('i')),
         Stream_Element (Character'Pos ('g')),
         Stream_Element (Character'Pos ('n')),
         Stream_Element (Character'Pos ('a')),
         Stream_Element (Character'Pos ('l'))];
   begin
      if Name_Data'Length /= Signal_Name'Length then
         return False;
      end if;

      for Offset_Value in 0 .. Name_Data'Length - 1 loop
         if Name_Data (Name_Data'First + Stream_Element_Offset (Offset_Value))
           /= Signal_Name
                (Signal_Name'First + Stream_Element_Offset (Offset_Value))
         then
            return False;
         end if;
      end loop;
      return True;
   exception
      when others =>
         return False;
   end Request_Is_Exit_Signal;

   function Encode_Exit_Status_Request
     (Recipient_Channel : Unsigned_32;
      Want_Reply        : Boolean;
      Exit_Status       : Unsigned_32) return Packet_Buffer
   is
      Result       : Packet_Buffer :=
        Append_Message_And_Channel
          (SSH_MSG_CHANNEL_REQUEST, Recipient_Channel);
      Status_Value : Status;
   begin
      if Is_Empty (Result) then
         return Result;
      end if;

      Status_Value := Append_String (Result, "exit-status");
      if Status_Value /= Ok then
         Clear (Result);
         return Result;
      end if;

      Status_Value :=
        Append_Byte
          (Result, SSH_Lib.Protocol.Numbers.Encode_Boolean (Want_Reply));
      if Status_Value /= Ok then
         Clear (Result);
         return Result;
      end if;

      Status_Value :=
        Append (Result, SSH_Lib.Protocol.Numbers.Encode_Uint32 (Exit_Status));
      if Status_Value /= Ok then
         Clear (Result);
      end if;
      return Result;
   exception
      when others =>
         Clear (Result);
         return Result;
   end Encode_Exit_Status_Request;

   function Encode_Channel_Success
     (Recipient_Channel : Unsigned_32) return Packet_Buffer is
   begin
      return
        Append_Message_And_Channel
          (SSH_MSG_CHANNEL_SUCCESS, Recipient_Channel);
   end Encode_Channel_Success;

   function Encode_Channel_Failure
     (Recipient_Channel : Unsigned_32) return Packet_Buffer is
   begin
      return
        Append_Message_And_Channel
          (SSH_MSG_CHANNEL_FAILURE, Recipient_Channel);
   end Encode_Channel_Failure;

end SSH_Lib.Protocol.Channels;
