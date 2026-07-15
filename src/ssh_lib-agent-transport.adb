with SSH_Lib.Agent.Protocol;

package body SSH_Lib.Agent.Transport is
   use Ada.Streams;
   use CryptoLib.Errors;

   procedure Reset (Item : in out Agent_Connection) is
   begin
      Hostkit.Local_Channel.Close (Item.Channel);
      Item.Connected := False;
   end Reset;

   function Connect
     (Socket_Path : String;
      Item        : out Agent_Connection)
      return Status
   is
   begin
      Item.Connected := False;
      if Socket_Path'Length = 0 then
         return Connection_Failed;
      end if;

      if not Hostkit.Local_Channel.Connect (Socket_Path, Item.Channel) then
         return Connection_Failed;
      end if;

      Item.Connected := True;
      return Ok;
   exception
      when others =>
         Reset (Item);
         return Internal_Error;
   end Connect;

   function Connect
     (Socket_Path : String;
      Timeout_MS  : Natural;
      Item        : out Agent_Connection)
      return Status
   is
   begin
      Item.Connected := False;
      if Timeout_MS = 0 then
         return Timeout;
      end if;
      return Connect (Socket_Path, Item);
   exception
      when others =>
         Reset (Item);
         return Internal_Error;
   end Connect;

   function Send_All
     (Item : in out Agent_Connection;
      Data : Stream_Element_Array)
      return Status
   is
   begin
      if Data'Length = 0 then
         return Ok;
      end if;

      if not Hostkit.Local_Channel.Send (Item.Channel, Data) then
         Reset (Item);
         return Write_Failed;
      end if;

      return Ok;
   exception
      when others =>
         Reset (Item);
         return Internal_Error;
   end Send_All;

   function Read_Exact
     (Item : in out Agent_Connection;
      Data : out Stream_Element_Array)
      return Status
   is
   begin
      if Data'Length = 0 then
         return Ok;
      end if;

      if not Hostkit.Local_Channel.Receive (Item.Channel, Data) then
         Reset (Item);
         return Read_Failed;
      end if;

      return Ok;
   exception
      when others =>
         Reset (Item);
         return Internal_Error;
   end Read_Exact;

   function Send_Message
     (Item    : in out Agent_Connection;
      Payload : Stream_Element_Array)
      return Status
   is
      Header : constant Stream_Element_Array :=
        SSH_Lib.Agent.Protocol.Encode_Message_Length (Payload'Length);
      Status_Value : Status;
   begin
      if not Item.Connected then
         return Write_Failed;
      elsif Payload'Length = 0
        or else Payload'Length > SSH_Lib.Agent.Max_Agent_Message_Size
      then
         Reset (Item);
         return Authentication_Failed;
      end if;

      Status_Value := Send_All (Item, Header);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      return Send_All (Item, Payload);
   exception
      when others =>
         Reset (Item);
         return Internal_Error;
   end Send_Message;

   function Send_Message
     (Item       : in out Agent_Connection;
      Payload    : Stream_Element_Array;
      Timeout_MS : Natural)
      return Status
   is
   begin
      if Timeout_MS = 0 then
         return Timeout;
      end if;
      return Send_Message (Item, Payload);
   exception
      when others =>
         Reset (Item);
         return Internal_Error;
   end Send_Message;

   function Receive_Message
     (Item    : in out Agent_Connection;
      Payload : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return Status
   is
      Header       : Stream_Element_Array (1 .. 4);
      Payload_Size : Natural := 0;
      Status_Value : Status;
   begin
      SSH_Lib.Protocol.Buffers.Clear (Payload);
      if not Item.Connected then
         return Read_Failed;
      end if;

      Status_Value := Read_Exact (Item, Header);
      if Status_Value /= Ok then
         Header := [others => 0];
         return Status_Value;
      end if;

      Status_Value := SSH_Lib.Agent.Protocol.Decode_Message_Length (Header, Payload_Size);
      Header := [others => 0];
      if Status_Value /= Ok then
         Reset (Item);
         return Status_Value;
      end if;

      declare
         Body_Data : Stream_Element_Array (1 .. Stream_Element_Offset (Payload_Size));
      begin
         Status_Value := Read_Exact (Item, Body_Data);
         if Status_Value /= Ok then
            Body_Data := [others => 0];
            return Status_Value;
         end if;
         Status_Value := SSH_Lib.Protocol.Buffers.Set (Payload, Body_Data);
         Body_Data := [others => 0];
         if Status_Value /= Ok then
            Reset (Item);
            SSH_Lib.Protocol.Buffers.Clear (Payload);
            return Status_Value;
         end if;
      end;

      return Ok;
   exception
      when others =>
         SSH_Lib.Protocol.Buffers.Clear (Payload);
         Reset (Item);
         return Internal_Error;
   end Receive_Message;

   function Receive_Message
     (Item       : in out Agent_Connection;
      Payload    : out SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Timeout_MS : Natural)
      return Status
   is
   begin
      SSH_Lib.Protocol.Buffers.Clear (Payload);
      if Timeout_MS = 0 then
         return Timeout;
      end if;
      return Receive_Message (Item, Payload);
   exception
      when others =>
         SSH_Lib.Protocol.Buffers.Clear (Payload);
         Reset (Item);
         return Internal_Error;
   end Receive_Message;

   function Close
     (Item : in out Agent_Connection)
      return Status
   is
   begin
      Reset (Item);
      return Ok;
   exception
      when others =>
         Item.Connected := False;
         return Ok;
   end Close;
end SSH_Lib.Agent.Transport;
