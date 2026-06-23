with Interfaces;
with SSH_Lib.Protocol.Numbers;
with SSH_Lib.Protocol.Transport_Messages;

package body SSH_Lib.Protocol.Global_Requests is
   use Ada.Streams;
   use CryptoLib.Errors;
   use SSH_Lib.Protocol.Buffers;
   use type Interfaces.Unsigned_32;

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

   function Valid_Bind_Address (Value : String) return Boolean is
   begin
      if Value'Length = 0 then
         return False;
      end if;

      for Character_Value of Value loop
         if Character_Value = Character'Val (0)
           or else Character_Value = Character'Val (10)
           or else Character_Value = Character'Val (13)
         then
            return False;
         end if;
      end loop;

      return True;
   end Valid_Bind_Address;

   function Encode_TCPIP_Forward_Like_Request
     (Request_Name : String;
      Bind_Address : String;
      Bind_Port    : Natural)
      return Packet_Buffer
   is
      Result       : Packet_Buffer;
      Status_Value : Status;
   begin
      Clear (Result);
      if not Valid_Bind_Address (Bind_Address) or else Bind_Port > 65_535 then
         return Result;
      end if;

      Status_Value := Append_Byte (Result, SSH_MSG_GLOBAL_REQUEST);
      if Status_Value /= Ok then
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

      Status_Value := Append_String (Result, Bind_Address);
      if Status_Value /= Ok then
         Clear (Result);
         return Result;
      end if;

      Status_Value :=
        Append
          (Result,
           SSH_Lib.Protocol.Numbers.Encode_Uint32
             (Interfaces.Unsigned_32 (Bind_Port)));
      if Status_Value /= Ok then
         Clear (Result);
      end if;
      return Result;
   exception
      when others =>
         Clear (Result);
         return Result;
   end Encode_TCPIP_Forward_Like_Request;

   function Encode_TCPIP_Forward_Request
     (Bind_Address : String;
      Bind_Port    : Natural)
      return Packet_Buffer is
   begin
      return Encode_TCPIP_Forward_Like_Request
        ("tcpip-forward", Bind_Address, Bind_Port);
   end Encode_TCPIP_Forward_Request;

   function Encode_Cancel_TCPIP_Forward_Request
     (Bind_Address : String;
      Bind_Port    : Natural)
      return Packet_Buffer is
   begin
      return Encode_TCPIP_Forward_Like_Request
        ("cancel-tcpip-forward", Bind_Address, Bind_Port);
   end Encode_Cancel_TCPIP_Forward_Request;

   function Parse_TCPIP_Forward_Reply
     (Payload        : Stream_Element_Array;
      Requested_Port : Natural;
      Bound_Port     : out Natural)
      return Status
   is
      Cursor     : Stream_Element_Offset;
      Port_Value : Interfaces.Unsigned_32 := 0;
      Decode_Status : Status;
   begin
      Bound_Port := 0;
      if Payload'Length = 0 then
         return Channel_Request_Failed;
      elsif Payload (Payload'First) = SSH_MSG_REQUEST_FAILURE then
         if Payload'Length = 1 then
            return Channel_Request_Failed;
         end if;
         return Channel_Request_Failed;
      elsif Payload (Payload'First) /= SSH_MSG_REQUEST_SUCCESS then
         return Channel_Request_Failed;
      end if;

      if Requested_Port = 0 then
         if Payload'Length /= 5 then
            return Channel_Request_Failed;
         end if;
         Cursor := Payload'First + 1;
         Decode_Status :=
           SSH_Lib.Protocol.Numbers.Decode_Uint32
             (Payload, Cursor, Port_Value, Cursor);
         if Decode_Status /= Ok
           or else Cursor /= Payload'Last + 1
           or else Port_Value = 0
           or else Port_Value > 65_535
         then
            return Channel_Request_Failed;
         end if;
         Bound_Port := Natural (Port_Value);
      else
         if Payload'Length /= 1 or else Requested_Port > 65_535 then
            return Channel_Request_Failed;
         end if;
         Bound_Port := Requested_Port;
      end if;

      return Ok;
   exception
      when others =>
         Bound_Port := 0;
         return Channel_Request_Failed;
   end Parse_TCPIP_Forward_Reply;

   function Parse_Global_Request
     (Payload : Stream_Element_Array;
      Item    : out Global_Request)
      return Status
   is
      Cursor       : Stream_Element_Offset := Payload'First;
      Name_Buffer  : Packet_Buffer;
      Status_Value : Status;
   begin
      Item.Want_Reply := False;
      if Payload'Length < 6 or else Payload (Cursor) /= SSH_MSG_GLOBAL_REQUEST then
         return Read_Failed;
      end if;

      Cursor := Cursor + 1;
      Status_Value := SSH_Lib.Protocol.Numbers.Decode_SSH_String
        (Payload, Cursor, Name_Buffer, Cursor);
      if Status_Value /= Ok or else Cursor > Payload'Last then
         return Read_Failed;
      end if;

      Status_Value := SSH_Lib.Protocol.Numbers.Decode_Boolean
        (Payload (Cursor), Item.Want_Reply);
      if Status_Value /= Ok then
         return Read_Failed;
      end if;

      --  RFC 4254 global requests may carry request-specific trailing data
      --  after want-reply.  The SSH transport layer does not need to interpret
      --  extension payloads such as OpenSSH hostkeys notifications while it is
      --  synchronizing channel-open or exec replies; accepting and ignoring the
      --  bounded trailing bytes keeps the protected packet stream aligned.
      return Ok;
   exception
      when others =>
         Item.Want_Reply := False;
         return Read_Failed;
   end Parse_Global_Request;

   function Encode_Request_Failure
      return Packet_Buffer
   is
      Result       : Packet_Buffer;
      Status_Value : Status;
   begin
      Clear (Result);
      Status_Value := Append_Byte (Result, SSH_MSG_REQUEST_FAILURE);
      if Status_Value /= Ok then
         Clear (Result);
      end if;
      return Result;
   exception
      when others =>
         Clear (Result);
         return Result;
   end Encode_Request_Failure;

   function Ignorable_While_Waiting_For_Channel_Response
     (Payload : Stream_Element_Array)
      return Boolean
   is
   begin
      if Payload'Length = 0 then
         return False;
      end if;

      return Payload (Payload'First) = SSH_MSG_REQUEST_SUCCESS
        or else Payload (Payload'First) = SSH_MSG_REQUEST_FAILURE
        or else SSH_Lib.Protocol.Transport_Messages.Is_Ignorable_During_Wait
          (Payload);
   exception
      when others =>
         return False;
   end Ignorable_While_Waiting_For_Channel_Response;
end SSH_Lib.Protocol.Global_Requests;
