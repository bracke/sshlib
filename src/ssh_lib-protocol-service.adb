with SSH_Lib.Protocol.Numbers;
with SSH_Lib.Protocol.Validation;

package body SSH_Lib.Protocol.Service is
   use Ada.Streams;
   use CryptoLib.Errors;
   use SSH_Lib.Protocol.Buffers;

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

   function Text_From_Bytes
     (Data         : Stream_Element_Array;
      Status_Value : out Status)
      return String
   is
      Result : String (1 .. Data'Length);
      Cursor : Positive := Result'First;
   begin
      Status_Value := Ok;
      for Byte_Value of Data loop
         if Byte_Value > 127 then
            Status_Value := Handshake_Failed;
            return "";
         end if;
         Result (Cursor) := Character'Val (Natural (Byte_Value));
         Cursor := Cursor + 1;
      end loop;
      return Result;
   end Text_From_Bytes;

   function Encode_Service_Request
     (Service_Name : String)
      return Packet_Buffer
   is
      Result       : Packet_Buffer;
      Encoded_Name : constant Packet_Buffer :=
        SSH_Lib.Protocol.Numbers.Encode_SSH_String (Bytes_From_String (Service_Name));
      Status_Value : Status;
   begin
      Clear (Result);
      if not SSH_Lib.Protocol.Validation.Is_ASCII_Protocol_Name (Service_Name) then
         return Result;
      end if;

      Status_Value := Append_Byte (Result, SSH_MSG_SERVICE_REQUEST);
      if Status_Value = Ok then
         Status_Value := Append (Result, To_Array (Encoded_Name));
      end if;
      if Status_Value /= Ok then
         Clear (Result);
      end if;
      return Result;
   exception
      when others =>
         Clear (Result);
         return Result;
   end Encode_Service_Request;

   function Encode_Userauth_Service_Request
      return Packet_Buffer
   is
   begin
      return Encode_Service_Request ("ssh-userauth");
   end Encode_Userauth_Service_Request;

   function Parse_Service_Accept
     (Payload       : Stream_Element_Array;
      Expected_Name : String)
      return Status
   is
      Cursor       : Stream_Element_Offset;
      Next_Index   : Stream_Element_Offset;
      Name_Buffer  : Packet_Buffer;
      Status_Value : Status;
   begin
      if not SSH_Lib.Protocol.Validation.Is_ASCII_Protocol_Name (Expected_Name) then
         return Handshake_Failed;
      end if;

      if Payload'Length < 1 or else Payload (Payload'First) /= SSH_MSG_SERVICE_ACCEPT then
         return Handshake_Failed;
      end if;

      Cursor := Payload'First + 1;
      Status_Value := SSH_Lib.Protocol.Numbers.Decode_SSH_String
        (Payload, Cursor, Name_Buffer, Next_Index);
      if Status_Value /= Ok then
         return Handshake_Failed;
      end if;

      if Next_Index /= Payload'Last + 1 then
         return Handshake_Failed;
      end if;

      declare
         Actual_Text : constant String := Text_From_Bytes (To_Array (Name_Buffer), Status_Value);
      begin
         if Status_Value /= Ok or else Actual_Text /= Expected_Name then
            return Handshake_Failed;
         end if;
      end;

      return Ok;
   exception
      when others =>
         return Internal_Error;
   end Parse_Service_Accept;
end SSH_Lib.Protocol.Service;
