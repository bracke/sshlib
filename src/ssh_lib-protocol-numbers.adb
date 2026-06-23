with SSH_Lib.Protocol.Validation;

package body SSH_Lib.Protocol.Numbers is
   use Ada.Streams;
   use Ada.Strings.Unbounded;
   use Interfaces;
   use CryptoLib.Errors;
   use SSH_Lib.Protocol.Buffers;

   function Encode_Uint32
     (Value : Unsigned_32)
      return Stream_Element_Array
   is
      Result : Stream_Element_Array (1 .. 4);
   begin
      Result (1) := Stream_Element (Shift_Right (Value, 24) and 16#FF#);
      Result (2) := Stream_Element (Shift_Right (Value, 16) and 16#FF#);
      Result (3) := Stream_Element (Shift_Right (Value, 8) and 16#FF#);
      Result (4) := Stream_Element (Value and 16#FF#);
      return Result;
   end Encode_Uint32;

   function Decode_Uint32
     (Data        : Stream_Element_Array;
      First_Index : Stream_Element_Offset;
      Value       : out Unsigned_32;
      Next_Index  : out Stream_Element_Offset)
      return Status
   is
   begin
      Value := 0;
      Next_Index := First_Index;

      if First_Index < Data'First
        or else First_Index + 3 > Data'Last
      then
         return Handshake_Failed;
      end if;

      Value := Shift_Left (Unsigned_32 (Data (First_Index)), 24)
        or Shift_Left (Unsigned_32 (Data (First_Index + 1)), 16)
        or Shift_Left (Unsigned_32 (Data (First_Index + 2)), 8)
        or Unsigned_32 (Data (First_Index + 3));
      Next_Index := First_Index + 4;
      return Ok;
   exception
      when others =>
         Value := 0;
         Next_Index := First_Index;
         return Internal_Error;
   end Decode_Uint32;

   function Encode_Boolean
     (Value : Boolean)
      return Stream_Element
   is
   begin
      if Value then
         return 1;
      else
         return 0;
      end if;
   end Encode_Boolean;

   function Decode_Boolean
     (Value  : Stream_Element;
      Result : out Boolean)
      return Status
   is
   begin
      if Value = 0 then
         Result := False;
         return Ok;
      elsif Value = 1 then
         Result := True;
         return Ok;
      else
         Result := False;
         return Handshake_Failed;
      end if;
   end Decode_Boolean;

   function Encode_SSH_String
     (Payload : Stream_Element_Array)
      return Packet_Buffer
   is
      Result : Packet_Buffer;
      Status_Value : Status;
   begin
      Clear (Result);
      if Payload'Length > Max_Packet_Length - 4 then
         return Result;
      end if;

      Status_Value := Append
        (Result, Encode_Uint32 (Unsigned_32 (Payload'Length)));
      if Status_Value /= Ok then
         Clear (Result);
         return Result;
      end if;

      Status_Value := Append (Result, Payload);
      if Status_Value /= Ok then
         Clear (Result);
      end if;
      return Result;
   exception
      when others =>
         Clear (Result);
         return Result;
   end Encode_SSH_String;

   function Decode_SSH_String
     (Data        : Stream_Element_Array;
      First_Index : Stream_Element_Offset;
      Payload     : out Packet_Buffer;
      Next_Index  : out Stream_Element_Offset)
      return Status
   is
      Size_Value : Unsigned_32;
      Cursor : Stream_Element_Offset;
      Last_Payload : Stream_Element_Offset;
      Status_Value : Status;
   begin
      Clear (Payload);
      Next_Index := First_Index;
      Status_Value := Decode_Uint32 (Data, First_Index, Size_Value, Cursor);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      if Size_Value > Unsigned_32 (Max_Packet_Length) then
         return Handshake_Failed;
      end if;

      if Size_Value = 0 then
         Next_Index := Cursor;
         return Ok;
      end if;

      Last_Payload := Cursor + Stream_Element_Offset (Size_Value) - 1;
      if Last_Payload > Data'Last then
         return Handshake_Failed;
      end if;

      Status_Value := Set (Payload, Data (Cursor .. Last_Payload));
      if Status_Value /= Ok then
         Clear (Payload);
         return Status_Value;
      end if;

      Next_Index := Last_Payload + 1;
      return Ok;
   exception
      when others =>
         Clear (Payload);
         Next_Index := First_Index;
         return Internal_Error;
   end Decode_SSH_String;

   function Encode_Name_List
     (Value : String)
      return Packet_Buffer
   is
      Payload : Stream_Element_Array
        (Stream_Element_Offset'(1) .. Stream_Element_Offset (Value'Length));
      Position_Index : Stream_Element_Offset := 1;
   begin
      for Character_Value of Value loop
         Payload (Position_Index) := Stream_Element (Character'Pos (Character_Value));
         Position_Index := Position_Index + 1;
      end loop;
      return Encode_SSH_String (Payload);
   end Encode_Name_List;

   function Decode_Name_List
     (Data        : Stream_Element_Array;
      First_Index : Stream_Element_Offset;
      Value       : out Unbounded_String;
      Next_Index  : out Stream_Element_Offset)
      return Status
   is
      Payload : Packet_Buffer;
      Status_Value : Status;
   begin
      Value := Null_Unbounded_String;
      Status_Value := Decode_SSH_String (Data, First_Index, Payload, Next_Index);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      declare
         Payload_Data : constant Stream_Element_Array := To_Array (Payload);
      begin
         for Byte_Value of Payload_Data loop
            if Byte_Value > 127 then
               Value := Null_Unbounded_String;
               return Handshake_Failed;
            end if;
            Append (Value, Character'Val (Natural (Byte_Value)));
         end loop;
      end;

      declare
         Text_Value : constant String := To_String (Value);
         Segment_First : Positive;
      begin
         if Text_Value'Length = 0 then
            return Ok;
         end if;

         Segment_First := Text_Value'First;
         for Text_Index in Text_Value'Range loop
            if Text_Value (Text_Index) = ',' then
               if Text_Index = Segment_First then
                  Value := Null_Unbounded_String;
                  return Handshake_Failed;
               end if;

               if not SSH_Lib.Protocol.Validation.Is_ASCII_Protocol_Name
                 (Text_Value (Segment_First .. Text_Index - 1))
               then
                  Value := Null_Unbounded_String;
                  return Handshake_Failed;
               end if;

               if Text_Index = Text_Value'Last then
                  Value := Null_Unbounded_String;
                  return Handshake_Failed;
               end if;

               Segment_First := Text_Index + 1;
            end if;
         end loop;

         if not SSH_Lib.Protocol.Validation.Is_ASCII_Protocol_Name
           (Text_Value (Segment_First .. Text_Value'Last))
         then
            Value := Null_Unbounded_String;
            return Handshake_Failed;
         end if;
      end;

      return Ok;
   exception
      when others =>
         Value := Null_Unbounded_String;
         Next_Index := First_Index;
         return Internal_Error;
   end Decode_Name_List;
end SSH_Lib.Protocol.Numbers;
