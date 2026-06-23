
package body SSH_Lib.Protocol.Identification is
   use Ada.Streams;
   use Ada.Strings.Unbounded;
   use CryptoLib.Errors;

   procedure Reset (Item : out Identification_State) is
   begin
      Item.Local_Value := To_Unbounded_String (Local_Identification);
      Item.Remote_Value := Null_Unbounded_String;
      Item.Has_Remote_Value := False;
   end Reset;

   function Has_Remote_Identification
     (Item : Identification_State)
      return Boolean
   is
   begin
      return Item.Has_Remote_Value;
   end Has_Remote_Identification;

   function Local_Text
     (Item : Identification_State)
      return String
   is
   begin
      if Length (Item.Local_Value) = 0 then
         return Local_Identification;
      end if;
      return To_String (Item.Local_Value);
   end Local_Text;

   function Remote_Text
     (Item : Identification_State)
      return String
   is
   begin
      return To_String (Item.Remote_Value);
   end Remote_Text;

   function Local_Identification return String is
   begin
      return "SSH-2.0-SSH_Lib_1.0";
   end Local_Identification;

   function Local_Identification_Line
      return Stream_Element_Array
   is
      Text_Value : constant String := Local_Identification;
      Result : Stream_Element_Array
        (1 .. Stream_Element_Offset (Text_Value'Length + 2));
      Cursor : Stream_Element_Offset := 1;
   begin
      for Character_Value of Text_Value loop
         Result (Cursor) := Stream_Element (Character'Pos (Character_Value));
         Cursor := Cursor + 1;
      end loop;
      Result (Cursor) := 13;
      Result (Cursor + 1) := 10;
      return Result;
   end Local_Identification_Line;

   function Starts_With (Value : String; Prefix : String) return Boolean is
   begin
      return Value'Length >= Prefix'Length
        and then Value (Value'First .. Value'First + Prefix'Length - 1) = Prefix;
   end Starts_With;

   function Parse_Remote_Identification
     (Data              : Stream_Element_Array;
      Remote_Text       : out Unbounded_String;
      Consumed_Index    : out Stream_Element_Offset;
      Accept_SSH_1_99   : Boolean := False)
      return Status
   is
      Line_Start : Stream_Element_Offset := Data'First;
      Line_Count : Natural := 0;
   begin
      Remote_Text := Null_Unbounded_String;
      Consumed_Index := Data'First - 1;

      if Data'Length = 0 then
         return Timeout;
      end if;

      while Line_Start <= Data'Last loop
         declare
            Line_End : Stream_Element_Offset := Line_Start;
            Found_LF : Boolean := False;
            Text_Last : Stream_Element_Offset;
         begin
            while Line_End <= Data'Last loop
               if Data (Line_End) = 0 then
                  return Handshake_Failed;
               end if;

               if Line_End - Line_Start + 1 >
                 Stream_Element_Offset (Max_Identification_Line_Length)
               then
                  return Handshake_Failed;
               end if;

               if Data (Line_End) = 10 then
                  Found_LF := True;
                  exit;
               end if;

               Line_End := Line_End + 1;
            end loop;

            if not Found_LF then
               return Timeout;
            end if;

            Line_Count := Line_Count + 1;
            if Line_Count > Max_Banner_Lines + 1 then
               return Handshake_Failed;
            end if;

            Text_Last := Line_End - 1;
            if Text_Last >= Line_Start and then Data (Text_Last) = 13 then
               Text_Last := Text_Last - 1;
            end if;

            declare
               Line_Text : String (1 .. Natural (Text_Last - Line_Start + 1));
               String_Index : Natural := 1;
            begin
               for Source_Index in Line_Start .. Text_Last loop
                  if Data (Source_Index) > 127 then
                     return Handshake_Failed;
                  end if;
                  Line_Text (String_Index) := Character'Val (Natural (Data (Source_Index)));
                  String_Index := String_Index + 1;
               end loop;

               if Starts_With (Line_Text, "SSH-") then
                  if Starts_With (Line_Text, "SSH-2.0-") then
                     Remote_Text := To_Unbounded_String (Line_Text);
                     Consumed_Index := Line_End;
                     return Ok;
                  elsif Starts_With (Line_Text, "SSH-1.99-") then
                     if Accept_SSH_1_99 then
                        Remote_Text := To_Unbounded_String (Line_Text);
                        Consumed_Index := Line_End;
                        return Ok;
                     else
                        return Unsupported_Feature;
                     end if;
                  else
                     return Unsupported_Feature;
                  end if;
               end if;
            end;

            if Line_Count > Max_Banner_Lines then
               return Handshake_Failed;
            end if;

            Line_Start := Line_End + 1;
         end;
      end loop;

      return Handshake_Failed;
   exception
      when others =>
         Remote_Text := Null_Unbounded_String;
         Consumed_Index := Data'First - 1;
         return Internal_Error;
   end Parse_Remote_Identification;

   function Parse_And_Store_Remote_Identification
     (Item              : in out Identification_State;
      Data              : Stream_Element_Array;
      Consumed_Index    : out Stream_Element_Offset;
      Accept_SSH_1_99   : Boolean := False)
      return Status
   is
      Parsed_Remote : Unbounded_String;
      Status_Value  : Status;
   begin
      Status_Value := Parse_Remote_Identification
        (Data, Parsed_Remote, Consumed_Index, Accept_SSH_1_99);

      if Status_Value = Ok then
         if Length (Item.Local_Value) = 0 then
            Item.Local_Value := To_Unbounded_String (Local_Identification);
         end if;
         Item.Remote_Value := Parsed_Remote;
         Item.Has_Remote_Value := True;
      else
         Item.Remote_Value := Null_Unbounded_String;
         Item.Has_Remote_Value := False;
      end if;

      return Status_Value;
   exception
      when others =>
         Item.Remote_Value := Null_Unbounded_String;
         Item.Has_Remote_Value := False;
         return Internal_Error;
   end Parse_And_Store_Remote_Identification;
end SSH_Lib.Protocol.Identification;
