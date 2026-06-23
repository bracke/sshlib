with SSH_Lib.Protocol.Numbers;

package body SSH_Lib.Protocol.Auth_Methods is
   use Ada.Streams;
   use Ada.Strings.Unbounded;
   use CryptoLib.Errors;

   SSH_MSG_USERAUTH_FAILURE : constant Stream_Element := 51;

   function Parse_Failure
     (Payload : Stream_Element_Array;
      Info    : out Failure_Info)
      return Status
   is
      Cursor       : Stream_Element_Offset;
      Next_Index   : Stream_Element_Offset;
      Status_Value : Status;
   begin
      Info.Remaining_Methods := Null_Unbounded_String;
      Info.Partial_Success := False;

      if Payload'Length < 1 or else Payload (Payload'First) /= SSH_MSG_USERAUTH_FAILURE then
         return Authentication_Failed;
      end if;

      Cursor := Payload'First + 1;
      Status_Value := SSH_Lib.Protocol.Numbers.Decode_Name_List
        (Payload, Cursor, Info.Remaining_Methods, Next_Index);
      if Status_Value /= Ok then
         Info.Remaining_Methods := Null_Unbounded_String;
         return Authentication_Failed;
      end if;

      if Next_Index > Payload'Last then
         Info.Remaining_Methods := Null_Unbounded_String;
         return Authentication_Failed;
      end if;

      Status_Value := SSH_Lib.Protocol.Numbers.Decode_Boolean
        (Payload (Next_Index), Info.Partial_Success);
      if Status_Value /= Ok or else Next_Index + 1 /= Payload'Last + 1 then
         Info.Remaining_Methods := Null_Unbounded_String;
         Info.Partial_Success := False;
         return Authentication_Failed;
      end if;

      return Ok;
   exception
      when others =>
         Info.Remaining_Methods := Null_Unbounded_String;
         Info.Partial_Success := False;
         return Internal_Error;
   end Parse_Failure;

   function Contains_Publickey
     (Info : Failure_Info)
      return Boolean
   is
      Text_Value : constant String := To_String (Info.Remaining_Methods);
      First_Pos  : Positive := Text_Value'First;
   begin
      if Text_Value'Length = 0 then
         return False;
      end if;

      for Index_Value in Text_Value'Range loop
         if Text_Value (Index_Value) = ',' then
            if Text_Value (First_Pos .. Index_Value - 1) = "publickey" then
               return True;
            end if;
            First_Pos := Index_Value + 1;
         end if;
      end loop;

      return Text_Value (First_Pos .. Text_Value'Last) = "publickey";
   end Contains_Publickey;
end SSH_Lib.Protocol.Auth_Methods;
