with Interfaces;
with SSH_Lib.Protocol.Messages;
with SSH_Lib.Protocol.Numbers;

package body SSH_Lib.Protocol.Transport_Messages is
   use type CryptoLib.Errors.Status;
   use Ada.Streams;
   use Interfaces;

   function Classify
     (Payload : Stream_Element_Array) return Transport_Message_Kind
   is
      Message_Number : Natural;
   begin
      if Payload'Length = 0 then
         return Transport_Other;
      end if;

      Message_Number := Natural (Payload (Payload'First));
      if Message_Number = SSH_Lib.Protocol.Messages.SSH_MSG_DISCONNECT then
         return Transport_Disconnect;
      elsif Message_Number = SSH_Lib.Protocol.Messages.SSH_MSG_IGNORE then
         return Transport_Ignore;
      elsif Message_Number = SSH_Lib.Protocol.Messages.SSH_MSG_UNIMPLEMENTED
      then
         return Transport_Unimplemented;
      elsif Message_Number = SSH_Lib.Protocol.Messages.SSH_MSG_DEBUG then
         return Transport_Debug;
      elsif Message_Number = SSH_Lib.Protocol.Messages.SSH_MSG_EXT_INFO then
         return Transport_Ext_Info;
      else
         return Transport_Other;
      end if;
   exception
      when others =>
         return Transport_Other;
   end Classify;

   function Is_Ignorable_During_Wait
     (Payload : Stream_Element_Array) return Boolean is
   begin
      case Classify (Payload) is
         when Transport_Ignore
            | Transport_Unimplemented
            | Transport_Debug
            | Transport_Ext_Info =>
            return True;

         when others             =>
            return False;
      end case;
   exception
      when others =>
         return False;
   end Is_Ignorable_During_Wait;

   function Failure_Status
     (Payload         : Stream_Element_Array;
      Default_Failure : CryptoLib.Errors.Status) return CryptoLib.Errors.Status
   is
   begin
      if Classify (Payload) = Transport_Disconnect then
         return CryptoLib.Errors.Connection_Failed;
      else
         return Default_Failure;
      end if;
   exception
      when others =>
         return Default_Failure;
   end Failure_Status;

   function To_Bytes (Value : String) return Stream_Element_Array is
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
   end To_Bytes;

   function Append_SSH_Text
     (Item : in out SSH_Lib.Protocol.Buffers.Packet_Buffer; Value : String)
      return CryptoLib.Errors.Status
   is
      Text_Buffer : SSH_Lib.Protocol.Buffers.Packet_Buffer;
   begin
      if Value'Length = 0 then
         return
           SSH_Lib.Protocol.Buffers.Append
             (Item, SSH_Lib.Protocol.Numbers.Encode_Uint32 (0));
      end if;

      Text_Buffer :=
        SSH_Lib.Protocol.Numbers.Encode_SSH_String (To_Bytes (Value));
      if SSH_Lib.Protocol.Buffers.Is_Empty (Text_Buffer) then
         return CryptoLib.Errors.Internal_Error;
      end if;
      return
        SSH_Lib.Protocol.Buffers.Append
          (Item, SSH_Lib.Protocol.Buffers.To_Array (Text_Buffer));
   exception
      when others =>
         return CryptoLib.Errors.Internal_Error;
   end Append_SSH_Text;

   function Encode_Disconnect
     (Reason_Code : Natural; Description : String)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer
   is
      Result       : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Status_Value : CryptoLib.Errors.Status;
   begin
      SSH_Lib.Protocol.Buffers.Clear (Result);

      Status_Value :=
        SSH_Lib.Protocol.Buffers.Append_Byte
          (Result,
           Stream_Element (SSH_Lib.Protocol.Messages.SSH_MSG_DISCONNECT));
      if Status_Value /= CryptoLib.Errors.Ok then
         SSH_Lib.Protocol.Buffers.Clear (Result);
         return Result;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Buffers.Append
          (Result,
           SSH_Lib.Protocol.Numbers.Encode_Uint32 (Unsigned_32 (Reason_Code)));
      if Status_Value /= CryptoLib.Errors.Ok then
         SSH_Lib.Protocol.Buffers.Clear (Result);
         return Result;
      end if;

      Status_Value := Append_SSH_Text (Result, Description);
      if Status_Value /= CryptoLib.Errors.Ok then
         SSH_Lib.Protocol.Buffers.Clear (Result);
         return Result;
      end if;

      Status_Value := Append_SSH_Text (Result, "");
      if Status_Value /= CryptoLib.Errors.Ok then
         SSH_Lib.Protocol.Buffers.Clear (Result);
      end if;

      return Result;
   exception
      when others =>
         SSH_Lib.Protocol.Buffers.Clear (Result);
         return Result;
   end Encode_Disconnect;
end SSH_Lib.Protocol.Transport_Messages;
