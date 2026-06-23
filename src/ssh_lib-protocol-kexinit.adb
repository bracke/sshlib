with SSH_Lib.Algorithms;
with SSH_Lib.Protocol.Numbers;

package body SSH_Lib.Protocol.Kexinit is
   use Ada.Streams;
   use Ada.Strings.Unbounded;
   use Interfaces;
   use CryptoLib.Errors;
   use SSH_Lib.Protocol.Buffers;

   procedure Clear (Item : out Kexinit_Message) is
   begin
      Item.Cookie := [others => 0];
      Item.Kex_Algorithms := Null_Unbounded_String;
      Item.Server_Host_Key_Algorithms := Null_Unbounded_String;
      Item.Encryption_Algorithms_Client_To_Server := Null_Unbounded_String;
      Item.Encryption_Algorithms_Server_To_Client := Null_Unbounded_String;
      Item.Mac_Algorithms_Client_To_Server := Null_Unbounded_String;
      Item.Mac_Algorithms_Server_To_Client := Null_Unbounded_String;
      Item.Compression_Algorithms_Client_To_Server := Null_Unbounded_String;
      Item.Compression_Algorithms_Server_To_Client := Null_Unbounded_String;
      Item.Languages_Client_To_Server := Null_Unbounded_String;
      Item.Languages_Server_To_Client := Null_Unbounded_String;
      Item.First_Kex_Packet_Follows := False;
      Item.Reserved := 0;
      SSH_Lib.Protocol.Buffers.Clear (Item.Raw_Payload);
   end Clear;

   function Append_Name_List
     (Payload : in out Packet_Buffer;
      Value   : String)
      return Status
   is
      Encoded : constant Packet_Buffer := SSH_Lib.Protocol.Numbers.Encode_Name_List (Value);
   begin
      return Append (Payload, To_Array (Encoded));
   end Append_Name_List;

   function Validate_List (Value : Unbounded_String) return Boolean is
   begin
      return SSH_Lib.Algorithms.Validate_Name_List (To_String (Value));
   end Validate_List;

   function Encode
     (Item    : Kexinit_Message;
      Payload : out Packet_Buffer)
      return Status
   is
      Status_Value : Status;
   begin
      SSH_Lib.Protocol.Buffers.Clear (Payload);

      if not Validate_List (Item.Kex_Algorithms)
        or else not Validate_List (Item.Server_Host_Key_Algorithms)
        or else not Validate_List (Item.Encryption_Algorithms_Client_To_Server)
        or else not Validate_List (Item.Encryption_Algorithms_Server_To_Client)
        or else not Validate_List (Item.Mac_Algorithms_Client_To_Server)
        or else not Validate_List (Item.Mac_Algorithms_Server_To_Client)
        or else not Validate_List (Item.Compression_Algorithms_Client_To_Server)
        or else not Validate_List (Item.Compression_Algorithms_Server_To_Client)
        or else not Validate_List (Item.Languages_Client_To_Server)
        or else not Validate_List (Item.Languages_Server_To_Client)
      then
         return Handshake_Failed;
      end if;

      Status_Value := Append_Byte (Payload, Message_Number);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      for Byte_Value of Item.Cookie loop
         Status_Value := Append_Byte (Payload, Byte_Value);
         if Status_Value /= Ok then
            return Status_Value;
         end if;
      end loop;

      Status_Value := Append_Name_List (Payload, To_String (Item.Kex_Algorithms));
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Status_Value := Append_Name_List (Payload, To_String (Item.Server_Host_Key_Algorithms));
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Status_Value := Append_Name_List (Payload, To_String (Item.Encryption_Algorithms_Client_To_Server));
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Status_Value := Append_Name_List (Payload, To_String (Item.Encryption_Algorithms_Server_To_Client));
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Status_Value := Append_Name_List (Payload, To_String (Item.Mac_Algorithms_Client_To_Server));
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Status_Value := Append_Name_List (Payload, To_String (Item.Mac_Algorithms_Server_To_Client));
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Status_Value := Append_Name_List (Payload, To_String (Item.Compression_Algorithms_Client_To_Server));
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Status_Value := Append_Name_List (Payload, To_String (Item.Compression_Algorithms_Server_To_Client));
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Status_Value := Append_Name_List (Payload, To_String (Item.Languages_Client_To_Server));
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Status_Value := Append_Name_List (Payload, To_String (Item.Languages_Server_To_Client));
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      Status_Value := Append_Byte
        (Payload, SSH_Lib.Protocol.Numbers.Encode_Boolean (Item.First_Kex_Packet_Follows));
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      return Append (Payload, SSH_Lib.Protocol.Numbers.Encode_Uint32 (Item.Reserved));
   exception
      when others =>
         SSH_Lib.Protocol.Buffers.Clear (Payload);
         return Internal_Error;
   end Encode;

   function Construct_Client
     (Source_Item : in out CryptoLib.Random.Random_Source;
      Item        : out Kexinit_Message;
      Payload     : out Packet_Buffer)
      return Status
   is
      Random_Data : Stream_Element_Array (1 .. 16);
      Status_Value : Status;
   begin
      Clear (Item);
      Status_Value := CryptoLib.Random.Fill (Source_Item, Random_Data);
      if Status_Value /= Ok then
         SSH_Lib.Protocol.Buffers.Clear (Payload);
         return Status_Value;
      end if;

      for Index_Value in Cookie_Index loop
         Item.Cookie (Index_Value) := Random_Data (Stream_Element_Offset (Index_Value));
      end loop;

      Item.Kex_Algorithms := To_Unbounded_String
        (SSH_Lib.Algorithms.Advertised_Name_List (SSH_Lib.Algorithms.Key_Exchange));
      Item.Server_Host_Key_Algorithms := To_Unbounded_String
        (SSH_Lib.Algorithms.Advertised_Name_List (SSH_Lib.Algorithms.Server_Host_Key));
      Item.Encryption_Algorithms_Client_To_Server := To_Unbounded_String
        (SSH_Lib.Algorithms.Advertised_Name_List (SSH_Lib.Algorithms.Encryption_Client_To_Server));
      Item.Encryption_Algorithms_Server_To_Client := To_Unbounded_String
        (SSH_Lib.Algorithms.Advertised_Name_List (SSH_Lib.Algorithms.Encryption_Server_To_Client));
      Item.Mac_Algorithms_Client_To_Server := To_Unbounded_String
        (SSH_Lib.Algorithms.Advertised_Name_List (SSH_Lib.Algorithms.Mac_Client_To_Server));
      Item.Mac_Algorithms_Server_To_Client := To_Unbounded_String
        (SSH_Lib.Algorithms.Advertised_Name_List (SSH_Lib.Algorithms.Mac_Server_To_Client));
      Item.Compression_Algorithms_Client_To_Server := To_Unbounded_String
        (SSH_Lib.Algorithms.Advertised_Name_List (SSH_Lib.Algorithms.Compression_Client_To_Server));
      Item.Compression_Algorithms_Server_To_Client := To_Unbounded_String
        (SSH_Lib.Algorithms.Advertised_Name_List (SSH_Lib.Algorithms.Compression_Server_To_Client));
      Item.First_Kex_Packet_Follows := False;
      Item.Reserved := 0;

      Status_Value := Encode (Item, Payload);
      if Status_Value = Ok then
         Status_Value := Set (Item.Raw_Payload, To_Array (Payload));
      end if;
      return Status_Value;
   exception
      when others =>
         Clear (Item);
         SSH_Lib.Protocol.Buffers.Clear (Payload);
         return Internal_Error;
   end Construct_Client;

   function Parse
     (Payload : Stream_Element_Array;
      Item    : out Kexinit_Message)
      return Status
   is
      Cursor : Stream_Element_Offset;
      Next_Cursor : Stream_Element_Offset;
      Status_Value : Status;
      Boolean_Value : Boolean;
      Reserved_Value : Unsigned_32;

      function Fail (Status_Item : Status) return Status is
      begin
         Clear (Item);
         return Status_Item;
      end Fail;
   begin
      Clear (Item);
      if Payload'Length < 22 then
         return Fail (Handshake_Failed);
      end if;
      if Payload (Payload'First) /= Message_Number then
         return Fail (Handshake_Failed);
      end if;

      Cursor := Payload'First + 1;
      if Cursor + 15 > Payload'Last then
         return Fail (Handshake_Failed);
      end if;
      for Index_Value in Cookie_Index loop
         Item.Cookie (Index_Value) := Payload (Cursor);
         Cursor := Cursor + 1;
      end loop;

      Status_Value := SSH_Lib.Protocol.Numbers.Decode_Name_List
        (Payload, Cursor, Item.Kex_Algorithms, Next_Cursor);
      if Status_Value /= Ok then
         return Fail (Status_Value);
      end if;
      Cursor := Next_Cursor;
      Status_Value := SSH_Lib.Protocol.Numbers.Decode_Name_List
        (Payload, Cursor, Item.Server_Host_Key_Algorithms, Next_Cursor);
      if Status_Value /= Ok then
         return Fail (Status_Value);
      end if;
      Cursor := Next_Cursor;
      Status_Value := SSH_Lib.Protocol.Numbers.Decode_Name_List
        (Payload, Cursor, Item.Encryption_Algorithms_Client_To_Server, Next_Cursor);
      if Status_Value /= Ok then
         return Fail (Status_Value);
      end if;
      Cursor := Next_Cursor;
      Status_Value := SSH_Lib.Protocol.Numbers.Decode_Name_List
        (Payload, Cursor, Item.Encryption_Algorithms_Server_To_Client, Next_Cursor);
      if Status_Value /= Ok then
         return Fail (Status_Value);
      end if;
      Cursor := Next_Cursor;
      Status_Value := SSH_Lib.Protocol.Numbers.Decode_Name_List
        (Payload, Cursor, Item.Mac_Algorithms_Client_To_Server, Next_Cursor);
      if Status_Value /= Ok then
         return Fail (Status_Value);
      end if;
      Cursor := Next_Cursor;
      Status_Value := SSH_Lib.Protocol.Numbers.Decode_Name_List
        (Payload, Cursor, Item.Mac_Algorithms_Server_To_Client, Next_Cursor);
      if Status_Value /= Ok then
         return Fail (Status_Value);
      end if;
      Cursor := Next_Cursor;
      Status_Value := SSH_Lib.Protocol.Numbers.Decode_Name_List
        (Payload, Cursor, Item.Compression_Algorithms_Client_To_Server, Next_Cursor);
      if Status_Value /= Ok then
         return Fail (Status_Value);
      end if;
      Cursor := Next_Cursor;
      Status_Value := SSH_Lib.Protocol.Numbers.Decode_Name_List
        (Payload, Cursor, Item.Compression_Algorithms_Server_To_Client, Next_Cursor);
      if Status_Value /= Ok then
         return Fail (Status_Value);
      end if;
      Cursor := Next_Cursor;
      Status_Value := SSH_Lib.Protocol.Numbers.Decode_Name_List
        (Payload, Cursor, Item.Languages_Client_To_Server, Next_Cursor);
      if Status_Value /= Ok then
         return Fail (Status_Value);
      end if;
      Cursor := Next_Cursor;
      Status_Value := SSH_Lib.Protocol.Numbers.Decode_Name_List
        (Payload, Cursor, Item.Languages_Server_To_Client, Next_Cursor);
      if Status_Value /= Ok then
         return Fail (Status_Value);
      end if;
      Cursor := Next_Cursor;

      if Cursor > Payload'Last then
         return Fail (Handshake_Failed);
      end if;
      Status_Value := SSH_Lib.Protocol.Numbers.Decode_Boolean (Payload (Cursor), Boolean_Value);
      if Status_Value /= Ok then
         return Fail (Status_Value);
      end if;
      Item.First_Kex_Packet_Follows := Boolean_Value;
      Cursor := Cursor + 1;

      Status_Value := SSH_Lib.Protocol.Numbers.Decode_Uint32
        (Payload, Cursor, Reserved_Value, Next_Cursor);
      if Status_Value /= Ok then
         return Fail (Status_Value);
      end if;
      Cursor := Next_Cursor;
      Item.Reserved := Reserved_Value;
      if Reserved_Value /= 0 then
         return Fail (Handshake_Failed);
      end if;

      if Cursor /= Payload'Last + 1 then
         return Fail (Handshake_Failed);
      end if;

      Status_Value := Set (Item.Raw_Payload, Payload);
      if Status_Value /= Ok then
         return Fail (Status_Value);
      end if;
      return Ok;
   exception
      when others =>
         Clear (Item);
         return Internal_Error;
   end Parse;
end SSH_Lib.Protocol.Kexinit;
