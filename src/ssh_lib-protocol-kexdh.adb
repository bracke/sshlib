with Interfaces;
with SSH_Lib.ECDSA;
with SSH_Lib.Protocol.Numbers;

package body SSH_Lib.Protocol.Kexdh is
   use Ada.Streams;
   use CryptoLib.Errors;
   use SSH_Lib.Protocol.Buffers;

   procedure Clear (Item : out Group_Exchange_Group) is
   begin
      SSH_Lib.Protocol.Buffers.Clear (Item.Prime_Value);
      SSH_Lib.Protocol.Buffers.Clear (Item.Generator_Value);
   end Clear;

   procedure Clear (Item : out Reply) is
   begin
      SSH_Lib.Protocol.Buffers.Clear (Item.Host_Key_Blob);
      SSH_Lib.Protocol.Buffers.Clear (Item.Server_Public_Value);
      SSH_Lib.Protocol.Buffers.Clear (Item.Signature_Blob);
   end Clear;

   function Encode_Group_Exchange_Request
     (Minimum_Bits   : Natural;
      Preferred_Bits : Natural;
      Maximum_Bits   : Natural;
      Payload        : out Packet_Buffer)
      return Status
   is
      Status_Value : Status;
   begin
      SSH_Lib.Protocol.Buffers.Clear (Payload);
      if Minimum_Bits < 1024
        or else Preferred_Bits < Minimum_Bits
        or else Maximum_Bits < Preferred_Bits
        or else Maximum_Bits > 8192
      then
         return Handshake_Failed;
      end if;

      Status_Value := Append_Byte (Payload, SSH_MSG_KEX_DH_GEX_REQUEST);
      if Status_Value /= Ok then
         SSH_Lib.Protocol.Buffers.Clear (Payload);
         return Status_Value;
      end if;
      Status_Value := Append
        (Payload, SSH_Lib.Protocol.Numbers.Encode_Uint32
           (Interfaces.Unsigned_32 (Minimum_Bits)));
      if Status_Value /= Ok then
         SSH_Lib.Protocol.Buffers.Clear (Payload);
         return Status_Value;
      end if;
      Status_Value := Append
        (Payload, SSH_Lib.Protocol.Numbers.Encode_Uint32
           (Interfaces.Unsigned_32 (Preferred_Bits)));
      if Status_Value /= Ok then
         SSH_Lib.Protocol.Buffers.Clear (Payload);
         return Status_Value;
      end if;
      Status_Value := Append
        (Payload, SSH_Lib.Protocol.Numbers.Encode_Uint32
           (Interfaces.Unsigned_32 (Maximum_Bits)));
      if Status_Value /= Ok then
         SSH_Lib.Protocol.Buffers.Clear (Payload);
      end if;
      return Status_Value;
   exception
      when others =>
         SSH_Lib.Protocol.Buffers.Clear (Payload);
         return Internal_Error;
   end Encode_Group_Exchange_Request;

   function Parse_Group_Exchange_Group
     (Payload : Stream_Element_Array;
      Item    : out Group_Exchange_Group)
      return Status
   is
      Cursor_Value     : Stream_Element_Offset;
      After_Prime      : Stream_Element_Offset;
      After_Generator  : Stream_Element_Offset;
      Status_Value     : Status;
   begin
      Clear (Item);
      if Payload'Length < 2 or else Payload (Payload'First) /= SSH_MSG_KEX_DH_GEX_GROUP then
         return Handshake_Failed;
      end if;
      Cursor_Value := Payload'First + 1;
      Status_Value := SSH_Lib.Protocol.Numbers.Decode_SSH_String
        (Payload, Cursor_Value, Item.Prime_Value, After_Prime);
      if Status_Value /= Ok then
         Clear (Item);
         return Status_Value;
      end if;
      Status_Value := SSH_Lib.Protocol.Numbers.Decode_SSH_String
        (Payload, After_Prime, Item.Generator_Value, After_Generator);
      if Status_Value /= Ok then
         Clear (Item);
         return Status_Value;
      end if;
      if After_Generator /= Payload'Last + 1
        or else Length (Item.Prime_Value) = 0
        or else Length (Item.Generator_Value) = 0
      then
         Clear (Item);
         return Handshake_Failed;
      end if;
      return Ok;
   exception
      when others =>
         Clear (Item);
         return Internal_Error;
   end Parse_Group_Exchange_Group;

   function Encode_Group_Exchange_Init
     (Client_Public_Value : Stream_Element_Array;
      Payload             : out Packet_Buffer)
      return Status
   is
      Status_Value : Status;
   begin
      SSH_Lib.Protocol.Buffers.Clear (Payload);
      if Client_Public_Value'Length = 0 then
         return Handshake_Failed;
      end if;
      Status_Value := Append_Byte (Payload, SSH_MSG_KEX_DH_GEX_INIT);
      if Status_Value /= Ok then
         SSH_Lib.Protocol.Buffers.Clear (Payload);
         return Status_Value;
      end if;
      Status_Value := Append
        (Payload,
         SSH_Lib.Protocol.Buffers.To_Array
           (SSH_Lib.Protocol.Numbers.Encode_SSH_String (Client_Public_Value)));
      if Status_Value /= Ok then
         SSH_Lib.Protocol.Buffers.Clear (Payload);
      end if;
      return Status_Value;
   exception
      when others =>
         SSH_Lib.Protocol.Buffers.Clear (Payload);
         return Internal_Error;
   end Encode_Group_Exchange_Init;

   function Parse_Group_Exchange_Reply
     (Payload : Stream_Element_Array;
      Item    : out Reply)
      return Status
   is
      Cursor_Value       : Stream_Element_Offset;
      After_Host_Key     : Stream_Element_Offset;
      After_Public_Value : Stream_Element_Offset;
      After_Signature    : Stream_Element_Offset;
      Status_Value       : Status;
   begin
      Clear (Item);
      if Payload'Length < 2 or else Payload (Payload'First) /= SSH_MSG_KEX_DH_GEX_REPLY then
         return Handshake_Failed;
      end if;
      Cursor_Value := Payload'First + 1;
      Status_Value := SSH_Lib.Protocol.Numbers.Decode_SSH_String
        (Payload, Cursor_Value, Item.Host_Key_Blob, After_Host_Key);
      if Status_Value /= Ok then
         Clear (Item);
         return Status_Value;
      end if;
      Status_Value := SSH_Lib.Protocol.Numbers.Decode_SSH_String
        (Payload, After_Host_Key, Item.Server_Public_Value, After_Public_Value);
      if Status_Value /= Ok then
         Clear (Item);
         return Status_Value;
      end if;
      Status_Value := SSH_Lib.Protocol.Numbers.Decode_SSH_String
        (Payload, After_Public_Value, Item.Signature_Blob, After_Signature);
      if Status_Value /= Ok then
         Clear (Item);
         return Status_Value;
      end if;
      if After_Signature /= Payload'Last + 1
        or else Length (Item.Host_Key_Blob) = 0
        or else Length (Item.Server_Public_Value) = 0
        or else Length (Item.Signature_Blob) = 0
      then
         Clear (Item);
         return Handshake_Failed;
      end if;
      return Ok;
   exception
      when others =>
         Clear (Item);
         return Internal_Error;
   end Parse_Group_Exchange_Reply;

   function Encode_Group14_Init
     (Client_Public_Value : Stream_Element_Array;
      Payload             : out Packet_Buffer)
      return Status
   is
      Status_Value : Status;
   begin
      SSH_Lib.Protocol.Buffers.Clear (Payload);
      if Client_Public_Value'Length = 0 then
         return Handshake_Failed;
      end if;

      Status_Value := Append_Byte (Payload, SSH_MSG_KEXDH_INIT);
      if Status_Value /= Ok then
         SSH_Lib.Protocol.Buffers.Clear (Payload);
         return Status_Value;
      end if;

      Status_Value := Append
        (Payload,
         SSH_Lib.Protocol.Buffers.To_Array
           (SSH_Lib.Protocol.Numbers.Encode_SSH_String (Client_Public_Value)));
      if Status_Value /= Ok then
         SSH_Lib.Protocol.Buffers.Clear (Payload);
      end if;
      return Status_Value;
   exception
      when others =>
         SSH_Lib.Protocol.Buffers.Clear (Payload);
         return Internal_Error;
   end Encode_Group14_Init;

   function Parse_Group14_Reply
     (Payload : Stream_Element_Array;
      Item    : out Reply)
      return Status
   is
      Cursor_Value       : Stream_Element_Offset;
      After_Host_Key     : Stream_Element_Offset;
      After_Public_Value : Stream_Element_Offset;
      After_Signature    : Stream_Element_Offset;
      Status_Value       : Status;
   begin
      Clear (Item);
      if Payload'Length < 2 or else Payload (Payload'First) /= SSH_MSG_KEXDH_REPLY then
         return Handshake_Failed;
      end if;

      Cursor_Value := Payload'First + 1;
      Status_Value := SSH_Lib.Protocol.Numbers.Decode_SSH_String
        (Payload, Cursor_Value, Item.Host_Key_Blob, After_Host_Key);
      if Status_Value /= Ok then
         Clear (Item);
         return Status_Value;
      end if;

      Status_Value := SSH_Lib.Protocol.Numbers.Decode_SSH_String
        (Payload, After_Host_Key, Item.Server_Public_Value, After_Public_Value);
      if Status_Value /= Ok then
         Clear (Item);
         return Status_Value;
      end if;

      Status_Value := SSH_Lib.Protocol.Numbers.Decode_SSH_String
        (Payload, After_Public_Value, Item.Signature_Blob, After_Signature);
      if Status_Value /= Ok then
         Clear (Item);
         return Status_Value;
      end if;

      if After_Signature /= Payload'Last + 1
        or else Length (Item.Host_Key_Blob) = 0
        or else Length (Item.Server_Public_Value) = 0
        or else Length (Item.Signature_Blob) = 0
      then
         Clear (Item);
         return Handshake_Failed;
      end if;

      return Ok;
   exception
      when others =>
         Clear (Item);
         return Internal_Error;
   end Parse_Group14_Reply;

   function Encode_Curve25519_Init
     (Client_Public_Key : Stream_Element_Array;
      Payload           : out Packet_Buffer)
      return Status
   is
   begin
      if Client_Public_Key'Length /= 32 then
         SSH_Lib.Protocol.Buffers.Clear (Payload);
         return Handshake_Failed;
      end if;

      return Encode_Group14_Init (Client_Public_Key, Payload);
   end Encode_Curve25519_Init;

   function Parse_Curve25519_Reply
     (Payload : Stream_Element_Array;
      Item    : out Reply)
      return Status
   is
      Status_Value : Status;
   begin
      Status_Value := Parse_Group14_Reply (Payload, Item);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      if SSH_Lib.Protocol.Buffers.Length (Item.Server_Public_Value) /= 32 then
         Clear (Item);
         return Handshake_Failed;
      end if;

      return Ok;
   exception
      when others =>
         Clear (Item);
         return Internal_Error;
   end Parse_Curve25519_Reply;

   function Encode_ECDH_Nistp256_Init
     (Client_Public_Key : Stream_Element_Array;
      Payload           : out Packet_Buffer)
      return Status
   is
      Status_Value : Status;
   begin
      SSH_Lib.Protocol.Buffers.Clear (Payload);

      --  RFC 5656 sends Q_C as an SSH string containing the SEC1
      --  uncompressed point.  Do not route through the finite-field KEXDH
      --  helper even though the message number is shared; that helper is
      --  mpint-oriented by protocol semantics and future maintenance should
      --  not be able to change ECDH framing accidentally.
      Status_Value := SSH_Lib.ECDSA.Validate_Raw_Point_Nistp256
        (Client_Public_Key);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      Status_Value := Append_Byte (Payload, SSH_MSG_KEX_ECDH_INIT);
      if Status_Value /= Ok then
         SSH_Lib.Protocol.Buffers.Clear (Payload);
         return Status_Value;
      end if;

      Status_Value := Append
        (Payload,
         SSH_Lib.Protocol.Buffers.To_Array
           (SSH_Lib.Protocol.Numbers.Encode_SSH_String (Client_Public_Key)));
      if Status_Value /= Ok then
         SSH_Lib.Protocol.Buffers.Clear (Payload);
      end if;
      return Status_Value;
   exception
      when others =>
         SSH_Lib.Protocol.Buffers.Clear (Payload);
         return Internal_Error;
   end Encode_ECDH_Nistp256_Init;

   function Parse_ECDH_Nistp256_Reply
     (Payload : Stream_Element_Array;
      Item    : out Reply)
      return Status
   is
      Cursor_Value       : Stream_Element_Offset;
      After_Host_Key     : Stream_Element_Offset;
      After_Public_Value : Stream_Element_Offset;
      After_Signature    : Stream_Element_Offset;
      Status_Value       : Status;
   begin
      Clear (Item);
      if Payload'Length < 2 or else Payload (Payload'First) /= SSH_MSG_KEX_ECDH_REPLY then
         return Handshake_Failed;
      end if;

      --  RFC 5656 KEX_ECDH_REPLY contains string K_S, string Q_S,
      --  string signature.  Parse it directly instead of sharing the
      --  finite-field reply parser so the elliptic-curve string semantics
      --  remain explicit at this boundary.
      Cursor_Value := Payload'First + 1;
      Status_Value := SSH_Lib.Protocol.Numbers.Decode_SSH_String
        (Payload, Cursor_Value, Item.Host_Key_Blob, After_Host_Key);
      if Status_Value /= Ok then
         Clear (Item);
         return Status_Value;
      end if;

      Status_Value := SSH_Lib.Protocol.Numbers.Decode_SSH_String
        (Payload, After_Host_Key, Item.Server_Public_Value, After_Public_Value);
      if Status_Value /= Ok then
         Clear (Item);
         return Status_Value;
      end if;

      Status_Value := SSH_Lib.Protocol.Numbers.Decode_SSH_String
        (Payload, After_Public_Value, Item.Signature_Blob, After_Signature);
      if Status_Value /= Ok then
         Clear (Item);
         return Status_Value;
      end if;

      if After_Signature /= Payload'Last + 1
        or else Length (Item.Host_Key_Blob) = 0
        or else Length (Item.Server_Public_Value) = 0
        or else Length (Item.Signature_Blob) = 0
      then
         Clear (Item);
         return Handshake_Failed;
      end if;

      declare
         Server_Public_Array : constant Stream_Element_Array :=
           SSH_Lib.Protocol.Buffers.To_Array (Item.Server_Public_Value);
      begin
         Status_Value := SSH_Lib.ECDSA.Validate_Raw_Point_Nistp256
           (Server_Public_Array);
         if Status_Value /= Ok then
            Clear (Item);
            return Status_Value;
         end if;
      end;

      return Ok;
   exception
      when others =>
         Clear (Item);
         return Internal_Error;
   end Parse_ECDH_Nistp256_Reply;

   function Validate_ECDH_Point
     (Curve_Name : String; Public_Point : Stream_Element_Array) return Status is
   begin
      if Curve_Name = "nistp256" then
         return SSH_Lib.ECDSA.Validate_Raw_Point_Nistp256 (Public_Point);
      elsif Curve_Name = "nistp384" then
         return SSH_Lib.ECDSA.Validate_Raw_Point_Nistp384 (Public_Point);
      elsif Curve_Name = "nistp521" then
         return SSH_Lib.ECDSA.Validate_Raw_Point_Nistp521 (Public_Point);
      end if;
      return Unsupported_Feature;
   exception
      when others =>
         return Internal_Error;
   end Validate_ECDH_Point;

   function Encode_ECDH_Init
     (Curve_Name        : String;
      Client_Public_Key : Stream_Element_Array;
      Payload           : out Packet_Buffer)
      return Status
   is
      Status_Value : Status;
   begin
      SSH_Lib.Protocol.Buffers.Clear (Payload);

      Status_Value := Validate_ECDH_Point (Curve_Name, Client_Public_Key);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      Status_Value := Append_Byte (Payload, SSH_MSG_KEX_ECDH_INIT);
      if Status_Value /= Ok then
         SSH_Lib.Protocol.Buffers.Clear (Payload);
         return Status_Value;
      end if;

      Status_Value := Append
        (Payload,
         SSH_Lib.Protocol.Buffers.To_Array
           (SSH_Lib.Protocol.Numbers.Encode_SSH_String (Client_Public_Key)));
      if Status_Value /= Ok then
         SSH_Lib.Protocol.Buffers.Clear (Payload);
      end if;
      return Status_Value;
   exception
      when others =>
         SSH_Lib.Protocol.Buffers.Clear (Payload);
         return Internal_Error;
   end Encode_ECDH_Init;

   function Parse_ECDH_Reply
     (Curve_Name : String;
      Payload    : Stream_Element_Array;
      Item       : out Reply)
      return Status
   is
      Status_Value : Status;
   begin
      Status_Value := Parse_Group14_Reply (Payload, Item);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      declare
         Server_Public_Array : constant Stream_Element_Array :=
           SSH_Lib.Protocol.Buffers.To_Array (Item.Server_Public_Value);
      begin
         Status_Value := Validate_ECDH_Point (Curve_Name, Server_Public_Array);
         if Status_Value /= Ok then
            Clear (Item);
            return Status_Value;
         end if;
      end;

      return Ok;
   exception
      when others =>
         Clear (Item);
         return Internal_Error;
   end Parse_ECDH_Reply;

   function Encode_ECDH_Nistp384_Init
     (Client_Public_Key : Stream_Element_Array;
      Payload           : out Packet_Buffer)
      return Status is
   begin
      return Encode_ECDH_Init ("nistp384", Client_Public_Key, Payload);
   end Encode_ECDH_Nistp384_Init;

   function Parse_ECDH_Nistp384_Reply
     (Payload : Stream_Element_Array;
      Item    : out Reply)
      return Status is
   begin
      return Parse_ECDH_Reply ("nistp384", Payload, Item);
   end Parse_ECDH_Nistp384_Reply;

   function Encode_ECDH_Nistp521_Init
     (Client_Public_Key : Stream_Element_Array;
      Payload           : out Packet_Buffer)
      return Status is
   begin
      return Encode_ECDH_Init ("nistp521", Client_Public_Key, Payload);
   end Encode_ECDH_Nistp521_Init;

   function Parse_ECDH_Nistp521_Reply
     (Payload : Stream_Element_Array;
      Item    : out Reply)
      return Status is
   begin
      return Parse_ECDH_Reply ("nistp521", Payload, Item);
   end Parse_ECDH_Nistp521_Reply;

   function Encode_Hybrid_PQ_Init
     (Client_Init : Stream_Element_Array;
      Payload     : out Packet_Buffer)
      return Status
   is
      Status_Value : Status;
   begin
      SSH_Lib.Protocol.Buffers.Clear (Payload);
      if Client_Init'Length = 0 then
         return Handshake_Failed;
      end if;

      Status_Value := Append_Byte (Payload, SSH_MSG_KEX_ECDH_INIT);
      if Status_Value /= Ok then
         SSH_Lib.Protocol.Buffers.Clear (Payload);
         return Status_Value;
      end if;

      Status_Value := Append
        (Payload,
         SSH_Lib.Protocol.Buffers.To_Array
           (SSH_Lib.Protocol.Numbers.Encode_SSH_String (Client_Init)));
      if Status_Value /= Ok then
         SSH_Lib.Protocol.Buffers.Clear (Payload);
      end if;
      return Status_Value;
   exception
      when others =>
         SSH_Lib.Protocol.Buffers.Clear (Payload);
         return Internal_Error;
   end Encode_Hybrid_PQ_Init;

   function Parse_Hybrid_PQ_Reply
     (Payload : Stream_Element_Array;
      Item    : out Reply)
      return Status
   is
   begin
      return Parse_Group14_Reply (Payload, Item);
   exception
      when others =>
         Clear (Item);
         return Internal_Error;
   end Parse_Hybrid_PQ_Reply;

end SSH_Lib.Protocol.Kexdh;
