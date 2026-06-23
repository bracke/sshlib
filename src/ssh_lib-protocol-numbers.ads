with Ada.Streams;
with Ada.Strings.Unbounded;
with Interfaces;
with CryptoLib.Errors;
with SSH_Lib.Protocol.Buffers;

package SSH_Lib.Protocol.Numbers is

   function Encode_Uint32
     (Value : Interfaces.Unsigned_32)
      return Ada.Streams.Stream_Element_Array;

   function Decode_Uint32
     (Data        : Ada.Streams.Stream_Element_Array;
      First_Index : Ada.Streams.Stream_Element_Offset;
      Value       : out Interfaces.Unsigned_32;
      Next_Index  : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   function Encode_Boolean
     (Value : Boolean)
      return Ada.Streams.Stream_Element;

   function Decode_Boolean
     (Value  : Ada.Streams.Stream_Element;
      Result : out Boolean)
      return CryptoLib.Errors.Status;

   function Encode_SSH_String
     (Payload : Ada.Streams.Stream_Element_Array)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;

   function Decode_SSH_String
     (Data        : Ada.Streams.Stream_Element_Array;
      First_Index : Ada.Streams.Stream_Element_Offset;
      Payload     : out SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Next_Index  : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   function Encode_Name_List
     (Value : String)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;

   function Decode_Name_List
     (Data        : Ada.Streams.Stream_Element_Array;
      First_Index : Ada.Streams.Stream_Element_Offset;
      Value       : out Ada.Strings.Unbounded.Unbounded_String;
      Next_Index  : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;
end SSH_Lib.Protocol.Numbers;
