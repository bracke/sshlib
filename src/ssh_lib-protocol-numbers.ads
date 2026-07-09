with Ada.Streams;
with Ada.Strings.Unbounded;
with Interfaces;
with CryptoLib.Errors;
with SSH_Lib.Protocol.Buffers;

--  @summary Encode and decode the primitive SSH wire data types (RFC 4251 section 5).
--
--  Serializes and parses the base SSH binary types -- 32-bit unsigned integers,
--  booleans, length-prefixed strings, and comma-separated name-lists -- that the
--  rest of the protocol layer composes into messages.
package SSH_Lib.Protocol.Numbers is

   --  Encode a 32-bit unsigned integer as four big-endian bytes.
   --  @param Value the integer to encode
   --  @return the 4-byte big-endian encoding
   function Encode_Uint32
     (Value : Interfaces.Unsigned_32)
      return Ada.Streams.Stream_Element_Array;

   --  Decode a big-endian uint32 from a buffer at a given offset.
   --  @param Data        the buffer to read from
   --  @param First_Index the offset of the first of the four bytes
   --  @param Value       the decoded integer
   --  @param Next_Index  the offset just past the four consumed bytes
   --  @return Ok on success, an error status if the buffer is too short
   function Decode_Uint32
     (Data        : Ada.Streams.Stream_Element_Array;
      First_Index : Ada.Streams.Stream_Element_Offset;
      Value       : out Interfaces.Unsigned_32;
      Next_Index  : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   --  Encode a boolean as the single SSH byte (0 for False, 1 for True).
   --  @param Value the boolean to encode
   --  @return the encoded byte
   function Encode_Boolean
     (Value : Boolean)
      return Ada.Streams.Stream_Element;

   --  Decode a single SSH boolean byte (any nonzero value is True).
   --  @param Value  the byte to decode
   --  @param Result the decoded boolean
   --  @return Ok on success
   function Decode_Boolean
     (Value  : Ada.Streams.Stream_Element;
      Result : out Boolean)
      return CryptoLib.Errors.Status;

   --  Encode a byte payload as a length-prefixed SSH string (uint32 length then bytes).
   --  @param Payload the raw bytes to wrap
   --  @return the encoded length-prefixed string
   function Encode_SSH_String
     (Payload : Ada.Streams.Stream_Element_Array)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;

   --  Decode a length-prefixed SSH string from a buffer at a given offset.
   --  @param Data        the buffer to read from
   --  @param First_Index the offset of the uint32 length prefix
   --  @param Payload     the decoded string contents
   --  @param Next_Index  the offset just past the consumed string
   --  @return Ok on success, an error status if the buffer is too short or malformed
   function Decode_SSH_String
     (Data        : Ada.Streams.Stream_Element_Array;
      First_Index : Ada.Streams.Stream_Element_Offset;
      Payload     : out SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Next_Index  : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;

   --  Encode a comma-separated name-list as a length-prefixed SSH string.
   --  @param Value the comma-separated names
   --  @return the encoded name-list
   function Encode_Name_List
     (Value : String)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;

   --  Decode a length-prefixed SSH name-list into its comma-separated text.
   --  @param Data        the buffer to read from
   --  @param First_Index the offset of the uint32 length prefix
   --  @param Value       the decoded comma-separated names
   --  @param Next_Index  the offset just past the consumed name-list
   --  @return Ok on success, an error status if the buffer is too short or malformed
   function Decode_Name_List
     (Data        : Ada.Streams.Stream_Element_Array;
      First_Index : Ada.Streams.Stream_Element_Offset;
      Value       : out Ada.Strings.Unbounded.Unbounded_String;
      Next_Index  : out Ada.Streams.Stream_Element_Offset)
      return CryptoLib.Errors.Status;
end SSH_Lib.Protocol.Numbers;
