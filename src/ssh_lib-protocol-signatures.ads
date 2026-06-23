with Ada.Streams;
with Ada.Strings.Unbounded;
with CryptoLib.Errors;
with SSH_Lib.Keys;
with SSH_Lib.Protocol.Buffers;

package SSH_Lib.Protocol.Signatures is
   type Parsed_Signature is private;

   procedure Clear (Item : out Parsed_Signature);

   function Algorithm (Item : Parsed_Signature) return String;

   function Bytes
     (Item : Parsed_Signature)
      return Ada.Streams.Stream_Element_Array;

   function Parse
     (Blob                 : Ada.Streams.Stream_Element_Array;
      Negotiated_Algorithm : String;
      Item                 : out Parsed_Signature)
      return CryptoLib.Errors.Status;

   function Verify
     (Negotiated_Algorithm : String;
      Key_Item             : SSH_Lib.Keys.Public_Key;
      Signature_Item       : Parsed_Signature;
      Exchange_Hash        : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

private
   type Parsed_Signature is record
      Present        : Boolean := False;
      Algorithm_Text : Ada.Strings.Unbounded.Unbounded_String;
      Signature_Data : SSH_Lib.Protocol.Buffers.Packet_Buffer;
   end record;
end SSH_Lib.Protocol.Signatures;
